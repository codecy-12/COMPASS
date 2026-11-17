from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Sequence, Set

from ..acg import ACG
from ..schema import (
    ArgumentBinding,
    AuditEvent,
    BoundValue,
    CandidateInput,
    EdgeKind,
    ExternalInputEntry,
    SyscallSite,
)
from ..util import parse_int
from .provenance import ProvenanceGraph


SYSCALL_ARGUMENT_ORDER: Dict[str, Sequence[str]] = {
    "read": ("fd", "buf", "count"),
    "readv": ("fd", "iov", "iovcnt"),
    "pread64": ("fd", "buf", "count", "offset"),
    "recvfrom": ("fd", "buf", "len", "flags", "src_addr", "addrlen"),
    "recvmsg": ("fd", "msg", "flags"),
    "recvmmsg": ("fd", "msgvec", "vlen", "flags", "timeout"),
    "write": ("fd", "buf", "count"),
    "writev": ("fd", "iov", "iovcnt"),
    "pwrite64": ("fd", "buf", "count", "offset"),
    "sendto": ("fd", "buf", "len", "flags", "dest_addr", "addrlen"),
    "sendmsg": ("fd", "msg", "flags"),
    "open": ("path", "flags", "mode"),
    "openat": ("dirfd", "path", "flags", "mode"),
    "openat2": ("dirfd", "path", "how", "size"),
    "accept": ("fd", "addr", "addrlen"),
    "accept4": ("fd", "addr", "addrlen", "flags"),
    "connect": ("fd", "addr", "addrlen"),
}


@dataclass
class AuditBindingIndex:

    by_event: Dict[str, List[ArgumentBinding]] = field(default_factory=dict)

    def bindings_for(self, event_id: str) -> List[ArgumentBinding]:
        return list(self.by_event.get(event_id, []))

    def site_ids(self, event_id: str) -> List[str]:
        return [binding.site_id for binding in self.bindings_for(event_id)]

    def functions(self, event_id: str) -> Set[str]:
        return {binding.function_id for binding in self.bindings_for(event_id)}


@dataclass
class BindingPlan:
    entry: ExternalInputEntry
    candidate: CandidateInput
    current_event: AuditEvent
    events: List[AuditEvent]
    bindings: List[ArgumentBinding]
    alternatives: Dict[str, List[str]] = field(default_factory=dict)

    @property
    def by_site(self) -> Dict[str, List[ArgumentBinding]]:
        values: Dict[str, List[ArgumentBinding]] = {}
        for binding in self.bindings:
            values.setdefault(binding.site_id, []).append(binding)
        return values


class ArgumentBinder:

    def match_audit(self, events: Iterable[AuditEvent], acg: ACG) -> AuditBindingIndex:
        ordered = sorted(events, key=lambda event: (event.sequence, event.timestamp_ns, event.id))
        matches: Dict[str, List[ArgumentBinding]] = {}
        for event in ordered:
            sites = [site for site in acg.syscall_candidates(event.syscall) if self._compatible(site, event)]
            explicit_site = event.metadata.get("syscall_site_id", event.metadata.get("site_id"))
            if explicit_site:
                sites = [site for site in sites if site.id == str(explicit_site)]
            observed_functions = self._observed_functions(event, acg)
            if observed_functions:
                sites = [site for site in sites if site.function_id in observed_functions]
            module = str(event.metadata.get("module", ""))
            if event.callsite is not None and module:
                rva = int(event.callsite) - (parse_int(event.metadata.get("module_base"), 0) or 0)
                located = [
                    site for site in sites
                    if (site.module == module or site.module.rsplit("/", 1)[-1] == module.rsplit("/", 1)[-1])
                    and site.rva == rva
                ]
                sites = located

            bindings = [self._binding(event, site, observed_functions) for site in sites]
            bindings.sort(key=lambda item: (-item.score, item.site_id))
            if bindings:
                matches[event.id] = bindings
        return AuditBindingIndex(matches)

    def build_plan(
        self,
        candidate: CandidateInput,
        current: AuditEvent,
        entry: ExternalInputEntry,
        provenance: ProvenanceGraph,
        acg: ACG,
        index: AuditBindingIndex,
    ) -> BindingPlan:
        event_ids = set(candidate.metadata.get("context_event_ids", []))
        event_ids.update(event.id for event in candidate.events)
        event_ids.add(current.id)
        events = sorted(
            (
                provenance.events[event_id] for event_id in event_ids
                if event_id in provenance.events
                and candidate.first_event.sequence <= provenance.events[event_id].sequence <= current.sequence
            ),
            key=lambda event: (event.sequence, event.timestamp_ns, event.id),
        )

        reachable_functions = self._reachable_functions(entry.function_id, acg)
        bindings: List[ArgumentBinding] = []
        alternatives: Dict[str, List[str]] = {}
        for event in events:
            event_bindings = [
                binding
                for binding in index.bindings_for(event.id)
                if binding.function_id in reachable_functions
            ]
            if event.id in {item.id for item in candidate.events} and "input_site_ids" in candidate.metadata:
                allowed = set(candidate.metadata["input_site_ids"])
                event_bindings = [binding for binding in event_bindings if binding.site_id in allowed]
            elif event.id == current.id and "output_site_ids" in candidate.metadata:
                allowed = set(candidate.metadata["output_site_ids"])
                event_bindings = [binding for binding in event_bindings if binding.site_id in allowed]
            if not event_bindings:
                continue
            alternatives[event.id] = [binding.site_id for binding in event_bindings]
            bindings.extend(event_bindings)
        return BindingPlan(entry, candidate, current, events, bindings, alternatives)

    @staticmethod
    def _reachable_functions(entry_function: str, acg: ACG) -> Set[str]:
        pending = [entry_function]
        reached = set()
        functions = set()
        while pending:
            node = pending.pop()
            if node in reached:
                continue
            reached.add(node)
            if node in acg.functions:
                functions.add(node)
            elif node in acg.blocks:
                functions.add(acg.blocks[node].function_id)
            pending.extend(edge.target for edge in acg.outgoing(node) if edge.target not in reached)
        return functions

    @staticmethod
    def _observed_functions(event: AuditEvent, acg: ACG) -> Set[str]:
        functions: Set[str] = set()
        for frame in event.metadata.get("stack_modules", []):
            function = acg.function_at(
                str(frame.get("module", "")),
                (parse_int(frame.get("address"), 0) or 0) - (parse_int(frame.get("module_base"), 0) or 0),
            )
            if function:
                functions.add(function.id)
        if functions:
            return functions
        module = str(event.metadata.get("module", ""))
        module_base = parse_int(event.metadata.get("module_base"), 0) or 0
        addresses = ([event.callsite] if event.callsite is not None else []) + list(event.user_stack)
        for address in addresses:
            if not module:
                continue
            function = acg.function_at(module, (parse_int(address, 0) or 0) - module_base)
            if function:
                functions.add(function.id)
        return functions

    def _binding(
        self, event: AuditEvent, site: SyscallSite, observed_functions: Set[str]
    ) -> ArgumentBinding:
        score = 1
        score += int(site.syscall == event.syscall) * 4
        score += int(site.function_id in observed_functions) * 4
        score += int(bool(event.handle)) * 2
        score += len(site.argument_layout)
        return ArgumentBinding(
            event_id=event.id,
            site_id=site.id,
            function_id=site.function_id,
            score=score,
            values=self._values(event, site),
            evidence=["syscall-type", "acfg-label", "runtime-context", "concrete-values"],
        )

    @staticmethod
    def _compatible(site: SyscallSite, event: AuditEvent) -> bool:
        if site.syscall not in {"unknown", event.syscall}:
            return False
        count = site.metadata.get("argument_count")
        observed_count = event.metadata.get("argument_count")
        if count is not None and observed_count is not None and int(count) != int(observed_count):
            return False
        roles = site.metadata.get("argument_roles", {})
        observed_roles = event.metadata.get("argument_roles", {})
        if isinstance(roles, dict) and isinstance(observed_roles, dict):
            if any(name in observed_roles and observed_roles[name] != role for name, role in roles.items()):
                return False
        constants = site.metadata.get("constant_arguments", {})
        for name, expected in constants.items():
            if name in event.args and str(event.args[name]) != str(expected):
                return False
        expected_result = site.metadata.get("constant_result")
        if expected_result is not None and parse_int(expected_result) != parse_int(event.result):
            return False
        return True

    @staticmethod
    def _values(event: AuditEvent, site: SyscallSite) -> List[BoundValue]:
        values: List[BoundValue] = []
        order = SYSCALL_ARGUMENT_ORDER.get(event.syscall, tuple(event.args.keys()))
        for index, name in enumerate(order):
            if name not in event.args:
                continue
            values.append(
                BoundValue(
                    name=name,
                    value=event.args[name],
                    location=ArgumentBinder._argument_location(site, name, index),
                    apply_at_site=site.id,
                    source_event=event.id,
                )
            )
        if event.handle:
            values.append(
                BoundValue(
                    name="handle_object",
                    value=event.handle.object_id,
                    location="metadata:handle_object",
                    apply_at_site=site.id,
                    source_event=event.id,
                )
            )
        if event.data:
            values.append(
                BoundValue(
                    name="transferred_data",
                    value=event.data[: event.successful_bytes],
                    location="buffer:" + ArgumentBinder._argument_location(site, "buf", 1),
                    width=event.successful_bytes,
                    apply_at_site=site.id,
                    source_event=event.id,
                )
            )
        values.append(
            BoundValue(
                name="return_value",
                value=event.result,
                location="return",
                apply_at_site=site.id,
                source_event=event.id,
            )
        )
        return values

    @staticmethod
    def _argument_location(site: SyscallSite, name: str, index: int) -> str:
        if name in site.argument_layout:
            return site.argument_layout[name]
        mnemonic = str(site.metadata.get("mnemonic", "")).lower()
        native = mnemonic in {"syscall", "sysenter", "svc"} or site.metadata.get("abi") in {"syscall", "linux-syscall"}
        if native:
            architecture = str(site.metadata.get("architecture", "X86" if mnemonic == "sysenter" else "AARCH64" if mnemonic == "svc" else "AMD64")).upper()
            registers = {
                "AMD64": ("rdi", "rsi", "rdx", "r10", "r8", "r9"),
                "X86_64": ("rdi", "rsi", "rdx", "r10", "r8", "r9"),
                "X86": ("ebx", "ecx", "edx", "esi", "edi", "ebp"),
                "I386": ("ebx", "ecx", "edx", "esi", "edi", "ebp"),
                "AARCH64": ("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"),
            }.get(architecture, ())
            if index < len(registers):
                return "reg:" + registers[index]
        return "arg:%d" % index
