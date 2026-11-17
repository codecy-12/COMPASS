from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, DefaultDict, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from .errors import SchemaError
from .schema import (
    ACGEdgeRecord,
    BasicBlockRecord,
    EdgeKind,
    ExternalInputEntry,
    FunctionRecord,
    SyscallSite,
)
from .util import dump_json, load_json, primitive


IO_INTERFACES = {
    "read": ("input", ("fd", "buf", "count")),
    "readv": ("input", ("fd", "iov", "iovcnt")),
    "pread": ("input", ("fd", "buf", "count", "offset")),
    "pread64": ("input", ("fd", "buf", "count", "offset")),
    "recv": ("input", ("fd", "buf", "len", "flags")),
    "recvfrom": ("input", ("fd", "buf", "len", "flags", "src_addr", "addrlen")),
    "recvmsg": ("input", ("fd", "msg", "flags")),
    "recvmmsg": ("input", ("fd", "msgvec", "vlen", "flags", "timeout")),
    "accept": ("input", ("fd", "addr", "addrlen")),
    "accept4": ("input", ("fd", "addr", "addrlen", "flags")),
    "write": ("output", ("fd", "buf", "count")),
    "writev": ("output", ("fd", "iov", "iovcnt")),
    "pwrite": ("output", ("fd", "buf", "count", "offset")),
    "pwrite64": ("output", ("fd", "buf", "count", "offset")),
    "send": ("output", ("fd", "buf", "len", "flags")),
    "sendto": ("output", ("fd", "buf", "len", "flags", "dest_addr", "addrlen")),
    "sendmsg": ("output", ("fd", "msg", "flags")),
    "sendmmsg": ("output", ("fd", "msgvec", "vlen", "flags")),
    "open": ("output", ("path", "flags", "mode")),
    "open64": ("output", ("path", "flags", "mode")),
    "openat": ("output", ("dirfd", "path", "flags", "mode")),
    "openat64": ("output", ("dirfd", "path", "flags", "mode")),
    "openat2": ("output", ("dirfd", "path", "how", "size")),
    "execve": ("output", ("path", "argv", "envp")),
    "execveat": ("output", ("dirfd", "path", "argv", "envp", "flags")),
}


@dataclass(frozen=True)
class AddressRef:
    module: str
    rva: int


class ACG:
    """Build-specific augmented call graph with attached function CFGs.

    ``DIRECT_CALL``, ``INDIRECT_CALL``, and ``CROSS_CONTEXT`` are ACG edges.
    ``CFG`` and ``RETURN`` records belong to the attached per-function CFGs and
    are kept in the same artifact so the symbolic executor can move between
    function-level selection and basic-block execution without a second file.
    """

    schema_version = 2
    ACG_KINDS = frozenset(
        {EdgeKind.DIRECT_CALL, EdgeKind.INDIRECT_CALL, EdgeKind.CROSS_CONTEXT}
    )
    CFG_KINDS = frozenset({EdgeKind.CFG, EdgeKind.RETURN})

    def __init__(self, *, build_id: str = "", binary: str = "", architecture: str = "") -> None:
        self.build_id = build_id
        self.binary = binary
        self.architecture = architecture
        self.functions: Dict[str, FunctionRecord] = {}
        self.blocks: Dict[str, BasicBlockRecord] = {}
        self.edges: Dict[str, ACGEdgeRecord] = {}
        self.syscall_sites: Dict[str, SyscallSite] = {}
        self.entries: Dict[str, ExternalInputEntry] = {}
        self.metadata: Dict[str, Any] = {}
        self._out: DefaultDict[str, List[str]] = defaultdict(list)
        self._in: DefaultDict[str, List[str]] = defaultdict(list)
        self._function_by_address: Dict[Tuple[str, int], str] = {}
        self._block_by_address: Dict[Tuple[str, int], str] = {}
        self._syscalls_by_name: DefaultDict[str, List[str]] = defaultdict(list)

    def _index_edge(self, edge: ACGEdgeRecord) -> None:
        if edge.id not in self._out[edge.source]:
            self._out[edge.source].append(edge.id)
        if edge.id not in self._in[edge.target]:
            self._in[edge.target].append(edge.id)

    def add_function(self, function: FunctionRecord) -> None:
        self.functions[function.id] = function
        self._function_by_address[(function.module, function.rva)] = function.id

    def add_block(self, block: BasicBlockRecord) -> None:
        self.blocks[block.id] = block
        self._block_by_address[(block.module, block.rva)] = block.id
        function = self.functions.get(block.function_id)
        if function and block.id not in function.blocks:
            function.blocks.append(block.id)

    def add_edge(self, edge: ACGEdgeRecord) -> None:
        if edge.source not in self.blocks and edge.source not in self.functions:
            raise SchemaError("graph relation source does not exist: %s" % edge.source)
        if edge.target not in self.blocks and edge.target not in self.functions:
            raise SchemaError("graph relation target does not exist: %s" % edge.target)
        previous = self.edges.get(edge.id)
        if previous is not None:
            self._out[previous.source] = [item for item in self._out[previous.source] if item != edge.id]
            self._in[previous.target] = [item for item in self._in[previous.target] if item != edge.id]
        self.edges[edge.id] = edge
        self._index_edge(edge)

    def acg_edges(self) -> List[ACGEdgeRecord]:
        return sorted(
            (edge for edge in self.edges.values() if edge.kind in self.ACG_KINDS),
            key=lambda edge: edge.id,
        )

    def cfg_edges(self) -> List[ACGEdgeRecord]:
        return sorted(
            (edge for edge in self.edges.values() if edge.kind in self.CFG_KINDS),
            key=lambda edge: edge.id,
        )

    def add_syscall_site(self, site: SyscallSite) -> None:
        previous = self.syscall_sites.get(site.id)
        if previous is not None:
            for name in (previous.syscall, "*"):
                self._syscalls_by_name[name] = [item for item in self._syscalls_by_name[name] if item != site.id]
            block = self.blocks.get(previous.block_id)
            if block is not None:
                for name in ("input_labels", "output_labels"):
                    if name in block.metadata:
                        block.metadata[name] = [item for item in block.metadata[name] if item != site.id]
        self.annotate_io_site(site)
        self.syscall_sites[site.id] = site
        self._syscalls_by_name[site.syscall].append(site.id)
        if site.syscall != "unknown":
            self._syscalls_by_name["*"].append(site.id)

    def annotate_io_site(self, site: SyscallSite) -> None:
        name = site.syscall.lstrip("_").split("@", 1)[0]
        if name.startswith("libc_"):
            name = name[5:]
        interface = IO_INTERFACES.get(name)
        site.metadata.setdefault("build_id", self.build_id)
        site.metadata.setdefault("block_id", site.block_id)
        if interface is None:
            return
        direction, roles = interface
        native = site.metadata.get("kind") == "syscall_instruction" or site.metadata.get("mnemonic") in {"syscall", "sysenter", "svc"}
        architecture = self.architecture.upper()
        registers: List[str] = []
        if native and architecture in {"AMD64", "X86_64", "METAPC"}:
            registers = ["rdi", "rsi", "rdx", "r10", "r8", "r9"]
        elif native and architecture in {"X86", "I386", "I686"}:
            registers = ["ebx", "ecx", "edx", "esi", "edi", "ebp"]
        elif native and architecture == "AARCH64":
            registers = ["x%d" % index for index in range(8)]
        elif native and architecture.startswith("ARM"):
            registers = ["r%d" % index for index in range(7)]
        for index, role in enumerate(roles):
            location = "reg:" + registers[index] if index < len(registers) else "arg:%d" % index
            site.argument_layout.setdefault(role, location)
        site.metadata.setdefault("interface_kind", "syscall_instruction" if native else "library_interface")
        site.metadata.setdefault("argument_count", len(roles))
        site.metadata.setdefault("argument_roles", list(roles))
        site.metadata.setdefault("return_location", "return")
        initialization = bool(site.metadata.get("initialization")) or site.metadata.get("phase") in {"initialization", "startup"}
        if direction == "input" and initialization:
            site.metadata.pop("input_label", None)
            block = self.blocks.get(site.block_id)
            if block is not None:
                block.metadata["input_labels"] = [label for label in block.metadata.get("input_labels", []) if label != site.id]
            site.metadata["excluded_input"] = "initialization"
            return
        site.metadata["direction"] = direction
        site.metadata[direction + "_label"] = site.id
        block = self.blocks.get(site.block_id)
        if block is not None:
            labels = block.metadata.setdefault(direction + "_labels", [])
            if site.id not in labels:
                labels.append(site.id)

    def add_entry(self, entry: ExternalInputEntry) -> None:
        self.entries[entry.id] = entry

    def outgoing(self, node: str, kinds: Optional[Set[EdgeKind]] = None) -> List[ACGEdgeRecord]:
        edges = [self.edges[edge_id] for edge_id in self._out.get(node, [])]
        if kinds is not None:
            edges = [edge for edge in edges if edge.kind in kinds]
        return sorted(edges, key=lambda edge: (edge.kind.value, edge.target, edge.id))

    def incoming(self, node: str, kinds: Optional[Set[EdgeKind]] = None) -> List[ACGEdgeRecord]:
        edges = [self.edges[edge_id] for edge_id in self._in.get(node, [])]
        if kinds is not None:
            edges = [edge for edge in edges if edge.kind in kinds]
        return sorted(edges, key=lambda edge: (edge.kind.value, edge.source, edge.id))

    def function_at(self, module: str, rva: int) -> Optional[FunctionRecord]:
        exact = self._function_by_address.get((module, rva))
        if exact:
            return self.functions[exact]
        candidates = [
            function for function in self.functions.values()
            if function.module == module and function.rva <= rva < function.rva + max(function.size, 1)
        ]
        return min(candidates, key=lambda item: item.size or 2**63) if candidates else None

    def block_at(self, module: str, rva: int) -> Optional[BasicBlockRecord]:
        exact = self._block_by_address.get((module, rva))
        if exact:
            return self.blocks[exact]
        candidates = [
            block for block in self.blocks.values()
            if block.module == module and block.rva <= rva < block.rva + max(block.size, 1)
        ]
        return min(candidates, key=lambda item: item.size or 2**63) if candidates else None

    def syscall_candidates(self, syscall: str) -> List[SyscallSite]:
        ids = list(self._syscalls_by_name.get(syscall, []))
        ids.extend(self._syscalls_by_name.get("unknown", []))
        return [self.syscall_sites[site_id] for site_id in dict.fromkeys(ids)]

    def entry_candidates(self, profile_key: str, input_class: str = "") -> List[ExternalInputEntry]:
        values = [entry for entry in self.entries.values() if not profile_key or entry.profile_key == profile_key]
        if input_class:
            exact = [entry for entry in values if entry.input_class == input_class]
            if exact:
                values = exact
        return sorted(values, key=lambda item: (-item.stable_replays, item.rva, item.id))

    def reachable(
        self,
        source: str,
        target: str,
        kinds: Optional[Set[EdgeKind]] = None,
        forbidden: Optional[Set[str]] = None,
    ) -> bool:
        if source == target:
            return True
        forbidden = forbidden or set()
        queue = deque([source])
        seen = {source}
        while queue:
            node = queue.popleft()
            for edge in self.outgoing(node, kinds):
                if edge.target in forbidden or edge.target in seen:
                    continue
                if edge.target == target:
                    return True
                seen.add(edge.target)
                queue.append(edge.target)
        return False

    def shortest_path(
        self, source: str, target: str, kinds: Optional[Set[EdgeKind]] = None
    ) -> List[ACGEdgeRecord]:
        if source == target:
            return []
        queue = deque([source])
        previous: Dict[str, Tuple[str, str]] = {}
        seen = {source}
        while queue:
            node = queue.popleft()
            for edge in self.outgoing(node, kinds):
                if edge.target in seen:
                    continue
                previous[edge.target] = (node, edge.id)
                if edge.target == target:
                    path_ids: List[str] = []
                    cursor = target
                    while cursor != source:
                        parent, edge_id = previous[cursor]
                        path_ids.append(edge_id)
                        cursor = parent
                    return [self.edges[edge_id] for edge_id in reversed(path_ids)]
                seen.add(edge.target)
                queue.append(edge.target)
        return []

    def nodes_reaching(self, targets: Iterable[str]) -> Set[str]:
        queue = deque(targets)
        seen = set(targets)
        while queue:
            node = queue.popleft()
            for edge in self.incoming(node):
                if edge.source not in seen:
                    seen.add(edge.source)
                    queue.append(edge.source)
        return seen

    def validate(self) -> None:
        for block in self.blocks.values():
            if block.function_id not in self.functions:
                raise SchemaError("block %s references missing function %s" % (block.id, block.function_id))
        for site in self.syscall_sites.values():
            if site.function_id not in self.functions or site.block_id not in self.blocks:
                raise SchemaError("syscall site %s references a missing function or block" % site.id)
            if self.blocks[site.block_id].function_id != site.function_id:
                raise SchemaError("syscall site %s has inconsistent function and block identities" % site.id)
        for edge in self.edges.values():
            if edge.source not in self.blocks and edge.source not in self.functions:
                raise SchemaError("edge %s has a missing source" % edge.id)
            if edge.target not in self.blocks and edge.target not in self.functions:
                raise SchemaError("edge %s has a missing target" % edge.id)

    def statistics(self) -> Dict[str, Any]:
        by_kind: Dict[str, int] = defaultdict(int)
        for edge in self.edges.values():
            by_kind[edge.kind.value] += 1
        return {
            "build_id": self.build_id,
            "functions": len(self.functions),
            "blocks": len(self.blocks),
            "acg_edges": len(self.acg_edges()),
            "cfg_edges": len(self.cfg_edges()),
            "edges_by_kind": dict(sorted(by_kind.items())),
            "syscall_sites": len(self.syscall_sites),
            "external_input_entries": len(self.entries),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "build_id": self.build_id,
            "binary": self.binary,
            "architecture": self.architecture,
            "functions": [primitive(item) for item in sorted(self.functions.values(), key=lambda x: (x.module, x.rva, x.id))],
            "blocks": [primitive(item) for item in sorted(self.blocks.values(), key=lambda x: (x.module, x.rva, x.id))],
            "acg_edges": [primitive(item) for item in self.acg_edges()],
            "cfg_edges": [primitive(item) for item in self.cfg_edges()],
            "syscall_sites": [primitive(item) for item in sorted(self.syscall_sites.values(), key=lambda x: (x.module, x.rva, x.id))],
            "entries": [primitive(item) for item in sorted(self.entries.values(), key=lambda x: x.id)],
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ACG":
        graph = cls(build_id=str(raw.get("build_id", "")), binary=str(raw.get("binary", "")), architecture=str(raw.get("architecture", "")))
        for item in raw.get("functions", []):
            graph.add_function(FunctionRecord.from_dict(item))
        for item in raw.get("blocks", []):
            graph.add_block(BasicBlockRecord.from_dict(item))
        relations = list(raw.get("acg_edges", [])) + list(raw.get("cfg_edges", []))
        if not relations:
            relations = list(raw.get("edges", []))
        for item in relations:
            graph.add_edge(ACGEdgeRecord.from_dict(item))
        for item in raw.get("syscall_sites", []):
            graph.add_syscall_site(SyscallSite.from_dict(item))
        for item in raw.get("entries", []):
            graph.add_entry(ExternalInputEntry.from_dict(item))
        graph.metadata = dict(raw.get("metadata", {}))
        graph.validate()
        return graph

    @classmethod
    def load(cls, path: Path) -> "ACG":
        raw = load_json(path)
        if not isinstance(raw, Mapping):
            raise SchemaError("ACG root must be an object")
        return cls.from_dict(raw)

    def save(self, path: Path) -> None:
        self.validate()
        dump_json(path, self.to_dict())


ACFG = ACG
