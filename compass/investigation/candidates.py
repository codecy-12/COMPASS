from __future__ import annotations

from typing import List, Optional

from ..acg import ACG
from ..config import InvestigationConfig
from ..schema import AuditEvent, CandidateInput, EdgeKind, EventDirection, ExecutionModel, SyscallSite
from ..util import parse_int
from .binding import AuditBindingIndex
from .provenance import ProvenanceGraph


INPUT_CALLS = {
    "read", "readv", "pread64", "preadv", "preadv2", "recv", "recvfrom",
    "recvmsg", "recvmmsg", "getrandom", "getdents", "getdents64",
}


class CandidatePredecessorAcquirer:
    def __init__(self, config: InvestigationConfig) -> None:
        self.config = config
        self.incomplete_reasons: List[str] = []

    def acquire(
        self,
        current: AuditEvent,
        model: Optional[ExecutionModel],
        graph: ProvenanceGraph,
        acg: ACG,
        bindings: AuditBindingIndex,
    ) -> List[CandidateInput]:
        self.incomplete_reasons = []
        outputs = [
            acg.syscall_sites[binding.site_id]
            for binding in bindings.bindings_for(current.id)
            if binding.site_id in acg.syscall_sites
        ]
        targets = {site.block_id for site in outputs}
        if current.direction == EventDirection.FAULT and not targets:
            targets.update(bindings.functions(current.id))
        if not targets:
            self.incomplete_reasons.append("unmatched-output-label")
        reached = acg.nodes_reaching(targets) if targets else set()
        labels = {
            site.id for site in acg.syscall_sites.values()
            if self._input_site(site)
            and (not targets or site.block_id in reached)
        }
        inputs = graph.prior_input_events(current.id, minimum_sequence=self._minimum_sequence(current, graph))
        candidates: List[CandidateInput] = []
        for event in inputs:
            if event.pid != current.pid or not self._valid_handle(event):
                continue
            possible = [
                binding for binding in bindings.bindings_for(event.id)
                if binding.site_id in acg.syscall_sites and self._input_site(acg.syscall_sites[binding.site_id])
            ]
            matching = [
                binding for binding in possible
                if binding.site_id in labels
                and self._compatible_context(event, current, acg.syscall_sites[binding.site_id], outputs, acg)
            ]
            if not matching:
                matching = [binding for binding in possible if self._coverage_uncertain(acg.syscall_sites[binding.site_id], acg)]
                if matching:
                    candidates.append(self._candidate(event, current, matching, outputs, incomplete=True))
            else:
                candidates.append(self._candidate(event, current, matching, outputs))
        if not candidates and (not targets or not labels):
            self.incomplete_reasons.append("missing-input-label-path")
            for event in inputs:
                if event.pid == current.pid and self._valid_handle(event):
                    candidates.append(self._candidate(event, current, [], outputs, incomplete=True))
        return sorted(
            candidates,
            key=lambda candidate: (-int(candidate.metadata["parameter_score"]), candidate.first_event.sequence, candidate.id),
        )

    def _candidate(self, event, current, matching, outputs, incomplete=False):
        related = event.metadata.get("related_event_ids", [])
        return CandidateInput(
            id="candidate:%s:%s" % (event.id, current.id),
            model=ExecutionModel.UNKNOWN,
            events=[event],
            current_event_id=current.id,
            producer_tid=event.tid,
            consumer_tid=current.tid,
            carrier=event.handle.object_id if event.handle else "",
            data=event.data[:event.successful_bytes],
            metadata={
                "input_site_ids": [binding.site_id for binding in matching],
                "output_site_ids": [site.id for site in outputs],
                "context_event_ids": list(related) if isinstance(related, (list, tuple)) else [],
                "parameter_score": self._score(event, current) + max((binding.score for binding in matching), default=0),
                "handle_generation": event.handle.generation if event.handle else None,
                "incomplete": bool(incomplete),
                "incomplete_reason": "incomplete-acfg-path" if matching else "unmatched-input-label",
            },
        )

    @staticmethod
    def _input_site(site: SyscallSite) -> bool:
        if site.metadata.get("initialization") or site.metadata.get("initialization_only") or site.metadata.get("excluded_input"):
            return False
        return bool(
            site.metadata.get("input_label")
            or site.metadata.get("direction") == "input"
            or site.syscall in INPUT_CALLS
            or site.syscall == "unknown"
        )

    @staticmethod
    def _coverage_uncertain(site: SyscallSite, acg: ACG) -> bool:
        cuts = list(acg.metadata.get("unresolved_indirect_sites", []))
        cuts.extend(acg.metadata.get("rejected_cross_context_candidates", []))
        for item in cuts:
            if not isinstance(item, dict):
                return True
            module = str(item.get("source_module", item.get("module", "")))
            rva = parse_int(item.get("source_rva", item.get("rva")), None)
            if not module or rva is None:
                return True
            block = acg.block_at(module, rva)
            if block is None or acg.reachable(site.block_id, block.id):
                return True
        return False

    @staticmethod
    def _valid_handle(event: AuditEvent) -> bool:
        if event.handle is None:
            return True
        if event.handle.pid != event.pid:
            return False
        fd = parse_int(event.args.get("fd", event.args.get("sockfd")), None)
        return fd is None or fd == event.handle.fd

    @staticmethod
    def _compatible_context(event, current, site, outputs, acg):
        tids = site.metadata.get("thread_ids", [])
        if tids and event.tid not in {int(value) for value in tids}:
            return False
        if event.tid == current.tid or not outputs:
            return True
        for output in outputs:
            forward = acg.nodes_reaching({output.block_id})
            if any(
                edge.kind == EdgeKind.CROSS_CONTEXT
                and edge.target in forward
                and acg.reachable(site.block_id, edge.source)
                for edge in acg.acg_edges()
            ):
                return True
        return False

    @staticmethod
    def _score(event: AuditEvent, current: AuditEvent) -> int:
        score = 0
        for name, value in event.args.items():
            if name in {"buf", "buffer", "fd", "sockfd", "count", "len", "length"}:
                continue
            if name in current.args and value == current.args[name]:
                score += 2
        for value in current.args.values():
            if isinstance(value, str) and len(value) > 1 and value.encode("utf-8") in event.data:
                score += 4
        if current.data and current.data in event.data:
            score += 4
        return score

    def _minimum_sequence(self, current: AuditEvent, graph: ProvenanceGraph) -> int:
        if self.config.input_window_seconds <= 0:
            return 0
        cutoff = current.timestamp_ns - int(self.config.input_window_seconds * 1_000_000_000)
        sequences = [event.sequence for event in graph.events.values() if event.timestamp_ns >= cutoff]
        return min(sequences) if sequences else 0
