from __future__ import annotations

from pathlib import Path
import threading
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ..config import CompassConfig
from ..schema import AuditEvent
from ..util import iter_jsonl, write_jsonl
from .handles import VersionedHandleMap
from .sysdig import SysdigBackend, SysdigNormalizer
from .ebpf import SupplementaryEBPF


class RuntimeCollector:
    """Normalizes runtime observations and maintains descriptor lifetimes."""

    def __init__(self, config: CompassConfig) -> None:
        self.config = config

    def normalize(
        self,
        sysdig_log: Path,
        output: Path,
        supplementary_log: Optional[Path] = None,
    ) -> List[AuditEvent]:
        events = SysdigNormalizer(buffer_encoding="base64").normalize_file(sysdig_log)
        supplemental = list(iter_jsonl(supplementary_log)) if supplementary_log else []
        self._merge_supplementary(events, supplemental)
        self._annotate_modules(events, supplemental)
        handles = VersionedHandleMap()
        ordered = sorted(events, key=lambda item: (item.timestamp_ns, item.sequence, item.id))
        for event in ordered:
            handles.resolve_event(event)
        write_jsonl(output, [event.to_dict() for event in ordered])
        return ordered

    def capture_sysdig(self, raw_output: Path, duration_seconds: float = 0.0, pid: Optional[int] = None) -> Path:
        return SysdigBackend(self.config.monitor).capture(raw_output, duration_seconds, pid)

    def capture(
        self,
        raw_sysdig: Path,
        raw_supplementary: Path,
        output: Path,
        duration_seconds: float,
        pid: Optional[int] = None,
    ) -> List[AuditEvent]:
        errors: List[BaseException] = []

        def supplementary() -> None:
            try:
                SupplementaryEBPF(self.config.monitor.capture_bytes).capture(raw_supplementary, duration_seconds, pid)
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=supplementary, name="compass-ebpf", daemon=True)
        thread.start()
        try:
            self.capture_sysdig(raw_sysdig, duration_seconds, pid)
        finally:
            thread.join(timeout=max(duration_seconds + 10.0, 10.0))
        if errors:
            raise errors[0]
        return self.normalize(raw_sysdig, output, raw_supplementary)

    @staticmethod
    def load(path: Path) -> List[AuditEvent]:
        return [AuditEvent.from_dict(item) for item in iter_jsonl(path)]

    @staticmethod
    def _merge_supplementary(events: Sequence[AuditEvent], records: Sequence[Mapping[str, Any]]) -> None:
        by_thread: Dict[Tuple[int, int], List[Mapping[str, Any]]] = {}
        for record in records:
            by_thread.setdefault((int(record.get("pid", 0)), int(record.get("tid", 0))), []).append(record)
        for values in by_thread.values():
            values.sort(key=lambda item: int(item.get("timestamp_ns", 0)))
        tolerance_ns = 5_000_000
        used: set = set()
        for event in events:
            candidates = by_thread.get((event.pid, event.tid), [])
            compatible = [
                item for item in candidates
                if id(item) not in used
                and abs(int(item.get("timestamp_ns", 0)) - event.timestamp_ns) <= tolerance_ns
                and str(item.get("syscall", "")) == event.syscall
                and (item.get("result") is None or str(item.get("result")) == str(event.result))
            ]
            if not compatible:
                continue
            selected = min(compatible, key=lambda item: abs(int(item.get("timestamp_ns", 0)) - event.timestamp_ns))
            used.add(id(selected))
            if selected.get("user_stack"):
                event.user_stack = [int(item) for item in selected.get("user_stack", [])]
                event.callsite = event.user_stack[0] if event.user_stack else None
            if selected.get("data") and not event.data:
                from ..util import decode_bytes
                event.data = decode_bytes(selected.get("data"))
            if selected.get("fault"):
                event.fault = dict(selected.get("fault", {}))

    @staticmethod
    def _annotate_modules(events: Sequence[AuditEvent], records: Sequence[Mapping[str, Any]]) -> None:
        mappings = [item for item in records if item.get("kind") == "module_mapping"]
        for event in events:
            stack_modules = []
            for address in event.user_stack:
                mapping = next(
                    (
                        item for item in mappings
                        if int(item.get("pid", event.pid)) == event.pid
                        and int(item.get("runtime_start", 0)) <= address < int(item.get("runtime_end", 0))
                    ),
                    None,
                )
                if mapping is None:
                    continue
                stack_modules.append({
                    "address": address,
                    "module": str(mapping.get("module", "")),
                    "module_base": int(mapping.get("runtime_start", 0)) - int(mapping.get("file_offset", 0)),
                })
            if stack_modules:
                event.metadata["stack_modules"] = stack_modules
                event.metadata["module"] = stack_modules[0]["module"]
                event.metadata["module_base"] = stack_modules[0]["module_base"]
