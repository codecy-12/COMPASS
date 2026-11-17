from __future__ import annotations

import ctypes as ct
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..errors import BackendUnavailable, CaptureError


_UPROBE_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
struct transfer_t {
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u64 instruction;
    u64 arg0;
    u64 arg1;
    u64 arg2;
    u64 arg3;
    u64 arg4;
    u64 arg5;
};
BPF_PERF_OUTPUT(transfers);
int trace_transfer(struct pt_regs *ctx) {
    struct transfer_t event = {};
    u64 id = bpf_get_current_pid_tgid();
    event.timestamp_ns = bpf_ktime_get_ns();
    event.pid = id >> 32;
    event.tid = (u32)id;
    event.instruction = PT_REGS_IP(ctx);
    event.arg0 = PT_REGS_PARM1(ctx);
    event.arg1 = PT_REGS_PARM2(ctx);
    event.arg2 = PT_REGS_PARM3(ctx);
    event.arg3 = PT_REGS_PARM4(ctx);
    event.arg4 = PT_REGS_PARM5(ctx);
    event.arg5 = PT_REGS_PARM6(ctx);
    transfers.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""


class _TransferEvent(ct.Structure):
    _fields_ = [
        ("timestamp_ns", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("tid", ct.c_uint),
        ("instruction", ct.c_ulonglong),
        ("arg0", ct.c_ulonglong),
        ("arg1", ct.c_ulonglong),
        ("arg2", ct.c_ulonglong),
        ("arg3", ct.c_ulonglong),
        ("arg4", ct.c_ulonglong),
        ("arg5", ct.c_ulonglong),
    ]


@dataclass
class HandoffProbe:
    rva: int
    role: str
    carrier_argument: int = 0
    value_argument: int = 1
    function_id: str = ""
    transfer_fields: List[Dict[str, Any]] = field(default_factory=list)
    input_class: str = ""
    parameter_layout: Dict[str, str] = field(default_factory=dict)
    input_site_id: str = ""
    prefix_snapshot: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "HandoffProbe":
        return cls(
            rva=int(str(raw.get("rva", "0")), 0),
            role=str(raw.get("role", "")),
            carrier_argument=int(raw.get("carrier_argument", 0)),
            value_argument=int(raw.get("value_argument", 1)),
            function_id=str(raw.get("function_id", "")),
            transfer_fields=[dict(item) for item in raw.get("transfer_fields", [])],
            input_class=str(raw.get("input_class", "")),
            parameter_layout={str(key): str(value) for key, value in dict(raw.get("parameter_layout", {})).items()},
            input_site_id=str(raw.get("input_site_id", "")),
            prefix_snapshot=str(raw.get("prefix_snapshot", "")),
            metadata=dict(raw.get("metadata", {})),
        )


class PreparationHandoffRecorder:
    """Captures queue/shared-object handoffs at statically recovered function sites."""

    def capture(
        self,
        binary: Path,
        probes: Sequence[HandoffProbe],
        output: Path,
        replay_id: str,
        profile_key: str,
        module_base: int,
        duration_seconds: float = 0.0,
        pid: Optional[int] = None,
        stop_event: Optional[Any] = None,
        ready_event: Optional[Any] = None,
    ) -> Path:
        try:
            from bcc import BPF  # type: ignore
        except ImportError as exc:
            raise BackendUnavailable("BCC is required for preparation handoff capture") from exc
        if not probes:
            raise CaptureError("at least one producer or consumer probe is required")
        bpf = BPF(text=_UPROBE_PROGRAM)
        try:
            return self._capture(bpf, binary, probes, output, replay_id, profile_key, module_base,
                                 duration_seconds, pid, stop_event, ready_event)
        finally:
            bpf.cleanup()

    def _capture(self, bpf: Any, binary: Path, probes: Sequence[HandoffProbe], output: Path,
                 replay_id: str, profile_key: str, module_base: int, duration_seconds: float,
                 pid: Optional[int], stop_event: Optional[Any], ready_event: Optional[Any]) -> Path:
        from elftools.elf.elffile import ELFFile
        with binary.open("rb") as stream:
            image_base = min(int(segment["p_vaddr"]) - int(segment["p_offset"])
                             for segment in ELFFile(stream).iter_segments() if segment["p_type"] == "PT_LOAD")
        by_rva: Dict[int, List[HandoffProbe]] = {}
        for probe in probes:
            if probe.role not in {"entry", "producer", "consumer", "function"} or not 0 <= probe.carrier_argument < 6 or not 0 <= probe.value_argument < 6:
                raise CaptureError("handoff probes require a valid role and argument index in 0..5")
            by_rva.setdefault(probe.rva, []).append(probe)
        for rva in by_rva:
            bpf.attach_uprobe(name=str(binary), addr=image_base + rva, fn_name="trace_transfer", pid=pid or -1)
        sequence = 0
        lost_events = 0
        window_start_ns = time.monotonic_ns()
        window_end_ns = 0
        output.parent.mkdir(parents=True, exist_ok=True)

        with output.open("w", encoding="utf-8", buffering=1) as stream:
            def callback(cpu: int, data: int, size: int) -> None:
                nonlocal sequence
                event = ct.cast(data, ct.POINTER(_TransferEvent)).contents
                if pid is not None and int(event.pid) != pid or int(event.timestamp_ns) < window_start_ns:
                    return
                if window_end_ns and int(event.timestamp_ns) > window_end_ns:
                    return
                arguments = [int(event.arg0), int(event.arg1), int(event.arg2), int(event.arg3), int(event.arg4), int(event.arg5)]
                observed_rva = int(event.instruction) - module_base
                matched = by_rva.get(observed_rva) or by_rva.get(observed_rva - 1)
                if not matched:
                    return
                for probe in matched:
                    sequence += 1
                    record = {
                    "kind": "function_entry" if probe.role == "function" else ("external_input" if probe.role == "entry" else "carrier_access"),
                    "access": "" if probe.role in {"entry", "function"} else ("producer_write" if probe.role == "producer" else "consumer_read"),
                    "replay_id": replay_id,
                    "profile_key": profile_key,
                    "sequence": sequence,
                    "timestamp_ns": int(event.timestamp_ns),
                    "pid": int(event.pid),
                    "tid": int(event.tid),
                    "user_address": module_base + probe.rva,
                    "carrier_id": "0x%x" % arguments[probe.carrier_argument],
                    "value_object": "0x%x" % arguments[probe.value_argument],
                    "function_id": probe.function_id,
                    "arguments": arguments,
                    "transfer_fields": probe.transfer_fields,
                    "metadata": probe.metadata,
                    "source": "preparation-ebpf-uprobe",
                    }
                    if probe.role == "consumer" and probe.prefix_snapshot:
                        record["consumer_snapshot"] = probe.prefix_snapshot
                    if probe.role in {"entry", "function"}:
                        record.update({
                        "entry_address": module_base + probe.rva,
                        "input_class": probe.input_class,
                        "input_site_id": probe.input_site_id,
                        "parameter_layout": probe.parameter_layout,
                        "prefix_snapshot": probe.prefix_snapshot,
                        })
                    stream.write(json.dumps(record, sort_keys=True) + "\n")
            def lost_callback(cpu: int, count: int) -> None:
                nonlocal lost_events
                lost_events += int(count)
            bpf["transfers"].open_perf_buffer(callback, lost_cb=lost_callback)
            if ready_event is not None:
                ready_event.set()
            start = time.monotonic()
            try:
                while duration_seconds <= 0 or time.monotonic() - start < duration_seconds:
                    if stop_event is not None and stop_event.is_set():
                        break
                    bpf.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                pass
            window_end_ns = time.monotonic_ns()
            bpf.perf_buffer_poll(timeout=0)
            bpf.perf_buffer_poll(timeout=0)
            function_sites = [{"module": binary.name, "rva": rva} for rva, selected in sorted(by_rva.items())
                              if any(probe.role == "function" for probe in selected)]
            if function_sites:
                stopped = False
                if pid is not None and stop_event is not None and stop_event.is_set():
                    try:
                        stopped = Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()[0] == "Z"
                    except OSError:
                        stopped = True
                stream.write(json.dumps({"kind": "function_trace_metadata", "replay_id": replay_id, "profile_key": profile_key,
                    "scope": "configured-function-projection", "function_sites": function_sites,
                    "capture_window_complete": bool(stopped and lost_events == 0), "whole_process_complete": False,
                    "lost_events": lost_events, "window_start_ns": window_start_ns, "window_end_ns": window_end_ns,
                    "timestamp_ns": window_end_ns, "sequence": sequence + 1, "source": "preparation-ebpf-uprobe"}, sort_keys=True) + "\n")
        return output
