from __future__ import annotations

import ctypes as ct
import base64
import json
import time
import platform
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..errors import BackendUnavailable


_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#define COMPASS_BYTES __CAPTURE_BYTES__
struct enter_t {
    u64 buffer;
    u64 requested;
};
struct event_t {
    u64 timestamp_ns;
    u32 pid;
    u32 tid;
    u32 syscall_nr;
    s64 result;
    u64 user_stack_id;
    u32 data_length;
    unsigned char data[COMPASS_BYTES];
};
BPF_PERF_OUTPUT(events);
BPF_STACK_TRACE(stack_traces, 16384);
BPF_HASH(inflight, u64, struct enter_t);
BPF_PERCPU_ARRAY(scratch, struct event_t, 1);
TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    u64 id = bpf_get_current_pid_tgid();
    __PID_FILTER__
    struct enter_t enter = {};
    switch (args->id) {
        case 0:   /* read */
        case 1:   /* write */
        case 17:  /* pread64 */
        case 18:  /* pwrite64 */
        case 44:  /* sendto */
        case 45:  /* recvfrom */
            enter.buffer = args->args[1];
            enter.requested = args->args[2];
            inflight.update(&id, &enter);
            break;
        default:
            break;
    }
    return 0;
}
TRACEPOINT_PROBE(raw_syscalls, sys_exit) {
    u32 slot = 0;
    struct event_t *event = scratch.lookup(&slot);
    if (!event) return 0;
    u64 id = bpf_get_current_pid_tgid();
    __PID_FILTER__
    event->timestamp_ns = bpf_ktime_get_ns();
    event->pid = id >> 32;
    event->tid = (u32)id;
    event->syscall_nr = args->id;
    event->result = args->ret;
    event->user_stack_id = bpf_get_stackid(args, BPF_F_USER_STACK);
    event->data_length = 0;
    struct enter_t *enter = inflight.lookup(&id);
    if (enter && args->ret > 0) {
        u64 amount = args->ret;
        if (amount > enter->requested) amount = enter->requested;
        if (amount > COMPASS_BYTES) amount = COMPASS_BYTES;
        if (bpf_probe_read_user(&event->data, amount, (void *)enter->buffer) == 0)
            event->data_length = amount;
    }
    events.perf_submit(args, event, __builtin_offsetof(struct event_t, data) + event->data_length);
    inflight.delete(&id);
    return 0;
}
"""


class _Event(ct.Structure):
    _fields_ = [
        ("timestamp_ns", ct.c_ulonglong),
        ("pid", ct.c_uint),
        ("tid", ct.c_uint),
        ("syscall_nr", ct.c_uint),
        ("result", ct.c_longlong),
        ("user_stack_id", ct.c_ulonglong),
        ("data_length", ct.c_uint),
        ("data", ct.c_ubyte * 256),
    ]


class SupplementaryEBPF:
    """Captures user call context for correlation with Sysdig records."""

    def __init__(self, capture_bytes: int = 60000) -> None:
        self.capture_bytes = min(max(int(capture_bytes), 1), 60000)

    def capture(self, output: Path, duration_seconds: float = 0.0, pid: Optional[int] = None) -> Path:
        if platform.system() != "Linux" or platform.machine().lower() not in {"x86_64", "amd64"}:
            raise BackendUnavailable("supplementary syscall probes currently require Linux x86-64")
        try:
            from bcc import BPF  # type: ignore
        except ImportError as exc:
            raise BackendUnavailable("BCC is required for supplementary eBPF capture") from exc
        filter_code = "if ((id >> 32) != %d) return 0;" % pid if pid is not None else ""
        bpf = BPF(text=_PROGRAM.replace("__PID_FILTER__", filter_code).replace("__CAPTURE_BYTES__", str(self.capture_bytes)))
        class CaptureEvent(ct.Structure):
            _fields_ = _Event._fields_[:-1] + [("data", ct.c_ubyte * self.capture_bytes)]
        epoch_offset_ns = time.time_ns() - time.monotonic_ns()
        output.parent.mkdir(parents=True, exist_ok=True)

        with output.open("w", encoding="utf-8", buffering=1) as stream:
            for record in self._module_mappings(pid) if pid is not None else []:
                stream.write(json.dumps(record, sort_keys=True) + "\n")

            def callback(cpu: int, data: int, size: int) -> None:
                event = ct.cast(data, ct.POINTER(CaptureEvent)).contents
                if pid is not None and int(event.pid) != pid:
                    return
                stack: List[int] = []
                try:
                    stack = [int(address) for address in bpf.get_table("stack_traces").walk(event.user_stack_id)]
                except Exception:
                    pass
                record = {
                    "kind": "syscall_context",
                    "timestamp_ns": int(event.timestamp_ns) + epoch_offset_ns,
                    "pid": int(event.pid),
                    "tid": int(event.tid),
                    "syscall_number": int(event.syscall_nr),
                    "syscall": self._syscall_name(int(event.syscall_nr)),
                    "result": int(event.result),
                    "user_stack": stack,
                    "data": {
                        "encoding": "base64",
                        "data": base64.b64encode(bytes(event.data[: event.data_length])).decode("ascii"),
                    } if event.data_length else None,
                    "source": "supplementary-ebpf",
                }
                stream.write(json.dumps(record, sort_keys=True) + "\n")

            bpf["events"].open_perf_buffer(callback, page_cnt=64)
            start = time.monotonic()
            try:
                while duration_seconds <= 0 or time.monotonic() - start < duration_seconds:
                    bpf.perf_buffer_poll(timeout=100)
            except KeyboardInterrupt:
                pass
        return output

    @staticmethod
    def _syscall_name(number: int) -> str:
        names = {
            2: "open", 3: "close", 9: "mmap", 10: "mprotect", 11: "munmap",
            22: "pipe", 32: "dup", 33: "dup2",
            0: "read", 1: "write", 17: "pread64", 18: "pwrite64",
            19: "readv", 20: "writev", 41: "socket", 42: "connect",
            43: "accept", 44: "sendto", 45: "recvfrom", 46: "sendmsg",
            47: "recvmsg", 53: "socketpair", 56: "clone", 57: "fork",
            58: "vfork", 59: "execve", 72: "fcntl", 202: "futex",
            257: "openat", 288: "accept4", 292: "dup3", 293: "pipe2",
            295: "preadv", 296: "pwritev", 299: "recvmmsg", 307: "sendmmsg", 322: "execveat",
            327: "preadv2", 328: "pwritev2", 435: "clone3", 437: "openat2",
        }
        return names.get(number, "")

    @staticmethod
    def _module_mappings(pid: int) -> List[Dict[str, Any]]:
        values: List[Dict[str, Any]] = []
        try:
            lines = Path("/proc/%d/maps" % pid).read_text(encoding="utf-8").splitlines()
        except OSError:
            return values
        for line in lines:
            fields = line.split(None, 5)
            if len(fields) < 5:
                continue
            bounds, permissions, offset, _device, _inode = fields[:5]
            path = fields[5] if len(fields) > 5 else ""
            if "x" not in permissions or not path.startswith("/"):
                continue
            start_text, end_text = bounds.split("-", 1)
            values.append({
                "kind": "module_mapping",
                "pid": pid,
                "module": Path(path).name,
                "path": path,
                "runtime_start": int(start_text, 16),
                "runtime_end": int(end_text, 16),
                "file_offset": int(offset, 16),
                "source": "proc-maps",
            })
        return values
