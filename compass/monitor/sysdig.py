from __future__ import annotations

import signal
import subprocess
import base64
import binascii
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

from ..config import MonitorConfig
from ..errors import CaptureError
from ..schema import AuditEvent, EventDirection
from ..util import decode_bytes, executable, iter_jsonl, parse_int


INPUT_SYSCALLS = {"read", "readv", "pread64", "recv", "recvfrom", "recvmsg", "recvmmsg"}
OUTPUT_SYSCALLS = {"write", "writev", "pwrite64", "send", "sendto", "sendmsg", "sendmmsg", "open", "openat", "openat2", "execve", "execveat"}
FAULT_EVENTS = {"segfault", "page_fault", "signal", "signal_deliver", "procexit"}
LIFECYCLE = {"socket", "socketpair", "accept", "accept4", "close", "dup", "dup2", "dup3", "pipe", "pipe2", "clone", "clone3", "fork", "vfork", "execve", "mmap", "munmap"}


class SysdigBackend:
    def __init__(self, config: MonitorConfig) -> None:
        self.config = config

    def capture(self, output: Path, duration_seconds: float = 0.0, pid: Optional[int] = None) -> Path:
        sysdig = executable(self.config.sysdig_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        filter_expression = "evt.type in (%s)" % ",".join(self.config.syscalls)
        if pid is not None:
            filter_expression += " and proc.pid=%d" % pid
        argv = [sysdig]
        if self.config.use_modern_ebpf:
            argv.append("--modern-bpf")
        fields = [
            "evt.num", "evt.rawtime", "proc.pid", "thread.tid", "proc.name", "proc.ppid",
            "evt.type", "evt.dir", "evt.rawres", "evt.buffer", "fd.name", "fd.ino",
            "fd.cip", "fd.cport", "fd.sip", "fd.sport",
        ]
        arguments = ["fd", "sockfd", "dirfd", "name", "path", "pathname", "filename", "flags", "mode",
                     "size", "count", "len", "buf", "data", "iov", "iovcnt", "msg", "vlen", "offset",
                     "oldfd", "newfd", "cmd", "arg", "args", "argv", "env", "addr", "length", "prot"]
        fields.extend("evt.arg." + name for name in arguments)
        fields.extend("evt.rawarg." + name for name in arguments)
        argv.extend(["-j", "-b", "-p", "*" + " ".join("%" + name for name in fields), "-s", str(self.config.snaplen), filter_expression])
        with output.open("wb") as stream:
            process = subprocess.Popen(argv, stdout=stream, stderr=subprocess.PIPE)
            try:
                if duration_seconds > 0:
                    process.wait(timeout=duration_seconds)
                else:
                    process.wait()
            except subprocess.TimeoutExpired:
                process.send_signal(signal.SIGINT)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.terminate()
                    process.wait(timeout=5)
            stderr = (process.stderr.read() if process.stderr else b"").decode("utf-8", errors="replace")
        if process.returncode not in {0, -signal.SIGINT, 130}:
            raise CaptureError("Sysdig capture failed: %s" % stderr)
        return output


class SysdigNormalizer:
    def __init__(self, buffer_encoding: str = "utf8") -> None:
        if buffer_encoding not in {"utf8", "base64"}:
            raise ValueError("unsupported Sysdig buffer encoding")
        self.buffer_encoding = buffer_encoding

    def normalize_file(self, path: Path) -> List[AuditEvent]:
        events: List[AuditEvent] = []
        pending: Dict[tuple, AuditEvent] = {}
        for sequence, raw in enumerate(iter_jsonl(path), 1):
            event = self.normalize(raw, sequence)
            if event is not None:
                direction = event.metadata.get("event_direction")
                key = (event.pid, event.tid, event.syscall)
                if direction == ">":
                    pending[key] = event
                    continue
                if direction == "<":
                    entry = pending.pop(key, None)
                    if entry is not None:
                        event.args = {**entry.args, **event.args}
                        if not event.data:
                            event.data = entry.data
                events.append(event)
        return events

    def normalize(self, raw: Mapping[str, Any], sequence: int) -> Optional[AuditEvent]:
        fields = dict(raw.get("output_fields", raw.get("fields", raw)))
        syscall = str(self._value(fields, "evt.type", "type", "syscall", default=""))
        if not syscall:
            return None
        event_number = self._value(fields, "evt.num", "event_num", default=sequence)
        timestamp = self._timestamp_ns(self._value(fields, "evt.rawtime", "evt.time.s", "timestamp_ns", "timestamp", default=0))
        pid = int(parse_int(self._value(fields, "proc.pid", "pid", default=0), 0) or 0)
        tid = int(parse_int(self._value(fields, "thread.tid", "tid", default=pid), pid) or pid)
        process = str(self._value(fields, "proc.name", "process", "comm", default=""))
        args = self._arguments(fields)
        result = self._value(fields, "evt.rawres", "evt.res", "result", "res", default=None)
        if isinstance(result, str) and result in {"<NA>", "N/A", "null"}:
            result = None
        payload_error = False
        if self.buffer_encoding == "base64" and isinstance(fields.get("evt.buffer"), str) and fields["evt.buffer"] not in {"", "<NA>", "N/A", "null"}:
            try:
                data = base64.b64decode(fields["evt.buffer"], validate=True)
            except (ValueError, binascii.Error):
                data = b""
                payload_error = True
        elif isinstance(fields.get("evt.buffer"), Mapping):
            data = decode_bytes(fields["evt.buffer"])
        elif self.buffer_encoding == "utf8" and fields.get("evt.buffer") is not None and str(fields["evt.buffer"]) not in {"<NA>", "N/A", "null"}:
            data = decode_bytes(fields["evt.buffer"])
        else:
            data = decode_bytes(self._value(fields, "data", "buffer", "evt.arg.data", default=b""))
        direction = self._direction(syscall, fields)
        metadata = {
            "source": "sysdig",
            "event_direction": self._value(fields, "evt.dir", "direction", default=""),
            "parent_pid": parse_int(self._value(fields, "proc.ppid", "ppid", default=None), None),
        }
        if payload_error:
            metadata["payload_decoding_error"] = True
        if syscall in {"clone", "clone3", "fork", "vfork"}:
            child = parse_int(result, None)
            if child and child > 0:
                metadata["child_pid"] = child
        return AuditEvent(
            id="evt:%s" % event_number,
            timestamp_ns=timestamp,
            sequence=int(parse_int(event_number, sequence) or sequence),
            pid=pid,
            tid=tid,
            process=process,
            syscall=syscall,
            direction=direction,
            args=args,
            result=result,
            data=data,
            fault=dict(args) if direction == EventDirection.FAULT else {},
            metadata=metadata,
        )

    @staticmethod
    def _value(fields: Mapping[str, Any], *names: str, default: Any = None) -> Any:
        for name in names:
            if name in fields:
                return fields[name]
        return default

    @staticmethod
    def _timestamp_ns(value: Any) -> int:
        if isinstance(value, int):
            return value
        text = str(value)
        try:
            numeric = float(text)
        except ValueError:
            return 0
        return int(numeric if numeric > 1e15 else numeric * 1_000_000_000)

    @staticmethod
    def _arguments(fields: Mapping[str, Any]) -> Dict[str, Any]:
        args: Dict[str, Any] = {}
        for key, value in fields.items():
            if value is None or isinstance(value, str) and value in {"<NA>", "N/A", "null"}:
                continue
            if key.startswith("evt.arg."):
                args[key[len("evt.arg."):]] = value
            elif key.startswith("evt.rawarg."):
                name = key[len("evt.rawarg."):]
                if parse_int(value, None) is not None:
                    args[name] = value
                else:
                    args.setdefault(name, value)
        nested = fields.get("args")
        if isinstance(nested, Mapping):
            args.update(nested)
        field_aliases = {
            "fd.name": "fd_name",
            "fd.ino": "inode",
            "fd.cip": "client_ip",
            "fd.cport": "client_port",
            "fd.sip": "server_ip",
            "fd.sport": "server_port",
            "fd.sockcookie": "socket_cookie",
        }
        for source, destination in field_aliases.items():
            if source in fields and destination not in args:
                args[destination] = fields[source]
        aliases = {
            "fd": ("fd", "sockfd"),
            "path": ("name", "path", "pathname"),
        }
        for destination, candidates in aliases.items():
            if destination not in args:
                for candidate in candidates:
                    if candidate in args:
                        args[destination] = args[candidate]
                        break
        return args

    @staticmethod
    def _direction(syscall: str, fields: Mapping[str, Any]) -> EventDirection:
        if syscall in INPUT_SYSCALLS:
            return EventDirection.INPUT
        if syscall in OUTPUT_SYSCALLS:
            return EventDirection.OUTPUT
        if syscall in FAULT_EVENTS:
            return EventDirection.FAULT
        if syscall in LIFECYCLE:
            return EventDirection.LIFECYCLE
        return EventDirection.CONTROL
