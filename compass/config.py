from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, List, Mapping, Optional

from .errors import ConfigurationError


@dataclass
class LLMConfig:
    provider: str = "deepseek"
    base_url: str = "https://api.deepseek.com/chat/completions"
    model: str = "deepseek-v3.2"
    api_key: str = ""
    timeout_seconds: float = 60.0
    temperature: float = 0.0


@dataclass
class StaticConfig:
    backend: str = "auto"
    ida_path: str = ""
    objdump_path: str = "objdump"
    load_external_libraries: bool = False


@dataclass
class DynamicConfig:
    perf_path: str = "perf"
    use_lbr: bool = True
    lbr_sample_period: int = 4000
    use_ebpf: bool = True
    known_producer_patterns: List[str] = field(
        default_factory=lambda: ["push", "enqueue", "submit", "dispatch", "wake", "notify", "write"]
    )
    known_consumer_patterns: List[str] = field(
        default_factory=lambda: ["pop", "dequeue", "take", "consume", "wait", "read"]
    )


@dataclass
class MonitorConfig:
    sysdig_path: str = "sysdig"
    use_modern_ebpf: bool = True
    snaplen: int = 65535
    capture_user_stacks: bool = True
    capture_bytes: int = 60000
    syscalls: List[str] = field(
        default_factory=lambda: [
            "read", "readv", "pread64", "recvfrom", "recvmsg", "recvmmsg",
            "write", "writev", "pwrite64", "sendto", "sendmsg", "sendmmsg",
            "open", "openat", "openat2", "close", "dup", "dup2", "dup3", "fcntl",
            "socket", "socketpair", "accept", "accept4", "connect", "pipe", "pipe2",
            "mmap", "munmap", "mprotect", "execve", "clone", "clone3", "fork", "vfork",
            "execveat", "futex", "epoll_wait", "epoll_pwait", "poll", "ppoll", "select", "pselect6",
            "newfstatat", "fstat", "statx", "rename", "renameat", "unlink", "unlinkat",
            "signal", "signal_deliver", "procexit", "kill", "tgkill", "ptrace",
        ]
    )


@dataclass
class InvestigationConfig:
    symbolic_backend: str = "angr"
    input_window_seconds: float = 0.0
    concretize_captured_input: bool = True
    simprocedure_manifest: str = ""


@dataclass
class CompassConfig:
    workspace: str = ".compass"
    llm: LLMConfig = field(default_factory=LLMConfig)
    static: StaticConfig = field(default_factory=StaticConfig)
    dynamic: DynamicConfig = field(default_factory=DynamicConfig)
    monitor: MonitorConfig = field(default_factory=MonitorConfig)
    investigation: InvestigationConfig = field(default_factory=InvestigationConfig)

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "CompassConfig":
        return cls(
            workspace=str(raw.get("workspace", ".compass")),
            llm=LLMConfig(**dict(raw.get("llm", {}))),
            static=StaticConfig(**dict(raw.get("static", {}))),
            dynamic=DynamicConfig(**dict(raw.get("dynamic", {}))),
            monitor=MonitorConfig(**dict(raw.get("monitor", {}))),
            investigation=InvestigationConfig(**dict(raw.get("investigation", {}))),
        )

    def workspace_path(self, base: Optional[Path] = None) -> Path:
        path = Path(self.workspace).expanduser()
        if not path.is_absolute() and base is not None:
            path = base / path
        return path.resolve()


def load_config(path: Path) -> CompassConfig:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError("cannot load configuration %s: %s" % (path, exc)) from exc
    if not isinstance(raw, dict):
        raise ConfigurationError("configuration root must be a JSON object")
    try:
        return CompassConfig.from_mapping(raw)
    except TypeError as exc:
        raise ConfigurationError("invalid configuration field: %s" % exc) from exc
