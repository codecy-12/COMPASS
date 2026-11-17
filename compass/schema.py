from __future__ import annotations

import base64
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .util import decode_bytes, parse_int, primitive


class EdgeKind(str, Enum):
    CFG = "cfg"
    DIRECT_CALL = "direct_call"
    RETURN = "return"
    INDIRECT_CALL = "indirect_call"
    CROSS_CONTEXT = "cross_context_data_flow"


class EventDirection(str, Enum):
    INPUT = "input"
    OUTPUT = "output"
    LIFECYCLE = "lifecycle"
    CONTROL = "control"
    FAULT = "fault"
    META = "meta"


class ObjectKind(str, Enum):
    FILE = "file"
    SOCKET = "socket"
    PIPE = "pipe"
    IPC = "ipc"
    MEMORY = "memory"
    PROCESS = "process"
    THREAD = "thread"
    UNKNOWN = "unknown"


class ExecutionModel(str, Enum):
    SERIAL = "a"
    CONTEXT_ISOLATED = "b"
    DATA_COUPLED = "c"
    EVENT_INTERLEAVED = "d"
    UNKNOWN = "unknown"


class ResolutionStatus(str, Enum):
    RESOLVED = "resolved"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class ModuleMapping:
    module: str
    path: str
    runtime_start: int
    runtime_end: int
    file_offset: int = 0
    build_id: str = ""

    def contains(self, address: int) -> bool:
        return self.runtime_start <= address < self.runtime_end

    def to_rva(self, address: int) -> int:
        return address - self.runtime_start + self.file_offset

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ModuleMapping":
        return cls(
            module=str(raw.get("module", raw.get("path", ""))),
            path=str(raw.get("path", "")),
            runtime_start=int(parse_int(raw.get("runtime_start"), 0) or 0),
            runtime_end=int(parse_int(raw.get("runtime_end"), 0) or 0),
            file_offset=int(parse_int(raw.get("file_offset"), 0) or 0),
            build_id=str(raw.get("build_id", "")),
        )


@dataclass
class FunctionRecord:
    id: str
    name: str
    module: str
    rva: int
    size: int = 0
    is_external: bool = False
    signature: str = ""
    blocks: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "FunctionRecord":
        return cls(
            id=str(raw["id"]), name=str(raw.get("name", raw["id"])), module=str(raw.get("module", "main")),
            rva=int(parse_int(raw.get("rva"), 0) or 0), size=int(parse_int(raw.get("size"), 0) or 0),
            is_external=bool(raw.get("is_external", False)), signature=str(raw.get("signature", "")),
            blocks=[str(item) for item in raw.get("blocks", [])], metadata=dict(raw.get("metadata", {})),
        )


@dataclass
class BasicBlockRecord:
    id: str
    function_id: str
    module: str
    rva: int
    size: int
    instruction_count: int = 0
    terminal_kind: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "BasicBlockRecord":
        return cls(
            id=str(raw["id"]), function_id=str(raw.get("function_id", "")), module=str(raw.get("module", "main")),
            rva=int(parse_int(raw.get("rva"), 0) or 0), size=int(parse_int(raw.get("size"), 0) or 0),
            instruction_count=int(raw.get("instruction_count", 0)), terminal_kind=str(raw.get("terminal_kind", "")),
            metadata=dict(raw.get("metadata", {})),
        )


@dataclass
class TransferField:
    source: str
    destination: str
    width: int = 0
    encoding: str = "native"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "TransferField":
        return cls(
            source=str(raw.get("source", "")), destination=str(raw.get("destination", "")),
            width=int(raw.get("width", 0)), encoding=str(raw.get("encoding", "native")),
            metadata=dict(raw.get("metadata", {})),
        )


@dataclass
class ACGEdgeRecord:
    id: str
    source: str
    target: str
    kind: EdgeKind
    callsite_rva: Optional[int] = None
    source_function: str = ""
    target_function: str = ""
    carrier: str = ""
    transfer_fields: List[TransferField] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ACGEdgeRecord":
        kind_raw = raw.get("kind", EdgeKind.CFG.value)
        return cls(
            id=str(raw["id"]), source=str(raw["source"]), target=str(raw["target"]), kind=EdgeKind(kind_raw),
            callsite_rva=parse_int(raw.get("callsite_rva")), source_function=str(raw.get("source_function", "")),
            target_function=str(raw.get("target_function", "")), carrier=str(raw.get("carrier", "")),
            transfer_fields=[TransferField.from_dict(item) for item in raw.get("transfer_fields", [])],
            evidence=[str(item) for item in raw.get("evidence", [])], metadata=dict(raw.get("metadata", {})),
        )


@dataclass
class SyscallSite:
    id: str
    function_id: str
    block_id: str
    module: str
    rva: int
    syscall: str = "unknown"
    number: Optional[int] = None
    argument_layout: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "SyscallSite":
        return cls(
            id=str(raw["id"]), function_id=str(raw.get("function_id", "")), block_id=str(raw.get("block_id", "")),
            module=str(raw.get("module", "main")), rva=int(parse_int(raw.get("rva"), 0) or 0),
            syscall=str(raw.get("syscall", "unknown")), number=parse_int(raw.get("number")),
            argument_layout={str(k): str(v) for k, v in dict(raw.get("argument_layout", {})).items()},
            metadata=dict(raw.get("metadata", {})),
        )


@dataclass
class ExternalInputEntry:
    id: str
    build_id: str
    profile_key: str
    input_class: str
    function_id: str
    module: str
    rva: int
    input_site_id: str
    parameter_layout: Dict[str, str] = field(default_factory=dict)
    stable_replays: int = 0
    prefix_snapshot: str = ""
    evidence: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ExternalInputEntry":
        return cls(
            id=str(raw["id"]), build_id=str(raw.get("build_id", "")), profile_key=str(raw.get("profile_key", "")),
            input_class=str(raw.get("input_class", "")), function_id=str(raw.get("function_id", "")),
            module=str(raw.get("module", "main")), rva=int(parse_int(raw.get("rva"), 0) or 0),
            input_site_id=str(raw.get("input_site_id", "")),
            parameter_layout={str(k): str(v) for k, v in dict(raw.get("parameter_layout", {})).items()},
            stable_replays=int(raw.get("stable_replays", 0)), prefix_snapshot=str(raw.get("prefix_snapshot", "")),
            evidence=[str(item) for item in raw.get("evidence", [])],
        )


@dataclass(frozen=True)
class HandleIdentity:
    pid: int
    fd: int
    generation: int
    kind: ObjectKind
    object_id: str

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "HandleIdentity":
        return cls(
            pid=int(raw.get("pid", 0)), fd=int(raw.get("fd", -1)), generation=int(raw.get("generation", 0)),
            kind=ObjectKind(raw.get("kind", ObjectKind.UNKNOWN.value)), object_id=str(raw.get("object_id", "")),
        )


@dataclass
class AuditEvent:
    id: str
    timestamp_ns: int
    sequence: int
    pid: int
    tid: int
    process: str
    syscall: str
    direction: EventDirection
    args: Dict[str, Any] = field(default_factory=dict)
    result: Any = None
    data: bytes = b""
    handle: Optional[HandleIdentity] = None
    callsite: Optional[int] = None
    user_stack: List[int] = field(default_factory=list)
    fault: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def successful_bytes(self) -> int:
        result = parse_int(self.result, -1)
        if result is None or result <= 0:
            return 0
        return min(result, len(self.data)) if self.data else result

    def is_successful_input(self) -> bool:
        return (
            self.direction == EventDirection.INPUT
            and bool(self.data)
            and self.successful_bytes > 0
        )

    def handle_key(self) -> Tuple[int, int, int]:
        if self.handle:
            return self.handle.pid, self.handle.fd, self.handle.generation
        parsed = parse_int(self.args.get("fd"), -1)
        fd = parsed if parsed is not None else -1
        return self.pid, fd, -1

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "AuditEvent":
        handle_raw = raw.get("handle")
        return cls(
            id=str(raw["id"]), timestamp_ns=int(raw.get("timestamp_ns", 0)), sequence=int(raw.get("sequence", 0)),
            pid=int(raw.get("pid", 0)), tid=int(raw.get("tid", raw.get("pid", 0))), process=str(raw.get("process", "")),
            syscall=str(raw.get("syscall", "")), direction=EventDirection(raw.get("direction", EventDirection.META.value)),
            args=dict(raw.get("args", {})), result=raw.get("result"), data=decode_bytes(raw.get("data", b"")),
            handle=HandleIdentity.from_dict(handle_raw) if isinstance(handle_raw, Mapping) else None,
            callsite=parse_int(raw.get("callsite")), user_stack=[int(parse_int(item, 0) or 0) for item in raw.get("user_stack", [])],
            fault=dict(raw.get("fault", {})), metadata=dict(raw.get("metadata", {})),
        )

    def to_dict(self) -> Dict[str, Any]:
        value = primitive(self)
        value["data"] = {"encoding": "base64", "data": base64.b64encode(self.data).decode("ascii")}
        return value


@dataclass
class ProcessProfile:
    build_id: str
    executable: str
    role: str
    command_line: List[str] = field(default_factory=list)
    modules: List[str] = field(default_factory=list)
    concurrency_module: str = ""
    concurrency: Dict[str, Any] = field(default_factory=dict)
    platform: str = "linux"
    preparation_key: str = ""

    @property
    def key(self) -> str:
        if self.preparation_key:
            return self.preparation_key
        parts = [self.build_id, self.role, self.concurrency_module]
        settings = ",".join("%s=%s" % item for item in sorted(self.concurrency.items()))
        return "|".join(parts + [settings])

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ProcessProfile":
        return cls(
            build_id=str(raw.get("build_id", "")), executable=str(raw.get("executable", "")),
            role=str(raw.get("role", "")), command_line=[str(item) for item in raw.get("command_line", [])],
            modules=[str(item) for item in raw.get("modules", [])],
            concurrency_module=str(raw.get("concurrency_module", "")), concurrency=dict(raw.get("concurrency", {})),
            platform=str(raw.get("platform", "linux")),
            preparation_key=str(raw.get("profile_key") or raw.get("preparation_key") or ""),
        )


@dataclass
class CatalogEntry:
    profile_key: str
    model: ExecutionModel
    scheduling_summary: str
    task_boundaries: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    runtime_validation: str = "insufficient"
    evidence_status: str = "insufficient"

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "CatalogEntry":
        return cls(
            profile_key=str(raw.get("profile_key", "")), model=ExecutionModel(raw.get("model", "unknown")),
            scheduling_summary=str(raw.get("scheduling_summary", "")),
            task_boundaries=[dict(item) for item in raw.get("task_boundaries", [])],
            evidence=[dict(item) for item in raw.get("evidence", [])],
            runtime_validation=str(raw.get("runtime_validation", "insufficient")),
            evidence_status=str(raw.get("evidence_status", "insufficient")),
        )


@dataclass
class CandidateInput:
    id: str
    model: ExecutionModel
    events: List[AuditEvent]
    current_event_id: str
    producer_tid: Optional[int] = None
    consumer_tid: Optional[int] = None
    carrier: str = ""
    data: bytes = b""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def first_event(self) -> AuditEvent:
        return min(self.events, key=lambda event: (event.sequence, event.timestamp_ns))

    @property
    def last_event(self) -> AuditEvent:
        return max(self.events, key=lambda event: (event.sequence, event.timestamp_ns))


@dataclass
class BoundValue:
    name: str
    value: Any
    location: str
    width: int = 0
    apply_at_site: str = ""
    source_event: str = ""


@dataclass
class ArgumentBinding:
    event_id: str
    site_id: str
    function_id: str
    score: int
    values: List[BoundValue] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)


@dataclass
class MemoryRegion:
    start: int
    permissions: str
    data: bytes
    name: str = ""

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "MemoryRegion":
        return cls(
            start=int(parse_int(raw.get("start"), 0) or 0), permissions=str(raw.get("permissions", "")),
            data=decode_bytes(raw.get("data", b"")), name=str(raw.get("name", "")),
        )


@dataclass
class PrefixSnapshot:
    build_id: str
    profile_key: str
    entry_rva: int
    module_bases: Dict[str, int] = field(default_factory=dict)
    registers: Dict[str, int] = field(default_factory=dict)
    memory: List[MemoryRegion] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "PrefixSnapshot":
        return cls(
            build_id=str(raw.get("build_id", "")), profile_key=str(raw.get("profile_key", "")),
            entry_rva=int(parse_int(raw.get("entry_rva"), 0) or 0),
            module_bases={str(k): int(parse_int(v, 0) or 0) for k, v in dict(raw.get("module_bases", {})).items()},
            registers={str(k): int(parse_int(v, 0) or 0) for k, v in dict(raw.get("registers", {})).items()},
            memory=[MemoryRegion.from_dict(item) for item in raw.get("memory", [])], metadata=dict(raw.get("metadata", {})),
        )


@dataclass
class ProvenanceNode:
    id: str
    kind: str
    label: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProvenanceEdge:
    id: str
    source: str
    target: str
    event_id: str
    operation: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InvestigationResult:
    symptom_event: str
    status: ResolutionStatus
    verified_predecessors: List[str]
    attack_nodes: List[ProvenanceNode]
    attack_edges: List[ProvenanceEdge]
    unresolved_events: List[str] = field(default_factory=list)
    candidate_paths: Dict[str, List[str]] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "symptom_event": self.symptom_event,
            "status": self.status.value,
            "verified_predecessors": list(self.verified_predecessors),
            "attack_nodes": primitive(self.attack_nodes),
            "attack_edges": primitive(self.attack_edges),
            "candidate_paths": primitive(self.candidate_paths),
            "metadata": primitive(self.metadata),
        }
