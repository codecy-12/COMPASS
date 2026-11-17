from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterator, List, Mapping, Optional, Sequence, Tuple

from ..config import DynamicConfig
from ..errors import CaptureError
from ..schema import ModuleMapping
from ..util import executable, iter_jsonl, run_checked


@dataclass
class RuntimeTransfer:
    source_address: int
    target_address: int
    source_tid: int
    target_tid: int
    kind: str
    callsite_address: Optional[int] = None
    carrier: str = ""
    fields: List[Dict[str, Any]] = field(default_factory=list)
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DynamicRun:
    replay_id: str
    profile_key: str
    mappings: List[ModuleMapping]
    records: List[Dict[str, Any]]


@dataclass
class DynamicCaptureResult:
    runs: List[DynamicRun]
    indirect_transfers: List[RuntimeTransfer]
    records: List[Dict[str, Any]]


class LBRRecorder:
    """Records user-space branch stacks with Linux perf's LBR support."""

    def __init__(self, config: DynamicConfig) -> None:
        self.config = config

    def record(self, command: Sequence[str], output: Path, cwd: Optional[Path] = None) -> Path:
        if not command:
            raise CaptureError("a preparation command is required for LBR capture")
        perf = executable(self.config.perf_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        argv = [
            perf, "record", "-q", "-e", "branches:u", "-c", str(self.config.lbr_sample_period),
            "-j", "any_call,u,any_ret,u", "-o", str(output), "--",
        ] + list(command)
        run_checked(argv, cwd=cwd)
        return output

    def export(self, capture: Path, output_jsonl: Path) -> Path:
        perf = executable(self.config.perf_path)
        result = run_checked([
            perf, "script", "-i", str(capture), "-F", "comm,pid,tid,time,ip,addr,brstack"
        ])
        records = self.parse_script((result.stdout or b"").decode("utf-8", errors="replace"))
        output_jsonl.parent.mkdir(parents=True, exist_ok=True)
        with output_jsonl.open("w", encoding="utf-8") as stream:
            for record in records:
                stream.write(json.dumps(record, sort_keys=True) + "\n")
        return output_jsonl

    @staticmethod
    def parse_script(text: str) -> Iterator[Dict[str, Any]]:
        header = re.compile(r"^\s*(?P<comm>.+?)\s+(?P<pid>\d+)(?:(?:/|\s+)(?P<tid>\d+))?(?:\s+\[\d+\])?\s+(?P<time>\d+\.\d+):")
        branch = re.compile(r"(?P<from>[0-9a-fA-F]+)\/(?P<to>[0-9a-fA-F]+)\/(?P<flags>[^\s]+)")
        sequence = 0
        for line in text.splitlines():
            match = header.search(line)
            if not match:
                continue
            pid = int(match.group("pid"))
            tid = int(match.group("tid") or pid)
            for item in branch.finditer(line):
                sequence += 1
                yield {
                    "kind": "branch",
                    "sequence": sequence,
                    "timestamp_ns": int(float(match.group("time")) * 1_000_000_000),
                    "pid": pid,
                    "tid": tid,
                    "source_address": int(item.group("from"), 16),
                    "target_address": int(item.group("to"), 16),
                    "branch_flags": item.group("flags"),
                    "source": "perf-lbr",
                }


class DynamicTraceLoader:
    """Loads normalized LBR/eBPF preparation records from one or more replays."""

    def load(self, paths: Sequence[Path], mappings_path: Optional[Path] = None) -> DynamicCaptureResult:
        default_mappings = self._load_mappings(mappings_path) if mappings_path else []
        grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        mappings: Dict[Tuple[str, str], List[ModuleMapping]] = {}
        all_records: List[Dict[str, Any]] = []
        for path in paths:
            for record in iter_jsonl(path):
                replay = str(record.get("replay_id", path.stem))
                profile = str(record.get("profile_key", "default"))
                key = (replay, profile)
                grouped.setdefault(key, []).append(record)
                all_records.append(record)
                if record.get("kind") == "module_mapping":
                    mappings.setdefault(key, []).append(ModuleMapping.from_dict(record))
        runs = [
            DynamicRun(
                replay_id=key[0],
                profile_key=key[1],
                mappings=mappings.get(key, default_mappings),
                records=sorted(values, key=lambda item: (int(item.get("sequence", 0)), int(item.get("timestamp_ns", 0)))),
            )
            for key, values in sorted(grouped.items())
        ]
        indirect = self._extract_indirect_transfers(runs)
        return DynamicCaptureResult(runs=runs, indirect_transfers=indirect, records=all_records)

    @staticmethod
    def _load_mappings(path: Path) -> List[ModuleMapping]:
        raw = json.loads(path.read_text(encoding="utf-8"))
        values = raw.get("mappings", raw) if isinstance(raw, Mapping) else raw
        return [ModuleMapping.from_dict(item) for item in values]

    @staticmethod
    def _extract_indirect_transfers(runs: Sequence[DynamicRun]) -> List[RuntimeTransfer]:
        found: Dict[Tuple[str, str, int, int, int], RuntimeTransfer] = {}
        projects: Dict[str, Any] = {}
        classifications: Dict[Tuple[str, int], bool] = {}
        for run in runs:
            for record in run.records:
                if record.get("kind") not in {"indirect_call", "branch"}:
                    continue
                flags = str(record.get("branch_flags", ""))
                source = int(record.get("source_address", 0))
                target = int(record.get("target_address", 0))
                classification = "runtime-indirect-call"
                if record.get("kind") == "branch":
                    if "IND_CALL" in flags.upper() or "INDIRECT_CALL" in flags.upper():
                        classification = "perf-indirect-call-type"
                    else:
                        mapping = next((item for item in run.mappings if item.contains(source)), None)
                        if mapping is None or not Path(mapping.path).is_file():
                            continue
                        key = mapping.path, mapping.to_rva(source)
                        if key not in classifications:
                            try:
                                import angr
                                import capstone
                                if mapping.path not in projects:
                                    projects[mapping.path] = angr.Project(mapping.path, auto_load_libs=False)
                                project = projects[mapping.path]
                                address = int(project.loader.main_object.mapped_base) + key[1]
                                instructions = project.factory.block(address, num_inst=1).capstone.insns
                                instruction = instructions[0].insn if instructions else None
                                classifications[key] = bool(instruction and instruction.group(capstone.CS_GRP_CALL)
                                    and instruction.operands and instruction.operands[0].type != capstone.CS_OP_IMM)
                            except Exception:
                                classifications[key] = False
                        if not classifications[key]:
                            continue
                        classification = "binary-call-instruction"
                tid = int(record.get("tid", 0))
                key = run.replay_id, run.profile_key, source, target, tid
                transfer = found.get(key)
                if transfer is None:
                    transfer = RuntimeTransfer(
                        source_address=source,
                        target_address=target,
                        callsite_address=int(record.get("callsite_address", source)),
                        source_tid=tid,
                        target_tid=tid,
                        kind="indirect_call",
                        evidence=[],
                        metadata={"replay_id": run.replay_id, "profile_key": run.profile_key,
                                  "indirect_call_validation": classification},
                    )
                    found[key] = transfer
                evidence = "%s:%s" % (run.replay_id, record.get("sequence", ""))
                if evidence not in transfer.evidence:
                    transfer.evidence.append(evidence)
        return list(found.values())


class DynamicCatcher:
    def __init__(self, config: DynamicConfig) -> None:
        self.config = config
        self.recorder = LBRRecorder(config)
        self.loader = DynamicTraceLoader()

    def load(self, traces: Sequence[Path], mappings: Optional[Path] = None) -> DynamicCaptureResult:
        return self.loader.load(traces, mappings)
