from __future__ import annotations

import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from ..acg import ACG
from ..config import StaticConfig
from ..errors import AnalysisError, BackendUnavailable
from ..schema import ACGEdgeRecord, BasicBlockRecord, EdgeKind, FunctionRecord, SyscallSite
from ..util import executable, load_json, run_checked, sha256_file


SYSCALL_WRAPPERS = {
    "read", "readv", "pread", "pread64", "recv", "recvfrom", "recvmsg", "recvmmsg",
    "write", "writev", "pwrite", "pwrite64", "send", "sendto", "sendmsg", "sendmmsg",
    "open", "open64", "openat", "openat64", "openat2", "close", "accept", "accept4",
    "socket", "socketpair", "connect", "pipe", "pipe2", "dup", "dup2", "dup3", "execve",
    "mmap", "munmap", "mprotect", "clone", "clone3", "fork", "vfork", "futex",
    "epoll_wait", "epoll_pwait", "poll", "ppoll", "select", "pselect6",
}


@dataclass
class StaticAnalysisResult:
    graph: ACG
    unresolved_indirect_sites: List[Dict[str, Any]] = field(default_factory=list)
    verified_direct_calls: int = 0
    backend: str = ""

    def to_dict(self) -> Dict[str, Any]:
        value = self.graph.to_dict()
        value["metadata"] = dict(value.get("metadata", {}))
        value["metadata"]["static_backend"] = self.backend
        value["metadata"]["unresolved_indirect_sites"] = self.unresolved_indirect_sites
        value["metadata"]["verified_direct_calls"] = self.verified_direct_calls
        return value


class ObjdumpCallVerifier:
    _CALL = re.compile(r"^\s*([0-9a-fA-F]+):.*\bcall\w*\s+([0-9a-fA-Fx]+)")

    def __init__(self, objdump_path: str = "objdump") -> None:
        self.objdump_path = objdump_path

    def direct_calls(self, binary: Path) -> Set[Tuple[int, int]]:
        tool = executable(self.objdump_path)
        result = run_checked([tool, "-d", str(binary)])
        calls: Set[Tuple[int, int]] = set()
        for line in (result.stdout or b"").decode("utf-8", errors="replace").splitlines():
            match = self._CALL.match(line)
            if not match:
                continue
            try:
                calls.add((int(match.group(1), 16), int(match.group(2), 0 if "0x" in match.group(2) else 16)))
            except ValueError:
                continue
        return calls

    def annotate(self, graph: ACG, binary: Path) -> int:
        image_base = int(graph.metadata.get("image_base", 0))
        calls = {(source - image_base, target - image_base) for source, target in self.direct_calls(binary)}
        verified = 0
        for edge in graph.edges.values():
            if edge.kind != EdgeKind.DIRECT_CALL or edge.callsite_rva is None:
                continue
            target = graph.functions.get(edge.target_function or edge.target)
            matched = bool(target and (edge.callsite_rva, target.rva) in calls)
            edge.metadata["objdump_verified"] = matched
            verified += int(matched)
        return verified


class IDAStaticAnalyser:
    def __init__(self, config: StaticConfig) -> None:
        self.config = config

    def analyse(self, binary: Path) -> StaticAnalysisResult:
        ida = executable(self.config.ida_path or "ida64")
        script = Path(__file__).resolve().parents[1] / "ida" / "ida_export.py"
        with tempfile.TemporaryDirectory(prefix="compass-ida-") as temporary:
            output = Path(temporary) / "static.json"
            argument = "%s --output %s" % (script, output)
            run_checked([ida, "-A", "-S%s" % argument, str(binary)], timeout=None)
            if not output.exists():
                raise AnalysisError("IDA completed without producing the static graph")
            raw = load_json(output)
        graph = ACG.from_dict(raw)
        unresolved = list(raw.get("metadata", {}).get("unresolved_indirect_sites", []))
        return StaticAnalysisResult(graph=graph, unresolved_indirect_sites=unresolved, backend="ida")


class AngrStaticAnalyser:
    def __init__(self, config: StaticConfig) -> None:
        self.config = config

    def analyse(self, binary: Path) -> StaticAnalysisResult:
        try:
            import angr  # type: ignore
        except ImportError as exc:
            raise BackendUnavailable("angr is required for the selected static backend") from exc
        project = angr.Project(str(binary), auto_load_libs=self.config.load_external_libraries)
        cfg = project.analyses.CFGFast(
            normalize=True,
            data_references=True,
            resolve_indirect_jumps=False,
            cross_references=True,
        )
        main = project.loader.main_object
        module = Path(main.binary).name
        base = int(main.mapped_base)
        graph = ACG(build_id=sha256_file(binary), binary=str(binary.resolve()), architecture=project.arch.name)
        graph.metadata["image_base"] = int(main.linked_base)
        function_ids: Dict[int, str] = {}
        block_ids: Dict[int, str] = {}
        unresolved: List[Dict[str, Any]] = []

        functions = sorted(cfg.kb.functions.values(), key=lambda item: int(item.addr))
        for function in functions:
            if not main.contains_addr(function.addr) and not self.config.load_external_libraries:
                continue
            owner = project.loader.find_object_containing(function.addr)
            owner_name = Path(owner.binary).name if owner is not None else module
            owner_base = int(owner.mapped_base) if owner is not None else base
            function_id = "%s:fn:%x" % (owner_name, int(function.addr) - owner_base)
            function_ids[int(function.addr)] = function_id
            graph.add_function(
                FunctionRecord(
                    id=function_id,
                    name=str(function.name or "sub_%x" % function.addr),
                    module=owner_name,
                    rva=int(function.addr) - owner_base,
                    size=max(int(getattr(function, "size", 0) or 0), 0),
                    is_external=bool(getattr(function, "is_plt", False)),
                    metadata={"is_plt": bool(getattr(function, "is_plt", False))},
                )
            )

        for function in functions:
            function_id = function_ids.get(int(function.addr))
            if not function_id:
                continue
            owner_name = graph.functions[function_id].module
            owner = next((item for item in project.loader.all_objects if Path(item.binary).name == owner_name), main)
            owner_base = int(owner.mapped_base)
            for block in sorted(function.blocks, key=lambda item: int(item.addr)):
                block_id = "%s:bb:%x" % (owner_name, int(block.addr) - owner_base)
                block_ids[int(block.addr)] = block_id
                terminal = ""
                try:
                    terminal = str(block.vex.jumpkind)
                except Exception:
                    pass
                graph.add_block(
                    BasicBlockRecord(
                        id=block_id,
                        function_id=function_id,
                        module=owner_name,
                        rva=int(block.addr) - owner_base,
                        size=int(block.size),
                        instruction_count=int(getattr(block, "instructions", 0) or 0),
                        terminal_kind=terminal,
                    )
                )
                self._recover_syscall_sites(graph, project, block, block_id, function_id, owner_name, owner_base)

        edge_number = 0
        for function in graph.functions.values():
            if not function.blocks:
                continue
            entry_block = min((graph.blocks[item] for item in function.blocks), key=lambda item: item.rva)
            edge_number += 1
            graph.add_edge(
                ACGEdgeRecord(
                    id="static:e%d" % edge_number,
                    source=function.id,
                    target=entry_block.id,
                    kind=EdgeKind.CFG,
                    source_function=function.id,
                    target_function=function.id,
                    evidence=["function-entry"],
                )
            )
        for source, target, data in cfg.graph.edges(data=True):
            source_id = block_ids.get(int(source.addr))
            if not source_id:
                continue
            target_id = block_ids.get(int(target.addr))
            jumpkind = str(data.get("jumpkind", getattr(source, "jumpkind", "")))
            if jumpkind == "Ijk_Call":
                target_function = function_ids.get(int(target.function_address or target.addr))
                if target_function:
                    edge_number += 1
                    graph.add_edge(
                        ACGEdgeRecord(
                            id="static:e%d" % edge_number,
                            source=source_id,
                            target=target_function,
                            kind=EdgeKind.DIRECT_CALL,
                            callsite_rva=graph.blocks[source_id].rva,
                            source_function=graph.blocks[source_id].function_id,
                            target_function=target_function,
                            evidence=["angr-cfgfast"],
                        )
                    )
                else:
                    unresolved.append({"module": graph.blocks[source_id].module, "rva": graph.blocks[source_id].rva})
            elif target_id:
                edge_number += 1
                source_function_id = graph.blocks[source_id].function_id
                target_function_id = graph.blocks[target_id].function_id
                if jumpkind == "Ijk_Ret":
                    kind = EdgeKind.RETURN
                    edge_target = target_id
                elif source_function_id != target_function_id:
                    kind = EdgeKind.DIRECT_CALL
                    edge_target = target_function_id
                else:
                    kind = EdgeKind.CFG
                    edge_target = target_id
                graph.add_edge(
                    ACGEdgeRecord(
                        id="static:e%d" % edge_number,
                        source=source_id,
                        target=edge_target,
                        kind=kind,
                        source_function=source_function_id,
                        target_function=target_function_id,
                        evidence=["angr-cfgfast"],
                        metadata={"tail_call": kind == EdgeKind.DIRECT_CALL},
                    )
                )

        for function in functions:
            if int(function.addr) not in function_ids:
                continue
            for site in getattr(function, "jumpout_sites", []):
                block_id = block_ids.get(int(site.addr))
                if block_id:
                    unresolved.append({"module": graph.blocks[block_id].module, "rva": graph.blocks[block_id].rva})
        graph.metadata["unresolved_indirect_sites"] = unresolved
        graph.validate()
        return StaticAnalysisResult(graph=graph, unresolved_indirect_sites=unresolved, backend="angr")

    @staticmethod
    def _recover_syscall_sites(
        graph: ACG, project: Any, block: Any, block_id: str, function_id: str, module: str, base: int
    ) -> None:
        try:
            instructions = list(block.capstone.insns)
        except Exception:
            return
        function_name = graph.functions[function_id].name.lower().lstrip("_")
        wrapper = function_name.split("@", 1)[0]
        if wrapper.startswith("libc_"):
            wrapper = wrapper[5:]
        for instruction in instructions:
            mnemonic = instruction.mnemonic.lower()
            syscall = "unknown"
            if mnemonic in {"syscall", "sysenter", "svc"}:
                syscall = wrapper if wrapper in SYSCALL_WRAPPERS else "unknown"
            elif mnemonic.startswith("call"):
                operand = instruction.op_str.lower().lstrip("_").split("@", 1)[0]
                try:
                    address = int(instruction.op_str.strip(), 0)
                    symbol = project.loader.main_object.reverse_plt.get(address)
                    target = project.kb.functions.get(address)
                    resolved = symbol or (target.name if target is not None else "")
                    if resolved:
                        operand = str(resolved).lower().lstrip("_").split("@", 1)[0]
                        if operand.startswith("libc_"):
                            operand = operand[5:]
                except (AttributeError, TypeError, ValueError):
                    pass
                syscall = next((name for name in SYSCALL_WRAPPERS if operand == name or operand.endswith("<%s>" % name)), "")
                if not syscall:
                    continue
            else:
                continue
            site_id = "%s:sys:%x" % (module, int(instruction.address) - base)
            if site_id not in graph.syscall_sites:
                graph.add_syscall_site(
                    SyscallSite(
                        id=site_id,
                        function_id=function_id,
                        block_id=block_id,
                        module=module,
                        rva=int(instruction.address) - base,
                        syscall=syscall,
                        metadata={"instruction_size": int(instruction.size), "mnemonic": mnemonic},
                    )
                )


class StaticAnalyser:
    def __init__(self, config: StaticConfig) -> None:
        self.config = config

    def analyse(self, binary: Path) -> StaticAnalysisResult:
        binary = binary.resolve()
        if not binary.is_file():
            raise AnalysisError("target binary does not exist: %s" % binary)
        backend = self.config.backend.lower()
        errors: List[str] = []
        if backend in {"auto", "ida"}:
            try:
                result = IDAStaticAnalyser(self.config).analyse(binary)
                result.verified_direct_calls = ObjdumpCallVerifier(self.config.objdump_path).annotate(result.graph, binary)
                return result
            except (BackendUnavailable, AnalysisError) as exc:
                if backend == "ida":
                    raise
                errors.append(str(exc))
        if backend in {"auto", "angr"}:
            try:
                result = AngrStaticAnalyser(self.config).analyse(binary)
                result.verified_direct_calls = ObjdumpCallVerifier(self.config.objdump_path).annotate(result.graph, binary)
                return result
            except (BackendUnavailable, AnalysisError) as exc:
                if backend == "angr":
                    raise
                errors.append(str(exc))
        raise BackendUnavailable("no static-analysis backend is available: %s" % "; ".join(errors))
