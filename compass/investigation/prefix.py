from __future__ import annotations

import re
import json
import subprocess
from pathlib import Path
from typing import Any, Mapping, Optional

from ..acg import ACG
from ..config import InvestigationConfig
from ..errors import AnalysisError
from ..schema import CandidateInput, ExternalInputEntry, PrefixSnapshot
from ..util import executable, load_json, parse_int, run_checked
from .binding import BindingPlan


ARGUMENT_REGISTERS = {
    "AMD64": ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    "X86": (),
    "AARCH64": ("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"),
}


class NativePrefixRecorder:
    """Uses GDB to stop a live process at the selected entry and save concrete state."""

    def capture_process(
        self,
        pid: int,
        entry_address: int,
        entry_rva: int,
        build_id: str,
        profile_key: str,
        module_base: int,
        output: Path,
        gdb_path: str = "gdb",
        timeout_seconds: float = 120.0,
    ) -> Path:
        if timeout_seconds <= 0:
            raise AnalysisError("prefix capture timeout must be positive")
        gdb = executable(gdb_path)
        helper = Path(__file__).resolve().parents[1] / "gdb" / "capture_prefix.py"
        environment = {
            "COMPASS_PREFIX_OUTPUT": str(output.resolve()),
            "COMPASS_ENTRY_RVA": hex(entry_rva),
            "COMPASS_BUILD_ID": build_id,
            "COMPASS_PROFILE_KEY": profile_key,
            "COMPASS_MODULE_BASE": hex(module_base),
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        try:
            run_checked(
                [
                    gdb, "--nx", "-q", "-batch", "-p", str(pid),
                    "-ex", "break *0x%x" % entry_address,
                    "-ex", "continue",
                    "-ex", "source %s" % json.dumps(str(helper), ensure_ascii=False),
                    "-ex", "detach",
                ],
                env=environment,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise AnalysisError("GDB prefix capture timed out before the requested entry") from exc
        if not output.is_file():
            raise AnalysisError("GDB did not create the path-prefix snapshot")
        return output


class PathPrefixInitializer:
    """Restores the concrete startup prefix and begins at the offline-selected entry."""

    def __init__(self, config: InvestigationConfig) -> None:
        self.config = config

    def initialize(self, project: Any, plan: BindingPlan, acg: ACG) -> Any:
        entry = plan.entry
        if not entry.prefix_snapshot:
            raise AnalysisError("external-input entry %s has no path-prefix snapshot" % entry.id)
        path = Path(entry.prefix_snapshot).expanduser()
        if not path.is_file():
            raise AnalysisError("path-prefix snapshot does not exist: %s" % path)
        snapshot = PrefixSnapshot.from_dict(load_json(path))
        if snapshot.entry_rva != entry.rva:
            raise AnalysisError("path-prefix snapshot entry does not match the selected input")
        address = self._absolute(project, entry.module, entry.rva)
        state = self.restore_context(project, snapshot, acg, plan.candidate.first_event.tid)
        state.regs.ip = address
        from .angr_extensions import compass_state

        plugin = compass_state(state)
        plugin.entry_id = entry.id
        plugin.path = [entry.function_id]
        self._bind_entry(state, plan.candidate, entry)
        return state

    @classmethod
    def restore_context(
        cls, project: Any, source: Any, acg: ACG, thread_id: Optional[int] = None
    ) -> Any:
        from .angr_extensions import compass_state

        if isinstance(source, PrefixSnapshot):
            snapshot = source
        elif isinstance(source, Mapping):
            snapshot = PrefixSnapshot.from_dict(source)
        else:
            path = Path(str(source)).expanduser()
            if not path.is_file():
                raise AnalysisError("consumer snapshot does not exist: %s" % path)
            snapshot = PrefixSnapshot.from_dict(load_json(path))
        if snapshot.build_id and snapshot.build_id != acg.build_id:
            raise AnalysisError("path-prefix snapshot build does not match the ACFG")
        if snapshot.metadata.get("complete") is False:
            raise AnalysisError("path-prefix snapshot contains incomplete memory evidence")
        address = int(project.loader.main_object.mapped_base) + snapshot.entry_rva
        state = project.factory.blank_state(addr=address)
        cls._restore_registers(state, snapshot, project)
        cls._restore_memory(state, snapshot, project)
        recorded_pc = snapshot.registers.get("rip", snapshot.registers.get("eip", snapshot.registers.get("pc")))
        if recorded_pc is not None:
            state.regs.ip = cls._relocate(project, snapshot, int(recorded_pc))
        else:
            state.regs.ip = address
        compass_state(state).thread_id = thread_id if thread_id is not None else snapshot.metadata.get("tid")
        return state

    @staticmethod
    def _absolute(project: Any, module: str, rva: int) -> int:
        for obj in project.loader.all_objects:
            if Path(obj.binary).name == module or obj.binary == module:
                return int(obj.mapped_base) + rva
        if module in {"", "main", Path(project.loader.main_object.binary).name}:
            return int(project.loader.main_object.mapped_base) + rva
        raise AnalysisError("module required by the path-prefix snapshot is not loaded: %s" % module)

    @staticmethod
    def _restore_registers(state: Any, snapshot: PrefixSnapshot, project: Any = None) -> None:
        for name, value in snapshot.registers.items():
            if state.arch.name == "AMD64" and name in {"fs_base", "gs_base"}:
                name = name[:2]
            elif state.arch.name == "AMD64" and name in {"fs", "gs"} and name + "_base" in snapshot.registers:
                continue
            if hasattr(state.regs, name):
                if project is not None and name not in {"eflags", "rflags", "flags", "cs", "ss", "ds", "es", "fs", "gs"}:
                    value = PathPrefixInitializer._relocate(project, snapshot, int(value))
                setattr(state.regs, name, value)

    @staticmethod
    def _restore_memory(state: Any, snapshot: PrefixSnapshot, project: Any) -> None:
        for region in snapshot.memory:
            address = PathPrefixInitializer._relocate(project, snapshot, region.start)
            if region.data:
                state.memory.store(address, region.data, disable_actions=True, inspect=False)

    @staticmethod
    def _relocate(project: Any, snapshot: PrefixSnapshot, address: int) -> int:
        bases = dict(snapshot.module_bases)
        captured_main = int(snapshot.metadata.get("main_module_base", 0))
        if captured_main:
            bases.setdefault(Path(project.loader.main_object.binary).name, captured_main)
        for obj in project.loader.all_objects:
            name = Path(obj.binary).name
            captured = bases.get(name, bases.get(str(obj.binary)))
            if captured is None:
                continue
            size = int(obj.max_addr) - int(obj.min_addr) + 1
            if int(captured) <= address < int(captured) + size:
                return int(obj.mapped_base) + address - int(captured)
        return address

    def _bind_entry(self, state: Any, candidate: CandidateInput, entry: ExternalInputEntry) -> None:
        from .angr_extensions import compass_state

        registers = ARGUMENT_REGISTERS.get(state.arch.name, ARGUMENT_REGISTERS.get(state.arch.name.upper(), ()))
        data = candidate.data
        plugin = compass_state(state)
        input_variables = set(plugin.input_variables)
        for semantic, location in entry.parameter_layout.items():
            value: Any = None
            if semantic in {"buffer", "data", "request_bytes"}:
                if candidate.first_event.syscall in {"readv", "writev", "preadv", "pwritev", "recvmsg", "sendmsg", "recvmmsg", "sendmmsg"}:
                    continue
                allocation = parse_int(candidate.first_event.args.get("buf"), None)
                if allocation is None and location.startswith("arg:"):
                    index = int(location.split(":", 1)[1])
                    if index < len(registers):
                        pointer = getattr(state.regs, registers[index])
                        if not state.solver.symbolic(pointer):
                            allocation = state.solver.eval(pointer)
                if not allocation:
                    allocation = state.heap.allocate(max(len(data) + 1, 1))
                label = re.sub(r"[^A-Za-z0-9_]", "_", candidate.id)
                import claripy

                for offset, byte in enumerate(data):
                    symbol = claripy.BVS("compass_input_%s_%d" % (label, offset), 8)
                    state.memory.store(allocation + offset, symbol, inspect=False)
                    input_variables.update(symbol.variables)
                    if self.config.concretize_captured_input:
                        state.add_constraints(symbol == byte)
                plugin.log_progress.setdefault("input_regions", []).append((int(allocation), len(data)))
                value = allocation
            elif semantic in {"length", "size", "request_length"}:
                arguments = candidate.first_event.args
                value = parse_int(arguments.get("count", arguments.get("len", arguments.get("iovcnt"))), len(data))
            elif semantic in {"fd", "socket", "handle"}:
                value = candidate.first_event.handle.fd if candidate.first_event.handle else parse_int(candidate.first_event.args.get("fd"), None)
            if value is None:
                continue
            if location.startswith("arg:"):
                index = int(location.split(":", 1)[1])
                if index < len(registers):
                    setattr(state.regs, registers[index], value)
            elif location.startswith("reg:"):
                register = location.split(":", 1)[1]
                if hasattr(state.regs, register):
                    setattr(state.regs, register, value)
            elif location.startswith("mem:"):
                state.memory.store(int(location.split(":", 1)[1], 0), value, endness=state.arch.memory_endness)
        plugin.input_variables = input_variables
