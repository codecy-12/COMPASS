from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from ..acg import ACG
from ..errors import AnalysisError, BackendUnavailable
from ..schema import ACGEdgeRecord, ArgumentBinding, AuditEvent, EdgeKind, EventDirection
from ..util import parse_int, sha256_file
from .binding import BindingPlan
from .simprocedures import SimProcedureRegistry


ARGUMENT_REGISTERS = {
    "AMD64": ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    "X86": (),
    "AARCH64": ("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"),
}

RETURN_REGISTERS = {"AMD64": "rax", "X86": "eax", "AARCH64": "x0"}
NAMED_CONSTANTS = {"AT_FDCWD": -100, "NULL": 0}


@dataclass
class GuidedExecutionOutcome:
    accepted: bool
    function_path: List[str] = field(default_factory=list)
    matched_events: List[str] = field(default_factory=list)
    explored_paths: int = 0
    complete: bool = True
    reasons: List[str] = field(default_factory=list)


class ACGGuidedSymbolicExecutor:
    """Depth-first symbolic execution constrained by the ACG and audit checkpoints."""

    def __init__(self, acg: ACG, simprocedure_manifest: str = "") -> None:
        self.acg = acg
        self.simprocedure_manifest = simprocedure_manifest
        self._incomplete_reasons: List[str] = []
        self._accepted_state: Any = None
        self._explored_paths = 0
        self._events: Dict[str, AuditEvent] = {}
        self._plan: Optional[BindingPlan] = None
        self.binary_fingerprint_verified = False

    def open_project(
        self, base_address: Optional[int] = None, module_bases: Optional[Dict[str, int]] = None,
        module_paths: Optional[Dict[str, str]] = None,
    ) -> Any:
        try:
            import angr  # type: ignore
        except ImportError as exc:
            raise BackendUnavailable("angr is required for guided symbolic execution") from exc
        if not self.acg.binary:
            raise AnalysisError("the ACG does not identify its target binary")
        binary = Path(self.acg.binary).expanduser().resolve()
        fingerprint = self.acg.build_id.lower()
        self.binary_fingerprint_verified = len(fingerprint) == 64 and all(character in "0123456789abcdef" for character in fingerprint)
        if self.binary_fingerprint_verified and sha256_file(binary) != fingerprint:
            raise AnalysisError("target binary fingerprint does not match the ACFG")
        main_names = {"", "main", binary.name, str(binary), self.acg.binary}
        required = {function.module for function in self.acg.functions.values()} - main_names
        configured = dict(self.acg.metadata.get("module_paths", {}))
        configured.update(module_paths or {})
        paths = {}
        for module in required:
            candidate = configured.get(module, configured.get(Path(module).name, module))
            path = Path(str(candidate)).expanduser()
            if not path.is_absolute():
                path = binary.parent / path
            if path.is_file():
                paths[module] = path.resolve()
        kwargs: Dict[str, Any] = {"auto_load_libs": bool(required)}
        if base_address:
            kwargs["main_opts"] = {"base_addr": base_address}
        if paths:
            kwargs["force_load_libs"] = [str(path) for path in paths.values()]
            kwargs["ld_path"] = sorted({str(path.parent) for path in paths.values()})
        if module_bases:
            kwargs["lib_opts"] = {Path(name).name: {"base_addr": int(value)} for name, value in module_bases.items() if name not in main_names}
        project = angr.Project(self.acg.binary, **kwargs)
        loaded = {Path(str(obj.binary or "")).name: obj for obj in project.loader.all_objects}
        missing = {module for module in required if Path(module).name not in loaded}
        if missing:
            raise AnalysisError("ACFG dependency modules are not available: %s" % ", ".join(sorted(missing)))
        for name, expected in dict(self.acg.metadata.get("module_build_ids", {})).items():
            obj = loaded.get(Path(name).name)
            actual = getattr(obj, "build_id", None) if obj is not None else None
            actual = actual.hex() if isinstance(actual, bytes) else str(actual or "")
            if actual.lower().removeprefix("0x") != str(expected).lower().removeprefix("0x"):
                raise AnalysisError("ACFG dependency build mismatch: %s" % name)
        SimProcedureRegistry().apply(project, self.simprocedure_manifest)
        return project

    def execute(self, project: Any, initial_state: Any, plan: BindingPlan) -> GuidedExecutionOutcome:
        from .angr_extensions import ACFGExplorationTechnique, compass_state

        self._incomplete_reasons = []
        self._accepted_state = None
        self._explored_paths = 0
        self._plan = plan
        self._events = {event.id: event for event in plan.events}
        checkpoints = [event for event in plan.events if event.id in plan.alternatives]
        if plan.current_event.id not in {event.id for event in checkpoints}:
            return GuidedExecutionOutcome(False, complete=False, reasons=["target-output-site-unmatched"])
        plugin = compass_state(initial_state)
        plugin.checkpoint_index = 0
        plugin.matched_events = []
        plugin.accepted = False
        self._install_inspection(initial_state)
        manager = project.factory.simulation_manager(initial_state)
        technique = ACFGExplorationTechnique(self, project, plan, checkpoints)
        manager.use_technique(technique)
        budget = max(int(plan.current_event.metadata.get("symbolic_max_steps", 100000)), 1)
        while manager.active and not manager.found and technique.steps < budget:
            manager.step()
        if manager.errored:
            self._incomplete("symbolic-engine-error")
        if (manager.active or manager.stashes.get("deferred")) and not manager.found:
            self._incomplete("symbolic-search-budget-exhausted")
        if manager.found:
            result = compass_state(manager.found[0])
            return GuidedExecutionOutcome(True, list(result.path), list(result.matched_events), self._explored_paths)
        return GuidedExecutionOutcome(
            False, explored_paths=self._explored_paths,
            complete=not self._incomplete_reasons, reasons=list(self._incomplete_reasons)
        )

    @staticmethod
    def _plugin(state: Any) -> Any:
        from .angr_extensions import compass_state

        return compass_state(state)

    def _incomplete(self, reason: str) -> None:
        if reason not in self._incomplete_reasons:
            self._incomplete_reasons.append(reason)

    @staticmethod
    def _install_inspection(state: Any) -> None:
        import angr

        from .angr_extensions import capture_exit, capture_handoff_memory, capture_handoff_register, compass_state

        plugin = compass_state(state)
        if plugin.log_progress.get("inspection_installed"):
            return
        state.inspect.b("exit", when=angr.BP_BEFORE, action=capture_exit)
        state.inspect.b("reg_write", when=angr.BP_BEFORE, action=capture_handoff_register)
        state.inspect.b("mem_read", when=angr.BP_AFTER, action=capture_handoff_memory)
        plugin.log_progress["inspection_installed"] = True

    def _query_successors(
        self, project: Any, state: Any, checkpoints: Sequence[AuditEvent], plan: BindingPlan
    ) -> List[Any]:
        if not state.solver.satisfiable():
            self._explored_paths += 1
            return []
        plugin = self._plugin(state)
        plugin.selected_edge = ""
        plugin.indirect_target = None
        block = self._block_for_state(project, state)
        if block is None:
            if project.is_hooked(self._state_address(state)):
                return self._ordinary_successors(project, state)
            self._incomplete("execution-left-recovered-acfg")
            self._explored_paths += 1
            return []
        self._record_path(state, block.function_id)
        checkpoint = self._checkpoint_at_block(state, block.id, checkpoints, plan)
        if checkpoint is not None:
            event, site_id, binding = checkpoint
            bases = self._advance_to_site(project, state, self.acg.syscall_sites[site_id])
            if not bases:
                self._explored_paths += 1
                return []
            values = []
            for base in bases:
                target = event.id == plan.current_event.id
                self._plugin(base).binding_expressions = self._binding_expressions(base, binding)
                if not self._apply_binding(base, event, binding):
                    self._explored_paths += 1
                    continue
                resumed = self._resume_after_checkpoint(project, base, block.id, event)
                for successor in resumed:
                    progress = self._plugin(successor)
                    progress.matched_events.append(event.id)
                    progress.checkpoint_index += 1
                    if target:
                        self._explored_paths += 1
                        if self._termination_matches(successor, event, binding):
                            progress.accepted = True
                            self._accepted_state = successor
                            return []
                    else:
                        values.append(successor)
            return self._select_successors(project, state, block.id, values, checkpoints, plan)
        successors = self._ordinary_successors(project, state)
        successors.extend(self._cross_context_successors(project, state, block.id))
        selected = self._select_successors(project, state, block.id, successors, checkpoints, plan)
        if not selected:
            self._explored_paths += 1
        return selected

    def _advance_to_site(self, project: Any, state: Any, site: Any) -> List[Any]:
        address = self._node_address(project, site.block_id)
        site_address = self._module_address(project, site.module, site.rva)
        return self._advance_to_address(project, state, address, site_address)

    def _advance_to_address(
        self, project: Any, state: Any, block_address: Optional[int], target_address: Optional[int]
    ) -> List[Any]:
        current = self._state_address(state)
        if target_address is None:
            return []
        if current == target_address:
            return [state]
        if block_address is None or not (block_address <= current <= target_address):
            return []
        try:
            block = project.factory.block(current, size=max(target_address - current + 1, 1))
            count = sum(1 for instruction in block.capstone.insns if int(instruction.address) < target_address)
            if count == 0:
                successor = state.copy()
                successor.regs.ip = target_address
                return [successor]
            result = project.factory.successors(state, num_inst=count)
            return [
                successor for successor in result.flat_successors
                if self._state_address(successor) == target_address and successor.solver.satisfiable()
            ]
        except Exception:
            return []

    def _checkpoint_at_block(
        self,
        state: Any,
        block_id: str,
        checkpoints: Sequence[AuditEvent],
        plan: BindingPlan,
    ) -> Optional[Tuple[AuditEvent, str, ArgumentBinding]]:
        index = self._plugin(state).checkpoint_index
        if index >= len(checkpoints):
            return None
        event = checkpoints[index]
        site_ids = set(plan.alternatives.get(event.id, []))
        bindings = [binding for binding in plan.bindings if binding.event_id == event.id and binding.site_id in site_ids and self.acg.syscall_sites[binding.site_id].block_id == block_id]
        if not bindings:
            return None
        binding = max(bindings, key=lambda item: (item.score, item.site_id))
        return event, binding.site_id, binding

    def _apply_binding(self, state: Any, event: AuditEvent, binding: ArgumentBinding) -> bool:
        import claripy

        if event.metadata.get("payload_decoding_error"):
            self._incomplete("io-payload-decoding-failed:%s" % event.id)
            return False
        candidate_ids = {item.id for item in self._plan.candidate.events} if self._plan else set()
        for value in binding.values:
            if value.location.startswith("metadata:") or value.location == "return":
                continue
            if value.name == "transferred_data" and value.location.startswith("buffer:"):
                segments = self._io_segments(state, event, value)
                if segments is None:
                    return False
                position = 0
                for address, data in segments:
                    if event.direction == EventDirection.INPUT:
                        plugin = self._plugin(state)
                        if event.id in candidate_ids:
                            region = (address, len(data))
                            if region not in plugin.log_progress.setdefault("input_regions", []):
                                plugin.log_progress["input_regions"].append(region)
                        for offset, byte in enumerate(data):
                            existing = state.memory.load(address + offset, 1)
                            if event.id in candidate_ids and not self._depends_on_input(state, existing):
                                existing = claripy.BVS("compass_input_%s_%d" % (event.id, position + offset), 8)
                                state.memory.store(address + offset, existing)
                                plugin.input_variables.update(existing.variables)
                            elif event.id not in candidate_ids:
                                existing = claripy.BVS("compass_environment_%s_%d" % (event.id, position + offset), 8)
                                state.memory.store(address + offset, existing)
                            state.add_constraints(existing == byte)
                    elif not self._constrain_buffer(state, address, data):
                        return False
                    position += len(data)
                continue
            expression = self._location_expression(state, value.location)
            if expression is None:
                self._incomplete("unsupported-argument-location")
                return False
            if isinstance(value.value, str) and self._integer(value.value) is None:
                if not self._constrain_string_pointer(state, expression, value.value):
                    return False
            else:
                parsed = self._integer(value.value)
                if parsed is not None:
                    state.add_constraints(expression == parsed)
            if not state.solver.satisfiable():
                return False
        return state.solver.satisfiable()

    def _io_segments(self, state: Any, event: AuditEvent, value: Any) -> Optional[List[Tuple[int, bytes]]]:
        pointer = self._location_expression(state, value.location[len("buffer:"):])
        addresses = state.solver.eval_upto(pointer, 2) if pointer is not None else []
        if len(addresses) != 1:
            self._incomplete("ambiguous-io-buffer-address")
            return None
        address = int(addresses[0])
        data = bytes(value.value)
        if event.syscall in {"read", "pread64", "recvfrom", "recv", "write", "pwrite64", "sendto", "send"}:
            return [(address, data)]
        width = state.arch.bytes
        if event.syscall in {"readv", "writev", "preadv", "pwritev"}:
            count = parse_int(event.args.get("iovcnt"), None)
            vector = address
        elif event.syscall in {"recvmsg", "sendmsg"}:
            vectors = state.solver.eval_upto(state.memory.load(address + 2 * width, width, endness=state.arch.memory_endness), 2)
            counts = state.solver.eval_upto(state.memory.load(address + 3 * width, width, endness=state.arch.memory_endness), 2)
            if len(vectors) != 1 or len(counts) != 1:
                self._incomplete("ambiguous-msghdr-layout")
                return None
            vector, count = int(vectors[0]), int(counts[0])
        else:
            self._incomplete("unsupported-io-layout:%s" % event.syscall)
            return None
        if count is None or not 0 <= count <= 1024:
            self._incomplete("unsupported-iovec-count")
            return None
        segments = []
        offset = 0
        capacity = 0
        for index in range(count):
            bases = state.solver.eval_upto(state.memory.load(vector + index * 2 * width, width, endness=state.arch.memory_endness), 2)
            sizes = state.solver.eval_upto(state.memory.load(vector + (index * 2 + 1) * width, width, endness=state.arch.memory_endness), 2)
            if len(bases) != 1 or len(sizes) != 1:
                self._incomplete("ambiguous-iovec-layout")
                return None
            capacity += int(sizes[0])
            size = min(int(sizes[0]), len(data) - offset)
            segments.append((int(bases[0]), data[offset:offset + size]))
            offset += size
        if offset != len(data):
            return None
        self._plugin(state).log_progress.setdefault("io_capacity", {})[event.id] = capacity
        return segments

    def _termination_matches(
        self, state: Any, event: AuditEvent, binding: ArgumentBinding
    ) -> bool:
        site = self.acg.syscall_sites.get(binding.site_id)
        plugin = self._plugin(state)
        if site is None or site.syscall not in {"unknown", event.syscall}:
            return False
        if plugin.last_operation != event.syscall:
            return False
        if not self._same_value(plugin.last_result, event.result):
            return False
        return state.solver.satisfiable() and self._input_dependency_matches(state, binding)

    def _input_dependency_matches(self, state: Any, binding: ArgumentBinding) -> bool:
        plugin = self._plugin(state)
        if plugin.control_dependencies.get(binding.event_id):
            return True
        return any(self._depends_on_input(state, expression) for expression in plugin.binding_expressions)

    def _binding_expressions(self, state: Any, binding: ArgumentBinding) -> List[Any]:
        expressions: List[Any] = []
        for value in binding.values:
            if value.location == "return" or value.location.startswith("metadata:"):
                continue
            if value.name == "transferred_data" and value.location.startswith("buffer:"):
                event = self._events.get(binding.event_id)
                segments = self._io_segments(state, event, value) if event is not None else None
                if segments is not None:
                    expressions.extend(state.memory.load(address, len(data)) for address, data in segments if data)
                continue
            expression = self._location_expression(state, value.location)
            if expression is None:
                continue
            if isinstance(value.value, str) and self._integer(value.value) is None:
                if state.solver.symbolic(expression):
                    expressions.append(expression)
                    continue
                width = len(value.value.encode("utf-8", errors="surrogateescape")) + 1
                expressions.append(state.memory.load(state.solver.eval(expression), width))
            else:
                expressions.append(expression)
        return expressions

    def _resume_after_checkpoint(self, project: Any, state: Any, block_id: str, event: AuditEvent) -> List[Any]:
        address = self._state_address(state)
        try:
            instruction = project.factory.block(address, num_inst=1).capstone.insns[0]
        except Exception:
            self._incomplete("audit-call-instruction-unavailable")
            return []
        if instruction.mnemonic.lower() not in {"call", "callq", "syscall", "sysenter", "int", "svc", "bl", "blr"}:
            self._incomplete("audit-site-is-not-a-call-instruction")
            return []
        if instruction.mnemonic.lower() in {"syscall", "sysenter", "int", "svc"}:
            if not self._constrain_syscall_operation(project, state, event):
                return []
        self._plugin(state).log_progress["pending_event"] = event.id
        SimProcedureRegistry.install_io(project, address, int(instruction.size), self)
        return self._ordinary_successors(project, state)

    def _constrain_syscall_operation(self, project: Any, state: Any, event: AuditEvent) -> bool:
        registers = {"AMD64": ("amd64", "rax"), "X86": ("i386", "eax"), "AARCH64": ("aarch64", "x8")}
        architecture = registers.get(state.arch.name)
        if architecture is None:
            self._incomplete("unsupported-syscall-number-abi")
            return False
        abi, register = architecture
        library = getattr(project.simos, "syscall_library", None)
        numbers = getattr(library, "syscall_number_mapping", {}).get(abi, {})
        candidates = [number for number, name in numbers.items() if name == event.syscall]
        if not candidates:
            self._incomplete("syscall-number-model-unavailable:%s" % event.syscall)
            return False
        import claripy

        expression = getattr(state.regs, register)
        self._plugin(state).binding_expressions.append(expression)
        state.add_constraints(claripy.Or(*(expression == number for number in candidates)))
        return state.solver.satisfiable()

    def _model_io(self, state: Any, event: AuditEvent) -> bool:
        import claripy

        result = self._integer(event.result)
        if result is None:
            self._incomplete("noninteger-syscall-result")
            return False
        if event.syscall in {"recvmmsg", "sendmmsg"}:
            self._incomplete("unsupported-batched-message-layout")
            return False
        byte_operations = {"read", "pread64", "recvfrom", "recv", "write", "pwrite64", "sendto", "send", "readv", "writev", "preadv", "pwritev", "recvmsg", "sendmsg"}
        if event.syscall in byte_operations and result >= 0 and len(event.data) != result:
            self._incomplete("incomplete-io-payload:%s" % event.id)
            return False
        length = self._integer(event.args.get("count", event.args.get("len")))
        if event.syscall in {"read", "pread64", "recvfrom", "recv", "write", "pwrite64", "sendto", "send"}:
            if result >= 0 and length is not None and result > length:
                return False
        capacity = self._plugin(state).log_progress.get("io_capacity", {}).get(event.id)
        if capacity is not None and result > capacity:
            return False
        register = RETURN_REGISTERS.get(state.arch.name)
        if register is None:
            self._incomplete("unsupported-return-register")
            return False
        expression = claripy.BVV(result & ((1 << state.arch.bits) - 1), state.arch.bits)
        if self._plan and event.id in {item.id for item in self._plan.candidate.events}:
            expression = claripy.BVS("compass_input_result_%s" % event.id, state.arch.bits)
            state.add_constraints(expression == result)
            self._plugin(state).input_variables.update(expression.variables)
        setattr(state.regs, register, expression)
        plugin = self._plugin(state)
        plugin.last_operation = event.syscall
        plugin.last_result = result
        plugin.last_object = event.handle.object_id if event.handle else ""
        return state.solver.satisfiable()

    def _ordinary_successors(self, project: Any, state: Any) -> List[Any]:
        try:
            result = project.factory.successors(state)
        except Exception as exc:
            self._plugin(state).step_fault = type(exc).__name__
            self._incomplete("symbolic-step-failed:%s" % type(exc).__name__)
            return []
        values = list(result.flat_successors)
        values.extend(item for item in result.unconstrained_successors if item not in values)
        return values

    def _cross_context_successors(self, project: Any, state: Any, block_id: str) -> List[Any]:
        from .prefix import PathPrefixInitializer

        values: List[Any] = []
        for edge in self.acg.outgoing(block_id, {EdgeKind.CROSS_CONTEXT}):
            snapshot = edge.metadata.get("consumer_snapshot", edge.metadata.get("target_snapshot"))
            if not snapshot:
                entry = next((item for item in self.acg.entries.values() if item.function_id == edge.target_function and item.prefix_snapshot), None)
                snapshot = entry.prefix_snapshot if entry else None
            if not snapshot:
                self._incomplete("consumer-snapshot-unavailable:%s" % edge.id)
                continue
            source_item = self.acg.blocks[block_id]
            write_rva = parse_int(edge.metadata.get("producer_write_rva"), edge.callsite_rva)
            if write_rva is None:
                self._incomplete("producer-write-location-unavailable:%s" % edge.id)
                continue
            write_address = self._module_address(project, source_item.module, write_rva)
            bases = self._advance_to_address(project, state, self._node_address(project, block_id), write_address)
            if not edge.metadata.get("producer_after_write", False):
                bases = [successor for base in bases for successor in self._complete_producer_write(project, base, edge.id)]
            for base in bases:
                try:
                    consumer = PathPrefixInitializer.restore_context(project, snapshot, self.acg, edge.metadata.get("consumer_tid"))
                except (AnalysisError, OSError, ValueError, KeyError):
                    self._incomplete("consumer-snapshot-invalid:%s" % edge.id)
                    continue
                target_item = self.acg.blocks.get(edge.target)
                target_module = target_item.module if target_item else source_item.module
                read_rva = parse_int(edge.metadata.get("consumer_read_rva"), target_item.rva if target_item else None)
                target = self._module_address(project, target_module, read_rva) if read_rva is not None else None
                if target is None:
                    self._incomplete("consumer-read-location-unavailable:%s" % edge.id)
                    continue
                arrivals = self._advance_consumer(project, consumer, target, edge.id)
                for successor in arrivals:
                    producer_plugin = self._plugin(base)
                    consumer_tid = self._plugin(successor).thread_id
                    successor.register_plugin("compass", producer_plugin.copy({}))
                    plugin = self._plugin(successor)
                    plugin.thread_id = consumer_tid
                    plugin.log_progress.pop("inspection_installed", None)
                    self._install_inspection(successor)
                    successor.add_constraints(*base.solver.constraints)
                    if not self._inject_fields(base, successor, edge, target):
                        continue
                    plugin.selected_edge = edge.id
                    plugin.handoff_edges.append(edge.id)
                    plugin.context_history.append({"edge": edge.id, "producer_tid": producer_plugin.thread_id, "consumer_tid": consumer_tid, "carrier": edge.carrier})
                    if successor.solver.satisfiable():
                        values.append(successor)
        return values

    def _complete_producer_write(self, project: Any, state: Any, edge_id: str) -> List[Any]:
        try:
            instruction = project.factory.block(self._state_address(state), num_inst=1).capstone.insns[0]
            result = project.factory.successors(state, num_inst=1)
        except Exception:
            self._incomplete("producer-write-execution-failed:%s" % edge_id)
            return []
        successors = list(result.flat_successors)
        if instruction.mnemonic.lower() not in {"call", "callq", "bl", "blr"}:
            return successors
        continuation = int(instruction.address) + int(instruction.size)
        depth = sum(1 for _ in state.callstack)
        pending = successors
        completed = []
        steps = 0
        while pending and steps < 10000:
            current = pending.pop()
            steps += 1
            if not current.solver.satisfiable():
                continue
            if self._state_address(current) == continuation and sum(1 for _ in current.callstack) <= depth:
                completed.append(current)
                continue
            pending.extend(reversed(self._ordinary_successors(project, current)))
        if pending or not completed:
            self._incomplete("producer-interface-return-unresolved:%s" % edge_id)
        return completed

    def _advance_consumer(self, project: Any, state: Any, target: int, edge_id: str) -> List[Any]:
        pending = [state]
        arrivals = []
        steps = 0
        while pending and steps < 10000:
            current = pending.pop()
            steps += 1
            if not current.solver.satisfiable():
                continue
            if self._state_address(current) == target:
                arrivals.append(current)
                continue
            block = self._block_for_state(project, current)
            if block is not None:
                block_address = self._node_address(project, block.id)
                if block_address is not None and block_address <= target < block_address + max(block.size, 1):
                    arrivals.extend(self._advance_to_address(project, current, block_address, target))
                    continue
            pending.extend(reversed(self._ordinary_successors(project, current)))
        if pending or not arrivals:
            self._incomplete("consumer-local-prefix-unresolved:%s" % edge_id)
        return arrivals

    def _inject_fields(self, producer: Any, consumer: Any, edge: ACGEdgeRecord, read_address: Optional[int] = None) -> bool:
        if not edge.transfer_fields:
            self._incomplete("handoff-field-map-unavailable:%s" % edge.id)
            return False
        plugin = self._plugin(consumer)
        aliases = {}
        for item in edge.transfer_fields:
            width = item.width or producer.arch.bytes
            expression = self._location_expression(producer, item.source, width)
            if expression is None:
                self._incomplete("handoff-source-field-unavailable:%s" % edge.id)
                return False
            pointers = producer.solver.eval_upto(expression, 2)
            inferred_size = None
            if len(pointers) == 1:
                inferred_size = next((start + size - int(pointers[0]) for start, size in self._plugin(producer).log_progress.get("input_regions", []) if start <= int(pointers[0]) < start + size), None)
            if item.encoding in {"pointer", "ptr"} or item.metadata.get("pointee_size") or inferred_size is not None:
                size = parse_int(item.metadata.get("pointee_size"), inferred_size)
                if len(pointers) != 1 or size is None or not 0 <= size <= 1048576:
                    self._incomplete("handoff-pointee-map-unavailable:%s" % edge.id)
                    return False
                pointer = int(pointers[0])
                if pointer not in aliases:
                    aliases[pointer] = pointer
                    if size:
                        consumer.memory.store(pointer, producer.memory.load(pointer, size))
                expression = producer.solver.eval(expression)
            if not self._write_location(consumer, item.destination, expression, width):
                self._incomplete("handoff-destination-field-unavailable:%s" % edge.id)
                return False
            if read_address is not None:
                location = item.destination
                if location.startswith("arg:"):
                    registers = ARGUMENT_REGISTERS.get(consumer.arch.name, ())
                    index = parse_int(location[4:], None)
                    location = "reg:" + registers[index] if index is not None and 0 <= index < len(registers) else location
                if location.startswith("reg:"):
                    register = consumer.arch.registers.get(location[4:])
                    memory_address = parse_int(item.metadata.get("consumer_read_address"), None)
                    if memory_address is not None:
                        consumer.memory.store(memory_address, expression, size=width, endness=consumer.arch.memory_endness)
                        plugin.handoff_reads.append({"instruction": read_address, "address": memory_address, "expression": consumer.memory.load(memory_address, width, endness=consumer.arch.memory_endness)})
                    elif register:
                        plugin.handoff_reads.append({"instruction": read_address, "register_offset": int(register[0]), "expression": self._location_expression(consumer, location, width)})
                elif location.startswith("mem:"):
                    address = self._memory_address(consumer, location)
                    if address is not None:
                        plugin.handoff_reads.append({"instruction": read_address, "address": address, "expression": consumer.memory.load(address, width, endness=consumer.arch.memory_endness)})
            plugin.object_mappings[(edge.carrier, item.source)] = item.destination
        return consumer.solver.satisfiable()

    def _select_successors(
        self,
        project: Any,
        source_state: Any,
        source_block: str,
        successors: Sequence[Any],
        checkpoints: Sequence[AuditEvent],
        plan: BindingPlan,
    ) -> List[Any]:
        outgoing = self.acg.outgoing(source_block)
        indirect = [edge for edge in outgoing if edge.kind == EdgeKind.INDIRECT_CALL]
        unresolved = self._is_unresolved_indirect_site(source_block)
        values = []
        for successor in successors:
            plugin = self._plugin(successor)
            if plugin.selected_edge and self.acg.edges[plugin.selected_edge].kind == EdgeKind.CROSS_CONTEXT:
                if self._can_reach_checkpoint(project, successor, checkpoints, plan):
                    values.append(successor)
                continue
            is_call = str(successor.history.jumpkind) == "Ijk_Call"
            if is_call and (indirect or unresolved):
                if not indirect:
                    self._incomplete("indirect-call-targets-missing")
                continue
            if successor.solver.satisfiable():
                self._remember_input_control_dependency(project, source_block, successor, outgoing, plan)
                if self._can_reach_checkpoint(project, successor, checkpoints, plan):
                    values.append(successor)
        if indirect:
            values.extend(item for item in self._materialize_indirect_targets(project, source_state, successors, indirect, [], set()) if self._can_reach_checkpoint(project, item, checkpoints, plan))
        return self._deduplicate(values)

    def _can_reach_checkpoint(
        self, project: Any, state: Any, checkpoints: Sequence[AuditEvent], plan: BindingPlan
    ) -> bool:
        index = self._plugin(state).checkpoint_index
        if index >= len(checkpoints):
            return True
        targets = [self.acg.syscall_sites[site].block_id for site in plan.alternatives.get(checkpoints[index].id, []) if site in self.acg.syscall_sites]
        block = self._block_for_state(project, state)
        if block is None:
            return True
        if any(self.acg.reachable(block.id, target) for target in targets):
            return True
        for frame in state.callstack:
            address = int(frame.ret_addr or 0)
            module, rva = self._relative(project, address)
            continuation = self.acg.block_at(module, rva) if module else None
            if continuation and any(self.acg.reachable(continuation.id, target) for target in targets):
                return True
        if self._is_unresolved_indirect_site(block.id):
            self._incomplete("next-anchor-requires-unrecovered-indirect-target")
        return False

    def _is_unresolved_indirect_site(self, block_id: str) -> bool:
        block = self.acg.blocks.get(block_id)
        if block is None:
            return False
        for item in self.acg.metadata.get("unresolved_indirect_sites", []):
            if not isinstance(item, dict):
                continue
            if str(item.get("module", "")) != block.module:
                continue
            rva = parse_int(item.get("rva"), None)
            if rva is not None and block.rva <= rva < block.rva + max(block.size, 1):
                return True
        return False

    def _materialize_indirect_targets(
        self,
        project: Any,
        source_state: Any,
        successors: Sequence[Any],
        edges: Sequence[ACGEdgeRecord],
        existing: Sequence[Any],
        next_functions: Set[str],
    ) -> List[Any]:
        values = []
        call_states = [state for state in successors if str(state.history.jumpkind) == "Ijk_Call"]
        if not call_states:
            self._incomplete("indirect-call-successor-unavailable")
            return []
        for edge in edges:
            address = self._node_address(project, edge.target)
            if address is None:
                self._incomplete("indirect-target-module-unavailable:%s" % edge.id)
                continue
            for base in call_states:
                target_expression = self._plugin(base).indirect_target
                if target_expression is None:
                    target_expression = base.history.jump_target
                if target_expression is None:
                    self._incomplete("indirect-target-expression-unavailable")
                    continue
                candidate = base.copy()
                candidate.add_constraints(target_expression == address)
                if not candidate.solver.satisfiable():
                    continue
                candidate.regs.ip = address
                self._plugin(candidate).selected_edge = edge.id
                if self._plan is not None:
                    self._remember_input_control_dependency(project, edge.source, candidate, edges, self._plan)
                values.append(candidate)
        return values

    def _next_checkpoint_functions(
        self, state: Any, checkpoints: Sequence[AuditEvent], plan: BindingPlan
    ) -> Set[str]:
        index = self._plugin(state).checkpoint_index
        if index >= len(checkpoints):
            return set()
        event_id = checkpoints[index].id
        return {binding.function_id for binding in plan.bindings if binding.event_id == event_id}

    def _function_reaches(self, source: str, targets: Set[str]) -> bool:
        if source in targets:
            return True
        adjacency: Dict[str, Set[str]] = {}
        for edge in self.acg.acg_edges():
            adjacency.setdefault(edge.source_function, set()).add(edge.target_function)
        pending = [source]
        seen = {source}
        while pending:
            item = pending.pop()
            for target in adjacency.get(item, set()):
                if target in targets:
                    return True
                if target not in seen:
                    seen.add(target)
                    pending.append(target)
        return False

    def _block_for_state(self, project: Any, state: Any) -> Optional[Any]:
        address = self._state_address(state)
        module, rva = self._relative(project, address)
        return self.acg.block_at(module, rva) if module else None

    def _function_for_address(self, project: Any, address: int) -> Optional[Any]:
        module, rva = self._relative(project, address)
        return self.acg.function_at(module, rva) if module else None

    def _fault_location_matches(self, project: Any, state: Any, event: AuditEvent) -> bool:
        recorded = event.callsite or parse_int(event.fault.get("address"), None)
        if recorded is None:
            return False
        module = str(event.metadata.get("module", ""))
        base = int(event.metadata.get("module_base", 0))
        if module and base:
            expected = self._module_address(project, module, int(recorded) - base)
        else:
            expected = int(recorded)
        current = self._state_address(state)
        block = self._block_for_state(project, state)
        if block is None or expected is None:
            return current == expected
        block_address = self._node_address(project, block.id)
        return block_address is not None and block_address <= expected < block_address + max(block.size, 1)

    def _fault_dependency_matches(self, state: Any) -> bool:
        expressions: List[Any] = [state.regs.ip]
        for owner, name in (
            (state.history, "jump_target"),
            (state.history, "jump_guard"),
            (state.inspect, "mem_read_address"),
            (state.inspect, "mem_write_address"),
            (state.inspect, "address_concretization_expr"),
        ):
            try:
                expression = getattr(owner, name)
            except Exception:
                expression = None
            if expression is not None:
                expressions.append(expression)
        return any(self._depends_on_input(state, expression) for expression in expressions)

    def _node_address(self, project: Any, node: str) -> Optional[int]:
        if node in self.acg.blocks:
            item = self.acg.blocks[node]
        elif node in self.acg.functions:
            item = self.acg.functions[node]
        else:
            return None
        return self._module_address(project, item.module, item.rva)

    @staticmethod
    def _module_address(project: Any, module: str, rva: int) -> Optional[int]:
        for obj in project.loader.all_objects:
            if Path(str(obj.binary or "")).name == module or obj.binary == module:
                return int(obj.mapped_base) + rva
        if module in {"", "main"} and project.loader.main_object is not None:
            return int(project.loader.main_object.mapped_base) + rva
        return None

    @staticmethod
    def _state_address(state: Any) -> int:
        try:
            return int(state.solver.eval(state.regs.ip))
        except Exception:
            return int(state.addr)

    @staticmethod
    def _relative(project: Any, address: int) -> Tuple[str, int]:
        obj = project.loader.find_object_containing(address)
        if obj is None:
            return "", 0
        return Path(str(obj.binary or "main")).name, address - int(obj.mapped_base)

    @staticmethod
    def _record_path(state: Any, function_id: str) -> None:
        from .angr_extensions import compass_state

        path = list(compass_state(state).path)
        if not path or path[-1] != function_id:
            path.append(function_id)
            compass_state(state).path = path

    def _remember_input_control_dependency(
        self, project: Any, source_block: str, state: Any, outgoing: Sequence[ACGEdgeRecord], plan: BindingPlan
    ) -> None:
        try:
            guard = state.history.jump_guard
            target_expression = self._plugin(state).indirect_target
        except Exception:
            return
        if not (self._depends_on_input(state, guard) or self._depends_on_input(state, target_expression)):
            return
        block = self._block_for_state(project, state)
        if block is None:
            return
        branches = [edge for edge in outgoing if edge.kind in {EdgeKind.CFG, EdgeKind.INDIRECT_CALL}]
        alternatives = [edge.target for edge in branches if edge.target not in {block.id, block.function_id}]
        if not alternatives:
            return
        targets = [self.acg.syscall_sites[site_id].block_id for site_id in plan.alternatives.get(plan.current_event.id, []) if site_id in self.acg.syscall_sites]
        for target in targets:
            if self.acg.reachable(block.id, target) and not any(self.acg.reachable(other, target) for other in alternatives):
                plugin = self._plugin(state)
                plugin.control_dependencies.setdefault(plan.current_event.id, []).append({"branch": source_block, "successor": block.id, "target": target})

    @staticmethod
    def _depends_on_input(state: Any, expression: Any) -> bool:
        if expression is None:
            return False
        from .angr_extensions import compass_state

        input_variables = set(compass_state(state).input_variables)
        return bool(input_variables & set(getattr(expression, "variables", set())))

    @staticmethod
    def _integer(value: Any) -> Optional[int]:
        if isinstance(value, str) and value in NAMED_CONSTANTS:
            return NAMED_CONSTANTS[value]
        return parse_int(value, None)

    @staticmethod
    def _location_expression(state: Any, location: str, width: int = 0) -> Optional[Any]:
        if location.startswith("arg:"):
            index = int(location.split(":", 1)[1])
            registers = ARGUMENT_REGISTERS.get(state.arch.name, ARGUMENT_REGISTERS.get(state.arch.name.upper(), ()))
            return getattr(state.regs, registers[index]) if index < len(registers) else None
        if location.startswith("reg:"):
            name = location.split(":", 1)[1]
            return getattr(state.regs, name) if hasattr(state.regs, name) else None
        if location.startswith("mem:"):
            address = ACGGuidedSymbolicExecutor._memory_address(state, location)
            if address is None:
                return None
            return state.memory.load(address, width or state.arch.bytes, endness=state.arch.memory_endness)
        return None

    @staticmethod
    def _memory_address(state: Any, location: str) -> Optional[int]:
        raw = location[len("mem:"):]
        if raw.startswith(("arg:", "reg:")):
            pieces = raw.split("+", 1)
            expression = ACGGuidedSymbolicExecutor._location_expression(state, pieces[0])
            if expression is None:
                return None
            values = state.solver.eval_upto(expression, 2)
            return int(values[0]) + (int(pieces[1], 0) if len(pieces) == 2 else 0) if len(values) == 1 else None
        return parse_int(raw, None)

    @staticmethod
    def _write_location(state: Any, location: str, expression: Any, width: int = 0) -> bool:
        if location.startswith("arg:"):
            index = int(location.split(":", 1)[1])
            registers = ARGUMENT_REGISTERS.get(state.arch.name, ())
            if index < len(registers):
                setattr(state.regs, registers[index], expression)
                return True
        elif location.startswith("reg:"):
            name = location.split(":", 1)[1]
            if hasattr(state.regs, name):
                setattr(state.regs, name, expression)
                return True
        elif location.startswith("mem:"):
            address = ACGGuidedSymbolicExecutor._memory_address(state, location)
            if address is None:
                return False
            state.memory.store(address, expression, size=width or state.arch.bytes, endness=state.arch.memory_endness)
            return True
        return False

    @staticmethod
    def _constrain_string_pointer(state: Any, pointer: Any, value: str) -> bool:
        if state.solver.symbolic(pointer):
            return False
        address = state.solver.eval(pointer)
        data = value.encode("utf-8", errors="surrogateescape") + b"\x00"
        for offset, byte in enumerate(data):
            expression = state.memory.load(address + offset, 1)
            state.add_constraints(expression == byte)
        return state.solver.satisfiable()

    @staticmethod
    def _constrain_buffer(state: Any, address: int, data: bytes) -> bool:
        for offset, byte in enumerate(data):
            expression = state.memory.load(address + offset, 1)
            state.add_constraints(expression == byte)
        return state.solver.satisfiable()

    @staticmethod
    def _same_value(left: Any, right: Any) -> bool:
        left_number = parse_int(left, None)
        right_number = parse_int(right, None)
        if left_number is not None and right_number is not None:
            return left_number == right_number
        return left == right

    @staticmethod
    def _deduplicate(states: Sequence[Any]) -> List[Any]:
        seen = set()
        values = []
        for state in states:
            if id(state) not in seen:
                seen.add(id(state))
                values.append(state)
        return values
