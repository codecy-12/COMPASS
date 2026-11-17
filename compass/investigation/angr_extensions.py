from __future__ import annotations

from copy import deepcopy
from typing import Any

import angr


class CompassState(angr.SimStatePlugin):
    def __init__(self) -> None:
        super().__init__()
        self.checkpoint_index = 0
        self.matched_events = []
        self.path = []
        self.input_variables = set()
        self.thread_id = None
        self.handoff_edges = []
        self.object_mappings = {}
        self.log_progress = {}
        self.context_history = []
        self.handoff_reads = []
        self.selected_edge = ""
        self.indirect_target = None
        self.exit_target = None
        self.exit_guard = None
        self.control_dependencies = {}
        self.binding_expressions = []
        self.last_operation = ""
        self.last_result = None
        self.last_object = ""
        self.entry_id = ""
        self.accepted = False
        self.step_fault = ""

    @angr.SimStatePlugin.memo
    def copy(self, memo: Any) -> "CompassState":
        result = CompassState()
        for name, value in self.__dict__.items():
            if name != "state":
                setattr(result, name, deepcopy(value, memo))
        return result


def compass_state(state: Any) -> CompassState:
    if not state.has_plugin("compass"):
        state.register_plugin("compass", CompassState())
    return state.get_plugin("compass")


def capture_exit(state: Any) -> None:
    plugin = compass_state(state)
    plugin.exit_target = state.inspect.exit_target
    plugin.exit_guard = state.inspect.exit_guard
    if str(state.inspect.exit_jumpkind) == "Ijk_Call":
        plugin.indirect_target = state.inspect.exit_target


def capture_handoff_register(state: Any) -> None:
    plugin = compass_state(state)
    if not plugin.handoff_reads:
        return
    instruction = state.scratch.ins_addr
    offset = state.inspect.reg_write_offset
    offsets = state.solver.eval_upto(offset, 2) if not isinstance(offset, int) else [offset]
    if len(offsets) != 1:
        return
    for index, item in enumerate(list(plugin.handoff_reads)):
        if item.get("instruction") != instruction or item.get("register_offset") != int(offsets[0]):
            continue
        expression = item["expression"]
        bits = state.inspect.reg_write_expr.size()
        if expression.size() < bits:
            expression = expression.zero_extend(bits - expression.size())
        elif expression.size() > bits:
            expression = expression[bits - 1:0]
        state.inspect.reg_write_expr = expression
        del plugin.handoff_reads[index]
        break


def capture_handoff_memory(state: Any) -> None:
    plugin = compass_state(state)
    if not plugin.handoff_reads:
        return
    instruction = state.scratch.ins_addr
    address = state.inspect.mem_read_address
    addresses = state.solver.eval_upto(address, 2) if not isinstance(address, int) else [address]
    if len(addresses) != 1:
        return
    for index, item in enumerate(list(plugin.handoff_reads)):
        if item.get("instruction") != instruction or item.get("address") != int(addresses[0]):
            continue
        expression = item["expression"]
        if expression.size() != state.inspect.mem_read_expr.size():
            continue
        state.inspect.mem_read_expr = expression
        del plugin.handoff_reads[index]
        break


class ACFGExplorationTechnique(angr.exploration_techniques.ExplorationTechnique):
    def __init__(self, executor: Any, project: Any, plan: Any, checkpoints: Any) -> None:
        super().__init__()
        self.executor = executor
        self.project = project
        self.plan = plan
        self.checkpoints = checkpoints
        self.steps = 0

    def setup(self, simgr: Any) -> None:
        simgr.stashes.setdefault("deferred", [])
        simgr.stashes.setdefault("found", [])
        self._schedule(simgr, "active")

    def step(self, simgr: Any, stash: str = "active", **kwargs: Any) -> Any:
        self._schedule(simgr, stash)
        if not simgr.stashes.get(stash):
            return simgr
        simgr = simgr.step(stash=stash, **kwargs)
        self.steps += 1
        self._schedule(simgr, stash)
        return simgr

    def step_state(self, simgr: Any, state: Any, **kwargs: Any) -> Any:
        successors = self.executor._query_successors(
            self.project, state, self.checkpoints, self.plan
        )
        if self.executor._accepted_state is not None:
            simgr.stashes["found"].append(self.executor._accepted_state)
        return {None: successors}

    @staticmethod
    def _schedule(simgr: Any, stash: str) -> None:
        active = simgr.stashes.setdefault(stash, [])
        deferred = simgr.stashes.setdefault("deferred", [])
        if len(active) > 1:
            deferred.extend(reversed(active[1:]))
            del active[1:]
        if not active and deferred:
            active.append(deferred.pop())
