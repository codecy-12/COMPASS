from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping

from ..errors import AnalysisError
from ..util import load_json, parse_int


class SimProcedureRegistry:
    """Installs declarative library models in addition to angr's built-in procedures."""

    def apply(self, project: Any, manifest_path: str) -> None:
        if not manifest_path:
            return
        path = Path(manifest_path).expanduser()
        if not path.is_file():
            raise AnalysisError("SimProcedure manifest does not exist: %s" % path)
        raw = load_json(path)
        values = raw.get("procedures", []) if isinstance(raw, Mapping) else raw
        for specification in values:
            if not isinstance(specification, Mapping):
                continue
            procedure = self._procedure(dict(specification))
            symbol = str(specification.get("symbol", ""))
            if symbol:
                project.hook_symbol(symbol, procedure, replace=True)
                continue
            address = parse_int(specification.get("address"), None)
            rva = parse_int(specification.get("rva"), None)
            if address is None and rva is not None:
                address = int(project.loader.main_object.mapped_base) + rva
            if address is None:
                raise AnalysisError("SimProcedure entry requires symbol, address, or rva")
            project.hook(address, procedure, replace=True)

    @staticmethod
    def install_io(project: Any, address: int, size: int, executor: Any) -> None:
        import angr
        import claripy

        from .angr_extensions import compass_state

        class ObservedIO(angr.SimProcedure):
            NO_RET = True
            ADDS_EXITS = True

            def run(self) -> None:
                plugin = compass_state(self.state)
                event = executor._events[plugin.log_progress["pending_event"]]
                if executor._model_io(self.state, event):
                    self.successors.add_successor(
                        self.state, address + size, claripy.true(), "Ijk_Boring"
                    )

        project.hook(address, ObservedIO(display_name="COMPASSObservedIO"), length=size, replace=True)

    @staticmethod
    def _procedure(specification: Dict[str, Any]) -> Any:
        try:
            import angr  # type: ignore
            import claripy
        except ImportError as exc:
            raise AnalysisError("angr is required to instantiate SimProcedures") from exc

        class ManifestProcedure(angr.SimProcedure):  # type: ignore
            ARGS_MISMATCH = True

            def run(self, *arguments: Any, **kwargs: Any) -> Any:
                for effect in specification.get("effects", []):
                    kind = str(effect.get("kind", ""))
                    if kind == "copy":
                        destination = arguments[int(effect["destination_argument"])]
                        source = arguments[int(effect["source_argument"])]
                        if "length_argument" in effect:
                            length = arguments[int(effect["length_argument"])]
                            if self.state.solver.symbolic(length):
                                length = int(effect.get("maximum_length", 4096))
                            else:
                                length = self.state.solver.eval(length)
                        else:
                            length = int(effect.get("length", 0))
                        data = self.state.memory.load(source, int(length))
                        self.state.memory.store(destination, data)
                    elif kind == "store":
                        destination = arguments[int(effect["destination_argument"])]
                        value = parse_int(effect.get("value"), 0) or 0
                        width = int(effect.get("width", self.state.arch.bytes))
                        self.state.memory.store(
                            destination,
                            claripy.BVV(value, width * 8),
                            endness=self.state.arch.memory_endness,
                        )
                return_value = specification.get("return", 0)
                if isinstance(return_value, Mapping) and "argument" in return_value:
                    return arguments[int(return_value["argument"])]
                integer = parse_int(return_value, 0) or 0
                return claripy.BVV(integer, self.state.arch.bits)

        argument_indices = []
        for effect in specification.get("effects", []):
            for name, value in effect.items():
                if name.endswith("_argument"):
                    argument_indices.append(int(value))
        returned = specification.get("return")
        if isinstance(returned, Mapping) and "argument" in returned:
            argument_indices.append(int(returned["argument"]))
        argument_count = int(specification.get("num_args", max(argument_indices, default=-1) + 1))
        return ManifestProcedure(num_args=argument_count, display_name=str(specification.get("name", specification.get("symbol", "COMPASSModel"))))
