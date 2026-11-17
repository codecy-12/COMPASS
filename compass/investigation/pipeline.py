from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Sequence, Set, Union

from ..acg import ACG
from ..config import CompassConfig
from ..errors import AnalysisError
from ..schema import InvestigationResult, ProcessProfile
from ..util import dump_json, load_json
from ..monitor.collector import RuntimeCollector
from .engine import AttackInvestigator
from .provenance import ProvenanceGraphBuilder


class InvestigationPipeline:
    def __init__(self, config: CompassConfig) -> None:
        self.config = config

    def run(
        self,
        acg_path: Union[Path, Sequence[Path]],
        log_path: Path,
        catalog_path: Optional[Path],
        symptom_event: str,
        output: Path,
        profile_path: Optional[Path] = None,
    ) -> InvestigationResult:
        graphs = self._load_graphs(acg_path)
        events = RuntimeCollector.load(log_path)
        provenance = ProvenanceGraphBuilder().build(events)
        profile = ProcessProfile.from_dict(load_json(profile_path)) if profile_path else None
        result = AttackInvestigator(self.config, graphs, provenance, default_profile=profile).investigate(symptom_event)
        dump_json(output, result.to_dict())
        return result

    @staticmethod
    def _load_graphs(paths: Union[Path, Sequence[Path]]) -> List[ACG]:
        values = [paths] if isinstance(paths, (str, Path)) else list(paths)
        graphs = []
        loaded: Set[Path] = set()
        active: Set[Path] = set()
        def visit(path: Path) -> None:
            path = Path(path).expanduser().resolve()
            if path in active:
                raise AnalysisError("cyclic ACFG bundle: %s" % path)
            if path in loaded:
                return
            raw = load_json(path)
            if not isinstance(raw, dict):
                raise AnalysisError("ACFG or bundle must be a JSON object")
            active.add(path)
            if "acfgs" in raw:
                members = raw["acfgs"]
                if not isinstance(members, list) or not members or any(not isinstance(item, str) or not item for item in members):
                    raise AnalysisError("ACFG bundle requires a nonempty acfgs path array")
                for member in members:
                    candidate = Path(member).expanduser()
                    visit(candidate if candidate.is_absolute() else path.parent / candidate)
            else:
                graph = ACG.from_dict(raw)
                graph.validate()
                graphs.append(graph)
            active.remove(path)
            loaded.add(path)
        for value in values:
            visit(Path(value))
        if not graphs:
            raise AnalysisError("investigation requires at least one ACFG")
        return graphs
