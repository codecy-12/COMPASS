from __future__ import annotations

from pathlib import Path
from typing import Optional, Sequence

from ..acg import ACG
from ..config import CompassConfig
from ..errors import AnalysisError
from .align import AlignmentCompletion
from .baseline import BaselineRequestRegionAnalyzer
from .dataflow import CrossContextRecoverer
from .dynamic import DynamicCatcher
from .entry import ExternalInputEntryFinder
from .static import StaticAnalyser


class OfflinePipeline:
    """Runs Static Analyser, Dynamic Catcher, then Alignment & Completion."""

    def __init__(self, config: CompassConfig) -> None:
        self.config = config

    def build(
        self,
        binary: Path,
        dynamic_traces: Sequence[Path],
        output: Path,
        mappings: Optional[Path] = None,
    ) -> ACG:
        static = StaticAnalyser(self.config.static).analyse(binary)
        capture = DynamicCatcher(self.config.dynamic).load(dynamic_traces, mappings)
        if not capture.runs:
            raise AnalysisError("Dynamic Catcher received no preparation records")
        baseline_regions = BaselineRequestRegionAnalyzer().analyze(static.graph, capture)
        cross_recoverer = CrossContextRecoverer()
        cross_context = cross_recoverer.recover(capture, baseline_regions)
        graph = AlignmentCompletion().complete(
            static.graph,
            capture,
            capture.indirect_transfers,
            cross_context,
        )
        entries = ExternalInputEntryFinder().find(graph, capture)
        if not entries:
            raise AnalysisError(
                "no External-Input Entry Function was stable across at least two controlled replays"
            )
        for entry in entries:
            graph.add_entry(entry)
        graph.metadata["static_backend"] = static.backend
        graph.metadata["verified_direct_calls"] = static.verified_direct_calls
        graph.metadata["unresolved_indirect_sites"] = static.unresolved_indirect_sites
        graph.metadata["rejected_cross_context_candidates"].extend(cross_recoverer.rejected)
        graph.save(output)
        return graph
