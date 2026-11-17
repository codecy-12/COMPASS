from __future__ import annotations

from typing import List

from ..schema import AuditEvent, CatalogEntry, ExecutionModel
from .provenance import ProvenanceGraph


class LightweightCausalityTracker:
    """Execution-unit tracing for serial and context-isolated deployments."""

    def trace(
        self,
        current: AuditEvent,
        graph: ProvenanceGraph,
        catalog: CatalogEntry,
    ) -> List[AuditEvent]:
        if catalog.model not in {ExecutionModel.SERIAL, ExecutionModel.CONTEXT_ISOLATED}:
            return []
        task_key = current.metadata.get("task_id", current.metadata.get("session_id"))
        inputs = graph.prior_input_events(current.id)
        if task_key is not None:
            matched = [
                event for event in inputs
                if event.metadata.get("task_id", event.metadata.get("session_id")) == task_key
            ]
            if matched:
                return matched
        if catalog.model == ExecutionModel.CONTEXT_ISOLATED:
            matched = [event for event in inputs if event.pid == current.pid and event.tid == current.tid]
            if current.handle:
                same_object = [event for event in matched if event.handle and event.handle.object_id == current.handle.object_id]
                if same_object:
                    matched = same_object
            return matched[-1:] if matched else []
        same_thread = [event for event in inputs if event.pid == current.pid and event.tid == current.tid]
        return same_thread[-1:] if same_thread else []
