from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Mapping, Sequence

from ..errors import AnalysisError
from ..schema import AuditEvent, CatalogEntry, ProcessProfile
from ..util import dump_json, load_json, primitive


class ExecutionModelCatalog:
    def __init__(self, entries: Sequence[CatalogEntry] = ()) -> None:
        self.entries: Dict[str, CatalogEntry] = {entry.profile_key: entry for entry in entries}

    def lookup(self, profile: ProcessProfile) -> CatalogEntry:
        exact = self.entries.get(profile.key)
        if exact:
            return exact
        compatible = [
            entry for key, entry in self.entries.items()
            if profile.build_id and key.startswith(profile.build_id + "|")
        ]
        if len(compatible) == 1:
            return compatible[0]
        raise AnalysisError("no validated execution-model catalog entry for profile %s" % profile.key)

    def add(self, entry: CatalogEntry) -> None:
        self.entries[entry.profile_key] = entry

    def save(self, path: Path) -> None:
        dump_json(path, {"entries": [primitive(item) for item in sorted(self.entries.values(), key=lambda x: x.profile_key)]})

    @classmethod
    def load(cls, path: Path) -> "ExecutionModelCatalog":
        raw = load_json(path)
        values = raw.get("entries", []) if isinstance(raw, Mapping) else raw
        return cls([CatalogEntry.from_dict(item) for item in values])


class DeploymentProfiler:
    def from_event(self, event: AuditEvent) -> ProcessProfile:
        metadata = event.metadata
        profile_raw = metadata.get("deployment_profile")
        if isinstance(profile_raw, Mapping):
            return ProcessProfile.from_dict(profile_raw)
        return ProcessProfile(
            build_id=str(metadata.get("build_id", "")),
            executable=str(metadata.get("executable", event.process)),
            role=str(metadata.get("process_role", event.process)),
            command_line=[str(item) for item in metadata.get("command_line", [])],
            modules=[str(item) for item in metadata.get("modules", [])],
            concurrency_module=str(metadata.get("concurrency_module", "")),
            concurrency=dict(metadata.get("concurrency", {})),
            platform=str(metadata.get("platform", "linux")),
        )


class CatalogBuilder:
    """Creates and validates catalog entries; LLM output remains a proposal."""

    def propose(self, advisor: Any, profile: ProcessProfile, documentation: str) -> CatalogEntry:
        return CatalogEntry.from_dict(advisor.propose(profile, documentation))

    def validate(self, proposal: CatalogEntry, trace_facts: Mapping[str, Any]) -> CatalogEntry:
        observed_model = str(trace_facts.get("model", "unknown"))
        if observed_model != proposal.model.value:
            raise AnalysisError(
                "execution-model proposal %s disagrees with validated runtime facts %s"
                % (proposal.model.value, observed_model)
            )
        proposal.runtime_validation = "validated"
        proposal.evidence_status = "validated"
        proposal.evidence.append({"kind": "runtime_trace", "value": dict(trace_facts)})
        return proposal
