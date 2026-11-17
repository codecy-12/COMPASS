from __future__ import annotations

from collections import deque
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Sequence, Set, Tuple, Union

from ..acg import ACG
from ..config import CompassConfig
from ..errors import AnalysisError, BackendUnavailable
from ..schema import AuditEvent, EventDirection, ExecutionModel, InvestigationResult, ProcessProfile, ProvenanceEdge, ResolutionStatus
from ..util import load_json, parse_int
from .binding import ArgumentBinder, AuditBindingIndex
from .candidates import CandidatePredecessorAcquirer
from .prefix import PathPrefixInitializer
from .provenance import ProvenanceGraph
from .symbolic import ACGGuidedSymbolicExecutor


class GuidedPredecessorVerifier:
    def __init__(self, config: CompassConfig, acg: ACG, provenance: ProvenanceGraph) -> None:
        self.config = config
        self.acg = acg
        self.acquirer = CandidatePredecessorAcquirer(config.investigation)
        self.binder = ArgumentBinder()
        self.binding_index: AuditBindingIndex = self.binder.match_audit(provenance.events.values(), acg)
        self.initializer = PathPrefixInitializer(config.investigation)
        self.executor = ACGGuidedSymbolicExecutor(acg, config.investigation.simprocedure_manifest)
        self.verified_event_ids: Set[str] = set()
        self.retained_event_ids: Set[str] = set()
        self.retention_reasons: Dict[str, List[str]] = {}
        self._projects: Dict[Tuple[Any, ...], Any] = {}

    def verify(
        self,
        current: AuditEvent,
        model: Optional[ExecutionModel],
        profile: ProcessProfile,
        provenance: ProvenanceGraph,
    ) -> Tuple[List[AuditEvent], Dict[str, List[str]]]:
        self.verified_event_ids = set()
        self.retained_event_ids = set()
        self.retention_reasons = {}
        candidates = self.acquirer.acquire(current, model, provenance, self.acg, self.binding_index)
        paths: Dict[str, List[str]] = {}
        incomplete: Dict[str, List[str]] = {}
        for candidate in candidates:
            reasons = list(self.acquirer.incomplete_reasons)
            if candidate.metadata.get("incomplete"):
                reasons.append(str(candidate.metadata.get("incomplete_reason", "incomplete-acfg-path")))
            entries = self._entries(candidate, profile)
            if not entries:
                reasons.append("missing-input-prefix")
            for entry in entries:
                try:
                    plan = self.binder.build_plan(candidate, current, entry, provenance, self.acg, self.binding_index)
                    if any(event.id not in plan.alternatives for event in candidate.events):
                        reasons.append("unmatched-input-binding")
                        continue
                    if current.direction != EventDirection.FAULT and current.id not in plan.alternatives:
                        reasons.append("unmatched-output-binding")
                        continue
                    snapshot = load_json(Path(entry.prefix_snapshot).expanduser())
                    base_address = parse_int(snapshot.get("metadata", {}).get("main_module_base"), 0) or 0
                    module_bases = {str(name): parse_int(value, 0) or 0 for name, value in dict(snapshot.get("module_bases", {})).items()}
                    module_paths = {str(name): str(value) for name, value in dict(snapshot.get("metadata", {}).get("module_paths", {})).items()}
                    key = (self.acg.binary, base_address, tuple(sorted(module_bases.items())), tuple(sorted(module_paths.items())))
                    if key not in self._projects:
                        self._projects[key] = self.executor.open_project(base_address or None, module_bases, module_paths)
                    project = self._projects[key]
                    state = self.initializer.initialize(project, plan, self.acg)
                    outcome = self.executor.execute(project, state, plan)
                    if outcome.accepted:
                        self.verified_event_ids.update(event.id for event in candidate.events)
                        paths[candidate.id] = outcome.function_path
                        reasons = []
                        break
                    if not getattr(outcome, "complete", False):
                        reasons.extend(getattr(outcome, "reasons", []) or ["incomplete-symbolic-search"])
                except (AnalysisError, BackendUnavailable, OSError, ValueError) as exc:
                    reasons.append("%s:%s" % (type(exc).__name__, exc))
            if reasons:
                for event in candidate.events:
                    if event.id not in self.verified_event_ids:
                        incomplete[event.id] = sorted(set(reasons))
        if self.verified_event_ids:
            self.retained_event_ids = set(incomplete) - self.verified_event_ids
        else:
            self.retained_event_ids = {event.id for candidate in candidates for event in candidate.events}
        for event_id in self.retained_event_ids:
            self.retention_reasons[event_id] = incomplete.get(event_id, ["no-verified-predecessor"])
        ids = self.verified_event_ids | self.retained_event_ids
        return sorted((provenance.events[event_id] for event_id in ids), key=lambda event: (event.sequence, event.id)), paths

    def _entries(self, candidate, profile):
        if profile.build_id and self.acg.build_id and profile.build_id.lower() != self.acg.build_id.lower():
            return []
        sites = set(candidate.metadata.get("input_site_ids", []))
        entries = self.acg.entry_candidates(profile.key, self._input_class(candidate.first_event))
        result = []
        for entry in entries:
            if entry.build_id and self.acg.build_id and entry.build_id != self.acg.build_id:
                continue
            if entry.input_site_id and sites and entry.input_site_id not in sites:
                continue
            if not entry.input_site_id and sites and not any(
                self.acg.reachable(entry.function_id, self.acg.syscall_sites[site].block_id)
                for site in sites if site in self.acg.syscall_sites
            ):
                continue
            result.append(entry)
        return result

    @staticmethod
    def _input_class(event: AuditEvent) -> str:
        if event.handle:
            if event.handle.kind.value == "socket":
                return "network"
            if event.handle.kind.value in {"pipe", "ipc"}:
                return "ipc"
            if event.handle.kind.value == "file":
                return "file"
        return "network" if event.syscall.startswith("recv") else "file"


class AttackInvestigator:
    def __init__(
        self,
        config: CompassConfig,
        acg: Union[ACG, Sequence[ACG]],
        provenance: ProvenanceGraph,
        catalog: Optional[Any] = None,
        default_profile: Optional[ProcessProfile] = None,
    ) -> None:
        self.config = config
        self.acgs = [acg] if isinstance(acg, ACG) else list(acg)
        if not self.acgs or any(not isinstance(graph, ACG) for graph in self.acgs):
            raise AnalysisError("investigation requires at least one ACFG")
        self.acg = self.acgs[0]
        self.provenance = provenance
        self.default_profile = default_profile
        self._verifiers = {id(graph): GuidedPredecessorVerifier(config, graph, provenance) for graph in self.acgs}
        self.guided = self._verifiers[id(self.acg)]

    def investigate(self, symptom_event: str) -> InvestigationResult:
        if symptom_event not in self.provenance.events:
            raise KeyError("symptom event does not exist: %s" % symptom_event)
        queue: Deque[str] = deque([symptom_event])
        visited: Set[str] = set()
        incident_events: Set[str] = set()
        dependencies: Dict[Tuple[str, str], str] = {}
        paths: Dict[str, List[str]] = {}
        reasons: Set[str] = set()
        retained = False
        incomplete = False
        routes: Dict[str, Dict[str, str]] = {}
        while queue:
            event_id = queue.pop()
            if event_id in visited:
                continue
            visited.add(event_id)
            incident_events.add(event_id)
            current = self.provenance.events[event_id]
            if current.direction == EventDirection.INPUT:
                if self.provenance.is_external_input(event_id):
                    continue
                predecessors = self.provenance.object_predecessors(event_id)
                relations = {event.id: "object_transfer" for event in predecessors}
                candidate_paths: Dict[str, List[str]] = {}
            else:
                selected, reason = self._select_graph(current)
                if selected is None:
                    predecessors = [event for event in self.provenance.prior_input_events(current.id) if event.pid == current.pid]
                    candidate_paths = {}
                    relations = {event.id: "retained_causality" for event in predecessors}
                    reasons.add(reason)
                    incomplete = True
                    routes[event_id] = {"status": "unmatched", "reason": reason}
                else:
                    guided = self._verifiers[id(selected)]
                    profile = self._profile_for_graph(current, selected)
                    predecessors, candidate_paths = guided.verify(current, None, profile, self.provenance)
                    relations = {
                        event.id: "verified_causality" if event.id in guided.verified_event_ids else "retained_causality"
                        for event in predecessors
                    }
                    for event_reasons in guided.retention_reasons.values():
                        reasons.update(event_reasons)
                    routes[event_id] = {"status": "selected", "binary": selected.binary, "build_id": selected.build_id, "profile_key": profile.key}
            paths.update(candidate_paths)
            if not predecessors:
                incomplete = True
                reasons.add("no-available-predecessor")
            for predecessor in predecessors:
                relation = relations[predecessor.id]
                dependencies[(predecessor.id, event_id)] = relation
                retained = retained or relation == "retained_causality"
                incident_events.add(predecessor.id)
                if predecessor.id not in visited:
                    queue.append(predecessor.id)
        nodes, edges = self.provenance.incident_subgraph(incident_events)
        for (source_event, target_event), relation in sorted(dependencies.items()):
            source_edge = self.provenance.edge_for_event(source_event)
            target_edge = self.provenance.edge_for_event(target_event)
            if source_edge is None or target_edge is None:
                continue
            edges.append(ProvenanceEdge(
                id="%s:%s:%s" % (relation, source_event, target_event),
                source=source_edge.source,
                target=target_edge.target,
                event_id="",
                operation=relation,
                metadata={"predecessor_event": source_event, "current_event": target_event, "verified": relation != "retained_causality"},
            ))
        verified = [pair for pair, relation in sorted(dependencies.items()) if relation == "verified_causality"]
        return InvestigationResult(
            symptom_event=symptom_event,
            status=ResolutionStatus.UNRESOLVED if retained or incomplete else ResolutionStatus.RESOLVED,
            verified_predecessors=sorted({source for source, _ in verified}),
            attack_nodes=nodes,
            attack_edges=edges,
            candidate_paths=paths,
            metadata={
                "verified_dependencies": verified,
                "retained_dependencies": [pair for pair, relation in sorted(dependencies.items()) if relation == "retained_causality"],
                "object_dependencies": [pair for pair, relation in sorted(dependencies.items()) if relation == "object_transfer"],
                "analysis_reasons": sorted(reasons),
                "acfg_routes": routes,
            },
        )

    @staticmethod
    def _name(value: Any) -> str:
        return str(value or "").replace("\\", "/").removesuffix(" (deleted)")

    def _named_graphs(self, values: Sequence[ACG], name: str) -> List[ACG]:
        normalized = self._name(name)
        exact = [graph for graph in values if self._name(graph.binary) == normalized]
        if exact:
            return exact
        basename = normalized.rsplit("/", 1)[-1]
        return [graph for graph in values if graph.binary and self._name(graph.binary).rsplit("/", 1)[-1] == basename]

    def _select_graph(self, event: AuditEvent) -> Tuple[Optional[ACG], str]:
        values = list(self.acgs)
        recorded = event.metadata.get("deployment_profile", {})
        recorded = recorded if isinstance(recorded, dict) else {}
        build_id = str(event.metadata.get("build_id") or recorded.get("build_id") or "")
        if build_id:
            values = [graph for graph in values if graph.build_id.lower() == build_id.lower()]
            if not values:
                return None, "missing-acfg-for-build:%s" % build_id
            if len(values) == 1:
                return values[0], ""
        profile_key = str(event.metadata.get("profile_key") or recorded.get("profile_key") or recorded.get("preparation_key") or "")
        if profile_key:
            matches = [graph for graph in values if any(entry.profile_key == profile_key for entry in graph.entries.values())]
            if matches:
                values = matches
                if len(values) == 1:
                    return values[0], ""
            elif len(values) > 1:
                return None, "missing-acfg-for-profile:%s" % profile_key
        executable = self._name(event.metadata.get("executable") or recorded.get("executable"))
        if executable:
            values = self._named_graphs(values, executable)
            if not values:
                return None, "missing-acfg-for-executable:%s" % executable
            if len(values) == 1:
                return values[0], ""
        process = self._name(event.process)
        if process:
            matches = self._named_graphs(values, process)
            if not matches and len(values) == 1 and not values[0].binary and not build_id and not executable:
                matches = values
            if not matches:
                return None, "missing-acfg-for-process:%s" % process
            values = matches
        if len(values) == 1:
            return values[0], ""
        return None, "ambiguous-acfg-for-event:%s" % event.id

    def _profile_for_graph(self, event: AuditEvent, graph: ACG) -> ProcessProfile:
        profile = self.default_profile
        recorded = self._profile(event)
        if profile is not None:
            build_matches = bool(profile.build_id and graph.build_id and profile.build_id.lower() == graph.build_id.lower())
            build_conflicts = bool(profile.build_id and graph.build_id and profile.build_id.lower() != graph.build_id.lower())
            named = bool(profile.executable and self._named_graphs([graph], profile.executable))
            keyed = bool(profile.preparation_key and any(entry.profile_key == profile.preparation_key for entry in graph.entries.values()))
            name_conflicts = bool(profile.executable and graph.binary and not named)
            key_conflicts = bool(profile.preparation_key and ((recorded.preparation_key and recorded.preparation_key != profile.preparation_key) or (graph.entries and not keyed)))
            if not build_conflicts and not name_conflicts and not key_conflicts and (build_matches or named or keyed):
                return profile
        return recorded

    @staticmethod
    def _profile(event: AuditEvent) -> ProcessProfile:
        metadata = event.metadata
        recorded = metadata.get("deployment_profile")
        if isinstance(recorded, dict):
            return ProcessProfile.from_dict(recorded)
        return ProcessProfile(
            build_id=str(metadata.get("build_id", "")),
            executable=str(metadata.get("executable", event.process)),
            role=str(metadata.get("process_role", event.process)),
            command_line=[str(value) for value in metadata.get("command_line", [])],
            modules=[str(value) for value in metadata.get("modules", [])],
            concurrency_module=str(metadata.get("concurrency_module", "")),
            concurrency=dict(metadata.get("concurrency", {})),
            platform=str(metadata.get("platform", "linux")),
            preparation_key=str(metadata.get("profile_key", "")),
        )
