from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from ..acg import ACG
from ..util import parse_int
from .dynamic import DynamicCaptureResult, DynamicRun


Location = Tuple[str, int]


class BaselineRequestRegionAnalyzer:
    def __init__(self, maximum_period: int = 64, minimum_repetitions: int = 2) -> None:
        if not isinstance(maximum_period, int) or isinstance(maximum_period, bool) or maximum_period < 1:
            raise ValueError("maximum_period must be a positive integer")
        if not isinstance(minimum_repetitions, int) or isinstance(minimum_repetitions, bool) or minimum_repetitions < 2:
            raise ValueError("minimum_repetitions must be an integer of at least two")
        self.maximum_period = maximum_period
        self.minimum_repetitions = minimum_repetitions

    def analyze(self, graph: ACG, capture: DynamicCaptureResult) -> Dict[str, Any]:
        normalized = [self._normalize(graph, run) for run in capture.runs]
        diagnostics: List[str] = []
        roles: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        patterns: List[Dict[str, Any]] = []
        regions: List[Dict[str, Any]] = []
        for run in normalized:
            if not run["baseline"] or not run["eligible"]:
                continue
            for context in run["contexts"]:
                cycles = self._cycles([event["location"] for event in context["events"]])
                context["baseline_cycles"] = len(cycles)
                if not cycles:
                    continue
                signature = tuple(sorted(cycles))
                key = run["profile_key"], run["scope_key"], signature
                if key not in roles:
                    role_id = "wait-role:" + hashlib.sha256(repr(key).encode("utf-8")).hexdigest()[:16]
                    roles[key] = {"id": role_id, "profile_key": run["profile_key"], "scope_key": run["scope_key"],
                                  "cycles": signature, "baseline_evidence": []}
                role = roles[key]
                context["role"] = role["id"]
                evidence = {"replay_id": run["replay_id"], "context_id": context["context_id"], "tid": context["tid"],
                            "event_sequences": [event["sequence"] for event in context["events"]]}
                role["baseline_evidence"].append(evidence)
                for cycle, repetitions in cycles.items():
                    patterns.append({"role": role["id"], "profile_key": run["profile_key"], "functions": self._locations(cycle),
                                     "observed_repetitions": repetitions, "baseline_evidence": evidence,
                                     "evidence_kind": "observed-baseline-tandem-repetition"})
        if not any(run["baseline"] for run in normalized):
            diagnostics.append("zero-input-baseline-missing")
        if not roles:
            diagnostics.append("no-complete-recurring-baseline-context")
        for run in normalized:
            diagnostics.extend("%s:%s" % (run["replay_id"], reason) for reason in run["diagnostics"])
            if run["baseline"] or not run["single_input"] or not run["eligible"]:
                continue
            for context in run["contexts"]:
                tokens = [event["location"] for event in context["events"]]
                matches = []
                for role in roles.values():
                    if role["profile_key"] != run["profile_key"] or role["scope_key"] != run["scope_key"]:
                        continue
                    mask, complete_matches = self._subtract(tokens, role["cycles"])
                    if complete_matches:
                        matches.append((role, mask))
                context["candidate_roles"] = [role["id"] for role, _ in matches]
                if len(matches) != 1:
                    context["status"] = "ambiguous" if matches else "unmatched"
                    diagnostics.append("%s:%s:%s-wait-role" % (run["replay_id"], context["context_id"], context["status"]))
                    continue
                role, mask = matches[0]
                context["role"] = role["id"]
                context["status"] = "matched"
                context["removed_event_sequences"] = [event["sequence"] for event, removed in zip(context["events"], mask) if removed]
                index = 0
                while index < len(tokens):
                    if mask[index]:
                        index += 1
                        continue
                    end = index + 1
                    while end < len(tokens) and not mask[end]:
                        end += 1
                    events = context["events"][index:end]
                    end_sequence = events[-1]["sequence"]
                    if end < len(tokens) and context["events"][end]["sequence"] > end_sequence:
                        end_sequence = context["events"][end]["sequence"] - 1
                    regions.append({"id": "request-region:%s:%s:%s:%d" % (run["replay_id"], context["pid"], context["context_id"], index),
                                    "replay_id": run["replay_id"], "profile_key": run["profile_key"],
                                    "context_id": context["context_id"], "tid": context["tid"], "pid": context["pid"],
                                    "role": role["id"], "start_sequence": events[0]["sequence"], "end_sequence": end_sequence,
                                    "functions": self._locations([event["location"] for event in events]),
                                    "event_sequences": [event["sequence"] for event in events],
                                    "event_positions": [event["position"] for event in events],
                                    "eligible": True, "scope": run["scope"], "evidence_kind": "baseline-projection-subtraction",
                                    "causal_proof": False})
                    index = end
        coverage = [{key: run[key] for key in ("replay_id", "profile_key", "scope", "eligible", "complete", "observed_functions", "diagnostics")}
                    for run in normalized]
        run_results = []
        for run in normalized:
            contexts = [{key: value for key, value in context.items() if key != "events"} for context in run["contexts"]]
            run_results.append({"replay_id": run["replay_id"], "profile_key": run["profile_key"], "baseline": run["baseline"],
                                "single_input": run["single_input"], "contexts": contexts})
        result = {"schema_version": 1, "status": "available" if regions else "no-request-regions",
                  "coverage": coverage, "runs": run_results, "patterns": patterns, "regions": regions,
                  "diagnostics": sorted(set(diagnostics)), "complete_program_coverage": False,
                  "use": "heuristic-endpoint-evidence-only"}
        graph.metadata["baseline_request_regions"] = result
        return result

    def _normalize(self, graph: ACG, run: DynamicRun) -> Dict[str, Any]:
        declarations = [record for record in run.records if record.get("kind") == "run_metadata"]
        baseline = any(record.get("phase") == "baseline" or record.get("input_count") == 0 for record in declarations)
        if not baseline:
            baseline = bool(run.records) and all(record.get("phase") == "baseline" or record.get("baseline") for record in run.records)
        counts = [parse_int(record.get("input_count")) for record in declarations if "input_count" in record]
        single_input = bool(counts) and all(count == 1 for count in counts)
        successful = all(record.get("status", "completed") == "completed" for record in declarations)
        traces = [record for record in run.records if record.get("kind") == "function_trace"]
        trace_metadata = [record for record in run.records if record.get("kind") == "function_trace_metadata"]
        completion = [record.get("function_trace_complete") for record in declarations if "function_trace_complete" in record]
        completion.extend(record.get("complete") for record in traces + trace_metadata if "complete" in record)
        completion.extend(record.get("capture_window_complete") for record in trace_metadata
                          if record.get("scope") == "configured-function-projection" and "capture_window_complete" in record)
        lost = sum(parse_int(record.get("lost_events"), 0) or 0 for record in trace_metadata)
        complete = bool(completion) and all(value is True for value in completion) and not lost
        projected = [record for record in trace_metadata if record.get("scope") == "configured-function-projection"]
        scope = "configured-function-projection" if projected else "declared-function-entry-observations"
        projection = sorted({(str(item.get("module", "")), parse_int(item.get("rva"), 0) or 0)
                             for record in projected for item in record.get("function_sites", []) if isinstance(item, Mapping)})
        scope_key = json.dumps([scope, projection], sort_keys=True)
        contexts: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        diagnostics: List[str] = []
        unresolved = 0
        observations = 0
        ordered = sorted(enumerate(run.records), key=lambda pair: (parse_int(pair[1].get("sequence"), pair[0]) or 0, pair[0]))
        for position, record in ordered:
            kind = record.get("kind")
            if kind not in {"function_entry", "function_call", "function_trace"}:
                continue
            members = record.get("functions", []) if kind == "function_trace" else [record]
            if not isinstance(members, list):
                unresolved += 1
                continue
            for subindex, member in enumerate(members):
                event = dict(record)
                event.pop("functions", None)
                if isinstance(member, Mapping):
                    event.update(member)
                elif isinstance(member, int):
                    event["address"] = member
                else:
                    unresolved += 1
                    continue
                observations += 1
                location = self._location(graph, run, event, kind)
                if location is None:
                    unresolved += 1
                    continue
                pid, tid = parse_int(event.get("pid"), 0) or 0, parse_int(event.get("tid"), 0) or 0
                context_id = str(event.get("context_id", event.get("thread_id", tid)))
                key = pid, context_id
                context = contexts.setdefault(key, {"context_id": context_id, "tid": tid, "pid": pid, "events": []})
                context["events"].append({"location": location, "sequence": parse_int(event.get("sequence"), position) or 0,
                                          "position": [position, subindex]})
        if not observations:
            if any(record.get("kind") == "branch" for record in run.records):
                diagnostics.append("sampled-lbr-is-not-a-complete-function-trace")
            else:
                diagnostics.append("function-entry-observations-missing")
        if not complete:
            diagnostics.append("function-trace-completeness-not-established")
        if lost:
            diagnostics.append("function-trace-events-lost:%d" % lost)
        if unresolved:
            diagnostics.append("unresolved-function-observations:%d" % unresolved)
        if not successful:
            diagnostics.append("controlled-run-not-successful")
        return {"replay_id": run.replay_id, "profile_key": run.profile_key, "baseline": baseline,
                "single_input": single_input, "complete": complete, "eligible": bool(complete and observations and not unresolved and successful),
                "observed_functions": observations, "scope": scope, "scope_key": scope_key,
                "contexts": list(contexts.values()), "diagnostics": diagnostics}

    @staticmethod
    def _location(graph: ACG, run: DynamicRun, record: Mapping[str, Any], kind: str) -> Optional[Location]:
        function_id = str(record.get("function_id", ""))
        function = graph.functions.get(function_id)
        if function is not None:
            return function.module, function.rva
        module = str(record.get("module", ""))
        rva = parse_int(record.get("rva"))
        if not module or rva is None:
            address = parse_int(record.get("target_address")) if kind == "function_call" else None
            if address is None:
                address = parse_int(record.get("entry_address", record.get("user_address", record.get("address"))))
            mapping = next((mapping for mapping in run.mappings if address is not None and mapping.contains(address)), None)
            if mapping is None or address is None:
                return None
            module, rva = mapping.module or mapping.path.replace("\\", "/").rsplit("/", 1)[-1], mapping.to_rva(address)
        function = graph.function_at(module, rva)
        return (function.module, function.rva) if function is not None else None

    def _cycles(self, tokens: Sequence[Location]) -> Dict[Tuple[Location, ...], int]:
        found: Dict[Tuple[Location, ...], int] = {}
        size = len(tokens)
        for period in range(1, min(self.maximum_period, size // self.minimum_repetitions) + 1):
            equal = [0] * (size + 1)
            for index in range(size - period - 1, -1, -1):
                if tokens[index] == tokens[index + period]:
                    equal[index] = equal[index + 1] + 1
            for index in range(size - period):
                repetitions = 1 + equal[index] // period
                if repetitions < self.minimum_repetitions or index and tokens[index - 1] == tokens[index + period - 1]:
                    continue
                word = tuple(tokens[index:index + period])
                if any(period % width == 0 and word == word[:width] * (period // width) for width in range(1, period)):
                    continue
                canonical = min(word[offset:] + word[:offset] for offset in range(period))
                found[canonical] = max(repetitions, found.get(canonical, 0))
        return found

    @staticmethod
    def _subtract(tokens: Sequence[Location], cycles: Sequence[Tuple[Location, ...]]) -> Tuple[List[bool], int]:
        words = sorted({word[offset:] + word[:offset] for word in cycles for offset in range(len(word))}, key=lambda word: (-len(word), word))
        removed = [False] * len(tokens)
        complete_matches = 0
        index = 0
        while index < len(tokens):
            word = next((word for word in words if tuple(tokens[index:index + len(word)]) == word), None)
            if word is None:
                index += 1
                continue
            removed[index:index + len(word)] = [True] * len(word)
            complete_matches += 1
            index += len(word)
        if complete_matches:
            for word in words:
                for length in range(1, min(len(word), len(tokens))):
                    if tuple(tokens[:length]) == word[-length:]:
                        removed[:length] = [True] * length
                    if tuple(tokens[-length:]) == word[:length]:
                        removed[-length:] = [True] * length
        return removed, complete_matches

    @staticmethod
    def _locations(tokens: Sequence[Location]) -> List[Dict[str, Any]]:
        return [{"module": module, "rva": rva} for module, rva in tokens]
