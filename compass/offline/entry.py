from __future__ import annotations

from collections import defaultdict
from typing import Any, DefaultDict, Dict, List, Mapping, Optional, Sequence, Tuple

from ..acg import ACG
from ..schema import ExternalInputEntry, ModuleMapping
from .dynamic import DynamicCaptureResult, DynamicRun


INPUT_OPERATIONS = {"accept", "accept4", "read", "readv", "pread64", "recv", "recvfrom", "recvmsg", "recvmmsg"}


def _mapping_at(mappings: Sequence[ModuleMapping], address: int) -> Optional[ModuleMapping]:
    return next((item for item in mappings if item.contains(address)), None)


class ExternalInputEntryFinder:
    """Keeps only stable input-related entry locations across controlled replays."""

    def __init__(self, minimum_stable_replays: int = 2) -> None:
        self.minimum_stable_replays = minimum_stable_replays

    def find(self, graph: ACG, capture: DynamicCaptureResult) -> List[ExternalInputEntry]:
        observations: DefaultDict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
        for run in capture.runs:
            if any(record.get("kind") == "run_metadata" and (record.get("phase") == "baseline"
                   or record.get("status", "completed") != "completed") for record in run.records):
                continue
            for record in run.records:
                if record.get("initialization") or record.get("phase") in {"initialization", "startup", "baseline"}:
                    continue
                if record.get("kind") not in {"external_input", "syscall"}:
                    continue
                syscall = str(record.get("syscall", ""))
                if syscall not in INPUT_OPERATIONS and record.get("kind") != "external_input":
                    continue
                input_class = str(record.get("input_class", "network" if syscall in {"accept", "accept4", "recv", "recvfrom", "recvmsg"} else "file"))
                key = run.profile_key, input_class
                candidate = self._entry_observation(graph, run, record)
                if candidate:
                    observations[key].append(candidate)
        entries: List[ExternalInputEntry] = []
        for (profile, input_class), values in observations.items():
            by_location: DefaultDict[Tuple[str, int, str], List[Dict[str, Any]]] = defaultdict(list)
            for item in values:
                by_location[(item["module"], item["rva"], item["input_site_id"])].append(item)
            if not by_location:
                continue
            for location, matched in sorted(by_location.items()):
                stable = len({value["replay_id"] for value in matched})
                if stable < self.minimum_stable_replays:
                    continue
                function = graph.function_at(location[0], location[1])
                if function is None:
                    continue
                layouts = [value.get("parameter_layout", {}) for value in matched]
                if any(layout != layouts[0] for layout in layouts[1:]):
                    continue
                entries.append(
                    ExternalInputEntry(
                        id="entry:%s:%s:%x:%s" % (profile, location[0], location[1], location[2]),
                        build_id=graph.build_id,
                        profile_key=profile,
                        input_class=input_class,
                        function_id=function.id,
                        module=location[0],
                        rva=location[1],
                        input_site_id=location[2],
                        parameter_layout=dict(layouts[0]),
                        stable_replays=stable,
                        prefix_snapshot=next((str(item["prefix_snapshot"]) for item in matched if item.get("prefix_snapshot")), ""),
                        evidence=["%s:%s" % (item["replay_id"], item["sequence"]) for item in matched],
                    )
                )
        return entries

    @staticmethod
    def _entry_observation(graph: ACG, run: DynamicRun, record: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        callchain = [int(item) for item in record.get("application_callchain", record.get("user_stack", []))]
        entry_address = int(record.get("entry_address", 0))
        if not entry_address:
            frames = []
            for address in reversed(callchain):
                mapping = _mapping_at(run.mappings, address)
                if mapping is None:
                    continue
                module = mapping.module or mapping.path.split("/")[-1]
                function = graph.function_at(module, mapping.to_rva(address))
                if function is None or function.is_external:
                    continue
                name = function.name.lower()
                if name in {"main", "_start", "start_thread", "clone", "clone3"}:
                    continue
                if "process_events_and_timers" in name or name in {"event_loop", "worker_loop"}:
                    continue
                frames.append(address)
            entry_address = frames[0] if frames else 0
        mapping = _mapping_at(run.mappings, entry_address)
        if mapping is None:
            return None
        module = mapping.module or mapping.path.split("/")[-1]
        rva = mapping.to_rva(entry_address)
        function = graph.function_at(module, rva)
        if function is None or function.is_external:
            return None
        site_address = int(record.get("callsite_address", record.get("user_address", 0)))
        site_mapping = _mapping_at(run.mappings, site_address) if site_address else mapping
        site_rva = site_mapping.to_rva(site_address) if site_mapping and site_address else rva
        site_module = (site_mapping.module or site_mapping.path.replace("\\", "/").rsplit("/", 1)[-1]) if site_mapping else module
        site = graph.block_at(site_module, site_rva)
        syscall = str(record.get("syscall", ""))
        syscall_site = next(
            (
                item for item in graph.syscall_sites.values()
                if site is not None and item.block_id == site.id
                and (item.syscall in {syscall, "unknown"} or not syscall and item.metadata.get("input_label"))
            ),
            None,
        )
        site_id = str(record.get("input_site_id", syscall_site.id if syscall_site else ""))
        if site_id not in graph.syscall_sites:
            return None
        matched_site = graph.syscall_sites[site_id]
        if matched_site.metadata.get("excluded_input") or matched_site.metadata.get("output_label") and not matched_site.metadata.get("input_label"):
            return None
        matched_site.metadata["input_label"] = matched_site.id
        matched_site.metadata["direction"] = "input"
        labels = graph.blocks[matched_site.block_id].metadata.setdefault("input_labels", [])
        if matched_site.id not in labels:
            labels.append(matched_site.id)
        return {
            "module": module,
            "rva": rva if record.get("entry_address") else function.rva,
            "input_site_id": site_id,
            "parameter_layout": dict(record.get("parameter_layout", {})),
            "prefix_snapshot": str(record.get("prefix_snapshot", "")),
            "replay_id": run.replay_id,
            "sequence": record.get("sequence", ""),
        }
