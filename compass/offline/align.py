from __future__ import annotations

from typing import Any, Dict, List, Sequence, Tuple

from ..acg import ACG
from ..errors import AnalysisError
from ..schema import ACGEdgeRecord, EdgeKind, ModuleMapping, TransferField
from .dataflow import VEXCarrierAnalyser
from .dynamic import DynamicCaptureResult, RuntimeTransfer


class AddressAligner:
    @staticmethod
    def locate(mappings: Sequence[ModuleMapping], address: int) -> Tuple[str, int]:
        mapping = next((item for item in mappings if item.contains(address)), None)
        if mapping is None:
            raise AnalysisError("runtime address 0x%x is outside the recorded module mappings" % address)
        return mapping.module or mapping.path.split("/")[-1], mapping.to_rva(address)


class AlignmentCompletion:
    """Aligns runtime endpoints and adds dynamic relations to the static ACG backbone."""

    def complete(
        self,
        graph: ACG,
        capture: DynamicCaptureResult,
        indirect: Sequence[RuntimeTransfer],
        cross_context: Sequence[RuntimeTransfer],
    ) -> ACG:
        run_by_id = {(run.replay_id, run.profile_key): run for run in capture.runs}
        number = len(graph.edges)
        added = set()
        rejected: List[Dict[str, Any]] = []
        for transfer in list(indirect) + list(cross_context):
            profile = str(transfer.metadata.get("profile_key", ""))
            replay_id = str(transfer.metadata.get("replay_id", ""))
            run = run_by_id.get((replay_id, profile))
            if run is None:
                candidates = [item for item in capture.runs if (not profile or item.profile_key == profile)
                              and (not replay_id or item.replay_id == replay_id)]
                run = candidates[0] if len(candidates) == 1 else None
            if run is None:
                continue
            try:
                source_module, source_rva = AddressAligner.locate(run.mappings, transfer.source_address)
                target_module, target_rva = AddressAligner.locate(run.mappings, transfer.target_address)
            except AnalysisError:
                continue
            source_block = graph.block_at(source_module, source_rva)
            source_function = graph.function_at(source_module, source_rva)
            target_block = graph.block_at(target_module, target_rva)
            target_function = graph.function_at(target_module, target_rva)
            if source_block is None or target_function is None:
                continue
            kind = EdgeKind.INDIRECT_CALL if transfer.kind == "indirect_call" else EdgeKind.CROSS_CONTEXT
            if kind == EdgeKind.INDIRECT_CALL:
                if target_function.id == source_block.function_id:
                    continue
                direct_targets = {
                    edge.target_function for edge in graph.outgoing(source_block.id, {EdgeKind.DIRECT_CALL})
                }
                if target_function.id in direct_targets:
                    continue
            target_node = target_function.id if kind == EdgeKind.INDIRECT_CALL else (target_block.id if target_block else target_function.id)
            key = (source_block.id, target_node, kind.value, transfer.carrier)
            if key in added:
                continue
            fields = [TransferField.from_dict(item) for item in transfer.fields]
            metadata = dict(transfer.metadata)
            if kind == EdgeKind.CROSS_CONTEXT:
                stable = metadata.get("stable_replays", [])
                reason = ""
                if not metadata.get("repeated_single_input") or len(set(stable)) < 2:
                    reason = "repeated single-input endpoint evidence missing"
                elif not metadata.get("producer_before_consumer"):
                    reason = "producer-before-consumer evidence missing"
                elif source_module != target_module or not graph.binary:
                    reason = "binary field analysis unavailable for endpoint modules"
                else:
                    try:
                        fields = VEXCarrierAnalyser(graph.binary).validate_fields(
                            source_rva, target_rva, fields, [metadata]
                        )
                    except Exception as exc:
                        fields = []
                        reason = "binary field analysis failed: %s" % type(exc).__name__
                    if not fields and not reason:
                        reason = "no statically confirmed producer-write/consumer-read field mapping"
                if reason:
                    rejected.append({"source_module": source_module, "source_rva": source_rva,
                                     "target_module": target_module, "target_rva": target_rva,
                                     "carrier": transfer.carrier, "reason": reason})
                    continue
                metadata.update({"producer_write_rva": fields[0].metadata["producer_write_rva"],
                                 "consumer_read_rva": fields[0].metadata["consumer_read_rva"],
                                 "producer_module": source_module, "consumer_module": target_module,
                                 "static_field_mapping_confirmed": True,
                                 "producer_role": metadata.get("producer_role", "producer"),
                                 "consumer_role": metadata.get("consumer_role", "consumer")})
            number += 1
            graph.add_edge(
                ACGEdgeRecord(
                    id="dynamic:e%d" % number,
                    source=source_block.id,
                    target=target_node,
                    kind=kind,
                    callsite_rva=source_rva,
                    source_function=source_block.function_id,
                    target_function=target_function.id,
                    carrier=transfer.carrier,
                    transfer_fields=fields,
                    evidence=list(transfer.evidence),
                    metadata=metadata,
                )
            )
            added.add(key)
        graph.metadata["alignment"] = "module-relative"
        graph.metadata["dynamic_replays"] = sorted({run.replay_id for run in capture.runs})
        graph.metadata["rejected_cross_context_candidates"] = rejected
        graph.validate()
        return graph
