from __future__ import annotations

from collections import defaultdict
from typing import Any, DefaultDict, Dict, List, Mapping, Optional, Sequence, Tuple

from ..schema import TransferField
from ..util import parse_int
from .dynamic import DynamicCaptureResult, DynamicRun, RuntimeTransfer


INPUT_SYSCALLS = {"read", "readv", "pread64", "recv", "recvfrom", "recvmsg", "recvmmsg", "accept", "accept4"}
OUTPUT_SYSCALLS = {"write", "writev", "pwrite64", "send", "sendto", "sendmsg", "sendmmsg"}
WAKE_SYSCALLS = {"futex", "eventfd", "eventfd2", "write", "writev"}


class VEXCarrierAnalyser:
    def __init__(self, binary: str) -> None:
        self.binary = binary

    def infer_fields(self, source_rva: int, target_rva: int, observations: Sequence[Mapping[str, Any]]) -> List[TransferField]:
        explicit = [TransferField.from_dict(field) for item in observations for field in item.get("transfer_fields", [])]
        return self.validate_fields(source_rva, target_rva, explicit, observations)

    def validate_fields(
        self, source_rva: int, target_rva: int, fields: Sequence[TransferField],
        observations: Sequence[Mapping[str, Any]],
    ) -> List[TransferField]:
        try:
            import angr
            project = angr.Project(self.binary, auto_load_libs=False)
            base = int(project.loader.main_object.mapped_base)
            source = project.factory.block(base + source_rva).vex
            target = project.factory.block(base + target_rva).vex
            stores, _, _ = self._operations(source)
            _, loads, assignments = self._operations(target)
        except (ImportError, OSError, ValueError):
            return []
        accepted: List[TransferField] = []
        for store_address, store_value, store_width, write_instruction in stores:
            for load_address, load_value, load_width, read_instruction in loads:
                if store_address != load_address or store_width != load_width or store_width <= 0:
                    continue
                for observation in observations:
                    producer = self._register_values(project, observation.get("producer_arguments", []))
                    consumer = self._register_values(project, observation.get("consumer_arguments", []))
                    source_address = self._evaluate(store_address, producer)
                    target_address = self._evaluate(load_address, consumer)
                    if source_address is None or target_address is None or source_address != target_address:
                        continue
                    candidates = list(fields) or [TransferField(
                        source="mem:0x%x" % source_address, destination="mem:0x%x" % target_address,
                        width=store_width,
                    )]
                    for item in candidates:
                        if not self._source_matches(item.source, project, store_address, store_value, source_address):
                            continue
                        if not self._destination_matches(item.destination, project, load_value, assignments, target_address):
                            continue
                        if item.width not in {0, store_width}:
                            continue
                        metadata = dict(item.metadata)
                        metadata.update({"analysis": "pyvex-def-use", "static_confirmed": True,
                                         "memory_expression": store_address,
                                         "producer_write_address": source_address,
                                         "consumer_read_address": target_address,
                                         "producer_write_rva": write_instruction - base,
                                         "consumer_read_rva": read_instruction - base})
                        accepted.append(TransferField(item.source, item.destination, store_width, item.encoding, metadata))
        return self._unique(accepted)

    @staticmethod
    def _operations(block: Any) -> Tuple[List[Any], List[Any], Dict[int, str]]:
        definitions: Dict[int, str] = {}
        stores: List[Any] = []
        loads: List[Any] = []
        assignments: Dict[int, str] = {}
        instruction = int(block.addr)
        for statement in block.statements:
            name = statement.__class__.__name__
            if name == "IMark":
                instruction = int(statement.addr)
            elif name == "WrTmp":
                expression = VEXCarrierAnalyser._expand_expression(statement.data, definitions)
                definitions[int(statement.tmp)] = expression
                if statement.data.__class__.__name__ == "Load":
                    loads.append((VEXCarrierAnalyser._expand_expression(statement.data.addr, definitions), expression,
                                  int(statement.data.result_size(block.tyenv)) // 8, instruction))
            elif name == "Store":
                stores.append((VEXCarrierAnalyser._expand_expression(statement.addr, definitions),
                               VEXCarrierAnalyser._expand_expression(statement.data, definitions),
                               int(statement.data.result_size(block.tyenv)) // 8, instruction))
            elif name == "Put":
                assignments[int(statement.offset)] = VEXCarrierAnalyser._expand_expression(statement.data, definitions)
        return stores, loads, assignments

    @staticmethod
    def _argument_registers(project: Any) -> List[str]:
        architecture = project.arch.name.upper()
        if architecture in {"AMD64", "X86_64"}:
            return ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        if architecture == "AARCH64":
            return ["x%d" % index for index in range(8)]
        if architecture.startswith("ARM"):
            return ["r%d" % index for index in range(4)]
        return []

    @staticmethod
    def _register_values(project: Any, arguments: Sequence[Any]) -> Dict[int, int]:
        values: Dict[int, int] = {}
        for name, value in zip(VEXCarrierAnalyser._argument_registers(project), arguments):
            try:
                values[int(project.arch.registers[name][0])] = int(str(value), 0)
            except (KeyError, ValueError, TypeError):
                continue
        return values

    @staticmethod
    def _register_location(location: str, project: Any) -> Any:
        if location == "return":
            return int(project.arch.ret_offset)
        if location.startswith("arg:"):
            try:
                location = "reg:" + VEXCarrierAnalyser._argument_registers(project)[int(location[4:])]
            except (IndexError, ValueError):
                return None
        if location.startswith("reg:"):
            register = project.arch.registers.get(location[4:])
            return int(register[0]) if register else None
        return None

    @staticmethod
    def _source_matches(location: str, project: Any, address: str, value: str, concrete: int) -> bool:
        if location.startswith("mem:"):
            try:
                return int(location[4:], 0) == concrete
            except ValueError:
                return False
        register = VEXCarrierAnalyser._register_location(location, project)
        return register is not None and value == "reg-offset:%d" % register

    @staticmethod
    def _destination_matches(location: str, project: Any, value: str, assignments: Mapping[int, str], concrete: int) -> bool:
        if location.startswith("mem:"):
            try:
                return int(location[4:], 0) == concrete
            except ValueError:
                return False
        register = VEXCarrierAnalyser._register_location(location, project)
        return register is not None and assignments.get(register) == value

    @staticmethod
    def _evaluate(expression: str, registers: Mapping[int, int]) -> Any:
        if expression.startswith("const:"):
            try:
                return int(expression[6:], 0)
            except ValueError:
                return None
        if expression.startswith("reg-offset:"):
            try:
                return registers.get(int(expression[11:]))
            except ValueError:
                return None
        if not expression.endswith(")") or "(" not in expression:
            return None
        operator, children = expression.split("(", 1)
        children = children[:-1]
        depth = 0
        split = None
        for index, character in enumerate(children):
            depth += int(character == "(") - int(character == ")")
            if character == "," and depth == 0:
                split = index
                break
        if split is None:
            return None
        left = VEXCarrierAnalyser._evaluate(children[:split], registers)
        right = VEXCarrierAnalyser._evaluate(children[split + 1:], registers)
        if left is None or right is None:
            return None
        if operator.startswith("Add"):
            return left + right
        if operator.startswith("Sub"):
            return left - right
        return None

    @staticmethod
    def _expand_expression(expression: Any, definitions: Mapping[int, str]) -> str:
        name = expression.__class__.__name__
        if name == "RdTmp":
            return definitions.get(int(expression.tmp), "tmp:%d" % int(expression.tmp))
        if name == "Get":
            return "reg-offset:%s" % getattr(expression, "offset", "")
        if name == "Const":
            return "const:%s" % getattr(getattr(expression, "con", None), "value", "")
        children = [VEXCarrierAnalyser._expand_expression(child, definitions) for child in getattr(expression, "child_expressions", [])]
        operator = str(getattr(expression, "op", name)).replace("Iop_", "")
        return "%s(%s)" % (operator, ",".join(children)) if children else str(expression)

    @staticmethod
    def _unique(values: Sequence[TransferField]) -> List[TransferField]:
        found: Dict[Tuple[str, str, int], TransferField] = {}
        for item in values:
            found[(item.source, item.destination, item.width)] = item
        return list(found.values())


class CrossContextRecoverer:
    """Builds cross-context candidates from observed handoffs and carrier evidence."""

    def __init__(self, minimum_stable_replays: int = 2) -> None:
        self.minimum_stable_replays = minimum_stable_replays
        self.rejected: List[Dict[str, Any]] = []

    def recover(self, capture: DynamicCaptureResult, baseline_regions: Optional[Mapping[str, Any]] = None) -> List[RuntimeTransfer]:
        self.rejected = []
        explicit = self._explicit(capture.runs)
        kernel = self._kernel_visible(capture.runs)
        user = self._user_space_handoffs(capture.runs)
        runs = {(run.replay_id, run.profile_key): run for run in capture.runs}
        merged: DefaultDict[Tuple[Any, ...], List[RuntimeTransfer]] = defaultdict(list)
        for item in explicit + kernel + user:
            run = runs.get((str(item.metadata.get("replay_id", "")), str(item.metadata.get("profile_key", ""))))
            if run is None or not self._single_input(run):
                self._reject(item, "single-input run not established")
                continue
            source = self._relative(run, item.source_address)
            target = self._relative(run, item.target_address)
            if source is None or target is None:
                self._reject(item, "missing endpoint module mapping")
                continue
            source_context = item.metadata.get("source_context", item.source_tid)
            target_context = item.metadata.get("target_context", item.target_tid)
            if source_context == target_context or not item.metadata.get("producer_before_consumer"):
                self._reject(item, "cross-context ordering not established")
                continue
            roles = (str(item.metadata.get("producer_role", "producer")), str(item.metadata.get("consumer_role", "consumer")))
            carrier_role = str(item.metadata.get("carrier_role", item.carrier.split(":", 1)[0]))
            key = (run.profile_key, source, target, roles, carrier_role)
            item.metadata["source_module"], item.metadata["source_rva"] = source
            item.metadata["target_module"], item.metadata["target_rva"] = target
            merged[key].append(item)
        accepted: List[RuntimeTransfer] = []
        for observations in merged.values():
            replay_ids = sorted({str(item.metadata["replay_id"]) for item in observations})
            if len(replay_ids) < self.minimum_stable_replays:
                for item in observations:
                    self._reject(item, "handoff endpoints not stable across repeated single-input runs")
                continue
            chosen = observations[-1]
            chosen.evidence = list(dict.fromkeys(value for item in observations for value in item.evidence))
            chosen.metadata["stable_replays"] = replay_ids
            chosen.metadata["repeated_single_input"] = True
            chosen.metadata["observations"] = [
                {"replay_id": item.metadata["replay_id"], "source_tid": item.source_tid,
                 "target_tid": item.target_tid, "producer_sequence": item.metadata.get("producer_sequence"),
                 "consumer_sequence": item.metadata.get("consumer_sequence"), "carrier": item.carrier}
                for item in observations
            ]
            if baseline_regions is not None:
                region_evidence = []
                for item in observations:
                    for endpoint, sequence_key, tid in (("producer", "producer_sequence", item.source_tid),
                                                        ("consumer", "consumer_sequence", item.target_tid)):
                        sequence = parse_int(item.metadata.get(sequence_key))
                        for region in baseline_regions.get("regions", []):
                            if region.get("replay_id") != item.metadata.get("replay_id") or region.get("profile_key") != item.metadata.get("profile_key"):
                                continue
                            if region.get("tid") == tid and sequence is not None and region["start_sequence"] <= sequence <= region["end_sequence"]:
                                region_evidence.append({"endpoint": endpoint, "region_id": region["id"], "role": region["role"],
                                                        "replay_id": region["replay_id"], "sequence": sequence})
                chosen.metadata["baseline_region_evidence"] = region_evidence
                chosen.metadata["baseline_region_status"] = "supported" if region_evidence else "no-unambiguous-request-region"
            accepted.append(chosen)
        return accepted

    def _reject(self, transfer: RuntimeTransfer, reason: str) -> None:
        self.rejected.append({"source_address": transfer.source_address, "target_address": transfer.target_address,
                              "carrier": transfer.carrier, "replay_id": transfer.metadata.get("replay_id", ""),
                              "reason": reason})

    @staticmethod
    def _relative(run: DynamicRun, address: int) -> Any:
        mapping = next((item for item in run.mappings if item.contains(address)), None)
        return (mapping.module or mapping.path.replace("\\", "/").rsplit("/", 1)[-1], mapping.to_rva(address)) if mapping else None

    @staticmethod
    def _single_input(run: DynamicRun) -> bool:
        if any(record.get("kind") == "run_metadata" and record.get("status", "completed") != "completed" for record in run.records):
            return False
        records = [record for record in run.records if record.get("phase") not in {"baseline", "initialization", "startup"}]
        if not records or any(record.get("baseline") for record in records):
            return False
        declarations = [record.get("input_count") for record in records if "input_count" in record]
        if declarations:
            try:
                return all(int(value) == 1 for value in declarations)
            except (ValueError, TypeError):
                return False
        explicit = [record.get("single_input") for record in records if "single_input" in record]
        if explicit:
            return all(value is True for value in explicit)
        return sum(record.get("kind") == "external_input" for record in records) == 1

    def learn_thread_patterns(
        self, capture: DynamicCaptureResult, transfers: Sequence[RuntimeTransfer]
    ) -> List[Dict[str, Any]]:
        patterns: Dict[Tuple[Tuple[str, ...], Tuple[str, ...], str], Dict[str, Any]] = {}
        for transfer in transfers:
            for run in capture.runs:
                producer = [
                    str(item.get("syscall")) for item in run.records
                    if int(item.get("tid", 0)) == transfer.source_tid and item.get("syscall")
                ]
                consumer = [
                    str(item.get("syscall")) for item in run.records
                    if int(item.get("tid", 0)) == transfer.target_tid and item.get("syscall")
                ]
                producer = self._trim_producer(producer)
                consumer = self._trim_consumer(consumer)
                if not producer or not consumer:
                    continue
                key = tuple(producer), tuple(consumer), transfer.carrier
                entry = patterns.setdefault(
                    key,
                    {
                        "producer": producer,
                        "consumer": consumer,
                        "carrier": transfer.carrier,
                        "replays": [],
                    },
                )
                if run.replay_id not in entry["replays"]:
                    entry["replays"].append(run.replay_id)
        return list(patterns.values())

    @staticmethod
    def _trim_producer(sequence: Sequence[str]) -> List[str]:
        start = next((index for index, item in enumerate(sequence) if item in INPUT_SYSCALLS), 0)
        return list(sequence[start:])

    @staticmethod
    def _trim_consumer(sequence: Sequence[str]) -> List[str]:
        # Keep the ordered consumer signature through its first externally visible output.
        for index, item in enumerate(sequence):
            if item in OUTPUT_SYSCALLS:
                return list(sequence[: index + 1])
        return list(sequence)

    @staticmethod
    def _explicit(runs: Sequence[DynamicRun]) -> List[RuntimeTransfer]:
        values: List[RuntimeTransfer] = []
        for run in runs:
            for record in run.records:
                if record.get("kind") != "cross_context":
                    continue
                if record.get("initialization") or record.get("phase") in {"baseline", "initialization", "startup"}:
                    continue
                metadata = dict(record.get("metadata", {}))
                metadata.update({key: value for key, value in record.items() if key not in {"metadata", "transfer_fields"}})
                metadata["profile_key"] = run.profile_key
                metadata["replay_id"] = run.replay_id
                producer_sequence = record.get("producer_sequence", record.get("source_sequence"))
                consumer_sequence = record.get("consumer_sequence", record.get("target_sequence"))
                producer_time = record.get("producer_timestamp_ns", record.get("source_timestamp_ns"))
                consumer_time = record.get("consumer_timestamp_ns", record.get("target_timestamp_ns"))
                metadata["producer_before_consumer"] = bool(
                    producer_sequence is not None and consumer_sequence is not None and int(producer_sequence) < int(consumer_sequence)
                    or producer_time is not None and consumer_time is not None and int(producer_time) < int(consumer_time)
                )
                values.append(
                    RuntimeTransfer(
                        source_address=int(record.get("source_address", 0)),
                        target_address=int(record.get("target_address", 0)),
                        source_tid=int(record.get("source_tid", 0)),
                        target_tid=int(record.get("target_tid", 0)),
                        kind="cross_context",
                        carrier=str(record.get("carrier", "user_object")),
                        fields=list(record.get("transfer_fields", [])),
                        evidence=["%s:%s" % (run.replay_id, record.get("sequence", ""))],
                        metadata=metadata,
                    )
                )
        return values

    @staticmethod
    def _kernel_visible(runs: Sequence[DynamicRun]) -> List[RuntimeTransfer]:
        values: List[RuntimeTransfer] = []
        for run in runs:
            by_object: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
            for record in run.records:
                object_id = str(record.get("object_id", ""))
                if object_id:
                    by_object[object_id].append(record)
            for object_id, records in by_object.items():
                ordered = sorted(records, key=lambda item: int(item.get("sequence", 0)))
                for left, right in zip(ordered, ordered[1:]):
                    if int(left.get("tid", 0)) == int(right.get("tid", 0)):
                        continue
                    if not left.get("user_address") or not right.get("user_address"):
                        continue
                    if left.get("syscall") not in OUTPUT_SYSCALLS or right.get("syscall") not in INPUT_SYSCALLS:
                        continue
                    producer_sequence = int(left.get("sequence", 0))
                    consumer_sequence = int(right.get("sequence", 0))
                    values.append(
                        RuntimeTransfer(
                            source_address=int(left["user_address"]),
                            target_address=int(right["user_address"]),
                            source_tid=int(left.get("tid", 0)),
                            target_tid=int(right.get("tid", 0)),
                            kind="cross_context",
                            carrier="kernel_object:%s" % object_id,
                            evidence=["%s:%s-%s" % (run.replay_id, left.get("sequence", ""), right.get("sequence", ""))],
                            metadata={"object_id": object_id, "profile_key": run.profile_key, "replay_id": run.replay_id,
                                      "producer_sequence": producer_sequence, "consumer_sequence": consumer_sequence,
                                      "producer_before_consumer": producer_sequence < consumer_sequence},
                        )
                    )
        return values

    @staticmethod
    def _user_space_handoffs(runs: Sequence[DynamicRun]) -> List[RuntimeTransfer]:
        values: List[RuntimeTransfer] = []
        for run in runs:
            writes: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
            reads: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
            sync: DefaultDict[str, List[Dict[str, Any]]] = defaultdict(list)
            for record in run.records:
                if record.get("initialization") or record.get("phase") in {"baseline", "initialization", "startup"}:
                    continue
                carrier = str(record.get("carrier_id", record.get("memory_object", "")))
                if not carrier:
                    continue
                access = str(record.get("access", record.get("kind", "")))
                if access in {"store", "queue_push", "producer_write"}:
                    writes[carrier].append(record)
                elif access in {"load", "queue_pop", "consumer_read"}:
                    reads[carrier].append(record)
                elif access in {"synchronize", "wake", "notify", "wait"}:
                    sync[carrier].append(record)
            for carrier, producers in writes.items():
                for producer in producers:
                    consumers = [
                        item for item in reads.get(carrier, [])
                        if item.get("context_id", item.get("tid", 0)) != producer.get("context_id", producer.get("tid", 0))
                        and int(item.get("sequence", 0)) > int(producer.get("sequence", 0))
                    ]
                    for consumer in consumers:
                        between = [
                            item for item in sync.get(carrier, [])
                            if int(producer.get("sequence", 0)) <= int(item.get("sequence", 0)) <= int(consumer.get("sequence", 0))
                        ]
                        values.append(
                            RuntimeTransfer(
                                source_address=int(producer.get("user_address", producer.get("source_address", 0))),
                                target_address=int(consumer.get("user_address", consumer.get("target_address", 0))),
                                source_tid=int(producer.get("tid", 0)),
                                target_tid=int(consumer.get("tid", 0)),
                                kind="cross_context",
                                carrier="user_object:%s" % carrier,
                                fields=list(producer.get("transfer_fields", [])),
                                evidence=["%s:%s-%s" % (run.replay_id, producer.get("sequence", ""), consumer.get("sequence", ""))],
                                metadata={
                                    "profile_key": run.profile_key,
                                    "replay_id": run.replay_id,
                                    "producer_sequence": int(producer.get("sequence", 0)),
                                    "consumer_sequence": int(consumer.get("sequence", 0)),
                                    "producer_before_consumer": True,
                                    "source_context": producer.get("context_id", producer.get("tid", 0)),
                                    "target_context": consumer.get("context_id", consumer.get("tid", 0)),
                                    "producer_role": str(producer.get("role", producer.get("function_id", "producer"))),
                                    "consumer_role": str(consumer.get("role", consumer.get("function_id", "consumer"))),
                                    "producer_arguments": producer.get("arguments", []),
                                    "consumer_arguments": consumer.get("arguments", []),
                                    "consumer_snapshot": consumer.get("consumer_snapshot", consumer.get("prefix_snapshot", consumer.get("metadata", {}).get("consumer_snapshot", ""))),
                                    "producer_metadata": dict(producer.get("metadata", {})),
                                    "consumer_metadata": dict(consumer.get("metadata", {})),
                                    "synchronization_records": [item.get("sequence") for item in between],
                                },
                            )
                        )
        return values
