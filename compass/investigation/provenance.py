from __future__ import annotations

from collections import defaultdict
from typing import Any, DefaultDict, Dict, List, Optional, Sequence, Set, Tuple

from ..schema import AuditEvent, EventDirection, ProvenanceEdge, ProvenanceNode
from ..util import parse_int, primitive


class ProvenanceGraph:
    def __init__(self) -> None:
        self.nodes: Dict[str, ProvenanceNode] = {}
        self.edges: Dict[str, ProvenanceEdge] = {}
        self.events: Dict[str, AuditEvent] = {}
        self.event_edges: Dict[str, str] = {}
        self._incoming: DefaultDict[str, List[str]] = defaultdict(list)
        self._outgoing: DefaultDict[str, List[str]] = defaultdict(list)

    def add_node(self, node: ProvenanceNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, edge: ProvenanceEdge) -> None:
        self.edges[edge.id] = edge
        self._outgoing[edge.source].append(edge.id)
        self._incoming[edge.target].append(edge.id)
        if edge.event_id:
            self.event_edges[edge.event_id] = edge.id

    def edge_for_event(self, event_id: str) -> Optional[ProvenanceEdge]:
        edge_id = self.event_edges.get(event_id)
        return self.edges.get(edge_id) if edge_id else None

    def subject_of(self, event_id: str) -> Optional[ProvenanceNode]:
        edge = self.edge_for_event(event_id)
        if edge is None:
            return None
        for node_id in (edge.source, edge.target):
            node = self.nodes.get(node_id)
            if node and node.kind == "thread":
                return node
        return None

    def prior_input_events(
        self,
        event_id: str,
        tids: Optional[Set[int]] = None,
        minimum_sequence: int = 0,
    ) -> List[AuditEvent]:
        current = self.events[event_id]
        values = [
            event for event in self.events.values()
            if event.sequence < current.sequence
            and event.sequence >= minimum_sequence
            and event.is_successful_input()
            and (tids is None or event.tid in tids)
        ]
        return sorted(values, key=lambda item: (item.sequence, item.timestamp_ns, item.id))

    def is_external_input(self, event_id: str) -> bool:
        event = self.events.get(event_id)
        if event is None or not event.is_successful_input():
            return False
        explicit = event.metadata.get("external_input")
        if explicit is not None:
            return bool(explicit)
        return not bool(self.object_predecessors(event_id))

    def object_predecessors(self, event_id: str) -> List[AuditEvent]:
        current = self.events.get(event_id)
        edge = self.edge_for_event(event_id)
        if current is None or edge is None or current.direction != EventDirection.INPUT:
            return []
        explicit = current.metadata.get("producer_event_ids", current.metadata.get("peer_event_ids", []))
        if isinstance(explicit, str):
            explicit = [explicit]
        explicit = set(explicit) if isinstance(explicit, (list, tuple, set)) else set()
        values = []
        write_calls = {"write", "writev", "pwrite64", "pwritev", "pwritev2", "send", "sendto", "sendmsg", "sendmmsg", "splice", "vmsplice"}
        for candidate in self.events.values():
            if candidate.sequence >= current.sequence or candidate.direction != EventDirection.OUTPUT:
                continue
            if candidate.timestamp_ns > 0 and current.timestamp_ns > 0 and candidate.timestamp_ns > current.timestamp_ns:
                continue
            if candidate.syscall not in write_calls or candidate.successful_bytes <= 0:
                continue
            if explicit and candidate.id not in explicit:
                continue
            candidate_edge = self.edge_for_event(candidate.id)
            if candidate_edge is not None and (explicit or candidate_edge.target == edge.source) and self._ranges_overlap(candidate, current):
                values.append(candidate)
        return sorted(values, key=lambda event: (event.sequence, event.id))

    @staticmethod
    def _ranges_overlap(producer: AuditEvent, consumer: AuditEvent) -> bool:
        left = parse_int(producer.metadata.get("stream_offset", producer.args.get("offset")), None)
        right = parse_int(consumer.metadata.get("stream_offset", consumer.args.get("offset")), None)
        if left is None or right is None:
            return True
        return left < right + consumer.successful_bytes and right < left + producer.successful_bytes

    def incident_subgraph(self, event_ids: Set[str]) -> Tuple[List[ProvenanceNode], List[ProvenanceEdge]]:
        edges = [self.edge_for_event(event_id) for event_id in event_ids]
        kept_edges = [edge for edge in edges if edge is not None]
        node_ids = {node for edge in kept_edges for node in (edge.source, edge.target)}
        return [self.nodes[node] for node in sorted(node_ids)], sorted(kept_edges, key=lambda item: item.id)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [primitive(item) for item in sorted(self.nodes.values(), key=lambda value: value.id)],
            "edges": [primitive(item) for item in sorted(self.edges.values(), key=lambda value: value.id)],
            "events": [event.to_dict() for event in sorted(self.events.values(), key=lambda value: value.sequence)],
        }


class ProvenanceGraphBuilder:
    def build(self, events: Sequence[AuditEvent]) -> ProvenanceGraph:
        graph = ProvenanceGraph()
        parent_links: Set[Tuple[str, str]] = set()
        for event in sorted(events, key=lambda item: (item.sequence, item.timestamp_ns, item.id)):
            graph.events[event.id] = event
            process_id = "process:%d" % event.pid
            thread_id = "thread:%d:%d" % (event.pid, event.tid)
            graph.add_node(ProvenanceNode(process_id, "process", event.process or str(event.pid), {"pid": event.pid}))
            graph.add_node(
                ProvenanceNode(thread_id, "thread", "%s/%d" % (event.process or event.pid, event.tid), {"pid": event.pid, "tid": event.tid})
            )
            link = (process_id, thread_id)
            if link not in parent_links:
                graph.add_edge(ProvenanceEdge("owns:%d:%d" % (event.pid, event.tid), process_id, thread_id, "", "owns"))
                parent_links.add(link)
            object_id, object_kind, object_label = self._object(event)
            graph.add_node(ProvenanceNode(object_id, object_kind, object_label, self._object_metadata(event)))
            if event.direction == EventDirection.INPUT:
                source, target = object_id, thread_id
            elif event.direction in {EventDirection.OUTPUT, EventDirection.FAULT}:
                source, target = thread_id, object_id
            else:
                source, target = thread_id, object_id
            edge = ProvenanceEdge(
                id="provenance:%s" % event.id,
                source=source,
                target=target,
                event_id=event.id,
                operation=event.syscall,
                metadata={
                    "sequence": event.sequence,
                    "timestamp_ns": event.timestamp_ns,
                    "args": event.args,
                    "result": event.result,
                    "transferred_bytes": event.successful_bytes,
                },
            )
            graph.add_edge(edge)
        return graph

    @staticmethod
    def _object(event: AuditEvent) -> Tuple[str, str, str]:
        if event.handle:
            return (
                "object:%s" % event.handle.object_id,
                event.handle.kind.value,
                event.handle.object_id,
            )
        if event.direction == EventDirection.FAULT:
            return "fault:%s" % event.id, "fault", str(event.fault.get("signal", event.syscall))
        path = str(event.args.get("path", event.args.get("name", "")))
        if path:
            return "path:%s" % path, "file", path
        return "event-object:%s" % event.id, "unknown", event.syscall

    @staticmethod
    def _object_metadata(event: AuditEvent) -> Dict[str, Any]:
        if event.handle:
            return {
                "pid": event.handle.pid,
                "fd": event.handle.fd,
                "generation": event.handle.generation,
                "object_id": event.handle.object_id,
            }
        return {}
