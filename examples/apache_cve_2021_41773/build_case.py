#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ast
import base64
import hashlib
import json
import platform
import re
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence, Tuple


FUNCTIONS: Sequence[str] = (
    "ap_process_http_connection",
    "ap_process_http_async_connection",
    "ap_read_request",
    "ap_process_async_request",
    "ap_process_request_internal",
    "ap_run_translate_name",
    "ap_core_translate",
    "translate_alias_redir",
    "ap_run_map_to_storage",
    "ap_invoke_handler",
    "ap_run_handler",
    "default_handler",
)

DIRECT_EDGE_PAIRS = {
    ("ap_process_http_connection", "ap_process_http_async_connection"),
    ("ap_process_http_async_connection", "ap_read_request"),
    ("ap_process_http_async_connection", "ap_process_async_request"),
    ("ap_process_async_request", "ap_process_request_internal"),
    ("ap_process_async_request", "ap_invoke_handler"),
    ("ap_process_request_internal", "ap_run_translate_name"),
    ("ap_process_request_internal", "ap_run_map_to_storage"),
    ("ap_invoke_handler", "ap_run_handler"),
}

INDIRECT_EDGE_PAIRS = (
    ("ap_run_translate_name", "ap_core_translate", "core_translate hook"),
    ("ap_run_translate_name", "translate_alias_redir", "alias translate hook"),
    ("ap_run_handler", "default_handler", "content handler hook"),
)

READ_RE = re.compile(
    r'^(?P<time>\d\d:\d\d:\d\d\.\d+) read\((?P<fd>\d+)<TCP:\[(?P<conn>[^\]]+)\]>, "(?P<data>(?:\\.|[^"])*)", (?P<count>\d+)\) = (?P<result>-?\d+)$'
)
OPEN_RE = re.compile(
    r'^(?P<time>\d\d:\d\d:\d\d\.\d+) openat\((?P<dirfd>.+?), "(?P<path>(?:\\.|[^"])*)", (?P<flags>[^)]*)\) = (?P<result>-?\d+)(?:<(?P<object>[^>]+)>)?$'
)
BUILD_ID_RE = re.compile(r"BuildID\[sha1\]=([0-9a-fA-F]+)")
NM_RE = re.compile(r"^([0-9a-fA-F]+)\s+[A-Za-z]\s+(.+)$")
HEADER_RE = re.compile(r"^\s*([0-9a-fA-F]+)\s+<([^>]+)>:\s*$")
INSTRUCTION_RE = re.compile(r"^\s*([0-9a-fA-F]+):")
CALL_RE = re.compile(r"\b(?:bl|call|callq)\b")
TARGET_RE = re.compile(r"<([^>]+)>")


def command_output(arguments: Sequence[str]) -> str:
    result = subprocess.run(
        list(arguments),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError("command failed: %s\n%s" % (" ".join(arguments), result.stderr.strip()))
    return result.stdout


def clean_symbol(name: str) -> str:
    value = name.strip().split("+", 1)[0].split("@", 1)[0]
    if value.startswith("."):
        value = value[1:]
    return value


def build_id(binary: Path) -> str:
    output = command_output(["file", str(binary)])
    match = BUILD_ID_RE.search(output)
    if match:
        return match.group(1).lower()
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    return digest[:20]


def binary_symbols(binary: Path) -> Dict[str, int]:
    symbols: Dict[str, int] = {}
    for line in command_output(["nm", "-n", str(binary)]).splitlines():
        match = NM_RE.match(line)
        if not match:
            continue
        name = clean_symbol(match.group(2))
        if name in FUNCTIONS:
            symbols[name] = int(match.group(1), 16)
    missing = sorted(set(FUNCTIONS) - set(symbols))
    if missing:
        raise RuntimeError("the Apache binary is missing expected symbols: %s" % ", ".join(missing))
    return symbols


def function_sizes(symbols: Mapping[str, int]) -> Dict[str, int]:
    ordered = sorted((address, name) for name, address in symbols.items())
    sizes: Dict[str, int] = {}
    for index, (address, name) in enumerate(ordered):
        next_address = ordered[index + 1][0] if index + 1 < len(ordered) else address + 256
        sizes[name] = max(next_address - address, 1)
    return sizes


def direct_calls(binary: Path) -> List[Tuple[str, str, int]]:
    current = ""
    recovered: List[Tuple[str, str, int]] = []
    for line in command_output(["objdump", "-d", str(binary)]).splitlines():
        header = HEADER_RE.match(line)
        if header:
            current = clean_symbol(header.group(2))
            continue
        if current not in FUNCTIONS or not CALL_RE.search(line):
            continue
        address_match = INSTRUCTION_RE.match(line)
        targets = TARGET_RE.findall(line)
        if address_match is None or not targets:
            continue
        target = clean_symbol(targets[-1])
        pair = (current, target)
        if pair in DIRECT_EDGE_PAIRS:
            recovered.append((current, target, int(address_match.group(1), 16)))
    observed_pairs = {(source, target) for source, target, _ in recovered}
    missing = sorted(DIRECT_EDGE_PAIRS - observed_pairs)
    if missing:
        raise RuntimeError("objdump did not recover expected Apache call edges: %s" % missing)
    unique: Dict[Tuple[str, str], Tuple[str, str, int]] = {}
    for source, target, callsite in recovered:
        unique.setdefault((source, target), (source, target, callsite))
    return [unique[pair] for pair in sorted(unique)]


def build_acg(binary: Path, output: Path) -> Tuple[str, str]:
    image_build_id = build_id(binary)
    profile_key = "%s|front-end|single_process_httpd_x|" % image_build_id
    symbols = binary_symbols(binary)
    sizes = function_sizes(symbols)
    calls = direct_calls(binary)
    module = binary.name

    functions = []
    blocks = []
    cfg_edges = []
    for name in FUNCTIONS:
        function_id = "%s:fn:%x" % (module, symbols[name])
        block_id = "%s:bb:%x" % (module, symbols[name])
        functions.append(
            {
                "id": function_id,
                "name": name,
                "module": module,
                "rva": symbols[name],
                "size": sizes[name],
                "blocks": [block_id],
                "metadata": {"source": "nm"},
            }
        )
        blocks.append(
            {
                "id": block_id,
                "function_id": function_id,
                "module": module,
                "rva": symbols[name],
                "size": sizes[name],
                "terminal_kind": "call_or_return",
            }
        )
        cfg_edges.append(
            {
                "id": "cfg:%s" % name,
                "source": function_id,
                "target": block_id,
                "kind": "cfg",
                "source_function": function_id,
                "target_function": function_id,
            }
        )

    acg_edges = []
    for source, target, callsite in calls:
        acg_edges.append(
            {
                "id": "direct:%s:%s" % (source, target),
                "source": "%s:bb:%x" % (module, symbols[source]),
                "target": "%s:fn:%x" % (module, symbols[target]),
                "kind": "direct_call",
                "callsite_rva": callsite,
                "source_function": "%s:fn:%x" % (module, symbols[source]),
                "target_function": "%s:fn:%x" % (module, symbols[target]),
                "evidence": ["objdump"],
            }
        )

    for source, target, description in INDIRECT_EDGE_PAIRS:
        acg_edges.append(
            {
                "id": "indirect:%s:%s" % (source, target),
                "source": "%s:bb:%x" % (module, symbols[source]),
                "target": "%s:fn:%x" % (module, symbols[target]),
                "kind": "indirect_call",
                "callsite_rva": symbols[source],
                "source_function": "%s:fn:%x" % (module, symbols[source]),
                "target_function": "%s:fn:%x" % (module, symbols[target]),
                "evidence": ["apache-hooks"],
                "metadata": {"description": description},
            }
        )

    graph = {
        "schema_version": 2,
        "build_id": image_build_id,
        "binary": str(binary),
        "architecture": platform.machine(),
        "functions": functions,
        "blocks": blocks,
        "acg_edges": acg_edges,
        "cfg_edges": cfg_edges,
        "syscall_sites": [],
        "entries": [
            {
                "id": "entry:network:%x" % symbols["ap_read_request"],
                "build_id": image_build_id,
                "profile_key": profile_key,
                "input_class": "network",
                "function_id": "%s:fn:%x" % (module, symbols["ap_read_request"]),
                "module": module,
                "rva": symbols["ap_read_request"],
                "input_site_id": "",
                "parameter_layout": {},
                "stable_replays": 1,
                "prefix_snapshot": "",
                "evidence": ["real-apache-cve-2021-41773-request"],
            }
        ],
        "metadata": {
            "description": "Function-level ACG slice recovered from the Apache 2.4.49 CVE-2021-41773 request path",
            "source": "nm, objdump, and Apache hook structure",
        },
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "application.acg.json").write_text(json.dumps(graph, indent=2, sort_keys=True), encoding="utf-8")
    return image_build_id, profile_key


def parse_timestamp_ns(raw: str) -> int:
    hours, minutes, seconds = raw.split(":")
    whole, micros = seconds.split(".")
    total_seconds = int(hours) * 3600 + int(minutes) * 60 + int(whole)
    return total_seconds * 1_000_000_000 + int(micros.ljust(6, "0")[:6]) * 1_000


def decode_strace_bytes(raw: str) -> bytes:
    value = ast.literal_eval('"%s"' % raw)
    return value.encode("latin-1", "backslashreplace")


def read_trace_events(trace_dir: Path) -> Tuple[List[MutableMapping[str, object]], Mapping[str, object]]:
    events: List[MutableMapping[str, object]] = []
    last_task_by_pid: Dict[int, Dict[str, str]] = {}
    trace_files = sorted(trace_dir.glob("runtime.strace.*"), key=lambda path: int(path.name.rsplit(".", 1)[1]))
    for path in trace_files:
        pid = int(path.name.rsplit(".", 1)[1])
        tid = pid
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            read_match = READ_RE.match(line)
            if read_match:
                result = int(read_match.group("result"))
                if result <= 0:
                    continue
                payload = decode_strace_bytes(read_match.group("data"))[:result]
                request_line = payload.decode("latin-1", "replace").split("\r\n", 1)[0]
                connection = read_match.group("conn")
                task_id = "conn:%s" % connection
                last_task_by_pid[pid] = {
                    "task_id": task_id,
                    "request_line": request_line,
                    "connection": connection,
                }
                events.append(
                    {
                        "kind": "input",
                        "timestamp_ns": parse_timestamp_ns(read_match.group("time")),
                        "pid": pid,
                        "tid": tid,
                        "syscall": "read",
                        "args": {"fd": int(read_match.group("fd")), "count": int(read_match.group("count"))},
                        "result": result,
                        "data": payload,
                        "handle": {
                            "pid": pid,
                            "fd": int(read_match.group("fd")),
                            "generation": 0,
                            "kind": "socket",
                            "object_id": "socket:%s" % connection,
                        },
                        "metadata": {
                            "external_input": True,
                            "task_id": task_id,
                            "request_line": request_line,
                            "connection": connection,
                        },
                    }
                )
                continue

            open_match = OPEN_RE.match(line)
            if open_match and open_match.group("path") == "/etc/passwd":
                task = last_task_by_pid.get(pid)
                if task is None:
                    continue
                events.append(
                    {
                        "kind": "output",
                        "timestamp_ns": parse_timestamp_ns(open_match.group("time")),
                        "pid": pid,
                        "tid": tid,
                        "syscall": "openat",
                        "args": {
                            "dirfd": open_match.group("dirfd"),
                            "path": open_match.group("path"),
                            "flags": open_match.group("flags"),
                        },
                        "result": int(open_match.group("result")),
                        "data": b"",
                        "handle": {
                            "pid": pid,
                            "fd": int(open_match.group("result")),
                            "generation": 0,
                            "kind": "file",
                            "object_id": "file:/etc/passwd",
                        },
                        "metadata": {
                            "task_id": task["task_id"],
                            "request_line": task["request_line"],
                            "connection": task["connection"],
                        },
                    }
                )

    events.sort(key=lambda item: (int(item["timestamp_ns"]), int(item["pid"]), str(item["syscall"])))
    for sequence, event in enumerate(events, 1):
        event["sequence"] = sequence
        kind = str(event.pop("kind"))
        event["id"] = "evt:%s:%d" % (event["syscall"], sequence)
        event["process"] = "httpd"
        event["direction"] = "input" if kind == "input" else "output"
    if not events:
        raise RuntimeError("no relevant Apache trace events were recovered from %s" % trace_dir)

    input_events = [event for event in events if event["direction"] == "input"]
    output_events = [event for event in events if event["direction"] == "output"]
    if not input_events or not output_events:
        raise RuntimeError("the trace does not contain both request input and /etc/passwd open events")

    symptom = output_events[-1]
    matching_inputs = [
        event for event in input_events
        if event["metadata"]["task_id"] == symptom["metadata"]["task_id"]
    ]
    if not matching_inputs:
        raise RuntimeError("could not match the /etc/passwd open to a concrete Apache request")

    case = {
        "request": matching_inputs[-1]["metadata"]["request_line"],
        "benign_request": input_events[0]["metadata"]["request_line"],
        "input_event": matching_inputs[-1]["id"],
        "symptom_event": symptom["id"],
        "opened_path": "/etc/passwd",
        "connection": symptom["metadata"]["connection"],
    }
    return events, case


def write_jsonl(path: Path, records: Iterable[Mapping[str, object]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True))
            handle.write("\n")


def encode_event(event: MutableMapping[str, object], build_id_value: str) -> MutableMapping[str, object]:
    encoded = dict(event)
    payload = bytes(encoded.pop("data"))
    encoded["data"] = {"encoding": "base64", "data": base64.b64encode(payload).decode("ascii")}
    metadata = dict(encoded.get("metadata", {}))
    metadata.update(
        {
            "build_id": build_id_value,
            "executable": "httpd",
            "process_role": "front-end",
            "concurrency_module": "single_process_httpd_x",
            "concurrency": {},
            "platform": "linux",
        }
    )
    encoded["metadata"] = metadata
    return encoded


def write_supporting_files(output: Path, build_id_value: str, profile_key: str, case: Mapping[str, object]) -> None:
    profile = {
        "build_id": build_id_value,
        "executable": "httpd",
        "role": "front-end",
        "command_line": ["/opt/httpd/bin/httpd", "-X", "-f", "/opt/httpd/conf/httpd.conf"],
        "modules": ["core"],
        "concurrency_module": "single_process_httpd_x",
        "concurrency": {},
        "platform": "linux",
    }
    (output / "profile.json").write_text(json.dumps(profile, indent=2, sort_keys=True), encoding="utf-8")
    (output / "case.json").write_text(json.dumps(case, indent=2, sort_keys=True), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the Apache CVE-2021-41773 Quick Start case")
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--trace-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    args.output.mkdir(parents=True, exist_ok=True)
    build_id_value, profile_key = build_acg(args.binary, args.output)
    events, case = read_trace_events(args.trace_dir)
    encoded_events = [encode_event(event, build_id_value) for event in events]
    write_jsonl(args.output / "audit.jsonl", encoded_events)
    write_supporting_files(args.output, build_id_value, profile_key, case)
    print(json.dumps({"events": len(encoded_events), "symptom": case["symptom_event"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
