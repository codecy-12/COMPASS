from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

from ..config import CompassConfig
from ..errors import ConfigurationError
from ..llm import DeepSeekClient, PreparationInputGenerator
from ..util import dump_json, load_json, primitive, sha256_file
from .controlled import ControlledPreparationRunner


def _number(value: Any, name: str, minimum: float, inclusive: bool = True) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigurationError("%s must be a finite number" % name)
    try:
        finite = math.isfinite(value)
    except OverflowError:
        finite = False
    if not finite:
        raise ConfigurationError("%s must be a finite number" % name)
    if value < minimum or (not inclusive and value == minimum):
        raise ConfigurationError("invalid %s" % name)
    return float(value)


def _integer(value: Any, name: str, minimum: Optional[int] = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or (minimum is not None and value < minimum):
        raise ConfigurationError("invalid %s" % name)
    return value


def _argv(value: Any, name: str, empty: bool = True) -> list:
    if not isinstance(value, list) or (not empty and not value) or any(not isinstance(item, str) or "\x00" in item for item in value):
        raise ConfigurationError("%s must be an argv array" % name)
    return list(value)


def _payload(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, Mapping) and set(value) == {"encoding", "data"} and value["encoding"] == "base64" and isinstance(value["data"], str):
        try:
            return base64.b64decode(value["data"], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise ConfigurationError("invalid base64 preparation input") from exc
    if isinstance(value, list) and all(isinstance(item, int) and not isinstance(item, bool) and 0 <= item <= 255 for item in value):
        return bytes(value)
    raise ConfigurationError("input data must be UTF-8 text, byte values, or a base64 object")


def _exit_codes(value: Any) -> list:
    if not isinstance(value, list) or not value:
        raise ConfigurationError("expected exit codes must be a nonempty integer array")
    return [_integer(item, "expected exit code") for item in value]


def _input(specification: Any, command: Sequence[str], allow_empty: bool = False) -> Dict[str, Any]:
    if not isinstance(specification, Mapping):
        raise ConfigurationError("each preparation input must be an object")
    result = dict(specification)
    if not isinstance(result.get("id"), str) or not result["id"].strip():
        raise ConfigurationError("each preparation input requires a nonempty id")
    result["transport"] = result.get("transport", "stdin")
    if not isinstance(result["transport"], str) or result["transport"] not in {"stdin", "file", "tcp"}:
        raise ConfigurationError("input transport must be stdin, file, or tcp")
    if "data" not in result:
        raise ConfigurationError("each preparation input requires data")
    result["data"] = _payload(result["data"])
    if not result["data"] and not allow_empty:
        raise ConfigurationError("preparation input data must be nonempty")
    result["arguments"] = _argv(result.get("arguments", []), "input arguments")
    if result["transport"] == "file" and not any("{input}" in value for value in list(command) + result["arguments"]):
        raise ConfigurationError("file transport requires an {input} argv placeholder")
    if result["transport"] == "tcp":
        port = _integer(result.get("port"), "TCP port", 1)
        if port > 65535:
            raise ConfigurationError("invalid TCP port")
        result["port"] = port
        host = result.get("host", "127.0.0.1")
        if not isinstance(host, str) or not host.strip() or "\x00" in host:
            raise ConfigurationError("TCP host must be nonempty")
        result["host"] = host
    if "terminate_after_input" in result and not isinstance(result["terminate_after_input"], bool):
        raise ConfigurationError("terminate_after_input must be boolean")
    for name, minimum, inclusive in (("observation_seconds", 0, True), ("response_timeout_seconds", 0, False)):
        if name in result:
            result[name] = _number(result[name], name, minimum, inclusive)
    if "maximum_response_bytes" in result:
        result["maximum_response_bytes"] = _integer(result["maximum_response_bytes"], "maximum_response_bytes", 0)
    result["expected_returncodes"] = _exit_codes(result.get("expected_returncodes", [0]))
    return result


def load_preparation_plan(path: Path, allow_empty_inputs: bool = False) -> Dict[str, Any]:
    path = Path(path).expanduser().resolve()
    raw = load_json(path)
    if not isinstance(raw, dict):
        raise ConfigurationError("preparation plan must be a JSON object")
    result = dict(raw)
    result["command"] = _argv(result.get("command"), "preparation command", False)
    if not result["command"][0]:
        raise ConfigurationError("preparation executable must be nonempty")
    candidate = Path(result["command"][0]).expanduser()
    if not candidate.is_absolute() and (path.parent / candidate).is_file():
        result["command"][0] = str((path.parent / candidate).resolve())
    for name in ("binary", "cwd"):
        if result.get(name) is not None:
            if not isinstance(result[name], str) or not result[name]:
                raise ConfigurationError("%s must be a path" % name)
            value = Path(result[name]).expanduser()
            result[name] = (value if value.is_absolute() else path.parent / value).resolve()
    if result.get("cwd") and not result["cwd"].is_dir():
        raise ConfigurationError("preparation cwd does not exist")
    result["repeats"] = _integer(result.get("repeats", 2), "repeats", 1)
    result["timeout_seconds"] = _number(result.get("timeout_seconds", 30.0), "timeout_seconds", 0, False)
    result["baseline_seconds"] = _number(result.get("baseline_seconds", 1.0), "baseline_seconds", 0)
    result["startup_seconds"] = _number(result.get("startup_seconds", 0.25), "startup_seconds", 0)
    if not isinstance(result.get("recorder", "lbr"), str) or result.get("recorder", "lbr") not in {"lbr", "none"}:
        raise ConfigurationError("preparation recorder must be lbr or none")
    result["recorder"] = result.get("recorder", "lbr")
    if not isinstance(result.get("include_baseline", True), bool):
        raise ConfigurationError("include_baseline must be boolean")
    result["include_baseline"] = result.get("include_baseline", True)
    environment = result.get("env", {})
    if not isinstance(environment, dict) or any(not isinstance(key, str) or not key or "=" in key or "\x00" in key or not isinstance(value, str) or "\x00" in value for key, value in environment.items()):
        raise ConfigurationError("preparation env must map valid names to strings")
    result["env"] = environment
    if not isinstance(result.get("profile_key", "default"), str) or not result.get("profile_key", "default"):
        raise ConfigurationError("profile_key must be nonempty")
    result["profile_key"] = result.get("profile_key", "default")
    for name, key in (("handoff_probes", "probes"), ("prefix_sites", "sites")):
        values = result.get(name, [])
        if isinstance(values, str):
            source = Path(values).expanduser()
            values = load_json(source if source.is_absolute() else path.parent / source)
            if isinstance(values, Mapping):
                values = values.get(key)
        if not isinstance(values, list) or any(not isinstance(item, Mapping) for item in values):
            raise ConfigurationError("%s must be an object array or JSON path" % name)
        result[name] = [dict(item) for item in values]
    values = result.get("inputs", [])
    if not isinstance(values, list) or (not values and not allow_empty_inputs):
        raise ConfigurationError("preparation inputs must be a nonempty array")
    result["inputs"] = [_input(item, result["command"]) for item in values]
    ids = [item["id"] for item in result["inputs"]]
    if len(ids) != len(set(ids)):
        raise ConfigurationError("preparation input ids must be unique")
    result["_plan_path"] = path
    return result


def _execute(plan: Mapping[str, Any], config: CompassConfig, output: Path, inputs: Optional[Sequence[Mapping[str, Any]]] = None, **overrides: Any) -> Dict[str, Any]:
    names = ("binary", "profile_key", "repeats", "include_baseline", "timeout_seconds", "baseline_seconds", "startup_seconds", "recorder", "handoff_probes", "prefix_sites", "cwd", "env")
    options = {name: plan[name] for name in names if name in plan}
    options.update(overrides)
    return ControlledPreparationRunner(config).run(plan["command"], plan["inputs"] if inputs is None else inputs, Path(output), **options)


def exercise_plan(path: Path, output: Path, config: CompassConfig) -> Dict[str, Any]:
    return _execute(load_preparation_plan(path), config, output)


def run_once(path: Path, input_id: str, output: Optional[Path], config: CompassConfig) -> Dict[str, Any]:
    plan = load_preparation_plan(path)
    values = [item for item in plan["inputs"] if item["id"] == input_id]
    if len(values) != 1:
        raise ConfigurationError("unknown preparation input id: %s" % input_id)
    destination = Path(output) if output else Path(path).resolve().parent / ".compass-run-once" / hashlib.sha256(input_id.encode("utf-8")).hexdigest()[:16]
    return _execute(plan, config, destination, values, repeats=1, include_baseline=False)


def _json(payload: bytes) -> Any:
    def unique(pairs: Sequence[Any]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def constant(value: str) -> None:
        raise ValueError("nonfinite JSON number")
    return json.loads(payload.decode("utf-8"), object_pairs_hook=unique, parse_constant=constant)


def _chunked(body: bytes) -> bool:
    position = 0
    while True:
        end = body.find(b"\r\n", position)
        if end < 0:
            return False
        size = body[position:end].split(b";", 1)[0]
        if not re.fullmatch(b"[0-9A-Fa-f]+", size):
            return False
        length = int(size, 16)
        position = end + 2
        if not length:
            trailers = body[position:]
            if trailers == b"\r\n":
                return True
            if not trailers.endswith(b"\r\n\r\n"):
                return False
            return all(re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\t\x20-\x7e]*", line) for line in trailers[:-4].split(b"\r\n"))
        if position + length + 2 > len(body) or body[position + length:position + length + 2] != b"\r\n":
            return False
        position += length + 2


class ProtocolInputValidator:
    def __init__(self, settings: Mapping[str, Any]) -> None:
        if not isinstance(settings, Mapping):
            raise ConfigurationError("input_generation must be an object")
        self.settings = dict(settings)
        self.format = self.settings.get("format", "raw")
        if not isinstance(self.format, str) or self.format not in {"raw", "json", "http"}:
            raise ConfigurationError("input format must be raw, json, or http")
        self.maximum = _integer(self.settings.get("max_input_bytes", 65535), "max_input_bytes", 1)
        for name in ("required_json_keys", "required_headers", "methods"):
            if name in self.settings and (not isinstance(self.settings[name], list) or any(not isinstance(item, str) or not item for item in self.settings[name])):
                raise ConfigurationError("%s must be a string array" % name)
        if not isinstance(self.settings.get("json_type", "any"), str) or self.settings.get("json_type", "any") not in {"any", "object", "array", "string", "number", "boolean", "null"}:
            raise ConfigurationError("invalid json_type")
        for name in ("prefix_utf8", "suffix_utf8"):
            if name in self.settings and not isinstance(self.settings[name], str):
                raise ConfigurationError("%s must be a string" % name)
        self.reason = ""

    def __call__(self, payload: bytes) -> bool:
        self.reason = ""
        try:
            if not payload or len(payload) > self.maximum:
                raise ValueError("payload_size")
            if not payload.startswith(self.settings.get("prefix_utf8", "").encode("utf-8")) or not payload.endswith(self.settings.get("suffix_utf8", "").encode("utf-8")):
                raise ValueError("payload_boundary")
            if self.format == "json":
                value = _json(payload)
                expected = self.settings.get("json_type", "any")
                types = {"object": dict, "array": list, "string": str, "number": (int, float), "boolean": bool, "null": type(None)}
                if expected != "any" and (not isinstance(value, types[expected]) or (expected == "number" and isinstance(value, bool))):
                    raise ValueError("json_type")
                if self.settings.get("required_json_keys") and (not isinstance(value, dict) or any(key not in value for key in self.settings["required_json_keys"])):
                    raise ValueError("missing_json_key")
            elif self.format == "http":
                self._http(payload)
            return True
        except (ValueError, UnicodeError, OverflowError, RecursionError) as exc:
            self.reason = str(exc) or type(exc).__name__
            return False

    def _http(self, payload: bytes) -> None:
        header, separator, body = payload.partition(b"\r\n\r\n")
        if not separator:
            raise ValueError("http_header_boundary")
        lines = header.split(b"\r\n")
        match = re.fullmatch(rb"([A-Z]+) ([\x21-\x7e]+) HTTP/1\.[01]", lines[0])
        if match is None:
            raise ValueError("http_request_line")
        if self.settings.get("methods") and match.group(1).decode("ascii") not in self.settings["methods"]:
            raise ValueError("http_method")
        headers = {}
        for line in lines[1:]:
            if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+:[\t\x20-\x7e]*", line):
                raise ValueError("http_header")
            name, value = line.split(b":", 1)
            name = name.lower()
            if name in headers and name in {b"content-length", b"transfer-encoding", b"host"}:
                raise ValueError("http_duplicate_header")
            headers[name] = value.strip()
        if lines[0].endswith(b"HTTP/1.1") and not headers.get(b"host"):
            raise ValueError("http_host")
        if any(name.lower().encode("ascii") not in headers for name in self.settings.get("required_headers", [])):
            raise ValueError("http_required_header")
        if b"transfer-encoding" in headers:
            if b"content-length" in headers or headers[b"transfer-encoding"].lower() != b"chunked" or not _chunked(body):
                raise ValueError("http_chunked_body")
        elif b"content-length" in headers:
            length = headers[b"content-length"]
            if not re.fullmatch(b"[0-9]+", length) or int(length) != len(body):
                raise ValueError("http_content_length")
        elif body:
            raise ValueError("http_unframed_body")


def generate_inputs(plan_path: Path, documentation_path: Path, input_class: str, count: int, output: Path, validation_output: Optional[Path], config: CompassConfig) -> Dict[str, Any]:
    plan = load_preparation_plan(plan_path, allow_empty_inputs=True)
    settings = plan.get("input_generation", {})
    validator = ProtocolInputValidator(settings)
    template = {name: settings[name] for name in ("transport", "host", "port", "arguments", "observation_seconds", "terminate_after_input", "response_timeout_seconds", "maximum_response_bytes") if name in settings}
    template.update({"id": "generated", "data": b"validation", "expected_returncodes": _exit_codes(settings.get("expected_exit_codes", [0]))})
    template = _input(template, plan["command"])
    output = Path(output).expanduser().resolve()
    validation_output = Path(validation_output).expanduser().resolve() if validation_output else output.with_name(output.stem + ".validation.json")
    provenance_output = output.with_name(output.stem + ".provenance.json")
    if len({output, validation_output, provenance_output}) != 3:
        raise ConfigurationError("suite, validation, and provenance outputs must be distinct")
    for destination in (output, validation_output, provenance_output):
        if destination.exists():
            raise ConfigurationError("refusing to overwrite generated input output: %s" % destination)
    documentation_path = Path(documentation_path).expanduser().resolve()
    documentation = documentation_path.read_text(encoding="utf-8")
    generator = PreparationInputGenerator(DeepSeekClient(config.llm))
    structural = []
    executions = []
    run_directory = validation_output.with_name(validation_output.stem + ".runs")
    def validate(payload: bytes) -> bool:
        valid = validator(payload)
        structural.append({"sha256": hashlib.sha256(payload).hexdigest(), "valid": valid, "reason": validator.reason})
        return valid
    def replay(payload: bytes) -> bool:
        specification = dict(template, id="generated-%03d" % (len(executions) + 1), data=payload)
        result = _execute(plan, config, run_directory / specification["id"], [specification], repeats=1, include_baseline=False, recorder="none", handoff_probes=[], prefix_sites=[])
        runs = result.get("runs", [])
        accepted = len(runs) == 1 and runs[0].get("status") == "completed" and runs[0].get("transport_success") is True and (runs[0].get("returncode") in specification["expected_returncodes"] or (specification["transport"] == "tcp" and runs[0].get("terminated") is True))
        executions.append({"sha256": hashlib.sha256(payload).hexdigest(), "accepted": accepted, "manifest": result["manifest"], "runs": runs})
        return accepted
    accepted = generator.generate(documentation, input_class, count, validate, replay)
    suite = {key: primitive(value) for key, value in plan.items() if key != "_plan_path"}
    suite["inputs"] = []
    provenance = []
    for index, item in enumerate(accepted, 1):
        specification = dict(template, id="generated-%03d" % index, data=item.payload)
        suite["inputs"].append(primitive(specification))
        provenance.append({"id": specification["id"], "name": item.name, "content_type": item.content_type, "rationale": item.rationale, "sha256": hashlib.sha256(item.payload).hexdigest()})
    timestamp = datetime.now(timezone.utc).isoformat()
    report = {"created_at": timestamp, "requested": count, "accepted": len(accepted), "suite": str(output), "provenance": str(provenance_output), "inputs": generator.last_validation, "structural_validation": structural, "executions": executions}
    source = {"created_at": timestamp, "plan": str(Path(plan_path).resolve()), "plan_sha256": sha256_file(Path(plan_path)), "documentation": str(documentation_path), "documentation_sha256": sha256_file(documentation_path), "input_class": input_class, "provider": config.llm.provider, "model": config.llm.model, "endpoint": config.llm.base_url, "purpose": "offline_protocol_inputs_only", "inputs": provenance}
    dump_json(output, suite)
    dump_json(validation_output, report)
    dump_json(provenance_output, source)
    return {"suite": str(output), "validation": str(validation_output), "provenance": str(provenance_output), "requested": count, "accepted": len(accepted), "execution_manifests": [item["manifest"] for item in executions]}
