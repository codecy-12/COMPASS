from __future__ import annotations

import json
import base64
import binascii
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping

from .config import LLMConfig
from .errors import AnalysisError, ConfigurationError


@dataclass
class GeneratedInput:
    name: str
    content_type: str
    payload: bytes
    rationale: str = ""


class DeepSeekClient:
    """Small OpenAI-compatible client used only during offline preparation."""

    def __init__(self, config: LLMConfig) -> None:
        self.config = config

    def complete_json(self, system: str, user: str) -> Any:
        api_key = self.config.api_key.strip() or os.environ.get("COMPASS_LLM_API_KEY", "").strip()
        if not api_key:
            raise ConfigurationError(
                "DeepSeek api_key is empty; set llm.api_key or COMPASS_LLM_API_KEY before requesting LLM assistance"
            )
        request_body = {
            "model": self.config.model,
            "temperature": self.config.temperature,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        request = urllib.request.Request(
            self.config.base_url,
            data=json.dumps(request_body).encode("utf-8"),
            headers={
                "Authorization": "Bearer %s" % api_key,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                raw = json.loads(response.read().decode("utf-8"))
        except (OSError, urllib.error.HTTPError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise AnalysisError("DeepSeek request failed: %s" % exc) from exc
        try:
            content = raw["choices"][0]["message"]["content"]
            return json.loads(content)
        except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
            raise AnalysisError("DeepSeek returned an invalid structured response") from exc


class PreparationInputGenerator:
    """Proposes protocol-conforming inputs; callers must validate and replay them."""

    def __init__(self, client: DeepSeekClient) -> None:
        self.client = client
        self.last_validation: List[Dict[str, Any]] = []

    def generate(
        self,
        documentation: str,
        input_class: str,
        count: int,
        validator: Callable[[bytes], bool],
        replayer: Callable[[bytes], bool],
    ) -> List[GeneratedInput]:
        if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= 1000:
            raise ConfigurationError("generated input count must be between 1 and 1000")
        if not isinstance(documentation, str) or not documentation.strip() or not isinstance(input_class, str) or not input_class.strip():
            raise ConfigurationError("input documentation and input class must be nonempty")
        self.last_validation = []
        response = self.client.complete_json(
            "You generate valid application inputs from documentation. Return JSON only. "
            "Do not infer program edges, call targets, addresses, or execution results.",
            "Input class: %s\nRequested count: %d\nDocumentation:\n%s\n"
            "Return {\"inputs\":[{\"name\":str,\"content_type\":str,"
            "\"payload_utf8\":str or \"payload_base64\":str,\"rationale\":str}]}"
            % (input_class, count, documentation),
        )
        values = response.get("inputs") if isinstance(response, Mapping) else None
        if not isinstance(values, list):
            raise AnalysisError("DeepSeek input suite must contain an inputs array")
        accepted: List[GeneratedInput] = []
        seen = set()
        for index, item in enumerate(values[:count]):
            verdict: Dict[str, Any] = {"index": index, "accepted": False}
            self.last_validation.append(verdict)
            if not isinstance(item, Mapping) or set(item) - {"name", "content_type", "payload_utf8", "payload_base64", "rationale"}:
                verdict["reason"] = "invalid_input_schema"
                continue
            name, content_type, rationale = item.get("name"), item.get("content_type"), item.get("rationale", "")
            if not isinstance(name, str) or not name.strip() or not isinstance(content_type, str) or not content_type.strip() or not isinstance(rationale, str):
                verdict["reason"] = "invalid_input_metadata"
                continue
            verdict["name"] = name
            encodings = [key for key in ("payload_utf8", "payload_base64") if key in item]
            if len(encodings) != 1 or not isinstance(item[encodings[0]], str):
                verdict["reason"] = "invalid_payload_encoding"
                continue
            if encodings[0] == "payload_base64":
                try:
                    payload = base64.b64decode(item["payload_base64"], validate=True)
                except (ValueError, binascii.Error):
                    verdict["reason"] = "invalid_base64"
                    continue
            else:
                try:
                    payload = item["payload_utf8"].encode("utf-8")
                except UnicodeEncodeError:
                    verdict["reason"] = "invalid_utf8"
                    continue
            if not payload:
                verdict["reason"] = "empty_payload"
                continue
            if payload in seen:
                verdict["reason"] = "duplicate_payload"
                continue
            seen.add(payload)
            if not validator(payload):
                verdict["reason"] = "structural_validation_failed"
                continue
            if not replayer(payload):
                verdict["reason"] = "native_execution_failed"
                continue
            verdict.update({"accepted": True, "reason": "validated_and_executed"})
            accepted.append(
                GeneratedInput(
                    name=name,
                    content_type=content_type,
                    payload=payload,
                    rationale=rationale,
                )
            )
        return accepted

