from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping, Optional, Sequence

from .errors import BackendUnavailable, CompassError


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def executable(name_or_path: str) -> str:
    candidate = Path(name_or_path)
    if candidate.is_file() and os.access(str(candidate), os.X_OK):
        return str(candidate.resolve())
    located = shutil.which(name_or_path)
    if located:
        return located
    raise BackendUnavailable("required executable is unavailable: %s" % name_or_path)


def run_checked(
    argv: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    env: Optional[Mapping[str, str]] = None,
    stdout_path: Optional[Path] = None,
    timeout: Optional[float] = None,
) -> subprocess.CompletedProcess:
    merged_env = os.environ.copy()
    if env:
        merged_env.update({str(k): str(v) for k, v in env.items()})
    stdout_handle = stdout_path.open("wb") if stdout_path else subprocess.PIPE
    try:
        result = subprocess.run(
            list(argv),
            cwd=str(cwd) if cwd else None,
            env=merged_env,
            stdout=stdout_handle,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    finally:
        if stdout_path and stdout_handle is not subprocess.PIPE:
            stdout_handle.close()
    if result.returncode != 0:
        stderr = (result.stderr or b"").decode("utf-8", errors="replace")
        raise CompassError("command failed (%d): %s\n%s" % (result.returncode, " ".join(argv), stderr))
    return result


def primitive(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {key: primitive(item) for key, item in asdict(value).items()}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return {"encoding": "base64", "data": base64.b64encode(value).decode("ascii")}
    if isinstance(value, Mapping):
        return {str(key): primitive(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [primitive(item) for item in value]
    return value


def dump_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(primitive(value), indent=2, sort_keys=True, ensure_ascii=False)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(payload + "\n", encoding="utf-8")
    temporary.replace(path)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def iter_jsonl(path: Path) -> Iterator[dict]:
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line_number, raw in enumerate(stream, 1):
            line = raw.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CompassError("invalid JSONL at %s:%d: %s" % (path, line_number, exc)) from exc
            if not isinstance(value, dict):
                raise CompassError("JSONL record must be an object at %s:%d" % (path, line_number))
            yield value


def write_jsonl(path: Path, records: Iterable[Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        for record in records:
            stream.write(json.dumps(primitive(record), sort_keys=True, ensure_ascii=False))
            stream.write("\n")
    temporary.replace(path)


def decode_bytes(value: Any) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8", errors="surrogateescape")
    if isinstance(value, Mapping) and value.get("encoding") == "base64":
        return base64.b64decode(str(value.get("data", "")))
    if isinstance(value, Sequence):
        return bytes(int(item) & 0xFF for item in value)
    return str(value).encode("utf-8", errors="replace")


def parse_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    text = str(value).strip()
    try:
        return int(text, 0)
    except ValueError:
        return default


def temporary_directory(prefix: str = "compass-"):
    return tempfile.TemporaryDirectory(prefix=prefix)

