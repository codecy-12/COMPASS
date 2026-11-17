from __future__ import annotations

import json
import math
import os
import signal
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..config import CompassConfig
from ..errors import CaptureError
from ..schema import ModuleMapping
from ..util import decode_bytes, dump_json, executable, iter_jsonl, parse_int, primitive, sha256_file, write_jsonl
from .dynamic import LBRRecorder
from .ebpf import HandoffProbe, PreparationHandoffRecorder


class ControlledPreparationRunner:
    def __init__(self, config: CompassConfig) -> None:
        self.config = config

    def run(
        self,
        command: Sequence[str],
        inputs: Sequence[Mapping[str, Any]],
        output_dir: Path,
        *,
        binary: Optional[Path] = None,
        profile_key: str = "default",
        repeats: int = 2,
        include_baseline: bool = True,
        timeout_seconds: float = 30.0,
        baseline_seconds: float = 1.0,
        startup_seconds: float = 0.25,
        recorder: str = "lbr",
        handoff_probes: Optional[Sequence[Any]] = None,
        prefix_sites: Optional[Sequence[Mapping[str, Any]]] = None,
        cwd: Optional[Path] = None,
        env: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        if isinstance(command, (str, bytes)) or not command or any(not isinstance(item, str) or "\x00" in item for item in command):
            raise CaptureError("preparation command must be a nonempty argv array")
        if not isinstance(repeats, int) or isinstance(repeats, bool) or repeats < 1:
            raise CaptureError("preparation repeat count must be a positive integer")
        timings = (timeout_seconds, baseline_seconds, startup_seconds)
        if any(not isinstance(value, (int, float)) or not math.isfinite(value) for value in timings) or timeout_seconds <= 0 or baseline_seconds < 0 or startup_seconds < 0:
            raise CaptureError("invalid preparation repeat count or timing")
        if recorder not in {"lbr", "none"}:
            raise CaptureError("preparation recorder must be lbr or none")
        if recorder == "lbr":
            executable(self.config.dynamic.perf_path)
            if os.name != "posix":
                raise CaptureError("LBR preparation requires a Linux execution environment")
        executable_path = command[0]
        if cwd and not Path(executable_path).is_absolute() and (Path(cwd) / executable_path).is_file():
            executable_path = str(Path(cwd) / executable_path)
        resolved_binary = Path(binary).expanduser().resolve() if binary else Path(executable(executable_path)).resolve()
        if not resolved_binary.is_file():
            raise CaptureError("preparation binary does not exist: %s" % resolved_binary)
        checked_inputs = []
        for index, item in enumerate(inputs):
            if not isinstance(item, Mapping):
                raise CaptureError("preparation inputs must be objects")
            specification = dict(item)
            specification.setdefault("id", "input-%d" % (index + 1))
            specification.setdefault("transport", "stdin")
            if specification["transport"] not in {"stdin", "file", "tcp"}:
                raise CaptureError("unsupported input transport: %s" % specification["transport"])
            arguments = specification.get("arguments", [])
            if not isinstance(arguments, list) or any(not isinstance(argument, str) or "\x00" in argument for argument in arguments):
                raise CaptureError("input arguments must be an argv array")
            returncodes = specification.get("expected_returncodes", [0])
            if not isinstance(returncodes, list) or not returncodes or any(not isinstance(code, int) or isinstance(code, bool) for code in returncodes):
                raise CaptureError("expected_returncodes must be a nonempty integer array")
            for key in ("observation_seconds", "response_timeout_seconds"):
                if key in specification and (not isinstance(specification[key], (int, float)) or not math.isfinite(specification[key]) or specification[key] < 0):
                    raise CaptureError("%s must be a nonnegative duration" % key)
            maximum = specification.get("maximum_response_bytes", 1024 * 1024)
            if not isinstance(maximum, int) or isinstance(maximum, bool) or maximum < 0:
                raise CaptureError("maximum_response_bytes must be a nonnegative integer")
            if specification["transport"] == "file" and not any("{input}" in argument for argument in list(command) + arguments):
                raise CaptureError("file input requires an {input} placeholder in argv")
            if specification["transport"] == "tcp":
                port = parse_int(specification.get("port"))
                if port is None or not 0 < port < 65536:
                    raise CaptureError("TCP input requires a valid port")
            checked_inputs.append(specification)
        output_dir = Path(output_dir).expanduser().resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        if (output_dir / "manifest.json").exists():
            raise CaptureError("preparation output already contains a manifest: %s" % output_dir)
        build_id = sha256_file(resolved_binary)
        common = {"binary": resolved_binary, "profile_key": profile_key, "build_id": build_id,
                  "timeout_seconds": float(timeout_seconds), "baseline_seconds": float(baseline_seconds),
                  "startup_seconds": float(startup_seconds), "recorder": recorder,
                  "handoff_probes": list(handoff_probes or []), "prefix_sites": list(prefix_sites or []),
                  "cwd": Path(cwd).resolve() if cwd else None, "env": dict(env or {})}
        runs: List[Dict[str, Any]] = []
        if include_baseline:
            baseline = dict(checked_inputs[0]) if checked_inputs else {"transport": "stdin", "arguments": []}
            baseline.update({"id": "baseline", "data": b""})
            runs.append(self._run_one(list(command), baseline, output_dir / "baseline", "baseline", True, common))
        for index, specification in enumerate(checked_inputs):
            for repeat in range(repeats):
                replay = "input-%03d-run-%03d" % (index + 1, repeat + 1)
                runs.append(self._run_one(list(command), specification, output_dir / replay, replay, False, common))
        reasons: List[str] = []
        if recorder == "none":
            reasons.append("tracing_disabled")
        if not include_baseline:
            reasons.append("zero_input_baseline_missing")
        if repeats < 2:
            reasons.append("repeated_single_input_runs_missing")
        if not checked_inputs:
            reasons.append("no_preparation_inputs")
        for result in runs:
            if result["status"] != "completed":
                reasons.append("%s:%s" % (result["id"], result["status"]))
            reasons.extend("%s:%s" % (result["id"], value) for value in result["diagnostics"])
        trace_paths = [result["trace"] for result in runs if result.get("trace")]
        result = {"manifest": str(output_dir / "manifest.json"), "build_id": build_id, "profile_key": profile_key,
                  "binary": str(resolved_binary), "runs": runs, "trace_paths": trace_paths,
                  "complete": not reasons, "incomplete_reasons": list(dict.fromkeys(reasons))}
        dump_json(output_dir / "manifest.json", result)
        return result

    def _run_one(self, command: List[str], specification: Mapping[str, Any], directory: Path,
                 replay: str, baseline: bool, options: Mapping[str, Any]) -> Dict[str, Any]:
        if directory.exists() and any(directory.iterdir()):
            raise CaptureError("preparation run directory is not empty: %s" % directory)
        directory.mkdir(parents=True, exist_ok=True)
        input_path = directory / "input.bin"
        data = b"" if baseline else decode_bytes(specification.get("data", b""))
        input_path.write_bytes(data)
        argv = [argument.replace("{input}", str(input_path)) for argument in command + list(specification.get("arguments", []))]
        trace_capture = directory / "branches.perf"
        if options["recorder"] == "lbr":
            argv = [executable(self.config.dynamic.perf_path), "record", "-q", "-e", "branches:u", "-c",
                    str(self.config.dynamic.lbr_sample_period), "-j", "any_call,u,any_ret,u", "-o", str(trace_capture), "--"] + argv
        stdout_path, stderr_path = directory / "stdout.bin", directory / "stderr.bin"
        environment = os.environ.copy()
        environment.update(options["env"])
        result: Dict[str, Any] = {"id": replay, "input_id": str(specification.get("id", "")), "input_count": 0 if baseline else 1,
                                  "status": "completed", "returncode": None, "transport_success": baseline, "terminated": False,
                                  "trace": "", "stdout": str(stdout_path), "stderr": str(stderr_path), "response": "",
                                  "diagnostics": [], "command": argv, "prefix_snapshots": []}
        started = time.monotonic()
        deadline = started + options["timeout_seconds"]
        process = None
        probe_thread = None
        stop_probes = threading.Event()
        probe_errors: List[str] = []
        gdb_process = None
        mappings: List[ModuleMapping] = []
        with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
            try:
                process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                           cwd=str(options["cwd"]) if options["cwd"] else None, env=environment,
                                           start_new_session=os.name == "posix")
                target_pid = self._target_pid(process, options["binary"], options["recorder"])
                result["pid"] = target_pid
                mappings = self._mappings(target_pid)
                mapping_deadline = min(deadline, time.monotonic() + 0.1)
                while not mappings and process.poll() is None and time.monotonic() < mapping_deadline:
                    time.sleep(0.005)
                    mappings = self._mappings(target_pid)
                dump_json(directory / "mappings.json", {"mappings": mappings})
                main_mappings = [mapping for mapping in mappings if Path(mapping.path).resolve() == options["binary"]]
                module_base = min((mapping.runtime_start - mapping.file_offset for mapping in main_mappings), default=0)
                if options["handoff_probes"]:
                    if not mappings or not module_base:
                        result["diagnostics"].append("handoff_module_mapping_unavailable")
                    else:
                        probes = [probe if isinstance(probe, HandoffProbe) else HandoffProbe.from_dict(probe)
                                  for probe in options["handoff_probes"]]
                        ready_probes = threading.Event()
                        def capture_probes() -> None:
                            try:
                                PreparationHandoffRecorder().capture(options["binary"], probes, directory / "handoffs.jsonl",
                                    replay, options["profile_key"], module_base, options["timeout_seconds"], target_pid, stop_probes, ready_probes)
                            except Exception as exc:
                                probe_errors.append("handoff_capture:%s:%s" % (type(exc).__name__, exc))
                        probe_thread = threading.Thread(target=capture_probes, daemon=True)
                        probe_thread.start()
                        while not ready_probes.wait(timeout=0.05) and probe_thread.is_alive() and time.monotonic() < deadline:
                            pass
                        if not ready_probes.is_set():
                            result["diagnostics"].append("handoff_probes_not_ready")
                if options["prefix_sites"]:
                    try:
                        gdb_process = self._start_prefix_capture(target_pid, directory, options, mappings)
                    except Exception as exc:
                        result["diagnostics"].append("prefix_capture:%s:%s" % (type(exc).__name__, exc))
                delay = min(options["startup_seconds"], max(0.0, deadline - time.monotonic()))
                if delay:
                    time.sleep(delay)
                if baseline:
                    if process.stdin:
                        process.stdin.close()
                        process.stdin = None
                    self._observe(process, options["baseline_seconds"], deadline)
                    if process.poll() is None:
                        result["terminated"] = True
                        self._terminate(process)
                else:
                    transport = specification["transport"]
                    if transport == "stdin":
                        if process.stdin is None:
                            raise CaptureError("target stdin is unavailable")
                        self._stdin_input(process, data, deadline)
                        result["transport_success"] = True
                    elif transport == "file":
                        if process.stdin:
                            process.stdin.close()
                            process.stdin = None
                        result["transport_success"] = True
                    else:
                        result["response"] = str(directory / "response.bin")
                        response = self._tcp_input(specification, data, deadline)
                        (directory / "response.bin").write_bytes(response)
                        result["transport_success"] = True
                    terminate = bool(specification.get("terminate_after_input", transport == "tcp"))
                    if terminate:
                        self._observe(process, float(specification.get("observation_seconds", 0.25)), deadline)
                        if process.poll() is None:
                            result["terminated"] = True
                            self._terminate(process)
                    else:
                        process.wait(timeout=max(0.001, deadline - time.monotonic()))
                result["returncode"] = process.wait(timeout=2.0)
                allowed = specification.get("expected_returncodes", [0])
                if result["returncode"] not in allowed and not result["terminated"]:
                    result["status"] = "exit_error"
            except subprocess.TimeoutExpired:
                result["status"] = "timeout"
            except (OSError, CaptureError) as exc:
                result["status"] = "transport_error"
                result["diagnostics"].append("%s:%s" % (type(exc).__name__, exc))
            finally:
                if process is not None:
                    if process.poll() is None:
                        self._terminate(process)
                    result["returncode"] = process.poll()
                    if process.stdin is not None:
                        try:
                            process.stdin.close()
                        except OSError:
                            pass
                        process.stdin = None
                stop_probes.set()
                if probe_thread is not None:
                    probe_thread.join(timeout=3.0)
                    if probe_thread.is_alive():
                        result["diagnostics"].append("handoff_capture_did_not_stop")
                if gdb_process is not None:
                    try:
                        gdb_process.wait(timeout=2.0)
                    except subprocess.TimeoutExpired:
                        self._terminate(gdb_process)
        result["diagnostics"].extend(probe_errors)
        if not result["transport_success"]:
            result["input_count"] = 0
        result["duration_seconds"] = time.monotonic() - started
        records: List[Dict[str, Any]] = []
        for mapping in mappings:
            record = primitive(mapping)
            record.update({"kind": "module_mapping", "timestamp_ns": 0})
            records.append(record)
        if options["recorder"] == "lbr":
            if not trace_capture.is_file() or trace_capture.stat().st_size == 0:
                result["diagnostics"].append("lbr_capture_missing")
            else:
                try:
                    branches = directory / "branches.jsonl"
                    LBRRecorder(self.config.dynamic).export(trace_capture, branches)
                    records.extend(iter_jsonl(branches))
                except Exception as exc:
                    result["diagnostics"].append("lbr_export:%s:%s" % (type(exc).__name__, exc))
        handoffs = directory / "handoffs.jsonl"
        if handoffs.is_file():
            records.extend(iter_jsonl(handoffs))
        prefix_events = directory / "prefix_events.jsonl"
        if prefix_events.is_file():
            prefixes = list(iter_jsonl(prefix_events))
            result["prefix_snapshots"] = [str(record["prefix_snapshot"]) for record in prefixes]
            for record in records:
                if record.get("access") != "consumer_read":
                    continue
                snapshot = next((prefix for prefix in prefixes if prefix.get("role") == "consumer"
                    and prefix.get("tid") == record.get("tid")
                    and abs(int(prefix.get("user_address", 0)) - int(record.get("user_address", 0))) <= 1), None)
                if snapshot is not None:
                    record["consumer_snapshot"] = snapshot["prefix_snapshot"]
            records.extend(prefixes)
        if options["prefix_sites"] and not baseline and len(result["prefix_snapshots"]) != len(options["prefix_sites"]):
            result["diagnostics"].append("requested_prefix_snapshots_missing")
        observed = [record for record in records if record.get("kind") not in {"module_mapping"}]
        if options["recorder"] != "none" and not observed:
            result["diagnostics"].append("no_observed_program_events")
        if options["recorder"] != "none" and not baseline and not any(record.get("kind") == "external_input" for record in observed):
            result["diagnostics"].append("external_input_observation_missing")
        if result["status"] == "completed" and any(reason.startswith(("lbr_", "no_observed_program_events")) for reason in result["diagnostics"]):
            result["status"] = "trace_error"
        metadata = {"kind": "run_metadata", "replay_id": replay, "profile_key": options["profile_key"],
                    "build_id": options["build_id"], "phase": "baseline" if baseline else "controlled",
                    "input_count": result["input_count"], "single_input": result["input_count"] == 1, "sequence": 0,
                    "timestamp_ns": 0, "status": result["status"]}
        if options["recorder"] != "none" or observed:
            ordered = sorted(records, key=lambda record: (int(record.get("timestamp_ns", 0)), int(record.get("sequence", 0))))
            for index, record in enumerate(ordered, 1):
                record.update({"replay_id": replay, "profile_key": options["profile_key"], "build_id": options["build_id"], "sequence": index})
                if baseline:
                    record.update({"phase": "baseline", "baseline": True})
            trace_path = directory / "trace.jsonl"
            write_jsonl(trace_path, [metadata] + ordered)
            result["trace"] = str(trace_path)
        dump_json(directory / "result.json", result)
        return result

    @staticmethod
    def _stdin_input(process: subprocess.Popen, data: bytes, deadline: float) -> None:
        errors: List[Exception] = []
        def deliver() -> None:
            stream = process.stdin
            try:
                stream.write(data)
            except OSError as exc:
                errors.append(exc)
            finally:
                try:
                    stream.close()
                except OSError as exc:
                    errors.append(exc)
        writer = threading.Thread(target=deliver, daemon=True)
        writer.start()
        writer.join(timeout=max(0.001, deadline - time.monotonic()))
        if writer.is_alive():
            raise subprocess.TimeoutExpired(process.args, 0)
        process.stdin = None
        if errors:
            raise CaptureError("target did not consume stdin: %s" % errors[0])

    @staticmethod
    def _target_pid(process: subprocess.Popen, binary: Path, recorder: str) -> int:
        if recorder == "none":
            return process.pid
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and process.poll() is None:
            children = Path("/proc/%d/task/%d/children" % (process.pid, process.pid))
            try:
                for item in children.read_text().split():
                    pid = int(item)
                    if Path("/proc/%d/exe" % pid).resolve() == binary:
                        return pid
            except (OSError, ValueError):
                pass
            time.sleep(0.01)
        return process.pid

    @staticmethod
    def _mappings(pid: int) -> List[ModuleMapping]:
        path = Path("/proc/%d/maps" % pid)
        try:
            lines = path.read_text().splitlines()
        except OSError:
            return []
        result = []
        for line in lines:
            fields = line.split(None, 5)
            if len(fields) < 6 or not fields[5].startswith("/"):
                continue
            start, end = fields[0].split("-", 1)
            name = fields[5].removesuffix(" (deleted)")
            result.append(ModuleMapping(Path(name).name, name, int(start, 16), int(end, 16), int(fields[2], 16)))
        return result

    @staticmethod
    def _observe(process: subprocess.Popen, seconds: float, deadline: float) -> None:
        remaining = min(max(0.0, seconds), max(0.0, deadline - time.monotonic()))
        try:
            process.wait(timeout=max(0.001, remaining))
        except subprocess.TimeoutExpired:
            return

    @staticmethod
    def _terminate(process: subprocess.Popen) -> None:
        if process.poll() is not None:
            return
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            process.wait(timeout=2.0)
        except ProcessLookupError:
            pass

    @staticmethod
    def _tcp_input(specification: Mapping[str, Any], data: bytes, deadline: float) -> bytes:
        host = str(specification.get("host", "127.0.0.1"))
        port = int(specification["port"])
        last_error = None
        connection = None
        while time.monotonic() < deadline:
            try:
                connection = socket.create_connection((host, port), timeout=min(1.0, max(0.01, deadline - time.monotonic())))
                break
            except ConnectionRefusedError as exc:
                last_error = exc
                time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        if connection is None:
            raise CaptureError("TCP target did not accept the single input: %s" % last_error)
        with connection:
            connection.settimeout(min(float(specification.get("response_timeout_seconds", 1.0)), max(0.01, deadline - time.monotonic())))
            connection.sendall(data)
            try:
                connection.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            response = bytearray()
            maximum = int(specification.get("maximum_response_bytes", 1024 * 1024))
            while len(response) < maximum:
                try:
                    block = connection.recv(min(65536, maximum - len(response)))
                except socket.timeout:
                    break
                if not block:
                    break
                response.extend(block)
            return bytes(response)

    def _start_prefix_capture(self, pid: int, directory: Path, options: Mapping[str, Any], mappings: Sequence[ModuleMapping]) -> subprocess.Popen:
        gdb = executable("gdb")
        helper = Path(__file__).resolve().parents[1] / "gdb" / "capture_prefix.py"
        specifications = []
        for index, item in enumerate(options["prefix_sites"]):
            spec = dict(item)
            module = str(spec.get("module", options["binary"].name))
            candidates = [mapping for mapping in mappings if mapping.module == module or mapping.path == module]
            if not candidates:
                raise CaptureError("no mapping for requested prefix module: %s" % module)
            base = min(mapping.runtime_start - mapping.file_offset for mapping in candidates)
            rva = parse_int(spec.get("rva"))
            if rva is None:
                raise CaptureError("prefix site requires an rva")
            spec.update({"address": base + rva, "rva": rva, "module_base": base,
                         "output": str(directory / ("prefix-%03d.json" % index))})
            specifications.append(spec)
        script = directory / "capture_prefixes.py"
        driver = '''import gdb,json,os,time
SPECS = __SPECS__
HELPER = __HELPER__
EVENTS = __EVENTS__
class Capture(gdb.Breakpoint):
    def __init__(self,spec):
        super().__init__("*0x%x" % spec["address"],internal=False)
        self.spec=spec
    def stop(self):
        spec=self.spec
        os.environ.update({"COMPASS_PREFIX_OUTPUT":spec["output"],"COMPASS_ENTRY_RVA":hex(spec["rva"]),"COMPASS_BUILD_ID":__BUILD__,"COMPASS_PROFILE_KEY":__PROFILE__,"COMPASS_MODULE_BASE":hex(spec["module_base"])})
        gdb.execute("source "+json.dumps(HELPER,ensure_ascii=False))
        record={"kind":"external_input" if spec.get("role","input") in {"input","entry"} else "prefix_snapshot","role":spec.get("role","input"),"module":spec.get("module",""),"rva":spec["rva"],"input_class":spec.get("input_class","file"),"input_site_id":spec.get("input_site_id",""),"syscall":spec.get("syscall",""),"entry_address":spec["address"],"user_address":spec["address"],"prefix_snapshot":spec["output"],"parameter_layout":spec.get("parameter_layout",{}),"pid":gdb.selected_inferior().pid,"tid":gdb.selected_thread().ptid[1],"timestamp_ns":time.monotonic_ns()}
        with open(EVENTS,"a") as stream: stream.write(json.dumps(record)+"\\n")
        self.enabled=False
        return False
gdb.execute("set pagination off")
gdb.execute("set confirm off")
for spec in SPECS: Capture(spec)
gdb.write("COMPASS_PREFIX_READY\\n")
gdb.flush()
gdb.execute("continue")
'''
        for marker, value in {"__SPECS__": specifications, "__HELPER__": str(helper), "__EVENTS__": str(directory / "prefix_events.jsonl"),
                              "__BUILD__": options["build_id"], "__PROFILE__": options["profile_key"]}.items():
            driver = driver.replace(marker, repr(value))
        script.write_text(driver, encoding="utf-8")
        process = subprocess.Popen([gdb, "--nx", "-q", "-batch", "-p", str(pid), "-x", str(script)],
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace",
                                   start_new_session=os.name == "posix")
        ready = threading.Event()
        def output_reader() -> None:
            with process.stdout as captured, (directory / "gdb.log").open("w", encoding="utf-8") as stream:
                for line in captured:
                    stream.write(line)
                    stream.flush()
                    if "COMPASS_PREFIX_READY" in line:
                        ready.set()
        threading.Thread(target=output_reader, daemon=True).start()
        if not ready.wait(timeout=min(5.0, options["timeout_seconds"])):
            self._terminate(process)
            raise CaptureError("GDB did not install the requested prefix breakpoints")
        return process
