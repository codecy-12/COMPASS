from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from .config import CompassConfig, load_config
from .errors import CompassError
from .investigation.pipeline import InvestigationPipeline
from .investigation.prefix import NativePrefixRecorder
from .monitor.collector import RuntimeCollector
from .monitor.ebpf import SupplementaryEBPF
from .offline.dynamic import LBRRecorder
from .offline.ebpf import HandoffProbe, PreparationHandoffRecorder
from .offline.pipeline import OfflinePipeline
from .offline.inputs import exercise_plan, generate_inputs, run_once
from .offline.static import StaticAnalyser
from .util import load_json


def _path(value: str) -> Path:
    return Path(value).expanduser().resolve()


def _configuration(args: argparse.Namespace) -> CompassConfig:
    return load_config(_path(args.config)) if args.config else CompassConfig()


def _offline_static(args: argparse.Namespace) -> int:
    config = _configuration(args)
    result = StaticAnalyser(config.static).analyse(_path(args.binary))
    result.graph.metadata["static_backend"] = result.backend
    result.graph.metadata["verified_direct_calls"] = result.verified_direct_calls
    result.graph.metadata["unresolved_indirect_sites"] = result.unresolved_indirect_sites
    result.graph.save(_path(args.output))
    print(json.dumps(result.graph.statistics(), sort_keys=True))
    return 0


def _offline_build(args: argparse.Namespace) -> int:
    config = _configuration(args)
    graph = OfflinePipeline(config).build(
        _path(args.binary),
        [_path(item) for item in args.dynamic_trace],
        _path(args.output),
        _path(args.mappings) if args.mappings else None,
    )
    print(json.dumps(graph.statistics(), sort_keys=True))
    return 0


def _offline_exercise(args: argparse.Namespace) -> int:
    result = exercise_plan(_path(args.plan), _path(args.output), _configuration(args))
    print(json.dumps(result, sort_keys=True))
    return 0 if all(run["status"] == "completed" for run in result["runs"]) else 1


def _offline_run_once(args: argparse.Namespace) -> int:
    result = run_once(_path(args.plan), args.input_id, _path(args.output) if args.output else None, _configuration(args))
    print(json.dumps(result, sort_keys=True))
    return 0 if all(run["status"] == "completed" for run in result["runs"]) else 1


def _offline_generate_inputs(args: argparse.Namespace) -> int:
    result = generate_inputs(_path(args.plan), _path(args.documentation), args.input_class, args.count, _path(args.output), _path(args.validation_output) if args.validation_output else None, _configuration(args))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["accepted"] else 1


def _lbr_record(args: argparse.Namespace) -> int:
    config = _configuration(args)
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    LBRRecorder(config.dynamic).record(command, _path(args.output), _path(args.cwd) if args.cwd else None)
    return 0


def _lbr_export(args: argparse.Namespace) -> int:
    config = _configuration(args)
    LBRRecorder(config.dynamic).export(_path(args.capture), _path(args.output))
    return 0


def _handoff_capture(args: argparse.Namespace) -> int:
    raw = load_json(_path(args.probe_map))
    values = raw.get("probes", raw) if isinstance(raw, dict) else raw
    probes = [HandoffProbe.from_dict(item) for item in values]
    PreparationHandoffRecorder().capture(
        binary=_path(args.binary),
        probes=probes,
        output=_path(args.output),
        replay_id=args.replay_id,
        profile_key=args.profile_key,
        module_base=int(args.module_base, 0),
        duration_seconds=args.duration,
        pid=args.pid,
    )
    return 0


def _prefix_capture(args: argparse.Namespace) -> int:
    NativePrefixRecorder().capture_process(
        pid=args.pid,
        entry_address=int(args.entry_address, 0),
        entry_rva=int(args.entry_rva, 0),
        build_id=args.build_id,
        profile_key=args.profile_key,
        module_base=int(args.module_base, 0),
        output=_path(args.output),
        gdb_path=args.gdb,
    )
    return 0


def _monitor_capture(args: argparse.Namespace) -> int:
    config = _configuration(args)
    RuntimeCollector(config).capture_sysdig(_path(args.output), args.duration, args.pid)
    return 0


def _monitor_ebpf(args: argparse.Namespace) -> int:
    config = _configuration(args)
    SupplementaryEBPF(config.monitor.capture_bytes).capture(_path(args.output), args.duration, args.pid)
    return 0


def _monitor_normalize(args: argparse.Namespace) -> int:
    config = _configuration(args)
    events = RuntimeCollector(config).normalize(
        _path(args.sysdig_log),
        _path(args.output),
        _path(args.supplementary_log) if args.supplementary_log else None,
    )
    print(json.dumps({"events": len(events)}, sort_keys=True))
    return 0


def _monitor_run(args: argparse.Namespace) -> int:
    config = _configuration(args)
    events = RuntimeCollector(config).capture(
        _path(args.raw_sysdig),
        _path(args.raw_supplementary),
        _path(args.output),
        args.duration,
        args.pid,
    )
    print(json.dumps({"events": len(events)}, sort_keys=True))
    return 0


def _investigate(args: argparse.Namespace) -> int:
    config = _configuration(args)
    result = InvestigationPipeline(config).run(
        [_path(value) for value in args.acg],
        _path(args.log),
        _path(args.catalog) if args.catalog else None,
        args.symptom,
        _path(args.output),
        _path(args.profile) if args.profile else None,
    )
    print(json.dumps({"status": result.status.value, "predecessors": len(result.verified_predecessors)}, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="compass", description="COMPASS ACFG-guided attack provenance")
    parser.add_argument("--config", help="JSON configuration file")
    commands = parser.add_subparsers(dest="command", required=True)

    offline = commands.add_parser("offline", help="offline ACFG preparation")
    offline_commands = offline.add_subparsers(dest="offline_command", required=True)
    static = offline_commands.add_parser("static", help="recover the static interprocedural CFG")
    static.add_argument("--binary", required=True)
    static.add_argument("--output", required=True)
    static.set_defaults(handler=_offline_static)
    build = offline_commands.add_parser("build", help="construct a build-specific ACFG")
    build.add_argument("--binary", required=True)
    build.add_argument("--dynamic-trace", action="append", required=True)
    build.add_argument("--mappings")
    build.add_argument("--output", required=True)
    build.set_defaults(handler=_offline_build)
    exercise = offline_commands.add_parser("exercise", help="execute a zero-input baseline and controlled single-input runs")
    exercise.add_argument("--plan", required=True)
    exercise.add_argument("--output", required=True)
    exercise.set_defaults(handler=_offline_exercise)
    once = offline_commands.add_parser("run-once", help="execute one selected preparation input without a baseline")
    once.add_argument("--plan", required=True)
    once.add_argument("--input-id", required=True)
    once.add_argument("--output")
    once.set_defaults(handler=_offline_run_once)
    generate = offline_commands.add_parser("generate-inputs", help="generate, structurally validate, and natively execute offline inputs")
    generate.add_argument("--plan", required=True)
    generate.add_argument("--documentation", required=True)
    generate.add_argument("--input-class", required=True)
    generate.add_argument("--count", type=int, required=True)
    generate.add_argument("--output", required=True)
    generate.add_argument("--validation-output")
    generate.set_defaults(handler=_offline_generate_inputs)
    record = offline_commands.add_parser("lbr-record", help="record preparation branch stacks")
    record.add_argument("--output", required=True)
    record.add_argument("--cwd")
    record.add_argument("command", nargs=argparse.REMAINDER)
    record.set_defaults(handler=_lbr_record)
    export = offline_commands.add_parser("lbr-export", help="export LBR data as normalized JSONL")
    export.add_argument("--capture", required=True)
    export.add_argument("--output", required=True)
    export.set_defaults(handler=_lbr_export)
    handoff = offline_commands.add_parser("handoff-capture", help="capture cross-context carrier accesses")
    handoff.add_argument("--binary", required=True)
    handoff.add_argument("--probe-map", required=True)
    handoff.add_argument("--module-base", required=True)
    handoff.add_argument("--replay-id", required=True)
    handoff.add_argument("--profile-key", required=True)
    handoff.add_argument("--duration", type=float, default=0.0)
    handoff.add_argument("--pid", type=int)
    handoff.add_argument("--output", required=True)
    handoff.set_defaults(handler=_handoff_capture)
    prefix = offline_commands.add_parser("prefix-capture", help="capture state at an external-input entry")
    prefix.add_argument("--pid", type=int, required=True)
    prefix.add_argument("--entry-address", required=True)
    prefix.add_argument("--entry-rva", required=True)
    prefix.add_argument("--module-base", required=True)
    prefix.add_argument("--build-id", required=True)
    prefix.add_argument("--profile-key", required=True)
    prefix.add_argument("--gdb", default="gdb")
    prefix.add_argument("--output", required=True)
    prefix.set_defaults(handler=_prefix_capture)

    monitor = commands.add_parser("monitor", help="runtime monitoring")
    monitor_commands = monitor.add_subparsers(dest="monitor_command", required=True)
    run = monitor_commands.add_parser("run", help="capture and normalize the runtime log")
    run.add_argument("--raw-sysdig", required=True)
    run.add_argument("--raw-supplementary", required=True)
    run.add_argument("--output", required=True)
    run.add_argument("--duration", type=float, required=True)
    run.add_argument("--pid", type=int)
    run.set_defaults(handler=_monitor_run)
    capture = monitor_commands.add_parser("capture", help="capture Sysdig records")
    capture.add_argument("--output", required=True)
    capture.add_argument("--duration", type=float, default=0.0)
    capture.add_argument("--pid", type=int)
    capture.set_defaults(handler=_monitor_capture)
    ebpf = monitor_commands.add_parser("ebpf", help="capture supplementary eBPF context")
    ebpf.add_argument("--output", required=True)
    ebpf.add_argument("--duration", type=float, default=0.0)
    ebpf.add_argument("--pid", type=int)
    ebpf.set_defaults(handler=_monitor_ebpf)
    normalize = monitor_commands.add_parser("normalize", help="merge and normalize runtime records")
    normalize.add_argument("--sysdig-log", required=True)
    normalize.add_argument("--supplementary-log")
    normalize.add_argument("--output", required=True)
    normalize.set_defaults(handler=_monitor_normalize)

    investigate = commands.add_parser("investigate", help="construct the precise attack subgraph")
    investigate.add_argument("--acfg", "--acg", dest="acg", action="append", required=True, help="ACFG or bundle; repeat for multiple applications")
    investigate.add_argument("--log", required=True)
    investigate.add_argument("--catalog", help=argparse.SUPPRESS)
    investigate.add_argument("--symptom", required=True)
    investigate.add_argument("--profile")
    investigate.add_argument("--output", required=True)
    investigate.set_defaults(handler=_investigate)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (CompassError, OSError, ValueError, KeyError) as exc:
        parser.exit(2, "compass: %s\n" % exc)
    return 2
