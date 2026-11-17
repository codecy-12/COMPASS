# COMPASS

## 1. Environment

Use Linux x86-64 for native capture. The tested analysis environment is Ubuntu 22.04, Python 3.10, and angr 9.2.213. LBR capture additionally requires hardware and kernel support for perf branch stacks. WSL or virtual machines can run analysis but may not expose the required capture facilities.

Install the system dependencies:

```bash
sudo apt-get update
sudo apt-get install -y python3.10 python3.10-venv python3-dev \
  build-essential binutils gdb curl ca-certificates \
  linux-tools-common linux-tools-generic python3-bpfcc bpfcc-tools libbpfcc-dev
sudo apt-get install -y "linux-tools-$(uname -r)" "linux-headers-$(uname -r)"
```

Use tools and headers matching the running kernel. Install a [Sysdig release](https://github.com/draios/sysdig) supporting `--modern-bpf`. Install IDA Pro with IDAPython and FLIRT if using the IDA static backend. Docker is required only for the bundled Apache workflow.

Set the paths below to your installation, work directory, and application binary:

```bash
export COMPASS_ROOT=/absolute/path/to/COMPASS
export COMPASS_WORK=/absolute/path/to/compass-work
export COMPASS_BIN=/absolute/path/to/application
export COMPASS_ENV="$COMPASS_WORK/venv"
mkdir -p "$COMPASS_WORK"
python3.10 -m venv --system-site-packages "$COMPASS_ENV"
source "$COMPASS_ENV/bin/activate"
python -m pip install --upgrade pip
python -m pip install angr==9.2.213
export PYTHONDONTWRITEBYTECODE=1
cd "$COMPASS_ROOT"
cp config.example.json "$COMPASS_WORK/config.json"
python -c 'import angr, bcc; print("angr", angr.__version__); print("BCC available")'
python -m compass --help
```

For the existing Windows checkout, its WSL path is `/mnt/f/转投/BinAI/COMPASS`. The virtual environment must use a Python version compatible with the installed system BCC bindings; `--system-site-packages` makes those bindings visible.

Run commands from `COMPASS_ROOT`. Global `--config` precedes `offline`, `monitor`, or `investigate`. Privileged capture commands below explicitly use the virtual-environment interpreter.

## 2. Configuration

Edit `$COMPASS_WORK/config.json`:

| Setting | Value to configure |
| --- | --- |
| `static.backend` | `ida`, `angr`, or `auto` |
| `static.ida_path` | Absolute IDA executable path when using IDA |
| `static.load_external_libraries` | Enable when recovering library implementations |
| `dynamic.perf_path` | Path to `perf` |
| `dynamic.lbr_sample_period` | LBR sampling period |
| `monitor.sysdig_path` | Path to Sysdig |
| `monitor.use_modern_ebpf` | Enable for the modern Sysdig eBPF backend |
| `monitor.snaplen` | Sysdig payload limit; default `65535` |
| `monitor.capture_bytes` | Supplementary payload limit; maximum `60000` |
| `investigation.simprocedure_manifest` | Optional path to custom interface models |

Keep the matching application binary and dependency libraries available throughout preparation and investigation.

### LLM configuration

Replace the `llm` object in the copied configuration with your service settings:

```json
{
  "provider": "deepseek",
  "base_url": "https://api.deepseek.com/chat/completions",
  "model": "deepseek-chat",
  "api_key": "",
  "timeout_seconds": 60.0,
  "temperature": 0.0
}
```

`base_url` is the complete POST endpoint. Set `model` to an identifier accepted by that endpoint; use a pinned V3.2 deployment when reproducing the paper's model version. The client uses the OpenAI-compatible chat-completions protocol.

Set the key before generating inputs:

```bash
read -rsp 'LLM API key: ' COMPASS_LLM_API_KEY
export COMPASS_LLM_API_KEY
printf '\n'
```

A nonempty `llm.api_key` takes precedence over the environment variable. Leave it empty to use the environment. Handwritten inputs do not require LLM configuration.

## 3. Code Organization

```text
COMPASS/
|-- config.example.json
|-- README.md
|-- scripts/
|   |-- prepare.py                 Controlled preparation runner
|   `-- run_once.py                Single-input runner
|-- examples/apache_cve_2021_41773/ Apache container workflow
`-- compass/
    |-- __main__.py               Python module entry point
    |-- cli.py                    Command-line entry points
    |-- config.py                 Configuration types and loading
    |-- schema.py                 Events, profiles, graph and state records
    |-- acg.py                    ACFG storage, labels and traversal
    |-- errors.py                 Error types
    |-- util.py                   Serialization and process helpers
    |-- llm.py                    LLM client and input proposals
    |-- offline/
    |   |-- pipeline.py           Offline orchestration
    |   |-- static.py             IDA/angr static recovery
    |   |-- inputs.py             Input plans, validation and generation
    |   |-- controlled.py         Baseline and single-input execution
    |   |-- dynamic.py            LBR capture and trace loading
    |   |-- ebpf.py               Function and handoff probes
    |   |-- baseline.py           Waiting-loop and request-region analysis
    |   |-- dataflow.py           Carrier and field validation
    |   |-- align.py              Module-relative alignment and completion
    |   `-- entry.py              Stable input-entry recovery
    |-- monitor/
    |   |-- collector.py          Capture and normalization orchestration
    |   |-- sysdig.py              Sysdig interface and event normalization
    |   |-- ebpf.py                Supplementary context and payload capture
    |   `-- handles.py             Versioned handle map
    |-- investigation/
    |   |-- pipeline.py           Graph/log loading and result saving
    |   |-- engine.py             Iterative investigation and app routing
    |   |-- provenance.py         Initial graph and object predecessors
    |   |-- candidates.py         Candidate input collection and ranking
    |   |-- binding.py            Event-to-node matching and constraints
    |   |-- prefix.py             Initialized-state capture and restoration
    |   |-- symbolic.py           Guided dependency verification
    |   |-- angr_extensions.py    ExplorationTechnique and SimStatePlugin
    |   |-- simprocedures.py      I/O and interface models
    |   |-- catalog.py            Legacy compatibility module
    |   `-- lightweight.py        Legacy compatibility module
    |-- ida/ida_export.py          IDAPython graph exporter
    `-- gdb/capture_prefix.py      GDB state exporter
```

`catalog.py` and `lightweight.py` do not route the current investigation workflow.

## 4. Offline Preparation

### 4.1 Recover the static graph

```bash
python -m compass --config "$COMPASS_WORK/config.json" offline static \
  --binary "$COMPASS_BIN" --output "$COMPASS_WORK/static.acfg.json"
```

List the recovered syscall sites before choosing input and snapshot locations:

```bash
python - "$COMPASS_WORK/static.acfg.json" <<'PY'
import json, sys
with open(sys.argv[1]) as stream:
    graph = json.load(stream)
for site in graph['syscall_sites']:
    print(site['id'], site['syscall'], site['module'], hex(site['rva']), site['argument_layout'])
PY
```

Use the target's actual module names, site IDs, and RVAs in the preparation plan. RVAs are module-relative; runtime absolute addresses are used only by the separate manual capture commands.

### 4.2 Create the execution plan

Save the following structure as `$COMPASS_WORK/plan.json`. Replace the application paths, argv, input data, and address/site placeholders for your target. Run the application in the foreground.

```json
{
  "command": ["/absolute/path/to/server", "--foreground"],
  "binary": "/absolute/path/to/server",
  "cwd": "/absolute/path/to/application-directory",
  "env": {},
  "profile_key": "server-deployment",
  "inputs": [{
    "id": "request-1",
    "transport": "tcp",
    "host": "127.0.0.1",
    "port": 18080,
    "data": "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    "expected_returncodes": [0],
    "observation_seconds": 0.5,
    "response_timeout_seconds": 2.0
  }],
  "repeats": 2,
  "include_baseline": true,
  "timeout_seconds": 30,
  "baseline_seconds": 2,
  "startup_seconds": 0.5,
  "recorder": "lbr",
  "handoff_probes": [],
  "prefix_sites": [{
    "module": "server",
    "rva": "0x1234",
    "role": "input",
    "input_class": "network",
    "input_site_id": "REPLACE_WITH_ACTUAL_SITE_ID",
    "syscall": "recvfrom",
    "parameter_layout": {"fd": "arg:0", "buffer": "arg:1", "length": "arg:2"}
  }],
  "input_generation": {
    "format": "http",
    "transport": "tcp",
    "host": "127.0.0.1",
    "port": 18080,
    "expected_exit_codes": [0],
    "max_input_bytes": 65535
  }
}
```

Use the same binary for `COMPASS_BIN` and `plan.binary`. Use absolute argv paths or set `cwd`; argv entries other than the executable are not automatically resolved against the plan directory.

| Plan field | How to set it |
| --- | --- |
| `inputs` | Unique nonempty IDs and nonempty payloads; generation alone may start with an empty array |
| `transport` | `stdin`, `file`, or `tcp` |
| `data` | Actual UTF-8 text, byte-value array, or `{"encoding":"base64","data":"..."}` |
| File transport | Include the literal `{input}` in command/input argv |
| `repeats` / `include_baseline` | At least `2` / `true` for complete preparation evidence |
| `recorder` | `lbr` for branch capture; `none` for input smoke tests |
| `prefix_sites` | Actual input-entry and required consumer-context snapshot locations |
| `parameter_layout` | Entry ABI locations: `arg:N`, `reg:NAME`, or `mem:ADDRESS` |
| `input_generation.format` | `raw`, `json`, or `http` |

At raw x86-64 syscalls, use the syscall ABI, including `r10` for the fourth argument. Library wrappers use their own module and function ABI. Configure probes/snapshots for the actual process being followed; the runner does not automatically follow arbitrary daemon/fork trees.

For cross-context capture, populate `handoff_probes` with the actual function/access locations:

| Probe role | Fields to provide |
| --- | --- |
| `entry` | `rva`, `input_class`, `input_site_id`, `parameter_layout`, and the matching snapshot when managed separately |
| `producer` | `rva`, `carrier_argument`, `value_argument`, `transfer_fields` |
| `consumer` | `rva`, `carrier_argument`, `value_argument`, `transfer_fields`; provide a consumer snapshot |
| `function` | Function-entry `rva` and `function_id` from the static graph |

Argument indices are zero-based and range from 0 to 5. Each transfer field supplies `source`, `destination`, byte `width`, and any required object/pointee metadata. The locations and field mappings must correspond to the target binary. Add `prefix_sites` with `role: "consumer"` for receiver state; match the receiver thread and read/probe location, or explicitly provide its snapshot path.

To enable baseline request-region analysis, add `function` probes for the function set to observe and use the same set in baseline and controlled runs. LBR samples alone do not supply a complete function trajectory. `handoff_probes` and `prefix_sites` can also reference JSON files containing `probes` and `sites` arrays.

```bash
export COMPASS_PLAN="$COMPASS_WORK/plan.json"
```

### 4.3 Generate and test inputs with the LLM (optional)

Write the target protocol/input requirements to `$COMPASS_WORK/protocol.md`, configure the service, and run:

```bash
python -m compass --config "$COMPASS_WORK/config.json" offline generate-inputs \
  --plan "$COMPASS_PLAN" --documentation "$COMPASS_WORK/protocol.md" \
  --input-class network --count 20 \
  --output "$COMPASS_WORK/generated-suite.json" \
  --validation-output "$COMPASS_WORK/generated-validation.json"
export COMPASS_PLAN="$COMPASS_WORK/generated-suite.json"
```

The output suite is a reusable preparation plan. Review the validation/provenance files and execution manifests. `--count` accepts 1–1000. Generation validates and executes inputs with tracing disabled; continue with the capture stage below. Keep using the handwritten plan to skip generation.

### 4.4 Run the baseline and repeated inputs

```bash
sudo --preserve-env=PYTHONDONTWRITEBYTECODE "$COMPASS_ENV/bin/python" \
  -m compass --config "$COMPASS_WORK/config.json" offline exercise \
  --plan "$COMPASS_PLAN" --output "$COMPASS_WORK/preparation"
```

The equivalent script entry point is:

```bash
sudo --preserve-env=PYTHONDONTWRITEBYTECODE "$COMPASS_ENV/bin/python" \
  scripts/prepare.py --config "$COMPASS_WORK/config.json" \
  --plan "$COMPASS_PLAN" --output "$COMPASS_WORK/preparation"
```

Choose one entry point per run and use a new output directory when repeating it. Inspect `manifest.json`, each run's `result.json`, captured traces, and prefix snapshots. Resolve missing capture/snapshot diagnostics before full investigation. A zero command exit code alone does not establish `manifest.complete`.

### 4.5 Execute one selected input

Select the first input from the current plan, or set `COMPASS_INPUT_ID` to another ID present in it:

```bash
export COMPASS_INPUT_ID="$(python -c 'import json, sys; print(json.load(open(sys.argv[1]))["inputs"][0]["id"])' "$COMPASS_PLAN")"
sudo --preserve-env=PYTHONDONTWRITEBYTECODE "$COMPASS_ENV/bin/python" \
  scripts/run_once.py --config "$COMPASS_WORK/config.json" \
  --plan "$COMPASS_PLAN" --input-id "$COMPASS_INPUT_ID" --output "$COMPASS_WORK/single-run"
```

Alternatively use `offline run-once` with the same `--plan`, `--input-id`, and `--output`. Generated suites use IDs such as `generated-001`. This command performs one input without a baseline. For an unprivileged smoke test, use a separate plan with `recorder: "none"` and empty capture probes/sites, and omit `sudo`.

Existing manifests/run directories are not overwritten. When `--output` is omitted, run-once uses a directory under the plan's `.compass-run-once`; select a new output directory for repeated executions.

### 4.6 Build the final ACFG

Read all trace paths from the preparation manifest and pass them to the builder:

```bash
mapfile -t COMPASS_TRACES < <(python - "$COMPASS_WORK/preparation/manifest.json" <<'PY'
import json, sys
with open(sys.argv[1]) as stream:
    print('\n'.join(json.load(stream)['trace_paths']))
PY
)
COMPASS_TRACE_ARGS=()
for COMPASS_TRACE in "${COMPASS_TRACES[@]}"; do
  COMPASS_TRACE_ARGS+=(--dynamic-trace "$COMPASS_TRACE")
done
python -m compass --config "$COMPASS_WORK/config.json" offline build \
  --binary "$COMPASS_BIN" "${COMPASS_TRACE_ARGS[@]}" \
  --output "$COMPASS_WORK/application.acfg.json"
```

Keep the ACFG, referenced prefix snapshots, binary, and matching libraries together and accessible. Capture directories are still needed after graph construction.

## 5. Runtime Monitoring

Start the deployed application, set its actual PID, and collect audit logs:

```bash
export COMPASS_PID=12345
sudo --preserve-env=PYTHONDONTWRITEBYTECODE "$COMPASS_ENV/bin/python" \
  -m compass --config "$COMPASS_WORK/config.json" monitor run \
  --pid "$COMPASS_PID" --duration 3600 \
  --raw-sysdig "$COMPASS_WORK/sysdig.jsonl" \
  --raw-supplementary "$COMPASS_WORK/context.jsonl" \
  --output "$COMPASS_WORK/audit.jsonl"
```

`--pid` selects one process. Omit it to collect all participating worker/application processes system-wide.

For separate capture, run the first two commands concurrently in separate terminals, then normalize:

```bash
sudo --preserve-env=PYTHONDONTWRITEBYTECODE "$COMPASS_ENV/bin/python" \
  -m compass --config "$COMPASS_WORK/config.json" monitor capture \
  --pid "$COMPASS_PID" --duration 3600 --output "$COMPASS_WORK/sysdig.jsonl"

sudo --preserve-env=PYTHONDONTWRITEBYTECODE "$COMPASS_ENV/bin/python" \
  -m compass --config "$COMPASS_WORK/config.json" monitor ebpf \
  --pid "$COMPASS_PID" --duration 3600 --output "$COMPASS_WORK/context.jsonl"

python -m compass --config "$COMPASS_WORK/config.json" monitor normalize \
  --sysdig-log "$COMPASS_WORK/sysdig.jsonl" \
  --supplementary-log "$COMPASS_WORK/context.jsonl" \
  --output "$COMPASS_WORK/audit.jsonl"
```

Use a single capture workflow for a monitoring interval. Raw input to `monitor normalize` must use the explicit fields and Base64 buffers emitted by `monitor capture`.

## 6. Attack Investigation

### 6.1 Create the deployment profile

Generate `$COMPASS_WORK/profile.json` from the same binary and plan:

```bash
python - "$COMPASS_PLAN" "$COMPASS_WORK/profile.json" <<'PY'
import hashlib, json, sys
from pathlib import Path
plan_path = Path(sys.argv[1]).resolve()
plan = json.loads(plan_path.read_text())
binary = Path(plan.get('binary', plan['command'][0])).expanduser()
if not binary.is_absolute():
    binary = plan_path.parent / binary
binary = binary.resolve()
digest = hashlib.sha256()
with binary.open('rb') as stream:
    for block in iter(lambda: stream.read(1048576), b''):
        digest.update(block)
profile = {'profile_key': plan['profile_key'], 'build_id': digest.hexdigest(),
           'executable': str(binary), 'role': binary.name,
           'concurrency_module': '', 'concurrency': {}}
Path(sys.argv[2]).write_text(json.dumps(profile, indent=2) + '\n')
PY
```

### 6.2 Select the symptom event

List output/fault event IDs from the final audit log:

```bash
python - "$COMPASS_WORK/audit.jsonl" <<'PY'
import json, sys
with open(sys.argv[1]) as stream:
    for line in stream:
        event = json.loads(line)
        if event['direction'] in ('output', 'fault'):
            print(event['id'], event['pid'], event['syscall'], event['args'], event.get('result'))
PY
```

Select the event corresponding to the known symptom and set its exact ID:

```bash
export COMPASS_SYMPTOM=evt:123456
```

### 6.3 Run investigation

```bash
python -m compass --config "$COMPASS_WORK/config.json" investigate \
  --acfg "$COMPASS_WORK/application.acfg.json" \
  --log "$COMPASS_WORK/audit.jsonl" --profile "$COMPASS_WORK/profile.json" \
  --symptom "$COMPASS_SYMPTOM" --output "$COMPASS_WORK/attack-graph.json"
```

Inspect `attack-graph.json`: `attack_nodes`, `attack_edges`, `metadata.verified_dependencies`, `metadata.retained_dependencies`, and `metadata.analysis_reasons`. The result is JSON; no graph image is generated automatically. A result containing retained dependencies is `unresolved`.

### 6.4 Investigate across applications

Prepare each application's ACFG and profile separately. Add the matching `deployment_profile` to each application's audit events before investigation. A PID-to-profile mapping can be saved as `$COMPASS_WORK/profiles-by-pid.json`, with PID strings as keys and profile JSON paths as values.

```bash
python - "$COMPASS_WORK/profiles-by-pid.json" "$COMPASS_WORK/audit.jsonl" \
  "$COMPASS_WORK/audit-profiled.jsonl" <<'PY'
import json, sys
from pathlib import Path
mapping = json.loads(Path(sys.argv[1]).read_text())
profiles = {pid: json.loads(Path(path).read_text()) for pid, path in mapping.items()}
with open(sys.argv[2]) as source, open(sys.argv[3], 'w') as target:
    for line in source:
        event = json.loads(line)
        profile = profiles.get(str(event['pid']))
        if profile is not None:
            event.setdefault('metadata', {})['deployment_profile'] = profile
        target.write(json.dumps(event) + '\n')
PY
python -m compass --config "$COMPASS_WORK/config.json" investigate \
  --acfg "$COMPASS_WORK/frontend.acfg.json" \
  --acfg "$COMPASS_WORK/backend.acfg.json" \
  --log "$COMPASS_WORK/audit-profiled.jsonl" --symptom "$COMPASS_SYMPTOM" \
  --output "$COMPASS_WORK/attack-graph.json"
```

Use absolute profile paths in the PID mapping and ensure each PID belongs to that deployment throughout the selected log window. An ACFG bundle with `{"acfgs":["frontend.acfg.json","backend.acfg.json"]}` is also accepted; member paths are relative to the bundle file. Keep reliable shared-object or `producer_event_ids`/`peer_event_ids` associations for cross-endpoint transfers.

## 7. Separately Managed Offline Capture

Use these commands when the application lifecycle is managed outside `offline exercise`. Supply actual runtime addresses, mappings, and deployment identifiers.

```bash
python -m compass --config "$COMPASS_WORK/config.json" offline lbr-record \
  --output "$COMPASS_WORK/run.perf" -- "$COMPASS_BIN"
python -m compass --config "$COMPASS_WORK/config.json" offline lbr-export \
  --capture "$COMPASS_WORK/run.perf" --output "$COMPASS_WORK/branches.jsonl"
```

```bash
sudo --preserve-env=PYTHONDONTWRITEBYTECODE "$COMPASS_ENV/bin/python" \
  -m compass offline handoff-capture \
  --binary "$COMPASS_BIN" --probe-map "$COMPASS_WORK/probes.json" \
  --module-base "$COMPASS_MODULE_BASE" --replay-id "$COMPASS_REPLAY_ID" \
  --profile-key "$COMPASS_PROFILE_KEY" --pid "$COMPASS_PID" --duration 60 \
  --output "$COMPASS_WORK/handoffs.jsonl"
```

```bash
sudo --preserve-env=PYTHONDONTWRITEBYTECODE "$COMPASS_ENV/bin/python" \
  -m compass offline prefix-capture --pid "$COMPASS_PID" \
  --entry-address "$COMPASS_ENTRY_ADDRESS" --entry-rva "$COMPASS_ENTRY_RVA" \
  --module-base "$COMPASS_MODULE_BASE" --build-id "$COMPASS_BUILD_ID" \
  --profile-key "$COMPASS_PROFILE_KEY" --output "$COMPASS_WORK/prefix.json"
```

Set the address variables from the live process and static graph; set `COMPASS_BUILD_ID` to the binary SHA-256. Supply captured module mappings with `offline build --mappings` when they are not embedded in the traces. Use `--help` on any subcommand for its full argument list.

## 8. Bundled Apache Workflow

With Docker running and the analysis environment active:

```bash
bash examples/apache_cve_2021_41773/run.sh --keep "$COMPASS_WORK/apache-case"
```

This workflow retains its container trace, graph slice, audit log, and investigation output. Complete prefix snapshots are not supplied by this adapter; check whether the resulting dependency is verified or retained.
