"""Source from GDB after execution has stopped at an External-Input Entry Function."""

from __future__ import print_function

import base64
import json
import os

import gdb


def process_mappings(pid):
    mappings = []
    with open("/proc/%d/maps" % pid, "r") as stream:
        for line in stream:
            fields = line.rstrip("\n").split(None, 5)
            if len(fields) < 5:
                continue
            lower, upper = fields[0].split("-", 1)
            mappings.append({
                "start": int(lower, 16), "end": int(upper, 16),
                "permissions": fields[1], "file_offset": int(fields[2], 16),
                "name": fields[5] if len(fields) > 5 else "",
            })
    return mappings


def register_value(frame, name):
    value = frame.read_register(name)
    try:
        return int(value)
    except (TypeError, ValueError, gdb.error):
        for member in ("uint128", "uint256", "uint512"):
            try:
                return int(value[member])
            except (KeyError, TypeError, ValueError, gdb.error):
                pass
        for member, count in (("v8_int64", 8), ("v4_int64", 4), ("v2_int64", 2)):
            try:
                words = value[member]
                return sum((int(words[index]) & ((1 << 64) - 1)) << (64 * index) for index in range(count))
            except (KeyError, TypeError, ValueError, gdb.error):
                pass
        raise ValueError("unsupported register encoding: %s" % name)


def read_region(inferior, region, memory, failures):
    cursor = region["start"]
    while cursor < region["end"]:
        length = min(1024 * 1024, region["end"] - cursor)
        try:
            data = bytes(inferior.read_memory(cursor, length))
        except (gdb.error, MemoryError):
            length = min(4096, region["end"] - cursor)
            try:
                data = bytes(inferior.read_memory(cursor, length))
            except (gdb.error, MemoryError) as exc:
                failures.append({"start": cursor, "length": length, "error": str(exc)})
                cursor += length
                continue
        memory.append({
            "start": cursor, "permissions": region["permissions"], "name": region["name"],
            "data": {"encoding": "base64", "data": base64.b64encode(data).decode("ascii")},
        })
        cursor += length


def capture():
    output = os.environ.get("COMPASS_PREFIX_OUTPUT", "")
    if not output:
        raise gdb.GdbError("COMPASS_PREFIX_OUTPUT is not set")
    inferior = gdb.selected_inferior()
    frame = gdb.selected_frame()
    registers = {}
    names = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip", "eflags", "fs_base", "gs_base"]
    names += ["r%d" % index for index in range(8, 16)]
    names += ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"]
    names += ["x%d" % index for index in range(31)] + ["sp", "pc", "cpsr", "tpidr_el0"]
    names += ["xmm%d" % index for index in range(32)] + ["ymm%d" % index for index in range(32)]
    names += ["zmm%d" % index for index in range(32)] + ["v%d" % index for index in range(32)]
    names += ["mxcsr", "fpcr", "fpsr"]
    discovered = []
    try:
        discovered = [register.name for register in frame.architecture().registers()]
    except (AttributeError, gdb.error):
        pass
    missing_registers = []
    for name in sorted(set(names + discovered)):
        try:
            registers[name] = register_value(frame, name)
        except Exception:
            if name in discovered:
                missing_registers.append(name)
    memory = []
    mappings = process_mappings(inferior.pid)
    module_bases = {}
    module_paths = {}
    failures = []
    for region in mappings:
        name = region["name"]
        if name.startswith("/"):
            base = region["start"] - region["file_offset"]
            module_bases[name] = min(module_bases.get(name, base), base)
            module_paths[os.path.basename(name)] = name
        if "r" not in region["permissions"] or name in {"[vvar]", "[vvar_vclock]", "[vsyscall]"}:
            continue
        read_region(inferior, region, memory, failures)
    executable = os.readlink("/proc/%d/exe" % inferior.pid)
    main_base = module_bases.get(executable, int(os.environ.get("COMPASS_MODULE_BASE", "0"), 0))
    try:
        selected_thread = gdb.selected_thread()
        thread_id = int(selected_thread.ptid[1] or selected_thread.ptid[0])
    except (AttributeError, TypeError, gdb.error):
        thread_id = inferior.pid
    payload = {
        "build_id": os.environ.get("COMPASS_BUILD_ID", ""),
        "profile_key": os.environ.get("COMPASS_PROFILE_KEY", ""),
        "entry_rva": int(os.environ.get("COMPASS_ENTRY_RVA", "0"), 0),
        "module_bases": module_bases,
        "registers": registers,
        "memory": memory,
        "metadata": {
            "main_module_base": main_base, "module_paths": module_paths,
            "mappings": mappings, "tid": thread_id, "pid": inferior.pid,
            "memory_read_failures": failures, "missing_registers": missing_registers,
            "complete": not failures, "executable": executable,
        },
    }
    with open(output + ".tmp", "w") as stream:
        json.dump(payload, stream, indent=2, sort_keys=True)
    os.replace(output + ".tmp", output)


capture()
