"""Run inside IDA: ida64 -A -S'ida_export.py --output graph.json' binary."""

from __future__ import print_function

import argparse
import hashlib
import json
import os
import sys


def _arguments(arguments=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    return parser.parse_args(list(arguments) if arguments is not None else sys.argv[1:])


def main():
    try:
        import ida_auto
        import ida_bytes
        import ida_funcs
        import ida_gdl
        import ida_idaapi
        import ida_idp
        import ida_kernwin
        import ida_nalt
        import idautils
        import idc
    except ImportError as exc:
        raise RuntimeError("ida_export.py must run inside IDA") from exc

    args = _arguments(idc.ARGV[1:])
    ida_auto.auto_wait()
    binary = ida_nalt.get_input_file_path()
    module = os.path.basename(binary)
    imagebase = ida_nalt.get_imagebase()
    digest = hashlib.sha256()
    with open(binary, "rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    result = {
        "schema_version": 2,
        "build_id": digest.hexdigest(),
        "binary": binary,
        "architecture": ida_idp.get_idp_name(),
        "functions": [], "blocks": [], "acg_edges": [], "cfg_edges": [],
        "syscall_sites": [], "entries": [],
        "metadata": {"unresolved_indirect_sites": [], "image_base": imagebase},
    }
    block_for = {}
    function_for = {}
    edge_number = 0
    syscall_number = 0
    wrappers = set([
        "read", "readv", "pread64", "recv", "recvfrom", "recvmsg", "recvmmsg", "write", "writev", "send", "sendto", "sendmsg", "sendmmsg",
        "open", "openat", "openat2", "close", "accept", "accept4", "socket", "connect", "pipe", "pipe2",
        "dup", "dup2", "dup3", "execve", "mmap", "munmap", "mprotect", "clone", "clone3", "futex",
    ])
    for address in idautils.Functions():
        function = ida_funcs.get_func(address)
        if not function:
            continue
        function_id = "%s:fn:%x" % (module, address - imagebase)
        function_for[address] = function_id
        result["functions"].append({
            "id": function_id,
            "name": ida_funcs.get_func_name(address) or "sub_%x" % address,
            "module": module,
            "rva": address - imagebase,
            "size": function.end_ea - function.start_ea,
            "is_external": False,
            "signature": idc.get_type(address) or "",
            "blocks": [],
            "metadata": {},
        })
        flow = ida_gdl.FlowChart(function)
        for block in flow:
            block_id = "%s:bb:%x" % (module, block.start_ea - imagebase)
            block_for[block.start_ea] = block_id
            result["blocks"].append({
                "id": block_id, "function_id": function_id, "module": module,
                "rva": block.start_ea - imagebase, "size": block.end_ea - block.start_ea,
                "instruction_count": len(list(idautils.Heads(block.start_ea, block.end_ea))),
                "terminal_kind": "", "metadata": {},
            })
            result["functions"][-1]["blocks"].append(block_id)

    for function in result["functions"]:
        if not function["blocks"]:
            continue
        edge_number += 1
        result["cfg_edges"].append({
            "id": "static:e%d" % edge_number,
            "source": function["id"], "target": function["blocks"][0], "kind": "cfg",
            "source_function": function["id"], "target_function": function["id"],
            "evidence": ["function-entry"], "metadata": {},
        })

    for function_address, function_id in function_for.items():
        function = ida_funcs.get_func(function_address)
        for block in ida_gdl.FlowChart(function):
            source = block_for[block.start_ea]
            for successor in block.succs():
                target = block_for.get(successor.start_ea)
                if target:
                    edge_number += 1
                    result["cfg_edges"].append({
                        "id": "static:e%d" % edge_number, "source": source, "target": target,
                        "kind": "cfg", "source_function": function_id,
                        "target_function": next((x["function_id"] for x in result["blocks"] if x["id"] == target), ""),
                        "evidence": ["ida-flowchart"], "metadata": {},
                    })
            for instruction in idautils.Heads(block.start_ea, block.end_ea):
                if not ida_bytes.is_code(ida_bytes.get_full_flags(instruction)):
                    continue
                mnemonic = idc.print_insn_mnem(instruction).lower()
                if mnemonic in ("syscall", "sysenter", "svc"):
                    syscall_number += 1
                    wrapper_name = (ida_funcs.get_func_name(function_address) or "").lstrip("_").split("@", 1)[0]
                    if wrapper_name.startswith("libc_"):
                        wrapper_name = wrapper_name[5:]
                    result["syscall_sites"].append({
                        "id": "%s:sys:%x" % (module, instruction - imagebase),
                        "function_id": function_id, "block_id": source, "module": module,
                        "rva": instruction - imagebase, "syscall": wrapper_name if wrapper_name in wrappers else "unknown",
                        "argument_layout": {}, "metadata": {"kind": "syscall_instruction"},
                    })
                    continue
                is_tail = mnemonic.startswith("jmp") or mnemonic in ("b", "br")
                if not (mnemonic.startswith("call") or mnemonic in ("bl", "blr") or is_tail):
                    continue
                target_address = idc.get_operand_value(instruction, 0)
                target_function_address = ida_funcs.get_func_attr(target_address, idc.FUNCATTR_START)
                target_function = function_for.get(target_function_address)
                is_indirect = mnemonic in ("blr", "br") or idc.get_operand_type(instruction, 0) not in (idc.o_near, idc.o_far)
                if target_function == function_id and is_tail:
                    continue
                if target_function and not is_indirect:
                    edge_number += 1
                    result["acg_edges"].append({
                        "id": "static:e%d" % edge_number, "source": source, "target": target_function,
                        "kind": "direct_call", "callsite_rva": instruction - imagebase,
                        "source_function": function_id, "target_function": target_function,
                        "evidence": ["ida-direct-call"], "metadata": {"tail_call": is_tail},
                    })
                    if not is_tail:
                        for continuation in block.succs():
                            continuation_id = block_for.get(continuation.start_ea)
                            if continuation_id:
                                target_func = ida_funcs.get_func(target_function_address)
                                for return_block in ida_gdl.FlowChart(target_func):
                                    successors = list(return_block.succs())
                                    last = idc.prev_head(return_block.end_ea, return_block.start_ea)
                                    return_mnemonic = idc.print_insn_mnem(last).lower() if last != ida_idaapi.BADADDR else ""
                                    if successors or not (return_mnemonic.startswith("ret") or return_mnemonic in ("bx",)):
                                        continue
                                    return_block_id = block_for.get(return_block.start_ea)
                                    if not return_block_id:
                                        continue
                                    edge_number += 1
                                    result["cfg_edges"].append({
                                        "id": "static:e%d" % edge_number,
                                        "source": return_block_id, "target": continuation_id, "kind": "return",
                                        "source_function": target_function, "target_function": function_id,
                                        "evidence": ["ida-call-return-site"], "metadata": {},
                                    })
                    target_name = (ida_funcs.get_func_name(target_address) or "").lstrip("_").split("@", 1)[0]
                    if target_name.startswith("libc_"):
                        target_name = target_name[5:]
                    if target_name in wrappers:
                        syscall_number += 1
                        result["syscall_sites"].append({
                            "id": "%s:sys:%x" % (module, instruction - imagebase),
                            "function_id": function_id, "block_id": source, "module": module,
                            "rva": instruction - imagebase, "syscall": target_name,
                            "argument_layout": {}, "metadata": {"kind": "wrapper_call"},
                        })
                else:
                    result["metadata"]["unresolved_indirect_sites"].append({
                        "module": module, "rva": instruction - imagebase, "function_id": function_id,
                    })
    with open(args.output, "w") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
    ida_kernwin.qexit(0)


if __name__ == "__main__":
    main()
