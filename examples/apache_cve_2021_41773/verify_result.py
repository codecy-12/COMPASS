#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify the Apache CVE-2021-41773 Quick Start result")
    parser.add_argument("--case", required=True, type=Path)
    parser.add_argument("--result", required=True, type=Path)
    parser.add_argument("--require-verified", action="store_true")
    args = parser.parse_args()

    case = json.loads(args.case.read_text(encoding="utf-8"))
    result = json.loads(args.result.read_text(encoding="utf-8"))
    expected_dependency = [case["input_event"], case["symptom_event"]]
    dependencies = result.get("metadata", {}).get("verified_dependencies", [])
    retained = result.get("metadata", {}).get("retained_dependencies", [])

    if expected_dependency not in dependencies and expected_dependency not in retained:
        raise RuntimeError("the expected request-to-open dependency is missing")
    verified = expected_dependency in dependencies
    if args.require_verified and not verified:
        raise RuntimeError("the request remains retained; complete ACFG and prefix snapshots are required for verification")
    if verified and case["input_event"] not in result.get("verified_predecessors", []):
        raise RuntimeError("the verified exploit request was not returned as a predecessor")
    if not verified and result.get("status") != "unresolved":
        raise RuntimeError("a retained dependency must not be reported as resolved")

    print("Observed benign request: %s" % case["benign_request"])
    print("Observed exploit request: %s" % case["request"])
    print("Observed symptom: openat(%s)" % case["opened_path"])
    print("COMPASS result: %s" % result.get("status", "unknown"))
    print("%s dependency: %s -> %s" % (("Verified" if verified else "Retained",) + tuple(expected_dependency)))
    if not verified:
        print("This example provides a graph slice and audit log, not the complete prefix snapshots needed for symbolic verification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
