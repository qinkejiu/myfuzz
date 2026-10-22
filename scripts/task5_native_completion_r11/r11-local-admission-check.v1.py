#!/usr/bin/env python3
"""Local admission-only check for one r11 Stage 2 operation package.

This harness executes the frozen controller's own ``main``/``execute`` admission
path against a disposable byte-copy of the package.  It replaces exactly one
function, ``claimed_run``, with a recorder, so admission runs through the real
claims and preflight maps but no gate process, no ``native-cache`` directory, no
gate log, and no evidence directory is ever created.

Run it inside a user/mount namespace that binds the package mirror at the
target-absolute workspace path, for example::

    unshare -rm bash -c '
      mount --make-rprivate /
      mount -t tmpfs tmpfs /root
      mkdir -p /root/fanzehui/myfuzz
      mount --bind "$MIRROR" /root/fanzehui/myfuzz
      mkdir -p /root/fanzehui/system-20261016
      "$PYTHON" "$HARNESS" ...'

The result is local software evidence about admission, not a native gate, not a
passed independent audit, and not an exact-digest review.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys

sys.dont_write_bytecode = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--operation-dir", required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--workspace-dir", required=True)
    parser.add_argument("--stage2-manifest-sha256", required=True)
    parser.add_argument("--gate-run-id", required=True)
    parser.add_argument("--result")
    args = parser.parse_args()
    operation = args.operation_dir
    controller_path = operation + "/control/r11-one-shot-controller.v1.py"
    spec = importlib.util.spec_from_file_location("_r11_local_admission_controller",
                                                  controller_path)
    controller = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(controller)
    recorded = {}

    def recorder(*positional, **keyword):
        recorded["positional_count"] = len(positional)
        recorded["keyword_names"] = sorted(keyword)
        recorded["operation"] = positional[2]
        recorded["evidence"] = positional[3]
        recorded["workspace"] = positional[4]
        recorded["run"] = positional[5]
        recorded["run_id"] = positional[6]
        recorded["gate_interpreter"] = positional[9]
        recorded["claim"] = positional[12]
        recorded["lock_before"] = positional[11]
        return 0

    controller.claimed_run = recorder
    sys.argv = [controller_path, "--operation-dir", operation,
                "--evidence-dir", args.evidence_dir,
                "--workspace-dir", args.workspace_dir,
                "--stage2-manifest-sha256", args.stage2_manifest_sha256,
                "--execute"]
    result = {"schema_version": "r11_local_admission_check.v1",
              "status": "refused", "operation_dir": operation,
              "evidence_dir": args.evidence_dir,
              "workspace_dir": args.workspace_dir,
              "gate_run_id": args.gate_run_id,
              "stage2_manifest_sha256": args.stage2_manifest_sha256,
              "claimed_run_stubbed": True, "gate_launched": False}
    try:
        returncode = controller.main()
    except controller.Refusal as error:
        result["refusal"] = str(error)
        _emit(result, args.result)
        return 1
    except BaseException as error:  # noqa: BLE001 - report the exact failure
        result["error_type"] = type(error).__name__
        result["error"] = str(error)
        _emit(result, args.result)
        return 1
    claim_path = operation + "/control/claim.v1.json"
    launch_path = operation + "/control/launch-intent.v1.json"
    cache_path = operation + "/native-cache"
    evidence_path = args.evidence_dir
    claim = json.loads(open(claim_path, "rb").read())
    preflight_paths = [operation + "/control/protected-baselines-preflight.v1.json",
                       operation + "/control/submodules-preflight.v1.json"]
    checks = {
        "controller_main_returncode_zero": returncode == 0,
        "claimed_run_called_once": recorded.get("positional_count") == 13,
        "operation_identity": recorded.get("operation") == operation,
        "evidence_identity": recorded.get("evidence") == args.evidence_dir,
        "workspace_identity": recorded.get("workspace") == args.workspace_dir,
        "run_id_propagated": recorded.get("run_id") == args.gate_run_id
                               == recorded.get("run", {}).get("gate_run_id"),
        "stage2_sha_in_claim": claim.get("stage2_manifest_sha256") ==
                               args.stage2_manifest_sha256,
        "claim_gate_not_started": claim.get("gate_started") is False
                                  and claim.get("gate_executed") is False,
        "claim_one_shot": claim.get("one_shot") is True,
        "claim_argv_exact": claim.get("argv") == recorded.get("run", {}).get("argv"),
        "preflight_maps_written": all(os.path.isfile(path) for path in preflight_paths),
        "launch_intent_not_written": not os.path.exists(launch_path),
        "cache_not_created": not os.path.exists(cache_path),
        "gate_logs_not_created":
            not os.path.exists(operation + "/control/gate.stdout.log")
            and not os.path.exists(operation + "/control/gate.stderr.log"),
        "evidence_not_created": not os.path.exists(evidence_path),
        "gate_end_not_written":
            not os.path.exists(operation + "/control/gate-end.v1.json"),
        "post_run_not_written":
            not os.path.exists(operation + "/control/post-run-integrity.v1.json"),
    }
    result.update({"claim": claim, "checks": checks,
                   "recorded_run_id": recorded.get("run_id"),
                   "gate_interpreter": recorded.get("gate_interpreter"),
                   "status": "admission_preflight_passed" if all(checks.values())
                             else "admission_check_failed"})
    _emit(result, args.result)
    return 0 if all(checks.values()) else 1


def _emit(result, path):
    raw = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode()
    if path:
        with open(path, "wb") as stream:
            stream.write(raw)
    sys.stdout.buffer.write(raw)


if __name__ == "__main__":
    raise SystemExit(main())
