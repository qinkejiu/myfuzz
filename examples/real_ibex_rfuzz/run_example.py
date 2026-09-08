#!/usr/bin/env python3
"""Compose, test, and inspect the real-Ibex RFuzz example."""

import argparse
import hashlib
import json
import os
from pathlib import Path

from myfuzz.integration.real_cpu_campaign import build_candidate
from myfuzz.integration.rfuzz_live import replay_corpus, run_live


SCHEMA = "real_ibex_rfuzz_example.v1"
RESULT_SCHEMA = "real_ibex_rfuzz_example_result.v1"
EXPECTED_KEYS = frozenset({
    "schema_version", "id", "interface", "isa", "isa_contract", "protocol",
    "input_mode", "memory_domains", "test_header", "reset_vector", "probe_cycles", "composition_seed",
    "randomizable_fields", "control_defaults", "personality",
})
PERSONALITY_KEYS = frozenset({"name", "module", "source", "mode"})
ROOT = Path(__file__).resolve().parents[2]


def _object(value, label):
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _exact_keys(document, expected, label):
    unknown = sorted(set(document) - expected)
    missing = sorted(expected - set(document))
    if unknown:
        raise ValueError(f"{label} has unknown keys: {', '.join(unknown)}")
    if missing:
        raise ValueError(f"{label} is missing keys: {', '.join(missing)}")


def _integer(value, label, *, positive=False):
    if type(value) is not int or (positive and value <= 0):
        qualifier = "a positive integer" if positive else "an integer"
        raise ValueError(f"{label} must be {qualifier}")
    return value


def _string(value, label):
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a nonempty string")
    return value


def _source_path(root, value, label):
    relative = Path(_string(value, label))
    if relative.is_absolute():
        raise ValueError(f"{label} must be relative to the repository root")
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"{label} escapes the repository root") from error
    if not resolved.is_file():
        raise ValueError(f"{label} does not exist: {value}")
    return resolved


def _publish(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def load_example(path, root=ROOT):
    """Validate an example input and return production config/personality data."""
    root = Path(root).resolve()
    input_path = Path(path).resolve()
    try:
        document = _object(json.loads(input_path.read_text()), "example input")
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read example input: {error}") from error
    _exact_keys(document, EXPECTED_KEYS, "example input")
    if document["schema_version"] != SCHEMA:
        raise ValueError(f"schema_version must be {SCHEMA}")

    for key in ("id", "interface", "isa"):
        _string(document[key], key)
    _source_path(root, document["interface"], "interface")
    _object(document["isa_contract"], "isa_contract")
    if document["input_mode"] != "contract_transducer":
        raise ValueError("input_mode must be contract_transducer")
    if document["memory_domains"] != {
        "instruction_memory_master": "main", "data_memory_master": "main",
    }:
        raise ValueError("memory_domains must bind instruction and data memory to main")
    header = _object(document["test_header"], "test_header")
    _exact_keys(header, {"reset_cycles", "execution_cycles", "boot_address", "hart_id", "illegal_instruction"},
                "test_header")
    for key in ("reset_cycles", "execution_cycles"):
        _integer(header[key], f"test_header.{key}", positive=True)
    for key in ("boot_address", "hart_id"):
        _integer(header[key], f"test_header.{key}")
        if not 0 <= header[key] < 1 << 32:
            raise ValueError(f"test_header.{key} must fit an unsigned 32-bit value")
    if type(header["illegal_instruction"]) is not bool:
        raise ValueError("test_header.illegal_instruction must be boolean")
    protocol = document["protocol"]
    if not isinstance(protocol, list) or len(protocol) != 2 or not all(isinstance(v, str) and v for v in protocol):
        raise ValueError("protocol must contain two nonempty strings")
    for key in ("reset_vector", "composition_seed"):
        _integer(document[key], key)
    _integer(document["probe_cycles"], "probe_cycles", positive=True)
    if not document["probe_cycles"] <= header["execution_cycles"] <= 200:
        raise ValueError("probe_cycles must fit header execution_cycles (at most 200)")
    randomizable = document["randomizable_fields"]
    if not isinstance(randomizable, list) or not randomizable or not all(isinstance(v, str) and v for v in randomizable):
        raise ValueError("randomizable_fields must be a nonempty string array")
    controls = _object(document["control_defaults"], "control_defaults")
    if not all(isinstance(key, str) and type(value) is int for key, value in controls.items()):
        raise ValueError("control_defaults must map strings to integers")

    personality = _object(document["personality"], "personality")
    _exact_keys(personality, PERSONALITY_KEYS, "personality")
    for key in ("name", "module", "source"):
        _string(personality[key], f"personality.{key}")
    _integer(personality["mode"], "personality.mode")
    _source_path(root, personality["source"], "personality.source")

    config = {key: value for key, value in document.items()
              if key not in {"schema_version", "personality"}}
    return config, dict(personality)


def _prepare_output(output):
    output = Path(output).resolve()
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    output.mkdir(parents=True)
    return output


def _proof_identity(proof):
    return {key: proof[key] for key in (
        "composition_hash", "layout_hash", "constraint_hash", "transducer_hash", "header_hash",
        "instruction_source",
    )}


def _verify_replay_identity(proof, replay, saved):
    if replay["entries"] != saved["entries"]:
        raise ValueError("replay count does not match saved corpus")
    if proof["constraint_hash"] != proof["transducer_hash"]:
        raise ValueError("constraint and transducer hashes differ")
    if replay["layout_hash"] != proof["layout_hash"] or replay["constraint_hash"] != proof["constraint_hash"]:
        raise ValueError("replay layout/constraint hash differs from build")
    for fresh, original in zip(replay["replays"], saved["replays"], strict=True):
        coverage_hash = "sha256:" + hashlib.sha256(bytes(fresh["counters"])).hexdigest()
        if coverage_hash != original.get("coverage_sha256"):
            raise ValueError("replay coverage hash differs from saved manifest")
        if fresh["trace_sha256"] != original.get("trace_sha256"):
            raise ValueError("replay trace hash differs from saved manifest")
        for key in ("input_sha256", "layout_hash", "constraint_hash", "transducer_hash", "header_hash",
                    "physical_controls_sha256", "simulator_inputs_sha256"):
            if fresh[key] != original[key]:
                raise ValueError(f"replay identity changed: {key}")
        for key in ("layout_hash", "constraint_hash", "transducer_hash", "header_hash"):
            if fresh[key] != proof[key]:
                raise ValueError(f"replay identity differs from build: {key}")


def compose_example(root, input_path, output):
    root = Path(root).resolve()
    config, personality = load_example(input_path, root)
    output = _prepare_output(output)
    _, proof = build_candidate(root, output / "build", config, personality)
    summary = {
        "schema_version": RESULT_SCHEMA,
        "mode": "compose",
        "status": "passed",
        "input": str(Path(input_path).resolve()),
        "output": str(output),
        "execution": proof["execution"],
        **_proof_identity(proof),
        "coverage": proof["coverage"],
    }
    _publish(output / "summary.json", summary)
    return summary


def test_example(root, input_path, client, output, seconds):
    _integer(seconds, "seconds", positive=True)
    root = Path(root).resolve()
    client = Path(client)
    client = (root / client).resolve() if not client.is_absolute() else client.resolve()
    if not client.is_file():
        raise ValueError(f"RFuzz client does not exist: {client}")
    if not os.access(client, os.X_OK):
        raise ValueError(f"RFuzz client is not executable: {client}")
    config, personality = load_example(input_path, root)
    output = _prepare_output(output)
    artifact, proof = build_candidate(root, output / "build", config, personality)
    live = run_live(
        artifact, client, output / "live",
        duration_seconds=seconds, seed_cycles=config["probe_cycles"],
    )
    replay = replay_corpus(artifact, output / "live/corpus")
    if replay["entries"] != live["corpus_entries"]:
        raise ValueError("replay count does not match saved corpus")
    execution = live.get("execution_totals", {})
    if (live["tests"] <= 0 or live["completed_feedback_exchanges"] <= 0
            or live["returncode"] != 0 or live["remaining_segments"]
            or execution.get("instruction_requests", 0) <= 0
            or execution.get("instruction_responses", 0) <= 0
            or execution.get("instruction_initializations", 0) < 2
            or any(execution.get(key) != 0 for key in ("errors", "protocol_errors", "transducer_errors"))):
        raise ValueError("bounded RFuzz contract execution acceptance failed")
    _verify_replay_identity(proof, replay, live["corpus_manifest"])
    _publish(output / "replay.json", replay)
    summary = {
        "schema_version": RESULT_SCHEMA,
        "mode": "test",
        "status": "passed",
        "input": str(Path(input_path).resolve()),
        "output": str(output),
        "duration_seconds": live["duration_seconds"],
        "returncode": live["returncode"],
        "tests": live["tests"],
        "corpus_entries": live["corpus_entries"],
        "completed_feedback_exchanges": live.get("completed_feedback_exchanges", 0),
        "execution": execution,
        **_proof_identity(proof),
        "coverage_kind": live["coverage_kind"],
        "simulator_diagnostics": live.get("simulator_diagnostics", {}),
        "replay_entries": replay["entries"],
        "remaining_segments": live["remaining_segments"],
    }
    _publish(output / "summary.json", summary)
    return summary


def replay_example(root, input_path, output, build_output):
    """Rebuild the configured RTL and verify all retained corpus observations."""
    root, output = Path(root).resolve(), Path(output).resolve()
    summary = inspect_example(output)
    if summary["mode"] != "test":
        raise ValueError("replay requires a completed test run")
    saved = _object(json.loads((output / "live/corpus_manifest.json").read_text()), "corpus manifest")
    config, personality = load_example(input_path, root)
    artifact, proof = build_candidate(root, build_output, config, personality)
    if _proof_identity(proof) != {key: summary[key] for key in _proof_identity(proof)}:
        raise ValueError("rebuild identity differs from saved run")
    replay = replay_corpus(artifact, output / "live/corpus")
    _verify_replay_identity(proof, replay, saved)
    _publish(Path(build_output).resolve() / "rebuild_replay.json", replay)
    return {"status": "passed", "mode": "replay", "replay_entries": replay["entries"],
            "output": str(output), "build_output": str(Path(build_output).resolve()), **_proof_identity(proof)}


def inspect_example(output):
    path = Path(output).resolve() / "summary.json"
    try:
        summary = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read summary: {error}") from error
    if not isinstance(summary, dict):
        raise ValueError("summary must be a JSON object")
    if summary.get("schema_version") != RESULT_SCHEMA:
        raise ValueError(f"summary schema_version must be {RESULT_SCHEMA}")
    if summary.get("mode") not in {"compose", "test"} or summary.get("status") != "passed":
        raise ValueError("summary has invalid mode or status")
    return summary


def _parser():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    compose = subparsers.add_parser("compose", help="compose, compile, and probe real Ibex")
    compose.add_argument("--input", type=Path, required=True)
    compose.add_argument("--output", type=Path, required=True)
    test = subparsers.add_parser("test", help="run a bounded official-client RFuzz test")
    test.add_argument("--input", type=Path, required=True)
    test.add_argument("--client", type=Path, required=True)
    test.add_argument("--output", type=Path, required=True)
    test.add_argument("--seconds", type=int, default=5)
    inspect = subparsers.add_parser("inspect", help="print a completed example summary")
    inspect.add_argument("--output", type=Path, required=True)
    replay = subparsers.add_parser("replay", help="rebuild RTL and replay a retained test corpus")
    replay.add_argument("--input", type=Path, required=True)
    replay.add_argument("--output", type=Path, required=True)
    replay.add_argument("--build-output", type=Path, required=True)
    return parser


def main(argv=None):
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "compose":
            result = compose_example(ROOT, args.input, args.output)
        elif args.command == "test":
            result = test_example(ROOT, args.input, args.client, args.output, args.seconds)
        elif args.command == "replay":
            result = replay_example(ROOT, args.input, args.output, args.build_output)
        else:
            result = inspect_example(args.output)
    except (ValueError, OSError, RuntimeError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
