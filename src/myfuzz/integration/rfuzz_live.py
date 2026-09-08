"""Run the official RFuzz mutator against a generated persistent RTL simulator."""
import ctypes
import hashlib
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import time
from myfuzz.contracts import canonical_bytes
from .rfuzz_fifo import FifoEndpoint
from .rfuzz_shmem import process_pair
from .rfuzz_simulator import RtlSimulator
from .campaign import CampaignError, read_process_group_rss_bytes


def _hash_bytes(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _record_simulator_diagnostics(state, simulator):
    """Retain a bounded stdout sample while counting every captured RTL line."""
    report = state.setdefault("simulator_diagnostics", {"lines": 0, "sample_limit": 32, "samples": []})
    lines = getattr(simulator, "last_diagnostics", ())
    report["lines"] += len(lines)
    report["samples"].extend(lines[:max(0, report["sample_limit"] - len(report["samples"]))])


def _constraint_hash(artifact):
    projector = getattr(artifact, "projector", None)
    value = getattr(projector, "constraint_hash", None)
    if isinstance(value, str) and value:
        return value
    layout = getattr(artifact, "layout", None)
    fields = []
    for field in getattr(layout, "fields", ()):
        fields.append({
            "field_id": getattr(field, "field_id", None),
            "constraint": dict(getattr(field, "constraint", {})),
            "encoding": getattr(field, "encoding", None),
        })
    return _hash_bytes(canonical_bytes({
        "schema_version": "runtime_constraints.fallback.v1",
        "layout_hash": getattr(layout, "layout_hash", "unavailable"),
        "fields": fields,
    }))


def _binary_hash(artifact):
    executable = getattr(artifact, "executable", None)
    if executable is None:
        return "unavailable"
    path = Path(executable)
    if not path.is_file():
        return "unavailable"
    return _hash_bytes(path.read_bytes())


def _physical_control_document(artifact):
    defaults = getattr(artifact, "control_defaults", {})
    randomized = getattr(artifact, "randomized_controls", ())
    return {
        "defaults": defaults if isinstance(defaults, dict) else dict(defaults or {}),
        "randomized": list(randomized),
        "simulator": getattr(artifact, "simulator", "icarus"),
        "isolate_tests": getattr(artifact, "isolate_tests", False),
        "execution_monitor": getattr(artifact, "execution_monitor", None),
    }


def _simulator_input_document(artifact):
    document = []
    for argument in getattr(artifact, "simulator_args", ()):
        if argument.startswith("+riscv_boot_image="):
            path = Path(argument.split("=", 1)[1]).resolve()
            if not path.is_file():
                raise ValueError("simulator boot image is missing")
            document.append({"name": "riscv_boot_image", "sha256": _hash_bytes(path.read_bytes())})
        else:
            document.append({"value": argument})
    return document


def replay_identity(artifact, raw_payload):
    if not isinstance(raw_payload, bytes) or not raw_payload:
        raise ValueError("replay raw payload must be nonempty bytes")
    if getattr(artifact, "transducer_hash", None) is not None and not getattr(artifact, "implementation_hash", None):
        raise ValueError("replay transducer implementation identity is missing")
    layout = getattr(artifact, "layout", None)
    layout_hash = getattr(layout, "layout_hash", None)
    if not isinstance(layout_hash, str) or not layout_hash:
        raise ValueError("replay layout identity is missing")
    constraint_hash = _constraint_hash(artifact)
    binary_hash = _binary_hash(artifact)
    physical_controls = _physical_control_document(artifact)
    physical_controls_hash = _hash_bytes(canonical_bytes(physical_controls))
    simulator_inputs = _simulator_input_document(artifact)
    simulator_inputs_hash = _hash_bytes(canonical_bytes(simulator_inputs))
    inputs = {
        "raw_sha256": _hash_bytes(raw_payload),
        "layout_hash": layout_hash,
        "constraint_hash": constraint_hash,
        "binary_sha256": binary_hash,
        "physical_controls_sha256": physical_controls_hash,
        "simulator_inputs_sha256": simulator_inputs_hash,
    }
    for key in ("transducer_hash", "header_hash", "implementation_hash"):
        value = getattr(artifact, key, None)
        if value is not None:
            inputs[key] = value
    return {
        **inputs,
        "physical_controls": physical_controls,
        "simulator_inputs": simulator_inputs,
        "binary_hash": binary_hash,
        "replay_key": _hash_bytes(canonical_bytes(inputs)),
    }


_CONTRACT_REPLAY_KEYS = (
    "raw_sha256", "layout_hash", "constraint_hash", "transducer_hash",
    "implementation_hash", "header_hash", "physical_controls_sha256",
    "simulator_inputs_sha256",
)


def _corpus_document(path, *, byte_count):
    max_size = 5 * byte_count * 200 + 4 * 1024 * 1024
    if path.stat().st_size > max_size:
        raise ValueError("oversized RFuzz corpus entry")
    document = json.loads(path.read_text())
    if not isinstance(document, dict) or not isinstance(document.get("entry"), dict):
        raise ValueError("invalid RFuzz corpus entry")
    raw = document["entry"].get("inputs")
    expected = document.get("trace_bits")
    if (
        not isinstance(raw, list)
        or not isinstance(expected, list)
        or any(type(value) is not int or not 0 <= value <= 255 for value in raw + expected)
    ):
        raise ValueError("invalid RFuzz corpus bytes")
    if not raw or len(raw) % byte_count or len(raw) // byte_count > 200:
        raise ValueError("invalid RFuzz corpus input size")
    return document, bytes(raw), expected


def build_corpus_manifest(artifact, corpus_dir, *, feedback_receipts=None):
    """Index the actual RFuzz-saved wire corpus without synthesizing coverage."""
    corpus = Path(corpus_dir)
    paths = sorted(corpus.glob("entry_*.json"))
    if not paths:
        raise ValueError("empty RFuzz corpus")
    width = artifact.transport.byte_count
    verified = replay_corpus(artifact, corpus, _capture_receipts=feedback_receipts)
    verified_by_file = {entry["file"]: entry for entry in verified["replays"]}
    replays = []
    for path in paths:
        document, payload, expected = _corpus_document(path, byte_count=width)
        identity = replay_identity(artifact, payload)
        actual = verified_by_file.get(path.name)
        if actual is None or actual.get("input_sha256") != identity["raw_sha256"]:
            raise ValueError(f"RFuzz corpus coverage was not verified: {path.name}")
        declared = document.get("replay_identity")
        if isinstance(declared, dict):
            if getattr(artifact, "transducer_hash", None) is not None and not declared.get("implementation_hash"):
                raise ValueError(f"RFuzz replay identity mismatch: implementation_hash missing: {path.name}")
            for key in ("raw_sha256", "layout_hash", "constraint_hash", "binary_sha256",
                        "physical_controls_sha256", "simulator_inputs_sha256", "replay_key",
                        "transducer_hash", "header_hash", "implementation_hash"):
                if key in declared and declared[key] != identity.get(key):
                    raise ValueError(f"RFuzz replay identity mismatch: {path.name}")
        receipt = (identity["raw_sha256"], _hash_bytes(bytes(actual["counters"])))
        if feedback_receipts is not None and receipt not in feedback_receipts:
            raise ValueError(f"RFuzz corpus lacks completed shared-memory exchange: {path.name}")
        replays.append({
            "file": path.name,
            "input_bytes": len(payload),
            "cycles": len(payload) // width,
            "input_sha256": identity["raw_sha256"],
            "trace_sha256": _hash_bytes(bytes(expected)),
            "coverage_sha256": _hash_bytes(bytes(actual["counters"])),
            "coverage_verified": True,
            "shared_memory_exchange_verified": feedback_receipts is not None,
            **identity,
        })
    return {
        "schema_version": "rfuzz_corpus_manifest.v1",
        "coverage_kind": getattr(artifact, "coverage_kind", "unspecified-rtl-feedback"),
        "coverage_transport": "sysv-shared-memory-rfuzz-coverage-buffer",
        "entries": len(replays),
        "layout_hash": replays[0]["layout_hash"],
        **{key: replays[0][key] for key in ("transducer_hash", "header_hash", "implementation_hash") if key in replays[0]},
        "constraint_hash": replays[0]["constraint_hash"],
        "binary_sha256": replays[0]["binary_sha256"],
        "physical_controls_sha256": replays[0]["physical_controls_sha256"],
        "simulator_inputs_sha256": replays[0]["simulator_inputs_sha256"],
        "instruction_mode": getattr(getattr(artifact, "projector", None), "instruction_mode", "none"),
        "replays": replays,
    }


def _configuration(artifact):
    lines = ['[general]', 'filename = "live_tb.sv"', 'instrumented = "live_tb.sv"',
             'top = "myfuzz_live_tb"', 'timestamp = 2026-09-07T00:00:00Z',
             '[[input]]', 'name = "raw_bits"', f'width = {artifact.layout.raw_width}']
    for index, (port, bit) in enumerate(artifact.coverage_ports):
        name = json.dumps(f"{port}[{bit}]")
        lines.extend(['[[coverage]]', f'port = {name}', f'name = {name}', f'index = {index}',
            'filename = "live_tb.sv"', 'line = 0', 'column = 0',
            'human = "sampled output-bit event, not branch coverage"', '[[counter]]',
            f'name = {name}', 'width = 8', 'max = 255', 'scale = false',
            f'index = {index}', f'signal = {index}', 'fail = false'])
    return "\n".join(lines) + "\n"


def _owned_segments(pid):
    rows = Path("/proc/sysvipc/shm").read_text().splitlines()
    result = []
    for row in rows[1:]:
        entry = dict(zip(rows[0].split(), row.split()))
        if all(int(entry[key]) == value for key, value in (
                ("cpid", pid), ("uid", os.getuid()), ("cuid", os.getuid()))):
            result.append(int(entry["shmid"]))
    return result


def run_live(artifact, client_binary, output_dir, *, duration_seconds=30, seed_cycles=5):
    """Retain a failure report even when startup or an RTL exchange raises."""
    state = {}
    def terminated(signum, frame):
        # Defer asynchronous termination to a supervised checkpoint. Raising
        # inside Popen or cleanup can strand a successfully launched child.
        state["termination_signal"] = signal.Signals(signum).name
    # signal.signal deliberately rejects non-main-thread use before launching
    # anything: this supervisor must be able to handle external termination.
    previous_term = signal.signal(signal.SIGTERM, terminated)
    previous_int = signal.signal(signal.SIGINT, terminated)
    try:
        result = _run_live(artifact, client_binary, output_dir,
                           duration_seconds=duration_seconds, seed_cycles=seed_cycles, state=state)
        if "termination_signal" in state:
            raise KeyboardInterrupt(state["termination_signal"] + " received during RFuzz run")
        return result
    except BaseException as error:
        output = state.pop("_output", None)
        if output is not None:
            state.update(status="failed", error=f"{type(error).__name__}: {error}")
            (output / "report.json").write_text(json.dumps(state, sort_keys=True) + "\n")
        raise
    finally:
        signal.signal(signal.SIGTERM, previous_term)
        signal.signal(signal.SIGINT, previous_int)


def _run_live(artifact, client_binary, output_dir, *, duration_seconds, state, seed_cycles=5):
    if type(duration_seconds) not in (int,float) or not math.isfinite(duration_seconds) or not 0 < duration_seconds <= 86400:
        raise ValueError("finite positive live duration required")
    if type(seed_cycles) is not int or not 1 <= seed_cycles <= 200:
        raise ValueError("seed cycles must be between 1 and 200")
    binary=Path(client_binary).resolve(strict=True)
    output=Path(output_dir).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("live output must be new")
    output.mkdir(parents=True)
    state.update(_output=output, tests=0, status="starting", layout_hash=artifact.layout.layout_hash,
                 client_binary=str(binary), client_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                 coverage_kind=artifact.coverage_kind, requested_duration_seconds=duration_seconds,
                 transport=artifact.transport.document(),
                 constraint_hash=_constraint_hash(artifact),
                 binary_sha256=_binary_hash(artifact),
                 instruction_mode=getattr(getattr(artifact, "projector", None), "instruction_mode", "none"),
                 runtime_controls=getattr(artifact, "control_defaults", None),
                 randomized_controls=list(getattr(artifact, "randomized_controls", ())),
                 coverage_transport="sysv-shared-memory-rfuzz-coverage-buffer",
                 memory_scope="runner PID plus owned client and simulator process groups; sampled RSS",
                 soft_rss_bytes=512 * 1024 * 1024, hard_rss_bytes=768 * 1024 * 1024,
                 memory_poll_min_interval_seconds=.1,
                 memory_poll_policy="check at FIFO/RTL IO checkpoints; scheduling and encoding can delay sampling")
    if hasattr(artifact, "executable"):
        provenance = artifact.executable.parent / "artifact_provenance.json"
        if not provenance.is_file():
            provenance = artifact.executable.parent.parent / "artifact_provenance.json"
        state["artifact_provenance"] = json.loads(provenance.read_text()) if provenance.is_file() else None
        state["simulator_sha256"] = hashlib.sha256(artifact.executable.read_bytes()).hexdigest()
    state["mutation_seed"] = None
    state["mutation_seed_policy"] = "upstream has no global seed option; retain corpus lineage and raw inputs for replay"
    state["mutation_mode"] = "official default deterministic and havoc mutation, JQF level 2"
    state["initial_seed"] = {"kind": "all-zero", "cycles": seed_cycles}
    config=output/"rfuzz.toml"
    config.write_text(_configuration(artifact))
    state["config_sha256"] = hashlib.sha256(config.read_bytes()).hexdigest()
    started=time.monotonic()
    deadline=started+duration_seconds
    # Upstream completes a full shared-memory batch before honoring SIGINT.
    # Process-isolated RTL tests need a larger, still bounded drain allowance.
    drain_limit = 180 if getattr(artifact, "isolate_tests", False) else 60
    state["drain_limit_seconds"] = drain_limit
    tests=0
    maxima=[0]*len(artifact.coverage_ports)
    peak=0
    next_memory_check=0
    interrupted=False
    client=None
    removed=[]
    receipts = set()
    pending_receipts = []
    execution_totals = {}
    next_checkpoint = started
    with FifoEndpoint() as endpoint, RtlSimulator(artifact) as simulator, (output/"client.log").open("wb") as log:
        # The pinned client's prettytable 0.6.7 crashes on this Rust build when
        # -c prints the final table. Omit only that optional presentation step;
        # upstream still saves corpus, statistics and its final raw bitmap.
        try:
            client=subprocess.Popen(("nice","-n15",str(binary),str(config),"-s",endpoint.directory.name,
                "-o",str(output/"corpus"), "--seed-cycles", str(seed_cycles)),stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            state.update(status="running", client_pid=client.pid, command=list(client.args),
                         compatibility="omit optional -c prettytable output; mutation mode unchanged")
            def check():
                nonlocal interrupted, peak, next_memory_check, next_checkpoint
                if "termination_signal" in state:
                    raise KeyboardInterrupt(state["termination_signal"] + " received during RFuzz run")
                now=time.monotonic()
                if now >= next_memory_check:
                    try:
                        client_memory = read_process_group_rss_bytes(client.pid)
                    except CampaignError:
                        if client.poll() is None:
                            raise
                        client_memory = 0  # The owned child exited during sampling.
                    memory=client_memory+read_process_group_rss_bytes(simulator.process.pid)
                    own_rss = next(line for line in Path("/proc/self/status").read_text().splitlines()
                                   if line.startswith("VmRSS:"))
                    memory += int(own_rss.split()[1]) * 1024
                    peak=max(peak,memory)
                    next_memory_check=now+.1
                    if memory >= 512*1024*1024:
                        raise MemoryError("live aggregate RSS reached soft memory limit")
                if now >= next_checkpoint:
                    checkpoint = {
                        "elapsed_seconds": now-started, "tests": tests,
                        "counter_maxima": maxima, "peak_rss_bytes": peak,
                        "corpus_entries": len(tuple((output/"corpus").glob("entry_*.json"))),
                        "coverage_sha256": _hash_bytes(bytes(maxima)),
                        "errors": execution_totals.get("errors", 0),
                        "execution_totals": dict(execution_totals),
                        "completed_feedback_exchanges": len(receipts),
                    }
                    with (output/"checkpoints.jsonl").open("a") as checkpoints:
                        checkpoints.write(json.dumps(checkpoint, sort_keys=True)+"\n")
                    next_checkpoint = now+30
                if now>=deadline and not interrupted and client.poll() is None:
                    client.send_signal(signal.SIGINT)
                    interrupted=True
                    state["interrupt_elapsed_seconds"] = now-started
                if now>=deadline+drain_limit:
                    raise TimeoutError("RFuzz client failed to finish after interrupt")
            def execute(records):
                nonlocal tests
                check()
                try:
                    counters=simulator.run_test(records, monitor=check)
                finally:
                    _record_simulator_diagnostics(state, simulator)
                for key, value in getattr(simulator, "last_execution", {}).items():
                    execution_totals[key] = execution_totals.get(key, 0) + value
                state["execution_totals"] = dict(execution_totals)
                tests+=1
                state["tests"] = tests
                for index,value in enumerate(counters):
                    maxima[index]=max(maxima[index],value)
                pending_receipts.append((_hash_bytes(b"".join(records)), _hash_bytes(counters)))
                return counters
            while client.poll() is None:
                check()
                token=endpoint.receive(timeout=.02)
                if token is not None:
                    reply=process_pair(*token,creator_pid=client.pid,
                        input_bytes=artifact.transport.byte_count,counter_count=len(maxima),execute=execute)
                    endpoint.reply(reply)
                    receipts.update(pending_receipts)
                    pending_receipts.clear()
                    if len(receipts) > 250000:
                        raise RuntimeError("RFuzz feedback receipt bound exceeded")
        finally:
            if client is not None:
                # The launched client owns a new session. Clean the entire group
                # even if its leader already exited but left a descendant alive.
                try:
                    os.killpg(client.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    client.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
                try:
                    os.killpg(client.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                client.wait(timeout=1)
                # Only this launched child's creator-owned segments can be removed.
                # Upstream normally removes them; this covers abnormal client exits.
                libc=ctypes.CDLL(None,use_errno=True)
                for segment in _owned_segments(client.pid):
                    if libc.shmctl(segment,0,None) == 0:
                        removed.append(segment)
                state.update(returncode=client.returncode, counter_maxima=maxima,
                             coverage_maxima=maxima,
                             coverage_feedback={
                                 "transport": "sysv-shared-memory-rfuzz-coverage-buffer",
                                 "records": tests,
                                 "counter_width": 8,
                             },
                             peak_rss_bytes=peak, duration_seconds=time.monotonic()-started,
                             removed_owned_segments=removed, remaining_segments=_owned_segments(client.pid))
                state["drain_seconds"] = (state["duration_seconds"] - state["interrupt_elapsed_seconds"]
                                          if "interrupt_elapsed_seconds" in state else 0)
    result={"returncode":client.returncode,"tests":tests,"counter_maxima":maxima,
        "coverage_kind":artifact.coverage_kind,"duration_seconds":time.monotonic()-started,
        "peak_rss_bytes":peak,"corpus_entries":len(tuple((output/"corpus").glob("entry_*.json"))),
        "remaining_segments":_owned_segments(client.pid),"removed_owned_segments":removed,
        "layout_hash":artifact.layout.layout_hash,"client_binary":str(binary)}
    state.update(result)
    if client.returncode == 0:
        if not tests:
            raise RuntimeError("RFuzz client produced no RTL tests")
        if not result["corpus_entries"]:
            raise RuntimeError("RFuzz client produced no saved corpus")
        if result["remaining_segments"]:
            raise RuntimeError("RFuzz client left owned shared-memory segments")
        manifest = build_corpus_manifest(artifact, output / "corpus", feedback_receipts=receipts)
        manifest_path = output / "corpus_manifest.json"
        manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
        state["corpus_manifest_sha256"] = _hash_bytes(manifest_path.read_bytes())
        state["corpus_manifest"] = manifest
        state["completed_feedback_exchanges"] = len(receipts)
    result = {key: value for key, value in state.items() if key != "_output"}
    result["status"] = "completed" if client.returncode == 0 else "failed"
    (output/"report.json").write_text(json.dumps(result,sort_keys=True)+"\n")
    if client.returncode != 0:
        raise RuntimeError(f"RFuzz client exited {client.returncode}; see {output/'client.log'}")
    return result


def replay_corpus(artifact, corpus_dir, *, _capture_receipts=None):
    """Compare persisted upstream trace bytes with a fresh real RTL execution.

    Upstream config.rs aligns (counter bytes + two cycle-prefix bytes) to eight;
    its saved trace_bits includes the zero transport padding after the counters.
    """
    count = len(artifact.coverage_ports)
    padded_count = ((count + 9) // 8) * 8 - 2
    paths = sorted(Path(corpus_dir).glob("entry_*.json"))
    if not paths:
        raise ValueError("empty RFuzz corpus")
    constrained = getattr(artifact, "transducer_hash", None) is not None
    saved_entries = None
    manifest_path = Path(corpus_dir).parent / "corpus_manifest.json"
    if constrained and manifest_path.exists():
        if not manifest_path.is_file():
            raise ValueError("RFuzz saved corpus manifest is invalid")
        manifest = json.loads(manifest_path.read_text())
        if (not isinstance(manifest, dict) or manifest.get("entries") != len(paths)
                or not isinstance(manifest.get("replays"), list)
                or len(manifest["replays"]) != len(paths)):
            raise ValueError("RFuzz saved corpus manifest is invalid")
        saved_entries = {item.get("file"): item for item in manifest["replays"] if isinstance(item, dict)}
        if len(saved_entries) != len(paths) or set(saved_entries) != {path.name for path in paths}:
            raise ValueError("RFuzz saved corpus manifest entries mismatch")
    entries = []
    with RtlSimulator(artifact) as simulator:
        for path in paths:
            # Five JSON characters per byte covers even spaced decimal arrays;
            # reserve a separate bounded budget for upstream lineage/statistics.
            if path.stat().st_size > 5 * artifact.transport.byte_count * 200 + 4 * 1024 * 1024:
                raise ValueError("oversized RFuzz corpus entry")
            document, payload, expected = _corpus_document(
                path, byte_count=artifact.transport.byte_count
            )
            if len(expected) != padded_count or any(expected[count:]):
                raise ValueError("invalid RFuzz coverage padding")
            identity = replay_identity(artifact, payload)
            declared = document.get("replay_identity")
            if saved_entries is not None:
                saved = saved_entries[path.name]
                # A rebuild has its own binary/replay key. All semantic inputs
                # and the actual compiled rule identity must still match.
                for key in _CONTRACT_REPLAY_KEYS:
                    if not saved.get(key) or saved[key] != identity.get(key):
                        raise ValueError(f"RFuzz saved corpus identity mismatch: {key}: {path.name}")
                if saved.get("trace_sha256") != _hash_bytes(bytes(expected)):
                    raise ValueError(f"RFuzz saved corpus trace identity mismatch: {path.name}")
            elif constrained and not isinstance(declared, dict) and _capture_receipts is None:
                raise ValueError(f"RFuzz constrained corpus requires a saved identity manifest: {path.name}")
            if isinstance(declared, dict):
                if constrained:
                    for key in _CONTRACT_REPLAY_KEYS:
                        if not declared.get(key) or declared[key] != identity.get(key):
                            raise ValueError(f"RFuzz replay identity mismatch: {key}: {path.name}")
                for key in ("raw_sha256", "layout_hash", "constraint_hash", "binary_sha256",
                            "physical_controls_sha256", "simulator_inputs_sha256", "replay_key",
                            "transducer_hash", "header_hash", "implementation_hash"):
                    if key in declared and declared[key] != identity.get(key):
                        raise ValueError(f"RFuzz replay identity mismatch: {path.name}")
            width = artifact.transport.byte_count
            records = tuple(payload[i:i+width] for i in range(0, len(payload), width))
            counters = simulator.run_test(records)
            if saved_entries is not None and saved_entries[path.name].get("coverage_sha256") != _hash_bytes(counters):
                raise ValueError(f"RFuzz saved corpus coverage identity mismatch: {path.name}")
            if _capture_receipts is not None and (
                identity["raw_sha256"], _hash_bytes(counters)
            ) not in _capture_receipts:
                raise ValueError(f"RFuzz corpus lacks completed shared-memory exchange: {path.name}")
            if counters != bytes(expected[:count]):
                raise ValueError(f"RFuzz corpus coverage mismatch: {path.name}")
            physical = []
            projector = getattr(artifact, "projector", None)
            if projector is not None and hasattr(projector, "project_ports"):
                physical = [projector.project_ports(artifact.transport.unpack(record)) for record in records]
            entries.append({
                "file": path.name,
                "input_sha256": identity["raw_sha256"],
                "cycles": len(records),
                "counters": list(counters),
                "trace_sha256": _hash_bytes(bytes(expected)),
                "physical_ports_sha256": _hash_bytes(canonical_bytes(physical)),
                **identity,
            })
    return {
        "status": "passed", "entries": len(entries), "replays": entries,
        "layout_hash": artifact.layout.layout_hash,
        "constraint_hash": entries[0]["constraint_hash"],
        **{key: entries[0][key] for key in ("transducer_hash", "header_hash", "implementation_hash") if key in entries[0]},
        "binary_sha256": entries[0]["binary_sha256"],
        "coverage_kind": artifact.coverage_kind,
        "coverage_transport": "sysv-shared-memory-rfuzz-coverage-buffer",
    }
