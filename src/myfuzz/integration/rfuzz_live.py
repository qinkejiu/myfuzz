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
from .rfuzz_fifo import FifoEndpoint
from .rfuzz_shmem import process_pair
from .rfuzz_simulator import RtlSimulator
from .campaign import CampaignError, read_process_group_rss_bytes


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


def run_live(artifact, client_binary, output_dir, *, duration_seconds=30):
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
                           duration_seconds=duration_seconds, state=state)
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


def _run_live(artifact, client_binary, output_dir, *, duration_seconds, state):
    if type(duration_seconds) not in (int,float) or not math.isfinite(duration_seconds) or not 0 < duration_seconds <= 86400:
        raise ValueError("finite positive live duration required")
    binary=Path(client_binary).resolve(strict=True)
    output=Path(output_dir).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("live output must be new")
    output.mkdir(parents=True)
    state.update(_output=output, tests=0, status="starting", layout_hash=artifact.layout.layout_hash,
                 client_binary=str(binary), client_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                 coverage_kind=artifact.coverage_kind, requested_duration_seconds=duration_seconds,
                 transport=artifact.transport.document(),
                 memory_scope="runner PID plus owned client and simulator process groups; sampled RSS",
                 soft_rss_bytes=512 * 1024 * 1024, hard_rss_bytes=768 * 1024 * 1024,
                 memory_poll_min_interval_seconds=.1,
                 memory_poll_policy="check at FIFO/RTL IO checkpoints; scheduling and encoding can delay sampling")
    if hasattr(artifact, "executable"):
        provenance = artifact.executable.parent / "artifact_provenance.json"
        state["artifact_provenance"] = json.loads(provenance.read_text()) if provenance.is_file() else None
        state["simulator_sha256"] = hashlib.sha256(artifact.executable.read_bytes()).hexdigest()
    state["mutation_seed"] = None
    state["mutation_seed_policy"] = "upstream has no global seed option; retain corpus lineage and raw inputs for replay"
    state["mutation_mode"] = "official default deterministic and havoc mutation, JQF level 2"
    state["initial_seed"] = {"kind": "all-zero", "cycles": 5}
    config=output/"rfuzz.toml"
    config.write_text(_configuration(artifact))
    state["config_sha256"] = hashlib.sha256(config.read_bytes()).hexdigest()
    started=time.monotonic()
    deadline=started+duration_seconds
    tests=0
    maxima=[0]*len(artifact.coverage_ports)
    peak=0
    next_memory_check=0
    interrupted=False
    client=None
    removed=[]
    with FifoEndpoint() as endpoint, RtlSimulator(artifact) as simulator, (output/"client.log").open("wb") as log:
        # The pinned client's prettytable 0.6.7 crashes on this Rust build when
        # -c prints the final table. Omit only that optional presentation step;
        # upstream still saves corpus, statistics and its final raw bitmap.
        try:
            client=subprocess.Popen(("nice","-n15",str(binary),str(config),"-s",endpoint.directory.name,
                "-o",str(output/"corpus")),stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
            state.update(status="running", client_pid=client.pid, command=list(client.args),
                         compatibility="omit optional -c prettytable output; mutation mode unchanged")
            def check():
                nonlocal interrupted, peak, next_memory_check
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
                if now>=deadline and not interrupted and client.poll() is None:
                    client.send_signal(signal.SIGINT)
                    interrupted=True
                    state["interrupt_elapsed_seconds"] = now-started
                if now>=deadline+60:
                    raise TimeoutError("RFuzz client failed to finish after interrupt")
            def execute(records):
                nonlocal tests
                check()
                counters=simulator.run_test(records, monitor=check)
                tests+=1
                state["tests"] = tests
                for index,value in enumerate(counters):
                    maxima[index]=max(maxima[index],value)
                return counters
            while client.poll() is None:
                check()
                token=endpoint.receive(timeout=.02)
                if token is not None:
                    reply=process_pair(*token,creator_pid=client.pid,
                        input_bytes=artifact.transport.byte_count,counter_count=len(maxima),execute=execute)
                    endpoint.reply(reply)
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
    result = {key: value for key, value in state.items() if key != "_output"}
    result["status"] = "completed" if client.returncode == 0 else "failed"
    (output/"report.json").write_text(json.dumps(result,sort_keys=True)+"\n")
    if client.returncode != 0:
        raise RuntimeError(f"RFuzz client exited {client.returncode}; see {output/'client.log'}")
    return result


def replay_corpus(artifact, corpus_dir):
    """Compare persisted upstream trace bytes with a fresh real RTL execution.

    Upstream config.rs aligns (counter bytes + two cycle-prefix bytes) to eight;
    its saved trace_bits includes the zero transport padding after the counters.
    """
    count = len(artifact.coverage_ports)
    padded_count = ((count + 9) // 8) * 8 - 2
    paths = sorted(Path(corpus_dir).glob("entry_*.json"))
    if not paths:
        raise ValueError("empty RFuzz corpus")
    entries = []
    with RtlSimulator(artifact) as simulator:
        for path in paths:
            # Five JSON characters per byte covers even spaced decimal arrays;
            # reserve a separate bounded budget for upstream lineage/statistics.
            if path.stat().st_size > 5 * artifact.transport.byte_count * 200 + 4 * 1024 * 1024:
                raise ValueError("oversized RFuzz corpus entry")
            document = json.loads(path.read_text())
            raw, expected = document["entry"]["inputs"], document["trace_bits"]
            if (not isinstance(raw, list) or not isinstance(expected, list)
                    or any(type(v) is not int or not 0 <= v <= 255 for v in raw + expected)):
                raise ValueError("invalid RFuzz corpus bytes")
            if len(expected) != padded_count or any(expected[count:]):
                raise ValueError("invalid RFuzz coverage padding")
            width = artifact.transport.byte_count
            if not raw or len(raw) % width or len(raw) // width > 200:
                raise ValueError("invalid RFuzz corpus input size")
            payload = bytes(raw)
            records = tuple(payload[i:i+width] for i in range(0, len(payload), width))
            counters = simulator.run_test(records)
            if counters != bytes(expected[:count]):
                raise ValueError(f"RFuzz corpus coverage mismatch: {path.name}")
            entries.append({"file": path.name, "input_sha256": hashlib.sha256(payload).hexdigest(),
                            "cycles": len(records), "counters": list(counters)})
    return {"status": "passed", "entries": len(entries), "replays": entries,
            "layout_hash": artifact.layout.layout_hash, "coverage_kind": artifact.coverage_kind}
