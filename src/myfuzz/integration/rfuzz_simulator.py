"""Persistent layout-to-Icarus boundary with sampled output-bit event counters.

Counters count asserted observations after each driven cycle (saturating at
255). They are deliberately not advertised as RTL branch or toggle coverage.
"""
from dataclasses import asdict, dataclass, replace
import hashlib
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time

from myfuzz.contracts import canonical_bytes
from myfuzz.composition.auto import _generic_with_reset_contract, _generic_endpoint_reset_contract
from myfuzz.composition.input_layout import InputLayout, input_layout_document
from myfuzz.composition.interface_description import interface_description_document
from myfuzz.composition.protocol_composer import (
    _generic_routes, _generic_port_records, _generic_include_paths,
    _generic_define_options, _validate_generic_plan_freshness, write_generic_composition,
)
from myfuzz.composition.rfuzz_transport import build_rfuzz_transport, RfuzzInputTransport
from myfuzz.composition.runtime_projection import RuntimeProjector
from .campaign import CampaignOptions, run_supervised_command, read_process_group_rss_bytes

MAX_CYCLES = 65536
MAX_IO_BYTES = 8 * 1024 * 1024
RSS_POLL_SECONDS = 0.1


@dataclass(frozen=True)
class SimulatorArtifact:
    layout: InputLayout
    transport: RfuzzInputTransport
    executable: Path
    coverage_ports: tuple[tuple[str, int], ...]
    projector: RuntimeProjector
    coverage_kind: str = "sampled-output-bit-events-u8-saturating"


def _runtime_boundary(plan, base_dir):
    routes = _generic_routes(plan)
    internal = frozenset(f["source_port"] for r in routes for f in r["fields"])
    ports = {r["source_port"]: r for r in _generic_port_records(plan, internal_ports=internal)}
    clocks, resets, contracts = set(), set(), set()
    source_root = base_dir / plan.interface_description.source.source_root
    modules = {e["endpoint_id"]: e["module"] for e in plan.annotations["endpoints"]}
    bound = {r["source_endpoint_id"] for r in routes}
    for cap in plan.capabilities:
        if cap.protocol is not None and cap.endpoint_id not in bound:
            raise ValueError("unbound external protocol fields")
        for f in cap.fields:
            if f.role in {"clock", "reset"}:
                if f.direction != "input" or f.width != 1 or f.port not in ports:
                    raise ValueError("invalid runtime clock/reset")
                (clocks if f.role == "clock" else resets).add(f.port)
        controls = {f.role: f.port for f in cap.fields if f.role in {"clock", "reset"}}
        if set(controls) == {"clock", "reset"}:
            # Semantic field bindings survive even when the crawler cannot
            # infer its conventional active-low asynchronous control bundle.
            # The HDL reset verifier below still proves polarity/synchrony.
            endpoint = replace(cap, clock=controls["clock"], reset=controls["reset"])
            verified = _generic_with_reset_contract(endpoint, source_root, modules[cap.endpoint_id])
            semantics = _generic_endpoint_reset_contract(verified)
            contracts.add((semantics["polarity"], semantics["synchrony"]))
    if len(clocks) != 1 or len(resets) != 1 or len(contracts) != 1 or clocks & resets:
        raise ValueError("runtime requires one verified clock/reset domain")
    clock, reset = next(iter(clocks)), next(iter(resets))
    wanted = {p for p, r in ports.items() if r["direction"] == "input"} - clocks - resets
    fields, seen, cursor = [], set(), 0
    for field in plan.layout.fields:
        if field.port not in wanted:
            continue
        if field.port in seen:
            raise ValueError("ambiguous runtime input binding")
        seen.add(field.port)
        fields.append(replace(field, raw_lo=cursor, raw_hi=cursor + field.width - 1))
        cursor += field.width
    if seen != wanted or not fields or cursor > 65536:
        raise ValueError("unbound or oversized runtime input layout")
    provisional = InputLayout("input_layout.v1", cursor, tuple(fields), "pending")
    doc = input_layout_document(provisional)
    doc.pop("layout_hash")
    for f in doc["fields"]:
        f.pop("provenance", None)
    layout = replace(provisional, layout_hash=hashlib.sha256(canonical_bytes(doc)).hexdigest())
    projector = RuntimeProjector(layout, isa=plan.request.isa)
    return ports, clock, reset, next(iter(contracts))[0], layout, projector


def _bench(ports, clock, reset, polarity, layout, coverage):
    names = {p: r["opaque_port"] for p, r in ports.items()}
    declarations = [f"logic [{r['width']-1}:0] {r['opaque_port']};" for r in ports.values()]
    inputs = [f"assign {names[f.port]} = raw_bits[{f.raw_hi}:{f.raw_lo}];" for f in layout.fields]
    connections = ",".join(f".{n}({n})" for n in names.values())
    active = 0 if polarity == "active_low" else 1
    c, r = names[clock], names[reset]
    sample = []
    for i, (port, bit) in enumerate(coverage):
        sample += [f"if ({names[port]}[{bit}] !== 1'b0 && {names[port]}[{bit}] !== 1'b1) $fatal(1,\"unknown observation\");",
                   f"if ({names[port]}[{bit}] && counters[{i}] != 8'hff) counters[{i}] = counters[{i}] + 1'b1;"]
    return "\n".join([
        "module myfuzz_live_tb;", *declarations,
        f"reg [{layout.raw_width-1}:0] raw_bits = 0;",
        f"reg [7:0] counters[0:{len(coverage)-1}]; integer count, scan, i, j;",
        *inputs, f"generic_composition_top dut({connections});",
        f"task tick; begin #5; {c}=1; #5; {c}=0; end endtask",
        f"initial begin {c}=0; {r}={1-active};",
        '$display("RFUZZ_READY"); $fflush();',
        "forever begin",
        'scan=$fscanf(32\'h80000000,"%d",count);',
        'if (scan != 1) $finish;',
        f'if (count < 1 || count > {MAX_CYCLES}) $fatal(1,"cycle count");',
        f"raw_bits=0; {r}={active}; tick(); tick(); {r}={1-active};",
        f"for (j=0;j<{len(coverage)};j=j+1) counters[j]=0;",
        "for (i=0;i<count;i=i+1) begin",
        'scan=$fscanf(32\'h80000000,"%h",raw_bits);',
        'if (scan != 1) $fatal(1,"raw sample");',
        "tick();", *sample, "end",
        '$write("RFUZZ_COUNTERS ");',
        f'for (j=0;j<{len(coverage)};j=j+1) $write("%02x",counters[j]);',
        '$write("\\n"); $fflush();', "end end endmodule\n",
    ])


def build_simulator(plan, output_dir, *, base_dir, coverage_ports):
    """Publish into a new directory only; reject unsafe boundaries before build."""
    root, output = Path(base_dir).resolve(), Path(output_dir).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("simulator output already exists")
    plan = _validate_generic_plan_freshness(plan, root)
    ports, clock, reset, polarity, layout, projector = _runtime_boundary(plan, root)
    coverage = tuple(coverage_ports)
    if not coverage or len(coverage) > 4096:
        raise ValueError("explicit bounded output-bit observations required")
    for item in coverage:
        if not isinstance(item, tuple) or len(item) != 2:
            raise ValueError("invalid output-bit observation")
        port, bit = item
        if (not isinstance(port, str) or port not in ports or ports[port]["direction"] != "output"
                or type(bit) is not int or not 0 <= bit < ports[port]["width"]):
            raise ValueError("invalid output-bit observation")
    if len(set(coverage)) != len(coverage):
        raise ValueError("duplicate output-bit observation")
    transport = build_rfuzz_transport(layout)
    bench = _bench(ports, clock, reset, polarity, layout, coverage)
    output.mkdir(parents=True, exist_ok=False)
    write_generic_composition(plan, output / "composition", base_dir=root)
    (output / "runtime_layout.json").write_bytes(canonical_bytes(input_layout_document(layout)))
    (output / "runtime_transport.json").write_bytes(canonical_bytes(transport.document()))
    (output / "observations.json").write_bytes(canonical_bytes({
        "kind": "sampled-output-bit-events-u8-saturating", "ports": [list(c) for c in coverage]}))
    bench_path = output / "live_tb.sv"
    bench_path.write_text(bench)
    executable = output / "sim.vvp"
    command = ("nice", "-n15", "iverilog", "-g2012", "-s", "myfuzz_live_tb", "-o", str(executable),
               *("-I" + str(p) for p in _generic_include_paths(plan, root)),
               *_generic_define_options(plan), *(str(root / f) for f in plan.source_files),
               str(output / "composition/generic_composition_top.sv"), str(bench_path))
    result = run_supervised_command(CampaignOptions(command=command, output_dir=output / "build",
        duration_seconds=30, checkpoint_seconds=1, env={"JOBS": "1"}))
    if result["status"] != "completed" or result["returncode"] != 0:
        raise ValueError(f"Icarus build failed: {result}")
    (output / "artifact_provenance.json").write_bytes(canonical_bytes({
        "schema_version": "rfuzz_artifact_provenance.v1",
        "interface_description": interface_description_document(plan.interface_description),
        "composition_ir_hash": plan.composition_ir_hash,
        "source_evidence_hash": plan.source_evidence_hash,
        "composition_seed": plan.request.seed,
        "isa": asdict(plan.request.isa) if plan.request.isa is not None else None,
        "source_base_dir": str(root),
        "source_sha256": {f: hashlib.sha256((root / f).read_bytes()).hexdigest()
                          for f in plan.source_files},
        "build_command": list(command),
        "executable_sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
        "layout_hash": layout.layout_hash,
        "transport_hash": transport.document()["transport_hash"],
        "coverage_kind": "sampled-output-bit-events-u8-saturating",
        "coverage_ports": [list(c) for c in coverage],
    }))
    return SimulatorArtifact(layout, transport, executable, coverage, projector)


class RtlSimulator:
    """One private persistent child, with bounded per-test IO and cleanup."""
    def __init__(self, artifact, *, timeout_seconds=5.0):
        if not isinstance(artifact, SimulatorArtifact):
            raise ValueError("simulator artifact required")
        if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
                or not 0 < timeout_seconds <= 60):
            raise ValueError("finite simulator deadline required")
        self.artifact, self.timeout_seconds = artifact, timeout_seconds
        self._next_rss_poll = 0.0  # Immediate startup check; shared across tests.
        self.process = subprocess.Popen(("nice", "-n15", "vvp", str(artifact.executable)),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        self.closed = False
        try:
            os.set_blocking(self.process.stdin.fileno(), False)
            os.set_blocking(self.process.stdout.fileno(), False)
            if self._exchange(b"", 64) != b"RFUZZ_READY":
                raise ValueError("unexpected simulator startup")
        except BaseException:
            self.close()
            raise

    def _exchange(self, payload, max_reply, monitor=None):
        deadline = time.monotonic() + self.timeout_seconds
        pending, reply = memoryview(payload), bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(self.process.stdout, selectors.EVENT_READ)
            if pending:
                selector.register(self.process.stdin, selectors.EVENT_WRITE)
            while True:
                if monitor is not None:
                    monitor()
                now = time.monotonic()
                if now >= deadline:
                    raise TimeoutError("simulator IO deadline exceeded")
                if now >= self._next_rss_poll and self.process.poll() is None:
                    rss = read_process_group_rss_bytes(self.process.pid)
                    self._next_rss_poll = time.monotonic() + RSS_POLL_SECONDS
                    if rss >= 512 * 1024 * 1024:
                        raise RuntimeError("simulator group RSS soft limit exceeded")
                for key, _ in selector.select(min(0.02, max(0, deadline - time.monotonic()))):
                    if key.fileobj is self.process.stdin:
                        try:
                            count = os.write(key.fd, pending[:65536])
                        except BlockingIOError:
                            continue
                        pending = pending[count:]
                        if not pending:
                            selector.unregister(self.process.stdin)
                    else:
                        try:
                            chunk = os.read(key.fd, 4096)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            raise RuntimeError("simulator closed output")
                        reply.extend(chunk)
                        if len(reply) > max_reply:
                            raise ValueError("oversized simulator response")
                        if b"\n" in reply:
                            if pending or not reply.endswith(b"\n") or reply.count(b"\n") != 1:
                                raise ValueError("unexpected simulator response framing")
                            return bytes(reply[:-1])

    def run_test(self, records, *, monitor=None):
        if self.closed:
            raise ValueError("simulator is closed")
        if not isinstance(records, (tuple, list)) or not 1 <= len(records) <= MAX_CYCLES:
            raise ValueError("bounded nonempty sample sequence required")
        if len(records) * (self.artifact.layout.raw_width // 4 + 2) > MAX_IO_BYTES:
            raise ValueError("test input exceeds IO bound")
        samples = [self.artifact.projector.project(self.artifact.transport.unpack(r)) for r in records]
        payload = (str(len(samples)) + "\n" + "".join(f"{s:x}\n" for s in samples)).encode("ascii")
        try:
            count = len(self.artifact.coverage_ports)
            reply = self._exchange(payload, 2 * count + 32, monitor=monitor)
            prefix = b"RFUZZ_COUNTERS "
            if not reply.startswith(prefix) or len(reply) != len(prefix) + 2 * count:
                raise ValueError("invalid simulator counter response")
            counters = bytes.fromhex(reply[len(prefix):].decode("ascii"))
            if len(counters) != count:
                raise ValueError("invalid simulator counter length")
            return counters
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.closed:
            return
        self.closed = True
        # start_new_session establishes an owned process group. Signal only it,
        # including descendants even when the immediate VVP child exited.
        try:
            os.killpg(self.process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            self.process.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.process.wait(timeout=1)
        self.process.stdin.close()
        self.process.stdout.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
