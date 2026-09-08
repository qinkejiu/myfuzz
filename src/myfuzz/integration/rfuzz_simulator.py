"""Persistent layout-to-Icarus boundary with sampled output-bit event counters.

Counters count asserted observations after each driven cycle (saturating at
255). They are deliberately not advertised as RTL branch or toggle coverage.
"""
from dataclasses import asdict, dataclass, replace
from collections.abc import Mapping, Sequence
import hashlib
import math
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

from myfuzz.contracts import canonical_bytes, content_hash
from myfuzz.composition.contract_transducer import ContractRuntime, ContractTransducerPlan
from myfuzz.composition.cycle_input import CycleInputLayout, TestHeader, TEST_HEADER_SCHEMA_VERSION
from myfuzz.composition.auto import _generic_with_reset_contract, _generic_endpoint_reset_contract, _generic_source_evidence_hash
from myfuzz.composition.input_layout import InputLayout, input_layout_document
from myfuzz.composition.interface_description import interface_description_document
from myfuzz.composition.protocol_composer import (
    _generic_routes, _generic_port_records, _generic_include_paths,
    _generic_define_options, _validate_generic_plan_freshness, write_generic_composition,
    _validate_processor_transducer,
)
from myfuzz.composition.rfuzz_transport import build_rfuzz_transport, RfuzzInputTransport
from myfuzz.composition.runtime_projection import RuntimeProjector
from .rtl_execution_monitor import (
    validate_monitor, monitor_rtl, monitor_output, parse_metrics, validate_execution,
)
from .campaign import CampaignOptions, run_supervised_command, read_process_group_rss_bytes

MAX_CYCLES = 65536
MAX_IO_BYTES = 8 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 256 * 1024
MAX_DIAGNOSTIC_LINES = 1024
MAX_DIAGNOSTIC_LINE_BYTES = 4096
SIMULATOR_PROTOCOL_VERSION = 2
MAX_REQUEST_ID = (1 << 64) - 1
RSS_POLL_SECONDS = 0.1


@dataclass(frozen=True)
class SimulatorArtifact:
    layout: InputLayout | CycleInputLayout
    transport: RfuzzInputTransport
    executable: Path
    coverage_ports: tuple[tuple[str, int], ...]
    projector: "RuntimeProjector | CycleIdentityProjector"
    coverage_kind: str = "sampled-output-bit-events-u8-saturating"
    control_defaults: Mapping[str, object] = None
    randomized_controls: tuple[str, ...] = ()
    simulator_args: tuple[str, ...] = ()
    simulator: str = "icarus"
    isolate_tests: bool = False
    execution_monitor: dict | None = None
    transducer_hash: str | None = None
    header_hash: str | None = None
    test_header: TestHeader | None = None
    implementation_hash: str | None = None


class CycleIdentityProjector:
    """Keep backend entropy unchanged; expose only proven external bindings."""
    instruction_mode = "stateful-contract-transducer-rtl"

    def __init__(self, plan, external_fields):
        self.layout = plan.cycle_layout
        self.constraint_hash = plan.contract_hash
        self.external_fields = tuple(external_fields)

    def project(self, raw):
        if type(raw) is not int or not 0 <= raw < 1 << self.layout.raw_width:
            raise ValueError("raw sample outside cycle layout")
        return raw

    def project_ports(self, raw):
        self.project(raw)
        values = {}
        for field in self.external_fields:
            value = (raw >> field.raw_lo) & ((1 << field.width) - 1)
            values[field.port] = values.get(field.port, 0) | (value << (field.port_raw_lo or 0))
        return values


_CONTROL_ROLE_ALIASES = {
    "boot_address": frozenset(("boot_address", "boot_addr", "reset_vector")),
    "hart_id": frozenset(("hart_id", "hartid")),
    "debug_request": frozenset(("debug_request", "debug_req", "debug")),
    "interrupt": frozenset(("interrupt", "interrupt_request", "irq", "software_interrupt",
                             "timer_interrupt", "external_interrupt", "fast_interrupt",
                             "nonmaskable_interrupt", "non_maskable_interrupt")),
}
_CONTROL_DEFAULTS = {role: 0 for role in _CONTROL_ROLE_ALIASES}


def _canonical_control_role(role, explicit=()):
    for canonical, aliases in _CONTROL_ROLE_ALIASES.items():
        if role in aliases:
            return canonical
    return role if role in explicit else None


def _normalize_control_roles(value):
    if value is None:
        return ()
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ValueError("randomized controls must be a sequence")
    result = []
    for role in value:
        if not isinstance(role, str):
            raise ValueError("randomized control role must be a string")
        canonical = _canonical_control_role(role)
        if canonical is None:
            raise ValueError(f"unsupported randomized control: {role}")
        if canonical in result:
            raise ValueError("duplicate randomized control")
        result.append(canonical)
    return tuple(sorted(result))


def _control_defaults(value):
    if value is None:
        return dict(_CONTROL_DEFAULTS)
    if not isinstance(value, Mapping):
        raise ValueError("control defaults must be a mapping")
    result = dict(_CONTROL_DEFAULTS)
    for role, default in value.items():
        if not isinstance(role, str):
            raise ValueError("control default role must be a string")
        canonical = _canonical_control_role(role) or role
        if not role or not role.isidentifier():
            raise ValueError(f"invalid control default: {role}")
        if type(default) is not int or default < 0:
            raise ValueError("control default must be a nonnegative integer")
        result[canonical] = default
    return result


def _runtime_control_bindings(plan, ports, layout, randomized_controls, defaults):
    source_fields = tuple(getattr(getattr(plan, "layout", None), "fields", ()))
    included = {field.field_id for field in layout.fields}
    bindings = []
    present = set()
    for field in source_fields:
        canonical = _canonical_control_role(field.role, defaults)
        if canonical is None or field.field_id in included:
            continue
        present.add(canonical)
        if field.direction not in ("input", "inout") or field.port not in ports:
            raise ValueError("invalid runtime control binding")
        if ports[field.port]["direction"] != "input":
            raise ValueError("runtime control must drive an input port")
        value = defaults[canonical]
        field_mask = (1 << field.width) - 1
        if value > field_mask:
            raise ValueError(f"runtime control default exceeds {field.field_id} width")
        if field.member_path:
            if any(item is None for item in (field.port_raw_lo, field.port_raw_hi, field.port_width)):
                raise ValueError("incomplete packed runtime control")
        elif ports[field.port]["width"] != field.width:
            raise ValueError("scalar runtime control width mismatch")
        bindings.append((field, value))
    for role in randomized_controls:
        if not any(_canonical_control_role(field.role) == role and
                   field.field_id in included for field in source_fields):
            raise ValueError(f"randomized control lacks interface opt-in: {role}")
    document = {
        "roles": tuple(sorted(present)),
        "values": {role: defaults[role] for role in sorted(present)},
        "policy": "explicit-opt-in; otherwise constant",
        "bindings": [{"field_id": f.field_id, "port": f.port, "width": f.width,
                      "raw_lo": f.port_raw_lo, "raw_hi": f.port_raw_hi, "value": v}
                     for f, v in bindings],
    }
    return tuple(bindings), document


def _runtime_boundary(plan, base_dir, *, randomized_controls=(), control_defaults=(), contract_transducer=None):
    randomized_controls = _normalize_control_roles(randomized_controls)
    execution = getattr(plan, "processor_execution", None)
    if execution is None:
        routes = _generic_routes(plan)
        internal = frozenset(f["source_port"] for r in routes for f in r["fields"])
        bound = {r["source_endpoint_id"] for r in routes}
    else:
        processor_routes = getattr(execution, "routes", None)
        if not isinstance(processor_routes, tuple) or not processor_routes:
            raise ValueError("invalid processor runtime routes")
        internal = frozenset(
            str(physical.get("port", physical.get("container_port")))
            for route in processor_routes
            for connection in route.field_connections
            for physical in (connection["physical"],)
        )
        if "None" in internal:
            raise ValueError("invalid processor runtime physical port")
        bound = {route.endpoint_id for route in processor_routes}
    ports = {r["source_port"]: r for r in _generic_port_records(plan, internal_ports=internal)}
    clocks, resets, contracts = set(), set(), set()
    source_root = base_dir / plan.interface_description.source.source_root
    modules = {e["endpoint_id"]: e["module"] for e in plan.annotations["endpoints"]}
    if execution is not None:
        from myfuzz.composition.protocol_composer import _processor_controls
        processor_clock, processor_reset, semantics = _processor_controls(plan)
        clocks.add(processor_clock)
        resets.add(processor_reset)
        contracts.add((semantics["polarity"], semantics["synchrony"]))
    for cap in plan.capabilities:
        if cap.protocol is not None and cap.endpoint_id not in bound:
            raise ValueError("unbound external protocol fields")
        for f in cap.fields:
            if f.role in {"clock", "reset"}:
                if (f.direction != "input" or f.width != 1 or f.port not in ports or
                        f.member_path or f.container_width not in (None, 1) or
                        ports[f.port]["width"] != 1):
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
        role = _canonical_control_role(field.role, control_defaults)
        enabled = role in randomized_controls and field.constraint.get("randomizable") is True
        if field.port not in wanted or (role is not None and not enabled):
            continue
        seen.add(field.port)
        fields.append(replace(field, raw_lo=cursor, raw_hi=cursor + field.width - 1))
        cursor += field.width
    fixed = {field.port for field in plan.layout.fields
             if _canonical_control_role(field.role, control_defaults) is not None}
    expected = wanted - fixed
    if not expected.issubset(seen) or (not fields and contract_transducer is None) or cursor > 65536:
        raise ValueError("unbound or oversized runtime input layout")
    provisional = InputLayout("input_layout.v1", cursor, tuple(fields), "pending")
    doc = input_layout_document(provisional)
    doc.pop("layout_hash")
    for f in doc["fields"]:
        f.pop("provenance", None)
    layout = replace(provisional, layout_hash=hashlib.sha256(canonical_bytes(doc)).hexdigest())
    if contract_transducer is None:
        projector = RuntimeProjector(
            layout, isa=plan.request.isa,
            require_compiler_provenance=getattr(plan, "processor_execution", None) is not None,
        )
    else:
        declared = dict(contract_transducer.external_inputs)
        if declared != {field.field_id: field.width for field in fields}:
            raise ValueError("contract external inputs do not match runtime physical bindings")
        # Existing physical-binding checks prove packed compiler offsets and
        # complete, nonoverlapping ranges; no projection is applied to entropy.
        if fields:
            RuntimeProjector(layout, require_compiler_provenance=True)
        for field in fields:
            if field.encoding != "bits" or set(field.constraint) - {"randomizable"}:
                raise ValueError("contract external input requires unconstrained bits")
        cycle_fields = {field.field_id: field for field in contract_transducer.cycle_layout.fields}
        if {name: field.width for name, field in cycle_fields.items() if name.startswith("external.")} != {
            f"external.{field.field_id}": field.width for field in fields
        }:
            raise ValueError("external cycle slices do not match physical bindings")
        external_fields = tuple(replace(field,
            raw_lo=cycle_fields[f"external.{field.field_id}"].raw_lo,
            raw_hi=cycle_fields[f"external.{field.field_id}"].raw_hi) for field in fields)
        layout = replace(layout, fields=external_fields)
        projector = CycleIdentityProjector(contract_transducer, external_fields)
    return ports, clock, reset, next(iter(contracts))[0], layout, projector


def _bench(ports, clock, reset, polarity, layout, coverage, *, control_bindings=(), coverage_signals=(), execution_monitor=None,
           external_fields=None, test_header=None, address_width=None):
    names = {p: r["opaque_port"] for p, r in ports.items()}
    declarations = [f"logic [{r['width']-1}:0] {r['opaque_port']};" for r in ports.values()]
    inputs = []
    for field in layout.fields if external_fields is None else external_fields:
        target = names[field.port]
        if field.member_path:
            target += f"[{field.port_raw_hi}:{field.port_raw_lo}]"
        inputs.append(f"assign {target} = raw_bits[{field.raw_hi}:{field.raw_lo}];")
    controls = []
    for field, value in control_bindings:
        target = names[field.port]
        if field.member_path:
            target += f"[{field.port_raw_hi}:{field.port_raw_lo}]"
        controls.append(f"assign {target} = {field.width}'h{value:x};")
    connections = ",".join(f".{n}({n})" for n in names.values())
    test_controls = []
    begin_test = []
    if test_header is not None:
        test_controls = ["reg test_begin = 0;",
            f"wire [{address_width-1}:0] test_boot_address = {address_width}'h{test_header.boot_address:x};",
            f"wire test_illegal_instruction = 1'b{int(test_header.illegal_instruction)};"]
        connections += ",.rfuzz_cycle_bits(raw_bits),.test_begin(test_begin),.test_boot_address(test_boot_address),.test_illegal_instruction(test_illegal_instruction)"
        begin_test = ["test_begin=1; tick(); test_begin=0;"]
    active = 0 if polarity == "active_low" else 1
    c, r = names[clock], names[reset]
    observations = tuple(coverage) + tuple((f"dut.{signal}", bit) for signal, bit in coverage_signals)
    expressions = tuple(f"{names[port]}[{bit}]" for port, bit in coverage) + tuple(
        f"((dut.{signal} >> {bit}) & 1'b1)" for signal, bit in coverage_signals
    )
    sample = []
    for i, expression in enumerate(expressions):
        sample += [f"if ({expression} !== 1'b0 && {expression} !== 1'b1) $fatal(1,\"unknown observation\");",
                   f"if ({expression} && counters[{i}] != 8'hff) counters[{i}] = counters[{i}] + 1'b1;"]
    return "\n".join([
        "module myfuzz_live_tb;", *declarations, *controls, *test_controls,
        f"reg [{layout.raw_width-1}:0] raw_bits = 0;",
        f"reg [7:0] counters[0:{len(observations)-1}]; integer count, scan, i, j;",
        "logic [63:0] request_id, last_request_id=0;",
        *inputs, f"generic_composition_top dut({connections});",
        *(f'initial if ({bit} >= $bits(dut.{signal})) $fatal(1,"observation bit out of range");'
          for signal, bit in coverage_signals),
        *monitor_rtl(c, r, active, execution_monitor),
        f"task tick; begin #5; {c}=1; #5; {c}=0; end endtask",
        f"initial begin {c}=0; {r}={1-active};",
        f'$display("RFUZZ_READY {SIMULATOR_PROTOCOL_VERSION}"); $fflush();',
        "forever begin",
        'scan=$fscanf(32\'h80000000,"%h %d",request_id,count);',
        'if (scan == -1) $finish;',
        'if (scan != 2 || request_id == 0 || request_id <= last_request_id) $fatal(1,"request id");',
        "last_request_id=request_id;",
        f'if (count < 1 || count > {MAX_CYCLES}) $fatal(1,"cycle count");',
        "raw_bits=0;", *begin_test,
        (f"{r}={active}; repeat ({test_header.reset_cycles}) tick(); {r}={1-active};"
         if test_header is not None else f"{r}={active}; tick(); tick(); {r}={1-active};"),
        f"for (j=0;j<{len(observations)};j=j+1) counters[j]=0;",
        "for (i=0;i<count;i=i+1) begin",
        'scan=$fscanf(32\'h80000000,"%h",raw_bits);',
        'if (scan != 1) $fatal(1,"raw sample");',
        "tick();", *sample, "end",
        '$write("RFUZZ_COUNTERS %016h ",request_id);',
        f'for (j=0;j<{len(observations)};j=j+1) $write("%02x",counters[j]);',
        *monitor_output(execution_monitor),
        '$write("\\n"); $fflush();', "end end endmodule\n",
    ])


def build_simulator(plan, output_dir, *, base_dir, coverage_ports,
                    coverage_inputs=(),
                    randomized_controls=(), control_defaults=None, coverage_signals=(),
                    simulator_args=(), simulator="icarus", isolate_tests=False, execution_monitor=None,
                    contract_transducer=None, test_header=None):
    """Publish into a new directory only; reject unsafe boundaries before build."""
    root, output = Path(base_dir).resolve(), Path(output_dir).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("simulator output already exists")
    if simulator not in {"icarus", "verilator"}:
        raise ValueError("unsupported simulator")
    if type(isolate_tests) is not bool:
        raise ValueError("isolate_tests must be boolean")
    plan = _validate_generic_plan_freshness(plan, root)
    execution_monitor = validate_monitor(execution_monitor)
    if execution_monitor is not None and getattr(plan, "processor_execution", None) is None:
        raise ValueError("execution monitor requires generated processor backend")
    randomized_controls = _normalize_control_roles(randomized_controls)
    defaults = _control_defaults(control_defaults)
    if contract_transducer is not None:
        if not isinstance(contract_transducer, ContractTransducerPlan):
            raise ValueError("contract transducer plan required")
        if getattr(plan, "processor_execution", None) is None:
            raise ValueError("contract transducer requires processor execution")
        _validate_processor_transducer(plan, contract_transducer)
        contract_transducer.cycle_layout.validate()
        if contract_transducer.cycle_layout.raw_width > 65536:
            raise ValueError("oversized contract cycle layout")
        if test_header is None:
            test_header = TestHeader(TEST_HEADER_SCHEMA_VERSION,
                contract_transducer.cycle_layout.layout_hash, contract_transducer.contract_hash,
                2, MAX_CYCLES, defaults["boot_address"], defaults["hart_id"])
        ContractRuntime(contract_transducer).begin_test(test_header)
        if not 1 <= test_header.reset_cycles <= MAX_CYCLES or not 1 <= test_header.execution_cycles <= MAX_CYCLES:
            raise ValueError("header reset/execution cycles must be bounded and positive")
        if set(randomized_controls) & {"boot_address", "hart_id"}:
            raise ValueError("header boot address and hart id must be fixed")
        for role in ("boot_address", "hart_id"):
            value = getattr(test_header, role)
            if control_defaults is not None and any(
                (_canonical_control_role(key) or key) == role and default != value
                for key, default in control_defaults.items()
            ):
                raise ValueError("header conflicts with fixed runtime control")
            defaults[role] = value
    elif test_header is not None:
        raise ValueError("test header requires contract transducer")
    if execution_monitor is not None and execution_monitor.get("mode") == "contract_transducer":
        if contract_transducer is None:
            raise ValueError("contract execution monitor requires contract transducer")
        if execution_monitor["memory_capacity_entries"] != contract_transducer.memory_capacity_entries:
            raise ValueError("contract execution monitor memory capacity does not match transducer")
        if len(set(dict(contract_transducer.memory_domains).values())) != 1:
            raise ValueError("contract execution monitor requires one shared memory domain")
    if isinstance(simulator_args, (str, bytes)) or not isinstance(simulator_args, Sequence):
        raise ValueError("simulator args must be a sequence")
    if any(not isinstance(value, str) or not value for value in simulator_args):
        raise ValueError("simulator args must be nonempty strings")
    simulator_args = tuple(simulator_args)
    if contract_transducer is not None and any(arg.startswith("+riscv_boot_image=") for arg in simulator_args):
        raise ValueError("contract transducer does not accept a fixed boot image")
    ports, clock, reset, polarity, layout, projector = _runtime_boundary(
        plan, root, randomized_controls=randomized_controls, control_defaults=defaults,
        contract_transducer=contract_transducer,
    )
    control_bindings, control_document = _runtime_control_bindings(
        plan, ports, layout, randomized_controls, defaults
    )
    coverage = tuple(coverage_ports)
    input_coverage = tuple(coverage_inputs)
    signals = tuple(coverage_signals)
    if not coverage and not input_coverage and not signals:
        raise ValueError("explicit bounded output-bit observations required")
    if len(coverage) + len(input_coverage) + len(signals) > 4096:
        raise ValueError("too many coverage observations")
    for item in coverage:
        if not isinstance(item, tuple) or len(item) != 2:
            raise ValueError("invalid output-bit observation")
        port, bit = item
        if (not isinstance(port, str) or port not in ports or ports[port]["direction"] != "output"
                or type(bit) is not int or not 0 <= bit < ports[port]["width"]):
            raise ValueError("invalid output-bit observation")
    if len(set(coverage)) != len(coverage):
        raise ValueError("duplicate output-bit observation")
    randomized_input_ports = {
        field.port for field in layout.fields
        if field.constraint.get("randomizable") is True
    }
    external_fields = layout.fields if contract_transducer is not None else None
    if contract_transducer is not None:
        layout = contract_transducer.cycle_layout
    for item in input_coverage:
        if not isinstance(item, tuple) or len(item) != 2:
            raise ValueError("invalid randomized runtime input observation")
        port, bit = item
        if (not isinstance(port, str) or port not in randomized_input_ports
                or port not in ports or ports[port]["direction"] != "input"
                or type(bit) is not int or not 0 <= bit < ports[port]["width"]):
            raise ValueError("coverage input must be a randomized runtime input")
    if len(set(input_coverage)) != len(input_coverage):
        raise ValueError("duplicate randomized runtime input observation")
    for item in signals:
        if (not isinstance(item, tuple) or len(item) != 2 or not isinstance(item[0], str)
                or not item[0].isidentifier() or type(item[1]) is not int or item[1] < 0):
            raise ValueError("invalid internal coverage observation")
    if len(set(signals)) != len(signals):
        raise ValueError("duplicate internal coverage observation")
    boundary_coverage = coverage + input_coverage
    observations = boundary_coverage + tuple((f"dut.{signal}", bit) for signal, bit in signals)
    coverage_kind = (
        "sampled-dut-signal-bit-events-u8-saturating"
        if input_coverage else "sampled-output-bit-events-u8-saturating"
    )
    transport = (RfuzzInputTransport(layout.raw_width, layout.layout_hash)
                 if contract_transducer is not None else build_rfuzz_transport(layout))
    bench = _bench(ports, clock, reset, polarity, layout, boundary_coverage,
                   control_bindings=control_bindings, coverage_signals=signals,
                   execution_monitor=execution_monitor, external_fields=external_fields,
                   test_header=test_header,
                   address_width=contract_transducer.address_width if contract_transducer is not None else None)
    output.mkdir(parents=True, exist_ok=False)
    write_generic_composition(plan, output / "composition", base_dir=root,
        **({"contract_transducer": contract_transducer} if contract_transducer is not None else {}))
    header_hash = None
    if contract_transducer is not None:
        for filename in ("contract_transducer.json", "contract_transducer.sv"):
            (output / filename).write_bytes((output / "composition" / filename).read_bytes())
        header_hash = content_hash(asdict(test_header))
        (output / "test_header.json").write_bytes(canonical_bytes({**asdict(test_header), "header_hash": header_hash}))
    (output / "runtime_layout.json").write_bytes(canonical_bytes(
        layout.document() if contract_transducer is not None else input_layout_document(layout)))
    (output / "runtime_transport.json").write_bytes(canonical_bytes(transport.document()))
    (output / "observations.json").write_bytes(canonical_bytes({
        "kind": coverage_kind,
        "transport": "rfuzz-coverage-buffer",
        "ports": [list(c) for c in observations],
        "randomized_input_ports": [list(c) for c in input_coverage],
        "internal_signals": [list(c) for c in signals],
    }))
    bench_path = output / "live_tb.sv"
    bench_path.write_text(bench)
    # Publication adds execution sources (including the shared arbiter) which
    # are not necessarily members of the original CPU/component source list.
    published_sources = tuple(
        str((output / "composition" / line).resolve())
        for line in (output / "composition/sources.f").read_text().splitlines()
        if line and not line.startswith(("+", "-"))
    )
    sources = (*published_sources, str(bench_path))
    includes = tuple("-I" + str(p) for p in _generic_include_paths(plan, root))
    if simulator == "icarus":
        executable = output / "sim.vvp"
        command = ("nice", "-n15", "iverilog", "-g2012", "-s", "myfuzz_live_tb",
                   "-o", str(executable), *includes, *_generic_define_options(plan), *sources)
    else:
        executable = output / "obj_dir/Vmyfuzz_live_tb"
        command = ("nice", "-n15", "verilator", "--binary", "--timing",
                   "--top-module", "myfuzz_live_tb", "-Wno-fatal", "-j", "1",
                   "--Mdir", str(output / "obj_dir"),
                   *includes, *_generic_define_options(plan), *sources)
    log_path = output / "compiler.log"
    supervised = (sys.executable, "-c",
        "import subprocess,sys; "
        "log=open(sys.argv[1],'wb'); "
        "result=subprocess.call(sys.argv[2:],stdout=log,stderr=subprocess.STDOUT); "
        "log.close(); sys.exit(result)", str(log_path), *command)
    result = run_supervised_command(CampaignOptions(command=supervised, output_dir=output / "build",
        duration_seconds=120 if simulator == "verilator" else 30,
        checkpoint_seconds=1, env={"JOBS": "1", "MAKEFLAGS": "-j1"}))
    if result["status"] != "completed" or result["returncode"] != 0:
        raise ValueError(f"{simulator} build failed; see {log_path}: {result}")
    if _generic_source_evidence_hash(root, plan.source_files, plan.interface_description.source) != plan.source_evidence_hash:
        raise ValueError("simulator source evidence changed during compilation")
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
        "constraint_hash": projector.constraint_hash,
        "instruction_mode": projector.instruction_mode,
        "runtime_controls": {**control_document, "randomized": list(randomized_controls)},
        "coverage_transport": "sysv-shared-memory-rfuzz-coverage-buffer",
        "coverage_kind": coverage_kind,
        "coverage_ports": [list(c) for c in coverage],
        "coverage_inputs": [list(c) for c in input_coverage],
        "coverage_signals": [list(c) for c in signals],
        "simulator_args": list(simulator_args),
        "simulator": simulator,
        "isolate_tests": isolate_tests,
        "execution_monitor": execution_monitor,
        **({"transducer_hash": contract_transducer.contract_hash,
            "implementation_hash": contract_transducer.implementation_hash,
            "transducer_rtl_sha256": "sha256:" + hashlib.sha256((output / "contract_transducer.sv").read_bytes()).hexdigest(),
            "header_hash": header_hash, "test_header": asdict(test_header)}
           if contract_transducer is not None else {}),
    }))
    return SimulatorArtifact(
        layout, transport, executable, observations, projector,
        coverage_kind=coverage_kind,
        control_defaults=control_document,
        randomized_controls=randomized_controls,
        simulator_args=simulator_args,
        simulator=simulator,
        isolate_tests=isolate_tests,
        execution_monitor=execution_monitor,
        transducer_hash=contract_transducer.contract_hash if contract_transducer is not None else None,
        header_hash=header_hash,
        test_header=test_header,
        implementation_hash=contract_transducer.implementation_hash if contract_transducer is not None else None,
    )


class RtlSimulator:
    """One private persistent child, with bounded per-test IO and cleanup.

    ``last_diagnostics`` preserves non-protocol output from the latest exchange
    as UTF-8 strings (invalid bytes replaced), including when that test fails.
    Limits count original bytes, including newlines, and apply per exchange.
    Internal protocol v2 correlates every response with its monotonic uint64
    request id encoded as exactly 16 lowercase hexadecimal digits. Versionless
    executables must be rebuilt; no fallback is safe.
    """
    def __init__(self, artifact, *, timeout_seconds=5.0):
        if not isinstance(artifact, SimulatorArtifact):
            raise ValueError("simulator artifact required")
        if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
                or not 0 < timeout_seconds <= 60):
            raise ValueError("finite simulator deadline required")
        self.artifact, self.timeout_seconds = artifact, timeout_seconds
        self.last_diagnostics = ()
        self._next_rss_poll = 0.0  # Immediate startup check; shared across tests.
        self._executions = 0
        self._start()

    def _start(self):
        artifact = self.artifact
        runner = ("vvp",) if artifact.simulator == "icarus" else ()
        self.process = subprocess.Popen(("nice", "-n15", *runner, str(artifact.executable), *artifact.simulator_args),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        self.closed = False
        try:
            os.set_blocking(self.process.stdin.fileno(), False)
            os.set_blocking(self.process.stdout.fileno(), False)
            if self._exchange(b"", 64) != f"RFUZZ_READY {SIMULATOR_PROTOCOL_VERSION}".encode("ascii"):
                raise ValueError(f"unsupported simulator protocol; rebuild artifact for version {SIMULATOR_PROTOCOL_VERSION}")
        except BaseException:
            self.close()
            raise

    def _exchange(self, payload, max_reply, monitor=None):
        deadline = time.monotonic() + self.timeout_seconds
        pending, reply = memoryview(payload), bytearray()
        diagnostics, diagnostic_bytes, frame = [], 0, None
        self.last_diagnostics = ()
        try:
            # No output from the previous transaction may satisfy a new test.
            if pending:
                try:
                    stale = os.read(self.process.stdout.fileno(), 4096)
                except BlockingIOError:
                    pass
                else:
                    if not stale:
                        raise RuntimeError("simulator closed output")
                    raise ValueError("unexpected simulator response framing before test")
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
                            # Drain all currently readable chunks before accepting
                            # a frame, so read chunking cannot hide duplicates.
                            while True:
                                try:
                                    chunk = os.read(key.fd, 4096)
                                except BlockingIOError:
                                    if frame is not None:
                                        if self.process.poll() is not None:
                                            raise RuntimeError("simulator exited after response")
                                        return frame
                                    break
                                if not chunk:
                                    raise RuntimeError("simulator closed output")
                                if frame is not None:
                                    raise ValueError("unexpected simulator response framing")
                                reply.extend(chunk)
                                while b"\n" in reply:
                                    line, _, remaining = reply.partition(b"\n")
                                    reply = bytearray(remaining)
                                    if line.startswith(b"RFUZZ_"):
                                        expected = (line.startswith(b"RFUZZ_COUNTERS ")
                                                    if payload else line == b"RFUZZ_READY" or line.startswith(b"RFUZZ_READY "))
                                        if pending or not expected or reply:
                                            raise ValueError("unexpected simulator response framing")
                                        if len(line) > max_reply:
                                            raise ValueError("oversized simulator response")
                                        frame = bytes(line)
                                    else:
                                        if (len(line) > MAX_DIAGNOSTIC_LINE_BYTES
                                                or len(diagnostics) >= MAX_DIAGNOSTIC_LINES
                                                or diagnostic_bytes + len(line) + 1 > MAX_DIAGNOSTIC_BYTES):
                                            raise ValueError("simulator diagnostic output limit exceeded")
                                        diagnostic_bytes += len(line) + 1
                                        diagnostics.append(line.decode("utf-8", errors="replace"))
                                if reply.startswith(b"RFUZZ_"):
                                    if len(reply) > max_reply:
                                        raise ValueError("oversized simulator response")
                                elif (len(reply) > MAX_DIAGNOSTIC_LINE_BYTES
                                      or diagnostic_bytes + len(reply) > MAX_DIAGNOSTIC_BYTES):
                                    raise ValueError("simulator diagnostic output limit exceeded")
        finally:
            if (reply and not reply.startswith(b"RFUZZ_")
                    and len(reply) <= MAX_DIAGNOSTIC_LINE_BYTES
                    and len(diagnostics) < MAX_DIAGNOSTIC_LINES
                    and diagnostic_bytes + len(reply) <= MAX_DIAGNOSTIC_BYTES):
                diagnostics.append(reply.decode("utf-8", errors="replace"))
            self.last_diagnostics = tuple(diagnostics)

    def run_test(self, records, *, monitor=None):
        self.last_diagnostics = ()
        if self.closed:
            raise ValueError("simulator is closed")
        if not isinstance(records, (tuple, list)) or not 1 <= len(records) <= MAX_CYCLES:
            raise ValueError("bounded nonempty sample sequence required")
        if self.artifact.test_header is not None and len(records) > self.artifact.test_header.execution_cycles:
            raise ValueError("test exceeds header execution cycle limit")
        if len(records) * (self.artifact.layout.raw_width // 4 + 2) > MAX_IO_BYTES:
            raise ValueError("test input exceeds IO bound")
        if self._executions >= MAX_REQUEST_ID:
            raise ValueError("simulator request id exhausted")
        if self.artifact.isolate_tests and self._executions:
            self.close()
            self._start()
        self._executions += 1
        samples = [self.artifact.projector.project(self.artifact.transport.unpack(r)) for r in records]
        payload = (f"{self._executions:016x} {len(samples)}\n" + "".join(f"{s:x}\n" for s in samples)).encode("ascii")
        try:
            count = len(self.artifact.coverage_ports)
            reply = self._exchange(payload, 2 * count + 256, monitor=monitor)
            prefix = f"RFUZZ_COUNTERS {self._executions:016x} ".encode("ascii")
            if not reply.startswith(prefix):
                raise ValueError("invalid simulator response request id")
            reply = reply[len(prefix):]
            self.last_execution = {}
            if self.artifact.execution_monitor is not None:
                reply, separator, metrics = reply.partition(b" EXEC ")
                if not separator:
                    raise ValueError("missing RTL execution metrics")
                self.last_execution = validate_execution(parse_metrics(metrics, self.artifact.execution_monitor))
            if len(reply) != 2 * count:
                raise ValueError("invalid simulator counter response")
            counters = bytes.fromhex(reply.decode("ascii"))
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
