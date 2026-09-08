"""Generated composition receives real raw samples and returns RTL event coverage."""
from pathlib import Path
from dataclasses import replace
import os
import json
import hashlib
import signal
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch
import shutil
import tempfile
import textwrap
import time
import unittest

from myfuzz.composition import GenericCompositionRequest, load_interface_description, plan_generic_composition, source_tree_hash
from myfuzz.composition.input_layout import InputLayout, LayoutField
from myfuzz.composition.contract_transducer import compile_contract_transducer
from myfuzz.composition.cycle_input import CycleField, CycleInputLayout, TestHeader
from myfuzz.isa.constraints import IsaContract
try:
    from myfuzz.integration import rfuzz_simulator
except ImportError:
    rfuzz_simulator = None


def make_plan(root, *, renamed=False):
    directory = root / "source"
    directory.mkdir()
    names = ("clock_x", "reset_x", "payload_x", "enable_x", "flags_x") if renamed else ("clk", "rst", "value", "enable", "flags")
    clk, rst, value, enable, flags = names
    source = directory / "source.sv"
    source.write_text(f"module arbitrary(input logic {clk}, input logic {rst}, input logic [7:0] {value}, input logic {enable}, output logic [2:0] {flags}); logic [7:0] state; always_ff @(posedge {clk} or negedge {rst}) if(!{rst}) state <= 0; else if({enable}) state <= state + {value}; assign {flags} = state[2:0]; endmodule")
    description = load_interface_description({"schema_version":"interface_description.v1", "source":{"root":"source", "revision":source_tree_hash(directory,(source,)), "top_module":"arbitrary", "files":["source.sv"]}, "endpoints":[{"endpoint_id":"control", "function":"control", "module":"arbitrary", "fields":[{"role":role,"aliases":[port]} for role,port in zip(("clock","reset","data","valid","status"),names)]}]})
    return plan_generic_composition(GenericCompositionRequest(description,()),base_dir=root), names


def make_control_plan(root):
    directory = root / "source"
    directory.mkdir()
    source = directory / "source.sv"
    source.write_text(
        "module arbitrary(input logic clk, input logic rst, input logic [7:0] value, "
        "input logic enable, input logic [31:0] boot_address, input logic [3:0] hart_id, "
        "input logic debug_request, input logic [3:0] interrupt, output logic [2:0] flags); "
        "logic [7:0] state; always_ff @(posedge clk or negedge rst) "
        "if(!rst) state <= 0; else if(enable) state <= state + value; "
        "assign flags = state[2:0]; endmodule"
    )
    roles = ("clock", "reset", "data", "valid", "boot_address", "hart_id",
             "debug_request", "interrupt", "status")
    ports = ("clk", "rst", "value", "enable", "boot_address", "hart_id",
             "debug_request", "interrupt", "flags")
    description = load_interface_description({
        "schema_version": "interface_description.v1",
        "source": {"root": "source", "revision": source_tree_hash(directory, (source,)),
                    "top_module": "arbitrary", "files": ["source.sv"]},
        "endpoints": [{"endpoint_id": "control", "function": "control", "module": "arbitrary",
                       "fields": [{"role": role, "aliases": [port],
                                   **({"randomizable": True} if role == "interrupt" else {})}
                                  for role, port in zip(roles, ports)]}],
    })
    return plan_generic_composition(GenericCompositionRequest(description, ()), base_dir=root), ports


def make_contract_plan(root, *, external=False, controls=False, instruction_observation=False):
    from tests.integration.test_processor_auto_wiring import _split_fixture
    from myfuzz.composition.interface_description import interface_description_document
    plan = _split_fixture(root)
    if external or controls or instruction_observation:
        source = root / "source/rtl/renamed_split.sv"
        extra_ports, extra_logic, extra_fields = [], [], []
        if external:
            extra_ports += ["input logic [3:0] entropy_pin", "output logic [3:0] observed_entropy"]
            extra_logic.append("assign observed_entropy=entropy_pin;")
            extra_fields += [{"role": "data", "aliases": ["entropy_pin"]}, {"role": "status", "aliases": ["observed_entropy"]}]
        if controls:
            extra_ports += ["input logic [31:0] boot_pin", "input logic [3:0] hart_pin", "output logic controls_seen"]
            extra_logic.append("assign controls_seen=(boot_pin==32'h80)&&(hart_pin==3);")
            extra_fields += [{"role": "boot_address", "aliases": ["boot_pin"]}, {"role": "hart_id", "aliases": ["hart_pin"]},
                             {"role": "controls_seen", "aliases": ["controls_seen"]}]
        if instruction_observation:
            extra_ports.append("output logic [31:0] instruction_word")
            extra_logic.append("always_ff @(posedge clock_pin or negedge reset_pin) if(!reset_pin) instruction_word<=0; else if(i_response) instruction_word<=i_read_data;")
            extra_fields.append({"role": "instruction_word", "aliases": ["instruction_word"]})
        source.write_text(source.read_text().replace("output logic completion_flag,", ", ".join(extra_ports) + ", output logic completion_flag,")
            .replace("logic i_active, d_active;", " ".join(extra_logic) + " logic i_active, d_active;"))
        document = interface_description_document(plan.interface_description)
        document["source"]["revision"] = source_tree_hash(root / "source", (source,))
        document["endpoints"].append({"endpoint_id": "environment", "function": "control", "module": "renamed_split", "fields": extra_fields})
        plan = plan_generic_composition(replace(plan.request, interface_description=load_interface_description(document)),
            base_dir=root, component_catalog=plan.component_catalog, protocol_catalog=plan.protocol_catalog)
    external_inputs = {field.field_id: field.width for field in plan.layout.fields if field.port == "entropy_pin"}
    transducer = compile_contract_transducer(isa=IsaContract(32, ("I",)),
        protocol=("processor-memory-beat", "1"), address_width=32, data_width=32,
        memory_domains={"instruction_memory_master": "shared", "data_memory_master": "shared"},
        external_inputs=external_inputs, max_wait_cycles=2, allow_error=False, memory_capacity_entries=4)
    return plan, transducer


class SimulatorFramingTests(unittest.TestCase):
    def simulator(self, body, *, startup=b"RFUZZ_READY 2\n", isolate_tests=False):
        from myfuzz.composition.runtime_projection import RuntimeProjector
        layout = InputLayout("input_layout.v1", 1,
            (LayoutField("input:data", "input", "data", 1, 0, 0, "bits", {}),), "framing")
        script = (
            "import os, sys, time\n"
            f"os.write(1, {startup!r})\n"
            "def counter(value, response_id=None):\n"
            "    identity = request_id if response_id is None else response_id\n"
            "    return f'RFUZZ_COUNTERS {identity:016x} {value}\\n'.encode()\n"
            "execution = 0\n"
            "for header in sys.stdin:\n"
            "    identity_text, count_text = header.split()\n"
            "    request_id, count = int(identity_text, 16), int(count_text)\n"
            "    for _ in range(count):\n"
            "        sys.stdin.readline()\n"
            "    execution += 1\n" + textwrap.indent(textwrap.dedent(body), "    ")
        )
        artifact = rfuzz_simulator.SimulatorArtifact(layout,
            rfuzz_simulator.build_rfuzz_transport(layout), Path(sys.executable), (("flag", 0),),
            RuntimeProjector(layout), simulator="verilator", simulator_args=("-u", "-c", script),
            isolate_tests=isolate_tests)
        return rfuzz_simulator.RtlSimulator(artifact, timeout_seconds=1)

    def test_diagnostics_before_counter_frame_are_preserved_across_read_chunking(self):
        for chunk_size in (4096, 7, 1):
            with self.subTest(chunk_size=chunk_size), self.simulator("""
                os.write(1, b'generic note\\npartial UTF-8: \\xe4\\xb8\\xad\\n' + counter('01'))
            """) as simulator:
                read = os.read
                with patch.object(rfuzz_simulator.os, "read",
                                  side_effect=lambda fd, size: read(fd, min(size, chunk_size))):
                    self.assertEqual(b"\1", simulator.run_test((simulator.artifact.transport.pack(0),)))
                self.assertEqual(("generic note", "partial UTF-8: 中"), simulator.last_diagnostics)

    def test_diagnostics_and_partial_lines_may_arrive_in_later_chunks(self):
        with self.simulator("""
            os.write(1, b'first note\\npartial')
            time.sleep(.03)
            os.write(1, b' note\\n')
            time.sleep(.03)
            os.write(1, counter('02'))
        """) as simulator:
            self.assertEqual(b"\2", simulator.run_test((simulator.artifact.transport.pack(0),)))
            self.assertEqual(("first note", "partial note"), simulator.last_diagnostics)

    def test_diagnostics_reset_between_tests_and_allow_two_hundred_cpu_notes(self):
        with self.simulator("""
            if execution == 1:
                os.write(1, (b'normal execution note ' + b'x' * 100 + b'\\n') * 200)
            os.write(1, counter('00'))
        """) as simulator:
            records = (simulator.artifact.transport.pack(0),)
            self.assertEqual(b"\0", simulator.run_test(records))
            self.assertEqual(200, len(simulator.last_diagnostics))
            self.assertEqual(b"\0", simulator.run_test(records))
            self.assertEqual((), simulator.last_diagnostics)

    def test_diagnostics_clear_when_test_is_rejected_before_exchange(self):
        with self.simulator("os.write(1, b'note\\n' + counter('00'))") as simulator:
            record = simulator.artifact.transport.pack(0)
            for records in ((), (b"bad",)):
                self.assertEqual(b"\0", simulator.run_test((record,)))
                self.assertEqual(("note",), simulator.last_diagnostics)
                with self.assertRaises(ValueError):
                    simulator.run_test(records)
                self.assertEqual((), simulator.last_diagnostics)
            simulator.artifact = replace(simulator.artifact,
                test_header=TestHeader("cycle_test.v1", "framing", "contract", 2, 1, 0, 0))
            simulator.run_test((record,))
            with self.assertRaisesRegex(ValueError, "header execution"):
                simulator.run_test((record, record))
            self.assertEqual((), simulator.last_diagnostics)
            simulator.run_test((record,))
            simulator.close()
            with self.assertRaisesRegex(ValueError, "closed"):
                simulator.run_test((record,))
            self.assertEqual((), simulator.last_diagnostics)

    def test_duplicate_counter_frames_fail_with_whole_or_split_reads(self):
        for chunk_size in (4096, 7):
            with self.subTest(chunk_size=chunk_size), self.simulator("""
                os.write(1, counter('00') + counter('01'))
            """) as simulator:
                read = os.read
                with patch.object(rfuzz_simulator.os, "read",
                                  side_effect=lambda fd, size: read(fd, min(size, chunk_size))):
                    with self.assertRaisesRegex(ValueError, "framing"):
                        simulator.run_test((simulator.artifact.transport.pack(0),))
                self.assertTrue(simulator.closed)

    def test_delayed_duplicate_frame_cannot_satisfy_the_next_test(self):
        with self.simulator("""
            os.write(1, counter('00'))
            time.sleep(.03)
            os.write(1, counter('01'))
        """) as simulator:
            records = (simulator.artifact.transport.pack(0),)
            self.assertEqual(b"\0", simulator.run_test(records))
            time.sleep(.06)
            with self.assertRaisesRegex(ValueError, "framing"):
                simulator.run_test(records)
            self.assertTrue(simulator.closed)

    def test_prior_frame_arriving_after_next_request_is_rejected(self):
        # The child reads the complete next request before releasing the old
        # response. This ordering is deterministic and needs no timing window.
        with self.simulator("""
            if execution == 1:
                previous_id = request_id
                os.write(1, counter('00'))
            else:
                os.write(1, counter('01', previous_id))  # Next test should be 02.
        """) as simulator:
            records = (simulator.artifact.transport.pack(0),)
            self.assertEqual(b"\0", simulator.run_test(records))
            with self.assertRaisesRegex(ValueError, "request id"):
                simulator.run_test(records)
            self.assertTrue(simulator.closed)

    def test_response_request_id_is_required_canonical_and_exact(self):
        for response in (b"RFUZZ_COUNTERS 00\n", b"RFUZZ_COUNTERS 1\n",
                         b"RFUZZ_COUNTERS 0000000000000001\n",
                         b"RFUZZ_COUNTERS 0000000000000000 01\n",
                         b"RFUZZ_COUNTERS 0000000000000002 01\n",
                         b"RFUZZ_COUNTERS 10000000000000000 01\n",
                         b"RFUZZ_COUNTERS 0 01\n", b"RFUZZ_COUNTERS 2 01\n",
                         b"RFUZZ_COUNTERS 01 01\n", b"RFUZZ_COUNTERS +1 01\n",
                         b"RFUZZ_COUNTERS -1 01\n", b"RFUZZ_COUNTERS x 01\n",
                         b"RFUZZ_COUNTERS 18446744073709551616 01\n"):
            with self.subTest(response=response), self.simulator(f"os.write(1, {response!r})") as simulator:
                with self.assertRaisesRegex(ValueError, "request id"):
                    simulator.run_test((simulator.artifact.transport.pack(0),))
                self.assertTrue(simulator.closed)

    def test_versionless_or_unsupported_simulators_require_rebuilding(self):
        for startup in (b"RFUZZ_READY\n", b"RFUZZ_READY 1\n", b"RFUZZ_READY 3\n",
                        b"RFUZZ_READY 02\n", b"RFUZZ_READY 2 extra\n"):
            with self.subTest(startup=startup), self.assertRaisesRegex(ValueError, "protocol.*rebuild"):
                with self.simulator("pass", startup=startup):
                    pass

    def test_request_ids_increase_across_lengths_repeats_and_isolated_children(self):
        for isolated in (False, True):
            with self.subTest(isolated=isolated), self.simulator("""
                os.write(1, f'id={request_id} cycles={count}\\n'.encode() + counter(f'{count:02x}'))
            """, isolate_tests=isolated) as simulator:
                for identity, count in enumerate((1, 3, 2, 1), start=1):
                    self.assertEqual(bytes((count,)),
                        simulator.run_test((simulator.artifact.transport.pack(0),) * count))
                    self.assertEqual((f"id={identity} cycles={count}",), simulator.last_diagnostics)

    def test_request_id_exhaustion_does_not_wrap(self):
        with self.simulator("os.write(1, counter('00'))") as simulator:
            simulator._executions = (1 << 64) - 1
            with self.assertRaisesRegex(ValueError, "request id"):
                simulator.run_test((simulator.artifact.transport.pack(0),))

    def test_malformed_and_truncated_protocol_lines_are_not_diagnostics(self):
        for output in (b"RFUZZ_COUNTERS\nRFUZZ_COUNTERS 0000000000000001 00\n",
                       b"RFUZZ_UNKNOWN 00\nRFUZZ_COUNTERS 0000000000000001 00\n",
                       b"RFUZZ_COUNTERS 0000000000000001 0\n", b"RFUZZ_COUNTERS 0000000000000001 xx\n",
                       b"RFUZZ_COUNTERS 0000000000000001 00"):
            with self.subTest(output=output), self.simulator(f"os.write(1, {output!r})") as simulator:
                with self.assertRaises((ValueError, TimeoutError)):
                    simulator.run_test((simulator.artifact.transport.pack(0),))
                self.assertTrue(simulator.closed)

    def test_diagnostic_spam_has_byte_line_and_unterminated_line_limits(self):
        cases = (
            "os.write(1, b'line\\n' * 1025)",
            "os.write(1, (b'x' * 1023 + b'\\n') * 257)",
            "os.write(1, b'x' * 4097)",
        )
        for body in cases:
            with self.subTest(body=body), self.simulator(body) as simulator:
                started = time.monotonic()
                with self.assertRaisesRegex(ValueError, "diagnostic"):
                    simulator.run_test((simulator.artifact.transport.pack(0),))
                self.assertLess(time.monotonic() - started, .8)
                self.assertTrue(simulator.closed)
                self.assertLessEqual(len(simulator.last_diagnostics), 1024)
                self.assertLessEqual(sum(len(line.encode()) + 1 for line in simulator.last_diagnostics), 256 * 1024)

    def test_fatal_or_eof_before_counter_frame_still_fails_and_keeps_diagnostics(self):
        for exit_code in (0, 7):
            with self.subTest(exit_code=exit_code), self.simulator(f"""
                os.write(1, b'generic terminal diagnostic\\n')
                sys.exit({exit_code})
            """) as simulator:
                with self.assertRaisesRegex(RuntimeError, "closed output|exited"):
                    simulator.run_test((simulator.artifact.transport.pack(0),))
                self.assertEqual(("generic terminal diagnostic",), simulator.last_diagnostics)
                self.assertTrue(simulator.closed)
                self.assertIsNotNone(simulator.process.poll())

    def test_unterminated_diagnostic_is_preserved_when_process_exits(self):
        with self.simulator("os.write(1, b'terminal detail'); sys.exit(7)") as simulator:
            with self.assertRaisesRegex(RuntimeError, "closed output"):
                simulator.run_test((simulator.artifact.transport.pack(0),))
            self.assertEqual(("terminal detail",), simulator.last_diagnostics)


@unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp") and shutil.which("verilator"), "RTL tools required")
class ContractSimulatorTests(unittest.TestCase):
    def test_generated_bench_echoes_wide_request_ids_across_reuse_and_isolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, names = make_plan(root)
            for engine in ("icarus", "verilator"):
                artifact = rfuzz_simulator.build_simulator(plan, root / engine, base_dir=root,
                    simulator=engine, coverage_ports=((names[-1], 0),))
                for isolated in (False, True):
                    with self.subTest(engine=engine, isolated=isolated), rfuzz_simulator.RtlSimulator(
                            replace(artifact, isolate_tests=isolated)) as simulator:
                        simulator._executions = (1 << 63) - 2
                        for index, count in enumerate((1, 3, 2, 1), start=1):
                            self.assertEqual(b"\0", simulator.run_test((artifact.transport.pack(0),) * count))
                            self.assertEqual((1 << 63) - 2 + index, simulator._executions)
                        simulator._executions = (1 << 64) - 2
                        self.assertEqual(b"\0", simulator.run_test((artifact.transport.pack(0),)))
                        self.assertEqual((1 << 64) - 1, simulator._executions)
                        with self.assertRaisesRegex(ValueError, "request id"):
                            simulator.run_test((artifact.transport.pack(0),))

    def test_cycle_external_slices_must_match_declared_physical_bindings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, contract = make_contract_plan(root, external=True)
            changed_width = CycleInputLayout.build([CycleField(field.field_id,
                1 if field.field_id.startswith("external.") else field.width) for field in contract.cycle_layout.fields])
            extra_field = CycleInputLayout.build([*contract.cycle_layout.fields, CycleField("external.unbound", 1)])
            for index, layout in enumerate((changed_width, extra_field)):
                with self.subTest(index=index), self.assertRaisesRegex(ValueError, "external cycle"):
                    rfuzz_simulator.build_simulator(plan, root / f"bad-{index}", base_dir=root,
                        coverage_ports=(("completion_flag", 0),), contract_transducer=replace(contract, cycle_layout=layout))
                self.assertFalse((root / f"bad-{index}").exists())

    def test_maximal_contract_wait_is_not_cancelled_by_outer_watchdogs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, contract = make_contract_plan(root)
            contract = replace(contract, max_wait_cycles=20)
            artifact = rfuzz_simulator.build_simulator(plan, root / "runtime", base_dir=root,
                coverage_ports=(("completion_flag", 0), ("instruction_errors_ok", 0)), contract_transducer=contract)
            with rfuzz_simulator.RtlSimulator(artifact) as simulator:
                counters = simulator.run_test((artifact.transport.pack(0),) * 500)
            self.assertGreater(counters[0], 0)
            self.assertLess(counters[1], 150)

    def test_instruction_route_uses_instruction_entropy_and_fixed_header_mode(self):
        from myfuzz.isa.transducer import RiscvInstructionTransducer
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, contract = make_contract_plan(root, instruction_observation=True)
            fields = {field.field_id: field for field in contract.cycle_layout.fields}
            raw = (255 << fields["instruction_selector"].raw_lo) | (0xabcdef00 << fields["instruction_payload"].raw_lo)
            raw |= 3 << fields["response_choice"].raw_lo
            for illegal in (False, True):
                with self.subTest(illegal=illegal):
                    header = TestHeader("cycle_test.v1", contract.cycle_layout.layout_hash, contract.contract_hash, 2, 150, 0, 0, illegal)
                    artifact = rfuzz_simulator.build_simulator(plan, root / f"runtime-{illegal}", base_dir=root,
                        coverage_ports=tuple(("instruction_word", bit) for bit in range(32)), contract_transducer=contract, test_header=header)
                    with rfuzz_simulator.RtlSimulator(artifact) as simulator:
                        counters = simulator.run_test((artifact.transport.pack(raw),) * 150)
                    observed = sum((count > 0) << bit for bit, count in enumerate(counters))
                    expected = RiscvInstructionTransducer(contract.isa).repair(255, 0xabcdef00, illegal=illegal).word
                    self.assertEqual(observed, expected)

    def test_header_fixed_controls_reach_physical_cpu_ports(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, contract = make_contract_plan(root, controls=True)
            header = TestHeader("cycle_test.v1", contract.cycle_layout.layout_hash, contract.contract_hash, 2, 5, 0x80, 3)
            artifact = rfuzz_simulator.build_simulator(plan, root / "runtime", base_dir=root,
                coverage_ports=(("controls_seen", 0),), contract_transducer=contract, test_header=header)
            with rfuzz_simulator.RtlSimulator(artifact) as simulator:
                self.assertEqual(simulator.run_test((artifact.transport.pack(0),) * 5), bytes((5,)))

    def test_rejects_invalid_header_external_bindings_and_fixed_boot_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, contract = make_contract_plan(root, external=True)
            good = TestHeader("cycle_test.v1", contract.cycle_layout.layout_hash, contract.contract_hash, 2, 150, 0, 0)
            cases = (
                ({"test_header": replace(good, layout_hash="wrong")}, "layout hash"),
                ({"test_header": replace(good, contract_hash="wrong")}, "contract hash"),
                ({"test_header": replace(good, boot_address=2)}, "instruction alignment"),
                ({"test_header": replace(good, reset_cycles=0)}, "bounded and positive"),
                ({"test_header": good, "control_defaults": {"boot_address": 4}}, "conflicts"),
                ({"randomized_controls": ("hart_id",)}, "must be fixed"),
                ({"simulator_args": ("+riscv_boot_image=/missing",)}, "fixed boot image"),
                ({"contract_transducer": replace(contract, external_inputs=())}, "external inputs"),
            )
            for index, (kwargs, message) in enumerate(cases):
                with self.subTest(index=index), self.assertRaisesRegex(ValueError, message):
                    rfuzz_simulator.build_simulator(plan, root / f"bad-{index}", base_dir=root,
                        coverage_ports=(("completion_flag", 0),), **{"contract_transducer": contract, **kwargs})
                self.assertFalse((root / f"bad-{index}").exists())

    def test_publishes_contract_cycle_layout_and_identity_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, contract = make_contract_plan(root)
            artifact = rfuzz_simulator.build_simulator(plan, root / "runtime", base_dir=root,
                coverage_ports=(("completion_flag", 0),), contract_transducer=contract)
            self.assertTrue((root / "runtime/contract_transducer.json").is_file())
            self.assertTrue((root / "runtime/contract_transducer.sv").is_file())
            self.assertEqual(artifact.layout, contract.cycle_layout)
            self.assertEqual(artifact.transport.raw_width, contract.cycle_layout.raw_width)
            self.assertEqual(artifact.projector.project((1 << artifact.layout.raw_width) - 1), (1 << artifact.layout.raw_width) - 1)
            self.assertEqual(artifact.projector.constraint_hash, contract.contract_hash)
            self.assertEqual(artifact.transducer_hash, contract.contract_hash)
            self.assertTrue(artifact.header_hash)
            self.assertFalse(any(arg.startswith("+riscv_boot_image=") for arg in artifact.simulator_args))
            provenance = json.loads((root / "runtime/artifact_provenance.json").read_text())
            self.assertEqual(provenance["header_hash"], artifact.header_hash)
            self.assertEqual(provenance["transducer_hash"], artifact.transducer_hash)
            self.assertEqual(provenance["transducer_rtl_sha256"], "sha256:" + hashlib.sha256((root / "runtime/contract_transducer.sv").read_bytes()).hexdigest())

    def test_live_transducer_consumes_equal_width_cycles_and_clears_between_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, contract = make_contract_plan(root, external=True)
            artifact = rfuzz_simulator.build_simulator(plan, root / "runtime", base_dir=root,
                coverage_ports=(("completion_flag", 0), ("instruction_errors_ok", 0), ("data_history", 0), ("observed_entropy", 0)),
                contract_transducer=contract)
            fields = {field.field_id: field for field in artifact.layout.fields}
            raw = (3 << fields["response_choice"].raw_lo) | (1 << fields["response_data"].raw_lo)
            raw |= 1 << fields["external.environment:data"].raw_lo
            records = (artifact.transport.pack(raw),) * 150
            with rfuzz_simulator.RtlSimulator(artifact) as simulator:
                first = simulator.run_test(records)
                second_raw = raw & ~(1 << fields["response_data"].raw_lo) & ~(1 << fields["external.environment:data"].raw_lo)
                second = simulator.run_test((artifact.transport.pack(second_raw),) * 150)
                again = simulator.run_test(records)
            self.assertGreater(first[0], 0)
            self.assertLess(first[1], 50)  # Instruction reads complete without target errors.
            self.assertGreater(first[2], 0)
            self.assertEqual(first[3], 150)
            self.assertEqual(second[2:], bytes((0, 0)))
            self.assertEqual(first, again)

    def test_header_controls_and_cycle_limit_are_fixed_per_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, contract = make_contract_plan(root)
            header = TestHeader("cycle_test.v1", contract.cycle_layout.layout_hash, contract.contract_hash, 3, 10, 0, 0)
            artifact = rfuzz_simulator.build_simulator(plan, root / "runtime", base_dir=root,
                coverage_ports=(("completion_flag", 0),), contract_transducer=contract, test_header=header)
            self.assertEqual(artifact.test_header, header)
            bench = (root / "runtime/live_tb.sv").read_text()
            self.assertIn("repeat (3) tick();", bench)
            self.assertLess(bench.index("test_begin=1; tick(); test_begin=0;"), bench.index("repeat (3) tick();"))
            with rfuzz_simulator.RtlSimulator(artifact) as simulator:
                with self.assertRaisesRegex(ValueError, "header execution"):
                    simulator.run_test((artifact.transport.pack(0),) * 11)


@unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus required")
class RfuzzSimulatorTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(rfuzz_simulator, "live layout-to-RTL simulator missing")

    def test_bench_drives_packed_port_by_compiler_member_ranges(self):
        fields = (
            LayoutField("e:valid", "e", "valid", 1, 0, 0, "bits", {},
                        port="bundle", member_path=("valid",),
                        port_raw_lo=8, port_raw_hi=8, port_width=9),
            LayoutField("e:data", "e", "data", 8, 1, 8, "bits", {},
                        port="bundle", member_path=("data",),
                        port_raw_lo=0, port_raw_hi=7, port_width=9),
        )
        layout = InputLayout("input_layout.v1", 9, fields, "packed")
        ports = {
            "clk": {"opaque_port": "p_clk", "width": 1},
            "rst": {"opaque_port": "p_rst", "width": 1},
            "bundle": {"opaque_port": "p_bundle", "width": 9},
            "flags": {"opaque_port": "p_flags", "width": 1},
        }
        bench = rfuzz_simulator._bench(
            ports, "clk", "rst", "active_low", layout, (("flags", 0),)
        )
        self.assertIn("assign p_bundle[8:8] = raw_bits[0:0];", bench)
        self.assertIn("assign p_bundle[7:0] = raw_bits[8:1];", bench)
        self.assertNotIn("assign p_bundle =", bench)

    def test_packed_member_clock_is_rejected_before_container_driving(self):
        field = SimpleNamespace(
            role="clock", direction="input", width=1, port="ctl",
            member_path=("clk",), container_width=2,
        )
        capability = SimpleNamespace(
            protocol=None, endpoint_id="control", fields=(field,),
        )
        plan = SimpleNamespace(
            capabilities=(capability,), annotations={"endpoints": []},
            interface_description=SimpleNamespace(
                source=SimpleNamespace(source_root="source")
            ),
        )
        records = (
            {"source_port": "ctl", "opaque_port": "p_ctl", "direction": "input",
             "width": 2, "signed": False, "members": (("clk", 1, 1, 1),)},
        )
        with patch.object(rfuzz_simulator, "_generic_routes", return_value=()), \
             patch.object(rfuzz_simulator, "_generic_port_records", return_value=records), \
             self.assertRaisesRegex(ValueError, "clock/reset"):
            rfuzz_simulator._runtime_boundary(plan, Path("/tmp"))

    def test_processor_projection_excludes_packed_response_container_only(self):
        clock = SimpleNamespace(
            role="clock", direction="input", width=1, port="clk",
            member_path=(), container_width=None,
        )
        reset = SimpleNamespace(
            role="reset", direction="input", width=1, port="rst_n",
            member_path=(), container_width=None,
        )
        route = SimpleNamespace(
            endpoint_id="processor.memory",
            field_connections=(
                {"direction": "input", "physical": {
                    "container_port": "response_container",
                    "member_path": ["gnt"], "part_select": "[0:0]",
                    "raw_lo": 0, "raw_hi": 0, "container_width": 33,
                }},
                {"direction": "input", "physical": {
                    "container_port": "response_container",
                    "member_path": ["rdata"], "part_select": "[32:1]",
                    "raw_lo": 1, "raw_hi": 32, "container_width": 33,
                }},
            ),
        )
        packed_random = (
            LayoutField("random:low", "random", "low", 4, 33, 36, "bits", {},
                        port="random_container", member_path=("low",), evidence=("compiler_elaboration",),
                        port_raw_lo=0, port_raw_hi=3, port_width=8),
            LayoutField("random:high", "random", "high", 4, 37, 40, "bits", {},
                        port="random_container", member_path=("high",), evidence=("compiler_elaboration",),
                        port_raw_lo=4, port_raw_hi=7, port_width=8),
        )
        scalar_random = LayoutField(
            "random:scalar", "random", "scalar", 1, 41, 41, "bits", {},
            port="random_scalar", direction="input",
        )
        owned = (
            LayoutField("memory:gnt", "memory", "gnt", 1, 0, 0, "bits", {},
                        port="response_container", member_path=("gnt",),
                        port_raw_lo=0, port_raw_hi=0, port_width=33),
            LayoutField("memory:rdata", "memory", "rdata", 32, 1, 32, "bits", {},
                        port="response_container", member_path=("rdata",),
                        port_raw_lo=1, port_raw_hi=32, port_width=33),
        )
        plan = SimpleNamespace(
            processor_execution=SimpleNamespace(routes=(route,)),
            capabilities=(
                SimpleNamespace(protocol=None, endpoint_id="clock", fields=(clock,)),
                SimpleNamespace(protocol=None, endpoint_id="reset", fields=(reset,)),
                SimpleNamespace(protocol=("axi4", "1"), endpoint_id="processor.memory", fields=()),
            ),
            annotations={"endpoints": []},
            interface_description=SimpleNamespace(source=SimpleNamespace(source_root="source")),
            layout=InputLayout("input_layout.v1", 42, (*owned, *packed_random, scalar_random), "packed"),
            request=SimpleNamespace(isa=None),
        )
        records = (
            {"source_port": "clk", "opaque_port": "p_clk", "direction": "input", "width": 1},
            {"source_port": "rst_n", "opaque_port": "p_rst", "direction": "input", "width": 1},
            {"source_port": "response_container", "opaque_port": "p_rsp", "direction": "input", "width": 33},
            {"source_port": "random_container", "opaque_port": "p_random", "direction": "input", "width": 8},
            {"source_port": "random_scalar", "opaque_port": "p_scalar", "direction": "input", "width": 1},
        )

        def projected_records(_plan, *, internal_ports=frozenset(), **_kwargs):
            return tuple(record for record in records if record["source_port"] not in internal_ports)

        with patch.object(rfuzz_simulator, "_generic_port_records", side_effect=projected_records), \
             patch("myfuzz.composition.protocol_composer._processor_controls",
                   return_value=("clk", "rst_n", {"polarity": "active_low", "synchrony": "asynchronous"})):
            ports, _, _, _, layout, _ = rfuzz_simulator._runtime_boundary(plan, Path("/tmp"))

        self.assertNotIn("response_container", ports)
        self.assertEqual(
            [(field.port, field.member_path) for field in layout.fields],
            [("random_container", ("low",)), ("random_container", ("high",)),
             ("random_scalar", ())],
        )

    def test_campaign_monitor_runs_during_blocked_rtl_exchange(self):
        import time
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, names = make_plan(root)
            artifact = rfuzz_simulator.build_simulator(plan, root / "runtime", base_dir=root,
                coverage_ports=((names[-1], 0),))
            with rfuzz_simulator.RtlSimulator(artifact) as simulator:
                os.kill(simulator.process.pid, signal.SIGSTOP)
                started = time.monotonic()
                calls = []
                def monitor():
                    calls.append(time.monotonic())
                    if calls[-1] - started >= .05:
                        raise MemoryError("aggregate memory limit")
                with self.assertRaisesRegex(MemoryError, "aggregate"):
                    simulator.run_test((artifact.transport.pack(0),), monitor=monitor)
                self.assertGreater(len(calls), 1)
                self.assertLess(time.monotonic() - started, 1)
                self.assertIsNotNone(simulator.process.poll())

    def test_rss_poll_interval_spans_replays_and_enforces_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, names = make_plan(root)
            artifact = rfuzz_simulator.build_simulator(plan, root / "runtime", base_dir=root,
                coverage_ports=((names[-1], 0),))
            clock = SimpleNamespace(monotonic=Mock(return_value=100.0))
            # Keep real Icarus and real IO; replace only the clock and RSS
            # observation to test the polling cadence and limit deterministically.
            with patch.object(rfuzz_simulator, "time", clock), patch.object(
                    rfuzz_simulator, "read_process_group_rss_bytes", return_value=1024) as rss:
                with rfuzz_simulator.RtlSimulator(artifact) as simulator:
                    rss.assert_called_once_with(simulator.process.pid)
                    for _ in range(20):
                        self.assertEqual(simulator.run_test((artifact.transport.pack(0),)), b"\0")
                    self.assertEqual(rss.call_count, 1)
                    clock.monotonic.return_value = 100.099
                    simulator.run_test((artifact.transport.pack(0),))
                    self.assertEqual(rss.call_count, 1)
                    clock.monotonic.return_value = 100.1
                    simulator.run_test((artifact.transport.pack(0),))
                    self.assertEqual(rss.call_count, 2)
                    clock.monotonic.return_value = 100.2
                    rss.return_value = 512 * 1024 * 1024
                    with self.assertRaisesRegex(RuntimeError, "RSS soft limit"):
                        simulator.run_test((artifact.transport.pack(0),))
                    self.assertTrue(simulator.closed)
                    self.assertIsNotNone(simulator.process.poll())

    def test_rss_still_polled_while_waiting_for_io(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, names = make_plan(root)
            artifact = rfuzz_simulator.build_simulator(plan, root / "runtime", base_dir=root,
                coverage_ports=((names[-1], 0),))
            with rfuzz_simulator.RtlSimulator(artifact) as simulator:
                os.kill(simulator.process.pid, signal.SIGSTOP)
                with patch.object(rfuzz_simulator, "read_process_group_rss_bytes",
                                  return_value=512 * 1024 * 1024) as rss:
                    with self.assertRaisesRegex(RuntimeError, "RSS soft limit"):
                        simulator.run_test((artifact.transport.pack(0),))
                    rss.assert_called_once_with(simulator.process.pid)
                self.assertTrue(simulator.closed)

    def test_publication_lint_deadline_cleans_up_process_group(self):
        from myfuzz.composition import protocol_composer
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, names = make_plan(root)
            binaries = root / "bin"
            binaries.mkdir()
            linter = binaries / "verilator"
            # A real stalled linter and descendant. It eventually exits even
            # on the unfixed publisher, making the RED run finite and safe.
            linter.write_text(f"#!{sys.executable}\n"
                "import os, subprocess, sys\n"
                "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(2)'])\n"
                "with open(os.environ['MYFUZZ_LINT_PIDS'], 'w') as output:\n"
                "    output.write(f'{os.getpid()} {child.pid}')\n"
                "child.wait()\n")
            linter.chmod(0o700)
            pids = root / "linter.pids"
            with patch.dict(os.environ, {"PATH": str(binaries) + os.pathsep + os.environ["PATH"],
                                         "MYFUZZ_LINT_PIDS": str(pids)}), patch.object(
                    protocol_composer, "_GENERIC_LINT_TIMEOUT_SECONDS", 1, create=True):
                with self.assertRaisesRegex(ValueError, "lint.*timed-out"):
                    rfuzz_simulator.build_simulator(plan, root / "runtime", base_dir=root,
                        coverage_ports=((names[-1], 0),))
            self.assertFalse((root / "runtime/composition").exists())
            self.assertFalse((root / "runtime/sim.vvp").exists())
            self.assertEqual(len(pids.read_text().split()), 2)
            for pid in map(int, pids.read_text().split()):
                stat = Path(f"/proc/{pid}/stat")
                if stat.exists():
                    self.assertEqual(stat.read_text().rsplit(") ", 1)[1].split()[0], "Z",
                                     "owned linter process survived timeout")

    def test_raw_layout_drives_rtl_and_replay_resets_deterministically(self):
        for renamed in (False, True):
            with self.subTest(renamed=renamed), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                plan,names = make_plan(root,renamed=renamed)
                artifact = rfuzz_simulator.build_simulator(plan, root/"runtime", base_dir=root,
                    coverage_ports=tuple((names[-1], bit) for bit in range(3)))
                self.assertEqual(artifact.layout.raw_width,9) # excludes clock/reset
                self.assertEqual({f.role for f in artifact.layout.fields},{"data","valid"})
                def sample(value,enable):
                    return artifact.transport.pack(sum(({"data":value,"valid":enable}[f.role] << f.raw_lo) for f in artifact.layout.fields))
                records = (sample(2,1),sample(3,1))
                with rfuzz_simulator.RtlSimulator(artifact) as simulator:
                    self.assertEqual(simulator.run_test(records), b"\1\1\1")
                    self.assertEqual(simulator.run_test((sample(0,0),)*2), b"\0\0\0")
                    self.assertEqual(simulator.run_test(records), b"\1\1\1")
                    with self.assertRaises(ValueError):
                        simulator.run_test((b"bad",))

    def test_invalid_observable_or_existing_output_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            plan,names=make_plan(root)
            for coverage in (((names[2],0),), ((names[-1],3),), (("missing",0),), ()):
                with self.subTest(coverage=coverage), self.assertRaises(ValueError):
                    rfuzz_simulator.build_simulator(plan,root/"bad",base_dir=root,coverage_ports=coverage)
            out=root/"existing"
            out.mkdir()
            (out/"keep").write_text("user-owned")
            with self.assertRaises(ValueError):
                rfuzz_simulator.build_simulator(plan,out,base_dir=root,coverage_ports=((names[-1],0),))
            self.assertEqual((out/"keep").read_text(),"user-owned")

    def test_saturation_padding_and_process_reuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, names = make_plan(root)
            artifact = rfuzz_simulator.build_simulator(plan, root / "runtime", base_dir=root,
                coverage_ports=((names[-1], 0),))
            def sample(data, valid):
                raw = sum({"data": data, "valid": valid}[f.role] << f.raw_lo for f in artifact.layout.fields)
                # Padding mutations must not become DUT bits.
                return (int.from_bytes(artifact.transport.pack(raw), "big") | 1).to_bytes(8, "big")
            with rfuzz_simulator.RtlSimulator(artifact) as simulator:
                pid = simulator.process.pid
                self.assertEqual(simulator.run_test((sample(1, 1),) + (sample(0, 0),) * 299), b"\xff")
                self.assertEqual(simulator.run_test((sample(0, 0),)), b"\0")
                self.assertEqual(simulator.process.pid, pid)
                for records in ((), (sample(1, 1),) * 65537, (b"bad",)):
                    with self.assertRaises(ValueError):
                        simulator.run_test(records)
                self.assertEqual(simulator.run_test((sample(1, 1),)), b"\1")
            self.assertIsNotNone(simulator.process.poll())
            simulator.close()
            with self.assertRaises(ValueError):
                simulator.run_test((sample(1, 1),))

    def test_projector_is_applied_before_each_sample(self):
        from myfuzz.composition.runtime_projection import RuntimeProjector
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, names = make_plan(root)
            artifact = rfuzz_simulator.build_simulator(plan, root / "runtime", base_dir=root,
                coverage_ports=tuple((names[-1], b) for b in range(3)))
            fields = tuple(replace(f, constraint={"alignment": 2}) if f.role == "data" else f
                           for f in artifact.layout.fields)
            projector = RuntimeProjector(replace(artifact.layout, fields=fields))
            artifact = replace(artifact, projector=projector)
            raw = sum({"data": 3, "valid": 1}[f.role] << f.raw_lo for f in artifact.layout.fields)
            with rfuzz_simulator.RtlSimulator(artifact) as simulator:
                # Project 3 to 2 on both cycles: observe state 2, then 4.
                self.assertEqual(simulator.run_test((artifact.transport.pack(raw),) * 2), b"\0\1\1")

    def test_deadline_cleans_up_owned_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, names = make_plan(root)
            artifact = rfuzz_simulator.build_simulator(plan, root / "runtime", base_dir=root,
                coverage_ports=((names[-1], 0),))
            # Small request blocks on read; large request also fills stdin.
            for count in (1, 65536):
                with self.subTest(count=count):
                    simulator = rfuzz_simulator.RtlSimulator(artifact, timeout_seconds=0.1)
                    os.kill(simulator.process.pid, signal.SIGSTOP)
                    with self.assertRaises(TimeoutError):
                        simulator.run_test((artifact.transport.pack(0),) * count)
                    self.assertIsNotNone(simulator.process.poll())
                    self.assertTrue(simulator.closed)

    def test_unbound_protocol_and_multiple_clock_fail_closed(self):
        from tests.integration.test_native_protocol_composition import native_plan
        from myfuzz.composition.interface_description import FieldHint, EndpointDescription
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            native = native_plan(root, ("apb", "3"))
            unbound = plan_generic_composition(replace(native.request, component_types=()), base_dir=root,
                protocol_catalog=native.protocol_catalog)
            with self.assertRaisesRegex(ValueError, "unbound.*protocol"):
                rfuzz_simulator.build_simulator(unbound, root / "runtime", base_dir=root,
                    coverage_ports=(("monitor", 0),))
            self.assertFalse((root / "runtime").exists())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, names = make_plan(root)
            source = root / "source/source.sv"
            source.write_text(source.read_text().replace("module arbitrary(", "module arbitrary(input logic other_clk, "))
            desc = replace(plan.interface_description,
                source=replace(plan.interface_description.source, revision=source_tree_hash(root / "source", (source,))),
                endpoints=(*plan.interface_description.endpoints, EndpointDescription("other", "control", module="arbitrary",
                    fields=(FieldHint("clock", ("other_clk",)),))))
            plan = plan_generic_composition(GenericCompositionRequest(desc, ()), base_dir=root)
            with self.assertRaisesRegex(ValueError, "clock/reset"):
                rfuzz_simulator.build_simulator(plan, root / "runtime", base_dir=root, coverage_ports=((names[-1], 0),))

    def test_routed_bus_and_controls_are_not_runtime_inputs(self):
        from tests.integration.test_shared_native_bus import shared_plan
        from myfuzz.composition.interface_description import FieldHint
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan = shared_plan(root, ("apb", "3"))
            source = root / "source/source.sv"
            source.write_text(source.read_text().replace("module renamed_initiator(",
                "module renamed_initiator(input logic [7:0] random_bits, "))
            desc = replace(plan.interface_description,
                source=replace(plan.interface_description.source, revision=source_tree_hash(root / "source", (source,))),
                endpoints=(replace(plan.interface_description.endpoints[0],
                    fields=(*plan.interface_description.endpoints[0].fields, FieldHint("data", ("random_bits",)))),))
            plan = plan_generic_composition(replace(plan.request, interface_description=desc), base_dir=root,
                component_catalog=plan.component_catalog, protocol_catalog=plan.protocol_catalog)
            artifact = rfuzz_simulator.build_simulator(plan, root / "runtime", base_dir=root,
                coverage_ports=(("monitor", 0),))
            self.assertEqual(artifact.layout.raw_width, 8)
            self.assertEqual([f.port for f in artifact.layout.fields], ["random_bits"])
            with rfuzz_simulator.RtlSimulator(artifact) as simulator:
                self.assertEqual(simulator.run_test((artifact.transport.pack(99),)), b"\1")

    def test_unrepresentable_constraint_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, _ = make_plan(root)
            fields = tuple(replace(f, constraint={"unknown_temporal_rule": True}) if f.role == "data" else f
                           for f in plan.layout.fields)
            invalid = replace(plan, layout=replace(plan.layout, fields=fields))
            with self.assertRaisesRegex(ValueError, "unsupported runtime constraint"):
                rfuzz_simulator._runtime_boundary(invalid, root)

    def test_unknown_observation_fails_closed_and_cleans_up(self):
        for unknown in ("x", "z"):
            with self.subTest(unknown=unknown), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                plan, names = make_plan(root)
                source = root / "source/source.sv"
                source.write_text(source.read_text().replace("state[2:0]", f"3'b{unknown * 3}"))
                desc = replace(plan.interface_description, source=replace(plan.interface_description.source,
                    revision=source_tree_hash(root / "source", (source,))))
                plan = plan_generic_composition(GenericCompositionRequest(desc, ()), base_dir=root)
                artifact = rfuzz_simulator.build_simulator(plan, root / "runtime", base_dir=root,
                    coverage_ports=((names[-1], 0),))
                with rfuzz_simulator.RtlSimulator(artifact) as simulator:
                    with self.assertRaises((ValueError, RuntimeError)):
                        simulator.run_test((artifact.transport.pack(0),))
                    self.assertTrue(simulator.closed)

    def test_reset_polarity_and_synchrony_come_from_source(self):
        for high, synchronous in ((False, False), (True, False), (False, True), (True, True)):
            with self.subTest(high=high, synchronous=synchronous), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                plan, names = make_plan(root, renamed=True)
                source = root / "source/source.sv"
                text = source.read_text()
                if synchronous:
                    text = text.replace(" or negedge reset_x", "")
                if high:
                    text = text.replace("negedge reset_x", "posedge reset_x").replace("!reset_x", "reset_x")
                source.write_text(text)
                desc = replace(plan.interface_description, source=replace(plan.interface_description.source,
                    revision=source_tree_hash(root / "source", (source,))))
                plan = plan_generic_composition(GenericCompositionRequest(desc, ()), base_dir=root)
                artifact = rfuzz_simulator.build_simulator(plan, root / "runtime", base_dir=root,
                    coverage_ports=((names[-1], 0),))
                raw = sum(1 << f.raw_lo for f in artifact.layout.fields)
                with rfuzz_simulator.RtlSimulator(artifact) as simulator:
                    self.assertEqual(simulator.run_test((artifact.transport.pack(raw),)), b"\1")
                    self.assertEqual(simulator.run_test((artifact.transport.pack(0),)), b"\0")

    def test_cpu_control_inputs_are_constant_unless_explicitly_randomized(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, ports = make_control_plan(root)
            defaults = {"boot_address": 0x80, "hart_id": 0, "debug_request": 0, "interrupt": 0}
            artifact = rfuzz_simulator.build_simulator(
                plan, root / "runtime", base_dir=root, coverage_ports=(("flags", 0),),
                control_defaults=defaults,
            )
            self.assertEqual({"data", "valid"}, {field.role for field in artifact.layout.fields})
            self.assertEqual(tuple(sorted(defaults)), artifact.control_defaults["roles"])
            self.assertEqual((), artifact.randomized_controls)

            opt_in = rfuzz_simulator.build_simulator(
                plan, root / "runtime-opt-in", base_dir=root, coverage_ports=(("flags", 0),),
                control_defaults=defaults, randomized_controls=("interrupt",),
                coverage_inputs=(("interrupt", 0),),
            )
            self.assertIn("interrupt", {field.role for field in opt_in.layout.fields})
            self.assertNotIn("boot_address", {field.role for field in opt_in.layout.fields})
            self.assertEqual(("interrupt",), opt_in.randomized_controls)
            self.assertEqual(
                "sampled-dut-signal-bit-events-u8-saturating", opt_in.coverage_kind
            )
            raw = 1 << next(
                field.raw_lo for field in opt_in.layout.fields if field.role == "interrupt"
            )
            with rfuzz_simulator.RtlSimulator(opt_in) as simulator:
                self.assertEqual(simulator.run_test((opt_in.transport.pack(raw),))[-1], 1)

            with self.assertRaisesRegex(ValueError, "randomized runtime input"):
                rfuzz_simulator.build_simulator(
                    plan, root / "runtime-fixed-observation", base_dir=root,
                    coverage_ports=(("flags", 0),), coverage_inputs=(("boot_address", 0),),
                    control_defaults=defaults,
                )
