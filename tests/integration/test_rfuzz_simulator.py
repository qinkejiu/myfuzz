"""Generated composition receives real raw samples and returns RTL event coverage."""
from pathlib import Path
from dataclasses import replace
import os
import signal
import shutil
import tempfile
import unittest

from myfuzz.composition import GenericCompositionRequest, load_interface_description, plan_generic_composition, source_tree_hash
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


@unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus required")
class RfuzzSimulatorTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(rfuzz_simulator, "live layout-to-RTL simulator missing")

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
