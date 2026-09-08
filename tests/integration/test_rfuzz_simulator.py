"""Generated composition receives real raw samples and returns RTL event coverage."""
from pathlib import Path
from dataclasses import replace
import os
import signal
import sys
from types import SimpleNamespace
from unittest.mock import Mock, patch
import shutil
import tempfile
import unittest

from myfuzz.composition import GenericCompositionRequest, load_interface_description, plan_generic_composition, source_tree_hash
from myfuzz.composition.input_layout import InputLayout, LayoutField
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
                       "fields": [{"role": role, "aliases": [port]}
                                  for role, port in zip(roles, ports)]}],
    })
    return plan_generic_composition(GenericCompositionRequest(description, ()), base_dir=root), ports


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
                        port="random_container", member_path=("low",),
                        port_raw_lo=0, port_raw_hi=3, port_width=8),
            LayoutField("random:high", "random", "high", 4, 37, 40, "bits", {},
                        port="random_container", member_path=("high",),
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
            )
            self.assertIn("interrupt", {field.role for field in opt_in.layout.fields})
            self.assertNotIn("boot_address", {field.role for field in opt_in.layout.fields})
            self.assertEqual(("interrupt",), opt_in.randomized_controls)
