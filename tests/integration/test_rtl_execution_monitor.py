from dataclasses import replace
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from myfuzz.integration.rtl_execution_monitor import (
    monitor_output, monitor_rtl, parse_metrics, validate_execution, validate_monitor,
)


CONTRACT_CONFIG = {"mode": "contract_transducer", "memory_capacity_entries": 256}
CONTRACT_METRICS = ("cycles", "requests", "completions", "instruction_requests",
                    "instruction_responses", "instruction_initializations",
                    "protocol_errors", "transducer_errors", "errors")


def contract_metrics(**values):
    return dict.fromkeys(CONTRACT_METRICS, 0) | values


class RtlExecutionMonitorTests(unittest.TestCase):
    def test_contract_monitor_needs_no_fixed_instruction_or_pass_facts(self):
        config = {"mode": "contract_transducer", "memory_capacity_entries": 256}
        self.assertEqual(config, validate_monitor(config))

    def test_contract_metrics_allow_bounded_partial_execution(self):
        metrics = dict(cycles=1, requests=1, completions=0, instruction_requests=1,
                       instruction_responses=0, instruction_initializations=0,
                       protocol_errors=0, transducer_errors=0, errors=0)
        self.assertEqual(metrics, validate_execution(metrics))

    def test_contract_metrics_reject_protocol_and_transducer_errors(self):
        metrics = dict(cycles=80, requests=3, completions=2, instruction_requests=3,
                       instruction_responses=2, instruction_initializations=2,
                       protocol_errors=0, transducer_errors=0, errors=0)
        self.assertEqual(metrics, validate_execution(metrics))
        for key in ("protocol_errors", "transducer_errors", "errors"):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "execution acceptance failed"):
                validate_execution({**metrics, key: 1})

    def test_contract_monitor_rejects_unbounded_or_ambiguous_configuration(self):
        for capacity in (True, 0, -1, 4097, 1.5, "256"):
            with self.subTest(capacity=capacity), self.assertRaises(ValueError):
                validate_monitor(CONTRACT_CONFIG | {"memory_capacity_entries": capacity})
        for config in ({"mode": "contract_transducer"}, CONTRACT_CONFIG | {"reset_vector": 0},
                       CONTRACT_CONFIG | {"mode": "unknown"}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                validate_monitor(config)

    def test_contract_metrics_allow_no_requests_and_reject_inconsistent_counts(self):
        empty = contract_metrics(cycles=1)
        self.assertEqual(empty, validate_execution(empty))
        invalid = (
            empty | {"requests": 2},
            empty | {"completions": 1},
            empty | {"instruction_requests": 1},
            empty | {"instruction_responses": 1},
            empty | {"instruction_initializations": 1},
            empty | {"cycles": True},
            empty | {"requests": -1},
            empty | {"cycles": 5, "requests": 2},
            empty | {"cycles": 5, "requests": 1, "completions": 1, "instruction_requests": 1},
            empty | {"unknown": 0},
        )
        for metrics in invalid:
            with self.subTest(metrics=metrics), self.assertRaisesRegex(ValueError, "execution acceptance failed"):
                validate_execution(metrics)

    def test_contract_metric_wire_format_is_selected_explicitly(self):
        metrics = contract_metrics(cycles=80, requests=3, completions=2,
                                   instruction_requests=3, instruction_responses=2,
                                   instruction_initializations=2)
        payload = b"80,3,2,3,2,2,0,0,0"
        self.assertEqual(metrics, parse_metrics(payload, CONTRACT_CONFIG))
        for invalid in (b"1,0,0,0,0,0,0,0", b"1,0,0,0,0,0,0,0,-1",
                        b"65537,0,0,0,0,0,0,0,0", b"1,0,0,0,0,0,0,0,x"):
            with self.subTest(payload=invalid), self.assertRaises(ValueError):
                parse_metrics(invalid, CONTRACT_CONFIG)
        with self.assertRaises(ValueError):
            parse_metrics(payload)
        legacy = b"80,11,10,2,11,1,0,1"
        self.assertEqual(1, parse_metrics(legacy)["first_fetch_matched"])

    def test_accepts_complete_cpu_and_peripheral_progress(self):
        metrics = {
            "cycles": 80,
            "requests": 11,
            "successful_reads": 10,
            "progress_events": 10,
            "completions": 11,
            "pass_completions": 1,
            "errors": 0,
            "first_fetch_matched": 1,
        }
        self.assertEqual(metrics, validate_execution(metrics))

    def test_rejects_each_incomplete_execution_fact(self):
        valid = {
            "cycles": 80,
            "requests": 11,
            "successful_reads": 10,
            "progress_events": 2,
            "completions": 11,
            "pass_completions": 1,
            "errors": 0,
            "first_fetch_matched": 1,
        }
        invalid = {
            "first_fetch_matched": 0,
            "progress_events": 1,
            "completions": 0,
            "pass_completions": 0,
            "errors": 1,
        }
        for key, value in invalid.items():
            with self.subTest(key=key), self.assertRaisesRegex(
                ValueError, "execution acceptance failed"
            ):
                validate_execution({**valid, key: value})


@unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus required")
class ContractMonitorRtlTests(unittest.TestCase):
    def run_cycles(self, cycles, *, data_width=32, capacity=4):
        config = CONTRACT_CONFIG | {"memory_capacity_entries": capacity}
        signals = {
            "req_valid": 0, "req_ready": 0, "rsp_valid": 0, "rsp_ready": 0,
            "error": 0, "addr": 0, "write": 0, "be": (1 << (data_width // 8)) - 1,
            "req_instruction": 0,
        }
        stimulus = []
        for cycle in cycles:
            stimulus.append(f"rst_n={cycle.get('reset', 1)};")
            for name, default in signals.items():
                stimulus.append(f"dut.backend_target_{name}={cycle.get(name, default)};")
            for name in ("backend_rsp_valid", "backend_error"):
                stimulus.append(f"dut.{name}={cycle.get(name, 0)};")
            stimulus.extend(("#5; clk=1; #5; clk=0;", *monitor_output(config), '$write("\\n");'))
        source = "\n".join((
            "module boundary;",
            "logic backend_target_req_valid, backend_target_req_ready;",
            "logic backend_target_rsp_valid, backend_target_rsp_ready, backend_target_error;",
            "logic backend_target_write, backend_target_req_instruction;",
            "logic [63:0] backend_target_addr;",
            f"logic [{data_width // 8 - 1}:0] backend_target_be;",
            "logic backend_rsp_valid, backend_error;",
            "endmodule", "module tb;", "logic clk=0, rst_n=0; boundary dut();",
            *monitor_rtl("clk", "rst_n", 0, config),
            "initial begin", *stimulus, "$finish; end endmodule",
        ))
        with tempfile.TemporaryDirectory() as tmp:
            bench, image = Path(tmp) / "bench.sv", Path(tmp) / "bench.vvp"
            bench.write_text(source)
            built = subprocess.run(["iverilog", "-g2012", "-s", "tb", "-o", str(image), str(bench)],
                                   capture_output=True, text=True, timeout=30)
            self.assertEqual(0, built.returncode, built.stderr)
            result = subprocess.run(["vvp", str(image)], capture_output=True, timeout=30)
            self.assertEqual(0, result.returncode, result.stderr)
        return [parse_metrics(line.removeprefix(b" EXEC "), config)
                for line in result.stdout.splitlines() if line.startswith(b" EXEC ")]

    def test_successful_instruction_initialization_counts_unique_aligned_beats(self):
        for data_width in (32, 64):
            with self.subTest(data_width=data_width):
                cycles = [{"reset": 0}]
                for address in (0x100, 0x102, 0x100 + data_width // 8):
                    cycles.extend((dict(req_valid=1, req_ready=1, req_instruction=1, addr=address),
                                   dict(rsp_valid=1, rsp_ready=1)))
                result = self.run_cycles(cycles, data_width=data_width)[-1]
                expected = contract_metrics(cycles=6, requests=3, completions=3,
                                            instruction_requests=3, instruction_responses=3,
                                            instruction_initializations=2)
                self.assertEqual(expected, result)
                self.assertEqual(result, validate_execution(result))

    def test_successful_data_access_and_nonempty_write_prevent_instruction_initialization(self):
        cycles = [{"reset": 0}]
        for request in (dict(addr=0x100), dict(addr=0x102, req_instruction=1),
                        dict(addr=0x200, write=1, be=1), dict(addr=0x200, req_instruction=1),
                        dict(addr=0x300, write=1, be=0), dict(addr=0x302, req_instruction=1)):
            cycles.extend((dict(req_valid=1, req_ready=1) | request, dict(rsp_valid=1, rsp_ready=1)))
        self.assertEqual(contract_metrics(cycles=12, requests=6, completions=6,
                                          instruction_requests=3, instruction_responses=3,
                                          instruction_initializations=1), self.run_cycles(cycles)[-1])

    def test_errors_do_not_initialize_memory_or_double_count_backend_propagation(self):
        cycles = [{"reset": 0},
                  dict(req_valid=1, req_ready=1, req_instruction=1, addr=0x100),
                  dict(rsp_valid=1, rsp_ready=1, error=1),
                  dict(backend_rsp_valid=1, backend_error=1),
                  dict(backend_rsp_valid=1, backend_error=1),
                  dict(backend_error=1),
                  dict(req_valid=1, req_ready=1, req_instruction=1, addr=0x100),
                  dict(rsp_valid=1, rsp_ready=1)]
        self.assertEqual(contract_metrics(cycles=7, requests=2, completions=2,
                                          instruction_requests=2, instruction_responses=2,
                                          instruction_initializations=1, transducer_errors=1, errors=1),
                         self.run_cycles(cycles)[-1])

    def test_protocol_errors_include_orphans_duplicates_and_multiple_outstanding(self):
        cases = (
            ([dict(rsp_valid=1, rsp_ready=1)], 0, 1),
            ([dict(req_valid=1, req_ready=1), dict(rsp_valid=1, rsp_ready=1),
              dict(rsp_valid=1, rsp_ready=1)], 1, 2),
            ([dict(req_valid=1, req_ready=1), dict(req_valid=1, req_ready=1)], 2, 0),
        )
        for cycles, requests, completions in cases:
            with self.subTest(cycles=cycles):
                result = self.run_cycles([{"reset": 0}, *cycles])[-1]
                self.assertEqual((requests, completions, 1, 0, 1),
                                 tuple(result[key] for key in ("requests", "completions", "protocol_errors", "transducer_errors", "errors")))

    def test_watchdog_errors_are_observed_once_per_backend_response(self):
        cycles = [{"reset": 0}, dict(req_valid=1, req_ready=1),
                  dict(backend_rsp_valid=1, backend_error=1),
                  dict(backend_rsp_valid=1, backend_error=1), dict(backend_error=1),
                  dict(backend_rsp_valid=1, backend_error=1)]
        result = self.run_cycles(cycles)[-1]
        self.assertEqual((2, 0, 2), tuple(result[key] for key in ("protocol_errors", "transducer_errors", "errors")))

    def test_reset_clears_all_counts_pending_request_and_initialized_addresses(self):
        cycles = [{"reset": 0}, dict(req_valid=1, req_ready=1, req_instruction=1, addr=0x100),
                  dict(rsp_valid=1, rsp_ready=1), dict(rsp_valid=1, rsp_ready=1, error=1),
                  dict(req_valid=1, req_ready=1), {"reset": 0},
                  dict(req_valid=1, req_ready=1, req_instruction=1, addr=0x100),
                  dict(rsp_valid=1, rsp_ready=1)]
        results = self.run_cycles(cycles)
        self.assertEqual(contract_metrics(), results[5])
        self.assertEqual(contract_metrics(cycles=2, requests=1, completions=1,
                                          instruction_requests=1, instruction_responses=1,
                                          instruction_initializations=1), results[-1])

    def test_only_handshakes_count_and_one_unfinished_tail_request_is_accepted(self):
        cycles = [{"reset": 0}, dict(req_valid=1), dict(req_ready=1),
                  dict(req_valid=1, req_ready=1, req_instruction=1, addr=0x100)]
        result = self.run_cycles(cycles)[-1]
        self.assertEqual(contract_metrics(cycles=3, requests=1, instruction_requests=1), result)
        self.assertEqual(result, validate_execution(result))

    def test_successful_allocation_beyond_configured_capacity_is_a_protocol_error(self):
        cycles = [{"reset": 0}]
        for address in (0x100, 0x104):
            cycles.extend((dict(req_valid=1, req_ready=1, req_instruction=1, addr=address),
                           dict(rsp_valid=1, rsp_ready=1)))
        result = self.run_cycles(cycles, capacity=1)[-1]
        self.assertEqual(1, result["protocol_errors"])
        self.assertEqual(1, result["instruction_initializations"])


@unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp") and shutil.which("verilator"), "RTL tools required")
class ContractMonitorSimulatorTests(unittest.TestCase):
    def test_contract_monitor_requires_matching_transducer_capacity_and_shared_domain(self):
        from myfuzz.integration.rfuzz_simulator import build_simulator
        from tests.integration.test_rfuzz_simulator import make_contract_plan

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, transducer = make_contract_plan(root)
            config = CONTRACT_CONFIG | {"memory_capacity_entries": transducer.memory_capacity_entries}
            cases = (
                (None, config, "contract transducer"),
                (transducer, CONTRACT_CONFIG, "capacity"),
                (replace(transducer, memory_domains=(("instruction_memory_master", "instruction"),
                                                     ("data_memory_master", "data"))), config, "shared memory domain"),
            )
            for index, (contract, monitor, message) in enumerate(cases):
                with self.subTest(index=index), self.assertRaisesRegex(ValueError, message):
                    build_simulator(plan, root / f"invalid-{index}", base_dir=root,
                                    coverage_ports=(("completion_flag", 0),),
                                    contract_transducer=contract, execution_monitor=monitor)
                self.assertFalse((root / f"invalid-{index}").exists())

    def test_live_simulator_parses_contract_metrics_and_allows_partial_tests(self):
        from myfuzz.integration.rfuzz_simulator import build_simulator, RtlSimulator
        from tests.integration.test_rfuzz_simulator import make_contract_plan

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, transducer = make_contract_plan(root)
            for engine in ("icarus", "verilator"):
                with self.subTest(simulator=engine):
                    artifact = build_simulator(plan, root / engine, base_dir=root,
                        simulator=engine, coverage_ports=(("completion_flag", 0),), contract_transducer=transducer,
                        execution_monitor=CONTRACT_CONFIG | {"memory_capacity_entries": transducer.memory_capacity_entries})
                    with RtlSimulator(artifact) as simulator:
                        simulator.run_test((artifact.transport.pack(0),))
                        self.assertEqual(contract_metrics(cycles=1), simulator.last_execution)
                        simulator.run_test((artifact.transport.pack(0),) * 150)
                        self.assertEqual(150, simulator.last_execution["cycles"])
                        self.assertGreater(simulator.last_execution["instruction_initializations"], 0)
                        self.assertEqual(0, simulator.last_execution["errors"])


if __name__ == "__main__":
    unittest.main()
