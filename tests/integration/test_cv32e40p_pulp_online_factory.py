"""The CV32E40P PULP dual-source wiring reuses the Ibex wiring without RTL.

Every assertion here is construction-only: the factory renders the pinned
harnesses and builds three real sessions, but no session process is started.
Nothing in this file runs Verilator, a simulator, or an online fuzz slot.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from myfuzz.integration import cv32e40p_pulp_online as cv_online
from myfuzz.integration import ibex_pulp_online as ibex_online
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.scenario import cv32e40p_pulp_dual_source as cv_pulp
from myfuzz.scenario import ibex_pulp_dual_source as ibex_pulp

#: Byte-exact regression guard for the existing Ibex stream firmware.  The
#: shared builder was parameterized for the second CPU; these hashes prove the
#: Ibex images did not change.
IBEX_IMAGE_SHA256 = {
    "cpu.stream.bootstrap": "51e344aca5262f86996969b317b31373232521311fb9eb3e8ff5844d31b23b2c",
    "cpu.stream.direct_vector": "f80ee57d28f7fc8f2f649e9c9dd27f7702f26d9406da6a5a8684c92ac0f8fa83",
    "cpu.stream.external_vector": "60c4deba81bd29487b64f5d91b848d8096cb301f30881348ae312c20a7db5078",
    "cpu.stream.isr": "4f07e4a5d2905dcd796fd6fec08fefb99e110d900ca4cc21b5946d8b2bc0e21d",
    "cpu.stream.end": "77df2fdd2f4ec9dfb8ba23140df8696a3247b6e5c439566dabb84120d3bcfca9",
}

CPU_TO_IP = "cpu_to_ip_to_cpu.closed_loop"
IP_TO_CPU = "ip_to_cpu_to_ip.closed_loop"


def _image_bytes(image) -> bytes:
    return image.data if isinstance(image.data, bytes) else bytes.fromhex(image.data)


def _images(bootstrap):
    return {image.image_id: (image.address, _image_bytes(image))
            for image in bootstrap.template.initial_images}


def _word(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset:offset + 4], "little")


def _jal_offset(word: int) -> int:
    decoded = (((word >> 31) & 1) << 20) | (((word >> 21) & 0x3ff) << 1) | \
        (((word >> 20) & 1) << 11) | (((word >> 12) & 0xff) << 12)
    return decoded - (1 << 21) if decoded & (1 << 20) else decoded


class Cv32e40pPulpFactoryTests(unittest.TestCase):
    """Real construction, real artifacts, no RTL process."""

    @classmethod
    def setUpClass(cls):
        cls._cache = TemporaryDirectory()
        cls.addClassCleanup(cls._cache.cleanup)
        cache = Path(cls._cache.name)
        # A dict keeps the callables off the descriptor protocol, so a test
        # method can call them without binding ``self`` as an argument.
        cls._factories = {
            "ibex": ibex_pulp.make_ibex_pulp_dual_source_factory(cache),
            "cv32e40p": cv_pulp.make_cv32e40p_pulp_dual_source_factory(cache)}

    def test_factory_builds_three_real_sessions_and_starts_no_process(self):
        runner = self._factories["cv32e40p"]()
        self.assertEqual({"cpu", "gpio_a", "gpio_b"}, set(runner.sessions))
        self.assertIsInstance(runner.sessions["cpu"], GeneratedCve2Session)
        self.assertIsInstance(runner.sessions["gpio_a"], GeneratedPulpGpioSession)
        self.assertIsInstance(runner.sessions["gpio_b"], GeneratedPulpGpioSession)
        for component, session in runner.sessions.items():
            with self.subTest(component=component):
                self.assertIsNone(session._process, "construction must not start RTL")
        cpu = runner.sessions["cpu"]
        self.assertEqual("cv32e40p", cpu.artifact.plan.profile.component_id)
        self.assertEqual("cpu", cpu.artifact.plan.request.instance_id)
        self.assertEqual("obi_cpu", cpu.artifact.runtime_document["kind"])
        self.assertEqual(0x10000, cpu.artifact.runtime_document["boot_contract"]
                         ["configured_boot_base"])
        for component in ("gpio_a", "gpio_b"):
            gpio = runner.sessions[component]
            self.assertEqual("pulp_gpio", gpio.artifact.plan.profile.component_id)
            self.assertEqual(component, gpio.artifact.plan.request.instance_id)
            self.assertEqual("apb_gpio", gpio.artifact.runtime_document["kind"])

    def test_cpu_difference_is_only_the_profile_and_the_declared_firmware_facts(self):
        runner = self._factories["cv32e40p"]()
        cpu = runner.sessions["cpu"]
        names = {row["runtime_name"]
                 for row in cpu.artifact.runtime_document["physical_exports"]}
        self.assertFalse([name for name in names if name.startswith("rvfi_")])
        self.assertNotIn("probe_irq_taken_pre", names)
        self.assertNotIn("probe_irq_masked_pre", names)
        identity = cpu.identity_document()
        self.assertNotIn("cpu_observation_schema_version", identity)
        self.assertNotIn("cpu_native_irq_receipt_contract", identity)
        irq_inputs = [row for row in cpu.artifact.runtime_document["runtime_ports"]
                      if row["direction"] == "input" and row["width"] == 1
                      and row["name"].startswith("rt_lh_p_")]
        self.assertEqual(1, len(irq_inputs), "exactly one declared IRQ input line")

    def test_ownership_and_bindings_are_field_identical_to_the_ibex_wiring(self):
        ibex = self._factories["ibex"]()
        cv = self._factories["cv32e40p"]()
        self.assertEqual(ibex.ownership.document(), cv.ownership.document())
        self.assertEqual(ibex.bindings, cv.bindings)
        self.assertEqual(
            [(field["component_id"], field["port"], field["width"])
             for field in cv.ownership.document()["fields"]],
            [("cpu", "irq", 1), ("gpio_a", "gpio_in", 32), ("gpio_b", "gpio_in", 32)])
        self.assertEqual(
            [(owner["component_id"], owner["port"], owner["bit_offset"],
              owner["width"], owner["kind"], owner["producer_ref"])
             for owner in cv.ownership.document()["owners"]],
            [("cpu", "irq", 0, 1, "bound", "gpio_b.irq"),
             ("gpio_a", "gpio_in", 0, 32, "fixed", "constant_zero"),
             ("gpio_b", "gpio_in", 0, 8, "bound", "gpio_a.gpio_out"),
             ("gpio_b", "gpio_in", 8, 1, "source", "external_b.pin8"),
             ("gpio_b", "gpio_in", 9, 23, "fixed", "constant_zero")])

    def test_router_windows_and_irq_pulse_wiring_match_the_ibex_wiring(self):
        ibex, cv = self._factories["ibex"](), self._factories["cv32e40p"]()
        for runner in (ibex, cv):
            self.assertEqual(("gpio_a", 0x40001000, 0x1000), (
                runner.sessions["cpu"].router.windows[0].device_id,
                runner.sessions["cpu"].router.windows[0].base,
                runner.sessions["cpu"].router.windows[0].size))
            self.assertEqual(("gpio_b", 0x40000000, 0x1000), (
                runner.sessions["cpu"].router.windows[1].device_id,
                runner.sessions["cpu"].router.windows[1].base,
                runner.sessions["cpu"].router.windows[1].size))
        self.assertIs(cv.sessions["gpio_a"], cv.sessions["cpu"].router.windows[0].target)
        self.assertIs(cv.sessions["gpio_b"], cv.sessions["cpu"].router.windows[1].target)
        self.assertEqual([(w.device_id, w.base, w.size) for w in ibex.sessions["cpu"].router.windows],
                         [(w.device_id, w.base, w.size) for w in cv.sessions["cpu"].router.windows])
        self.assertEqual((cv.bindings[1],), tuple(cv._irq_pulses))
        self.assertEqual({binding: delivery.width_ticks
                          for binding, delivery in cv._irq_pulses.items()},
                         {cv.bindings[1]: 4})

    def test_cpu_profile_selection_is_explicit_and_retirement_is_refused(self):
        with patch.object(ibex_pulp, "_artifact") as render:
            cv_pulp.make_cv32e40p_pulp_dual_source_factory(Path("/tmp/cv-profile-only"))
        self.assertEqual((cv_pulp.CV32E40P_CPU_PROFILE, "cpu"), render.call_args_list[0].args)
        self.assertEqual([(ibex_pulp.GPIO_PROFILE, "gpio_a"),
                          (ibex_pulp.GPIO_PROFILE, "gpio_b")],
                         [call.args for call in render.call_args_list[1:]])
        with patch.object(ibex_pulp, "_artifact") as render:
            cv_pulp.make_cv32e40p_pulp_dual_source_factory(
                Path("/tmp/cv-profile-only"), gpio_consumption=True)
        self.assertEqual([(ibex_pulp.CAUSAL_GPIO_PROFILE, "gpio_a"),
                          (ibex_pulp.CAUSAL_GPIO_PROFILE, "gpio_b")],
                         [call.args for call in render.call_args_list[1:]])

    def test_retirement_and_native_receipts_are_refused_before_artifact_work(self):
        for kwargs in ({"cpu_retirement": True},
                       {"cpu_retirement": True, "native_irq_receipts": True},
                       {"native_irq_receipts": True},
                       {"cpu_retirement": 1},
                       {"native_irq_receipts": 0},
                       {"gpio_consumption": "yes"}):
            with self.subTest(kwargs=kwargs), patch.object(ibex_pulp, "_artifact") as render:
                with self.assertRaises(ValueError):
                    cv_pulp.make_cv32e40p_pulp_dual_source_factory(
                        Path("/tmp/cv-no-artifact"), **kwargs)
                render.assert_not_called()
        with self.assertRaisesRegex(ValueError,
                                    "native IRQ receipts require explicit RVFI retirement"):
            cv_pulp.make_cv32e40p_pulp_dual_source_factory(
                Path("/tmp/cv-no-artifact"), native_irq_receipts=True)
        with self.assertRaisesRegex(ValueError, "no authenticated RVFI retirement profile"):
            cv_pulp.make_cv32e40p_pulp_dual_source_factory(
                Path("/tmp/cv-no-artifact"), cpu_retirement=True)


class Cv32e40pPulpFirmwareTests(unittest.TestCase):
    """The one explicit CPU difference block: first fetch and mtvec mode."""

    @classmethod
    def setUpClass(cls):
        cls.ibex = _images(ibex_pulp.make_ibex_pulp_dual_source_stream_bootstrap())
        cls.cv = _images(cv_pulp.make_cv32e40p_pulp_dual_source_stream_bootstrap())

    def test_ibex_stream_images_are_byte_identical_after_the_refactor(self):
        self.assertEqual(IBEX_IMAGE_SHA256,
                         {name: hashlib.sha256(data).hexdigest()
                          for name, (_, data) in self.ibex.items()})

    def test_cv32e40p_reuses_every_image_except_boot_entry_and_mtvec_mode(self):
        self.assertEqual(set(self.ibex) | {"cpu.stream.entry"}, set(self.cv))
        for name in ("cpu.stream.direct_vector", "cpu.stream.external_vector",
                     "cpu.stream.isr", "cpu.stream.end"):
            with self.subTest(image=name):
                self.assertEqual(self.ibex[name], self.cv[name])
        self.assertEqual((0x10000, 4), (self.cv["cpu.stream.entry"][0],
                                        len(self.cv["cpu.stream.entry"][1])))
        self.assertEqual((0x10080, 96), (self.cv["cpu.stream.bootstrap"][0],
                                         len(self.cv["cpu.stream.bootstrap"][1])))
        self.assertEqual(self.ibex["cpu.stream.bootstrap"][0],
                         self.cv["cpu.stream.bootstrap"][0])

    def test_boot_entry_is_a_single_jal_to_the_shared_main_program(self):
        address, data = self.cv["cpu.stream.entry"]
        word = _word(data, 0)
        self.assertEqual(0x6F, word & 0x7F)
        self.assertEqual(0, (word >> 7) & 0x1F, "the entry trampoline must not link")
        self.assertEqual(0x10080, address + _jal_offset(word))

    def test_mtvec_word_is_the_only_bootstrap_word_that_differs(self):
        ibex_data = self.ibex["cpu.stream.bootstrap"][1]
        cv_data = self.cv["cpu.stream.bootstrap"][1]
        changed = [index for index in range(len(ibex_data)) if ibex_data[index] != cv_data[index]]
        self.assertTrue(changed, "the declared mtvec difference must be present")
        offset = changed[0] // 4 * 4
        self.assertTrue(all(offset <= index < offset + 4 for index in changed),
                        "only the mtvec ADDI immediate may differ")
        self.assertEqual(0x00010137, _word(ibex_data, offset - 4))
        self.assertEqual(0x10010113, _word(ibex_data, offset))   # addi x2, x2, 0x100
        self.assertEqual(0x10110113, _word(cv_data, offset))     # addi x2, x2, 0x101
        self.assertEqual(0x30511073, _word(ibex_data, offset + 4))
        self.assertEqual(0x30511073, _word(cv_data, offset + 4))

    def test_declared_mtvec_mode_reaches_the_shared_external_vector(self):
        """Transcribe (never execute) the pinned vector formulas.

        CV32E40P: ``cv32e40p_if_stage.sv:147`` computes an interrupt entry as
        ``{trap_base_addr, 1'b0, exc_vec_pc_mux, 2'b0}`` where
        ``cv32e40p_core.sv:361`` selects ``0`` in direct mode and ``exc_cause``
        in vectored mode; ``cv32e40p_cs_registers.sv:666-667`` keeps
        ``csr_wdata_int[31:8]`` as the base and ``csr_wdata_int[0]`` as the
        mode.  Machine external cause 11 is irq_i[11] (pkg.sv:522).
        Ibex: ``ibex_if_stage.sv`` always enters ``{mtvec[31:8], 1'b0, irq_vec,
        2'b00}``, so both declared values must satisfy the shared 0x1012c
        coverage target.  A direct-mode CV32E40P would enter 0x10100 instead.
        """
        ibex = ibex_pulp.IBEX_STREAM_CPU_PROGRAM
        cv = ibex_pulp.CV32E40P_STREAM_CPU_PROGRAM
        cause = 11
        cv_base, cv_mode = (cv.mtvec_value >> 8) << 8, cv.mtvec_value & 1
        ibex_base = (ibex.mtvec_value >> 8) << 8
        cv_vectored = cv_base + 4 * cause if cv_mode else cv_base
        cv_direct = cv_base
        ibex_entry = ibex_base + 4 * cause
        self.assertEqual(0x1012C, cv_vectored)
        self.assertEqual(0x1012C, ibex_entry)
        self.assertEqual(0x10100, cv_direct)
        self.assertNotEqual(0x1012C, cv_direct)
        self.assertEqual(0x1012C, ibex_pulp.EXTERNAL_VECTOR)
        self.assertEqual((0x10100, 0x1012C),
                         (ibex_pulp.VECTOR_BASE, ibex_pulp.EXTERNAL_VECTOR))

    def test_online_slot_declarations_and_schedule_are_shared(self):
        ibex = ibex_pulp.make_ibex_pulp_dual_source_stream_bootstrap()
        cv = cv_pulp.make_cv32e40p_pulp_dual_source_stream_bootstrap()
        self.assertEqual((ibex.instruction_start, ibex.instruction_end, ibex.instruction_count),
                         (cv.instruction_start, cv.instruction_end, cv.instruction_count))
        self.assertEqual((0x11000, 0x2FE00, 31616),
                         (cv.instruction_start, cv.instruction_end, cv.instruction_count))
        self.assertEqual(ibex.template.schedule_order, cv.template.schedule_order)
        self.assertEqual(ibex.template.max_steps, cv.template.max_steps)
        self.assertFalse(cv.runtime_accepted)
        self.assertFalse(cv.template.actions)

    def test_declared_cpu_program_layout_is_validated_before_any_image(self):
        from dataclasses import replace
        from myfuzz.scenario.ibex_pulp_dual_source import (
            CV32E40P_STREAM_CPU_PROGRAM, make_pulp_dual_source_stream_bootstrap)
        for program, message in (
                (replace(CV32E40P_STREAM_CPU_PROGRAM, boot_trampoline=False),
                 "trampoline must match"),
                (replace(CV32E40P_STREAM_CPU_PROGRAM, main_address=0x10100),
                 "does not fit the shared firmware layout"),
                (replace(CV32E40P_STREAM_CPU_PROGRAM, mtvec_value=0x10102),
                 "does not fit the shared firmware layout"),
                (object(), "declared dual-source CPU program is required")):
            with self.subTest(program=program):
                with self.assertRaisesRegex(ValueError, message):
                    make_pulp_dual_source_stream_bootstrap(program=program)
        for bounds in ((0x11000, 0x2FF00), (0x10FFC, 0x20000), (0x20000, 0x11000)):
            with self.subTest(bounds=bounds), self.assertRaisesRegex(
                    ValueError, "must fit below ISR scratch"):
                make_pulp_dual_source_stream_bootstrap(
                    program=CV32E40P_STREAM_CPU_PROGRAM,
                    instruction_start=bounds[0], instruction_end=bounds[1])

    def test_stream_program_declarations_are_explicit_and_typed(self):
        ibex = ibex_pulp.IBEX_STREAM_CPU_PROGRAM
        cv = ibex_pulp.CV32E40P_STREAM_CPU_PROGRAM
        self.assertEqual((ibex_pulp.CPU_PROFILE, 0x10080, 0x10100, False),
                         (ibex.profile_path, ibex.first_fetch, ibex.mtvec_value,
                          ibex.boot_trampoline))
        self.assertEqual((cv_pulp.CV32E40P_CPU_PROFILE, 0x10000, 0x10101, True),
                         (cv.profile_path, cv.first_fetch, cv.mtvec_value,
                          cv.boot_trampoline))
        self.assertEqual(0x10080, ibex.main_address)
        self.assertEqual(0x10080, cv.main_address)


class Cv32e40pPulpDecoderTests(unittest.TestCase):
    """Identical sources, targets, paths and ownership; the CPU is not a branch."""

    @classmethod
    def setUpClass(cls):
        cls.ibex = ibex_pulp.make_ibex_pulp_dual_source_online_decoder(
            bootstrap=ibex_pulp.make_ibex_pulp_dual_source_stream_bootstrap())
        cls.cv = cv_pulp.make_cv32e40p_pulp_dual_source_online_decoder()

    def sources(self, decoder):
        return [(source.source_id, source.kind, source.component, source.direction,
                 source.port, source.bit_offset, source.width,
                 tuple(source.coverage_target_ids))
                for source in decoder.sources]

    def test_decoder_sources_targets_and_flows_are_identical(self):
        self.assertEqual(
            [("cpu.online_instruction", "instruction", "cpu", "CPU_TO_IP_TO_CPU",
              "", 0, 1, ("gpio_a_output_bit0", "cpu_data_write")),
             ("gpio_b.external_pin8", "source", "gpio_b", "IP_TO_CPU_TO_IP",
              "gpio_in", 8, 1, ("gpio_b_irq", "cpu_external_irq_vector_fetch"))],
            self.sources(self.cv))
        self.assertEqual(self.sources(self.ibex), self.sources(self.cv))
        self.assertEqual({CPU_TO_IP: "F4", IP_TO_CPU: "F5"}, self.cv.flow_by_target)
        self.assertEqual(self.ibex.flow_by_target, self.cv.flow_by_target)

    def test_runtime_paths_graph_and_contract_are_identical(self):
        self.assertEqual(self.ibex.runtime_paths, self.cv.runtime_paths)
        self.assertEqual(("CPU_TO_IP_TO_CPU", "IP_TO_CPU_TO_IP"),
                         tuple(direction for direction, _ in self.cv.runtime_paths))
        self.assertEqual(self.ibex.ownership.document(), self.cv.ownership.document())
        self.assertEqual(
            [(source.source_id, source.kind, source.component)
             for source in self.ibex.graph.sources.values()],
            [(source.source_id, source.kind, source.component)
             for source in self.cv.graph.sources.values()])
        self.assertEqual(self.ibex.runtime_contract.document(),
                         self.cv.runtime_contract.document())
        self.assertEqual([(node.node_id, node.kind) for node in self.ibex.runtime_contract.nodes],
                         [(node.node_id, node.kind) for node in self.cv.runtime_contract.nodes])
        self.assertEqual([(edge.relation, edge.device_id) for edge in self.ibex.runtime_contract.edges],
                         [(edge.relation, edge.device_id) for edge in self.cv.runtime_contract.edges])

    def test_decoder_wrappers_refuse_a_forged_bootstrap(self):
        for builder in (cv_pulp.make_cv32e40p_pulp_dual_source_online_decoder,
                        ibex_pulp.make_ibex_pulp_dual_source_online_decoder):
            with self.subTest(builder=builder.__name__):
                with self.assertRaisesRegex(ValueError,
                                            "dual-source stream bootstrap is required"):
                    builder(bootstrap=object())

    def test_decoder_limits_and_mmio_window_are_identical(self):
        self.assertEqual([(window.base, window.size) for window in self.ibex.windows],
                         [(window.base, window.size) for window in self.cv.windows])
        self.assertEqual([(0x4000100C, 4)],
                         [(window.base, window.size) for window in self.cv.windows])
        self.assertEqual(self.ibex.document(), self.cv.document())
        for attribute in ("instruction_start", "instruction_end", "max_steps",
                          "max_input_bytes", "allowed_mmio_operations",
                          "support_words"):
            with self.subTest(attribute=attribute):
                self.assertEqual(getattr(self.ibex, attribute), getattr(self.cv, attribute))
        self.assertEqual(0x11000, self.cv.instruction_start)
        self.assertEqual(0x2FE00, self.cv.instruction_end)


class Cv32e40pPulpRuntimeTests(unittest.TestCase):
    """Runtime assembly, replay reuse and the campaign CLI contract."""

    def test_builder_accepts_a_checker_and_configures_before_begin(self):
        import inspect

        from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
        from myfuzz.integration.scenario_rfuzz_replay import replay_scenario_rfuzz_continuous
        self.assertIn("checker", inspect.signature(cv_online.make_cv32e40p_pulp_online_runtime)
                      .parameters)
        self.assertIn("checker", inspect.signature(ScenarioRfuzzExecutor.__init__).parameters)
        self.assertIn("session_checker",
                      inspect.signature(replay_scenario_rfuzz_continuous).parameters)

    def test_runtime_configures_the_contract_before_begin_and_never_warmups_blind(self):
        session = Mock()
        session.begin.side_effect = RuntimeError("stop before RTL")
        decoder = cv_pulp.make_cv32e40p_pulp_dual_source_online_decoder()
        with TemporaryDirectory() as directory, \
                patch.object(ibex_online, "ScenarioSession", return_value=session), \
                patch.object(cv_online, "make_cv32e40p_pulp_dual_source_factory",
                             return_value=Mock(return_value=Mock())) as build:
            with self.assertRaisesRegex(RuntimeError, "stop before RTL"):
                cv_online.make_cv32e40p_pulp_online_runtime(
                    cache_dir=Path(directory), run_id="cv32e40p-preflight")
        self.assertEqual({"cpu_retirement": False, "gpio_consumption": False,
                          "native_irq_receipts": False},
                         build.call_args.kwargs)
        ordered = [call[0] for call in session.mock_calls]
        self.assertLess(ordered.index("configure_runtime_paths"), ordered.index("begin"))
        session.declare_instruction_slots.assert_called_once_with("cpu", 0x11000, 31616)
        self.assertEqual(decoder.ownership.document(),
                         session.configure_runtime_paths.call_args.kwargs
                         ["source_ownership"].document())
        self.assertEqual(decoder.runtime_paths,
                         session.configure_runtime_paths.call_args.args[2])
        session.advance_initial.assert_not_called()
        session.submit_case.assert_not_called()

    def test_runtime_rejects_unavailable_probes_before_building_a_factory(self):
        for kwargs, message in (({"native_irq_receipts": True},
                                 "native IRQ receipts require explicit RVFI retirement"),
                                ({"cpu_retirement": True},
                                 "no authenticated RVFI retirement profile"),
                                ({"native_irq_receipts": "yes"},
                                 "native IRQ receipts require explicit RVFI retirement"),
                                ({"max_warmup_rounds": 0}, "max_warmup_rounds must be positive")):
            with self.subTest(kwargs=kwargs), \
                    patch.object(cv_online, "make_cv32e40p_pulp_dual_source_factory") as build:
                with self.assertRaisesRegex(ValueError, message):
                    cv_online.make_cv32e40p_pulp_online_runtime(
                        cache_dir=Path("/tmp/cv-preflight"), run_id="cv32e40p-preflight",
                        **kwargs)
                build.assert_not_called()

    def test_replay_uses_the_shared_verified_bundle_order_and_cv_factory(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "online_plan.json"
            plan.write_bytes(b"{}")
            trace = root / "online_final_trace.json"
            trace.write_text(json.dumps({"genome_sha256": "0" * 64, "status": "complete",
                                         "events": [], "local_ticks": {},
                                         "semantic_sha256": "0" * 64,
                                         "manifest_sha256": "0" * 64}))
            order = []

            def verify(*args, **kwargs):
                order.append("bundle")
                return None

            def factory(*args, **kwargs):
                order.append("factory")
                return Mock()

            with patch.object(ibex_online, "_verify_online_run_identity", side_effect=verify), \
                    patch.object(ibex_online, "_saved_gpio_consumption_mode", return_value=False), \
                    patch.object(cv_online, "make_cv32e40p_pulp_dual_source_factory",
                                 side_effect=factory) as build, \
                    patch.object(ibex_online, "replay_online_session", return_value="matched"):
                self.assertEqual("matched", cv_online.replay_cv32e40p_pulp_online_files(
                    cache_dir=root / "cache", plan_path=plan, trace_path=trace))
            self.assertEqual(["bundle", "factory"], order)
            self.assertEqual({"cpu_retirement": False, "gpio_consumption": False},
                             build.call_args.kwargs)

    def test_replay_refuses_a_bundle_that_claims_ibex_rvfi_retirement(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "online_plan.json"
            plan.write_bytes(b"{}")
            trace = root / "online_final_trace.json"
            trace.write_text(json.dumps({"genome_sha256": "0" * 64, "status": "complete",
                                         "events": [], "local_ticks": {},
                                         "semantic_sha256": "0" * 64,
                                         "manifest_sha256": "0" * 64}))
            saved = {"runner": {"sessions": {"cpu": {"identity": {
                "cpu_observation_schema_version": "ibex_rvfi_observation.v1"}}}}}
            canonical = json.dumps(saved, sort_keys=True, separators=(",", ":")).encode()
            raw = canonical + b"\n"
            (root / "online_session_manifest.json").write_bytes(raw)
            verified = {"session": {"manifest_sha256": hashlib.sha256(canonical).hexdigest()},
                        "artifacts": {"online_session_manifest.json":
                                      hashlib.sha256(raw).hexdigest()}}
            # This fixture isolates CPU selection; GPIO selection has its own
            # complete-manifest coverage.
            with patch.object(ibex_online, "_verify_online_run_identity",
                              return_value=verified), \
                    patch.object(ibex_online, "_saved_gpio_consumption_mode",
                                 return_value=False), \
                    patch.object(ibex_online, "replay_online_session", return_value="matched"):
                with self.assertRaisesRegex(ValueError,
                                            "no authenticated RVFI retirement profile"):
                    cv_online.replay_cv32e40p_pulp_online_files(
                        cache_dir=root / "cache", plan_path=plan, trace_path=trace)

    def test_replay_rejects_a_tampered_bundle_before_any_factory_call(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / "online_plan.json"
            plan.write_bytes(b"{}")
            trace = root / "online_final_trace.json"
            trace.write_text(json.dumps({"genome_sha256": "0" * 64, "status": "complete",
                                         "events": [], "local_ticks": {},
                                         "semantic_sha256": "0" * 64,
                                         "manifest_sha256": "0" * 64}))
            with patch.object(ibex_online, "_verify_online_run_identity",
                              side_effect=ValueError("tampered")), \
                    patch.object(cv_online, "make_cv32e40p_pulp_dual_source_factory") as build:
                with self.assertRaisesRegex(ValueError, "tampered"):
                    cv_online.replay_cv32e40p_pulp_online_files(
                        cache_dir=root / "cache", plan_path=plan, trace_path=trace)
                build.assert_not_called()


def _cli_module():
    path = Path(__file__).resolve().parents[2] / "scripts/run_cv32e40p_pulp_online.py"
    spec = importlib.util.spec_from_file_location("_cv32e40p_pulp_online_cli", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Cv32e40pPulpCliTests(unittest.TestCase):
    """The CLI has the Ibex parameter semantics and refuses unavailable probes."""

    @classmethod
    def setUpClass(cls):
        cls.cli = _cli_module()

    def test_run_help_lists_the_shared_parameter_semantics(self):
        with self.assertRaises(SystemExit) as caught, redirect_stdout(io.StringIO()) as out:
            self.cli.main(["run", "--help"])
        self.assertEqual(0, caught.exception.code)
        for flag in ("--client-binary", "--cache-dir", "--output", "--seconds",
                     "--max-tests", "--seed", "--run-id", "--cpu-retirement",
                     "--gpio-consumption", "--native-irq-receipts", "--compressed-trace"):
            with self.subTest(flag=flag):
                self.assertIn(flag, out.getvalue())

    def test_replay_help_lists_the_shared_replay_inputs(self):
        with self.assertRaises(SystemExit) as caught, redirect_stdout(io.StringIO()) as out:
            self.cli.main(["replay", "--help"])
        self.assertEqual(0, caught.exception.code)
        for flag in ("--cache-dir", "--plan", "--trace"):
            with self.subTest(flag=flag):
                self.assertIn(flag, out.getvalue())

    def test_missing_required_arguments_fail_with_usage(self):
        for argv in (["run"], ["replay"], ["run", "--client-binary", "/tmp/client"]):
            with self.subTest(argv=argv), self.assertRaises(SystemExit) as caught, \
                    redirect_stderr(io.StringIO()):
                self.cli.main(argv)
            self.assertEqual(2, caught.exception.code)

    def test_existing_output_directory_is_refused_before_any_runtime(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "existing-run"
            output.mkdir()
            errors = io.StringIO()
            with patch.object(self.cli, "make_cv32e40p_pulp_online_runtime") as runtime, \
                    redirect_stderr(errors):
                code = self.cli.main(["run", "--client-binary", "/tmp/client",
                                      "--cache-dir", "/tmp/cache", "--output", str(output)])
            self.assertEqual(1, code)
            runtime.assert_not_called()
            self.assertIn("output directory must be new", errors.getvalue())

    def test_run_forwards_every_flag_to_the_shared_live_entry(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "new-run"
            result = Mock(output_dir=output, tests=3, statuses={}, elapsed_seconds=1.0,
                          effective_search_seconds=1.0)
            with patch.object(self.cli, "make_cv32e40p_pulp_online_runtime",
                              return_value=Mock()) as runtime, \
                    patch.object(self.cli, "run_scenario_rfuzz_live",
                                 return_value=result) as live, redirect_stdout(io.StringIO()):
                code = self.cli.main(["run", "--client-binary", "/tmp/client",
                                      "--cache-dir", "/tmp/cache", "--output", str(output),
                                      "--seconds", "5", "--max-tests", "7", "--seed", "3",
                                      "--run-id", "cv32e40p-test", "--gpio-consumption",
                                      "--compressed-trace"])
            self.assertEqual(0, code)
            self.assertEqual(False, runtime.call_args.kwargs["cpu_retirement"])
            self.assertEqual(True, runtime.call_args.kwargs["gpio_consumption"])
            self.assertNotIn("native_irq_receipts", runtime.call_args.kwargs)
            self.assertEqual("cv32e40p-test", runtime.call_args.kwargs["run_id"])
            self.assertEqual(Path("/tmp/cache"), runtime.call_args.kwargs["cache_dir"])
            self.assertEqual({"executor": runtime.return_value.executor,
                              "client_binary": Path("/tmp/client"), "output_dir": output,
                              "duration_seconds": 5.0, "max_tests": 7, "search_seed": 3,
                              "max_runs_per_batch": 1, "compressed_trace": True},
                             live.call_args.kwargs)

    def test_native_irq_receipts_without_retirement_is_refused_not_downgraded(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "new-run"
            errors = io.StringIO()
            with redirect_stderr(errors):
                code = self.cli.main(["run", "--client-binary", "/tmp/client",
                                      "--cache-dir", "/tmp/cache", "--output", str(output),
                                      "--native-irq-receipts"])
            self.assertEqual(1, code)
            self.assertIn("native IRQ receipts require explicit RVFI retirement",
                          errors.getvalue())
            self.assertFalse(output.exists(), "no output may be created for a refused probe")

    def test_cpu_retirement_is_refused_for_a_cpu_without_an_rvfi_profile(self):
        for flag in ("--cpu-retirement", "--cpu-retirement --native-irq-receipts"):
            with self.subTest(flag=flag), TemporaryDirectory() as directory:
                output = Path(directory) / "new-run"
                errors = io.StringIO()
                with redirect_stderr(errors):
                    code = self.cli.main(["run", "--client-binary", "/tmp/client",
                                          "--cache-dir", "/tmp/cache", "--output", str(output),
                                          *flag.split()])
                self.assertEqual(1, code)
                self.assertIn("no authenticated RVFI retirement profile", errors.getvalue())
                self.assertFalse(output.exists())

    def test_replay_reuses_the_shared_entry_and_reports_a_mismatch(self):
        matched = Mock(matches=True, first_difference=None, difference_context=None)
        with patch.object(self.cli, "replay_cv32e40p_pulp_online_files",
                          return_value=matched) as replay, redirect_stdout(io.StringIO()):
            code = self.cli.main(["replay", "--cache-dir", "/tmp/cache",
                                  "--plan", "/tmp/plan.json", "--trace", "/tmp/trace.json"])
        self.assertEqual(0, code)
        self.assertEqual({"cache_dir": Path("/tmp/cache"), "plan_path": Path("/tmp/plan.json"),
                          "trace_path": Path("/tmp/trace.json")}, replay.call_args.kwargs)
        mismatched = Mock(matches=False, first_difference="status", difference_context=None)
        with patch.object(self.cli, "replay_cv32e40p_pulp_online_files",
                          return_value=mismatched), redirect_stdout(io.StringIO()):
            code = self.cli.main(["replay", "--cache-dir", "/tmp/cache",
                                  "--plan", "/tmp/plan.json", "--trace", "/tmp/trace.json"])
        self.assertEqual(2, code)

    def test_error_prefix_names_this_wiring(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "existing-run"
            output.mkdir()
            errors = io.StringIO()
            with redirect_stderr(errors):
                self.cli.main(["run", "--client-binary", "/tmp/client",
                               "--cache-dir", "/tmp/cache", "--output", str(output)])
            self.assertIn("cv32e40p-pulp-online-error:", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
