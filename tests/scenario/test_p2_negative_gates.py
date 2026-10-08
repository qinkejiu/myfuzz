"""P2 negative gates: a declared path break must fail before any RTL exists.

Every negative case is declarative: the wiring declaration, the runtime path
contract and the runtime paths are transformed, never a real event or an RTL
source.  The probe counts render, build, process and session effects, so a
"rejected" result that still rendered a harness or started a process cannot
pass.
"""
from dataclasses import replace
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from myfuzz.scenario.ibex_pulp_dual_source import (
    make_ibex_pulp_dual_source_factory)
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.p2_negative_gates import (
    GATE_SCHEMA, LaunchProbe, NegativeGateError, NegativeGateVariant,
    PathDeclaration, ProbeViolation,
    assert_replay_identity_not_mutually_recognized, compile_declared_paths,
    declared_topology, declaration_delta, expect_preflight_rejection,
    p2_negative_gate_variants, preflight_path_declaration,
    replay_identity_record, trusted_gate, trusted_path_declaration)
from myfuzz.scenario.runtime_path_contract import (
    PreparedRuntimePathContract, compile_runtime_path_contract)

AUTHORITIES = ("online", "genome")

#: The repository root, used only to call a probe-intercepted build entry point.
ROOT = Path(__file__).resolve().parents[2]

#: The exact break each trusted variant must produce, located by edge identity.
VARIANT_EDGES = {
    "cut_binding": (2, 0),
    "drop_irq_binding": (4, 0),
    "wrong_mmio_base": (0, 0),
    "wrong_target_window": (0, 0),
    "edge_identity_swap": (0, 0),
    "producer_drift": (2, 0),
}

VARIANT_FIELDS = {
    "cut_binding": "wiring.bindings[gpio_a.gpio_out->gpio_b.gpio_in@0:8]",
    "drop_irq_binding": "wiring.bindings[gpio_b.irq->cpu.irq@0:1]",
    "wrong_mmio_base": "wiring.windows[gpio_a].base",
    "wrong_target_window": "wiring.windows[gpio_a].component",
    "edge_identity_swap": "paths.contract.edges[(0, 0)].rule_index",
    "producer_drift": "wiring.ownership.owners[gpio_b.gpio_in@0:8].producer_ref",
}

ZERO_COUNTS = ("rtl_process_launches", "rtl_begin_attempts", "tool_process_invocations",
               "harness_renders", "harness_builds", "harness_session_constructions",
               "filesystem_writes", "factory_calls")


def forbidden_factory():
    raise AssertionError("the factory must not be constructed for a rejected declaration")


class P2NegativeGatePreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.declarations = {authority: trusted_path_declaration(authority)
                            for authority in AUTHORITIES}

    def test_trusted_declaration_is_not_rejected_and_touches_no_harness(self):
        for authority in AUTHORITIES:
            declaration = self.declarations[authority]
            with self.subTest(authority=authority):
                result = preflight_path_declaration(declaration,
                                                    factory=forbidden_factory)
                self.assertFalse(result["rejected"], result)
                self.assertEqual("accepted", result["stage"])
                self.assertEqual([], result["declaration_delta"])
                self.assertTrue(result["no_harness_effects"], result["probe"])
                for key in ZERO_COUNTS:
                    self.assertEqual(0, result["probe"][key], key)
                self.assertEqual(2, len(result["path_ids"]))

    def test_six_variants_reject_before_harness_with_located_edge_and_field(self):
        seen = set()
        for authority in AUTHORITIES:
            declaration = self.declarations[authority]
            variants = p2_negative_gate_variants(declaration=declaration)
            self.assertEqual(set(VARIANT_EDGES), {v.variant_id for v in variants})
            for variant in variants:
                with self.subTest(authority=authority, variant=variant.variant_id):
                    seen.add(variant.variant_id)
                    factory = Mock(side_effect=AssertionError("must not construct"))
                    result = expect_preflight_rejection(variant, factory,
                                                        declaration=declaration)
                    self.assertTrue(result["rejected"], result)
                    self.assertIn(result["stage"],
                                  ("contract_compile", "declaration_coherence"), result)
                    self.assertTrue(result["rejected_before_harness"], result["probe"])
                    self.assertEqual(0, factory.call_count)
                    for key in ZERO_COUNTS:
                        self.assertEqual(0, result["probe"][key], key)
                    edge = result["first_failing_edge"]
                    self.assertEqual(VARIANT_EDGES[variant.variant_id],
                                     (edge["rule_index"], edge["prerequisite_index"]), result)
                    self.assertEqual(VARIANT_FIELDS[variant.variant_id], edge["field"])
                    self.assertTrue(edge["path_id"], result)
                    # The exact break is also returned as a one-record delta.
                    self.assertEqual(1, len(result["declaration_delta"]), result)
                    self.assertEqual(VARIANT_FIELDS[variant.variant_id],
                                     result["declaration_delta"][0]["field"])
                    expected = variant.expected_reason
                    self.assertTrue(expected in (result["framework_reason"] or "")
                                    or expected in (result["reason"] or "")
                                    or expected in (result["located_reason"] or ""),
                                    (variant.variant_id, expected, result))
        self.assertEqual(set(VARIANT_EDGES), seen)

    def test_variant_mutation_is_confined_to_its_declared_target(self):
        for authority in AUTHORITIES:
            declaration = self.declarations[authority]
            trusted_paths = declaration.prepared.document()["selections"]
            for variant in p2_negative_gate_variants(declaration=declaration):
                with self.subTest(authority=authority, variant=variant.variant_id):
                    mutated = variant.apply(declaration)
                    self.assertNotEqual(declaration.identity_sha256,
                                        mutated.identity_sha256)
                    self.assertEqual(declaration.prepared.document()["graph"],
                                     mutated.prepared.document()["graph"])
                    self.assertEqual(trusted_paths,
                                     mutated.prepared.document()["selections"])
                    delta = declaration_delta(declaration, mutated)
                    self.assertEqual(1, len(delta), delta)
                    self.assertEqual(VARIANT_FIELDS[variant.variant_id], delta[0]["field"])
                    self.assertEqual(list(VARIANT_EDGES[variant.variant_id]),
                                     [delta[0]["edge"]["rule_index"],
                                      delta[0]["edge"]["prerequisite_index"]])

    def test_apply_returns_a_copy_and_never_mutates_its_input(self):
        """A gate is a pure declaration transform: input object stays trusted."""
        for authority in AUTHORITIES:
            declaration = self.declarations[authority]
            before = json.dumps(declaration.document(), sort_keys=True)
            for variant in p2_negative_gate_variants(declaration=declaration):
                with self.subTest(authority=authority, variant=variant.variant_id):
                    mutated = variant.apply(declaration)
                    self.assertIsNot(declaration, mutated)
                    self.assertEqual(before, json.dumps(declaration.document(),
                                                        sort_keys=True))
                    self.assertEqual(declaration.identity_sha256,
                                     trusted_path_declaration(authority).identity_sha256)
                    # Applying the same gate twice yields the same break.
                    self.assertEqual(mutated.document(),
                                     variant.apply(declaration).document())

    def test_probe_counts_and_refuses_real_harness_effects(self):
        """The zero counts are meaningful only if the probe really intercepts."""
        import myfuzz.local_harness as local_harness
        import subprocess

        def effect(call):
            probe = LaunchProbe()
            with self.assertRaises(ProbeViolation):
                with probe.arm("probe-self-test"):
                    call()
            return probe

        rendered = effect(lambda: local_harness.render_local_harness(None))
        self.assertEqual(1, rendered.counts["harness_renders"])
        self.assertEqual(1, rendered.effects)
        launched = effect(lambda: subprocess.Popen(("true",)))
        self.assertEqual(1, launched.counts["rtl_process_launches"])
        written = effect(lambda: Path("p2-probe-self-test").write_text("x"))
        self.assertEqual(1, written.counts["filesystem_writes"])
        built = effect(lambda: local_harness.build_local_harness(None, base_dir=ROOT))
        self.assertEqual(1, built.counts["harness_builds"])

    def test_permitted_effect_is_counted_and_delegated(self):
        """The runner stage may permit session construction; permission is explicit."""
        probe = LaunchProbe()
        done = []
        with probe.arm("permit-self-test"):
            with probe.permit("harness_session_constructions"):
                done.append(True)
        self.assertEqual([True], done)
        self.assertEqual(0, probe.counts["harness_session_constructions"])
        with self.assertRaises(NegativeGateError):
            with probe.arm("permit-unknown"):
                with probe.permit("not_a_counter"):
                    pass

    def test_declaration_and_variant_documents_round_trip(self):
        for authority in AUTHORITIES:
            declaration = self.declarations[authority]
            rebuilt = PathDeclaration.from_document(declaration.document())
            self.assertEqual(declaration, rebuilt)
            self.assertEqual(declaration.document(), rebuilt.document())
            for variant in p2_negative_gate_variants(declaration=declaration):
                with self.subTest(authority=authority, variant=variant.variant_id):
                    self.assertEqual(variant,
                                     NegativeGateVariant.from_document(variant.document()))
                    self.assertEqual(variant.document(),
                                     trusted_gate(variant.variant_id).document())

    def test_illegal_variants_and_tampered_gate_documents_are_rejected(self):
        variant = trusted_gate("cut_binding")
        document = variant.document()
        self.assertEqual(GATE_SCHEMA, document["schema_version"])
        tampered = {
            "schema": {**document, "schema_version": "p2_negative_gate.v2"},
            "extra": {**document, "extra": 1},
            "unknown-id": {**document, "variant_id": "cut_everything"},
            "operation": {**document, "operation": "replace"},
            "mutated": {**document, "mutated_value": {"width": 8}},
            "baseline": {**document, "baseline_value": {**document["baseline_value"],
                                                        "width": 7}},
            "field": {**document, "target": {**document["target"],
                                             "field": "wiring.bindings[invented]"}},
            "edge": {**document, "target": {**document["target"],
                                            "edge": {"rule_index": 9,
                                                     "prerequisite_index": 0}}},
            "identity": {**document, "target": {**document["target"],
                                                "identity": {**document["target"]["identity"],
                                                             "target_port": "irq"}}},
            "reason": {**document, "expected_reason": "no error at all"},
        }
        for label, changed in tampered.items():
            with self.subTest(tampered=label), self.assertRaises(ValueError):
                NegativeGateVariant.from_document(changed)
        with self.assertRaises(ValueError):
            trusted_gate("not_a_gate")
        with self.assertRaises(ValueError):
            trusted_path_declaration("not_an_authority")

    def test_variant_cannot_be_applied_to_a_declaration_it_does_not_describe(self):
        declaration = self.declarations["online"]
        variant = trusted_gate("cut_binding")
        mutated = variant.apply(declaration)
        with self.assertRaises(NegativeGateError):
            variant.apply(mutated)
        other = replace(declaration, authority="genome")
        with self.assertRaises(NegativeGateError):
            variant.apply(other)
        with self.assertRaises(NegativeGateError):
            p2_negative_gate_variants(declaration=mutated)

    def test_contract_digest_drift_cannot_become_a_declaration_at_all(self):
        declaration = self.declarations["online"]
        drifted = replace(declaration.contract, graph_sha256="0" * 64)
        with self.assertRaisesRegex(ValueError, "graph digest"):
            PreparedRuntimePathContract(declaration.graph, drifted,
                                        declaration.runtime_paths)

    def test_declared_topology_cannot_start_a_harness(self):
        topology = declared_topology(self.declarations["online"])
        for session in topology.sessions.values():
            with self.assertRaisesRegex(RuntimeError, "declaration topology"):
                session.begin_case("never")
            self.assertIsNone(session.process)
        with self.assertRaisesRegex(RuntimeError, "declaration topology"):
            topology.begin_test("never")
        compiled = compile_declared_paths(self.declarations["online"])
        self.assertEqual("selected_declared_topology_only",
                         compiled.document()["proof_scope"])


class P2NegativeGateReplayIdentityTests(unittest.TestCase):
    def test_edge_identity_swap_replay_identities_do_not_recognize_each_other(self):
        declaration = trusted_path_declaration("genome")
        variant = trusted_gate("edge_identity_swap", declaration=declaration)
        swapped = variant.apply(declaration)
        # The swapped identity is still refused by the preflight itself.
        rejection = expect_preflight_rejection(variant, forbidden_factory,
                                               declaration=declaration)
        self.assertTrue(rejection["rejected"], rejection)
        self.assertEqual((0, 0), (rejection["first_failing_edge"]["rule_index"],
                                  rejection["first_failing_edge"]["prerequisite_index"]))
        report = assert_replay_identity_not_mutually_recognized(declaration, swapped)
        self.assertTrue(report["same_graph"])
        self.assertEqual(2, len(report["path_ids"]))
        self.assertEqual(report["path_ids"], report["swapped_path_ids"])
        self.assertNotEqual(report["contract_sha256"], report["swapped_contract_sha256"])
        self.assertNotEqual(report["declaration_sha256"],
                            report["swapped_declaration_sha256"])
        self.assertTrue(report["trusted_recognized_by_trusted"])
        self.assertFalse(report["trusted_recognized_by_swapped"])
        self.assertFalse(report["swapped_recognized_by_trusted"])
        self.assertEqual("fresh replay runtime path declaration mismatch",
                         report["trusted_rejected_by_swapped"])
        self.assertEqual("fresh replay runtime path declaration mismatch",
                         report["swapped_rejected_by_trusted"])
        self.assertTrue(report["rejected_before_harness"], report["probe"])
        for key in ZERO_COUNTS:
            self.assertEqual(0, report["probe"][key], key)
        record = replay_identity_record(swapped)
        self.assertEqual("contract_preflight", record["status"])
        self.assertEqual({}, record["compiled"])
        self.assertEqual(swapped.prepared.document(), record["declaration"])


class P2NegativeGateRealRunnerTests(unittest.TestCase):
    """The declaration is only useful if it is the real wiring; render once."""

    @classmethod
    def setUpClass(cls):
        cls._cache = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls._cache.cleanup)
        # staticmethod keeps the factory a plain zero-argument callable instead
        # of a bound method of the test case.
        cls.factory = staticmethod(
            make_ibex_pulp_dual_source_factory(Path(cls._cache.name)))

    def test_real_runner_topology_equals_the_trusted_declaration(self):
        wiring = trusted_path_declaration("online").wiring
        runner = self.factory()
        with patch.object(runner, "begin_test",
                          side_effect=AssertionError("must not begin")) as begin:
            self.assertEqual(wiring.bindings, runner.bindings)
            self.assertEqual(
                tuple((window.device_id, window.base, window.size,
                       window.target is runner.sessions[component])
                      for window, (_, _, _, component)
                      in zip(runner.sessions["cpu"].router.windows, wiring.windows)),
                tuple((device_id, base, size, True)
                      for device_id, base, size, _ in wiring.windows))
            self.assertEqual(
                compile_ownership(wiring.ownership_fields,
                                  wiring.ownership_owners).document(),
                runner.ownership.document())
            self.assertEqual(
                {binding: policy.width_ticks for binding, policy
                 in runner._irq_pulses.items()},
                dict(wiring.irq_pulse_widths))
            memory = runner.sessions[wiring.memory_component].memory
            self.assertEqual(wiring.memory_regions, tuple(memory._regions))
            self.assertEqual(wiring.memory_initialization_seed,
                             memory.initialization_seed)
            self.assertEqual(wiring.max_initialized_bytes,
                             memory.max_initialized_bytes)
            begin.assert_not_called()
        self.assertTrue(all(session._process is None
                            for session in runner.sessions.values()))

    def test_declared_topology_compiles_byte_identical_to_the_real_runner(self):
        declaration = trusted_path_declaration("online")
        runner = self.factory()
        with patch.object(runner, "begin_test",
                          side_effect=AssertionError("must not begin")) as begin:
            real = compile_runtime_path_contract(
                declaration.graph, declaration.contract, runner,
                paths=declaration.runtime_paths)
            declared = compile_declared_paths(declaration)
            begin.assert_not_called()
        self.assertEqual(real.document(), declared.document())
        self.assertEqual(real.identity_sha256, declared.identity_sha256)
        self.assertTrue(all(session._process is None
                            for session in runner.sessions.values()))

    def test_real_runner_breakages_reproduce_the_declared_gate_reasons(self):
        declaration = trusted_path_declaration("online")
        wiring = declaration.wiring
        binding = next(b for b in wiring.bindings
                       if (b.source_component, b.target_component) == ("gpio_a", "gpio_b"))
        irq = next(b for b in wiring.bindings if b.target_component == "cpu")
        for variant in p2_negative_gate_variants(declaration=declaration):
            if variant.variant_id == "edge_identity_swap":
                # An identity swap is a contract-document change, not a runner
                # object change; the dedicated test below drives it.
                continue
            with self.subTest(variant=variant.variant_id):
                rejected = expect_preflight_rejection(variant, forbidden_factory,
                                                      declaration=declaration)
                runner = self.factory()
                if variant.variant_id == "cut_binding":
                    runner.bindings = tuple(b for b in runner.bindings if b != binding)
                elif variant.variant_id == "drop_irq_binding":
                    runner.bindings = tuple(b for b in runner.bindings if b != irq)
                elif variant.variant_id == "wrong_mmio_base":
                    runner.sessions["cpu"].router.windows = tuple(
                        replace(window, base=0x40002000)
                        if window.device_id == "gpio_a" else window
                        for window in runner.sessions["cpu"].router.windows)
                elif variant.variant_id == "wrong_target_window":
                    runner.sessions["cpu"].router.windows = tuple(
                        replace(window, target=runner.sessions["gpio_b"])
                        if window.device_id == "gpio_a" else window
                        for window in runner.sessions["cpu"].router.windows)
                elif variant.variant_id == "producer_drift":
                    runner.ownership._bits[("gpio_b", "gpio_in")] = tuple(
                        replace(owner, producer_ref="gpio_a.gpio_out_drift")
                        if (owner.kind == "bound" and owner.bit_offset == 0) else owner
                        for owner in runner.ownership._bits[("gpio_b", "gpio_in")])
                with patch.object(runner, "begin_test",
                                  side_effect=AssertionError("must not begin")) as begin, \
                        self.assertRaisesRegex(ValueError,
                                               rejected["reason"].replace("(", r"\(")
                                               .replace(")", r"\)")) as error:
                    compile_runtime_path_contract(
                        declaration.graph, declaration.contract, runner,
                        paths=declaration.runtime_paths)
                self.assertEqual(rejected["reason"], str(error.exception))
                begin.assert_not_called()
                self.assertTrue(all(session._process is None
                                    for session in runner.sessions.values()))

    def test_real_swap_contract_is_rejected_by_the_real_runner_checker(self):
        declaration = trusted_path_declaration("online")
        variant = trusted_gate("edge_identity_swap", declaration=declaration)
        swapped = variant.apply(declaration)
        runner = self.factory()
        with patch.object(runner, "begin_test",
                          side_effect=AssertionError("must not begin")) as begin, \
                self.assertRaisesRegex(ValueError, "lacks contract") as error:
            compile_runtime_path_contract(swapped.graph, swapped.contract, runner,
                                          paths=swapped.runtime_paths)
        self.assertEqual("selected cross-component edge (0, 0) lacks contract",
                         str(error.exception))
        begin.assert_not_called()

    def test_rejection_never_invokes_the_real_ibex_dual_source_factory(self):
        calls = []

        def counted_factory():
            calls.append(1)
            return self.factory()

        for variant_id in sorted(VARIANT_EDGES):
            with self.subTest(variant=variant_id):
                result = expect_preflight_rejection(trusted_gate(variant_id),
                                                    counted_factory)
                self.assertTrue(result["rejected"], result)
                self.assertTrue(result["rejected_before_harness"], result["probe"])
        self.assertEqual([], calls)

    def test_accepted_declaration_reaches_the_real_runner_stage_without_rtl(self):
        """Positive control for the runner stage and for live probe counters."""
        probe = LaunchProbe()
        result = preflight_path_declaration(trusted_path_declaration("online"),
                                            factory=self.factory, probe=probe,
                                            runner_stage=True)
        self.assertFalse(result["rejected"], result)
        self.assertEqual("accepted", result["stage"])
        counts = result["probe"]
        # The counters are live: three real sessions were constructed by the
        # one counted factory call, and nothing was rendered or started inside
        # the preflight.
        self.assertEqual(1, counts["factory_calls"])
        self.assertEqual(3, counts["harness_session_constructions"])
        self.assertEqual(0, counts["harness_renders"])
        self.assertEqual(0, counts["harness_builds"])
        self.assertEqual(0, counts["rtl_process_launches"])
        self.assertEqual(0, counts["rtl_begin_attempts"])
        self.assertEqual(0, counts["filesystem_writes"])
        self.assertTrue(result["runner_topology"]["proof_scope"],
                        "runner stage must carry the real compiled proof")


if __name__ == "__main__":
    unittest.main()
