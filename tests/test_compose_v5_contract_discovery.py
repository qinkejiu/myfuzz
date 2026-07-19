import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.contract_discovery_v5 import discover_contract_v5_module  # noqa: E402
from myfuzz.builder.contract_v5 import canonicalize_contract_v5_hypothesis  # noqa: E402
from myfuzz.builder.frontend_v5 import (  # noqa: E402
    FrontendV5Expression,
    FrontendV5Guard,
    FrontendV5ModuleBehavior,
    FrontendV5Process,
    FrontendV5Sensitivity,
    FrontendV5Transition,
)
from myfuzz.builder.input_model import PortDirection  # noqa: E402
from myfuzz.builder.rtl_analysis import (  # noqa: E402
    Evidence,
    EvidenceState,
    RTLModule,
    RTLPort,
)


KNOWN = Evidence(EvidenceState.KNOWN, "fixture", "fixture fact")


def port(name, direction, width):
    return RTLPort(name, PortDirection(direction), width, width, (), False, KNOWN)


def module(name, ports):
    return RTLModule(
        name=name,
        original_name=name,
        source_file="fixture.sv",
        top=False,
        level=0,
        parameters=(),
        ports=tuple(sorted(ports, key=lambda item: item.name)),
        instances=(),
        memories=(),
        dependencies=(),
        evidence=KNOWN,
    )


def sig(name, width=1):
    return FrontendV5Expression("VARREF", width, name, None, ())


def op(kind, children, width=1):
    return FrontendV5Expression(kind, width, None, None, tuple(children))


def transition(target, value, sources, guard):
    return FrontendV5Transition(
        "nonblocking",
        sig(target, 2),
        value,
        (target,),
        tuple(sources),
        (FrontendV5Guard("true", guard),),
    )


def behavior(name, clock, reset, transitions):
    return FrontendV5ModuleBehavior(
        name=name,
        original_name=name,
        processes=(
            FrontendV5Process(
                0,
                "always_ff",
                (
                    FrontendV5Sensitivity("posedge", sig(clock), (clock,)),
                    FrontendV5Sensitivity("negedge", sig(reset), (reset,)),
                ),
                tuple(transitions),
            ),
        ),
    )


def handshake_fixture(prefix):
    names = {
        "clock": f"{prefix}_clock",
        "reset": f"{prefix}_reset",
        "state": f"{prefix}_state",
        "valid": f"{prefix}_out_bit",
        "ready": f"{prefix}_in_bit",
        "payload": f"{prefix}_payload_bus",
    }
    mod = module(
        f"{prefix}_block",
        (
            port(names["clock"], "input", 1),
            port(names["reset"], "input", 1),
            port(names["valid"], "output", 1),
            port(names["ready"], "input", 1),
            port(names["payload"], "output", 8),
        ),
    )
    beh = behavior(
        mod.name,
        names["clock"],
        names["reset"],
        (
            transition(
                names["state"],
                FrontendV5Expression("CONST", 2, None, "0", ()),
                (),
                op("LOGNOT", (sig(names["reset"]),)),
            ),
            transition(
                names["state"],
                sig(names["payload"], 8),
                (names["payload"],),
                op("AND", (sig(names["valid"]), sig(names["ready"]))),
            ),
        ),
    )
    return mod, beh


class ComposeV5ContractDiscoveryTest(unittest.TestCase):
    def test_behavior_discovery_produces_unique_contract_and_survives_renaming(self):
        first_module, first_behavior = handshake_fixture("alpha")
        second_module, second_behavior = handshake_fixture("omega")

        first = discover_contract_v5_module(first_module, first_behavior)
        second = discover_contract_v5_module(second_module, second_behavior)

        self.assertEqual(first.ambiguity.status, "unique")
        self.assertEqual(second.ambiguity.status, "unique")
        self.assertEqual(first.ambiguity.selected_digest, second.ambiguity.selected_digest)
        self.assertEqual(len(first.hypotheses), 1)
        hypothesis = first.hypotheses[0]
        self.assertEqual(hypothesis.interface_kind, "guarded_bit_level")
        self.assertEqual(hypothesis.interface_role, "initiator")
        self.assertEqual(
            sorted((signal.role, signal.direction, signal.width) for signal in hypothesis.signals),
            [
                ("clock", "input", 1),
                ("payload", "output", 8),
                ("request_ready", "input", 1),
                ("request_valid", "output", 1),
                ("reset", "input", 1),
            ],
        )
        canonical = canonicalize_contract_v5_hypothesis(hypothesis).to_dict()
        serialized = json.dumps(canonical, sort_keys=True)
        self.assertNotIn("alpha_clock", serialized)
        self.assertNotIn("alpha_out_bit", serialized)

    def test_target_direction_is_inferred_from_opposite_port_directions(self):
        names = {
            "clock": "tick_source",
            "reset": "clear_source",
            "state": "state_shadow",
            "valid": "incoming_level",
            "ready": "outgoing_level",
            "payload": "incoming_payload",
        }
        mod = module(
            "receiver_shape",
            (
                port(names["clock"], "input", 1),
                port(names["reset"], "input", 1),
                port(names["valid"], "input", 1),
                port(names["ready"], "output", 1),
                port(names["payload"], "input", 8),
            ),
        )
        beh = behavior(
            mod.name,
            names["clock"],
            names["reset"],
            (
                transition(names["state"], FrontendV5Expression("CONST", 2, None, "0", ()),
                           (), op("LOGNOT", (sig(names["reset"]),))),
                transition(names["state"], sig(names["payload"], 8), (names["payload"],),
                           op("AND", (sig(names["valid"]), sig(names["ready"])))),
            ),
        )
        result = discover_contract_v5_module(mod, beh)
        self.assertEqual(result.ambiguity.status, "unique")
        self.assertEqual(result.hypotheses[0].interface_role, "target")
        roles = {(signal.role, signal.direction) for signal in result.hypotheses[0].signals}
        self.assertIn(("request_valid", "input"), roles)
        self.assertIn(("request_ready", "output"), roles)
        self.assertIn(("payload", "input"), roles)

    def test_multiple_physical_bindings_are_ambiguous_even_with_same_canonical_shape(self):
        names = {
            "clock": "edge_a",
            "reset": "edge_b",
            "state": "shadow",
            "v0": "one_a",
            "r0": "one_b",
            "v1": "one_c",
            "r1": "one_d",
            "payload": "wide_a",
        }
        mod = module(
            "many_pairs",
            (
                port(names["clock"], "input", 1),
                port(names["reset"], "input", 1),
                port(names["v0"], "output", 1),
                port(names["r0"], "input", 1),
                port(names["v1"], "output", 1),
                port(names["r1"], "input", 1),
                port(names["payload"], "output", 8),
            ),
        )
        beh = behavior(
            mod.name,
            names["clock"],
            names["reset"],
            (
                transition(names["state"], FrontendV5Expression("CONST", 2, None, "0", ()),
                           (), op("LOGNOT", (sig(names["reset"]),))),
                transition(
                    names["state"],
                    sig(names["payload"], 8),
                    (names["payload"],),
                    op("AND", (
                        sig(names["v0"]), sig(names["r0"]),
                        sig(names["v1"]), sig(names["r1"]),
                    )),
                ),
            ),
        )
        result = discover_contract_v5_module(mod, beh)
        self.assertEqual(result.ambiguity.status, "ambiguous")
        self.assertEqual(result.ambiguity.canonical_class_count, 1)
        self.assertIn("physical signal bindings", result.ambiguity.reason)
        self.assertGreater(result.ambiguity.surviving_count, 1)

    def test_missing_opposite_direction_guard_pair_and_inout_fail_closed(self):
        mod, beh = handshake_fixture("lonely")
        only_one_guard = behavior(
            mod.name,
            "lonely_clock",
            "lonely_reset",
            (
                transition("lonely_state", FrontendV5Expression("CONST", 2, None, "0", ()),
                           (), op("LOGNOT", (sig("lonely_reset"),))),
                transition("lonely_state", sig("lonely_payload_bus", 8), ("lonely_payload_bus",),
                           sig("lonely_out_bit")),
            ),
        )
        result = discover_contract_v5_module(mod, only_one_guard)
        self.assertEqual(result.ambiguity.status, "empty")
        self.assertEqual(result.hypotheses, ())

        bad = module(
            "inout_block",
            (
                port("edge0", "input", 1),
                port("edge1", "input", 1),
                port("physical_pin", "inout", 1),
            ),
        )
        bad_behavior = behavior(
            bad.name,
            "edge0",
            "edge1",
            (transition("state", sig("physical_pin"), ("physical_pin",), sig("physical_pin")),),
        )
        rejected = discover_contract_v5_module(bad, bad_behavior)
        self.assertEqual(rejected.ambiguity.status, "empty")
        self.assertIn("inout", " ".join(rejected.rejected_reasons))

    def test_discovery_source_does_not_contain_fixture_port_names(self):
        source = (ROOT / "src/myfuzz/builder/contract_discovery_v5.py").read_text(encoding="ascii")
        for forbidden in ("alpha_clock", "omega_clock", "incoming_level", "physical_pin"):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()

