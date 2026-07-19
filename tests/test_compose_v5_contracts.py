import dataclasses
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder.contract_v5 import (  # noqa: E402
    CONTRACT_V5_CANONICAL_SCHEMA,
    CONTRACT_V5_GRAMMAR_VERSION,
    ContractV5Event,
    ContractV5Hypothesis,
    ContractV5Ordering,
    ContractV5Predicate,
    ContractV5SignalRef,
    canonicalize_contract_v5_hypothesis,
    classify_contract_v5_ambiguity,
    contract_v5_hypothesis_digest,
)
from myfuzz.builder.input_model import InputValidationError  # noqa: E402


def _signal(source_id, module, port, direction, width, role, polarity="level"):
    return ContractV5SignalRef(
        source_id=source_id,
        module=module,
        port=port,
        direction=direction,
        width=width,
        role=role,
        polarity=polarity,
    )


def _request_guard(valid, ready):
    return ContractV5Predicate(
        "and",
        children=(
            ContractV5Predicate("signal_nonzero", signal=valid),
            ContractV5Predicate("signal_nonzero", signal=ready),
        ),
    )


def _error_guard(resp_valid, error):
    return ContractV5Predicate(
        "and",
        children=(
            ContractV5Predicate("signal_nonzero", signal=resp_valid),
            ContractV5Predicate("signal_nonzero", signal=error),
        ),
    )


def base_hypothesis(prefix="a", module="u_cpu", renamed=False):
    ids = {
        "clk": f"{prefix}_clk",
        "rst": f"{prefix}_rst",
        "valid": f"{prefix}_valid",
        "ready": f"{prefix}_ready",
        "addr": f"{prefix}_addr",
        "wdata": f"{prefix}_wdata",
        "op": f"{prefix}_op",
        "resp": f"{prefix}_resp",
        "err": f"{prefix}_err",
    }
    ports = {
        "clk": "clock_input" if renamed else "clk_i",
        "rst": "reset_input" if renamed else "rst_ni",
        "valid": "transaction_v" if renamed else "req_valid_o",
        "ready": "transaction_r" if renamed else "req_ready_i",
        "addr": "target_index" if renamed else "addr_o",
        "wdata": "payload_bits" if renamed else "wdata_o",
        "op": "command_bits" if renamed else "op_o",
        "resp": "return_v" if renamed else "rsp_valid_i",
        "err": "return_error" if renamed else "err_i",
    }
    return ContractV5Hypothesis(
        interface_kind="memory_mapped",
        interface_role="initiator",
        signals=(
            _signal(ids["clk"], module, ports["clk"], "input", 1, "clock", "edge"),
            _signal(ids["rst"], module, ports["rst"], "input", 1, "reset", "active_low"),
            _signal(ids["valid"], module, ports["valid"], "output", 1, "request_valid"),
            _signal(ids["ready"], module, ports["ready"], "input", 1, "request_ready"),
            _signal(ids["addr"], module, ports["addr"], "output", 32, "address"),
            _signal(ids["wdata"], module, ports["wdata"], "output", 32, "write_data"),
            _signal(ids["op"], module, ports["op"], "output", 3, "operation"),
            _signal(ids["resp"], module, ports["resp"], "input", 1, "response_valid"),
            _signal(ids["err"], module, ports["err"], "input", 1, "error"),
        ),
        events=(
            ContractV5Event(
                name="fire" if renamed else "accept",
                kind="request_accept",
                guard=_request_guard(ids["valid"], ids["ready"]),
                payload_signals=(ids["addr"], ids["wdata"], ids["op"]),
            ),
            ContractV5Event(
                name="bad" if renamed else "error",
                kind="error_response",
                guard=_error_guard(ids["resp"], ids["err"]),
                payload_signals=(ids["err"],),
            ),
        ),
        invariants=(
            ContractV5Predicate(
                "not",
                children=(ContractV5Predicate("signal_is", signal=ids["rst"], value=0),),
            ),
        ),
        ordering=(ContractV5Ordering(before="accept" if not renamed else "fire",
                                     after="error" if not renamed else "bad",
                                     relation="may_follow"),),
        source_evidence={"module": module, "note": "must not affect canonical digest"},
    )


class ComposeV5ContractGrammarTest(unittest.TestCase):
    def test_alpha_renaming_ignores_module_port_source_and_event_names(self):
        first = base_hypothesis()
        renamed = base_hypothesis(prefix="z", module="renamed_block", renamed=True)

        first_canonical = canonicalize_contract_v5_hypothesis(first)
        second_canonical = canonicalize_contract_v5_hypothesis(renamed)

        self.assertEqual(first_canonical.digest, second_canonical.digest)
        self.assertEqual(first_canonical.payload["schema"], CONTRACT_V5_CANONICAL_SCHEMA)
        self.assertEqual(first_canonical.payload["grammar_version"], CONTRACT_V5_GRAMMAR_VERSION)
        self.assertEqual([signal["id"] for signal in first_canonical.payload["signals"]],
                         [f"s{index}" for index in range(9)])

        serialized = json.dumps(first_canonical.to_dict(), sort_keys=True)
        for forbidden in ("u_cpu", "clk_i", "req_valid_o", "rsp_valid_i", "another_valid"):
            self.assertNotIn(forbidden, serialized)

    def test_same_canonical_class_is_unique_and_semantic_split_is_ambiguous(self):
        first = base_hypothesis()
        renamed = base_hypothesis(prefix="z", module="renamed_block", renamed=True)
        report = classify_contract_v5_ambiguity((first, renamed))
        self.assertEqual(report.status, "unique")
        self.assertEqual(report.selected_digest, contract_v5_hypothesis_digest(first))
        self.assertEqual(report.surviving_count, 2)
        self.assertEqual(report.canonical_class_count, 1)

        changed_event = ContractV5Event(
            name="accept",
            kind="request_stall",
            guard=_request_guard("a_valid", "a_ready"),
            payload_signals=("a_addr", "a_wdata", "a_op"),
        )
        changed = dataclasses.replace(first, events=(changed_event, first.events[1]))
        ambiguous = classify_contract_v5_ambiguity((first, changed))
        self.assertEqual(ambiguous.status, "ambiguous")
        self.assertIsNone(ambiguous.selected_digest)
        self.assertEqual(ambiguous.canonical_class_count, 2)

    def test_empty_candidate_set_is_reported_fail_closed(self):
        report = classify_contract_v5_ambiguity(())
        self.assertEqual(report.status, "empty")
        self.assertIsNone(report.selected_digest)
        self.assertEqual(report.reason, "no surviving contract hypotheses")
        self.assertEqual(report.digest, classify_contract_v5_ambiguity(()).digest)

    def test_non_alpha_distinguishable_duplicate_signal_shape_is_rejected(self):
        hypothesis = base_hypothesis()
        duplicate = _signal("extra_valid", "u_cpu", "another_valid", "output", 1, "request_valid")
        with self.assertRaisesRegex(InputValidationError, "alpha-renaming is ambiguous"):
            canonicalize_contract_v5_hypothesis(
                dataclasses.replace(hypothesis, signals=hypothesis.signals + (duplicate,))
            )

    def test_unknown_signal_and_out_of_width_constant_fail_closed(self):
        hypothesis = base_hypothesis()
        with self.assertRaisesRegex(InputValidationError, "unknown signal"):
            canonicalize_contract_v5_hypothesis(
                dataclasses.replace(
                    hypothesis,
                    events=(
                        ContractV5Event(
                            name="broken",
                            kind="request_accept",
                            guard=ContractV5Predicate("signal_nonzero", signal="missing"),
                        ),
                    ),
                )
            )
        with self.assertRaisesRegex(InputValidationError, "does not fit"):
            canonicalize_contract_v5_hypothesis(
                dataclasses.replace(
                    hypothesis,
                    invariants=(ContractV5Predicate("signal_is", signal="a_op", value=8),),
                )
            )


if __name__ == "__main__":
    unittest.main()
