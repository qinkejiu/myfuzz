"""Named integration boundary for the step-9 replay implementation."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from myfuzz.composition.soc_boundary_replay import (
    BOUNDARY_REPLAY_SCHEMA,
    replay_boundary,
    replay_boundary_document,
)
from myfuzz.composition.soc_failure_evidence import (
    EvidencePackage,
    ReplayResult,
    SocFailureEvidenceError,
    _comparison_fields,
)


def _package() -> EvidencePackage:
    return EvidencePackage(
        schema_version="soc_failure_evidence.v1", kind="boundary",
        identity={}, samples=(), results=(), inputs_complete=False)


class BoundaryReplayFacadeTests(unittest.TestCase):
    def test_invalid_package_is_rejected_before_runtime(self):
        with self.assertRaisesRegex(SocFailureEvidenceError, "evidence-package-required"):
            replay_boundary(object(), object())

    def test_directory_and_document_entry_points_preserve_replay_result(self):
        result = ReplayResult(status="refused", reason="identity mismatch")
        package = _package()
        with tempfile.TemporaryDirectory() as directory, \
                patch("myfuzz.composition.soc_boundary_replay.read_evidence_package",
                      return_value=package), \
                patch("myfuzz.composition.soc_boundary_replay.replay_package",
                      return_value=result):
            self.assertIs(replay_boundary(Path(directory), object()), result)
            document = replay_boundary_document(Path(directory), object())
        self.assertEqual(BOUNDARY_REPLAY_SCHEMA, document["schema_version"])
        self.assertEqual("refused", document["status"])

    def test_peer_applied_events_are_part_of_boundary_comparison(self):
        fields = _comparison_fields({
            "request_id": 1, "status": "OK", "cycles": 4,
            "trace": [], "applied_trace": [], "observations": {}, "counters": {},
            "peer_applied": [{"cycle": 3, "instance": "uart0",
                              "slot": "uart.tx_byte", "value": 0xA5}],
        })
        self.assertEqual(3, fields["peer_applied[3].uart0.uart.tx_byte.cycle"])
        self.assertEqual(0xA5, fields["peer_applied[3].uart0.uart.tx_byte.value"])

    def test_peer_oracle_identity_and_status_are_boundary_fields(self):
        fields = _comparison_fields({
            "request_id": 1, "status": "OK", "cycles": 4,
            "trace": [], "applied_trace": [], "observations": {}, "counters": {},
            "peer_oracle": {"oracle_hash": "sha256:oracle", "status": "pass"},
        })
        self.assertEqual("sha256:oracle", fields["peer_oracle:hash"])
        self.assertEqual("pass", fields["peer_oracle:status"])


if __name__ == "__main__":
    unittest.main()
