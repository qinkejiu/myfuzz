import tempfile
import unittest
from pathlib import Path
import sys
import json
import hashlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from myfuzz.builder import (  # noqa: E402
    CampaignCheckpointStoreV4, InputValidationError, MutationConfig,
    V4Controller,
)
from test_builder_controller_v4 import _layout  # noqa: E402


class CheckpointV4Test(unittest.TestCase):
    def test_commit_loads_content_addressed_objects(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CampaignCheckpointStoreV4(directory)
            digest = store.commit({"counter": 3, "schema": "state"}, {"bitmap": b"\x01\x02"})
            state, objects = store.load()
            self.assertEqual(state["counter"], 3)
            self.assertEqual(objects["bitmap"], b"\x01\x02")
            self.assertEqual(store.commit_root.read_text().count(digest), 1)
            with self.assertRaises(InputValidationError):
                store.commit({"elapsed": float("nan")})

    def test_corrupt_object_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CampaignCheckpointStoreV4(directory)
            store.commit({"counter": 1}, {"bitmap": b"good"})
            object_path = next((Path(directory) / "objects").iterdir())
            object_path.write_bytes(b"corrupt")
            with self.assertRaises(InputValidationError):
                store.load()

    def test_unreferenced_object_is_ignored_and_non_object_state_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            store = CampaignCheckpointStoreV4(directory)
            store.commit({"counter": 1})
            orphan = b"interrupted publish"
            orphan_digest = hashlib.sha256(orphan).hexdigest()
            (store.objects / orphan_digest).write_bytes(orphan)
            state, objects = store.load()
            self.assertEqual(state, {"counter": 1})
            self.assertEqual(objects, {})

            state_bytes = b"[]\n"
            state_digest = hashlib.sha256(state_bytes).hexdigest()
            (store.objects / state_digest).write_bytes(state_bytes)
            root = json.loads(store.commit_root.read_text(encoding="utf-8"))
            root["state_digest"] = state_digest
            store.commit_root.write_text(json.dumps(root), encoding="utf-8")
            with self.assertRaises(InputValidationError):
                store.load()

    def test_controller_decision_checkpoint_restores_exact_next_decisions(self):
        layout = _layout()
        config = MutationConfig(acceptance_numerators=(32, 32, 32))
        controller = V4Controller(
            layout, policy="D", seed=41, coverage_bits=16,
            mutation_config=config,
        )
        controller.run(lambda _transport: b"\x00\x00", testcase_count=18)
        with tempfile.TemporaryDirectory() as directory:
            store = CampaignCheckpointStoreV4(directory)
            store.commit_controller(controller)
            state, objects = store.load()
            self.assertNotIn("coverage_bitmap_hex", state["controller"])
            self.assertNotIn("corpus_payloads", state["controller"])
            self.assertIn("coverage", objects)
            self.assertTrue(any(name.startswith("corpus/") for name in objects))
            resumed = store.load_controller(layout)

            expected = controller.run(
                lambda _transport: b"\x00\x00", testcase_count=20,
            )
            actual = resumed.run(
                lambda _transport: b"\x00\x00", testcase_count=20,
            )
            self.assertEqual(
                [item.transport_sha256 for item in actual],
                [item.transport_sha256 for item in expected],
            )
            self.assertEqual(resumed.checkpoint(), controller.checkpoint())

    def test_controller_checkpoint_rejects_extra_or_missing_object(self):
        layout = _layout()
        controller = V4Controller(layout, policy="D", seed=43, coverage_bits=16)
        controller.run(lambda _transport: b"\x00\x00", testcase_count=3)
        with tempfile.TemporaryDirectory() as directory:
            store = CampaignCheckpointStoreV4(directory)
            state, objects = controller.decision_checkpoint_bundle()
            store.commit(state, {**objects, "unreferenced": b"extra"})
            with self.assertRaisesRegex(InputValidationError, "closure"):
                store.load_controller(layout)

        with tempfile.TemporaryDirectory() as directory:
            store = CampaignCheckpointStoreV4(directory)
            store.commit_controller(controller)
            root = json.loads(store.commit_root.read_text(encoding="utf-8"))
            corpus_name = next(name for name in root["objects"] if name.startswith("corpus/"))
            del root["objects"][corpus_name]
            store.commit_root.write_text(json.dumps(root), encoding="utf-8")
            with self.assertRaisesRegex(InputValidationError, "closure"):
                store.load_controller(layout)


if __name__ == "__main__":
    unittest.main()
