"""Transport chunk boundaries do not define testcase or RTL step boundaries."""

import hashlib
import unittest

from myfuzz.scenario.genome import (Action, ChunkAssembler, GenomeCodec,
                                    ScenarioGenome, Trigger)
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.replay import record_scenario
from myfuzz.scenario.runner import ScenarioRunner


class _PinSession:
    def __init__(self):
        self.begins = 0

    def identity_document(self):
        return {"fixture": "chunk-equivalence-v1"}

    def begin_case(self, testcase_id):
        self.begins += 1

    def step_local(self, inputs):
        return {"out": inputs.get("pin", 0)}

    def end_case(self):
        pass


class GenomeStreamTests(unittest.TestCase):
    def setUp(self):
        self.genome = ScenarioGenome(
            testcase_id="whole", direction="IP_TO_IP", path_id="gpio-link",
            schedule_order=("a", "b"), max_steps=17,
            actions=(Action("edge", "a", "pin", 1, "IP_TO_IP",
                            Trigger("START")),))
        self.raw = GenomeCodec.encode(self.genome)
        self.digest = hashlib.sha256(self.raw).hexdigest()

    def test_arbitrary_chunks_reconstruct_same_complete_genome(self):
        for chunk_size in (1, 3, 17, len(self.raw)):
            with self.subTest(chunk_size=chunk_size):
                assembly = ChunkAssembler(len(self.raw), self.digest)
                for offset in range(0, len(self.raw), chunk_size):
                    assembly.accept(offset, self.raw[offset:offset + chunk_size])
                self.assertEqual(self.genome, assembly.finish())

    def test_chunk_shapes_preserve_execution_trace_and_one_begin(self):
        instances = []
        ownership = compile_ownership(
            (InputField("a", "pin", 1), InputField("b", "pin", 1)),
            (InputOwner("a", "pin", 0, 1, "source", "external"),
             InputOwner("b", "pin", 0, 1, "source", "external")))

        def factory():
            sessions = {name: _PinSession() for name in ("a", "b")}
            instances.append(sessions)
            return ScenarioRunner(sessions=sessions, ownership=ownership,
                                  bindings=())

        reference = record_scenario(self.genome, factory)
        for sizes in ((1,), (3,), (17,), (len(self.raw),), (1, 7, 2, 19, 5)):
            with self.subTest(sizes=sizes):
                assembly = ChunkAssembler(len(self.raw), self.digest)
                offset = 0
                index = 0
                while offset < len(self.raw):
                    size = sizes[index % len(sizes)]
                    assembly.accept(offset, self.raw[offset:offset + size])
                    offset += size
                    index += 1
                trace = record_scenario(assembly.finish(), factory)
                self.assertEqual(reference.semantic_sha256, trace.semantic_sha256)
                self.assertEqual(reference.events, trace.events)
                self.assertEqual(reference.local_ticks, trace.local_ticks)
                self.assertEqual({"a": 9, "b": 8}, trace.local_ticks)
                self.assertEqual([1, 1], [session.begins for session in instances[-1].values()])

    def test_component_registration_order_preserves_declared_schedule(self):
        ownership = compile_ownership(
            (InputField("a", "pin", 1), InputField("b", "pin", 1)),
            (InputOwner("a", "pin", 0, 1, "source", "external"),
             InputOwner("b", "pin", 0, 1, "source", "external")))

        def factory(order):
            return lambda: ScenarioRunner(
                sessions={name: _PinSession() for name in order},
                ownership=ownership, bindings=())

        normal = record_scenario(self.genome, factory(("a", "b")))
        reversed_order = record_scenario(self.genome, factory(("b", "a")))
        self.assertEqual(normal.events, reversed_order.events)
        self.assertEqual(normal.local_ticks, reversed_order.local_ticks)
        self.assertEqual(normal.semantic_sha256, reversed_order.semantic_sha256)

    def test_duplicate_transport_chunk_is_idempotent_but_overlap_rejected(self):
        assembly = ChunkAssembler(len(self.raw), self.digest)
        assembly.accept(0, self.raw[:8])
        assembly.accept(0, self.raw[:8])
        with self.assertRaisesRegex(ValueError, "changed content"):
            assembly.accept(0, bytes((self.raw[0] ^ 1,)) + self.raw[1:8])
        with self.assertRaisesRegex(ValueError, "overlap"):
            assembly.accept(4, self.raw[4:12])
        with self.assertRaisesRegex(ValueError, "incomplete"):
            assembly.finish()

    def test_finalized_genome_rejects_even_duplicate_late_chunks(self):
        assembly = ChunkAssembler(len(self.raw), self.digest)
        assembly.accept(0, self.raw)
        self.assertEqual(self.genome, assembly.finish())
        with self.assertRaisesRegex(ValueError, "final"):
            assembly.accept(0, self.raw)
        with self.assertRaisesRegex(ValueError, "final"):
            assembly.accept(len(self.raw), b"x")

    def test_digest_and_order_rejected_before_any_scenario_execution(self):
        assembly = ChunkAssembler(len(self.raw), self.digest)
        with self.assertRaisesRegex(ValueError, "order"):
            assembly.accept(1, self.raw[1:2])
        corrupted = bytearray(self.raw)
        corrupted[-1] ^= 1
        assembly.accept(0, bytes(corrupted))
        with self.assertRaisesRegex(ValueError, "digest"):
            assembly.finish()


if __name__ == "__main__":
    unittest.main()
