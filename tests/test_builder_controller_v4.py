import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from myfuzz.builder import (  # noqa: E402
    AddressBiasConfigV4, AxiLiteV4Capability, MutationConfig, RawBitsV4Lane,
    RawBitsV4Submode, V4Controller, build_axi_lite_v4_layout, build_rawbits_v4_layout,
    decode_rawbits_v4_testcase, TargetExecutionResultV4, V4TargetServer,
)


def _layout():
    def field(name, width, submodes):
        return {
            "name": name, "width": width, "source": "test", "consumer": "test",
            "used": True, "submodes": submodes, "default_interpretation": "bits",
            "provenance": {"test": True},
        }
    return build_rawbits_v4_layout({
        RawBitsV4Lane.RAW_ESCAPE: (field("raw", 16, ("RAW_LITERAL",)),),
        RawBitsV4Lane.PROTOCOL_WAVEFORM: (field("wave", 16, ("LITERAL_TRACE", "GUARDED_INTENT")),),
        RawBitsV4Lane.ADVERSARIAL_MUTATION: (field("mut", 16, ("MUTATION",)),),
    })


class ControllerV4Test(unittest.TestCase):
    def test_protocol_sequence_templates_preserve_random_lane_and_shape_operations(self):
        layout = build_axi_lite_v4_layout(AxiLiteV4Capability(32, 32))
        bias = AddressBiasConfigV4((("ip0", 0x20000000, 0x1000),))
        controller = V4Controller(
            layout, policy="C", seed=13, coverage_bits=8, address_bias=bias,
        )
        protocol = []
        def dispatch(transport):
            testcase = decode_rawbits_v4_testcase(layout, transport)
            if testcase.lane == RawBitsV4Lane.PROTOCOL_WAVEFORM.name:
                protocol.append(testcase.records)
            return b"\x00"
        controller.run(dispatch, testcase_count=20, records_per_testcase=8)
        self.assertGreaterEqual(len(protocol), 16)
        fields = {
            field.name: field
            for field in layout.lane_layout(RawBitsV4Lane.PROTOCOL_WAVEFORM).fields
        }
        def value(record, name):
            field = fields[name]
            return (record >> field.offset) & ((1 << field.width) - 1)

        write = protocol[11]
        self.assertEqual(value(write[0], "guarded_aw_start"), 1)
        self.assertEqual(value(write[0], "guarded_w_start"), 1)
        self.assertTrue(all(value(item, "guarded_bready") == 0 for item in write[:-1]))
        self.assertEqual(value(write[-1], "guarded_bready"), 1)

        read = protocol[12]
        self.assertEqual(value(read[0], "guarded_ar_start"), 1)
        self.assertTrue(all(value(item, "guarded_rready") == 0 for item in read[:-1]))
        self.assertEqual(value(read[-1], "guarded_rready"), 1)

        partial = protocol[13]
        strobe = value(partial[0], "guarded_wstrb")
        self.assertEqual(strobe.bit_count(), 1)
        boundary = protocol[14]
        self.assertEqual(value(boundary[0], "guarded_araddr"), 0x20000000)
        recovery = protocol[15]
        middle = len(recovery) // 2
        self.assertEqual(value(recovery[middle], "guarded_dut_reset"), 1)
        self.assertEqual(value(recovery[middle + 1], "guarded_ar_start"), 1)
        self.assertEqual(
            controller.manifest()["protocol_sequence_templates"]["random_share"],
            "11/16",
        )

    def test_novel_completed_protocol_projection_enters_primary_corpus(self):
        layout = build_axi_lite_v4_layout(AxiLiteV4Capability(32, 32))
        controller = V4Controller(layout, policy="D", seed=17, coverage_bits=8)
        def dispatch(transport):
            testcase = decode_rawbits_v4_testcase(layout, transport)
            if testcase.logical_testcase_id == 3:
                return b"\x01"
            return b"\x00"
        controller.run(dispatch, testcase_count=5, records_per_testcase=8)
        diagnostics = controller.mutation.diagnostics()
        self.assertEqual(diagnostics["protocol_seed_new_branch_results"], 1)
        self.assertEqual(diagnostics["primary_size"], 1)
        self.assertGreaterEqual(diagnostics["protocol_seed_results"], 1)


    def test_guarded_protocol_seed_is_projected_by_field_semantics(self):
        def field(name, width, submode):
            return {
                "name": name, "width": width, "source": "test", "consumer": "test",
                "used": True, "submodes": (submode,),
                "default_interpretation": "bits", "provenance": {"test": True},
            }
        layout = build_rawbits_v4_layout({
            RawBitsV4Lane.RAW_ESCAPE: (field("raw", 1, "RAW_LITERAL"),),
            RawBitsV4Lane.PROTOCOL_WAVEFORM: (
                field("guarded_aw_start", 1, "GUARDED_INTENT"),
                field("guarded_awaddr", 7, "GUARDED_INTENT"),
                field("literal_aw", 1, "LITERAL_TRACE"),
            ),
            RawBitsV4Lane.ADVERSARIAL_MUTATION: (
                field("mutation_awaddr", 7, "MUTATION"),
                field("mutation_awvalid", 1, "MUTATION"),
            ),
        })
        observed = {}
        for policy in ("C", "D"):
            testcases = []
            controller = V4Controller(layout, policy=policy, seed=41, coverage_bits=8)
            def dispatch(transport):
                testcase = decode_rawbits_v4_testcase(layout, transport)
                testcases.append(testcase)
                return b"\x00"
            results = controller.run(dispatch, testcase_count=3)
            protocol_record = testcases[1].records[0]
            mutation_record = testcases[2].records[0]
            expected = ((protocol_record >> 1) & 0x7f) | ((protocol_record & 1) << 7)
            self.assertEqual(mutation_record, expected)
            self.assertEqual(results[2].mutation_operator, "protocol_seed")
            projection = controller.manifest()["protocol_seed_projection"]
            self.assertTrue(projection["available"])
            self.assertEqual(
                [(item["source"], item["target"]) for item in projection["fields"]],
                [
                    ("guarded_awaddr", "mutation_awaddr"),
                    ("guarded_aw_start", "mutation_awvalid"),
                ],
            )
            observed[policy] = testcases[2].records
        self.assertEqual(observed["C"], observed["D"])

        interrupted = V4Controller(layout, policy="D", seed=41, coverage_bits=8)
        interrupted.run(lambda _transport: b"\x00", testcase_count=2)
        resumed = V4Controller.from_checkpoint(layout, interrupted.checkpoint())
        resumed_result = resumed.run(lambda _transport: b"\x00", testcase_count=1)[0]
        self.assertEqual(resumed_result.mutation_operator, "protocol_seed")

    def test_protocol_seed_projection_falls_back_for_unmapped_layout(self):
        controller = V4Controller(_layout(), policy="D", seed=5, coverage_bits=8)
        projection = controller.manifest()["protocol_seed_projection"]
        self.assertFalse(projection["available"])
        result = controller.run(lambda _transport: b"\x00", testcase_count=3)[-1]
        self.assertEqual(result.mutation_operator, "seed")

    def test_address_bias_targets_generated_windows_and_keeps_uniform_path(self):
        def field(name, width):
            return {
                "name": name, "width": width, "source": "test", "consumer": "test",
                "used": True, "submodes": ("GUARDED_INTENT",),
                "default_interpretation": "bits", "provenance": {"test": True},
            }
        layout = build_rawbits_v4_layout({
            RawBitsV4Lane.RAW_ESCAPE: ({
                **field("raw", 1), "submodes": ("RAW_LITERAL",),
            },),
            RawBitsV4Lane.PROTOCOL_WAVEFORM: (
                field("guarded_awaddr", 32), field("guarded_araddr", 32),
                {**field("literal", 1), "submodes": ("LITERAL_TRACE",)},
            ),
            RawBitsV4Lane.ADVERSARIAL_MUTATION: ({
                **field("mutation", 1), "submodes": ("MUTATION",),
            },),
        })
        bias = AddressBiasConfigV4((("unseen_ip", 0x20001000, 0x100),))
        controller = V4Controller(
            layout, policy="C", seed=9, coverage_bits=8, address_bias=bias,
        )
        observed = []
        def dispatch(transport):
            testcase = decode_rawbits_v4_testcase(layout, transport)
            if testcase.lane == RawBitsV4Lane.PROTOCOL_WAVEFORM.name:
                observed.extend(testcase.records)
            return b"\x00"
        controller.run(dispatch, testcase_count=64)
        lane = layout.lane_layout(RawBitsV4Lane.PROTOCOL_WAVEFORM)
        fields = {item.name: item for item in lane.fields}
        addresses = [
            (record >> fields[name].offset) & ((1 << fields[name].width) - 1)
            for record in observed
            for name in ("guarded_awaddr", "guarded_araddr")
        ]
        self.assertTrue(any(0x20001000 <= address < 0x20001100 for address in addresses))
        self.assertTrue(any(address % 4 == 0 for address in addresses if 0x20001000 <= address < 0x20001100))
        self.assertEqual(controller.manifest()["address_bias"], bias.to_dict())
        resumed = V4Controller.from_checkpoint(layout, controller.checkpoint())
        self.assertEqual(resumed.address_bias, bias)

        uniform = AddressBiasConfigV4(
            (("unseen_ip", 0x20001000, 0x100),),
            aligned_weight=0, byte_weight=0, uniform_weight=1,
        )
        uniform_controller = V4Controller(
            layout, policy="C", seed=9, coverage_bits=8, address_bias=uniform,
        )
        lane_layout = layout.lane_layout(RawBitsV4Lane.PROTOCOL_WAVEFORM)
        original = (1 << layout.record_width_bits) - 1
        self.assertEqual(
            uniform_controller._bias_protocol_addresses(original, b"x" * 32, lane_layout),
            original,
        )

    def test_protocol_policy_dispatches_guarded_intent_not_literal_trace(self):
        layout = _layout()
        observed = []
        controller = V4Controller(layout, policy="C", seed=7, coverage_bits=8)

        def dispatch(transport):
            testcase = decode_rawbits_v4_testcase(layout, transport)
            observed.append((testcase.lane, testcase.submode))
            return b"\x00"

        controller.run(dispatch, testcase_count=1)
        self.assertEqual(observed, [(
            RawBitsV4Lane.PROTOCOL_WAVEFORM.name,
            int(RawBitsV4Submode.GUARDED_INTENT),
        )])

    def test_controller_owns_transport_and_merges_bitmap(self):
        layout = _layout()
        seen = []
        def dispatch(transport):
            testcase = decode_rawbits_v4_testcase(layout, transport)
            seen.append(testcase)
            bitmap = bytearray(2)
            bitmap[testcase.logical_testcase_id // 8] |= 1 << (testcase.logical_testcase_id % 8)
            return bytes(bitmap)
        controller = V4Controller(layout, policy="B", seed=7, coverage_bits=16)
        results = controller.run(dispatch, testcase_count=3)
        self.assertEqual([item.lane for item in results], ["RAW_ESCAPE"] * 3)
        self.assertEqual(len(seen), 3)
        self.assertEqual(results[-1].new_branch_count, 1)
        self.assertEqual(controller.coverage.digest, results[-1].coverage_digest)

    def test_d_feedback_is_controller_side_and_deterministic(self):
        layout = _layout()
        def dispatch(_transport):
            return b"\x01\x00"
        left = V4Controller(layout, policy="D", seed=11, coverage_bits=16)
        right = V4Controller(layout, policy="D", seed=11, coverage_bits=16)
        self.assertEqual(left.run(dispatch, testcase_count=5), right.run(dispatch, testcase_count=5))
        self.assertEqual(left.manifest(), right.manifest())

    def test_d_retains_seed_and_uses_it_as_next_mutation_parent(self):
        layout = _layout()
        adversarial_count = [0]
        transports = []
        def dispatch(transport):
            testcase = decode_rawbits_v4_testcase(layout, transport)
            transports.append(transport)
            if testcase.lane == RawBitsV4Lane.ADVERSARIAL_MUTATION.name:
                adversarial_count[0] += 1
                return b"\x01\x00" if adversarial_count[0] == 1 else b"\x00\x00"
            return b"\x00\x00"

        controller = V4Controller(
            layout, policy="D", seed=31, coverage_bits=16,
            mutation_config=MutationConfig(acceptance_numerators=(32, 32, 32)),
        )
        results = controller.run(dispatch, testcase_count=8)
        mutations = [item for item in results if item.mutation_operator is not None]
        self.assertGreaterEqual(len(mutations), 2)
        self.assertEqual(mutations[0].mutation_operator, "seed")
        self.assertEqual(mutations[0].parent_digest, "")
        self.assertEqual(
            mutations[1].parent_digest, mutations[0].mutation_payload_digest,
        )
        self.assertEqual(mutations[1].mutation_generation, 1)
        self.assertEqual(mutations[1].mutation_operator, "bit_flip")
        self.assertIn(mutations[1].mutation_old_value, (0, 1))
        self.assertEqual(
            mutations[1].mutation_new_value,
            mutations[1].mutation_old_value ^ 1,
        )
        diagnostics = controller.mutation.diagnostics()
        self.assertGreaterEqual(diagnostics["seed_size"], 1)
        self.assertLessEqual(diagnostics["seed_size"], 64)
        self.assertEqual(diagnostics["primary_size"], 0)
        self.assertGreaterEqual(diagnostics["exploration_size"], 1)
        self.assertGreaterEqual(diagnostics["seed_selections"], 1)

        resumed = V4Controller.from_checkpoint(layout, controller.checkpoint())
        expected = controller.run(dispatch, testcase_count=5)
        replay_count = [adversarial_count[0]]
        def replay_dispatch(transport):
            testcase = decode_rawbits_v4_testcase(layout, transport)
            if testcase.lane == RawBitsV4Lane.ADVERSARIAL_MUTATION.name:
                replay_count[0] += 1
            return b"\x00\x00"
        actual = resumed.run(replay_dispatch, testcase_count=5)
        self.assertEqual(
            [item.transport_sha256 for item in actual],
            [item.transport_sha256 for item in expected],
        )

    def test_c_and_d_share_the_first_adversarial_seed(self):
        layout = _layout()
        observed = {}
        for policy in ("C", "D"):
            transports = []
            controller = V4Controller(layout, policy=policy, seed=37, coverage_bits=16)
            def dispatch(transport):
                testcase = decode_rawbits_v4_testcase(layout, transport)
                if testcase.lane == RawBitsV4Lane.ADVERSARIAL_MUTATION.name:
                    transports.append(transport)
                return b"\x00\x00"
            controller.run(dispatch, testcase_count=3)
            observed[policy] = transports
        self.assertEqual(len(observed["C"]), 1)
        self.assertEqual(observed["C"], observed["D"])

        for policy in ("C", "D"):
            controller = V4Controller(layout, policy=policy, seed=37, coverage_bits=16)
            transports = []
            def dispatch(transport):
                testcase = decode_rawbits_v4_testcase(layout, transport)
                if testcase.lane == RawBitsV4Lane.ADVERSARIAL_MUTATION.name:
                    transports.append(transport)
                return b"\x00\x00"
            controller.run(dispatch, testcase_count=8)
            observed[policy] = transports
        self.assertEqual(observed["C"], observed["D"])

    def test_checkpoint_resume_preserves_next_decision(self):
        layout = _layout()
        def dispatch(transport):
            testcase = decode_rawbits_v4_testcase(layout, transport)
            return bytes((1 << (testcase.logical_testcase_id % 8), 0))
        continuous = V4Controller(layout, policy="D", seed=19, coverage_bits=16)
        continuous.run(dispatch, testcase_count=5)
        expected = continuous.run(dispatch, testcase_count=3)
        interrupted = V4Controller(layout, policy="D", seed=19, coverage_bits=16)
        interrupted.run(dispatch, testcase_count=5)
        resumed = V4Controller.from_checkpoint(layout, interrupted.checkpoint())
        self.assertEqual(expected, resumed.run(dispatch, testcase_count=3))

    def test_target_server_validates_before_execute(self):
        layout = _layout()
        observed = []
        server = V4TargetServer(layout, lambda testcase: (observed.append(testcase) or b"\x00\x00"))
        controller = V4Controller(layout, policy="B", seed=2, coverage_bits=16)
        transport = []
        controller.run(lambda value: (transport.append(value) or server.handle(value)), testcase_count=1)
        self.assertEqual(len(observed), 1)

    def test_observed_classification_and_first_violation_reach_controller(self):
        layout = _layout()
        server = V4TargetServer(layout, lambda _testcase: TargetExecutionResultV4(
            b"\x01\x00", "adversarial", violation_rule=2, violation_cycle=7,
        ))
        controller = V4Controller(layout, policy="C", seed=3, coverage_bits=16)
        result = controller.run(server.handle_result, testcase_count=1)[0]
        self.assertEqual(result.lane, "PROTOCOL_WAVEFORM")
        self.assertEqual(result.observed_classification, "adversarial")
        self.assertEqual((result.violation_rule, result.violation_cycle), (2, 7))

    def test_controller_samples_only_the_declared_submode_mask(self):
        def field(name, submode):
            return {
                "name": name, "width": 1, "source": "test", "consumer": "test",
                "used": True, "submodes": (submode,),
                "default_interpretation": "bits", "provenance": {"test": True},
            }
        layout = build_rawbits_v4_layout({
            RawBitsV4Lane.RAW_ESCAPE: (field("raw", "RAW_LITERAL"),),
            RawBitsV4Lane.PROTOCOL_WAVEFORM: (
                field("literal_only", "LITERAL_TRACE"),
                field("guarded_only", "GUARDED_INTENT"),
            ),
            RawBitsV4Lane.ADVERSARIAL_MUTATION: (field("mutation", "MUTATION"),),
        })
        controller = V4Controller(layout, policy="C", seed=3, coverage_bits=16)
        observed = []
        def dispatch(transport):
            testcase = decode_rawbits_v4_testcase(layout, transport)
            observed.append(testcase)
            return b"\x00\x00"
        controller.run(dispatch, testcase_count=20)
        for testcase in observed:
            lane = layout.lane_layout(RawBitsV4Lane[testcase.lane])
            mask = dict(lane.submode_used_masks)[RawBitsV4Submode(testcase.submode).name]
            self.assertTrue(all(record & ~mask == 0 for record in testcase.records))


if __name__ == "__main__":
    unittest.main()
