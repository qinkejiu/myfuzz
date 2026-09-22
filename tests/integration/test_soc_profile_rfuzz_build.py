"""The profile builder must produce the real persistent RFuzz protocol artifact."""
from pathlib import Path
import json
import tempfile
import unittest

from myfuzz.integration.soc_builder import (
    build_soc_campaign_artifact, SocBuildError, ProfileCampaignProjector,
    _peer_projection_slots,
)
from myfuzz.integration.soc_campaign import preflight_soc_campaign
from myfuzz.integration.rfuzz_simulator import RtlSimulator, SimulatorArtifact
from tests.composition.soc_generation_fixture import (
    ROOT, example_plan, profile_paths, request_path, tools_available,
    profile_tools_available,
)


def config():
    return {"root": str(ROOT), "config_id": "profile-production",
            "composition_request": str(request_path()),
            "component_profiles": [str(p) for p in profile_paths()],
            "drive_profile": "cpu_execute", "mode": "cpu_only"}


class ProfileAdmissionTest(unittest.TestCase):
    def test_peer_stimulus_fields_are_part_of_the_profile_rfuzz_abi(self):
        """Attached peers must be driven by the same raw word as the SoC top.

        The renderer already exports these request ports and the runtime already
        has peer slot metadata.  The profile RFuzz path must expose the same
        ports in its concrete layout; otherwise a persistent testbench leaves
        every peer request at its idle value.  Peer bits live after the image
        segment, and image projection must ignore them while preparing reset
        state.
        """
        from myfuzz.composition.component_profile import (
            load_component_profile, load_composition_request,
        )
        from myfuzz.composition.input_constraints import compile_input_constraints
        from myfuzz.composition.soc_composition import build_composition
        from myfuzz.composition.soc_image import build_image_plan, combined_input_layout

        profile_names = ("novacore", "novauart_link", "novaspi", "novagpio")
        profiles = {}
        for name in profile_names:
            path = ROOT / "examples" / "soc_generation" / "profiles" / f"{name}.json"
            profile = load_component_profile(path)
            profiles[str(path.relative_to(ROOT))] = profile
            profiles[profile.component_id] = profile
        request = load_composition_request(
            ROOT / "examples" / "soc_generation" / "request-peers.json",
            profiles=profiles)
        plan = build_composition(request, base_dir=ROOT)
        image = build_image_plan(plan)
        layout = combined_input_layout(plan, image)

        expected = {
            signal.top_port
            for peer in plan.peers
            for slot in peer.slots
            for signal in slot.signals
        }
        peer_fields = {
            field.port: field for field in layout.fields
            if field.owner == "soc_peer"
        }
        self.assertEqual(expected, set(peer_fields))
        self.assertTrue(peer_fields)
        self.assertTrue(all(field.raw_lo >= image.raw_width for field in peer_fields.values()))
        cursor = image.raw_width
        for field in sorted(peer_fields.values(), key=lambda item: item.raw_lo):
            self.assertEqual(cursor, field.raw_lo)
            cursor = field.raw_hi + 1
        self.assertEqual(layout.raw_width, cursor)

        policy = compile_input_constraints(plan, drive_profile="cpu_execute")
        projector = ProfileCampaignProjector(
            layout, policy.policy_hash, int(plan.raw_layout["raw_width"]),
            policy=policy, image_plan=image)
        peer_bit = min(peer_fields.values(), key=lambda field: field.raw_lo)
        raw = 1 << peer_bit.raw_lo
        self.assertEqual(raw, projector.project(raw))

    def test_peer_pulse_spacing_is_checked_before_profile_execution(self):
        """Raw peer requests must honor the model's declared minimum gap."""
        from myfuzz.composition.input_constraints import compile_input_constraints
        from myfuzz.composition.soc_image import build_image_plan, combined_input_layout
        from tests.integration.test_soc_peer_models import build_peer_plan

        plan = build_peer_plan(drive_profile="cpu_execute")
        image = build_image_plan(plan)
        layout = combined_input_layout(plan, image)
        policy = compile_input_constraints(plan, drive_profile="cpu_execute")
        uart = plan.peer("uart0")
        self.assertIsNotNone(uart)
        slot = next(item for item in uart.slots if item.slot == "uart.tx_byte")
        valid = next(signal for signal in slot.signals
                     if signal.source == "pulse")
        field = next(item for item in layout.fields if item.port == valid.top_port)
        projector = ProfileCampaignProjector(
            layout, policy.policy_hash, int(plan.raw_layout["raw_width"]),
            policy=policy, image_plan=image,
            peer_slots=({"instance_id": slot.instance_id, "slot": slot.slot,
                         "minimum_gap_cycles": slot.minimum_gap_cycles,
                         "pulse_ports": (valid.top_port,)},))
        raw = 1 << field.raw_lo
        with self.assertRaisesRegex(SocBuildError, "peer-event-gap-violation:uart0:uart.tx_byte"):
            projector.project_records([raw, raw])
        legal = projector.project_records([raw] + [0] * (slot.minimum_gap_cycles - 1) + [raw])
        self.assertEqual(raw, legal[0])
        self.assertEqual(raw, legal[-1])

    def test_peer_raw_fields_decode_to_replayable_event_evidence(self):
        """The profile ABI must retain the peer slot meaning, not only bits."""
        from myfuzz.composition.input_constraints import compile_input_constraints
        from myfuzz.composition.soc_image import build_image_plan, combined_input_layout
        from myfuzz.composition.soc_peer_replay import decode_peer_raw_events
        from tests.integration.test_soc_peer_models import build_peer_plan

        plan = build_peer_plan(drive_profile="cpu_execute")
        image = build_image_plan(plan)
        layout = combined_input_layout(plan, image)
        policy = compile_input_constraints(plan, drive_profile="cpu_execute")
        slots = _peer_projection_slots(plan, layout)
        uart = next(item for item in slots
                     if item["instance_id"] == "uart0" and item["slot"] == "uart.tx_byte")
        signals = {item["source"]: item for item in uart["signals"]}
        def raw(payload: int) -> int:
            value = 0
            for source, part in (("pulse", 1), ("payload", payload)):
                signal = signals[source]
                value |= int(part) << int(signal["raw_lo"])
            return value

        # The UART contract in the fixture is 81 cycles apart.  The decoded
        # records are the evidence later persisted beside the raw corpus.
        values = [raw(0x31)] + [0] * 80 + [raw(0xA6)]
        events = decode_peer_raw_events(values, layout, slots)
        self.assertEqual(
            [(item["instance_id"], item["slot"], item["cycle"], item["payload"])
             for item in events],
            [("uart0", "uart.tx_byte", 0, 0x31),
             ("uart0", "uart.tx_byte", 81, 0xA6)],
        )
        # Projection does not discard the event evidence when it masks other
        # environment-owned bits.
        projector = ProfileCampaignProjector(
            layout, policy.policy_hash, int(plan.raw_layout["raw_width"]),
            policy=policy, image_plan=image, peer_slots=slots)
        projector.project_records(values)
        self.assertEqual(events, projector.last_peer_events)
        # The constraint-only arm has no image plan, but peer fields are still
        # environment-owned runtime inputs and must not be mistaken for a
        # forbidden dynamic image load.
        baseline = ProfileCampaignProjector(
            layout, policy.policy_hash, int(plan.raw_layout["raw_width"]),
            policy=policy, image_plan=None, peer_slots=slots)
        self.assertEqual(values, baseline.project_records(values))

    def test_peer_raw_event_decoder_rejects_stale_pulse_spacing(self):
        from myfuzz.composition.input_constraints import compile_input_constraints
        from myfuzz.composition.soc_image import build_image_plan, combined_input_layout
        from myfuzz.composition.soc_peer_replay import PeerRawReplayError, decode_peer_raw_events
        from tests.integration.test_soc_peer_models import build_peer_plan

        plan = build_peer_plan(drive_profile="cpu_execute")
        image = build_image_plan(plan)
        layout = combined_input_layout(plan, image)
        slots = _peer_projection_slots(plan, layout)
        uart = next(item for item in slots
                     if item["instance_id"] == "uart0" and item["slot"] == "uart.tx_byte")
        valid = next(item for item in uart["signals"] if item["source"] == "pulse")
        payload = next(item for item in uart["signals"] if item["source"] == "payload")
        raw = lambda value: (1 << int(valid["raw_lo"])) | (value << int(payload["raw_lo"]))
        with self.assertRaisesRegex(PeerRawReplayError, "peer-event-gap-violation:uart0:uart.tx_byte"):
            decode_peer_raw_events([raw(1), raw(2)], layout, slots)

    def test_special_sample_is_projected_by_the_compiled_policy(self):
        from myfuzz.composition.input_constraints import compile_rules
        from myfuzz.composition.input_layout import InputLayout, LayoutField
        layout = InputLayout("input_layout.v1", 8, (
            LayoutField("special", "cpu", "event", 4, 0, 3, "bits", {}),
            LayoutField("reserved_image", "soc_image", "data", 4, 4, 7, "bits", {}),
        ), "test-layout")
        policy = compile_rules([{
            "rule_id": "legal-special", "category": "environment_hard",
            "owner": "environment", "primitive": "value_enum", "phase": "sample",
            "fields": ["special"], "read_set": [], "write_set": ["special"],
            "raw_bits": [[0, 3]], "parameters": [["values", [2, 6]]],
            "basis": "test legal event values",
        }], drive_profile="cpu_execute", layout_hash="test-layout", plan_hash="test-plan")
        projector = ProfileCampaignProjector(layout, policy.policy_hash, 4, policy=policy)
        self.assertIn(projector.project(15), (2, 6))
        self.assertEqual(projector.project(2), 2)
        with self.assertRaisesRegex(SocBuildError, "dynamic-image-loading-unsupported"):
            projector.project(0x1f)

    def test_unknown_drive_profiles_are_refused_and_bfm_profiles_are_admitted(self):
        """The guard refuses unknown names, not the profiles the BFM now serves."""
        from myfuzz.integration.soc_builder import load_profile_campaign_request
        for profile in ("unknown", "bfm_isolated_typo", "cpu_only"):
            with self.subTest(profile=profile), tempfile.TemporaryDirectory() as directory:
                with self.assertRaisesRegex(SocBuildError, "profile-drive-unsupported"):
                    build_soc_campaign_artifact(dict(config(), drive_profile=profile),
                                                Path(directory) / "build")
        # A declared profile with another profile's mode is a contradiction.
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(SocBuildError, "profile-drive-mode-mismatch"):
                build_soc_campaign_artifact(
                    dict(config(), drive_profile="bfm_isolated", mode="cpu_only"),
                    Path(directory) / "build")
        # Both BFM profiles are admitted with their own declared mode.
        for profile, mode in (("bfm_isolated", "mmio_only"), ("contention", "mixed")):
            with self.subTest(profile=profile):
                request = load_profile_campaign_request(
                    dict(config(), drive_profile=profile, mode=mode), ROOT)
                self.assertEqual("cpu0", request.cpu.instance_id)

    def test_the_combined_layout_drives_the_bfm_raw_fields(self):
        """The RFuzz ABI must carry the synthetic master's raw request fields.

        Without them the harness would drive the master's inputs from its idle
        default and every BFM offer would be the constant zero offer.
        """
        from myfuzz.composition.soc_composition import build_composition
        from myfuzz.composition.soc_image import build_image_plan, combined_input_layout
        from myfuzz.composition.rfuzz_transport import build_rfuzz_transport
        from tests.composition.soc_generation_fixture import example_request
        for profile in ("bfm_isolated", "contention"):
            with self.subTest(profile=profile):
                plan = build_composition(example_request(), base_dir=ROOT,
                                         drive_profile=profile)
                image = build_image_plan(plan)
                layout = combined_input_layout(plan, image)
                fields = {field.field_id: field for field in layout.fields}
                for item in plan.synthetic["raw_ports"]:
                    field = fields[f"soc_stimulus:{item['port']}"]
                    self.assertEqual((int(item["raw_lo"]), int(item["raw_hi"]), str(item["name"])),
                                     (field.raw_lo, field.raw_hi, field.port))
                    self.assertGreater(field.width, 0)
                # The mapping stays total and contiguous, and the image segments
                # are placed after the reserved stimulus block.
                build_rfuzz_transport(layout)
                image_low = min(field.raw_lo for field in layout.fields
                                if str(field.owner) == "soc_image")
                self.assertGreater(image_low, max(int(item["raw_hi"])
                                                  for item in plan.synthetic["raw_ports"]))

    def test_profile_config_does_not_require_legacy_cpu_name(self):
        report = preflight_soc_campaign(config(), root=ROOT)
        self.assertEqual(report["cpu"], "cpu0")
        self.assertEqual(report["mode"], "cpu_only")


class ProfileToolchainAdmissionTest(unittest.TestCase):
    def _tool(self, directory: Path, name: str, version: str) -> Path:
        path = directory / name
        path.write_text("#!/bin/sh\nprintf '%s\\n' '" + version + "'\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def test_profile_builder_rejects_unpinned_verilator_version(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool = self._tool(root, "verilator", "Verilator 5.051 devel")
            with self.assertRaisesRegex(SocBuildError, "rfuzz-verilator-version-mismatch"):
                build_soc_campaign_artifact(
                    dict(config(), verilator=str(tool)), root / "build")

    def test_profile_builder_rejects_nested_verilator_conflict(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self._tool(root, "verilator-a", "Verilator 5.020")
            second = self._tool(root, "verilator-b", "Verilator 5.020")
            with self.assertRaisesRegex(SocBuildError, "rfuzz:conflict:verilator"):
                build_soc_campaign_artifact(
                    dict(config(), verilator=str(first),
                         rfuzz={"verilator": str(second)}), root / "build")


@unittest.skipUnless(profile_tools_available(), "bundled RFuzz Verilator 5.020 required for profile build")
class ProfileArtifactTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.plan = example_plan()
        cls.defaults = {}
        for instance in cls.plan.instances:
            for entry in instance.dispositions:
                if entry.disposition == "external" and entry.direction == "input":
                    suffix = "" if (entry.bit_lo, entry.bit_hi) == (0, entry.width - 1) else f"_{entry.bit_hi}_{entry.bit_lo}"
                    cls.defaults[f"{entry.instance_id}__{entry.port}{suffix}"] = 0
        cls.image = cls.directory / "boot.hex"
        cls.image.write_text("13\n00\n00\n00\n")
        cls.artifact = build_soc_campaign_artifact(
            dict(config(), external_input_defaults=cls.defaults, boot_image=str(cls.image)),
            cls.directory / "build")

    def test_persistent_protocol_two_executes_and_resets(self):
        self.assertIsInstance(self.artifact, SimulatorArtifact)
        simulator = RtlSimulator(self.artifact, timeout_seconds=30)
        try:
            records = [self.artifact.transport.pack(0)] * 12
            first = simulator.run_test(records)
            second = simulator.run_test(records)
            self.assertEqual(len(first), len(self.artifact.coverage_ports))
            self.assertTrue(any(first), "real DUT branches must feed RFuzz")
            self.assertEqual(first, second)
        finally:
            simulator.close()

    def test_provenance_records_profile_identity_and_unimplemented_segments(self):
        from myfuzz.composition.soc_image import build_image_plan, combined_input_layout
        directory = self.directory / "build"
        document = json.loads((directory / "artifact_provenance.json").read_text())
        self.assertEqual(document["composition_hash"], self.plan.plan_hash)
        self.assertEqual(document["layout_hash"], self.artifact.layout.layout_hash)
        self.assertTrue(document["policy_hash"])
        self.assertTrue((directory / "image_plan.json").is_file())
        self.assertEqual(document["tool"]["simulator_protocol_version"], 2)
        self.assertIn("multi_candidate_images", document["unsupported_capabilities"])
        audit = json.loads((directory / "soc_structure_audit.json").read_text())
        self.assertEqual("pass", audit["summary"]["status"])
        self.assertEqual("pass", document["structure_audit"]["status"])
        self.assertGreater(document["sources"]["source_count"], 0)
        self.assertTrue(document["sources"]["source_files"])
        combined = combined_input_layout(self.plan, build_image_plan(self.plan))
        self.assertEqual(self.artifact.layout, combined)

    def _image_candidate(self):
        from myfuzz.composition.soc_image import build_image_plan
        image = build_image_plan(self.plan)
        values = {"init_offer": 1, "init_address": image.entry_address,
                  "init_data": 0x00000013, "init_be": 15,
                  "data_offer": 1, "data_address": image.data_base,
                  "data_value": 0x1234abcd, "data_be": 15}
        return sum(value << image.segment(name).raw_lo for name, value in values.items())

    def test_dynamic_code_and_data_load_before_cpu_release(self):
        raw = self._image_candidate()
        self.assertEqual(self.artifact.projector.project(raw), raw)
        simulator = RtlSimulator(self.artifact, timeout_seconds=30)
        try:
            records = [self.artifact.transport.pack(raw)] + [self.artifact.transport.pack(0)] * 11
            simulator.run_test(records)
            diagnostics = "\n".join(simulator.last_diagnostics)
            self.assertIn("MYFUZZ_IMAGE kind=instruction addr=00010000 value=00000013 reset=0", diagnostics)
            self.assertIn("MYFUZZ_IMAGE kind=data addr=80000000 value=1234abcd reset=0", diagnostics)
        finally:
            simulator.close()

    def test_profile_build_cache_reuses_the_compiled_rtl_artifact(self):
        cache = self.directory / "profile-cache"
        first_dir = self.directory / "cached-first"
        second_dir = self.directory / "cached-second"
        options = dict(config(), external_input_defaults=self.defaults,
                       boot_image=str(self.image), build_cache_dir=str(cache))
        first = build_soc_campaign_artifact(options, first_dir)
        second = build_soc_campaign_artifact(options, second_dir)
        first_doc = json.loads((first_dir / "artifact_provenance.json").read_text())
        second_doc = json.loads((second_dir / "artifact_provenance.json").read_text())
        self.assertFalse(first_doc["cache_hit"])
        self.assertTrue(second_doc["cache_hit"])
        self.assertEqual(first_doc["cache_key"], second_doc["cache_key"])
        self.assertEqual(first_doc["executable_sha256"], second_doc["executable_sha256"])
        self.assertEqual("pass", second_doc["structure_audit"]["status"])
        self.assertTrue(second.executable.is_file())

    def test_dynamic_image_is_a_reset_restorable_test_local_base(self):
        text = (self.directory / "build" / "live_tb.sv").read_text()
        self.assertIn(".initial_memory[image_address", text)
        self.assertNotIn(".memory[image_address-32'd65536+image_lane]=", text)
        self.assertIn("repeat (1) tick(); // restore candidate image while CPU is held in reset", text)

    def test_addresses_are_repaired_with_explicit_strict_diagnostic_mode(self):
        image = self.artifact.projector.image_plan
        raw = self._image_candidate()
        for name in ("init_address", "data_address"):
            lo = image.segment(name).raw_lo
            raw = (raw & ~(0xffffffff << lo)) | (3 << lo)
        projector = self.artifact.projector
        before = projector.repair_counts.get("address_repair", 0)
        repaired = projector.project_records([raw])[0]
        self.assertEqual(repaired, projector.project_records([raw])[0])
        self.assertGreater(projector.repair_counts["address_repair"], before)
        image.materialize(repaired)
        strict = ProfileCampaignProjector(
            projector.layout, projector.constraint_hash, projector.special_width,
            policy=projector.policy, image_plan=image, image_address_policy="strict")
        with self.assertRaises((ValueError, SocBuildError)):
            strict.project(raw)

    def test_multiple_candidates_are_rejected_without_claiming_dependency_support(self):
        simulator = RtlSimulator(self.artifact, timeout_seconds=30)
        try:
            record = self.artifact.transport.pack(self._image_candidate())
            with self.assertRaisesRegex(SocBuildError, "multiple-image-candidates-unsupported"):
                simulator.run_test([record, record])
        finally:
            simulator.close()


@unittest.skipUnless(profile_tools_available(), "bundled RFuzz Verilator 5.020 required for profile build")
class MultiCandidateImageArtifactTest(unittest.TestCase):
    """Roadmap item 3 on real RTL: several declared candidates per test.

    The plan declares three instruction slots; the build publishes the declared
    program's static image as the fixed boot image, and one test overlays three
    candidates into the memory model's ``initial_memory`` while the CPU is held
    in reset.  The memory model's own readback (``MYFUZZ_IMAGE`` lines) is the
    evidence that N independent per-test overlays really land -- and that a
    candidate which would rewrite a slot the test already committed is refused
    instead of applied.
    """

    SLOTS = 3

    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix=".myfuzz-multicandidate-",
                                                    dir=ROOT)
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.plan = example_plan()
        cls.defaults = {}
        for instance in cls.plan.instances:
            for entry in instance.dispositions:
                if entry.disposition == "external" and entry.direction == "input":
                    suffix = "" if (entry.bit_lo, entry.bit_hi) == (0, entry.width - 1) \
                        else f"_{entry.bit_hi}_{entry.bit_lo}"
                    cls.defaults[f"{entry.instance_id}__{entry.port}{suffix}"] = 0
        # No boot_image: the declared candidate program *is* the fixed image.
        cls.artifact = build_soc_campaign_artifact(
            dict(config(), external_input_defaults=cls.defaults,
                 instruction_candidates=cls.SLOTS),
            cls.directory / "build")
        cls.program = cls.artifact.projector.candidate_program

    def records(self, words):
        return [self.artifact.transport.pack(word) for word in words]

    def candidate(self, prefix, *, word=0x00000013, address=None):
        """One fuzz word that offers exactly one declared slot."""
        slot = self.program.slots.slot(prefix)
        value = 1 << slot.segment("offer").raw_lo
        value |= (slot.declared_address if address is None else address) \
            << slot.segment("address").raw_lo
        value |= word << slot.segment("data").raw_lo
        value |= 0xF << slot.segment("be").raw_lo
        return value

    def test_the_build_declares_the_program_and_withdraws_the_gap(self):
        directory = self.directory / "build"
        document = json.loads((directory / "artifact_provenance.json").read_text())
        self.assertNotIn("multi_candidate_images", document["unsupported_capabilities"])
        self.assertNotIn("general_dependency_repair", document["unsupported_capabilities"])
        self.assertIn("compressed_instruction_images", document["unsupported_capabilities"])
        self.assertEqual(self.SLOTS,
                         document["candidate_program"]["instruction_candidates"])
        self.assertEqual(1, document["candidate_program"]["data_candidates"])
        self.assertTrue((directory / "candidate_program.json").is_file())
        # The published fixed image is the declared program's static image.
        static = self.program.static_image()
        text = (directory / "boot_image.hex").read_text(encoding="utf-8")
        self.assertEqual("".join(f"{byte:02x}\n" for byte in static), text)

    def test_three_candidates_really_land_in_the_memory_model(self):
        names = ["init", "init1", "init2"]
        words = [self.candidate(name) for name in names]
        simulator = RtlSimulator(self.artifact, timeout_seconds=60)
        try:
            simulator.run_test(self.records(words))
            diagnostics = "\n".join(simulator.last_diagnostics)
        finally:
            simulator.close()
        for name in names:
            slot = self.program.slots.slot(name)
            self.assertIn(
                "MYFUZZ_IMAGE kind=instruction addr=%08x value=00000013 reset=0 slot=%s"
                % (slot.declared_address, name), diagnostics)
        self.assertEqual(self.SLOTS, diagnostics.count("MYFUZZ_IMAGE"))

    def data_candidate(self, *, value=0x1234ABCD, address=None):
        """One fuzz word that offers the declared data slot."""
        program = self.program
        slot = program.slots.slot("data")
        offer = 1 << slot.segment("offer").raw_lo
        offer |= (slot.declared_address if address is None else address) \
            << slot.segment("address").raw_lo
        offer |= value << slot.segment("value").raw_lo
        offer |= 0xF << slot.segment("be").raw_lo
        return offer

    def test_a_data_candidate_is_frozen_into_the_writable_memory_model(self):
        words = [self.candidate("init"), self.candidate("init1"),
                 self.candidate("init2"), self.data_candidate()]
        slot = self.program.slots.slot("data")
        simulator = RtlSimulator(self.artifact, timeout_seconds=60)
        try:
            simulator.run_test(self.records(words))
            diagnostics = "\n".join(simulator.last_diagnostics)
        finally:
            simulator.close()
        self.assertIn("MYFUZZ_IMAGE kind=data addr=%08x value=1234abcd reset=0 slot=data"
                      % slot.declared_address, diagnostics)

    def test_an_address_the_fuzzer_chose_is_repaired_to_the_declared_slot(self):
        words = [self.candidate("init", address=3), self.candidate("init1"),
                 self.candidate("init2")]
        projector = self.artifact.projector
        before = projector.repair_counts.get("address_repair", 0)
        projected = projector.project_records(words)
        self.assertGreater(projector.repair_counts["address_repair"], before)
        slot = self.program.slots.slot("init")
        self.assertEqual(slot.declared_address,
                         slot.segment("address").extract(projected[0]))
        simulator = RtlSimulator(self.artifact, timeout_seconds=60)
        try:
            simulator.run_test(self.records(projected))
            diagnostics = "\n".join(simulator.last_diagnostics)
        finally:
            simulator.close()
        self.assertIn("MYFUZZ_IMAGE kind=instruction addr=%08x value=00000013 reset=0 "
                      "slot=init" % slot.declared_address, diagnostics)

    def test_a_candidate_that_would_rewrite_a_committed_slot_is_refused(self):
        words = [self.candidate("init"), self.candidate("init", word=0x00000013),
                 self.candidate("init1"), self.candidate("init2")]
        slot = self.program.slots.slot("init")
        simulator = RtlSimulator(self.artifact, timeout_seconds=60)
        try:
            with self.assertRaisesRegex(
                    SocBuildError,
                    "repair-would-rewrite-committed-word:init:0x%08x"
                    % slot.declared_address):
                simulator.run_test(self.records(words))
        finally:
            simulator.close()

    def test_a_test_with_an_empty_declared_slot_is_refused(self):
        simulator = RtlSimulator(self.artifact, timeout_seconds=60)
        try:
            with self.assertRaisesRegex(SocBuildError,
                                        "candidate-slot-not-offered:init1"):
                simulator.run_test(self.records([self.candidate("init")]))
        finally:
            simulator.close()


@unittest.skipUnless(profile_tools_available(), "bundled RFuzz Verilator 5.020 required for profile build")
class BfmProfileArtifactTest(unittest.TestCase):
    """A BFM profile really builds, and its raw request reaches the RTL."""

    @classmethod
    def setUpClass(cls):
        from myfuzz.composition.soc_composition import build_composition
        from tests.composition.soc_generation_fixture import example_request
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.image = cls.directory / "boot.hex"
        cls.image.write_text("13\n00\n00\n00\n")
        cls.plan = build_composition(example_request(), base_dir=ROOT,
                                     drive_profile="bfm_isolated")
        cls.artifact = build_soc_campaign_artifact(
            dict(config(), drive_profile="bfm_isolated", mode="mmio_only",
                 external_input_defaults={"gpio0__gpio_in_i": 0, "uart0__uart_rx_i": 0,
                                          "uart1__uart_rx_i": 0},
                 boot_image=str(cls.image)),
            cls.directory / "bfm-build")

    def _raw(self, **fields):
        layout = {field.role: field for field in self.artifact.layout.fields
                  if str(field.owner) == "soc_stimulus" and str(field.role) != "reserved"}
        value = 0
        for role, raw in fields.items():
            field = layout[role]
            value |= (int(raw) & ((1 << field.width) - 1)) << field.raw_lo
        return value

    def test_the_bfm_build_is_admitted_audited_and_transport_driven(self):
        document = json.loads(
            (self.directory / "bfm-build" / "artifact_provenance.json").read_text())
        self.assertEqual("bfm_isolated", document["drive_profile"])
        self.assertEqual("mmio_only", document["mode"])
        self.assertEqual("pass", document["structure_audit"]["status"])
        self.assertNotIn("bfm_isolated", document["unsupported_capabilities"])
        text = (self.directory / "bfm-build" / "live_tb.sv").read_text()
        for field in self.artifact.layout.fields:
            if str(field.owner) != "soc_stimulus" or str(field.role) == "reserved":
                continue
            if field.raw_lo == field.raw_hi:
                self.assertIn(f"assign {field.port} = raw_bits[{field.raw_lo}];", text)
            else:
                self.assertIn(f"assign {field.port} = raw_bits[{field.raw_hi}:{field.raw_lo}];",
                              text)
        # Every projection arm is available over this one build.
        self.assertEqual({"direct_input", "constrained_baseline", "dependency_repair"},
                         set(self.artifact.projection_arms))

    def test_a_bfm_offer_changes_the_real_rtl_feedback(self):
        bases = [int(value) for value in self.plan.synthetic["parameters"]["WINDOW_BASE"]]
        selector = bases.index(0x4000_0000)
        offer = self._raw(stim_offer=1, stim_target_selector=selector,
                          stim_offset=0x4000_0000, stim_write=1, stim_wdata=0x5A,
                          stim_be=0xF)
        simulator = RtlSimulator(self.artifact, timeout_seconds=30)
        try:
            zero = simulator.run_test([self.artifact.transport.pack(0)] * 8)
            driven = simulator.run_test([self.artifact.transport.pack(offer)] * 8)
        finally:
            simulator.close()
        self.assertNotEqual(bytes(zero), bytes(driven),
                            "the BFM inputs are driven as zero: the offer had no effect")
        self.assertGreater(sum(1 for value in driven if value),
                           sum(1 for value in zero if value))


if __name__ == "__main__":
    unittest.main()
