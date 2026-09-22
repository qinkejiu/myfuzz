"""The declared candidate program on real RTL: several candidates, a generated
prologue, a projected jump and a store-before-load dependency, all executed.

The composition-level tests prove the declarations; this module proves the
*program*: it composes the real pinned Ibex (``examples/soc_generation/
request-ibex.json``), declares a seven-slot candidate program over that plan,
freezes the composed image and runs it through ``soc_runtime`` with the real
Verilator binary.  The CPU's own stores into RAM are the evidence:

* slot 0 sets a scratch register, slot 1 stores it (the prologue's declared
  ``x3`` data base is what makes that store land in RAM at all),
* slot 2 loads those bytes back and slot 3 stores the loaded value, which is the
  store-before-load dependency satisfied by the declared order,
* slot 4 is a jump whose *raw* target is outside the declared program window and
  is projected onto slot 6, so slot 5 (a store of a different value into a third
  word) must not execute and slot 6 must,
* the RAM words the run reads back are exactly those four outcomes.

``MYFUZZ_SOC_REAL=1`` gates the real build; when the flag is set nothing skips
and a missing dependency fails naming it.  The build is cached under
``runs/soc-input-repair-runtime/<plan-prefix>/`` and the run's observation
record is written there, so the replay compares a real execution with the saved
one instead of re-describing it.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import time
import unittest
from pathlib import Path

from myfuzz.composition.component_profile import (
    load_component_profile,
    load_composition_request,
)
from myfuzz.composition.soc_candidate_program import (
    CandidateProgramError,
    CandidateProgramPolicy,
    build_candidate_program,
    encode_addi,
    encode_jal,
    encode_lw,
    encode_sw,
    project_address,
)
from myfuzz.composition.soc_composition import build_composition
from myfuzz.composition.soc_profile_renderer import render_composition, source_list
from myfuzz.composition.soc_runtime import (
    RuntimeBuild,
    RuntimeSample,
    SocRuntimeError,
    build_profile_runtime,
    run_sample,
)

ROOT = Path(__file__).resolve().parents[2]
OPT_IN = os.environ.get("MYFUZZ_SOC_REAL") == "1"
OUTPUT_ROOT = ROOT / "runs/soc-input-repair-runtime"
REQUEST_FILE = "examples/soc_generation/request-ibex.json"
CPU_PROFILE = "configs/cpus/ibex/component_profile.json"
RUN_SCHEMA = "soc_input_repair_run.v1"

#: The declared program: seven instruction slots and one data slot.
SLOTS = 7
DATA_OFFSET = 0x80
CYCLES = 400
RAM_BASE = 0x8000_0000

_MEMORY_KEY = re.compile(r"^u_mem_(\d+)\[(\d+)\]$")

#: The word offsets the program writes and the value it writes there.
SCRATCH_WORD = 0x40          # slot 1: the value slot 0 put in a register
DEPENDENT_WORD = 0x48        # slot 3: the value slot 2 loaded back
POISON_WORD = 0x44           # slot 5: must stay zero (the jump skips it)
LANDING_WORD = 0x4C          # slot 6: proves where the projected jump landed
SCRATCH_VALUE = 0x123


def _plan():
    profiles: dict = {}
    document = json.loads((ROOT / REQUEST_FILE).read_text(encoding="utf-8"))
    references = [document["cpu"]["profile"]] + [item["profile"]
                                                 for item in document["peripherals"]]
    for relative in sorted(set(references) | {CPU_PROFILE}):
        profile = load_component_profile(ROOT / relative)
        profiles[relative] = profile
        profiles.setdefault(profile.component_id, profile)
    request = load_composition_request(document, profiles=profiles)
    return build_composition(request, base_dir=ROOT)


def _program(plan):
    return build_candidate_program(
        plan, instruction_candidates=SLOTS, data_candidates=1,
        policy=CandidateProgramPolicy(data_slot_offset=DATA_OFFSET))


def _raw_jump_target(window: int, size: int, slot: int) -> int:
    """A raw target outside the window whose projection lands on ``slot``."""
    slots = size // 4
    target = window + size + 4 * slot
    while project_address(target, window, size) != window + 4 * slot:
        target += 4
    return target


def _directed(program, *, landing: int = SLOTS - 1) -> dict[str, int]:
    """The declared program, one exact instruction word per slot."""
    window, size = program.window()
    data_base = int(program.register_bindings["data_base"]["value"])
    jump_slot = 4
    raw = _raw_jump_target(window, size, landing)
    words = {
        "init": encode_addi(5, 0, SCRATCH_VALUE),
        "init1": encode_sw(5, 3, SCRATCH_WORD),
        "init2": encode_lw(6, 3, SCRATCH_WORD),
        "init3": encode_sw(6, 3, DEPENDENT_WORD),
        "init4": encode_jal(0, raw - (window + 4 * jump_slot)),
        "init5": encode_sw(5, 3, POISON_WORD),
        "init6": encode_sw(5, 3, LANDING_WORD),
    }
    assert data_base == RAM_BASE
    return words


def _ram_word(result, instance: int, address: int) -> int:
    offset = address - RAM_BASE
    index, lane = divmod(offset, 8)
    key = f"u_mem_{instance}[{index}]"
    if key not in result.observations:
        raise AssertionError(f"the run read back no {key}")
    return (int(result.observations[key]) >> (lane * 8)) & 0xFFFF_FFFF


def _raw_request(program, *, word: int = 0x00000013) -> list[int]:
    """One fuzz word per declared instruction slot, each offering its slot.

    ``0x00000013`` (``addi x0, x0, 0``) is a fixed point of the reference ISA
    repair, so this request is the fuzz channel with a deterministic placement.
    """
    request = []
    for slot in program.slots.instruction:
        value = 1 << slot.segment("offer").raw_lo
        value |= slot.declared_address << slot.segment("address").raw_lo
        value |= word << slot.segment("data").raw_lo
        value |= 0xF << slot.segment("be").raw_lo
        request.append(value)
    return request


def _memory_index(plan, region_id: str) -> int:
    """The fabric target index (``u_mem_<index>``) of one declared region."""
    for row in plan.plan["fabric"]["decode"]["windows"]:
        if str(row["window_id"]) == region_id:
            return int(row["target_index"])
    raise AssertionError(f"no decoded window backs {region_id}")


def _build(plan, image: Path) -> RuntimeBuild:
    """Compile the composition once, caching the build under ``runs/``."""
    key = str(plan.plan_hash).split(":", 1)[-1][:16]
    directory = OUTPUT_ROOT / key
    record = directory / "runtime_build.json"
    if record.is_file():
        try:
            document = json.loads(record.read_text(encoding="utf-8"))
        except ValueError:
            document = {}
        recorded_image = document.get("boot_image_abs")
        if document.get("plan_hash") == plan.plan_hash and recorded_image \
                and Path(recorded_image).is_file():
            build = _build_from_document(directory, document["build"],
                                         boot_image=Path(recorded_image))
            if build.executable.is_file():
                return build
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True, exist_ok=True)
    files = render_composition(plan)
    records = source_list(plan)
    sources = [item["path"] for item in records if item["role"] != "include_root"]
    include_roots = sorted({item["path"] for item in records
                            if item["role"] == "include_root"})
    verilator = shutil.which("verilator")
    if verilator is None:
        raise AssertionError("Verilator is required for the real candidate-program run")
    tool = verilator
    flags = [f"-I{ROOT / item}" for item in include_roots]
    for instance in plan.instances:
        elaboration = getattr(instance.profile.source, "elaboration", None)
        for name, value in getattr(elaboration, "defines", ()) or ():
            flags.append(f"-D{name}={value}")
    if flags:
        wrapper = directory / "verilator_with_profile_flags.sh"
        wrapper.write_text("#!/bin/sh\nexec %s %s \"$@\"\n" % (verilator, " ".join(flags)),
                           encoding="utf-8")
        wrapper.chmod(0o755)
        tool = wrapper.as_posix()
    last: Exception | None = None
    for _attempt in (1, 2):
        try:
            build = build_profile_runtime(
                plan, output_dir=directory / "build", base_dir=ROOT,
                top_text=files["myfuzz_soc_top.sv"], sources=sources,
                boot_image=image, verilator=tool)
            break
        except SocRuntimeError as error:
            last = error
            if "runtime-build-failed" not in str(error):
                raise
            shutil.rmtree(directory / "build", ignore_errors=True)
    else:
        raise last  # type: ignore[misc]
    record.write_text(json.dumps({
        "schema_version": RUN_SCHEMA, "plan_hash": plan.plan_hash,
        "image_hash": _file_hash(image), "boot_image_abs": str(image),
        "build": build.document()}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return build


def _recorded_path(output: Path, value: object) -> Path:
    """Resolve one path from a build record against the build directory.

    A record stores paths relative to its build directory, and the executable
    really lives under ``obj_dir``.  The bare-basename form written by an older
    revision is only accepted when the plain join does not exist, so a legacy
    record cannot make this cache silently replay nothing.
    """
    candidate = output / str(value)
    if candidate.exists():
        return candidate
    nested = output / "obj_dir" / str(value)
    return nested if nested.exists() else candidate


def _build_from_document(directory: Path, document: dict, *,
                         boot_image: Path | None = None) -> RuntimeBuild:
    output = directory / "build"
    boot = document.get("boot_image")
    if boot_image is not None:
        resolved = Path(boot_image)
    elif boot is None:
        resolved = None
    else:
        resolved = output / str(boot)
    return RuntimeBuild(
        output_dir=output, top_path=_recorded_path(output, document["top"]),
        testbench_path=_recorded_path(output, document["testbench"]),
        executable=_recorded_path(output, document["executable"]),
        sources=tuple(str(item) for item in document.get("sources", ())),
        raw_width=int(document["raw_width"]),
        slots=tuple(dict(item) for item in document.get("slots", ())),
        observations=tuple(dict(item) for item in document.get("observations", ())),
        boot_image=resolved,
        boot_image_policy=str(document.get("boot_image_policy", "")),
        build_hash=str(document["build_hash"]), warnings=int(document.get("warnings", 0)))


def _file_hash(path: Path) -> str:
    import hashlib
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real candidate-program run")
class SocInputRepairRuntimeTests(unittest.TestCase):
    """The declared candidate program really runs on the real pinned CPU."""

    @classmethod
    def setUpClass(cls):
        cls.started = time.monotonic()
        cls.blocker: str | None = None
        try:
            cls._prepare()
        except Exception as error:                     # noqa: BLE001 - reported verbatim
            cls.blocker = f"{type(error).__name__}: {error}"

    @classmethod
    def _prepare(cls) -> None:
        if shutil.which("verilator") is None:
            raise AssertionError("Verilator is required for the real candidate-program run")
        cls.plan = _plan()
        cls.program = _program(cls.plan)
        cls.directed = _directed(cls.program)
        cls.repaired = cls.program.repairer().repair_test([], directed=cls.directed)
        cls.fuzz_request = _raw_request(cls.program)
        cls.ram_instance = _memory_index(cls.plan, "ram0")
        cls.rom_instance = _memory_index(cls.plan, "rom0")
        OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
        # One fixed image path: the generated testbench embeds the ``+riscv_boot_image``
        # plusarg, so a different image at the same path is a new run of the same
        # compiled build -- which is what makes a mutation check cheap.
        cls.image = OUTPUT_ROOT / "candidate_program.hex"
        cls.program.image.write_hex(cls.repaired.image.image, cls.image)
        cls.build = _build(cls.plan, cls.image)
        cls.sample = RuntimeSample(request_id=0x1CE_B00C, raw=(0,) * CYCLES)
        started = time.monotonic()
        cls.result = run_sample(cls.build, cls.sample)
        cls.run_seconds = time.monotonic() - started
        cls.document = {
            "schema_version": RUN_SCHEMA,
            "plan_hash": cls.plan.plan_hash,
            "program_hash": cls.program.document()["static_image"]["content_hash"],
            "program": {
                "program_base": cls.program.program_base,
                "program_size": cls.program.program_size,
                "prologue_words": len(cls.program.prologue_words),
                "register_bindings": {name: int(binding["value"]) for name, binding
                                      in cls.program.register_bindings.items()},
                "slots": [slot.document() for slot in cls.program.slots.slots()],
            },
            "test": cls.repaired.document(),
            "image_hash": cls.repaired.image.content_hash,
            "build_hash": cls.build.build_hash,
            "ram_instance": cls.ram_instance,
            "run": cls.result.document(),
        }
        directory = OUTPUT_ROOT / f"run-{cls.program.program_base:08x}"
        directory.mkdir(parents=True, exist_ok=True)
        cls.record_path = directory / "run.json"
        cls.record_path.write_text(
            json.dumps(cls.document, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        if cls.blocker is None:
            print("\nMYFUZZ_SOC_INPUT_REPAIR_TIMING slots=%d program_base=0x%08x "
                  "run_s=%.2f wall_s=%.1f image_bytes=%d"
                  % (SLOTS, cls.program.program_base, cls.run_seconds,
                     time.monotonic() - cls.started, len(cls.repaired.image.image)))

    def setUp(self):
        if self.blocker is not None:
            self.fail("the candidate-program run could not be prepared: %s" % self.blocker)

    # -- helpers -----------------------------------------------------------

    def ram_word(self, address: int, result=None) -> int:
        """One 32-bit RAM word out of a run's own hierarchical readback."""
        return _ram_word(self.result if result is None else result,
                         self.ram_instance, address)

    def run_image(self, image: bytes):
        """Run exactly these image bytes on the compiled build, then restore it.

        The generated testbench embeds the image *path*, so overwriting the file
        runs a different program without recompiling anything.
        """
        original = self.image.read_bytes()
        try:
            self.program.image.write_hex(image, self.image)
            return run_sample(self.build, self.sample)
        finally:
            self.image.write_bytes(original)

    # -- the positive run --------------------------------------------------

    def test_the_run_completes_and_executes_cycles(self) -> None:
        self.assertEqual("OK", self.result.status, self.result.reason)
        self.assertGreater(self.result.cycles, 0)

    def test_every_declared_slot_is_placed_at_its_declared_address(self) -> None:
        placements = {item["slot"]: item for item in self.repaired.placements}
        self.assertEqual(SLOTS, self.repaired.counters["instruction_slots_placed"])
        for slot in self.program.slots.instruction:
            self.assertEqual(slot.declared_address,
                             placements[slot.prefix]["declared_address"])
        # The frozen image really carries the placed words.
        rom = self.repaired.image.region_images["rom0"]
        for slot in self.program.slots.instruction:
            offset = slot.declared_address - self.program.image.base
            word = int(placements[slot.prefix]["word_value"])
            self.assertEqual(word.to_bytes(4, "little"), rom[offset:offset + 4],
                             f"image disagrees with the placement of {slot.prefix}")

    def test_the_prologue_base_register_makes_the_store_land_in_ram(self) -> None:
        """Without the generated x3 data base the store could not reach RAM."""
        self.assertEqual(SCRATCH_VALUE, self.ram_word(RAM_BASE + SCRATCH_WORD))
        binding = self.program.register_bindings["data_base"]
        self.assertEqual(RAM_BASE, int(binding["value"]))
        self.assertEqual(3, int(binding["register"]))

    def test_the_store_before_load_dependency_really_ordered_the_accesses(self) -> None:
        edge = next(item for item in self.repaired.dependencies
                    if item.kind == "store-before-load")
        self.assertEqual("satisfied", edge.status)
        self.assertEqual(SCRATCH_VALUE, edge.value)
        # Slot 3 stored what slot 2 loaded from the bytes slot 1 wrote.
        self.assertEqual(SCRATCH_VALUE, self.ram_word(RAM_BASE + DEPENDENT_WORD))

    def test_the_projected_jump_skipped_one_slot_and_landed_on_another(self) -> None:
        records = [item for item in self.repaired.records if item.kind == "target"]
        self.assertEqual(1, len(records))
        window, size = self.program.window()
        self.assertFalse(window <= records[0].before < window + size,
                         "the raw target was already inside the declared window")
        self.assertEqual(self.program.program_base + 4 * (SLOTS - 1), records[0].after)
        self.assertEqual(1, self.repaired.counters["target_repair"])
        # The skipped slot's store did not execute ...
        self.assertEqual(0, self.ram_word(RAM_BASE + POISON_WORD))
        # ... and the slot the projection landed on did.
        self.assertEqual(SCRATCH_VALUE, self.ram_word(RAM_BASE + LANDING_WORD))

    def test_the_declared_image_is_the_one_the_memory_model_loaded(self) -> None:
        """The ROM readback agrees with the frozen image the composer wrote."""
        rom = self.repaired.image.region_images["rom0"]
        for word_index in range(4):
            key = f"u_mem_{self.rom_instance}[{word_index}]"
            if key not in self.result.observations:
                continue
            observed = int(self.result.observations[key])
            expected = int.from_bytes(rom[word_index * 8:(word_index + 1) * 8], "little")
            self.assertEqual(expected, observed, key)

    def test_the_harness_discriminates_a_different_projection(self) -> None:
        """A mutation check: the same build really reports a different program.

        The only change is the raw jump target, which now projects onto the
        poison slot instead of the landing slot.  If the run could not tell the
        two apart, every assertion above would be vacuous.
        """
        mutated = self.program.repairer().repair_test(
            [], directed=_directed(self.program, landing=5))
        result = self.run_image(mutated.image.image)
        self.assertEqual("OK", result.status, result.reason)
        # The poison slot really ran in this image (it is zero in the declared
        # one), and the slot after it was reached by fall-through.
        self.assertEqual(SCRATCH_VALUE, self.ram_word(RAM_BASE + POISON_WORD, result))
        self.assertEqual(SCRATCH_VALUE, self.ram_word(RAM_BASE + LANDING_WORD, result))
        self.assertEqual(0, self.ram_word(RAM_BASE + POISON_WORD))

    # -- replay ------------------------------------------------------------

    def test_the_recorded_run_replays_to_the_same_observations(self) -> None:
        self.assertTrue(self.record_path.is_file())
        recorded = json.loads(self.record_path.read_text(encoding="utf-8"))
        self.assertEqual(recorded["run"]["observations"],
                         self.result.document()["observations"])
        replay = run_sample(self.build, self.sample)
        self.assertEqual(recorded["run"]["observations"],
                         replay.document()["observations"])
        self.assertEqual(recorded["run"]["applied_trace"],
                         replay.document()["applied_trace"])
        self.assertEqual(recorded["image_hash"], self.repaired.image.content_hash)

    # -- negatives ---------------------------------------------------------

    def projector(self):
        """The campaign projector that places tests through this program."""
        from myfuzz.integration.soc_builder import ProfileCampaignProjector

        return ProfileCampaignProjector(
            None, "test", 0, policy=None, image_plan=self.program.image,
            candidate_program=self.program)

    def test_the_campaign_projector_places_the_declared_program(self) -> None:
        """The integration path really uses the declared program, not a copy."""
        processor = self.projector()
        projected = processor.project_records(self.fuzz_request)
        self.assertEqual(len(self.program.slots.instruction), len(projected))
        for slot, word in zip(self.program.slots.instruction, projected):
            self.assertEqual(slot.declared_address,
                             slot.segment("address").extract(word))
            self.assertEqual(1, slot.segment("offer").extract(word))
        self.assertIsNotNone(processor.last_repaired_test)
        self.assertEqual(len(self.program.slots.instruction),
                         processor.last_repaired_test.counters["slots_placed"])

    def test_the_runtime_projection_refuses_a_committed_slot_rewrite(self) -> None:
        """The declared program's committed-input rule reaches the projector."""
        from myfuzz.integration.soc_builder import SocBuildError

        request = [self.fuzz_request[0], self.fuzz_request[0]]
        slot = self.program.slots.slot("init")
        with self.assertRaises(SocBuildError) as caught:
            self.projector().project_records(request)
        self.assertEqual(
            f"repair-would-rewrite-committed-word:init:0x{slot.declared_address:08x}",
            str(caught.exception))

    def test_a_declared_refusal_keeps_its_exact_name_on_the_runtime_path(self) -> None:
        from myfuzz.integration.soc_builder import SocBuildError

        directed = dict(self.directed)
        directed["init1"] = encode_lw(6, 31, 0)          # x31 is never established
        with self.assertRaises(CandidateProgramError) as caught:
            self.program.repairer().repair_test([], directed=directed)
        self.assertEqual("candidate-base-register-unset:x31", str(caught.exception))
        # A test that does not offer every declared slot is refused, with its own
        # name, before any RTL is driven.
        with self.assertRaises(SocBuildError) as wrapped:
            self.projector().project_records([self.fuzz_request[0]])
        self.assertEqual("candidate-slot-not-offered:init1", str(wrapped.exception))


if __name__ == "__main__":
    unittest.main()
