"""Task 6 minimal bootstrap: the legal online missing slot without the forbidden boots.

The plan's first Task-6 bullet asks for a code-owned minimal bootstrap that
reaches the legal online missing slot without writing DIR/OUT/GPIOEN/B.INTEN,
with a fixed selector identity and no PC/waiting/epoch assignment.  Root's
recorded D2 decision keeps ``gpio_a`` GPIOEN (the shipped online checker reads it
before it verifies A PADOUT writes) and keeps the fixed CSR/INTTYPE words the
recorded post-read arming path needs, and moves B's arm out of the bootstrap.
Everything here is software construction plus one real bounded Popen lifecycle;
no RTL, build or native execution.

The restated observability claim (never the original wording): the fixed ISR
bytes remain present in the fixture and are executed once a recorded case arms B
through the register-program channel.  A native gate is the only place that can
claim the execution.
"""
import contextlib
import hashlib
import json

import pytest

from myfuzz.integration import ibex_pulp_register_replay as api
from myfuzz.scenario import ibex_pulp_dual_source as fixture
from myfuzz.scenario.ibex_pulp_dual_source import (
    IBEX_STREAM_CPU_PROGRAM, make_ibex_pulp_dual_source_stream_bootstrap)
from myfuzz.scenario.session_runtime import ScenarioSession
from tests.scenario.test_register_alias_verifier import alias_factory

#: The byte-exact regression guard of the shipped firmware, copied from
#: tests/integration/test_cv32e40p_pulp_online_factory.py:28-36.  The minimal
#: variant must leave every one of these bytes untouched (default-off).
SHIPPED_IMAGE_SHA256 = {
    "cpu.stream.bootstrap": "51e344aca5262f86996969b317b31373232521311fb9eb3e8ff5844d31b23b2c",
    "cpu.stream.direct_vector": "f80ee57d28f7fc8f2f649e9c9dd27f7702f26d9406da6a5a8684c92ac0f8fa83",
    "cpu.stream.external_vector": "60c4deba81bd29487b64f5d91b848d8096cb301f30881348ae312c20a7db5078",
    "cpu.stream.isr": "4f07e4a5d2905dcd796fd6fec08fefb99e110d900ca4cc21b5946d8b2bc0e21d",
    "cpu.stream.end": "77df2fdd2f4ec9dfb8ba23140df8696a3247b6e5c439566dabb84120d3bcfca9",
}
#: The one fixed handler image whose bytes the minimal variant must preserve.
ISR_IMAGE_ID = "cpu.stream.isr"
BOOT_IMAGE_ID = fixture.STREAM_BOOTSTRAP_IMAGE_ID
WINDOW_BASES = {device: base for device, base, *_ in fixture.dual_source_wiring().windows}


def _word(data, offset):
    return int.from_bytes(data[offset:offset + 4], "little")


def fixed_image(bootstrap, image_id):
    return next(image for image in bootstrap.template.initial_images
                if image.image_id == image_id)


def image_bytes(bootstrap, image_id):
    image = fixed_image(bootstrap, image_id)
    return image.address, bytes(image.data)


def decoded_stores(bootstrap):
    """Independent lui/addi/sw decode of one fixed boot image.

    Written here on purpose: the removal claim has to be recomputed from the
    produced bytes by the test, not trusted from the module under test.
    """
    image = fixed_image(bootstrap, BOOT_IMAGE_ID)
    registers = [0] * 32
    stores = []
    for offset in range(0, len(image.data), 4):
        word = _word(image.data, offset)
        opcode = word & 0x7F
        rd, rs1 = word >> 7 & 31, word >> 15 & 31
        if opcode == 0x37:
            registers[rd] = word & 0xFFFFF000
        elif opcode == 0x13:
            assert word >> 12 & 7 == 0
            immediate = word >> 20
            immediate -= 4096 if immediate & 2048 else 0
            registers[rd] = (registers[rs1] + immediate) & 0xFFFFFFFF
        elif opcode == 0x23:
            assert word >> 12 & 7 == 2
            immediate = ((word >> 25) << 5) | (word >> 7 & 31)
            immediate -= 4096 if immediate & 2048 else 0
            stores.append(((registers[rs1] + immediate) & 0xFFFFFFFF,
                           registers[word >> 20 & 31], image.address + offset))
        elif opcode in (0x73, 0x6F):  # csrrw/csrrs/jal: no memory effect in this decode
            continue
        else:
            raise AssertionError("unexpected fixed boot word " + hex(word))
        registers[0] = 0
    return stores


def removed_addresses(document):
    return {WINDOW_BASES[row["instance"]] + row["offset"]
            for row in document["removed_gpio_writes"]}


def test_minimal_bootstrap_declaration_binds_the_actual_fixture():
    bootstrap = fixture.make_ibex_pulp_dual_source_minimal_bootstrap()
    document = fixture.minimal_bootstrap_declaration(bootstrap)
    assert document["selector"] == fixture.MINIMAL_BOOTSTRAP_SELECTOR
    assert document["schema_version"] == fixture.MINIMAL_BOOTSTRAP_SCHEMA_VERSION
    assert document["cpu_program"]["first_fetch"] == IBEX_STREAM_CPU_PROGRAM.first_fetch
    assert (document["instruction_start"], document["instruction_end"]) == (
        bootstrap.instruction_start, bootstrap.instruction_end)
    # Actual initial images, hashed from the bytes the builder really produced.
    images = {row["image_id"]: row for row in document["images"]}
    assert set(images) == {image.image_id for image in bootstrap.template.initial_images}
    for image in bootstrap.template.initial_images:
        assert images[image.image_id] == dict(
            image_id=image.image_id, address=image.address, byte_count=len(image.data),
            sha256=hashlib.sha256(image.data).hexdigest())
    # Memory slot permissions: the exact reservation the assembly declares.
    assert document["instruction_slots"] == [
        ["cpu", bootstrap.instruction_start, bootstrap.instruction_count]]
    boot = fixed_image(bootstrap, BOOT_IMAGE_ID)
    assert document["initial_ram_window"]["base"] == boot.address + len(boot.data)
    assert document["initial_ram_window"]["byte_count"] == 0x10100 - (boot.address + len(boot.data))
    assert document["initial_ram_window"]["byte_count"] == 52
    # Shiped cross-case source-action policy and result-slot policy, bound by value.
    assert document["source_action_declaration"]["component"] == "cpu"
    assert document["memory_policy_declaration"]["result_address"] == fixture.RESULT_ADDRESS
    # The declaration describes the fixture; it grants nothing.
    assert document["grants"] == dict(grants_storage=False, grants_version_dependency=False,
                                      grants_prerequisites=False, grants_functional=False)
    # Source closure: this module, the pinned register profile and its declared RTL.
    closure = {row["path"]: row["sha256"] for row in document["source_files"]}
    assert set(closure) == {"src/myfuzz/scenario/ibex_pulp_dual_source.py",
                            "configs/peripherals/pulp_gpio/component_profile.json",
                            "third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv"}
    assert closure["third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv"] == \
        "1e271914da4d25c87acd12121dde60a6ed955033870fd7a6730b2c9bafcbcaef"


def test_minimal_bootstrap_declaration_is_closed_and_recomputable():
    document = fixture.minimal_bootstrap_declaration()
    # A saved copy may only ever be compared: this one still matches current code ...
    saved = json.loads(json.dumps(document))
    assert fixture.validate_minimal_bootstrap_declaration(saved) == document
    # ... and every mutation of it is refused, so no saved document can select a
    # different fixture, a different image, or a shrunken reservation.
    for change in (
            {**saved, "selector": "ibex_pulp_dual_source.shipped_bootstrap"},
            {**saved, "instruction_slots": [["cpu", 0x11000, 1]]},
            {**saved, "instruction_start": 0x12000},
            {**saved, "images": saved["images"][:-1]},
            {**saved, "images": [{**saved["images"][0], "sha256": "0" * 64}] + saved["images"][1:]},
            {key: value for key, value in saved.items() if key != "removed_gpio_writes"},
            {**saved, "unexpected": 1}):
        with pytest.raises(ValueError):
            fixture.validate_minimal_bootstrap_declaration(change)


def test_minimal_bootstrap_removes_every_forbidden_boot_write():
    bootstrap = fixture.make_ibex_pulp_dual_source_minimal_bootstrap()
    document = fixture.minimal_bootstrap_declaration(bootstrap)
    forbidden = removed_addresses(document)
    # The forbidden list is instance-qualified: the plan's single word "GPIOEN" is two
    # writes, and the audit's correction 1 requires the selector to say which instance.
    assert {(row["instance"], row["register"], row["offset"], row["value"])
            for row in document["removed_gpio_writes"]} == {
        ("gpio_b", "GPIOEN", 0x04, 0x101), ("gpio_b", "INTEN", 0x18, 0x101),
        ("gpio_a", "PADDIR", 0x00, 0xFF), ("gpio_a", "PADOUT", 0x0C, 0x00)}
    assert forbidden == {0x40000004, 0x40000018, 0x40001000, 0x4000100C}
    # The shipped bootstrap really performs all four: the removal is a removal.
    assert {address for address, _, _ in
            decoded_stores(make_ibex_pulp_dual_source_stream_bootstrap())} >= forbidden
    stores = decoded_stores(bootstrap)
    assert stores == [(0x4000001C, 0x10001, 0x1008C), (0x40001004, 0xFF, 0x10098)]
    assert not {address for address, _, _ in stores} & forbidden
    # The retained set is exactly the two declared words, so it cannot grow silently.
    assert [(row["instance"], row["register"], row["offset"], row["value"])
            for row in document["gpio_writes"]] == [
        ("gpio_b", "INTTYPE_LOW", 0x1C, 0x10001), ("gpio_a", "GPIOEN", 0x04, 0xFF)]
    # The CSR setup keeps the trap vector, the ISR scratch pointer and the enables the
    # fixed ISR needs; those are the fixed bytes the recorded arming path relies on.
    # The two enables are CSRRS (set bits) in the shipped body, not CSRRW: the
    # declaration records the operation instead of smoothing it into a plain write.
    assert [(row["name"], row["operation"], row["value"])
            for row in document["csr_writes"]] == [
        ("mtvec", "csrrw", 0x10100), ("mscratch", "csrrw", 0x2FF00),
        ("mie", "csrrs", 0x800), ("mstatus", "csrrs", 8)]


def test_shipped_bootstrap_is_byte_identical_and_keeps_its_fixed_images():
    shipped = make_ibex_pulp_dual_source_stream_bootstrap()
    images = {image.image_id: hashlib.sha256(image.data).hexdigest()
              for image in shipped.template.initial_images}
    assert images == SHIPPED_IMAGE_SHA256
    boot = fixed_image(shipped, BOOT_IMAGE_ID)
    assert (boot.address, len(boot.data)) == (0x10080, 96)
    # Independent of the module: the shipped body still writes all six GPIO words.
    assert {address for address, _, _ in decoded_stores(shipped)} == {
        0x40000004, 0x40000018, 0x4000001C, 0x40001000, 0x40001004, 0x4000100C}


def test_minimal_bootstrap_keeps_the_fixed_vector_isr_and_guard_bytes():
    shipped = make_ibex_pulp_dual_source_stream_bootstrap()
    minimal = fixture.make_ibex_pulp_dual_source_minimal_bootstrap()
    for image_id in ("cpu.stream.direct_vector", "cpu.stream.external_vector",
                     ISR_IMAGE_ID, "cpu.stream.end"):
        assert image_bytes(minimal, image_id) == image_bytes(shipped, image_id), image_id
    # The ISR bytes are present and unchanged: the restated claim is about executing
    # exactly these bytes, never about deleting or rewriting them.
    assert hashlib.sha256(fixed_image(minimal, ISR_IMAGE_ID).data).hexdigest() == \
        SHIPPED_IMAGE_SHA256[ISR_IMAGE_ID]
    boot = fixed_image(minimal, BOOT_IMAGE_ID)
    last = _word(boot.data, len(boot.data) - 4)
    offset = (((last >> 31) & 1) << 20) | (((last >> 21) & 0x3FF) << 1) | \
             (((last >> 20) & 1) << 11) | (((last >> 12) & 0xFF) << 12)
    offset -= 1 << 21 if offset & (1 << 20) else 0
    assert boot.address + len(boot.data) - 4 + offset == minimal.instruction_start


def test_minimal_declaration_refuses_the_shipped_fixture():
    """The removal check is load-bearing: the shipped body cannot claim the identity."""
    with pytest.raises(ValueError, match="removed GPIO word"):
        fixture.minimal_bootstrap_declaration(make_ibex_pulp_dual_source_stream_bootstrap())


def test_minimal_bootstrap_refuses_malformed_program_or_reservation():
    with pytest.raises(ValueError):
        fixture.make_pulp_dual_source_minimal_bootstrap(program="ibex")
    with pytest.raises(ValueError):
        fixture.make_ibex_pulp_dual_source_minimal_bootstrap(instruction_end=0x2FF00)


def bootstrap_lifecycle_factory(factory, directory, recorded):
    """Real bounded READY/END processes; the actual CPU service fetches every word.

    Copied from tests/scenario/test_register_reset_resume.py:12-67 (that file is
    not owned here) with one addition: the executed boot's stores and CSR writes
    are recorded, because "no forbidden boot write" is an execution claim, not a
    decode claim.
    """
    create_base = alias_factory(factory)
    first_word = IBEX_STREAM_CPU_PROGRAM.first_fetch

    def create():
        runner = create_base()
        begin_base = runner.begin_test
        case_steps = runner.step_batch
        cpu = runner.sessions["cpu"]
        registers = [0] * 32
        fetch = {"address": first_word, "epoch": None}
        for name, target in runner.sessions.items():
            digest, asserted, released, _ = target._expected_ready()
            binary = directory / (name + "-bootstrap-lifecycle.py")
            binary.write_text('#!/usr/bin/env python3\nimport sys\nprint(' + repr(
                f"READY local_driver.v1 {digest} {asserted:x} {released:x}")
                + ',flush=True)\nfor line in sys.stdin:\n if line.strip()=="END":break\n')
            binary.chmod(0o700)
            target._binary = binary

        def begin(case_id):
            begin_base(case_id)
            for target in runner.sessions.values():
                target.begin_case(case_id)

        def steps(order):
            active = runner._test_session._register_program_runtime._active_submission
            if active is not None:
                return case_steps(order)
            if cpu.waiting_instruction_address is not None:
                return
            if fetch["epoch"] != cpu.reset_epoch:
                fetch["epoch"] = cpu.reset_epoch
                fetch["address"] = first_word
                registers[:] = [0] * 32
                recorded["boots"] += 1
            address = fetch["address"]
            cpu._pending_instr = None
            response = cpu._serve("instr", 0, address, 0, 15)
            runner._append_external_events("cpu", len(runner._events))
            if response is None:
                return
            word = response[0]
            recorded["words"].append((address, word))
            assert address == first_word + 4 * (len(recorded["words"]) - 1), \
                "the fixed boot must be executed in order from its first word"
            op = word & 127
            rd, rs1 = word >> 7 & 31, word >> 15 & 31
            funct = word >> 12 & 7
            next_address = address + 4
            if op == 0x37:
                registers[rd] = word & 0xFFFFF000
            elif op == 0x13:
                assert funct == 0
                immediate = word >> 20
                immediate -= 4096 if immediate & 2048 else 0
                registers[rd] = (registers[rs1] + immediate) & 0xFFFFFFFF
            elif op in (0x03, 0x23):
                assert funct == 2
                immediate = ((word >> 25) << 5) | (word >> 7 & 31) if op == 0x23 else word >> 20
                immediate -= 4096 if immediate & 2048 else 0
                bus = (registers[rs1] + immediate) & 0xFFFFFFFF
                cpu._pending_data = None
                if op == 0x23:
                    recorded["stores"].append((bus, registers[word >> 20 & 31]))
                response = cpu._serve("data", int(op == 0x23), bus,
                                      registers[word >> 20 & 31] if op == 0x23 else 0, 15)
                runner._append_external_events("cpu", len(runner._events))
                if cpu.router.owns(bus):
                    window = next(w for w in cpu.router.windows
                                  if w.base <= bus < w.base + w.size)
                    runner._step_once(window.device_id)
                    response = cpu._pending_data
                assert response is not None
                if op == 0x03:
                    registers[rd] = response[0]
                cpu._pending_data = None
            elif op == 0x73:
                # The fixed body uses csrrw for mtvec/mscratch and csrrs for the two
                # enables.  The model keeps a CSR file that starts empty because this
                # fixture models the boot body's own writes only; the OR of csrrs is
                # modelled rather than assumed into a plain write.
                assert funct in (1, 2) and rd == 0, "unsupported fixed CSR form"
                number = word >> 20
                if funct == 1:
                    recorded["csr"][number] = registers[rs1]
                else:
                    recorded["csr"][number] = recorded["csr"].get(number, 0) | registers[rs1]
            elif op == 0x6F:
                immediate = (((word >> 31) & 1) << 20) | (((word >> 12) & 255) << 12) | \
                            (((word >> 20) & 1) << 11) | (((word >> 21) & 1023) << 1)
                immediate -= 1 << 21 if immediate & (1 << 20) else 0
                registers[rd] = address + 4
                next_address = address + immediate
            else:
                raise AssertionError("unexpected real bootstrap word " + hex(word))
            registers[0] = 0
            fetch["address"] = next_address
            cpu._pending_instr = None

        def finish():
            for target in runner.sessions.values():
                target.end_case()

        runner.begin_test = begin
        runner.step_batch = steps
        runner.finalize = finish
        return runner
    return create


@contextlib.contextmanager
def boot_to_deferred_fetch(tmp_path, bootstrap, render_dir):
    """Real bounded lifecycle: execute the fixed words until the first absent slot.

    The session is a real ScenarioSession over a real generated factory with
    bounded READY/END worker processes, and the only thing that makes the CPU
    wait is the real fetch of a still-unmaterialized reserved word.  Nothing
    assigns a PC, a waiting address or a reset epoch.
    """
    recorded = {"stores": [], "csr": {}, "words": [], "boots": 0}
    assembly = api.make_register_assembly(
        advance_rounds=1, ordinary_apb_access_evidence={"max_records": 32})
    factory = bootstrap_lifecycle_factory(
        api.make_register_factory(cache_dir=render_dir, assembly=assembly),
        tmp_path, recorded)
    session = ScenarioSession(bootstrap.template, factory())
    session.runner._test_session = session
    session.declare_instruction_slots("cpu", bootstrap.instruction_start,
                                      bootstrap.instruction_count)
    api.make_register_runtime_factory(assembly)(session)
    cpu = session.runner.sessions["cpu"]
    try:
        session.begin()
        for _ in range(128):
            if cpu.waiting_instruction_address == bootstrap.instruction_start:
                break
            session.advance_initial(bootstrap.template.schedule_order)
        else:
            raise AssertionError("software boot did not reach the deferred fetch")
        yield session, cpu, recorded
    finally:
        for target in session.runner.sessions.values():
            target.end_case()


def test_minimal_bootstrap_reaches_the_legal_online_missing_slot(tmp_path):
    """The real service executes the fixed words and then waits at 0x11000."""
    bootstrap = fixture.make_ibex_pulp_dual_source_minimal_bootstrap()
    with boot_to_deferred_fetch(tmp_path, bootstrap,
                                tmp_path / "render") as (session, cpu, recorded):
        assert recorded["boots"] == 1
        # Reachability came from executing real fetched words, in order, ending on the
        # self-computed jump: no PC, waiting address or epoch was assigned anywhere.
        boot = fixed_image(bootstrap, BOOT_IMAGE_ID)
        assert len(recorded["words"]) == len(boot.data) // 4 == 19
        assert recorded["words"][-1] == (boot.address + 72, _word(boot.data, 72))
        # The executed boot's actual stores are exactly the retained declared words ...
        assert recorded["stores"] == [(0x4000001C, 0x10001), (0x40001004, 0xFF)]
        document = fixture.minimal_bootstrap_declaration(bootstrap)
        assert recorded["stores"] == [
            (WINDOW_BASES[row["instance"]] + row["offset"], row["value"])
            for row in document["gpio_writes"]]
        # ... and none of the forbidden addresses was ever written.
        assert not {address for address, _ in recorded["stores"]} & removed_addresses(document)
        # The executed CSR writes leave exactly the state the fixed ISR needs.
        assert recorded["csr"] == {0x305: 0x10100, 0x340: 0x2FF00, 0x304: 0x800, 0x300: 8}
        # The reservation is still absent: the CPU is held by a real unanswered fetch.
        assert cpu.memory.instruction_slot_unmaterialized(bootstrap.instruction_start)
        assert all(cpu.memory.instruction_slot_unmaterialized(
            bootstrap.instruction_start + 4 * index) for index in range(4))
        assert all(target.reset_epoch == 0 for target in session.runner.sessions.values())


#: The audit's zero-GPIO structural control (bootstrap-audit command 3), written
#: as literal words so this test does not reuse the module's encoder.  It is NOT
#: the declared selector fixture -- Root's D2 keeps gpio_a GPIOEN and the B edge
#: type -- it is the proof that reachability itself depends on no GPIO write at all.
ZERO_GPIO_CONTROL_WORDS = (0x00010137, 0x10010113, 0x30511073,
                           0x00030137, 0xf0010113, 0x34011073,
                           0x00001137, 0x80010113, 0x30412073,
                           0x00800113, 0x30012073)
#: Image of those eleven words plus their self-computed jump, as measured by the
#: read-only audit this session reproduces.
ZERO_GPIO_CONTROL_SHA256 = "5f527184af1854b12d57e1b7e8eda1d9fd81a0aad2788483dcfb11e48a3ff77f"


def test_zero_gpio_boot_body_also_reaches_the_missing_slot(tmp_path):
    control = fixture._assemble_stream_bootstrap(
        program=IBEX_STREAM_CPU_PROGRAM, main=list(ZERO_GPIO_CONTROL_WORDS))
    image = fixed_image(control, BOOT_IMAGE_ID)
    assert (len(image.data), hashlib.sha256(image.data).hexdigest()) == (
        48, ZERO_GPIO_CONTROL_SHA256)
    assert _word(image.data, len(image.data) - 4) == 0x7550006F
    assert decoded_stores(control) == []
    window = fixture.declared_initial_ram_data_window(control)
    assert (window.base, window.byte_count) == (0x100B0, 80)
    with boot_to_deferred_fetch(tmp_path, control,
                                tmp_path / "render-zero-gpio") as (session, cpu, recorded):
        assert recorded["boots"] == 1
        assert len(recorded["words"]) == 12
        assert recorded["stores"] == []
        assert cpu.memory.instruction_slot_unmaterialized(control.instruction_start)
        assert cpu.waiting_instruction_address == control.instruction_start
