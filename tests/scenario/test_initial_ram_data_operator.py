"""Pre-session initial RAM data operator: declared bytes, mutated once.

Software only: no RTL is compiled, rendered into a process or started.  Every
session below is a real ``ScenarioSession`` over a real ``ScenarioRunner`` with
real persistent memory; only the local harness is a stub, because this operator
decides *declared* initial bytes before any RTL step and the read below is the
shipped ``MemoryService`` one.

Plan requirement (P4/A2): "初始数据在会话启动前变异；会话内仅未知数据字节的首次
读取可物化一次" -- initial data is mutated before the session starts, and inside
the session only the first read of an unknown data byte may materialize it, once.
No value is invented: the address comes from the trusted declaration, the value
from a domain-separated digest of the raw record, and every refusal states its
own reason plus the shipped rejection code that applies.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest

from myfuzz.integration.rfuzz_wire import InputBatch
from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.scenario.dependency import DependencyRule
from myfuzz.scenario.feedback import CoverageTarget
from myfuzz.scenario.genome import GenomeCodec, MemoryImage, ScenarioGenome
from myfuzz.scenario.initial_ram_data import (
    INITIAL_RAM_DATA_DECLARATION_SCHEMA_VERSION,
    INITIAL_RAM_DATA_DECISION_SCHEMA_VERSION,
    INITIAL_RAM_DATA_DOMAIN,
    INITIAL_RAM_DATA_ENV,
    INITIAL_RAM_DATA_REASONS,
    INITIAL_RAM_DATA_STATE_SCHEMA_VERSION,
    InitialRamDataState,
    TrustedInitialRamDataDeclaration,
    evaluate_initial_ram_data,
    propose_initial_ram_byte,
    resolve_initial_ram_data_switch,
)
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.online_case_decoder import (
    OnlineCaseDecoder,
    OnlineDependencyGraph,
    OnlineDependencySource,
    OnlineSource,
)
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.rv32i_sources import MmioWindow
from myfuzz.scenario import slot_immutability
from myfuzz.scenario.session_runtime import ScenarioSession, replay_online_session

#: The documented draw rule, pinned here as the contract instead of imported:
#: ``sha256(b"<domain>\0" + raw)``, first eight bytes select the declared byte,
#: second eight bytes select its value inside the declared mask.
DOMAIN = b"myfuzz.online.initial_ram_data.v1\0"
#: The shipped online path-switch domain, to show the two draws are disjoint.
PATH_SWITCH_DOMAIN = b"myfuzz.online.path_switch.v1\0"

RAM_BASE, RAM_SIZE = 0x1000, 0x100
#: Declared initial data window: inside RAM, outside the fixed image and
#: outside the instruction reservation.
WINDOW_BASE, WINDOW_BYTES = 0x1040, 16
FIXED_IMAGE = MemoryImage("boot", "cpu", RAM_BASE, "13000000" * 4)
SLOT_ADDRESS, SLOT_COUNT = 0x1080, 1
RAW = bytes((0x5A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))


# --------------------------------------------------------------------------
# real session over a stub local harness (no RTL)
# --------------------------------------------------------------------------

class _MemoryCpuSession:
    """One local harness stub whose only real part is persistent memory."""

    def __init__(self, memory: PersistentMemory) -> None:
        self.memory = memory

    def begin_case(self, testcase_id: str) -> None:
        pass

    def step_local(self, inputs):
        return {"out": 0}

    def end_case(self) -> None:
        pass

    def declare_instruction_slots(self, address: int, count: int = 1) -> None:
        self.memory.declare_instruction_slots(address, count)


def _memory() -> PersistentMemory:
    return PersistentMemory(regions=(MemoryRegion("ram", RAM_BASE, RAM_SIZE),),
                            initialization_seed=7, max_initialized_bytes=RAM_SIZE)


def _factory(memory: PersistentMemory | None = None) -> ScenarioRunner:
    ownership = compile_ownership(
        (InputField("cpu", "pin", 8),),
        (InputOwner("cpu", "pin", 0, 8, "source", "external_pin"),))
    session = _MemoryCpuSession(_memory() if memory is None else memory)
    return ScenarioRunner(sessions={"cpu": session}, ownership=ownership,
                          bindings=())


def _template() -> ScenarioGenome:
    return ScenarioGenome(testcase_id="initial-ram-unit", direction="CPU_TO_IP",
                          path_id="unit", schedule_order=("cpu",), max_steps=4,
                          actions=(), initial_images=(FIXED_IMAGE,))


def _declaration(**overrides) -> TrustedInitialRamDataDeclaration:
    fields = {"scope": "unit.declared.initial_ram_window", "component": "cpu",
              "memory_id": "ram", "base": WINDOW_BASE,
              "byte_count": WINDOW_BYTES, "value_mask": 0xFF}
    fields.update(overrides)
    return TrustedInitialRamDataDeclaration(**fields)


def _session(*, memory: PersistentMemory | None = None) -> ScenarioSession:
    return ScenarioSession(_template(), _factory(memory))


def _draw(declaration, raw: bytes) -> tuple[int, int, int]:
    """The documented rule, recomputed here instead of imported.

    Returns ``(address, byte_offset, value)`` where ``byte_offset`` is the
    offset inside the declared RAM region, which is what a decision records.
    """
    digest = hashlib.sha256(DOMAIN + raw).digest()
    window_offset = int.from_bytes(digest[:8], "little") % declaration.byte_count
    address = declaration.base + window_offset
    value = ((declaration.value_base & ~declaration.value_mask)
             | (int.from_bytes(digest[8:16], "little") & declaration.value_mask))
    return address, address - RAM_BASE, value


def _raws_by_offset(declaration) -> dict[int, tuple[bytes, int]]:
    """One raw record per declared byte offset, by the documented draw rule."""
    found: dict[int, tuple[bytes, int]] = {}
    for first in range(256):
        raw = bytes((first, 0, 0, 0, 0, 0, 0, 0))
        _address, offset, value = _draw(declaration, raw)
        found.setdefault(offset, (raw, value))
    return found


def _shipped_initial_byte(memory: PersistentMemory, memory_id: str,
                          byte_offset: int, generation: int = 0) -> int:
    """The shipped unknown-once value (``memory-init-v1``), recomputed here."""
    fields = ["memory-init-v1", memory.initialization_seed, memory_id,
              generation, byte_offset]
    encoded = json.dumps(fields, ensure_ascii=False,
                         separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).digest()[0]


def _aligned(address: int) -> int:
    return address & ~0x3


def _lane(address: int) -> int:
    return address & 0x3


# --------------------------------------------------------------------------
# declaration and draw
# --------------------------------------------------------------------------

class InitialRamDeclarationTests(unittest.TestCase):
    def test_declaration_is_content_addressed_and_compact(self):
        declaration = _declaration()
        document = declaration.document()
        self.assertEqual(INITIAL_RAM_DATA_DECLARATION_SCHEMA_VERSION,
                         document["schema_version"])
        self.assertNotIn("allowed_values", document)
        self.assertEqual(0xFF, document["value_mask"])
        # The identity is the digest of the declaration's own material, so a
        # reviewer recomputes which window a decision was taken under.
        material = {key: value for key, value in document.items()
                    if key != "declaration_id"}
        recomputed = hashlib.sha256(json.dumps(
            material, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()
        self.assertEqual(recomputed, declaration.declaration_id)
        self.assertEqual(declaration,
                         TrustedInitialRamDataDeclaration.from_document(document))
        self.assertTrue(declaration.allows_address(WINDOW_BASE))
        self.assertTrue(declaration.allows_address(WINDOW_BASE + WINDOW_BYTES - 1))
        self.assertFalse(declaration.allows_address(WINDOW_BASE - 1))
        self.assertFalse(declaration.allows_address(WINDOW_BASE + WINDOW_BYTES))
        self.assertTrue(declaration.allows_value(0xFF))
        self.assertFalse(_declaration(value_base=0x10, value_mask=0x0F)
                         .allows_value(0x20))

    def test_degenerate_declarations_are_refused(self):
        for overrides in ({"byte_count": 0}, {"byte_count": True},
                          {"base": -1}, {"value_mask": 0}, {"value_mask": 0x100},
                          {"scope": ""}, {"component": ""}, {"memory_id": ""},
                          {"value_base": 0x100}, {"image_id": ""}):
            with self.subTest(overrides=overrides):
                with self.assertRaises(ValueError):
                    _declaration(**overrides)
        document = _declaration().document()
        for tampered in ({**document, "x": 1},
                         {**document, "declaration_id": "0" * 64}):
            with self.subTest(tampered=sorted(tampered)):
                with self.assertRaises(ValueError):
                    TrustedInitialRamDataDeclaration.from_document(tampered)

    def test_draw_is_deterministic_domain_separated_and_declared(self):
        declaration = _declaration()
        first = propose_initial_ram_byte(declaration, RAW)
        second = propose_initial_ram_byte(declaration, RAW)
        self.assertEqual(first, second)
        address, byte_offset, value = _draw(declaration, RAW)
        self.assertEqual((address, value),
                         (first.address, first.value))
        # The pure draw never guesses a region base: only a caller holding the
        # declared memory window states the byte offset, and the evaluator does.
        self.assertIsNone(first.byte_offset)
        del byte_offset
        self.assertTrue(declaration.allows_address(first.address))
        self.assertTrue(declaration.allows_value(first.value))
        self.assertEqual(hashlib.sha256(DOMAIN + RAW).hexdigest(),
                         first.draw_sha256)
        # The operator's draw can never alias the shipped switch draw, and the
        # domain literal is the contract rather than an implementation detail.
        self.assertNotEqual(hashlib.sha256(PATH_SWITCH_DOMAIN + RAW).digest(),
                            hashlib.sha256(DOMAIN + RAW).digest())
        self.assertEqual(b"myfuzz.online.initial_ram_data.v1\0",
                         INITIAL_RAM_DATA_DOMAIN)
        # Different records propose different bytes, and the declared mask keeps
        # every value inside the declared domain.
        raws = _raws_by_offset(declaration)
        self.assertGreater(len({value for _raw, value in raws.values()}), 1)
        narrow = _declaration(value_mask=0x0F)
        for first_byte in range(64):
            proposal = propose_initial_ram_byte(
                narrow, bytes((first_byte,)) + bytes(7))
            self.assertEqual(0, proposal.value & 0xF0)

    def test_switch_resolution_mirrors_the_shipped_convention(self):
        self.assertEqual("MYFUZZ_INITIAL_RAM_DATA", INITIAL_RAM_DATA_ENV)
        resolve = resolve_initial_ram_data_switch
        self.assertEqual((True, "environment"),
                         resolve(None, online=True,
                                 environ={"MYFUZZ_INITIAL_RAM_DATA": "1"}))
        self.assertEqual((False, "environment"),
                         resolve(None, online=True,
                                 environ={"MYFUZZ_INITIAL_RAM_DATA": "off"}))
        self.assertEqual((False, "default"), resolve(None, online=True,
                                                     environ={}))
        # Without the online path the environment is never consulted.
        self.assertEqual((False, "default"),
                         resolve(None, online=False,
                                 environ={"MYFUZZ_INITIAL_RAM_DATA": "1"}))
        self.assertEqual((True, "constructor"),
                         resolve(True, online=True, environ={}))
        with self.assertRaises(ValueError):
            resolve(None, online=True,
                    environ={"MYFUZZ_INITIAL_RAM_DATA": "maybe"})
        with self.assertRaises(ValueError):
            resolve(1, online=True, environ={})


# --------------------------------------------------------------------------
# the legal mutation and its refusal reasons
# --------------------------------------------------------------------------

class InitialRamMutationTests(unittest.TestCase):
    def _adopt(self, session, declaration, raw=RAW, **kwargs) -> dict:
        return session.mutate_initial_ram_data(declaration=declaration, raw=raw,
                                               **kwargs)

    def test_legal_mutation_declares_the_declared_byte_before_launch(self):
        session = _session()
        declaration = _declaration()
        decision = self._adopt(session, declaration)
        address, byte_offset, value = _draw(declaration, RAW)
        self.assertEqual(INITIAL_RAM_DATA_DECISION_SCHEMA_VERSION,
                         decision["schema_version"])
        self.assertEqual("adopted", decision["reason"])
        self.assertIsNone(decision["rejection"])
        self.assertEqual(
            {"declaration_id": declaration.declaration_id, "component": "cpu",
             "memory_id": "ram", "address": address, "byte_offset": byte_offset,
             "value": value,
             "draw_sha256": hashlib.sha256(DOMAIN + RAW).hexdigest()},
            {key: decision["proposal"][key] for key in (
                "declaration_id", "component", "memory_id", "address",
                "byte_offset", "value", "draw_sha256")})
        # The mutation is a *declaration*: nothing is materialized until the
        # session starts, so no RTL command ran and no memory byte changed.
        self.assertEqual((), session.runner.events)
        self.assertEqual((), session.runner.sessions["cpu"].memory.determined_bytes())
        images = session.template.initial_images
        self.assertEqual(len(_template().initial_images) + 1, len(images))
        adopted_image = images[-1]
        self.assertEqual(("cpu", address, bytes((value,)).hex()),
                         (adopted_image.component, adopted_image.address,
                          adopted_image.data_hex))
        self.assertEqual(decision["proposal"]["image_id"],
                         adopted_image.image_id)
        # The state document states the declaration, the operator identity and
        # the one adopted byte; a refusal would state null and its reason.
        state = session.initial_ram_data_state()
        self.assertEqual(INITIAL_RAM_DATA_STATE_SCHEMA_VERSION,
                         state["schema_version"])
        self.assertTrue(state["enabled"])
        self.assertEqual("constructor", state["source"])
        self.assertEqual(1, state["attempts"])
        self.assertEqual(1, state["adopted"])
        self.assertEqual({}, state["refusals"])
        self.assertEqual(
            [{"memory_id": "ram", "byte_offset": byte_offset, "address": address,
              "value": value, "image_id": adopted_image.image_id,
              "proposal_id": decision["proposal"]["proposal_id"]}],
            state["bytes"])
        self.assertIn("sha256", state["operator"]["source"])
        self.assertEqual(hashlib.sha256(DOMAIN).hexdigest(),
                         state["operator"]["domain_sha256"])

        session.begin()
        preloads = [event for event in session.runner.events
                    if event.get("kind") == "initial_image"]
        self.assertEqual(len(images), len(preloads))
        mutated = [event for event in preloads
                   if event["image_id"] == adopted_image.image_id]
        self.assertEqual(1, len(mutated))
        self.assertEqual((address, adopted_image.data_hex),
                         (mutated[0]["address"], mutated[0]["data_hex"]))
        self.assertIn(("ram", byte_offset, value, "INITIAL_IMAGE"),
                      session.runner.sessions["cpu"].memory.determined_bytes())

    def test_mutated_value_is_what_the_first_unknown_read_returns(self):
        declaration = _declaration()
        address, byte_offset, value = _draw(declaration, RAW)
        lane = _lane(address)
        # Disabled twin: the byte stays unknown, so its first read is the
        # shipped unknown-once materialization of the digest value.
        disabled = _session()
        decision = self._adopt(disabled, declaration, enabled=False,
                               source="environment")
        self.assertEqual("operator_disabled", decision["reason"])
        self.assertIsNone(decision["proposal"])
        self.assertIsNone(decision["adopted"])
        self.assertIsNone(decision["rejection"])
        disabled.begin()
        memory = disabled.runner.sessions["cpu"].memory
        shipped = memory.read(_aligned(address), 4, transaction_id="off-1")
        self.assertEqual("FIRST_READ", shipped.writer_kinds[lane])
        self.assertEqual(_shipped_initial_byte(
            memory, "ram", _aligned(address) - RAM_BASE), shipped.data[0])
        # Frozen once: the second read returns the same word and writers.
        self.assertEqual(shipped.data, memory.read(
            _aligned(address), 4, transaction_id="off-2").data)

        # Enabled twin: the same first read returns the mutated byte, with the
        # initial image as its writer identity, never the first-read digest.
        enabled = _session()
        adopted = self._adopt(enabled, declaration)
        self.assertEqual("adopted", adopted["reason"])
        enabled.begin()
        memory = enabled.runner.sessions["cpu"].memory
        first = memory.read(_aligned(address), 4, transaction_id="on-1")
        self.assertEqual(value, first.data[lane])
        self.assertEqual("INITIAL_IMAGE", first.writer_kinds[lane])
        self.assertEqual("initial-image", first.writer_event_ids[lane])
        # The mutated lane was determined by the image, so the read materializes
        # only the still-unknown lanes of the same word, once.
        self.assertNotIn(byte_offset, first.materialized_offsets)
        self.assertEqual({byte_offset - lane + other for other in range(4)
                          if other != lane},
                         set(first.materialized_offsets))
        self.assertNotEqual(
            value, _shipped_initial_byte(memory, "ram", byte_offset))
        self.assertEqual(first.data, memory.read(
            _aligned(address), 4, transaction_id="on-2").data)

    def test_undeclared_byte_is_refused(self):
        # The declaration names a window the session's memory does not map, and
        # a memory the session does not declare: both are undeclared bytes.
        for declaration in (_declaration(base=0x2000, byte_count=8),
                            _declaration(memory_id="other")):
            with self.subTest(memory_id=declaration.memory_id,
                              base=hex(declaration.base)):
                session = _session()
                decision = self._adopt(session, declaration)
                self.assertEqual("undeclared_byte", decision["reason"])
                self.assertEqual("mmio.out_of_window",
                                 decision["rejection"]["code"])
                self.assertEqual("initial_ram.address",
                                 decision["rejection"]["pointer"])
                # No guessed offset is reported for an undeclared byte.
                self.assertIsNone(decision["proposal"]["byte_offset"])
                self.assertIsNone(decision["adopted"])
                self.assertEqual(_template(), session.template)
                state = session.initial_ram_data_state()
                self.assertEqual({"undeclared_byte": 1}, state["refusals"])
                self.assertEqual({"mmio.out_of_window": 1},
                                 state["rejection_codes"])
                self.assertEqual(0, state["adopted"])
                self.assertEqual([], state["bytes"])

    def test_a_second_different_declaration_is_refused(self):
        session = _session()
        declaration = _declaration()
        self.assertEqual("adopted", self._adopt(session, declaration)["reason"])
        with self.assertRaisesRegex(ValueError, "fixed once"):
            self._adopt(session, _declaration(base=WINDOW_BASE + 4))
        self.assertEqual(1, session.initial_ram_data_state()["attempts"])

    def test_fixed_image_byte_is_refused(self):
        session = _session()
        declaration = _declaration(base=RAM_BASE, byte_count=WINDOW_BYTES)
        decision = self._adopt(session, declaration)
        self.assertEqual("fixed_image_byte", decision["reason"])
        self.assertEqual("ownership.fixed_input", decision["rejection"]["code"])
        self.assertEqual({"occupant": "boot"}, decision["rejection"]["detail"])
        self.assertIsNone(decision["adopted"])
        self.assertEqual(_template(), session.template)

    def test_bound_instruction_slot_byte_is_refused(self):
        session = _session()
        session.declare_instruction_slots("cpu", SLOT_ADDRESS, SLOT_COUNT)
        declaration = _declaration(base=SLOT_ADDRESS, byte_count=4)
        decision = self._adopt(session, declaration)
        self.assertEqual("bound_slot_byte", decision["reason"])
        self.assertEqual("ownership.bound_input", decision["rejection"]["code"])
        self.assertEqual({"occupant": "online_instruction_slot"},
                         decision["rejection"]["detail"])
        self.assertIsNone(decision["adopted"])

    def test_materialized_and_unknown_once_bytes_are_refused(self):
        declaration = _declaration()
        address, _byte_offset, _value = _draw(declaration, RAW)
        # A real Store already determined the byte: fail closed, never rewrite.
        stored = _session()
        stored.runner.sessions["cpu"].memory.write(
            address, 0x9E, width_bytes=1, byte_enable=1, writer_event_id="store-1")
        decision = self._adopt(stored, declaration)
        self.assertEqual("materialized_byte", decision["reason"])
        self.assertEqual("slot.materialized", decision["rejection"]["code"])
        self.assertEqual({"occupant": "STORE"}, decision["rejection"]["detail"])
        self.assertEqual(0x9E, stored.runner.sessions["cpu"].memory.read(
            address, 1, transaction_id="probe").value)
        self.assertIsNone(decision["adopted"])
        # A byte already materialized once as unknown is not re-materialized.
        unknown = _session()
        snapshot = unknown.runner.sessions["cpu"].memory.read(
            address, 1, transaction_id="first")
        decision = self._adopt(unknown, declaration)
        self.assertEqual("materialized_byte", decision["reason"])
        self.assertEqual({"occupant": "FIRST_READ"},
                         decision["rejection"]["detail"])
        self.assertEqual(snapshot.data,
                         unknown.runner.sessions["cpu"].memory.read(
                             address, 1, transaction_id="second").data)
        self.assertIsNone(decision["adopted"])
        self.assertEqual(_template(), unknown.template)

    def test_second_adoption_and_budget_are_refused(self):
        declaration = _declaration()
        raws = _raws_by_offset(declaration)
        offsets = sorted(raws)
        self.assertGreaterEqual(len(offsets), 2)
        first_raw, first_value = raws[offsets[0]]
        second_raw, _second_value = raws[offsets[1]]
        session = _session()
        first = self._adopt(session, declaration, raw=first_raw)
        self.assertEqual("adopted", first["reason"])
        images = session.template.initial_images
        # The same byte is never re-materialized: adopting it again is refused
        # even though nothing has reached memory yet.
        again = self._adopt(session, declaration, raw=first_raw)
        self.assertEqual("already_adopted", again["reason"])
        self.assertEqual("slot.already_consumed", again["rejection"]["code"])
        self.assertEqual({"value": first_value, "proposed": first_value},
                         again["rejection"]["detail"])
        self.assertEqual(offsets[0], again["proposal"]["byte_offset"])
        self.assertEqual(images, session.template.initial_images)
        # The adopted-byte budget is declared and enforced.
        other = self._adopt(session, declaration, raw=second_raw)
        self.assertEqual("budget_exhausted", other["reason"])
        self.assertEqual("budget.exhausted", other["rejection"]["code"])
        self.assertEqual({"max_bytes": 1, "adopted_bytes": 1},
                         other["rejection"]["detail"])
        self.assertEqual(offsets[1], other["proposal"]["byte_offset"])
        self.assertEqual(images, session.template.initial_images)
        # A larger declared bound widens the operator's own budget explicitly.
        wider = self._adopt(session, declaration, raw=second_raw, max_bytes=2,
                            source="constructor")
        self.assertEqual("adopted", wider["reason"])
        self.assertEqual(len(images) + 1, len(session.template.initial_images))
        state = session.initial_ram_data_state()
        self.assertEqual(2, state["adopted"])
        self.assertEqual(2, state["bounds"]["max_bytes"])
        self.assertEqual({"already_adopted": 1, "budget_exhausted": 1},
                         state["refusals"])
        for entry in state["bytes"]:
            self.assertTrue(declaration.allows_address(entry["address"]))
            self.assertTrue(declaration.allows_value(entry["value"]))

    def test_malformed_raw_is_refused_without_a_guessed_value(self):
        session = _session()
        declaration = _declaration()
        for raw in (b"", bytearray(b"\x01"), "0102", None):
            with self.subTest(raw=raw):
                decision = session.mutate_initial_ram_data(
                    declaration=declaration, raw=raw)
                self.assertEqual("malformed_raw", decision["reason"])
                self.assertEqual("decode.malformed_record",
                                 decision["rejection"]["code"])
                self.assertIsNone(decision["proposal"])
                self.assertIsNone(decision["adopted"])
        self.assertEqual(_template(), session.template)

    def test_wrong_phase_is_refused_before_and_after_the_session(self):
        declaration = _declaration()
        started = _session()
        started.begin()
        with self.assertRaisesRegex(RuntimeError, "before begin"):
            started.mutate_initial_ram_data(declaration=declaration, raw=RAW)
        self.assertEqual(_template(), started.template)
        self.assertIsNone(started.initial_ram_data_state())
        finished = _session()
        finished.begin()
        finished.finish()
        with self.assertRaisesRegex(RuntimeError, "before begin"):
            finished.mutate_initial_ram_data(declaration=declaration, raw=RAW)
        self.assertIsNone(finished.initial_ram_data_state())

    def test_unknown_declaration_type_and_bounds_are_refused(self):
        session = _session()
        with self.assertRaisesRegex(ValueError, "TrustedInitialRamDataDeclaration"):
            session.mutate_initial_ram_data(declaration={"base": 1}, raw=RAW)
        with self.assertRaisesRegex(ValueError, "max_bytes"):
            session.mutate_initial_ram_data(declaration=_declaration(), raw=RAW,
                                            max_bytes=0)
        with self.assertRaisesRegex(ValueError, "enabled"):
            session.mutate_initial_ram_data(declaration=_declaration(), raw=RAW,
                                            enabled=1)
        self.assertIsNone(session.initial_ram_data_state())


# --------------------------------------------------------------------------
# the pure evaluator over a declared state view
# --------------------------------------------------------------------------

class InitialRamEvaluatorTests(unittest.TestCase):
    def _state(self, **overrides) -> InitialRamDataState:
        fields = {"regions": (("ram", RAM_BASE, RAM_BASE + RAM_SIZE),),
                  "determined": (), "reserved": (),
                  "fixed_images": (("cpu", FIXED_IMAGE.address,
                                    FIXED_IMAGE.address + len(FIXED_IMAGE.data),
                                    "boot"),),
                  "adopted": ()}
        fields.update(overrides)
        return InitialRamDataState(**fields)

    def test_state_view_decides_without_a_session(self):
        declaration = _declaration()
        address, byte_offset, value = _draw(declaration, RAW)
        decision = evaluate_initial_ram_data(declaration, RAW, self._state(),
                                             enabled=True, max_bytes=1)
        self.assertEqual("adopted", decision["reason"])
        self.assertEqual((address, byte_offset, value),
                         (decision["proposal"]["address"],
                          decision["proposal"]["byte_offset"],
                          decision["proposal"]["value"]))
        for reason in ("adopted", "operator_disabled", "malformed_raw",
                       "undeclared_byte", "fixed_image_byte", "bound_slot_byte",
                       "materialized_byte", "already_adopted",
                       "budget_exhausted"):
            self.assertIn(reason, INITIAL_RAM_DATA_REASONS)

    def test_result_is_independent_of_search_state(self):
        declaration = _declaration()
        state = self._state(fixed_images=())
        first = evaluate_initial_ram_data(declaration, RAW, state,
                                          enabled=True, max_bytes=1)
        second = evaluate_initial_ram_data(declaration, RAW, state,
                                           enabled=True, max_bytes=1)
        self.assertEqual(json.dumps(first, sort_keys=True),
                         json.dumps(second, sort_keys=True))
        # The evaluator never mutates the state view it was handed.
        self.assertEqual((), state.adopted)


# --------------------------------------------------------------------------
# replay and default identity
# --------------------------------------------------------------------------

class InitialRamReplayTests(unittest.TestCase):
    def test_adopted_image_replays_from_the_saved_prefix(self):
        from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent
        from myfuzz.scenario.session_runtime import OnlineCase

        declaration = _declaration()
        session = _session()
        decision = session.mutate_initial_ram_data(declaration=declaration,
                                                   raw=RAW)
        self.assertEqual("adopted", decision["reason"])
        session.begin()
        memory = session.runner.sessions["cpu"].memory
        address = decision["proposal"]["address"]
        case = OnlineCase("case-1", "CPU_TO_IP", "unit",
                          BatchSourceEvent("source-1", "cpu", "pin", 0, width=8),
                          (BatchAdvance(("cpu",)),))
        memory.read(_aligned(address), 4, transaction_id="read-before")
        session.submit_case(case)
        reference = session.finish()
        plan = session.encode_plan()
        document = json.loads(plan)
        # The mutated byte is part of the saved template, so a fresh replay
        # needs no operator at all and proposes exactly the recorded value.
        self.assertEqual(bytes((decision["proposal"]["value"],)).hex(),
                         document["template"]["initial_images"][-1]["data_hex"])
        result = replay_online_session(plan, _factory, reference)
        self.assertTrue(result.matches, result.difference_context)
        self.assertEqual(reference.events, result.actual_trace.events)
        # A tampered initial byte is refused by the plan identity itself.
        document["template"]["initial_images"][-1]["data_hex"] = "00"
        tampered = json.dumps(document, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False).encode("utf-8")
        with self.assertRaisesRegex(ValueError, "plan identity mismatch"):
            replay_online_session(tampered, _factory, reference)

    def test_default_off_identity_of_manifest_plan_and_candidate_ids(self):
        # A real session: the manifest is the shipped online manifest, and the
        # operator is absent from it whether it was never declared or declared
        # off.
        pristine = _session()
        pristine.begin()
        disabled = _session()
        disabled.mutate_initial_ram_data(declaration=_declaration(), raw=RAW,
                                         enabled=False, source="environment")
        disabled.begin()
        self.assertEqual(pristine.manifest_document, disabled.manifest_document)
        self.assertEqual(pristine.manifest_sha256, disabled.manifest_sha256)
        self.assertNotIn("initial_ram_data", pristine.manifest_document)
        self.assertNotIn("initial_ram_data", disabled.manifest_document)
        self.assertIsNone(pristine.initial_ram_data_state())
        state = disabled.initial_ram_data_state()
        self.assertFalse(state["enabled"])
        self.assertEqual("environment", state["source"])
        self.assertEqual(0, state["adopted"])
        self.assertEqual({"operator_disabled": 1}, state["refusals"])
        self.assertEqual([], state["bytes"])
        # Nothing in the default template or plan moved.
        self.assertEqual(GenomeCodec.encode(_template()),
                         GenomeCodec.encode(pristine.template))
        self.assertEqual(GenomeCodec.encode(_template()),
                         GenomeCodec.encode(disabled.template))
        self.assertEqual(pristine.encode_plan(), disabled.encode_plan())

        # Candidate identity: the operator cannot reach the decoder, so the
        # explicitly declared twin decodes the same records to the same ids.
        records = (bytes((0, 0, 0, 1, 2, 3, 4, 5)),
                   bytes((0, 0, 0, 6, 7, 8, 9, 10)))
        default = _executor()
        _run(default, records)
        declared = _executor(session=_declared_stub_session())
        _run(declared, records)
        self.assertEqual([row["candidate_id"] for row in default.online_decisions],
                         [row["candidate_id"] for row in declared.online_decisions])
        self.assertEqual([row["source_id"] for row in default.online_decisions],
                         [row["source_id"] for row in declared.online_decisions])
        self.assertEqual(default.session.manifest_document,
                         declared.session.manifest_document)
        self.assertIsNone(default.session.initial_ram_data_state())
        self.assertEqual(0, declared.session.initial_ram_data_state()["adopted"])

    def test_default_declaration_still_matches_the_shipped_run_plan(self):
        """The default bootstrap declaration is byte-identical to the shipped run.

        This is the "today" half of the identity argument: the saved real plan
        of ``runs/current-dataflow-p4-path-switch-on-20261007-online`` carries
        the template the current tree still declares with the operator off.
        """
        from myfuzz.scenario.ibex_pulp_dual_source import (
            make_ibex_pulp_dual_source_stream_bootstrap)
        plan_path = (Path(__file__).resolve().parents[2] / "runs" /
                     "current-dataflow-p4-path-switch-on-20261007-online" /
                     "online_plan.json")
        if not plan_path.is_file():
            self.skipTest(f"shipped run plan is absent: {plan_path}")
        saved = json.loads(plan_path.read_bytes())["template"]
        current = make_ibex_pulp_dual_source_stream_bootstrap()
        self.assertEqual(
            json.dumps(saved, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False).encode("utf-8"),
            GenomeCodec.encode(current.template))

    def test_declared_ibex_window_is_the_declared_gap_word(self):
        """The Ibex declaration is derived from the trusted bootstrap layout."""
        from myfuzz.scenario.ibex_pulp_dual_source import (
            declared_initial_ram_data_window,
            make_ibex_pulp_dual_source_stream_bootstrap)
        bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
        declaration = declared_initial_ram_data_window(bootstrap)
        self.assertEqual("cpu", declaration.component)
        self.assertEqual("ram", declaration.memory_id)
        program = next(image for image in bootstrap.template.initial_images
                       if image.image_id == "cpu.stream.bootstrap")
        self.assertEqual(program.address + len(program.data), declaration.base)
        next_segment = min(image.address for image in bootstrap.template.initial_images
                           if image.address > declaration.base)
        self.assertEqual(next_segment - declaration.base, declaration.byte_count)
        self.assertFalse(declaration.allows_address(next_segment))
        self.assertEqual(0xFF, declaration.value_mask)
        # Every declared byte is unmaterialized, outside the reservation and
        # outside every fixed image of the same declaration.
        for offset in range(declaration.byte_count):
            address = declaration.base + offset
            self.assertFalse(bootstrap.instruction_start
                             <= address < bootstrap.instruction_end)
            for image in bootstrap.template.initial_images:
                self.assertFalse(image.address <= address
                                 < image.address + len(image.data))


class InitialRamLiveWiringTests(unittest.TestCase):
    """The live CLI forwards one declared record to the operator and the client.

    No RTL is rendered or started: the two entry points are replaced by
    recorders, so this checks the wiring contract (the operator's raw record is
    the same record the RFuzz client is seeded with, and the OFF arm declares
    nothing at all) without a harness.
    """

    def _script(self):
        import importlib.util
        path = (Path(__file__).resolve().parents[2] / "scripts" /
                "run_ibex_pulp_online.py")
        spec = importlib.util.spec_from_file_location("initial_ram_cli_under_test",
                                                      path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _run_arm(self, script, *extra) -> tuple[int, dict]:
        """Run the CLI with both live entry points replaced by recorders."""
        import contextlib
        import io
        import tempfile
        import types
        calls = {}

        def fake_runtime(**kwargs):
            calls["runtime"] = kwargs
            return types.SimpleNamespace(executor="executor")

        def fake_live(**kwargs):
            calls["live"] = kwargs
            return types.SimpleNamespace(
                output_dir=kwargs["output_dir"], tests=0, statuses={},
                elapsed_seconds=0.0, effective_search_seconds=0.0)

        script.make_ibex_pulp_online_runtime = fake_runtime
        script.run_scenario_rfuzz_live = fake_live
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as temporary:
            with contextlib.redirect_stderr(stderr):
                code = script.main(["run", "--client-binary", "/bin/true",
                                    "--cache-dir", str(Path(temporary) / "cache"),
                                    "--output", str(Path(temporary) / "arm"),
                                    *extra])
        calls["stderr"] = stderr.getvalue()
        return code, calls

    def test_off_arm_declares_nothing_and_on_arm_shares_one_record(self):
        script = self._script()
        code, off = self._run_arm(script)
        self.assertEqual(0, code)
        # The shipped default: the flag is None, so the operator is not declared
        # at all and the client keeps its shipped eight-byte seed.
        self.assertIsNone(off["runtime"]["initial_ram_data"])
        self.assertEqual(bytes(8), off["runtime"]["initial_ram_record"])
        self.assertEqual((bytes(8),), off["live"]["seed_records"])

        record = "5a00010203040506"
        code, on = self._run_arm(script, "--initial-ram-data",
                                 "--initial-ram-record", record)
        self.assertEqual(0, code)
        self.assertIs(True, on["runtime"]["initial_ram_data"])
        self.assertEqual(bytes.fromhex(record), on["runtime"]["initial_ram_record"])
        # The draw is derived from exactly the record the client receives, and
        # the run stores that record in seed.bin for a replay to recompute.
        self.assertEqual((bytes.fromhex(record),), on["live"]["seed_records"])

    def test_a_malformed_record_is_refused_before_any_harness(self):
        script = self._script()
        code, refused = self._run_arm(script, "--initial-ram-data",
                                      "--initial-ram-record", "zz")
        # Fail closed before a harness exists: non-zero exit, a stated reason
        # and neither live entry point reached.
        self.assertEqual(1, code)
        self.assertIn("--initial-ram-record must be hexadecimal",
                      refused["stderr"])
        self.assertNotIn("runtime", refused)
        self.assertNotIn("live", refused)
        code, empty = self._run_arm(script, "--initial-ram-data",
                                    "--initial-ram-record", "")
        self.assertEqual(1, code)
        self.assertIn("--initial-ram-record must not be empty", empty["stderr"])
        self.assertNotIn("runtime", empty)


class InitialRamReportHookTests(unittest.TestCase):
    def test_report_hook_states_a_declared_operator_and_is_absent_otherwise(self):
        from myfuzz.integration.scenario_rfuzz_live import _initial_ram_data_record

        undeclared = _session()
        self.assertIsNone(_initial_ram_data_record(
            type("Executor", (), {"session": undeclared})()))
        declared = _session()
        declared.mutate_initial_ram_data(declaration=_declaration(), raw=RAW,
                                         enabled=True)
        state = _initial_ram_data_record(
            type("Executor", (), {"session": declared})())
        self.assertTrue(state["enabled"])
        self.assertEqual(1, state["adopted"])
        self.assertEqual(1, len(state["operator"]["raws"]))
        self.assertEqual(hashlib.sha256(RAW).hexdigest(),
                         state["operator"]["raws"][0]["sha256"])
        self.assertEqual(RAW.hex(), state["operator"]["raws"][0]["hex"])


class _StubSession(ScenarioSession):
    """One real session journal fed by synthetic cases (no RTL)."""

    def __init__(self, runner, decoder):
        source = decoder.sources[0]
        super().__init__(ScenarioGenome(
            testcase_id="initial-ram-stub", direction=source.direction,
            path_id=source.path_id,
            schedule_order=tuple(decoder.advances[0].schedule),
            max_steps=(decoder.max_steps or 512), actions=()), runner)
        self._manifest_sha256 = hashlib.sha256(b"initial-ram-stub").hexdigest()
        self._manifest_document = {"schema_version": "online_session_manifest.v1",
                                   "stub": True}

    def submit_case(self, case, *, source_role="fuzz_source"):
        from myfuzz.scenario.session_runtime import OnlineCaseReceipt
        start = self.runner.event_count
        ticks_before = dict(self.runner.local_ticks)
        return OnlineCaseReceipt(case.case_id, start, self.runner.event_count,
                                 self.runner.events_since(start), ticks_before,
                                 dict(self.runner.local_ticks), "running")


TARGET = "target"
DIRECTION = "CPU_TO_IP"


def _identity_decoder() -> OnlineCaseDecoder:
    graph = OnlineDependencyGraph(
        sources=(OnlineDependencySource("cpu.it", "instruction", "cpu",
                                        (DIRECTION,)),),
        rules=(DependencyRule(TARGET, ("cpu.it",), "EVENT_ORDER"),))
    return OnlineCaseDecoder(
        sources=(OnlineSource("cpu.it", "instruction", "cpu", DIRECTION, TARGET),),
        ownership=compile_ownership(
            (InputField("cpu", "irq", 1),),
            (InputOwner("cpu", "irq", 0, 1, "fixed", "constant_zero"),)),
        schedule=("cpu",), instruction_start=0x1000, instruction_end=0x1008,
        advance_rounds=1, max_input_bytes=8, graph=graph, support_words=0,
        windows=(MmioWindow(0x40000000, 0x1000),))


def _declared_stub_session() -> _StubSession:
    """A stub session whose initial-RAM operator was explicitly declared off."""
    decoder = _identity_decoder()
    runner = ScenarioRunner(sessions={"cpu": object()},
                            ownership=decoder.ownership, bindings=())
    session = _StubSession(runner, decoder)
    session.mutate_initial_ram_data(declaration=_declaration(), raw=RAW,
                                    enabled=False, source="environment")
    return session


def _executor(*, session=None) -> ScenarioRfuzzExecutor:
    decoder = _identity_decoder()
    if session is None:
        runner = ScenarioRunner(sessions={"cpu": object()},
                                ownership=decoder.ownership, bindings=())
        session = _StubSession(runner, decoder)
    return ScenarioRfuzzExecutor(
        run_id="initial-ram-identity", online_decoder=decoder, session=session,
        factory=lambda: None,
        targets=(CoverageTarget("cpu_data_write", "cpu", "data_write", 1, 1),))


def _run(executor, records) -> None:
    executor.batch_size = len(records)
    executor.execute_batch(InputBatch(1, 8, tuple((raw,) for raw in records)))


# --------------------------------------------------------------------------
# slot immutability
# --------------------------------------------------------------------------

def _slot_immutability_trace(session: ScenarioSession, declaration):
    """A real preload plus a real memory-service read, in journal order.

    The runner journal owns the ``initial_image`` record with the runner's own
    event id.  The read goes through the shipped ``MemoryService``, so the
    ``memory_initialization`` (still-unknown lanes) and ``memory_read`` records
    are the shipped ones; their event ids continue that same journal order.
    """
    memory = session.runner.sessions["cpu"].memory
    service = MemoryService(memory, TransactionLedger(), include_writer_kinds=True)
    trace = [dict(event) for event in session.runner.events]
    service.read(TransactionKey("local-execution", "case-1", "cpu", 0, "data", 1),
                 _aligned(_draw(declaration, RAW)[0]), width_bytes=4)
    for event in service.events:
        trace.append({**dict(event), "event_id": len(trace) + 1})
    return trace


class InitialRamSlotImmutabilityTests(unittest.TestCase):
    def test_mutated_byte_is_initial_image_materialization_not_a_violation(self):
        declaration = _declaration()
        address, _byte_offset, value = _draw(declaration, RAW)
        session = _session()
        decision = session.mutate_initial_ram_data(declaration=declaration,
                                                   raw=RAW)
        self.assertEqual("adopted", decision["reason"])
        session.begin()
        trace = _slot_immutability_trace(session, declaration)
        report = slot_immutability.analyze_events(
            trace, program_range=(_aligned(address), _aligned(address) + 4),
            range_source="unit declared initial data window")
        slot = next(item for item in report.slots if item.address == address)
        self.assertEqual("initial_image", slot.first_kind)
        self.assertEqual(value, slot.value)
        self.assertEqual("immutable", slot.verdict)
        self.assertEqual("immutable", report.run_conclusion)
        # Two declared images materialize a declared byte here: the fixed boot
        # image in its own region and the adopted initial-data image in the
        # window under test.  The mutated slot's own first kind is above.
        self.assertEqual(2, report.materializations_by_kind["initial_image"])
        self.assertEqual(0, report.counts["violated"])
        # The read carries the mutated lane with the preload's writer identity,
        # and the still-unknown lanes of the same word are first-read lanes.
        read = next(event for event in trace if event.get("kind") == "memory_read")
        lane = _lane(address)
        self.assertEqual(bytes((value,)).hex(),
                         read["data_hex"][2 * lane:2 * lane + 2])
        self.assertEqual("initial-image", read["writer_event_ids"][lane])
        for other in range(4):
            if other != lane:
                self.assertEqual("FIRST_READ", read["writer_kinds"][other])

    def test_a_wrong_read_value_is_a_violation(self):
        """Negative control: the gate is not vacuous about the mutated value."""
        declaration = _declaration()
        address, _byte_offset, value = _draw(declaration, RAW)
        session = _session()
        session.mutate_initial_ram_data(declaration=declaration, raw=RAW)
        session.begin()
        trace = _slot_immutability_trace(session, declaration)
        read = next(event for event in trace if event.get("kind") == "memory_read")
        wrong = bytearray(bytes.fromhex(read["data_hex"]))
        wrong[_lane(address)] ^= 0x01
        read["data_hex"] = bytes(wrong).hex()
        read["value"] = int.from_bytes(bytes(wrong), "little")
        report = slot_immutability.analyze_events(
            trace, program_range=(_aligned(address), _aligned(address) + 4),
            range_source="unit declared initial data window")
        slot = next(item for item in report.slots if item.address == address)
        self.assertEqual("violated", slot.verdict)
        self.assertEqual("later_read_different_value", slot.conflict_kind)
        self.assertEqual(value, slot.value)
        self.assertEqual("violated", report.run_conclusion)


if __name__ == "__main__":
    unittest.main()
