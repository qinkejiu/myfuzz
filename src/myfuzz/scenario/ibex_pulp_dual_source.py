"""Dual-source wiring for independent generated OBI CPU and PULP GPIO RTL.

This module supplies the *same* runner with a CPU boot-program source and an
external GPIO B source. Legal boot and pin-event templates configure pin 8
IRQ and write GPIO A from a real ISR. Runtime closed-loop acceptance remains
pending observation from generated RTL. It does not inject an
IRQ, a GPIO output, or an MMIO result: those remain outputs of real RTL.

Ownership, MMIO windows, bindings, IRQ pulse policy, the boot/ISR firmware
body, the online decoder and the runtime path contract are shared by every
CPU that reuses this wiring. The only per-CPU facts are declared once, next to
each other, in the ``DualSourceCpuProgram`` block below; no runner, router,
mutator or protocol template inspects a component name.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import asdict, dataclass, field, replace
import hashlib
import json
from pathlib import Path

from myfuzz.local_harness import (GeneratedPulpGpioSession,
                                  load_local_harness_request,
                                  plan_local_harness, render_local_driver,
                                  render_local_harness, render_local_runtime,
                                  verify_local_source_lock)
from myfuzz.local_harness.cpu_session import GeneratedCve2Session

from .dependency import (DependencyGraph, DependencyRule, FuzzableSource,
                         SourceBinding, SourceBindings)
from .genome import Action, MemoryImage, ScenarioGenome, Trigger
from .initial_ram_data import TrustedInitialRamDataDeclaration
from .batch import BatchSourceEvent
from .online_case_decoder import OnlineCaseDecoder
from .rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder
from .ibex_pulp_rfuzz import _source_span
from .memory import MemoryRegion, PersistentMemory
from .memory_commit_authority import MemoryCommitAuthority
from .ownership import InputField, InputOwner, OwnershipMap, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner
from .runtime_path_contract import RuntimeNode, RuntimeEdgeContract, RuntimePathContract
from .source_actions import (CrossCaseEffectTracker, DynamicPrerequisiteBinder,
                             EffectWitness, InstructionSlotReservationGate,
                             SourceAction, SourceActionGate,
                             TrustedRamByteDeclaration)


ROOT = Path(__file__).resolve().parents[3]
CPU_PROFILE = "configs/cpus/ibex_obi_local/component_profile.json"
RVFI_CPU_PROFILE = "configs/cpus/ibex_rvfi_local/component_profile.json"
GPIO_PROFILE = "configs/peripherals/pulp_gpio/component_profile.json"
CAUSAL_GPIO_PROFILE = "configs/peripherals/pulp_gpio_causal_local/component_profile.json"

#: Shared physical topology of this trusted fixed wiring.  Nothing below is
#: CPU-specific: the CPU only replaces the program image at these addresses.
VECTOR_BASE = 0x10100
EXTERNAL_VECTOR = 0x1012C
ISR_BASE = 0x10200
ISR_SCRATCH = 0x2FF00
RESULT_ADDRESS = 0x10000

#: Declared online instruction reservation of this wiring.  The stream bootstrap
#: reserves exactly these words, and the shipped cross-case prerequisite policy
#: binds every admitted instruction case to its own still-unmaterialized word(s)
#: inside them.  0x11000..0x2fe00 is 0x1ee00 bytes = 31616 words: the declared
#: *upper bound* on distinct slots one run can fill, not a registration (see
#: ``make_pulp_dual_source_source_action_gate``).
ONLINE_INSTRUCTION_START = 0x11000
ONLINE_INSTRUCTION_END = 0x2FE00
#: Declared namespace of one per-case reservation evidence reference.
ONLINE_SLOT_RESERVATION_PREFIX = "online-instruction-slot.v1"

#: Appended cross-case RAM consumption declaration of this wiring.
#:
#: The fixed ISR stores the observed PADIN byte at ``RESULT_ADDRESS`` with
#: ``lui x3,0x10000; sw x2,0(x3)``, and a later online case can load that byte
#: back.  The host memory service labels every committed byte ``STORE``
#: (``scenario/memory.py``) and re-publishes exactly that per-cell kind on the
#: commit stream (``scenario/memory_service.py``), so the only writer kind this
#: wiring may consume is ``STORE``.
RESULT_SLOT_WRITER_KINDS = ("STORE",)
#: Declared identity of the adapter gate that publishes both shipped policies.
RAM_PREREQUISITE_BINDING_GATE_SCHEMA_VERSION = "ram_prerequisite_binding_gate.v1"
#: The one declared rule ``reads_result_slot`` implements; published so a
#: reviewer recomputes the decision instead of trusting a per-case story.
RESULT_SLOT_READ_RULE = "statically_materialized_lw_base_equals_result_address"

# ---------------------------------------------------------------------------
# Opt-in partial byte write of the result-slot window (default off).
#
# The shipped declaration admits ``LW``/``SW`` only, so every RAM commit this
# wiring can produce is a full-enable word store: P3's
# ``byte_enable_lane_selectivity`` -- "a byte-enable covering only its own
# lanes never moves the other lanes" -- can never be observed from such an
# artifact.  The explicit opt-in below adds one *declared* narrow write, in
# exactly the place ``result_slot_readback`` already declares the window:
#
# * address: ``RESULT_ADDRESS`` alone (``0x10000``), the same window the fixed
#   ISR stores its observed PADIN byte in;
# * width: one byte (``SB``), the only narrow width any RV32I store offers;
# * lanes: the four byte lanes of that declared window, i.e. the byte at
#   ``RESULT_ADDRESS + n`` for ``n`` in ``RESULT_SLOT_BYTE_STORE_BYTE_LANES``.
#
# GPIO A PADOUT is narrowed to the word-only width while the opt-in is on, so
# the one declared byte width cannot be proposed to a device register, and
# ``rv32i_sources.mutate_mmio_access`` keeps refusing every other address, width
# and misaligned word access with the shipped codes.  Off, not one declaration
# below reaches a decoder document.
# ---------------------------------------------------------------------------
#: The one operation the opt-in adds to the declared operation set.
RESULT_SLOT_BYTE_STORE_OPERATION = "SB"
#: Byte lanes of the declared result-slot window a one-byte store may enable.
RESULT_SLOT_BYTE_STORE_BYTE_LANES = (0, 1, 2, 3)
#: Declared write widths of the result-slot window when the opt-in is on: the
#: shipped word width plus the one declared byte width, never a wider set.
RESULT_SLOT_BYTE_STORE_WRITE_WIDTHS = (1, 4)
#: Declared write widths of every other window while the opt-in is on.
RESULT_SLOT_WORD_ONLY_WRITE_WIDTHS = (4,)
#: Schema of :func:`result_slot_byte_store_declaration`.
RESULT_SLOT_BYTE_STORE_SCHEMA_VERSION = "result_slot_byte_store.v1"


def result_slot_byte_store_declaration() -> dict:
    """The recomputable declared scope of the opt-in partial result-slot write.

    A reviewer reads this instead of a comment: one address, one operation, one
    byte width and the exact lane addresses the decoder may propose.  It names
    no other window, so the declaration proves the byte width is confined to
    the result slot.  It is not evidence that any RTL store happened: the
    artifact's own byte-enable records are.
    """
    return {
        "schema_version": RESULT_SLOT_BYTE_STORE_SCHEMA_VERSION,
        "operation": RESULT_SLOT_BYTE_STORE_OPERATION,
        "address": RESULT_ADDRESS,
        "byte_width": 1,
        "write_widths": list(RESULT_SLOT_BYTE_STORE_WRITE_WIDTHS),
        "lanes": [{"lane": lane, "address": RESULT_ADDRESS + lane}
                  for lane in RESULT_SLOT_BYTE_STORE_BYTE_LANES],
        "word_only_windows": [0x4000100C],
        "not_proof_of": ["RTL byte-enable lane selectivity",
                         "cross-case acceptance"],
    }

# ---------------------------------------------------------------------------
# Appended persistent_state declarations of the online contract.
#
# Both resources are named exactly as the *observed* event shapes name them;
# nothing below invents a field or an address:
#
# * host RAM: ``memory_write``/``memory_write_commit`` carry ``component``,
#   ``memory_id`` (the value of the declared ``PersistentMemory`` region),
#   ``generation``, ``byte_offset``, ``byte_enable`` and ``version``; a later
#   ``memory_read`` of the same resource carries ``generation``, ``versions``,
#   ``writer_event_ids`` and ``writer_kinds`` per byte.
# * GPIO A PADOUT: ``gpio_register_commit`` carries ``component``, ``register``
#   and per-bit ``bit_resources[]`` with ``bit``/``value``/``version``/
#   ``observation_event_id``; a later ``gpio_register_read`` of the same
#   register carries those same per-bit rows (see
#   ``scenario/gpio_consumption.py``: offset 12 is the ``out`` register).
#
# The two rules are appended after every legacy row, so no existing
# ``mmio_route``/``direct_binding`` rule index, field or enumerated path moves.
# ---------------------------------------------------------------------------
#: Component/resource identity of the host persistent RAM byte versions.
ONLINE_RAM_RESOURCE_COMPONENT = "cpu"
ONLINE_RAM_RESOURCE_ID = "ram"
#: Component/register identity of the GPIO A PADOUT bit versions.
ONLINE_GPIO_REGISTER_RESOURCE_COMPONENT = "gpio_a"
ONLINE_GPIO_REGISTER_RESOURCE_ID = "out"
#: Declared node identities of the two appended persistent_state edges.
ONLINE_RAM_VERSION_NODE = "online.cpu.persistent_ram_byte"
ONLINE_GPIO_REGISTER_VERSION_NODE = "online.gpio_a.persistent_register_bit"


@dataclass(frozen=True)
class DualSourceCpuProgram:
    """The complete set of per-CPU firmware facts for this wiring.

    Every other byte of the stream firmware is shared.  A CPU difference may
    only appear here, with its RTL evidence recorded in the declaration below,
    and never as a component-name branch in a runner, router, mutator or
    protocol template.
    """

    profile_path: str
    #: Evidence label of the one fixed stream template for this CPU.
    testcase_id: str
    #: Address of the first instruction the pinned core fetches after reset.
    first_fetch: int
    #: Address of the shared main program (GPIO configuration and the jump into
    #: the online instruction interval).  Cores whose reset vector differs get
    #: one unconditional JAL at ``first_fetch`` instead of a moved program.
    main_address: int
    #: Value written to ``mtvec``.  The shared firmware loads it as
    #: ``lui x2, hi; addi x2, x2, lo; csrw mtvec, x2`` with the low bit free for
    #: CPUs that encode the direct/vectored mode there.
    mtvec_value: int
    boot_trampoline: bool


# ---------------------------------------------------------------------------
# Explicit CPU difference block: the only two facts that differ between the
# pinned Ibex and the pinned CV32E40P on this exact wiring.
#
# Ibex (third_party/rfuzz/upstream/ibex/rtl/ibex_if_stage.sv):
#   PC_BOOT     fetch_addr_n = {boot_addr_i[31:8], 8'h80}      -> 0x10080
#   EXC_PC_IRQ  exc_pc       = {csr_mtvec_i[31:8], 1'b0, irq_vec, 2'b00}
#               so machine external cause 11 always enters 0x1012c and
#               csr_mtvec_i[7:0] is unused (``unused_csr_mtvec``): mtvec[0] has
#               no meaning on Ibex, which is why 0x10100 is written there.
#
# CV32E40P (external_designs/cv32e40p/rtl):
#   cv32e40p_if_stage.sv:157,160  PC_BOOT = {boot_addr_i[31:2], 2'b0} -> 0x10000
#   cv32e40p_if_stage.sv:147      EXC_PC_IRQ = {trap_base_addr, 1'b0,
#                                 exc_vec_pc_mux, 2'b0}  (interrupts vectored)
#   cv32e40p_core.sv:361          m_exc_vec_pc_mux_id = (mtvec_mode == 0) ? 0
#                                 : exc_cause, so direct mode would enter
#                                 0x10100 and vectored mode enters 0x1012c
#   cv32e40p_cs_registers.sv:666-667  mtvec = csr_wdata_int[31:8] (256-byte
#                                 aligned) and mtvec_mode = csr_wdata_int[0]
#   cv32e40p_int_controller.sv   irq_i[11] is MEI (CSR_MEIX_BIT=11,
#                                 cv32e40p_pkg.sv:522), gated by mie[11] and
#                                 mstatus.MIE (global_irq_enable = m_ie_i), and
#                                 IRQ_MASK = 32'hFFFF0888 (pkg.sv:725) passes
#                                 bit 11.
#   Therefore mtvec = 0x10101 selects vectored entry so cause 11 reaches the
#   shared 0x1012c slot, and a single JAL trampoline at 0x10000 reaches the
#   shared main program at 0x10080.
# ---------------------------------------------------------------------------
IBEX_STREAM_CPU_PROGRAM = DualSourceCpuProgram(
    profile_path=CPU_PROFILE, testcase_id="ibex-dual-source-stream",
    first_fetch=0x10080, main_address=0x10080,
    mtvec_value=0x10100, boot_trampoline=False)
CV32E40P_STREAM_CPU_PROGRAM = DualSourceCpuProgram(
    profile_path="configs/cpus/cv32e40p/component_profile.json",
    testcase_id="cv32e40p-dual-source-stream",
    first_fetch=0x10000, main_address=0x10080, mtvec_value=0x10101,
    boot_trampoline=True)



def _artifact(profile_path: str, instance_id: str):
    request = load_local_harness_request({
        "schema_version": "local_harness.v1",
        "profile_path": profile_path,
        "instance_id": instance_id,
        "reset_assert_ticks": 8,
        "reset_release_ticks": 8,
        "max_wait_cycles": 16,
    })
    plan = plan_local_harness(request, base_dir=ROOT)
    structural = render_local_harness(plan)
    verified = verify_local_source_lock(plan.profile, base_dir=ROOT)
    runtime = render_local_runtime(plan, structural, verified, base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


def dual_source_ownership_declaration() -> tuple[tuple[InputField, ...],
                                                 tuple[InputOwner, ...]]:
    """The one declared ownership authority for this wiring (no compiled map).

    Keeping fields and owners as plain immutable records lets a caller compare
    or transform the ownership declaration without compiling a map, and lets
    the compiled map below stay the only runtime form.
    """
    return ((InputField("cpu", "irq", 1),
             InputField("gpio_a", "gpio_in", 32),
             InputField("gpio_b", "gpio_in", 32)),
            (InputOwner("cpu", "irq", 0, 1, "bound", "gpio_b.irq"),
             InputOwner("gpio_a", "gpio_in", 0, 32, "fixed", "constant_zero"),
             InputOwner("gpio_b", "gpio_in", 0, 8, "bound", "gpio_a.gpio_out"),
             InputOwner("gpio_b", "gpio_in", 8, 1, "source", "external_b.pin8"),
             InputOwner("gpio_b", "gpio_in", 9, 23, "fixed", "constant_zero")))


def dual_source_ownership() -> OwnershipMap:
    """Keep GPIO B low byte and CPU IRQ bound while exposing B pin 8.

    GPIO B pin 8 is an independent external pin. The CPU program must enable
    the intended GPIO interrupt sources; ownership alone does not do so.
    """
    return compile_ownership(*dual_source_ownership_declaration())


#: Aperture of one PULP GPIO window as declared by the pinned profile
#: (``configs/peripherals/pulp_gpio/component_profile.json`` APB_ADDR_WIDTH=12).
#: The SoC base of each instance is an integration fact, not a profile fact.
PULP_GPIO_PROFILE_APERTURE = 0x1000

#: Memory carved out for the CPU program and its fixed result slot.
DUAL_SOURCE_MEMORY_REGIONS = (MemoryRegion("ram", 0x10000, 0x30000),)


@dataclass(frozen=True)
class PulpDualSourceWiring:
    """Declarative topology of this fixed wiring: endpoints, ranges, apertures.

    ``make_pulp_dual_source_factory`` builds every runner from one instance of
    this declaration, so the declaration cannot silently drift from the factory.
    It names no session, artifact, binary or process.  The constructor rejects
    only malformed records (unknown components, invalid types and ranges);
    *route semantics* (a window's target, an aperture against the runtime
    contract, a declared producer against its binding) stay preflight rules so
    that a broken declaration remains representable and can be rejected with a
    located reason instead of failing to exist.
    """

    cpu_profile: str
    gpio_profile: str
    router_initiator: str
    sessions: tuple[str, ...]
    windows: tuple[tuple[str, int, int, str], ...]
    bindings: tuple[Binding, ...]
    ownership_fields: tuple[InputField, ...]
    ownership_owners: tuple[InputOwner, ...]
    irq_pulse_widths: tuple[tuple[Binding, int], ...]
    memory_component: str
    memory_regions: tuple[MemoryRegion, ...]
    memory_initialization_seed: int
    max_initialized_bytes: int
    profile_aperture: int = PULP_GPIO_PROFILE_APERTURE

    def __post_init__(self) -> None:
        if (not self.cpu_profile or not self.gpio_profile or not self.router_initiator
                or not isinstance(self.sessions, tuple) or not self.sessions
                or any(not isinstance(name, str) or not name for name in self.sessions)
                or len(set(self.sessions)) != len(self.sessions)):
            raise ValueError('invalid dual-source wiring component declaration')
        if (not isinstance(self.windows, tuple)
                or any(type(window) is not tuple or len(window) != 4
                       or not isinstance(window[0], str) or not window[0]
                       or type(window[1]) is not int or window[1] < 0
                       or type(window[2]) is not int or window[2] < 4
                       or not isinstance(window[3], str) or not window[3]
                       for window in self.windows)
                or len({window[0] for window in self.windows}) != len(self.windows)):
            raise ValueError('invalid dual-source MMIO window declaration')
        if (not isinstance(self.bindings, tuple)
                or any(not isinstance(binding, Binding) for binding in self.bindings)
                or len(set(self.bindings)) != len(self.bindings)):
            raise ValueError('invalid dual-source binding declaration')
        if (not isinstance(self.ownership_fields, tuple)
                or not isinstance(self.ownership_owners, tuple)
                or any(not isinstance(field, InputField) for field in self.ownership_fields)
                or any(not isinstance(owner, InputOwner) for owner in self.ownership_owners)):
            raise ValueError('invalid dual-source ownership declaration')
        if (not isinstance(self.irq_pulse_widths, tuple)
                or any(type(item) is not tuple or len(item) != 2
                       or not isinstance(item[0], Binding)
                       or type(item[1]) is not int or item[1] < 1
                       for item in self.irq_pulse_widths)):
            raise ValueError('invalid dual-source IRQ pulse declaration')
        if (not isinstance(self.memory_regions, tuple) or not self.memory_regions
                or any(not isinstance(region, MemoryRegion) for region in self.memory_regions)
                or type(self.memory_initialization_seed) is not int
                or type(self.max_initialized_bytes) is not int
                or self.max_initialized_bytes < 0
                or type(self.profile_aperture) is not int or self.profile_aperture < 4):
            raise ValueError('invalid dual-source memory or aperture declaration')
        named = set(self.sessions)
        if any(component not in named for _, _, _, component in self.windows):
            raise ValueError('declared MMIO window names an unregistered component')
        if any(component not in named for component in (
                self.router_initiator, self.memory_component,
                *(endpoint for binding in self.bindings
                  for endpoint in (binding.source_component, binding.target_component)))):
            raise ValueError('declared wiring endpoint names an unregistered component')
        compile_ownership(self.ownership_fields, self.ownership_owners)

    def document(self) -> dict:
        return {'schema_version': 'pulp_dual_source_wiring.v1',
                'cpu_profile': self.cpu_profile, 'gpio_profile': self.gpio_profile,
                'router_initiator': self.router_initiator,
                'sessions': list(self.sessions),
                'windows': [{'device_id': device_id, 'base': base, 'size': size,
                             'component': component}
                            for device_id, base, size, component in self.windows],
                'bindings': [asdict(binding) for binding in self.bindings],
                'ownership': {'fields': [asdict(field) for field in self.ownership_fields],
                              'owners': [asdict(owner) for owner in self.ownership_owners]},
                'irq_pulse_widths': [{'binding': asdict(binding), 'width_cpu_ticks': width}
                                     for binding, width in self.irq_pulse_widths],
                'memory': {'component': self.memory_component,
                           'regions': [asdict(region) for region in self.memory_regions],
                           'initialization_seed': self.memory_initialization_seed,
                           'max_initialized_bytes': self.max_initialized_bytes},
                'profile_aperture': self.profile_aperture}

    @property
    def identity_sha256(self) -> str:
        return hashlib.sha256(json.dumps(self.document(), sort_keys=True,
            separators=(',', ':'), ensure_ascii=False,
            allow_nan=False).encode('utf-8')).hexdigest()

    @classmethod
    def from_document(cls, document: dict) -> PulpDualSourceWiring:
        try:
            if (type(document) is not dict
                    or set(document) != {'schema_version', 'cpu_profile', 'gpio_profile',
                                         'router_initiator', 'sessions', 'windows',
                                         'bindings', 'ownership', 'irq_pulse_widths',
                                         'memory', 'profile_aperture'}
                    or document['schema_version'] != 'pulp_dual_source_wiring.v1'
                    or type(document['sessions']) is not list
                    or type(document['windows']) is not list
                    or type(document['bindings']) is not list
                    or type(document['irq_pulse_widths']) is not list):
                raise ValueError('invalid dual-source wiring schema')
            ownership = document['ownership']
            memory = document['memory']
            if (type(ownership) is not dict
                    or set(ownership) != {'fields', 'owners'}
                    or type(ownership['fields']) is not list
                    or type(ownership['owners']) is not list
                    or type(memory) is not dict
                    or set(memory) != {'component', 'regions', 'initialization_seed',
                                       'max_initialized_bytes'}
                    or type(memory['regions']) is not list):
                raise ValueError('invalid dual-source wiring record')
            wiring = cls(
                cpu_profile=document['cpu_profile'],
                gpio_profile=document['gpio_profile'],
                router_initiator=document['router_initiator'],
                sessions=tuple(document['sessions']),
                windows=tuple((row['device_id'], row['base'], row['size'], row['component'])
                              for row in document['windows']),
                bindings=tuple(Binding(**row) for row in document['bindings']),
                ownership_fields=tuple(InputField(**row) for row in ownership['fields']),
                ownership_owners=tuple(InputOwner(**row) for row in ownership['owners']),
                irq_pulse_widths=tuple((Binding(**row['binding']), row['width_cpu_ticks'])
                                       for row in document['irq_pulse_widths']),
                memory_component=memory['component'],
                memory_regions=tuple(MemoryRegion(**row) for row in memory['regions']),
                memory_initialization_seed=memory['initialization_seed'],
                max_initialized_bytes=memory['max_initialized_bytes'],
                profile_aperture=document['profile_aperture'])
            if _canonical_document(wiring.document()) != _canonical_document(document):
                raise ValueError('dual-source wiring document is not canonical')
            return wiring
        except (KeyError, TypeError) as error:
            raise ValueError('invalid dual-source wiring document') from error


def _canonical_document(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False)


def dual_source_wiring(*, cpu_profile: str = CPU_PROFILE,
                       gpio_consumption: bool = False) -> PulpDualSourceWiring:
    """Declare the trusted topology this module's factory must build.

    ``gpio_consumption`` selects the causal GPIO profile that exports a real
    consumption probe; it changes which profile is rendered, never the declared
    endpoints, apertures or ownership.
    """
    if type(gpio_consumption) is not bool:
        raise ValueError('gpio_consumption must be boolean')
    fields, owners = dual_source_ownership_declaration()
    irq = Binding("gpio_b", "irq", "cpu", "irq", 1)
    return PulpDualSourceWiring(
        cpu_profile=cpu_profile,
        gpio_profile=CAUSAL_GPIO_PROFILE if gpio_consumption else GPIO_PROFILE,
        router_initiator="cpu",
        sessions=("cpu", "gpio_a", "gpio_b"),
        windows=(("gpio_a", 0x40001000, PULP_GPIO_PROFILE_APERTURE, "gpio_a"),
                 ("gpio_b", 0x40000000, PULP_GPIO_PROFILE_APERTURE, "gpio_b")),
        bindings=(Binding("gpio_a", "gpio_out", "gpio_b", "gpio_in", 8), irq),
        ownership_fields=fields,
        ownership_owners=owners,
        irq_pulse_widths=((irq, 4),),
        memory_component="cpu",
        memory_regions=DUAL_SOURCE_MEMORY_REGIONS,
        memory_initialization_seed=37,
        max_initialized_bytes=0x20000)


def make_pulp_dual_source_source_action_gate(
        *, component: str,
        instruction_start: int = ONLINE_INSTRUCTION_START,
        instruction_end: int = ONLINE_INSTRUCTION_END,
        tracker: CrossCaseEffectTracker | None = None
        ) -> InstructionSlotReservationGate:
    """Declare the shipped cross-case prerequisite policy of this wiring.

    Declared requirement: an admitted online instruction case must fill fetch
    slots that are still unmaterialized.  The address cannot be declared once
    for all cases -- the decoder cursor moves forward and every earlier slot
    stays filled -- so :class:`InstructionSlotReservationGate` binds the slot(s)
    the action's *own* declared payload names and registers exactly those
    reservations in the tracker, lazily, one word per admitted case.  Real
    ``instruction_source`` evidence of an earlier case is what materializes a
    word and makes a later case that names it fail closed.

    Registration range and bound: the window is the same declared online
    instruction reservation the stream bootstrap installs
    (``instruction_start .. instruction_end``, default ``0x11000..0x2fe00``).
    ``(instruction_end - instruction_start) // 4`` is 31616 words -- the
    declared upper bound on distinct words one run can name, not a
    registration.  The window is never registered up front: doing that would
    fill the tracker's ``max_slots`` capacity immediately and evict the
    earliest slots before their cases could query them.  The tracker is
    constructed with ``max_slots`` equal to that declared word count so no
    reservation can be evicted, and no materialization can degrade the tracker,
    before the case that declares it is admitted.
    """
    if not isinstance(component, str) or not component.strip():
        raise ValueError("slot reservation policy requires a CPU component")
    declared_words = (instruction_end - instruction_start) // 4
    if declared_words < 1:
        raise ValueError("slot reservation policy requires a nonempty word window")
    subject = (CrossCaseEffectTracker(max_slots=declared_words)
               if tracker is None else tracker)
    return InstructionSlotReservationGate(
        SourceActionGate(subject), component=component,
        first_address=instruction_start, last_address=instruction_end,
        reservation_ref_prefix=ONLINE_SLOT_RESERVATION_PREFIX)


# ---------------------------------------------------------------------------
# Appended dynamic RAM-byte prerequisite binding of this wiring.
#
# The slot policy above answers "is the word this case fills still fresh?".  The
# capability appended below answers the other cross-case question of P3: a later
# case that *reads* the byte an earlier case committed must declare that exact
# committed version as its prerequisite, and that version is only decided by the
# evidence the earlier case really produced.  Nothing here executes an
# instruction, injects a value or guesses a register: the decision is a static,
# recomputable reading of the action's own declared fragment.
# ---------------------------------------------------------------------------

def result_slot_ram_location(
        result_address: int = RESULT_ADDRESS) -> tuple[str, int]:
    """Declared host-memory ``(memory_id, byte_offset)`` of one address.

    Derived from ``DUAL_SOURCE_MEMORY_REGIONS`` -- the same declaration the
    factory builds its ``PersistentMemory`` from -- so no memory id is spelled
    here and no offset is guessed.  An address outside every declared region
    raises: this wiring does not own it, so no binding may consume it.
    """
    if type(result_address) is not int or result_address < 0:
        raise ValueError("result address must be a nonnegative integer")
    for region in DUAL_SOURCE_MEMORY_REGIONS:
        if region.base <= result_address < region.base + region.size:
            return region.memory_id, result_address - region.base
    raise ValueError("declared dual-source memory has no region containing "
                     f"{result_address:#x}")


def result_slot_declaration(
        result_address: int = RESULT_ADDRESS,
        writer_kinds: tuple[str, ...] = RESULT_SLOT_WRITER_KINDS
        ) -> TrustedRamByteDeclaration:
    """The one trusted RAM declaration this wiring publishes for its result slot."""
    memory_id, byte_offset = result_slot_ram_location(result_address)
    return TrustedRamByteDeclaration(memory_id=memory_id,
                                     byte_offsets=(byte_offset,),
                                     writer_kinds=writer_kinds)


def instruction_words(words_hex: object) -> tuple[int, ...] | None:
    """Read one declared fragment as its 32-bit words, or ``None``.

    ``None`` means "this fragment cannot be read": a non-string, an empty
    payload, non-canonical hex or a partial word is refused instead of being
    guessed at.  Nothing here executes or validates ISA semantics.
    """
    if type(words_hex) is not str or not words_hex:
        return None
    try:
        raw = bytes.fromhex(words_hex)
    except ValueError:
        return None
    if not raw or len(raw) % 4 or raw.hex() != words_hex:
        return None
    return tuple(int.from_bytes(raw[index:index + 4], "little")
                 for index in range(0, len(raw), 4))


def _sign_extend(value: int, bits: int) -> int:
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def materialized_lw_addresses(words_hex: object) -> tuple[int, ...]:
    """Every ``LW`` effective address one declared fragment *proves*.

    The declared static rule (no execution, no assumed register state, one
    deterministic pass over the fragment's words):

    * a register is materialized only by *this same fragment*: ``LUI rd, imm20``
      sets ``rd = sign_extend_32(imm20 << 12)`` and ``ADDI rd, rs1, imm12``
      propagates ``rd = rs1 + sign_extend_12(imm12)``; ``rs1 == x0`` folds to
      the immediate because ``x0`` is hardwired zero, and a write to ``x0``
      changes nothing;
    * ``LW rd, imm12(rs1)`` with a materialized ``rs1`` yields
      ``(base + sign_extend_12(imm12)) mod 2**32``.  An online case runs after
      the fixed bootstrap, so a register this fragment never wrote is *unknown*
      and proves nothing;
    * an ``OP-IMM``/``LUI``/``LW`` whose value is not materializable invalidates
      its own destination register, a store writes no register, and every other
      encoding invalidates every materialization, because this folder cannot
      tell which register it writes.

    An unreadable payload returns ``()``: the policy never guesses.
    """
    words = instruction_words(words_hex)
    if words is None:
        return ()
    known: dict[int, int] = {}
    addresses: list[int] = []
    for word in words:
        opcode, rd = word & 0x7F, (word >> 7) & 0x1F
        rs1, funct3 = (word >> 15) & 0x1F, (word >> 12) & 0x7
        if opcode == 0x37:  # LUI
            if rd:
                known[rd] = (_sign_extend(word >> 12, 20) << 12) & 0xFFFFFFFF
            continue
        if opcode == 0x13 and funct3 in (0, 1, 4, 5, 6, 7):  # OP-IMM
            base = 0 if rs1 == 0 else known.get(rs1)
            value = ((base + _sign_extend((word >> 20) & 0xFFF, 12)) & 0xFFFFFFFF
                     if funct3 == 0 and base is not None else None)
            if rd:
                if value is None:
                    known.pop(rd, None)
                else:
                    known[rd] = value
            continue
        if opcode == 0x03 and funct3 == 2:  # LW
            base = 0 if rs1 == 0 else known.get(rs1)
            if base is not None:
                addresses.append((base + _sign_extend((word >> 20) & 0xFFF, 12))
                                 & 0xFFFFFFFF)
            if rd:
                known.pop(rd, None)
            continue
        if opcode == 0x23:  # SW/SB: a store writes no register
            continue
        known.clear()
    return tuple(addresses)


def reads_result_slot(words_hex: object,
                      result_address: int = RESULT_ADDRESS) -> bool:
    """Whether one fragment declares a read of the wiring's result slot.

    This is the exact policy decision :class:`RamPrerequisiteBindingGate` takes
    before it binds: only a proven ``LW`` of ``result_address`` (see
    :func:`materialized_lw_addresses`) is bound, everything else keeps the
    shipped slot-only path.
    """
    if type(result_address) is not int or result_address < 0:
        raise ValueError("result address must be a nonnegative integer")
    return result_address in materialized_lw_addresses(words_hex)


@dataclass
class RamPrerequisiteBindingGate(InstructionSlotReservationGate):
    """Adapter gate: bind a witnessed result-slot read, then the slot policy.

    ``make_pulp_dual_source_factory(source_actions=True)`` and
    ``make_ibex_pulp_online_runtime`` attach this class instead of the bare
    :class:`InstructionSlotReservationGate`.  It is a subclass on purpose: the
    shipped slot policy is neither reimplemented nor replaced, because every
    slot step is the inherited implementation reached through ``super()``.  An
    action that does not read the result slot therefore takes exactly the
    previous code path, and the object stays an
    ``InstructionSlotReservationGate`` for every existing caller (``component``,
    ``first_address``, ``last_address``, ``declared_words``,
    ``reservation_ref`` and the slot ``declaration()``).

    Declared policy, applied by :meth:`register` *before* the slot policy sees
    the action (no per-case invention, no component-name branch):

    * an action of kind ``instruction`` on this gate's component whose payload
      fragment *proves* an ``LW`` of ``result_address`` -- by
      :func:`reads_result_slot`, i.e. a base register materialized inside the
      same fragment -- is bound by :class:`DynamicPrerequisiteBinder` to the
      latest retained version of the one declared RAM byte
      (:func:`result_slot_declaration`, writer kinds closed to the real
      ``STORE`` producer).  The ``ram_byte_version`` prerequisite is *added* to
      the action and its payload is never touched; the bound action is what the
      slot policy then registers, reserves and admits;
    * ``DynamicBindingUnbound`` (no retained witness) and
      ``DynamicBindingRefused`` (any policy violation) propagate unchanged, so
      the executor refuses the case before it issues one RTL command;
    * every other action -- another component, kind ``external_event``, an
      unreadable payload, or a fragment whose ``LW`` addresses are not proven to
      include ``result_address`` -- reaches the slot policy untouched.

    :meth:`observe` feeds the binder exactly once per admitted receipt, and the
    binder reads the *same* tracker object the slot policy reads (construction
    refuses a binder over any other tracker), so one ``observe`` call can never
    ingest the same events twice.

    ``document()`` keeps every previously published slot key at its old path
    (``schema_version``, ``enforce``, ``action_ids``, ``declaration``,
    ``counters``, ``gate``) and publishes the two policy blocks beside them:
    ``slot_gate`` (the same slot document) and ``dynamic_binding`` (the
    ``dynamic_prerequisite_binder.v1`` proof policy), plus ``ram_prerequisite``
    naming this adapter's own declared rule.
    """

    binder: DynamicPrerequisiteBinder | None = None
    result_address: int = RESULT_ADDRESS
    memory_id: str = ""
    byte_offset: int = 0
    _policy_counters: dict = field(default_factory=lambda: {
        "registered": 0, "policy_matched": 0, "policy_unparsed": 0,
        "policy_not_matched": 0, "observations": 0}, repr=False)

    def __post_init__(self) -> None:
        super().__post_init__()
        if not isinstance(self.binder, DynamicPrerequisiteBinder):
            raise ValueError("RAM prerequisite binding gate requires a binder")
        if self.binder.tracker is not self.gate.tracker:
            raise ValueError(
                "RAM prerequisite binding gate must bind the tracker its slot "
                "policy reads")
        if type(self.result_address) is not int or self.result_address < 0:
            raise ValueError("RAM prerequisite binding gate needs a result address")
        if type(self.memory_id) is not str or not self.memory_id:
            raise ValueError("RAM prerequisite binding gate needs a memory_id")
        if (type(self.byte_offset) is not int or self.byte_offset < 0
                or not self.binder.declaration.allows(self.memory_id,
                                                      self.byte_offset)):
            raise ValueError(
                "the trusted declaration does not cover the declared result slot")

    @classmethod
    def from_slot_gate(cls, slot_gate: InstructionSlotReservationGate, *,
                       binder: DynamicPrerequisiteBinder,
                       result_address: int = RESULT_ADDRESS,
                       memory_id: str, byte_offset: int
                       ) -> RamPrerequisiteBindingGate:
        """Adopt one shipped slot policy and add the binding step in front.

        The inner :class:`SourceActionGate` object is *shared*, so exactly one
        registration and query state exists.  The intermediate slot gate must be
        discarded by the caller (:func:`make_pulp_dual_source_dynamic_binding_gate`
        is the only caller): a second live gate over the one tracker could
        register the same action twice.
        """
        if (not isinstance(slot_gate, InstructionSlotReservationGate)
                or isinstance(slot_gate, RamPrerequisiteBindingGate)):
            raise ValueError("a distinct shipped slot gate is required")
        return cls(gate=slot_gate.gate, component=slot_gate.component,
                   first_address=slot_gate.first_address,
                   last_address=slot_gate.last_address,
                   reservation_ref_prefix=slot_gate.reservation_ref_prefix,
                   binder=binder, result_address=result_address,
                   memory_id=memory_id, byte_offset=byte_offset)

    # -- declared policy --------------------------------------------------
    @property
    def ram_prerequisite_declaration(self) -> dict:
        """The declared binding policy a reviewer recomputes a decision from."""
        return {"schema_version": RAM_PREREQUISITE_BINDING_GATE_SCHEMA_VERSION,
                "rule": RESULT_SLOT_READ_RULE,
                "result_address": self.result_address,
                "memory_id": self.memory_id, "byte_offset": self.byte_offset,
                "writer_kinds": list(self.binder.declaration.writer_kinds),
                "declaration_id": self.binder.declaration.declaration_id,
                "binding": "latest_retained_ram_byte_evidence",
                "on_unproven_fragment": "not_bound"}

    # -- gate protocol ----------------------------------------------------
    def register(self, action: SourceAction) -> SourceAction:
        """Bind a proven result-slot read, then run the unchanged slot policy."""
        self._policy_counters["registered"] += 1
        return super().register(self._bind_result_slot_read(action))

    def _bind_result_slot_read(self, action: SourceAction) -> SourceAction:
        if (not isinstance(action, SourceAction) or action.kind != "instruction"
                or action.component != self.component
                or not action.payload_mutable):
            # Another component, an external event or a malformed record is the
            # slot policy's business, never this policy's.
            self._policy_counters["policy_not_matched"] += 1
            return action
        if instruction_words(action.payload["words_hex"]) is None:
            # An unreadable fragment proves nothing, so it is never bound.
            self._policy_counters["policy_unparsed"] += 1
            return action
        if not reads_result_slot(action.payload["words_hex"],
                                 result_address=self.result_address):
            self._policy_counters["policy_not_matched"] += 1
            return action
        self._policy_counters["policy_matched"] += 1
        # A missing witness or any policy violation propagates from here, before
        # the slot policy registers anything and before one RTL command.
        binding = self.binder.bind(action, memory_id=self.memory_id,
                                   byte_offset=self.byte_offset)
        return binding.action

    def observe(self, receipt: object) -> tuple[EffectWitness, ...]:
        """Feed one admitted receipt to the binder -- and so to the tracker once.

        The binder makes two passes over the receipt's events (authoritative
        tracker ingestion, then the writer provenance of the witnesses the
        tracker really retained).  Every session receipt already carries a
        materialized event tuple, so both passes read the same events and no
        event is ever ingested twice by one call.
        """
        self._policy_counters["observations"] += 1
        return self.binder.observe(receipt)

    @property
    def counters(self) -> dict:
        return {**super().counters, **self._policy_counters}

    def document(self) -> dict:
        slot_document = super().document()
        return {**slot_document, "counters": self.counters,
                "slot_gate": slot_document,
                "dynamic_binding": self.binder.document(),
                "ram_prerequisite": self.ram_prerequisite_declaration}


def make_pulp_dual_source_dynamic_binding_gate(
        *, component: str,
        instruction_start: int = ONLINE_INSTRUCTION_START,
        instruction_end: int = ONLINE_INSTRUCTION_END,
        tracker: CrossCaseEffectTracker | None = None,
        result_address: int = RESULT_ADDRESS,
        writer_kinds: tuple[str, ...] = RESULT_SLOT_WRITER_KINDS
        ) -> RamPrerequisiteBindingGate:
    """The shipped slot policy plus the result-slot RAM binding step.

    The slot policy itself is built by
    :func:`make_pulp_dual_source_source_action_gate` -- same declared window,
    same ``max_slots`` capacity refusal, same reservation namespace, same
    tracker object -- and adopted by :class:`RamPrerequisiteBindingGate`; the
    trusted declaration and the ``(memory_id, byte_offset)`` pair come from this
    wiring's own declarations (:func:`result_slot_declaration`,
    :func:`result_slot_ram_location`), never from a caller's claim.
    """
    slot = make_pulp_dual_source_source_action_gate(
        component=component, instruction_start=instruction_start,
        instruction_end=instruction_end, tracker=tracker)
    memory_id, byte_offset = result_slot_ram_location(result_address)
    declaration = TrustedRamByteDeclaration(
        memory_id=memory_id, byte_offsets=(byte_offset,), writer_kinds=writer_kinds)
    return RamPrerequisiteBindingGate.from_slot_gate(
        slot, binder=DynamicPrerequisiteBinder(slot.tracker, declaration),
        result_address=result_address, memory_id=memory_id, byte_offset=byte_offset)


#: Declared schema of the opt-in host-RAM commit journal of this wiring.
HOST_RAM_COMMIT_JOURNAL_SCHEMA_VERSION = "host_ram_commit_journal.v1"


class HostRamCommitJournal:
    """Authenticate and journal this wiring's own host-RAM commits (opt-in).

    A runner journals an issued ``memory_write_commit`` only through a commit
    join (``ScenarioRunner._append_external_events``), and its fallback hook
    ``_uart_ram_commit_join`` is consulted exactly when no UART join is
    configured -- which is this CPU/PULP wiring's case.  This object is that
    hook for a plain host-RAM commit stream:

    * ``stage_commit`` re-authenticates the drained commit against the installed
      service's own callback issuance through :class:`MemoryCommitAuthority`
      (the same authority the UART joins use) and resolves the token at once, so
      the authority stays bounded and the runner's acknowledgement releases the
      service FIFO before its declared capacity can be reached;
    * ``consume`` emits no certificate of its own: this object authorizes the
      commit record the runner already journals, it never invents evidence.

    Nothing is installed unless a session was built with
    ``memory_commit_receipts=True``; the default path keeps the previous runner
    behaviour and the previous session identity byte for byte.
    """

    def __init__(self, services: Mapping, *, max_pending: int = 256) -> None:
        self._authority = MemoryCommitAuthority(services=services,
                                                max_pending=max_pending)

    @property
    def schema_version(self) -> str:
        return HOST_RAM_COMMIT_JOURNAL_SCHEMA_VERSION

    @property
    def degraded(self) -> bool:
        """Whether the bounded authority refused every further claim."""
        return self._authority.degraded

    @property
    def pending_count(self) -> int:
        return self._authority.pending_count

    def document(self) -> dict:
        return {"schema_version": HOST_RAM_COMMIT_JOURNAL_SCHEMA_VERSION,
                "degraded": self.degraded, "pending_count": self.pending_count}

    def stage_commit(self, component, service, ledger, key, receipt) -> bool:
        """Pin and resolve one actual issued commit; ``False`` refuses the log."""
        token = self._authority.stage(component, service, ledger, key, receipt)
        if token is None:
            return False
        return self._authority.resolve(token) is not None

    def consume(self, event) -> tuple:
        """No certificate of its own: the runner journals the commit record."""
        return ()


def install_host_ram_commit_journal(runner: ScenarioRunner, *, component: str,
                                    service
                                    ) -> HostRamCommitJournal:
    """Install the opt-in commit journal on one runner of this wiring.

    The hook is the runner's declared fallback join slot, consulted only when no
    UART join is configured; it is never installed on the default path, so no
    previous runner behaviour moves unless a caller enables
    ``memory_commit_receipts``.
    """
    if not isinstance(component, str) or not component.strip():
        raise ValueError("commit journal requires a component name")
    if getattr(runner, "_uart_ram_commit_join", None) is not None:
        raise ValueError("runner already carries a commit journal")
    journal = HostRamCommitJournal({component: service})
    runner._uart_ram_commit_join = journal
    return journal


def make_pulp_dual_source_factory(
        cache_dir: Path, *, cpu_profile: str, gpio_consumption: bool = False,
        native_irq_receipts: bool = False, source_actions: bool = False,
        memory_commit_receipts: bool = False,
        instruction_start: int = ONLINE_INSTRUCTION_START,
        instruction_end: int = ONLINE_INSTRUCTION_END) -> Callable[[], ScenarioRunner]:
    """Render pinned local harnesses once, then make fresh runner sessions.

    The caller supplies the CPU profile; every other part of the wiring, the
    ownership map and the bindings come from ``dual_source_wiring``. The
    returned factory creates one real CPU plus two real PULP GPIO processes
    when its runner is begun. A caller must keep that runner alive across
    online testcase inputs to avoid repeated initialization.

    ``source_actions`` is the shipped cross-case prerequisite policy switch.
    When it is enabled the returned callable also exposes
    ``new_source_action_gate()``, which builds one *fresh*
    :class:`RamPrerequisiteBindingGate` per session over the declared online
    instruction window (see
    :func:`make_pulp_dual_source_dynamic_binding_gate`, which reuses
    :func:`make_pulp_dual_source_source_action_gate` unchanged).  Gate state is
    run state,
    so it is created per session, is never shared between runners and never
    enters a manifest identity.  The shared factory defaults to disabled so a
    second CPU on this wiring keeps its previous behaviour; the Ibex factory
    below enables it.

    ``memory_commit_receipts`` is the declared host-memory commit-stream switch
    and defaults to disabled: off, the CPU session is byte for byte the previous
    one (no ``memory_commit_stream`` observation, no commit journal installed)
    and only the legacy unattributed ``memory_write`` records are journaled.  On,
    the session declares ``memory_write_commit_stream.v1`` and this factory
    installs the matching :class:`HostRamCommitJournal` on the runner, so each
    issued commit is authenticated, journaled as ``memory_write_commit`` (with
    ``commit_id``, ``commit_document`` and per-cell ``writer_kind``) and
    acknowledged.  That is the only mode in which the declared ``STORE``
    whitelist of the RAM prerequisite policy can be satisfied.
    """
    if type(gpio_consumption) is not bool:
        raise ValueError('gpio_consumption must be boolean')
    if type(native_irq_receipts) is not bool:
        raise ValueError('native_irq_receipts must be boolean')
    if type(source_actions) is not bool:
        raise ValueError('source_actions must be boolean')
    if type(memory_commit_receipts) is not bool:
        raise ValueError('memory_commit_receipts must be boolean')
    cache_dir = Path(cache_dir)
    wiring = dual_source_wiring(cpu_profile=cpu_profile,
                                gpio_consumption=gpio_consumption)
    cpu_artifact = _artifact(wiring.cpu_profile, "cpu")
    a_artifact = _artifact(wiring.gpio_profile, "gpio_a")
    b_artifact = _artifact(wiring.gpio_profile, "gpio_b")
    # The policy names the component the wiring declares as the owner of the
    # persistent RAM the online instruction slots live in; no literal component
    # name and no renderer internals are consulted.
    cpu_component = wiring.memory_component
    if source_actions and cpu_component not in wiring.sessions:
        raise ValueError('declared CPU memory component is not a wiring session')

    def factory() -> ScenarioRunner:
        memory = PersistentMemory(
            regions=wiring.memory_regions,
            initialization_seed=wiring.memory_initialization_seed,
            max_initialized_bytes=wiring.max_initialized_bytes)
        a = GeneratedPulpGpioSession(a_artifact, base_dir=ROOT,
                                     cache_dir=cache_dir)
        b = GeneratedPulpGpioSession(b_artifact, base_dir=ROOT,
                                     cache_dir=cache_dir)
        devices = {"gpio_a": a, "gpio_b": b}
        # Every declared route must resolve to a constructed session before the
        # router exists; the declaration names components, never objects.
        if {"cpu", *devices} != set(wiring.sessions) or wiring.router_initiator != "cpu":
            raise ValueError('declared dual-source wiring does not match the constructed sessions')
        windows = tuple(DeviceWindow(device_id, base, size, devices[component])
                        for device_id, base, size, component in wiring.windows)
        cpu = GeneratedCve2Session(cpu_artifact, base_dir=ROOT,
                                   cache_dir=cache_dir, memory=memory,
                                   router=DataflowRouter(windows), defer_mmio=True,
                                   native_irq_receipts=native_irq_receipts,
                                   memory_commit_receipts=memory_commit_receipts)
        constructed = {"cpu": cpu, **devices}
        runner = ScenarioRunner(
            sessions={name: constructed[name] for name in wiring.sessions},
            ownership=compile_ownership(wiring.ownership_fields,
                                        wiring.ownership_owners),
            bindings=wiring.bindings,
            irq_pulses=dict(wiring.irq_pulse_widths))
        if memory_commit_receipts:
            # The opt-in commit stream journals and acknowledges its own issued
            # commits only through this runner hook; without it the bounded
            # service FIFO would fill and no ``memory_write_commit`` would reach
            # the journal at all.
            install_host_ram_commit_journal(runner, component=cpu_component,
                                            service=cpu.service)
        return runner

    if source_actions:
        # One fresh gate per session: two sessions of one factory never share
        # tracker evidence, because journal event ids restart per runner.  The
        # gate is the adapter of both shipped policies: the slot reservation
        # above plus the result-slot RAM binding of
        # ``make_pulp_dual_source_dynamic_binding_gate``, which reuses this same
        # slot policy and the declared host memory region.
        factory.new_source_action_gate = \
            lambda: make_pulp_dual_source_dynamic_binding_gate(
                component=cpu_component, instruction_start=instruction_start,
                instruction_end=instruction_end)
    return factory


def make_ibex_pulp_dual_source_factory(
        cache_dir: Path, *, cpu_retirement: bool = False,
        gpio_consumption: bool = False,
        native_irq_receipts: bool = False,
        source_actions: bool = True,
        memory_commit_receipts: bool = False) -> Callable[[], ScenarioRunner]:
    """Select the pinned Ibex variant, then share the CPU-agnostic wiring.

    ``cpu_retirement`` selects the authenticated RVFI profile. Native parsed
    IRQ receipts are an Ibex RVFI observation and stay unavailable without it.
    ``source_actions`` is the shipped cross-case prerequisite policy and is on
    by default; ``source_actions=False`` is the explicitly declared legacy path
    with no gate.  ``memory_commit_receipts`` declares the host-memory commit
    stream and stays off by default, so the default identity and behaviour of
    this factory are unchanged.
    """
    if type(cpu_retirement) is not bool:
        raise ValueError('cpu_retirement must be boolean')
    if type(gpio_consumption) is not bool:
        raise ValueError('gpio_consumption must be boolean')
    if type(native_irq_receipts) is not bool or (native_irq_receipts and not cpu_retirement):
        raise ValueError('native IRQ receipts require explicit RVFI retirement')
    if type(source_actions) is not bool:
        raise ValueError('source_actions must be boolean')
    if type(memory_commit_receipts) is not bool:
        raise ValueError('memory_commit_receipts must be boolean')
    return make_pulp_dual_source_factory(
        cache_dir, cpu_profile=RVFI_CPU_PROFILE if cpu_retirement else CPU_PROFILE,
        gpio_consumption=gpio_consumption, native_irq_receipts=native_irq_receipts,
        source_actions=source_actions, memory_commit_receipts=memory_commit_receipts)


@dataclass(frozen=True)
class DualSourceMap:
    graph: DependencyGraph
    ownership: OwnershipMap
    bindings: SourceBindings
    runtime_contract: RuntimePathContract


def _pulp_route_declarations(cpu_id: str, pin_id: str, *, online: bool):
    """Explicit aliases for this trusted fixed topology, not signal discovery."""
    names = (
        ('online.gpio_a.padout', 'online.gpio_a.output', 'online.gpio_b.bound_low',
         'online.gpio_b.irq_from_low', 'online.cpu.irq_from_low',
         'online.gpio_b.padin_after_low_irq', 'online.cpu.padin_after_low_irq',
         'online.gpio_b.pin8', 'online.gpio_b.irq_from_pin8', 'online.cpu.irq_from_pin8',
         'online.gpio_b.padin_after_pin8_irq', 'online.cpu.padin_after_pin8_irq', 'online.gpio_a.isr_padout')
        if online else
        ('gpio_a.padout_state', 'gpio_a.gpio_out', 'gpio_b.pin0',
         'gpio_b.irq_from_a', 'cpu.irq_from_a', 'gpio_b.padin_after_irq', 'cpu.b_padin_after_irq',
         'gpio_b.pin8', 'gpio_b.irq_from_pin8', 'cpu.irq_from_pin8',
         'gpio_b.padin_after_pin8_irq', 'cpu.b_padin_after_pin8_irq', 'gpio_a.padout_from_isr'))
    a_state, a_out, b_low, b_irq, cpu_irq, b_read, cpu_read, b_pin, b_ext_irq, cpu_ext_irq, b_ext_read, cpu_ext_read, a_isr = names
    cpu_path, pin_path = 'cpu_to_ip_to_cpu.closed_loop', 'ip_to_cpu_to_ip.closed_loop'
    rows = (
        (a_state, cpu_id, 'PERSISTENT_STATE_RULE', 'mmio_route', 'gpio_a'),
        (a_out, a_state, 'DATA_BINDING', None, None),
        (b_low, a_out, 'DATA_BINDING', 'direct_binding', None),
        (b_irq, b_low, 'EVENT_ORDER', None, None),
        (cpu_irq, b_irq, 'EVENT_ORDER', 'direct_binding', None),
        (b_read, cpu_irq, 'EVENT_ORDER', 'mmio_route', 'gpio_b'),
        (cpu_read, b_read, 'DATA_BINDING', 'mmio_route', 'gpio_b'),
        (cpu_path, cpu_read, 'EVENT_ORDER', None, None),
        (b_pin, pin_id, 'ENV_PRECONDITION', None, None),
        (b_ext_irq, b_pin, 'EVENT_ORDER', None, None),
        (cpu_ext_irq, b_ext_irq, 'EVENT_ORDER', 'direct_binding', None),
        (b_ext_read, cpu_ext_irq, 'EVENT_ORDER', 'mmio_route', 'gpio_b'),
        (cpu_ext_read, b_ext_read, 'DATA_BINDING', 'mmio_route', 'gpio_b'),
        (a_isr, cpu_ext_read, 'PERSISTENT_STATE_RULE', 'mmio_route', 'gpio_a'),
        (pin_path, a_isr, 'EVENT_ORDER', None, None))
    nodes = (
        RuntimeNode(cpu_id, 'cpu', 'logical'), RuntimeNode(pin_id, 'gpio_b', 'physical', 'gpio_in', 8, 1),
        RuntimeNode(a_state, 'gpio_a', 'state'), RuntimeNode(a_out, 'gpio_a', 'physical', 'gpio_out', 0, 8),
        RuntimeNode(b_low, 'gpio_b', 'physical', 'gpio_in', 0, 8), RuntimeNode(b_irq, 'gpio_b', 'physical', 'irq', 0, 1),
        RuntimeNode(cpu_irq, 'cpu', 'physical', 'irq', 0, 1), RuntimeNode(b_read, 'gpio_b', 'logical'),
        RuntimeNode(cpu_read, 'cpu', 'logical'), RuntimeNode(cpu_path, 'cpu', 'logical'),
        RuntimeNode(b_pin, 'gpio_b', 'physical', 'gpio_in', 8, 1), RuntimeNode(b_ext_irq, 'gpio_b', 'physical', 'irq', 0, 1),
        RuntimeNode(cpu_ext_irq, 'cpu', 'physical', 'irq', 0, 1), RuntimeNode(b_ext_read, 'gpio_b', 'logical'),
        RuntimeNode(cpu_ext_read, 'cpu', 'logical'), RuntimeNode(a_isr, 'gpio_a', 'state'),
        RuntimeNode(pin_path, 'gpio_a', 'logical'))
    if online:
        # Appended ``persistent_state`` declarations of this wiring: CPU store ->
        # host RAM byte version -> later load, and GPIO A PADOUT register commit
        # -> later read of that same register bit version.  They extend the
        # declaration *after* every legacy row, so no existing rule index,
        # contract field, enumerated path or endpoint moves.
        rows = rows + (
            (ONLINE_RAM_VERSION_NODE, cpu_id, 'PERSISTENT_STATE_RULE',
             'persistent_state',
             (ONLINE_RAM_RESOURCE_COMPONENT, ONLINE_RAM_RESOURCE_ID)),
            (ONLINE_GPIO_REGISTER_VERSION_NODE, a_isr, 'PERSISTENT_STATE_RULE',
             'persistent_state',
             (ONLINE_GPIO_REGISTER_RESOURCE_COMPONENT,
              ONLINE_GPIO_REGISTER_RESOURCE_ID)))
        nodes = nodes + (
            RuntimeNode(ONLINE_RAM_VERSION_NODE, ONLINE_RAM_RESOURCE_COMPONENT,
                        'logical'),
            RuntimeNode(ONLINE_GPIO_REGISTER_VERSION_NODE,
                        ONLINE_GPIO_REGISTER_RESOURCE_COMPONENT, 'logical'))
    rules = tuple(DependencyRule(target, (prerequisite,), kind) for target, prerequisite, kind, _, _ in rows)
    edges = tuple(RuntimeEdgeContract(index, 0, relation, **(
        {'initiator_component': 'cpu', 'device_id': device,
         'base': 0x40001000 if device == 'gpio_a' else 0x40000000, 'size': 0x1000}
        if relation == 'mmio_route' else
        {'resource_component': device[0], 'resource_id': device[1]}
        if relation == 'persistent_state' else {}))
        for index, (_, _, _, relation, device) in enumerate(rows) if relation is not None)
    return rules, nodes, edges


def _pulp_runtime_contract(graph, nodes, edges):
    graph_hash = hashlib.sha256(json.dumps(graph.edge_document(), sort_keys=True,
        separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()
    return RuntimePathContract(graph_hash, nodes, edges)


def _dual_template_source_span(seed, maximum):
    """Validate the fixed dual-template x1/A store, preserving the legacy map."""
    first, last = (next(image for image in genome.initial_images
                        if image.component == 'cpu' and image.image_id == 'boot')
                   for genome in (seed, maximum))
    if len(first.data) != len(last.data):
        raise ValueError('dual-source boot image length differs')
    changed = [byte * 8 + bit for byte, (left, right) in enumerate(zip(first.data, last.data))
               for bit in range(8) if (left ^ right) & (1 << bit)]
    if len(changed) != 7 or changed != list(range(changed[0], changed[0] + 7)) or changed[0] % 32 != 21:
        raise ValueError('dual-source immediate must be seven contiguous ADDI bits')
    offset = changed[0] // 32 * 4
    words = tuple(int.from_bytes(image.data[offset:offset + 4], 'little') for image in (first, last))
    stores = tuple(int.from_bytes(image.data[offset + 4:offset + 8], 'little') for image in (first, last))
    if words != (0x00100113, 0x0ff00113):
        raise ValueError('dual-source immediate is not ADDI x2, x0, 1/255')
    if stores == (0x0021a623,) * 2:
        return _source_span(seed, maximum)
    if (stores != (0x0020a623,) * 2 or offset < 16
            or any(int.from_bytes(image.data[offset - 16:offset - 12], 'little') != 0x400010b7
                   for image in (first, last))):
        raise ValueError('dual-source x1 PADOUT store lacks fixed GPIO A base')
    return changed[0], 7


def make_ibex_pulp_dual_source_map(
        seed: ScenarioGenome, maximum: ScenarioGenome) -> DualSourceMap:
    """Declare two candidate paths for a pinned legal ADDI/MMIO program.

    ``seed`` and ``maximum`` must share the boot image and differ only in the
    seven high immediate bits of ``ADDI x2, x0, imm`` immediately before a
    ``SW x2`` to GPIO A PADOUT. This is a deliberately narrow legal-instruction
    source; an arbitrary instruction generator needs its own ISA validation.
    The companion template builder supplies a pin-8 Action and compatible
    CPU IRQ/ISR program, validated with this same ownership map. The graph
    describes candidate propagation; it does not establish runtime coverage.
    """
    first = next((image for image in seed.initial_images
                  if image.component == "cpu" and image.image_id == "boot"), None)
    last = next((image for image in maximum.initial_images
                 if image.component == "cpu" and image.image_id == "boot"), None)
    if first is None or last is None or first.address != 0x10080 \
            or last.address != first.address:
        raise ValueError("dual-source map requires matching Ibex boot images")
    source_offset, source_width = _dual_template_source_span(seed, maximum)
    cpu_source = "cpu.program.gpio_a_padout_immediate"
    pin_source = "gpio_b.external_pin8"
    rules, nodes, edges = _pulp_route_declarations(cpu_source, pin_source, online=False)
    graph = DependencyGraph(
        sources=(
            FuzzableSource(cpu_source, "cpu", "boot", source_offset,
                           source_width, ("CPU_TO_IP_TO_CPU",), "memory_image"),
            FuzzableSource(pin_source, "gpio_b", "gpio_in", 8, 1,
                           ("IP_TO_CPU_TO_IP",), "source"),
        ),
        rules=rules)
    ownership = dual_source_ownership()
    bindings = SourceBindings((
        SourceBinding(cpu_source, "memory_image", "cpu", "boot",
                      source_offset, source_width,
                      "initial_image:cpu:boot", first.address),
        SourceBinding(pin_source, "source", "gpio_b", "gpio_in", 8, 1,
                      "external_b.pin8"),
    ))
    bindings.validate(graph, ownership, (seed, maximum))
    return DualSourceMap(graph, ownership, bindings, _pulp_runtime_contract(graph, nodes, edges))


@dataclass(frozen=True)
class DualSourceTemplates:
    """Legal examples; real propagation remains pending runtime acceptance.

    Boot image mutation is admitted before initialization. An active session
    keeps its boot image immutable and can continue accepting pin events.
    """

    cpu_seed: ScenarioGenome
    cpu_maximum: ScenarioGenome
    ip_seed: ScenarioGenome
    decoder: GenomeRecordDecoder
    runtime_accepted: bool = False


def make_ibex_pulp_dual_source_templates(*, max_steps: int = 400
                                       ) -> DualSourceTemplates:
    """Provide real CPU configuration/ISR and a separately mutable pin action.

    B GPIOEN/INTEN enable pins 0 and 8. INTTYPE_LOW uses bit 16 for pin 8
    rising edges. The ISR reads real PADIN, saves it to RAM, shifts pin 8
    into A PADOUT, and reads INTSTATUS to acknowledge the observed event.
    """
    def addi(rd: int, rs: int, value: int) -> int:
        return ((value & 0xfff) << 20) | (rs << 15) | (rd << 7) | 0x13

    def sw(rs: int, base: int, offset: int) -> int:
        return (((offset >> 5) & 0x7f) << 25) | (rs << 20) | (base << 15) | \
            (2 << 12) | ((offset & 31) << 7) | 0x23

    def lw(rd: int, base: int, offset: int) -> int:
        return (offset << 20) | (base << 15) | (2 << 12) | (rd << 7) | 3

    def genome(output: int, direction: str) -> ScenarioGenome:
        # x1=B, x3=A, x4=RAM; the CSR setup is fixed, never fuzzed.
        main = [0x400000b7, addi(2, 0, 0x101), sw(2, 1, 4),
                sw(2, 1, 0x18), 0x00010137, addi(2, 2, 1),
                sw(2, 1, 0x1c), 0x00010137, addi(2, 2, 0x100),
                0x30511073, 0x00001137, addi(2, 2, -2048), 0x30412073,
                addi(2, 0, 8), 0x30012073, 0x400010b7,
                addi(2, 0, 0xff), sw(2, 1, 0), 0x00010237,
                addi(2, 0, output), sw(2, 1, 0x0c), 0x0000006f]
        loop = 0x10080 + 4 * (len(main) - 1)
        isr = [0x400000b7, lw(2, 1, 8), sw(2, 4, 0),
               0x00815113, 0x400011b7, sw(2, 3, 0x0c),
               lw(2, 1, 0x24), 0x30200073]
        data = bytearray(b"\x13\x00\x00\x00" * 64)
        for address, words in ((0x10080, main), (0x10100, isr),
                               (0x1012c, isr)):
            start = address - 0x10080
            packed = b"".join(word.to_bytes(4, "little") for word in words)
            data[start:start + len(packed)] = packed
        actions = ()
        if direction == "IP_TO_CPU_TO_IP":
            # Real idle-loop fetch follows all configuration instructions.
            actions = (Action(
                "external-b-pin8-rise", "gpio_b", "gpio_in", 1,
                direction, Trigger("AFTER_OUTPUT", "cpu", "instr_addr",
                                   0xffffffff, loop),
                delay_component="gpio_b", delay_ticks=4,
                bit_offset=8, width=1),)
        return ScenarioGenome(
            testcase_id=f"dual-source-{direction.lower()}-{output}",
            direction=direction, path_id=f"dual-source-{direction.lower()}",
            schedule_order=("cpu", "gpio_a", "gpio_b"), max_steps=max_steps,
            actions=actions,
            initial_images=(MemoryImage("boot", "cpu", 0x10080, data.hex()),))

    seed = genome(1, "CPU_TO_IP_TO_CPU")
    maximum = genome(255, "CPU_TO_IP_TO_CPU")
    ip_seed = genome(0, "IP_TO_CPU_TO_IP")
    source_map = make_ibex_pulp_dual_source_map(seed, maximum)
    decoder = GenomeRecordDecoder(
        graph=source_map.graph, ownership=source_map.ownership,
        source_bindings=source_map.bindings, runtime_contract=source_map.runtime_contract,
        templates=(DecoderTemplate("cpu_to_ip_to_cpu.closed_loop", seed),
                   DecoderTemplate("ip_to_cpu_to_ip.closed_loop", ip_seed)))
    return DualSourceTemplates(seed, maximum, ip_seed, decoder)


@dataclass(frozen=True)
class DualSourceStreamBootstrap:
    """Fixed startup images and an uninitialized online instruction interval."""

    template: ScenarioGenome
    instruction_start: int
    instruction_end: int
    runtime_accepted: bool = False

    @property
    def instruction_count(self) -> int:
        return (self.instruction_end - self.instruction_start) // 4


def _lui(rd: int, value: int) -> int:
    return ((value & 0xfffff) << 12) | (rd << 7) | 0x37


def _addi(rd: int, base: int, value: int) -> int:
    return ((value & 0xfff) << 20) | (base << 15) | (rd << 7) | 0x13


def _sw(rs: int, base: int, offset: int) -> int:
    return (((offset >> 5) & 127) << 25) | (rs << 20) | (base << 15) | \
        (2 << 12) | ((offset & 31) << 7) | 0x23


def _lw(rd: int, base: int, offset: int) -> int:
    return (offset << 20) | (base << 15) | (2 << 12) | (rd << 7) | 3


def _jal(pc: int, destination: int) -> int:
    """Encode and self-check one fixed JAL; no legalization is inferred."""
    offset = destination - pc
    if offset % 2 or not -(1 << 20) <= offset < 1 << 20:
        raise ValueError("fixed jump target exceeds JAL displacement")
    value = offset & 0x1fffff
    word = (((value >> 20) & 1) << 31) | (((value >> 1) & 0x3ff) << 21) | \
        (((value >> 11) & 1) << 20) | (((value >> 12) & 0xff) << 12) | 0x6f
    decoded = (((word >> 31) & 1) << 20) | (((word >> 21) & 0x3ff) << 1) | \
        (((word >> 20) & 1) << 11) | (((word >> 12) & 0xff) << 12)
    signed = decoded - (1 << 21) if decoded & (1 << 20) else decoded
    if signed != offset or word & 0xfff != 0x6f:
        raise ValueError("fixed JAL encoding does not reach instruction reservation")
    return word


def _lui_addi_load(rd: int, value: int) -> tuple[int, int]:
    """Encode ``lui rd, hi; addi rd, rd, lo`` for one 32-bit constant."""
    if type(value) is not int or not 0 <= value < 1 << 32:
        raise ValueError("loaded constant must be a 32-bit word")
    high = (value + 0x800) >> 12
    low = value - (high << 12)
    if not -2048 <= low < 2048 or high >= 1 << 20:
        raise ValueError("loaded constant does not fit one lui/addi pair")
    return _lui(rd, high), _addi(rd, rd, low)


def make_pulp_dual_source_stream_bootstrap(
        *, program: DualSourceCpuProgram,
        instruction_start: int = ONLINE_INSTRUCTION_START,
        instruction_end: int = ONLINE_INSTRUCTION_END
        ) -> DualSourceStreamBootstrap:
    """Jump from fixed real startup to reserved, initially absent RAM words.

    Before begin(), call session.declare_instruction_slots('cpu',
    result.instruction_start, result.instruction_count). The stream is finite;
    its end is an admission limit followed by fixed self-loop guard words. Fixed
    CSR setup and ISR are outside the fuzzed RV32I subset. Runtime acceptance
    remains pending; the jump displacement is checked by decoding its fields.

    ``program`` carries the declared per-CPU facts and nothing else changes:
    the GPIO configuration, the trap vector slots, the ISR body and its
    addresses, the online interval and the guard words are shared bytes.
    """
    if type(program) is not DualSourceCpuProgram:
        raise ValueError("a declared dual-source CPU program is required")
    if any(type(value) is not int or value % 4
           for value in (instruction_start, instruction_end)) or not (
               0x11000 <= instruction_start < instruction_end
               and instruction_end + 64 <= ISR_SCRATCH):
        raise ValueError("online instructions and fixed guard must fit below ISR scratch")
    if RESULT_ADDRESS % 0x1000:
        raise ValueError("ISR result slot must be one aligned lui pointer")
    if not (program.first_fetch <= program.main_address < VECTOR_BASE
            and program.main_address % 4 == 0
            and program.mtvec_value % 256 == program.mtvec_value % 2):
        raise ValueError("declared CPU program does not fit the shared firmware layout")
    if program.boot_trampoline != (program.first_fetch != program.main_address):
        raise ValueError("declared CPU program trampoline must match its first fetch")

    # GPIO configuration matches the dual-source examples; no initial edge.
    mtvec_high, mtvec_low = _lui_addi_load(2, program.mtvec_value)
    scratch_high, scratch_low = _lui_addi_load(2, ISR_SCRATCH)
    main = [0x400000b7, _addi(2, 0, 0x101), _sw(2, 1, 4), _sw(2, 1, 0x18),
            0x00010137, _addi(2, 2, 1), _sw(2, 1, 0x1c),
            0x400010b7, _addi(2, 0, 0xff), _sw(2, 1, 0), _sw(2, 1, 4),
            _sw(0, 1, 0x0c),
            mtvec_high, mtvec_low, 0x30511073,
            scratch_high, scratch_low, 0x34011073,
            0x00001137, _addi(2, 2, -2048), 0x30412073,
            _addi(2, 0, 8), 0x30012073]
    main.append(_jal(program.main_address + len(main) * 4, instruction_start))
    # mscratch exchanges the interrupted x31 with the reserved scratch pointer;
    # save and restore all other registers used by this fixed handler.  The
    # observed PADIN byte is stored to the shared result slot the checker reads.
    swap_scratch = (0x340 << 20) | (31 << 15) | (1 << 12) | (31 << 7) | 0x73
    result_pointer = _lui(3, RESULT_ADDRESS >> 12)
    isr = [swap_scratch, _sw(1, 31, 0), _sw(2, 31, 4), _sw(3, 31, 8),
           0x400000b7, _lw(2, 1, 8), result_pointer, _sw(2, 3, 0),
           0x00815113, 0x400011b7, _sw(2, 3, 0x0c), _lw(2, 1, 0x24),
           _lw(1, 31, 0), _lw(2, 31, 4), _lw(3, 31, 8), swap_scratch, 0x30200073]
    # Both pinned vector conventions land on a slot that jumps to the one
    # shared handler: entry 0 for direct mode and exception entry, entry 11
    # (0x1012c) for a vectored machine external interrupt.
    segments = tuple(
        ([("cpu.stream.entry", program.first_fetch,
           [_jal(program.first_fetch, program.main_address)])]
         if program.boot_trampoline else [])
        + [("cpu.stream.bootstrap", program.main_address, main),
           ("cpu.stream.direct_vector", VECTOR_BASE, [_jal(VECTOR_BASE, ISR_BASE)]),
           ("cpu.stream.external_vector", EXTERNAL_VECTOR,
            [_jal(EXTERNAL_VECTOR, ISR_BASE)]),
           ("cpu.stream.isr", ISR_BASE, isr),
           ("cpu.stream.end", instruction_end,
            [_jal(instruction_end + 4 * index, instruction_end + 4 * index)
             for index in range(16)])])
    images = tuple(MemoryImage(name, "cpu", address,
                               b"".join(word.to_bytes(4, "little")
                                        for word in words).hex())
                   for name, address, words in segments)
    for image in images:
        if image.address < instruction_end and instruction_start < image.address + len(image.data):
            raise ValueError("startup image overlaps online instruction slots")
    template = ScenarioGenome(
        testcase_id=program.testcase_id, direction="MULTI_COMPONENT_CHAIN",
        path_id="cpu-and-pin8-online-stream", schedule_order=("cpu", "gpio_a", "gpio_b"),
        max_steps=512, actions=(), initial_images=images)
    return DualSourceStreamBootstrap(template, instruction_start, instruction_end)


def make_ibex_pulp_dual_source_stream_bootstrap(
        *, instruction_start: int = ONLINE_INSTRUCTION_START,
        instruction_end: int = ONLINE_INSTRUCTION_END
        ) -> DualSourceStreamBootstrap:
    """The Ibex instance of the shared stream firmware (unchanged bytes)."""
    return make_pulp_dual_source_stream_bootstrap(
        program=IBEX_STREAM_CPU_PROGRAM, instruction_start=instruction_start,
        instruction_end=instruction_end)


#: Identity of the one fixed bootstrap program segment whose end bounds the
#: declared initial RAM data window below.  It is a declared segment name of
#: :func:`make_pulp_dual_source_stream_bootstrap`, not a discovered fact.
STREAM_BOOTSTRAP_IMAGE_ID = "cpu.stream.bootstrap"
#: Upper bound of the declared initial data window.  A widened or moved layout
#: must fail closed here instead of silently mutating another region.
INITIAL_RAM_DATA_WINDOW_LIMIT = 256


def declared_initial_ram_data_window(
        bootstrap: DualSourceStreamBootstrap) -> TrustedInitialRamDataDeclaration:
    """The declared initial RAM data window of one stream bootstrap.

    Rule, applied to the bootstrap's own declaration only: the window is the
    contiguous gap between the end of the one fixed bootstrap program image
    (:data:`STREAM_BOOTSTRAP_IMAGE_ID`) and the next declared segment above it.
    The fixed firmware leaves exactly that gap un-materialized, so the real CPU
    prefetch of the first word there is this wiring's shipped "unknown byte
    first read", and a pre-session initial image inside the gap is what that
    first read then returns.

    Fail closed: a layout without that segment, without a following segment, with
    a gap outside the declared RAM window, with a gap overlapping the online
    instruction reservation, or with a gap wider than
    :data:`INITIAL_RAM_DATA_WINDOW_LIMIT` raises instead of guessing a window.
    """
    if not isinstance(bootstrap, DualSourceStreamBootstrap):
        raise ValueError("a declared dual-source stream bootstrap is required")
    images = tuple(bootstrap.template.initial_images)
    program = next((image for image in images
                    if image.image_id == STREAM_BOOTSTRAP_IMAGE_ID), None)
    if program is None:
        raise ValueError("stream bootstrap declares no fixed program segment")
    start = program.address + len(program.data)
    following = sorted(image.address for image in images
                       if image.address >= start)
    if not following:
        raise ValueError("stream bootstrap declares no segment after the program")
    byte_count = following[0] - start
    if not 1 <= byte_count <= INITIAL_RAM_DATA_WINDOW_LIMIT:
        raise ValueError("declared initial RAM data window exceeds its bound")
    reservation = (bootstrap.instruction_start, bootstrap.instruction_end)
    if start < reservation[1] and reservation[0] < start + byte_count:
        raise ValueError("declared initial RAM data window overlaps the reservation")
    region = next((item for item in DUAL_SOURCE_MEMORY_REGIONS
                   if item.base <= start
                   and start + byte_count <= item.base + item.size), None)
    if region is None:
        raise ValueError("declared initial RAM data window is outside the declared RAM")
    return TrustedInitialRamDataDeclaration(
        scope="ibex_pulp_dual_source.cpu.stream.bootstrap.gap",
        component="cpu", memory_id=region.memory_id, base=start,
        byte_count=byte_count, value_mask=0xFF, value_base=0)


#: Declared schema of the opt-in per-case cross-case advance policy.
IP_CROSS_CASE_ADVANCE_SCHEMA_VERSION = "ip_cross_case_advance.v1"
#: The one declared rule that policy implements.  It is published so a reviewer
#: recomputes every per-case budget from the decoder document instead of
#: trusting a per-run story.
IP_CROSS_CASE_RULE = "declared_external_source_case_advances_one_declared_round"


class IpCrossCaseOnlineDecoder(OnlineCaseDecoder):
    """The shipped decoder plus one declared per-case budget for the IP source.

    Why a per-case budget is the minimal trusted change: this wiring's session
    executes one case's declared advances as one uninterrupted batch, and the
    IRQ the external pin source raises is delivered to the CPU by a *later local
    step* of the same batch.  A source case that owns the whole declared budget
    therefore accepts its own interrupt and completes its ISR inside one case,
    which is exactly the ``IP_TO_CPU_TO_IP`` same-case result P3 already has.
    Nothing in the runner clears a pending pulse at a case boundary -- the
    pulse is measured in CPU local ticks, and no CPU tick passes between two
    cases -- so the only fact that has to change is how many declared rounds a
    source case runs.

    Declared rule (:data:`IP_CROSS_CASE_RULE`), applied by :meth:`_decode_case`
    before any RTL command:

    * a decoded case whose source is the *one* declared external source named at
      construction (component, port, bit offset and width all taken from that
      declared :class:`OnlineSource`) advances exactly ``cross_case_rounds``
      declared rounds -- one by default -- instead of the decoder's
      ``advance_rounds``;
    * every other case, including every CPU instruction case, keeps the
      unchanged declared budget, so instruction search, the instruction
      reservation cursor and the per-case ``local_step_budget`` of the CPU path
      do not move;
    * the declared schedule itself is untouched: the shortened case still steps
      the same declared components in the same declared order, so the injected
      value is applied by that case's own final declared step and the IRQ pulse
      it raises can only be accepted by a later case's CPU step.

    The declaration is published by :meth:`document` and therefore enters the
    saved ``decoder_manifest.json``; the object is only ever built when a caller
    asks for it, so the shipped decoder document -- and every run identity
    produced without this option -- is unchanged.
    """

    def __init__(self, *, cross_case_source_id: str, cross_case_rounds: int = 1,
                 **kwargs) -> None:
        super().__init__(**kwargs)
        if type(cross_case_source_id) is not str or not cross_case_source_id:
            raise ValueError("cross-case budget requires a declared source identity")
        source = next((item for item in self.sources
                       if item.source_id == cross_case_source_id), None)
        if source is None or source.kind != "source":
            raise ValueError(
                "cross-case budget requires one declared external source")
        if (type(cross_case_rounds) is not int or cross_case_rounds < 1
                or cross_case_rounds >= len(self.advances)):
            # A "shortened" budget that is not shorter would silently change
            # nothing while still changing the run identity, so it is refused.
            raise ValueError("cross-case budget must shorten the declared case budget")
        self.cross_case_source = source
        self.cross_case_rounds = cross_case_rounds

    @property
    def cross_case_declaration(self) -> dict:
        """The declared per-case budget a reviewer recomputes a case from."""
        source = self.cross_case_source
        return {
            "schema_version": IP_CROSS_CASE_ADVANCE_SCHEMA_VERSION,
            "rule": IP_CROSS_CASE_RULE,
            "source_id": source.source_id, "component": source.component,
            "port": source.port, "bit_offset": source.bit_offset,
            "width": source.width, "direction": source.direction,
            "advance_rounds": self.cross_case_rounds,
            "declared_advance_rounds": len(self.advances),
            "declared_schedule": list(self.advances[0].schedule),
            "effect": ("the declared source case applies its injected value at "
                       "its own final declared step, so the interrupt pulse it "
                       "raises can only be accepted by a later case's CPU step"),
            "not_proof_of": ["DUT causality", "cross-case acceptance"],
        }

    def document(self) -> dict:
        """The shipped decoder document plus this opt-in policy block."""
        return {**super().document(), "ip_cross_case": self.cross_case_declaration}

    def _decode_case(self, raw, *, coverage_hints=None):
        """Shorten the declared source case, keeping every other case unchanged."""
        case, degradation, direct_selected = super()._decode_case(
            raw, coverage_hints=coverage_hints)
        adjusted = self._cross_case_case(case)
        if adjusted is not case:
            # ``decode`` and ``decode_candidate`` promise that ``commit`` follows
            # the returned case; the shipped implementation retained the
            # unadjusted proposal, so the replacement is retained here.
            self._proposal = adjusted
        return adjusted, degradation, direct_selected

    def _cross_case_case(self, case):
        """Replace one case's advance budget, or return it unchanged."""
        source = case.source
        declared = self.cross_case_source
        if (not isinstance(source, BatchSourceEvent)
                or source.component != declared.component
                or source.port != declared.port
                or source.bit_offset != declared.bit_offset
                or source.width != declared.width):
            return case
        return replace(case, advances=self.advances[:self.cross_case_rounds])


def make_ibex_pulp_dual_source_online_decoder(
        *, bootstrap: DualSourceStreamBootstrap | None = None,
        result_slot_readback: bool = False,
        result_slot_byte_store: bool = False,
        ip_cross_case: bool = False):
    """Assemble checked online source declarations for this fixed RTL wiring.

    Paths are candidate causal chains, not coverage claims. Instruction
    mutation may generate a NOP or change configuration without closing a
    chain. Real events alone can establish downstream consumption. MMIO
    mutation is confined to A PADOUT for this first closed-loop path. B's
    interrupt configuration is written by real CPU bootstrap instructions;
    a separate configuration path can expose those registers later without
    destroying this path's preconditions. Read-only/status addresses are not
    generated here.

    ``result_slot_readback`` appends the declared result slot
    (``RESULT_ADDRESS``, the byte the fixed ISR stores at) as a second readable
    4-byte window beside GPIO A PADOUT, so the decoder can propose the ``LW``
    the RAM prerequisite policy consumes.  It stays off by default because this
    builder is shared with the second CPU of this wiring
    (``cv32e40p_pulp_dual_source`` delegates here): the default declaration, and
    therefore every other campaign's decoder identity, is unchanged.

    ``result_slot_byte_store`` is the explicit opt-in partial byte write of the
    declared result-slot window and stays off by default.  Off, not one
    declaration moves: the windows, the allowed operations and therefore the
    whole decoder document are the shipped bytes.  On (it requires
    ``result_slot_readback``, the window the opt-in narrows), the builder
    declares exactly :func:`result_slot_byte_store_declaration`: the result-slot
    window gains the one-byte write width of
    ``RESULT_SLOT_BYTE_STORE_OPERATION`` and that operation joins the declared
    set, while GPIO A PADOUT is narrowed to word-only so no byte write can be
    proposed to a device register.  Address, width and alignment refusals keep
    their shipped codes
    (``rv32i_sources.mutate_mmio_access``/``mmio_access_fragment``).

    ``ip_cross_case`` is the opt-in per-case budget declaration of
    :class:`IpCrossCaseOnlineDecoder` and stays off by default: off, this
    function returns the shipped decoder object and byte-for-byte the shipped
    decoder document, so no existing run identity moves.  On, only the declared
    external pin-8 source case is shortened to one declared round; see the
    class below for the declared rule and its exact effect.
    """
    from .online_case_decoder import (OnlineDependencyGraph,
                                      OnlineDependencySource, OnlineSource)
    from .rv32i_sources import MmioWindow

    if type(result_slot_readback) is not bool:
        raise ValueError("result slot readback must be boolean")
    if type(result_slot_byte_store) is not bool:
        raise ValueError("result slot byte store must be boolean")
    if result_slot_byte_store and not result_slot_readback:
        raise ValueError(
            "result slot byte store requires the declared result slot window")
    if type(ip_cross_case) is not bool:
        raise ValueError("IP cross-case declaration must be boolean")
    if bootstrap is None:
        bootstrap = make_ibex_pulp_dual_source_stream_bootstrap()
    if not isinstance(bootstrap, DualSourceStreamBootstrap):
        raise ValueError("dual-source stream bootstrap is required")
    windows = ((MmioWindow(0x4000100c, 4), MmioWindow(RESULT_ADDRESS, 4))
               if result_slot_readback else (MmioWindow(0x4000100c, 4),))
    allowed_mmio_operations = ("LW", "SW")
    if result_slot_byte_store:
        # The one declared narrow width is confined to the result-slot window:
        # ``mutate_mmio_access`` only offers a byte store to windows whose
        # declared write widths contain it, so every other window stays
        # word-only and every other address keeps its shipped refusal.
        windows = tuple(
            replace(window,
                    write_widths=(RESULT_SLOT_BYTE_STORE_WRITE_WIDTHS
                                  if window.base == RESULT_ADDRESS
                                  else RESULT_SLOT_WORD_ONLY_WRITE_WIDTHS))
            for window in windows)
        allowed_mmio_operations = (*allowed_mmio_operations,
                                   RESULT_SLOT_BYTE_STORE_OPERATION)
    cpu_id = "cpu.online_instruction"
    pin_id = "gpio_b.external_pin8"
    cpu_path = "cpu_to_ip_to_cpu.closed_loop"
    pin_path = "ip_to_cpu_to_ip.closed_loop"
    rules, nodes, edges = _pulp_route_declarations(cpu_id, pin_id, online=True)
    graph = OnlineDependencyGraph(
        sources=(OnlineDependencySource(cpu_id, "instruction", "cpu",
                                        ("CPU_TO_IP_TO_CPU",)),
                 OnlineDependencySource(pin_id, "source", "gpio_b",
                                        ("IP_TO_CPU_TO_IP",),
                                        port="gpio_in", bit_offset=8, width=1)),
        rules=rules)
    declared = dict(
        sources=(OnlineSource(cpu_id, "instruction", "cpu", "CPU_TO_IP_TO_CPU", cpu_path,
                              coverage_target_ids=("gpio_a_output_bit0", "cpu_data_write")),
                 OnlineSource(pin_id, "source", "gpio_b", "IP_TO_CPU_TO_IP", pin_path,
                              port="gpio_in", bit_offset=8, width=1,
                              coverage_target_ids=("gpio_b_irq",
                                                   "cpu_external_irq_vector_fetch"))),
        graph=graph, runtime_contract=_pulp_runtime_contract(graph, nodes, edges), ownership=dual_source_ownership(),
        # The CPU instruction path starts with real MMIO control; the external
        # pin path starts with the GPIO interrupt event delivered to Ibex.
        flow_by_target={cpu_path: "F4", pin_path: "F5"},
        schedule=bootstrap.template.schedule_order,
        instruction_start=bootstrap.instruction_start,
        instruction_end=bootstrap.instruction_end,
        windows=windows,
        max_steps=bootstrap.template.max_steps, max_input_bytes=8,
        advance_rounds=32,
        allowed_mmio_operations=allowed_mmio_operations,
        support_words=4)
    if not ip_cross_case:
        return OnlineCaseDecoder(**declared)
    return IpCrossCaseOnlineDecoder(cross_case_source_id=pin_id, **declared)

