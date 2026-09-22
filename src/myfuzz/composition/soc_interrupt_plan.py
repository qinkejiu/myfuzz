"""Deterministic interrupt source numbering, controller instance and routing plan.

The first-phase topology is fixed by the assurance plan: every peripheral
interrupt output goes to one generic controller, the controller raises one
same-domain level notification, and the CPU reaches both the controller's MMIO
window and the peripheral clear registers over the bus.

Numbering is computed, never looked up: sources are ordered by stable instance
id, interface id, the source id the profile declares and the logical bit order
inside the port.  Input list order, physical port names and component models do
not participate.  A plan that cannot be represented by the verified controller
capacity is rejected instead of being truncated.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from .component_profile import (
    INTERRUPT_EDGE_PARAMETER,
    INTERRUPT_TRIGGERS,
    INTERRUPT_TRIGGERS_EDGE_DETECTED,
    ProfileBinding,
)

INTERRUPT_PLAN_SCHEMA = "soc_interrupt_plan.v1"
CONTROLLER_MODULE = "soc_irq_controller"
CONTROLLER_VERSION = "soc_irq_controller.v1"
CONTROLLER_RTL_SOURCE = "src/myfuzz/protocols/rtl/soc_irq_controller.sv"
#: The converter the renderer inserts for an edge-shaped (held) source.  It is
#: published as part of the plan so the composition's source closure and the
#: independent audit can both see which module a source really goes through.
EDGE_DETECT_MODULE = "soc_irq_edge_detect"
EDGE_DETECT_RTL_SOURCE = "src/myfuzz/protocols/rtl/soc_irq_edge_detect.sv"
EDGE_DETECT_VERSION = "soc_irq_edge_detect.v1"
#: CPU interrupt semantics this composer can really wire.  Everything else is
#: refused by name rather than being wired to the one external entry point; see
#: ``CPU_IRQ_SEMANTICS_REFUSED`` for the enumerated refusals and their reasons.
CPU_IRQ_SEMANTICS_SUPPORTED = ("machine_external",)
CPU_IRQ_SEMANTICS_REFUSED = {
    "machine_timer": "the controller drives one external entry point and has no "
                     "machine-timer compare path",
    "machine_software": "there is no software-interrupt register in the controller",
    "supervisor_external": "the composer only binds the machine-mode external entry",
    "supervisor_timer": "the composer only binds the machine-mode external entry",
    "supervisor_software": "the composer only binds the machine-mode external entry",
    "user_external": "the composer only binds the machine-mode external entry",
    "nmi": "a non-maskable entry cannot be expressed by a maskable level controller",
    "debug": "debug entry is an external debugger request, not an interrupt source",
    "machine_local": "local interrupts are not routed through the controller",
}
#: Admission limit for this controller implementation version.  It is not
#: derived from the register bitmap width: it is the largest source count that
#: the controller's independent behavioural verification actually exercised
#: (see tests/protocols/test_soc_irq_controller_rtl.py).  Raising it requires
#: adding and passing a wider verification case first.
CONTROLLER_VERIFIED_SOURCES = 40
CONTROLLER_VERIFIED_CASES = (1, 40)
HEADER_BYTES = 0x20
CONTROLLER_NOTIFY_POLARITY = "active_high"


class InterruptPlanError(ValueError):
    """The declared interrupt topology cannot be realized as specified."""


def _error(reason: str) -> None:
    raise InterruptPlanError(reason)


@dataclass(frozen=True, slots=True)
class InterruptSourceRequest:
    """One declared interrupt source, before numbering."""

    instance_id: str
    component_id: str
    endpoint_id: str
    role: str
    declared_source_id: str = ""
    bit: int | None = None


@dataclass(frozen=True, slots=True)
class ResolvedSource:
    source_id: int
    instance_id: str
    component_id: str
    endpoint_id: str
    role: str
    declared_source_id: str
    port: str
    bit: int
    polarity: str
    polarity_inversion: bool
    trigger: str
    clock_domain: str
    hold: str
    clear: str
    #: How the source's raw output reaches the controller's sampling input.
    #: ``{"kind": "direct"}`` means the (optionally polarity-inverted) source is
    #: wired straight in: the controller's per-cycle sampling is the capture
    #: mechanism.  ``{"kind": "edge_detect", ...}`` means the renderer inserts
    #: ``soc_irq_edge_detect`` so a *held* edge-shaped condition produces exactly
    #: one event instead of re-pending after every COMPLETE.
    normalizer: Mapping[str, object] = field(default_factory=dict)
    #: Profile-declared MMIO preparation bits for the source's raise path.
    prerequisites: tuple[Mapping[str, object], ...] = ()
    #: Ordered stores used to raise the source after a peer is armed.
    raise_actions: tuple[Mapping[str, object], ...] = ()

    @property
    def converter(self) -> str | None:
        return None if self.normalizer.get("kind") == "direct" \
            else str(self.normalizer.get("module", "")) or None

    def document(self) -> dict[str, object]:
        return {
            "source_id": self.source_id,
            "instance_id": self.instance_id,
            "component_id": self.component_id,
            "endpoint_id": self.endpoint_id,
            "role": self.role,
            "declared_source_id": self.declared_source_id,
            "port": self.port,
            "bit": self.bit,
            "polarity": self.polarity,
            "polarity_inversion": self.polarity_inversion,
            "trigger": self.trigger,
            "clock_domain": self.clock_domain,
            "controller_bit": self.source_id - 1,
            "hold": self.hold,
            "clear": self.clear,
            "prerequisites": [dict(item) for item in self.prerequisites],
            "raise_actions": [dict(item) for item in self.raise_actions],
            "normalizer": dict(self.normalizer),
        }


@dataclass(frozen=True, slots=True)
class CpuEntry:
    instance_id: str
    component_id: str
    endpoint_id: str
    role: str
    port: str
    bit: int
    polarity: str
    inversion: bool
    semantics: str
    domain: str

    def document(self) -> dict[str, object]:
        return {
            "instance_id": self.instance_id,
            "component_id": self.component_id,
            "endpoint_id": self.endpoint_id,
            "role": self.role,
            "port": self.port,
            "bit": self.bit,
            "polarity": self.polarity,
            "inversion": self.inversion,
            "semantics": self.semantics,
            "clock_domain": self.domain,
        }


@dataclass(frozen=True, slots=True)
class InterruptPlan:
    controller_instance_id: str | None
    module: str
    version: str
    rtl_source: str
    num_sources: int
    id_width: int
    bitmap_words: int
    #: Address width of the controller's own byte-address port.  The controller
    #: decodes a window-LOCAL offset, so this is the width of the declared
    #: window, not the fabric width; the renderer feeds it the proven low bits.
    address_width: int
    fabric_address_width: int
    window_size: int
    window_alignment: int
    register_map: tuple[dict[str, object], ...]
    sources: tuple[ResolvedSource, ...]
    cpu_entry: CpuEntry | None
    notify_polarity: str
    verified_max_sources: int
    #: Bit k set means controller bit k (source id k+1) is latched: pending is
    #: set-dominant and cleared only by CLAIM.  Derived from the sources' own
    #: declared capture contracts, never passed in, so the rendered parameter and
    #: the plan can only agree.
    latch_mask: int = 0
    gaps: tuple[str, ...] = ()

    @property
    def present(self) -> bool:
        return self.controller_instance_id is not None

    def source_for(self, instance_id: str, endpoint_id: str, bit: int) -> ResolvedSource | None:
        for item in self.sources:
            if (item.instance_id, item.endpoint_id, item.bit) == (instance_id, endpoint_id, bit):
                return item
        return None


def window_base_alignment_ok(size: int) -> bool:
    """A window of ``size`` bytes is self-aligned and a power of two."""
    return size > 0 and size & (size - 1) == 0


def _bitmap_words(num_sources: int) -> int:
    return (num_sources + 1 + 31) // 32


def _window_size(bitmap_words: int) -> int:
    required = HEADER_BYTES + 8 * bitmap_words
    size = 0x20
    while size < required:
        size <<= 1
    return size


def register_map(num_sources: int) -> tuple[dict[str, object], ...]:
    """The frozen 32-bit register ABI for one controller capacity."""
    words = _bitmap_words(num_sources)
    registers: list[dict[str, object]] = [
        {"name": "CLAIM", "offset": 0x00, "access": "ro", "side_effect": "claim_and_clear_pending",
         "description": "Returns the claimed source id, or 0 when nothing can be claimed."},
        {"name": "COMPLETE", "offset": 0x04, "access": "wo", "side_effect": "complete_in_service",
         "description": "Accepts only the id currently in service; anything else is an error."},
        {"name": "IN_SERVICE", "offset": 0x08, "access": "ro", "side_effect": "none",
         "description": "Current in-service source id, 0 when idle."},
        {"name": "SOURCE_COUNT", "offset": 0x0c, "access": "ro", "side_effect": "none",
         "description": "Number of physical sources N."},
    ]
    for index in range(words):
        registers.append({
            "name": f"PENDING{index}", "offset": HEADER_BYTES + 4 * index, "access": "ro",
            "side_effect": "none",
            "description": f"Pending bitmap word {index}; bit k is source id {32 * index}+k.",
        })
    for index in range(words):
        registers.append({
            "name": f"ENABLE{index}", "offset": HEADER_BYTES + 4 * words + 4 * index,
            "access": "rw", "side_effect": "none",
            "description": f"Enable bitmap word {index}; reset value 0.",
        })
    return tuple(registers)


def _resolve_source(binding: ProfileBinding, request: InterruptSourceRequest,
                    profile_source: object) -> ResolvedSource:
    endpoint = binding.endpoint(request.endpoint_id)
    if endpoint.function != "interrupt_source":
        _error(f"interrupt-endpoint-not-a-source:{request.endpoint_id}")
    field = next((item for item in endpoint.fields if item.role == request.role), None)
    if field is None:
        _error(f"interrupt-role-not-bound:{request.endpoint_id}:{request.role}")
    bit = request.bit
    if bit is None:
        if field.width != 1:
            # A multi-bit vector with one aggregate declaration is only legal
            # when it really is one summary output.  The generator never ORs
            # several outputs together on its own.
            _error(f"interrupt-vector-bit-ambiguous:{request.instance_id}:"
                   f"{request.endpoint_id}:{request.role}:width={field.width}")
        bit = field.raw_lo
    if not field.raw_lo <= bit <= field.raw_hi:
        _error(f"interrupt-bit-outside-port:{request.instance_id}:{request.endpoint_id}:"
               f"{request.role}:{bit}")
    polarity = getattr(profile_source, "polarity")
    if polarity not in ("active_high", "active_low"):
        _error(f"unsupported-interrupt-polarity:{polarity}")
    trigger = str(getattr(profile_source, "trigger"))
    normalizer = _normalizer(request, trigger, polarity, profile_source)
    return ResolvedSource(
        source_id=0,
        instance_id=request.instance_id,
        component_id=request.component_id,
        endpoint_id=request.endpoint_id,
        role=request.role,
        declared_source_id=request.declared_source_id,
        port=field.port,
        bit=bit,
        polarity=polarity,
        polarity_inversion=polarity != CONTROLLER_NOTIFY_POLARITY,
        trigger=getattr(profile_source, "trigger"),
        clock_domain=getattr(profile_source, "clock_domain"),
        hold=getattr(profile_source, "hold"),
        clear=getattr(profile_source, "clear"),
        normalizer=normalizer,
        prerequisites=tuple(dict(item) for item in
                            getattr(profile_source, "prerequisites", ()) or ()),
        raise_actions=tuple(dict(item) for item in
                            getattr(profile_source, "raise_actions", ()) or ()),
    )


def _normalizer(request: InterruptSourceRequest, trigger: str, polarity: str,
                profile_source: object) -> dict[str, object]:
    """How one source's raw output is turned into what the controller samples.

    The controller samples its input on every clock, so:
      * ``level`` is wired straight in and follows its input;
      * ``pulse`` is wired straight in, and the declared ``pulse_width_cycles``
        is the capture contract that makes the sampling correct;
      * the three edge triggers describe a source that *holds* an edge-shaped
        condition, so ``soc_irq_edge_detect`` is inserted.  Polarity inversion
        happens *before* the detector, so the detector always sees an
        active-high signal whose idle level is 0 and a rising edge is the only
        thing that can fire it.  That is why the rendered ``RESET_LEVEL`` is
        always 0.
    """
    if trigger == "pulse":
        width = getattr(profile_source, "pulse_width_cycles", None)
        if not isinstance(width, int) or isinstance(width, bool) or width < 1:
            _error(f"interrupt-pulse-width-required:{request.instance_id}:"
                   f"{request.endpoint_id}:{request.role}")
        return {"kind": "direct", "capture": "controller-latches-every-high",
                "pending": "latched-until-claim",
                "pulse_width_cycles": width,
                "declared_idle_level": 0 if polarity == "active_high" else 1}
    if trigger in INTERRUPT_TRIGGERS_EDGE_DETECTED:
        width = getattr(profile_source, "detect_pulse_cycles", 1)
        if not isinstance(width, int) or isinstance(width, bool) or width < 1:
            _error(f"invalid-interrupt-detect-pulse-width:{request.instance_id}:"
                   f"{request.endpoint_id}:{request.role}")
        return {
            "kind": "edge_detect",
            "module": EDGE_DETECT_MODULE,
            "version": EDGE_DETECT_VERSION,
            "source": EDGE_DETECT_RTL_SOURCE,
            "edge": trigger,
            "edge_parameter": INTERRUPT_EDGE_PARAMETER[trigger],
            "pulse_cycles": width,
            "reset_level": 0,
            "polarity_before_detector": polarity,
            "capture": "one-event-per-edge",
            # The converter emits a pulse, so the controller must latch it: a
            # level-following pending bit would drop the event before the CPU
            # could claim it (this is exactly the defect the edge lifecycle run
            # found).
            "pending": "latched-until-claim",
            "non_features": ["no-clock-domain-crossing", "no-glitch-filter"],
        }
    if trigger != "level":
        _error(f"unsupported-interrupt-trigger:{trigger}:{request.instance_id}:"
               f"{request.endpoint_id}:{request.role}")
    return {"kind": "direct", "capture": "controller-follows-level",
            "pending": "follows-input-level",
            "declared_idle_level": 0 if polarity == "active_high" else 1}


def build_interrupt_plan(*, sources: Sequence[tuple[InterruptSourceRequest, object]],
                         bindings: Mapping[str, ProfileBinding],
                         cpu_instance_id: str,
                         cpu_binding: ProfileBinding,
                         cpu_profile: object,
                         address_width: int) -> InterruptPlan:
    """Assign controller source ids and the CPU entry, or reject the topology."""
    if isinstance(address_width, bool) or not isinstance(address_width, int) or address_width < 5:
        _error("interrupt-controller-address-width")
    cpu = getattr(cpu_profile, "cpu", None)
    if cpu is None:
        _error("cpu-contract-missing")
    entry_endpoint_id = getattr(cpu, "irq_entry_endpoint", None)
    entry_role = getattr(cpu, "irq_entry_role", None)
    semantics = getattr(cpu, "irq_semantics", None)
    cpu_entry: CpuEntry | None = None
    if entry_endpoint_id is None:
        if getattr(cpu, "boot_address_required", True):
            _error(f"cpu-interrupt-entry-undeclared:{cpu_instance_id}")
    else:
        endpoint = cpu_binding.endpoint(entry_endpoint_id)
        if endpoint.function != "interrupt_entry":
            _error(f"cpu-entry-not-an-interrupt-entry:{entry_endpoint_id}")
        if entry_role is None:
            _error(f"cpu-interrupt-entry-role-undeclared:{entry_endpoint_id}")
        field = next((item for item in endpoint.fields if item.role == entry_role), None)
        if field is None:
            _error(f"cpu-interrupt-entry-role-not-bound:{entry_endpoint_id}:{entry_role}")
        if field.width != 1:
            _error(f"cpu-interrupt-entry-vector-unsupported:{entry_endpoint_id}:{entry_role}:"
                   f"width={field.width}")
        if semantics not in CPU_IRQ_SEMANTICS_SUPPORTED:
            if semantics in CPU_IRQ_SEMANTICS_REFUSED:
                _error(f"unsupported-cpu-interrupt-semantics:{semantics}:"
                       f"{CPU_IRQ_SEMANTICS_REFUSED[semantics]}")
            _error(f"unsupported-cpu-interrupt-semantics:{semantics}:"
                   f"unknown-semantics:supported="
                   f"{','.join(CPU_IRQ_SEMANTICS_SUPPORTED)}")
        entry_polarity = str(getattr(cpu, "irq_entry_polarity", "active_high"))
        if entry_polarity not in ("active_high", "active_low"):
            _error(f"unsupported-cpu-interrupt-polarity:{entry_polarity}")
        cpu_entry = CpuEntry(
            instance_id=cpu_instance_id,
            component_id=cpu_binding.component_id,
            endpoint_id=entry_endpoint_id,
            role=entry_role,
            port=field.port,
            bit=field.raw_lo,
            polarity=entry_polarity,
            inversion=entry_polarity != CONTROLLER_NOTIFY_POLARITY,
            semantics=str(semantics),
            domain=_clock_domain_of(cpu_binding),
        )

    ordered: list[ResolvedSource] = []
    for request, profile_source in sources:
        binding = bindings.get(request.instance_id)
        if binding is None:
            _error(f"interrupt-source-instance-unknown:{request.instance_id}")
        if binding.component_id != request.component_id:
            _error(f"interrupt-source-component-mismatch:{request.instance_id}")
        if getattr(profile_source, "trigger") not in INTERRUPT_TRIGGERS:
            _error(f"unsupported-interrupt-trigger:{getattr(profile_source, 'trigger')}"
                   f":{request.instance_id}:{request.endpoint_id}")
        ordered.append(_resolve_source(binding, request, profile_source))
    ordered.sort(key=lambda item: (item.instance_id, item.endpoint_id,
                                   item.declared_source_id, item.bit, item.role))
    physical: set[tuple[str, str, int]] = set()
    for item in ordered:
        key = (item.instance_id, item.port, item.bit)
        if key in physical:
            _error(f"duplicate-physical-interrupt-source:{item.instance_id}:{item.port}[{item.bit}]")
        physical.add(key)

    num_sources = len(ordered)
    numbered = tuple(
        ResolvedSource(
            source_id=index + 1, instance_id=item.instance_id, component_id=item.component_id,
            endpoint_id=item.endpoint_id, role=item.role,
            declared_source_id=item.declared_source_id or f"{item.endpoint_id}:{item.role}",
            port=item.port, bit=item.bit, polarity=item.polarity,
            polarity_inversion=item.polarity_inversion, trigger=item.trigger,
            clock_domain=item.clock_domain, hold=item.hold, clear=item.clear,
            normalizer=item.normalizer, prerequisites=item.prerequisites,
            raise_actions=item.raise_actions,
        )
        for index, item in enumerate(ordered)
    )
    for item in numbered:
        if item.clock_domain != "core":
            _error(f"cross-domain-interrupt-source:{item.instance_id}:{item.clock_domain}")

    gaps: list[str] = []
    if num_sources > CONTROLLER_VERIFIED_SOURCES:
        _error(f"interrupt-controller-capacity-exceeded:{num_sources}>"
               f"{CONTROLLER_VERIFIED_SOURCES}")
    if not numbered:
        gaps.append(
            "no interrupt source is declared, so no controller is instantiated; the CPU entry "
            "must be disabled by contract and no interrupt-driven coverage is claimed")
        if cpu_entry is not None:
            # The entry cannot be left floating: the plan records the constant
            # that disables it, which the renderer materialises.
            cpu_entry = CpuEntry(
                instance_id=cpu_entry.instance_id, component_id=cpu_entry.component_id,
                endpoint_id=cpu_entry.endpoint_id, role=cpu_entry.role, port=cpu_entry.port,
                bit=cpu_entry.bit, polarity=cpu_entry.polarity, inversion=cpu_entry.inversion,
                semantics=cpu_entry.semantics + "+disabled_no_sources",
                domain=cpu_entry.domain,
            )
        return InterruptPlan(
            controller_instance_id=None, module=CONTROLLER_MODULE, version=CONTROLLER_VERSION,
            rtl_source=CONTROLLER_RTL_SOURCE, num_sources=0, id_width=1, bitmap_words=0,
            address_width=address_width, fabric_address_width=address_width,
            window_size=0, window_alignment=0,
            register_map=(), sources=(), cpu_entry=cpu_entry,
            notify_polarity=CONTROLLER_NOTIFY_POLARITY,
            verified_max_sources=CONTROLLER_VERIFIED_SOURCES, gaps=tuple(gaps))

    words = _bitmap_words(num_sources)
    size = _window_size(words)
    if size > (1 << address_width):
        _error(f"interrupt-controller-window-exceeds-address-width:{size}")
    id_width = max(1, (num_sources + 1 - 1).bit_length())
    # The controller sees the window-local byte offset, so its address port is
    # exactly as wide as the window needs.  Slicing the fabric address to these
    # bits is lossless because the window base is a multiple of the window size
    # (checked above) and the size fits the width by construction.
    local_width = max(5, (size - 1).bit_length())
    if window_base_alignment_ok(size) is False:
        _error(f"interrupt-controller-window-not-self-aligned:{size}")
    return InterruptPlan(
        controller_instance_id="irq_controller0",
        module=CONTROLLER_MODULE,
        version=CONTROLLER_VERSION,
        rtl_source=CONTROLLER_RTL_SOURCE,
        num_sources=num_sources,
        id_width=id_width,
        bitmap_words=words,
        address_width=local_width,
        fabric_address_width=address_width,
        window_size=size,
        window_alignment=size,
        register_map=register_map(num_sources),
        sources=numbered,
        cpu_entry=cpu_entry,
        notify_polarity=CONTROLLER_NOTIFY_POLARITY,
        verified_max_sources=CONTROLLER_VERIFIED_SOURCES,
        latch_mask=latch_mask_of(numbered),
        gaps=tuple(gaps),
    )


def latch_mask_of(sources: Sequence[ResolvedSource]) -> int:
    """Bit ``k`` set means controller bit ``k`` (source id ``k+1``) is latched.

    A source is latched exactly when its capture contract is a *moment* rather
    than a *state*: a bounded ``pulse`` (which the controller could otherwise
    follow down again before the CPU claims) and any edge-detected source (whose
    converter emits a pulse).  A ``level`` source is not latched, so the
    controller keeps following its input.
    """
    mask = 0
    for item in sources:
        if str(item.normalizer.get("pending", "")) == "latched-until-claim":
            mask |= 1 << (int(item.source_id) - 1)
    return mask


def latch_mask_bits(mask: int, width: int) -> str:
    """The mask as the sized SystemVerilog literal the renderer emits."""
    return f"{int(width)}'b{int(mask):0{int(width)}b}"


def _clock_domain_of(binding: ProfileBinding) -> str:
    return binding.clocks[0][0].domain if binding.clocks else "core"


def interrupt_plan_document(plan: InterruptPlan, *,
                            window_base: int | None = None,
                            provenance: Mapping[str, object] | None = None) -> dict[str, object]:
    """The versioned interrupt plan, including the three physical paths."""
    window: dict[str, object] | None = None
    if plan.present:
        if window_base is None:
            _error("interrupt-controller-window-base-required")
        if window_base % plan.window_alignment:
            _error(f"interrupt-controller-window-misaligned:{window_base}")
        if not window_base_alignment_ok(plan.window_size) or window_base % plan.window_size:
            _error(f"interrupt-controller-window-not-self-aligned:"
                   f"base=0x{window_base:x}:size=0x{plan.window_size:x}")
        window = {
            "base": window_base,
            "size": plan.window_size,
            # The target sees this local base; the fabric forwards the global
            # address, so the renderer connects the proven low address bits.
            "local_base": 0,
            "address_width": plan.address_width,
            "fabric_address_width": plan.fabric_address_width,
            "narrowing_proof": (f"window base 0x{window_base:x} is a multiple of its size "
                                f"0x{plan.window_size:x}, so the low {plan.address_width} "
                                f"address bits carry the local offset without aliasing"),
        }
    document: dict[str, object] = {
        "schema_version": INTERRUPT_PLAN_SCHEMA,
        "controller": {
            "present": plan.present,
            "instance_id": plan.controller_instance_id,
            "module": plan.module,
            "version": plan.version,
            "rtl_source": plan.rtl_source,
            "num_sources": plan.num_sources,
            "id_width": plan.id_width,
            "bitmap_words": plan.bitmap_words,
            "verified_max_sources": plan.verified_max_sources,
            "parameters": ({"NUM_SOURCES": plan.num_sources,
                            "ADDRESS_WIDTH": plan.address_width,
                            "LATCH_MASK": plan.latch_mask} if plan.present else {}),
            "latch_mask": plan.latch_mask if plan.present else 0,
            "latch_mask_literal": (latch_mask_bits(plan.latch_mask, plan.num_sources)
                                   if plan.present else ""),
            "latched_source_ids": [item.source_id for item in plan.sources
                                   if str(item.normalizer.get("pending", ""))
                                   == "latched-until-claim"],
            "window": window,
            "register_map": [dict(item) for item in plan.register_map],
            "notify_polarity": plan.notify_polarity,
            "reserved_bits": "bit 0 of every bitmap word is reserved and reads 0",
        },
        "sources": [item.document() for item in plan.sources],
        "paths": {
            "source_to_controller": [
                {
                    "path_id": f"irq_src:{item.source_id}",
                    "from": {"instance_id": item.instance_id, "port": item.port, "bit": item.bit},
                    "to": {"instance_id": plan.controller_instance_id,
                           "port": "source_i", "bit": item.source_id - 1},
                    "inversion": item.polarity_inversion,
                    "reason": f"declared {item.polarity} source normalized to the controller's "
                              f"{plan.notify_polarity} level convention",
                }
                for item in plan.sources
            ],
            "controller_to_cpu": ([{
                "path_id": "irq_notify",
                "from": {"instance_id": plan.controller_instance_id, "port": "irq_o"},
                "to": {"instance_id": plan.cpu_entry.instance_id,
                       "port": plan.cpu_entry.port, "bit": plan.cpu_entry.bit},
                "inversion": plan.cpu_entry.inversion,
                "reason": "controller notification is active high and the declared CPU entry "
                          "semantics is %s" % plan.cpu_entry.semantics,
            }] if (plan.present and plan.cpu_entry is not None) else []),
            "cpu_to_mmio": ([{
                "path_id": "irq_mmio",
                "from": {"instance_id": plan.cpu_entry.instance_id,
                         "interface": plan.cpu_entry.endpoint_id},
                "to": {"instance_id": plan.controller_instance_id,
                       "window_base": window_base, "window_size": plan.window_size},
                "inversion": False,
                "reason": "CLAIM/COMPLETE/IN_SERVICE/ENABLE are reached over the CPU data path",
            }] if (plan.present and plan.cpu_entry is not None) else []),
        },
        "service_contract": {
            "priority": "fixed_lowest_id",
            "in_service": "single_source_no_nesting",
            "pending": "level_sampled_each_clock_unless_latched",
            "pending_latched": "set_dominant_cleared_only_by_claim",
            "complete": "id_matching_write_only",
            "peripheral_clear": "separate_cpu_mmio_operation_on_the_peripheral",
            "environment_control_entry": "none",
        },
        # Which triggers this composition really consumes, and with what.  The
        # independent audit re-reads this list against the rendered converters,
        # so it is a claim and not a comment.
        "trigger_support": _trigger_support(plan),
        "cpu_entry_support": {
            "supported": list(CPU_IRQ_SEMANTICS_SUPPORTED),
            "refused": dict(CPU_IRQ_SEMANTICS_REFUSED),
        },
        "gaps": list(plan.gaps),
    }
    if plan.cpu_entry is not None:
        document["cpu_entry"] = plan.cpu_entry.document()
    if provenance is not None:
        document["provenance"] = dict(provenance)
    return document


def _trigger_support(plan: InterruptPlan) -> dict[str, object]:
    """The per-trigger converters the plan actually instantiated."""
    direct = sorted({item.trigger for item in plan.sources if item.normalizer.get("kind")
                     == "direct"})
    converted = sorted({item.trigger for item in plan.sources
                        if item.normalizer.get("kind") == "edge_detect"})
    return {
        "direct": direct,
        "edge_detected": converted,
        "module": EDGE_DETECT_MODULE,
        "rtl_source": EDGE_DETECT_RTL_SOURCE,
        "version": EDGE_DETECT_VERSION,
        "instances": [
            {
                "source_id": item.source_id,
                "instance_id": item.instance_id,
                "endpoint_id": item.endpoint_id,
                "role": item.role,
                "net": f"irq_src_{item.source_id}",
                **{k: v for k, v in item.normalizer.items() if k != "non_features"},
            }
            for item in plan.sources if item.normalizer.get("kind") == "edge_detect"
        ],
        "cross_domain": "refused; the detector is synchronous and same-domain only",
    }


__all__ = [
    "CONTROLLER_MODULE",
    "CONTROLLER_RTL_SOURCE",
    "CONTROLLER_VERIFIED_CASES",
    "CONTROLLER_VERIFIED_SOURCES",
    "CONTROLLER_VERSION",
    "CPU_IRQ_SEMANTICS_REFUSED",
    "CPU_IRQ_SEMANTICS_SUPPORTED",
    "EDGE_DETECT_MODULE",
    "EDGE_DETECT_RTL_SOURCE",
    "EDGE_DETECT_VERSION",
    "HEADER_BYTES",
    "INTERRUPT_PLAN_SCHEMA",
    "CpuEntry",
    "InterruptPlan",
    "InterruptPlanError",
    "InterruptSourceRequest",
    "ResolvedSource",
    "build_interrupt_plan",
    "interrupt_plan_document",
    "latch_mask_bits",
    "latch_mask_of",
    "register_map",
]
