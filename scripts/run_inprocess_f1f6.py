#!/usr/bin/env python3
"""Build and run one process that receives F1-F6 inputs on one CPU/IP/DMA set.

One CPU model, one register target model, optional Wishbone DMA, and host RAM
are initialized once.  The shared loop supports declared OBI or Wishbone CPU
buses and APB3 or AXI4-Lite register targets within the limits of each binding.
Available flows depend on the CPU, target, and DMA declarations: for example,
the current Wishbone CPU binding does not provide IRQ delivery or DMA, and an
AXI4-Lite UART without declared IRQ behavior cannot run F5.  Unsupported target
kinds and flows are refused by name.
The CPU executes a fixed polling program from that RAM, so
a case is handed over by writing one mailbox word (or the instruction trampoline
slot, or the input block the CPU reads); no case recompiles, re-initializes or
resets any model.  The six flows share that one RAM, one address route, one IRQ
delivery and one model lifetime:

* F1 the CPU fetches and retires one word from the trampoline slot
* F2 the CPU reads a RAM word or the target
* F3 the CPU stores to RAM
* F4 the CPU stores through the target window
* F5 the CPU writes the declared trigger registers, the target's own IRQ output
  is sampled and delivered to the CPU input its profile declares, and the ISR
  reads the declared status register, stores the value it read, and returns
* F6 the CPU copies the input block into DMA source RAM and configures the DMA
  control port; the DMA master really reads that RAM and really writes the
  destination, its completion IRQ is delivered, and the ISR stores the status
  word it read while clearing the declared interrupt.  The transfer is the one
  ``myfuzz.composition.dma_transfer`` plans: the block is 1..8 words for ZipDMA
  (four for the proven wbdmac path), the start word, length encoding and master
  byte enables are the plan's, and a declared response delay is generated and
  measured per response instead of assumed.  A declared ``dma_route`` replaces
  the RAM destination with one fixed target register: the host presents each
  accepted master write on that target's APB3 request port, holds the master
  until the target answers, and the F6 firmware reads the declared evidence word
  before and after the transfer so a FIFO level is a readback, not an inference

Nothing is wired per CPU x IP combination: which models exist and which I/O names
they expose comes from the generated binding header, and the report contains only
facts the models produced.  Unsupported components, windows, or device behavior
are refused by name.  F5 exists only when the target declares the four facts it
needs (an IRQ output, its bit, a writable trigger sequence and one readable
status word); a target that declares none of them keeps F1-F4 and F6 and the
report states the refusal by name.  The result is a compact observation, not a
certificate and not a replay.

Two input modes share that loop.  ``--records`` (optionally ``--online``) hands
over the operator's fixed sequence.  ``--fuzz`` runs the same process as a
closed loop: after each case line its *observed* facts (retirements, target
transfers, IRQ takes, DMA traffic, traps, timeouts) score the input and the
declaration-driven input space produces the next legal one.  No model is
rebuilt, reset or restarted between ordinary cases.

F1 is the one flow whose input can be a short program: ``f1_program_words``
declares 1..16 words, the firmware points x18 at the declared data window, and
the host writes the words plus a fixed return jump into the trampoline slot.
The case line reports the real retirement count, order and installed-word match,
the RVFI writeback mask and last writeback, traps and the sampled data-window
changes.  Only LUI/AUIPC/OP-IMM/OP and full-word LW/SW against x18 are admitted
by default; a scenario may additionally declare strictly-forward B-type
branches (``f1_allow_branches``) and statically proven computed memory bases
(``f1_allow_address_forms``).  A branch program may skip words, so its evidence
is the in-slot RVFI retirement trace (``prog_trace_hash``/``prog_trace_count``/
``prog_pc_order``) compared with the Python reference trace; no JAL/JALR, CSR
word, compressed parcel, loop or out-of-image branch is admitted.

Device behavior - how an interrupt is triggered and cleared, which register is
its status word, how pads resolve, where the DMA control status bits live - is
declared in ``source_behavior``/``dma_behavior`` files (or the historical
inline scenario keys); the protocol adapter itself is written once.  F5/F6
wait loops are bounded: a case that never sees its interrupt writes the timeout
marker 2, is reported as ``wait_timeout 1``, and only the devices are reset
before the next case (``wait_timeouts``/``device_resets`` in the summary).

``--quiet`` suppresses the per-tick/per-transfer event lines while keeping the
case and summary lines; fuzz mode always uses it.  Neither mode claims RTL
coverage, a certificate or a replay.
"""
import argparse
from collections import Counter
from pathlib import Path
import json
import math
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT))

from scripts.inprocess_build import build_axi4_adapter, build_link_run
from myfuzz.local_harness.build import build_local_harness_with_receipt
from scripts.profile_scenario_inputs import _capability
from scripts.run_inprocess_f1f4 import (Program, _check_spans, _jalr, explicit_timing,
                                        incremental_runner, run_arguments)
from myfuzz.composition.multi_target import (declared_targets, route_address,
                                             target_as_legacy_config, target_for_f5,
                                             target_windows, targets_for_f5)

# Fixed offsets of the one RAM image.  Nothing here moves between cases: only the
# trampoline slot word, the mailbox, the handler block the ISR reads and the DMA
# source block are written by the host between cases.
VECTOR_OFFSET = 0x200
HANDLER_OFFSET = 0x400
MAIN_OFFSET = 0x1000
SLOT_OFFSET = 0x2000
MAILBOX_OFFSET = 0x3000
HANDLER_BLOCK_OFFSET = MAILBOX_OFFSET + 0x40
DATA_OFFSET = 0x4000
RESULT_OFFSET = 0x5000
DMA_SOURCE_OFFSET = 0x6000
DMA_DESTINATION_OFFSET = 0x7000
INPUT_BLOCK = 16                      # first input word inside the mailbox
#: The mailbox span the host reports and checks.  F5 and F6 read their input words
#: from ``INPUT_BLOCK``; the eight-word F6 block this increment admits needs
#: ``INPUT_BLOCK + 4*8 = 48`` bytes, which stays clear of the handler block the
#: ISR reads at ``HB = 0x40``.  A block longer than eight words would need a
#: larger gap between the mailbox and the handler block and is refused by name
#: rather than silently overlapping it.
MAILBOX_BYTES = INPUT_BLOCK + 4 * 8
#: The deepest DMA block this entry actually executes.  The C++ host honours
#: ``DMA_BLOCK_WORDS`` and accepts a 1..16-word record; the bound here is the
#: entry's own RAM image (the input block above, the source/destination spans
#: below) and that is what an F6 record is refused against.
DMA_MAX_BLOCK_WORDS = 8
#: The deepest block each pinned device has actually been run at through this
#: entry, reported beside the planner's device bound.  ZipDMA's LENGTH register
#: encodes far more; wbdmac's block-length field is the low LGMEMLEN=10 bits of its
#: start word, and the eight-word transfer this entry now executes is inside it.
DMA_PROVEN_BLOCK_WORDS = {'zipdma': DMA_MAX_BLOCK_WORDS, 'wbdmac': DMA_MAX_BLOCK_WORDS}
#: The longest host-generated master response delay this entry can produce and
#: measure.  The planner admits up to 64 declared ticks; the entry refuses more
#: than it has a scenario for rather than silently clamping.
DMA_MAX_RESPONSE_DELAY = 8
#: The word every F6 destination cell (and the guard word on either side of the
#: declared block) is pre-filled with before a case.  A DMA word that is never
#: written therefore reads back as this sentinel instead of as zero, and a write
#: outside the declared block is visible in the guard words.
DMA_DESTINATION_SENTINEL = 0xA5A5A5A5
#: The word the two route-evidence RAM cells hold before a routed case.  It is
#: not a legal PULP SPI STATUS value (the control-status field is 7 bits and the
#: reserved field is zero), so a cell that still holds it was never written by
#: this case's firmware and the level is reported as unknown instead of stale.
DMA_ROUTE_SENTINEL = 0xFFFFFFFF
#: The route shapes this entry executes.  A fixed-destination write into one
#: declared APB3 target, a fixed-source read from one declared readable APB3
#: register or FIFO port, and an incrementing read over a declared readable
#: register aperture are the shapes the C++ host implements.  Anything else is
#: refused by name, never run as if it were a RAM transfer.
DMA_ROUTE_DIRECTIONS = ('write', 'read')
DMA_ROUTE_ADDRESS_MODES = ('fixed', 'aperture')
#: The register side effect a FIFO read route needs: the pinned RTL pops on the
#: read access itself.  A readable register without it is not a FIFO.
DMA_ROUTE_FIFO_POP_SIDE_EFFECT = 'read_pops_fifo'
#: The evidence kinds this host can read back.  ``fifo_level`` needs a readable
#: word with a declared bit field and depth; ``register_readback`` needs a
#: readable word (a write route changes it, a read route must return it
#: unchanged).
DMA_ROUTE_EVIDENCE_KINDS = ('fifo_level', 'register_readback')
# The handler block keeps the cells the ISR reads plus the flag cell.  Their
# offsets are stated from the mailbox pointer, the base the ISR already holds.
# The first five cells are the historical single-link set: one status address,
# one result cell, one clear address/value and the flag.  A "both" case
# (two declaring targets, one link each) publishes a second status/result/clear
# set, the two cause masks the handler tests, the serviced mask the firmware
# waits on and the expected mask.  A build without a both link leaves the second
# set at zero, so the ISR skips it and the historical single-link case lines and
# their handler traffic are unchanged.  A declaration whose clear is an ordered
# two-write sequence adds the second step's address/value pair (HB_CLEAR_B); a
# build with no such declaration leaves it at zero and emits the historical
# single-clear ISR byte for byte.
HB = 0x40
HB_STATUS, HB_RESULT, HB_CLEAR, HB_CLEAR_VALUE, HB_FLAG = HB, HB + 4, HB + 8, HB + 12, HB + 16
HB_STATUS2, HB_RESULT2, HB_CLEAR2, HB_CLEAR_VALUE2 = HB + 20, HB + 24, HB + 28, HB + 32
HB_MASK1, HB_MASK2, HB_NEED, HB_SERVICED = HB + 36, HB + 40, HB + 44, HB + 48
HB_CLEAR_B, HB_CLEAR_VALUE_B = HB + 52, HB + 56
HANDLER_BLOCK_BYTES = 60
#: The longest declared clear-write sequence this ISR performs.  One handler cell
#: pair per step means two: the single-link path carries HB_CLEAR +
#: HB_CLEAR_VALUE for the first step and HB_CLEAR_B + HB_CLEAR_VALUE_B for the
#: second.  Anything longer is refused by name instead of being truncated.
MAX_CLEAR_WRITES = 2
DATA_WORDS = (0xDEADBEEF, 0x11111111, 0x00000000)
#: The declared program data window, in 32-bit words, starting at the data base.
#: A multi-word F1 program gets x18 = that base from the firmware, and its only
#: allowed memory words are LW/SW against it.  The host samples exactly this
#: window before and after a case, so ``data_changed`` is a measured effect.
PROGRAM_DATA_WORDS = 16
#: How many instruction words one F1 record may carry when the scenario declares
#: a program (default 1 keeps the single-word legacy input unchanged).
MAX_F1_PROGRAM_WORDS = 16
MRET_WORD = 0x30200073
FLOW_ARITY = {'F1': 1, 'F2': 1, 'F3': 2, 'F4': 2}
# The one adapter decision of this entry: which target kind the selected profile
# declares, which protocol that means, and which bridge module the generated model
# instantiates for it.  The bridge name is quoted in the binding header so a saved
# run states which of the two real RTL bridges carried its transfers.
TARGET_PROTOCOLS = {'apb3_register_observe': 'apb3',
                    'axi4lite_register_observe': 'axi4-lite',
                    # The pinned PULP GPIO is an APB3 register target with an
                    # extra pin endpoint.  It is the same protocol behind the same
                    # bridge; the pin side is an observation this host adds, not a
                    # second target protocol.
                    'apb_gpio': 'apb3',
                    # The generic Wishbone register member.  Its generated model
                    # drives the pinned target kernel through beat_to_wishbone and
                    # exposes that kernel's own cyc/stb/we/adr/dat_w/sel/ack/dat_r
                    # as passive taps, so a case can state the real handshake it
                    # sampled.  The specialised wishbone_timer/wishbone_uart kinds
                    # are not mapped: the timer exposes no passive protocol trace
                    # at all and the uart's trace omits dat_r, so a case under
                    # either would have to invent a sampled word.
                    'wishbone_register_observe': 'wishbone',
                    # The generic TL-UL register member: the same beat face through
                    # beat_to_tlul, with the pinned kernel's a_*/d_* channels
                    # exposed as passive taps.
                    'tlul_register_observe': 'tl-ul',
                    # The pinned Caliptra SHA-256 slave.  Its generated model
                    # drives the unmodified ``sha256_ctrl`` AHB-Lite slave port
                    # through ahb_lite_mmio_target and exposes that port's own
                    # ten roles as passive taps, so a case can state both phases
                    # it really saw on the target's own pins.
                    'ahb_lite_register_observe': 'ahb-lite'}
TARGET_BRIDGES = {'apb3': 'apb3_mmio_bridge', 'axi4-lite': 'axi4_lite_mmio_bridge',
                  'wishbone': 'beat_to_wishbone', 'tl-ul': 'beat_to_tlul',
                  'ahb-lite': 'ahb_lite_mmio_target'}
#: The one AHB-Lite *target* kind the local harness can render: the unmodified
#: Caliptra ``sha256_ctrl`` slave behind the generated ``ahb_lite_mmio_target``
#: manager, whose address and data phases are separate edges and whose completion
#: is the target's own HREADYOUT in the data phase.  The CVW AHB-Lite *CPU* is a
#: CPU boundary and is never used as a target.  A profile that declares this kind
#: but a trace that is not the two-phase AHB one is refused by name through
#: ``target_protocol`` (``unsupported-target-trace:<kind>:<declared>``), never
#: driven through another protocol's criterion.
AHB_TARGET_KIND = 'ahb_lite_register_observe'
#: The target protocols this host has a real adapter and a real passive trace for.
#: A homogeneous build may declare any one of them; any subset of 2..5 of them may
#: share one build (see ``MIXED_TARGET_PROTOCOLS``), because every target states
#: its own protocol from its own artifact and the generated traits select the
#: trace sample, the completion criterion and the case-line counters per target.
SUPPORTED_TARGET_PROTOCOLS = ('apb3', 'axi4-lite', 'wishbone', 'tl-ul', 'ahb-lite')
#: The target protocols one mixed build may declare at the same time: any subset
#: of 2..5 of ``SUPPORTED_TARGET_PROTOCOLS``.  The per-target dispatch is what
#: makes this admissible - the generated header states one protocol per target and
#: the host never applies one target's adapter to another.  A protocol outside the
#: supported set keeps the historical ``unsupported-targets:mixed-protocol:``
#: refusal, named by the protocols the declaration actually asked for.
MIXED_TARGET_PROTOCOLS = SUPPORTED_TARGET_PROTOCOLS
MIXED_TARGET_PROTOCOL_MIN = 2
MIXED_TARGET_PROTOCOL_MAX = len(SUPPORTED_TARGET_PROTOCOLS)
#: The one pair this entry has historical evidence for.  The name is kept so a
#: reader can find the exact-pair behaviour (case-line spelling, bridge word and
#: transfer criterion) this increment generalizes without changing: a build that
#: declares exactly these two protocols prints the lines it always did.
MIXED_TARGET_PROTOCOL_PAIRS = ('apb3', 'axi4-lite')
#: The word this entry uses in place of one target protocol when a declaration
#: routes to more than one.  It is a session-level *fact about the declaration*
#: ("this build carries both"), never a third wire protocol: each case still
#: states the protocol of the target it was routed to.
MIXED_TARGET_PROTOCOL = 'mixed'
#: The target protocols whose F5 path this host has really run.  F5 is the CPU's
#: own load/store of the declared status, trigger and clear words under that
#: target's protocol adapter: the handler does not use the APB3 bridge at all, so
#: the admitted set is a protocol fact rather than a device allowlist.  APB3
#: register targets keep the historical path; the TL-UL OpenTitan rv_timer is the
#: first non-APB3 target with a real F5 run (runs/p0-1-ip/).  A protocol with no
#: F5 run stays refused under its own name instead of being given an untested one.
F5_TARGET_PROTOCOLS = ('apb3', 'tl-ul')
F5_TARGET_PROTOCOL_REFUSAL = 'unsupported-f5:target-protocol-not-run:'
#: The target protocols a DMA route may present its master beat on.  A route is
#: one master word carried to one target register through that target's *own*
#: adapter: every generated target artifact binds its protocol bridge to the same
#: generic beat port (req_valid/req_ready/req_write/req_addr/req_wdata/req_be in,
#: rsp_valid/rsp_ready/rsp_rdata/rsp_error out) and exposes that protocol's own
#: passive trace.  So APB3 is no longer the only admissible wire: a TL-UL,
#: Wishbone or AXI4-Lite target of this build is routed through its own bridge,
#: its own completion and its own trace, and a protocol outside this set is
#: refused under its own name instead of being driven through another protocol.
#: The same admitted set the planner states (``dma_transfer.ROUTE_PROTOCOLS``),
#: in that module's order so the two halves of the declaration agree.
DMA_ROUTE_PROTOCOLS = ('apb3', 'tl-ul', 'wishbone', 'axi4-lite')
DMA_ROUTE_PROTOCOL_REFUSAL = 'unsupported-dma-route:target-protocol-not-admitted:'
#: Which CPU-side bus this entry can drive, from the generated artifact's own
#: kind.  An OBI CPU has two request channels (instruction and data) with one
#: response each; a Wishbone CPU has one cyc/stb/adr/we/sel master whose fetch/data
#: identity comes from the CPU's own mem_instr output; an AHB-Lite CPU is the
#: manager of one unified external bus, so its fetch/data identity comes from the
#: accepted address phase (HTRANS/HSEL at the manager's aggregate HREADY, then
#: HPROT[0]) and never from the address.  A kind with no adapter is refused by
#: name instead of being mapped onto the other bus.
CPU_BUSES = {'obi_cpu': 'obi', 'wishbone_cpu': 'wishbone', 'ahb_lite_cpu': 'ahb',
             'cva6_packed_axi4_cpu': 'axi4'}
CPU_BUS_LABELS = {'obi': 'OBI i/d', 'wishbone': 'Wishbone single master',
                  'ahb': 'AHB-Lite single manager',
                  'axi4': 'AXI4 packed single master'}
#: The name a flow is refused under when the CPU side cannot supply its witness.
#: F1 is a *retirement* input: an AHB boundary with no RVFI/commit export has no
#: retirement observation, and a fetch beat is not a retirement, so F1 is refused
#: by this exact word in both this entry and the C++ host.
AHB_F1_REFUSAL = 'unsupported-f1:no-retirement-observation:ahb_cvw'
#: F5 needs a CPU interrupt input to deliver to.  The AHB wrapper exports none.
AHB_F5_REFUSAL = 'unsupported-f5:cpu-irq-unexported:ahb_cvw'
#: F1 for the packed AXI4 CPU is refused under this exact word when the model
#: exports no RVFI probe bundle (see axi4_rvfi_probe_export): a fetch beat is
#: never a retirement.
AXI4_F1_REFUSAL = 'unsupported-f1:no-retirement-observation:cva6_packed_axi4'
#: F5 on the packed AXI4 CPU when the built model exposes no interrupt entry at
#: all: nothing can be driven, so no interrupt can be delivered.  The name follows
#: the same shape as the Wishbone refusal.
AXI4_F5_REFUSAL = 'unsupported-f5:cpu-irq-unwired:cva6_packed_axi4'
#: F5 on the packed AXI4 CPU when the entry exists but the retirement face states
#: no take witness (no RVFI probe bundle, hence no cause/intr/mode record and no
#: CSR readback).  The line could be driven, but the CPU's acceptance could only
#: be *inferred* from the ISR's own store, which is exactly what this entry never
#: does; the flow is refused by name instead.
AXI4_F5_WITNESS_REFUSAL = 'unsupported-f5:no-take-witness:cva6_packed_axi4'
#: The IRQ features this composer does not build.  Each refusal is a fact about
#: the pinned CPU profile and the declared targets, not a limitation invented
#: from the harness's own convenience: an NMI port the profile holds at a
#: constant, a PLIC no endpoint declares, a CPU entry that has one external bit,
#: a multi-bit CPU entry whose other bits the profile holds inactive, a device
#: polarity no target declares, and a write-one-clear method no composed target
#: register declares are named under these prefixes.
IRQ_NMI_REFUSAL_PREFIX = 'unsupported-irq:nmi-uncomposed:'
IRQ_PLIC_REFUSAL_PREFIX = 'unsupported-irq:plic-not-composed:'
IRQ_CPU_VECTOR_REFUSAL_PREFIX = 'unsupported-irq:cpu-multibit-vector:'
IRQ_CPU_PARTIAL_VECTOR_PREFIX = 'unsupported-irq:cpu-vector-partial:'
IRQ_ACTIVE_LOW_REFUSAL_PREFIX = 'unsupported-irq:device-active-low:'
IRQ_WRITE_ONE_CLEAR_REFUSAL_PREFIX = 'unsupported-irq:write-one-clear:'
#: The PLIC RTL this repository really contains.  No component profile composes
#: it and no CPU profile declares its claim/complete target port, so it is a
#: precise refusal rather than a host-only OR labelled a PLIC.
PLIC_RTL_FACT = ('third_party/soc-opentitan/hw/top_earlgrey/ip_autogen/rv_plic/rtl/'
                 'rv_plic.sv:63-89')


def advanced_irq_refusals(cpu_profile, target_profiles=()):
    """The named IRQ features the pinned profiles do not compose.

    ``cpu_profile`` is the CPU profile document (a mapping) and
    ``target_profiles`` the profile document of every declared target.  The
    result is a dict of facts a reader can re-check against those documents:

    * ``nmi`` - the CPU's NMI port disposition.  A ``constant`` action is a wire
      the composition holds inactive, so no NMI source can be delivered even
      though the RTL has the input.  ``None`` only when a profile really states
      a composed NMI entry.
    * ``plic`` - whether any endpoint/port of the CPU or a target names a PLIC.
    * ``plic_rtl`` - the PLIC RTL this repository really contains, with the
      composition fact that is missing (no profile composes it and no CPU profile
      declares a claim/complete target port).  Stated beside the named refusal so
      a reader can re-check why a host-only OR of device outputs is not a PLIC.
    * ``cpu_vector`` - the CPU interrupt entry's declared fields and widths.  A
      single one-bit external field is why there is no per-source CPU vector; a
      multi-bit entry whose other bits the profile itself holds at a constant is
      reported as a *partial* vector with the held bit named, never averaged into
      "multi-bit vector".
    * ``device_active_low`` - whether any declared target output is really
      active-low (the link sample inverts only such a device).
    * ``write_one_clear`` - whether any composed target register declares the
      write-one-clear side effect the clear path would have to name.

    Nothing here runs or refuses a case: the entry uses it to state, once, what
    the RTL boundary does not offer.
    """
    cpu = cpu_profile if isinstance(cpu_profile, dict) else {}
    component = str(cpu.get('component_id') or 'unknown-cpu')
    actions = {}
    for row in cpu.get('port_actions') or ():
        if isinstance(row, dict) and isinstance(row.get('port'), str):
            actions[row['port']] = row
    refusals = {}
    nmi_ports = sorted(port for port in actions if 'irq_nm' in port.lower()
                       or port.lower() in ('nmi', 'irq_nmi'))
    composed = [port for port in nmi_ports
                if actions[port].get('action') not in ('constant', None)]
    if composed:
        refusals['nmi'] = None
    elif nmi_ports:
        port = nmi_ports[0]
        row = actions[port]
        refusals['nmi'] = ('%s%s:%s=%s-%s'
                           % (IRQ_NMI_REFUSAL_PREFIX, component, port,
                              row.get('action'), row.get('value')))
    else:
        refusals['nmi'] = ('%s%s:no-declared-nmi-port'
                           % (IRQ_NMI_REFUSAL_PREFIX, component))
    targets = [row for row in target_profiles or ()
               if isinstance(row, dict)]
    # A PLIC is named as its own token; ``duplicate`` or ``multiplication`` in a
    # profile sentence is not an interrupt controller.
    import re
    plic_token = re.compile(r'(^|[^a-z])plic([^a-z]|$)')
    plic = sorted({port for port in actions if plic_token.search(port.lower())})
    plic += [str(row.get('component_id') or 'target') for row in targets
             if plic_token.search(json.dumps(row).lower())]
    refusals['plic'] = (None if plic else
                        '%s%s:no-declared-interrupt-controller-endpoint'
                        % (IRQ_PLIC_REFUSAL_PREFIX, component))
    # The RTL fact behind that refusal.  ``rv_plic.sv:63-89`` is a real
    # claim/complete controller; it becomes a *composed* PLIC only when a device
    # profile binds its bus/clock/reset and a CPU profile declares its
    # claim/complete target port.  No profile here does either, which is what the
    # refusal states, instead of claiming the RTL does not exist.
    refusals['plic_rtl'] = dict(
        rtl=PLIC_RTL_FACT,
        composed_by_profile=bool(plic),
        cpu_target_port=any('claim' in str(port).lower()
                            or 'complete' in str(port).lower()
                            for port in actions),
        statement=('the rv_plic RTL is present but no component profile composes '
                   'it and no CPU profile declares a claim/complete target port; a '
                   'host-only OR of device outputs is not a PLIC'))
    entry = next((row for row in cpu.get('endpoints') or ()
                  if isinstance(row, dict)
                  and row.get('endpoint_id') == 'processor.interrupts'), None)
    fields = [field for field in (entry or {}).get('fields') or ()
              if isinstance(field, dict) and field.get('direction') == 'input']
    aliases = [alias for field in fields for alias in (field.get('aliases') or ())]
    held = []
    for port in aliases:
        row = actions.get(port)
        if row is None or row.get('action') != 'constant':
            continue
        for bit in row.get('bits') or ():
            held.append((port, bit, row.get('value')))
    if not fields:
        refusals['cpu_vector'] = ('%s%s:no-declared-interrupt-entry'
                                  % (IRQ_CPU_VECTOR_REFUSAL_PREFIX, component))
    elif len(fields) == 1 and fields[0].get('width') == 1:
        refusals['cpu_vector'] = ('%s%s:one-%s-input:%s-width-%s'
                                  % (IRQ_CPU_VECTOR_REFUSAL_PREFIX, component,
                                     fields[0].get('role') or 'interrupt',
                                     (fields[0].get('aliases') or ['external'])[0],
                                     fields[0].get('width')))
    elif held:
        port, bit, value = held[0]
        refusals['cpu_vector'] = ('%s%s:%s[%s]=constant-%s-not-taken:%s'
                                  % (IRQ_CPU_PARTIAL_VECTOR_PREFIX, component,
                                     port, bit, value,
                                     'only the ' + str(fields[0].get('role')
                                                       or 'interrupt') +
                                     ' bit is driven and taken, so no per-source '
                                     'CPU vector is claimed'))
    else:
        refusals['cpu_vector'] = None
    refusals['cpu_vector_entry'] = dict(
        endpoint=(entry or {}).get('endpoint_id'),
        role=fields[0].get('role') if fields else None,
        declared_width=fields[0].get('width') if fields else None,
        aliases=aliases,
        held_bits=[dict(port=port, bit=bit, value=value) for port, bit, value in held],
        driven='the bits no profile port action holds at a constant')
    active_low = []
    for row in targets:
        for source in row.get('interrupts') or ():
            if isinstance(source, dict) and source.get('polarity') == 'active_low':
                active_low.append(str(row.get('component_id') or 'target'))
    refusals['device_active_low'] = (None if active_low else
                                     '%sno-declared-target-output-active-low'
                                     % IRQ_ACTIVE_LOW_REFUSAL_PREFIX)
    write_one_clear = []
    for row in targets:
        address = row.get('address') or {}
        for register in address.get('registers') or ():
            if not isinstance(register, dict):
                continue
            name = str(register.get('name') or '').upper()
            # A write-one-clear *interrupt status* register is what the F5 clear
            # path would name; PULP GPIO's PADOUTCLR is a W1C output register,
            # not an interrupt acknowledge, and is not counted here.
            if (register.get('side_effect') == 'write_one_clears'
                    and ('STATUS' in name or 'INT' in name)):
                write_one_clear.append(str(row.get('component_id') or 'target'))
    refusals['write_one_clear'] = (None if write_one_clear else
                                   '%sno-composed-target-register-declares-'
                                   'write_one_clears' % IRQ_WRITE_ONE_CLEAR_REFUSAL_PREFIX)
    return refusals


#: The packed AXI4 CPU's retirement channel is the RVFI *probe bundle* the RTL
#: really exports (`output rvfi_probes_t rvfi_probes_o`, core/cva6.sv:339).  The
#: pinned scoreboard that turns those 6974 bits into instruction records is
#: `core/cva6_rvfi.sv`, which is not in the core filelist, so it is Verilated
#: beside the run and driven from this port.  Both numbers below are the bundle
#: and its 32-bit-word count; the adapter reports its own width and the host
#: refuses to run when the two disagree.
CVA6_RVFI_PROBES_BITS = 6974
CVA6_RVFI_PROBES_WORDS = (CVA6_RVFI_PROBES_BITS + 31) // 32


def cpu_irq_entry(cpu, profile_cpu):
    """The declared interrupt entry a CPU's physical exports really carry.

    ``profile_cpu`` is the component profile's ``cpu`` block (the endpoint and
    role names).  The entry is a fact of the built artifact, not of the profile
    text: exactly one *input* export must carry that endpoint/role, and it must
    state a width.  ``None`` means the archive does not expose the entry the
    profile declares, so nothing may be driven.
    """
    rows = [row for row in cpu.get('physical_exports') or ()
            if row.get('direction') == 'input'
            and row.get('endpoint_id') == profile_cpu.irq_entry_endpoint
            and row.get('role') == profile_cpu.irq_entry_role]
    if len(rows) != 1:
        return None
    row = rows[0]
    if type(row.get('width')) is not int or row['width'] < 1:
        return None
    return dict(width=row['width'], runtime_name=row['runtime_name'],
                physical_port=row.get('physical_port'))


def packed_axi4_irq_contract(cpu, profile):
    """The packed AXI4 CPU's interrupt contract, or ``None``.

    Two independent facts are required before this CPU may take an interrupt:
    the declared entry has to exist on the built model (``cpu_irq_entry``), and
    the retirement face has to state the commit lane's cause/intr/mode witness
    (the RVFI probe bundle adapter).  The first says a line can be driven, the
    second says a take can be *observed*; F5 requires both, because an ISR store
    alone is not a take.
    """
    entry = cpu_irq_entry(cpu, profile.cpu)
    if entry is None or axi4_rvfi_probe_export(cpu) is None:
        return None
    return entry


def axi4_rvfi_probe_export(cpu):
    """The packed AXI4 CPU's exported RVFI probe bundle, or None.

    F1 is a *retirement* input.  This CPU does not export rvfi_* ports; it
    exports the raw 6974-bit probe bundle, which the pinned scoreboard converts
    into records.  The export is returned only when the whole bundle is present
    with its declared width, so a partial export cannot be read as a retirement
    channel; every caller keeps F1 refused by name when this returns None.
    """
    for row in cpu.get('physical_exports') or ():
        if (isinstance(row, dict) and row.get('physical_port') == 'rvfi_probes_o'
                and row.get('direction') == 'output'
                and row.get('width') == CVA6_RVFI_PROBES_BITS
                and isinstance(row.get('runtime_name'), str)):
            return row
    return None
#: The packed AXI4 CPU roles.  The first group is driven by the CPU into the
#: repository's processor-side adapter; the second group is driven back into the
#: CPU by that adapter.  Both are selected from the artifact, never inferred.
AXI4_CPU_OUTPUT_ROLES = ('awid', 'awaddr', 'awlen', 'awsize', 'awburst', 'awlock',
                         'awcache', 'awprot', 'awqos', 'awregion', 'awatop', 'awuser',
                         'awvalid', 'wdata', 'wstrb', 'wlast', 'wuser', 'wvalid',
                         'bready', 'arid', 'araddr', 'arlen', 'arsize', 'arburst',
                         'arlock', 'arcache', 'arprot', 'arqos', 'arregion', 'aruser',
                         'arvalid', 'rready')
AXI4_CPU_INPUT_ROLES = ('awready', 'arready', 'wready', 'bvalid', 'bid', 'bresp',
                        'buser', 'rvalid', 'rid', 'rdata', 'rresp', 'rlast', 'ruser')
#: The address-phase roles an AHB-Lite CPU trace must expose for the host to
#: classify a beat.  ``hready`` here is HREADYEXT (the subordinate's completion),
#: which is never used as manager acceptance; the manager's aggregate HREADY is a
#: separate declared observation role.
AHB_IDENTITY_ROLES = ('htrans', 'haddr', 'hwrite', 'hprot', 'hsel')
# The protocol's name in an operator-facing record message.
TARGET_LABELS = {'apb3': 'APB', 'axi4-lite': 'AXI4-Lite', 'wishbone': 'Wishbone',
                 'tl-ul': 'TL-UL', 'ahb-lite': 'AHB-Lite',
                 MIXED_TARGET_PROTOCOL: 'APB3+AXI4-Lite'}
# The passive tap roles each protocol's trace must expose.  An APB3 trace may omit
# pslverr (the error channel is then unknown); an AXI4-Lite trace always carries
# bresp/rresp, but a slave that only ever drives OKAY is still reported as unknown.
APB_TRACE_ROLES = ('psel', 'penable', 'pready', 'pwrite', 'paddr', 'pwdata', 'prdata')
AXI_TRACE_ROLES = ('awaddr', 'awprot', 'awvalid', 'awready',
                   'wdata', 'wstrb', 'wvalid', 'wready',
                   'bresp', 'bvalid', 'bready',
                   'araddr', 'arprot', 'arvalid', 'arready',
                   'rdata', 'rresp', 'rvalid', 'rready')
#: A Wishbone classic target trace.  ``adr`` is required: the host prints the
#: offset the slave's own address port carried, and an addressless target (the
#: zipcpu_timer's ``addressless-select-ignored`` variant) has no such port, so
#: selecting one is refused by name instead of printing a derived offset as if it
#: had been sampled.  ``stall`` is sampled when the trace has it (the pinned
#: target kernel does) and is not required.
WB_TRACE_ROLES = ('cyc', 'stb', 'ack', 'we', 'adr', 'dat_w', 'dat_r', 'sel')
WB_OPTIONAL_TRACE_ROLES = ('stall',)
#: A TL-UL target trace.  The ten roles the host samples are exactly the ones the
#: request and response channels need to state a completed transfer.
TLUL_TRACE_ROLES = ('a_valid', 'a_ready', 'a_opcode', 'a_address', 'a_mask',
                    'a_data', 'd_valid', 'd_ready', 'd_data', 'd_error')
#: An AHB-Lite target trace: the ten roles the slave's own port carries.  The
#: address phase is one sample (hsel, htrans, haddr, hwrite, hsize, hreadyin) and
#: the data phase the next one (hwdata for a write, hrdata/hresp for a read,
#: hreadyout completing it); hreadyin and hreadyout are separate declared pins
#: because a single-target fabric ties them and the host never assumes it.
AHB_TRACE_ROLES = ('hsel', 'htrans', 'haddr', 'hwrite', 'hsize', 'hwdata',
                   'hreadyin', 'hreadyout', 'hrdata', 'hresp')
#: Protocol -> the passive tap roles that protocol's trace must carry.
PROTOCOL_TRACE_ROLES = {'apb3': APB_TRACE_ROLES, 'axi4-lite': AXI_TRACE_ROLES,
                        'wishbone': WB_TRACE_ROLES, 'tl-ul': TLUL_TRACE_ROLES,
                        'ahb-lite': AHB_TRACE_ROLES}
# The facts F5 needs from the declaration.  When a target declares fewer, F5 is
# refused by name instead of being invented from the profile.
F5_KEYS = ('source_port', 'source_bit_offset', 'trigger_writes', 'status_offsets')
#: The device-behavior keys a legacy one-target scenario states at its top level.
#: They are carried into the normalized target row's config, so an inline
#: declaration keeps exactly the meaning it had before targets were normalized.
LEGACY_BEHAVIOR_KEYS = ('source_behavior', 'source_port', 'source_bit_offset',
                        'pulse_width_ticks', 'trigger_writes', 'status_offsets',
                        'status_cause_bits', 'clear_writes', 'pins',
                        'source_fixed_inputs', 'source_tuning')
CASE_OBSERVATION_KEYS = {
    'F1': ('fetch', 'retire_pc', 'retire_insn', 'successor_pc',
           'prog_words', 'prog_retires', 'prog_pc_ordered', 'prog_insns_match',
           'prog_trace_hash', 'prog_trace_count', 'prog_pc_order',
           'prog_pc_repeat',
           'prog_writebacks', 'prog_rd_mask', 'prog_last_rd', 'prog_last_wdata',
           'prog_last_pc', 'prog_last_insn', 'prog_traps',
           'data_hash_before', 'data_hash_after', 'data_changed'),
    'F2': ('read_addr', 'read_value', 'echo_value', 'read_from', 'apb_rdata'),
    'F3': ('write_addr', 'write_value', 'write_be', 'ram_before', 'ram_after'),
    'F4': ('mmio_addr', 'mmio_value', 'apb_offset', 'apb_pwdata', 'apb_pready'),
    'F5': ('trigger_writes', 'trigger_writes_declared', 'trigger_writes_observed',
           'clear_writes', 'last_trigger_offset', 'last_trigger_data',
           'last_clear_offset', 'last_clear_data',
           'wait_timeout', 'apb_read_offset', 'apb_read_data',
           'apb_last_write_offset',
           'apb_last_write_data', 'irq_edges', 'irq_high_ticks', 'device_high_ticks',
           'delivered_high_ticks', 'irq_takes', 'isr_result', 'isr_flag',
           'isr_read_addr', 'isr_read_value', 'isr_read_register_kind', 'isr_cause',
           'irq_link', 'irq_link_target', 'irq_level_final', 'level_stuck'),
    'F6': ('dma_reads', 'dma_writes', 'dma_first_read_addr', 'dma_first_read_value',
           'dma_last_write_addr', 'dma_last_write_value', 'ctl_config_writes',
           'ctl_start_writes', 'ctl_clear_writes', 'ctl_reads', 'ctl_status',
           'irq_edges', 'irq_high_ticks', 'device_high_ticks', 'delivered_high_ticks',
           'irq_takes', 'isr_result', 'isr_flag', 'ctl_reads_before_start', 'busy_before',
           'err_before', 'busy_after', 'err_after', 'dma_clear_declared', 'dma_status_kind',
           'dma_done_tick', 'level_stuck',
           # The declared shape this case ran under, and the fact that shows the
           # firmware's start write is the plan's word.
           'dma_start_word', 'dma_start_write', 'dma_block_words',
           'dma_master_beats_per_word', 'dma_master_partial', 'dma_lane_count',
           'dma_lane_masks', 'dma_expected_reads', 'dma_expected_writes',
           # Which DMA device carried the transfer, on which channel, what one
           # beat is on it, and the depth of the host's response pipeline as
           # declared and as measured.  A build whose device is the historical
           # single-channel 32-bit ZipDMA shape prints none of these, so every
           # saved ZipDMA F6 case line keeps its exact bytes; a line that carries
           # them can never be read as if the ZipDMA had produced it.
           'dma_device', 'dma_channels', 'dma_channel', 'dma_beat_bytes',
           'dma_max_outstanding', 'dma_outstanding_peak',
           # Backpressure, measured per response.
           'dma_response_delay_declared', 'dma_acks', 'dma_delayed_acks',
           'dma_wait_min', 'dma_wait_max', 'dma_wait_total', 'dma_stall_ticks',
           'dma_max_consecutive_stalls', 'dma_delay_evidence', 'dma_stall_expectation',
           'dma_stall_expect_min', 'dma_stall_expect_max',
           # Byte enables as the device presented them, and the lane coverage of
           # the declared destination block.
           'dma_sel_full', 'dma_sel_partial', 'dma_sel_undeclared',
           'dma_read_lane_partial', 'dma_lane_written', 'dma_lane_missing',
           'dma_lane_extra', 'dma_bytes_outside_block', 'dma_guard_lo', 'dma_guard_hi',
           # Every destination word the host can hold: a block is 1..16 words, so
           # the key set covers the whole parseable record instead of four words.
           *('dst%d' % index for index in range(16))),
}
# An AXI4-Lite target prints the same transfer facts under their neutral names and
# adds the channel counters and the response code of the transaction it completed.
#: F5's transfer facts under the protocol-neutral names.  The historical F5 field
#: list spells them ``apb_*``; an AXI4-Lite or mixed build prints the neutral
#: names for the same facts (the routed target's own bridge), so the neutral F5
#: list replaces those four spellings and keeps every other field.
NEUTRAL_F5_KEYS = tuple(
    {'apb_read_offset': 'target_read_offset',
     'apb_read_data': 'target_read_data',
     'apb_last_write_offset': 'target_last_write_offset',
     'apb_last_write_data': 'target_last_write_data'}.get(key, key)
    for key in CASE_OBSERVATION_KEYS['F5'])
AXI_CASE_OBSERVATION_KEYS = dict(
    CASE_OBSERVATION_KEYS,
    F2=('read_addr', 'read_value', 'echo_value', 'read_from', 'target_rdata',
        'target_offset', 'target_resp', 'target_ready'),
    F4=('mmio_addr', 'mmio_value', 'target_offset', 'target_wdata', 'target_wstrb',
        'target_resp', 'target_ready', 'target_writes'),
    F5=NEUTRAL_F5_KEYS)
#: The Wishbone handshake a wishbone-target case line states, sampled from the
#: pinned kernel's own ports.  ``wb_adr`` is the slave's word address as it was
#: driven; the host prints the byte offset it means beside it.
WB_CASE_TRACE_KEYS = ('wb_cyc', 'wb_stb', 'wb_ack', 'wb_we', 'wb_adr', 'wb_dat_w',
                      'wb_dat_r', 'wb_sel')
#: The TL-UL channels a tl-ul-target case line states: the A channel the request
#: was accepted on and the D channel the response completed on.
TLUL_CASE_TRACE_KEYS = ('tlul_a_valid', 'tlul_a_ready', 'tlul_a_opcode',
                        'tlul_a_address', 'tlul_a_mask', 'tlul_a_data',
                        'tlul_d_valid', 'tlul_d_ready', 'tlul_d_data',
                        'tlul_d_error')
#: A Wishbone target prints the neutral transfer facts plus its own sampled
#: handshake.  There is no response code in a classic Wishbone cycle whose target
#: declares ``has_error: false``, so no ``target_resp`` field is claimed.
WB_CASE_OBSERVATION_KEYS = dict(
    CASE_OBSERVATION_KEYS,
    F2=('read_addr', 'read_value', 'echo_value', 'read_from', 'target_rdata',
        'target_offset', 'target_ready') + WB_CASE_TRACE_KEYS,
    F4=('mmio_addr', 'mmio_value', 'target_offset', 'target_wdata', 'target_ready',
        'target_writes') + WB_CASE_TRACE_KEYS,
    F5=NEUTRAL_F5_KEYS)
#: A TL-UL target prints the same neutral transfer facts plus the two channels.
TLUL_CASE_OBSERVATION_KEYS = dict(
    CASE_OBSERVATION_KEYS,
    F2=('read_addr', 'read_value', 'echo_value', 'read_from', 'target_rdata',
        'target_offset', 'target_ready') + TLUL_CASE_TRACE_KEYS,
    F4=('mmio_addr', 'mmio_value', 'target_offset', 'target_wdata', 'target_ready',
        'target_writes') + TLUL_CASE_TRACE_KEYS,
    F5=NEUTRAL_F5_KEYS)
CASE_COUNTER_KEYS = ('i_fetches', 'd_reads', 'd_writes', 'apb_reads', 'apb_writes',
                     'retires', 'rvfi_writebacks', 'rvfi_order_monotonic', 'traps',
                     'bus_errors')
#: The counter fields a Wishbone/TL-UL case line carries: the same neutral group
#: an AXI4-Lite line prints, plus the handshake counters of that protocol.
WB_CASE_COUNTER_KEYS = tuple(key for key in CASE_COUNTER_KEYS
                             if key not in ('apb_reads', 'apb_writes')) + (
    'target_reads', 'target_writes', 'target_transfers', 'wb_acks',
    'wb_stb_pulses', 'wb_stalls', 'target_error')
TLUL_CASE_COUNTER_KEYS = tuple(key for key in CASE_COUNTER_KEYS
                               if key not in ('apb_reads', 'apb_writes')) + (
    'target_reads', 'target_writes', 'target_transfers', 'tlul_a_handshakes',
    'tlul_d_handshakes', 'tlul_errors', 'target_error')
#: The two phases an AHB-Lite *target* case line states, sampled from the slave
#: port's own pins.  The address phase is one sample and the data phase the next;
#: ``ahb_hreadyin`` is the address phase's completion input and ``ahb_hreadyout``
#: the data phase's, which is why both are printed instead of one assumed HREADY.
AHB_TARGET_CASE_TRACE_KEYS = ('ahb_hsel', 'ahb_htrans', 'ahb_haddr', 'ahb_hwrite',
                              'ahb_hsize', 'ahb_hwdata', 'ahb_hreadyin',
                              'ahb_hreadyout', 'ahb_hrdata', 'ahb_hresp')
#: An AHB-Lite target prints the same neutral transfer facts plus both phases.
#: ``ahb_hresp`` is printed as the sampled pin and is *not* turned into a clean
#: bus: the wrapper ties HRESP's err input low, so the case's error word stays
#: ``ahb_error unknown`` whatever the pin says.
AHB_TARGET_CASE_OBSERVATION_KEYS = dict(
    CASE_OBSERVATION_KEYS,
    F2=('read_addr', 'read_value', 'echo_value', 'read_from', 'target_rdata',
        'target_offset', 'target_ready') + AHB_TARGET_CASE_TRACE_KEYS,
    F4=('mmio_addr', 'mmio_value', 'target_offset', 'target_wdata', 'target_ready',
        'target_writes') + AHB_TARGET_CASE_TRACE_KEYS,
    F5=NEUTRAL_F5_KEYS)
#: The AHB-Lite target's own phase counters.  ``ahb_address_phases`` counts the
#: accepted address phases and ``ahb_data_phases`` the data phases the target
#: completed; a case is one transfer only when both are 1.
AHB_TARGET_CASE_COUNTER_KEYS = tuple(key for key in CASE_COUNTER_KEYS
                                     if key not in ('apb_reads', 'apb_writes')) + (
    'target_reads', 'target_writes', 'target_transfers', 'ahb_address_phases',
    'ahb_data_phases', 'ahb_error')
#: The route facts a routed F6 case line carries.  They are read into the case
#: document only when the host printed them, so a RAM-only F6 document keeps the
#: exact key set it always had.
#: The two-source F5 case facts.  A both case prints its own group (the two
#: stored results, both status addresses, both causes and each member target's
#: read/trigger/clear counters); a single-link line carries none of these keys and
#: its case document is unchanged.
F5_BOTH_CASE_KEYS = (
    'both_link', 'both_members', 'both_targets', 'both_trigger_writes',
    'both_clear_writes', 'both_link_edges', 'both_level_final',
    'isr_result2', 'isr_read_addr2', 'isr_read_value2',
    'isr_read_register_kind2', 'isr_cause2',
    *('target%d_%s' % (index, key)
      for index in range(8)
      for key in ('read_offset', 'read_data', 'last_trigger_offset',
                  'last_trigger_data', 'clear_writes',
                  'last_clear_offset', 'last_clear_data')))
#: The routed beat's own protocol trace, printed by a route whose target is not
#: APB3: which wire carried the beat, how many routed beats the target completed
#: on its own port, and that protocol's own handshake counters.  An APB3 route
#: prints none of these, so its case line and document keep their exact key set.
F6_ROUTE_PROTOCOL_CASE_KEYS = ('dma_route_protocol',
                               'dma_route_protocol_transfers',
                               'dma_route_wb_acks',
                               'dma_route_tlul_a_handshakes',
                               'dma_route_tlul_d_handshakes',
                               'dma_route_axi_aw', 'dma_route_axi_w',
                               'dma_route_axi_b', 'dma_route_axi_ar',
                               'dma_route_axi_r')
F6_ROUTE_CASE_KEYS = ('dma_route_enabled', 'dma_route_target_index',
                      'dma_route_destination', 'dma_route_offset',
                      'dma_route_writes', 'dma_route_acks',
                      'dma_route_target_writes', 'dma_route_target_ready',
                      'dma_ram_writes', 'dma_route_expected_level',
                      'dma_route_accepted', 'dma_route_partial',
                      'fifo_status_before', 'fifo_status_after',
                      'tx_fifo_level_before', 'tx_fifo_level_after',
                      'dma_route_evidence', 'dma_route_reset_before_case',
                      *F6_ROUTE_PROTOCOL_CASE_KEYS)
#: A read route prints its own facts instead of the write route's: the routed
#: source, the captured PRDATA, the per-beat read counters, the CPU readback of
#: the register and of the RAM destination block, and the RAM read count that
#: proves the routed beat was not served from RAM.  A case line only carries the
#: group its direction printed, so a write-route document keeps its key set.
F6_ROUTE_READ_CASE_KEYS = ('dma_route_enabled', 'dma_route_direction',
                           'dma_route_target_index', 'dma_route_source',
                           'dma_route_offset', 'dma_route_reads',
                           'dma_route_acks', 'dma_route_target_reads',
                           'dma_route_target_ready', 'dma_route_read_value',
                           'dma_route_read_stable', 'dma_route_read_matched',
                           'dma_route_cpu_matched', 'dma_ram_reads',
                           'dma_ram_writes', 'dma_route_evidence_before',
                           'dma_route_evidence_after', 'dma_route_evidence',
                           'dma_route_reset_before_case',
                           'dma_ram_lane_written', 'dma_ram_lane_missing',
                           # The declared read shape and its evidence: the FIFO
                           # level the CPU read back before and after the pops,
                           # the word the popped entries had to carry, the number
                           # of captured words that were that word, the aperture
                           # sequence the master presented, and the declared error
                           # injection as it executed.
                           'dma_route_address_mode', 'dma_route_source_kind',
                           'dma_route_level_before', 'dma_route_level_after',
                           'dma_route_level_before_declared',
                           'dma_route_level_after_declared',
                           'dma_route_expected_word', 'dma_route_fifo_matched',
                           'dma_route_sequence', 'dma_route_cpu_aper_matched',
                           'dma_error_injected',
                           'dma_error_injections', 'dma_error_beat',
                           # The CPU's own readback of each RAM destination word,
                           # of each aperture word, and the target offset every
                           # routed beat presented.
                           *('dma_route_cpu_dst%d' % index for index in range(16)),
                           *('dma_route_cpu_aper%d' % index for index in range(16)),
                           *('dma_route_beat_offset%d' % index
                             for index in range(16)),
                           *F6_ROUTE_PROTOCOL_CASE_KEYS)
#: An AHB-Lite case line adds what the sampled address phase said about its beats.
#: ``ahb_unknown`` counts beats served without an observed address phase; they are
#: never part of ``i_fetches`` or the data counters.
AHB_CASE_COUNTER_KEYS = CASE_COUNTER_KEYS + ('ahb_beats', 'ahb_unknown',
                                             'ahb_unknown_reset')
#: The pin side a pin target adds to every case line: the two drivers' values and
#: the sampled consequences.  A target without the pin endpoint prints none of
#: them, so an APB3 register target's saved case line is unchanged.
PIN_CASE_KEYS = ('pad_before', 'pad_after', 'out_before', 'out_after', 'dir_after',
                 'ext_value', 'pad_changes', 'pad_rise_events', 'pad_fall_events',
                 'rise_mask', 'fall_mask')
PIN_F2_KEYS = ('pad_at_read', 'padin_latch', 'pad_settled', 'pin_stimulus')
PIN_F5_KEYS = ('irq_cause_pins', 'inten_at_irq', 'first_rise_tick', 'first_fall_tick',
               'first_transition_tick', 'first_irq_tick', 'status_after_read')
#: An AXI4-Lite case line carries no apb_* field at all, so the APB3 spellings are
#: replaced rather than reported as unknown facts of an AXI4-Lite run.
AXI_CASE_COUNTER_KEYS = tuple(key for key in CASE_COUNTER_KEYS
                              if key not in ('apb_reads', 'apb_writes')) + (
    'target_reads', 'target_writes', 'axi_aw', 'axi_w', 'axi_b', 'axi_ar', 'axi_r',
    'target_error')
#: Neutral name -> the log spelling each protocol prints it under.  The C++ host
#: prints one counter under the protocol's own word, so a reader of a saved log
#: sees either ``apb_*`` (APB3) or ``target_*`` plus ``axi_*`` (AXI4-Lite) while
#: this entry reads both into the same neutral observation.
TARGET_FIELD_ALIASES = {
    'target_reads': ('target_reads', 'apb_reads'),
    'target_writes': ('target_writes', 'apb_writes'),
    'target_offset': ('target_offset', 'apb_offset'),
    'target_wdata': ('target_wdata', 'apb_pwdata'),
    'target_rdata': ('target_rdata', 'apb_rdata'),
    'target_ready': ('target_ready', 'apb_pready'),
    'target_read_offset': ('target_read_offset', 'apb_read_offset'),
    'target_read_data': ('target_read_data', 'apb_read_data'),
    'target_last_write_offset': ('target_last_write_offset', 'apb_last_write_offset'),
    'target_last_write_data': ('target_last_write_data', 'apb_last_write_data'),
    'target_errors': ('target_errors', 'apb_errors', 'bus_errors'),
    'target_transfers': ('target_transfers', 'apb_transfers'),
}
# The selected DMA profiles declare the control register's side effect only, not
# the meaning of its bits.  These are the ZipDMA control bits
# (third_party/soc-zipcpu/rtl/zipdma/zipdma_ctrl.v:116-117); the generated header
# carries them as DMA_BUSY_BIT / DMA_ERR_BIT so another profile can override them,
# and the summary states that the profile does not declare them.
DMA_BUSY_BIT = 31
DMA_ERR_BIT = 30


# ---------------------------------------------------------------------------
# Declaration checks: the selected components decide what is offered
# ---------------------------------------------------------------------------
#: Which request builder an MMIO endpoint protocol needs.  The profile states the
#: protocol of its slave port; the adapter is chosen from that, not from a name.
PROFILE_PROTOCOLS = {('apb', '3'): 'apb3', ('axi4-lite', '1'): 'axi4-lite',
                     ('wishbone', 'classic'): 'wishbone', ('tl-ul', '1'): 'tl-ul',
                     ('ahb-lite', '1'): 'ahb-lite'}


def profile_protocol(profile):
    """The protocol of the profile's one MMIO slave port, or a named refusal."""
    protocols = {tuple(endpoint.get('protocol'))
                 for endpoint in profile.get('endpoints', [])
                 if endpoint.get('function') == 'mmio_slave'}
    if len(protocols) != 1:
        raise ValueError('unsupported-target-protocol:expected-one-mmio-slave:' +
                         ','.join('/'.join(map(str, row)) for row in sorted(protocols)))
    protocol = PROFILE_PROTOCOLS.get(next(iter(protocols)))
    if protocol is None:
        raise ValueError('unsupported-target-protocol:' +
                         '/'.join(map(str, next(iter(protocols)))))
    return protocol


def target_protocol(ip_artifact):
    """The target protocol the selected profile declares, or a named refusal.

    The kind is the artifact's own word; the protocol is the trace the artifact
    exposes.  A kind this entry has no adapter for is refused by name, and a kind
    whose trace contradicts it is refused under its own name too - neither case
    falls back to the APB3 path.  The AHB-Lite target kind carries the
    ``ahb-lite`` trace, so it is admitted on the same terms as the other four and
    a mismatched trace is still the named ``unsupported-target-trace:`` refusal.
    """
    kind = ip_artifact.get('kind')
    protocol = TARGET_PROTOCOLS.get(kind)
    if protocol is None:
        raise ValueError('unsupported-target-kind:' + str(kind))
    declared = (ip_artifact.get('base_protocol_trace') or {}).get('protocol')
    if declared != protocol:
        raise ValueError('unsupported-target-trace:' + str(kind) + ':' + str(declared))
    return protocol


def target_protocol_axis(protocols):
    """The build's target-protocol axis: one protocol, a mixed build, or a refusal.

    Every target states its own protocol from its own artifact, so this is a pure
    decision over the declared set.  One protocol keeps the historical
    single-protocol build (the global ``TARGET_PROTOCOL_*`` macros are that
    protocol's); any subset of 2..4 supported protocols is a mixed build (the
    macros stay neutral, each target's trait carries its own protocol, and the
    host selects the trace sample and the completion criterion per routed
    target); a set that names a protocol outside ``SUPPORTED_TARGET_PROTOCOLS``
    keeps the historical named refusal, listing the protocols it was asked for.

    Returns ``(protocol, mixed)`` where ``protocol`` is the one protocol of a
    homogeneous build and ``MIXED_TARGET_PROTOCOL`` for a mixed one.
    """
    declared = set(protocols)
    if not declared:
        raise ValueError('unsupported-targets:none')
    unsupported = declared.difference(SUPPORTED_TARGET_PROTOCOLS)
    if unsupported:
        raise ValueError('unsupported-targets:mixed-protocol:' +
                         ','.join(sorted(declared)))
    if len(declared) == 1:
        return next(iter(declared)), False
    if len(declared) > MIXED_TARGET_PROTOCOL_MAX:
        # Unreachable while SUPPORTED_TARGET_PROTOCOLS is the only source of a
        # protocol word, but stated rather than resolved in favour of a subset.
        raise ValueError('unsupported-targets:mixed-protocol:' +
                         ','.join(sorted(declared)))
    return MIXED_TARGET_PROTOCOL, True


def ordered_target_protocols(protocols):
    """The declared protocols in the canonical order this entry prints them.

    A mixed build states its protocols in one build-wide word (the target-protocol
    evidence, the bridge word).  The order is ``SUPPORTED_TARGET_PROTOCOLS``', not
    a set's iteration order, so the same declaration always renders the same text
    - the historical APB3 + AXI4-Lite pair keeps exactly the word it had.
    """
    declared = set(protocols)
    return [protocol for protocol in SUPPORTED_TARGET_PROTOCOLS if protocol in declared]


def mixed_target_bridge(protocols):
    """The build-wide bridge word of a mixed build: each declared protocol's bridge."""
    ordered = ordered_target_protocols(protocols)
    if len(ordered) < MIXED_TARGET_PROTOCOL_MIN:
        raise ValueError('unsupported-targets:mixed-protocol:none')
    return 'mixed:' + '+'.join(TARGET_BRIDGES[protocol] for protocol in ordered)


#: The target protocol's own completion criterion, in the word the run document
#: states.  A mixed build joins the declared protocols' words, so a reader of the
#: run document sees which handshake each declared target had to complete instead
#: of one build-wide rule.
TARGET_TRANSFER_CRITERIA = {
    'apb3': 'sel_enable_ready',
    'axi4-lite': 'aw_w_b or ar_r',
    'wishbone': 'cyc_held_with_ack_after_one_stb_pulse',
    'tl-ul': 'a_valid_and_a_ready_then_d_valid_and_d_ready',
    'ahb-lite': 'hsel_and_htrans_address_phase_then_hreadyout_data_phase'}


def mixed_target_criterion(protocols):
    """The per-target transfer criterion word of a mixed build."""
    ordered = ordered_target_protocols(protocols)
    return 'per_target: ' + '; '.join(
        '%s=%s' % (protocol, TARGET_TRANSFER_CRITERIA[protocol])
        for protocol in ordered)


#: How each target protocol states its own error-response observation.  The word
#: is a fact about the pinned trace, not a claim of a clean bus.
TARGET_ERROR_RESPONSES = {
    'apb3': 'unknown unless the trace carries pslverr',
    'axi4-lite': 'unknown: this AXI4-Lite slave only ever drives OKAY',
    'wishbone': 'not declared: the target profile states has_error false, so no '
                'cycle carries an error response',
    'tl-ul': 'sampled: d_error is a real trace output; a completed beat that '
             'carries it is counted as a target error',
    'ahb-lite': 'unknown: this wrapper drives hresp from a tied-low err input '
                "(sha256_ctrl.sv .err(1'b0)) and the profile declares "
                'has_error false, so a completed beat cannot carry an observed '
                'error response'
}


def target_protocol_label(protocol, protocols=None):
    """The operator-facing label of the build's target-protocol axis.

    A homogeneous build keeps its own label.  A mixed build names the protocols it
    really declares; the historical APB3 + AXI4-Lite pair keeps the exact label
    its saved evidence uses, so an old reader still recognizes it.
    """
    if protocol != MIXED_TARGET_PROTOCOL or protocols is None:
        return TARGET_LABELS[protocol]
    ordered = ordered_target_protocols(protocols)
    if set(ordered) == set(MIXED_TARGET_PROTOCOL_PAIRS):
        return TARGET_LABELS[MIXED_TARGET_PROTOCOL]
    return '+'.join(TARGET_LABELS[row] for row in ordered)


def neutral_case_protocol(protocol):
    """Whether a case line carries the protocol-neutral field spelling.

    An AXI4-Lite target prints the neutral names (``target_*``) plus its channel
    counters, and a mixed build prints the same neutral group for every case: one
    case line cannot state one protocol's spelling for two protocols, so the
    target's own protocol is stated per case (``target_protocol``) and per target
    in the summary.  A Wishbone and a TL-UL target have no historical spelling to
    keep, so they print the same neutral group and state their own protocol word
    plus the handshake they sampled.
    """
    return protocol in ('axi4-lite', 'wishbone', 'tl-ul', 'ahb-lite',
                        MIXED_TARGET_PROTOCOL)


#: The neutral group every non-APB3 target prints: the transfer facts under their
#: protocol-neutral names, plus the per-protocol channel/handshake fields of the
#: protocols the build declares.  A mixed build always prints this group (one case
#: line cannot state two protocols' spellings), and each declared protocol adds
#: its own sampled handshake keys.
NEUTRAL_CASE_OBSERVATION_KEYS = dict(
    CASE_OBSERVATION_KEYS,
    F2=('read_addr', 'read_value', 'echo_value', 'read_from', 'target_rdata',
        'target_offset', 'target_ready'),
    F4=('mmio_addr', 'mmio_value', 'target_offset', 'target_wdata', 'target_ready',
        'target_writes'),
    F5=NEUTRAL_F5_KEYS)


def mixed_case_observation_keys(flow, protocols):
    """The case-line fields a mixed build prints for one flow.

    The base is the neutral group; each declared protocol adds the handshake keys
    it really printed.  The historical APB3 + AXI4-Lite pair renders exactly the
    AXI4-Lite table (its two protocols contribute the same keys), and a build with
    a Wishbone or TL-UL target adds that target's own sampled handshake beside
    them.  A key a case line did not print reads as ``unknown`` in the document,
    never as an inferred value.
    """
    declared = set(protocols)
    keys = list(AXI_CASE_OBSERVATION_KEYS[flow]
                if 'axi4-lite' in declared else NEUTRAL_CASE_OBSERVATION_KEYS[flow])
    if 'wishbone' in declared and flow in ('F2', 'F4'):
        keys += [key for key in WB_CASE_TRACE_KEYS if key not in keys]
    if 'tl-ul' in declared and flow in ('F2', 'F4'):
        keys += [key for key in TLUL_CASE_TRACE_KEYS if key not in keys]
    if 'ahb-lite' in declared and flow in ('F2', 'F4'):
        keys += [key for key in AHB_TARGET_CASE_TRACE_KEYS if key not in keys]
    return tuple(keys)


def mixed_case_counter_keys(protocols):
    """The counter fields a mixed build prints for every case.

    The neutral counters are always printed; each declared protocol adds its own
    channel/handshake counters, and exactly one protocol group prints the shared
    ``target_error`` word (the host's own choice, see the generated header).  The
    historical APB3 + AXI4-Lite pair renders exactly ``AXI_CASE_COUNTER_KEYS``.
    """
    declared = set(protocols)
    keys = [key for key in CASE_COUNTER_KEYS if key not in ('apb_reads', 'apb_writes')]
    keys += ['target_reads', 'target_writes']
    if 'axi4-lite' in declared:
        keys += ['axi_aw', 'axi_w', 'axi_b', 'axi_ar', 'axi_r']
    if 'wishbone' in declared:
        keys += ['target_transfers', 'wb_acks', 'wb_stb_pulses', 'wb_stalls']
    if 'tl-ul' in declared:
        keys += ['target_transfers', 'tlul_a_handshakes', 'tlul_d_handshakes',
                 'tlul_errors']
    if 'ahb-lite' in declared:
        keys += ['target_transfers', 'ahb_address_phases', 'ahb_data_phases',
                 'ahb_error']
    keys += ['target_error']
    return tuple(keys)


def case_observation_keys(flow, protocol, pins=False, protocols=None, groups=None,
                          serial=False):
    """The case-line fields one flow carries under this target protocol.

    A mixed build takes the declared protocol set (``protocols``): its case lines
    print the neutral group plus each declared protocol's own handshake, so the
    projection has to cover every protocol the build can route to.  When the set
    is omitted the historical pair's table is used, which is what a caller that
    only knows the axis word keeps reading.

    A pin target adds the resolved pad facts to every flow and the read/stimulus
    pair to F2, the only flow that can carry an external stimulus.
    """
    table = CASE_OBSERVATION_KEYS
    if protocol == MIXED_TARGET_PROTOCOL:
        keys = mixed_case_observation_keys(
            flow, MIXED_TARGET_PROTOCOL_PAIRS if protocols is None else protocols)
        table = dict(CASE_OBSERVATION_KEYS, **{flow: keys})
    elif protocol == 'axi4-lite':
        table = AXI_CASE_OBSERVATION_KEYS
    elif protocol == 'wishbone':
        table = WB_CASE_OBSERVATION_KEYS
    elif protocol == 'tl-ul':
        table = TLUL_CASE_OBSERVATION_KEYS
    elif protocol == 'ahb-lite':
        table = AHB_TARGET_CASE_OBSERVATION_KEYS
    keys = table[flow]
    if groups:
        # One family per declared pad group, plus the group-level totals.  A build
        # that declares no group list prints none of these and its case document
        # keeps its historical key set exactly.
        keys = keys + tuple(key for key in pin_group_case_keys(groups)
                            if key not in keys)
    if serial:
        keys = keys + tuple(key for key in serial_peer_case_keys()
                            if key not in keys)
    if not pins:
        return keys
    keys = keys + tuple(key for key in PIN_CASE_KEYS if key not in keys)
    if flow == 'F2':
        keys = keys + tuple(key for key in PIN_F2_KEYS if key not in keys)
    if flow == 'F5':
        keys = keys + tuple(key for key in PIN_F5_KEYS if key not in keys)
    return keys


def case_counter_keys(protocol, bus=None, protocols=None):
    """The counter fields one case line carries for this target protocol/bus.

    ``protocols`` is the declared protocol set of a mixed build (see
    ``case_observation_keys``); it selects the union of the declared protocols'
    counters.  Without it the historical pair's set is used.
    """
    if bus == 'ahb':
        return (AXI_CASE_COUNTER_KEYS if neutral_case_protocol(protocol)
                else AHB_CASE_COUNTER_KEYS)
    if protocol == MIXED_TARGET_PROTOCOL:
        return mixed_case_counter_keys(
            MIXED_TARGET_PROTOCOL_PAIRS if protocols is None else protocols)
    if protocol == 'wishbone':
        return WB_CASE_COUNTER_KEYS
    if protocol == 'tl-ul':
        return TLUL_CASE_COUNTER_KEYS
    if protocol == 'ahb-lite':
        return AHB_TARGET_CASE_COUNTER_KEYS
    return (AXI_CASE_COUNTER_KEYS if neutral_case_protocol(protocol)
            else CASE_COUNTER_KEYS)


def generic_target_request_from_profile(config, profile, protocol):
    """The v2 request one generic Wishbone/TL-UL register target is built from.

    The profile's own MMIO slave endpoint names the protocol and the template
    variant the pinned kernel registers; the config's declared fixed inputs are
    the pin constants the request pins.  This builder states only what the
    declaration says: the renderer's own policy is the authority on whether those
    constants are admissible, and it refuses an unowned input by name.

    An addressless classic Wishbone target is refused here, by name: its kernel
    has no ``adr`` port, so no case could print the offset the slave really
    decoded and the only available value would be the request the host itself
    drove.  The generic target this increment runs is the word-addressed
    registered-ack variant, whose trace carries ``adr``.
    """
    expected = {'wishbone': ('wishbone', 'classic'), 'tl-ul': ('tl-ul', '1')}[protocol]
    endpoints = [row for row in profile.get('endpoints', [])
                 if row.get('function') == 'mmio_slave'
                 and tuple(row.get('protocol') or ()) == expected]
    if len(endpoints) != 1:
        raise ValueError('unsupported: source_profile requires exactly one ' +
                         TARGET_LABELS[protocol] + ' MMIO slave endpoint')
    endpoint = endpoints[0]
    capabilities = profile.get('capabilities') or {}
    if protocol == 'wishbone':
        if capabilities.get('has_address_port') is not True:
            raise ValueError('unsupported-target-trace:wishbone:addressless:' +
                             str(config.get('source_profile')))
        policy = dict(endpoint_id=endpoint['endpoint_id'],
                      template_id='target.wishbone', template_version='1',
                      variant_id='word-addressed-registered-ack', max_outstanding=1)
    else:
        policy = dict(endpoint_id=endpoint['endpoint_id'],
                      template_id='target.tl-ul', template_version='1',
                      variant_id='user-integrity', max_outstanding=1)
    pins = {(row.get('endpoint_id'), row.get('role')): row.get('value')
            for row in config.get('source_fixed_inputs') or []}
    tuning = dict(config.get('source_tuning') or {})
    tuning.setdefault('endpoint_policies', [policy])
    tuning.setdefault('fixed_inputs', [
        dict(endpoint_id=endpoint_id, role=role, value=value)
        for (endpoint_id, role), value in sorted(pins.items())])
    return dict(schema_version='local_harness.v2', profile_path=config['source_profile'],
                instance_id=config['active_id'],
                **explicit_timing(config, 'source_timing'), tuning=tuning)


def ahb_target_request_from_profile(config, profile):
    """The v2 request one generic AHB-Lite register target is built from.

    The profile's own ``mmio_slave`` endpoint names the pinned AHB-Lite template
    variant (``target.ahb-lite/1`` full-word-single) and the config's declared
    fixed inputs are the pin constants the request pins.  This builder states
    only what the declaration says: the renderer's own ``register_observe_policy``
    is the authority on whether the endpoint shape, the window and the constants
    are admissible, and it refuses an unowned input by name.

    A profile whose MMIO endpoint is not exactly one ``ahb-lite/1`` slave is
    refused here rather than built as an APB3 request: the builder selects the
    wire from the profile's declared protocol, never from a component name.
    """
    endpoints = [row for row in profile.get('endpoints', [])
                 if row.get('function') == 'mmio_slave'
                 and tuple(row.get('protocol') or ()) == ('ahb-lite', '1')]
    if len(endpoints) != 1:
        raise ValueError('unsupported: source_profile requires exactly one '
                         'AHB-Lite MMIO slave endpoint')
    endpoint = endpoints[0]
    policy = dict(endpoint_id=endpoint['endpoint_id'],
                  template_id='target.ahb-lite', template_version='1',
                  variant_id='full-word-single', max_outstanding=1)
    pins = {(row.get('endpoint_id'), row.get('role')): row.get('value')
            for row in config.get('source_fixed_inputs') or []}
    tuning = dict(config.get('source_tuning') or {})
    tuning.setdefault('endpoint_policies', [policy])
    tuning.setdefault('fixed_inputs', [
        dict(endpoint_id=endpoint_id, role=role, value=value)
        for (endpoint_id, role), value in sorted(pins.items())])
    return dict(schema_version='local_harness.v2', profile_path=config['source_profile'],
                instance_id=config['active_id'],
                **explicit_timing(config, 'source_timing'), tuning=tuning)


def cpu_bus(artifact):
    """The CPU bus this entry drives, from the generated artifact's own kind."""
    kind = artifact.get('kind')
    bus = CPU_BUSES.get(kind)
    if bus is None:
        raise ValueError('unsupported-cpu-kind:' + str(kind))
    return bus


def ahb_beat_address_width(cpu_artifact):
    """The declared width of the one AHB-Lite backend beat address."""
    rows = [row for row in cpu_artifact.get('backend_ports') or []
            if row.get('channel') == 'm' and row.get('role') == 'req_addr']
    if len(rows) != 1 or type(rows[0].get('width')) is not int \
            or not 1 <= rows[0]['width'] <= 64:
        raise ValueError('unsupported-ahb-beat-width:req_addr')
    return rows[0]['width']


def ahb_declared_boot(cpu_artifact, windows):
    """The boot address an AHB-Lite CPU declares in its own configuration.

    Unlike the OBI/Wishbone CPUs this entry already drives, CVW has no
    boot-address port: its reset vector is a configuration constant the artifact
    reports, and the source-lock contract pins the configuration bytes it comes
    from.  The address is therefore taken as declared and checked against the
    declared image; the first real fetch is reported from the run (the artifact
    declares ``first_fetch_verification: runtime_observation_required``), not
    predicted here.
    """
    contract = cpu_artifact.get('boot_contract')
    base = contract.get('configured_boot_base') if isinstance(contract, dict) else None
    if type(base) is not int or base % 4 or not 0 <= base < 1 << 32:
        raise ValueError('unsupported-ahb-boot-contract:' + str(base))
    if not (windows['ram_base'] <= base < windows['ram_base'] + windows['ram_size']):
        raise ValueError('ram-base-does-not-follow-boot-contract:' +
                         hex(windows['ram_base']) + ':' + hex(base))
    return base


def cpu_irq_width(cpu_artifact):
    """The width of the CPU's declared external interrupt input, or a refusal."""
    endpoints = [row for row in cpu_artifact.get('physical_exports', [])
                 if (row.get('endpoint_id') or '').endswith('interrupts')
                 and row.get('direction') == 'input']
    if len(endpoints) != 1 or type(endpoints[0].get('width')) is not int:
        raise ValueError('unsupported-cpu-irq-input:'
                         + str(cpu_artifact.get('module_name')))
    return endpoints[0]['width']


def cpu_rvfi_trap_port(cpu_artifact):
    """The CPU model's ``rvfi_trap`` output, or ``None`` when it has none.

    The F1 record states how many of the case's retirements trapped.  A CPU
    whose RVFI face assigns ``rvfi_trap`` can state that count; a CPU whose
    pinned monitor assigns only valid/order/insn/pc (the local CV32E40P top is
    one) cannot, and its trap flag is *unobservable* rather than false.  This
    reads the real generated export, never an inference from another field:
    ``None`` is reported as ``unknown`` on the case line, and the program's own
    retirement trace still gates the case.
    """
    rows = [row for row in cpu_artifact.get('physical_exports') or []
            if row.get('physical_port') == 'rvfi_trap'
            and row.get('direction') == 'output']
    if len(rows) > 1:
        raise ValueError('unsupported: ambiguous rvfi_trap export')
    return rows[0] if rows else None


def target_view(fields):
    """One case's target transfer facts under their neutral names.

    The host prints one counter under the protocol's own word, so this reads both
    spellings into the same neutral keys.  Every neutral key is present, and a
    field neither spelling carries stays ``unknown`` instead of becoming zero.
    """
    view = {}
    for neutral, aliases in TARGET_FIELD_ALIASES.items():
        view[neutral] = next((fields[key] for key in aliases if key in fields), 'unknown')
    view['read_from'] = {'apb': 'target', 'axi4lite': 'target'}.get(
        fields.get('read_from'), fields.get('read_from', 'unknown'))
    for key in ('target_resp', 'target_wstrb', 'axi_aw', 'axi_w', 'axi_b', 'axi_ar',
                'axi_r', 'target_error'):
        if key in fields:
            view[key] = fields[key]
    return view


def declared_windows(config, dma_window_size=None):
    """The address windows this host routes between, from the declaration.

    A declaration with a DMA profile also states its control window and the two
    windows are checked against the RAM and each other.  A declaration with no
    DMA (the pin and the Wishbone-CPU builds) states only the target window, and
    F6 is then refused by name instead of being served from an absent model.
    """
    window, dma = config.get('target_window'), config.get('dma_window')
    ram_base, ram_end = config.get('image_start'), config.get('image_end')
    if any(type(value) is not int for value in (ram_base, ram_end)):
        raise ValueError('config requires integer image_start and image_end')
    if not isinstance(window, dict) or any(type(window.get(key)) is not int
                                           for key in ('base', 'size')):
        raise ValueError('config requires a declared APB target_window')
    ram_size = ram_end - ram_base
    # The DMA destination block plus one guard word on either side has to fit
    # above the fixed image: those are the bytes this host both writes and
    # samples, so a declared RAM that cannot hold them is refused here.
    dma_span = 4 * (DMA_MAX_BLOCK_WORDS + 2)
    if ram_base % 4 or ram_size < DMA_DESTINATION_OFFSET + dma_span:
        raise ValueError('declared RAM is too small for the fixed image and the DMA block')
    if window['base'] % 4 or window['size'] < 4 or window['base'] + window['size'] > 1 << 32:
        raise ValueError('declared APB window is unusable for this host')
    if dma is None:
        if dma_window_size is not None:
            raise ValueError('config requires a declared dma_window')
        if max(window['base'], ram_base) < min(window['base'] + window['size'], ram_end):
            raise ValueError('declared windows overlap: APB target and RAM')
        return dict(ram_base=ram_base, ram_size=ram_size, ip_base=window['base'],
                    ip_size=window['size'], dma_base=None, dma_size=None,
                    data_base=ram_base + DATA_OFFSET)
    if not isinstance(dma, dict) or any(type(dma.get(key)) is not int for key in ('base', 'size')):
        raise ValueError('config requires a declared dma_window')
    if type(dma_window_size) is not int:
        raise ValueError('a declared dma_window needs its declared window size')
    if dma['size'] != dma_window_size or dma['base'] % dma_window_size:
        raise ValueError('declared DMA control window must match the declared DMA window size')
    if dma['base'] + dma['size'] > 1 << 32:
        raise ValueError('declared DMA control window leaves the address space')
    for left, right, name in ((window, dma, 'APB target and DMA control'),
                              (window, dict(base=ram_base, size=ram_size), 'APB target and RAM'),
                              (dma, dict(base=ram_base, size=ram_size), 'DMA control and RAM')):
        if max(left['base'], right['base']) < min(left['base'] + left['size'],
                                                 right['base'] + right['size']):
            raise ValueError('declared windows overlap: ' + name)
    return dict(ram_base=ram_base, ram_size=ram_size, ip_base=window['base'],
                ip_size=window['size'], dma_base=dma['base'], dma_size=dma['size'],
                data_base=ram_base + DATA_OFFSET)


def target_window_list(windows):
    """The ordered target windows this host routes, from the address view.

    ``myfuzz.composition.multi_target.target_windows`` returns every declared
    target under ``ip_targets``; a legacy window dict (the one
    :func:`declared_windows` still builds for the old callers) has only the one
    ``ip_base``/``ip_size`` pair, which is the same list of length one.
    """
    rows = windows.get('ip_targets')
    if isinstance(rows, list) and rows:
        return rows
    return [dict(base=windows['ip_base'], size=windows['ip_size'])]


def target_window_of(windows, index):
    """One target window by index, or a named refusal."""
    rows = target_window_list(windows)
    if type(index) is not int or not 0 <= index < len(rows):
        raise ValueError('unsupported-target-index:' + str(index))
    return rows[index]


def route_target_index(windows, address):
    """The target index one CPU address belongs to, or ``None``.

    A target address that is not 4-byte aligned is refused by name, because a
    target word is the unit the host routes; RAM, the DMA window and every
    address outside the declared target windows return ``None``.
    """
    if len(target_window_list(windows)) == 1 and 'ip_targets' not in windows:
        row = target_window_list(windows)[0]
        if row['base'] <= address <= row['base'] + row['size'] - 4:
            if address % 4:
                raise ValueError('unsupported-address:unaligned')
            return 0
        return None
    route = route_address(windows, address)
    return None if route is None else route[0]


def observed_irq_output(artifact):
    """The one interrupt-like output a target exposes for observation, or None.

    A target without a declared F5 source may still have a real interrupt output
    (the PULP I2C's held ``interrupt_o``).  Observing it is not delivering it:
    the host counts its level ticks and never wires it to the CPU.  A single
    output whose name says interrupt/irq qualifies whatever its width; an
    ambiguous model with two such outputs states no observability instead of
    guessing one.
    """
    rows = [row for row in artifact.get('physical_exports', [])
            if row.get('direction') == 'output'
            and type(row.get('width')) is int and row['width'] >= 1
            and any(word in str(row.get('physical_port') or '').lower()
                    for word in ('interrupt', 'irq'))]
    return rows[0] if len(rows) == 1 else None


def _dma_result_span(dma):
    """The result-block bytes this F6 image writes, from its own declaration.

    The fixed cells are 16 bytes (result, flag, control-before and the F5
    result); a routed case adds the two evidence cells at +16/+20, and a read
    route adds one CPU destination-readback cell per declared destination word.
    """
    if dma is None or dma.get('route') is None:
        return 16
    route = dma['route']
    if route.get('direction') == 'read':
        # A read route's CPU destination readback is one cell per destination
        # word; an aperture read adds one more cell per routed beat for the CPU's
        # own readback of the aperture words.
        span = 24 + 4 * dma['block_words']
        if route.get('aperture'):
            span += 4 * dma['block_words']
        return span
    return 24


def build_layout(windows, boot, irq_base=None, result_span=24,
                 dma_block_words=0):
    """Every fixed address of the one RAM image, checked for overlap.

    ``irq_base`` is the window base of the one target the F5 handler addresses
    (the declaration selected it through ``target_for_f5``).  A legacy
    single-target caller omits it and keeps the first target's window, which is
    the same address the old firmware used.  ``ip_targets`` carries every
    declared target window to the header, not just the first one.

    ``result_span`` is how many bytes of the result block this firmware image
    uses.  The fixed cells take 24 bytes; a both-source F5 image adds the second
    result cell at +28, and a read-route F6 image adds one CPU
    destination-readback cell per declared destination word, so the caller
    states the span it needs and the overlap check below uses it.
    """
    ram = windows['ram_base']
    targets = target_window_list(windows)
    layout = dict(boot=boot, vector=ram + VECTOR_OFFSET, handler=ram + HANDLER_OFFSET,
                  main=ram + MAIN_OFFSET, slot=ram + SLOT_OFFSET,
                  mailbox=ram + MAILBOX_OFFSET, mailbox_bytes=MAILBOX_BYTES,
                  handler_block=ram + HANDLER_BLOCK_OFFSET,
                  handler_block_bytes=HANDLER_BLOCK_BYTES,
                  data_base=windows['data_base'],
                  result=ram + RESULT_OFFSET, result_f5=ram + RESULT_OFFSET,
                  result_f6=ram + RESULT_OFFSET + 4, flag=ram + RESULT_OFFSET + 8,
                  ctl_before=ram + RESULT_OFFSET + 12,
                  # The second result cell a both-source F5 ISR stores into.  It
                  # is never written by a single-link or F6 case, and the C++
                  # host reads it only for a both case.
                  result_f5b=ram + RESULT_OFFSET + 28,
                  # The routed F6 firmware stores the evidence word it read before
                  # and after the transfer in these two cells; a case that never
                  # reached one leaves the sentinel and is reported as unknown.
                  route_before=ram + RESULT_OFFSET + 16,
                  route_after=ram + RESULT_OFFSET + 20,
                  # A read route's firmware reads the RAM destination block back
                  # and stores each word here, so the CPU's own read of what the
                  # DMA wrote is a fact the host can print beside its RAM sample.
                  route_dst=ram + RESULT_OFFSET + 24,
                  # An aperture read route's firmware reads every declared
                  # aperture word back from the target after the transfer and
                  # stores each word here: the CPU's own read of the register the
                  # DMA captured is the witness that the captured word really was
                  # the register content.
                  route_aper=ram + RESULT_OFFSET + 24 + 4 * max(dma_block_words, 0),
                  dma_source=ram + DMA_SOURCE_OFFSET,
                  dma_destination=ram + DMA_DESTINATION_OFFSET,
                  data_end=ram + windows['ram_size'], ram_base=ram,
                  ram_size=windows['ram_size'], ip_base=windows['ip_base'],
                  ip_size=windows['ip_size'], dma_base=windows['dma_base'],
                  dma_size=windows['dma_size'],
                  ip_targets=[dict(row) for row in targets],
                  target_count=len(targets),
                  irq_base=(windows['ip_base'] if irq_base is None else irq_base))
    if boot % 4 or not ram <= boot <= ram + windows['ram_size'] - 4:
        raise ValueError('the declared CPU boot address is not an aligned RAM word')
    # F6 pre-fills one guard word below the destination block and one above it;
    # the lower guard is the only byte of that scheme outside the two declared
    # DMA spans, so it is checked against the fixed image here.  The result block
    # also holds the two route-evidence cells at +16/+20 and, for a read route,
    # one destination-readback cell per block word from +24.
    if layout['dma_destination'] - 4 < layout['result'] + result_span:
        raise ValueError('the DMA destination guard word reaches the result block')
    if boot + 4 * 12 > layout['vector']:
        raise ValueError('the declared CPU boot address leaves no room for the bootstrap')
    return layout


def _csr(address, source, operation=1, destination=0):
    """Encode one Zicsr instruction (same convention as the fixed F5 firmware)."""
    if not 0 <= address < 1 << 12 or not 0 <= source < 32 or not 0 <= destination < 32:
        raise ValueError('fixed CSR operands are out of range')
    if operation not in (1, 2, 3, 5, 6, 7):
        raise ValueError('unsupported CSR operation')
    return (address << 20) | (source << 15) | (operation << 12) | (destination << 7) | 0x73


def _and(rd, rs1, rs2):
    """Encode one RV32I AND (funct7 0, funct3 7, opcode 0x33)."""
    return (rs2 << 20) | (rs1 << 15) | (7 << 12) | (rd << 7) | 0x33


def _ori(rd, rs1, value):
    """Encode one RV32I ORI (funct3 6, opcode 0x13) for a 12-bit immediate."""
    if not 0 <= value < 1 << 12:
        raise ValueError('ORI immediate is out of range')
    return (value << 20) | (rs1 << 15) | (6 << 12) | (rd << 7) | 0x13


def register_kind(name):
    """What a declared register is, from the name the profile itself states.

    The ISR read value is labelled with this, so a handler that reads a timer
    counter is never reported as having read a status or cause word.  A name
    without a recognisable word stays ``undeclared`` - the declaration, not the
    host, decides.
    """
    upper = (name or '').upper()
    # OpenTitan's interrupt status register is spelled INTR_STATE; it is the
    # same word the APB/PULP profiles spell STATUS, so the host's read-value
    # vocabulary recognises the convention instead of reporting the timer's
    # status word as ``undeclared``.  This is a name rule, not a device branch:
    # any profile that names its status word this way gets the same label.
    # INTSTA is the PULP SPI's interrupt-status word spelling (base + 0x28); the
    # rule is still the name the profile states, not the device.
    if 'INTR_STATE' in upper or 'STATUS' in upper or upper == 'INTSTA':
        return 'status'
    if 'COUNT' in upper:
        return 'count'
    if 'CMP' in upper or 'COMPARE' in upper:
        return 'compare'
    if 'CTRL' in upper or 'CONTROL' in upper:
        return 'control'
    if 'DATA' in upper:
        return 'data'
    return 'undeclared'


def irq_declaration(config, ip_profile, *, facts=None, index=0, name=None):
    """Check one declared IRQ link against the target's own register map.

    ``facts`` overrides the link-specific keys of ``config``; the window and the
    profile stay the same for every link.  A v1 declaration is one link, so the
    returned dict keeps its historical field set exactly.
    """
    facts = dict(config) if facts is None else {**config, **facts}
    window = facts['target_window']
    address = ip_profile.address
    if address is None or window['size'] != address.window_size or window['base'] % address.alignment:
        raise ValueError('unsupported: the APB window does not match the target profile')
    registers = {row.offset: row for row in address.registers}
    offsets = facts.get('status_offsets')
    if not isinstance(offsets, list) or len(offsets) != 1:
        raise ValueError('unsupported: exactly one declared status register is required')
    status = registers.get(offsets[0])
    if status is None or status.width != 32 or status.access not in ('ro', 'rw'):
        raise ValueError('unsupported: the declared status register is not a readable word')
    triggers = facts.get('trigger_writes')
    if not isinstance(triggers, list) or not triggers:
        raise ValueError('unsupported: F5 needs a declared trigger write sequence')
    for row in triggers:
        if (not isinstance(row, list) or len(row) != 2 or type(row[0]) is not int
                or type(row[1]) is not int or row[0] not in registers
                or registers[row[0]].width != 32 or registers[row[0]].access not in ('wo', 'rw')):
            raise ValueError('unsupported: a declared trigger register is not a writable word')
    sequence = facts.get('clear_sequence')
    if sequence is not None:
        # An ordered clear sequence is the declaration's own statement of a
        # multi-write acknowledge protocol.  Only write steps are executed by
        # this host: a read step would need a read in the handler, which is a
        # different flow and is refused by name instead of being folded into a
        # write.  The scenario-level spelling of this key is
        # ``irq_clear_sequence`` (the behavior-file spelling is the schema's
        # ``clear_sequence``); both arrive here as the same ordered list.
        if facts.get('clear_writes'):
            raise ValueError('unsupported: both clear_writes and clear_sequence are '
                             'declared for one link')
        if not isinstance(sequence, list) or not sequence:
            raise ValueError('unsupported: clear_sequence must be a non-empty list')
        steps = []
        for row in sequence:
            if isinstance(row, list):
                if len(row) != 2 or type(row[0]) is not int or type(row[1]) is not int:
                    raise ValueError('unsupported: a clear sequence pair needs offset and value')
                steps.append([row[0], row[1]])
            elif isinstance(row, dict):
                if row.get('kind') != 'write':
                    raise ValueError('unsupported: a clear sequence read step is not '
                                     'executed by this host')
                if type(row.get('offset')) is not int or type(row.get('value')) is not int:
                    raise ValueError('unsupported: a clear sequence write step needs '
                                     'offset and value')
                steps.append([row['offset'], row['value']])
            else:
                raise ValueError('unsupported: a clear sequence step is neither a pair '
                                 'nor a step object')
        clears = steps
    else:
        clears = facts.get('clear_writes') or []
    if len(clears) > MAX_CLEAR_WRITES:
        raise ValueError('unsupported: this host performs at most %d declared clear '
                         'writes' % MAX_CLEAR_WRITES)
    for row in clears:
        if (not isinstance(row, list) or len(row) != 2 or type(row[0]) is not int
                or type(row[1]) is not int or row[0] not in registers
                or registers[row[0]].width != 32 or registers[row[0]].access not in ('wo', 'rw')):
            raise ValueError('unsupported: a declared clear register is not a writable word')
    bit, port = facts.get('source_bit_offset'), facts.get('source_port')
    if type(bit) is not int or not isinstance(port, str):
        raise ValueError('config requires source_port and source_bit_offset')
    endpoints = {endpoint.endpoint_id: endpoint for endpoint in ip_profile.endpoints}
    sources = [source for source in ip_profile.interrupts
               if (source.bit if source.bit is not None else 0) == bit
               and source.endpoint_id in endpoints
               and any(field.role == source.role and port in field.aliases
                       for field in endpoints[source.endpoint_id].fields)]
    if len(sources) != 1:
        raise ValueError('unsupported: the target declares no single IRQ output on ' + port)
    source = sources[0]
    if source.polarity not in ('active_high', 'active_low'):
        raise ValueError('unsupported: declared IRQ polarity')
    if source.trigger not in ('pulse', 'level'):
        raise ValueError('unsupported: declared IRQ trigger')
    width = facts.get('pulse_width_ticks', 0)
    if source.trigger == 'pulse':
        if type(width) is not int or not 1 <= width <= 4096:
            raise ValueError('a pulse IRQ source needs a delivery width')
    else:
        if width not in (0, None):
            raise ValueError('a level IRQ source takes no delivery width')
        # A level that nobody clears is an interrupt storm, not a pass.  The
        # only honest ways to deassert it are a declared clear write or a status
        # word whose own profile says a read clears it (PULP GPIO INTSTATUS).
        if not clears and status.side_effect != 'read_clears':
            raise ValueError('a level IRQ source needs a declared clear write or a '
                             'read-clearing status word')
    cause_bits = facts.get('status_cause_bits') or []
    if any(type(cause) is not int or not 0 <= cause <= 31 for cause in cause_bits):
        raise ValueError('unsupported: declared cause bits are not word bit positions')
    cause_mask = sum(1 << cause for cause in cause_bits)
    result = dict(port=port, bit=bit, trigger=source.trigger, polarity=source.polarity,
                  pulse_ticks=width if source.trigger == 'pulse' else 0,
                  status_offset=offsets[0], trigger_offsets=[row[0] for row in triggers],
                  status_kind=register_kind(status.name),
                  # The profile is the authority for a read-clearing status word
                  # (PULP GPIO INTSTATUS: rtl/apb_gpio.sv:154/160).  It is a
                  # property of the device register, not of this host, and the
                  # case line states it so a clear with no write is explainable.
                  status_read_clears=(status.side_effect == 'read_clears'),
                  cause_declared=bool(cause_bits), cause_bits=list(cause_bits),
                  cause_mask=cause_mask,
                  # The declared clear is an ordered write sequence.  ``clear`` is
                  # its first write (the acknowledge), which is the word every
                  # saved case line and every header macro has always named;
                  # ``clears`` is the whole sequence, so a device whose ack
                  # protocol is two register writes is stated as what it is
                  # instead of being truncated to its first write.
                  clear=dict(offset=clears[0][0], value=clears[0][1]) if clears else None,
                  clears=[dict(offset=row[0], value=row[1]) for row in clears],
                  clear_steps=len(clears))
    if index or name is not None:
        result.update(index=index, name=name if name is not None else 'source%d' % index)
    return result


def f5_declaration(config, ip_profile, protocol, *, cpu_bus_kind='obi', cpu_irq_bits=None,
                   cpu_custom_irq=False, cpu_irq_witness=False, cpu_irq_refusal=None):
    """F5 when the declaration carries it, a named refusal when it cannot.

    F5 is the one flow whose facts come from the device rather than from the CPU,
    so it is offered only when the declaration states all four of them.  A target
    that states fewer is refused under its own name --
    ``unsupported-f5:target-irq-semantics:<protocol>:<missing facts>`` -- and the
    run keeps F1-F4 and F6 instead of inventing a trigger, a status word or an
    interrupt edge.

    A v2 ``irq_sources`` list is checked link by link.  All links must share one
    trigger-write count: the F5 record carries the link index followed by that
    many values, so a different count would make one input shape ambiguous.

    A Wishbone CPU build has one more structural refusal: this host drives that
    CPU's declared multi-bit ``irq`` input to zero (it has no per-bit wiring
    declaration), so no interrupt can be delivered and F5 cannot exist.  The
    refusal is named after the wire, not after the target.

    The packed AXI4 CPU is admitted only when the built model exports the
    declared interrupt entry *and* the retirement face states a take witness
    (``cpu_irq_witness``); otherwise ``cpu_irq_refusal`` names which of the two
    facts is missing.  A driveable line without a witness would leave the CPU's
    acceptance to be inferred from an ISR store, which this entry never does.
    """
    if cpu_bus_kind == 'ahb':
        # The AHB-Lite boundary declares no interrupt input at all, so there is
        # no wire to deliver a sampled device output to.  The refusal names the
        # CPU side, not the target, so a target's own F5 facts stay visible.
        return None, AHB_F5_REFUSAL
    if cpu_bus_kind == 'axi4' and not cpu_irq_witness:
        # Without a driven entry *and* a retirement witness, F5 would have to
        # claim the CPU accepted the interrupt from an ISR side effect alone.
        # ``cpu_irq_refusal`` names which of the two facts the built artifact
        # lacks; the fallback name is the missing-entry one.
        return None, (cpu_irq_refusal or AXI4_F5_REFUSAL)
    if cpu_bus_kind == 'wishbone' and not cpu_custom_irq:
        return None, ('unsupported-f5:cpu-irq-unwired:wishbone:'
                      + str(cpu_irq_bits) + '-bit-irq-held-at-zero')
    declared = config.get('irq_sources')
    if declared is not None:
        if not isinstance(declared, list) or not 1 <= len(declared) <= 8:
            return None, 'unsupported-f5:irq-sources-shape'
        links = []
        for index, source in enumerate(declared):
            try:
                links.append(irq_declaration(config, ip_profile, facts=source,
                                             index=index,
                                             name=source.get('name') if isinstance(source, dict) else None))
            except ValueError as error:
                return None, 'unsupported-f5:' + str(error)
        counts = {len(link['trigger_offsets']) for link in links}
        if len(counts) != 1:
            return None, 'unsupported-f5:irq-links-differ-in-arity'
        result = dict(links=links, source_count=len(links), **links[0])
        return result, None
    missing = [key for key in F5_KEYS if key not in config]
    if missing:
        return None, 'unsupported-f5:target-irq-semantics:' + protocol + ':' + ','.join(missing)
    return irq_declaration(config, ip_profile), None


def cpu_irq_take_witness(cpu_document, custom_irq=None):
    """Which CPU-side port witnesses an interrupt take, or None.

    F5/F6 acceptance is a CPU capability, not a device fact: the host has to read
    a port that says the CPU really entered the handler.  The three witnesses
    this harness can read from the generated artifact are the CPU model's own
    pre-edge take probe (``probe_irq_taken_pre``), a custom EOI vector (Pico's
    declared EOI output, which latches the accepted bit), and the RVFI retirement
    face's ``rvfi_intr`` bit - the architectural flag that marks the first
    instruction retired in a trap handler.  A CPU that exports none of them keeps
    the named refusal: a successful bus access is never a substitute witness.

    Returns ``(witness, missing)`` where ``witness`` is one of the three names or
    None, and ``missing`` names the exact contract F5/F6 would need.
    """
    rows = [row for row in cpu_document.get('runtime_ports', [])
            if row.get('name') == 'probe_irq_taken_pre'
            and row.get('direction') == 'output']
    if len(rows) == 1:
        return 'probe_irq_taken_pre', None
    if custom_irq is not None:
        return 'custom_eoi', None
    intr = [row for row in cpu_document.get('physical_exports', [])
            if row.get('physical_port') == 'rvfi_intr'
            and row.get('direction') == 'output']
    if len(intr) == 1:
        return 'rvfi_intr', None
    return None, ('needs-one-of:probe_irq_taken_pre,custom_eoi,rvfi_intr at '
                  + str(cpu_document.get('module_name', 'cpu')))


def cpu_dma_port_refusal(bus, dma_kind, has_custom_irq):
    """Why this CPU/DMA combination cannot run F6, or None when it can.

    F6 needs a DMA master the host can drive on this CPU's bus.  The unified
    entry implements that for an OBI CPU beside a Wishbone DMA model (and, for a
    Wishbone CPU, only with a declared custom IRQ bit that carries the DMA
    completion).  A combination without that port is refused under the F6 flow's
    own name instead of letting a bus access stand in for a DMA transfer.
    """
    if dma_kind is None:
        return None
    if bus == 'wishbone' and not has_custom_irq:
        return ('unsupported-f6:cpu-dma-port-unexported:wishbone:'
                'no-custom-irq-bit-declared')
    if bus == 'ahb':
        return ('unsupported-f6:cpu-dma-port-unexported:ahb:'
                'the-ahb-boundary-has-no-dma-port')
    if bus == 'axi4':
        return ('unsupported-f6:cpu-dma-port-unexported:axi4:'
                'the-packed-axi4-boundary-has-no-dma-port')
    if dma_kind != 'wishbone_dma':
        return 'unsupported-f6:requires-wishbone-dma:' + str(dma_kind)
    return None


def cpu_flow_witness_refusals(bus, witness, missing):
    """The F5/F6 refusals a CPU's take witness imposes, or an empty dict.

    A flow whose acceptance needs the CPU to have entered the handler stays
    refused by name when the CPU exports no take probe, custom EOI or rvfi_intr,
    even when the device/bus half of the declaration is complete.  AHB and packed
    AXI4 keep their own named refusals (that boundary/archive decides them, not
    this witness), so they are not restated here.
    """
    if witness is not None or bus not in ('obi', 'wishbone'):
        return {}
    detail = bus + ':' + str(missing)
    return {'F5': 'unsupported-f5:cpu-take-witness-unexported:' + detail,
            'F6': 'unsupported-f6:cpu-take-witness-unexported:' + detail}


def f5_protocol_check(protocol, name, irq):
    """F5 on a target protocol this host has run, or a named refusal.

    The F5 handler's trigger, status and clear words are the CPU's own stores and
    loads through the target's protocol adapter; the host does not drive them on
    the APB3 bridge, and it never has.  APB3 register targets keep the historical
    path, and this increment admits the TL-UL target after a real F5 run against
    the pinned OpenTitan rv_timer.  A target that *declares* the four F5 facts
    under another protocol is refused by name rather than given an untested path.
    A target that declares none keeps its own, longer-standing refusal
    (``unsupported-f5:target-irq-semantics:<protocol>:<missing facts>``), so this
    gate only speaks about a declaration that would otherwise be accepted.
    """
    if irq is None or protocol in F5_TARGET_PROTOCOLS:
        return None
    raise ValueError(F5_TARGET_PROTOCOL_REFUSAL + protocol + ':' + name)


def dma_route_protocol_check(protocol, name):
    """A DMA route presents its beat on the routed target's own adapter, or a refusal.

    The route holds one master beat on the target's generic request port and
    completes it from that target's own response, so the admitted set is the set
    of protocols whose generated artifact really binds a bridge and a passive
    trace to that port: APB3, TL-UL, Wishbone and AXI4-Lite.  Each of them has
    been driven by this host for the CPU's own MMIO on the same port, and the
    routed beat uses exactly that path - no protocol is served through another
    one's completion.  The APB3 route keeps the exact shape it always had; a
    protocol outside the admitted set is refused under its own name.
    """
    if protocol in DMA_ROUTE_PROTOCOLS:
        return None
    raise ValueError(DMA_ROUTE_PROTOCOL_REFUSAL + str(protocol) + ':' + str(name))


def pad_endpoint(ip_profile):
    """The target's dir-resolved pad endpoint, if it declares one.

    A component may declare an ``external_pins`` endpoint of single-bit serial
    pins (a UART's rx/cts_n) that are driven by the declaration's fixed inputs,
    not by a pad model.  Only an endpoint that declares ``in``, ``out`` and
    ``dir`` as a 32-bit group is the pad model this host resolves.
    """
    pads = [endpoint for endpoint in ip_profile.endpoints
            if endpoint.function == 'external_pins'
            and {'in', 'out', 'dir'} <= {field.role for field in endpoint.fields}]
    if len(pads) > 1:
        raise ValueError('unsupported: the target declares more than one pad endpoint')
    return pads[0] if pads else None


def pin_declaration(config, ip_profile):
    """Check the declared pad model against the target's own pin endpoint.

    A target without a pad endpoint (an APB3 register target) has no pin side, so
    the declaration must carry none either; a pad target must declare exactly the
    dir-resolved model this host implements.
    """
    declaration = config.get('pins')
    pads = pad_endpoint(ip_profile)
    if declaration is None:
        if pads is not None:
            raise ValueError('the target declares a dir-resolved pad endpoint but the '
                             'config declares no pins model')
        return None
    if not isinstance(declaration, dict):
        raise ValueError('config pins declaration must be an object')
    if declaration.get('pad_resolution') != 'device_drives_when_dir_bit_high_else_host':
        raise ValueError('unsupported: only the dir-resolved pad model is implemented')
    if pads is None:
        raise ValueError('unsupported: the target declares no dir-resolved pad endpoint')
    shape = {field.role: field.direction for field in pads.fields}
    if (shape.get('in') != 'input' or shape.get('out') != 'output'
            or shape.get('dir') != 'output'):
        raise ValueError('unsupported: the target declares no dir-resolved pad endpoint')
    declared = {field.role: field.width for field in pads.fields}
    if declared.get('in') != 32:
        raise ValueError('unsupported: the declared pad input is not 32 bits wide')
    value = declaration.get('external_value')
    if type(value) is not int or not 0 <= value < 1 << 32:
        raise ValueError('pins.external_value must be one 32-bit word')
    padin = config.get('target_window')
    registers = {row.offset: row for row in ip_profile.address.registers}
    offset = declaration.get('padin_offset')
    if type(offset) is not int or offset not in registers:
        raise ValueError('unsupported: pins.padin_offset is not a declared register')
    row = registers[offset]
    if row.width != 32 or row.access not in ('ro', 'rw'):
        raise ValueError('unsupported: pins.padin_offset is not a readable word')
    if not isinstance(padin, dict):
        raise ValueError('config requires a declared APB target_window')
    return dict(endpoint_id=pads.endpoint_id, width=32, external_value=value,
                padin_offset=offset)


#: The three writable pads of the PULP apb_gpio map the host reasons about when a
#: pin-model build performs a target write.  Their offsets are the profile's own
#: register map, checked against the config's ``registers`` when it states them.
PIN_REGISTER_NAMES = ('PADOUT', 'PADOUTSET', 'PADOUTCLR')


def pin_registers(ip_profile, config):
    """The PADOUT-family offsets, from the target's own register map."""
    registers = {row.name: row.offset for row in ip_profile.address.registers}
    declared = config.get('registers') or {}
    out = {}
    for name in PIN_REGISTER_NAMES:
        offset = registers.get(name)
        if offset is None:
            raise ValueError('unsupported: the target declares no ' + name + ' register')
        if declared.get(name) is not None and declared[name] != offset:
            raise ValueError('config registers.' + name + ' disagrees with the target profile')
        out[name] = offset
    return out


def expected_out_after(offset, before, value, registers):
    """The PADOUT family's declared side effect, applied to the sampled before state."""
    if offset == registers['PADOUT']:
        return value
    if offset == registers['PADOUTSET']:
        return before | value
    if offset == registers['PADOUTCLR']:
        return before & ~value
    return before


#: The two group kinds a ``pin_groups`` list may state.  ``dir_resolved_pad_word``
#: is the pad word this host resolves; ``serial_peer`` is a framed serial line the
#: host drives and samples itself.  The order of a declaration is the order the
#: host drives: the pad groups take the wire one after another, each for its own
#: declared window.
PIN_GROUP_KIND_DIR = 'dir_resolved_pad_word'
PIN_GROUP_KIND_SERIAL = 'serial_peer'
#: The frame shapes the host's own serial driver encodes and decodes, with the
#: frame code the generated header states and the bit count one frame occupies
#: (start + 8 data + optional parity + stop).
SERIAL_FRAME_CODES = {'8n1': 0, '8e1': 1, '8o1': 2}
SERIAL_FRAME_BITS = {'8n1': 10, '8e1': 11, '8o1': 11}
#: A serial peer's role is a pin direction the profile must declare.  The host
#: drives ``rx_role`` and samples ``tx_role``; ``tx_en_role`` (when stated) is
#: driven alongside a frame the host sends.
SERIAL_ROLE_DIRECTIONS = {'rx': 'input', 'tx': 'output', 'tx_en': 'output'}
#: The CPU-side buses whose host loop can park the CPU while the peer drives a
#: frame.  The packed AXI4 host owns its own CPU/adapter edge, so a serial peer
#: there is refused by name rather than driven on a CPU that keeps running.
SERIAL_PARKABLE_BUSES = ('obi', 'wishbone')


def pin_group_declaration(behavior, ip_profile, artifact, *, bus, target_count):
    """Validate a declared ``pin_groups`` list against the bound device.

    The declaration is the behavior layer's normalized list (``pin_groups`` in
    ``source_behavior``'s facts); this function is the executor half: it decides
    which pad word the bound endpoint really exposes, which pad roles the peer may
    own, and returns exactly the facts the generated header states.  Nothing here
    rewrites the declaration: a group the host cannot execute is refused by name.

    ``behavior`` is the merged behavior fact dict (``None`` when the scenario
    declares no behavior at all), ``artifact`` the built target's runtime
    document (its ``physical_exports`` name every pin port) and ``bus`` the
    CPU-side bus word.  A multi-target build has one pad/serial wire per host, so
    the declaration is refused there by the same name the pad model uses.
    """
    if behavior is None:
        return None
    declared = behavior.get('pin_groups')
    if declared is None:
        return None
    if target_count != 1:
        raise ValueError('unsupported-pins:multiple-targets')
    groups = []
    pad_words = []
    serial_rows = []
    for group in declared:
        if group['kind'] == PIN_GROUP_KIND_DIR:
            pad_words.append(group)
        elif group['kind'] == PIN_GROUP_KIND_SERIAL:
            serial_rows.append(group)
    if pad_words:
        pads = pad_endpoint(ip_profile)
        if pads is None:
            raise ValueError('unsupported-pins:pin_groups:no-pad-endpoint')
        registers = {row.offset: row for row in ip_profile.address.registers}
        offsets = []
        for group in pad_words:
            offset = group['padin_offset']
            row = registers.get(offset)
            if row is None or row.width != 32 or row.access not in ('ro', 'rw'):
                raise ValueError('unsupported-pins:pin_groups:padin_offset')
            offsets.append(offset)
        # One pad endpoint is one pad word.  Two groups naming different readable
        # pad registers would need a second pad port on the model, which the bound
        # endpoint does not expose: that declaration is refused by name instead of
        # being folded onto the first word.
        if len(set(offsets)) != 1:
            raise ValueError('unsupported-pins:pin_groups:second-pad-word')
        for group in pad_words:
            groups.append(dict(kind=PIN_GROUP_KIND_DIR, name=group['name'],
                               direction=group['direction'],
                               hold_ticks=group['hold_ticks'],
                               external_value=group['external_value'],
                               padin_offset=group['padin_offset']))
    serial = None
    if serial_rows:
        serial = serial_rows[0]
        if bus not in SERIAL_PARKABLE_BUSES:
            raise ValueError('unsupported-serial:cpu-clock-not-parkable:' + str(bus))
        exports = {(row.get('endpoint_id'), row.get('role')): row
                   for row in artifact.get('physical_exports', [])}
        roles = [(serial['rx_role'], 'rx'), (serial['tx_role'], 'tx')]
        if serial.get('tx_en_role') is not None:
            roles.append((serial['tx_en_role'], 'tx_en'))
        pads = pad_endpoint(ip_profile)
        serial_pads = [endpoint for endpoint in ip_profile.endpoints
                       if endpoint.function == 'external_pins'
                       and (pads is None or endpoint.endpoint_id != pads.endpoint_id)]
        references = {}
        for role, kind in roles:
            owners = [endpoint for endpoint in serial_pads
                      if any(field.role == role for field in endpoint.fields)]
            if len(owners) != 1:
                raise ValueError('unsupported-serial:role:' + role)
            endpoint = owners[0]
            field = next(field for field in endpoint.fields if field.role == role)
            if field.direction != SERIAL_ROLE_DIRECTIONS[kind]:
                raise ValueError('unsupported-serial:direction:' + role)
            port = exports.get((endpoint.endpoint_id, role))
            if port is None or port.get('direction') not in ('input', 'output'):
                raise ValueError('unsupported-serial:port:' + role)
            # The peer's rx and tx lines are single wires; a vector port would need
            # a lane declaration the peer schema has not.
            if kind in ('rx', 'tx') and port.get('width') not in (None, 1):
                raise ValueError('unsupported-serial:width:' + role)
            references[role] = dict(runtime_name=port['runtime_name'],
                                    width=port.get('width'),
                                    direction=port['direction'])
        groups.append(dict(kind=PIN_GROUP_KIND_SERIAL, name=serial['name'],
                           rx_role=serial['rx_role'], tx_role=serial['tx_role'],
                           tx_en_role=serial.get('tx_en_role'),
                           idle_level=serial['idle_level'],
                           bit_ticks=serial['bit_ticks'], frame=serial['frame'],
                           frame_code=SERIAL_FRAME_CODES[serial['frame']],
                           frame_bits=SERIAL_FRAME_BITS[serial['frame']],
                           ports=references))
    if not groups:
        return None
    return dict(groups=groups, serial=groups[-1] if serial is not None else None)


def pin_group_case_keys(groups):
    """The case-line fields a declared pad-group list prints, group by group.

    Every declared group owns one family, so a case line states per group that it
    was applied and what it did: the external word it drove, the direction witness
    the device's own dir port produced, how many ticks it held the wire, and the
    changes the resolution made while it held it.
    """
    if not groups:
        return ()
    keys = ['pin_groups_declared', 'pin_groups_executed', 'pin_groups_ticks',
            'pin_groups_changes', 'pin_groups_direction_conflicts',
            'pin_stimulus_group']
    for index, _ in enumerate(groups):
        keys += ['pin_group%d_name' % index, 'pin_group%d_kind' % index,
                 'pin_group%d_ext' % index, 'pin_group%d_direction' % index,
                 'pin_group%d_hold_ticks' % index, 'pin_group%d_ticks' % index,
                 'pin_group%d_changes' % index, 'pin_group%d_rise_events' % index,
                 'pin_group%d_fall_events' % index,
                 'pin_group%d_direction_witness' % index,
                 'pin_group%d_pad_before' % index, 'pin_group%d_pad_after' % index]
    return tuple(keys)


def serial_peer_case_keys():
    """The tick-level facts one declared serial peer prints on every case line.

    The rx family states what the host really drove: the byte, the frame, the
    declared bit period, how many bit times it held, the first and last tick of
    the frame, and the levels it drove.  The tx family states what the host really
    sampled from the device: the decoded byte, the sampled levels, the first and
    last tick, the parity bit and whether the frame was well framed.  Nothing here
    is derived from the declaration alone.
    """
    return ('serial_peer_name', 'serial_peer_frame', 'serial_peer_bit_ticks',
            'serial_peer_idle_level',
            'serial_rx_frames', 'serial_rx_bits', 'serial_rx_byte',
            'serial_rx_levels', 'serial_rx_first_tick', 'serial_rx_last_tick',
            'serial_rx_parity_bit', 'serial_rx_framing_ok',
            'serial_rx_cpu_held_ticks',
            'serial_tx_frames', 'serial_tx_bits', 'serial_tx_byte',
            'serial_tx_levels', 'serial_tx_first_tick', 'serial_tx_last_tick',
            'serial_tx_parity_bit', 'serial_tx_framing_ok',
            'serial_tx_stop_bits_ok', 'serial_tx_en_ticks', 'serial_tx_en_level')


def dma_irq_pulse_ticks(config, dma_facts):
    """The declared DMA pulse width: behavior file wins over the inline key.

    The host may hold a pulse source for several ticks so a slow CPU cannot miss
    it.  A behavior file that states ``irq_pulse_ticks`` is authoritative; an
    inline scenario key is only the fallback when the file is silent.
    """
    value = None if dma_facts is None else dma_facts.get('irq_pulse_ticks')
    if value is None:
        value = config.get('dma_irq_pulse_ticks')
    return 16 if value is None else value


#: What this host can execute, as an answer to each host-limit *code* the
#: planning module reports.  ``None`` means "not implemented in this increment":
#: a plan carrying that limit is refused by name before any model is built.
#: A code this table does not know is refused too, so a future planner limit can
#: never pass silently.
#: The device-capability facts an F6 declaration carries so the generated header
#: can state them.  A declaration built without the planner (a caller that assembles
#: the dict itself) keeps this historical single-channel 32-bit shape, which is also
#: the shape the case-line group is silent for.
DMA_DEVICE_FACTS_DEFAULT = {'channels': 1, 'beat_bytes': 4, 'max_outstanding': 1,
                            'burst_beats': 1}

DMA_HOST_CAPABILITY = {
    # The planner's 1..4 block bound describes the previous entry.  This host
    # carries 1..DMA_MAX_BLOCK_WORDS input words (MAILBOX_BYTES), pre-fills the
    # same number of destination words plus one guard word on either side
    # (declared_windows) and the C++ host parses a 1..16-word record.
    'host-block-words-cap': DMA_MAX_BLOCK_WORDS,
    # The firmware writes the plan's own start word, the header carries it as
    # DMA_START_WORD and the host counts a start write only when the device
    # observed exactly that word.
    'host-fixed-start-word': True,
    # A device-driven lane mask (ZipDMA's size-derived lanes) is served as the
    # master presents it; a host-forced mask the RTL does not drive is refused.
    'host-full-word-master-sel': 15,
    # The host holds mwb_stall/mwb_ack for the declared ticks and measures each
    # response's wait, so a declared delay is observed instead of assumed.
    'host-response-delay-absent': DMA_MAX_RESPONSE_DELAY,
    # A dependency-free declaration of the route shapes this host runs: the
    # accepted DMA master beat is presented on the declared target's APB3
    # request port (same bridge the CPU uses), the master is held until that
    # target answers, and the declared evidence word is read back by the F6
    # firmware.  A write route pushes the routed register; a read route captures
    # the routed register's PRDATA and the DMA writes it to the RAM block.  An
    # aperture route, an AXI4-Lite route or a FIFO read route is refused by name.
    'host-dma-target-route-absent': 'fixed-read-write-apb3-target',
    'host-error-injection-absent': None,
    # The deepest master-response pipeline this host serves.  The historical host
    # held mwb_stall from the accepted beat to its ack, which is a depth of one;
    # the host now keeps a ring of this many pending responses and stalls the
    # master only when the ring is full.
    'host-outstanding-cap': 2,
}


def _route_register(profile, offset):
    """The target profile's own register row at ``offset``, or ``None``."""
    address = getattr(profile, 'address', None)
    if address is None:
        return None
    return next((row for row in address.registers if row.offset == offset), None)


def dma_route_support(plan, targets, cpu_bus=None):
    """Check this host can execute the plan's declared route, or refuse by name.

    The planning module already refused a route the *device* cannot encode.  This
    function answers the host half: the C++ host presents one accepted master
    beat at a time on the routed target's *generic* request port (req_valid/
    req_ready/req_write/req_addr/req_wdata/req_be in, rsp_valid/rsp_ready/
    rsp_rdata/rsp_error out), and every generated target artifact binds its own
    protocol bridge to that port.  So APB3 is no longer the only executable wire:
    a fixed read or a fixed write route into one declared TL-UL, Wishbone or
    AXI4-Lite target of this build is executed through that target's own adapter
    and completed from its own response.  The target's own register map is the
    authority for the routed register and for the readable evidence word, and the
    target artifact's own protocol is the authority for the wire; a route that
    names an unadmitted protocol is refused under its own name (before any model
    is built) instead of being driven through another protocol's completion.

    A write route presents the routed register as a fixed *destination* (the RAM
    block keeps its sentinel); a read route presents it as a fixed *source*, so
    the destination must increment and the captured word lands in the RAM block.
    A read route also requires ``register_readback`` evidence on the routed
    register itself: the word the DMA master captured, the CPU's own pre/post
    readback of that register and the RAM destination words are compared against
    each other.  It does *not* reset the devices before its case, because the
    register's state (for example a value an earlier F4 case wrote) is the
    transfer's source data; a write route does reset them so a FIFO starts empty.

    ``targets`` is the entry's per-target row list (each with ``index``,
    ``name``, ``window``, ``profile``, ``profile_path`` and ``protocol``).  A
    route with no target list cannot be resolved and is refused.  ``cpu_bus`` is
    the CPU bus this build drives: the route shares the target port with the CPU's
    own MMIO, and the arbitration this host implements is the OBI one, so a route
    on another CPU bus is refused by name rather than half-supported.
    """
    route = plan.get('route')
    if route is None:
        return None

    def refuse(reason):
        raise ValueError('unsupported-dma-route:' + reason)

    if cpu_bus is not None and cpu_bus != 'obi':
        refuse('cpu-bus:' + str(cpu_bus))
    direction = route.get('direction')
    if direction not in DMA_ROUTE_DIRECTIONS:
        refuse('direction:' + str(direction))
    mode = route.get('address_mode')
    if mode not in DMA_ROUTE_ADDRESS_MODES:
        refuse('address-mode:' + str(mode))
    if direction == 'write':
        if plan.get('increment_destination'):
            refuse('fixed-but-incrementing')
    else:
        # The routed register is the read source: a fixed read presents one
        # address, an aperture read lets the device advance it.  Either way the
        # RAM block on the other side is the incrementing destination.
        if not plan.get('increment_destination'):
            refuse('read-destination-not-incrementing')
        if mode == 'fixed' and plan.get('increment_source'):
            refuse('read-source-incrementing')
        if mode == 'aperture' and not plan.get('increment_source'):
            refuse('read-source-fixed')
    # Every admitted target bridge forwards one whole 32-bit word per beat (the
    # APB3 bridge has no write strobes, the Wishbone/AXI4-Lite/TL-UL beat face
    # carries a lane mask this host drives as a full word), so a routed beat has
    # to be a full-word master beat on every protocol.
    byte_enable = plan.get('master_byte_enable') or {}
    if byte_enable.get('kind') != 'full_word' or byte_enable.get('mask') != 15:
        refuse('master-byte-enable:' + str(byte_enable.get('kind')))
    if not plan.get('block_words') or plan['block_words'] < 1:
        refuse('block-words')
    target = None
    index = route.get('target_index')
    for row in targets or ():
        if row.get('index') == index:
            target = row
            break
    if target is None:
        refuse('target-not-declared:' + str(index))
    window = route.get('target_window')
    if not isinstance(window, dict):
        refuse('target-window-absent')
    if (window['base'] != target['window']['base']
            or window['size'] != target['window']['size']):
        refuse('target-window-mismatch')
    if route.get('target_profile') not in (None, target.get('profile_path')):
        refuse('target-profile-mismatch')
    # The routed target's own wire protocol, from the artifact this build really
    # produced.  A route is one held master beat on that target's generic request
    # port, completed by that target's own response, so every protocol whose
    # artifact binds a bridge to that port is admissible and each is driven
    # through its own adapter and its own passive trace.  A protocol outside the
    # admitted set keeps the named refusal ``dma_route_protocol_check`` states,
    # before any model is built.
    target_protocol = target.get('protocol')
    if target_protocol not in DMA_ROUTE_PROTOCOLS:
        raise ValueError(DMA_ROUTE_PROTOCOL_REFUSAL + str(target_protocol)
                         + ':' + str(target.get('name')))
    offset = route.get('offset')
    if type(offset) is not int or offset < 0 or offset % 4:
        refuse('offset')
    register = route.get('register') or {}
    if register.get('offset') != offset:
        refuse('register-offset')
    row = _route_register(target.get('profile'), offset)
    if row is None:
        refuse('register-not-in-profile:0x%x' % offset)
    # The direction, not the host, decides which access the routed register has
    # to support: a write pushes it, a read must be able to return it.
    if row.width != 32:
        refuse('register-width')
    if direction == 'write' and row.access not in ('rw', 'wo'):
        refuse('register-not-writable')
    if direction == 'read' and row.access not in ('rw', 'ro'):
        refuse('register-not-readable')
    address = window['base'] + offset
    bits = plan['byte_address_units']['source_destination_bits']
    if address > (1 << bits) - 1:
        refuse('route-address-unreachable:0x%08x' % address)
    evidence = route.get('evidence')
    if not isinstance(evidence, dict):
        refuse('evidence-absent')
    kind = evidence.get('kind')
    if kind not in DMA_ROUTE_EVIDENCE_KINDS:
        refuse('evidence-kind:' + str(kind))
    # The three read shapes have three witnesses.  ``fifo_read`` pops one entry
    # per accepted beat on a port the pinned RTL declares as popping on a read;
    # ``aperture_read`` walks ``words`` consecutive readable registers; a fixed
    # read returns one register word.
    fifo_read = direction == 'read' and route.get('kind') == 'fifo'
    aperture_read = direction == 'read' and mode == 'aperture'
    if fifo_read:
        if getattr(row, 'side_effect', None) != DMA_ROUTE_FIFO_POP_SIDE_EFFECT:
            # A readable register without the declared pop-on-read side effect
            # is not a FIFO: reading it would not pop anything, so claiming a
            # FIFO read would be false.  The TXFIFO at 0x18 is exactly this case
            # (its read arm has no case in spi_master_apb_if.sv:185-212).
            refuse('read-not-popping:%s' % getattr(row, 'side_effect', None))
        if kind != 'fifo_level':
            refuse('read-evidence-kind:' + str(kind))
    elif aperture_read:
        if kind != 'register_readback':
            refuse('aperture-evidence-kind:' + str(kind))
    elif direction == 'read' and kind != 'register_readback':
        refuse('read-evidence-kind:' + str(kind))
    evidence_offset = evidence.get('offset', 0)
    if type(evidence_offset) is not int or evidence_offset < 0 or evidence_offset % 4:
        refuse('evidence-offset')
    evidence_row = _route_register(target.get('profile'), evidence_offset)
    if evidence_row is None:
        refuse('evidence-register-not-in-profile:0x%x' % evidence_offset)
    if evidence_row.width != 32 or evidence_row.access not in ('rw', 'ro'):
        refuse('evidence-register-not-readable')
    if direction == 'read' and not fifo_read and not aperture_read \
            and evidence_offset != offset:
        # The read route's evidence is the routed register itself: only then do
        # the CPU's pre/post readbacks and the DMA's captured word describe the
        # same word.
        refuse('read-evidence-register-mismatch')
    if aperture_read and evidence_offset != offset:
        # An aperture readback starts at the first routed register: the CPU then
        # reads exactly the words the master walked.
        refuse('aperture-evidence-offset')
    if evidence_offset + 4 > window['size'] or offset + 4 > window['size']:
        refuse('offset-outside-window')
    beats = plan['block_words'] * byte_enable['beats_per_word']
    low = high = None
    mask = 0
    depth = evidence.get('depth')
    if kind == 'fifo_level':
        bits = evidence.get('bits')
        if (not isinstance(bits, list) or len(bits) != 2
                or any(type(bit) is not int or not 0 <= bit <= 31 for bit in bits)):
            refuse('evidence-bits')
        low, high = min(bits), max(bits)
        if high >= evidence_row.width:
            refuse('evidence-bits')
        mask = ((1 << (high - low + 1)) - 1) << low
        if type(depth) is not int or not 1 <= depth <= 1 << 20:
            refuse('evidence-depth')
        if fifo_read and depth < beats:
            # A block larger than the FIFO is a partial pop; this host has no
            # partial-pop evidence, so the declaration is refused instead.
            refuse('fifo-read-beyond-depth:%d>%d' % (beats, depth))
    expected_word = evidence.get('expected_word')
    if expected_word is not None:
        if type(expected_word) is not int or not 0 <= expected_word < 1 << 32:
            refuse('expected-word')
        if not fifo_read:
            refuse('expected-word-without-fifo-read')
    words = evidence.get('words')
    aperture = None
    if aperture_read:
        if type(words) is not int or words != beats:
            refuse('aperture-words:%s!=%d' % (words, beats))
        aperture = []
        for step in range(beats):
            step_offset = offset + 4 * step
            step_row = _route_register(target.get('profile'), step_offset)
            if step_row is None:
                refuse('aperture-register-not-in-profile:0x%x' % step_offset)
            if step_row.width != 32 or step_row.access not in ('rw', 'ro'):
                refuse('aperture-register-not-readable:0x%x' % step_offset)
            aperture.append({'offset': step_offset,
                             'address': window['base'] + step_offset,
                             'name': step_row.name})
    elif words not in (None, 1):
        refuse('aperture-words:%s' % words)
    error = plan.get('error_injection') or {}
    error_beat = None
    if error.get('requested'):
        if direction != 'read':
            # The host drives the error response on a routed read beat; a write
            # route's beats are pushes and this entry does not inject on them.
            refuse('error-injection-needs-read-route:' + str(direction))
        error_beat = error.get('beat_index')
        if type(error_beat) is not int or not 0 <= error_beat < beats:
            refuse('error-injection-beat:%s' % error_beat)
        declared_beat_direction = error.get('direction')
        if (declared_beat_direction is not None
                and declared_beat_direction != direction):
            refuse('error-injection-direction:' + str(declared_beat_direction))
    return dict(
        enabled=True,
        kind=route.get('kind'),
        direction=direction,
        address_mode=mode,
        target_index=index,
        target_name=target.get('name'),
        target_profile=target.get('profile_path'),
        # The routed target's own adapter protocol (from its artifact), and the
        # beat port the beat is presented on.  The header, the case line and the
        # evidence all name it, so no case is read as if APB3 carried every route.
        target_protocol=target_protocol,
        target_bridge=target.get('bridge'),
        beat_port=('target generic request/response port: '
                   'req_valid/req_ready/req_write/req_addr/req_wdata/req_be in, '
                   'rsp_valid/rsp_ready/rsp_rdata/rsp_error out'),
        target_window=dict(window),
        address=address,
        offset=offset,
        register=dict(name=row.name, offset=row.offset, access=row.access,
                      width=row.width, side_effect=row.side_effect),
        evidence=dict(kind=kind,
                      register=evidence_row.name,
                      offset=evidence_offset,
                      field=evidence.get('field'),
                      low=low, high=high, mask=mask,
                      depth=depth,
                      expected_word=expected_word,
                      words=words,
                      sampling=evidence.get('sampling', 'pre_post'),
                      source=evidence.get('source')),
        fifo=fifo_read,
        aperture=aperture,
        aperture_addresses=[step['address'] for step in aperture] if aperture else [],
        # A FIFO read of N words is declared against a FIFO holding exactly those
        # N words: the level before the transfer is the beat count and the level
        # after it is zero.  Both are read back by the CPU, not assumed.
        level_before=beats if fifo_read else None,
        level_after=0 if fifo_read else None,
        expected_word=expected_word,
        error_beat=error_beat,
        pushes=plan['block_words'],
        # The routed beats this build must observe: a write route pushes one
        # register word per beat, a read route captures one word per beat.
        reads=beats if direction == 'read' else 0,
        # A write route into a FIFO starts from the device's own reset state.  A
        # read route must not be reset: the register state left by an earlier
        # case is exactly the source data this transfer reads.
        reset_before_case=direction == 'write',
    )


def dma_host_limits(plan, validation=None, route_support=None):
    """Answer the planner's host limits from what this entry implements.

    ``validate_transfer_plan`` reports the host-only limits its author knew
    about; this entry owns the host, so every one of those codes is answered
    here.  The result lists the codes this increment *raised* (with evidence
    words), the ones already satisfied and the first refusal by name.  A plan
    whose route or error injection the host cannot execute is refused, never run
    through the RAM-only path while pretending to be the declared transfer.

    ``route_support`` is :func:`dma_route_support`'s answer for this plan: when
    the host can execute the declared route, the planner's route limit is
    satisfied and recorded with the evidence path this run will produce.
    """
    limits = list((validation or {}).get('host_limits') or [])
    byte_enable = plan.get('master_byte_enable') or {}
    delay = (plan.get('response_delay') or {}).get('ticks', 0)
    satisfied, raised, refusal = [], [], None
    for limit in limits:
        code = limit.get('code')
        value = limit.get('plan_value')
        if code == 'host-block-words-cap':
            if type(value) is int and value <= DMA_HOST_CAPABILITY[code]:
                raised.append(dict(code=code, plan_value=value,
                                   host_limit=DMA_HOST_CAPABILITY[code],
                                   evidence='MAILBOX_BYTES=%d, DMA_MAX_BLOCK_WORDS=%d'
                                            % (MAILBOX_BYTES, DMA_MAX_BLOCK_WORDS)))
                continue
            refusal = refusal or '%s:%s>%d' % (code, value, DMA_HOST_CAPABILITY[code])
            continue
        if code == 'host-fixed-start-word':
            satisfied.append(dict(code=code, plan_value=value,
                                  host_limit='plan_start_word'))
            raised.append(dict(code=code, plan_value=value,
                               host_limit='plan_start_word',
                               evidence='DMA_START_WORD carries the plan start word '
                                        'and the firmware writes it'))
            continue
        if code == 'host-full-word-master-sel':
            kind = byte_enable.get('kind')
            if kind in ('full_word', 'size_derived_lanes'):
                satisfied.append(dict(code=code, plan_value=kind,
                                      host_limit=DMA_HOST_CAPABILITY[code]))
                if kind != 'full_word':
                    raised.append(dict(code=code, plan_value=kind,
                                       host_limit='device_driven_lane_masks',
                                       evidence='mwb_sel is applied as the device '
                                                'presents it (DMA_LANE_PATTERN)'))
                continue
            refusal = refusal or ('partial-byte-enable-not-driven-by-device:'
                                  + str(kind))
            continue
        if code == 'host-response-delay-absent':
            if type(delay) is int and 0 <= delay <= DMA_HOST_CAPABILITY[code]:
                satisfied.append(dict(code=code, plan_value=delay,
                                      host_limit=DMA_HOST_CAPABILITY[code]))
                if delay:
                    raised.append(dict(code=code, plan_value=delay,
                                       host_limit=DMA_HOST_CAPABILITY[code],
                                       evidence='DMA_RESPONSE_DELAY holds mwb_stall for '
                                                'the declared ticks'))
                continue
            refusal = refusal or ('%s:%s>%d' % (code, delay,
                                               DMA_HOST_CAPABILITY[code]))
            continue
        if code == 'host-dma-target-route-absent':
            if route_support is not None:
                target = route_support['target_index']
                direction = route_support['direction']
                satisfied.append(dict(code=code, plan_value=value,
                                      host_limit=DMA_HOST_CAPABILITY[code]))
                if direction == 'read':
                    evidence_text = (
                        'the DMA master read beat at 0x%08x is presented on target '
                        '%d\'s APB3 request port at offset 0x%x with PWRITE=0, the '
                        'beat is held until that target returns PRDATA, and the '
                        'captured word is returned to the DMA on mwb_dat_r and '
                        'compared with the RAM destination words and the CPU\'s own '
                        'pre/post readback of the declared %s word'
                        % (route_support['address'], target,
                           route_support['offset'],
                           route_support['evidence']['register']))
                else:
                    evidence_text = (
                        'the DMA master beat at 0x%08x is presented on target %d\'s '
                        'APB3 request port at offset 0x%x, the beat is held until '
                        'that target responds, and the F6 firmware reads the '
                        'declared %s evidence word before and after the transfer'
                        % (route_support['address'], target,
                           route_support['offset'],
                           route_support['evidence']['register']))
                raised.append(dict(
                    code=code, plan_value=value,
                    host_limit=DMA_HOST_CAPABILITY[code],
                    evidence=evidence_text))
                continue
            refusal = refusal or (code + ':' + str(value))
            continue
        if code == 'host-error-injection-absent':
            # A declared error is a host action on the device's own error input,
            # so it needs a routed beat to land on: one declared beat of the
            # route is answered with ACK+ERR.  With no route there is no beat to
            # inject on and the declaration is refused by name.
            if route_support is not None and route_support.get('error_beat') is not None:
                satisfied.append(dict(code=code, plan_value=value,
                                      host_limit=DMA_HOST_CAPABILITY[code]))
                raised.append(dict(
                    code=code, plan_value=value,
                    host_limit=DMA_HOST_CAPABILITY[code],
                    evidence='mwb_err is asserted with the ack of routed beat %d of '
                             '%d (dma_error_injection beat_index); the device latches '
                             'its own sticky ERR status bit and raises its completion '
                             'interrupt, and the CPU readback of that bit is the case '
                             'evidence'
                             % (route_support['error_beat'],
                                route_support['reads'])))
                continue
            refusal = refusal or 'error-injection-requires-route'
            continue
        if code == 'host-outstanding-cap':
            # The declared depth of the master-response pipeline.  This host serves
            # it from a ring (the header's DMA_MASTER_OUTSTANDING), and the case line
            # reports the peak it really reached, so the limit is raised with that
            # evidence instead of being a hidden clamp.
            plan_depth = plan.get('max_outstanding', 1)
            if type(plan_depth) is int and plan_depth <= DMA_HOST_CAPABILITY[code]:
                raised.append(dict(code=code, plan_value=plan_depth,
                                   host_limit=DMA_HOST_CAPABILITY[code],
                                   evidence='DMA_MASTER_OUTSTANDING=%d, mwb_stall is '
                                            'held only while the response ring is '
                                            'full, and the case line reports '
                                            'dma_outstanding_peak'
                                            % plan_depth))
                continue
            refusal = refusal or '%s:%s>%d' % (code, plan_depth,
                                               DMA_HOST_CAPABILITY[code])
            continue
        refusal = refusal or 'unknown-host-limit:' + str(code)
    return dict(capability=dict(DMA_HOST_CAPABILITY),
                planner_host_supported=bool((validation or {}).get('host_supported')),
                satisfied=satisfied, raised=raised, refusal=refusal)


def _plan_behavior_facts(plan):
    """The behavior facts the report reads, taken from the plan itself.

    ``myfuzz.composition.inprocess_behavior.dma_behavior`` keeps the historical
    1..4 block bound.  The plan normalized the same behavior file against the
    device's own bound, so this reading states the same control-status facts for
    a block length that loader still refuses; the loader's refusal is reported
    beside them instead of being mistaken for a device limit.
    """
    status = plan['status']
    return dict(block_words=plan['block_words'],
                irq_pulse_ticks=plan['irq_pulse_ticks'],
                busy_bit=status['busy_bit'], err_bit=status['err_bit'],
                status_kind=status['kind'],
                status_bits_declared=status['declared_by'] == 'file',
                status_bits_source=status['source'],
                declared_by=plan['declaration']['behavior_declared_by'],
                declaration_path=plan['declaration']['behavior_path'])


def dma_declaration(config, dma_profile, dma_artifact, dma_facts=None,
                    targets=None, cpu_bus=None):
    """Check one declared DMA transfer against its device, binding and this host.

    The device and encodability half is the planning module's:
    ``dma_transfer_declaration`` normalizes the scenario's declaration against
    the pinned device contract, and ``validate_transfer_plan`` refuses anything
    the selected RTL cannot encode.  This entry therefore carries no block,
    increment or byte-enable limits of its own: it reads the plan's
    ``block_words``, ``start`` word, ``length_value``, ``master_byte_enable``,
    ``max_outstanding`` and ``response_delay``, answers the planner's host limits
    from ``DMA_HOST_CAPABILITY`` and refuses by name whatever it cannot execute
    (a DMA-master route the host has no fabric for, host-driven error injection
    or a lane mask the RTL does not drive).

    ``targets`` is the entry's per-target row list (``index``/``name``/
    ``window``/``profile``/``protocol``).  A plan that declares a route is
    cross-checked against it by :func:`dma_route_support`; a route with no target
    list cannot be resolved and is refused by name.

    ``dma_facts`` is the merged ``myfuzz.composition.inprocess_behavior`` DMA
    declaration: it states the control-status bit positions per device, and the
    reported ``status_bits_declared``/``status_bits_source`` say whether the run
    used a device declaration or the built-in ZipDMA default.  The profile and
    the generated edge contract remain the authority for register offsets,
    request shape and IRQ behavior.
    """
    from myfuzz.composition.dma_transfer import (DmaTransferError,
                                                 dma_transfer_declaration,
                                                 validate_transfer_plan)
    from myfuzz.composition.inprocess_behavior import dma_behavior
    from myfuzz.scenario.f6_dma_source_provider import select_f6_dma_source_provider
    # The scenario's own inline keys are checked first, so an invalid inline value
    # is refused under the key the operator wrote, not as a behavior-file error.
    inline_block = config.get('dma_block_words')
    if inline_block is not None and (type(inline_block) is not int
                                     or inline_block < 1):
        raise ValueError('unsupported: dma_block_words must be a positive integer')
    inline_pulse = config.get('dma_irq_pulse_ticks')
    if inline_pulse is not None and (type(inline_pulse) is not int
                                     or not 1 <= inline_pulse <= 4096):
        raise ValueError('unsupported: a pulse DMA IRQ needs dma_irq_pulse_ticks')
    try:
        plan = dma_transfer_declaration(config, dma_profile, dma_artifact,
                                        base_dir=ROOT)
        validation = validate_transfer_plan(plan, dma_profile, dma_artifact)
    except DmaTransferError as error:
        detail = '' if error.detail is None else ':' + str(error.detail)
        raise ValueError('unsupported-dma-declaration:' + error.reason + detail) from None
    family = plan['device']['family']
    block = plan['block_words']
    bound = DMA_PROVEN_BLOCK_WORDS.get(family)
    if bound is None:
        raise ValueError('unsupported-dma-device:' + str(family))
    if block > bound:
        raise ValueError('unsupported-dma-block:%s:%d>%d' % (family, block, bound))
    route = dma_route_support(plan, targets, cpu_bus=cpu_bus)
    host = dma_host_limits(plan, validation, route_support=route)
    if host['refusal'] is not None:
        raise ValueError('unsupported-dma-declaration:' + host['refusal'])
    # The host renders the declared lane pattern as one formula (n contiguous
    # lanes per beat), so a pattern it cannot express is refused here instead of
    # being silently replaced by a full word.
    byte_enable = plan['master_byte_enable']
    lanes_per_beat = byte_enable['lanes_per_beat']
    for index, mask in enumerate(byte_enable['lane_pattern']):
        expected_mask = ((1 << lanes_per_beat) - 1) << (index * lanes_per_beat)
        if mask != expected_mask:
            raise ValueError('unsupported-dma-lane-pattern:' +
                             ','.join(str(item) for item in byte_enable['lane_pattern']))
    # A declared observation expectation has to agree with the declared transfer:
    # an expectation that contradicts the plan would fail every case for a reason
    # the operator never wrote, so it is refused by name.
    expectation = plan['response_delay'].get('observation') or {}
    for key, value in (('stall_ticks_min', plan['response_delay']['ticks']),
                       ('stall_ticks_max', plan['response_delay']['ticks'])):
        declared = expectation.get(key)
        if declared is not None and (
                (key == 'stall_ticks_min' and declared > value)
                or (key == 'stall_ticks_max' and declared < value)):
            raise ValueError('unsupported-dma-declaration:declared-%s-vs-delay-%d'
                             % (key, value))
    beats_per_word = byte_enable['beats_per_word']
    for key, value in (('dma_reads', block * beats_per_word),
                       ('dma_writes', block * beats_per_word)):
        declared = expectation.get(key)
        if declared is not None and declared != value:
            raise ValueError('unsupported-dma-declaration:declared-%s-%d-vs-plan-%d'
                             % (key, declared, value))
    # The host holds every accepted beat's response for the declared delay, so a
    # pattern that would hold only one direction, or fewer ticks than the delay,
    # is refused by name instead of being partly applied.
    backpressure = plan['response_delay'].get('backpressure') or {}
    pattern = backpressure.get('pattern')
    if pattern is not None and pattern not in ('per_response_stall', 'none'):
        raise ValueError('unsupported-dma-backpressure:' + str(pattern))
    if pattern == 'none' and plan['response_delay']['ticks']:
        raise ValueError('unsupported-dma-backpressure:none-declares-no-hold')
    applies = backpressure.get('applies_to')
    if applies is not None and sorted(applies) != ['read', 'write']:
        raise ValueError('unsupported-dma-backpressure:applies_to:' +
                         ','.join(str(item) for item in applies))
    hold = backpressure.get('max_consecutive_ticks')
    if hold is not None and hold < plan['response_delay']['ticks']:
        raise ValueError('unsupported-dma-backpressure:max_consecutive_ticks-%d-vs-delay-%d'
                         % (hold, plan['response_delay']['ticks']))

    behavior_refusal = None
    if dma_facts is None:
        try:
            dma_facts = dma_behavior(config, base_dir=ROOT)
        except ValueError as error:
            # The composition loader keeps a 1..4 block bound the plan has
            # already replaced; the same file is read from the plan instead.
            behavior_refusal = str(error)
            dma_facts = _plan_behavior_facts(plan)
    provider = select_f6_dma_source_provider(dma_profile, base_dir=ROOT)
    csr, behavior = provider.csr, provider.behavior
    if csr.get('source_destination_units') != 'byte_address':
        raise ValueError('unsupported: DMA source/destination must be byte addresses')
    if csr.get('master_address_units') != 'word':
        raise ValueError('unsupported: DMA master addresses must be word addresses')
    if behavior.get('length_unit') != plan['length_unit']:
        raise ValueError('unsupported: the declared DMA length unit')
    offsets = csr['offsets']
    for role in ('control', 'source', 'destination', 'length'):
        if offsets[role] != plan['device']['registers'][role]['offset']:
            raise ValueError('unsupported: the DMA register map disagrees with the plan')
    clear = behavior.get('irq_clear') or {}
    if clear.get('method') not in ('none', 'write'):
        raise ValueError('unsupported: the declared DMA IRQ clear method')
    if clear.get('method') == 'write' and clear.get('byte_enable', 15) != 15:
        raise ValueError('unsupported: a partial DMA clear write')
    if provider.irq_trigger not in ('level', 'pulse'):
        raise ValueError('unsupported: the declared DMA IRQ trigger')
    # A declared pulse source must state how long the host may hold the CPU line;
    # a one-tick spike would be dropped silently, which is never reported honestly.
    pulse_ticks = dma_irq_pulse_ticks(config, dma_facts)
    if provider.irq_trigger == 'pulse' and (type(pulse_ticks) is not int
                                            or not 1 <= pulse_ticks <= 4096):
        raise ValueError('unsupported: a pulse DMA IRQ needs dma_irq_pulse_ticks')
    edge = dma_artifact['dma_edge_contract']
    if (edge.get('master_address_units') != 'word' or edge.get('master_address_shift') != 2
            or not isinstance(edge.get('environment_max_outstanding'), int)
            or edge.get('environment_max_outstanding') < 1
            or edge.get('same_edge_accept_and_complete')
            or edge.get('control_address_units') != 'word_index'):
        raise ValueError('unsupported: the generated DMA edge contract')
    if edge.get('control_byte_enable_signal') not in (None, 'swb_sel'):
        raise ValueError('unsupported: DMA control byte-enable signal')
    if edge.get('master_byte_enable_signal') not in (None, 'mwb_sel'):
        raise ValueError('unsupported: DMA master byte-enable signal')
    if edge.get('master_byte_enable_signal') is None and edge.get('master_fixed_byte_enable') != 15:
        raise ValueError('unsupported: a non-full fixed DMA master byte enable')
    # The host serves the control port at its declared word index and the master
    # at word granularity, so the generated port shapes have to match exactly.
    ports = {(row['channel'], row['role']): row for row in dma_artifact['backend_ports']}
    expected = {('swb', 'cyc'): 'swb_cyc', ('swb', 'stb'): 'swb_stb', ('swb', 'we'): 'swb_we',
                ('swb', 'adr'): 'swb_adr', ('swb', 'dat_w'): 'swb_dat_w',
                ('swb', 'stall'): 'swb_stall', ('swb', 'ack'): 'swb_ack',
                ('swb', 'dat_r'): 'swb_dat_r',
                ('mwb', 'cyc'): 'mwb_cyc', ('mwb', 'stb'): 'mwb_stb', ('mwb', 'we'): 'mwb_we',
                ('mwb', 'adr'): 'mwb_adr', ('mwb', 'dat_w'): 'mwb_dat_w',
                ('mwb', 'stall'): 'mwb_stall', ('mwb', 'ack'): 'mwb_ack',
                ('mwb', 'dat_r'): 'mwb_dat_r', ('mwb', 'err'): 'mwb_err'}
    for key, name in expected.items():
        row = ports.get(key)
        if row is None or row['name'] != name:
            raise ValueError('unsupported: the DMA model does not expose ' + name)
    if ports['swb', 'adr']['width'] != 2:
        raise ValueError('unsupported: the DMA control port must index four words')
    beats = block * beats_per_word
    control_rows = [row for row in dma_profile.address.registers
                    if row.offset == offsets['control']]
    return dict(control_offset=offsets['control'], source_offset=offsets['source'],
                destination_offset=offsets['destination'], length_offset=offsets['length'],
                start_word=plan['start']['word'], block_words=block,
                length_value=plan['length_value'], length_unit=plan['length_unit'],
                status_kind=register_kind(control_rows[0].name if control_rows else ''),
                master_shift=edge['master_address_shift'],
                control_select=int(edge.get('control_byte_enable_signal') == 'swb_sel'),
                master_select=int(edge.get('master_byte_enable_signal') == 'mwb_sel'),
                clear=None if clear.get('method') == 'none' else
                dict(offset=clear['offset'], value=clear['value']),
                # The control register's busy/error bit positions are the one
                # device fact the DMA profile chain does not state: they come
                # from a behavior declaration when one exists, and otherwise
                # from the built-in ZipDMA default, reported as such.
                busy_bit=dma_facts['busy_bit'], err_bit=dma_facts['err_bit'],
                status_bits_declared=dma_facts['status_bits_declared'],
                status_bits_source=dma_facts['status_bits_source'],
                declared_behavior=dma_facts,
                behavior_loader_refusal=behavior_refusal,
                behavior_declared_by=plan['declaration']['behavior_declared_by'],
                irq=dict(port=provider.irq_port, trigger=provider.irq_trigger,
                         polarity='active_high',
                         pulse_ticks=pulse_ticks if provider.irq_trigger == 'pulse' else 0,
                         endpoint=provider.irq_endpoint_id),
                # --- the plan and what this host does with it -----------------
                plan=plan, validation=validation,
                planner_host_supported=validation['host_supported'],
                host_limits=validation['host_limits'],
                host_limits_satisfied=host['satisfied'],
                host_limits_raised=host['raised'],
                host_capability=host['capability'],
                supported=True, refusal=None,
                device_family=family,
                # The pinned device's declarable capabilities, as the planner
                # cross-checked them, and whether this build's case line has to
                # state the device/channel/beat group instead of leaving it to the
                # historical ZipDMA default.
                device_capabilities=dict(plan['device']['device_capabilities']),
                device_reported=(family != 'zipdma'
                                 or plan['device']['device_capabilities']['channels'] != 1
                                 or plan['device']['device_capabilities']['beat_bytes'] != 4
                                 or plan['max_outstanding'] != 1),
                max_outstanding=plan['max_outstanding'],
                master_byte_enable=dict(kind=byte_enable['kind'],
                                        mask=byte_enable['mask'],
                                        lane_pattern=list(byte_enable['lane_pattern']),
                                        lanes_per_beat=byte_enable['lanes_per_beat'],
                                        beats_per_word=byte_enable['beats_per_word'],
                                        size_bytes=byte_enable['size_bytes'],
                                        size_code=byte_enable['size_code'],
                                        partial=byte_enable['partial']),
                expected_reads=beats, expected_writes=beats,
                response_delay=plan['response_delay'],
                delay_ticks=plan['response_delay']['ticks'],
                # --- the declared DMA-to-target route, as this host executes it --
                # ``None`` is the RAM-only transfer the first increment ran.  A
                # dict states the one route shape it can run: a fixed write into
                # one declared APB3 target (the master pushes the register) or a
                # fixed read from one readable register (the master captures
                # PRDATA and the DMA writes it to RAM), with the evidence word
                # the F6 firmware samples before and after the transfer.
                route=route,
                # The declared error injection (if any): a host action on the
                # device's own mwb_err input, answered with the ack of the
                # declared routed beat.
                error_injection=dict(plan['error_injection']),
                source_destination_byte_address_bits=(
                    plan['byte_address_units']['source_destination_bits']))


# ---------------------------------------------------------------------------
# Input records
# ---------------------------------------------------------------------------
def flow_arity(irq, dma):
    """The word count of every flow these components can actually serve.

    A flow whose declaration is absent is absent from the table, so a record for
    it is refused by name before any model is built.
    """
    arity = dict(FLOW_ARITY)
    if irq is not None:
        # A multi-link target names which link this case triggers: the record is
        # the link index followed by that link's declared trigger values.
        arity['F5'] = len(irq['trigger_offsets']) + (
            1 if irq.get('source_count', 1) > 1 else 0)
    if dma is not None:
        arity['F6'] = dma['block_words']
    return arity


def f5_link_word_count(link):
    """How many record words one global F5 link's case carries.

    A single link is the link index (only when the table has more than one row)
    followed by that link's trigger values.  The synthetic "both" row carries
    the link index followed by every member link's trigger values in member
    order, because its case triggers all of them.
    """
    if link.get('mode') == 'both':
        return 1 + sum(len(member['trigger_offsets']) for member in link['members'])
    return 1 + len(link['trigger_offsets'])


def f5_record_word_counts(f5_links):
    """The accepted F5 word counts for this global link table.

    A one-row table keeps the historical shape (no index word); a multi-row one
    states one count per row, so a both row and a single row are both accepted
    by the record gate and the index word decides which one the case is.
    """
    if len(f5_links) == 1:
        return (f5_link_word_count(f5_links[0]) - 1,)
    return tuple(sorted({f5_link_word_count(link) for link in f5_links}))


def f5_link_table(irq):
    """Every selectable F5 link, including the synthetic "both" row.

    ``irq['links']`` is the physical link table (one row per declared device
    output); ``irq['both']`` is the optional two-source selection over it.  The
    record gate, the firmware dispatch and the evidence checks read this one
    combined view, so a both case and a single-link case share the same global
    numbering without either being folded into the other.
    """
    if irq is None:
        return []
    links = list(irq.get('links') or [irq])
    both = irq.get('both')
    if both is not None:
        links.append(both)
    return links


def f5_both_link(irq):
    """The synthetic two-source row of this declaration, or ``None``."""
    return None if irq is None else irq.get('both')


def f5_both_selected(irq, record):
    """Whether this F5 record selected the two-source row."""
    if irq is None or record.get('flow') != 'F5':
        return False
    both = irq.get('both')
    if both is None:
        return False
    links = f5_link_table(irq)
    if len(links) <= 1 or not record.get('fields'):
        return False
    return record['fields'][0] == both['index']


def parse_record(text, *, windows, arity, label='APB', refusals=None, pin=None,
                 f1_words=1, f5_links=None, f5_target_index=None,
                 f1_allow_compressed=False, serial=None):
    """Turn one operator record into the exact input this host will hand over.

    A flow the selected components cannot serve is refused by name.  When the
    declaration explains why (``refusals``), that stated reason is what the
    operator sees, so a missing F5 reads as the declaration's own refusal instead
    of as an unknown tag.

    An F2 or F4 address is routed to one declared target window and the record
    carries that ``target_index``; F2 may instead name a RAM data word, which is
    no target.  F5 is always the one target ``target_for_f5`` selected, so its
    ``target_index`` comes from the declaration rather than from a record word.

    A pin target's F2 carries the external pin word as its optional second
    operand: the host driver value is applied before the CPU reads PADIN, so the
    read is a CPU read of the target *under a declared external stimulus* rather
    than a separate flow.  A one-word F2 keeps the declared external value and is
    reported as exactly that (``pin_stimulus declared_default``).

    ``f1_allow_compressed`` states the scenario's compressed declaration.  With it
    a record word whose bits [1:0] are not ``11`` is two 16-bit parcels and the
    lexical "one 32-bit word" refusal does not apply; the shape itself (the safe
    ALU subset, no compressed control or memory) is still the record gate's job.
    """
    if type(text) is not str or not text:
        raise ValueError('one record text is required')
    fields = text.split(':')
    flow = fields[0]
    if flow == 'P':
        raise ValueError('unsupported-flow:P:pin-stimulus-is-the-optional-second-'
                         'word-of-F2-on-a-pin-target')
    if flow not in arity:
        if refusals and flow in refusals:
            raise ValueError(refusals[flow])
        raise ValueError('unsupported flow tag: ' + flow)
    if flow == 'F1':
        counts = tuple(range(1, f1_words + 1))
    elif flow == 'F2' and (pin is not None or serial is not None):
        # A stimulus word: the pad target reads it as the host driver value, and a
        # serial peer reads its low byte as the byte it clocks onto the wire.  A
        # one-word F2 carries no stimulus on either kind of target.
        counts = (1, 2)
    elif flow == 'F5' and f5_links:
        # One F5 record shape carries the global link index followed by that
        # link's trigger values.  A "both" row in the table (two declaring
        # targets, one link each) carries both trigger sequences, so its record
        # is longer; the first word is what states which shape this is.
        counts = f5_record_word_counts(f5_links)
    else:
        counts = (arity[flow],)
    if len(fields) - 1 not in counts:
        raise ValueError(flow + ' needs ' +
                         (' or '.join(str(count) for count in counts)) + ' word(s)')
    values = []
    for field in fields[1:]:
        if not 0 < len(field) <= 8 or any(character not in '0123456789abcdefABCDEF'
                                          for character in field):
            raise ValueError('record words must be 1-8 hexadecimal digits')
        values.append(int(field, 16))
    if flow == 'F5' and f5_links is not None and len(f5_links) > 1:
        if values[0] >= len(f5_links):
            raise ValueError('F5 link index ' + str(values[0]) + ' is not one of the ' +
                             str(len(f5_links)) + ' declared links')
        link = f5_links[values[0]]
        expected = f5_link_word_count(link)
        if len(values) != expected:
            raise ValueError('F5 link ' + str(values[0]) + ' needs ' +
                             str(expected) + ' word(s)')
    first = values[0]
    data_base = windows['data_base']
    ram_window = dict(base=windows['ram_base'], size=windows['ram_size'])
    if flow == 'F1':
        for position, value in enumerate(values):
            if value & 3 != 3 and not f1_allow_compressed:
                raise ValueError('F1 instruction ' + str(position) +
                                 ' must be one 32-bit instruction word')
    elif flow == 'F2':
        ram = data_base <= first <= ram_window['base'] + ram_window['size'] - 4
        target_index = None
        if first % 4 == 0 and not ram:
            try:
                target_index = route_target_index(windows, first)
            except ValueError as error:
                raise ValueError('F2 address is not an aligned word in a declared '
                                 'target window: ' + str(error)) from error
        if first & 3 or not (ram or target_index is not None):
            raise ValueError('F2 address must be an aligned ' + label +
                             ' or data-window RAM word')
        if len(values) == 2:
            if pin is not None:
                if (target_index != 0
                        or first != windows['ip_base'] + pin['padin_offset']):
                    raise ValueError('an F2 stimulus word applies only to the declared '
                                     'PADIN address')
                if values[1] >= 1 << pin['width']:
                    raise ValueError('F2 stimulus exceeds the declared pad width')
            elif serial is not None:
                # A serial peer's stimulus is the one byte it clocks onto the wire;
                # the address is any readable word of the same target, and the byte
                # is the low eight bits of the record word.
                if target_index != 0:
                    raise ValueError('an F2 serial stimulus applies only to the one '
                                     'target the declared peer belongs to')
                if values[1] > 0xff:
                    raise ValueError('F2 serial stimulus is one byte, not a longer word')
            else:
                raise ValueError('F2 takes one word on a target without a pin model '
                                 'or serial peer')
    elif flow == 'F3':
        if first & 3 or not data_base <= first <= ram_window['base'] + ram_window['size'] - 4:
            raise ValueError('F3 address must be an aligned data-window RAM word')
    elif flow == 'F4':
        target_index = route_target_index(windows, first) if first % 4 == 0 else None
        if first & 3 or target_index is None:
            raise ValueError('F4 address must be an aligned word in the ' + label + ' window')
    if flow == 'F5':
        # The one global link numbering covers every declaring target.  A
        # single-link build keeps the historical record shape (no index word), so
        # its case is routed to the one F5 target exactly as before.  A multi-link
        # build puts the global link index first, and the link states its target.
        target_index = f5_target_index
        if f5_links:
            link = f5_links[values[0] if len(f5_links) > 1 else 0]
            target_index = link.get('target_index', f5_target_index)
    if flow in ('F1', 'F3', 'F6'):
        target_index = None
    text = flow + ':' + ':'.join(format(value, '08x') for value in values)
    message = 'CASE ' + flow + ' ' + ' '.join(format(value, '08x') for value in values)
    return dict(flow=flow, fields=tuple(values), text=text, message=message,
                target_index=target_index)


def f1_flags_for_record(f1_words, f1_subword, f1_flags):
    """The scenario's F1 program-shape flags, or the historical default.

    The entry reads the declaration once (:func:`f1_gate_flags_from_scenario`)
    and passes the result to every gate call site.  A caller that only states
    the historical ``f1_words``/``f1_subword`` (the older pure-Python tests and
    helper scripts) gets the same flags reconstructed from those two values, so
    no existing call site changes meaning.
    """
    from myfuzz.fuzz.f1_program_gate import F1GateFlags, normalize_f1_gate_flags
    if f1_flags is not None:
        return normalize_f1_gate_flags(f1_flags)
    # The one-word legacy contract is handled before this helper; reaching it
    # means program mode, so the reconstruction states at least two words.
    return F1GateFlags(program_words=f1_words if f1_words > 1 else 2,
                       subword=f1_subword)


def _f1_compressed(config, f1_flags):
    """Whether the declaration admits two-parcel (compressed) F1 record words.

    The scenario flag is read once by the one scenario gate; this helper states
    the same fact for the lexical record parser, which runs before the shape
    gate and must therefore accept a word whose bits [1:0] are not ``11`` when
    the scenario declared compressed parcels.  A caller that states no flags
    (the older pure-Python helpers) falls back to the scenario mapping, whose
    default is off.
    """
    from myfuzz.fuzz.f1_program_gate import normalize_f1_gate_flags
    if f1_flags is not None:
        return bool(normalize_f1_gate_flags(f1_flags).allow_compressed)
    return bool(config.get('f1_allow_compressed', False))


def validate_record(record, *, isa, windows, f1_words=1, f1_subword=False,
                    f1_flags=None):
    """Reject an F1 input the fixed trampoline or the declared ISA cannot execute.

    A one-word record keeps the exact legacy gate (one ALU word, mailbox register
    x8 untouched).  A declared program (``f1_words > 1``) is validated by the
    shared F1 program gate :func:`myfuzz.fuzz.f1_program_gate.
    validate_f1_program_record`, which dispatches on the scenario's declared
    shape.  The legacy program mode reproduces the historical refusals word for
    word; ``f1_allow_address_forms`` admits a statically proven computed base
    (:func:`myfuzz.fuzz.rv32_program.validate_address_program`) and
    ``f1_allow_branches`` admits strictly-forward B-type branches
    (:func:`myfuzz.fuzz.rv32_program.validate_program_words`).  The C++ host
    repeats the same rules; this is the operator-facing refusal.
    """
    from scripts.run_inprocess_f1f4 import validate_record as validate_f1
    if record['flow'] != 'F1':
        return validate_f1(record, isa=isa, windows=windows)
    if len(record['fields']) == 1 and f1_words == 1:
        return validate_f1(record, isa=isa, windows=windows)
    from myfuzz.fuzz.f1_program_gate import validate_f1_program_record
    # The image base is the fixed slot address: a JALR and a C.JR/C.JALR are
    # absolute transfers, and the gate resolves their target against it.
    validate_f1_program_record(
        record, isa=isa, window_bytes=PROGRAM_DATA_WORDS * 4,
        flags=f1_flags_for_record(f1_words, f1_subword, f1_flags),
        image_base=windows['ram_base'] + SLOT_OFFSET)
    return record

def build_firmware(layout, *, irq, dma, interrupt_bootstrap=True, f1_words=1,
                   wait_iterations=256, custom_irq=None, f1_trap=None,
                   irq_take_clear=False):
    """Assemble the one-time RAM image; nothing here changes per case.

    The ISR is one body parameterized by four RAM cells the flow bodies publish
    (the status address to read, the result cell, the clear address and value),
    so there is no handler branch per device: what it touches is what the case
    declared before it enabled that source.

    A target that declares no F5 facts contributes no ``irq`` declaration: its
    command branch and its body are left out of the image instead of being
    emitted against facts the declaration does not have.

    ``irq['links']`` is the one global link table: a link that states ``base``
    addresses its own target window, so a multi-declaring scenario's selected
    link publishes that target's status/clear addresses and writes the trigger
    sequence into that target's window.  A link without ``base`` keeps the
    historical single-target base ``layout['irq_base']``, so a one-target image
    is byte-identical to the old one.

    ``interrupt_bootstrap`` is the CPU bus's own capability, not a per-device
    choice: an OBI CPU declares a machine-external interrupt input, so its
    bootstrap installs the declared vector and enables it.  A Wishbone CPU build
    delivers no interrupt at all (F5 is refused by name), and that CPU declares no
    such CSR contract, so its bootstrap is one jump from its reset vector into the
    loop.

    ``irq_take_clear`` is the packed AXI4 CPU's take witness: that boundary has
    no probe port, so the CPU's own ``mcause`` readback is the observation, and
    the ISR clears it after the entry so the *next* case's take is a fresh
    transition instead of the previous case's stale cause.  A build without that
    witness emits the historical ISR byte for byte.

    ``f1_trap`` is the one declared exception path (``f1_trap_program``): when it
    is stated, this image also carries an M-mode trap handler at
    ``layout['trap_handler']`` and the three RAM cells it stores to, and the
    exception entry of the vector points at it instead of at the F5 handler.  The
    slot program only ever executes the faulting instruction; the handler is the
    firmware image's and is never written by a case.
    """
    if type(wait_iterations) is not int or not 1 <= wait_iterations <= 2047:
        raise ValueError('wait_iterations must be an integer in 1..2047')
    # Whether this image carries the synthetic two-source row.  A build without
    # one emits the historical boot, bodies and ISR byte for byte: the extra
    # cells and the second read are a both-build feature, not a tax on every
    # single-link image.
    both = None if irq is None else irq.get('both')
    # The longest declared clear-write sequence over the physical links.  One
    # step keeps the historical single-clear ISR byte for byte; two steps add the
    # second address/value cell pair and one more handler store, so a device
    # whose acknowledge protocol is two ordered register writes runs as declared.
    physical = [] if irq is None else (
        [irq] if irq.get('links') is None else list(irq['links']))
    clear_steps = max([len(link.get('clears') or ()) for link in physical] or [0])
    multi_clear = clear_steps > 1
    from myfuzz.integration.rv32_fixed_firmware import _addi, _jal, _lui_addi_load, _lw, _sw
    program = Program(layout['main'])
    program.emit(*_lui_addi_load(8, layout['mailbox']))
    # A spurious interrupt can arrive before any F5 body published the handler
    # cells (for example an F4 store to a timer COUNT that overflows).  Publish
    # safe, valid cells at boot so that handler reads a real status/RAM address
    # instead of address zero: the case is then classified as interference, not
    # turned into an unmapped data access that aborts the batch.
    status_address = layout['irq_base'] + (0 if irq is None else irq['status_offset'])
    program.emit(*_lui_addi_load(9, status_address))
    program.emit(_sw(9, 8, HB_STATUS))
    program.emit(*_lui_addi_load(9, layout['result_f5']))
    program.emit(_sw(9, 8, HB_RESULT))
    program.emit(_sw(0, 8, HB_CLEAR), _sw(0, 8, HB_CLEAR_VALUE))
    if multi_clear:
        # The second clear step is published per case; the boot value is zero so
        # a spurious interrupt before any body cannot perform it.
        program.emit(_sw(0, 8, HB_CLEAR_B), _sw(0, 8, HB_CLEAR_VALUE_B))
    if both is not None:
        # The second (both-source) cell set starts at zero: status2 = 0 is what
        # makes the handler skip the second read for a single-link case.  The
        # masks and the serviced/expected cells are zero for the same reason, so
        # a spurious or leftover interrupt never performs a second access.
        program.emit(_sw(0, 8, HB_STATUS2), _sw(0, 8, HB_RESULT2),
                     _sw(0, 8, HB_CLEAR2), _sw(0, 8, HB_CLEAR_VALUE2),
                     _sw(0, 8, HB_MASK1), _sw(0, 8, HB_MASK2),
                     _sw(0, 8, HB_NEED), _sw(0, 8, HB_SERVICED))
    program.emit(*_lui_addi_load(9, layout['flag']))
    program.emit(_sw(9, 8, HB_FLAG))
    program.mark('poll')
    program.emit(_lw(5, 8, 0))
    program.branch(5, 0, 'poll')
    commands = [(1, 'f1'), (2, 'f2'), (3, 'store'), (4, 'store')]
    if irq is not None:
        commands.append((5, 'f5'))
    if dma is not None:
        commands.append((6, 'f6'))
    for command, target in commands:
        program.emit(_addi(6, 0, command))
        program.branch(5, 6, target)
    program.jump('poll')
    program.mark('f1')
    if f1_words > 1:
        # A multi-word program may use LW/SW, and x18 is the only base the host
        # admits: the firmware points it at the declared data window before the
        # jump, so the program's addresses are bounded without a prologue word.
        program.emit(*_lui_addi_load(18, layout['data_base']))
    program.emit(*_lui_addi_load(9, layout['slot']))
    program.emit(_jalr(0, 9))
    program.mark('f1_back')
    program.emit(_sw(0, 8, 0))
    program.jump('poll')
    program.mark('f2')
    program.emit(_lw(9, 8, 4), _lw(7, 9, 0), _sw(7, 8, 8), _sw(0, 8, 0))
    program.jump('poll')
    program.mark('store')
    program.emit(_lw(9, 8, 4), _lw(7, 8, 12), _sw(7, 9, 0), _sw(0, 8, 0))
    program.jump('poll')

    # F5: publish the declared handler parameters, then perform the declared
    # trigger writes with the values this case put in the input block.  With N
    # selectable links the case's first input word selects one link; the body is
    # emitted once per link from that link's own declaration, so two sources are
    # never folded into one handler read.  A "both" row publishes *two* status /
    # result / clear sets and writes both trigger sequences; its ISR reads both
    # targets and stores both results, which is the one shape this host can
    # attribute two simultaneously asserted sources with.
    if irq is not None:
        links = f5_link_table(irq)
        program.mark('f5')
        program.emit(*_lui_addi_load(10, layout['flag']))
        program.emit(_sw(0, 10, 0))
        if both is not None:
            # The second cell set is zero for every single-link body, so the
            # handler skips it; a both body publishes it below.
            program.emit(_sw(0, 8, HB_STATUS2), _sw(0, 8, HB_RESULT2),
                         _sw(0, 8, HB_CLEAR2), _sw(0, 8, HB_CLEAR_VALUE2),
                         _sw(0, 8, HB_MASK1), _sw(0, 8, HB_MASK2),
                         _sw(0, 8, HB_NEED), _sw(0, 8, HB_SERVICED))

        # The link's own target window.  A one-target declaration keeps
        # ``layout['irq_base']`` (the old firmware image is unchanged); a global
        # link table from a multi-declaring scenario states each link's base, so
        # a selected link addresses the target that really declared it.
        def link_base(link):
            base = link.get('base')
            return layout['irq_base'] if base is None else base

        def publish_clear(link, clear_cell, value_cell):
            # The declared ack protocol is an ordered sequence: the first step is
            # the acknowledge every case line names, and a second declared step
            # is published into the extra pair the extended ISR reads.  A link
            # with one step (or none) leaves the extra cells zero, so the ISR
            # performs exactly the writes this link declared.
            sequence = list(link.get('clears') or ())
            if not sequence and link['clear'] is not None:
                sequence = [link['clear']]
            if sequence:
                program.emit(*_lui_addi_load(9, link_base(link) + sequence[0]['offset']))
                program.emit(_sw(9, 8, clear_cell))
                program.emit(*_lui_addi_load(9, sequence[0]['value']))
                program.emit(_sw(9, 8, value_cell))
            else:
                program.emit(_sw(0, 8, clear_cell), _sw(0, 8, value_cell))
            if multi_clear:
                if len(sequence) > 1:
                    program.emit(*_lui_addi_load(9, link_base(link)
                                                 + sequence[1]['offset']))
                    program.emit(_sw(9, 8, HB_CLEAR_B))
                    program.emit(*_lui_addi_load(9, sequence[1]['value']))
                    program.emit(_sw(9, 8, HB_CLEAR_VALUE_B))
                else:
                    program.emit(_sw(0, 8, HB_CLEAR_B),
                                 _sw(0, 8, HB_CLEAR_VALUE_B))

        def wait_for(cell, expected, index=None, pointer=False, cleanup=()):
            """The bounded wait: the flag word zero (single) or a mask (both).

            A trigger value that never raises the declared IRQ must not park the
            CPU in the wait loop and kill the whole batch.  The counter sits in
            x11 (untouched by the handler's x12..x16); when it expires the
            timeout marker 2 is written into the flag word, so the host reports a
            timed-out case and the CPU returns to polling.

            ``pointer`` states what the cell is: the historical single-link body
            publishes the *address* of the flag word in HB_FLAG (x10), so the
            loop loads through x10; a both body publishes the serviced mask as a
            value in HB_SERVICED, so the loop loads that cell directly.
            """
            suffix = '' if index is None else str(index)
            program.emit(_addi(11, 0, -wait_iterations))
            program.mark('f5_wait' + suffix)
            program.emit(_lw(9, 10, 0) if pointer else _lw(9, 8, cell))
            if expected is None:
                program.branch(9, 0, 'f5_done' + suffix, funct3=1)
            else:
                program.emit(_addi(7, 0, expected))
                program.branch(9, 7, 'f5_done' + suffix, funct3=0)
            program.emit(_addi(11, 11, 1))
            program.branch(11, 0, 'f5_wait' + suffix, funct3=1)
            program.emit(_addi(9, 0, 2), _sw(9, 10, 0))
            program.mark('f5_done' + suffix)
            # A both case withdraws its published second-source cells once the
            # case is complete, so a spurious interrupt in a later F1-F4 case
            # cannot perform an undeclared second read or clear at a stale
            # address.  A single-link body has nothing to withdraw.
            for cleanup_cell in cleanup:
                program.emit(_sw(0, 8, cleanup_cell))
            program.emit(_sw(0, 8, 0))
            program.jump('poll')

        if len(links) == 1:
            link = links[0]
            program.emit(*_lui_addi_load(9, link_base(link) + link['status_offset']))
            program.emit(_sw(9, 8, HB_STATUS))
            program.emit(*_lui_addi_load(9, layout['result_f5']))
            program.emit(_sw(9, 8, HB_RESULT))
            publish_clear(link, HB_CLEAR, HB_CLEAR_VALUE)
            program.emit(*_lui_addi_load(11, link_base(link)))
            for index, offset in enumerate(link['trigger_offsets']):
                program.emit(_lw(9, 8, INPUT_BLOCK + 4 * index))
                program.emit(_sw(9, 11, offset))
            wait_for(HB_FLAG, None, pointer=True)
        else:
            # The link index is the first input word; the trigger values follow.
            program.emit(_lw(12, 8, INPUT_BLOCK))
            for index in range(len(links)):
                program.emit(_addi(13, 0, index))
                program.branch(12, 13, 'f5_link%d' % index, funct3=0)
            program.jump('poll')
            for index, link in enumerate(links):
                program.mark('f5_link%d' % index)
                if link.get('mode') == 'both':
                    # Publish both sources' status/result/clear cells and the two
                    # cause masks.  The handler marks a source serviced when its
                    # read is attributed to that source: a declared cause mask is
                    # tested against the read value, and a source that declares no
                    # cause bit is serviced by its own status read (the delivered
                    # interrupt is its evidence).  The firmware waits for both
                    # bits, so the case cannot finish before both devices have
                    # really asserted.
                    for position, member in enumerate(link['members']):
                        status_cell = HB_STATUS if position == 0 else HB_STATUS2
                        result_cell = HB_RESULT if position == 0 else HB_RESULT2
                        clear_cell = HB_CLEAR if position == 0 else HB_CLEAR2
                        value_cell = (HB_CLEAR_VALUE if position == 0
                                      else HB_CLEAR_VALUE2)
                        mask_cell = HB_MASK1 if position == 0 else HB_MASK2
                        program.emit(*_lui_addi_load(
                            9, link_base(member) + member['status_offset']))
                        program.emit(_sw(9, 8, status_cell))
                        program.emit(*_lui_addi_load(
                            9, layout['result_f5'] if position == 0
                            else layout['result_f5b']))
                        program.emit(_sw(9, 8, result_cell))
                        publish_clear(member, clear_cell, value_cell)
                        program.emit(*_lui_addi_load(
                            9, member['cause_mask'] if member['cause_declared'] else 0))
                        program.emit(_sw(9, 8, mask_cell))
                    expected = (1 << len(link['members'])) - 1
                    program.emit(_addi(9, 0, expected))
                    program.emit(_sw(9, 8, HB_NEED))
                    # Both trigger sequences, in member order, from the input
                    # words that follow the link index.
                    word = 1
                    for member in link['members']:
                        program.emit(*_lui_addi_load(11, link_base(member)))
                        for offset in member['trigger_offsets']:
                            program.emit(_lw(9, 8, INPUT_BLOCK + 4 * word))
                            program.emit(_sw(9, 11, offset))
                            word += 1
                    # The stored result2 cell is kept: it is the evidence the
                    # host reads at case end.  Only the address/mask/expected
                    # cells are withdrawn.
                    wait_for(HB_SERVICED, expected, index,
                             cleanup=(HB_STATUS2, HB_CLEAR2,
                                      HB_MASK1, HB_MASK2, HB_NEED, HB_SERVICED))
                    continue
                program.emit(*_lui_addi_load(9, link_base(link) + link['status_offset']))
                program.emit(_sw(9, 8, HB_STATUS))
                program.emit(*_lui_addi_load(9, layout['result_f5']))
                program.emit(_sw(9, 8, HB_RESULT))
                publish_clear(link, HB_CLEAR, HB_CLEAR_VALUE)
                program.emit(*_lui_addi_load(11, link_base(link)))
                for position, offset in enumerate(link['trigger_offsets']):
                    program.emit(_lw(9, 8, INPUT_BLOCK + 4 * (1 + position)))
                    program.emit(_sw(9, 11, offset))
                wait_for(HB_FLAG, None, index, pointer=True)

    # F6: publish the DMA handler parameters, copy the input block into the DMA
    # source window, then configure and start the transfer.  A build without a
    # DMA model emits no F6 body at all: the flow is refused by name, so there is
    # no command branch and nothing to execute.
    if dma is not None:
        program.mark('f6')
        program.emit(*_lui_addi_load(10, layout['flag']))
        program.emit(_sw(0, 10, 0))
        program.emit(*_lui_addi_load(9, layout['dma_base'] + dma['control_offset']))
        program.emit(_sw(9, 8, HB_STATUS))
        program.emit(*_lui_addi_load(9, layout['result_f6']))
        program.emit(_sw(9, 8, HB_RESULT))
        if dma['clear'] is not None:
            program.emit(*_lui_addi_load(9, layout['dma_base'] + dma['clear']['offset']))
            program.emit(_sw(9, 8, HB_CLEAR))
            program.emit(*_lui_addi_load(9, dma['clear']['value']))
            program.emit(_sw(9, 8, HB_CLEAR_VALUE))
        else:
            program.emit(_sw(0, 8, HB_CLEAR), _sw(0, 8, HB_CLEAR_VALUE))
        if multi_clear:
            # A multi-step clear build withdraws the second step's cells in the
            # F6 body, so a stale F5 case can never add a clear write to the DMA
            # completion handler.
            program.emit(_sw(0, 8, HB_CLEAR_B), _sw(0, 8, HB_CLEAR_VALUE_B))
        if both is not None:
            # This body publishes the DMA completion source only: the second
            # cell set is cleared so a stale both case can never make an F6
            # interrupt read a second target word.
            program.emit(_sw(0, 8, HB_STATUS2), _sw(0, 8, HB_RESULT2),
                         _sw(0, 8, HB_CLEAR2), _sw(0, 8, HB_CLEAR_VALUE2),
                         _sw(0, 8, HB_MASK1), _sw(0, 8, HB_MASK2),
                         _sw(0, 8, HB_NEED), _sw(0, 8, HB_SERVICED))
        route = dma.get('route')
        read_route = route is not None and route.get('direction') == 'read'
        if not read_route:
            # The historical block copy into the DMA source window: a RAM-to-RAM
            # transfer reads it, and a write route ignores it.  A read route has
            # no RAM source at all (the routed register is the source), so the
            # record's payload words are not written anywhere.
            program.emit(*_lui_addi_load(11, layout['dma_source']))
            for index in range(dma['block_words']):
                program.emit(_lw(9, 8, INPUT_BLOCK + 4 * index), _sw(9, 11, 4 * index))
        if route is not None:
            # The "before" sample the evidence criterion needs: a real MMIO read
            # of the declared evidence word, stored in a RAM cell the host reads at
            # case end.  It runs before the DMA is configured, so the transfer can
            # neither be affected by it nor be mistaken for it.
            program.emit(*_lui_addi_load(12, route['target_window']['base']
                                         + route['evidence']['offset']))
            program.emit(_lw(9, 12, 0))
            program.emit(*_lui_addi_load(13, layout['route_before']))
            program.emit(_sw(9, 13, 0))
        program.emit(*_lui_addi_load(11, layout['dma_base']))
        # A read route programs the source register with the route target's own
        # address and the destination with the RAM block; a write route does the
        # opposite, and a RAM-to-RAM transfer keeps both RAM windows.
        source = (route['address'] if read_route else layout['dma_source'])
        program.emit(*_lui_addi_load(9, source))
        program.emit(_sw(9, 11, dma['source_offset']))
        destination = (layout['dma_destination'] if route is None or read_route
                       else route['address'])
        program.emit(*_lui_addi_load(9, destination))
        program.emit(_sw(9, 11, dma['destination_offset']))
        program.emit(*_lui_addi_load(9, dma['length_value']))
        program.emit(_sw(9, 11, dma['length_offset']))
        # Read the declared control word once before the start write: this is the
        # "before" sample of the busy/error bits the completion criterion uses.
        # The handler's status read after the transfer is the "after" sample.
        # Register 10 still holds the handler flag the wait loop polls, so the
        # cell address goes to register 12.
        program.emit(_lw(9, 11, dma['control_offset']))
        program.emit(*_lui_addi_load(12, layout['ctl_before']))
        program.emit(_sw(9, 12, 0))
        program.emit(*_lui_addi_load(9, dma['start_word']))
        program.emit(_sw(9, 11, dma['control_offset']))
        # The same bounded wait for the DMA completion flag: a transfer that
        # never completes leaves the host a timed-out case, not a lost batch.
        program.emit(_addi(11, 0, -wait_iterations))
        program.mark('f6_wait')
        program.emit(_lw(9, 10, 0))
        program.branch(9, 0, 'f6_done', funct3=1)
        program.emit(_addi(11, 11, 1))
        program.branch(11, 0, 'f6_wait', funct3=1)
        program.emit(_addi(9, 0, 2), _sw(9, 10, 0))     # timeout marker
        program.mark('f6_done')
        if route is not None:
            # The "after" sample, read only after the DMA completion interrupt's
            # handler has run (the flag above), so it brackets every routed beat
            # the transfer made.  A timed-out case leaves the timeout marker in
            # the flag and the host reports the evidence as not written.
            program.emit(*_lui_addi_load(12, route['target_window']['base']
                                         + route['evidence']['offset']))
            program.emit(_lw(9, 12, 0))
            program.emit(*_lui_addi_load(13, layout['route_after']))
            program.emit(_sw(9, 13, 0))
        if read_route:
            # The CPU's own read of the RAM destination block: one word per
            # declared destination word, stored in the readback cells.  The host
            # reads those cells back, so "the DMA wrote the captured word into
            # RAM" is witnessed by the CPU's load and not only by the host's own
            # memory sample.
            program.emit(*_lui_addi_load(12, layout['dma_destination']))
            program.emit(*_lui_addi_load(13, layout['route_dst']))
            for index in range(dma['block_words']):
                program.emit(_lw(9, 12, 4 * index))
                program.emit(_sw(9, 13, 4 * index))
            if route.get('aperture'):
                # An aperture read: the CPU reads every declared aperture word
                # itself, after the transfer, and stores it beside the captured
                # words.  A read of these registers does not change them, so the
                # CPU's own read is an independent witness of the word the DMA
                # master captured from the same address.
                program.emit(*_lui_addi_load(12, route['target_window']['base']
                                             + route['evidence']['offset']))
                program.emit(*_lui_addi_load(13, layout['route_aper']))
                for index in range(dma['block_words']):
                    program.emit(_lw(9, 12, 4 * index))
                    program.emit(_sw(9, 13, 4 * index))
        program.emit(_sw(0, 8, 0))
        program.jump('poll')
    code = program.link()

    handler = Program(layout['handler'])
    handler.emit(_lw(12, 8, HB_STATUS))          # address of the declared status word
    handler.emit(_lw(13, 12, 0))                 # real MMIO read of that word
    handler.emit(_lw(14, 8, HB_RESULT))          # RAM cell that keeps the read value
    handler.emit(_sw(13, 14, 0))
    if both is None:
        # The historical single-source ISR, byte for byte: one declared clear,
        # written whenever the case declared one, then the flag and MRET.  A
        # build whose declaration carries a second clear step adds exactly one
        # more gated store, so its image is not the historical one but every
        # single-step build's image still is.
        handler.emit(_lw(12, 8, HB_CLEAR))       # zero means "no clear declared"
        handler.branch(12, 0, 'ack')
        handler.emit(_lw(15, 8, HB_CLEAR_VALUE))
        handler.emit(_sw(15, 12, 0))             # real MMIO clear write
        if multi_clear:
            # The declared second step (e.g. releasing a held acknowledge bit):
            # its own published address gates it, so a link that declared one
            # step performs exactly one write.
            handler.emit(_lw(12, 8, HB_CLEAR_B))
            handler.branch(12, 0, 'ack')
            handler.emit(_lw(15, 8, HB_CLEAR_VALUE_B))
            handler.emit(_sw(15, 12, 0))         # real MMIO clear write, step 2
    else:
        # The first declared clear write.  A both-source member publishes its
        # declared cause mask and is cleared only when that cause is in the word
        # just read: the ISR can run before that source asserted, and a clear
        # then would be a write this case cannot attribute.
        handler.emit(_lw(12, 8, HB_CLEAR))       # zero means "no clear declared"
        handler.branch(12, 0, 'c1_done')
        handler.emit(_lw(15, 8, HB_MASK1))
        handler.branch(15, 0, 'c1_write')
        handler.emit(_and(15, 13, 15))
        handler.branch(15, 0, 'c1_done')
        handler.mark('c1_write')
        handler.emit(_lw(15, 8, HB_CLEAR_VALUE))
        handler.emit(_sw(15, 12, 0))             # real MMIO clear write
        handler.mark('c1_done')
        # The second declared source.  status2 = 0 means the current case
        # published only one source, so the second read is skipped.
        handler.emit(_lw(12, 8, HB_STATUS2))
        handler.branch(12, 0, 'ack')
        handler.emit(_lw(16, 8, HB_SERVICED))    # mask carried across entries
        handler.emit(_lw(13, 12, 0))             # real MMIO read of status 2
        handler.emit(_lw(14, 8, HB_RESULT2))     # second result cell
        handler.emit(_sw(13, 14, 0))
        # A source is serviced when its own status read carries its declared
        # cause; a source that declares no cause bit is serviced by its own read
        # (the delivered interrupt is the evidence that it asserted).
        handler.emit(_lw(15, 8, HB_MASK1))
        handler.branch(15, 0, 's1_mark')
        handler.emit(_and(15, 13, 15))
        handler.branch(15, 0, 's1_done')
        handler.mark('s1_mark')
        handler.emit(_ori(16, 16, 1))
        handler.mark('s1_done')
        # The second declared clear write, gated on its own cause.
        handler.emit(_lw(12, 8, HB_CLEAR2))
        handler.branch(12, 0, 'c2_done')
        handler.emit(_lw(15, 8, HB_MASK2))
        handler.branch(15, 0, 'c2_write')
        handler.emit(_and(15, 13, 15))
        handler.branch(15, 0, 'c2_done')
        handler.mark('c2_write')
        handler.emit(_lw(15, 8, HB_CLEAR_VALUE2))
        handler.emit(_sw(15, 12, 0))
        handler.mark('c2_done')
        handler.emit(_lw(15, 8, HB_MASK2))
        handler.branch(15, 0, 's2_mark')
        handler.emit(_and(15, 13, 15))
        handler.branch(15, 0, 's2_done')
        handler.mark('s2_mark')
        handler.emit(_ori(16, 16, 2))
        handler.mark('s2_done')
        handler.emit(_sw(16, 8, HB_SERVICED))
    handler.mark('ack')
    handler.emit(_lw(14, 8, HB_FLAG))
    handler.emit(_addi(15, 0, 1))
    handler.emit(_sw(15, 14, 0))
    if irq_take_clear:
        # The packed AXI4 take witness: the core's own mcause readback.  Clearing
        # it here makes each take a clean transition, so the next case's take is
        # observed as its own entry instead of inheriting this one's cause.
        handler.emit(_csr(0x342, 0, 1, 0))       # CSRRW x0, mcause, x0
    handler.emit(MRET_WORD)
    handler_code = handler.link()

    # The declared M-mode trap handler: a real exception handler that reads the
    # CSR state with CSRRS, stores the two values the host compares, advances
    # mepc past the faulting word and returns.  It is part of the image: no case
    # writes it, and the slot program cannot install or replace it.  It also
    # clears mcause after storing it, so the scoreboard's readback shows a clean
    # 0 -> cause transition for *each* trap case instead of carrying the previous
    # case's cause (the CSR is not reset between cases; the CPU is not either).
    trap_code = b''
    if f1_trap is not None:
        trap = Program(layout['trap_handler'])
        trap.emit(_csr(0x342, 0, 2, 10))            # CSRRS x10, mcause, x0
        trap.emit(_csr(0x341, 0, 2, 11))            # CSRRS x11, mepc,   x0
        trap.emit(*_lui_addi_load(9, layout['trap_cause']))
        trap.emit(_sw(10, 9, 0))                    # store the cause it read
        trap.emit(*_lui_addi_load(9, layout['trap_epc']))
        trap.emit(_sw(11, 9, 0))                    # store the PC it read
        trap.emit(_csr(0x342, 0, 1, 0))             # CSRRW x0, mcause, x0: clear it
        trap.emit(_addi(11, 11, 4))                 # resume past the ECALL
        trap.emit(_csr(0x341, 11, 2, 0))            # CSRRS x0, mepc, x11
        trap.emit(*_lui_addi_load(9, layout['trap_flag']))
        trap.emit(_addi(10, 0, 1))
        trap.emit(_sw(10, 9, 0))                    # the handler ran (once)
        trap.emit(MRET_WORD)
        trap_code = trap.link()

    # The trampoline slot reserves the declared program length plus the fixed
    # return jump.  The host overwrites the first words and writes its own jump
    # right after the program it hands over, so the image's own jump at the last
    # reserved word is only a fallback for a full-length program.
    slot = (b'\x13\x00\x00\x00' * f1_words
            + _jal(layout['slot'] + 4 * f1_words,
                   program.labels['f1_back']).to_bytes(4, 'little'))
    # In vectored mode an *exception* enters at the vector base itself, so that
    # entry is the exception handler; the interrupt slots keep their own target.
    exception_target = (layout['handler'] if f1_trap is None
                        else layout['trap_handler'])
    vector_words = ([_jal(layout['vector'], exception_target)]
                    + [0x00000013] * 10           # machine-external slot is vector + 11*4
                    + [_jal(layout['vector'] + 44, layout['handler'])])
    boot = Program(layout['boot'])
    if interrupt_bootstrap:
        boot.emit(*_lui_addi_load(8, layout['mailbox']))       # mailbox pointer before any IRQ
        boot.emit(*_lui_addi_load(3, layout['vector'] | 1))    # declared vector, vectored mode
        boot.emit(_csr(0x305, 3))
        boot.emit(*_lui_addi_load(3, 0x800))                   # mie.MEIE
        boot.emit(_csr(0x304, 3, 2))
        boot.emit(_addi(3, 0, 8))                              # mstatus.MIE
        boot.emit(_csr(0x300, 3, 2))
    boot.emit(_jal(boot.address, layout['main']))
    boot_code = boot.link()

    handler_block = bytearray(HANDLER_BLOCK_BYTES)
    flag_cell = HB_FLAG - HB
    handler_block[flag_cell:flag_cell + 4] = layout['flag'].to_bytes(4, 'little')
    data = b''.join(word.to_bytes(4, 'little') for word in DATA_WORDS)
    images = {layout['boot']: boot_code, layout['vector']: b''.join(
                  word.to_bytes(4, 'little') for word in vector_words),
              layout['handler']: handler_code, layout['main']: code,
              layout['slot']: slot, layout['data_base']: data,
              layout['handler_block']: bytes(handler_block)}
    if f1_trap is not None:
        images[layout['trap_handler']] = trap_code
        images[layout['trap_cause']] = bytes(layout['trap_block_bytes'])
    custom_segments = {}
    if custom_irq is not None:
        from scripts.inprocess_wishbone_irq import custom_irq_segments
        custom_segments = custom_irq_segments(
            layout, irq_bit=custom_irq['irq_bit'], vector=custom_irq['handler_address'],
            status=HB_STATUS, result=HB_RESULT, clear=HB_CLEAR,
            clear_value=HB_CLEAR_VALUE, flag=HB_FLAG)
        del images[layout['vector']]
        images.update(custom_segments)
        handler_code = custom_segments[layout['handler']]
    irq_spans = ({'boot': (layout['boot'], len(boot_code)),
                  'vector': (layout['vector'], len(vector_words) * 4),
                  'handler': (layout['handler'], len(handler_code))} if custom_irq is None else
                 {'custom_' + str(address): (address, len(data))
                  for address, data in custom_segments.items()} |
                 {'custom_scratch': (layout['result'] + 16, 16)})
    # The declared DMA block decides how much of the mailbox and of the two DMA
    # RAM windows this image reserves.  The handler block sits HB into the
    # mailbox, so an input block that reaches it is refused by name instead of
    # overlapping the cells the ISR reads.
    dma_block = 0 if dma is None else dma['block_words']
    if dma_block:
        if INPUT_BLOCK + 4 * dma_block > MAILBOX_BYTES:
            raise ValueError('the declared DMA block does not fit the mailbox span: %d words'
                             % dma_block)
        if layout['mailbox'] + MAILBOX_BYTES > layout['handler_block']:
            raise ValueError('the mailbox span reaches the handler block')
    dma_span = 4 * (dma_block + 1)
    # A routed F6 body also writes the two evidence cells at result+16/+20, and a
    # read route's CPU destination readback adds one cell per destination word
    # from +24.  A both-source F5 image writes its second result cell at +28, so
    # the two shapes cannot share one result block; that combination is refused
    # by name instead of overlapping the cells.
    both = None if irq is None else irq.get('both')
    if (both is not None and dma is not None and dma.get('route') is not None
            and dma['route'].get('direction') == 'read'):
        raise ValueError('unsupported-f5:both-result-cell-conflicts-with-dma-read-route')
    result_span = _dma_result_span(dma)
    if both is not None:
        result_span = max(result_span, 32)
    trap_spans = ({} if f1_trap is None else
                  {'trap_handler': (layout['trap_handler'], len(trap_code)),
                   'trap_cells': (layout['trap_cause'], layout['trap_block_bytes'])})
    _check_spans(layout, {**irq_spans, **trap_spans,
                          'main': (layout['main'], len(code)),
                          'slot': (layout['slot'], len(slot)),
                          'mailbox': (layout['mailbox'], MAILBOX_BYTES),
                          'handler_block': (layout['handler_block'], HANDLER_BLOCK_BYTES),
                          'data': (layout['data_base'], len(data)),
                          'result': (layout['result'], result_span),
                          'dma_source': (layout['dma_source'], max(16, dma_span)),
                          'dma_destination': (layout['dma_destination'], max(16, dma_span))})
    if layout['handler_block'] != layout['mailbox'] + HB_STATUS:
        raise ValueError('the handler block must sit HB_STATUS into the mailbox')
    # The finalized layout carries the real trampoline return label, so a header
    # rendered from it states the address the image actually jumps to.
    layout = dict(layout, slot_return=program.labels['f1_back'])
    return dict(images=images, layout=layout, slot_return=program.labels['f1_back'],
                f1_words=f1_words, main_words=len(program.words),
                handler_words=len(handler.words),
                trap_words=(0 if f1_trap is None else len(trap_code) // 4))


def firmware_text(firmware):
    return ''.join(f'{address:x} {data.hex()}\n'
                   for address, data in sorted(firmware['images'].items()))


# ---------------------------------------------------------------------------
# Generated binding header
# ---------------------------------------------------------------------------
#: How many grid steps one declared half-period ratio may divide.  One grid
#: step is the reference CPU's half period, so a model declared at 1/1024 of the
#: CPU's rate toggles once every 1024 host phases; a larger ratio is refused
#: instead of letting one case run for an unreasonable number of phases.
MAX_PHASE_RATIO = 1024
CLOCK_PHASE_POLICY = 'all_low_then_half_period_toggle'


def model_clock_rate(artifact, role):
    """The one simple declared clock rate of a generated model, or a refusal.

    The phase scheduler below drives one clock port per model: the generated
    artifact states a single ``clk`` signal at its own fastest declared domain
    with the low-first, half-period-toggle policy.  A model whose schedule
    states anything else (several host-driven clock ports, a ratio other than
    one, a first rising edge that is not one fast tick) is refused by name here
    instead of being half-driven.
    """
    schedule = artifact.get('clock_schedule', {})
    clocks = schedule.get('clocks', [])
    if (len(clocks) != 1 or schedule.get('phase_policy') != CLOCK_PHASE_POLICY
            or clocks[0].get('signal') != 'clk' or clocks[0].get('ratio') != 1
            or clocks[0].get('first_rising_fast_tick') != 1
            or clocks[0].get('half_period_fast_ticks') != 1
            or type(clocks[0].get('frequency_hz')) is not int
            or clocks[0]['frequency_hz'] <= 0):
        raise ValueError('unsupported: ' + role + ' requires one simple clock '
                         '(one clk signal, phase_policy ' + CLOCK_PHASE_POLICY +
                         ', ratio 1, first rising at one fast tick)')
    return clocks[0]['frequency_hz']


def declared_half_period_ps(frequency_hz):
    """The declared half period in whole picoseconds, or None when it is not."""
    if type(frequency_hz) is not int or frequency_hz <= 0:
        raise ValueError('unsupported: a declared clock rate must be a positive integer')
    if 10 ** 12 % (2 * frequency_hz):
        return None
    return 10 ** 12 // (2 * frequency_hz)


def _exact_ratio(numerator, denominator):
    """One declared half period as an exact fraction of the CPU's half period."""
    divisor = math.gcd(numerator, denominator)
    return dict(numerator=numerator // divisor, denominator=denominator // divisor)


def common_grid_hz(rates):
    """The one rate whose half period divides every declared half period.

    ``lcm`` of the declared rates: one grid step is ``1 / (2 * lcm)`` seconds, so
    every declared half period is a whole number of grid steps and no declared
    frequency is ever rounded.
    """
    grid = rates[0]
    for rate in rates[1:]:
        grid = grid * rate // math.gcd(grid, rate)
    return grid


def phase_clock_plan(rows, assume_single_clock=False):
    """Normalize the declared per-model clocks into one exact rational phase plan.

    ``rows`` is the ordered model list - ``cpu`` first, then every declared
    target, then the optional DMA - and each row states ``role``, ``name``,
    ``frequency_hz`` and, for a model built with Verilator ``--timing``, its own
    ``timed_half_period_ps``.  The returned plan states every model's half
    period as an integer number of *grid steps*.

    One grid step is the greatest common half period of the declarations: with
    ``L`` the least common multiple of the declared rates it is ``1 / (2L)``
    seconds, so a model declared at ``f`` Hz has a half period of exactly
    ``L / f`` grid steps and the reference CPU's half period is
    ``C = L / cpu_hz`` grid steps.  Every admitted ratio is therefore exact,
    integer or not: 50 MHz beside 25 MHz is ``C = 1`` and ``R = 2`` (the
    historical whole-divisor numbers, unchanged), 50 MHz beside 30 MHz is
    ``C = 3`` and ``R = 5`` (a 50:30 rational ratio that has no whole divider),
    and 50 MHz beside 75 MHz is ``C = 3`` and ``R = 2`` - a model declared
    *faster* than the CPU.  The host advances one host tick per reference CPU
    cycle, i.e. ``2C`` grid steps, so a model whose ``R`` is below ``C`` takes
    several of its own edges inside one host tick: that is the sub-stepping a
    faster model needs, and it is the same ``level (step // R) % 2`` schedule
    rather than a second mechanism.  All clocks start low and a model's first
    rising edge is exactly at its own half period (``first_rising_fast_tick``
    stays 1 in that model's own schedule).

    A timed model's own contract is checked against the same grid: the grid step
    has to be a whole number of picoseconds (that is the time the shared
    simulation context advances per step) and the model's half period has to be
    exactly its own number of grid steps, or the plan is refused with both
    numbers.

    A declared rate pair whose exact grid does not fit ``MAX_PHASE_RATIO`` -
    either side - has no usable common grid in this host, which clocks every
    model from one synchronous grid and has no phase-independent sampler.  Such
    a pair (two independent oscillators, or a rate far above or below the CPU's)
    is refused by name with the exact grid and both step counts instead of being
    rounded, truncated, or driven from an invented phase relation.

    ``assume_single_clock`` keeps the historical fallback: every model is
    toggled together on one host tick and the plan says the equal-period
    assumption explicitly.  Timed models still have to agree on one half period
    in that mode, because one shared simulation-time advance cannot satisfy two.
    """
    if not rows or rows[0].get('role') != 'cpu':
        raise ValueError('unsupported: the phase clock plan needs the CPU first')
    cpu = rows[0]
    cpu_hz = cpu.get('frequency_hz')
    if type(cpu_hz) is not int or cpu_hz <= 0:
        raise ValueError('unsupported: the reference CPU declares no positive clock rate')
    for row in rows:
        if type(row.get('frequency_hz')) is not int or row['frequency_hz'] <= 0:
            raise ValueError('unsupported: clock rate of ' + str(row.get('name')) +
                             ' is not a positive integer')
        half = row.get('timed_half_period_ps')
        if half is not None and (type(half) is not int or half < 1):
            raise ValueError('unsupported: timed model contract:' + str(row.get('name')))
    rates = [row['frequency_hz'] for row in rows]
    equal = len(set(rates)) == 1
    timed = [row for row in rows if row.get('timed_half_period_ps') is not None]

    def plan_row(row, half_ticks, cpu_half_ticks):
        return dict(role=row['role'], name=row['name'],
                    frequency_hz=row['frequency_hz'],
                    half_period_ticks=half_ticks,
                    # The same number as a reduced exact fraction of the reference
                    # CPU's half period, so a reader states ``R = 5/3`` instead of
                    # a rounded 1.667: one CPU half period is ``cpu_half_ticks``.
                    half_period_of_cpu_half=_exact_ratio(half_ticks, cpu_half_ticks),
                    timed=row.get('timed_half_period_ps') is not None,
                    timed_half_period_ps=row.get('timed_half_period_ps'),
                    phase_policy=CLOCK_PHASE_POLICY,
                    first_rising_grid_step=half_ticks)

    if equal or assume_single_clock:
        # One host tick toggles every clock: the historical fallback and the
        # equal-rate case.  A timed model states the half period the shared
        # simulation context advances; two different ones cannot both be right.
        timed_half = None
        for row in timed:
            half = row['timed_half_period_ps']
            if timed_half is not None and half != timed_half:
                raise ValueError('unsupported: timed models declare different half periods '
                                 '(' + str(timed_half) + ' ps vs ' + str(half) + ' ps at ' +
                                 row['name'] + ')')
            timed_half = half
        return dict(
            mode='equal_rates' if equal else 'assumed_single_clock',
            assumed=(not equal) and bool(assume_single_clock),
            reference=dict(role='cpu', name=cpu['name'], frequency_hz=cpu_hz),
            # The physical half period of the reference clock, stated even for an
            # untimed build: it is the length of one logical grid step, while
            # grid_ps is the simulation time the shared timed context advances.
            reference_half_period_ps=declared_half_period_ps(cpu_hz),
            grid_ps=timed_half,
            # One tick toggles every model, so one grid step is one CPU half
            # period and the grid's own sub-frequency is the reference rate.
            grid_lcm_hz=cpu_hz,
            grid_steps_per_cpu_half=1,
            grid_steps_per_tick=2,
            timed=bool(timed),
            contract=('one host tick toggles every declared model; each model states one '
                      'low-first clk with ratio 1, so every first rising edge is one tick '
                      'after the schedule origin' if equal else
                      'one host tick toggles every declared model even though the declared '
                      'rates differ; the equal-period assumption is stated, not derived'),
            rows=[plan_row(row, 1, 1) for row in rows])

    # The exact common grid of the declarations: one grid step is 1 / (2 * L)
    # seconds, so every declared half period - integer ratio or not, slower than
    # the CPU or faster - is a whole number of steps.  Nothing below rounds a
    # declared frequency; a pair whose exact grid is finer or coarser than the
    # phase-grid bound is refused by name instead.
    grid_hz = common_grid_hz(rates)
    cpu_half_ticks = grid_hz // cpu_hz
    planned = {'cpu': cpu_half_ticks}
    worst = None
    for row in rows[1:]:
        steps = grid_hz // row['frequency_hz']
        planned[row['role']] = steps
        if worst is None or steps > planned[worst['role']]:
            worst = row
    if cpu_half_ticks > MAX_PHASE_RATIO or planned[worst['role']] > MAX_PHASE_RATIO:
        # No usable common grid: the pair is exact in principle and unusable in
        # practice, which is the asynchronous case.  This host drives every model
        # from one synchronous grid and its generated models expose only
        # clock/reset/eval (no per-model asynchronous event queue), so there is
        # no phase-independent sampler to fall back on: the session is refused
        # by name with the exact grid rather than rounded to one that is not the
        # declared one.
        raise ValueError('unsupported: declared clock rates differ (' +
                         ','.join(str(rate) for rate in rates) + '); no common phase grid '
                         'fits the ' + str(MAX_PHASE_RATIO) + '-step phase-grid bound: the '
                         'exact grid is ' + str(grid_hz) + ' Hz, so the reference CPU half '
                         'period is ' + str(cpu_half_ticks) + ' grid steps and ' +
                         str(worst['name']) + ' half period is ' +
                         str(planned[worst['role']]) + ' grid steps; this host clocks every '
                         'model from one synchronous grid and implements no '
                         'phase-independent sampler, so an asynchronous pair is refused '
                         'by name instead of being rounded or truncated')
    grid_ps = None
    if timed:
        # The shared timed context advances one grid step of simulation time per
        # step, so the grid step itself has to be a whole number of picoseconds
        # and every timed model's contract has to be exactly its own number of
        # grid steps.  A rational ratio whose grid step is a fraction of a
        # picosecond is refused here instead of being rounded.
        if 10 ** 12 % (2 * grid_hz):
            raise ValueError('unsupported: timed phase grid: the common grid step of the '
                             'declared rates (' + ','.join(str(rate) for rate in rates) +
                             ' Hz) is 1 / (2 x ' + str(grid_hz) + ') s, which is not a '
                             'whole number of picoseconds, so the shared timed context '
                             'cannot advance to it exactly')
        grid_ps = 10 ** 12 // (2 * grid_hz)
        for row in timed:
            expected = planned[row['role']] * grid_ps
            if row['timed_half_period_ps'] != expected:
                raise ValueError('unsupported: timed contract disagrees with the declared '
                                 'clock ratio: ' + row['name'] + ' declares ' +
                                 str(row['timed_half_period_ps']) + ' ps but ' +
                                 str(planned[row['role']]) + ' x ' + str(grid_ps) +
                                 ' ps = ' + str(expected) + ' ps')
    return dict(
        mode='per_model_ratio',
        assumed=False,
        reference=dict(role='cpu', name=cpu['name'], frequency_hz=cpu_hz),
        reference_half_period_ps=declared_half_period_ps(cpu_hz),
        grid_ps=grid_ps,
        # The exact declarations of the grid, so the saved plan and the run
        # summary state what the ratio really was instead of asserting it.
        grid_lcm_hz=grid_hz,
        grid_steps_per_cpu_half=cpu_half_ticks,
        grid_steps_per_tick=2 * cpu_half_ticks,
        timed=bool(timed),
        contract=('one grid step is 1 / (2 x ' + str(grid_hz) + ') s, the greatest common '
                  'half period of the declared models; model M whose half period is R grid '
                  'steps keeps its declared low-first phase and toggles at level '
                  '(step // R) % 2, so its first rising edge is at step R; the reference '
                  'CPU half period is ' + str(cpu_half_ticks) + ' grid steps and one host '
                  'tick advances ' + str(2 * cpu_half_ticks) + ' grid steps (exactly one '
                  'CPU cycle), so a model declared faster than the CPU still takes its '
                  'own edges inside one host tick'),
        rows=[plan_row(row, planned[row['role']], cpu_half_ticks) for row in rows])


def clock_plan_header(plan):
    """The generated-macro half of one phase clock plan, as header lines."""
    roles = plan['rows']
    target_rows = [row for row in roles if row['role'].startswith('target')]
    dma_rows = [row for row in roles if row['role'] == 'dma']
    lines = [
        f'#define CLOCK_PLAN_MODE "{plan["mode"]}"',
        f'#define CLOCK_ASSUMED_SINGLE {int(bool(plan["assumed"]))}',
        f'#define CLOCK_REFERENCE_HZ {plan["reference"]["frequency_hz"]}u',
        f'#define CLOCK_GRID_PERIOD_PS {0 if plan["grid_ps"] is None else plan["grid_ps"]}u',
        ('#define CLOCK_REFERENCE_HALF_PERIOD_PS ' +
         str(plan['reference_half_period_ps']) + 'u'
         if plan.get('reference_half_period_ps') is not None
         else '#define CLOCK_REFERENCE_HALF_PERIOD_PS 0u'),
        # The exact declarations of the grid the half-period macros below are
        # counted in: one grid step is 1 / (2 * CLOCK_GRID_LCM_HZ) seconds, the
        # reference CPU's half period is CLOCK_CPU_HALF_TICKS of them, and one
        # host tick advances CLOCK_GRID_STEPS_PER_TICK of them (= one CPU cycle).
        f'#define CLOCK_GRID_LCM_HZ {plan["grid_lcm_hz"]}u',
        f'#define CLOCK_GRID_STEPS_PER_TICK {plan["grid_steps_per_tick"]}u',
        f'#define CLOCK_CPU_HALF_TICKS {plan["grid_steps_per_cpu_half"]}u',
        ('#define CLOCK_IP_HALF_TICKS ' +
         ', '.join(str(row['half_period_ticks']) + 'u' for row in target_rows)
         if target_rows else '#define CLOCK_IP_HALF_TICKS 1u'),
        ('#define CLOCK_DMA_HALF_TICKS ' +
         (str(dma_rows[0]['half_period_ticks']) if dma_rows else '1') + 'u'),
        f'#define CLOCK_ROW_COUNT {len(roles)}u',
    ]
    return lines


def clock_assumption_text(plan):
    """The one-line statement of the schedule a run really used."""
    rates = '/'.join(str(row['frequency_hz']) for row in plan['rows'])
    if plan['mode'] == 'equal_rates':
        return ('one host tick for every model; declared rates are equal (' + rates +
                ' Hz) and each model keeps its own low-first clk')
    if plan['mode'] == 'assumed_single_clock':
        return ('assume_single_clock: declared rates ' + rates + ' Hz differ and one '
                'host tick toggles every model; the equal-period assumption is declared, '
                'not derived')
    ratios = ', '.join(row['role'] + '=' + str(row['half_period_ticks'])
                       for row in plan['rows'])
    exact = ', '.join(row['role'] + '=' +
                      str(row['half_period_of_cpu_half']['numerator']) + '/' +
                      str(row['half_period_of_cpu_half']['denominator'])
                      for row in plan['rows'])
    half_ps = plan.get('reference_half_period_ps')
    physical = (str(half_ps) + ' ps' if half_ps is not None
                else 'not a whole number of picoseconds')
    return ('per-model phase divider from the exact common grid (' +
            str(plan['grid_lcm_hz']) + ' Hz, one grid step = 1 / (2 x ' +
            str(plan['grid_lcm_hz']) + ') s); the reference CPU (' +
            str(plan['reference']['frequency_hz']) + ' Hz, half period ' + physical +
            ') is ' + str(plan['grid_steps_per_cpu_half']) + ' grid steps and one host '
            'tick advances ' + str(plan['grid_steps_per_tick']) + ' grid steps; half '
            'periods in grid steps: ' + ratios + '; as exact fractions of the CPU half '
            'period: ' + exact + '; one grid step is ' +
            (str(plan['grid_ps']) + ' ps of shared simulation time'
             if plan['grid_ps'] is not None
             else 'a logical grid step (untimed: no simulation time advanced)'))


def clock_plan_for_artifacts(cpu, targets, dma_model=None, *, assume_single_clock=False):
    """The normalized phase plan of one already-built model set.

    ``cpu``/``dma_model`` are runtime documents and ``targets`` is the ordered
    target descriptor list (each row states ``name`` and ``artifact``); the rate
    of every model is read from that artifact's own clock schedule.  This is the
    one place the plan is derived, so the header, the saved plan and the run
    summary cannot disagree.
    """
    def timed_half(document):
        contract = document.get('driver_timing')
        return (contract.get('half_period_ps')
                if isinstance(contract, dict) else None)

    rows = [dict(role='cpu', name='cpu', frequency_hz=model_clock_rate(cpu, 'cpu'),
                 timed_half_period_ps=timed_half(cpu))]
    for row in targets or ():
        artifact = row['artifact']
        role = 'target:' + str(row['name'])
        rows.append(dict(role=role, name=row['name'],
                         frequency_hz=model_clock_rate(artifact, role),
                         timed_half_period_ps=timed_half(artifact)))
    if dma_model is not None:
        rows.append(dict(role='dma', name='dma',
                         frequency_hz=model_clock_rate(dma_model, 'dma'),
                         timed_half_period_ps=timed_half(dma_model)))
    return phase_clock_plan(rows, assume_single_clock=assume_single_clock)


def faster_model_traffic_refusal(clock_plan, records):
    """The named refusal of bus traffic to a model declared faster than the CPU.

    A model declared faster than the reference CPU is admitted and really
    sub-stepped: one host tick is exactly one reference CPU cycle (``2 * C`` grid
    steps) and a model whose half period is ``R < C`` steps takes several of its
    own rising edges inside it (see :func:`phase_clock_plan`).  Its *protocol*
    traffic is a different contract, and this host cannot serve it:

    * the host reads a model's registered protocol outputs once per host tick:
      ``phase_sample_gates`` gives one ``trace`` sample (pre-edge, low phase) and
      one ``response`` sample (one tick after the edge) per tick, and the whole
      tick is ``2 * C`` grid steps;
    * the APB3 bridge every generated APB3 target instantiates
      (``src/myfuzz/protocols/rtl/apb3_mmio_bridge.sv``) asserts
      ``psel_o = SETUP || ACCESS`` for exactly two of the target's own cycles and
      clears ``rsp_valid_q`` on the target's next edge, because the generated
      ``drive_request`` ties ``rsp_ready_i`` high;
    * so both windows a case must observe are ``2 * R`` grid steps long, which is
      shorter than one tick (``2 * R < 2 * C``) for every faster model: a window
      can fall entirely between two samples, and then the transfer is never
      counted.  That is not a rounding of the declared rate - the clock is exact
      - but a limit of this host's single per-tick sample point.

    A record routed to such a model (F2/F4 by its ``target_index``, F5 by the
    link's target) and an F6 record with a faster DMA model are therefore
    refused by name, with both step counts, instead of being run and timing out.
    The real failing run is kept as evidence in ``runs/p2-timing-20261103``.
    """
    cpu_half = clock_plan.get('grid_steps_per_cpu_half', 1)
    if cpu_half < 2:
        return None

    def too_fast(row):
        return row['half_period_ticks'] < cpu_half

    targets = [row for row in clock_plan['rows'] if row['role'].startswith('target:')]
    faster = {index: row for index, row in enumerate(targets) if too_fast(row)}
    dma_rows = [row for row in clock_plan['rows'] if row['role'] == 'dma']
    faster_dma = [row for row in dma_rows if too_fast(row)]

    def text(row):
        return ('unsupported-target-traffic:' + str(row['name']) +
                ':faster-than-reference-cpu: the host reads a model\'s protocol '
                'outputs once per host tick and this model\'s whole cycle is ' +
                str(2 * row['half_period_ticks']) + ' grid steps of the ' +
                str(2 * cpu_half) + '-step tick (the target asserts psel/penable for '
                'two of its own cycles and the bridge clears rsp_valid on its next '
                'edge because rsp_ready is tied high), so its access window can fall '
                'between two samples; its clock is still sub-stepped and its '
                'rising-edge count is measured, but a case cannot be routed to it')

    for record in records or ():
        index = record.get('target_index')
        if index is not None and index in faster:
            raise ValueError(text(faster[index]))
        if record.get('flow') == 'F6' and faster_dma:
            raise ValueError(text(faster_dma[0]))
    return None


def render_bindings(config, cpu, ip, dma_model, layout, profile, *, irq, dma, dma_irq,
                    pins=None, registers=None, f1_words=1, custom_irq=None,
                    case_tick_budget=4000, targets=None, f5_target_index=None,
                    f5_links=None, f5_both=None, clock_plan=None,
                    pin_groups=None, serial_peer=None):
    """Bind generated model ports from the artifacts; nothing is inferred.

    The target kind selects the adapter: which protocol trace roles must exist and
    which words the run log prints for one completed target transfer.  Both
    protocols drive the target bridge at its beat side, so the rest of the header
    - the CPU channels, the DMA port, the IRQ links, the windows - is the same.

    Two independent axes are rendered from the artifacts themselves: the CPU bus
    (an OBI CPU's i/d channels or a Wishbone CPU's single cyc/stb master) and the
    target's pin endpoint (a register target has none).  A DMA model is optional:
    without one the header states HAVE_DMA 0 and F6 is refused by name.

    ``targets`` is the ordered per-target descriptor list the multi-target entry
    built (each row carries its artifact, protocol, IRQ selection, pins and fixed
    inputs).  When it is omitted the one artifact/graph this legacy signature
    already received is the list of length one, so every existing caller renders
    the same header it always did.  A multi-target build states ``IP_COUNT``,
    one ``IP_*_<n>`` family per target and the generated ``IpTarget<n>`` port
    traits; a one-target build keeps the historical flat macro names beside them.

    ``f5_links`` is the one global F5 link table: every declaring target's links
    in declaration order, each stating ``target_index`` and ``base``.  It is what
    makes the multi-target header possible - one ``IRQ_SOURCES`` row per link,
    each sampling its own target's real output and each carrying its own status
    offset, trigger sequence, clear write and polarity, plus ``IRQ_LINK_TARGETS``
    / ``IRQ_LINK_BASES`` so the host knows which window each link addresses.  A
    caller that omits it keeps the historical one-target rendering.
    """
    from scripts.prepare_inprocess_irq_bindings import identifier, one

    if targets is None:
        timing = (ip.get('plan') or {}).get('timing') or {}
        targets = [dict(index=0, name='source', artifact=ip,
                        protocol=target_protocol(ip), irq=irq, pins=pins,
                        registers=registers,
                        fixed_inputs=list(config.get('source_fixed_inputs') or []),
                        has_f5=irq is not None,
                        reset_assert=timing.get('reset_assert_ticks', 2),
                        reset_release=timing.get('reset_release_ticks', 3))]
    normalized = []
    for position, row in enumerate(targets):
        item = dict(row)
        item.setdefault('index', position)
        item.setdefault('name', 'target%d' % position)
        item.setdefault('fixed_inputs', [])
        item.setdefault('pins', None)
        item.setdefault('registers', None)
        item.setdefault('irq', None)
        item.setdefault('has_f5', item['irq'] is not None)
        artifact = item.get('artifact')
        if not isinstance(artifact, dict) and hasattr(artifact, 'runtime_document'):
            artifact = artifact.runtime_document
        item['artifact'] = artifact
        timing = (artifact.get('plan') or {}).get('timing') or {}
        item.setdefault('reset_assert', timing.get('reset_assert_ticks', 2))
        item.setdefault('reset_release', timing.get('reset_release_ticks', 3))
        if 'window' not in item:
            window = config.get('target_window')
            if not isinstance(window, dict):
                raise ValueError('unsupported-target-window:' + item['name'])
            item['window'] = dict(window)
        if 'protocol' not in item:
            item['protocol'] = target_protocol(artifact)
        normalized.append(item)
    targets = normalized
    count = len(targets)
    if count > 1:
        # A pin model is a one-target feature: every target is clocked and
        # evaluated, but the host resolves one pad wire per build.
        for row in targets:
            if row['pins'] is not None:
                raise ValueError('unsupported-pins:multiple-targets')
        if pins is not None:
            raise ValueError('unsupported-pins:multiple-targets')
    protocols = {row['protocol'] for row in targets}
    # A mixed build drives one protocol per target: the generated traits state
    # each target's protocol and the host selects the trace sample, the completion
    # path and the printed counters from the routed target's own trait.  Any
    # subset of 2..4 supported protocols may be mixed; a protocol outside that
    # set keeps the named refusal.
    protocol, mixed = target_protocol_axis(protocols)
    protocol = None if mixed else protocol
    for row in targets:
        declared = target_protocol(row['artifact'])
        if declared != row['protocol']:
            raise ValueError('unsupported-target-protocol:' + row['name'] + ':' + declared)
        if type(row['index']) is not int or not 0 <= row['index'] < count:
            raise ValueError('unsupported-target-index:' + row['name'])
    bus = cpu_bus(cpu)
    # F6 is a DMA flow, so a combination that has no DMA port at all refuses that
    # flow under its own name.  The refusals name the F6 axis and the exact wire
    # the combination lacks; a bus access that never happened is never reported
    # as an F6 transfer.
    dma_refusal = cpu_dma_port_refusal(
        bus, None if dma_model is None else dma_model.get('kind'),
        custom_irq is not None)
    if dma_refusal is not None:
        raise ValueError(dma_refusal)
    artifacts = [row['artifact'] for row in targets]
    # A model whose profile declares ``verilator_timing_mode: timing`` is built
    # with Verilator --timing: its RTL schedules real simulation time (a passive
    # monitor with a delayed clock and delayed tasks is the usual reason), so the
    # host has to advance the shared context between clock edges instead of only
    # evaluating the models.  That is a property of the model, not of a CPU x IP
    # pair: every timed artifact states its own half period in picoseconds and
    # the normalized phase plan states the same half period as an integer number
    # of reference-CPU half periods.  The two statements have to agree; when they
    # do not, the model is refused by name with both numbers.
    #
    # ``clock_plan`` is supplied by the caller that also saves it as run evidence,
    # so the header and the saved plan describe one normalization.  A caller that
    # omits it (the legacy one-artifact callers and their tests) gets the plan of
    # exactly the artifacts it passed.
    if clock_plan is None:
        clock_plan = clock_plan_for_artifacts(
            cpu, targets, dma_model,
            assume_single_clock=config.get('assume_single_clock') is True)
    if clock_plan['timed'] and bus == 'axi4':
        # The packed AXI4 link owns its own begin/end tick pair, so the phase
        # contract this host advances is the OBI/Wishbone/AHB one.  A timed CPU
        # on the packed path is refused by name instead of being half-driven.
        raise ValueError('unsupported: timed model on the packed-axi4-clock-path')
    if clock_plan['grid_steps_per_cpu_half'] != 1 and bus == 'axi4':
        # The packed AXI4 link clocks the CPU/adapter pair exactly once per host
        # tick, so a grid whose reference half period is several grid steps (that
        # is, a rational or faster-than-CPU ratio) has no place on it.  Refused
        # by name instead of advancing the pair at a rate it does not declare.
        raise ValueError('unsupported: rational phase grid on the packed-axi4-clock-path: '
                         'one host tick advances ' + str(clock_plan['grid_steps_per_tick']) +
                         ' grid steps but the packed link clocks the CPU/adapter pair once')
    if pins is not None and clock_plan['grid_steps_per_cpu_half'] != 1:
        # The host's pin transition probe is sampled once per tick on the tick's
        # first boundary, which is where a ratio-1 model's rise lands.  A slower
        # or faster pin target's rise can land later in a tick, so a pin group on
        # a rational grid is refused by name rather than silently under-sampled.
        raise ValueError('unsupported: pin-group target on a rational phase grid: the pin '
                         'transition probe is sampled on each tick\'s first boundary (a '
                         'ratio-1 phase), not per model cycle; ' +
                         str(clock_plan['grid_steps_per_tick']) + ' grid steps per tick')
    models = [cpu, *artifacts] + ([dma_model] if dma_model is not None else [])
    timed_contracts = [row for row in clock_plan['rows'] if row['timed']]
    rates = [row['frequency_hz'] for row in clock_plan['rows']]
    timed_half_period_ps = clock_plan['grid_ps'] or 0
    fields = {}
    # The retirement channel, the interrupt input and the CPU bus are three
    # independent declaration axes.  An AHB-Lite CPU has neither RVFI nor an
    # interrupt input at its declared boundary, so those two are stated as absent
    # here (no pin is invented) and the flows that need them are refused by name.
    # Whether the retirement face states the trap/interrupt witness (cause, intr,
    # mode) and the CSR readback of the trap state.  The packed AXI4 scoreboard
    # does; the OBI/Wishbone rvfi_* ports this entry reads do not, so the host
    # prints their trap cause as unknown and never claims one.
    have_trap_witness = 0
    # Whether the CPU model exports the retirement trap bit at all.  AHB states
    # no retirement face, the packed AXI4 scoreboard always carries one, and the
    # OBI/Wishbone branch reads it from the CPU's own exports below.
    have_trap_port = 0
    # Whether the retirement face exports ``rvfi_intr``: the architectural flag
    # that marks the first instruction retired in a trap handler.  It is the
    # retirement witness F5/F6 can read as a take (see cpu_irq_take_witness);
    # a CPU that assigns only valid/order/insn/pc states 0 and keeps the named
    # refusal rather than turning an unobserved take into a zero.
    have_rvfi_intr = 0
    if bus == 'ahb':
        have_writeback = 0
        have_expanded = 0
        irq_bits = 0
        cpu_irq = None
    elif bus == 'axi4':
        have_expanded = 0
        have_trap_port = 1
        irq_bits = cpu_irq_width(cpu)
        try:
            cpu_irq = one(cpu['physical_exports'],
                          endpoint_id=profile.cpu.irq_entry_endpoint,
                          role=profile.cpu.irq_entry_role, direction='input')
            fields['CPU_IRQ'] = cpu_irq['runtime_name']
        except ValueError:
            cpu_irq = None
        # This CPU's retirement channel is the RVFI *probe bundle* its RTL
        # exports, not a set of rvfi_* ports: core/cva6_rvfi.sv, which turns the
        # bundle into instruction records, is not in the core filelist and is
        # therefore Verilated beside the run (build_cva6_rvfi_adapter).  When the
        # whole bundle is exported, the record fields below are that adapter
        # model's own ports, carried by `cpu_retirement` (rvfi) in the host.
        # Without the bundle nothing is invented: have_writeback stays 0 and F1
        # keeps its named refusal.
        rvfi_probes = axi4_rvfi_probe_export(cpu)
        if rvfi_probes is not None:
            fields['CPU_RVFI_PROBES'] = rvfi_probes['runtime_name']
            for role in ('valid', 'order', 'insn', 'pc_rdata', 'trap',
                         'rd_addr', 'rd_wdata'):
                fields['CPU_RVFI_' + role.upper()] = 'rvfi_' + role
            # The trap / interrupt witness the same record carries: the commit
            # lane's architectural cause, the scoreboard's own XLEN-wide ``intr``
            # word and the privilege level the instruction retired in.  The CSR
            # readback is the scoreboard's registered view of the trap state the
            # firmware handler reads (mcause/mepc/mtval/mtvec) plus mstatus.  A
            # wrapper without these ports fails the header build rather than
            # silently reporting a trap with an unknown cause.
            for role in ('cause', 'intr', 'mode'):
                fields['CPU_RVFI_' + role.upper()] = 'rvfi_' + role
            for role in ('mcause', 'mepc', 'mtval', 'mtvec', 'mstatus'):
                fields['CPU_RVFI_CSR_' + role.upper()] = 'rvfi_' + role
            have_trap_witness = 1
            have_writeback = 1
            # The scoreboard's ``rvfi_intr`` is part of the witness bundle above.
            have_rvfi_intr = 1
        else:
            have_writeback = 0
    else:
        try:
            for role in ('valid', 'insn', 'pc_rdata'):
                fields['CPU_RVFI_' + role.upper()] = one(
                    cpu['physical_exports'], physical_port='rvfi_' + role,
                    direction='output')['runtime_name']
            # ``rvfi_trap`` is not universal.  A CPU that assigns it keeps the
            # historical header byte for byte (HAVE_RVFI_TRAP_PORT 1 and the
            # real port name); the pinned passive CV32E40P monitor assigns only
            # valid/order/insn/pc, so its trap flag is unobservable and the case
            # line says ``traps unknown`` instead of an unobserved zero.
            trap_port = cpu_rvfi_trap_port(cpu)
            if trap_port is not None:
                fields['CPU_RVFI_TRAP'] = trap_port['runtime_name']
            have_trap_port = 1 if trap_port is not None else 0
            # The retirement face's interrupt-take flag.  It is optional on the
            # same terms as rvfi_trap: a CPU that assigns it can witness a
            # handler entry (CPU_RVFI_INTR and HAVE_RVFI_INTR_PORT 1), and one
            # that does not keeps the named F5/F6 refusal instead of a zero.
            intr_rows = [row for row in cpu['physical_exports']
                         if row.get('physical_port') == 'rvfi_intr'
                         and row.get('direction') == 'output']
            if len(intr_rows) == 1:
                fields['CPU_RVFI_INTR'] = intr_rows[0]['runtime_name']
                have_rvfi_intr = 1
        except ValueError as error:
            raise ValueError('unsupported: F1 needs the CPU rvfi_* retirement probe (' +
                             str(error) + ')')
        try:
            for role in ('order', 'rd_addr', 'rd_wdata'):
                fields['CPU_RVFI_' + role.upper()] = one(
                    cpu['physical_exports'], physical_port='rvfi_' + role,
                    direction='output')['runtime_name']
            have_writeback = 1
        except ValueError:
            have_writeback = 0
        try:
            fields['CPU_RVFI_EXPANDED_VALID'] = one(
                cpu['physical_exports'], physical_port='rvfi_ext_expanded_insn_valid',
                direction='output')['runtime_name']
            have_expanded = 1
        except ValueError:
            have_expanded = 0
        irq_bits = cpu_irq_width(cpu)
        cpu_irq = one(cpu['physical_exports'], endpoint_id=profile.cpu.irq_entry_endpoint,
                      role=profile.cpu.irq_entry_role, direction='input')
        fields['CPU_IRQ'] = cpu_irq['runtime_name']
        if custom_irq is not None:
            fields['CPU_IRQ_EOI'] = custom_irq['eoi_runtime_name']
        if bus == 'obi':
            if cpu_irq['width'] != 1:
                raise ValueError('unsupported: requires a one-bit CPU IRQ input')
            if (profile.cpu.irq_entry_polarity != 'active_high'
                    or profile.cpu.irq_semantics != 'machine_external'):
                raise ValueError('unsupported: requires an active-high machine-external '
                                 'CPU IRQ input')
        else:
            if cpu_irq['width'] != irq_bits:
                raise ValueError('unsupported: the CPU IRQ input width is not the declared one')
            if profile.cpu.irq_entry_polarity != 'active_high':
                raise ValueError('unsupported: requires an active-high CPU IRQ input')
    take = [row for row in cpu.get('runtime_ports', [])
            if row.get('name') == 'probe_irq_taken_pre' and row.get('direction') == 'output']
    have_take = len(take) == 1
    if have_take:
        fields['CPU_IRQ_TAKE'] = 'probe_irq_taken_pre'
    roles = ('req_valid', 'req_ready', 'req_write', 'req_addr', 'req_wdata', 'req_be',
             'rsp_valid', 'rsp_ready', 'rsp_rdata', 'rsp_error')
    ahb_address_width = 0
    axi4_id_width = 0
    if bus == 'obi':
        for channel in ('i', 'd'):
            for role in roles:
                fields['CPU_' + channel.upper() + '_' + role.upper()] = one(
                    cpu['backend_ports'], channel=channel, role=role)['name']
    elif bus == 'axi4':
        for role in AXI4_CPU_OUTPUT_ROLES:
            row = one(cpu['backend_ports'], channel='axi', role=role, direction='output')
            if type(row.get('width')) is not int or not 1 <= row['width'] <= 64:
                raise ValueError('unsupported-axi4-role-width:' + role)
            fields['CPU_AXI_' + role.upper()] = row['name']
        for role in AXI4_CPU_INPUT_ROLES:
            row = one(cpu['backend_ports'], channel='axi', role=role, direction='input')
            if type(row.get('width')) is not int or not 1 <= row['width'] <= 64:
                raise ValueError('unsupported-axi4-role-width:' + role)
            fields['CPU_AXI_' + role.upper()] = row['name']
        axi4_id_width = one(cpu['backend_ports'], channel='axi',
                            role='arid', direction='output')['width']
    elif bus == 'ahb':
        for role in roles:
            row = one(cpu['backend_ports'], channel='m', role=role)
            width = row.get('width')
            if type(width) is not int or not 1 <= width <= 64:
                raise ValueError('unsupported-ahb-beat-width:' + role)
            fields['CPU_M_' + role.upper()] = row['name']
            if role == 'req_addr':
                ahb_address_width = width
        contract = cpu.get('manager_domain')
        roles_rows = (contract or {}).get('roles') if isinstance(contract, dict) else None
        if not isinstance(roles_rows, dict):
            raise ValueError('unsupported-ahb-manager-domain:no_declared_contract')
        for row_name, key in (('manager_ready', 'AHB_MANAGER_READY'),
                              ('bus_reset_n', 'AHB_BUS_RESET_N')):
            row = roles_rows.get(row_name)
            if (not isinstance(row, dict) or not isinstance(row.get('runtime_name'), str)
                    or row.get('direction') != 'output' or row.get('width') != 1
                    or row.get('physical_port') is None):
                raise ValueError('unsupported-ahb-manager-domain:' + row_name)
            fields[key] = row['runtime_name']
        traces = [row for row in (cpu.get('base_protocol_traces') or {}).get('traces', [])
                  if row.get('protocol') == 'ahb-lite']
        if len(traces) != 1:
            raise ValueError('unsupported-ahb-trace:expected_one_ahb_lite_trace')
        signals = traces[0].get('signals') or {}
        missing = [role for role in AHB_IDENTITY_ROLES if role not in signals]
        if missing:
            raise ValueError('unsupported-ahb-trace:lacks:' + ','.join(missing))
        for role in AHB_IDENTITY_ROLES:
            fields['CPU_AHB_TRACE_' + role.upper()] = signals[role]
    else:
        marker = cpu.get('instruction_identity_observation')
        if not isinstance(marker, str) or not marker:
            raise ValueError('unsupported: the CPU declares no mem_instr observation')
        fields['CPU_WB_INSTR'] = identifier(marker)
        for role in ('cyc', 'stb', 'we', 'adr', 'dat_w', 'sel'):
            fields['CPU_WB_' + role.upper()] = one(
                cpu['backend_ports'], channel='wb', role=role, direction='output')['name']
        for role in ('ack', 'dat_r'):
            fields['CPU_WB_' + role.upper()] = one(
                cpu['backend_ports'], channel='wb', role=role, direction='input')['name']

    # Every target is bound from its own artifact: the beat channel, the passive
    # protocol trace, the fixed physical inputs and the optional pads.
    target_fields = []
    fixed_rows = []
    pad_rows = []
    observed_irq = {}
    for row in targets:
        artifact = row['artifact']
        item = {}
        for role in roles:
            rows = [row_ for row_ in artifact['backend_ports']
                    if row_.get('role') == role
                    and row_.get('channel') != 'ip_protocol_trace']
            if len(rows) != 1:
                raise ValueError('unsupported: the target does not expose one ' + role +
                                 ' beat role')
            item['IP_' + role.upper()] = rows[0]['name']
        signals = artifact['base_protocol_trace'].get('signals', {})
        # The trace roles are this target's own protocol's: a mixed build binds
        # one target from its APB3 taps and the next from its AXI4-Lite taps, and
        # a Wishbone or TL-UL target binds its own channels the same way.
        trace_roles = PROTOCOL_TRACE_ROLES[row['protocol']]
        missing = [role for role in trace_roles if role not in signals]
        if missing:
            raise ValueError('unsupported: the ' + TARGET_LABELS[row['protocol']] +
                             ' trace lacks ' + ','.join(missing))
        for role in trace_roles:
            item['IP_TRACE_' + role.upper()] = signals[role]
        # Optional taps: sampled when the trace carries them, never required.
        for role in WB_OPTIONAL_TRACE_ROLES:
            if role in signals:
                item['IP_TRACE_' + role.upper()] = signals[role]
        have_pslverr = 1 if 'pslverr' in signals else 0
        if have_pslverr:
            item['IP_TRACE_PSLVERR'] = signals['pslverr']
        target_fields.append(item)
        declared_pins = {(pin_row.get('endpoint_id'), pin_row.get('role')): pin_row.get('value')
                         for pin_row in (row.get('fixed_inputs') or [])}
        fixed = {(pin_row.get('endpoint_id'), pin_row.get('role')): pin_row
                 for pin_row in (artifact.get('fixed_physical_inputs') or [])}
        if set(fixed) != set(declared_pins):
            raise ValueError('unsupported: the generated target does not expose every declared pin')
        rows = []
        for key, value in sorted(declared_pins.items()):
            width = fixed[key].get('width')
            if (not isinstance(fixed[key].get('runtime_name'), str)
                    or fixed[key].get('value') != value
                    or type(width) is not int or not 1 <= width <= 64
                    or value >= 1 << width):
                raise ValueError('unsupported: the generated target pin constant or name differs')
            rows.append((identifier(fixed[key]['runtime_name']), value))
        fixed_rows.append(rows)
        row_pins = row.get('pins')
        if row_pins is not None:
            item_pads = {}
            for role, key in (('in', 'IP_PIN_IN'), ('out', 'IP_PIN_OUT'),
                              ('dir', 'IP_PIN_DIR'), ('in_sync', 'IP_PIN_IN_SYNC')):
                port = one(artifact['physical_exports'],
                           endpoint_id=row_pins['endpoint_id'], role=role)
                if port['direction'] not in ('input', 'output'):
                    raise ValueError('unsupported: pin port direction for ' + role)
                if port['width'] != row_pins['width']:
                    raise ValueError('unsupported: the generated pin port ' + role +
                                     ' is not ' + str(row_pins['width']) + ' bits wide')
                item_pads[key] = port['runtime_name']
            for name, key in (('status', 'IP_PROBE_STATUS'),
                              ('padin_latch', 'IP_PROBE_PADIN_LATCH'),
                              ('rise', 'IP_PROBE_RISE'), ('fall', 'IP_PROBE_FALL'),
                              ('inten', 'IP_PROBE_INTEN')):
                item_pads[key] = one(artifact['physical_exports'],
                                     physical_port='gpio_probe_' + name,
                                     direction='output')['runtime_name']
            item.update(item_pads)
        pad_rows.append(row_pins)
        observed_irq[row['index']] = observed_irq_output(artifact)

    # Every target that declares F5 owns one or more IRQ links.  ``f5_links`` is
    # the entry's one global link table: each row names the target that declared
    # it (``target_index``), the window it addresses (``base``) and its own
    # trigger/status/clear facts.  A legacy caller states no table, and then the
    # one declaring target's own links are used exactly as before - including the
    # refusal of a second declaring target, which has no link table to describe.
    target_by_index = {row['index']: row for row in targets}
    declaring = [row for row in targets if row.get('irq') is not None]
    if f5_links is None:
        if len(declaring) > 1:
            raise ValueError('unsupported-f5:multiple-target-irq-sources')
        f5_row = declaring[0] if declaring else None
        f5_index = None if f5_row is None else f5_row['index']
        if f5_target_index is not None:
            if f5_index is not None and f5_target_index != f5_index:
                raise ValueError('unsupported-f5:selected-target-differs')
            f5_index = f5_target_index
        target_links = (f5_row['irq'].get('links') or [f5_row['irq']]) if f5_row else []
        link_targets = [f5_index if f5_index is not None else 0] * len(target_links)
    else:
        f5_row = declaring[0] if declaring else None
        f5_index = None if f5_row is None else f5_row['index']
        if f5_target_index is not None:
            if f5_index is not None and f5_target_index != f5_index:
                raise ValueError('unsupported-f5:selected-target-differs')
            f5_index = f5_target_index
        target_links = list(f5_links)
        link_targets = [int(link['target_index']) for link in target_links]
        # Every declaring target owns at least one link and every link names a
        # declaring target; a table that says otherwise is refused instead of
        # being folded onto the first target.  A target may own several links
        # (the two-link timer), so the check is set equality, not a count.
        if set(link_targets) != {row['index'] for row in declaring}:
            raise ValueError('unsupported-f5:link-target-count-differs')
    # The F5 source itself is the observed interrupt output of its target, even
    # when the port is a vector: the declared bit selects the link and the raw
    # port value is what the link lambdas sample.  Every declaring target gets
    # that treatment, so a multi-target build samples both real outputs.
    for declaring_row in declaring:
        declaring_links = (declaring_row['irq'].get('links')
                           or [declaring_row['irq']])
        observed_irq[declaring_row['index']] = one(
            declaring_row['artifact']['physical_exports'],
            physical_port=declaring_links[0]['port'], direction='output')
    sources = []
    for position, source in enumerate(target_links):
        owner = target_by_index[link_targets[position]]
        row = one(owner['artifact']['physical_exports'], physical_port=source['port'],
                  direction='output')
        bit = source['bit']
        if row['width'] > 64 or not row['bit_lo'] <= bit <= row['bit_hi']:
            raise ValueError('unsupported: target IRQ bit')
        local = bit - row['bit_lo']
        if count == 1:
            expression = 'ip.' + identifier(row['runtime_name'])
        else:
            expression = 'g_ip_irq[%d]' % link_targets[position]
        sources.append((expression, local, source['pulse_ticks'],
                        1 if source['polarity'] == 'active_low' else 0, 'target'))
    if dma_irq is not None:
        row = one(dma_model['physical_exports'], physical_port=dma_irq['port'],
                  direction='output')
        bit = 0
        if row['width'] > 64 or not row['bit_lo'] <= bit <= row['bit_hi']:
            raise ValueError('unsupported: dma IRQ bit')
        sources.append((f'dma.{identifier(row["runtime_name"])}', bit - row['bit_lo'],
                        dma_irq['pulse_ticks'],
                        1 if dma_irq['polarity'] == 'active_low' else 0, 'dma'))
    dma_link = next((index for index, row in enumerate(sources) if row[4] == 'dma'), 0)
    cpu_model = 'V' + identifier(cpu['module_name'])
    target_models = ['V' + identifier(row['artifact']['module_name']) for row in targets]
    includes = [f'#include "{cpu_model}.h"']
    includes += [f'#include "{model}.h"' for model in target_models]
    if bus == 'axi4':
        includes.append('#include "Vaxi4_processor_memory_adapter.h"')
    if bus == 'axi4' and have_writeback:
        # The pinned RVFI scoreboard is a second Verilated model beside the CPU
        # (core/cva6_rvfi.sv is not in the core filelist); its generated header
        # carries the RVFI record ports the retirement block reads.
        includes.append('#include "Vcva6_rvfi_top.h"')
    if 'slot_return' not in layout:
        layout = build_firmware(
            layout, irq=irq, dma=dma,
            interrupt_bootstrap=bus in ('obi', 'axi4'),
            f1_words=f1_words,
            irq_take_clear=(bus == 'axi4' and irq is not None
                            and packed_axi4_irq_contract(cpu, profile) is not None))['layout']
    lines = ['#pragma once', *includes]
    if dma_model is not None:
        dma_name = 'V' + identifier(dma_model['module_name'])
        lines += [f'#include "{dma_name}.h"', f'#define DMA_MODEL {dma_name}']
    lines += [f'#define CPU_MODEL {cpu_model}',
              f'#define IP_COUNT {count}']
    if count == 1:
        lines.append(f'#define IP_MODEL {target_models[0]}')
    for index, model in enumerate(target_models):
        lines.append(f'#define IP_MODEL_{index} {model}')
    # Which CPU-side port witnesses an interrupt take in this build, stated once
    # for the header and the summary.  AHB states none (that boundary declares no
    # interrupt entry at all); the packed AXI4 build states the scoreboard's
    # rvfi_intr when its cause/intr/mode witness bundle is present; every other
    # bus reads its own generated artifact.  ``unexported`` is a refusal, not a
    # zero: F5/F6 are gated on this word by the caller.
    if bus == 'ahb':
        take_witness_word = 'none'
    elif bus == 'axi4':
        # Measured, not assumed: the pinned cva6_rvfi scoreboard sets its ``intr``
        # word on the interrupt cycle (cva6_rvfi.sv:499-503) but the interrupt
        # entry is not a valid RVFI record (valid=0 there, cva6_rvfi.sv:490-497),
        # so the record this host reads never carries it - see the CVA6 run in
        # runs/p1-irq/, where no valid record had intr bit 2 set while the core
        # really entered the handler.  The take this host observes is the core's
        # own mcause readback (bit 63 set), which the F5 ISR clears after the
        # entry so each case's take is its own transition.
        take_witness_word = 'mcause_readback' if have_trap_witness else 'unexported'
    else:
        take_witness_word = (cpu_irq_take_witness(cpu, custom_irq)[0]
                             or 'unexported')
    lines += [
        '#define IP_TARGETS_GENERATED %d' % int(count > 1),
        # The first declaring target's index stays under the historical name (a
        # one-target build reads it unchanged); the header also states how many
        # targets declare F5 and whether more than one does, so the host summary
        # never has to guess which target a delivered line belongs to.
        '#define IP_F5_TARGET_INDEX %s' %
        ('0xffffffffu' if f5_index is None else '%du' % f5_index),
        '#define IP_F5_TARGET_COUNT %du' % len(set(link_targets)),
        '#define IP_F5_TARGET_MULTI %d' % int(len(set(link_targets)) > 1),
        '#define IP_MODEL_TYPES ' +
        ', '.join(f'std::unique_ptr<IP_MODEL_{index}>' for index in range(count)),
        '#define IP_MODEL_INSTANCES(context) ' +
        ', '.join('std::make_unique<IP_MODEL_%d>((&context), "%s")' %
                  (index, 'target' if count == 1 else 'target%d' % index)
                  for index in range(count)),
        f'#define HAVE_DMA {int(dma_model is not None)}',
        f'#define HAVE_IRQ_LINKS {int(bool(sources))}',
        f'#define HAVE_CPU_TAKE {int(have_take)}',
        '#define HAVE_EVENT_LAYER 1',
        f'#define HAVE_RVFI_WRITEBACK {have_writeback}',
        f'#define HAVE_RVFI_EXPANDED {have_expanded}',
        # Whether the CPU model exports the retirement trap bit at all.  A model
        # that does not (the pinned CV32E40P monitor assigns valid/order/insn/pc
        # only) reports the case's trap count as ``unknown``; it is never turned
        # into an unobserved zero.
        f'#define HAVE_RVFI_TRAP_PORT {have_trap_port}',
        # A packed AXI4 build carries its retirement face on the probe-bundle
        # adapter model, not on the CPU model; every other bus states 0 here so
        # the host's `#if HAVE_RVFI_ADAPTER` gate compiles the same way.
        f'#define HAVE_RVFI_ADAPTER {int(bus == "axi4" and have_writeback)}',
        # Whether the retirement face also states the commit lane's cause/intr/
        # mode and the CSR readback (the packed AXI4 scoreboard does).  A build
        # without them prints a trap's cause as unknown and never claims one.
        f'#define HAVE_RVFI_TRAP_WITNESS {have_trap_witness}',
        # Whether the retirement face exports rvfi_intr, the architectural
        # first-handler-retirement flag the host reads as an interrupt take when
        # the CPU has no take probe or custom EOI.  A build without the port
        # states 0 and the flows stay refused by name, never counted from a bus
        # success.
        f'#define HAVE_RVFI_INTR_PORT {have_rvfi_intr}',
        f'#define CPU_TAKE_WITNESS "{take_witness_word}"',
        f'#define HAVE_CPU_TAKE_WITNESS {int(take_witness_word != "unexported")}',
        *(['#define RVFI_ADAPTER Vcva6_rvfi_top',
           f'#define CPU_RVFI_PROBES_WIDTH {CVA6_RVFI_PROBES_BITS}',
           f'#define CPU_RVFI_PROBES_WORDS {CVA6_RVFI_PROBES_WORDS}']
          if bus == 'axi4' and have_writeback else []),
        '#define HAVE_APB_PSLVERR %d' % int(bool(any(
            item.get('IP_TRACE_PSLVERR') for item in target_fields))),
        f'#define CPU_BUS_WISHBONE {int(bus == "wishbone")}',
        f'#define CPU_BUS_AHB {int(bus == "ahb")}',
        f'#define CPU_BUS_AXI4 {int(bus == "axi4")}',
        # One model (or several agreeing ones) built with Verilator --timing:
        # the host advances the shared simulation context by this declared half
        # period on each clock phase so the model's own scheduled events (a
        # delayed monitor edge, a delayed task) really run.  0 states that every
        # model is the default no-timing build and the host only evaluates.
        f'#define CPU_TIMED_MODEL {int(bool(timed_contracts))}',
        # The normalized per-model clock plan.  TIMED_GRID_PS is the one
        # simulation-time step the shared timed context advances per phase: the
        # reference CPU's half period, which every declared timed model's own
        # half period is an integer multiple of (0 states an untimed build).
        f'#define TIMED_GRID_PS {timed_half_period_ps}u',
        *clock_plan_header(clock_plan),
        f'#define CPU_BOOT_ADDRESS 0x{layout["boot"]:x}u',
        f'#define CPU_MAIN_ADDRESS 0x{layout["main"]:x}u',
        f'#define CPU_M_ADDR_WIDTH {ahb_address_width}u',
        f'#define AXI4_ADAPTER Vaxi4_processor_memory_adapter',
        f'#define CPU_AXI4_ADDR_WIDTH 64u',
        f'#define CPU_AXI4_DATA_WIDTH 64u',
        f'#define CPU_AXI4_ID_WIDTH {axi4_id_width}u',
        f'#define CPU_AXI4_USER_WIDTH 64u',
        f'#define CPU_IRQ_WIDTH {irq_bits}',
        # Which builds really drive the CPU interrupt entry: an OBI CPU's
        # one-bit machine-external input, the packed AXI4 CPU's machine-external
        # bit (bit 0 of its two-bit irq_i), and a Wishbone CPU's declared custom
        # IRQ bit.  A build with no declared source states 0 and the summary says
        # the line is held at zero.
        f'#define CPU_IRQ_WIRED '
        f'{int((bus in ("obi", "axi4") or custom_irq is not None) and bool(sources))}',
        # A CPU with no probe port observes a take on its own mcause readback;
        # the ISR clears it after the entry so every case's take is a fresh
        # transition.  A build with a probe port keeps the historical ISR.
        f'#define IRQ_TAKE_CLEAR '
        f'{int(bus == "axi4" and irq is not None and packed_axi4_irq_contract(cpu, profile) is not None)}',
        f'#define CPU_CUSTOM_IRQ {int(custom_irq is not None)}',
        f'#define CASE_TICK_BUDGET {case_tick_budget}u',
        f'#define CPU_CUSTOM_IRQ_BIT {custom_irq["irq_bit"] if custom_irq else 0}u',
        # The one-protocol declaration stays under the historical names.  A
        # mixed build states TARGET_PROTOCOLS_MIXED 1 and leaves both protocol
        # macros neutral, so the host cannot accidentally apply one target's
        # protocol to another: every protocol-specific step is selected from the
        # routed target's own trait (TARGET_PROTOCOL_*_<n> / IpTarget<n>).
        f'#define TARGET_PROTOCOLS_MIXED {int(mixed)}',
        f'#define TARGET_PROTOCOL_APB3 {int(protocol == "apb3")}',
        f'#define TARGET_PROTOCOL_AXI4LITE {int(protocol == "axi4-lite")}',
        f'#define TARGET_PROTOCOL_WISHBONE {int(protocol == "wishbone")}',
        f'#define TARGET_PROTOCOL_TLUL {int(protocol == "tl-ul")}',
        f'#define TARGET_PROTOCOL_AHB {int(protocol == "ahb-lite")}',
        # Which protocols this build really contains, whether it is homogeneous
        # or mixed.  A one-protocol header states none of these and its own
        # TARGET_PROTOCOL_* macro answers; a mixed build states its members here
        # because all four TARGET_PROTOCOL_* macros are neutral for it.  The host
        # compiles and prints only the trace/completion/counter groups the build
        # has, so a mixed build without an AXI4-Lite target never prints a zero
        # axi_* group and a two-protocol APB3 + AXI4-Lite build keeps the exact
        # case and summary lines it had.
        f'#define TARGET_MIXED_HAS_APB3 {int(mixed and "apb3" in protocols)}',
        f'#define TARGET_MIXED_HAS_AXI4LITE {int(mixed and "axi4-lite" in protocols)}',
        f'#define TARGET_MIXED_HAS_WISHBONE {int(mixed and "wishbone" in protocols)}',
        f'#define TARGET_MIXED_HAS_TLUL {int(mixed and "tl-ul" in protocols)}',
        f'#define TARGET_MIXED_HAS_AHB {int(mixed and "ahb-lite" in protocols)}',
        # A build whose case lines state the routed target's protocol word: a
        # mixed build always does, and a Wishbone/TL-UL build does because those
        # protocols have no historical spelling to preserve.  An APB3 or an
        # AXI4-Lite one-protocol build states 0 and keeps its saved line exactly.
        f'#define TARGET_PROTOCOL_VERBOSE '
        f'{int(mixed or protocol in ("wishbone", "tl-ul", "ahb-lite"))}',
        '#define TARGET_BRIDGE "%s"' %
        (mixed_target_bridge(protocols) if mixed
         else TARGET_BRIDGES[protocol]),
        '#define TARGET_NAME "%s"' %
        ('MMIO' if mixed else TARGET_LABELS[protocol]),
        '#define TARGET_BUS_CHANNEL "%s"' %
        ('mixed' if mixed else
         {'axi4-lite': 'axi', 'wishbone': 'wb', 'tl-ul': 'tlul',
          'ahb-lite': 'ahb'}.get(protocol, 'apb')),
        f'#define IRQ_TARGET_LINK_COUNT {len(target_links)}u',
        f'#define IRQ_DMA_LINK_INDEX {dma_link}u',
        f'#define DMA_IRQ_LEVEL {int(bool(dma_irq and dma_irq["trigger"] == "level"))}',
        # The one F5 target's status declaration is also kept under the flat
        # names: the host's fallback link table and the saved summary use them.
        '#define IP_STATUS_KIND "%s"' %
        ('undeclared' if f5_row is None else f5_row['irq']['status_kind']),
        f'#define IP_CAUSE_DECLARED '
        f'{int(f5_row["irq"].get("cause_declared", False)) if f5_row else 0}',
        '#define IP_CAUSE_MASK 0x%08xu' %
        ((f5_row['irq'].get('cause_mask', 0) if f5_row else 0)),
        '#define IP_STATUS_READ_CLEARS %d' %
        int(bool(f5_row and f5_row['irq'].get('status_read_clears', False))),
        f'#define IP_CLEAR_DECLARED {int(bool(f5_row and f5_row["irq"]["clear"]))}',
        f'#define IP_CLEAR_OFFSET '
        f'{f5_row["irq"]["clear"]["offset"] if f5_row and f5_row["irq"]["clear"] else 0}u',
        '#define IP_CLEAR_VALUE 0x%08xu' %
        ((f5_row['irq']['clear']['value'] if f5_row and f5_row['irq']['clear'] else 0)),
        '#define DMA_STATUS_KIND "{0}"'.format(dma['status_kind'] if dma else 'undeclared'),
        '#define HAVE_PINS %d' % int(count == 1 and pins is not None)]
    # Each target's status/clear declaration is its own facts.  The F5 target's
    # values are the ones the handler actually addresses; a target without F5
    # facts states that it has none rather than inheriting the other's.
    for row in targets:
        index = row['index']
        target_irq = row.get('irq')
        lines += [
            # This target's own protocol declaration, from its own artifact.  The
            # host selects its trace sample, its completion criterion and its
            # case-line words from these values (through the generated
            # `IpTarget<n>` trait), so a mixed build never applies one target's
            # protocol to another.
            '#define TARGET_PROTOCOL_APB3_%d %d' %
            (index, int(row['protocol'] == 'apb3')),
            '#define TARGET_PROTOCOL_AXI4LITE_%d %d' %
            (index, int(row['protocol'] == 'axi4-lite')),
            '#define TARGET_PROTOCOL_WISHBONE_%d %d' %
            (index, int(row['protocol'] == 'wishbone')),
            '#define TARGET_PROTOCOL_TLUL_%d %d' %
            (index, int(row['protocol'] == 'tl-ul')),
            '#define TARGET_PROTOCOL_AHB_%d %d' %
            (index, int(row['protocol'] == 'ahb-lite')),
            '#define TARGET_BRIDGE_%d "%s"' % (index, TARGET_BRIDGES[row['protocol']]),
            '#define TARGET_NAME_%d "%s"' % (index, TARGET_LABELS[row['protocol']]),
            '#define TARGET_BUS_CHANNEL_%d "%s"' %
            (index, {'axi4-lite': 'axi', 'wishbone': 'wb', 'tl-ul': 'tlul',
                     'ahb-lite': 'ahb'}.get(row['protocol'], 'apb')),
            '#define IP_PROTOCOL_%d "%s"' % (index, row['protocol']),
            '#define IP_HAS_F5_%d %d' % (index, int(bool(target_irq))),
            '#define IP_STATUS_KIND_%d "%s"' %
            (index, target_irq['status_kind'] if target_irq else 'undeclared'),
            '#define IP_STATUS_OFFSET_%d %du' %
            (index, target_irq['status_offset'] if target_irq else 0),
            '#define IP_CAUSE_DECLARED_%d %d' %
            (index, int(target_irq.get('cause_declared', False)) if target_irq else 0),
            '#define IP_CAUSE_MASK_%d 0x%08xu' %
            (index, target_irq.get('cause_mask', 0) if target_irq else 0),
            '#define IP_CLEAR_DECLARED_%d %d' %
            (index, int(bool(target_irq and target_irq['clear']))),
            '#define IP_CLEAR_OFFSET_%d %du' %
            (index, target_irq['clear']['offset'] if target_irq and target_irq['clear'] else 0),
            '#define IP_CLEAR_VALUE_%d 0x%08xu' %
            (index, target_irq['clear']['value'] if target_irq and target_irq['clear'] else 0),
            '#define IP_RESET_ASSERT_%d %du' % (index, row['reset_assert']),
            '#define IP_RESET_RELEASE_%d %du' % (index, row['reset_release']),
            '#define IP_BASE_%d 0x%xu' % (index, row['window']['base']),
            '#define IP_SIZE_%d %du' % (index, row['window']['size'])]
        observed = observed_irq.get(index)
        lines += ['#define IP_HAS_IRQ_%d %d' % (index, int(observed is not None)),
                  '#define IP_IRQ_BIT_%d %du' %
                  (index, observed['bit_lo'] if observed is not None else 0)]
    if mixed or protocol in ('axi4-lite', 'wishbone', 'tl-ul', 'ahb-lite'):
        # The protocol-neutral field names, printed beside the per-target
        # counters.  A mixed build prints this group for every case because a
        # case line cannot state one spelling for two protocols: the target's own
        # protocol is stated per case (``target_protocol``) and per target in the
        # summary, and the neutral names carry the transfer facts.  A Wishbone or
        # TL-UL build prints the same group because it has no historical spelling
        # of its own, and states its sampled handshake beside it.  An AHB-Lite
        # build does exactly the same: both of its phases are its own, so no
        # ``apb_*`` spelling may appear on its case line.
        lines += ['#define KEY_TARGET_READS "target_reads"',
                  '#define KEY_TARGET_WRITES "target_writes"',
                  '#define KEY_TARGET_TRANSFERS "target_transfers"',
                  '#define KEY_TARGET_ERRORS "target_errors"',
                  '#define KEY_TARGET_READY "target_ready"',
                  '#define KEY_TARGET_OFFSET "target_offset"',
                  '#define KEY_TARGET_WDATA "target_wdata"',
                  '#define KEY_TARGET_RDATA "target_rdata"',
                  '#define KEY_TARGET_READ_OFFSET "target_read_offset"',
                  '#define KEY_TARGET_READ_DATA "target_read_data"',
                  '#define KEY_TARGET_LAST_WRITE_OFFSET "target_last_write_offset"',
                  '#define KEY_TARGET_LAST_WRITE_DATA "target_last_write_data"',
                  # The ``read_from`` word names the bridge that carried the read.
                  # A one-protocol build keeps its historical word; a mixed build
                  # states the neutral one and the per-case protocol field.
                  '#define KEY_READ_FROM_TARGET "%s"' %
                  ('axi4lite' if protocol == 'axi4-lite' else 'target')]
    if count == 1:
        first = targets[0]
        first_pins = first['pins']
        if first_pins is not None:
            lines += [f'#define PAD_WIDTH {first_pins["width"]}',
                      f'#define IP_PAD_EXT_DEFAULT 0x{first_pins["external_value"]:x}u',
                      f'#define IP_PADIN_OFFSET {first_pins["padin_offset"]}u',
                      f'#define IP_PADOUT_OFFSET {registers["PADOUT"]}u',
                      f'#define IP_PADOUTSET_OFFSET {registers["PADOUTSET"]}u',
                      f'#define IP_PADOUTCLR_OFFSET {registers["PADOUTCLR"]}u']
        # The declared pad-group list and serial peer, rendered exactly as the
        # declaration states them.  Each group states its kind, its own declared
        # facts and, for a serial peer, the model port each pad role was bound to.
        # The host walks the groups in this order; nothing here is derived from a
        # component name.  A build with no declared group list states none of
        # these macros and the host's historical single-pad path stays enabled.
        if pin_groups:
            pad_groups = [group for group in pin_groups
                          if group['kind'] == PIN_GROUP_KIND_DIR]
            serial_groups = [group for group in pin_groups
                             if group['kind'] == PIN_GROUP_KIND_SERIAL]
            lines += [f'#define HAVE_PIN_GROUPS {int(bool(pad_groups))}',
                      f'#define PIN_GROUP_COUNT {len(pad_groups)}',
                      f'#define PIN_SERIAL_COUNT {len(serial_groups)}']
            # One row per dir-resolved group, in the declaration's own order: the
            # host walks this table, so a reordering of the declaration really does
            # reorder the wire.  The declaration's name, direction, hold window and
            # external driver word are the row; nothing is derived from the device.
            rows = []
            for group in pad_groups:
                direction = {'in': 0, 'out': 1, 'inout': 2}[group['direction']]
                rows.append((f'  X("{group["name"]}", {direction}u, '
                              f'{group["hold_ticks"]}u, '
                              f'0x{group["external_value"]:x}u)'))
            lines.append('#define PIN_GROUP_TABLE(X) ' + ' \\\n  '.join(rows)
                         if rows else '#define PIN_GROUP_TABLE(X)')
            if serial_groups:
                peer = serial_groups[0]
                ports = peer['ports']
                lines += [
                    f'#define HAVE_SERIAL_PEER 1',
                    f'#define SERIAL_PEER_NAME "{peer["name"]}"',
                    f'#define SERIAL_PEER_FRAME "{peer["frame"]}"',
                    f'#define SERIAL_PEER_FRAME_CODE {peer["frame_code"]}',
                    f'#define SERIAL_PEER_FRAME_BITS {peer["frame_bits"]}',
                    f'#define SERIAL_PEER_BIT_TICKS {peer["bit_ticks"]}u',
                    f'#define SERIAL_PEER_IDLE_LEVEL {peer["idle_level"]}u',
                    f'#define SERIAL_PEER_RX_PORT {ports[peer["rx_role"]]["runtime_name"]}',
                    f'#define SERIAL_PEER_TX_PORT {ports[peer["tx_role"]]["runtime_name"]}']
                if peer.get('tx_en_role') is not None:
                    lines += ['#define HAVE_SERIAL_TX_EN 1',
                              '#define SERIAL_PEER_TX_EN_PORT '
                              + ports[peer['tx_en_role']]['runtime_name']]
    # The historical flat fixed-input macro family stays the first target's, so
    # an old caller and the summary line keep reading it; every target also has
    # its own `_<n>` family below.
    lines.append(f'#define IP_FIXED_INPUT_COUNT {len(fixed_rows[0])}')
    lines.append('#define IP_FIXED_INPUTS(X)' +
                 ''.join(' \\\n  X(%s, %su)' % row for row in fixed_rows[0]))
    for row in targets:
        index = row['index']
        lines.append(f'#define IP_FIXED_INPUT_COUNT_{index} {len(fixed_rows[index])}')
        lines.append('#define IP_FIXED_INPUTS_%d(X)' % index +
                     ''.join(' \\\n  X(%s, %su)' % item for item in fixed_rows[index]))
        if row['pins'] is not None:
            target_pins = row['pins']
            lines += [f'#define PAD_WIDTH_{index} {target_pins["width"]}',
                      f'#define IP_PAD_EXT_DEFAULT_{index} 0x{target_pins["external_value"]:x}u',
                      f'#define IP_PADIN_OFFSET_{index} {target_pins["padin_offset"]}u']
            if row['registers'] is not None:
                lines += [f'#define IP_PADOUT_OFFSET_{index} {row["registers"]["PADOUT"]}u',
                          f'#define IP_PADOUTSET_OFFSET_{index} {row["registers"]["PADOUTSET"]}u',
                          f'#define IP_PADOUTCLR_OFFSET_{index} {row["registers"]["PADOUTCLR"]}u']
    for key, value in fields.items():
        lines.append(f'#define {key} {identifier(value)}')
    for index, item in enumerate(target_fields):
        for key, value in item.items():
            lines.append(f'#define {key}_{index} {identifier(value)}')
            if count == 1:
                lines.append(f'#define {key} {identifier(value)}')
    rows = ['  X((uint64_t({expression})), {bit}u, {pulse}u, {invert}u)'.format(
                expression=expression, bit=bit, pulse=pulse, invert=invert)
            for expression, bit, pulse, invert, name in sources]
    lines.append(f'#define IRQ_SOURCE_COUNT {len(sources)}')
    lines.append('#define IRQ_SOURCES(X)' + ''.join(' \\\n' + row for row in rows))
    if target_links:
        def array(name, values):
            return '#define %s %s' % (name, ' '.join(values))
        lines.append(array('IRQ_LINK_STATUS_OFFSETS',
                           ['%du,' % link['status_offset'] for link in target_links]).rstrip(','))
        lines.append(array('IRQ_LINK_CAUSE_MASKS',
                           ['0x%08xu,' % link['cause_mask'] for link in target_links]).rstrip(','))
        lines.append(array('IRQ_LINK_CLEAR_DECLARED',
                           ['%du,' % int(link['clear'] is not None)
                            for link in target_links]).rstrip(','))
        lines.append(array('IRQ_LINK_CLEAR_OFFSETS',
                           ['%du,' % (link['clear']['offset'] if link['clear'] else 0)
                            for link in target_links]).rstrip(','))
        lines.append(array('IRQ_LINK_CLEAR_VALUES',
                           ['0x%08xu,' % (link['clear']['value'] if link['clear'] else 0)
                            for link in target_links]).rstrip(','))
        # The declared clear is an ordered sequence.  ``CLEAR_COUNTS`` states how
        # many steps this link declares, and the second step's own address/value
        # are stated so the host can check the handler performed it.  A link with
        # one step states 1 and zeros here, and the host's pass condition keeps
        # the historical single-clear reading.
        lines.append(array('IRQ_LINK_CLEAR_COUNTS',
                           ['%du,' % len(link.get('clears') or ())
                            for link in target_links]).rstrip(','))
        lines.append(array('IRQ_LINK_CLEAR2_OFFSETS',
                           ['%du,' % ((link.get('clears') or [None] * 2)[1]['offset']
                                      if len(link.get('clears') or ()) > 1 else 0)
                            for link in target_links]).rstrip(','))
        lines.append(array('IRQ_LINK_CLEAR2_VALUES',
                           ['0x%08xu,' % ((link.get('clears') or [None] * 2)[1]['value']
                                          if len(link.get('clears') or ()) > 1 else 0)
                            for link in target_links]).rstrip(','))
        lines.append('#define IRQ_CLEAR_STEPS %du' % max(
            [len(link.get('clears') or ()) for link in target_links] or [0]))
        lines.append(array('IRQ_LINK_CAUSE_DECLARED',
                           ['%du,' % int(link['cause_declared']) for link in target_links]).rstrip(','))
        lines.append(array('IRQ_LINK_READ_CLEARS',
                           ['%du,' % int(link.get('status_read_clears', False))
                            for link in target_links]).rstrip(','))
        lines.append(array('IRQ_LINK_LEVEL',
                           ['%du,' % int(link['trigger'] == 'level')
                            for link in target_links]).rstrip(','))
        lines.append(array('IRQ_LINK_TRIGGER_LAST',
                           ['%du,' % link['trigger_offsets'][-1] for link in target_links]).rstrip(','))
        lines.append(array('IRQ_LINK_TRIGGER_COUNTS',
                           ['%du,' % len(link['trigger_offsets']) for link in target_links]).rstrip(','))
        # The link-to-target mapping: which declared target window each link
        # belongs to, and the base the link's own firmware body addresses.  A
        # one-target build states the same index and base on every row, so the
        # host computes exactly what it computed before.
        lines.append(array('IRQ_LINK_TARGETS',
                           ['%du,' % target for target in link_targets]).rstrip(','))
        lines.append(array('IRQ_LINK_BASES',
                           ['0x%xu,' % (link['base'] if link.get('base') is not None
                                        else layout.get('irq_base', 0))
                            for link in target_links]).rstrip(','))
        lines.append('#define IRQ_LINK_STATUS_KINDS ' + ' '.join(
            '"%s",' % link['status_kind'] for link in target_links).rstrip(','))
    # The two-source selection row, when this declaration states one.  Its case
    # selects a global index one past the physical links and addresses every
    # member link's own status/clear cells; the host repeats the member facts
    # here so its pass condition never indexes the physical tables with the
    # synthetic index.  A build without one states IRQ_BOTH_ENABLED 0 and the
    # host compiles the historical single-link path only.
    if f5_both is not None:
        members = f5_both['members']
        def both_array(name, values):
            return '#define %s %s' % (name, ', '.join(values))
        lines += [
            '#define IRQ_BOTH_ENABLED 1',
            '#define IRQ_BOTH_LINK_INDEX %du' % f5_both['index'],
            '#define IRQ_BOTH_MEMBER_COUNT %du' % len(members),
            both_array('IRQ_BOTH_LINKS', ['%du' % member['index'] for member in members]),
            '#define IRQ_BOTH_WORDS %du' % f5_link_word_count(f5_both),
            '#define IRQ_BOTH_TRIGGER_WORDS %du' % sum(
                len(member['trigger_offsets']) for member in members),
            both_array('IRQ_BOTH_TRIGGER_POSITIONS',
                       [str(1 + sum(len(member['trigger_offsets'])
                                    for member in members[:position]))
                        for position in range(len(members))]),
            both_array('IRQ_BOTH_TRIGGER_COUNTS',
                       ['%du' % len(member['trigger_offsets']) for member in members]),
            '#define IRQ_BOTH_STATUS_KINDS ' + ' '.join(
                '"%s",' % member['status_kind'] for member in members).rstrip(','),
            both_array('IRQ_BOTH_TARGETS',
                       ['%du' % member['target_index'] for member in members]),
            both_array('IRQ_BOTH_CAUSE_MASKS',
                       ['0x%08xu' % member['cause_mask'] for member in members]),
            both_array('IRQ_BOTH_CAUSE_DECLARED',
                       ['%du' % int(member['cause_declared']) for member in members]),
            both_array('IRQ_BOTH_CLEAR_DECLARED',
                       ['%du' % int(member['clear'] is not None) for member in members]),
            both_array('IRQ_BOTH_CLEAR_OFFSETS',
                       ['%du' % (member['clear']['offset'] if member['clear'] else 0)
                        for member in members]),
            both_array('IRQ_BOTH_CLEAR_VALUES',
                       ['0x%08xu' % (member['clear']['value'] if member['clear'] else 0)
                        for member in members]),
            both_array('IRQ_BOTH_LEVEL',
                       ['%du' % int(member['trigger'] == 'level') for member in members]),
        ]
    else:
        lines.append('#define IRQ_BOTH_ENABLED 0')
    f5_irq = f5_row['irq'] if f5_row is not None else None
    lines += [f'#define IP_STATUS_OFFSET {f5_irq["status_offset"] if f5_irq else 0}u',
              f'#define IP_TRIGGER_LAST_OFFSET '
              f'{f5_irq["trigger_offsets"][-1] if f5_irq else 0}u',
              f'#define IP_RESULT_ADDRESS {layout["result_f5"]}u',
              f'#define IP_RESULT2_ADDRESS '
              f'{layout.get("result_f5b", layout["result_f5"] + 28)}u',
              f'#define FLAG_ADDRESS {layout["flag"]}u',
              f'#define TRIGGER_COUNT {len(f5_irq["trigger_offsets"]) if f5_irq else 0}u',
              f'#define RAM_BASE {layout["ram_base"]}u', f'#define RAM_SIZE {layout["ram_size"]}u',
              f'#define IP_BASE 0x{layout["ip_targets"][0]["base"]:x}u',
              f'#define IP_SIZE {layout["ip_targets"][0]["size"]}u',
              f'#define SLOT_ADDRESS {layout["slot"]}u',
              f'#define SLOT_RETURN {layout["slot_return"]}u',
              f'#define F1_MAX_WORDS {f1_words}u',
              f'#define F1_ALLOW_SUBWORD {int(config.get("f1_subword", False))}',
              # The program-shape fact the C++ gate mirrors: with this set, an
              # LW/SW may name a register statically proven to hold an in-window
              # data address instead of x18 itself.
              f'#define F1_ALLOW_ADDRESS_FORMS '
              f'{int(config.get("f1_allow_address_forms", False))}',
              # With this set, a strictly-forward B-type branch may appear in the
              # program, and the case's retirement evidence is the in-slot RVFI
              # trace (count, strictly-increasing order and the FNV-1a hash of
              # pc/insn/rd/wdata) rather than "every installed word retired".
              f'#define F1_ALLOW_BRANCHES '
              f'{int(config.get("f1_allow_branches", False))}',
              # With this set, a record word whose bits [1:0] are not 11 is two
              # 16-bit parcels (the low half at pc, the high half at pc + 2), a
              # 32-bit instruction still occupies a whole word, and the case's
              # retirement evidence is the parcel/word trace (prog_retires counts
              # instructions, a parcel steps 2 bytes, and the same FNV-1a trace
              # hash is printed and compared with the Python reference model).
              f'#define F1_ALLOW_COMPRESSED '
              f'{int(config.get("f1_allow_compressed", False))}',
              # With this set, a JAL/JALR with a link destination of x0/x1 and a
              # statically proven, strictly forward target may appear in the
              # program.  JALR is absolute, so its base must be x0 or a register
              # the program provably loads one exact constant into.
              f'#define F1_ALLOW_JUMPS '
              f'{int(config.get("f1_allow_jumps", False))}',
              # With this set, the canonical bounded loop is admitted: an
              # `addi xN, x0, K` init, a body that never writes xN, an
              # `addi xN, xN, -1` step and a `bne xN, x0, head` back edge.  The
              # trip count is static, repeated PCs are legal, and the case's
              # evidence is the reference trace (count and FNV-1a hash), not a
              # strictly increasing PC order.
              f'#define F1_ALLOW_LOOPS '
              f'{int(config.get("f1_allow_loops", False))}',
              # With these set, the compressed parcel subset is widened: the six
              # compressed control transfers (forward, statically proven target)
              # and the four compressed word loads/stores (statically proven
              # in-window base) are admitted.  The default (both 0) keeps the
              # historical safe-ALU-only compressed gate.
              f'#define F1_ALLOW_COMPRESSED_CONTROL '
              f'{int(config.get("f1_allow_compressed_control", False))}',
              f'#define F1_ALLOW_COMPRESSED_MEMORY '
              f'{int(config.get("f1_allow_compressed_memory", False))}',
              # The two declared whole-record F1 modes.  Each is its own module
              # and its own host rule; both are 0 in an RV32 build, so the
              # historical F1 path compiles and runs unchanged.
              f'#define F1_RV64 {int(bool(config.get("f1_rv64", False)))}',
              f'#define F1_TRAP_PROGRAM '
              f'{int(config.get("f1_trap_program") is not None)}',
              f'#define PROGRAM_DATA_WORDS {PROGRAM_DATA_WORDS}u',
              f'#define MAILBOX_ADDRESS {layout["mailbox"]}u',
              f'#define DATA_BASE {layout["data_base"]}u']
    if config.get('f1_trap_program') is not None:
        # The declared trap handler's three RAM cells and the sentinel the host
        # writes before a case.  The addresses are the layout's, so the host and
        # the firmware handler name the same words.
        from myfuzz.fuzz.f1_trap_program import (ENV_CALL_MMODE, TRAP_SENTINEL,
                                                 trap_layout)
        cells = layout if 'trap_cause' in layout else trap_layout(layout)
        declared_words = config['f1_trap_program'].get('words', 2)
        lines += [f'#define F1_TRAP_CAUSE {ENV_CALL_MMODE}u',
                  f'#define F1_TRAP_WORDS {int(declared_words)}u',
                  f'#define TRAP_CAUSE_CELL {cells["trap_cause"]}u',
                  f'#define TRAP_EPC_CELL {cells["trap_epc"]}u',
                  f'#define TRAP_FLAG_CELL {cells["trap_flag"]}u',
                  f'#define TRAP_SENTINEL 0x{TRAP_SENTINEL:08x}u']
    if dma is not None:
        # The declared *observation* expectation is printed beside the measured
        # per-response wait.  A scenario that states no stall bounds declares
        # none; the host then reports the measurement without an expectation.
        observation = (dma.get('response_delay') or {}).get('observation') or {}
        stall_min = observation.get('stall_ticks_min')
        stall_max = observation.get('stall_ticks_max')
        stall_min = 0 if stall_min is None else stall_min
        stall_max = 0 if stall_max is None else stall_max
        lines += [f'#define DMA_CONTROL_SEL {dma["control_select"]}',
                  f'#define DMA_MASTER_SEL {dma["master_select"]}',
                  f'#define DMA_MASTER_SHIFT {dma["master_shift"]}',
                  f'#define DMA_BASE 0x{layout["dma_base"]:x}u',
                  f'#define DMA_SIZE {layout["dma_size"]}u',
                  f'#define DMA_CONTROL_OFFSET {dma["control_offset"]}u',
                  f'#define DMA_SOURCE_OFFSET {dma["source_offset"]}u',
                  f'#define DMA_DESTINATION_OFFSET {dma["destination_offset"]}u',
                  f'#define DMA_LENGTH_OFFSET {dma["length_offset"]}u',
                  f'#define DMA_START_WORD {dma["start_word"]}u',
                  f'#define DMA_BLOCK_WORDS {dma["block_words"]}u',
                  f'#define DMA_SOURCE {layout["dma_source"]}u',
                  f'#define DMA_DESTINATION {layout["dma_destination"]}u',
                  f'#define DMA_RESULT_ADDRESS {layout["result_f6"]}u',
                  f'#define DMA_CTL_BEFORE_ADDRESS {layout["ctl_before"]}u',
                  f'#define DMA_CLEAR_DECLARED {int(dma["clear"] is not None)}',
                  ('#define DMA_CLEAR_MASK 0x%08xu' % dma['clear']['value'])
                  if dma['clear'] is not None else '#define DMA_CLEAR_MASK 0u',
                  f'#define DMA_BUSY_BIT {dma.get("busy_bit", DMA_BUSY_BIT)}u',
                  f'#define DMA_ERR_BIT {dma.get("err_bit", DMA_ERR_BIT)}u',
                  # --- the transfer plan, rendered into the host ---------------
                  # The declared shape is what the C++ host checks its own
                  # observations against; nothing here is inferred per case.
                  f'#define DMA_MASTER_PARTIAL {int(dma["master_byte_enable"]["partial"])}',
                  f'#define DMA_MASTER_BEATS_PER_WORD '
                  f'{dma["master_byte_enable"]["beats_per_word"]}u',
                  f'#define DMA_MASTER_LANE_COUNT '
                  f'{len(dma["master_byte_enable"]["lane_pattern"])}u',
                  f'#define DMA_MASTER_LANES_PER_BEAT '
                  f'{dma["master_byte_enable"]["lanes_per_beat"]}u',
                  f'#define DMA_RESPONSE_DELAY {dma["delay_ticks"]}u',
                  f'#define DMA_STALL_EXPECT_MIN {stall_min}u',
                  f'#define DMA_STALL_EXPECT_MAX {stall_max}u',
                  f'#define DMA_EXPECTED_READS {dma["expected_reads"]}u',
                  f'#define DMA_EXPECTED_WRITES {dma["expected_writes"]}u',
                  # The device, its channel/beat facts and the response pipeline
                  # the host must serve.  DMA_DEVICE_REPORTED decides whether the
                  # case line states that group, and it is 0 exactly for the
                  # historical ZipDMA shape so those lines stay byte-identical.
                  # A hand-built F6 declaration (a caller that states the plan
                  # without the planner behind it) defaults to the historical
                  # single-channel 32-bit shape, which is the case the group is
                  # silent for anyway.
                  f'#define DMA_MASTER_OUTSTANDING {dma["max_outstanding"]}u',
                  f'#define DMA_DEVICE_CHANNELS '
                  f'{(dma.get("device_capabilities") or DMA_DEVICE_FACTS_DEFAULT)["channels"]}u',
                  f'#define DMA_DEVICE_BEAT_BYTES '
                  f'{(dma.get("device_capabilities") or DMA_DEVICE_FACTS_DEFAULT)["beat_bytes"]}u',
                  f'#define DMA_DEVICE_FAMILY "{dma.get("device_family", "zipdma")}"',
                  f'#define DMA_DEVICE_REPORTED {int(dma.get("device_reported", 0))}',
                  f'#define DMA_DEST_SENTINEL 0x{DMA_DESTINATION_SENTINEL:08x}u']
        route = dma.get('route')
        lines += [f'#define DMA_ROUTE_ENABLED {int(route is not None)}']
        if route is not None:
            evidence = route['evidence']
            # The host needs the exact routed target, the fixed route address,
            # the declared target register offset and the readable evidence word.
            # Everything here is the plan's own value; the host never derives a
            # route address, an evidence field or a depth of its own.
            lines += [
                f'#define DMA_ROUTE_TARGET_INDEX {route["target_index"]}u',
                f'#define DMA_ROUTE_TARGET_BASE 0x{route["target_window"]["base"]:x}u',
                f'#define DMA_ROUTE_TARGET_SIZE {route["target_window"]["size"]}u',
                f'#define DMA_ROUTE_ADDRESS 0x{route["address"]:x}u',
                f'#define DMA_ROUTE_OFFSET {route["offset"]}u',
                f'#define DMA_ROUTE_FIXED {int(route["address_mode"] == "fixed")}',
                f'#define DMA_ROUTE_READ {int(route["direction"] == "read")}',
                f'#define DMA_ROUTE_EVIDENCE_OFFSET {evidence["offset"]}u',
                f'#define DMA_ROUTE_EVIDENCE_LOW {evidence["low"] if evidence["low"] is not None else 0}u',
                f'#define DMA_ROUTE_EVIDENCE_HIGH {evidence["high"] if evidence["high"] is not None else 0}u',
                f'#define DMA_ROUTE_EVIDENCE_MASK 0x{evidence["mask"]:08x}u',
                f'#define DMA_ROUTE_EVIDENCE_DEPTH {evidence["depth"] if evidence["depth"] is not None else 0}u',
                f'#define DMA_ROUTE_BEFORE_ADDRESS {layout["route_before"]}u',
                f'#define DMA_ROUTE_AFTER_ADDRESS {layout["route_after"]}u',
                # The read route's CPU destination-readback cells and the beat
                # count the routed direction has to observe.  A write route keeps
                # its historical pushes count; a read route states its reads.
                f'#define DMA_ROUTE_DST_ADDRESS '
                f'{layout["route_dst"] if route["direction"] == "read" else 0}u',
                f'#define DMA_ROUTE_READS {route["reads"]}u',
                f'#define DMA_ROUTE_RESET_BEFORE_CASE {int(route["reset_before_case"])}',
                f'#define DMA_ROUTE_SENTINEL 0x{DMA_ROUTE_SENTINEL:08x}u',
                f'#define DMA_ROUTE_PUSHES {route["pushes"]}u',
                # The declared read shape: a FIFO read pops one entry per beat on
                # a port whose RTL declares that pop; an aperture read walks a
                # declared list of consecutive target addresses.  Both carry the
                # word/level the target itself must return.
                f'#define DMA_ROUTE_FIFO {int(bool(route.get("fifo")))}',
                f'#define DMA_ROUTE_APERTURE {int(bool(route.get("aperture")))}',
                f'#define DMA_ROUTE_LEVEL_BEFORE '
                f'{route["level_before"] if route.get("level_before") is not None else 0}u',
                f'#define DMA_ROUTE_LEVEL_AFTER '
                f'{route["level_after"] if route.get("level_after") is not None else 0}u',
                f'#define DMA_ROUTE_EXPECT_WORD '
                f'{int(bool(route.get("expected_word") is not None))}',
                f'#define DMA_ROUTE_EXPECT_VALUE '
                f'0x{route["expected_word"]:08x}u' if route.get('expected_word')
                is not None else '#define DMA_ROUTE_EXPECT_VALUE 0u',
                f'#define DMA_ROUTE_ERROR_BEAT '
                f'{-1 if route.get("error_beat") is None else route["error_beat"]}',
                # The routed target's own adapter protocol and the protocol trace
                # the host must sample for the routed beat.  The word is the
                # target artifact's protocol (never a build-wide assumption), and
                # DMA_ROUTE_TRACE states whether the host has its own route trace
                # to print: the APB3 route already counts its beat in the APB3
                # block, so its case line keeps exactly the fields it always had
                # and only a TL-UL/Wishbone/AXI4-Lite route adds the trace group.
                '#define DMA_ROUTE_PROTOCOL "%s"' % route['target_protocol'],
                '#define DMA_ROUTE_TRACE %d'
                % int(route['target_protocol'] != 'apb3')]
            if route.get('aperture'):
                # One declared target address per routed beat, so the host can
                # check the sequence the device itself presented instead of
                # trusting the increment flag.
                lines.append('#define DMA_ROUTE_APERTURE_COUNT %du'
                             % len(route['aperture_addresses']))
                lines.append('#define DMA_ROUTE_APERTURE_ADDRESSES(X)' + ''.join(
                    ' \\\n  X(%d, 0x%xu)' % (index, address)
                    for index, address in enumerate(route['aperture_addresses'])))
                lines.append(f'#define DMA_ROUTE_APERTURE_ADDRESS '
                             f'{layout["route_aper"]}u')
            else:
                lines.append('#define DMA_ROUTE_APERTURE_COUNT 0u')
                lines.append('#define DMA_ROUTE_APERTURE_ADDRESSES(X)')
                lines.append('#define DMA_ROUTE_APERTURE_ADDRESS 0u')
        else:
            lines += ['#define DMA_ROUTE_BEFORE_ADDRESS 0u',
                      '#define DMA_ROUTE_AFTER_ADDRESS 0u',
                      '#define DMA_ROUTE_DST_ADDRESS 0u',
                      '#define DMA_ROUTE_APERTURE_ADDRESS 0u',
                      '#define DMA_ROUTE_READS 0u']
    for tag, artifact in (('CPU', cpu), ('IP', targets[0]['artifact']),
                          ('DMA', dma_model)):
        if artifact is None:
            continue
        timing = artifact['plan']['timing']
        lines += [f'#define {tag}_RESET_ASSERT {timing["reset_assert_ticks"]}u',
                  f'#define {tag}_RESET_RELEASE {timing["reset_release_ticks"]}u']
    if count > 1:
        lines += _generated_target_traits(targets, target_fields, fixed_rows,
                                          observed_irq, protocol, identifier)
    return '\n'.join(lines) + '\n'


def _generated_target_traits(targets, target_fields, fixed_rows, observed_irq,
                             protocol, identifier):
    """The per-target C++ port traits a multi-target header declares.

    Each pin the host touches is named by the artifact's own runtime row, so the
    host loop has no CPU x IP branch and no device name: swapping one target's
    profile changes only this generated text.  The trait interface is the one the
    host's legacy fallback already implements with the flat macros, so the same
    loop drives a one-target and an N-target build.

    ``protocol`` is the build's one protocol (``None`` for a mixed build).  The
    protocol facts themselves always come from each target's own row, so a mixed
    build emits one target's APB3 taps and the next target's AXI4-Lite taps in
    the same header.  ``axi4lite``/``apb`` are compile-time constants the host
    dispatches on, which is what keeps a per-case decision (which target did this
    transfer go to) separate from a per-build decision (which protocol).
    """
    lines = ['namespace myfuzz_ip {', 'template <unsigned I> struct IpTarget;']
    for row in targets:
        index = row['index']
        fields = target_fields[index]
        row_protocol = row['protocol']
        lines.append('template <> struct IpTarget<%d> {' % index)
        lines.append('  using Model = IP_MODEL_%d;' % index)
        # This target's own protocol: the harness reads it from here, never from
        # the build-wide macro (which a mixed build leaves neutral).
        lines.append('  static constexpr bool apb = %s;' %
                     ('true' if row_protocol == 'apb3' else 'false'))
        lines.append('  static constexpr bool axi4lite = %s;' %
                     ('true' if row_protocol == 'axi4-lite' else 'false'))
        lines.append('  static constexpr bool wishbone = %s;' %
                     ('true' if row_protocol == 'wishbone' else 'false'))
        lines.append('  static constexpr bool tlul = %s;' %
                     ('true' if row_protocol == 'tl-ul' else 'false'))
        lines.append('  static constexpr bool ahb = %s;' %
                     ('true' if row_protocol == 'ahb-lite' else 'false'))
        lines.append('  static constexpr bool apb_error_sampled = %s;' %
                     ('true' if 'IP_TRACE_PSLVERR' in fields else 'false'))
        lines.append('  static constexpr const char *protocol = "%s";' % row_protocol)
        lines.append('  static constexpr const char *name = TARGET_NAME_%d;' % index)
        lines.append('  static constexpr const char *bridge = TARGET_BRIDGE_%d;' % index)
        lines.append('  static constexpr const char *bus_channel = TARGET_BUS_CHANNEL_%d;'
                     % index)
        # The declared pin constants this target's own request builder pinned, so
        # a mixed summary can state each target's count instead of the first one's.
        lines.append('  static constexpr unsigned fixed_input_count = '
                     'IP_FIXED_INPUT_COUNT_%d;' % index)
        lines.append('  static constexpr uint32_t base = 0x%xu;' % row['window']['base'])
        lines.append('  static constexpr uint32_t size = %du;' % row['window']['size'])
        lines.append('  static constexpr unsigned reset_assert = %du;' % row['reset_assert'])
        lines.append('  static constexpr unsigned reset_release = %du;' % row['reset_release'])
        lines.append('  static constexpr bool has_f5 = %s;' % ('true' if row.get('irq') else 'false'))
        observed = observed_irq[index]
        lines.append('  static constexpr bool has_irq = %s;' % ('true' if observed else 'false'))
        lines += [
            '  static void clock(Model &m, int level) { m.clk = level; }',
            '  static void set_reset(Model &m, int level) { m.reset = level; }',
            '  static void eval(Model &m) { m.eval(); }',
            '  static void finalize(Model &m) { m.final(); }',
            '  static bool events_pending(Model &m) { return m.eventsPending(); }',
            # The time of this model's earliest scheduled event, read only when
            # events_pending() is true.  A timed model schedules its own events;
            # an untimed one never has any, so this stays unused for it.
            '  static uint64_t next_time_slot(Model &m) { return m.nextTimeSlot(); }',
            '  static void fixed_inputs(Model &m) {',
            '#if IP_FIXED_INPUT_COUNT_%d > 0' % index,
            '#define MYFUZZ_FIXED_INPUT_%d(name, value) m.name = (value);' % index,
            '    IP_FIXED_INPUTS_%d(MYFUZZ_FIXED_INPUT_%d)' % (index, index),
            '#undef MYFUZZ_FIXED_INPUT_%d' % index,
            '#endif',
            '  }',
            '  static void drive_request(Model &m, bool valid, bool write,',
            '                            uint32_t address, uint32_t value, unsigned be) {',
            '    m.%s = valid;' % fields['IP_REQ_VALID'],
            '    m.%s = write;' % fields['IP_REQ_WRITE'],
            '    m.%s = address;' % fields['IP_REQ_ADDR'],
            '    m.%s = value;' % fields['IP_REQ_WDATA'],
            '    m.%s = be;' % fields['IP_REQ_BE'],
            '    m.%s = 1;' % fields['IP_RSP_READY'],
            '  }',
            '  static bool request_ready(const Model &m) { return m.%s; }' % fields['IP_REQ_READY'],
            '  static bool response_valid(const Model &m) { return m.%s; }' % fields['IP_RSP_VALID'],
            '  static uint32_t response_rdata(const Model &m) { return m.%s; }' % fields['IP_RSP_RDATA'],
            '  static bool response_error(const Model &m) { return m.%s; }' % fields['IP_RSP_ERROR']]
        if observed:
            lines.append('  static uint64_t irq_value(const Model &m) '
                         '{ return uint64_t(m.%s); }' % observed['runtime_name'])
        if row_protocol == 'apb3':
            lines += [
                '  static bool apb_sel(const Model &m) { return m.%s; }' % fields['IP_TRACE_PSEL'],
                '  static bool apb_enable(const Model &m) { return m.%s; }' % fields['IP_TRACE_PENABLE'],
                '  static bool apb_ready(const Model &m) { return m.%s; }' % fields['IP_TRACE_PREADY'],
                '  static bool apb_write(const Model &m) { return m.%s; }' % fields['IP_TRACE_PWRITE'],
                '  static uint32_t apb_addr(const Model &m) { return m.%s; }' % fields['IP_TRACE_PADDR'],
                '  static uint32_t apb_wdata(const Model &m) { return m.%s; }' % fields['IP_TRACE_PWDATA'],
                '  static uint32_t apb_rdata(const Model &m) { return m.%s; }' % fields['IP_TRACE_PRDATA']]
            if 'IP_TRACE_PSLVERR' in fields:
                lines.append('  static bool apb_error(const Model &m) { return m.%s; }'
                             % fields['IP_TRACE_PSLVERR'])
        elif row_protocol == 'wishbone':
            # The classic handshake this target's own slave port carried.  The
            # accessors are named after the roles the trace declares, so the host
            # samples exactly the pins the generated model exposes.
            for role, name, kind in (
                    ('cyc', 'CYC', 'bool'), ('stb', 'STB', 'bool'),
                    ('ack', 'ACK', 'bool'), ('we', 'WE', 'bool'),
                    ('adr', 'ADR', 'uint32_t'), ('dat_w', 'DAT_W', 'uint32_t'),
                    ('dat_r', 'DAT_R', 'uint32_t'), ('sel', 'SEL', 'unsigned'),
                    ('stall', 'STALL', 'bool')):
                if 'IP_TRACE_' + name not in fields:
                    continue
                expression = 'm.%s' % fields['IP_TRACE_' + name]
                if kind == 'bool':
                    expression = 'bool(%s)' % expression
                lines.append('  static %s wb_%s(const Model &m) { return %s; }' % (
                    kind, role, expression))
            # Whether this target's own trace carries the optional stall pin.
            # The host guards its stall sample with this per-target constant (the
            # build-wide header cannot answer it for a mixed build), and the
            # fallback specialization below states the same constant from
            # IP_TRACE_STALL, so both header shapes drive the same loop.
            lines.append('  static constexpr bool wb_stall_sampled = %s;' %
                         ('true' if 'IP_TRACE_STALL' in fields else 'false'))
        elif row_protocol == 'tl-ul':
            # The A channel the request was accepted on and the D channel the
            # response completed on, from this target's own taps.
            for role, name, kind in (
                    ('a_valid', 'A_VALID', 'bool'), ('a_ready', 'A_READY', 'bool'),
                    ('a_opcode', 'A_OPCODE', 'unsigned'),
                    ('a_address', 'A_ADDRESS', 'uint32_t'),
                    ('a_mask', 'A_MASK', 'unsigned'),
                    ('a_data', 'A_DATA', 'uint32_t'),
                    ('d_valid', 'D_VALID', 'bool'), ('d_ready', 'D_READY', 'bool'),
                    ('d_data', 'D_DATA', 'uint32_t'), ('d_error', 'D_ERROR', 'bool')):
                expression = 'm.%s' % fields['IP_TRACE_' + name]
                if kind == 'bool':
                    expression = 'bool(%s)' % expression
                lines.append('  static %s tlul_%s(const Model &m) { return %s; }' % (
                    kind, role, expression))
        elif row_protocol == 'ahb-lite':
            # The slave port's own two phases.  The accessors are named after the
            # roles this target's trace declares, so the host samples exactly the
            # pins the generated model exposes: an address phase (hsel/htrans/
            # haddr/hwrite/hsize/hreadyin) and a data phase (hwdata or hrdata/
            # hresp, completed by hreadyout).
            for role, name, kind in (
                    ('hsel', 'HSEL', 'bool'), ('htrans', 'HTRANS', 'unsigned'),
                    ('haddr', 'HADDR', 'uint32_t'), ('hwrite', 'HWRITE', 'bool'),
                    ('hsize', 'HSIZE', 'unsigned'),
                    ('hwdata', 'HWDATA', 'uint32_t'),
                    ('hreadyin', 'HREADYIN', 'bool'),
                    ('hreadyout', 'HREADYOUT', 'bool'),
                    ('hrdata', 'HRDATA', 'uint32_t'), ('hresp', 'HRESP', 'bool')):
                expression = 'm.%s' % fields['IP_TRACE_' + name]
                if kind == 'bool':
                    expression = 'bool(%s)' % expression
                lines.append('  static %s ahb_%s(const Model &m) { return %s; }' % (
                    kind, role, expression))
        else:
            for role, name, kind in (
                    ('awvalid', 'AWVALID', 'bool'), ('awready', 'AWREADY', 'bool'),
                    ('awaddr', 'AWADDR', 'uint32_t'), ('awprot', 'AWPROT', 'unsigned'),
                    ('wvalid', 'WVALID', 'bool'), ('wready', 'WREADY', 'bool'),
                    ('wdata', 'WDATA', 'uint32_t'), ('wstrb', 'WSTRB', 'unsigned'),
                    ('bvalid', 'BVALID', 'bool'), ('bready', 'BREADY', 'bool'),
                    ('bresp', 'BRESP', 'unsigned'),
                    ('arvalid', 'ARVALID', 'bool'), ('arready', 'ARREADY', 'bool'),
                    ('araddr', 'ARADDR', 'uint32_t'), ('arprot', 'ARPROT', 'unsigned'),
                    ('rvalid', 'RVALID', 'bool'), ('rready', 'RREADY', 'bool'),
                    ('rdata', 'RDATA', 'uint32_t'), ('rresp', 'RRESP', 'unsigned')):
                expression = 'm.%s' % fields['IP_TRACE_' + name]
                if kind == 'bool':
                    expression = 'bool(%s)' % expression
                lines.append('  static %s axi_%s(const Model &m) { return %s; }' % (
                    kind, role, expression))
        lines.append('};')
    lines.append('}  // namespace myfuzz_ip')
    lines.append('#define IP_TARGETS_TRAITS 1')
    return lines


# ---------------------------------------------------------------------------
# Run log
# ---------------------------------------------------------------------------
def _value(key, text):
    if text.startswith('0x'):
        return int(text, 16)
    if key.endswith('seconds'):
        try:
            return float(text)
        except ValueError:
            raise ValueError('invalid seconds value: ' + text)
    if text.isdigit() or (text.startswith('-') and text[1:].isdigit()):
        return int(text)
    return text


def _pairs(tokens):
    if len(tokens) % 2:
        raise ValueError('observation fields must be key/value pairs')
    fields = {}
    for position in range(0, len(tokens), 2):
        key = tokens[position]
        if key in fields:
            raise ValueError('duplicate observation field: ' + key)
        fields[key] = _value(key, tokens[position + 1])
    return fields


def parse_case_line(line, *, flows):
    """Parse one `case <index> <status> <key> <value> ...` line."""
    tokens = line.split()
    if len(tokens) < 5 or tokens[0] != 'case':
        raise ValueError('not a case line')
    try:
        index = int(tokens[1])
    except ValueError:
        raise ValueError('case index is not an integer: ' + tokens[1])
    if tokens[2] not in ('observations_passed', 'failed'):
        raise ValueError('unsupported case status: ' + tokens[2])
    fields = _pairs(tokens[3:])
    if 'flow' not in fields or fields['flow'] not in flows:
        raise ValueError('case line lacks a supported flow tag')
    fields['index'] = index
    fields['status'] = tokens[2]
    return fields


def parse_summary_line(line):
    tokens = line.split()
    if len(tokens) < 3 or tokens[0] != 'summary':
        raise ValueError('not a summary line')
    fields = _pairs(tokens[2:])
    fields['status'] = tokens[1]
    return fields


EVENT_KINDS = ('ifetch', 'rvfi', 'trap', 'bus_error', 'dma_done', 'axi')
#: The CSR witness lines a trap-capable CPU prints.  They are not a separate
#: event family (the per-case facts are on the case line), so they are parsed and
#: collected beside the counted families instead of inside the counts dict.
CSR_EVENT_KINDS = ('csr_trap', 'csr_mepc')
# The channels a sampled bus error can belong to.  ``axi`` is the AXI4-Lite
# target's own channel: its BRESP/RRESP pins are sampled, but a slave that has
# only ever driven OKAY is reported as unknown, never as a clean bus.  ``wb`` is
# the single Wishbone master of a Wishbone-CPU build (or a Wishbone target's own
# sampled error channel, when its profile declared one); ``tlul`` is a TL-UL
# target's sampled ``d_error``.
#: ``ahb`` is the AHB-Lite manager's response-error input, which this host drives
#: and therefore states as unknown rather than as a covered channel.
BUS_CHANNELS = ('apb', 'axi', 'obi_i', 'obi_d', 'mwb', 'wb', 'tlul', 'ahb')


def _decimal(text, what):
    if not text.isdigit():
        raise ValueError(what + ' is not a decimal number: ' + text)
    return int(text)


def _hex_word(text, what):
    if not text.startswith('0x') or len(text) < 3:
        raise ValueError(what + ' is not a hexadecimal word: ' + text)
    try:
        return int(text, 16)
    except ValueError:
        raise ValueError(what + ' is not a hexadecimal word: ' + text)


def parse_event_line(line):
    """Parse one event line of the run log; every other line is not an event.

    Shapes printed by the C++ host:

    * ``ifetch <tick> <ia> <word>`` - one accepted instruction fetch beat;
    * ``rvfi <tick> <order> <rd_addr> <rd_wdata>`` - one RVFI-valid retirement;
    * ``trap <tick> pc <pc> insn <insn> cause <cause>`` - a trapped retirement;
    * ``bus_error <tick> <channel> <addr>`` or ``bus_error unknown <channel>``;
    * ``dma_done <tick>`` - the derived DMA completion (see the summary);
    * ``axi <channel> <tick> ...`` - one completed AXI4-Lite channel handshake,
      with the payload that channel carried (``aw <tick> <addr> prot <n>``,
      ``w <tick> <data> strb <n>``, ``b <tick> resp <n>``,
      ``ar <tick> <addr> prot <n>``, ``r <tick> <data> resp <n>``).
    """
    if type(line) is not str or not line:
        raise ValueError('one event line is required')
    tokens = line.split()
    kind = tokens[0]
    if kind == 'ifetch':
        if len(tokens) != 4:
            raise ValueError('an ifetch line needs one tick, address and word')
        return dict(kind=kind, tick=_decimal(tokens[1], 'ifetch tick'),
                    address=_hex_word(tokens[2], 'ifetch address'),
                    word=_hex_word(tokens[3], 'ifetch word'))
    if kind == 'rvfi':
        if len(tokens) != 5:
            raise ValueError('an rvfi line needs one tick, order, rd_addr and rd_wdata')
        return dict(kind=kind, tick=_decimal(tokens[1], 'rvfi tick'),
                    order=_decimal(tokens[2], 'rvfi order'),
                    rd_addr=_decimal(tokens[3], 'rvfi rd_addr'),
                    rd_wdata=_hex_word(tokens[4], 'rvfi rd_wdata'))
    if kind == 'trap':
        # Two shapes: the historical ``cause unknown`` line (a CPU whose RVFI
        # face states no cause) and the witnessed line a trap-capable face
        # prints, which adds the record's own ``intr`` word and its ``mode``.
        if len(tokens) not in (8, 12) or tokens[2] != 'pc' or tokens[4] != 'insn' \
                or tokens[6] != 'cause':
            raise ValueError('a trap line needs pc, insn and cause')
        event = dict(kind=kind, tick=_decimal(tokens[1], 'trap tick'),
                     pc=_hex_word(tokens[3], 'trap pc'),
                     insn=_hex_word(tokens[5], 'trap insn'), cause=tokens[7],
                     intr=None, mode=None)
        if len(tokens) == 12:
            if tokens[8] != 'intr' or tokens[10] != 'mode':
                raise ValueError('a witnessed trap line needs intr and mode')
            event['intr'] = _hex_word(tokens[9], 'trap intr')
            event['mode'] = _decimal(tokens[11], 'trap mode')
        return event
    if kind == 'csr_trap':
        # The scoreboard's registered CSR snapshot at the trap entry.
        if (len(tokens) != 12 or tokens[2] != 'mcause' or tokens[4] != 'mepc'
                or tokens[6] != 'mtval' or tokens[8] != 'mtvec'
                or tokens[10] != 'mstatus'):
            raise ValueError('a csr_trap line needs mcause, mepc, mtval, mtvec '
                             'and mstatus')
        return dict(kind=kind, tick=_decimal(tokens[1], 'csr_trap tick'),
                    mcause=_hex_word(tokens[3], 'csr_trap mcause'),
                    mepc=_hex_word(tokens[5], 'csr_trap mepc'),
                    mtval=_hex_word(tokens[7], 'csr_trap mtval'),
                    mtvec=_hex_word(tokens[9], 'csr_trap mtvec'),
                    mstatus=_hex_word(tokens[11], 'csr_trap mstatus'))
    if kind == 'csr_mepc':
        # A later change of the readback while the trap cause stands: the
        # handler's own CSRRS write to mepc.
        if len(tokens) != 6 or tokens[2] != 'mcause' or tokens[4] != 'mepc':
            raise ValueError('a csr_mepc line needs mcause and mepc')
        return dict(kind=kind, tick=_decimal(tokens[1], 'csr_mepc tick'),
                    mcause=_hex_word(tokens[3], 'csr_mepc mcause'),
                    mepc=_hex_word(tokens[5], 'csr_mepc mepc'),
                    mtval=None, mtvec=None, mstatus=None)
    if kind == 'bus_error':
        if len(tokens) == 3 and tokens[1] == 'unknown':
            if tokens[2] not in BUS_CHANNELS:
                raise ValueError('unsupported bus error channel: ' + tokens[2])
            return dict(kind=kind, tick=None, channel=tokens[2], address=None)
        if len(tokens) != 4 or tokens[2] not in BUS_CHANNELS:
            raise ValueError('a bus_error line needs a tick, a channel and an address')
        return dict(kind=kind, tick=_decimal(tokens[1], 'bus_error tick'),
                    channel=tokens[2], address=_hex_word(tokens[3], 'bus_error address'))
    if kind == 'dma_done':
        if len(tokens) != 2:
            raise ValueError('a dma_done line needs exactly one tick')
        return dict(kind=kind, tick=_decimal(tokens[1], 'dma_done tick'))
    if kind == 'axi':
        return _axi_event(tokens)
    raise ValueError('not an event line: ' + kind)


def _axi_event(tokens):
    """One AXI4-Lite channel handshake, in the exact shape the host prints.

    ``aw``/``ar`` carry an address and its protection bits, ``w`` an address-free
    data beat and its strobes, ``b`` only a response code and ``r`` a data word
    and a response code.  Each channel has its own shape, so each is checked.
    """
    if len(tokens) < 3:
        raise ValueError('an axi line needs a channel and a tick')
    channel = tokens[1]
    event = dict(kind='axi', channel=channel, tick=_decimal(tokens[2], 'axi tick'),
                 address=None, data=None, prot=None, strb=None, resp=None)
    if channel in ('aw', 'ar'):
        if len(tokens) != 6 or tokens[4] != 'prot':
            raise ValueError('an axi ' + channel + ' line needs an address and prot bits')
        event['address'] = _hex_word(tokens[3], 'axi ' + channel + ' address')
        event['prot'] = _decimal(tokens[5], 'axi ' + channel + ' prot')
        return event
    if channel == 'w':
        if len(tokens) != 6 or tokens[4] != 'strb':
            raise ValueError('an axi w line needs its data and strobes')
        event['data'] = _hex_word(tokens[3], 'axi w data')
        event['strb'] = _decimal(tokens[5], 'axi w strb')
        return event
    if channel == 'b':
        if len(tokens) != 5 or tokens[3] != 'resp':
            raise ValueError('an axi b line needs its response code')
        event['resp'] = _decimal(tokens[4], 'axi b resp')
        return event
    if channel == 'r':
        if len(tokens) != 6 or tokens[4] != 'resp':
            raise ValueError('an axi r line needs its data and response code')
        event['data'] = _hex_word(tokens[3], 'axi r data')
        event['resp'] = _decimal(tokens[5], 'axi r resp')
        return event
    raise ValueError('unsupported axi channel: ' + channel)


def _zero_counts():
    return {kind: 0 for kind in EVENT_KINDS}


def summarize_events(text):
    """Count the event lines of one run log and derive their tri-state evidence.

    Every number here comes from the log: counts and the tri-state are computed,
    never copied from a constant.  A per-case bucket collects the events printed
    before that case's own line, and a ``bus_error unknown <channel>`` line is a
    declaration about a channel, not an occurrence, so it never enters a bucket.
    """
    if type(text) is not str:
        raise ValueError('run log text required')
    counts, declarations, buckets = _zero_counts(), _zero_counts(), [_zero_counts()]
    traps, bus_errors, dma_done, rvfi, csr_witness = [], [], [], [], []
    unknown_channels = set()
    # The CPU's own retirement line is not one of the counted event families
    # (``retire`` is not an EVENT_KINDS member and never joins ``counts``), but
    # it is what proves the retirement face produced records when the CPU
    # exports no RVFI writeback pair to print an ``rvfi`` line from.  A case
    # line whose ``traps`` word is ``unknown`` states that the CPU has no trap
    # bit, so that family's evidence is unobservable rather than missing.
    retirements = 0
    traps_unobservable = False
    for line in text.splitlines():
        tokens = line.split()
        if not tokens:
            continue
        if tokens[0] == 'retire':
            if len(tokens) == 4:
                retirements += 1
            continue
        if tokens[0] == 'case':
            if any(tokens[index] == 'traps' and tokens[index + 1] == 'unknown'
                   for index in range(len(tokens) - 1)):
                traps_unobservable = True
            buckets.append(_zero_counts())
            continue
        if tokens[0] in CSR_EVENT_KINDS:
            # The trap-capable CPU's registered CSR readback: parsed and kept
            # beside the counted families, not folded into them, so the event
            # families a build without that witness prints are unchanged.
            csr_witness.append(parse_event_line(line))
            continue
        if tokens[0] not in EVENT_KINDS:
            continue
        event = parse_event_line(line)
        counts[event['kind']] += 1
        if event['kind'] == 'trap':
            traps.append(event)
        elif event['kind'] == 'bus_error':
            bus_errors.append(event)
            if event['tick'] is None:
                unknown_channels.add(event['channel'])
                declarations['bus_error'] += 1
                continue
        elif event['kind'] == 'dma_done':
            dma_done.append(event)
        elif event['kind'] == 'rvfi':
            rvfi.append(event)
        buckets[-1][event['kind']] += 1
    per_case, trailing = buckets[:-1], buckets[-1]
    writebacks = sum(1 for row in rvfi if row['rd_addr'])
    monotonic = all(older['order'] < newer['order']
                    for older, newer in zip(rvfi, rvfi[1:]))
    return dict(
        lines=sum(counts.values()), counts=counts, per_case=per_case,
        declarations=declarations, trailing=trailing,
        traps=traps, bus_errors=bus_errors, dma_done=dma_done, rvfi=rvfi,
        csr_witness=csr_witness,
        # The retirement lines, kept beside the counted families (they are not
        # one of them) so a CPU that prints no ``rvfi`` pair still states that
        # retirements were observed.
        retirements=retirements,
        rvfi_orders=[row['order'] for row in rvfi], rvfi_writebacks=writebacks,
        rvfi_order_monotonic=monotonic,
        bus_error_unknown_channels=sorted(unknown_channels),
        evidence=dict(
            ifetch='observed' if counts['ifetch'] else 'missing',
            # The retirement face is either the RVFI order/writeback pair or the
            # bare ``retire`` line the host prints from the same validity.
            rvfi=('observed' if counts['rvfi'] or retirements else 'missing'),
            rvfi_writeback='observed' if writebacks else 'missing',
            # A trap belongs to a retirement: with no retirement the trap signal
            # was never sampled, so its evidence is missing, not "no trap".  A
            # CPU whose model exports no trap bit states that in its case lines,
            # and then the family is unobservable rather than missing.
            trap=('unobservable' if traps_unobservable else
                  'observed' if counts['rvfi'] or retirements else 'missing'),
            dma_done='observed' if dma_done else 'missing',
            # The AXI4-Lite channel events exist only for an AXI4-Lite target;
            # an APB3 build prints none, so its evidence word is missing, not
            # "no handshake happened".
            axi='observed' if counts['axi'] else 'missing'))


def event_document(events, summary):
    """The event layer of one run, with the tri-state of every event family.

    Counts come from the run log; the per-channel bus error word merges the
    log's ``bus_error unknown <channel>`` lines with the summary's per-channel
    word.  ``derived`` is computed from the log alone, ``stated`` is what the
    host's summary claims, and the two are compared instead of trusted.
    """
    if events is None or summary is None:
        raise ValueError('an event document needs the parsed log and its summary')
    channels = {}
    for channel in BUS_CHANNELS:
        if channel in events['bus_error_unknown_channels']:
            channels[channel] = 'unknown'
        elif summary.get('bus_error_' + channel) == 'observed':
            channels[channel] = 'observed'
        else:
            channels[channel] = 'missing'
    unknown = [name for name, word in channels.items() if word == 'unknown']
    derived = dict(events['evidence'])
    derived['expanded_insn'] = 'observed' if summary.get('expanded_insn_events') else 'missing'
    derived['irq_cause'] = 'observed' if summary.get('irq_cause') == 'observed' else 'unknown'
    derived['dma_busy'] = 'observed' if summary.get('dma_busy_high_reads') else 'missing'
    # The log's channel events and the host's own channel counters are two
    # statements about the same handshakes; they are compared, not trusted.
    channel_handshakes = sum(summary.get(key) for key in
                             ('axi_aw', 'axi_w', 'axi_b', 'axi_ar', 'axi_r')
                             if isinstance(summary.get(key), int))
    derived['bus_error'] = 'unknown' if unknown else (
        'observed' if all(word == 'observed' for word in channels.values()) else 'missing')
    stated = dict(
        ifetch=summary.get('ifetch_evidence', 'missing'),
        rvfi=summary.get('retirement_evidence', 'missing'),
        rvfi_writeback=summary.get('rvfi_writeback_evidence', 'missing'),
        trap=summary.get('trap_evidence', 'missing'),
        expanded_insn=summary.get('expanded_insn_evidence', 'missing'),
        irq_cause=summary.get('irq_cause', 'unknown'),
        dma_done=summary.get('dma_done_evidence', 'missing'),
        dma_busy=summary.get('dma_busy_evidence', 'missing'),
        axi='observed' if channel_handshakes else 'missing',
        bus_error=summary.get('bus_error', 'unknown'))
    return dict(
        lines=events['lines'], counts=events['counts'], per_case=events['per_case'],
        declarations=events['declarations'], trailing=events['trailing'],
        traps=events['traps'], bus_errors=events['bus_errors'],
        dma_done=events['dma_done'], rvfi_orders=events['rvfi_orders'],
        rvfi_writebacks=events['rvfi_writebacks'],
        rvfi_order_monotonic=events['rvfi_order_monotonic'],
        bus_error_unknown_channels=events['bus_error_unknown_channels'],
        dma_done_derivation=summary.get('dma_done_derivation', 'missing'),
        evidence=dict(derived, bus_error_channels=channels),
        stated=stated,
        conflicts=sorted(name for name in derived if name != 'bus_error_channels'
                         and derived[name] != stated.get(name)))


def parse_run_log(text, *, flows):
    """Read the compact case/summary lines; anything else is not interpreted."""
    if type(text) is not str:
        raise ValueError('run log text required')
    cases, summary, installed = [], None, []
    for line in text.splitlines():
        if line.startswith('case '):
            cases.append(parse_case_line(line, flows=flows))
        elif line.startswith('summary '):
            if summary is not None:
                raise ValueError('duplicate summary line')
            summary = parse_summary_line(line)
        elif line.startswith('CASE_INSTALLED '):
            installed.append(int(line.split()[1]))
        elif line.startswith('NEED_RECORD '):
            continue
    if summary is None:
        raise ValueError('run log has no summary line')
    return dict(cases=cases, summary=summary, installed=installed)


#: Every outcome class a case can receive.  ``not_triggered`` is an expected
#: exploration outcome (the declared trigger sequence ran but the random input
#: did not make the device raise an interrupt); it is not a hardware defect.
FAILURE_CLASSES = ('passed', 'not_triggered', 'wait_budget_exceeded',
                   'protocol_error', 'device_anomaly', 'execution_exception',
                   'execution_anomaly', 'state_contamination',
                   'level_irq_left_asserted', 'observation_mismatch',
                   'declared_error_injected')
#: Classes whose failures are expected random-input behaviour, not findings.
#: ``declared_error_injected`` is expected in the same sense: the case ran a
#: declared host injection and the device behaved as the declaration said, so the
#: observed ERR is the injection's own consequence, not a finding.
EXPECTED_FAILURE_CLASSES = ('not_triggered', 'declared_error_injected')
#: The severity attached to each class, so a report can keep them apart.
FAILURE_SEVERITY = {'passed': 'none', 'not_triggered': 'expected',
                    'wait_budget_exceeded': 'limit', 'protocol_error': 'anomaly',
                    'device_anomaly': 'anomaly', 'execution_exception': 'anomaly',
                    'execution_anomaly': 'anomaly', 'state_contamination': 'anomaly',
                    'level_irq_left_asserted': 'anomaly',
                    'observation_mismatch': 'anomaly',
                    'declared_error_injected': 'expected'}


def _case_int(case, key):
    value = case.get(key) if isinstance(case, dict) else None
    return value if type(value) is int else None


def classify_case(case):
    """Classify one parsed case line from the facts it actually carries.

    The categories separate four things the fuzz loop must not conflate:
    a random input that simply did not trigger the device (expected), a bounded
    wait that expired, a protocol/bus error, and a device/execution anomaly.
    """
    if not isinstance(case, dict):
        raise ValueError('one parsed case line is required')
    flow = case.get('flow')
    if flow not in ('F1', 'F2', 'F3', 'F4', 'F5', 'F6'):
        raise ValueError('unsupported case flow: ' + str(flow))
    if flow in ('F5', 'F6') and _case_int(case, 'level_stuck') == 1:
        # The host reported the storm itself: a declared level link was still
        # asserted after the CPU re-entered the handler past the take limit, and
        # the devices were reset (the case line keeps both facts).  This is a
        # device/source finding, never an expected random-input outcome.
        return dict(failure_class='level_irq_left_asserted', severity='anomaly',
                    expected=False,
                    detail='a declared level IRQ was still asserted after the handler; '
                           'the CPU stormed it and only the devices were reset')
    status = case.get('status')
    # A declared error injection is its own outcome class: the case passed every
    # observation its declaration made possible, and the injected response is a
    # fact of the case, not a defect.  It is never reported as a plain pass and
    # never as an anomaly, so a batch summary keeps it apart from both.
    if _case_int(case, 'dma_error_injected') == 1:
        return dict(failure_class='declared_error_injected', severity='expected',
                    expected=True,
                    detail='the declared host-injected DMA error response ran on '
                           'beat %s and the device reported its own ERR status bit'
                           % case.get('dma_error_beat'))
    if status == 'observations_passed':
        return dict(failure_class='passed', severity='none', expected=False,
                    detail='case passed its declared observations')
    traps = _case_int(case, 'traps') or 0
    if traps:
        return dict(failure_class='execution_exception', severity='anomaly',
                    expected=False,
                    detail='the CPU retired ' + str(traps) +
                           ' trap(s); the RVFI ports carry no cause')
    errors = _case_int(case, 'bus_errors') or _case_int(case, 'target_errors') or 0
    if errors:
        return dict(failure_class='protocol_error', severity='anomaly',
                    expected=False,
                    detail='the target/bus reported ' + str(errors) + ' error response(s)')
    response = case.get('target_resp')
    if type(response) is int and response != 0:
        return dict(failure_class='protocol_error', severity='anomaly', expected=False,
                    detail='the AXI4-Lite response code is ' + str(response) +
                           ', not OKAY')
    if flow not in ('F5', 'F6') and (_case_int(case, 'irq_takes') or 0) > 0:
        return dict(failure_class='state_contamination', severity='anomaly',
                    expected=False,
                    detail='an interrupt was taken during a flow that declares none; '
                           'a previous case left a pending interrupt or handler state')
    target_reads = ((_case_int(case, 'target_reads') or
                     _case_int(case, 'apb_reads')) or 0)
    if flow == 'F4' and target_reads > 0:
        return dict(failure_class='state_contamination', severity='anomaly',
                    expected=False,
                    detail='a target read completed during a store-only case; a pending '
                           'interrupt handler likely ran inside this case')
    timeout = _case_int(case, 'wait_timeout') == 1
    if timeout and flow in ('F5', 'F6'):
        edges = _case_int(case, 'irq_edges') or 0
        takes = _case_int(case, 'irq_takes') or 0
        if edges == 0:
            return dict(failure_class='not_triggered', severity='expected',
                        expected=True,
                        detail='the declared trigger sequence ran, but the device never '
                               'asserted its interrupt; the bounded wait expired')
        if takes == 0:
            return dict(failure_class='wait_budget_exceeded', severity='limit',
                        expected=False,
                        detail='the device asserted its interrupt, but the CPU did not '
                               'take it within the bounded wait')
        return dict(failure_class='wait_budget_exceeded', severity='limit',
                    expected=False,
                    detail='the CPU took the interrupt, but the handler did not complete '
                           'within the bounded wait')
    takes = _case_int(case, 'irq_takes') or 0
    if flow in ('F5', 'F6') and takes > 1:
        return dict(failure_class='state_contamination', severity='anomaly',
                    expected=False,
                    detail='more than one interrupt was accepted in this case; a level '
                           'or duplicate source from an earlier case was likely taken')
    if flow == 'F5':
        if takes and _case_int(case, 'isr_flag') != 1:
            return dict(failure_class='device_anomaly', severity='anomaly',
                        expected=False,
                        detail='the CPU took the interrupt, but the handler did not set '
                               'its completion flag')
        read_data = _case_int(case, 'apb_read_data')
        if read_data is None:
            read_data = _case_int(case, 'target_read_data')
        result = _case_int(case, 'isr_result')
        if read_data is not None and result is not None and result != read_data:
            return dict(failure_class='device_anomaly', severity='anomaly',
                        expected=False,
                        detail='the handler stored a value that differs from the declared '
                               'status word it read')
        return dict(failure_class='observation_mismatch', severity='anomaly',
                    expected=False,
                    detail='F5 completed without the declared trigger/read/IRQ facts')
    if flow == 'F6':
        if takes and _case_int(case, 'isr_flag') != 1:
            return dict(failure_class='device_anomaly', severity='anomaly',
                        expected=False,
                        detail='the CPU took the DMA completion interrupt, but the handler '
                               'did not set its completion flag')
        busy = _case_int(case, 'busy_after')
        error = _case_int(case, 'err_after')
        if busy not in (None, 0) or error not in (None, 0):
            return dict(failure_class='device_anomaly', severity='anomaly',
                        expected=False,
                        detail='the DMA control word still reports busy=' + str(busy) +
                               ' err=' + str(error) + ' after completion')
        status_word = _case_int(case, 'ctl_status')
        result = _case_int(case, 'isr_result')
        if status_word is not None and result is not None and result != status_word:
            return dict(failure_class='device_anomaly', severity='anomaly',
                        expected=False,
                        detail='the handler did not store the declared DMA status word')
        return dict(failure_class='observation_mismatch', severity='anomaly',
                    expected=False,
                    detail='F6 completed without the declared control/transfer/IRQ facts')
    if flow == 'F1':
        words = _case_int(case, 'prog_words')
        retired = _case_int(case, 'prog_retires')
        # A branch, jump or loop build states its own retirement criteria on the
        # line: the RVFI trace has to match the host's count and the PC order it
        # counted.  A word that does not retire (or that retires again in a
        # bounded loop) is legal there, so the straight-line "every word retired"
        # test is only applied when the line states none of these facts.
        branch_mode = 'prog_pc_order' in case or 'prog_trace_count' in case
        if branch_mode:
            trace_count = _case_int(case, 'prog_trace_count')
            repeated = _case_int(case, 'prog_pc_repeat')
            # A loop build prints a non-zero repeated-PC count and is allowed a
            # zero strict-rise flag; the entry's reference-trace comparison is
            # what decides it.  Every other traced build must still rise.
            loop_mode = repeated is not None and repeated > 0
            if ((_case_int(case, 'prog_pc_order') == 0 and not loop_mode)
                    or _case_int(case, 'prog_insns_match') == 0
                    or (trace_count is not None and retired is not None
                        and trace_count != retired)):
                return dict(failure_class='execution_anomaly', severity='anomaly',
                            expected=False,
                            detail='the program retirements are not the installed-word '
                                   'RVFI trace the host counted')
            return dict(failure_class='observation_mismatch', severity='anomaly',
                        expected=False,
                        detail='F1 completed without the declared retirement facts')
        if (words is not None and retired is not None and retired != words) or \
                _case_int(case, 'prog_pc_ordered') == 0 or \
                _case_int(case, 'prog_insns_match') == 0:
            return dict(failure_class='execution_anomaly', severity='anomaly',
                        expected=False,
                        detail='the program did not retire every installed word in order '
                               'as the instruction that was installed')
        return dict(failure_class='observation_mismatch', severity='anomaly',
                    expected=False,
                    detail='F1 completed without the declared retirement facts')
    if flow == 'F2':
        if _case_int(case, 'read_value') != _case_int(case, 'echo_value'):
            return dict(failure_class='execution_anomaly', severity='anomaly',
                        expected=False,
                        detail='the CPU did not commit the read word back to RAM')
        target_data = _case_int(case, 'apb_rdata')
        if target_data is None:
            target_data = _case_int(case, 'target_rdata')
        read_value = _case_int(case, 'read_value')
        if target_data is not None and read_value is not None and target_data != read_value:
            return dict(failure_class='device_anomaly', severity='anomaly',
                        expected=False,
                        detail='the target read data differs from the CPU response')
        return dict(failure_class='observation_mismatch', severity='anomaly',
                    expected=False,
                    detail='F2 completed without the declared read/commit facts')
    if flow == 'F3':
        if _case_int(case, 'ram_after') != _case_int(case, 'write_value'):
            return dict(failure_class='device_anomaly', severity='anomaly',
                        expected=False,
                        detail='the RAM word after the store differs from the written value')
        return dict(failure_class='observation_mismatch', severity='anomaly',
                    expected=False,
                    detail='F3 completed without the declared store/readback facts')
    # F4: a completed bus transfer whose declared write effect does not match.
    return dict(failure_class='device_anomaly', severity='anomaly', expected=False,
                detail='F4 completed without the declared target write effect')


def classify_host_failure(text):
    """The last host-side line, classified as wait limit, protocol or abort."""
    candidates = []
    for line in (text or '').splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        if (stripped.startswith('case ') and len(parts) > 1 and parts[1].isdigit()) \
                or stripped.startswith('summary ') \
                or stripped.startswith(('NEED_RECORD', 'CASE_INSTALLED',
                                        'bus_error unknown')):
            continue
        candidates.append(stripped)
    message = candidates[-1] if candidates else 'the host stopped without a summary line'
    lowered = message.lower()
    if 'tick budget' in lowered or 'exceeded its tick' in lowered:
        kind = 'wait_budget_exceeded'
    elif any(token in lowered for token in
             ('protocol', 'handshake', 'outside the declared', 'outside ram',
              'answered without', 'dropped a pending', 'invalid', 'malformed',
              'unsupported', 'does not expose', 'refused', 'did not complete')):
        kind = 'protocol_error'
    else:
        kind = 'host_abort'
    return dict(kind=kind, message=message)


def recovery_declaration(config, *, irq, dma, pins, bus):
    """What the timeout/storm recovery does and does not reset, stated in the summary."""
    source = config.get('source_timing') or {}
    dma_timing = config.get('dma_timing') or {}
    device = irq is not None or dma is not None
    return dict(
        scope=('ip and dma reset only; the CPU and RAM are retained'
               if device else 'no device is wired, so no recovery can occur'),
        triggered_by=('a case whose bounded F5/F6 wait expired (wait_timeout 1), a '
                      'declared level IRQ still asserted after the handler '
                      '(level_stuck 1, reported as a storm at the take limit), or a '
                      'routed F6 case being installed so its declared evidence word '
                      'starts from the devices\' reset state'),
        cpu_reset=False, ram_reset=False,
        ip_reset_assert_ticks=(source.get('reset_assert_ticks') if irq is not None
                               else None),
        dma_reset_assert_ticks=(dma_timing.get('reset_assert_ticks')
                                if dma is not None else None),
        cleared=['device internal registers and outputs',
                 'pending sampled IRQ edges/levels',
                 'host MMIO and DMA transactions in flight'],
        retained=['CPU program counter, registers and pipeline state',
                  'the RAM image, mailbox and handler block',
                  'the firmware code and trampoline slot',
                  'the session inputs and corpus'],
        pad_model=('resampled from the device ports after the reset'
                   if pins is not None else None),
        consequences=['a device configuration written before the timed-out case is lost',
                      'a pending interrupt or DMA transfer from that case is discarded',
                      'a level source that was not cleared loses its configuration and '
                      'asserted level, and the case that found it stays failed',
                      'the next case starts from the device reset state, not from the '
                      'state before the timeout',
                      'the CPU keeps its state and the firmware has returned to its poll '
                      'loop before the next input is installed'],
        evidence=['the case line carries wait_timeout 1 or level_stuck 1',
                  'the summary carries wait_timeouts, level_stuck and device_resets',
                  'the summary states recovery_scope devices_only_cpu_and_ram_retained'])


def case_document(record, case, events=None, protocol='apb3', pins=False, bus=None,
                  protocols=None, groups=None, serial=False):
    """One case: the input, the real observations and the time it took.

    The protocol decides which spelling the case line used; the neutral
    ``target`` block beside the protocol's own fields is the same reading for
    both, so a reader never has to know which bridge carried the transfer.  A pin
    target adds its pad facts under the same names the host printed them.

    ``protocols`` is a mixed build's declared protocol set: the case line prints
    the neutral group plus each declared protocol's own sampled handshake, so the
    projection has to cover all of them.  A homogeneous build ignores it.
    """
    observation = {key: case.get(key, 'unknown')
                   for key in case_observation_keys(record['flow'], protocol,
                                                    pins=pins, protocols=protocols,
                                                    groups=groups, serial=serial)}
    observation.update({key: case.get(key, 'unknown')
                        for key in case_counter_keys(protocol, bus=bus,
                                                     protocols=protocols)})
    if 'both_link' in case:
        # A two-source F5 case states both status reads, both stores, both
        # declared clears and each member target's own counters.  A single-link
        # F5 line carries none of these keys and its document is unchanged.
        observation.update({key: case.get(key, 'unknown')
                            for key in F5_BOTH_CASE_KEYS})
    if 'dma_route_enabled' in case:
        # A routed F6 case states the target route, the target's own response
        # counters and the evidence word the firmware read back.  A RAM-only case
        # carries none of these keys and its document is unchanged.  A read route
        # printed its own group (routed source, captured PRDATA, RAM read count,
        # CPU readbacks), so it replaces the write route's group instead of
        # inheriting fields that line never printed.
        keys = (F6_ROUTE_READ_CASE_KEYS if case.get('dma_route_direction') == 'read'
                else F6_ROUTE_CASE_KEYS)
        observation.update({key: case.get(key, 'unknown') for key in keys})
    verdict = classify_case(case)
    document = dict(index=case['index'], flow=case['flow'], record=record['text'],
                    input=case.get('record', 'unknown'),
                    status=case['status'], ticks=case.get('ticks', 'unknown'),
                    seconds=case.get('seconds', 'unknown'), observation=observation,
                    target=target_view(case), failure_class=verdict['failure_class'],
                    failure_detail=verdict['detail'],
                    failure_severity=verdict['severity'])
    if 'target_index' in case:
        # A multi-target case line names the window it was routed to; a legacy
        # one-target line carries no such field and this document stays as it was.
        document['target_index'] = case['target_index']
    if 'target_protocol' in case:
        # A mixed build states the protocol of the target this case was routed to.
        # The correspondence check compares it with what the artifacts declare for
        # that target, so it is copied here as an observation, not as a claim.
        document['target_protocol'] = case['target_protocol']
    if pins:
        document['pins'] = {key: case.get(key, 'unknown')
                            for key in PIN_CASE_KEYS + (PIN_F2_KEYS if record['flow'] == 'F2'
                                                        else ()) + (PIN_F5_KEYS if
                                                                    record['flow'] == 'F5' else ())}
    if groups:
        # The declared pad groups as the host executed them, group by group.  A
        # build that declares none carries no ``pin_groups`` block.
        document['pin_groups'] = {key: case.get(key, 'unknown')
                                  for key in pin_group_case_keys(groups)}
    if serial:
        # The serial peer's tick-level evidence: what the host drove onto rx and
        # what it sampled from tx, in the declared frame and bit period.
        document['serial_peer'] = {key: case.get(key, 'unknown')
                                   for key in serial_peer_case_keys()}
    if events is not None:
        document['events'] = dict(events)
    return document


def _declared_target_count(windows):
    """How many target windows this address view declares (legacy: one)."""
    return int(windows.get('target_count') or len(windows.get('ip_targets') or ()) or 1)


def case_target_protocol(case, windows, default='apb3'):
    """The protocol of the target one case line was routed to.

    The address view carries each declared target's own protocol under
    ``target_protocols`` (the entry states it there from the artifacts it built),
    and a multi-target case line names the target it was routed to.  A case with
    no target access (an F3 RAM store, an F2 RAM read, a RAM-only F6) or a legacy
    one-target view keeps the build's protocol, which is what its line's field
    spelling follows.  ``default`` is the build's protocol: the one protocol of a
    homogeneous build, or ``mixed`` for a mixed one.
    """
    rows = windows.get('target_protocols')
    index = case.get('target_index') if isinstance(case, dict) else None
    if isinstance(rows, list) and isinstance(index, int) and 0 <= index < len(rows):
        return rows[index]
    return default


def _target_protocol_mismatch(case, windows, default):
    """Check a case line's own ``target_protocol`` word against the declaration.

    A mixed build prints the protocol of the target the case was routed to; the
    entry compares it with the protocol the artifacts declare for that target
    instead of trusting the line.  A homogeneous build prints no such word, and a
    RAM-only case states ``none`` because no target carried it.
    """
    stated = case.get('target_protocol')
    if stated is None:
        return None
    if stated == 'none':
        if isinstance(case.get('target_index'), int) and case['target_index'] >= 0:
            return 'case target_protocol none on a case that named a target'
        return None
    declared = case_target_protocol(case, windows, default)
    if declared not in TARGET_LABELS:
        return None
    if stated != declared:
        return ('case target_protocol %s differs from the declared target protocol %s'
                % (stated, declared))
    return None


#: The FNV-1a constants the C++ host uses for ``window_hash`` and the F1 trace
#: hash.  They are restated here because the entry computes the same digest over
#: the window the host printed, which ties that printed sample to
#: ``data_hash_before``; the trace hash itself comes from the Python authority.
_FNV1A_OFFSET = 2166136261
_FNV1A_PRIME = 16777619


def f1_window_hash(values):
    """FNV-1a 32 over one data window in address order.

    The value is the C++ ``window_hash`` digest: four little-endian bytes per
    word, hashed from the window base upward.  The entry uses it to check that
    the window words the host printed for a branch case are the same sample its
    ``data_hash_before`` states.
    """
    digest = _FNV1A_OFFSET
    for value in values:
        if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
            raise ValueError('a data window word is not a 32-bit unsigned integer')
        for byte in value.to_bytes(4, 'little'):
            digest ^= byte
            digest = (digest * _FNV1A_PRIME) & 0xFFFFFFFF
    return digest


def f1_sampled_window(case):
    """The data window the host printed for one branch case, or None."""
    values = []
    for index in range(PROGRAM_DATA_WORDS):
        value = case.get('prog_data_%d' % index)
        if type(value) is not int:
            return None
        values.append(value)
    return tuple(values)


def f1_rvfi_trace(expectation):
    """The reference retirement trace projected onto what RVFI exposes.

    ``f1_reference_expectation`` carries the reference model's own ``wdata``: a
    store reports the value it stored.  RVFI states a retirement that writes no
    register with ``rd_addr 0`` and ``rd_wdata 0``, so the projected trace zeroes
    ``wdata`` whenever there is no destination register.  That projection is
    exactly what the host hashes from its own retirement stream.
    """
    projected = []
    for entry in expectation['trace']:
        projected.append(dict(pc=entry['pc'], insn=entry['insn'],
                              insn_word=entry['insn_word'], rd=entry['rd'],
                              wdata=(entry['wdata'] if entry['rd'] else 0)))
    return projected


def f1_trace_mismatch(record, case, *, layout, flags, isa):
    """Compare one traced F1 case with the reference retirement trace, or None.

    The witness is the host's real RVFI stream (`prog_retires`,
    `prog_trace_count`, `prog_trace_hash`, `prog_pc_order`, the window words it
    sampled and the after-hash), never the installed words: a branch program
    legally skips words and a compressed record retires two parcels per record
    word, so the reference trace is the only authority for what should have
    retired.  Returns the first mismatch as a sentence.

    ``flags`` decides the mode: a branch (``branch``/``extended``) or a
    compressed (``compressed``) declaration both reach this check, and only the
    wording of the sentences differs.
    """
    from myfuzz.fuzz.f1_program_gate import (
        f1_reference_expectation, normalize_f1_gate_flags, trace_hash)
    gate_flags = normalize_f1_gate_flags(flags)
    compressed = gate_flags.compressed
    looping = gate_flags.allow_loops
    # A branch build states its count in installed words; a compressed record
    # states it in instructions (parcels + whole words), and the sentence says so.
    noun = 'instructions' if compressed else 'words'
    if isa is None:
        return ('F1 compressed correspondence needs the declared ISA'
                if compressed else 'F1 branch correspondence needs the declared ISA')
    window = f1_sampled_window(case)
    if window is None:
        return ('F1 compressed case did not state the sampled data window'
                if compressed else 'F1 branch case did not state the sampled data window')
    if case.get('data_hash_before') != f1_window_hash(window):
        return 'F1 printed data window does not hash to data_hash_before'
    memory = {layout['data_base'] + 4 * index: value
              for index, value in enumerate(window)}
    try:
        expectation = f1_reference_expectation(
            record, isa=isa, window_bytes=PROGRAM_DATA_WORDS * 4, flags=flags,
            registers={18: layout['data_base']}, memory=memory,
            data_base=layout['slot'], image_base=layout['slot'])
    except ValueError as error:
        return 'F1 reference expectation refused the record: ' + str(error)
    retired = expectation['retired_count']
    if case.get('prog_retires') != retired:
        return ('F1 %s program retired %s %s; the reference trace retires %d'
                % ('compressed' if compressed else 'branch',
                   case.get('prog_retires'), noun, retired))
    if case.get('prog_trace_count') != retired:
        return ('F1 RVFI trace count %s differs from the %d reference retirements'
                % (case.get('prog_trace_count'), retired))
    observed_hash = case.get('prog_trace_hash')
    if type(observed_hash) is not int:
        return ('F1 compressed case did not state its RVFI trace hash'
                if compressed else 'F1 branch case did not state its RVFI trace hash')
    expected_hash = trace_hash(f1_rvfi_trace(expectation))
    if 'fnv1a32:%08x' % observed_hash != expected_hash:
        return ('F1 RVFI trace hash fnv1a32:%08x differs from the reference %s'
                % (observed_hash, expected_hash))
    reference_pcs = expectation['pc_order']
    reference_repeats = sum(1 for previous, current in
                            zip(reference_pcs, reference_pcs[1:])
                            if current <= previous)
    if looping:
        # A bounded loop repeats PCs by construction, so the strict-rise flag is
        # not the criterion here: the observed repeat count must be the
        # reference one, and the trace hash above already pins the exact
        # sequence.  The host prints both, so the strict-rise fact stays visible.
        observed_repeats = case.get('prog_pc_repeat')
        if type(observed_repeats) is not int:
            return 'F1 loop case did not state its repeated-PC count'
        if observed_repeats != reference_repeats:
            return ('F1 loop program repeated %s PC(s); the reference trace '
                    'repeats %d' % (observed_repeats, reference_repeats))
    elif case.get('prog_pc_order') != 1:
        return ('F1 compressed program retirements are not strictly increasing'
                if compressed else
                'F1 branch program retirements are not strictly increasing')
    if case.get('prog_insns_match') != 1:
        if compressed:
            return ('F1 compressed program retired a parcel that was not '
                    'installed')
        return 'F1 branch program retired an instruction that was not installed'
    # The stores the reference model performed have to be the ones the host's
    # after-sample shows: the trace hash carries no store data (RVFI exposes no
    # writeback for a store), so the window is the store witness.
    final = list(window)
    for address, value in expectation['memory_changes'].items():
        offset = address - layout['data_base']
        if 0 <= offset < 4 * PROGRAM_DATA_WORDS and offset % 4 == 0:
            final[offset // 4] = value
    if case.get('data_hash_after') != f1_window_hash(final):
        return 'F1 program data window after the case differs from the reference stores'
    changed = sum(1 for before, after in zip(window, final) if before != after)
    if case.get('data_changed') != changed:
        return ('F1 data_changed %s differs from the %d reference store(s)'
                % (case.get('data_changed'), changed))
    return None


def f1_declared_mode(config):
    """The declared whole-record F1 mode, or ``None`` for the RV32 subset.

    ``trap`` and ``rv64`` are the two modes this entry states at the record's
    own width.  They are mutually exclusive and each is refused outside the one
    CPU/bus it was proven on (see the validation in ``main``).
    """
    if config.get('f1_trap_program') is not None:
        return 'trap'
    if config.get('f1_rv64', False):
        return 'rv64'
    return None


def f1_trap_mismatch(record, case, *, layout):
    """Compare one declared trap case with its reference expectation, or None.

    Every compared field is a measured one: the RVFI record's own
    trap/cause/intr/mode for the ECALL, the scoreboard's registered mcause/mepc
    readback, the two words the firmware handler stored, and the reference
    retirement trace hashed with the host's FNV-1a 32.
    """
    from myfuzz.fuzz.f1_trap_program import expectation as trap_expectation

    words = list(record['fields'])
    try:
        expected = trap_expectation(words, slot=layout['slot'])
    except ValueError as error:
        return 'F1 trap reference refused the record: ' + str(error)
    slot = layout['slot']
    if case.get('fetch') != slot:
        return 'F1 trap case fetch address is not the trampoline slot'
    if case.get('retire_pc') != slot or case.get('retire_insn') != words[0]:
        return 'F1 trap case did not retire the ECALL at the slot'
    if case.get('successor_pc') != expected['successor_pc']:
        return 'F1 trap case has no observed successor after the handler returned'
    if case.get('prog_words') != len(words):
        return 'F1 trap program length differs from the input'
    if case.get('prog_retires') != expected['retired']:
        return ('F1 trap program retired %s word(s); the reference retires %d'
                % (case.get('prog_retires'), expected['retired']))
    if case.get('prog_insns_match') != 1:
        return 'F1 trap program retired an instruction that was not installed'
    if case.get('prog_pc_ordered') != 1:
        return 'F1 trap program retirements are not in address order'
    if case.get('trap_count') != 1:
        return ('F1 trap case observed %s trap(s); exactly one ECALL was declared'
                % case.get('trap_count'))
    if case.get('trap_pc') != slot or case.get('trap_insn') != words[0]:
        return 'F1 trap case attributed the trap to a word other than the ECALL'
    if case.get('trap_cause') != expected['cause']:
        return ('F1 trap cause %s is not the declared cause %d'
                % (case.get('trap_cause'), expected['cause']))
    if case.get('trap_intr') != 0:
        return ('F1 trap record carries intr %s; a synchronous trap is not an '
                'interrupt' % case.get('trap_intr'))
    if case.get('trap_mode') != expected['mode']:
        return ('F1 trap retired in mode %s; the declared handler is M-mode (3)'
                % case.get('trap_mode'))
    if case.get('rvfi_mcause') != expected['cause']:
        return ('F1 CSR readback mcause %s is not the trap cause %d'
                % (case.get('rvfi_mcause'), expected['cause']))
    if case.get('rvfi_mepc') != expected['stored_epc']:
        return ('F1 CSR readback mepc %s is not the ECALL pc 0x%x'
                % (case.get('rvfi_mepc'), expected['stored_epc']))
    if case.get('rvfi_mepc_final') != expected['stored_epc'] + 4:
        return ('F1 CSR readback mepc did not advance past the ECALL: %s, not 0x%x'
                % (case.get('rvfi_mepc_final'), expected['stored_epc'] + 4))
    if case.get('trap_stored_cause') != expected['stored_cause']:
        return ('F1 handler stored mcause %s, not %d'
                % (case.get('trap_stored_cause'), expected['stored_cause']))
    if case.get('trap_stored_epc') != expected['stored_epc']:
        return ('F1 handler stored mepc %s, not 0x%x'
                % (case.get('trap_stored_epc'), expected['stored_epc']))
    if case.get('trap_flag') != 1:
        return 'F1 trap handler never set its flag'
    observed_hash = case.get('prog_trace_hash')
    if type(observed_hash) is not int:
        return 'F1 trap case did not state its RVFI trace hash'
    if 'fnv1a32:%08x' % observed_hash != expected['trace_hash']:
        return ('F1 trap RVFI trace hash fnv1a32:%08x differs from the reference %s'
                % (observed_hash, expected['trace_hash']))
    if case.get('prog_trace_count') != expected['retired']:
        return ('F1 trap RVFI trace count %s differs from the %d reference '
                'retirements' % (case.get('prog_trace_count'), expected['retired']))
    return None


def f1_rv64_mismatch(record, case, *, layout, windows):
    """Compare one RV64 case with its 64-bit reference expectation, or None.

    The witness is the host's RVFI retirement stream at the record's own width:
    the printed 64-bit trace hash, the 64-bit last writeback and PC, the
    instruction words, and the data window after the case (an SD is witnessed by
    the window, not by a writeback).  The 32-bit digest is never read here.
    """
    from myfuzz.fuzz.f1_rv64 import expectation as rv64_expectation
    from myfuzz.fuzz.f1_rv64 import validate_rv64_record

    words = list(record['fields'])
    slot = layout['slot']
    window = f1_sampled_window(case)
    if window is None:
        return 'F1 RV64 case did not state the sampled data window'
    if case.get('data_hash_before') != f1_window_hash(window):
        return 'F1 printed data window does not hash to data_hash_before'
    try:
        validate_rv64_record(words, max_words=len(words))
        expected = rv64_expectation(words, slot=slot,
                                    data_base=layout['data_base'], window=window)
    except ValueError as error:
        return 'F1 RV64 reference refused the record: ' + str(error)
    if case.get('fetch') != slot:
        return 'F1 RV64 fetch address is not the trampoline slot'
    if case.get('retire_pc') != slot or case.get('retire_insn') != words[0]:
        return 'F1 RV64 case did not retire the installed first word'
    if case.get('successor_pc') != slot + 4 * len(words):
        return 'F1 RV64 case has no observed successor'
    if case.get('prog_words') != len(words):
        return 'F1 RV64 program length differs from the input'
    if case.get('prog_retires') != expected['retired']:
        return ('F1 RV64 program retired %s word(s); the reference retires %d'
                % (case.get('prog_retires'), expected['retired']))
    if case.get('prog_trace_count') != expected['retired']:
        return ('F1 RV64 RVFI trace count %s differs from the %d reference '
                'retirements' % (case.get('prog_trace_count'), expected['retired']))
    if case.get('prog_insns_match') != 1:
        return 'F1 RV64 program retired an instruction that was not installed'
    if case.get('prog_pc_ordered') != 1:
        return 'F1 RV64 program retirements are not in address order'
    if case.get('prog_traps') != 0:
        return 'F1 RV64 program trapped inside the trampoline slot'
    if expected['last_rd']:
        if case.get('prog_last_rd') != expected['last_rd']:
            return ('F1 RV64 last writeback register x%s differs from the '
                    'reference x%d' % (case.get('prog_last_rd'),
                                       expected['last_rd']))
        if case.get('prog_last_wdata64') != expected['last_wdata']:
            return ('F1 RV64 last 64-bit writeback 0x%x differs from the '
                    'reference 0x%x' % (case.get('prog_last_wdata64') or 0,
                                        expected['last_wdata']))
        if case.get('prog_last_pc64') != expected['last_pc']:
            return ('F1 RV64 last writeback pc 0x%x differs from the reference '
                    '0x%x' % (case.get('prog_last_pc64') or 0,
                              expected['last_pc']))
    observed_hash = case.get('prog_trace_hash64')
    if type(observed_hash) is not int:
        return 'F1 RV64 case did not state its 64-bit RVFI trace hash'
    if 'fnv1a64:%016x' % observed_hash != expected['trace_hash']:
        return ('F1 RV64 trace hash fnv1a64:%016x differs from the reference %s'
                % (observed_hash, expected['trace_hash']))
    if case.get('data_hash_after') != f1_window_hash(expected['window_after']):
        return 'F1 RV64 data window after the case differs from the reference stores'
    if case.get('data_changed') != expected['window_changed']:
        return ('F1 RV64 data_changed %s differs from the %d reference store word(s)'
                % (case.get('data_changed'), expected['window_changed']))
    return None


def _target_counter_mismatch(case, windows, selected):
    """Check the host's per-target counters against the routed target.

    Only a multi-target build prints them; each target's ``target<i>_reads`` and
    ``target<i>_writes`` are the transfers that target's own window carried.
    The routed target has to equal the case's global target counters and every
    other target has to stay at zero, which is what makes "the other IP did not
    move" an observation instead of an assumption.
    """
    count = _declared_target_count(windows)
    if count <= 1:
        return None
    view = target_view(case)
    global_reads, global_writes = view['target_reads'], view['target_writes']
    for index in range(count):
        reads = case.get('target%d_reads' % index)
        writes = case.get('target%d_writes' % index)
        if not isinstance(reads, int) or not isinstance(writes, int):
            return 'the host did not report target%d reads/writes' % index
        if index == selected:
            if reads != global_reads or writes != global_writes:
                return ('target%d counters differ from the case target counters'
                        % index)
        elif reads or writes:
            return 'target%d moved without being the routed target' % index
    if selected is None and (global_reads != 0 or global_writes != 0):
        return 'a RAM-only case counted a target transfer'
    return None


def f5_case_link(irq, record):
    """The one global F5 link a record selects, or ``None``.

    A single-link declaration keeps the historical record shape (no index word),
    so the one link is selected.  With several links the first record word is the
    global link index, and the link itself states which target declared it.  The
    caller's record gate has already refused an out-of-range index; a link table
    that somehow lacks one is reported by the caller's own check, never guessed.
    The synthetic both row states its member links instead of one target, so it
    is selected exactly like a single link and the evidence check dispatches on
    its ``mode``.
    """
    if irq is None:
        return None
    links = f5_link_table(irq)
    if len(links) > 1:
        index = record['fields'][0]
        if not isinstance(index, int) or not 0 <= index < len(links):
            return None
        return links[index]
    return links[0]


class RouteReadExpectation:
    """The value a preceding F4 case wrote to a read route's register.

    A fixed record chain states a deterministic source word by writing it with an
    F4 case before the F6 read.  The expectation is the *observed* value of the
    most recent passing F4 case that addressed the routed register, so the check
    is against what the CPU really wrote and the target really acknowledged, not
    against a re-reading of the operator's record text.  A run with no such case
    (a fuzz batch, or a scenario that only reads a reset value) states no
    expectation, and the route's own evidence (DMA captured word == CPU readback
    == RAM destination words) still applies.
    """

    def __init__(self, route):
        self.address = None if route is None else route.get('address')
        self.value = None

    def observe(self, case):
        """Take the MMIO value of one passing F4 case aimed at the route."""
        if self.address is None or case.get('status') != 'observations_passed':
            return
        if case.get('flow') != 'F4':
            return
        address = _case_int(case, 'mmio_addr')
        value = _case_int(case, 'mmio_value')
        if address == self.address and value is not None:
            self.value = value


#: The per-protocol trace counter group a routed beat has to be observed with.
#: A routed beat is one real transfer on the target's own port, so the protocol
#: that carried it must count it - the routed transfer is never evidenced by the
#: DMA master's ack alone.  APB3 keeps the psel/penable/pready counters its route
#: always had (and its case line unchanged), so it is not listed here.
DMA_ROUTE_TRACE_KEYS = {
    'wishbone': ('dma_route_wb_acks',),
    'tl-ul': ('dma_route_tlul_a_handshakes', 'dma_route_tlul_d_handshakes'),
    'axi4-lite': {'write': ('dma_route_axi_aw', 'dma_route_axi_w',
                            'dma_route_axi_b'),
                  'read': ('dma_route_axi_ar', 'dma_route_axi_r')},
}


def dma_route_protocol_mismatch(case, route, beats):
    """The routed beat's own protocol trace, or the first difference.

    A route to a TL-UL, Wishbone or AXI4-Lite target prints the trace group of
    the protocol that target really uses: the protocol word, the number of
    routed beats that target completed on its own port, and that protocol's own
    handshake counters.  Every one of them has to equal the routed beat count, so
    the route is evidenced by the target's real handshake and not by the DMA
    master's ack.  An APB3 route keeps exactly the fields it always printed and
    is not checked here; a route whose target states no protocol is refused by
    the caller before this point.
    """
    protocol = route.get('target_protocol')
    if protocol in (None, 'apb3'):
        return None
    if case.get('dma_route_protocol') != protocol:
        return ('F6 the case states route protocol %s but the routed target '
                'declares %s' % (case.get('dma_route_protocol'), protocol))
    if case.get('dma_route_protocol_transfers') != beats:
        return ('F6 the target completed %s routed %s transfers, not the %d routed '
                'beats' % (case.get('dma_route_protocol_transfers'), protocol,
                           beats))
    keys = DMA_ROUTE_TRACE_KEYS.get(protocol)
    if isinstance(keys, dict):
        keys = keys.get(route.get('direction'))
    if not keys:
        return 'F6 route protocol %s has no routed protocol trace' % protocol
    for key in keys:
        if case.get(key) != beats:
            return ('F6 routed %s beat(s) were not all observed on the target\'s '
                    'own %s trace (%s is %s)'
                    % (beats, protocol, key, case.get(key)))
    return None


def _f5_int_list(case, key):
    """The integer list the host printed for a comma-separated case field."""
    value = case.get(key)
    if not isinstance(value, str) or not value:
        return None
    try:
        return [int(item, 10) for item in value.split(',')]
    except ValueError:
        return None


def _f5_both_mismatch(record, case, *, both):
    """Check one two-source F5 case line against the declaration it ran under.

    Every term is a fact the host printed from the real models: each member
    target's own status read at its own address and the RAM store that followed,
    each declared clear write, each member link's own IRQ edge and final raw
    level, and the CPU's accepted takes.  The case is deliberately not credited
    to one ``target_index``: the CPU has one OR'ed external input, so what is
    attributed is the two status words the ISR really read, never a vector the
    CPU does not have.
    """
    members = both['members']
    expected_trigger_words = sum(len(member['trigger_offsets']) for member in members)
    expected_clear_words = sum(1 for member in members if member['clear'] is not None)
    if case.get('irq_link') != both['index'] or case.get('both_link') != both['index']:
        return 'F5 two-source case does not state the both link index'
    if case.get('both_members') != ','.join(str(member['index']) for member in members):
        return 'F5 two-source members differ from the declaration'
    if case.get('both_targets') != ','.join(str(member['target_index'])
                                            for member in members):
        return 'F5 two-source targets differ from the declaration'
    if case.get('isr_flag') != 1:
        return 'F5 two-source handler did not complete'
    if case.get('wait_timeout') != 0:
        return 'F5 two-source case timed out before both sources were serviced'
    if case.get('level_stuck') != 0:
        return 'F5 two-source case left a declared level link asserted'
    takes = case.get('irq_takes')
    edges_total = case.get('irq_edges')
    if not (isinstance(takes, int) and takes >= 1
            and isinstance(edges_total, int) and edges_total >= 1):
        return 'F5 two-source case has no sampled IRQ edge and CPU take'
    if case.get('trigger_writes_observed') != expected_trigger_words:
        return 'F5 two-source case did not complete every declared trigger write'
    if case.get('both_trigger_writes') != expected_trigger_words:
        return 'F5 two-source trigger-write count differs from the declaration'
    if case.get('clear_writes') != expected_clear_words:
        return 'F5 two-source clear-write count differs from the declaration'
    if case.get('both_clear_writes') != expected_clear_words:
        return 'F5 two-source declared clear writes were not both performed'
    edges = _f5_int_list(case, 'both_link_edges')
    if edges is None or len(edges) != len(members):
        return 'F5 two-source case does not state every member link edge'
    levels = case.get('both_level_final')
    if not isinstance(levels, int):
        return 'F5 two-source case does not state the final raw link levels'
    word = 1
    for position, member in enumerate(members):
        target = member['target_index']
        prefix = 'target%d' % target
        readings = case.get(prefix + '_reads')
        if not isinstance(readings, int) or readings < 1:
            return 'F5 two-source handler did not read target ' + str(target) + ' status'
        if case.get(prefix + '_read_offset') != member['status_offset']:
            return 'F5 two-source status read address differs from the declaration'
        result_key = 'isr_result' if position == 0 else 'isr_result2'
        address_key = 'isr_read_addr' if position == 0 else 'isr_read_addr2'
        value_key = 'isr_read_value' if position == 0 else 'isr_read_value2'
        kind_key = 'isr_read_register_kind' if position == 0 else 'isr_read_register_kind2'
        cause_key = 'isr_cause' if position == 0 else 'isr_cause2'
        if case.get(result_key) != case.get(prefix + '_read_data'):
            return 'F5 two-source stored result differs from the status value read'
        if case.get(address_key) != member['base'] + member['status_offset']:
            return 'F5 two-source ISR read address differs from the declared status word'
        if case.get(value_key) != case.get(prefix + '_read_data'):
            return 'F5 two-source ISR read value differs from the target read data'
        if case.get(kind_key) != member['status_kind']:
            return 'F5 two-source ISR read kind differs from the declared register'
        if case.get(prefix + '_last_trigger_offset') != member['trigger_offsets'][-1]:
            return 'F5 two-source last trigger write address differs from the declaration'
        if word + len(member['trigger_offsets']) > len(record['fields']):
            return 'F5 two-source record is shorter than its declared trigger sequences'
        last_value = record['fields'][word + len(member['trigger_offsets']) - 1]
        if case.get(prefix + '_last_trigger_data') != last_value:
            return 'F5 two-source last trigger value differs from the input'
        if case.get(prefix + '_clear_writes') != (1 if member['clear'] else 0):
            return 'F5 two-source clear write for target ' + str(target) + ' differs'
        if member['clear'] is not None:
            if case.get(prefix + '_last_clear_offset') != member['clear']['offset']:
                return 'F5 two-source clear address differs from the declaration'
            if case.get(prefix + '_last_clear_data') != member['clear']['value']:
                return 'F5 two-source clear value differs from the declaration'
        if member['cause_declared']:
            cause = case.get(cause_key)
            if not isinstance(cause, int) or (cause & member['cause_mask']) == 0:
                return 'F5 two-source declared cause bits are not set in its status read'
        elif case.get(cause_key) != 'unknown':
            return 'F5 claims a cause the device does not declare'
        if edges[position] < 1:
            return 'F5 two-source member link did not raise its real IRQ output'
        if (levels >> member['index']) & 1:
            return 'F5 two-source member link is still asserted after the handler'
        word += len(member['trigger_offsets'])
    return None


def correspondence(record, case, *, layout, windows, irq, dma, protocol='apb3',
                   pins=None, registers=None, bus='obi', irq_base=None,
                   f5_target_index=None, f1_flags=None, isa=None,
                   route_expected=None, f1_mode=None):
    """Check that the observed facts belong to the input that was handed over.

    This re-reads the native report; it never derives a fact from the profile.
    Every target term is read through ``target_view``, so the check is written
    once for both protocols instead of once per spelling.  A pin build adds the
    two checks the pin model makes possible: the pad the host resolved *is* the
    value the CPU read (F2 under an external stimulus), and a target write is
    followed by the pad consequence the written register declares (F4).  Returns
    None when every checked fact matches, or the first mismatch.

    On a multi-target declaration the record's routed ``target_index`` has to be
    the index the host routed, and the per-target counters have to show that
    only that target moved.  A single-target declaration keeps the historical
    checks byte for byte: its case line carries no target index at all.

    ``f1_flags`` is the scenario's F1 program-shape declaration.  When it admits
    branches or compressed parcels, an F1 program is compared with the Python
    reference retirement trace instead of the straight-line "every installed word
    retired" rule; ``isa`` is the declared ISA that reference run is validated
    against.

    ``route_expected`` is the value a preceding F4 case in this same run wrote to
    the read route's register, when the operator's fixed record chain declares
    one.  The read route has to return exactly that word; the fuzz path passes
    None because the generator owns its record sequence, and the route's own
    evidence (DMA captured word == CPU readback == RAM destination words) still
    applies there.
    """
    target = target_view(case)
    if case['flow'] != record['flow']:
        return 'flow differs from the input'
    if case.get('record') != record['text']:
        return 'echoed record differs from the input'
    if record['flow'] in ('F5', 'F6') and _case_int(case, 'level_stuck') == 1:
        # The host sampled a declared level link still asserted after the
        # handler (and aborted the storm at the take limit).  The case is a real
        # finding; its other facts describe the storm, not a completed transfer.
        return 'F5/F6 declared level IRQ storm was not cleared'
    first = record['fields'][0]
    count = _declared_target_count(windows)
    expected_target = None
    both_case = False
    if record['flow'] == 'F2':
        expected_target = record.get('target_index')
    elif record['flow'] == 'F4':
        expected_target = record.get('target_index')
    elif record['flow'] == 'F5':
        link = f5_case_link(irq, record)
        both_case = link is not None and link.get('mode') == 'both'
        expected_target = (None if link is None else
                           link.get('target_index', f5_target_index))
    elif record['flow'] == 'F6' and dma is not None and dma.get('route') is not None:
        # A routed F6 transfer is addressed to the declared target window: that
        # target is the one whose APB port carries the pushes, and the firmware's
        # two evidence reads select the same window.  The per-target counters are
        # checked against it, so "the other IP did not move" stays measurable.
        expected_target = dma['route']['target_index']
    if count > 1 and not both_case:
        observed = case.get('target_index')
        wanted = -1 if expected_target is None else expected_target
        if observed != wanted:
            return 'case target_index %s differs from the routed input %s' % (
                observed, wanted)
        mismatch = _target_counter_mismatch(case, windows, expected_target)
        if mismatch is not None:
            return mismatch
    # A mixed build's case line names the protocol of the target it was routed to.
    # It is checked against what the artifacts declare for that target, so a case
    # can never be credited to the wrong bridge.
    mismatch = _target_protocol_mismatch(case, windows, protocol)
    if mismatch is not None:
        return mismatch
    routed_base = (windows['ip_base'] if expected_target is None
                   else target_window_of(windows, expected_target)['base'])
    irq_status_base = windows['ip_base'] if irq_base is None else irq_base
    if record['flow'] == 'F1':
        # The two declared whole-record modes have their own comparison: the
        # trap mode's witness is the RVFI cause/CSR/state of a real exception,
        # and the RV64 mode's is the 64-bit trace.  Neither is judged by the
        # RV32 "every installed word retired untrapped" rule.
        if f1_mode == 'trap':
            return f1_trap_mismatch(record, case, layout=layout)
        if f1_mode == 'rv64':
            return f1_rv64_mismatch(record, case, layout=layout, windows=windows)
        words = len(record['fields'])
        # The first in-slot retirement is the first *instruction* of the image: a
        # whole 32-bit word, or the low parcel of a compressed record word (RVFI
        # reports that parcel zero-extended as ``insn``).
        compressed_mode = False
        traced_mode = False
        if f1_flags is not None:
            from myfuzz.fuzz.f1_program_gate import normalize_f1_gate_flags
            gate_flags = normalize_f1_gate_flags(f1_flags)
            compressed_mode = gate_flags.compressed
            traced_mode = gate_flags.traced
        first_instruction = (first & 0xFFFF
                            if compressed_mode and (first & 3) != 3 else first)
        if case.get('fetch') != layout['slot']:
            return 'F1 fetch address is not the trampoline slot'
        if (case.get('retire_pc') != layout['slot']
                or case.get('retire_insn') != first_instruction):
            return 'F1 retired word differs from the input'
        if case.get('successor_pc') != layout['slot'] + 4 * words:
            return 'F1 has no observed successor'
        if words > 1 and traced_mode:
            # A branch, jump or loop program and a compressed record are their
            # own retirement evidence, but not "every installed word": a
            # branch/jump legally skips words, a loop repeats them and a
            # compressed record retires two parcels per record word.  The
            # host's RVFI trace is compared with the reference retirement trace
            # (count, order, hash and the exit through the return jump).
            if case.get('prog_words') != words:
                return 'F1 program length differs from the input'
            # ``unknown`` is the honest answer for a CPU whose RVFI face assigns
            # no trap bit.  The retirement trace below still has to match the
            # reference, so a trapped program is caught by its own missing
            # retirements; the flag itself is simply not observable there.
            if _case_int(case, 'prog_traps') not in (None, 0):
                return 'F1 program trapped inside the trampoline slot'
            mismatch = f1_trace_mismatch(record, case, layout=layout,
                                         flags=f1_flags, isa=isa)
            if mismatch is not None:
                return mismatch
        elif words > 1:
            # A program is its own retirement evidence: every installed word
            # retired, in address order, as the instruction that was installed,
            # and the trampoline left through its fixed return jump.
            if case.get('prog_words') != words:
                return 'F1 program length differs from the input'
            if case.get('prog_retires') != words:
                return 'F1 did not retire every program word'
            if case.get('prog_pc_ordered') != 1:
                return 'F1 program retirements are not in address order'
            if case.get('prog_insns_match') != 1:
                return 'F1 program retired an instruction that was not installed'
            # See the traced branch above: an unobservable trap flag is not a
            # trap, and the word-by-word retirement evidence still gates it.
            if _case_int(case, 'prog_traps') not in (None, 0):
                return 'F1 program trapped inside the trampoline slot'
        if bus == 'wishbone' and case.get('rvfi_order_monotonic') not in (1, 'unknown'):
            return 'F1 RVFI order did not rise at every retirement'
        return None
    if record['flow'] == 'F2':
        if case.get('read_addr') != first:
            return 'F2 read address differs from the input'
        if case.get('echo_value') != case.get('read_value'):
            return 'F2 CPU did not commit the returned word'
        if target['read_from'] == 'target':
            if target['target_rdata'] != case.get('read_value'):
                return 'F2 target read data differs from the CPU response'
            if target['target_reads'] != 1:
                return 'F2 expected exactly one target transfer'
            # The transfer's own offset, when the host printed one: an APB3 case
            # line carries the read data but not its offset, an AXI4-Lite one
            # carries both, so the check is applied to what was reported.
            if (target['target_offset'] != 'unknown'
                    and target['target_offset'] != first - routed_base):
                return 'F2 target read offset differs from the input address'
            if target['target_ready'] not in (1, 'unknown'):
                return 'F2 target read never completed its handshake'
            if target.get('target_resp', 0) not in (0, 'unknown'):
                return 'F2 target read was answered with an error response'
            # The protocol's own sampled handshake, when the case line carries
            # it.  A Wishbone read is one one-cycle stb request phase followed by
            # a held cyc+ack completion with we low; a TL-UL read is one Get A
            # channel handshake and one D channel handshake that carried the word
            # the CPU committed.  Both compare the slave's own pins with the value
            # the CPU read back, so a case cannot be credited to a bridge that
            # did not carry it.
            case_protocol = case_target_protocol(case, windows, protocol)
            read_offset = first - routed_base
            if case_protocol == 'wishbone' and 'wb_ack' in case:
                if case.get('wb_ack') != 1 or case.get('wb_cyc') != 1:
                    return 'F2 Wishbone read did not complete on a held cyc+ack cycle'
                if case.get('wb_we') != 0:
                    return 'F2 Wishbone read presented the write pin'
                if case.get('wb_stb_pulses') != 1:
                    return 'F2 Wishbone read did not present exactly one stb request phase'
                if case.get('wb_adr') != read_offset // 4:
                    return 'F2 Wishbone adr differs from the read address'
                if case.get('wb_dat_r') != case.get('read_value'):
                    return 'F2 Wishbone dat_r differs from the word the CPU committed'
            if case_protocol == 'tl-ul' and 'tlul_d_valid' in case:
                if case.get('tlul_a_opcode') != 4:
                    return 'F2 TL-UL read did not present a Get A-channel opcode'
                if case.get('tlul_a_handshakes') != 1 or case.get('tlul_d_handshakes') != 1:
                    return 'F2 TL-UL read did not complete one A and one D handshake'
                if case.get('tlul_a_address') != read_offset:
                    return 'F2 TL-ul a_address differs from the read address'
                if case.get('tlul_d_error') != 0:
                    return 'F2 TL-UL read was answered with d_error'
                if case.get('tlul_d_data') != case.get('read_value'):
                    return 'F2 TL-UL d_data differs from the word the CPU committed'
        elif target['read_from'] != 'ram' or target['target_reads'] != 0:
            return 'F2 read was not a plain RAM read'
        if pins is not None and first == windows['ip_base'] + pins['padin_offset']:
            # The CPU can only observe the device's own synchronizer latch.  The
            # instantaneous wire may already have moved (the synchronizer has a
            # real latency), so the wire is reported as pad_settled and is not
            # required to equal the read in the same sample.  The host-driven
            # pins on the wire still have to carry this case's driver value.
            if case.get('read_value') != case.get('padin_latch'):
                return 'F2 PADIN read differs from the device synchronizer latch'
            mask = 0xFFFFFFFF
            if ((case.get('pad_at_read') & ~case.get('dir_after') & mask)
                    != (case.get('ext_value') & ~case.get('dir_after') & mask)):
                return 'F2 the host driver value did not reach the input pins'
            if len(record['fields']) == 2 and case.get('pin_stimulus') != 'applied':
                return 'F2 stimulus word was not applied to the host driver'
        return None
    if record['flow'] == 'F3':
        if case.get('write_addr') != first or case.get('write_value') != record['fields'][1]:
            return 'F3 write differs from the input'
        if case.get('write_be') != 15 or case.get('ram_after') != record['fields'][1]:
            return 'F3 RAM did not commit the input word'
        return None
    if record['flow'] == 'F4':
        if case.get('mmio_addr') != first or case.get('mmio_value') != record['fields'][1]:
            return 'F4 MMIO write differs from the input'
        if (target['target_offset'] != first - routed_base
                or target['target_ready'] != 1
                or target['target_wdata'] != record['fields'][1]
                or target['target_writes'] != 1):
            return 'F4 target transfer differs from the input'
        # An AXI4-Lite write carries its strobes and its response code on the W
        # and B channels; an APB3 transfer has neither and states neither.  In a
        # mixed build the decision follows the target this case was routed to
        # (checked above against the declaration), never the build-wide word.
        case_protocol = case_target_protocol(case, windows, protocol)
        if case_protocol == 'axi4-lite':
            if target['target_wstrb'] != 15:
                return 'F4 AXI4-Lite write strobes differ from a full word'
            if target['target_resp'] != 0:
                return 'F4 AXI4-Lite write response is not OKAY'
            if (target['axi_aw'], target['axi_w'], target['axi_b']) != (1, 1, 1):
                return 'F4 AXI4-Lite write did not complete AW, W and B exactly once'
        # The protocol's own sampled handshake, when the case line carries it.
        # A Wishbone write is one one-cycle stb request phase and one held cyc+ack
        # completion with we high and the full byte select; a TL-UL write is one
        # PUT A channel handshake with a full mask and one D channel response that
        # carried no error.  The address and data compared here are the slave's
        # own pins, not the request the host drove.
        if case_protocol == 'wishbone' and 'wb_ack' in case:
            if (case.get('wb_ack') != 1 or case.get('wb_cyc') != 1
                    or case.get('wb_we') != 1):
                return 'F4 Wishbone write did not complete on a held cyc+ack cycle with we set'
            if case.get('wb_stb_pulses') != 1:
                return 'F4 Wishbone write did not present exactly one stb request phase'
            if case.get('wb_sel') != 15:
                return 'F4 Wishbone write strobes are not the full word'
            if case.get('wb_adr') != (first - routed_base) // 4:
                return 'F4 Wishbone adr differs from the write offset'
            if case.get('wb_dat_w') != record['fields'][1]:
                return 'F4 Wishbone dat_w differs from the written value'
        if case_protocol == 'tl-ul' and 'tlul_d_valid' in case:
            if case.get('tlul_a_opcode') not in (0, 1):
                return 'F4 TL-UL write did not present a PUT A-channel opcode'
            if case.get('tlul_a_handshakes') != 1 or case.get('tlul_d_handshakes') != 1:
                return 'F4 TL-UL write did not complete one A and one D handshake'
            if case.get('tlul_a_mask') != 15:
                return 'F4 TL-UL a_mask is not the full word'
            if case.get('tlul_a_address') != first - routed_base:
                return 'F4 TL-UL a_address differs from the write offset'
            if case.get('tlul_a_data') != record['fields'][1]:
                return 'F4 TL-UL a_data differs from the written value'
            if case.get('tlul_d_error') != 0:
                return 'F4 TL-UL write was answered with d_error'
        if pins is not None:
            offset = first - routed_base
            expected = expected_out_after(offset, case.get('out_before', 'unknown'),
                                          record['fields'][1], registers or {})
            mask = 0xFFFFFFFF
            if case.get('out_after') != expected & mask:
                return 'F4 sampled gpio_out does not follow the written register'
            if ((case.get('pad_after') & case.get('dir_after') & mask)
                    != (expected & case.get('dir_after') & mask)):
                return 'F4 device-driven pads do not show the written output'
            if ((case.get('pad_after') & ~case.get('dir_after') & mask)
                    != (case.get('ext_value') & ~case.get('dir_after') & mask)):
                return 'F4 host-driven pads changed without a host stimulus'
        return None
    if record['flow'] == 'F5':
        both = f5_both_link(irq)
        if both is not None and f5_both_selected(irq, record):
            return _f5_both_mismatch(record, case, both=both)
        links = irq.get('links') or [irq]
        if len(links) > 1:
            link_index = record['fields'][0]
            if case.get('irq_link') != link_index:
                return 'F5 link index differs from the input'
            link = links[link_index]
            trigger_fields = record['fields'][1:]
        else:
            if case.get('irq_link') not in (None, 0):
                return 'F5 link index differs from the single declared link'
            link = links[0]
            trigger_fields = record['fields']
        # The link's own target window.  A legacy link states none and keeps the
        # historical single-target base; a global link table states it, and the
        # case line names the target, so an ISR read of another target's status
        # word cannot pass as this one's.
        link_base = irq_status_base if link.get('base') is None else link['base']
        link_target = link.get('target_index', f5_target_index)
        if 'irq_link_target' in case and case.get('irq_link_target') != link_target:
            return 'F5 case target differs from the selected link target'
        triggers = case.get('trigger_writes_observed')
        clears = case.get('clear_writes')
        # The declared clear is an ordered sequence: the host counts one completed
        # write per step, and the case has to state the whole sequence.  A
        # one-step declaration keeps the historical word-for-word check.
        sequence = list(link.get('clears') or ())
        if not sequence and link['clear'] is not None:
            sequence = [link['clear']]
        if triggers != len(link['trigger_offsets']):
            return 'F5 did not complete every declared trigger write'
        if clears != len(sequence):
            return 'F5 clear-write count differs from the declaration'
        if case.get('last_trigger_offset') != link['trigger_offsets'][-1]:
            return 'F5 last trigger write address differs from the declaration'
        if case.get('last_trigger_data') != trigger_fields[-1]:
            return 'F5 last trigger value differs from the input'
        if sequence:
            if case.get('last_clear_offset') != sequence[-1]['offset']:
                return 'F5 declared clear write address differs'
            if case.get('last_clear_data') != sequence[-1]['value']:
                return 'F5 declared clear write value differs'
        if link['cause_declared']:
            cause = case.get('isr_cause')
            if not isinstance(cause, int) or (cause & link['cause_mask']) == 0:
                return 'F5 declared cause bits are not set in the status read'
        elif case.get('isr_cause') != 'unknown':
            return 'F5 claims a cause the device does not declare'
        if (target['target_reads'] != 1
                or target['target_read_offset'] != link['status_offset']):
            return 'F5 handler did not read the declared status register'
        if case.get('isr_result') != target['target_read_data']:
            return 'F5 handler store differs from the status value it read'
        # The ISR read is labelled with what the declaration says the word is.
        # The timer's offset 0 is its counter, and the profile declares no
        # cause bits, so a cause is never claimed here.
        if case.get('isr_read_addr') != link_base + link['status_offset']:
            return 'F5 ISR read address differs from the declared status word'
        if case.get('isr_read_value') != target['target_read_data']:
            return 'F5 ISR read value differs from the target read data'
        if case.get('isr_read_register_kind') != link['status_kind']:
            return 'F5 ISR read kind differs from the declared register'
        if not link['cause_declared'] and case.get('isr_cause') != 'unknown':
            return 'F5 claims a cause the device does not declare'
        level_final = case.get('irq_level_final')
        if isinstance(level_final, int) and (level_final >> link.get('index', 0)) & 1:
            # A level that is still asserted after the handler ran was not
            # cleared.  Reporting it as a pass would hide a real signal.
            return 'F5 declared level IRQ is still asserted after the handler'
        # The device level and the delivered level are separate facts: a pulse
        # source is stretched by the host, so neither may stand for the other.
        if not (case.get('device_high_ticks') >= 1 and case.get('delivered_high_ticks') >= 1):
            return 'F5 has no sampled device level and delivered level'
        if case.get('isr_flag') != 1:
            return 'F5 handler did not complete'
        if not (case.get('irq_edges') >= 1 and case.get('irq_takes') >= 1):
            return 'F5 has no sampled target IRQ edge and CPU take'
        if pins is not None:
            # A causal pin interrupt: a pad transition this device reported came
            # first, the asserted source has an enabled pin in its cause mask, and
            # the interrupt edge is not earlier than the transition.
            rise_events = case.get('pad_rise_events')
            fall_events = case.get('pad_fall_events')
            events = ((rise_events if isinstance(rise_events, int) else 0)
                      + (fall_events if isinstance(fall_events, int) else 0))
            transition_tick = case.get('first_transition_tick')
            if not isinstance(transition_tick, int):
                transition_tick = (case.get('first_rise_tick')
                                   if isinstance(case.get('first_rise_tick'), int)
                                   else case.get('first_fall_tick'))
            irq_tick = case.get('first_irq_tick')
            if not events:
                return 'F5 no pin transition was observed on the sampled pads'
            if not isinstance(transition_tick, int) or not isinstance(irq_tick, int):
                return 'F5 has no sampled transition tick and interrupt tick'
            if irq_tick < transition_tick:
                return 'F5 the interrupt preceded the pin transition it is attributed to'
            if not (case.get('irq_cause_pins', 0) & case.get('inten_at_irq', 0)):
                return 'F5 the asserted interrupt has no enabled pin in its cause mask'
        return None
    if dma is None:
        return 'F6 was recorded but the declaration has no DMA model'
    route = dma.get('route')
    # The declared beat counts.  A declared error injection aborts the transfer at
    # the injected routed beat: the beats before it completed (each read plus its
    # write) and the injected read itself completed with an error response, so the
    # case has one more read than write and its ERR status bit is the device's own
    # latch of that response.
    error = dma.get('error_injection') or {}
    injected = bool(error.get('requested'))
    expected_reads = dma['expected_reads']
    expected_writes = dma['expected_writes']
    if injected:
        beat = error.get('beat_index')
        if type(beat) is not int or beat < 0:
            return 'F6 the declared error injection names no beat'
        # The pinned ZipDMA's read side buffers the whole chunk before its write
        # side drains it, so an error on a read beat aborts the transfer before a
        # single write: the block's reads minus one completed, no write did.
        expected_reads = beat + 1
        expected_writes = 0
    if (case.get('dma_reads') != expected_reads
            or case.get('dma_writes') != expected_writes):
        # The declared beat count is the plan's: one beat per word for a full-word
        # transfer, one per declared lane beat for a size-derived transfer.
        return 'F6 DMA did not complete the declared block'
    if route is not None and route.get('direction') != 'read':
        # This host injects a declared error on a routed *read* beat only; the
        # declaration side refuses a write-beat injection by name, so a write
        # route can never carry one and its case line has no such field.
        if injected:
            return 'F6 an error injection was declared on a route this host does not inject'
    if route is not None and route.get('direction') == 'read':
        # Every routed read case states whether an error was injected, and the
        # host only ever injects a declared one: an undeclared error is a finding,
        # never a quietly tolerated detail.
        stated = case.get('dma_error_injected')
        if stated != (1 if injected else 0):
            return ('F6 the case states dma_error_injected %s but the declaration '
                    '%s one' % (stated, 'declares' if injected else 'declares no'))
        if injected:
            if case.get('dma_error_beat') != error.get('beat_index'):
                return 'F6 the injected beat differs from the declared beat'
            if case.get('dma_error_injections') != 1:
                return 'F6 the declared injection did not run'
            # The ERR bit is the device's own sticky status bit, read by the
            # completion handler after the transfer aborted.
            if case.get('err_after') != 1:
                return 'F6 the device did not latch its own ERR status bit'
            if case.get('busy_after') != 0:
                return 'F6 the device was still busy after the error response'
        else:
            if case.get('err_after') != 0:
                return 'F6 the device reported an undeclared error'
    if route is not None and route.get('direction') == 'read':
        # --- a read route: the master reads the declared source and writes the
        # captured word to the RAM block --------------------------------
        source = route['address']
        fifo = bool(route.get('fifo'))
        aperture = bool(route.get('aperture_addresses'))
        if case.get('dma_first_read_addr') != source:
            return 'F6 DMA read start differs from the declared route register'
        if case.get('dma_route_enabled') != 1:
            return 'F6 route case does not state the enabled route'
        if case.get('dma_route_direction') != 'read':
            return 'F6 read route case does not state its direction'
        if case.get('dma_route_target_index') != route['target_index']:
            return 'F6 routed target index differs from the declaration'
        if case.get('dma_route_source') != source:
            return 'F6 routed source differs from the declaration'
        if case.get('dma_route_offset') != route['offset']:
            return 'F6 routed register offset differs from the declaration'
        if case.get('dma_route_address_mode') != ('aperture' if aperture else 'fixed'):
            return 'F6 the case routed a different address mode than declared'
        if case.get('dma_route_source_kind') != ('fifo' if fifo else 'register'):
            return 'F6 the case routed a different source kind than declared'
        captured = case.get('dma_route_read_value')
        if not isinstance(captured, int):
            return 'F6 has no captured route read value'
        if case.get('dma_route_reads') != expected_reads:
            return 'F6 did not route every declared master read beat'
        if case.get('dma_route_acks') != expected_reads:
            return 'F6 routed read beats were not all answered by the target'
        if case.get('dma_route_target_reads') != expected_reads:
            return 'F6 target did not complete the routed reads'
        if case.get('dma_route_target_ready') != 1:
            return 'F6 routed target never signalled a completed transfer'
        # The routed beat's own protocol trace, for a target whose adapter is not
        # the APB3 one: the target has to have completed every routed beat on its
        # own port, and its case line has to carry that protocol's counters.
        mismatch = dma_route_protocol_mismatch(case, route, expected_reads)
        if mismatch is not None:
            return mismatch
        if case.get('dma_ram_reads') != 0:
            return 'F6 routed read beat was also served from RAM'
        if case.get('dma_ram_writes') != expected_writes:
            return 'F6 the captured words were not all written to RAM'
        if fifo:
            # A FIFO read: the level the CPU read back before the transfer is the
            # declared fill (the number of entries the earlier fill left), the
            # level after it fell by exactly the accepted reads, every popped word
            # is the declared word of the port, and the FIFO had no reason to hold
            # a different word.
            before = case.get('dma_route_level_before')
            after = case.get('dma_route_level_after')
            if not isinstance(before, int) or not isinstance(after, int):
                return 'F6 the FIFO level was not read back before and after'
            if before != case.get('dma_route_level_before_declared'):
                return ('F6 the FIFO held %d entries before the transfer, the '
                        'declaration states %s'
                        % (before, case.get('dma_route_level_before_declared')))
            if after != before - expected_reads:
                return ('F6 the FIFO level fell from %d to %d across %d accepted '
                        'read(s)' % (before, after, expected_reads))
            expected_word = case.get('dma_route_expected_word')
            if not isinstance(expected_word, int):
                return 'F6 the FIFO route declares no expected word'
            if case.get('dma_route_fifo_matched') != expected_writes:
                return ('F6 %s of the %d popped words were the declared word '
                        '0x%08x' % (case.get('dma_route_fifo_matched'),
                                    expected_writes, expected_word))
        elif aperture:
            # An aperture read: the master presented the declared addresses in
            # order, and the CPU's own read of every aperture word matches the
            # captured word.
            if case.get('dma_route_sequence') != expected_reads:
                return 'F6 the master did not present the declared aperture in order'
            if case.get('dma_route_cpu_aper_matched') != dma['block_words']:
                return 'F6 the CPU aperture readback differs from the captured word'
        elif case.get('dma_route_read_stable') != expected_reads:
            return 'F6 the routed register returned different words across the reads'
        if case.get('dma_route_read_matched') != expected_writes:
            return 'F6 a RAM destination word differs from the word the DMA captured'
        if case.get('dma_route_cpu_matched') != expected_writes:
            return 'F6 the CPU destination readback differs from the captured word'
        if (case.get('dma_last_write_addr')
                != (layout['dma_destination'] + 4 * (expected_writes - 1)
                    if expected_writes else 0)):
            return 'F6 DMA write end differs from the declared RAM destination block'
        for index in range(dma['block_words']):
            word = case.get('dst%d' % index)
            if index >= expected_writes:
                # The aborted transfer never reached this word: it has to still
                # be the declared destination sentinel.
                if word != DMA_DESTINATION_SENTINEL:
                    return ('F6 RAM destination word %d was written after the '
                            'transfer aborted' % index)
                continue
            # A fixed register read returns one word on every beat and a FIFO pop
            # of equal words likewise; an aperture read captures a different word
            # per beat, and the CPU's own readback of that aperture word is the
            # declaration-side witness the case line carries.
            expected = (case.get('dma_route_cpu_aper%d' % index)
                        if aperture else captured)
            if word != expected:
                return 'F6 RAM destination word %d differs from the captured word' % index
        if case.get('dma_ram_lane_written') != 4 * expected_writes:
            return 'F6 DMA did not write every byte of the declared RAM destination block'
        if case.get('dma_ram_lane_missing') != 4 * (dma['block_words'] - expected_writes):
            return 'F6 DMA left RAM destination bytes unwritten'
        if (case.get('dma_guard_lo') != DMA_DESTINATION_SENTINEL
                or case.get('dma_guard_hi') != DMA_DESTINATION_SENTINEL):
            return 'F6 read route changed a guard word outside the destination block'
        # The declared evidence word, as the CPU read it before and after the
        # transfer.  For a fixed register read that word is the routed register
        # itself; for a FIFO read it is the level register, whose declared field
        # is checked above and whose whole word is printed beside it.
        before_word = case.get('dma_route_evidence_before')
        after_word = case.get('dma_route_evidence_after')
        if not isinstance(before_word, int) or not isinstance(after_word, int):
            return 'F6 has no CPU readback of the routed evidence word'
        # A fixed register read returns one word; an aperture read's evidence word
        # is its *first* register, which is also the address the F4 chain's write
        # expectation is keyed on.
        reference = (case.get('dma_route_cpu_aper0') if aperture else captured)
        if not fifo and (before_word != reference or after_word != reference):
            return ('F6 CPU readback of the routed register (0x%08x/0x%08x) differs '
                    'from the word the DMA captured there (0x%08x)'
                    % (before_word, after_word, reference))
        if route_expected is not None and reference != route_expected:
            return ('F6 the DMA read 0x%08x but the preceding F4 case wrote 0x%08x '
                    'to the routed register' % (reference, route_expected))
        if case.get('dma_route_evidence') != 'observed':
            return 'F6 read route evidence was not observed'
    elif route is not None:
        if case.get('dma_first_read_addr') != layout['dma_source']:
            return 'F6 DMA read start differs from the declared source block'
        # A routed transfer never writes the RAM destination block: the master's
        # write address is the declared route address on every beat, and the
        # block and its guards keep the sentinel.  The transfer is proven by the
        # target's own responses and by the evidence readback below, not by a
        # RAM word that happens to match.
        if case.get('dma_route_enabled') != 1:
            return 'F6 route case does not state the enabled route'
        if case.get('dma_route_target_index') != route['target_index']:
            return 'F6 routed target index differs from the declaration'
        if case.get('dma_route_destination') != route['address']:
            return 'F6 routed destination differs from the declaration'
        if case.get('dma_route_offset') != route['offset']:
            return 'F6 routed register offset differs from the declaration'
        if case.get('dma_last_write_addr') != route['address']:
            return 'F6 DMA write end is not the declared route address'
        if case.get('dma_route_writes') != dma['expected_writes']:
            return 'F6 did not route every declared master write beat'
        if case.get('dma_route_acks') != dma['expected_writes']:
            return 'F6 routed beats were not all answered by the target'
        if case.get('dma_route_target_writes') != dma['expected_writes']:
            return 'F6 target did not complete the routed writes'
        if case.get('dma_route_target_ready') != 1:
            return 'F6 routed target never signalled a completed transfer'
        mismatch = dma_route_protocol_mismatch(case, route, dma['expected_writes'])
        if mismatch is not None:
            return mismatch
        if case.get('dma_ram_writes') != 0:
            return 'F6 routed beats were also written to RAM'
        for index in range(dma['block_words']):
            if case.get('dst%d' % index) != DMA_DESTINATION_SENTINEL:
                return 'F6 routed transfer wrote RAM destination word %d' % index
        if (case.get('dma_guard_lo') != DMA_DESTINATION_SENTINEL
                or case.get('dma_guard_hi') != DMA_DESTINATION_SENTINEL):
            return 'F6 routed transfer changed a guard word'
        # The evidence the route declared is a readback, not an ack: the F6
        # firmware read the target's own status word before and after the
        # transfer, and the declared field has to show exactly the accepted
        # pushes (a full FIFO is the declared depth, never more).
        before = case.get('fifo_status_before')
        after = case.get('fifo_status_after')
        if not isinstance(before, int) or not isinstance(after, int):
            return 'F6 has no status readback for the routed target'
        level_before = case.get('tx_fifo_level_before')
        level_after = case.get('tx_fifo_level_after')
        evidence = route['evidence']
        if evidence['kind'] == 'fifo_level':
            if not isinstance(level_before, int) or not isinstance(level_after, int):
                return 'F6 FIFO level readback is missing'
            if ((before & evidence['mask']) >> evidence['low'] != level_before
                    or (after & evidence['mask']) >> evidence['low'] != level_after):
                return 'F6 FIFO level fields disagree with the STATUS words read'
            if level_before != 0:
                return 'F6 routed case did not start from the empty (reset) FIFO'
            expected = min(dma['expected_writes'], evidence['depth'])
            if level_after != expected:
                return ('F6 FIFO level %d is not the %d pushes the target accepted'
                        % (level_after, expected))
            if case.get('dma_route_expected_level') != expected:
                return 'F6 host expected FIFO level differs from the declaration'
            if case.get('dma_route_accepted') != expected - level_before:
                return 'F6 accepted-push count differs from the readback difference'
            partial = int(level_before + dma['expected_writes'] > evidence['depth'])
            if case.get('dma_route_partial') != partial:
                return 'F6 partial-acceptance flag differs from the declared depth'
        else:
            if not isinstance(level_before, int) or not isinstance(level_after, int):
                return 'F6 register-readback evidence is missing'
            if before == after:
                return 'F6 evidence word did not change across the routed transfer'
    else:
        if case.get('dma_first_read_addr') != layout['dma_source']:
            return 'F6 DMA read start differs from the declared source block'
        if case.get('dma_last_write_addr') != layout['dma_destination'] + 4 * (dma['block_words'] - 1):
            return 'F6 DMA write end differs from the declared destination block'
        for index, value in enumerate(record['fields']):
            if case.get('dst%d' % index) != value:
                return 'F6 destination word %d differs from the input' % index
        if case.get('dma_lane_written') != 4 * dma['block_words']:
            return 'F6 DMA did not write every byte of the declared destination block'
        if case.get('dma_lane_missing') != 0 or case.get('dma_lane_extra') != 0:
            return 'F6 DMA byte lanes were skipped or written twice'
        if case.get('dma_bytes_outside_block') != 0:
            return 'F6 DMA strobed bytes outside the declared destination block'
        if (case.get('dma_guard_lo') != DMA_DESTINATION_SENTINEL
                or case.get('dma_guard_hi') != DMA_DESTINATION_SENTINEL):
            return 'F6 DMA changed a guard word outside the declared destination block'
    if case.get('dma_block_words') != dma['block_words']:
        return 'F6 host block length differs from the declared block'
    if case.get('dma_expected_reads') != dma['expected_reads']:
        return 'F6 host expected-read count differs from the plan'
    # The start word the plan derived has to be the word the device received: the
    # host counts a start write only when its value is DMA_START_WORD.
    if case.get('dma_start_word') != dma['start_word']:
        return 'F6 header start word differs from the plan'
    if case.get('dma_start_write') != dma['start_word']:
        return 'F6 device did not receive the plan start word'
    # Byte enables: the device's own strobes have to be the declared pattern.  A
    # routed transfer is a full-word write (the target's APB bridge has no
    # strobes), so the same full-word criterion applies to both paths.
    if case.get('dma_master_partial') != int(dma['master_byte_enable']['partial']):
        return 'F6 host byte-enable mode differs from the plan'
    if case.get('dma_sel_undeclared') != 0:
        return 'F6 DMA presented a byte enable the plan does not declare'
    # A declared error injection aborts the transfer before its write side, so
    # the accepted master writes are the ones the injection left, not the block.
    write_beats = expected_writes if (route is not None) else dma['expected_writes']
    if dma['master_byte_enable']['partial']:
        if (case.get('dma_sel_partial') != write_beats
                or case.get('dma_sel_full') != 0):
            return 'F6 DMA byte enables are not the declared lane pattern'
    elif (case.get('dma_sel_full') != write_beats
          or case.get('dma_sel_partial') != 0):
        return 'F6 DMA byte enables are not a full word'
    # Backpressure: the declared delay is either measured per response or
    # reported as unknown, never assumed.
    delay = dma['delay_ticks']
    if case.get('dma_response_delay_declared') != delay:
        return 'F6 host response delay differs from the declaration'
    if delay:
        if case.get('dma_delay_evidence') != 'observed':
            return 'F6 declared response delay was not observed'
        if (case.get('dma_delayed_acks') != dma['expected_reads'] + dma['expected_writes']
                or case.get('dma_wait_min', 0) < delay + 1
                or case.get('dma_max_consecutive_stalls', 0) < delay + 1):
            return 'F6 measured response delay is shorter than the declaration'
    elif case.get('dma_delay_evidence') != 'not_declared':
        return 'F6 claims a response delay it never declared'
    if case.get('ctl_config_writes') != 3 or case.get('ctl_start_writes') != 1:
        return 'F6 CPU did not configure and start the DMA through its control port'
    if dma['clear'] is not None and case.get('ctl_clear_writes') != 1:
        return 'F6 handler did not perform the declared clear write'
    if dma['clear'] is None and case.get('ctl_clear_writes') != 0:
        return 'F6 performed a clear write the declaration does not have'
    if case.get('dma_clear_declared') != int(dma['clear'] is not None):
        return 'F6 clear expectation differs from the declaration'
    if case.get('ctl_reads') != 2 or case.get('ctl_reads_before_start') != 1:
        return 'F6 did not read the control word once before the start and once in the handler'
    # The completion criterion is the declared control word's busy and error
    # bits, not "the word is not zero": the transfer length sits in the same word.
    # A declared error injection is the one case whose ERR bit must be set: it is
    # the device's own sticky latch of the injected response, and the injected
    # case is the only place the entry expects it.
    expected_err = 1 if injected else 0
    if case.get('busy_after') != 0 or case.get('err_after') != expected_err:
        return 'F6 completion control word was still busy or in error'
    if case.get('isr_result') != case.get('ctl_status'):
        return 'F6 handler status read and its store disagree'
    if not injected and case.get('dma_done_tick') == 'unknown':
        # The completion event is derived from the last completed master write;
        # an injected error aborts before any write, and its completion is the
        # device's own error interrupt plus the ERR bit checked above.
        return 'F6 has no derived DMA completion event'
    if case.get('isr_flag') != 1:
        return 'F6 handler did not complete'
    if not (case.get('irq_edges') >= 1 and case.get('irq_takes') >= 1):
        return 'F6 has no sampled DMA IRQ edge and CPU take'
    return None


#: The key observations a prefix replay compares.  They are the case-line facts
#: that identify what the device/CPU actually did, not the wall-clock fields.
REPLAY_VIEW_FIELDS = {
    'F1': ('prog_words', 'prog_retires', 'prog_pc_ordered', 'prog_insns_match',
           'prog_trace_hash', 'prog_trace_count', 'prog_pc_order',
           'prog_writebacks', 'prog_rd_mask', 'prog_last_rd', 'prog_last_wdata',
           'prog_traps', 'data_changed'),
    'F2': ('read_addr', 'read_value', 'echo_value', 'read_from', 'target_reads',
           'apb_reads', 'target_read_offset', 'apb_read_offset', 'pad_settled',
           'pin_stimulus'),
    'F3': ('write_addr', 'write_value', 'write_be', 'ram_after'),
    'F4': ('mmio_addr', 'mmio_value', 'target_offset', 'apb_offset', 'target_wdata',
           'apb_pwdata', 'target_ready', 'apb_pready', 'target_resp', 'target_wstrb',
           'target_writes', 'apb_writes', 'out_after', 'dir_after'),
    'F5': ('trigger_writes', 'wait_timeout', 'irq_edges', 'irq_takes', 'isr_result',
           'isr_flag', 'target_reads', 'target_read_offset', 'apb_read_offset',
           'apb_read_data', 'target_read_data', 'isr_read_addr', 'isr_read_value',
           'isr_read_register_kind', 'irq_link', 'irq_link_target',
           'irq_cause_pins', 'inten_at_irq',
           # A two-source case adds its own keys; only the ones the saved line
           # really carried are compared, so a single-link replay view is
           # unchanged.
           *F5_BOTH_CASE_KEYS),
    'F6': ('dma_reads', 'dma_writes', 'ctl_config_writes', 'ctl_start_writes',
           'ctl_clear_writes', 'ctl_reads', 'ctl_status', 'wait_timeout', 'irq_edges',
           'irq_takes', 'isr_result', 'isr_flag', 'busy_after', 'err_after',
           'dma_first_read_addr', 'dma_last_write_addr', 'dma_start_write',
           'dma_acks', 'dma_delayed_acks', 'dma_wait_min', 'dma_wait_max',
           'dma_stall_ticks', 'dma_max_consecutive_stalls', 'dma_sel_full',
           'dma_sel_partial', 'dma_lane_written', 'dma_lane_missing', 'dma_lane_extra',
           'dma_bytes_outside_block', 'dma_guard_lo', 'dma_guard_hi',
           # A routed case adds its own key facts; a RAM-only case line carries
           # none of these keys and its replay view is unchanged.
           *F6_ROUTE_CASE_KEYS,
           # A read route printed a different group; only the keys the saved
           # line really carried are compared.
           *F6_ROUTE_READ_CASE_KEYS,
           *('dst%d' % index for index in range(16))),
}


def replay_view(case):
    """The comparable key observations of one parsed case line."""
    flow = case.get('flow')
    if flow not in REPLAY_VIEW_FIELDS:
        raise ValueError('unsupported replay flow: ' + str(flow))
    view = {'flow': flow, 'record': case.get('record'), 'status': case.get('status')}
    for key in REPLAY_VIEW_FIELDS[flow]:
        if key in case:
            value = case[key]
            if type(value) in (int, str):
                view[key] = value
    return view


def compare_replay(expected, observed):
    """Compare saved key observations with a replayed case; first mismatch wins."""
    if len(observed) < len(expected):
        return 'replay stopped after ' + str(len(observed)) + ' of ' + \
               str(len(expected)) + ' cases'
    for index, (want, got) in enumerate(zip(expected, observed)):
        if want.get('record') != got.get('record'):
            return 'case ' + str(index) + ' record differs'
        for key, value in want.items():
            if key in ('flow', 'record'):
                continue
            if got.get(key) != value:
                return ('case ' + str(index) + ' ' + str(key) + ' differs: saved ' +
                        repr(value) + ', replay ' + repr(got.get(key)))
    return None


class _PrefixRecorder:
    """Stream the exact input order to ``prefix.txt`` for a later replay.

    Only one text line per handed-over input is written; it is not a case
    document and not a certificate.  The file is flushed periodically and on
    close so a crash keeps the prefix up to the last flush.
    """

    def __init__(self, handle):
        self.handle = handle
        self.lines = 0

    def write(self, input_):
        self.handle.write(input_.text + '\n')
        self.lines += 1
        if self.lines % 32 == 0:
            self.handle.flush()

    def close(self):
        try:
            self.handle.flush()
        finally:
            self.handle.close()


class _ObservationRecorder:
    """Stream the key observations of each case for a prefix replay comparison."""

    def __init__(self, handle):
        self.handle = handle
        self.lines = 0

    def write(self, case):
        view = replay_view(case)
        self.handle.write(json.dumps(view, sort_keys=True) + '\n')
        self.lines += 1
        if self.lines % 32 == 0:
            self.handle.flush()

    def close(self):
        try:
            self.handle.flush()
        finally:
            self.handle.close()


class _RecordingStrategy:
    """Delegate to the real strategy and stream every input it returns."""

    def __init__(self, strategy, recorder):
        self.strategy = strategy
        self.recorder = recorder

    @property
    def flows(self):
        return self.strategy.flows

    def seed_inputs(self):
        inputs = self.strategy.seed_inputs()
        for input_ in inputs:
            self.recorder.write(input_)
        return inputs

    def next_input(self):
        input_ = self.strategy.next_input()
        self.recorder.write(input_)
        return input_


def fuzz_collaborators(config, *, base_dir, windows, arity, behavior_config,
                       ip_profile, pins, dma, f1_words, isa, refusals, label,
                       seed, cases, seconds, corpus_path=None,
                       max_cases_recorded=512, max_submitted_recorded=512,
                       stall_seconds=30.0, output=None, case_check=None,
                       log_case_lines=True, target_rows=None, f5_target_index=None,
                       f1_flags=None, fuzz_flows=None, f1_program_profile=None):
    """Build the closed-loop collaborators from the same declarations the run uses.

    The word input space is derived once from the scenario's windows, the
    target's own register map and the declared behavior; F1 programs come from
    the CPU profile through ``myfuzz.fuzz.rv32_program``.  Every input is gated
    by this entry's own ``parse_record``/``validate_record`` before the strategy
    may return it, so the fuzzer cannot hand the host a record the acceptance
    entry would refuse.

    ``fuzz_flows`` optionally narrows the offered flow set to the declared
    subset (for example ``["F1"]`` for a program-focused batch); a flow the
    components cannot serve is refused by name, never silently dropped.
    """
    from myfuzz.fuzz.corpus import Corpus
    from myfuzz.fuzz.feedback import FeedbackState
    from myfuzz.fuzz.session import SessionBudget, run_session
    from myfuzz.fuzz.strategy import FuzzStrategy
    from myfuzz.fuzz.word_spaces import DeclaredSpace, WordSpace
    from myfuzz.riscv.profile import profile_from_mapping

    flows = tuple(sorted(arity))
    if fuzz_flows is not None:
        # A declared subset is a selection, not a fallback: every named flow has
        # to be one this declaration can serve, and an unknown tag is refused by
        # name instead of being dropped from the batch.
        if (not isinstance(fuzz_flows, (list, tuple)) or not fuzz_flows
                or any(type(flow) is not str for flow in fuzz_flows)):
            raise ValueError('fuzz_flows must be a non-empty list of flow tags')
        selected = set(fuzz_flows)
        unknown = sorted(selected - set(flows))
        if unknown:
            raise ValueError('fuzz_flows names flow(s) this declaration cannot '
                             'serve: ' + ','.join(unknown))
        flows = tuple(flow for flow in flows if flow in selected)
        if not flows:
            raise ValueError('fuzz_flows selected no servable flow')
    program_profile = None
    f1_note = None
    if 'F1' in flows:
        candidate = profile_from_mapping(
            json.loads((base_dir / config['cpu_profile']).read_text()))
        if candidate.xlen == 32:
            program_profile = candidate
        elif f1_program_profile is not None:
            # The scenario declared an explicit RV32 projection for a 64-bit CPU
            # (see main): the generator emits RV32IM words, the 64-bit core
            # executes them, and the retirement trace is compared on the low 32
            # bits of the RV64 RVFI record.  The projection is the declaration's,
            # never inferred from the xlen.
            program_profile = f1_program_profile
        else:
            # The program generator is RV32-only.  An RV64 CPU still runs the
            # fixed-record F1 path, but the fuzzer states the narrower offer
            # instead of failing every F1 attempt.
            flows = tuple(flow for flow in flows if flow != 'F1')
            f1_note = ('F1 is not offered by the fuzzer: the short-program generator '
                       'supports RV32 only (the CPU declares xlen ' +
                       str(candidate.xlen) + ')')
            if fuzz_flows is not None and 'F1' in fuzz_flows:
                raise ValueError('fuzz_flows names F1 but: ' + f1_note)
    registers = tuple(dict(offset=row.offset, name=row.name, width=row.width,
                           access=row.access)
                      for row in ip_profile.address.registers)
    # One F5 example vector is the *value* column of the declared trigger writes;
    # the offsets are already fixed by the firmware's declared write sequence.
    trigger_rows = [row for row in (behavior_config.get('trigger_writes') or ())
                    if isinstance(row, list) and len(row) == 2]
    trigger_values = ((tuple(row[1] for row in trigger_rows),) if trigger_rows else ())
    declaration = DeclaredSpace(
        ram_base=windows['ram_base'], ram_size=windows['ram_size'],
        data_base=windows['data_base'], target_base=windows['ip_base'],
        target_size=windows['ip_size'], arity=dict(arity), registers=registers,
        pins=(dict(padin_offset=pins['padin_offset'], width=pins['width'])
              if pins is not None else None),
        trigger_values=trigger_values,
        block_words=(dma['block_words'] if dma is not None else 0),
        program_data_words=PROGRAM_DATA_WORDS,
        targets=tuple(target_rows or ()))
    space = WordSpace(declaration)
    # A flow whose declared address/value set is empty must not be offered: the
    # strategy would fail every attempt for it and end the batch.  The exclusion
    # is stated in the saved input document rather than silently dropped.
    excluded = []
    offered = []
    for flow in flows:
        if flow == 'F1':
            if program_profile is not None:
                offered.append(flow)
            continue
        try:
            counts = space.candidates(flow)
        except ValueError as error:
            excluded.append(dict(flow=flow, reason=str(error)))
            continue
        if counts.get('total', 0) > 0:
            offered.append(flow)
        else:
            excluded.append(dict(flow=flow, reason='no declared candidate'))
    if not offered:
        raise ValueError('no fuzz input flow can be generated from this declaration')
    flows = tuple(offered)

    def gate(flow, fields):
        text = flow + ':' + ':'.join(format(int(word), '08x') for word in fields)
        record = parse_record(text, windows=windows, arity=arity, label=label,
                              refusals=refusals, pin=pins, f1_words=f1_words,
                              f5_target_index=f5_target_index,
                              f1_allow_compressed=_f1_compressed(config, f1_flags))
        validate_record(record, isa=isa, windows=windows, f1_words=f1_words,
                        f1_subword=config.get('f1_subword', False),
                        f1_flags=f1_flags)
        return record['text'], record['message']

    # Operator-declared seed records state a real precondition (for example the
    # F4 PADDIR write a GPIO pin interrupt needs); they go through the same gate
    # and are served before generated inputs.
    seeds = config.get('fuzz_seed_records') or []
    if not isinstance(seeds, list) or any(not isinstance(item, str) for item in seeds):
        raise ValueError('fuzz_seed_records must be a list of record strings')
    extra_seeds = []
    for text in seeds:
        record = parse_record(text, windows=windows, arity=arity, label=label,
                              refusals=refusals, pin=pins, f1_words=f1_words,
                              f5_target_index=f5_target_index,
                              f1_allow_compressed=_f1_compressed(config, f1_flags))
        validate_record(record, isa=isa, windows=windows, f1_words=f1_words,
                        f1_subword=config.get('f1_subword', False),
                        f1_flags=f1_flags)
        extra_seeds.append((record['flow'], record['fields']))
    corpus = (Corpus.load(corpus_path, max_entries=256) if corpus_path is not None
              else Corpus(max_entries=256))
    feedback = FeedbackState()
    strategy = FuzzStrategy(
        flows=flows, gate=gate, program_profile=program_profile,
        f1_words=f1_words, program_window=PROGRAM_DATA_WORDS * 4,
        word_space=space, trigger_values=trigger_values, seed=seed, corpus=corpus,
        extra_seeds=extra_seeds, f1_subword=config.get('f1_subword', False),
        # The generator may only draw a computed-base shape the scenario
        # declared, so the flag is threaded from the one scenario gate.
        f1_allow_address_forms=getattr(
            f1_flags, 'allow_address_forms',
            bool(config.get('f1_allow_address_forms', False))),
        # The same gate decides whether the fuzzer may emit forward branches;
        # a branch program's retirement trace is then checked against the
        # reference trace by ``correspondence``.
        f1_allow_branches=getattr(
            f1_flags, 'allow_branches',
            bool(config.get('f1_allow_branches', False))),
        # And whether it may emit two-parcel (compressed) record words.  Every
        # offered program is trace-deterministic from the state the entry can
        # declare, so its reference trace stays comparable.
        f1_allow_compressed=_f1_compressed(config, f1_flags),
        # The control-flow shapes: statically proven jumps, the canonical
        # bounded loop, and the compressed control/memory parcel groups.  Each
        # generator validates its own image with the same flags, and
        # ``f1_image_base`` is the fixed slot address a JALR or C.JR resolves
        # its absolute target against.
        f1_allow_jumps=getattr(f1_flags, 'allow_jumps',
                               bool(config.get('f1_allow_jumps', False))),
        f1_allow_loops=getattr(f1_flags, 'allow_loops',
                               bool(config.get('f1_allow_loops', False))),
        f1_allow_compressed_control=getattr(
            f1_flags, 'allow_compressed_control',
            bool(config.get('f1_allow_compressed_control', False))),
        f1_allow_compressed_memory=getattr(
            f1_flags, 'allow_compressed_memory',
            bool(config.get('f1_allow_compressed_memory', False))),
        f1_image_base=windows['ram_base'] + SLOT_OFFSET)
    budget = SessionBudget(cases=cases, seconds=seconds)
    holder = {}
    classes = Counter()
    prefix_recorder = None
    observation_recorder = None
    if output is not None:
        output = Path(output)
        prefix_recorder = _PrefixRecorder((output / 'prefix.txt').open('w'))
        observation_recorder = (_ObservationRecorder(
            (output / 'observations.jsonl').open('w')))

    def classified_case_parser(line, *, flows):
        # Every case is classified here, before the session may drop it from its
        # bounded row sample, so the failure-class counts are complete even for a
        # long batch that retains only the first/last rows.
        case = parse_case_line(line, flows=flows)
        verdict = classify_case(case)
        case['failure_class'] = verdict['failure_class']
        case['failure_detail'] = verdict['detail']
        case['failure_severity'] = verdict['severity']
        classes[verdict['failure_class']] += 1
        if observation_recorder is not None:
            observation_recorder.write(case)
        return case

    session_strategy = (_RecordingStrategy(strategy, prefix_recorder)
                        if prefix_recorder is not None else strategy)

    def runner(command, log_path):
        try:
            session = run_session(command, log_path=log_path, strategy=session_strategy,
                                  feedback=feedback, corpus=corpus,
                                  case_parser=classified_case_parser,
                                  summary_parser=parse_summary_line, budget=budget,
                                  max_cases_recorded=max_cases_recorded,
                                  max_submitted_recorded=max_submitted_recorded,
                                  stall_seconds=stall_seconds,
                                  log_case_lines=log_case_lines,
                                  case_check=case_check)
        finally:
            if prefix_recorder is not None:
                prefix_recorder.close()
            if observation_recorder is not None:
                observation_recorder.close()
        holder['session'] = session
        return 0 if session.status in ('completed', 'completed_with_error') else 1

    return dict(strategy=strategy, feedback=feedback, corpus=corpus, budget=budget,
                runner=runner, holder=holder, declaration=declaration,
                classes=classes,
                prefix_file=('prefix.txt' if prefix_recorder is not None else None),
                observations_file=('observations.jsonl'
                                   if observation_recorder is not None else None),
                document=dict(schema_version='inprocess_fuzz_inputs.v1',
                              seed=seed, flows=list(flows),
                              declared_flows=(None if fuzz_flows is None
                                              else list(fuzz_flows)),
                              f1_program_words=f1_words,
                              f1_flags=(f1_flags.as_dict()
                                        if f1_flags is not None else None),
                              program_data_words=PROGRAM_DATA_WORDS,
                              corpus_source=None if corpus_path is None
                              else str(corpus_path),
                              prefix_file=('prefix.txt' if output is not None else None),
                              observations_file=('observations.jsonl'
                                                 if output is not None else None),
                              seed_records=[record['text'] for record in [
                                  parse_record(text, windows=windows, arity=arity,
                                               label=label, refusals=refusals,
                                               pin=pins, f1_words=f1_words,
                                               f5_target_index=f5_target_index,
                                               f1_allow_compressed=_f1_compressed(config, f1_flags))
                                  for text in (config.get('fuzz_seed_records') or [])]],
                              word_space=space.document(),
                              f1=(f1_note if f1_note is not None else
                                  'profile-driven short program, 1 to ' +
                                  str(f1_words) + ' words' if program_profile
                                  else 'not offered')))


def final_status(result, parsed, records):
    if result['returncode'] != 0:
        return 'failed'
    if parsed is None or parsed['summary'].get('status') != 'observations_passed':
        return 'failed'
    if len(parsed['cases']) != len(records):
        return 'failed'
    if any(case['status'] != 'observations_passed' for case in parsed['cases']):
        return 'failed'
    return 'observations_passed'


def apply_correspondence(result, parsed, records, checks):
    """Make the batch status account for the per-case correspondence checks.

    The host's own pass criteria cannot see a branch program's expected
    retirement trace: it knows the words it installed, not which of them a taken
    branch should skip.  Python does, so a case whose observed trace differs from
    the reference is a batch failure here even though the host marked the case
    ``observations_passed``.  A mismatch is therefore never only a recorded
    remark: the run ends ``failed`` with the first mismatch as its reason.
    """
    mismatched = [check for check in checks if check is not None]
    result['status'] = final_status(result, parsed, records)
    if result['status'] == 'observations_passed' and (
            mismatched or len(parsed['cases']) != len(records)):
        result['status'] = 'failed'
        result['failure'] = ('correspondence: ' + mismatched[0]
                             if mismatched else 'case count')
    return result


#: The component sets one process can build.  ``combined`` is the historical
#: CPU + target IP (+ DMA) session; the two single-side modes build exactly one
#: side of the boundary and are dispatched to their own modules, so the combined
#: declarations below are not read and no combined model is built for them.
MODES = ('combined', 'cpu-only', 'ip-only')

#: The run statuses a secondary mode may end on with a zero exit code.
SECONDARY_MODE_OK_STATUSES = frozenset(('observations_passed', 'fuzz_completed',
                                        'fuzz_completed_with_findings',
                                        'replay_matched'))


def dispatch_secondary_mode(args, parser):
    """Run one non-combined mode; return its exit code and printed payload.

    ``--mode cpu-only`` builds only the CPU (agent C's ``run_cpu_only`` API): no
    target and no DMA model exists in that process.  ``--mode ip-only`` builds
    only the selected target (``run_ip_only``): no CPU and no DMA model exists.
    A replay is a combined-mode session shape and is refused here by name instead
    of being silently ignored.  The mode runners own their output directory
    creation, their summary and their component inventories; this dispatch only
    selects one and maps its status onto the process exit code.
    """
    if args.replay_prefix is not None:
        parser.error('--replay-prefix is a combined-mode option')
    if args.mode == 'cpu-only':
        try:
            from scripts.inprocess_cpu_only import run_cpu_only
        except ImportError:
            parser.error('--mode cpu-only needs scripts/inprocess_cpu_only.py (the '
                         'CPU-only runner); it is not present in this workspace yet')
        # The CPU-only route consumes one mailbox word per record, so the entry's
        # comma-separated list is handed over as a list and the runner parses the
        # words (it owns that record shape).  Its fuzz shape is a {cases, seed,
        # mode} mapping, so the entry's --cases/--seed/--fuzz-mode are passed as
        # that mapping rather than reimplementing the loop here.  --fuzz-mode
        # defaults to program: this entry's --fuzz generates and executes a
        # different RV32 program per case, and data is the opt-in P0 shape.
        result = run_cpu_only(args.config, args.cache, args.output,
                              records=(None if not args.records else
                                       [word for word in args.records.split(',')
                                        if word.strip()]),
                              fuzz=(dict(cases=args.cases, seed=args.seed,
                                         mode=args.fuzz_mode)
                                    if args.fuzz else None),
                              max_ticks=args.max_ticks)
    elif args.mode == 'ip-only':
        from scripts.inprocess_ip_only import run_ip_only
        result = run_ip_only(args.config, args.cache, args.output,
                             records=args.records,
                             fuzz=(dict(cases=args.cases, seed=args.seed)
                                   if args.fuzz else None),
                             max_ticks=args.max_ticks, online=args.online,
                             quiet=args.quiet,
                             case_isolation=getattr(args, 'case_isolation', None))
    else:  # argparse already restricts the choices; this is a programming error.
        raise AssertionError('unsupported mode: ' + str(args.mode))
    if not isinstance(result, dict) or 'status' not in result:
        raise RuntimeError(args.mode + ' runner returned no status document')
    archives = result.get('model_archives')
    if isinstance(archives, dict):
        archives = archives.get('all')
    if archives is None:
        # The CPU-only runner states its archives as a row list under
        # ``archives``; keep one payload shape for every mode.
        rows = result.get('archives')
        if isinstance(rows, list):
            archives = [row.get('path') if isinstance(row, dict) else str(row)
                        for row in rows]
    components = result.get('components_loaded')
    components_source = 'the mode runner summary'
    if not isinstance(components, dict):
        # The CPU-only runner states its model set as ``archives[].kind`` rows and
        # its own summary is that runner's document; the entry derives the same
        # component counters from those rows instead of rewriting that document.
        rows = result.get('archives')
        if isinstance(rows, list):
            counts = Counter(row.get('kind') for row in rows
                             if isinstance(row, dict) and row.get('kind'))
            components = dict(cpu=counts.get('cpu', 0),
                              targets=sum(count for kind, count in counts.items()
                                          if kind not in ('cpu', 'dma')),
                              dma=counts.get('dma', 0), ram=0,
                              model_archives=len(rows))
            components_source = 'derived from the runner archives[].kind rows'
    payload = dict(mode=args.mode, status=result['status'], output=str(args.output),
                   cases=result.get('cases_executed', result.get('cases_total',
                                                                result.get('case_count'))),
                   model_archives=archives, components_loaded=components,
                   total_seconds=result.get('total_seconds',
                                            result.get('wall_seconds')))
    # The one place the entry itself documents the selected mode.  The combined
    # and IP-only summaries already carry mode/components_loaded/model_archives;
    # the CPU-only runner keeps its own summary document, so the entry states the
    # same three facts beside it without rewriting that document.
    mode_document = dict(
        schema_version='inprocess_entry_mode.v1', mode=args.mode,
        status=result['status'], components_loaded=components,
        components_source=components_source, model_archives=archives,
        runner_output=str(args.output),
        note='written by scripts/run_inprocess_f1f6.py --mode dispatcher')
    try:
        Path(args.output).mkdir(parents=True, exist_ok=True)
        (Path(args.output) / 'entry_mode.json').write_text(
            json.dumps(mode_document, indent=2) + '\n')
    except OSError:
        pass
    return (0 if result['status'] in SECONDARY_MODE_OK_STATUSES else 1), payload


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True,
                        help='CPU + IRQ target + DMA declaration with explicit timing')
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True,
                        help='new directory inside the workspace')
    parser.add_argument('--mode', choices=MODES, default='combined',
                        help='which components one process builds: the historical '
                             'CPU + target IP (+ DMA) session (default), the CPU-only '
                             'session, or the IP-only target session')
    parser.add_argument('--records', default=None,
                        help='comma-separated records, e.g. '
                             'F1:2ab00693,F5:00000000:00000000:ffffffff')
    parser.add_argument('--online', action='store_true',
                        help='hand over one record per NEED_RECORD instead of preloading all')
    parser.add_argument('--fuzz', action='store_true',
                        help='closed loop: generate/mutate the next input from the real '
                             'case observations of the previous one, in the same process')
    parser.add_argument('--fuzz-mode', choices=('program', 'data'), default='program',
                        help='--mode cpu-only: program generates and executes a different '
                             'RV32 program per case (default), data is the P0 shape of one '
                             '32-bit mailbox word per case for the pinned polling program')
    parser.add_argument('--cases', type=int, default=32,
                        help='fuzz case budget (default 32)')
    parser.add_argument('--seconds', type=float, default=None,
                        help='fuzz wall-clock budget in seconds (optional)')
    parser.add_argument('--seed', type=int, default=0,
                        help='fuzz PRNG seed (deterministic for the same tree and budget)')
    parser.add_argument('--corpus', type=Path, default=None,
                        help='seed the corpus from a saved corpus.json')
    parser.add_argument('--replay-prefix', type=Path, default=None,
                        help='replay a saved prefix.txt in a new process (fixed inputs)')
    parser.add_argument('--replay-observations', type=Path, default=None,
                        help='the observations.jsonl saved with the prefix')
    parser.add_argument('--replay-limit', type=int, default=None,
                        help='replay only the first N prefix inputs (default: all)')
    parser.add_argument('--stall-seconds', type=float, default=30.0,
                        help='fuzz mode: terminate a host that prints nothing for this '
                             'long (default 30 s)')
    parser.add_argument('--log-mode', choices=('case', 'summary'), default='case',
                        help='fuzz mode: keep per-case host lines (case) or only '
                             'summary/errors (summary; the conversation still parses '
                             'every case)')
    parser.add_argument('--no-prefix', action='store_true',
                        help='fuzz mode: do not stream prefix.txt/observations.jsonl '
                             '(long soak runs without replay)')
    parser.add_argument('--retain-cases', type=int, default=512,
                        help='fuzz mode: bound on retained per-case rows in summary.json '
                             'and fuzz.json (rolling counts are always complete)')
    parser.add_argument('--max-ticks', type=int, default=None,
                        help='total host tick budget for the whole process; the default '
                             'is 20000 for a fixed-record run and max(20000, cases*4096) '
                             'for --fuzz (each case has its own 4000-tick guard)')
    parser.add_argument('--quiet', action='store_true',
                        help='suppress per-tick/per-transfer event lines; case and '
                             'summary lines are unchanged (a lean batch run)')
    parser.add_argument('--case-isolation', choices=('long-running', 'prefix-replay'),
                        default=None,
                        help='--mode ip-only session shape: one long-running process '
                             'for the whole transaction list (default), or the '
                             'historical one-child-per-case prefix replay')
    args = parser.parse_args(argv)
    if args.max_ticks is not None and args.max_ticks < 1:
        parser.error('--max-ticks must be positive')
    if args.mode != 'combined':
        # The two single-side modes are their own processes: their module reads the
        # declaration and builds one side of the boundary.  Nothing below this
        # branch runs for them, and nothing above it builds a model.
        if args.output.exists():
            parser.error('output directory already exists')
        try:
            code, payload = dispatch_secondary_mode(args, parser)
        except ValueError as error:
            parser.error(str(error))
        print(json.dumps(payload))
        return code
    replay = None
    if args.replay_prefix is not None:
        if args.fuzz or args.records:
            parser.error('--replay-prefix is an alternative to --fuzz and --records')
        if args.replay_observations is None:
            parser.error('--replay-observations is required with --replay-prefix')
        if args.replay_limit is not None and args.replay_limit < 1:
            parser.error('--replay-limit must be positive')
        try:
            prefix_lines = [line.strip() for line in
                            args.replay_prefix.read_text().splitlines() if line.strip()]
            expected_lines = [line for line in
                              args.replay_observations.read_text().splitlines() if line.strip()]
        except OSError as error:
            parser.error('cannot read the saved prefix: ' + str(error))
        limit = len(prefix_lines) if args.replay_limit is None else args.replay_limit
        prefix_lines = prefix_lines[:limit]
        if not prefix_lines:
            parser.error('the saved prefix has no input')
        if len(expected_lines) < len(prefix_lines):
            parser.error('the saved observations are shorter than the replayed prefix')
        try:
            expected = [json.loads(line) for line in expected_lines[:len(prefix_lines)]]
        except ValueError as error:
            parser.error('the saved observations are not JSON lines: ' + str(error))
        replay = dict(prefix=prefix_lines, expected=expected,
                      source=str(args.replay_prefix), limit=len(prefix_lines))
        args.online = True
    elif args.fuzz:
        if args.records:
            parser.error('--records and --fuzz are alternatives')
        if args.cases < 1:
            parser.error('--cases must be positive')
        if args.seconds is not None and args.seconds <= 0:
            parser.error('--seconds must be positive')
        if args.seed < 0:
            parser.error('--seed must be non-negative')
        if args.retain_cases < 1:
            parser.error('--retain-cases must be positive')
        if args.stall_seconds <= 0:
            parser.error('--stall-seconds must be positive')
        # The fuzz loop is the online handover by construction.
        args.online = True
    elif not args.records:
        parser.error('--records is required unless --fuzz or --replay-prefix is given')
    # A fixed-record run keeps the historical 20000-tick process budget.  A fuzz
    # batch or a prefix replay reserves the per-case guard for every input, so a
    # long batch is not cut short by the process-level tick counter.
    if args.max_ticks is None:
        if args.fuzz:
            args.max_ticks = max(20000, args.cases * 4096)
        elif replay is not None:
            args.max_ticks = max(20000, len(replay['prefix']) * 4096)
        else:
            args.max_ticks = 20000
    try:
        config = json.loads(args.config.read_text())
    except (OSError, ValueError) as error:
        parser.error('cannot read the declaration: ' + str(error))
    if args.output.exists():
        parser.error('output directory already exists')
    # The declared program length is a scenario fact: 1 keeps the single-word
    # legacy F1 input, >1 declares a short straight-line program in the
    # trampoline slot.  The firmware, header and record gate all read it here.
    f1_words = config.get('f1_program_words', 1)
    f1_subword = config.get('f1_subword', False)
    if type(f1_subword) is not bool or (f1_subword and f1_words < 2):
        parser.error('f1_subword requires a boolean and f1_program_words > 1')
    wait_iterations = config.get('handler_wait_iterations', 256)
    case_tick_budget = config.get('case_tick_budget', 4000)
    if type(case_tick_budget) is not int or not 1 <= case_tick_budget <= 1000000:
        parser.error('case_tick_budget must be an integer in 1..1000000')
    if type(wait_iterations) is not int or not 1 <= wait_iterations <= 2047:
        parser.error('handler_wait_iterations must be an integer in 1..2047')
    if type(f1_words) is not int or not 1 <= f1_words <= MAX_F1_PROGRAM_WORDS:
        parser.error('f1_program_words must be an integer in 1..' +
                     str(MAX_F1_PROGRAM_WORDS))
    # The declared program *shape* is read once, here, by the one scenario gate:
    # it owns the boolean checks, the program-mode requirement of every opt-in,
    # and the shape combinations this increment cannot execute.  Every record
    # gate, the fuzz strategy and the header consume this one value.
    from myfuzz.fuzz.f1_program_gate import f1_gate_flags_from_scenario
    try:
        f1_flags = f1_gate_flags_from_scenario(config)
    except ValueError as error:
        parser.error(str(error))
    # An optional declared subset of the fuzzed flows (``["F1"]`` focuses a
    # program batch).  It is checked here, before any model exists, and again by
    # the collaborator builder against the flows this declaration can serve.
    fuzz_flows = config.get('fuzz_flows')
    if fuzz_flows is not None and (
            not isinstance(fuzz_flows, list) or not fuzz_flows
            or any(type(flow) is not str for flow in fuzz_flows)):
        parser.error('fuzz_flows must be a non-empty list of flow tags')

    from myfuzz.composition.component_profile import (elaboration_mode_scope,
                                                      load_component_profile)
    from myfuzz.composition.inprocess_behavior import (HOST_SOURCE_EXECUTION,
                                                       SOURCE_BEHAVIOR_KEYS,
                                                       behavior_document, source_behavior)
    from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
    from myfuzz.isa.constraints import f1_isa_from_profile
    from myfuzz.local_harness.build import host_source_discovery_scope, harness_validation_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from scripts.run_timer_irq_smoke import timer_artifact
    from scripts.run_inprocess_f1f4 import (cpu_request_from_config,
                                            source_request_from_profile)

    started = time.monotonic()
    args.output.mkdir(parents=True)
    with elaboration_mode_scope('direct'), host_source_discovery_scope(reuse_nested=True), \
            harness_validation_scope(), execution_validation_scope():
        cpu_request_path = (args.output / 'cpu_request.json').resolve()
        cpu_request_path.write_text(json.dumps(cpu_request_from_config(config), indent=2) + '\n')
        cpu = timer_artifact(ROOT, str(cpu_request_path),
                             config.get('cpu_instance_id', 'cpu'))
        bus = cpu_bus(cpu.runtime_document)
        custom_irq = None
        if bus == 'wishbone' and 'cpu_irq_bit' in config:
            from myfuzz.local_harness.profile_custom_irq import verify_custom_irq_artifact
            bit = config['cpu_irq_bit']
            if type(bit) is not int or not 3 <= bit < 32:
                raise ValueError('cpu_irq_bit must name an external Pico IRQ bit 3..31')
            contract = verify_custom_irq_artifact(cpu, base_dir=ROOT)
            custom_irq = dict(irq_bit=bit, handler_address=contract['handler_address'],
                              eoi_runtime_name=contract['bindings']['eoi_port'])
        # The CPU's declared interrupt width is only meaningful when the CPU
        # has an interrupt input at all; an AHB-Lite boundary declares none, so
        # asking for a width there is what makes the refusal concrete.
        cpu_irq_bits = None if bus == 'ahb' else cpu_irq_width(cpu.runtime_document)
        # A packed AXI4 CPU may only take an interrupt when its built model really
        # carries the declared entry and its retirement face really states the
        # take witness.  Both are facts of the artifact, so the contract is
        # resolved once and passed to every target's F5 declaration; which fact
        # is missing decides the named refusal.
        axi4_irq = (packed_axi4_irq_contract(cpu.runtime_document, cpu.plan.profile)
                    if bus == 'axi4' else None)
        axi4_irq_refusal = None
        if bus == 'axi4' and axi4_irq is None:
            axi4_irq_refusal = (AXI4_F5_REFUSAL
                                if cpu_irq_entry(cpu.runtime_document,
                                                 cpu.plan.profile) is None
                                else AXI4_F5_WITNESS_REFUSAL)
        # The CPU-side take witness every F5/F6 case needs.  It is a declared port
        # of this CPU model, never inferred from a successful bus access; a model
        # that exports none of the three carries a named refusal into both flows.
        # The packed AXI4 face is the scoreboard model Verilated beside the CPU,
        # not a CPU port, so its rvfi_intr is stated from the witness bundle the
        # AXI4 path resolved above.
        if bus == 'axi4':
            cpu_take_witness = 'rvfi_intr' if axi4_irq is not None else None
            cpu_take_witness_missing = (
                None if cpu_take_witness is not None else
                'needs-one-of:probe_irq_taken_pre,custom_eoi,rvfi_intr at the '
                'packed-axi4 scoreboard')
        else:
            cpu_take_witness, cpu_take_witness_missing = cpu_irq_take_witness(
                cpu.runtime_document, custom_irq)
        cpu_witness_missing = (None if cpu_take_witness is not None
                               else str(cpu_take_witness_missing))
        # One generated artifact per declared target, each with its own
        # declaration-derived request.  The legacy single-target keys normalize
        # to a one-row target list through the composition layer, so this loop is
        # also the old build: no CPU x IP branch and no device name decides the
        # request or the bound ports.
        declared = declared_targets(config)
        declared_count = len(declared)
        states = []
        protocols = set()
        for target in declared:
            target_config = target_as_legacy_config(target)
            if 'targets' not in config:
                # A legacy one-target declaration keeps its device behavior facts
                # (the F5 source/trigger/status keys and the optional behavior
                # file) at the top level of the scenario.  The normalized target
                # row does not repeat them, so they are carried into the row's
                # legacy config here: without this an inline F5 declaration would
                # silently become "no IRQ facts" and F5 would be refused by name.
                for key in LEGACY_BEHAVIOR_KEYS:
                    if key in config and key not in target_config:
                        target_config[key] = config[key]
                # The ordered clear sequence is an executor declaration in this
                # increment (the behavior schema's own ``clear_sequence`` spelling
                # is still bounded to one step by its host capability fact), so a
                # legacy scenario states it under the executor's key.
                if 'irq_clear_sequence' in config:
                    target_config.setdefault('irq_clear_sequence',
                                             config['irq_clear_sequence'])
                if target.get('behavior') is not None:
                    target_config.setdefault('source_behavior', target['behavior'])
                target_config.setdefault('source_fixed_inputs', list(target.get('fixed_inputs') or ()))
                target_config.setdefault('source_tuning', dict(target.get('tuning') or {}))
                if target.get('pins') is not None:
                    target_config.setdefault('pins', target['pins'])
            profile_document = json.loads((ROOT / target['profile']).read_text())
            target_protocol_kind = profile_protocol(profile_document)
            # A dir-resolved pad endpoint needs the pre/post tick stream its probes
            # are sampled on; a component whose "external pins" are single serial
            # pins does not, so the profile's own field roles decide.
            pinned = any(endpoint.get('function') == 'external_pins'
                         and {'in', 'out', 'dir'} <= {field.get('role')
                                                      for field in endpoint.get('fields', [])}
                         for endpoint in profile_document.get('endpoints', []))
            if pinned and declared_count > 1:
                raise ValueError('unsupported-pins:multiple-targets')
            if target_protocol_kind == 'axi4-lite':
                from scripts.run_inprocess_axi4lite import (
                    source_request_from_profile as axi_source_request_from_profile)
                target_request = axi_source_request_from_profile(target_config,
                                                               profile_document)
            elif target_protocol_kind in ('wishbone', 'tl-ul'):
                # The generic Wishbone and TL-UL register kernels are built from
                # the same v2 request shape: the profile names the endpoint, the
                # protocol selects the pinned template variant, and the declared
                # fixed inputs are the pin constants.
                target_request = generic_target_request_from_profile(
                    target_config, profile_document, target_protocol_kind)
            elif target_protocol_kind == 'ahb-lite':
                # The one AHB-Lite target kind: the profile's own mmio slave
                # endpoint selects the pinned ``target.ahb-lite/1`` full-word
                # variant, and the generated model binds it to the real
                # ``ahb_lite_mmio_target`` manager.  Dispatching on the declared
                # protocol keeps this a device/protocol fact, not a CPU x IP
                # branch.
                target_request = ahb_target_request_from_profile(
                    target_config, profile_document)
            elif pinned:
                tuning = dict(target_config.get('source_tuning') or {})
                tuning.setdefault('raw_tick_stream', [dict(sampling='pre_post')])
                target_request = dict(schema_version='local_harness.v2',
                                      profile_path=target['profile'],
                                      instance_id=target['active_id'],
                                      **explicit_timing(target_config, 'source_timing'),
                                      tuning=tuning)
            else:
                target_request = source_request_from_profile(target_config)
            name = ('source_request.json' if declared_count == 1 else
                    'source_request_%d_%s.json' % (target['index'], target['name']))
            request_path = (args.output / name).resolve()
            request_path.write_text(json.dumps(target_request, indent=2) + '\n')
            artifact = timer_artifact(ROOT, str(request_path), target['active_id'])
            # The generated artifact is the authority on what was built; the
            # profile's declared protocol and the artifact's kind and trace have
            # to agree, and a disagreement is refused instead of being resolved
            # in favour of one.
            artifact_protocol = target_protocol(artifact.runtime_document)
            if artifact_protocol != target_protocol_kind:
                raise ValueError('unsupported-target-protocol:' +
                                 target_protocol_kind + ':' + artifact_protocol)
            if bus == 'wishbone' and artifact_protocol == 'axi4-lite':
                raise ValueError('unsupported: a Wishbone CPU build drives APB3 targets only')
            protocols.add(artifact_protocol)
            # Protocol wiring and device behavior are separate declarations: the
            # profile/bus adapter decides what the components can be connected to,
            # and the behavior layer states how this device raises and clears an
            # interrupt, which registers trigger it, how its pads are driven, and
            # where its DMA control bits live.
            # The declared clear sequence is this executor's declaration and is
            # kept out of the behavior-schema call: the two spellings are not
            # merged, and the schema's host capability still bounds its own
            # ``clear_sequence`` fact to one step.
            declared_clear_sequence = target_config.pop('irq_clear_sequence', None)
            if declared_clear_sequence is None:
                declared_clear_sequence = target.get('irq_clear_sequence')
            target_facts = source_behavior(target_config, base_dir=ROOT)
            target_behavior = dict(target_config)
            if declared_clear_sequence is not None:
                target_behavior['clear_sequence'] = declared_clear_sequence
            if target_facts is not None:
                for key in SOURCE_BEHAVIOR_KEYS:
                    if key in target_facts:
                        target_behavior[key] = target_facts[key]
                # A v2 file states its links as a list; keep that list intact so
                # the executor can validate and render each link instead of
                # flattening it into the first one.
                if 'sources' in target_facts:
                    target_behavior['irq_sources'] = target_facts['sources']
                if target_facts.get('pins') is not None:
                    target_behavior['pins'] = target_facts['pins']
            target_pins = pin_declaration(target_behavior, artifact.plan.profile)
            if target_pins is not None and declared_count > 1:
                raise ValueError('unsupported-pins:multiple-targets')
            target_registers = (pin_registers(artifact.plan.profile, target_behavior)
                                if target_pins is not None else None)
            target_irq, target_refusal = f5_declaration(
                target_behavior, artifact.plan.profile, artifact_protocol,
                cpu_bus_kind=bus, cpu_irq_bits=cpu_irq_bits,
                cpu_custom_irq=custom_irq is not None,
                cpu_irq_witness=axi4_irq is not None,
                cpu_irq_refusal=axi4_irq_refusal)
            f5_protocol_check(artifact_protocol, target['name'], target_irq)
            timing = target.get('timing') or {}
            states.append(dict(target=target, config=target_config,
                              profile=artifact.plan.profile,
                              artifact=artifact, protocol=artifact_protocol,
                              behavior=target_facts, behavior_config=target_behavior,
                              pins=target_pins, registers=target_registers,
                              irq=target_irq, f5_refusal=target_refusal,
                              window=dict(target['window']),
                              reset_assert=timing.get('reset_assert_ticks', 2),
                              reset_release=timing.get('reset_release_ticks', 3)))
        # A build may route to more than one target protocol: each target's own
        # artifact states its protocol, and the host selects the trace sample and
        # the completion criterion from the routed target's trait.  Any subset of
        # 2..4 supported protocols may be mixed; a protocol outside that set keeps
        # the named refusal.  ``axis_label`` names the declared axis in the run
        # document and in a record-refusal message, so a three-protocol session
        # never calls itself the historical pair.
        protocol, mixed = target_protocol_axis(protocols)
        axis_label = target_protocol_label(protocol, protocols if mixed else None)
        # Every target that declares the four F5 facts owns its IRQ links.  The
        # composition layer returns them in declaration order, and the entry
        # numbers every declaring target's links in one global table so one F5
        # record selects one link - and therefore one target's trigger, status
        # and clear path.  The CPU has one interrupt input, so the host delivers
        # the OR of all those real device outputs; a case's evidence still names
        # the one target its ISR really read.
        # A CPU with no take/EOI/retirement witness cannot pass F5: the flow's
        # acceptance needs the CPU to have entered the handler and the host will
        # not read that from a bus success.  The target's own IRQ facts stay
        # stated by the per-target refusal the target loop already produced, so
        # the device half of the declaration remains visible.
        witness_refusals = cpu_flow_witness_refusals(
            bus, cpu_take_witness, cpu_witness_missing)
        if 'F5' in witness_refusals:
            for state in states:
                if state['irq'] is not None:
                    state['irq'] = None
                    state['f5_refusal'] = witness_refusals['F5']
        declaring_facts = [state['behavior'] if state['irq'] is not None else None
                           for state in states]
        declaring_targets = targets_for_f5(declared, declaring_facts)
        state_by_index = {state['target']['index']: state for state in states}
        declaring_states = [state_by_index[row['index']] for row in declaring_targets]
        if not declaring_states:
            f5_index = None
            irq = None
            f5_links = []
            f5_both = None
            f5_refusal = next((state['f5_refusal'] for state in states
                               if state['f5_refusal'] is not None), None)
        else:
            f5_index = declaring_states[0]['target']['index']
            f5_links = []
            for state in declaring_states:
                for link in (state['irq'].get('links') or [state['irq']]):
                    row = dict(link)
                    row['index'] = len(f5_links)
                    row['target_index'] = state['target']['index']
                    row['base'] = state['window']['base']
                    f5_links.append(row)
            # One F5 record shape serves every physical link: the global link
            # index followed by that link's declared trigger values.  Two links
            # with a different trigger-write count would make one input shape
            # ambiguous, so that declaration is refused instead of resolved in
            # favour of one.
            if len({len(link['trigger_offsets']) for link in f5_links}) != 1:
                raise ValueError('unsupported-f5:irq-links-differ-in-arity')
            # The synthetic "both" row: a two-source case addresses every
            # member's status/result/clear cells in one ISR entry and writes both
            # trigger sequences.  Its ISR carries two status/result/clear cell
            # sets, so the row has exactly two members however many targets
            # declare F5: with three or more declaring targets it pairs the first
            # two in declaration order, and every other target stays selectable
            # through its own single-link row.  Each member must be the only link
            # its target declares, because the pair's per-target read/clear
            # counters cannot tell two simultaneously asserted links of one
            # target apart.  Anything else keeps the single-link cases and states
            # the reason the both row is absent.
            f5_both = None
            f5_both_refusal = None
            if len(declaring_states) >= 2:
                members = []
                for state in declaring_states:
                    owned = [link for link in f5_links
                             if link['target_index'] == state['target']['index']]
                    if len(owned) != 1:
                        members = None
                        f5_both_refusal = 'unsupported-f5:both-needs-one-link-per-target'
                        break
                    members.append(owned[0])
                if members is not None:
                    # Two members, by the ISR's two cell sets.  A declaration with
                    # more than two single-link targets pairs the first two; the
                    # summary states the pair the case really addresses.
                    members = members[:2]
                    if any(len(member.get('clears') or ()) > 1 for member in members):
                        # The pair's ISR carries one clear cell pair per member;
                        # a member whose ack protocol is an ordered multi-write
                        # sequence would need its own sequence cells, so the pair
                        # is refused by name rather than truncated to one write.
                        f5_both_refusal = 'unsupported-f5:both-with-multi-step-clear'
                        members = None
                if members is not None:
                    f5_both = dict(
                        index=len(f5_links), mode='both',
                        target_index=None, base=None,
                        target_indices=[member['target_index'] for member in members],
                        members=members,
                        trigger_offsets=[offset for member in members
                                         for offset in member['trigger_offsets']],
                        status_offsets=[member['status_offset'] for member in members],
                        status_kinds=[member['status_kind'] for member in members],
                        cause_declared=any(member['cause_declared']
                                           for member in members),
                        cause_mask=sum(member['cause_mask'] for member in members),
                        cause_masks=[member['cause_mask'] for member in members],
                        cause_bits=[bit for member in members
                                    for bit in member['cause_bits']],
                        clear=None,
                        clears=[member['clear'] for member in members],
                        trigger='both',
                        level=any(member['trigger'] == 'level'
                                  for member in members),
                        port=None, bit=None, polarity=None,
                        status_kind='both')
            else:
                f5_both_refusal = 'unsupported-f5:both-needs-two-targets'
            irq = dict(links=f5_links, both=f5_both,
                       both_refusal=f5_both_refusal,
                       source_count=len(f5_links),
                       multi_target=len(declaring_states) > 1, **f5_links[0])
            f5_refusal = None
        pins = states[0]['pins'] if declared_count == 1 else None
        registers = states[0]['registers'] if declared_count == 1 else None
        # The declared pad groups and serial peer are one wire each on one target,
        # so they are resolved against the very artifact the host binds.  The
        # declaration layer normalized them; this is the executor half: which pad
        # word the endpoint exposes, which pad roles the peer may own.  A form the
        # bound device cannot serve is refused by name here, before any build.
        group_declaration = (pin_group_declaration(
            states[0]['behavior'], states[0]['profile'],
            states[0]['artifact'].runtime_document,
            bus=bus, target_count=declared_count)
            if declared_count == 1 else None)
        pin_groups = None if group_declaration is None else group_declaration['groups']
        serial_peer = None if group_declaration is None else group_declaration['serial']
        if pins is None and any(group['kind'] == PIN_GROUP_KIND_DIR
                                for group in (pin_groups or ())):
            # A dir-resolved group is a pad word: the host binds it only on a
            # target whose profile declares the dir-resolved pad endpoint, which is
            # what the pad-model check above already required for the derived
            # ``pins`` fact.  A declaration that mixes that group with a serial peer
            # is refused whole, not run for the half this host could resolve.
            raise ValueError('unsupported-pins:pin_groups:no-pad-endpoint')
        # The DMA declaration is a session-wide component, not a target.
        dma_model = None
        dma_facts = None
        if config.get('dma_profile') is not None:
            dma_request_path = (args.output / 'dma_request.json').resolve()
            dma_request_path.write_text(json.dumps(
                dict(schema_version='local_harness.v1', profile_path=config['dma_profile'],
                     instance_id='dma', **explicit_timing(config, 'dma_timing')), indent=2) + '\n')
            dma_model = timer_artifact(ROOT, str(dma_request_path), 'dma')
            if 'dma_capability' in config:
                _capability(dma_model.plan.profile, config['dma_capability'], 'dma',
                            ROOT, args.output)
        # The executor-level behavior keeps the scenario-wide keys (DMA block
        # words, pins) and adds the F5 target's own declared facts.
        source_facts = (states[f5_index]['behavior'] if f5_index is not None
                        else states[0]['behavior'])
        behavior_config = dict(config)
        if f5_index is not None:
            for key, value in states[f5_index]['behavior_config'].items():
                if (key in SOURCE_BEHAVIOR_KEYS
                        or key in ('irq_sources', 'pins', 'clear_sequence')):
                    behavior_config[key] = value
        dma = None
        f6_refusal = None
        if dma_model is None:
            f6_refusal = 'unsupported-f6:no-dma-model:' + axis_label
        else:
            # The route, when one is declared, is resolved against the target
            # rows that were really built: their windows, profiles and protocols
            # are the authority, so a route can never name a target this build
            # does not have.
            route_targets = [dict(index=state['target']['index'],
                                  name=state['target']['name'],
                                  window=dict(state['window']),
                                  profile=state['profile'],
                                  profile_path=state['target']['profile'],
                                  protocol=state['protocol'])
                             for state in states]
            dma = dma_declaration(behavior_config, dma_model.plan.profile,
                                  dma_model.runtime_document,
                                  targets=route_targets, cpu_bus=bus)
            dma_facts = dma['declared_behavior']
            if dma.get('route') is not None:
                # The route's completion criterion is the APB3 one; a route that
                # names another protocol is refused by name and the APB3 route is
                # unchanged.
                routed = state_by_index[dma['route']['target_index']]
                dma_route_protocol_check(routed['protocol'], routed['target']['name'])
        # F6 completion is witnessed by the same CPU-side take port F5 needs: the
        # DMA's own interrupt is delivered to the CPU's declared input and the
        # handler's completion is what the case accepts.  A CPU model that exports
        # no take/EOI/retirement witness cannot supply that, so F6 is refused by
        # name and a successful bus access is never used in its place.  The DMA
        # model itself is still bound and its own declared facts stay in the
        # summary; only the flow is refused.
        if dma_model is not None and 'F6' in witness_refusals:
            f6_refusal = witness_refusals['F6']
        # The address view carries every target window, not just the first one:
        # the record parser, the host header and the fuzz input space all read
        # the same list.
        windows = target_windows(
            config, dma_window=(None if dma_model is None
                                else dma_model.plan.profile.address.window_size))
        windows['target_count'] = declared_count
        # Each target's own protocol travels with the address view, so the record
        # parser, the per-case correspondence check and the saved summary all read
        # one declaration instead of re-deriving it from a device name.
        windows['target_protocols'] = [state['protocol'] for state in
                                       sorted(states, key=lambda row: row['target']['index'])]
        irq_base = (target_window_of(windows, f5_index)['base']
                    if f5_index is not None else windows['ip_base'])
        # The header and the run summary state the same ordered target list.
        target_descriptors = [dict(index=state['target']['index'],
                                   name=state['target']['name'],
                                   artifact=state['artifact'].runtime_document,
                                   protocol=state['protocol'], window=state['window'],
                                   irq=state['irq'], pins=state['pins'],
                                   registers=state['registers'],
                                   fixed_inputs=list(state['target']['fixed_inputs']),
                                   has_f5=state['irq'] is not None,
                                   reset_assert=state['reset_assert'],
                                   reset_release=state['reset_release'])
                              for state in states]
        # One normalized clock plan for this model set.  It is saved beside the
        # requests as run evidence and handed to the header, so the generated
        # macros and the saved plan are two renderings of one normalization - and
        # the summary below can state the very schedule the host ran.
        clock_plan = clock_plan_for_artifacts(
            cpu.runtime_document, target_descriptors,
            None if dma_model is None else dma_model.runtime_document,
            assume_single_clock=config.get('assume_single_clock') is True)
        (args.output / 'clock_plan.json').write_text(json.dumps(
            dict(schema_version='inprocess_clock_plan.v1', **clock_plan),
            indent=2) + '\n')
        target_rows = [dict(index=state['target']['index'],
                            base=state['window']['base'],
                            size=state['window']['size'],
                            registers=tuple(dict(offset=row.offset, name=row.name,
                                                 width=row.width, access=row.access)
                                            for row in state['profile'].address.registers))
                       for state in states]
        arity = flow_arity(irq, dma)
        refusals = {}
        # A packed AXI4 CPU serves F1 only when its RVFI probe bundle is exported
        # whole: that is the retirement channel the pinned scoreboard turns into
        # records, and the host's own F1 gate re-checks the count, the order, the
        # installed words and the trap count from that stream.  A model without
        # the bundle keeps the named refusal, because a fetch beat is not a
        # retirement.
        axi4_retirement = axi4_rvfi_probe_export(cpu.runtime_document)
        if bus == 'ahb' or (bus == 'axi4' and axi4_retirement is None):
            # F1 is a retirement input.  These CPUs export no RVFI/commit channel,
            # so the flow is removed from the servable set and refused by name:
            # a fetch beat is not a retirement.
            arity.pop('F1', None)
            refusals['F1'] = (AHB_F1_REFUSAL if bus == 'ahb' else AXI4_F1_REFUSAL)
        if f5_refusal is not None:
            refusals['F5'] = f5_refusal
        if f6_refusal is not None:
            refusals['F6'] = f6_refusal
        refusals = refusals or None
        if windows['data_base'] + 4 * PROGRAM_DATA_WORDS > (
                windows['ram_base'] + windows['ram_size']):
            raise ValueError('the declared RAM leaves no room for the program data '
                             'window at ' + hex(windows['data_base']))
        # ``f5_links`` is the entry's global physical link table (empty when F5 is
        # refused); the record parser, the header and the evidence checks all
        # read it.  ``f5_select_links`` adds the synthetic both row, which only
        # the record gate and the firmware dispatch need.  A multi-declaring
        # scenario hands the header the physical table; a single-target one keeps
        # the historical rendering path.
        header_f5_links = f5_links if (irq is not None and irq.get('multi_target')) else None
        f5_select_links = f5_link_table(irq) if irq is not None else []
        records = [parse_record(text, windows=windows, arity=arity,
                                label=axis_label, refusals=refusals, pin=pins,
                                serial=serial_peer,
                                f1_words=f1_words, f5_links=f5_select_links,
                                f5_target_index=f5_index,
                                f1_allow_compressed=_f1_compressed(config, f1_flags))
                   for text in (replay['prefix'] if replay is not None
                                else [] if args.fuzz else args.records.split(','))]
        # A model declared faster than the reference CPU has its clock
        # sub-stepped (several of its own edges inside one host tick) but its
        # whole access window is shorter than the one per-tick protocol sample
        # this host takes, so a record routed to it is refused by name instead
        # of being run and timing out.  See faster_model_traffic_refusal.
        faster_model_traffic_refusal(clock_plan, records)
        if bus in ('ahb', 'axi4'):
            # These CPUs bake their reset vector into their own configuration and
            # declare no IF-stage formula this entry can evaluate.  The artifact's
            # declared base IS the boot address; the host observes the first fetch
            # at runtime instead of predicting one.  (CVA6 additionally exports
            # RV64 state, which the RV32 formula layer does not model.)
            boot = cpu.runtime_document['boot_contract']['configured_boot_base']
            if type(boot) is not int or boot % 4:
                raise ValueError('boot-contract:unaligned-configured-base')
        else:
            boot = source_backed_boot_fetch(cpu.plan.profile, base_dir=ROOT,
                                            configured_boot_base=cpu.runtime_document['boot_contract']['configured_boot_base'])
        # The RAM base follows the CPU's own boot contract: the reset vector the
        # artifact declares has to be inside the declared image, so a CPU whose
        # reset vector is 0 (PicoRV32) needs the image at 0 and never a base
        # copied from another CPU's run.
        if not (windows['ram_base'] <= boot < windows['ram_base'] + windows['ram_size']):
            raise ValueError('ram-base-does-not-follow-boot-contract:' +
                             hex(windows['ram_base']) + ':' + hex(boot))
        isa = f1_isa_from_profile(load_component_profile(ROOT / config['cpu_profile']))
        # An explicitly declared RV32 projection.  A 64-bit CPU that declares
        # this fact executes the same RV32IM words the F1 gate emits: the low 32
        # bits of every 64-bit RVFI writeback are the RV32 result, the record is
        # a 32-bit word, and the reference trace is RV32.  Declaring it here - in
        # one place, from the scenario - is what lets the record validator, the
        # reference trace and the fuzz gate run on the projected RV32 profile;
        # a 64-bit CPU without the declaration keeps the gate's own refusal.
        f1_isa = isa
        rv32_projection = config.get('f1_rv32_projection', False)
        if type(rv32_projection) is not bool:
            raise ValueError('unsupported-f1-projection:not-a-boolean')
        if rv32_projection:
            if getattr(isa, 'xlen', None) != 64:
                raise ValueError('unsupported-f1-projection:declared-cpu-is-not-64-bit')
            if bus != 'axi4':
                raise ValueError('unsupported-f1-projection:proven-on-the-packed-axi4-'
                                 'retirement-path-only')
            from myfuzz.riscv.profile import RiscvProfile
            extensions = {str(item).upper() for item in isa.extensions}
            # The admitted subset is RV32IM: the base integer set plus M when the
            # CPU declares it.  No compressed parcel, no F/D, no A: an
            # instruction from those extensions is refused by the gate, not
            # executed under an RV32 name.
            f1_isa = RiscvProfile(32, frozenset(ext for ext in ('I', 'M')
                                                if ext in extensions),
                                  4, 32, 0)
        # Two more declared whole-record F1 modes, each its own module and each
        # refused by name outside the one CPU/bus it was proven on.  Neither
        # reuses the RV32 gate: ``f1_rv64`` is real RV64I execution compared at
        # the record's own width, and ``f1_trap_program`` is a declared M-mode
        # ECALL whose handler lives in the firmware image.
        from myfuzz.fuzz.f1_trap_program import (
            trap_declaration as f1_trap_declaration,
            trap_layout as f1_trap_layout,
            validate_trap_record as f1_trap_validate)
        from myfuzz.fuzz.f1_rv64 import validate_rv64_record as f1_rv64_validate
        f1_trap = f1_trap_declaration(config)
        f1_rv64 = config.get('f1_rv64', False)
        if type(f1_rv64) is not bool:
            raise ValueError('unsupported-f1-rv64:not-a-boolean')
        if f1_rv64:
            if getattr(isa, 'xlen', None) != 64:
                raise ValueError('unsupported-f1-rv64:declared-cpu-is-not-64-bit')
            if bus != 'axi4':
                raise ValueError('unsupported-f1-rv64:proven-on-the-packed-axi4-'
                                 'retirement-path-only')
            if rv32_projection:
                raise ValueError('unsupported-f1-rv64:not-with-the-rv32-projection')
            if f1_flags is not None and any(
                    (f1_flags.subword, f1_flags.allow_branches,
                     f1_flags.allow_address_forms, f1_flags.allow_compressed,
                     f1_flags.allow_jumps, f1_flags.allow_loops)):
                raise ValueError('unsupported-f1-rv64:not-with-a-control-or-'
                                 'compressed-program-declaration')
        if f1_trap is not None:
            if bus != 'axi4' or axi4_retirement is None:
                raise ValueError('unsupported-f1-trap:needs-the-packed-axi4-'
                                 'retirement-and-csr-witness')
            if f1_rv64 or rv32_projection:
                raise ValueError('unsupported-f1-trap:not-with-an-rv32-or-rv64-'
                                 'program-declaration')
            if f1_flags is not None and any(
                    (f1_flags.subword, f1_flags.allow_branches,
                     f1_flags.allow_address_forms, f1_flags.allow_compressed,
                     f1_flags.allow_jumps, f1_flags.allow_loops)):
                raise ValueError('unsupported-f1-trap:not-with-a-control-or-'
                                 'compressed-program-declaration')
            if f1_words < 1:
                raise ValueError('unsupported-f1-trap:needs-a-program-slot')
        for record in records:
            if f1_trap is not None and record['flow'] == 'F1':
                # The declaration's own word count is the record's ceiling: a
                # longer record is refused even when the slot could hold it.
                f1_trap_validate(record, slot=windows['ram_base'] + SLOT_OFFSET,
                                 max_words=min(f1_words, f1_trap['words']))
                continue
            if f1_rv64 and record['flow'] == 'F1':
                f1_rv64_validate(record, max_words=f1_words)
                continue
            validate_record(record, isa=f1_isa, windows=windows, f1_words=f1_words,
                            f1_subword=f1_subword, f1_flags=f1_flags)
        layout = build_layout(windows, boot, irq_base=irq_base,
                              result_span=max(_dma_result_span(dma),
                                              32 if f5_both is not None else 0),
                              dma_block_words=0 if dma is None else dma['block_words'])
        if f1_trap is not None:
            # The handler address and its three cells are one declaration; the
            # firmware builder places them and the host reads the same cells.
            layout = f1_trap_layout(layout)
        firmware = build_firmware(layout, irq=irq, dma=dma,
                                  interrupt_bootstrap=bus in ('obi', 'axi4'),
                                  f1_words=f1_words,
                                  wait_iterations=wait_iterations, custom_irq=custom_irq,
                                  f1_trap=f1_trap,
                                  irq_take_clear=axi4_irq is not None and irq is not None)
        header = render_bindings(config, cpu.runtime_document,
                                 states[0]['artifact'].runtime_document,
                                 None if dma_model is None else dma_model.runtime_document,
                                 firmware['layout'], cpu.plan.profile,
                                 irq=irq, dma=dma, dma_irq=dma['irq'] if dma else None,
                                 pins=pins, registers=registers, f1_words=f1_words,
                                 custom_irq=custom_irq,
                                 case_tick_budget=case_tick_budget,
                                 targets=target_descriptors,
                                 f5_target_index=f5_index,
                                 f5_links=header_f5_links,
                                 f5_both=f5_both,
                                 clock_plan=clock_plan,
                                 pin_groups=pin_groups,
                                 serial_peer=serial_peer)
        (args.output / 'spike_config.h').write_text(header)
        (args.output / 'firmware.txt').write_text(firmware_text(firmware))
        fuzz = None
        if args.fuzz:
            record_cache = {}

            def fuzz_case_check(input_, case):
                if case.get('status') != 'observations_passed':
                    return None
                text = case.get('record')
                record = record_cache.get(text)
                if record is None:
                    record = parse_record(text, windows=windows, arity=arity,
                                          label=axis_label,
                                          refusals=refusals, pin=pins,
                                          serial=serial_peer,
                                          f1_words=f1_words, f5_links=f5_select_links,
                                          f5_target_index=f5_index,
                                          f1_allow_compressed=_f1_compressed(config, f1_flags))
                    record_cache[text] = record
                return correspondence(record, case, layout=firmware['layout'],
                                      windows=windows, irq=irq, dma=dma,
                                      protocol=protocol, pins=pins,
                                      registers=registers, bus=bus,
                                      irq_base=firmware['layout']['irq_base'],
                                      f5_target_index=f5_index,
                                      f1_flags=f1_flags, isa=f1_isa,
                                      f1_mode=f1_declared_mode(config))

            fuzz = fuzz_collaborators(
                config, base_dir=ROOT, windows=windows, arity=arity,
                behavior_config=behavior_config,
                ip_profile=states[f5_index if f5_index is not None else 0]['profile'],
                pins=pins, dma=dma, f1_words=f1_words, isa=f1_isa,
                refusals=refusals, label=axis_label,
                seed=args.seed, cases=args.cases, seconds=args.seconds,
                corpus_path=args.corpus, max_cases_recorded=args.retain_cases,
                max_submitted_recorded=args.retain_cases,
                stall_seconds=args.stall_seconds,
                output=(None if args.no_prefix else args.output),
                case_check=fuzz_case_check,
                log_case_lines=(args.log_mode == 'case'),
                target_rows=(target_rows if declared_count > 1 else None),
                f5_target_index=f5_index, f1_flags=f1_flags,
                # The declared RV32 projection, when the scenario declares one,
                # is also what the F1 program generator runs on.
                f1_program_profile=(f1_isa if rv32_projection else None),
                fuzz_flows=fuzz_flows)
            (args.output / 'fuzz_inputs.json').write_text(
                json.dumps(fuzz['document'], indent=2) + '\n')
        submitted = []
        if fuzz is not None:
            runner = fuzz['runner']
        elif args.online:
            runner = incremental_runner([record['message'] for record in records], submitted)
        else:
            runner = None
        target_artifacts = tuple(state['artifact'] for state in states)
        artifacts = (cpu, *target_artifacts) + (() if dma_model is None
                                                else (dma_model,))
        argv = run_arguments(args.output, records, args.online, args.max_ticks)
        if args.quiet or fuzz is not None:
            argv = argv + ['--quiet']
        extra_archives, extra_includes = [], []
        rvfi_adapter_evidence = None
        if bus == 'axi4':
            adapter = build_axi4_adapter(
                ROOT / 'src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv',
                args.output)
            extra_archives = [adapter['archive']]
            extra_includes = [adapter['include']]
            if axi4_retirement is not None:
                # The pinned RVFI scoreboard is a second RTL model beside the run.
                # It is compiled from the generated model's own cached input tree
                # (the same pinned bytes the CPU model was built from), not from a
                # second checkout, because cva6_rvfi.sv is outside the core
                # filelist and may not be added to the closure.
                from scripts.inprocess_cva6_rvfi_build import build_cva6_rvfi_adapter
                cpu_build = build_local_harness_with_receipt(
                    cpu, base_dir=ROOT, cache_dir=args.cache)
                build_directory = cpu_build.validate_current(
                    cpu, base_dir=ROOT, cache_dir=args.cache).parent
                rvfi_adapter = build_cva6_rvfi_adapter(
                    ROOT, args.output, pinned_root=build_directory / 'inputs',
                    wrapper_root=ROOT, jobs=2,
                    probes_width=CVA6_RVFI_PROBES_BITS)
                extra_archives = extra_archives + [rvfi_adapter['archive']]
                extra_includes = extra_includes + [rvfi_adapter['include']]
                rvfi_adapter_evidence = rvfi_adapter['evidence']
        result = build_link_run(artifacts,
                                ROOT / 'scripts/inprocess_obi_apb_f1f4_spike.cpp',
                                args.output, args.cache, argv,
                                root=ROOT, runner=runner,
                                extra_archives=extra_archives,
                                extra_includes=extra_includes)
        if rvfi_adapter_evidence is not None:
            # The exact RTL that produced this run's retirement records: which
            # sources, which bytes, which Verilator invocation.
            result['cva6_rvfi_adapter'] = rvfi_adapter_evidence
        if fuzz is not None:
            session = fuzz['holder'].get('session')
            if session is None:
                raise RuntimeError('the fuzz session did not run the host')
            result['fuzz'] = session.document()
            result['fuzz_inputs'] = fuzz['document']
            # The session already parsed every case with the same parser the
            # fixed-record path uses, so the rest of this entry applies unchanged.
            try:
                records = [parse_record(row['record'], windows=windows, arity=arity,
                                        label=axis_label,
                                        refusals=refusals, pin=pins,
                                        serial=serial_peer,
                                        f1_words=f1_words, f5_links=f5_select_links,
                                        f5_target_index=f5_index,
                                        f1_allow_compressed=_f1_compressed(config, f1_flags))
                           for row in session.cases]
                # The same per-target gate as the fixed-record path: a fuzz case
                # routed to a sub-stepped faster model cannot be observed.
                faster_model_traffic_refusal(clock_plan, records)
                parsed = dict(cases=[row['case'] for row in session.cases],
                              summary=session.summary or {},
                              installed={'records': session.stats.submitted})
                failure = session.error
                events = None
                submitted = [row['text'] for row in session.submitted]
            except (KeyError, ValueError) as error:
                parsed, events, failure = None, None, 'fuzz case unreadable: ' + str(error)
        else:
            log = (args.output / 'run.log').read_text()
            try:
                parsed, failure = parse_run_log(log, flows=arity), None
                # A quiet run deliberately prints no per-tick event lines: the
                # case and summary lines are still parsed, but the event layer is
                # stated as suppressed instead of reported as missing evidence.
                events = None if args.quiet else summarize_events(log)
            except ValueError as error:
                parsed, events, failure = None, None, 'run log unreadable: ' + str(error)
        cases = [] if parsed is None else parsed['cases']
        verified, checks = [], []
        per_case_events = [] if events is None else events['per_case']
        # A fixed record chain that writes the routed register with F4 before the
        # F6 read states a deterministic source word; the expectation is the
        # observed value of the most recent passing F4 write to that address.  A
        # fuzz batch owns its own sequence (and may write a value the device
        # truncates), so it states no expectation here: the route's own evidence
        # still checks the DMA's word against the CPU's readback and RAM.
        route_expectation = RouteReadExpectation(
            None if dma is None else dma.get('route'))
        for record, case, case_events in zip(records, cases,
                                             per_case_events + [None] * len(records)):
            document = case_document(record, case, events=case_events, protocol=protocol,
                                     pins=pins is not None, bus=bus,
                                     protocols=(protocols if mixed else None),
                                     groups=pin_groups, serial=serial_peer is not None)
            mismatch = correspondence(record, case, layout=layout, windows=windows,
                                      irq=irq, dma=dma, protocol=protocol,
                                      pins=pins, registers=registers, bus=bus,
                                      irq_base=layout['irq_base'],
                                      f5_target_index=f5_index,
                                      f1_flags=f1_flags, isa=f1_isa,
                                      f1_mode=f1_declared_mode(config),
                                      route_expected=(None if fuzz is not None
                                                      else route_expectation.value))
            if (route_expectation.address is not None and fuzz is None
                    and record['flow'] == 'F6'):
                # The expected word is the entry's own reading of the record
                # chain, so it is reported beside the observed one instead of
                # being left implicit in a pass/fail.  None means the fixed chain
                # wrote nothing to the routed register, so it declares nothing.
                document['route_read_expected_value'] = route_expectation.value
            route_expectation.observe(case)
            document['correspondence'] = 'matched' if mismatch is None else 'mismatched'
            if mismatch is not None:
                document['correspondence_reason'] = mismatch
            verified.append(document)
            checks.append(mismatch)
        models = artifacts
        model_count = {2: 'two', 3: 'three', 4: 'four'}[len(models)]
        pin_stimulus = ('observed' if any(record['flow'] == 'F2'
                                         and len(record['fields']) == 2 for record in records)
                        else 'declared_default_only') if pins is not None else None
        # What the declared F1 subset does *not* claim, in one place, because a
        # packed AXI4 build adds the RV64->RV32 projection clause to whatever the
        # declared program shape already limits.
        f1_mode_text = f1_declared_mode(config)
        if bus == 'ahb':
            f1_limit_text = 'refused: ' + AHB_F1_REFUSAL
        elif bus == 'axi4' and axi4_retirement is None:
            f1_limit_text = AXI4_F1_REFUSAL
        elif f1_mode_text == 'trap':
            # The declared trap case: nothing here is projected or inferred.
            f1_limit_text = (
                'one declared M-mode ECALL (cause 11) followed by straight-line '
                'RV32I ALU words: the firmware image installs mtvec in vectored '
                'mode and its own handler reads mcause/mepc with CSRRS, stores '
                'them, advances mepc past the ECALL and returns with MRET; the '
                'host compares the RVFI record trap/cause/intr/mode, the '
                'scoreboard CSR readback and the two stored words. No other CSR '
                'access, no privilege switch beyond that ECALL, no second trap, '
                'no compressed parcel, no RV64 word and no F5')
        elif f1_mode_text == 'rv64':
            f1_limit_text = (
                'real RV64I execution of 1..' + str(f1_words) + ' words from the '
                'declared subset (LUI, ADDI, ADD, SUB, AND, OR, XOR, ADDIW, ADDW, '
                'SLLIW, SRLIW, SRAIW, and LD/SD against x18 inside the declared '
                'window), compared at the record\'s own width: 64-bit pc/rd_wdata, '
                '64-bit reference values and an FNV-1a 64 trace hash. No branch, '
                'jump, CSR, system, compressed, FP, atomic or RV64-compressed word')
        elif f1_words > 1:
            if f1_flags.allow_loops:
                f1_limit_text = (
                    'the canonical bounded loop (addi xN, x0, K with K in 2..6, '
                    'a body that never writes xN, addi xN, xN, -1, and '
                    'bne xN, x0, head) plus forward B-type branches and '
                    'statically proven forward JAL/JALR; a backward jump, a '
                    'non-canonical or nested loop, CSR, compressed parcel or '
                    'RV64 word is refused by name')
            elif f1_flags.allow_jumps:
                f1_limit_text = (
                    'statically proven forward JAL/JALR (link x0/x1; JALR base '
                    'x0 or a register the program loads one exact constant into) '
                    'plus strictly-forward B-type branches; a backward jump, '
                    'loop, CSR, compressed parcel or RV64 word is refused by name')
            elif f1_flags.allow_compressed_control or f1_flags.allow_compressed_memory:
                f1_limit_text = (
                    'the safe compressed ALU parcels plus the declared '
                    'compressed control transfers (forward, statically proven '
                    'target) and/or compressed word loads/stores (statically '
                    'proven in-window base); a backward compressed transfer, '
                    'an indirect base that is not a proven constant, an FP/'
                    'stack-pointer form, a jump, loop, CSR or RV64 word is '
                    'refused by name')
            elif f1_flags.allow_branches:
                f1_limit_text = (
                    'strictly-forward B-type branches only (BEQ/BNE/BLT/BGE/BLTU/'
                    'BGEU, 4-aligned, target == the appended return jump allowed); '
                    'no JAL/JALR, CSR, loop, compressed parcel or RV64 word')
            elif f1_subword:
                f1_limit_text = (
                    'straight-line 32-bit instructions only; LB/LH/LW/LBU/LHU/SB/SH/SW '
                    'against x18 inside the declared window; no control flow, CSR or '
                    'compressed word')
            else:
                f1_limit_text = (
                    'straight-line 32-bit instructions only; LW/SW only against x18 '
                    'inside the declared window; no control flow, CSR or compressed word')
        else:
            f1_limit_text = 'one 32-bit ALU word; no memory, control flow or CSR word'
        if (bus == 'axi4' and axi4_retirement is not None
                and f1_mode_text is None):
            f1_limit_text += (
                '; the CVA6 retirement record is RV64 and this subset compares the low '
                '32 bits of pc_rdata/rd_wdata, which are the whole RV32IM values inside '
                'the declared image window: no RV64-wide address, no 64-bit arithmetic '
                'and no RV64 writeback is claimed')
        result.update(
            # The component set this process really built, stated as data: the
            # archive list is the link's own, so a reader never has to infer from
            # a device name whether a CPU, a target or a DMA model was present.
            mode='combined',
            components_loaded=dict(cpu=1, targets=declared_count,
                                   dma=int(dma_model is not None), ram=1,
                                   model_archives=len(models)),
            model_archives=dict(
                cpu=[result['archives'][0]['path']],
                targets=[row['path'] for row in
                         result['archives'][1:1 + declared_count]],
                dma=([result['archives'][1 + declared_count]['path']]
                     if dma_model is not None else []),
                all=[row['path'] for row in result['archives']],
                sha256=[row.get('sha256') for row in result['archives']],
                source='the link command and its archive list, read from link.log and '
                       'the build result'),
            scope='one ' + CPU_BUS_LABELS[bus] + ' CPU + ' +
                  ('one ' if declared_count == 1 else str(declared_count) + ' address-routed ') +
                  axis_label + ' register target' +
                  ('' if declared_count == 1 else 's') +
                  ('' if pins is None else ' with a host pin model') +
                  (' + one Wishbone DMA' if dma is not None else '') +
                  ' + host RAM receiving ' +
                  ('/'.join(sorted(arity))) + ' in one process; compact observations only',
            target_protocol=dict(
                kind=('mixed' if mixed else
                      states[0]['artifact'].runtime_document['kind']),
                protocol=protocol,
                bridge=(mixed_target_bridge(protocols) if mixed
                        else TARGET_BRIDGES[protocol]),
                trace_roles=(None if mixed
                             else list(PROTOCOL_TRACE_ROLES[protocol])),
                # One completed transfer means: psel+penable+pready in one sample
                # (APB3), AW+W+B / AR+R handshakes of one single beat (AXI4-Lite),
                # cyc+stb held with ack in one sample (Wishbone classic), or an A
                # channel handshake followed by a D channel handshake (TL-UL).
                # A mixed build states every declared protocol's criterion and
                # lets each target's own protocol select one.
                transfer_criterion=(mixed_target_criterion(protocols)
                                    if mixed else
                                    TARGET_TRANSFER_CRITERIA[protocol]),
                # The neutral field names beside the protocol's own spelling, so a
                # reader of either log reads the same facts under the same names.
                neutral_fields=dict(TARGET_FIELD_ALIASES),
                error_response=('per_target: unknown (AXI4-Lite drives OKAY only)'
                                if mixed and set(protocols) == set(
                                    MIXED_TARGET_PROTOCOL_PAIRS)
                                else 'per_target: ' + '; '.join(
                                    '%s=%s' % (row, TARGET_ERROR_RESPONSES[row])
                                    for row in ordered_target_protocols(protocols))
                                if mixed else
                                TARGET_ERROR_RESPONSES[protocol])),
            # Every declared target's own protocol, its bridge and its window: the
            # per-case ``target_protocol``/``target_index`` words are read against
            # this list, so a case can never be credited to the other bridge.
            target_protocols=[dict(index=state['target']['index'],
                                   name=state['target']['name'],
                                   protocol=state['protocol'],
                                   bridge=TARGET_BRIDGES[state['protocol']],
                                   kind=state['artifact'].runtime_document['kind'],
                                   base=state['window']['base'],
                                   size=state['window']['size'],
                                   trace_roles=list(PROTOCOL_TRACE_ROLES[state['protocol']]))
                              for state in states],
            preparation_scope=model_count + ' component profiles only; no full D3, no '
                              'scenario search and no replay',
            cpu_bus=dict(kind=cpu.runtime_document['kind'], bus=bus,
                         label=CPU_BUS_LABELS[bus],
                         instruction_identity=(cpu.runtime_document.get(
                             'instruction_identity_observation')
                             or ('hprot[0] of the address phase accepted at the '
                                 "manager's aggregate HREADY" if bus == 'ahb'
                                 else 'arid0_rid0_at_address_phase' if bus == 'axi4'
                                 else 'unknown')),
                         irq_width=(None if bus == 'ahb' else
                                    cpu_irq_width(cpu.runtime_document)),
                         irq_wiring=('delivered: the OR of every declared target link\'s '
                                     'sampled device output (one CPU external IRQ input)'
                                     if irq is not None else
                                     ('no interrupt input at the declared CPU boundary'
                                      if bus == 'ahb' else 'held at zero')),
                         fetch_identity=('mem_instr' if bus == 'wishbone'
                                         else 'hprot0_at_manager_ready_address_phase'
                                         if bus == 'ahb'
                                         else 'arid0_rid0_at_address_phase'
                                         if bus == 'axi4'
                                         else 'separate instruction channel'),
                         retirement_observation=(
                             None if bus != 'axi4' else
                             'rvfi:cva6_rvfi_probes' if axi4_retirement is not None else
                             'none:cva6_no_rvfi_exported'),
                         ahb=None if bus != 'ahb' else dict(
                             manager_domain=dict(
                                 manager_ready=(cpu.runtime_document['manager_domain']
                                                ['roles']['manager_ready']['physical_port']),
                                 bus_reset_n=(cpu.runtime_document['manager_domain']
                                              ['roles']['bus_reset_n']['physical_port']),
                                 authority='observation_only'),
                             address_width=ahb_beat_address_width(
                                 cpu.runtime_document),
                             beat_channel='m',
                             identity_roles=list(AHB_IDENTITY_ROLES),
                             unknown_policy=('a beat whose accepted address phase was '
                                             'never sampled is served and counted apart; '
                                             'it is never counted as a fetch'))),
            boot_contract=dict(configured_boot_base=cpu.runtime_document['boot_contract']
                               ['configured_boot_base'],
                               resolved_boot=boot,
                               ram_base=windows['ram_base'],
                               follows_boot_contract=True),
            input_mode=('fuzz_mutation' if fuzz is not None else
                        'incremental' if args.online else 'preloaded'),
            input_channel=('held-RAM-mailbox'
                           + ('' if bus == 'ahb' else ' + instruction trampoline slot')
                           + ('' if bus == 'ahb' or f1_words == 1
                              else ' (1 to %d words)' % f1_words)
                           + ' + CPU-read input block'
                           + (' + host external pin driver' if pins is not None else '')),
            pin_groups=(None if not pin_groups else dict(
                groups=[dict(index=index, name=group['name'], kind=group['kind'],
                             direction=group.get('direction'),
                             hold_ticks=group.get('hold_ticks'),
                             external_value=group.get('external_value'),
                             padin_offset=group.get('padin_offset'))
                        for index, group in enumerate(pin_groups)],
                serial=None if serial_peer is None else dict(
                    name=serial_peer['name'], frame=serial_peer['frame'],
                    frame_bits=serial_peer['frame_bits'],
                    bit_ticks=serial_peer['bit_ticks'],
                    idle_level=serial_peer['idle_level'],
                    rx_role=serial_peer['rx_role'],
                    tx_role=serial_peer['tx_role'],
                    tx_en_role=serial_peer.get('tx_en_role')),
                # What this host can execute, stated beside what this run declared, so
                # a reader never has to infer the bound from one scenario.
                capacity=dict(pin_groups=HOST_SOURCE_EXECUTION['pin_groups'],
                              pin_group_kinds=list(HOST_SOURCE_EXECUTION['pin_group_kinds']),
                              serial_peers=HOST_SOURCE_EXECUTION['serial_peers']),
                driver=('the host drives every declared pad group in declaration order, '
                        'each for its own declared hold window, and resolves each pad bit '
                        'from the device\'s own out/dir ports'),
                serial_driver=('the host clocks the declared byte onto rx at bit_ticks '
                               'per bit with the CPU parked, samples tx at the same '
                               'period, and decodes the declared frame'))),
            recovery=recovery_declaration(
                dict(config, source_timing=(states[f5_index]['target']['timing']
                                            if f5_index is not None else None)),
                irq=irq, dma=dma, pins=pins, bus=bus),
            handler_wait=dict(
                iterations=wait_iterations,
                case_tick_budget=case_tick_budget,
                timeout_marker=2,
                on_timeout=('the case is reported failed and the devices are reset before '
                            'the next case; the CPU stays in its poll loop')),
            f1_program=dict(
                status=('refused' if bus == 'ahb' or (bus == 'axi4' and axi4_retirement is None)
                        else 'offered'),
                reason=(AHB_F1_REFUSAL if bus == 'ahb' else
                        AXI4_F1_REFUSAL if bus == 'axi4' and axi4_retirement is None
                        else None),
                declared_words=f1_words,
                mode=('refused' if bus == 'ahb'
                      else f1_flags.mode if f1_words > 1 else 'single_word'),
                subword=bool(f1_subword),
                address_forms=bool(f1_flags.allow_address_forms),
                branches=bool(f1_flags.allow_branches),
                jumps=bool(f1_flags.allow_jumps),
                loops=bool(f1_flags.allow_loops),
                compressed=bool(f1_flags.allow_compressed),
                compressed_control=bool(f1_flags.allow_compressed_control),
                compressed_memory=bool(f1_flags.allow_compressed_memory),
                # The declared width projection of the retirement record.  A
                # 64-bit CPU that declares f1_rv32_projection executes RV32IM
                # words and this run compares the low 32 bits of its RV64 RVFI
                # record; the trace, the hash and the reference model are RV32.
                # None means the record width is the CPU's own.
                projection=('rv32im_low32_of_rv64' if rv32_projection else None),
                data_window=dict(base=windows['data_base'], words=PROGRAM_DATA_WORDS),
                feedback=('a fetch beat is not a retirement: this CPU exports no '
                          'RVFI/commit channel, so the host records no retirement '
                          'count, no PC order and no register writeback for F1'
                          if bus == 'ahb' else
                          'the in-slot RVFI retirement trace (count, the PC order '
                          'the shape allows - strictly increasing except for a '
                          'bounded loop\'s repeated PCs - and its FNV-1a hash) '
                          'compared with the Python reference trace, the register '
                          'writeback mask and last writeback, traps, and the '
                          'sampled data-window change'
                          if f1_words > 1 and f1_flags.traced else
                          'every program word retired in order as the installed word, '
                          'the RVFI register writeback mask and last writeback, traps, '
                          'and the sampled data-window changes'
                          if f1_words > 1 else
                          'the one word retired at the slot and the trampoline left'),
                limit=f1_limit_text),
            records=[record['text'] for record in records],
            submitted=submitted if args.online else [record['text'] for record in records],
            cases=verified,
            run_summary=None if parsed is None else parsed['summary'],
            installed=None if parsed is None else parsed['installed'],
            cpu_instance='cpu',
            ip_instance=(states[0]['target']['active_id'] if declared_count == 1
                         else ','.join(state['target']['active_id'] for state in states)),
            dma_instance='dma' if dma is not None else None,
            components=dict(
                cpu=dict(profile=config['cpu_profile'], model=cpu.runtime_document['module_name'],
                         declared_hz=self_rate(cpu)),
                target=dict(profile=states[0]['target']['profile'],
                            model=states[0]['artifact'].runtime_document['module_name'],
                            declared_hz=self_rate(states[0]['artifact'])),
                **({'targets': [dict(index=state['target']['index'],
                                     name=state['target']['name'],
                                     profile=state['target']['profile'],
                                     active_id=state['target']['active_id'],
                                     model=state['artifact'].runtime_document['module_name'],
                                     declared_hz=self_rate(state['artifact']),
                                     window=state['window'],
                                     has_f5=state['irq'] is not None)
                               for state in states]}
                   if declared_count > 1 else {}),
                **({'dma': dict(profile=config['dma_profile'],
                                model=dma_model.runtime_document['module_name'],
                                declared_hz=self_rate(dma_model))} if dma_model is not None else {})),
            # The schedule the host really ran, from the same normalized plan the
            # header macros were rendered from.  ``timing`` carries every model's
            # declared rate, its half period in reference half periods and the one
            # simulation-time grid step, so a saved run states the ratio rather
            # than asserting that the rates matched.
            clock_assumption=clock_assumption_text(clock_plan),
            timing=dict(clock_plan),
            cpu_take_witness=(cpu_take_witness or 'unexported'),
            pin_model=None if pins is None else dict(
                endpoint=pins['endpoint_id'], width=pins['width'],
                padin_offset=pins['padin_offset'],
                external_value=pins['external_value'],
                resolution='device drives a pad while its dir bit is high; the host drives '
                           'the remaining pins with the declared value',
                sampling='gpio_out/gpio_dir/gpio_in_sync and the device transition/status/'
                         'inten probes sampled every tick from the authenticated contract',
                stimulus='F2 carries the external pin word as its optional second operand; '
                         'no other flow moves the host driver',
                status='observed', pin_stimulus=pin_stimulus),
            f5=dict(status='observed' if irq is not None else 'refused',
                    reason=None if irq is not None else f5_refusal,
                    declared_facts=sorted(key for key in F5_KEYS
                                          if key in behavior_config),
                    # The multi-target statement: how many targets declare F5,
                    # every global link with its target and window, and the one
                    # CPU input all of their real outputs are OR'ed into.
                    target_count=(0 if irq is None
                                  else len({link.get('target_index')
                                            for link in f5_links})),
                    multi_target=bool(irq is not None and irq.get('multi_target')),
                    links=([] if irq is None else
                           [dict(index=link['index'],
                                 target_index=link.get('target_index'),
                                 base=link.get('base'),
                                 port=link['port'], bit=link['bit'],
                                 trigger=link['trigger'],
                                 polarity=link['polarity'],
                                 status_offset=link['status_offset'],
                                 trigger_offsets=list(link['trigger_offsets']),
                                 clear=link['clear'],
                                 # The whole declared acknowledge sequence, in
                                 # the order the handler performs it.  A device
                                 # whose ack is two ordered writes states both;
                                 # one write keeps its historical single row.
                                 clears=list(link.get('clears') or ()),
                                 clear_steps=len(link.get('clears') or ()))
                            for link in f5_links]),
                    # The synthetic two-source selection row.  It is not a
                    # physical link: it names the member links one both case
                    # triggers and the two status/result/clear sets its ISR
                    # publishes.  ``refusal`` states why it is absent when the
                    # declaration has several declaring targets but not one link
                    # each.
                    both=(None if f5_both is None else
                          dict(index=f5_both['index'], mode='both',
                               word_count=f5_link_word_count(f5_both),
                               members=[dict(index=member['index'],
                                             target_index=member['target_index'],
                                             base=member['base'],
                                             status_offset=member['status_offset'],
                                             status_kind=member['status_kind'],
                                             trigger_offsets=list(
                                                 member['trigger_offsets']),
                                             clear=member['clear'],
                                             cause_declared=member['cause_declared'],
                                             cause_mask=member['cause_mask'])
                                        for member in f5_both['members']],
                               trigger_offsets=list(f5_both['trigger_offsets']),
                               status_offsets=list(f5_both['status_offsets']))),
                    both_refusal=(None if irq is None
                                  else irq.get('both_refusal')),
                    # The status vector a declared cause mask can carry.  The
                    # CPU has no per-source vector, so this is a word the ISR
                    # reads, never a CPU vector.
                    status_vector=dict(
                        declared_bits=max([bin(link['cause_mask']).count('1')
                                           for link in f5_links] or [0]),
                        source=(None if irq is None
                                else 'per-link status_cause_bits'),
                        cpu_vector=('one OR(ed) external input; no per-source '
                                    'CPU vector')),
                    delivery=('one CPU external IRQ input carries the OR of every '
                              'declared link\'s real device output; one case selects '
                              'one link, or the both row that triggers its two '
                              'member targets in one case'
                              if irq is not None else None),
                    simultaneous_attribution=(
                        'observed: one case selects the both row, so its ISR reads '
                        'each member target\'s status word at that target\'s own '
                        'address, stores both results in separate RAM cells and '
                        'performs each declared clear; the members are the first two '
                        'declaring targets (the ISR carries two cell sets), and the '
                        'CPU still has one OR\'ed external input, so this is '
                        'status-content attribution, not a CPU vector'
                        if f5_both is not None else
                        'not_supported: one case selects one link and the ISR '
                        'reads one status word'
                        if irq is not None and irq.get('multi_target') else None)),
            f6=dict(status='observed' if dma is not None else 'refused',
                    reason=None if dma is not None else f6_refusal,
                    plan_schema=(None if dma is None
                                 else dma['plan']['schema_version']),
                    device_family=(None if dma is None else dma['device_family']),
                    # The declaration states the device's bound; this entry states
                    # the block it actually executes, and every host limit the
                    # planning module reported with what the entry did about it.
                    device_max_block_words=(None if dma is None
                                            else dma['plan']['device']['device_max_block_words']),
                    entry_block_bound=(None if dma is None
                                       else DMA_PROVEN_BLOCK_WORDS[dma['device_family']]),
                    planner_host_supported=(None if dma is None
                                            else dma['planner_host_supported']),
                    host_limits=(None if dma is None else dma['host_limits']),
                    host_limits_raised=(None if dma is None else dma['host_limits_raised']),
                    host_capability=(None if dma is None else dma['host_capability']),
                    # The executed route, in the F6 section a reader looks at: a
                    # declaration-only run has no route here, and a run that
                    # refused the route never reaches this document.  The
                    # direction and the routed beat count are stated here so a
                    # saved summary says whether the master pushed the register
                    # or read it (``reads`` is 0 on a write route).
                    route=(None if dma is None or dma.get('route') is None else dict(
                        kind=dma['route']['kind'],
                        direction=dma['route']['direction'],
                        target_index=dma['route']['target_index'],
                        target_name=dma['route']['target_name'],
                        address=dma['route']['address'],
                        offset=dma['route']['offset'],
                        address_mode=dma['route']['address_mode'],
                        evidence=dma['route']['evidence'],
                        pushes=dma['route']['pushes'],
                        reads=dma['route']['reads'])),
                    behavior_loader_refusal=(None if dma is None
                                             else dma['behavior_loader_refusal'])),
            irq_sources=(
                # One entry per declared link: a multi-declaring scenario states
                # every target's own source, so the summary never folds two
                # targets into the first target's words.  A one-target build keeps
                # the historical single entry byte for byte.
                ([dict(index=0, device='target', target_index=f5_index,
                       port=irq['port'], bit=irq['bit'],
                       trigger=irq['trigger'], polarity=irq['polarity'],
                       delivery_ticks=irq['pulse_ticks'],
                       status_offset=irq['status_offset'],
                       trigger_offsets=irq['trigger_offsets'], clear=irq['clear'])]
                 if not irq.get('multi_target') else
                 [dict(index=link['index'], device='target',
                       target_index=link.get('target_index'),
                       port=link['port'], bit=link['bit'],
                       trigger=link['trigger'], polarity=link['polarity'],
                       delivery_ticks=link['pulse_ticks'],
                       status_offset=link['status_offset'],
                       trigger_offsets=link['trigger_offsets'], clear=link['clear'])
                  for link in f5_links])
                if irq is not None else []) + ([
                dict(index=(len(f5_links) if irq is not None and irq.get('multi_target')
                            else 1 if irq is not None else 0),
                     device='dma', port=dma['irq']['port'], bit=0,
                     trigger=dma['irq']['trigger'], polarity=dma['irq']['polarity'],
                     delivery_ticks=dma['irq']['pulse_ticks'],
                     control_offset=dma['control_offset'], clear=dma['clear'])]
                if dma is not None else []),
            dma=None if dma is None else dict(
                control_window=dict(base=windows['dma_base'], size=windows['dma_size']),
                source=layout['dma_source'], destination=layout['dma_destination'],
                block_words=dma['block_words'], length_value=dma['length_value'],
                length_unit=dma['length_unit'],
                start_word=dma['start_word'],
                start_word_source=dma['plan']['start']['source'],
                start_word_encoding=dma['plan']['start']['encoding'],
                increment_source=dma['plan']['increment_source'],
                increment_destination=dma['plan']['increment_destination'],
                control_offset=dma['control_offset'],
                status_kind=dma['status_kind'],
                clear_declared=dma['clear'] is not None, clear=dma['clear'],
                busy_bit=dma['busy_bit'], err_bit=dma['err_bit'],
                status_bits_declared=dma['status_bits_declared'],
                status_bits_source=dma['status_bits_source'],
                block_words_declared=dma_facts.get('block_words') is not None,
                master_byte_enable=dma['master_byte_enable'],
                expected_reads=dma['expected_reads'],
                expected_writes=dma['expected_writes'],
                max_outstanding=dma['max_outstanding'],
                response_delay=dma['response_delay'],
                destination_guard=dict(sentinel=DMA_DESTINATION_SENTINEL,
                                       lo=layout['dma_destination'] - 4,
                                       hi=layout['dma_destination'] + 4 * dma['block_words']),
                source_destination_byte_address_bits=(
                    dma['source_destination_byte_address_bits']),
                # The route this build executes, or None for the RAM-only path.
                # A dict here is the host's own answer, not the planner's
                # declaration: ``dma_route_support`` resolved it against the
                # targets that were really built, and the run's case lines carry
                # the per-case target responses and FIFO-level readback.
                route=None if dma.get('route') is None else dict(
                    dma['route'],
                    evidence_cells=dict(before=layout['route_before'],
                                        after=layout['route_after']),
                    completion_criterion=(
                        'every routed master beat is acked only after the target '
                        'responded, and the F6 firmware reads the declared evidence '
                        'word before and after the transfer; the case fails if the '
                        'observed FIFO level did not advance by the accepted pushes '
                        '(dma_route_accepted) or if the partial-acceptance flag '
                        'disagrees with the declared depth'))),
            # What the handler really addresses: a kind taken from the profile's
            # register name, and whether the device declares cause bits at all.
            # ``status_register`` keeps the historical first/only link shape; the
            # list states every declared link's own word and target.
            status_register=(dict(address=irq_base + irq['status_offset'],
                                  offset=irq['status_offset'], kind=irq['status_kind'],
                                  cause_declared=irq['cause_declared'])
                             if irq is not None else None),
            status_registers=(None if irq is None else
                              [dict(index=link['index'],
                                    target_index=link.get('target_index'),
                                    address=(irq_base if link.get('base') is None
                                             else link['base']) + link['status_offset'],
                                    offset=link['status_offset'],
                                    kind=link['status_kind'],
                                    read_clears=link.get('status_read_clears', False),
                                    cause_declared=link['cause_declared'])
                               for link in f5_links]),
            irq_cause=('per_link' if irq is not None and irq.get('multi_target')
                       else 'observed' if irq and irq['cause_declared'] else 'unknown'),
            irq_causes=(None if irq is None else
                        [('observed' if link['cause_declared'] else 'unknown')
                         for link in f5_links]),
            # What the pinned profiles do not compose: NMI, PLIC, a per-source
            # CPU vector, an active-low device output and a write-one-clear
            # register.  Each entry is a named fact a reader can re-check.
            irq_advanced=advanced_irq_refusals(
                json.loads((ROOT / config['cpu_profile']).read_text()),
                [json.loads((ROOT / state['target']['profile']).read_text())
                 for state in states]),
            dma_done_derivation=None if (parsed is None or dma is None) else
            parsed['summary'].get('dma_done_derivation', 'missing'),
            ram=dict(base=windows['ram_base'], size=windows['ram_size']),
            ip_window=dict(base=windows['ip_base'], size=windows['ip_size']),
            target_windows=[dict(index=state['target']['index'],
                                 name=state['target']['name'],
                                 base=state['window']['base'],
                                 size=state['window']['size'],
                                 profile=state['target']['profile'],
                                 protocol=state['protocol'],
                                 bridge=TARGET_BRIDGES[state['protocol']],
                                 has_f5=state['irq'] is not None)
                            for state in states],
            irq_base=irq_base,
            registers=dict(registers) if registers is not None else None,
            layout=firmware['layout'], slot_return=firmware['slot_return'],
            irq_delivery='observed' if (parsed is not None and irq is not None) else 'unknown',
            dma_transfer=('observed' if parsed is not None else 'unknown')
            if dma is not None else 'refused',
            combination_specific_branches='none: wiring comes from the generated binding '
                                          'header and the declared device behavior',
            limitations=[
                ('one host tick drives the ' + model_count +
                 ' models; the equal-period assumption is declared '
                 '(assume_single_clock), not derived from the declarations'
                 if clock_plan['mode'] == 'assumed_single_clock' else
                 'each of the ' + model_count + ' models is clocked at its declared rate by '
                 'the per-model phase divider; ' + clock_assumption_text(clock_plan)),
                *(['every declared target model is clocked, reset and evaluated on the '
                   'same host tick: only the routed target receives a CPU MMIO request.  '
                   'Every target that declares F5 has its real IRQ output sampled per '
                   'tick and OR\'ed into the CPU\'s one external input; a case selects '
                   'one global link, so the ISR reads and clears only that link\'s target',
                   ('the CPU has one external IRQ input.  A single-link case selects '
                    'one link and its ISR reads that link\'s one status word.  The both '
                    'row selects two member targets (the first two declaring ones: the '
                    'ISR carries two status/result/clear cell sets); its ISR reads each '
                    'member\'s status word at that target\'s own address, stores both '
                    'results in separate RAM cells and performs each declared clear.  '
                    'What is attributed is those two real status words and their '
                    'stores, never a CPU vector: the CPU still has one OR(ed) '
                    'external input and no per-source vector'
                    if f5_both is not None else
                    'the CPU has one external IRQ input and the F5 ISR has one '
                    'status/result/clear cell set, so one case attributes the delivered '
                    'interrupt to the one link it selected: two targets asserting at the '
                    'same instant would be delivered once and only the selected target\'s '
                    'status read would be observed, which is why no simultaneous '
                    'attribution is claimed'),
                   'a multi-link declaration needs every link to declare the same number '
                   'of trigger writes, because one F5 record shape carries the global '
                   'link index followed by that link\'s trigger values; links with '
                   'different arity are refused by name '
                   '(unsupported-f5:irq-links-differ-in-arity)',
                   ('every declared target states its own protocol and each case '
                    'states the protocol of the target it was routed to; only APB3 '
                    'and AXI4-Lite targets can be mixed in one build, and a target '
                    'of any other protocol keeps the named refusal '
                    '(unsupported-targets:mixed-protocol:...)' if mixed else
                    'every target declares the same target protocol; a target of '
                    'another protocol keeps the named refusal '
                    '(unsupported-targets:mixed-protocol:...)'),
                   ('the DMA master is routed to the declared target window only for the '
                    'declared fixed write: a read route, an aperture route or a second '
                    'target is not routed'
                    if dma is not None and dma.get('route') is not None else
                    'the DMA master is routed to RAM only: no DMA-to-target address route '
                    'is declared or claimed'),
                   'a pin model is a one-target feature: a multi-target declaration that '
                   'states pads is refused by name'] if declared_count > 1 else []),
                *(['the DMA master writes the declared target route (target %d at 0x%08x): '
                   'the RAM destination block keeps its sentinel, one master beat is '
                   'outstanding at a time, and only a fixed-destination write is executed'
                   % (dma['route']['target_index'], dma['route']['address'])]
                  if dma is not None and dma.get('route') is not None else []),
                ('the DMA master presents the byte enables the device drives: a '
                 'full-word transfer writes full words, and a declared size-derived '
                 'lane pattern is applied lane by lane.  A mask the device does not '
                 'drive itself is refused by name, never emulated'
                 if dma is not None else
                 'no DMA model is part of this build: no byte-enable pattern was '
                 'applied or observed'),
                *(['Pico custom IRQ uses one edge pulse per asserted shared line; '
                   'simultaneous source attribution is unknown, and IRQ acceptance '
                   'is observed through the CPU EOI vector'] if custom_irq else []),
                ('one CPU IRQ input carries the two declared sources'
                 if irq is not None else
                 ('the CPU declares a ' + str(cpu_irq_width(cpu.runtime_document)) +
                  '-bit irq vector this host holds at zero: no interrupt is delivered and '
                  'F5 is refused by name' if bus == 'wishbone' else
                  'one CPU IRQ input carries the DMA completion source only: the target '
                  'declares no F5 facts, so no target interrupt is wired')),
                'a pulse source is stretched to its declared delivery width by the host',
                ('the F1 slot runs one to ' + str(f1_words) +
                 ' words; a bounded loop may retire more instructions than the '
                 'slot holds words (K in 2..6 iterations of its body), a '
                 'statically proven forward JAL/JALR and a forward B-type branch '
                 'may skip words, and a compressed record retires one '
                 'instruction per parcel, while an unproven indirect target, a '
                 'backward jump, a non-canonical or nested loop, CSR, trap or '
                 'out-of-window memory word is refused, not repaired'
                 if f1_words > 1 and (f1_flags.allow_loops or f1_flags.allow_jumps
                                      or f1_flags.allow_compressed) else
                 'the F1 slot runs one to ' + str(f1_words) +
                 ' words; a strictly-forward B-type branch may skip words when the '
                 'scenario declares f1_allow_branches, while a jump, CSR, backward or '
                 'out-of-image branch, trap or out-of-window memory word is refused, '
                 'not repaired' if f1_words > 1 and f1_flags.allow_branches else
                 'the F1 slot runs one to ' + str(f1_words) +
                 ' straight-line words; a program that branches, traps or leaves the '
                 'declared data window is refused, not repaired' if f1_words > 1 else
                 'the F1 slot runs exactly one straight-line ALU word'),
                ('the pad has exactly two drivers: the device while its dir bit is high, '
                 'the host driver value otherwise; no contention and no pad delay beyond '
                 'the device\'s own two-stage synchronizer' if pins is not None else
                 'the target declares no external pin endpoint: no pad is driven or sampled'),
                ('the AXI4 CPU side\'s response error input is host-driven (this path '
                 'always drives it low), so that bus error channel stays unknown'
                 if bus == 'axi4' else
                 'OBI instruction/data error responses are host-driven and the DMA model has '
                 'no error output: those bus error channels stay unknown'),
                *(['the AXI4 CPU is the single master of the repository\'s existing '
                   'axi4_processor_memory_adapter: one adapter beat is outstanding at a '
                   'time, the adapter serves ARLEN 0 or a legal two-beat INCR read, and '
                   'longer bursts or LOCK/ATOP beats are answered with DECERR by that RTL',
                   ('the CVA6 exports its RVFI probe bundle (rvfi_probes_o, 6974 bits) '
                    'and the pinned scoreboard core/cva6_rvfi.sv, Verilated beside this '
                    'run, turns it into the one-record-per-clock retirement stream F1 '
                    'reads: the record is the committing uop\'s own instruction word and '
                    'the record is the acceptance test, so a fetch is never a retirement'
                    if axi4_retirement is not None else
                    'the CVA6 model exports no RVFI probe bundle: F1 and F5 are refused '
                    'by name, no retirement is claimed, and the F2-F4 evidence is real '
                    'channel/target traffic plus the CPU\'s own architecturally visible '
                    'stores (a fetch is never counted as a retirement)'),
                   'F5 is refused by name on this CPU: its machine-external irq_i input '
                   'is a scenario input the AXI4 host holds low, so no interrupt can be '
                   'delivered and no ISR side effect may be read as an interrupt take; '
                   'the retirement stream is evidence of retirements, not a replay',
                   'an IP beat is served only when it is exactly one full 32-bit word: a '
                   '64-bit beat that merges a target store with other bytes is refused by '
                   'name, never split across the target window or faked',
                   'the packed AXI4 port carries 64-bit beats while host RAM is 32-bit-word '
                   'addressed: each beat is split/joined with the adapter\'s own WSTRB/lane '
                   'pattern, so a sub-8-byte access is served as the lanes the CPU emitted',
                   'the program slot lies in the CPU configuration\'s uncached '
                   '0x10000..0x20000 window, so a slot rewritten between cases is re-fetched: '
                   'no fence.i and no cache invalidation is claimed or needed']
                  if bus == 'axi4' else []),
                *(['the AHB-Lite boundary exports no RVFI/commit channel, no interrupt '
                   'input and no DMA port: F1 is refused by name (a fetch beat is not a '
                   'retirement), F5 is refused by name, and only F2-F4 are served',
                   'one AHB-Lite manager beat is outstanding at a time and only the '
                   'generated ahb_lite_memory_target adapter is between the CPU and this '
                   'host: no burst acceleration and no second target window',
                   'an AHB beat whose accepted address phase was never sampled (the CPU '
                   "synchronized HRESETn had not been observed released yet) is served "
                   'and counted apart, never guessed into a fetch',
                   'the instruction cache is retained by the CPU configuration: F2-F4 '
                   'change only RAM/mailbox data, so no trampoline slot is rewritten '
                   'between cases and no cache invalidation is claimed or needed']
                  if bus == 'ahb' else []),
                ('the DMA model has no busy or done output: dma_done is derived from the last '
                 'master write plus the completion IRQ edge, and the busy bit is only '
                 'readable through the control register' if dma is not None else
                 'no DMA model is part of this build, so no DMA transfer, control port or '
                 'completion IRQ was observed'),
                ('the selected profiles do not declare the DMA control bit meanings; the '
                 'busy/error positions come from the declared DMA behavior or, when no '
                 'device states them, from the ZipDMA RTL default reported as such'
                 if dma is not None else
                 'no DMA model is part of this build, so no DMA control bits are used'),
                ('the fuzz loop mutates the declared input spaces and scores only the '
                 'observed case facts: no RTL coverage, no certificate and no replay'
                 if fuzz is not None else
                 'no feedback-driven input, certificate or replay in this entry')],
            behavior=behavior_document(source_facts, dma_facts),
            certificate='none', replay='not_performed',
            total_seconds=time.monotonic() - started)
        event_layer = None if (events is None or parsed is None) else \
            event_document(events, parsed['summary'])
        result['event_layer'] = ('suppressed_by_--quiet' if (args.quiet or fuzz is not None)
                                 else 'detailed' if event_layer is not None else 'unavailable')
        result['events'] = event_layer
        result['evidence'] = None if event_layer is None else dict(
            {key: word for key, word in event_layer['evidence'].items()},
            source='derived from the run log event lines; stated words are the host summary')
        if failure is not None:
            result['failure'] = failure
        apply_correspondence(result, parsed, records, checks)
        # The event lines and the summary must agree about what was observed; a
        # disagreement is a failure, not a rounding error.
        conflicts = [] if event_layer is None else event_layer['conflicts']
        if conflicts and result['status'] == 'observations_passed':
            result['status'] = 'failed'
            result['failure'] = 'event evidence: ' + ','.join(conflicts)
        if fuzz is not None:
            session = fuzz['holder']['session']
            passing_cases = [case for case in cases
                             if case.get('status') == 'observations_passed']
            fuzz_document = dict(session.document(), inputs=fuzz['document'])
            # A failed case is classified before it is called a finding.  A
            # random input that simply did not trigger the device is expected
            # exploration, not a hardware defect; the other classes stay findings.
            annotations = []
            defects, expected_failures = [], []
            for finding in fuzz_document.get('findings') or []:
                verdict = classify_case(finding.get('observation') or {})
                finding['failure_class'] = verdict['failure_class']
                finding['failure_detail'] = verdict['detail']
                finding['failure_severity'] = verdict['severity']
                index = (finding.get('observation') or {}).get('index')
                if isinstance(index, int):
                    finding['prefix_lines'] = index + 1
                (expected_failures if verdict['expected'] else defects).append(finding)
            fuzz_document['findings'] = defects
            fuzz_document['expected_failures'] = expected_failures
            classes = fuzz['classes']
            fuzz_document['failure_classes'] = dict(sorted(classes.items()))
            result['failure_classes'] = dict(sorted(classes.items()))
            # Every passing case was checked as it arrived (not only the
            # retained row sample); its counts are therefore the batch's own.
            mismatched_samples = list(session.correspondence_mismatches)
            checked = session.stats.correspondence_checked
            mismatched_count = session.stats.correspondence_mismatched
            non_expected = sum(count for cls, count in classes.items()
                               if cls not in ('passed',) + EXPECTED_FAILURE_CLASSES)
            expected_count = sum(classes.get(cls, 0) for cls in EXPECTED_FAILURE_CLASSES)
            retention = dict(fuzz_document.get('retention') or {})
            retention.update(
                cases_retained=len(verified), cases_total=session.stats.executed,
                findings_retained=len(defects),
                expected_failures_retained=len(expected_failures),
                failed_cases_retained=len(defects) + len(expected_failures),
                findings_total=non_expected,
                expected_failures_total=expected_count)
            fuzz_document['retention'] = retention
            fuzz_document['correspondence'] = dict(
                matched=max(0, checked - mismatched_count),
                mismatched=mismatched_samples,
                checked=checked,
                mismatched_total=mismatched_count,
                sampled=False,
                cases_retained=len(verified),
                cases_total=session.stats.executed,
                failed_cases=session.stats.failed,
                expected_failures=len(expected_failures),
                defects=len(defects))
            fuzz_document['findings_total'] = non_expected
            fuzz_document['expected_failures_total'] = expected_count
            (args.output / 'fuzz.json').write_text(json.dumps(fuzz_document, indent=2) + '\n')
            fuzz['corpus'].save(args.output / 'corpus.json')
            result['fuzz'] = fuzz_document
            result['cases_total'] = session.stats.executed
            result['cases_retained'] = len(verified)
            result['records_total'] = session.stats.executed
            result['submitted_total'] = fuzz_document.get('submitted_total')
            if session.status in ('host_error', 'completed_with_error'):
                result['status'] = 'fuzz_failed'
                log_text = ''
                try:
                    log_text = (args.output / 'run.log').read_text()
                except OSError:
                    pass
                result['host_failure'] = classify_host_failure(log_text)
                result['failure'] = session.error or result['host_failure']['message']
            elif mismatched_count:
                result['status'] = 'fuzz_failed'
                result['failure'] = ('correspondence: ' +
                                     (mismatched_samples[0]['reason']
                                      if mismatched_samples else 'a passing case'))
            else:
                result['failure'] = None
                result['status'] = ('fuzz_completed_with_findings' if non_expected
                                    else 'fuzz_completed')
            result['fuzz_result'] = dict(
                session_status=session.status,
                executed=session.stats.executed,
                passed=session.stats.passed,
                failed=session.stats.failed,
                findings=non_expected,
                findings_saved=len(defects),
                expected_failures=expected_count,
                expected_failures_saved=len(expected_failures),
                distinct_features=(None if session.feedback is None
                                   else session.feedback.get('distinct')),
                corpus_entries=(None if session.corpus is None
                                else len(session.corpus.get('entries') or ())),
                budget_reached=session.stats.budget_reached)
        if replay is not None:
            observed = [replay_view(case) for case in cases]
            mismatch = compare_replay(replay['expected'], observed)
            matched = mismatch is None and len(observed) >= len(replay['expected'])
            result['prefix_replay'] = dict(
                source=replay['source'], prefix_cases=len(replay['prefix']),
                expected_cases=len(replay['expected']),
                observed_cases=len(observed), matched=matched, mismatch=mismatch)
            result['replay'] = 'performed'
            result['status'] = 'replay_matched' if matched else 'replay_mismatched'
            result['failure'] = None if matched else mismatch
            (args.output / 'replay.json').write_text(json.dumps(
                dict(schema_version='inprocess_prefix_replay.v1',
                     source=replay['source'], matched=matched,
                     expected_cases=len(replay['expected']),
                     observed_cases=len(observed), mismatch=mismatch,
                     cases=observed), indent=2) + '\n')
        (args.output / 'summary.json').write_text(json.dumps(result, indent=2) + '\n')
        if fuzz is not None:
            print(json.dumps({'status': result['status'], 'output': str(args.output),
                              'cases': result['fuzz_result']['executed'],
                              'passed': result['fuzz_result']['passed'],
                              'failed': result['fuzz_result']['failed'],
                              'distinct_features': result['fuzz_result']['distinct_features'],
                              'corpus_entries': result['fuzz_result']['corpus_entries'],
                              'run_seconds': result['run_seconds'],
                              'total_seconds': result['total_seconds']}))
        elif replay is not None:
            print(json.dumps({'status': result['status'], 'output': str(args.output),
                              'cases': len(verified),
                              'matched': result['prefix_replay']['matched'],
                              'run_seconds': result['run_seconds'],
                              'total_seconds': result['total_seconds']}))
        else:
            print(json.dumps({'status': result['status'], 'output': str(args.output),
                              'cases': len(verified), 'run_seconds': result['run_seconds'],
                              'total_seconds': result['total_seconds']}))
        return 0 if result['status'] in ('observations_passed', 'fuzz_completed',
                                         'fuzz_completed_with_findings',
                                         'replay_matched') else 1


def self_rate(artifact):
    """The one declared clock rate of a generated model, or None."""
    clocks = artifact.runtime_document['clock_schedule']['clocks']
    return clocks[0]['frequency_hz'] if len(clocks) == 1 else None


if __name__ == '__main__':
    raise SystemExit(main())
