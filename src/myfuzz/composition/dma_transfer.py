"""Pure declaration and planning side of the F6 DMA transfer extension.

This module answers three questions, and deliberately only these three:

* what transfer does a scenario declare, normalized against the DMA device's
  own pinned CSR/edge facts (``dma_transfer_declaration``);
* is that declaration actually encodable by the selected device, and which of
  its limitations are *host-only* rather than device facts
  (``validate_transfer_plan``);
* if the transfer's destination/source is an IP window instead of RAM, what
  exactly would the host have to route, and what evidence would it have to
  produce (``dma_route_target``).

Nothing here builds, elaborates, simulates or replays a transfer.  A returned
plan/route is a *declaration*; the module never reports completion, coverage or
a measured transfer.  That is the integration owner's job.

The split between device facts and host limits is the point of the module:

* device facts come from the pinned component profile and the pinned RTL
  contract.  Examples: ZipDMA's SOURCE/DESTINATION are 30-bit *byte* address
  fields (``zipdma_ctrl.v:73-74,161-181``), so this ZipDMA cannot be aimed at
  ``0x40000000`` or above at all; wbdmac has no master SEL, so a partial byte
  enable is not encodable; ZipDMA writes its increment/size bits in the
  control word, wbdmac in its keyed start word.
* host-only limits are the current in-process F6 entry's bounds.  The
  declaration layers cap a block at four words (behavior file, executor and
  provider), the C++ host rejects a partial master SEL and any DMA master
  address outside RAM, and it drives ``mwb_err`` low.  Those go into
  ``host_limits`` with ``kind="host_only"`` and never masquerade as a device
  refusal.  The C++ host itself already reads ``DMA_BLOCK_WORDS`` and accepts
  up to sixteen record words, so the block cap is a property of the Python
  declaration layers, not of the model link.

The existing scenario keys stay compatible: ``dma_block_words``,
``dma_irq_pulse_ticks`` and ``dma_behavior`` are read with their historical
meaning and the behavior file keeps the ``inprocess_dma_behavior.v1`` schema.
New declaration keys are additive and are ignored by the existing executor:
``dma_increment_source`` / ``dma_increment_destination``,
``dma_transfer_size_bytes``, ``dma_master_byte_enable``, ``dma_start_word``,
``dma_max_outstanding``, ``dma_response_delay``, ``dma_backpressure``,
``dma_observation_expectations``, ``dma_error_injection`` and ``dma_route``.

A DMA behavior file (or the selected profile) may also declare *capabilities*:
``channels``, ``beat_bytes``, ``max_outstanding`` and ``burst_beats``.  Those are
declarations, not execution: this module normalizes them through
``myfuzz.composition.inprocess_behavior`` (so the declaration layer and the
planner agree on the shape) and refuses any that the selected device's pinned
facts cannot honour, by name
(``dma-capability-beyond-device:<capability>:<declared>><device>``).  A declared
capability is never narrowed to the single-channel, 32-bit-beat, one-outstanding
transfer the current F6 host runs.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

from myfuzz.composition.inprocess_behavior import (BehaviorError,
                                                   dma_capabilities,
                                                   dma_capability_refusals)

DMA_PLAN_SCHEMA = 'dma_transfer_plan.v1'
DMA_VALIDATION_SCHEMA = 'dma_transfer_validation.v1'
DMA_ROUTE_SCHEMA = 'dma_route_target.v1'
DMA_BEHAVIOR_SCHEMA = 'inprocess_dma_behavior.v1'

WORD_BYTES = 4
MAX_IRQ_PULSE_TICKS = 4096
MAX_RESPONSE_DELAY_TICKS = 64
#: The deepest master-response pipeline this module declares a *host* for.  The
#: historical in-process host served one response at a time and held
#: ``mwb_stall`` while it was owed, so a declared depth above one was a host
#: limit and not a device fact.  The unified host now serves a declared depth
#: from a ring of pending responses and reports the measured peak
#: (``scripts/inprocess_obi_apb_f1f4_spike.cpp``, ``DMA_MASTER_OUTSTANDING``).
#: The device fact is still the binding bound: a plan above the pinned device's
#: ``max_outstanding`` is refused by name, never clamped.
MAX_OUTSTANDING = 2

DMA_STATUS_KINDS = ('status', 'count', 'compare', 'control', 'data', 'undeclared')

BEHAVIOR_KEYS = ('block_words', 'irq_pulse_ticks', 'busy_bit', 'err_bit', 'status_kind',
                 'capabilities')
#: The capability names a DMA behavior file or a profile may declare.  The shape
#: bounds live in ``inprocess_behavior.DMA_CAPABILITY_BOUNDS``; the device bound
#: below is what the selected pinned RTL can honour.
DMA_CAPABILITY_KEYS = ('channels', 'beat_bytes', 'max_outstanding', 'burst_beats')
BEHAVIOR_METADATA_KEYS = ('schema_version', 'description', 'notes')
BEHAVIOR_INLINE_KEYS = {'block_words': 'dma_block_words',
                        'irq_pulse_ticks': 'dma_irq_pulse_ticks'}

ROUTE_KINDS = ('target_window', 'fifo')
ROUTE_DIRECTIONS = ('write', 'read')
ROUTE_ADDRESS_MODES = ('fixed', 'aperture')
ROUTE_EVIDENCE_KINDS = ('fifo_level', 'register_readback')
#: The target protocols a routed master beat may be presented on.  A route is a
#: transport of one master word to one target register, so the only protocol fact
#: it needs is that the target really has a request port the host can drive and a
#: response port that completes the beat.  All four protocols of
#: ``SUPPORTED_TARGET_PROTOCOLS`` have both (each generated target artifact binds
#: its own bridge to the same generic beat port, and its own passive trace), so a
#: route on any of them is admissible; a protocol with no such adapter is refused
#: by name instead of being driven through another protocol's completion.
ROUTE_PROTOCOLS = ('apb3', 'tl-ul', 'wishbone', 'axi4-lite')
#: The profile's endpoint protocol word, normalized to the names the harness uses
#: for the same wire: a PULP/OpenTitan ``apb`` endpoint is APB3, and the three
#: registered-target wires are already spelled the harness way.
PROFILE_PROTOCOL_NAMES = {'apb': 'apb3', 'apb3': 'apb3', 'apb4': 'apb4',
                          'axi4-lite': 'axi4-lite', 'wishbone': 'wishbone',
                          'tl-ul': 'tl-ul', 'ahb-lite': 'ahb-lite'}
ROUTE_KEYS = ('kind', 'direction', 'target_name', 'target_index', 'target_profile',
              'target_window', 'register', 'offset', 'address_mode', 'evidence',
              'notes')
#: ``words`` is the aperture width a read route covers (one readable target
#: register per word) and ``expected_word`` the word a popped FIFO entry must
#: carry; both are optional and both are cross-checked against the target's own
#: register map.  A declaration that states neither keeps the historical
#: single-register readback shape.
EVIDENCE_KEYS = ('kind', 'register', 'offset', 'field', 'bits', 'depth',
                 'sampling', 'source', 'words', 'expected_word')
#: The register side effects that make a FIFO port a FIFO port.  A read route is
#: admitted only on a port the RTL pops on read; a port the RTL does not pop is
#: refused by name instead of being called a FIFO read.
FIFO_POP_SIDE_EFFECT = 'read_pops_fifo'
FIFO_PUSH_SIDE_EFFECT = 'write_pushes_fifo'

#: A declared host-injected master error response: which routed beat carries it
#: and that it is the Wishbone master error input, not a target-side fault.
ERROR_INJECTION_KEYS = ('beat_index', 'mode', 'direction')
ERROR_INJECTION_MODES = ('master_response',)

ZIPDMA_REVISION = 'git:42606d2d6ef55df313772232977621b2d72f0159'
WBDMAC_REVISION = ZIPDMA_REVISION

#: The pinned ZipDMA file set, exactly as the selected profile states it.
ZIPDMA_FILES = (
    'rtl/zipdma/zipdma.v',
    'rtl/zipdma/zipdma_ctrl.v',
    'rtl/zipdma/zipdma_fsm.v',
    'rtl/zipdma/zipdma_mm2s.v',
    'rtl/zipdma/zipdma_s2mm.v',
    'rtl/zipdma/zipdma_rxgears.v',
    'rtl/zipdma/zipdma_txgears.v',
    'rtl/ex/sfifo.v',
    'rtl/ex/wbarbiter.v',
)
WBDMAC_FILES = ('rtl/peripherals/wbdmac.v',)

#: Device facts, pinned to the selected RTL and cross-checked against every
#: component profile this module is handed.  A profile that disagrees with the
#: pinned bytes is refused by name instead of the module quietly preferring one.
#: ``max_block_words`` is this module's declaration bound, not a measured RTL
#: limit: ZipDMA's LENGTH register is a 32-bit byte count, and wbdmac's
#: block-length field is the low LGMEMLEN=10 bits of its start word (1..1024).
DEVICE_FACTS = {
    'zipdma': {
        'family': 'zipdma',
        'top_module': 'zipdma',
        'source_revision': ZIPDMA_REVISION,
        'source_files': ZIPDMA_FILES,
        'registers': (
            ('CONTROL_STATUS', 0, 'rw', 'control'),
            ('SOURCE', 4, 'rw', 'source'),
            ('DESTINATION', 8, 'rw', 'destination'),
            ('LENGTH', 12, 'rw', 'length'),
        ),
        'length_unit': 'bytes',
        'length_register_bits': 32,
        # AW = ADDRESS_WIDTH - log2(BUS_WIDTH/8) = 32 - 2 = 30.  The top
        # zero-extends the 30-bit CSR field onto the 32-bit internal byte
        # address, so a byte address >= 0x40000000 cannot be programmed.
        'source_destination_byte_address_bits': 30,
        'master_address_units': 'word',
        'master_address_shift': 2,
        'master_address_width': 30,
        'master_has_error': True,
        'master_has_sel': True,
        'master_sel_signal': 'mwb_sel',
        'control_sel_signal': 'swb_sel',
        'master_fixed_byte_enable': None,
        'max_block_words': 64,
        'max_outstanding': 1,
        # Declarable capability bounds this pinned RTL really has: one channel,
        # one 32-bit beat per master request (BUS_WIDTH=32), one outstanding
        # request, and no master burst.  A declaration above any of them is
        # refused by name; nothing here is a host limitation in disguise.
        'channels': 1,
        'beat_bytes': 4,
        'burst_beats': 1,
        'default_size_bytes': 4,
        'size_codes': {1: 3, 2: 2, 4: 0},
        'start': {
            'encoding': 'zipdma_control_write',
            'key': 0,
            'key_bits': None,
            'block_words_bits': None,
            'increment_source_bit': 18,
            'increment_destination_bit': 22,
            'size_bits': {'source': (16, 17), 'destination': (20, 21)},
            'baseline_word': 0,
            'condition': 'full-word control write while idle, data[31] == 0',
        },
        'irq_trigger': 'level',
        'irq_clear': {'method': 'write', 'offset': 0, 'value': 0x80000000,
                      'byte_enable': 15},
        'status_default': {
            'kind': 'status', 'busy_bit': 31, 'err_bit': 30,
            'busy_bit_source': 'builtin_zipdma_rtl_default',
            'err_bit_source': 'builtin_zipdma_rtl_default',
            'evidence': 'third_party/soc-zipcpu/rtl/zipdma/zipdma_ctrl.v:116-117',
        },
        'evidence': {
            'source_destination_byte_address_bits':
                'third_party/soc-zipcpu/rtl/zipdma/zipdma_ctrl.v:73-74,161-181,259-260',
            'length_bits': 'third_party/soc-zipcpu/rtl/zipdma/zipdma_ctrl.v:44-46,263-264',
            'master_sel': 'third_party/soc-zipcpu/rtl/zipdma/zipdma.v:72,408',
            'master_byte_enable_lanes':
                'third_party/soc-zipcpu/rtl/zipdma/zipdma_s2mm.v:81,205-233',
            'size_and_increment_bits':
                'third_party/soc-zipcpu/rtl/zipdma/zipdma_ctrl.v:119-129,246-252',
            'start_and_clear':
                'third_party/soc-zipcpu/rtl/zipdma/zipdma_ctrl.v:303-321',
            'irq_level':
                'third_party/soc-zipcpu/rtl/zipdma/zipdma_ctrl.v:287,301,317',
        },
        #: The RTL byte(s) behind each declarable capability bound below.  A
        #: declaration above one of them is refused by name and this is the
        #: anchor the refusal points at, so the bound is never a bare number.
        'capability_evidence': {
            'channels': 'third_party/soc-zipcpu/rtl/zipdma/zipdma.v:52-96 '
                        '(one control port, one master port, one CSR set: there is '
                        'no per-channel register pair)',
            'beat_bytes': 'configs/peripherals/shared_profile_dma/component_profile.json '
                          'source.elaboration.parameters BUS_WIDTH=32 with '
                          'third_party/soc-zipcpu/rtl/zipdma/zipdma.v:69-75 '
                          '(o_mwb_data/o_mwb_sel/i_mwb_data are BUS_WIDTH wide); the '
                          'RTL parameter defaults to 512 but this pinned '
                          'elaboration fixes 32',
            'burst_beats': 'third_party/soc-zipcpu/rtl/zipdma/zipdma.v:69-75,403-411 '
                           '(one cyc/stb/ack beat per master request; there is no '
                           'burst-length master signal)',
            'max_outstanding': 'third_party/soc-zipcpu/rtl/zipdma/zipdma.v:403-411 '
                               'with third_party/soc-zipcpu/rtl/zipdma/'
                               'zipdma_s2mm.v:81,205-233 (the master holds one '
                               'request until its own ack; no request/ack counter '
                               'pair exists on this port)',
        },
    },
    'wbdmac': {
        'family': 'wbdmac',
        'top_module': 'wbdmac',
        'source_revision': WBDMAC_REVISION,
        'source_files': WBDMAC_FILES,
        'registers': (
            ('CONTROL_STATUS', 0, 'rw', 'control'),
            ('TOTAL_LENGTH', 4, 'rw', 'length'),
            ('SOURCE', 8, 'rw', 'source'),
            ('DESTINATION', 12, 'rw', 'destination'),
        ),
        'length_unit': 'words',
        'length_register_bits': 30,
        # The CSR takes a byte address in bits [31:2] and keeps the 30-bit word
        # address, so the full 32-bit byte address is programmable.
        'source_destination_byte_address_bits': 32,
        'master_address_units': 'word',
        'master_address_shift': 2,
        'master_address_width': 30,
        'master_has_error': True,
        'master_has_sel': False,
        'master_sel_signal': None,
        'control_sel_signal': None,
        'master_fixed_byte_enable': 15,
        'max_block_words': 1024,
        # One master response at a time - measured, not assumed.  The pinned
        # master *looks* pipelined: it counts the read requests it has presented
        # (``nracks``, wbdmac.v:410-420) separately from the read acks it received
        # (``nread``, wbdmac.v:422-432), and the write path likewise
        # (``nwritten``/``nwacks``, wbdmac.v:434-456).  But its burst terminator
        # compares a *request* count against the block length as if it counted acks
        # (``last_read_request <= (nracks + 1 == cfg_blocklen_sub_one) ||
        # (bus_nracks == cfg_len-2)``, wbdmac.v:472-491), so a host that accepts a
        # second request before the first ack ends the read burst one beat early.
        # Measured through this entry with a two-response host: seven read beats and
        # two write beats for a four-word block, destination words 1..3 left at the
        # prefill, no completion (runs/p2-dma-20261103/wbdmac-outstanding2-mismatch/).
        # The executable device fact is therefore one, and a plan above it is
        # refused by name rather than run into that.
        'max_outstanding': 1,
        # wbdmac's CSR and master data are 32 bits wide and it has no master
        # SEL/burst: one channel, one four-byte beat, one outstanding request.
        'channels': 1,
        'beat_bytes': 4,
        'burst_beats': 1,
        'default_size_bytes': 4,
        'size_codes': {},
        'start': {
            'encoding': 'wbdmac_keyed_start',
            'key': 0xfed,
            'key_bits': (16, 27),
            'block_words_bits': (0, 9),
            'increment_source_bit': 29,
            'increment_destination_bit': 28,
            'size_bits': None,
            'baseline_word': 0x0fed0004,
            'condition': 'keyed start while idle, cfg_len nonzero, bits[31:30] == 0',
        },
        'irq_trigger': 'pulse',
        'irq_clear': {'method': 'none'},
        'status_default': {
            'kind': 'status', 'busy_bit': 31, 'err_bit': 30,
            'busy_bit_source': 'pinned_wbdmac_rtl_readback',
            'err_bit_source': 'pinned_wbdmac_rtl_readback',
            'evidence':
                'third_party/soc-zipcpu/rtl/peripherals/wbdmac.v:602-606',
        },
        'evidence': {
            'source_destination_byte_address_bits':
                'third_party/soc-zipcpu/rtl/peripherals/wbdmac.v:274-275',
            'length_bits': 'third_party/soc-zipcpu/rtl/peripherals/wbdmac.v:399-406,610',
            'block_length_bits':
                'third_party/soc-zipcpu/rtl/peripherals/wbdmac.v:237,264-266',
            'start_key_and_increment_bits':
                'third_party/soc-zipcpu/rtl/peripherals/wbdmac.v:255-274',
            'no_master_sel': 'third_party/soc-zipcpu/rtl/peripherals/wbdmac.v:88-100',
            'irq_pulse': 'third_party/soc-zipcpu/rtl/peripherals/wbdmac.v:378-387',
            'status_readback':
                'third_party/soc-zipcpu/rtl/peripherals/wbdmac.v:602-606',
        },
        'capability_evidence': {
            'channels': 'third_party/soc-zipcpu/rtl/peripherals/wbdmac.v:167-179 '
                        '(one dma_state/cfg_raddr/cfg_waddr register set; the CSR '
                        'window has four words and no per-channel pair)',
            'beat_bytes': 'third_party/soc-zipcpu/rtl/peripherals/wbdmac.v:110-120 '
                          '(BUS_WIDTH=32 and o_mwb_data/i_mwb_data are BUS_WIDTH '
                          'wide); the module has no SEL pin either '
                          '(third_party/soc-zipcpu/rtl/peripherals/wbdmac.v:137-143)',
            'burst_beats': 'third_party/soc-zipcpu/rtl/peripherals/wbdmac.v:551-561 '
                           '(o_mwb_cyc/o_mwb_stb are one word per cycle; the length '
                           'register is the total word count, there is no '
                           'burst-length master signal)',
            'max_outstanding': 'third_party/soc-zipcpu/rtl/peripherals/wbdmac.v:410-456 '
                               '(nracks/nread and nwritten/nwacks count requests and '
                               'acks separately, so the port looks pipelined) against '
                               'third_party/soc-zipcpu/rtl/peripherals/wbdmac.v:472-491 '
                               '(last_read_request compares the *request* count with '
                               'the block length as if it counted acks): the counts '
                               'disagree as soon as two requests are in flight, which '
                               'is what the measured two-outstanding run shows.  One '
                               'response is the depth this entry can execute',
        },
    },
}

#: What this in-process F6 host can execute today, as opposed to what the
#: device can encode.  Every entry is reported with ``kind="host_only"``.
HOST_BLOCK_WORDS = 4
HOST_START_WORDS = {'zipdma': 0x00000000, 'wbdmac': 0x0fed0004}
HOST_SOURCE = 'inprocess_f6_host'


class DmaTransferError(ValueError):
    """A DMA transfer declaration, plan or route is absent, malformed or unencodable."""

    def __init__(self, reason: str, detail: str | None = None) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(reason if detail is None else reason + ':' + str(detail))


def _fail(reason: str, detail: str | None = None) -> None:
    raise DmaTransferError(reason, detail)


# ---------------------------------------------------------------------------
# small typed accessors
# ---------------------------------------------------------------------------
def _is_int(value: object) -> bool:
    """A JSON integer, not a bool and not a float."""
    return type(value) is int


def _is_bool(value: object) -> bool:
    return type(value) is bool


def _word(value: object, *, bits: int = 32) -> bool:
    return _is_int(value) and 0 <= value < (1 << bits)


def _attr(value: object, name: str, default: object = None) -> object:
    """Read one fact from a typed profile object or from its JSON mapping."""
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _copy(value: object) -> object:
    """A JSON-shaped deep copy, so a plan never shares a caller's lists."""
    if isinstance(value, Mapping):
        return {key: _copy(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_copy(item) for item in value]
    return value


def _relative_path(path: object, reason: str) -> str:
    """A repo-relative POSIX path, or a named refusal."""
    if (not isinstance(path, str) or not path or '\x00' in path or '\\' in path):
        _fail(reason, 'path')
    candidate = Path(path)
    if candidate.is_absolute() or not candidate.parts or '..' in candidate.parts:
        _fail(reason, 'path')
    return candidate.as_posix()


def _read_declared_json(path: object, base_dir: object, *, reason: str) -> dict:
    """Read one repo-relative JSON declaration without escaping ``base_dir``."""
    relative = _relative_path(path, reason + '-path')
    if base_dir is None:
        _fail(reason + '-base-dir-absent', relative)
    base = Path(base_dir).resolve()
    candidate = (base / relative).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        _fail(reason + '-path', relative)
    if not candidate.is_file():
        _fail(reason + '-file-missing', relative)
    try:
        document = json.loads(candidate.read_text(encoding='utf-8'))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        _fail(reason + '-json-invalid', relative)
    if not isinstance(document, dict):
        _fail(reason + '-document-invalid', relative)
    return document


# ---------------------------------------------------------------------------
# device declaration (profile cross-checks)
# ---------------------------------------------------------------------------
def _device_declaration(profile: object) -> dict:
    """The pinned device facts for one profile, cross-checked against its bytes.

    The returned dict is a declaration, not a measurement.  A profile that
    names an unmodelled device, a different source revision or a different CSR
    map is refused by name rather than inferred from its component id.
    """
    source = _attr(profile, 'source')
    top = _attr(source, 'top_module')
    family = top if isinstance(top, str) and top in DEVICE_FACTS else None
    if family is None:
        _fail('dma-device-unsupported', str(top) if top is not None else 'absent')
    pinned = DEVICE_FACTS[family]
    revision = _attr(source, 'revision')
    if revision != pinned['source_revision']:
        _fail('dma-profile-source-drift', family + ':revision')
    files = _attr(source, 'files', ()) or ()
    if tuple(sorted(files)) != tuple(sorted(pinned['source_files'])):
        _fail('dma-profile-source-drift', family + ':files')
    if _attr(source, 'include_roots', ()):
        _fail('dma-profile-source-drift', family + ':include_roots')

    address = _attr(profile, 'address')
    if address is None:
        _fail('dma-profile-source-drift', family + ':address')
    rows = {_attr(row, 'name'): row
            for row in (_attr(address, 'registers', ()) or ())
            if _attr(row, 'name') is not None}
    registers = {}
    for name, offset, access, role in pinned['registers']:
        row = rows.get(name)
        if row is None:
            _fail('dma-profile-source-drift', family + ':register:' + name)
        if (_attr(row, 'offset') != offset or _attr(row, 'width') != 32
                or _attr(row, 'access') != access):
            _fail('dma-profile-source-drift', family + ':register:' + name)
        registers[role] = {'name': name, 'offset': offset,
                           'access': access, 'width': 32}
    window = _attr(address, 'window_size')
    if not _is_int(window) or window < 16 or max(
            row['offset'] for row in registers.values()) + 4 > window:
        _fail('dma-profile-source-drift', family + ':window')

    capabilities = _attr(profile, 'capabilities', {}) or {}
    if not isinstance(capabilities, Mapping):
        _fail('dma-profile-source-drift', family + ':capabilities')
    expected = {
        'master_address_units': 'word',
        'master_address_width': 30,
        'master_has_error': True,
        'master_byte_enable': pinned['master_has_sel'],
        'byte_enable': pinned['master_has_sel'],
        'address_units': 'word',
        'address_width': 2,
    }
    boolean_keys = ('master_has_error', 'master_byte_enable', 'byte_enable')
    for key, value in expected.items():
        if key not in capabilities:
            continue
        observed = capabilities[key]
        if key in boolean_keys:
            if observed is not value:
                _fail('dma-profile-source-drift', family + ':' + key)
        elif observed != value:
            _fail('dma-profile-source-drift', family + ':' + key)
    if 'master_address_units' not in capabilities or 'master_has_error' not in capabilities:
        _fail('dma-profile-source-drift', family + ':capabilities-incomplete')
    if not pinned['master_has_sel']:
        if capabilities.get('master_fixed_byte_enable') != 15:
            _fail('dma-profile-source-drift', family + ':master_fixed_byte_enable')

    triggers = {_attr(row, 'trigger') for row in (_attr(profile, 'interrupts', ()) or ())
                if _attr(row, 'role') == 'irq'}
    if triggers != {pinned['irq_trigger']}:
        _fail('dma-profile-irq-drift', family)

    bound = pinned['max_block_words']
    declared_bound = capabilities.get('max_block_words')
    if declared_bound is not None:
        if not _is_int(declared_bound) or not 1 <= declared_bound <= bound:
            _fail('dma-profile-bound-invalid', family)
        bound = declared_bound
    declared_outstanding = capabilities.get('max_outstanding')
    if declared_outstanding is not None and (
            not _is_int(declared_outstanding) or declared_outstanding < 1):
        _fail('dma-profile-capability-invalid', family + ':max_outstanding')
    # A declared depth *below* the pinned device's is a narrowing declaration and
    # is allowed (it bounds the plan without claiming more than the RTL has); a
    # declared depth above it is refused by the capability loop below, which names
    # the device and the numbers.  So this fact is not restated here.
    # A profile may declare the same capability names a behavior file does.  The
    # pinned device is the bound: a profile that declares two channels, an
    # eight-byte beat or a burst is refused by name instead of being silently
    # ignored while the plan still describes a single-channel transfer.
    declared_capabilities = {}
    for key in DMA_CAPABILITY_KEYS:
        declared = capabilities.get(key)
        if declared is None:
            continue
        if not _is_int(declared) or declared < 1:
            _fail('dma-profile-capability-invalid', family + ':' + key)
        if declared > pinned[key]:
            _fail('dma-profile-capability-beyond-device',
                  '%s:%s:%d>%d' % (family, key, declared, pinned[key]))
        declared_capabilities[key] = declared

    declaration = {
        'family': family,
        'top_module': pinned['top_module'],
        'source_revision': pinned['source_revision'],
        'source_files': list(pinned['source_files']),
        'facts_source': 'pinned_source_contract',
        'registers': registers,
        'length_unit': pinned['length_unit'],
        'length_register_bits': pinned['length_register_bits'],
        'source_destination_byte_address_bits':
            pinned['source_destination_byte_address_bits'],
        'master_address_units': pinned['master_address_units'],
        'master_address_shift': pinned['master_address_shift'],
        'master_address_width': pinned['master_address_width'],
        'master_has_error': pinned['master_has_error'],
        'master_has_sel': pinned['master_has_sel'],
        'master_sel_signal': pinned['master_sel_signal'],
        'control_sel_signal': pinned['control_sel_signal'],
        'master_fixed_byte_enable': pinned['master_fixed_byte_enable'],
        'max_block_words': bound,
        'device_max_block_words': pinned['max_block_words'],
        'max_outstanding': pinned['max_outstanding'],
        'default_size_bytes': pinned['default_size_bytes'],
        'size_codes': dict(pinned['size_codes']),
        'start': _copy(pinned['start']),
        'irq_trigger': pinned['irq_trigger'],
        'irq_clear': _copy(pinned['irq_clear']),
        'status_default': _copy(pinned['status_default']),
        'evidence': dict(pinned['evidence']),
        # The RTL anchor behind each declarable capability bound, so a refusal
        # above a bound can name the bytes instead of only the number.
        'capability_evidence': _copy(pinned.get('capability_evidence') or {}),
        'declared_bounds': {
            'max_block_words': declared_bound,
            'max_outstanding': declared_outstanding,
        },
        'device_capabilities': _device_capabilities(family, pinned),
        'declared_profile_capabilities': declared_capabilities,
    }
    return declaration


def _device_capabilities(family: str, pinned: Mapping) -> dict:
    """The four declarable capabilities this pinned device really has."""
    return {'channels': pinned['channels'],
            'beat_bytes': pinned['beat_bytes'],
            'max_outstanding': pinned['max_outstanding'],
            'burst_beats': pinned['burst_beats']}


# ---------------------------------------------------------------------------
# behavior declaration
# ---------------------------------------------------------------------------
def _behavior_declaration(config: Mapping, base_dir: object, *,
                          max_block_words: int, family: str,
                          device_capabilities: Mapping | None = None) -> dict:
    """The declared DMA behavior file plus the compatible inline keys.

    The file schema and fact names are the existing ``inprocess_dma_behavior.v1``
    ones, so ``configs/behaviors/zipdma_f6.json`` and its siblings are read
    unchanged.  File-over-inline precedence and the conflict refusal match
    ``myfuzz.composition.inprocess_behavior``; only the block upper bound is the
    device's, not the current host's 1..4.  A declared ``capabilities`` block is
    normalized by that module and refused here, by name, when the pinned device
    cannot honour it.
    """
    declared = config.get('dma_behavior')
    document = None
    path = None
    if declared is not None:
        document = _read_declared_json(declared, base_dir, reason='dma-behavior')
        path = _relative_path(declared, 'dma-behavior-path')
        observed = document.get('schema_version')
        if observed != DMA_BEHAVIOR_SCHEMA:
            _fail('dma-behavior-schema', str(observed) if observed else 'missing')
        for key in document:
            if key in BEHAVIOR_METADATA_KEYS or key in BEHAVIOR_KEYS:
                continue
            _fail('dma-behavior-field', key)
        description = document.get('description')
        if description is not None and not isinstance(description, str):
            _fail('dma-behavior-value', 'description')
        notes = document.get('notes')
        if notes is not None and (not isinstance(notes, list)
                                  or any(not isinstance(note, str) for note in notes)):
            _fail('dma-behavior-value', 'notes')

    facts: dict = {}
    fact_sources: dict = {}
    for key, inline in BEHAVIOR_INLINE_KEYS.items():
        in_file = document is not None and key in document
        in_config = inline in config
        if in_file:
            if in_config and config[inline] != document[key]:
                _fail('behavior-source-conflict:' + key)
            facts[key] = document[key]
            fact_sources[key] = 'file'
        elif in_config:
            facts[key] = config[inline]
            fact_sources[key] = 'inline'
    if document is not None:
        for key in ('busy_bit', 'err_bit', 'status_kind'):
            if key in document:
                facts[key] = document[key]

    if 'block_words' in facts:
        block = facts['block_words']
        if not _is_int(block) or block < 1:
            _fail('dma-behavior-value', 'block_words')
        if block > max_block_words:
            _fail('block-beyond-declared-bound',
                  '%s:%d>%d' % (family, block, max_block_words))
        facts['block_words'] = block
    if 'irq_pulse_ticks' in facts:
        ticks = facts['irq_pulse_ticks']
        if not _is_int(ticks) or not 1 <= ticks <= MAX_IRQ_PULSE_TICKS:
            _fail('dma-behavior-value', 'irq_pulse_ticks')
        facts['irq_pulse_ticks'] = ticks
    if ('busy_bit' in facts) != ('err_bit' in facts):
        _fail('dma-behavior-value', 'status_bits')
    if 'busy_bit' in facts:
        busy, err = facts['busy_bit'], facts['err_bit']
        if not _is_int(busy) or not 0 <= busy <= 31:
            _fail('dma-behavior-value', 'busy_bit')
        if not _is_int(err) or not 0 <= err <= 31:
            _fail('dma-behavior-value', 'err_bit')
        if busy == err:
            _fail('dma-behavior-value', 'err_bit')
    if 'status_kind' in facts and facts['status_kind'] not in DMA_STATUS_KINDS:
        _fail('dma-behavior-value', 'status_kind')
    # The capability block is normalized by the declaration layer (one shape for
    # both readers) and refused here against the pinned device.  The declared
    # numbers stay declared: a plan never narrows them to what the host runs.
    capabilities = None
    if document is not None and 'capabilities' in document:
        try:
            capabilities = dma_capabilities(document['capabilities'])
        except BehaviorError as error:
            _fail('dma-capability-invalid', str(error))
        bound = device_capabilities or {}
        for name in dma_capability_refusals(capabilities, limit=bound):
            _fail('dma-capability-beyond-device', name)
    return {'facts': facts,
            'capabilities': capabilities,
            'fact_sources': fact_sources,
            'declared_by': 'file' if document is not None
            else ('inline' if facts else 'none'),
            'path': path,
            'document': document}


# ---------------------------------------------------------------------------
# edge artifact declaration
# ---------------------------------------------------------------------------
#: The edge contract's ``input_order`` is the host-driven step input vector:
#: the control request and the master response.  The outputs the host samples
#: (swb_stall/swb_ack/swb_dat_r/mwb_*) live in the runtime document's
#: ``backend_ports``, not here.  ``swb_sel``/``mwb_sel`` appear only when the
#: device and environment have a SEL.
_EDGE_INPUT_PORTS = ('swb_cyc', 'swb_stb', 'swb_we', 'swb_adr', 'swb_dat_w',
                     'mwb_stall', 'mwb_ack', 'mwb_dat_r', 'mwb_err')


def _artifact_declaration(artifact: object, device: Mapping) -> dict:
    """Normalize the generated edge artifact (or its absence) into facts.

    Three shapes are accepted: the generated runtime document (a mapping with
    ``dma_edge_contract``), a bare ``wishbone_dma_edge*`` contract, and the
    ``ip_test_capability.v2`` declaration.  The last one carries no edge facts;
    that absence is reported instead of guessed.
    """
    absent = {'kind': 'absent', 'edge_present': False,
              'environment_max_outstanding': None,
              'master_address_units': None, 'master_address_shift': None,
              'master_byte_enable_signal': None, 'control_byte_enable_signal': None,
              'master_fixed_byte_enable': None, 'input_order': None,
              'error_port': None}
    if artifact is None:
        return absent
    if not isinstance(artifact, Mapping):
        _fail('dma-artifact-invalid', 'not-a-mapping')
    edge = artifact.get('dma_edge_contract')
    kind = 'runtime_document'
    if edge is None:
        schema = artifact.get('schema_version')
        if isinstance(schema, str) and schema.startswith('wishbone_dma'):
            edge, kind = artifact, 'edge_contract'
        elif schema == 'ip_test_capability.v2':
            info = dict(absent)
            info['kind'] = 'test_capability_only'
            return info
        else:
            _fail('dma-artifact-invalid', 'unrecognized-document')
    if not isinstance(edge, Mapping):
        _fail('dma-artifact-invalid', 'edge-contract-not-a-mapping')
    schema = edge.get('schema_version')
    if not isinstance(schema, str) or not schema.startswith('wishbone_dma'):
        _fail('dma-artifact-invalid', 'edge-schema')
    if edge.get('master_address_units') != 'word':
        _fail('dma-artifact-master-address-unsupported', 'units')
    if edge.get('master_address_shift') != device['master_address_shift']:
        _fail('dma-artifact-master-address-unsupported', 'shift')
    outstanding = edge.get('environment_max_outstanding')
    if not _is_int(outstanding) or outstanding < 1:
        _fail('dma-artifact-invalid', 'environment_max_outstanding')
    if edge.get('same_edge_accept_and_complete') is not False:
        _fail('dma-artifact-invalid', 'same_edge_accept_and_complete')
    if edge.get('control_address_units') != 'word_index':
        _fail('dma-artifact-invalid', 'control_address_units')
    master_signal = edge.get('master_byte_enable_signal')
    if master_signal not in (None, 'mwb_sel'):
        _fail('dma-artifact-master-byte-enable-unsupported', 'signal')
    if master_signal is None and edge.get('master_fixed_byte_enable') != 15:
        _fail('dma-artifact-master-byte-enable-unsupported', 'fixed-enable')
    if not device['master_has_sel'] and master_signal is not None:
        _fail('dma-artifact-master-byte-enable-unsupported', 'select-on-no-select-device')
    if device['master_has_sel'] and master_signal is None:
        # The environment cannot drive SEL even though the RTL has one.  That
        # is a host limit, reported by validate_transfer_plan when the plan
        # actually needs a partial lane mask.
        pass
    control_signal = edge.get('control_byte_enable_signal')
    if control_signal not in (None, 'swb_sel'):
        _fail('dma-artifact-invalid', 'control_byte_enable_signal')
    order = edge.get('input_order')
    if order is not None:
        if not isinstance(order, list) or any(not isinstance(name, str) for name in order):
            _fail('dma-artifact-invalid', 'input_order')
        missing = [name for name in _EDGE_INPUT_PORTS if name not in order]
        if missing:
            _fail('dma-artifact-invalid', 'missing-port:' + missing[0])
    # An artifact may explicitly state whether its environment can inject a
    # native master error.  Without that statement the presence of the mwb_err
    # input in the step vector is the declaration.
    if 'error_injection' in edge:
        declared_injection = edge.get('error_injection')
        if not _is_bool(declared_injection):
            _fail('dma-artifact-invalid', 'error_injection')
        error_port = declared_injection
    elif order is not None:
        error_port = 'mwb_err' in order
    else:
        error_port = None
    return {'kind': kind, 'edge_present': True,
            'environment_max_outstanding': outstanding,
            'master_address_units': 'word',
            'master_address_shift': edge['master_address_shift'],
            'master_byte_enable_signal': master_signal,
            'control_byte_enable_signal': control_signal,
            'master_fixed_byte_enable': edge.get('master_fixed_byte_enable'),
            'input_order': None if order is None else list(order),
            'error_port': error_port}


# ---------------------------------------------------------------------------
# start word / byte enables
# ---------------------------------------------------------------------------
def _derive_start_word(device: Mapping, *, block_words: int,
                       increment_source: bool, increment_destination: bool,
                       size_bytes: int) -> int:
    """The control/start word the pinned device needs for this plan.

    ZipDMA starts on a full-word write of a word with data[31]=0; bits [17:16]
    and [21:20] select the source/destination beat size and bits 18/22 disable
    the matching address increment.  wbdmac requires 0xfed in bits [27:16], a
    zero in bits [31:30], the increment-disable bits 29/28 and the block length
    in bits [9:0].
    """
    start = device['start']
    if start['encoding'] == 'zipdma_control_write':
        code = device['size_codes'].get(size_bytes)
        if code is None:
            _fail('master-byte-enable-unsupported', 'size-bytes:' + str(size_bytes))
        word = start['baseline_word']
        if not increment_source:
            if start['increment_source_bit'] is None:
                _fail('non-incrementing-transfer-not-encoded-by-start-word', 'source')
            word |= 1 << start['increment_source_bit']
        if not increment_destination:
            if start['increment_destination_bit'] is None:
                _fail('non-incrementing-transfer-not-encoded-by-start-word', 'destination')
            word |= 1 << start['increment_destination_bit']
        word |= code << start['size_bits']['source'][0]
        word |= code << start['size_bits']['destination'][0]
        return word
    if start['encoding'] == 'wbdmac_keyed_start':
        if size_bytes != 4:
            _fail('master-byte-enable-unsupported', 'wbdmac-has-no-size-field')
        word = start['key'] << start['key_bits'][0]
        if not increment_source:
            word |= 1 << start['increment_source_bit']
        if not increment_destination:
            word |= 1 << start['increment_destination_bit']
        low, high = start['block_words_bits']
        word |= block_words & ((1 << (high - low + 1)) - 1)
        return word
    _fail('dma-device-unsupported', 'start-encoding')


def _check_start_word(plan_start: int, expected_start: int, *,
                      increment_source: bool, increment_destination: bool) -> None:
    """Refuse a start word that does not encode the declared transfer."""
    if plan_start == expected_start:
        return
    if not increment_source or not increment_destination:
        _fail('non-incrementing-transfer-not-encoded-by-start-word',
              'start_word=0x%08x' % plan_start)
    _fail('start-word-mismatch',
          'start_word=0x%08x expected=0x%08x' % (plan_start, expected_start))


def _master_byte_enable(device: Mapping, *,
                        size_bytes: int, declared_mask: object) -> dict:
    """The master lane mask: full word, an explicit mask, or ZipDMA size lanes."""
    sel_signal = device['master_sel_signal']
    sel_available = sel_signal is not None
    if declared_mask is not None:
        if not _is_int(declared_mask) or not 1 <= declared_mask <= 15:
            _fail('master-byte-enable-invalid', 'mask')
        if size_bytes != 4:
            _fail('master-byte-enable-conflict', 'mask-and-size')
        if not sel_available and declared_mask != 15:
            _fail('partial-byte-enable-on-no-select-device',
                  '%s:declared-mask' % device['family'])
        bits = bin(declared_mask).count('1')
        return {'kind': 'full_word' if declared_mask == 15 else 'declared_mask',
                'mask': declared_mask, 'lanes': None,
                'lane_pattern': [declared_mask], 'beats_per_word': 1,
                'lanes_per_beat': bits, 'size_bytes': WORD_BYTES,
                'size_code': device['size_codes'].get(WORD_BYTES),
                'sel_signal': sel_signal, 'sel_available': sel_available,
                'alignment_bytes': WORD_BYTES,
                'partial': declared_mask != 15}
    if device['family'] not in ('zipdma', 'wbdmac'):
        _fail('dma-device-unsupported', device['family'])
    if size_bytes not in (1, 2, 4):
        _fail('master-byte-enable-unsupported', 'size-bytes:' + str(size_bytes))
    if size_bytes == 4:
        if not sel_available and device.get('master_fixed_byte_enable') not in (None, 15):
            _fail('partial-byte-enable-on-no-select-device', 'fixed-enable')
        return {'kind': 'full_word', 'mask': 15, 'lanes': [0, 1, 2, 3],
                'lane_pattern': [15], 'beats_per_word': 1, 'lanes_per_beat': 4,
                'size_bytes': WORD_BYTES,
                'size_code': device['size_codes'].get(WORD_BYTES),
                'sel_signal': sel_signal, 'sel_available': sel_available,
                'alignment_bytes': WORD_BYTES, 'partial': False}
    if not sel_available:
        _fail('partial-byte-enable-on-no-select-device',
              '%s:size-%d' % (device['family'], size_bytes))
    code = device['size_codes'].get(size_bytes)
    if code is None:
        _fail('master-byte-enable-unsupported', 'size-bytes:' + str(size_bytes))
    if size_bytes == 2:
        pattern = [0b0011, 0b1100]
        lanes_per_beat = 2
    else:
        pattern = [0b0001, 0b0010, 0b0100, 0b1000]
        lanes_per_beat = 1
    return {'kind': 'size_derived_lanes', 'mask': None, 'lanes': None,
            'lane_pattern': pattern, 'beats_per_word': WORD_BYTES // size_bytes,
            'lanes_per_beat': lanes_per_beat, 'size_bytes': size_bytes,
            'size_code': code, 'sel_signal': sel_signal,
            'sel_available': True, 'alignment_bytes': size_bytes,
            'partial': True}


def _increment_flag(config: Mapping, key: str) -> bool:
    value = config.get(key, True)
    if not _is_bool(value):
        _fail('increment-flags-invalid', key)
    return value


# ---------------------------------------------------------------------------
# route declaration
# ---------------------------------------------------------------------------
def _route_declaration(config: Mapping, base_dir: object) -> dict | None:
    """Normalize ``dma_route`` and cross-check its target profile, if declared."""
    raw = config.get('dma_route')
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        _fail('dma-route-invalid', 'not-a-mapping')
    for key in raw:
        if key not in ROUTE_KEYS:
            _fail('dma-route-field', str(key))
    kind = raw.get('kind', 'target_window')
    if kind not in ROUTE_KINDS:
        _fail('dma-route-kind-unsupported', str(kind))
    direction = raw.get('direction', 'write')
    if direction not in ROUTE_DIRECTIONS:
        _fail('dma-route-direction-unsupported', str(direction))
    target_name = raw.get('target_name')
    if target_name is not None and (not isinstance(target_name, str) or not target_name):
        _fail('dma-route-invalid', 'target_name')
    target_index = raw.get('target_index')
    if target_index is not None and (not _is_int(target_index) or target_index < 0):
        _fail('dma-route-invalid', 'target_index')
    target_window = raw.get('target_window')
    if target_window is not None:
        if not isinstance(target_window, Mapping):
            _fail('dma-route-invalid', 'target_window')
        base, size = target_window.get('base'), target_window.get('size')
        if (not _is_int(base) or not _is_int(size) or base < 0 or size < WORD_BYTES
                or base % WORD_BYTES or base + size > 1 << 32):
            _fail('dma-route-window-invalid')
        target_window = {'base': base, 'size': size}
    register = raw.get('register')
    if register is not None and not isinstance(register, (str, Mapping)):
        _fail('dma-route-invalid', 'register')
    offset = raw.get('offset')
    if offset is not None and (not _is_int(offset) or offset < 0):
        _fail('dma-route-invalid', 'offset')
    mode = raw.get('address_mode',
                   'fixed' if kind == 'fifo' else 'aperture')
    if mode not in ROUTE_ADDRESS_MODES:
        _fail('dma-route-address-mode-unsupported', str(mode))
    evidence = raw.get('evidence')
    if evidence is not None:
        if not isinstance(evidence, Mapping):
            _fail('dma-route-invalid', 'evidence')
        for key in evidence:
            if key not in EVIDENCE_KEYS:
                _fail('dma-route-evidence-field', str(key))
        ekind = evidence.get('kind')
        if ekind not in ROUTE_EVIDENCE_KINDS:
            _fail('dma-route-evidence-unsupported', str(ekind))
        if evidence.get('register') is not None and not isinstance(
                evidence.get('register'), str):
            _fail('dma-route-evidence-invalid', 'register')
        if evidence.get('offset') is not None and (
                not _is_int(evidence.get('offset')) or evidence['offset'] < 0):
            _fail('dma-route-evidence-invalid', 'offset')
        if evidence.get('field') is not None and not isinstance(
                evidence.get('field'), str):
            _fail('dma-route-evidence-invalid', 'field')
        bits = evidence.get('bits')
        if bits is not None:
            if (not isinstance(bits, list) or len(bits) != 2
                    or not _is_int(bits[0]) or not _is_int(bits[1])
                    or not 0 <= bits[0] <= 31 or not 0 <= bits[1] <= 31):
                _fail('dma-route-evidence-invalid', 'bits')
        depth = evidence.get('depth')
        if depth is not None and (not _is_int(depth) or depth < 1):
            _fail('dma-route-evidence-invalid', 'depth')
        words = evidence.get('words')
        if words is not None and (not _is_int(words) or words < 1):
            _fail('dma-route-evidence-invalid', 'words')
        expected_word = evidence.get('expected_word')
        if expected_word is not None:
            if not _word(expected_word):
                _fail('dma-route-evidence-invalid', 'expected_word')
            # A popped word is a FIFO datum: an expectation on a plain register
            # readback would be a second, weaker copy of the captured-word check.
            if ekind != 'fifo_level':
                _fail('dma-route-evidence-invalid', 'expected-word-without-fifo')
        sampling = evidence.get('sampling')
        if sampling is not None and not isinstance(sampling, str):
            _fail('dma-route-evidence-invalid', 'sampling')
        source = evidence.get('source')
        if source is not None and not isinstance(source, str):
            _fail('dma-route-evidence-invalid', 'source')
        evidence = dict(evidence)
    notes = raw.get('notes')
    if notes is not None and (not isinstance(notes, list)
                              or any(not isinstance(note, str) for note in notes)):
        _fail('dma-route-invalid', 'notes')
    target_profile = raw.get('target_profile')
    profile_facts = None
    if target_profile is not None:
        profile_facts = _target_profile_facts(
            target_profile, base_dir, target_window=target_window,
            direction=direction, register=register, offset=offset,
            evidence=evidence)
    resolved_register = (profile_facts['register'] if profile_facts
                         else _register_declaration(register, offset))
    if offset is None and resolved_register is not None:
        offset = resolved_register.get('offset')
    route = {'kind': kind, 'is_fifo': kind == 'fifo', 'direction': direction,
             'target_name': target_name, 'target_index': target_index,
             'target_window': target_window, 'target_profile': target_profile,
             'register': resolved_register,
             'offset': offset, 'address_mode': mode, 'evidence': evidence,
             'notes': notes,
             'target_profile_facts': profile_facts,
             'declared_by': 'scenario'}
    return route


def _register_declaration(register: object, offset: object) -> dict | None:
    """The declared target register, from a name or a small mapping."""
    if register is None and offset is None:
        return None
    row = {'name': None, 'offset': None, 'access': None, 'width': None}
    if isinstance(register, Mapping):
        for key in register:
            if key not in ('name', 'offset', 'access', 'width'):
                _fail('dma-route-field', 'register.' + str(key))
        row.update({key: register[key] for key in
                    ('name', 'offset', 'access', 'width') if key in register})
        if row['name'] is not None and not isinstance(row['name'], str):
            _fail('dma-route-invalid', 'register.name')
        if row['offset'] is not None and (not _is_int(row['offset'])
                                          or row['offset'] < 0):
            _fail('dma-route-invalid', 'register.offset')
        if row['access'] is not None and row['access'] not in ('rw', 'ro', 'wo'):
            _fail('dma-route-invalid', 'register.access')
        if row['width'] is not None and (not _is_int(row['width'])
                                         or row['width'] < 1):
            _fail('dma-route-invalid', 'register.width')
        if offset is not None and row['offset'] is not None and offset != row['offset']:
            _fail('dma-route-register-mismatch', 'offset')
    elif isinstance(register, str):
        row['name'] = register
    elif register is not None:
        _fail('dma-route-invalid', 'register')
    if offset is not None:
        row['offset'] = offset
    return row


def _profile_protocol(document: Mapping) -> str | None:
    """The target's own MMIO protocol, from the profile's ``mmio_slave`` endpoint.

    A route's protocol is a fact about the target, not about the scenario: the
    endpoint that declares the register window is the one the host would drive,
    so its protocol word (normalized) is what the route reports.  A profile that
    declares no ``mmio_slave`` endpoint states no protocol here, and the entry
    resolves it against the artifact it actually built rather than guessing.
    """
    endpoints = document.get('endpoints')
    if not isinstance(endpoints, (list, tuple)):
        return None
    for endpoint in endpoints:
        if not isinstance(endpoint, Mapping):
            continue
        if endpoint.get('function') != 'mmio_slave':
            continue
        declared = endpoint.get('protocol')
        if isinstance(declared, (list, tuple)):
            declared = declared[0] if declared else None
        if not isinstance(declared, str):
            continue
        normalized = PROFILE_PROTOCOL_NAMES.get(declared.lower())
        if normalized is not None:
            return normalized
    return None


def _target_profile_facts(path: object, base_dir: object, *, target_window: object,
                          direction: str, register: object, offset: object,
                          evidence: object) -> dict:
    """Cross-check the route against the target's own address declaration."""
    document = _read_declared_json(path, base_dir, reason='dma-target-profile')
    protocol = _profile_protocol(document)
    if protocol is not None and protocol not in ROUTE_PROTOCOLS:
        # The target's own endpoint protocol is the fact: a wire this host has no
        # beat adapter and no passive trace for cannot carry a routed beat, so the
        # declaration is refused here rather than being mapped onto another
        # protocol's completion criterion.
        _fail('dma-route-target-protocol-unsupported', protocol)
    address = document.get('address')
    if not isinstance(address, Mapping):
        _fail('dma-target-profile-mismatch', 'address')
    window_size, alignment = address.get('window_size'), address.get('alignment')
    if (not _is_int(window_size) or window_size < WORD_BYTES
            or not _is_int(alignment) or alignment < WORD_BYTES):
        _fail('dma-target-profile-mismatch', 'window')
    if target_window is not None:
        if target_window['size'] != window_size:
            _fail('dma-target-profile-mismatch', 'window-size')
        if target_window['base'] % alignment:
            _fail('dma-target-profile-mismatch', 'window-alignment')
    rows = {}
    for row in address.get('registers', ()) or ():
        if not isinstance(row, Mapping):
            _fail('dma-target-profile-mismatch', 'register-row')
        rows[row.get('name')] = row
        if row.get('offset') is not None:
            rows[('offset', row['offset'])] = row
    declared = _register_declaration(register, offset)
    if declared is None or (declared['name'] is None and declared['offset'] is None):
        _fail('dma-route-register-not-declared')
    row = None
    if declared['name'] is not None:
        row = rows.get(declared['name'])
        if row is None:
            _fail('dma-target-profile-mismatch', 'register:' + declared['name'])
    if declared['offset'] is not None:
        by_offset = rows.get(('offset', declared['offset']))
        if by_offset is None:
            _fail('dma-target-profile-mismatch',
                  'offset:0x%x' % declared['offset'])
        if row is not None and row is not by_offset:
            _fail('dma-target-profile-mismatch', 'register-offset')
        row = by_offset
    resolved = {'name': row.get('name'),
                'offset': row.get('offset'),
                'access': row.get('access'),
                'width': row.get('width'),
                # The RTL side effect the profile declares for this register.  It
                # is what makes a port a FIFO port: only a port whose declared
                # side effect is a pop on read is admitted as a FIFO read route.
                'side_effect': row.get('side_effect')}
    if (not isinstance(resolved['offset'], int) or resolved['offset'] % WORD_BYTES
            or not isinstance(resolved['width'], int) or resolved['width'] != 32
            or resolved['access'] not in ('rw', 'ro', 'wo')):
        _fail('dma-target-profile-mismatch', 'register-shape')
    if resolved['side_effect'] is not None and not isinstance(
            resolved['side_effect'], str):
        _fail('dma-target-profile-mismatch', 'register-side-effect')
    if direction == 'write' and resolved['access'] not in ('rw', 'wo'):
        _fail('dma-route-direction-unsupported', 'write-to-read-only')
    if direction == 'read' and resolved['access'] not in ('rw', 'ro'):
        _fail('dma-route-direction-unsupported', 'read-from-write-only')
    evidence_facts = None
    if evidence is not None:
        evidence_facts = _evidence_facts(evidence, rows, window_size)
    return {'window_size': window_size, 'alignment': alignment,
            # The target's own wire protocol: the route reports it so the host,
            # the case line and this module's host_support block all name the
            # adapter that carries the beat instead of assuming APB3.
            'protocol': protocol,
            'register': resolved, 'evidence': evidence_facts}


def _evidence_facts(evidence: Mapping, rows: Mapping, window_size: int) -> dict:
    """Cross-check the declared observation against the target register map."""
    name = evidence.get('register')
    offset = evidence.get('offset')
    row = None
    if isinstance(name, str):
        row = rows.get(name)
        if row is None:
            _fail('dma-target-profile-mismatch', 'evidence-register:' + name)
    if offset is not None:
        by_offset = rows.get(('offset', offset))
        if by_offset is None:
            _fail('dma-target-profile-mismatch', 'evidence-offset:0x%x' % offset)
        if row is not None and row is not by_offset:
            _fail('dma-target-profile-mismatch', 'evidence-register-offset')
        row = by_offset
    if row is None:
        _fail('dma-route-evidence-absent', 'register')
    if row.get('access') not in ('rw', 'ro'):
        _fail('dma-route-evidence-absent', 'not-readable')
    if row.get('offset', 0) + WORD_BYTES > window_size:
        _fail('dma-target-profile-mismatch', 'evidence-window')
    bits = evidence.get('bits')
    if bits is not None:
        # A declared hardware bit span may be written MSB-first ([28, 24]) or
        # LSB-first ([24, 28]); both name the same register field.
        high = max(bits)
        if (row.get('width') or 32) <= high:
            _fail('dma-route-evidence-invalid', 'bits')
    # An aperture readback covers ``words`` consecutive target words starting at
    # the declared first register.  Every one of them has to be a readable
    # 32-bit register of the target's own map, so an aperture is never widened
    # over an offset the device does not decode as a readable register.
    words = evidence.get('words')
    aperture = []
    if words is not None:
        first = row.get('offset')
        for index in range(words):
            target_offset = first + WORD_BYTES * index
            if target_offset + WORD_BYTES > window_size:
                _fail('dma-target-profile-mismatch', 'aperture-window')
            aperture_row = rows.get(('offset', target_offset))
            if aperture_row is None:
                _fail('dma-target-profile-mismatch',
                      'aperture-offset:0x%x' % target_offset)
            if (aperture_row.get('width') != 32
                    or aperture_row.get('access') not in ('rw', 'ro')):
                _fail('dma-route-evidence-absent',
                      'aperture-not-readable:0x%x' % target_offset)
            aperture.append({'name': aperture_row.get('name'),
                             'offset': target_offset,
                             'access': aperture_row.get('access'),
                             'width': aperture_row.get('width')})
    return {'name': row.get('name'), 'offset': row.get('offset'),
            'access': row.get('access'), 'width': row.get('width'),
            'words': words, 'aperture': aperture or None}


# ---------------------------------------------------------------------------
# declaration
# ---------------------------------------------------------------------------
def dma_transfer_declaration(config: Mapping, profile: object,
                             artifact: object, *, base_dir: object = None) -> dict:
    """Normalize one scenario's DMA declaration into a transfer plan.

    ``config`` is the scenario document, ``profile`` the selected DMA component
    profile (typed or JSON mapping) and ``artifact`` the generated edge
    artifact, a bare edge contract, or an ``ip_test_capability.v2`` declaration.
    ``base_dir`` resolves the repo-relative ``dma_behavior``/
    ``dma_route.target_profile`` paths; it is required only when one is named.

    The returned plan is a declaration.  It states what the device encodes and
    what the scenario asks for; it does not state that anything ran.
    """
    if not isinstance(config, Mapping):
        _fail('dma-config-invalid')
    # The scenario's own inline keys are checked first, so an invalid inline
    # value is refused under the key the operator wrote, not as a behavior-file
    # error (the existing executor makes the same distinction).
    inline_block = config.get('dma_block_words')
    if inline_block is not None and (not _is_int(inline_block) or inline_block < 1):
        _fail('block-words-invalid', 'dma_block_words')
    inline_pulse = config.get('dma_irq_pulse_ticks')
    if inline_pulse is not None and (not _is_int(inline_pulse)
                                     or not 1 <= inline_pulse <= MAX_IRQ_PULSE_TICKS):
        _fail('irq-pulse-ticks-invalid', 'dma_irq_pulse_ticks')
    device = _device_declaration(profile)
    artifact_facts = _artifact_declaration(artifact, device)

    behavior = _behavior_declaration(config, base_dir,
                                     max_block_words=device['max_block_words'],
                                     family=device['family'],
                                     device_capabilities=device['device_capabilities'])
    facts = behavior['facts']
    block_words = facts.get('block_words')
    if block_words is None:
        _fail('block-words-not-declared')
    if not _is_int(block_words) or block_words < 1:
        _fail('block-words-invalid')
    if block_words > device['max_block_words']:
        _fail('block-beyond-declared-bound',
              '%s:%d>%d' % (device['family'], block_words,
                            device['max_block_words']))
    block_from_file = behavior['fact_sources'].get('block_words') == 'file'
    if block_from_file:
        block_source = 'behavior:' + str(behavior['path'])
        if inline_block is not None:
            block_source += '+scenario:dma_block_words'
    else:
        block_source = 'scenario:dma_block_words'

    increment_source = _increment_flag(config, 'dma_increment_source')
    increment_destination = _increment_flag(config, 'dma_increment_destination')

    size_declared = config.get('dma_transfer_size_bytes', device['default_size_bytes'])
    if not _is_int(size_declared) or size_declared < 1:
        _fail('master-byte-enable-invalid', 'dma_transfer_size_bytes')
    if size_declared != WORD_BYTES and device['family'] != 'zipdma':
        _fail('master-byte-enable-unsupported',
              device['family'] + ':size-bytes:' + str(size_declared))
    if size_declared not in (1, 2, 4):
        _fail('master-byte-enable-unsupported', 'size-bytes:' + str(size_declared))
    declared_mask = config.get('dma_master_byte_enable')
    byte_enable = _master_byte_enable(device, size_bytes=size_declared,
                                      declared_mask=declared_mask)
    size_bytes = byte_enable['size_bytes']

    length_value = (block_words * WORD_BYTES if device['length_unit'] == 'bytes'
                    else block_words)
    if length_value > (1 << device['length_register_bits']) - 1:
        _fail('length-not-encodable',
              '%d>%d' % (length_value, (1 << device['length_register_bits']) - 1))
    length_register = device['registers']['length']

    expected_start = _derive_start_word(device, block_words=block_words,
                                        increment_source=increment_source,
                                        increment_destination=increment_destination,
                                        size_bytes=size_bytes)
    declared_start = config.get('dma_start_word')
    if declared_start is not None:
        if not _word(declared_start):
            _fail('start-word-invalid')
        _check_start_word(declared_start, expected_start,
                          increment_source=increment_source,
                          increment_destination=increment_destination)
        start_word, start_source = declared_start, 'declared'
    else:
        start_word, start_source = expected_start, 'derived'

    irq_trigger = device['irq_trigger']
    pulse_ticks = facts.get('irq_pulse_ticks')
    pulse_source = None
    if pulse_ticks is not None:
        pulse_source = ('behavior'
                        if behavior['fact_sources'].get('irq_pulse_ticks') == 'file'
                        else 'scenario')
    if pulse_ticks is not None and (not _is_int(pulse_ticks)
                                    or not 1 <= pulse_ticks <= MAX_IRQ_PULSE_TICKS):
        _fail('irq-pulse-ticks-invalid')
    if irq_trigger == 'pulse' and pulse_ticks is None:
        pulse_ticks, pulse_source = 16, 'host_default'

    status_default = device['status_default']
    if 'busy_bit' in facts:
        status = {'kind': facts.get('status_kind', status_default['kind']),
                  'busy_bit': facts['busy_bit'], 'err_bit': facts['err_bit'],
                  'declared_by': 'file',
                  'source': behavior['path'],
                  'evidence': 'declared by ' + str(behavior['path'])}
    else:
        status = {'kind': status_default['kind'],
                  'busy_bit': status_default['busy_bit'],
                  'err_bit': status_default['err_bit'],
                  'declared_by': 'device_default',
                  'source': status_default['busy_bit_source'],
                  'evidence': status_default['evidence']}

    delay_ticks = config.get('dma_response_delay', 0)
    if not _is_int(delay_ticks) or not 0 <= delay_ticks <= MAX_RESPONSE_DELAY_TICKS:
        _fail('response-delay-not-declarable')
    backpressure = config.get('dma_backpressure')
    if backpressure is not None:
        if not isinstance(backpressure, Mapping):
            _fail('response-delay-not-declarable', 'dma_backpressure')
        pattern = backpressure.get('pattern', 'per_response_stall')
        if pattern not in ('per_response_stall', 'periodic_stall', 'none'):
            _fail('response-delay-not-declarable', 'backpressure.pattern')
        applies = backpressure.get('applies_to', ['read', 'write'])
        if (not isinstance(applies, list)
                or any(item not in ('read', 'write') for item in applies)):
            _fail('response-delay-not-declarable', 'backpressure.applies_to')
        hold = backpressure.get('max_consecutive_ticks')
        if hold is not None and (not _is_int(hold) or not 0 <= hold <=
                                 MAX_RESPONSE_DELAY_TICKS):
            _fail('response-delay-not-declarable', 'backpressure.hold')
        backpressure = _copy(backpressure)
    observation = config.get('dma_observation_expectations')
    if observation is not None:
        if not isinstance(observation, Mapping):
            _fail('dma-observation-invalid')
        minimum = observation.get('stall_ticks_min')
        maximum = observation.get('stall_ticks_max')
        for value in (minimum, maximum):
            if value is not None and (not _is_int(value) or value < 0):
                _fail('dma-observation-invalid', 'stall_ticks')
        if (minimum is not None and maximum is not None and minimum > maximum):
            _fail('dma-observation-invalid', 'stall_ticks_order')
        observation = _copy(observation)
    response_delay = {
        'ticks': delay_ticks,
        'mode': ('host_stall_before_response' if delay_ticks
                 else 'zero_wait'),
        'source': ('scenario:dma_response_delay' if 'dma_response_delay' in config
                   else 'device_default'),
        'backpressure': backpressure,
        'observation': observation,
    }

    declared_outstanding = config.get('dma_max_outstanding', 1)
    if not _is_int(declared_outstanding) or declared_outstanding < 1:
        _fail('outstanding-invalid', 'dma_max_outstanding')
    if declared_outstanding > MAX_OUTSTANDING:
        # Above this host's own declarable depth: named with the bound it broke,
        # so a reader sees whether the executor or the device is the limit.
        _fail('outstanding-beyond-one', 'host:%d>%d'
              % (declared_outstanding, MAX_OUTSTANDING))
    if declared_outstanding > device['max_outstanding']:
        # Above the pinned device's real depth: a device fact, named with the
        # device and the numbers.
        _fail('outstanding-beyond-one', '%s:%d>%d'
              % (device['family'], declared_outstanding, device['max_outstanding']))

    error_raw = config.get('dma_error_injection')
    error_beat = None
    error_direction = None
    if error_raw in (None, False, 'none'):
        error_requested = False
    elif error_raw in (True, 'host_drive', 'required'):
        # The historical spelling: one injected master error response, on the
        # first routed beat.
        error_requested = True
        error_beat = 0
    elif isinstance(error_raw, Mapping):
        for key in error_raw:
            if key not in ERROR_INJECTION_KEYS:
                _fail('error-injection-invalid', str(key))
        index = error_raw.get('beat_index')
        if not _is_int(index) or index < 0:
            _fail('error-injection-invalid', 'beat_index')
        mode = error_raw.get('mode', 'master_response')
        if mode not in ERROR_INJECTION_MODES:
            _fail('error-injection-invalid', 'mode')
        direction = error_raw.get('direction')
        if direction is not None and direction not in ROUTE_DIRECTIONS:
            _fail('error-injection-invalid', 'direction')
        error_requested = True
        error_beat = index
        error_direction = direction
    else:
        _fail('error-injection-invalid', str(error_raw))
    availability = 'undeclared'
    if artifact_facts['edge_present']:
        if artifact_facts['error_port'] is True:
            availability = 'declared'
        elif artifact_facts['error_port'] is False:
            availability = 'absent'
    error_injection = {
        'requested': error_requested,
        'mode': 'host_drive_response_error' if error_requested else 'none',
        # What is injected, where, and which device bit is the readback.  The
        # injection is a host action on the device's own error input: the case
        # line states it, and the ERR status bit the CPU reads back is the
        # device's own sticky latch (zipdma_ctrl.v:287-290,301-321), never a
        # value the host wrote into the status word.
        'kind': 'host_injected_master_response' if error_requested else 'none',
        'beat_index': error_beat,
        'direction': error_direction,
        'signal': 'mwb_err' if device['master_has_error'] else None,
        'device_error_port': bool(device['master_has_error']),
        'device_err_status_bit': device['status_default']['err_bit'],
        'device_err_status_source': device['status_default']['err_bit_source'],
        'aborts_transfer': True,
        'available': availability,
        'declared_by': 'scenario' if error_requested else 'default',
    }

    route = _route_declaration(config, base_dir)

    plan = {
        'schema_version': DMA_PLAN_SCHEMA,
        'component_id': _attr(profile, 'component_id'),
        'device': device,
        'block_words': block_words,
        'block_words_declared_by': ('behavior'
                                    if block_from_file else 'scenario'),
        'block_words_declaration': block_source,
        'block_bytes': block_words * WORD_BYTES,
        'word_bytes': WORD_BYTES,
        'length_unit': device['length_unit'],
        'length_value': length_value,
        'length_register': {'name': length_register['name'],
                            'offset': length_register['offset'],
                            'bits': device['length_register_bits'],
                            'unit': device['length_unit']},
        'increment_source': increment_source,
        'increment_destination': increment_destination,
        'master_byte_enable': byte_enable,
        'byte_address_units': {
            'source_destination': 'byte_address',
            'source_destination_bits': device['source_destination_byte_address_bits'],
            'master': device['master_address_units'],
            'master_shift': device['master_address_shift'],
            'master_width': device['master_address_width'],
            'alignment_bytes': WORD_BYTES,
        },
        'start': {
            'word': start_word,
            'word_hex': '0x%08x' % start_word,
            'source': start_source,
            'encoding': device['start']['encoding'],
            'key': device['start']['key'],
            'key_bits': list(device['start']['key_bits'])
            if device['start']['key_bits'] else None,
            'block_words_bits': list(device['start']['block_words_bits'])
            if device['start']['block_words_bits'] else None,
            'increment_source_bit': device['start']['increment_source_bit'],
            'increment_destination_bit': device['start']['increment_destination_bit'],
            'size_bits': _copy(device['start']['size_bits']),
            'condition': device['start']['condition'],
        },
        'max_outstanding': declared_outstanding,
        'response_delay': response_delay,
        'irq_trigger': irq_trigger,
        'irq_clear': _copy(device['irq_clear']),
        'irq_pulse_ticks': pulse_ticks,
        'irq_pulse_ticks_source': pulse_source,
        'status': status,
        'error_injection': error_injection,
        'route': route,
        'artifact': artifact_facts,
        'declaration': {'behavior_path': behavior['path'],
                        'behavior_declared_by': behavior['declared_by'],
                        'device_facts_source': device['facts_source'],
                        # The declarable capability facts, kept apart from the
                        # transfer geometry: they state what the device and the
                        # declaration allow, not what this run executes.
                        'device_capabilities': _copy(device['device_capabilities']),
                        'declared_capabilities': _copy(behavior['capabilities']),
                        'declared_profile_capabilities':
                            _copy(device['declared_profile_capabilities'])},
    }
    return plan


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------
def _recheck_plan_device(plan: Mapping, device: Mapping) -> None:
    declared = plan.get('device')
    if not isinstance(declared, Mapping):
        _fail('dma-plan-invalid', 'device')
    for key in ('family', 'top_module', 'source_revision'):
        if declared.get(key) != device.get(key):
            _fail('dma-plan-device-mismatch', key)


def _geometry(plan: Mapping) -> dict:
    """Route geometry: beat count, byte offsets and fixed/aperture shape."""
    byte_enable = plan.get('master_byte_enable')
    if not isinstance(byte_enable, Mapping):
        _fail('dma-plan-invalid', 'master_byte_enable')
    beats_per_word = byte_enable.get('beats_per_word')
    if not _is_int(beats_per_word) or beats_per_word < 1:
        _fail('dma-plan-invalid', 'beats_per_word')
    block_words = plan.get('block_words')
    if not _is_int(block_words) or block_words < 1:
        _fail('dma-plan-invalid', 'block_words')
    return {'beats': block_words * beats_per_word,
            'beats_per_word': beats_per_word,
            'block_words': block_words}


def _route_geometry(plan: Mapping, route: Mapping) -> dict:
    direction = route.get('direction')
    if direction not in ROUTE_DIRECTIONS:
        _fail('dma-route-direction-unsupported', str(direction))
    increment = (plan.get('increment_destination') if direction == 'write'
                 else plan.get('increment_source'))
    if not _is_bool(increment):
        _fail('dma-plan-invalid', 'increment')
    mode = route.get('address_mode')
    if mode not in ROUTE_ADDRESS_MODES:
        _fail('dma-route-address-mode-unsupported', str(mode))
    offset = route.get('offset')
    if not _is_int(offset) or offset < 0:
        _fail('dma-route-offset-not-declared')
    if offset % WORD_BYTES:
        _fail('dma-route-offset-unaligned')
    geometry = _geometry(plan)
    beats = geometry['beats']
    if mode == 'fixed':
        first = last = offset
        repeat = beats
    else:
        first = offset
        last = offset + WORD_BYTES * (beats - 1)
        repeat = 1
    return {'direction': direction, 'increment': increment, 'mode': mode,
            'beats': beats, 'first_offset': first, 'last_offset': last,
            'repeat': repeat}


def _route_reachability(plan: Mapping, route: Mapping,
                        geometry: Mapping) -> None:
    device = plan.get('device')
    if not isinstance(device, Mapping):
        _fail('dma-plan-invalid', 'device')
    window = route.get('target_window')
    if not isinstance(window, Mapping):
        return
    bits = device.get('source_destination_byte_address_bits')
    if not _is_int(bits):
        _fail('dma-plan-invalid', 'source_destination_byte_address_bits')
    maximum = (1 << bits) - 1
    last = window['base'] + geometry['last_offset']
    if last > maximum:
        _fail('dma-route-target-unreachable',
              '%s:0x%08x>0x%08x' % (device.get('family'), last, maximum))
    master_bits = device.get('master_address_width')
    if _is_int(master_bits) and (window['base'] + geometry['last_offset']) >> 2 \
            >= (1 << master_bits):
        _fail('dma-route-target-unreachable', 'master-word-address')


_HOST_LIMITS = {
    'max_outstanding': {
        'code': 'host-outstanding-cap',
        'host_limit': MAX_OUTSTANDING,
        'host': HOST_SOURCE,
        'where': [
            'scripts/inprocess_obi_apb_f1f4_spike.cpp (DMA_MASTER_OUTSTANDING: the '
            'host serves the declared depth from a ring of pending responses, '
            'holds mwb_stall only while the ring is full, and reports the '
            'measured peak as dma_outstanding_peak)',
            'scripts/run_inprocess_f1f6.py (the F6 case line states the device, '
            'the channel, the beat count and the declared/measured outstanding)',
        ],
        'means': 'the plan declares a pipelined master; the executor has to serve '
                 'that many responses at once, and the case line has to report the '
                 'depth it really reached.  The historical generated edge '
                 'environment (environment_max_outstanding=1) is the one executor '
                 'that still cannot, so the limit is reported instead of being a '
                 'device refusal',
    },
    'block_words': {
        'code': 'host-block-words-cap',
        'host_limit': HOST_BLOCK_WORDS,
        'host': HOST_SOURCE,
        'where': [
            'src/myfuzz/composition/inprocess_behavior.py:396 (block_words 1..4)',
            'scripts/run_inprocess_f1f6.py:759-773 (dma_block_words 1..4)',
            'src/myfuzz/integration/f6_dma_behavior.py:56-59 '
            '(fixed block_words=length_words=4)',
            'scripts/inprocess_obi_apb_f1f4_spike.cpp:695-702,464-471 '
            '(DMA_BLOCK_WORDS is honoured at run time; records carry up to 16 words)',
            'scripts/run_inprocess_f1f6.py:95-96,452 (INPUT_BLOCK/MAILBOX_BYTES and '
            'the reported mailbox span reserve four input words)',
            'scripts/run_inprocess_f1f6.py:416 (declared_windows requires four DMA '
            'destination words of RAM headroom)',
        ],
        'means': 'the declaration is valid; the three Python declaration bounds '
                 'still refuse more than four words, while the C++ host already '
                 'carries DMA_BLOCK_WORDS and a 1..16-word record.  The entry also '
                 'needs MAILBOX_BYTES/the reported mailbox span and declared_windows '
                 'raised to the declared block length.',
    },
    'start_word': {
        'code': 'host-fixed-start-word',
        'host_limit': HOST_START_WORDS,
        'host': HOST_SOURCE,
        'where': [
            'scripts/run_inprocess_f1f6.py:824-831 (start_word comes from the '
            'provider csr, not from the plan)',
            'scripts/run_inprocess_f1f6.py:1225-1226 (the firmware writes that one '
            'fixed word)',
            'src/myfuzz/local_harness/wbdmac_source_contract.py:16-22 '
            '(start_word=0x0fed0004)',
            'src/myfuzz/integration/f6_dma_behavior.py:56-59 '
            '(ZipDMA start_word=0, increment_source/destination=True)',
            'scripts/inprocess_obi_apb_f1f4_spike.cpp:2450-2463 '
            '(the host compares the written control word with DMA_START_WORD)',
        ],
        'means': 'a non-zero ZipDMA control word or a wbdmac increment-disable bit '
                 'would need the provider, the generated firmware header and the '
                 'host start write to carry the plan start word',
    },
    'master_byte_enable': {
        'code': 'host-full-word-master-sel',
        'host_limit': 15,
        'host': HOST_SOURCE,
        'where': [
            'scripts/inprocess_obi_apb_f1f4_spike.cpp:2484-2491 '
            '(master_select must be 0xf; the master access must be in RAM)',
            'scripts/inprocess_obi_apb_f1f4_spike.cpp:1772-1777 '
            '(DMA_MASTER_SEL selects whether mwb_sel is sampled at all)',
            'scripts/run_inprocess_f1f6.py:1207-1216 (the firmware copies full RAM '
            'words)',
        ],
        'means': 'the device has a master SEL and can present size-derived lanes, '
                 'but the current host only serves a full-word master beat',
    },
    'response_delay': {
        'code': 'host-response-delay-absent',
        'host_limit': 0,
        'host': HOST_SOURCE,
        'where': [
            'scripts/inprocess_obi_apb_f1f4_spike.cpp:1647-1648,2484-2505 '
            '(master.delay is the one-cycle write-data-late stall, not a declared '
            'delay; no backpressure knob)',
        ],
        'means': 'the declared stall is not applied by the current host, so no run '
                 'can evidence it yet',
    },
    'error_injection': {
        'code': 'host-error-injection-absent',
        'host_limit': 0,
        'host': HOST_SOURCE,
        'where': [
            'scripts/inprocess_obi_apb_f1f4_spike.cpp:1649 (dma.mwb_err is tied low)',
        ],
        'means': 'the device has a native error input but the current host cannot '
                 'drive it',
    },
    'route': {
        'code': 'host-dma-target-route-absent',
        'host_limit': False,
        'host': HOST_SOURCE,
        'where': [
            'scripts/inprocess_obi_apb_f1f4_spike.cpp:2484-2505 (every DMA master '
            'beat is answered from the RAM Memory; no target-window route exists)',
            'scripts/run_inprocess_f1f6.py:400-444 (declared_windows routes CPU '
            'MMIO and DMA control, not the DMA master)',
        ],
        'means': 'the route is declared; the host cannot implement it yet and this '
                 'plan claims no transfer, no completion and no FIFO evidence',
    },
}


def _host_limits(plan: Mapping) -> list[dict]:
    limits = []
    block = plan.get('block_words')
    if block != HOST_BLOCK_WORDS:
        limit = _copy(_HOST_LIMITS['block_words'])
        limit.update(kind='host_only', plan_value=block,
                     relationship='above' if block > HOST_BLOCK_WORDS else 'below')
        limits.append(limit)
    family = plan['device']['family']
    start = plan.get('start') or {}
    expected_host_word = HOST_START_WORDS.get(family)
    if start.get('word') != expected_host_word:
        limit = _copy(_HOST_LIMITS['start_word'])
        limit.update(kind='host_only', plan_value=start.get('word'),
                     host_limit=expected_host_word)
        limits.append(limit)
    byte_enable = plan.get('master_byte_enable') or {}
    if byte_enable.get('kind') != 'full_word' or byte_enable.get('mask') != 15:
        limit = _copy(_HOST_LIMITS['master_byte_enable'])
        limit.update(kind='host_only', plan_value=byte_enable.get('mask'),
                     host_limit=15)
        limits.append(limit)
    delay = plan.get('response_delay') or {}
    if delay.get('ticks'):
        limit = _copy(_HOST_LIMITS['response_delay'])
        limit.update(kind='host_only', plan_value=delay.get('ticks'), host_limit=0)
        limits.append(limit)
    error = plan.get('error_injection') or {}
    if error.get('requested'):
        limit = _copy(_HOST_LIMITS['error_injection'])
        limit.update(kind='host_only', plan_value=error.get('mode'), host_limit=0)
        limits.append(limit)
    if plan.get('route') is not None:
        limit = _copy(_HOST_LIMITS['route'])
        limit.update(kind='host_only',
                     plan_value=plan['route'].get('kind'), host_limit=False)
        limits.append(limit)
    # A pipelined plan is a host limit, not a device limit: the pinned wbdmac
    # really does keep more than one request in flight, and the executor is the
    # half that has to serve them.  The bound reported is the smaller of this
    # module's declared host depth and the generated edge environment's own
    # ``environment_max_outstanding``, so a plan above either is answered by the
    # executor that owns that number instead of being refused as unencodable.
    outstanding = plan.get('max_outstanding')
    if _is_int(outstanding) and outstanding > 1:
        environment = (plan.get('artifact') or {}).get('environment_max_outstanding')
        bound = MAX_OUTSTANDING
        evidence = 'this module declares %d' % MAX_OUTSTANDING
        if _is_int(environment) and environment < bound:
            bound = environment
            evidence = ('the generated edge environment declares %d'
                        % environment)
        limit = _copy(_HOST_LIMITS['max_outstanding'])
        limit.update(kind='host_only', plan_value=outstanding, host_limit=bound,
                     evidence=evidence)
        limits.append(limit)
    return limits


def _declaration_facts(plan: Mapping) -> list[dict]:
    """The device/scenario facts a plan is built from, tagged as declarations."""
    device = plan['device']
    facts = [
        {'fact': 'device', 'value': device['family'],
         'source': device['facts_source'], 'kind': 'declaration'},
        {'fact': 'block_words', 'value': plan['block_words'],
         'source': plan['block_words_declaration'], 'kind': 'declaration'},
        {'fact': 'device_max_block_words',
         'value': device['device_max_block_words'],
         'source': device['facts_source'], 'kind': 'declaration'},
        {'fact': 'length_unit', 'value': plan['length_unit'],
         'source': device['facts_source'], 'kind': 'declaration'},
        {'fact': 'length_value', 'value': plan['length_value'],
         'source': device['facts_source'], 'kind': 'declaration'},
        {'fact': 'start_word', 'value': plan['start']['word'],
         'source': plan['start']['source'], 'kind': 'declaration'},
        {'fact': 'increment_source', 'value': plan['increment_source'],
         'source': 'scenario', 'kind': 'declaration'},
        {'fact': 'increment_destination', 'value': plan['increment_destination'],
         'source': 'scenario', 'kind': 'declaration'},
        {'fact': 'master_byte_enable', 'value': plan['master_byte_enable']['kind'],
         'source': device['facts_source'], 'kind': 'declaration'},
        {'fact': 'max_outstanding', 'value': plan['max_outstanding'],
         'source': device['facts_source'], 'kind': 'declaration'},
        {'fact': 'irq_trigger', 'value': plan['irq_trigger'],
         'source': device['facts_source'], 'kind': 'declaration'},
        {'fact': 'irq_clear', 'value': plan['irq_clear']['method'],
         'source': device['facts_source'], 'kind': 'declaration'},
    ]
    return facts


def _route_read_evidence(plan: Mapping, route: Mapping, geometry: Mapping,
                         evidence: Mapping, register: object) -> None:
    """Check the evidence a *read* route declares against its own shape.

    The three read shapes have three different witnesses, and the declaration
    has to name the one its direction needs:

    * a fixed read of one target register declares ``register_readback`` on that
      register: a read returns the stored word and does not change it;
    * a FIFO read declares ``fifo_level`` on a *different*, readable level
      register, and the routed port's own declared side effect has to be a pop
      on read.  Each accepted read pops exactly one entry, so the declared depth
      has to hold the whole block and the level has to fall by the number of
      accepted reads;
    * an aperture read declares ``register_readback`` with ``words`` equal to the
      routed beat count, one readable register per word, so every captured word
      has a declared target register behind it.

    A declaration that states the wrong witness for its own direction is refused
    by name here; it is never downgraded to a weaker check by the entry.
    """
    if geometry.get('direction') != 'read':
        return
    kind = route.get('kind')
    ekind = evidence.get('kind')
    side_effect = register.get('side_effect') if isinstance(register, Mapping) else None
    words = evidence.get('words')
    if kind == 'fifo':
        if ekind != 'fifo_level':
            _fail('fifo-read-not-declared', 'fifo-level-evidence')
        if geometry['mode'] != 'fixed':
            _fail('fifo-route-address-mode-mismatch', 'fifo-read-aperture')
        # The pop is a property of the pinned RTL, declared by the target's own
        # profile: a readable register without that side effect is not a FIFO
        # and cannot witness a pop.
        if side_effect != FIFO_POP_SIDE_EFFECT:
            _fail('fifo-read-not-popping',
                  '%s:%s' % (route.get('register', {}).get('name')
                             if isinstance(route.get('register'), Mapping) else None,
                             side_effect))
        bits = evidence.get('bits')
        if (not isinstance(bits, list) or len(bits) != 2
                or any(not _is_int(bit) for bit in bits)):
            _fail('fifo-read-level-bits-absent')
        depth = evidence.get('depth')
        if not _is_int(depth) or depth < geometry['beats']:
            _fail('fifo-read-beyond-declared-depth',
                  '%s<%d' % (depth, geometry['beats']))
        return
    if ekind != 'register_readback':
        _fail('dma-route-evidence-unsupported', str(ekind))
    if geometry['mode'] == 'aperture':
        if words is None:
            _fail('aperture-read-words-absent')
        if words != geometry['beats']:
            _fail('aperture-read-words-mismatch',
                  '%d!=%d' % (words, geometry['beats']))
    elif words is not None and words != 1:
        _fail('aperture-read-words-mismatch', 'fixed-register')


def validate_transfer_plan(plan: Mapping, profile: object,
                           artifact: object) -> dict:
    """Refuse a plan the selected device cannot encode; report host-only limits.

    The declaration checks run against the profile and the artifact afresh, so a
    plan cannot smuggle in a start word, byte enable or block length that its
    device does not encode.  Device refusals raise ``DmaTransferError`` with a
    stable ``reason``; host-only limits are returned, never raised, because they
    are not properties of the selected device.
    """
    if not isinstance(plan, Mapping) or plan.get('schema_version') != DMA_PLAN_SCHEMA:
        _fail('dma-plan-invalid', 'schema_version')
    device = _device_declaration(profile)
    _recheck_plan_device(plan, device)
    # A declared capability is rechecked against the profile afresh, so a plan
    # cannot keep a two-channel / wider-beat declaration while claiming a device
    # that only has one channel and a 32-bit beat.
    declaration = plan.get('declaration')
    if isinstance(declaration, Mapping):
        declared_capabilities = declaration.get('declared_capabilities')
        if declared_capabilities:
            try:
                shape = dma_capabilities(declared_capabilities)
            except BehaviorError as error:
                _fail('dma-capability-invalid', str(error))
            for name in dma_capability_refusals(shape,
                                                limit=device['device_capabilities']):
                _fail('dma-capability-beyond-device', name)
    artifact_facts = _artifact_declaration(artifact, device)
    declared_artifact = plan.get('artifact')
    if isinstance(declared_artifact, Mapping):
        if (declared_artifact.get('kind') != artifact_facts.get('kind')
                or declared_artifact.get('environment_max_outstanding')
                != artifact_facts.get('environment_max_outstanding')):
            _fail('dma-plan-artifact-mismatch')

    block = plan.get('block_words')
    if not _is_int(block) or block < 1:
        _fail('block-words-invalid')
    if block > device['max_block_words']:
        _fail('block-beyond-declared-bound',
              '%s:%d>%d' % (device['family'], block,
                            device['max_block_words']))
    length_expected = (block * WORD_BYTES if device['length_unit'] == 'bytes'
                      else block)
    if plan.get('length_unit') != device['length_unit']:
        _fail('dma-plan-length-mismatch', 'unit')
    if plan.get('length_value') != length_expected:
        _fail('dma-plan-length-mismatch', 'value')
    if length_expected > (1 << device['length_register_bits']) - 1:
        _fail('length-not-encodable')

    increment_source = plan.get('increment_source')
    increment_destination = plan.get('increment_destination')
    if not _is_bool(increment_source) or not _is_bool(increment_destination):
        _fail('dma-plan-invalid', 'increment')
    byte_enable = plan.get('master_byte_enable')
    if not isinstance(byte_enable, Mapping):
        _fail('dma-plan-invalid', 'master_byte_enable')
    size_bytes = byte_enable.get('size_bytes')
    if size_bytes not in (1, 2, 4):
        _fail('master-byte-enable-unsupported', 'size-bytes')
    expected_start = _derive_start_word(
        device, block_words=block, increment_source=increment_source,
        increment_destination=increment_destination, size_bytes=size_bytes)
    start = plan.get('start')
    if not isinstance(start, Mapping) or not _is_int(start.get('word')):
        _fail('dma-plan-invalid', 'start')
    _check_start_word(start['word'], expected_start,
                      increment_source=increment_source,
                      increment_destination=increment_destination)

    # --- byte enables -----------------------------------------------------
    kind = byte_enable.get('kind')
    mask = byte_enable.get('mask')
    if kind not in ('full_word', 'declared_mask', 'size_derived_lanes'):
        _fail('master-byte-enable-unsupported', str(kind))
    if kind == 'full_word' and mask != 15:
        _fail('master-byte-enable-invalid', 'full-word-mask')
    if kind == 'declared_mask' and (not _is_int(mask) or not 1 <= mask <= 15):
        _fail('master-byte-enable-invalid', 'mask')
    if kind == 'size_derived_lanes':
        if device['family'] != 'zipdma' or size_bytes == 4:
            _fail('master-byte-enable-unsupported', 'size-derived-lanes')
        if byte_enable.get('size_code') != device['size_codes'].get(size_bytes):
            _fail('master-byte-enable-invalid', 'size_code')
        expected_beats = WORD_BYTES // size_bytes
        if byte_enable.get('beats_per_word') != expected_beats:
            _fail('master-byte-enable-invalid', 'beats_per_word')
        pattern = byte_enable.get('lane_pattern')
        if (not isinstance(pattern, list) or len(pattern) != expected_beats
                or any(not _is_int(item) or not 1 <= item <= 15 for item in pattern)):
            _fail('master-byte-enable-invalid', 'lane_pattern')
    if not device['master_has_sel']:
        if kind != 'full_word' or mask != 15 or byte_enable.get('partial'):
            _fail('partial-byte-enable-on-no-select-device', device['family'])
        if device.get('master_fixed_byte_enable') not in (None, 15):
            _fail('partial-byte-enable-on-no-select-device', 'fixed-enable')
    else:
        if kind == 'size_derived_lanes':
            if artifact_facts['edge_present'] \
                    and artifact_facts.get('master_byte_enable_signal') != 'mwb_sel':
                _fail('partial-byte-enable-on-no-select-device',
                      'artifact-master-sel-absent')
        if kind == 'declared_mask' and mask != 15 and artifact_facts['edge_present']:
            if artifact_facts.get('master_byte_enable_signal') != 'mwb_sel':
                _fail('partial-byte-enable-on-no-select-device',
                      'artifact-master-sel-absent')

    # --- outstanding / errors / delay / irq -------------------------------
    outstanding = plan.get('max_outstanding')
    if not _is_int(outstanding) or outstanding < 1:
        _fail('outstanding-invalid')
    if outstanding > MAX_OUTSTANDING:
        _fail('outstanding-beyond-one', 'host:%d>%d' % (outstanding, MAX_OUTSTANDING))
    if outstanding > device['max_outstanding']:
        _fail('outstanding-beyond-one', '%s:%d>%d'
              % (device['family'], outstanding, device['max_outstanding']))
    # The generated edge environment's own ``environment_max_outstanding`` is the
    # depth *that* executor serves, not a property of the selected device: the
    # plan keeps the declared depth and ``_host_limits`` reports the gap, which the
    # executor that owns the number answers.  Refusing here would hide a device
    # capability behind one executor's limit.
    error = plan.get('error_injection')
    if not isinstance(error, Mapping):
        _fail('dma-plan-invalid', 'error_injection')
    if error.get('requested') and error.get('available') == 'absent':
        _fail('error-injection-absent', 'artifact-declares-no-injection')
    if error.get('requested'):
        # A declared injection names one beat of the *routed* transfer.  The
        # plan-level check is only about the declaration's own consistency: the
        # routed beat count comes from the geometry, and a declared direction has
        # to be the route's direction.  Whether this host can drive the port is
        # the entry's answer, never this module's.
        error_beat = error.get('beat_index')
        if not _is_int(error_beat) or error_beat < 0:
            _fail('error-injection-invalid', 'beat_index')
        route_for_error = plan.get('route')
        if isinstance(route_for_error, Mapping) and plan.get('master_byte_enable'):
            routed = _route_geometry(plan, route_for_error)
            if error_beat >= routed['beats']:
                _fail('error-injection-beyond-block',
                      '%d>=%d' % (error_beat, routed['beats']))
            declared_direction = error.get('direction')
            if (declared_direction is not None
                    and declared_direction != routed['direction']):
                _fail('error-injection-direction-mismatch',
                      '%s!=%s' % (declared_direction, routed['direction']))
    if plan.get('irq_trigger') != device['irq_trigger']:
        _fail('dma-plan-irq-mismatch', 'trigger')
    if plan.get('irq_clear') != device['irq_clear']:
        _fail('dma-plan-irq-mismatch', 'clear')
    delay = plan.get('response_delay')
    if not isinstance(delay, Mapping) or not _is_int(delay.get('ticks')) \
            or not 0 <= delay['ticks'] <= MAX_RESPONSE_DELAY_TICKS:
        _fail('response-delay-not-declarable')
    if plan.get('irq_trigger') == 'pulse':
        ticks = plan.get('irq_pulse_ticks')
        if not _is_int(ticks) or not 1 <= ticks <= MAX_IRQ_PULSE_TICKS:
            _fail('irq-pulse-ticks-invalid')

    # --- route ------------------------------------------------------------
    route = plan.get('route')
    if route is not None:
        if not isinstance(route, Mapping):
            _fail('dma-route-invalid', 'route')
        kind = route.get('kind')
        if kind not in ROUTE_KINDS:
            _fail('dma-route-kind-unsupported', str(kind))
        geometry = _route_geometry(plan, route)
        window = route.get('target_window')
        if not isinstance(window, Mapping):
            if kind == 'fifo':
                _fail('fifo-route-not-declared', 'target_window')
            _fail('dma-route-target-not-declared', 'target_window')
        if route.get('target_name') is None and route.get('target_index') is None:
            if kind == 'fifo':
                _fail('fifo-route-not-declared', 'target')
            _fail('dma-route-target-not-declared', 'target')
        evidence = route.get('evidence')
        if not isinstance(evidence, Mapping):
            if kind == 'fifo':
                _fail('fifo-route-not-declared', 'evidence')
            _fail('dma-route-evidence-absent')
        if kind == 'fifo' and evidence.get('kind') != 'fifo_level':
            # A FIFO route has to declare the level evidence its direction needs.
            # The read direction's own name is used so a read declaration that
            # names a register readback is refused as the wrong *read* witness.
            _fail('fifo-read-not-declared' if geometry['direction'] == 'read'
                  else 'fifo-route-not-declared', 'fifo-level-evidence')
        if geometry['mode'] == 'fixed' and geometry['increment']:
            _fail('fifo-route-address-mode-mismatch', 'fixed-but-incrementing')
        if geometry['mode'] == 'aperture' and not geometry['increment']:
            _fail('fifo-route-address-mode-mismatch', 'aperture-but-fixed')
        if geometry['first_offset'] + WORD_BYTES > window['size']:
            _fail('dma-route-window-bounds', 'first')
        if geometry['mode'] == 'aperture' and \
                geometry['last_offset'] + WORD_BYTES > window['size']:
            _fail('dma-route-window-bounds', 'last')
        register = route.get('register') or {}
        access = register.get('access') if isinstance(register, Mapping) else None
        if access is not None:
            if geometry['direction'] == 'write' and access not in ('rw', 'wo'):
                _fail('dma-route-direction-unsupported', 'write-to-read-only')
            if geometry['direction'] == 'read' and access not in ('rw', 'ro'):
                _fail('dma-route-direction-unsupported', 'read-from-write-only')
        _route_read_evidence(plan, route, geometry, evidence, register)
        _route_reachability(plan, route, geometry)
        # The target's own wire protocol, from its declared profile facts.  A
        # route never assumes APB3: the protocol is reported so the host drives
        # the beat through that target's artifact and no other.
        protocol = (route.get('target_profile_facts') or {}).get('protocol')
    else:
        geometry = None
        protocol = None

    limits = _host_limits(plan)
    return {
        'schema_version': DMA_VALIDATION_SCHEMA,
        'status': 'declaration_valid',
        'refusals': [],
        'declaration_facts': _declaration_facts(plan),
        'host_limits': limits,
        'host_supported': not limits,
        'host': HOST_SOURCE,
        'device': plan['device']['family'],
        'block_words': block,
        'start_word': plan['start']['word'],
        'route': None if geometry is None else {
            'kind': route['kind'], 'direction': geometry['direction'],
            'address_mode': geometry['mode'],
            'beats': geometry['beats'],
            'first_offset': geometry['first_offset'],
            'last_offset': geometry['last_offset'],
            # The wire protocol of the target this route names, from the target's
            # own profile endpoint: the host has to drive the beat through it.
            'protocol': protocol,
        },
    }


# ---------------------------------------------------------------------------
# route target
# ---------------------------------------------------------------------------
def _window_rows(windows: object) -> list[dict]:
    """Normalize a window declaration into ordered rows with indices."""
    if isinstance(windows, Mapping):
        if 'windows' in windows:
            raw = windows['windows']
        elif 'ip_base' in windows and 'ip_size' in windows:
            raw = [{'name': 'target', 'base': windows['ip_base'],
                    'size': windows['ip_size']}]
        elif isinstance(windows.get('target_window'), Mapping):
            raw = [dict(windows['target_window'], name='target')]
        else:
            raw = [dict(value, name=key) if isinstance(value, Mapping) else value
                   for key, value in windows.items()]
    elif isinstance(windows, (list, tuple)):
        raw = list(windows)
    else:
        _fail('dma-route-window-invalid', 'windows')
    if not isinstance(raw, (list, tuple)) or not raw:
        _fail('dma-route-target-not-declared', 'windows')
    rows = []
    for position, row in enumerate(raw):
        if not isinstance(row, Mapping):
            _fail('dma-route-window-invalid', str(position))
        base, size = row.get('base'), row.get('size')
        if (not _is_int(base) or not _is_int(size) or base < 0
                or size < WORD_BYTES or base % WORD_BYTES or base + size > 1 << 32):
            _fail('dma-route-window-invalid', str(position))
        index = row.get('index', position)
        if not _is_int(index) or index < 0:
            _fail('dma-route-window-invalid', 'index')
        name = row.get('name', row.get('target_name'))
        if name is not None and (not isinstance(name, str) or not name):
            _fail('dma-route-window-invalid', 'name')
        rows.append({'index': index, 'name': name, 'base': base, 'size': size})
    return rows


def _select_target(route: Mapping, rows: list[dict]) -> dict:
    """Resolve the declared target index/name against the runtime windows."""
    index = route.get('target_index')
    name = route.get('target_name')
    if index is not None:
        matches = [row for row in rows if row['index'] == index]
        if not matches:
            _fail('dma-route-target-not-declared', 'index:%d' % index)
        if len(matches) > 1:
            _fail('dma-route-target-ambiguous', 'index:%d' % index)
        target = matches[0]
        if name is not None and target['name'] is not None and target['name'] != name:
            _fail('dma-route-target-mismatch',
                  'index:%d:%s' % (index, target['name']))
        return target
    if name is not None:
        matches = [row for row in rows if row['name'] == name]
        if not matches:
            _fail('dma-route-target-not-declared', 'name:' + name)
        if len(matches) > 1:
            _fail('dma-route-target-ambiguous', 'name:' + name)
        return matches[0]
    if len(rows) == 1:
        return rows[0]
    _fail('dma-route-target-ambiguous', 'no-index-or-name')


def _route_evidence_description(route: Mapping, plan: Mapping | None = None) -> dict:
    evidence = route.get('evidence')
    if not isinstance(evidence, Mapping):
        _fail('dma-route-evidence-absent')
    kind = evidence.get('kind')
    if kind not in ROUTE_EVIDENCE_KINDS:
        _fail('dma-route-evidence-unsupported', str(kind))
    direction = route.get('direction', 'write')
    if direction not in ROUTE_DIRECTIONS:
        _fail('dma-route-direction-unsupported', str(direction))
    # The evidence a route has to produce depends on which way the data moves:
    # a write route changes the target (a FIFO level rises, a register changes),
    # while a read route must *return* the target's word and leave it unchanged,
    # so its witness is the captured value and the destination it was written to.
    expectation = {
        ('write', 'fifo_level'):
            'sample the target FIFO level before and after the route; each '
            'accepted DMA beat must advance the level by one and the readback '
            'must bracket the pushes',
        ('write', 'register_readback'):
            'read the declared register before and after the route; the declared '
            'field must change from its pre-transfer value',
        ('read', 'register_readback'):
            'read the declared register before and after the route; the DMA '
            'master read must return that same word, the two CPU readbacks must '
            'agree with it (a read does not change the register), and the RAM '
            'destination words the master wrote must equal it',
        ('read', 'fifo_level'):
            'sample the target FIFO level before and after the route; each '
            'accepted DMA read must pop exactly one entry, so the level must '
            'fall by one per read and the words returned must be the words the '
            'target held',
    }[(direction, kind)]
    bits = evidence.get('bits')
    words = evidence.get('words')
    expected_word = evidence.get('expected_word')
    beats = _geometry_of_route(plan)
    level = None
    if direction == 'read' and kind == 'fifo_level':
        # A FIFO read of N words is declared against a FIFO that holds exactly
        # those N words: the level the fill leaves is the beat count and the
        # level the transfer must leave is zero.  Anything else is a different
        # declaration, not a weaker version of this one.
        level = {'before': beats, 'after': 0, 'drop': beats,
                 'rule': 'the level before the transfer equals the number of '
                         'accepted reads and the level after it is zero'}
    return {'kind': kind,
            'register': evidence.get('register'),
            'offset': evidence.get('offset'),
            'field': evidence.get('field'),
            'bits': _copy(bits),
            'bit_range': None if bits is None else {'low': min(bits),
                                                    'high': max(bits)},
            'depth': evidence.get('depth'),
            'words': words,
            'expected_word': expected_word,
            'level': level,
            'sampling': evidence.get('sampling', 'pre_post'),
            'expectation': expectation,
            'source': evidence.get('source')}


def _geometry_of_route(plan: Mapping | None) -> int:
    """The routed beat count of a plan, from its own block declaration."""
    if not isinstance(plan, Mapping):
        return 1
    block = plan.get('block_words')
    byte_enable = plan.get('master_byte_enable') or {}
    beats_per_word = byte_enable.get('beats_per_word', 1)
    if not _is_int(block) or block < 1 or not _is_int(beats_per_word):
        return 1
    return block * beats_per_word


def dma_route_target(plan: Mapping, windows: object) -> dict:
    """Describe a DMA master write/read routed to one declared target window.

    The result names the target index, the exact target offsets the master
    would touch, the master word addresses, and the FIFO/register readback that
    would be required as evidence.  It is a declaration: ``completion_claimed``
    is always false and no transfer is executed or inferred here.  The
    ``host_support`` block names the entry that can execute the declared shape;
    only that entry's own run can report a completed route.
    """
    if not isinstance(plan, Mapping) or plan.get('schema_version') != DMA_PLAN_SCHEMA:
        _fail('dma-plan-invalid', 'schema_version')
    route = plan.get('route')
    if not isinstance(route, Mapping):
        _fail('dma-route-not-declared')
    kind = route.get('kind')
    if kind not in ROUTE_KINDS:
        _fail('dma-route-kind-unsupported', str(kind))
    if route.get('offset') is None:
        _fail('dma-route-offset-not-declared')
    geometry = _route_geometry(plan, route)
    rows = _window_rows(windows)
    target = _select_target(route, rows)
    window = route.get('target_window')
    if isinstance(window, Mapping):
        if (window['base'] != target['base'] or window['size'] != target['size']):
            _fail('dma-route-target-mismatch',
                  'declared-window-vs-runtime-window')
    else:
        window = {'base': target['base'], 'size': target['size']}
    if geometry['first_offset'] + WORD_BYTES > window['size']:
        _fail('dma-route-window-bounds', 'first')
    if geometry['mode'] == 'aperture' and \
            geometry['last_offset'] + WORD_BYTES > window['size']:
        _fail('dma-route-window-bounds', 'last')
    if geometry['mode'] == 'fixed' and geometry['increment']:
        _fail('fifo-route-address-mode-mismatch', 'fixed-but-incrementing')
    if geometry['mode'] == 'aperture' and not geometry['increment']:
        _fail('fifo-route-address-mode-mismatch', 'aperture-but-fixed')
    _route_reachability(plan, dict(route, target_window=window), geometry)
    register = route.get('register') or {}
    access = register.get('access') if isinstance(register, Mapping) else None
    if access is not None:
        if geometry['direction'] == 'write' and access not in ('rw', 'wo'):
            _fail('dma-route-direction-unsupported', 'write-to-read-only')
        if geometry['direction'] == 'read' and access not in ('rw', 'ro'):
            _fail('dma-route-direction-unsupported', 'read-from-write-only')
    evidence = _route_evidence_description(route, plan)
    # An aperture read's per-word register rows, from the target's own profile.
    profile_facts = route.get('target_profile_facts') or {}
    profile_evidence = profile_facts.get('evidence') or {}
    if profile_evidence.get('aperture'):
        evidence['aperture'] = _copy(profile_evidence['aperture'])
    declared_evidence = route.get('evidence')
    if isinstance(declared_evidence, Mapping):
        _route_read_evidence(plan, route, geometry, declared_evidence, register)
    first_byte = window['base'] + geometry['first_offset']
    last_byte = window['base'] + geometry['last_offset']
    beats = geometry['beats']
    fifo_pop = (kind == 'fifo' and geometry['direction'] == 'read')
    return {
        'schema_version': DMA_ROUTE_SCHEMA,
        'kind': kind,
        'is_fifo': route.get('is_fifo', kind == 'fifo'),
        'fifo_pop': fifo_pop,
        'level_bounds': ({'before': beats, 'after': 0, 'drop': beats}
                         if fifo_pop else None),
        'expected_word': evidence.get('expected_word'),
        'aperture_words': (evidence.get('words')
                           if geometry['mode'] == 'aperture' else None),
        'direction': geometry['direction'],
        'target_index': target['index'],
        'target_name': target['name'] or route.get('target_name'),
        'target_window': {'base': window['base'], 'size': window['size']},
        'target_profile': route.get('target_profile'),
        # The target's own wire protocol, from its profile's mmio endpoint.  The
        # route does not assume one: the entry resolves the same protocol from the
        # artifact it built and refuses a mismatch, so a route is never driven
        # through another target protocol's completion.
        'target_protocol': profile_facts.get('protocol'),
        'route_protocols': list(ROUTE_PROTOCOLS),
        'register': _copy(register) if register else None,
        'offset': route['offset'],
        'address_mode': geometry['mode'],
        'increment': geometry['increment'],
        'block_words': plan.get('block_words'),
        'beat_count': geometry['beats'],
        'offset_bounds': {'first': geometry['first_offset'],
                          'last': geometry['last_offset'],
                          'repeat': geometry['repeat']},
        'byte_bounds': {'first': first_byte, 'last': last_byte},
        'master_word_bounds': {'first': first_byte >> 2, 'last': last_byte >> 2},
        'reachable': {'device_max_byte_address':
                      (1 << plan['device']['source_destination_byte_address_bits']) - 1,
                      'fits': True},
        'expected_evidence': evidence,
        # This module describes the route; it does not execute one and never
        # claims completion.  The in-process F6 entry resolves this declaration
        # against the target rows it actually built and its C++ host executes one
        # fixed APB3 route beat at a time (a write beat pushes the target
        # register, a read beat captures the target's PRDATA and hands it back to
        # the DMA master, which writes it to the RAM destination).  The entry,
        # not this module, is the authority for whether a given route ran.
        'host_support': {
            'status': 'executed_by_inprocess_f6_entry',
            # The route's transport is the target's *generic beat port*, not one
            # protocol's pins.  Every generated target artifact binds its own
            # bridge to that port and exposes its own passive trace, so the same
            # route geometry is admitted on any of these protocols and the
            # completion is always the routed target's own `rsp_valid`.
            'protocols': list(ROUTE_PROTOCOLS),
            'beat_interface': ('target generic request port: req_valid/req_ready, '
                               'req_write/req_addr/req_wdata/req_be in, '
                               'rsp_valid/rsp_ready/rsp_rdata/rsp_error out, one '
                               'outstanding master beat'),
            'implemented_by': [
                'scripts/run_inprocess_f1f6.py dma_route_support (fixed or '
                'aperture read/write route to one declared target of this build, '
                'with that target artifact\'s own protocol admitted)',
                'scripts/inprocess_obi_apb_f1f4_spike.cpp MasterRoute (one held '
                'master beat on the target trait\'s generic beat port; the '
                'completion is that target\'s own response_valid/response_rdata, '
                'never a RAM fallback, and the target\'s own protocol trace is '
                'sampled: APB3 psel/penable/pready, Wishbone cyc/stb/ack, '
                'TL-UL a_valid/a_ready->d_valid/d_ready, AXI4-Lite '
                'AW/W/B or AR/R)',
            ],
            'reason': 'the declaration is executable only through that entry; this '
                      'module states the required evidence and claims no transfer',
            'completion_claimed': False,
        },
        'completion_claimed': False,
        'executed': False,
    }


__all__ = [
    'BEHAVIOR_KEYS',
    'BEHAVIOR_METADATA_KEYS',
    'DEVICE_FACTS',
    'DMA_BEHAVIOR_SCHEMA',
    'DMA_PLAN_SCHEMA',
    'DMA_ROUTE_SCHEMA',
    'DMA_STATUS_KINDS',
    'DMA_VALIDATION_SCHEMA',
    'DmaTransferError',
    'HOST_BLOCK_WORDS',
    'HOST_START_WORDS',
    'MAX_OUTSTANDING',
    'MAX_RESPONSE_DELAY_TICKS',
    'PROFILE_PROTOCOL_NAMES',
    'ROUTE_KINDS',
    'ROUTE_DIRECTIONS',
    'ROUTE_PROTOCOLS',
    'WORD_BYTES',
    'dma_route_target',
    'dma_transfer_declaration',
    'validate_transfer_plan',
]
