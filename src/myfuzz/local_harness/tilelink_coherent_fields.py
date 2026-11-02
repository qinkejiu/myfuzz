"""Declared TileLink coherent client shape for the local harness.

The role vocabulary, every width and every direction are read from the bundled
``tilelink-coherent@1`` protocol plugin
(``src/myfuzz/protocols/plugins/tilelink-coherent.json``).  That plugin is the
same table ``myfuzz.integration.cpu_tlul`` publishes as the 39-role coherent
client map, and it is what the pinned derived ``BoomTile`` top declares: 47
physical ports = 39 client roles + ``clock`` + ``reset`` + 6 constant
interrupt/hartid inputs (see
``configs/cpus/boom/evidence/derived-20261017/physical_ports.json``).

Nothing here is hand-typed twice: the runtime renderer, the contract in
``local_harness/template_contracts.py`` and the coherent adapter all consume this
module, so a plugin edit that changes a role, a width or a direction is refused
at import (``tilelink-coherent-role-*``) instead of producing a harness whose
taps disagree with the contract.
"""
from __future__ import annotations

from myfuzz.protocols.catalog import load_builtin_protocol

PROTOCOL = ('tilelink-coherent', '1')
#: The coherent client's declared data width and the word width of the host
#: backend face (one 8-byte beat per backend transaction).
DATA_WIDTH = 64
ADDRESS_WIDTH = 32
#: A/B/C/D/E in the order the harness publishes them.
CHANNELS = ('a', 'b', 'c', 'd', 'e')
#: Prefix of every passive tap port on the generated runtime top.
TAP_PREFIX = 'cpu_tl_trace_'

#: Why this row cannot declare an instruction-only hop.  It is quoted verbatim
#: into the artifact, so the absence of an instruction hop is a declared scope
#: and never an oversight (see ``integration/native_mmio_data_hops.py``).
INSTRUCTION_HOP_REFUSAL = (
    'one shared coherent A/D boundary carries instruction fetches and data '
    'beats, so a fetch has no native channel identity distinct from a load: '
    'the coherent client declares a single endpoint '
    '(src/myfuzz/integration/cpu_tlul.py:76-101) and the pinned native journal '
    'reports A/D events with opcode/address/data only '
    '(src/myfuzz/local_harness/boom_cpu_session.py:222-235); the data joins are '
    'consumed without claiming an instruction hop'
)


def _declared():
    plugin = load_builtin_protocol(*PROTOCOL)
    shape = {}
    for spec in plugin.fields:
        width = spec.width_expression
        if not width.isdigit() or int(width) < 1:
            raise ValueError('tilelink-coherent-width-expression:' + spec.field_id)
        direction = 'output' if spec.direction == 'host_to_device' else 'input'
        shape[spec.field_id] = (direction, int(width))
    return shape


def _validated(shape):
    if len(shape) != 39:
        raise ValueError('tilelink-coherent-role-count:' + str(len(shape)))
    data = {shape[role][1] for role in ('a_bits_data', 'c_bits_data', 'd_bits_data')
            if role in shape}
    if data != {DATA_WIDTH}:
        raise ValueError('tilelink-coherent-data-width')
    for channel in CHANNELS:
        roles = [role for role in shape if role.startswith(channel + '_')]
        if not roles:
            raise ValueError('tilelink-coherent-channel-empty:' + channel)
    # The mask is one bit per data byte in the client's own declaration.
    for role in ('a_bits_mask', 'b_bits_mask'):
        if shape[role][1] != DATA_WIDTH // 8:
            raise ValueError('tilelink-coherent-mask-width:' + role)
    return shape


#: ``{role: (direction, width)}`` - ``output`` means the *pinned DUT* drives the
#: pin, which is the convention every other shape table in this package uses.
TL_COHERENT_SHAPE = _validated(_declared())


def channel_document(shape=None):
    """Per-channel ``{channel: {local_role: width}}`` view of the client."""
    shape = TL_COHERENT_SHAPE if shape is None else shape
    return {channel: {role[len(channel) + 1:]: width
                      for role, (_, width) in sorted(shape.items())
                      if role.startswith(channel + '_')}
            for channel in CHANNELS}


def tap_names(shape=None):
    """``{role: tap_port_name}`` for the passive per-role copies."""
    shape = TL_COHERENT_SHAPE if shape is None else shape
    return {role: TAP_PREFIX + role for role in sorted(shape)}
