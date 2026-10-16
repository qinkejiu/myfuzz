"""Which port labels count as "the CPU actually read its instruction bytes".

The scenario gate that asks "was every declared source exercised in this
direction?" counts *consumed* sources, not merely applied mutations: a mutated
instruction byte only counts once an accepted memory read returns that byte and
records the initial image as its writer.

That rule listed the port labels it accepts for a CPU as ``("instr", "unified")``.
Ibex exposes a dedicated instruction channel, and CVA6's local harness has one
unified instruction/data port - but the generated memory CPUs label their single
unified port ``"memory"`` (``local_harness/native_session.py`` emits every beat on
channel ``'memory'``).  For a pair built on one of those the mutation was applied
and visible in the receipts' ``applied_sources``, yet its consumption count stayed
0, which made the per-direction source gate *unsatisfiable*: a campaign over such
a pair could never reach ``complete`` however well the search performed.

These tests pin the corrected vocabulary and, just as importantly, pin that
widening the label list cannot manufacture credit: the byte must still read back
equal to the mutated image byte and must still be attributed to the initial image.
"""
from __future__ import annotations

from types import SimpleNamespace

from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
from myfuzz.scenario.genome import MemoryImage


SOURCE_ID = 'cpu.image'
# The generated AXI4-Lite CPU fixture hosts its program image at the
# base of its RAM window (`axil_uart_cpu_example.RAM_BASE`), and the rule
# compares the read address against the image address.
ADDRESS = 0


def _image(data_hex: str) -> MemoryImage:
    return MemoryImage(image_id='program', component='cpu', address=ADDRESS,
                       data_hex=data_hex)


def _decoder():
    """Only the three attributes the rule reads."""
    source = SimpleNamespace(kind='memory_image', component='cpu', port='program')
    return SimpleNamespace(
        templates=[SimpleNamespace(genome=SimpleNamespace(
            initial_images=[_image('13000000')], actions=[]))],
        graph=SimpleNamespace(sources={SOURCE_ID: source}))


def _genome(data_hex: str):
    return SimpleNamespace(initial_images=[_image(data_hex)], actions=[])


def _trace(channel_id: str, writer: str, *, read_byte: int | None = None):
    """The preload plus one accepted read of the mutated byte 0.

    ``writer_event_ids`` carries one attribution PER BYTE of the read, exactly as
    ``memory_service`` emits it (it unpacks the snapshot's per-byte writers).  A
    stream whose writer list is shorter than its data is skipped by the rule
    before the credit condition is ever reached, so a fixture that gets this
    wrong silently earns nothing.
    """
    return SimpleNamespace(events=[
        # The preload carries the MUTATED image bytes; the rule compares the
        # trace's preload against the genome's own image data.
        {'kind': 'initial_image', 'component': 'cpu', 'image_id': 'program',
         'address': ADDRESS, 'data_hex': '14000000', 'event_id': 1},
        {'kind': 'memory_read', 'component': 'cpu', 'address': ADDRESS,
         'data_hex': bytes([read_byte]).hex() + '000000', 'event_id': 2,
         'writer_event_ids': [writer, 'ram', 'ram', 'ram'],
         'transaction': {'channel_id': channel_id}},
    ])


def _consumed(channel_id: str, writer: str = 'initial-image', *,
              read_byte: int = 0x14):
    executor = ScenarioRfuzzExecutor.__new__(ScenarioRfuzzExecutor)
    executor.decoder = _decoder()
    # One mutated byte (0x13 -> 0x14) at offset 0 of the image.
    return executor._consumed_source_ids({SOURCE_ID: (0,)}, 0,
                                         _genome('14000000'),
                                         _trace(channel_id, writer,
                                                read_byte=read_byte))


def test_a_unified_memory_channel_read_credits_the_cpu_source():
    """The generated memory CPUs call their single port "memory"."""
    assert _consumed('memory') == (SOURCE_ID,)


def test_the_original_label_vocabulary_still_credits():
    for channel_id in ('instr', 'unified'):
        assert _consumed(channel_id) == (SOURCE_ID,), channel_id


def test_an_unknown_channel_label_still_earns_nothing():
    """Widening the list must not become "any read counts"."""
    assert _consumed('data') == ()
    assert _consumed('mmio') == ()


def test_the_writer_provenance_is_still_enforced():
    """The label is not what enforces provenance - the writer is.

    A read that returns the mutated byte but is attributed to some other writer
    must not earn credit on any channel label, including the newly accepted one.
    """
    for channel_id in ('instr', 'unified', 'memory'):
        assert _consumed(channel_id, 'program-image-copy') == (), channel_id


def test_reading_a_different_byte_earns_nothing():
    """The byte read back must equal the mutated image byte."""
    assert _consumed('memory', read_byte=0x99) == ()
