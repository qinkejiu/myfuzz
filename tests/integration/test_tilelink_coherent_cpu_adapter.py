"""The coherent TileLink CPU row: adapter selection, registry and beats.

The artifact under test is produced by the same pure code-generation entry the
admitted path calls (``runtime_renderer._render_admitted_runtime``); it is a
generation-only artifact (``source_verification`` is ``None``) because these
tests are about the *selection seam* - the taps it publishes, the session class
the executor would drive, and the registry row that pins all of it - not about
source admission, which ``create_preparation`` covers separately.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.integration import cpu_tlul
from myfuzz.local_harness import driver_renderer, runtime_renderer
from myfuzz.local_harness.plan import plan_local_harness
from myfuzz.local_harness.renderer import render_local_harness
from myfuzz.local_harness.request import load_local_harness_request
from myfuzz.runtime.adapters import tilelink_cpu
from myfuzz.runtime.registry import registrations

_ROOT = Path(__file__).resolve().parents[2]
_REQUEST = _ROOT / 'configs/scenarios/compiled-f2-f4-apb-i2c-boom/requests/processor.json'
_DOCUMENT: dict | None = None


def _artifact():
    """Generate the runtime artifact the admitted path would produce."""
    global _DOCUMENT
    if _DOCUMENT is None:
        if not _REQUEST.is_file():
            pytest.skip('BOOM descriptor is not checked out')
        request = load_local_harness_request(json.loads(_REQUEST.read_text()))
        plan = plan_local_harness(request, base_dir=_ROOT)
        structural = render_local_harness(plan)
        _DOCUMENT = runtime_renderer._render_admitted_runtime(
            plan, structural, None, _ROOT, native_raw=False)
    return _DOCUMENT


class TestGeneratedCoherentArtifact:
    def test_kind_taps_and_five_channel_view(self):
        document = _artifact().runtime_document
        assert document['kind'] == 'tilelink_coherent_cpu'
        taps = document['protocol_tap_ports']
        assert len(taps) == 39
        trace = document['base_protocol_traces']['traces'][0]
        assert trace['protocol'] == 'tilelink-coherent'
        assert {channel: len(rows) for channel, rows in trace['channels'].items()} == {
            'a': 9, 'b': 9, 'c': 8, 'd': 10, 'e': 3}
        assert trace['signal_widths']['a_bits_data'] == 64
        assert trace['signal_widths']['a_bits_mask'] == 8
        assert 'boom_cpu_session.py' in trace['instruction_hop_refusal']

    def test_driver_publishes_the_64bit_backend_face(self):
        artifact = _artifact()
        refreshed = driver_renderer.render_local_runtime
        driver_renderer.render_local_runtime = lambda plan, structural, verified, *, base_dir: (
            runtime_renderer._render_admitted_runtime(plan, structural, None, base_dir,
                                                      native_raw=False))
        try:
            driver = driver_renderer.render_local_driver(artifact, base_dir=_ROOT)
        finally:
            driver_renderer.render_local_runtime = refreshed
        text = driver.cpp_text
        assert 'STEP_TL_COHERENT' in text
        assert 'dut.m_req_wdata' in text and 'dut.m_rsp_rdata' in text
        assert 'tilelink_coherent_fault' in text


class TestSelectionSeam:
    def test_executor_gaps_are_empty_for_the_generated_session(self):
        session = cpu_tlul.session_class()
        assert session.__name__ == 'GeneratedTlCoherentSession'
        assert cpu_tlul.executor_gaps(session) == ()

    def test_pinned_cpp_harness_still_reports_its_gaps(self):
        from myfuzz.local_harness.boom_cpu_session import GeneratedBoomCpuSession
        gaps = cpu_tlul.executor_gaps(GeneratedBoomCpuSession)
        assert 'session-router-keyword-missing' in gaps
        assert 'host-memory-authority-missing' in gaps

    def test_select_mmio_cpu_returns_the_coherent_adapter(self):
        from myfuzz.integration.mmio_cpu_adapter import select_mmio_cpu
        artifact = _artifact()
        adapter = select_mmio_cpu(artifact, {'component': 'processor'},
                                  {'source_id': 'processor:image'})
        assert adapter.protocol == 'tilelink-coherent'
        assert adapter.channel_model == 'unified'
        assert adapter.session_type is cpu_tlul.session_class()
        assert adapter.traces['instruction_hop_refusal']
        assert set(adapter.traces['channels']) == set('abcde')
        assert adapter.policy['denial_signal'] == 'd_bits_denied'

    def test_pinned_artifact_without_declared_taps_is_refused_by_name(self):
        pinned = SimpleNamespace(runtime_document={'kind': 'tilelink_coherent_cpu'})
        with pytest.raises(ValueError, match='tilelink-coherent-traces-required'):
            cpu_tlul.cpu_adapter(pinned, {}, {})


class TestRegistryRow:
    def registration(self):
        rows = [row for row in registrations()
                if row.protocol == ('tilelink-coherent', '1')]
        assert len(rows) == 1
        return rows[0]

    def test_registration_matches_the_admitted_template(self):
        row = self.registration()
        assert row.adapter_id == 'tilelink.cpu.v1'
        assert row.roles == ('cpu',)
        assert row.semantic_kinds == ('cpu.tilelink-coherent.v1',)
        assert row.templates == (('cpu.tilelink-coherent', '1',
                                  'coherent-ab-cd-e-single-outstanding'),)
        assert row.data_widths == (64,) and row.address_widths == (32,)
        assert row.byte_enable is True and row.max_outstanding == 1
        assert row.completion_kinds == ('independent_channels_response',)

    def test_pin_covers_every_implementation_file(self):
        row = self.registration()
        for relative in row.implementation_files:
            assert (_ROOT / relative).is_file(), relative
        assert len(row.implementation_sha256()) == 64


class TestNativeBeats:
    def test_measured_pairing(self):
        events = [
            dict(kind='tilelink_a_accept', component='cpu', event_id=1,
                 address=0x4000, opcode=4, size=2, mask=0x0f, data=0),
            dict(kind='tilelink_d_complete', component='cpu', event_id=2, value=0x55),
        ]
        beats = tilelink_cpu.native_tl_beats(events, 'cpu', {})
        assert list(beats) == [('data', 1)]
        beat = beats[('data', 1)]
        assert beat['acceptance_event'] == 1 and beat['response_event'] == 2
        assert beat['address'] == 0x4000 and beat['rdata'] == 0x55
        assert beat['byte_enable'] == 0x0f

    def test_unpaired_events_are_refused(self):
        with pytest.raises(ValueError, match='tilelink-completion-without-acceptance'):
            tilelink_cpu.native_tl_beats(
                [dict(kind='tilelink_d_complete', component='cpu', event_id=1,
                      value=0)], 'cpu', {})
        with pytest.raises(ValueError, match='tilelink-acceptance-without-completion'):
            tilelink_cpu.native_tl_beats(
                [dict(kind='tilelink_a_accept', component='cpu', event_id=1,
                      address=0, mask=0xff, data=0)], 'cpu', {})
