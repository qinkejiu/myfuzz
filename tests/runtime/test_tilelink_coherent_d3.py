"""D3 admission surface for the coherent TileLink row.

Covers the three code-owned tables the D3 path added and the one refusal it must
keep: the static path compiler sees a real CPU transaction source, the admission
verifier and binding factory are registered for exactly this adapter id, and an
artifact whose taps were tampered with is refused by name instead of being
admitted with a different shape.
"""
from __future__ import annotations

import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from myfuzz.runtime.admission import _BUILTIN_VERIFIERS
from myfuzz.runtime.binding import _FACTORIES

_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE = _ROOT / 'configs/scenarios/compiled-f2-f4-apb-i2c-boom/compose.json'


class TestStaticPathCompiler:
    def _prepare(self, tmp_path, base_override=None):
        from myfuzz.integration.compiled_execution_files import (
            prepare_compiled_execution_inputs,
        )
        base = _ROOT / 'configs/scenarios/compiled-f2-f4-apb-i2c-boom'
        if not (base / 'compose.json').is_file():
            pytest.skip('BOOM descriptor is not checked out')
        compose = base / 'compose.json'
        if base_override is not None:
            # The patched composition keeps the descriptor's own requests: they
            # are referenced relative to the compose document.
            shutil.copytree(base / 'requests', tmp_path / 'requests')
            document = json.loads(compose.read_text())
            document['memory'] = [dict(document['memory'][0], **base_override)]
            compose = tmp_path / 'compose.json'
            compose.write_text(json.dumps(document))
        prepared = prepare_compiled_execution_inputs(
            base_dir=_ROOT, compose_path=compose,
            capability_paths=(base / 'test_capability.json',),
            supplement_path=base / 'execution_supplement.json',
            generated_dir=tmp_path / 'generated', flow_ids=('F2', 'F4'))
        return prepared.inputs['compiled']

    def test_f2_and_f4_are_executable_on_real_sources(self, tmp_path):
        compiled = self._prepare(tmp_path)
        rows = {row['flow_id']: row for row in compiled['paths']
                if row['flow_id'] in ('F2', 'F4')}
        assert set(rows) == {'F2', 'F4'}
        for row in rows.values():
            assert row['status'] == 'executable', row['reason']
            kinds = {source['kind'] for source in row['sources']}
            assert 'instruction_image' in kinds
            assert kinds & {'cpu_load_stream', 'cpu_mmio_stream'}

    def test_instruction_image_must_contain_the_reset_vector(self, tmp_path):
        """The boot page is a real requirement, not an assumption."""
        compiled = self._prepare(tmp_path, {'base': 2147483648})
        rows = {row['flow_id']: row for row in compiled['paths']
                if row['flow_id'] in ('F2', 'F4')}
        for row in rows.values():
            assert row['status'] == 'unsupported'
            assert row['reason']['code'] == 'instruction-image-resource-undeclared'


class TestAdmissionAndBinding:
    def test_dispatch_is_registered_for_exactly_this_kind(self):
        assert _BUILTIN_VERIFIERS['tilelink_coherent_cpu'] is not None
        assert _FACTORIES['tilelink.cpu.v1'] is not None

    def test_surface_refuses_a_tampered_artifact(self):
        from myfuzz.runtime.adapters.tilelink_cpu import (
            tl_coherent_cpu_surface_document,
        )
        artifact = type('A', (), {})()
        artifact.runtime_document = {'kind': 'tilelink_coherent_cpu'}
        with pytest.raises(ValueError, match='tilelink-coherent-traces-required'):
            tl_coherent_cpu_surface_document(artifact)

    def test_surface_refuses_a_wrong_kind(self):
        from myfuzz.runtime.adapters.tilelink_cpu import (
            tl_coherent_cpu_surface_document,
        )
        artifact = type('A', (), {})()
        artifact.runtime_document = {'kind': 'obi_cpu'}
        with pytest.raises(ValueError, match='tilelink coherent artifact required'):
            tl_coherent_cpu_surface_document(artifact)


class TestHopPairing:
    def test_pairing_is_ordered_and_refuses_gaps(self):
        from myfuzz.runtime.adapters.tilelink_cpu import native_tl_beats
        events = [
            dict(kind='tilelink_a_accept', component='cpu', event_id=1,
                 address=0x4000, opcode=4, size=2, mask=0x0f, data=0),
            dict(kind='tilelink_d_complete', component='cpu', event_id=2, value=7),
            dict(kind='tilelink_a_accept', component='cpu', event_id=3,
                 address=0x4000, opcode=0, size=2, mask=0x0f, data=7),
            dict(kind='tilelink_d_complete', component='cpu', event_id=4, value=0),
        ]
        beats = native_tl_beats(events, 'cpu', {})
        assert list(beats) == [('data', 1), ('data', 2)]
        assert [beats[key]['write'] for key in beats] == [False, True]
        with pytest.raises(ValueError, match='tilelink-acceptance-without-completion'):
            native_tl_beats(events[:3], 'cpu', {})
