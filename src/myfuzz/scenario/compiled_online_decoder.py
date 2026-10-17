"""Decode one RFuzz decision record into the exact admitted compiled candidate.

This module is the bridge between the RFuzz raw decision wire and the compiled
F4 candidate declared by D3.  It consumes the ``CandidateLayout`` that
``compile_candidate_layout`` issued for the one executable F4 path, calls
``declare_writer`` with the compiled ``cpu_mmio_stream`` source id, and carries
``source_id`` / ``path_id`` / register contract / value / compiled digest into a
typed candidate document.  Nothing is selected or named here: there is no
component, family, register or port name branch, and the candidate value is
never inferred from anything except the declared layout bytes.

Wire width
----------
The RFuzz decision wire in this repository is one eight byte record per test
(``myfuzz.scenario.rfuzz_decoder.RECORD_BYTES``); the scenario mode mutator
writes that whole record.  A compiled layout can be narrower than the wire
(the PULP timer F4 candidate is four bytes; the GPIO candidate is eight).  The
candidate is the exact declared prefix of the wire record and every byte after
``layout.byte_length`` is an unreferenced transport lane: it is not part of any
candidate value and never reaches the RTL.  A layout wider than the wire is
refused at construction, and a record whose length is not the transport record
length is refused at decode.  The exact original wire record is retained by the
caller's receipt/decision document; the candidate bytes retained by the runtime
are the declared projection of it.

Refusal contract
----------------
``CompiledCandidateRefused`` carries a stable ``code`` and, where the layout
reports one, the exact ``source_id`` pointer.  Forged audit documents, a layout
that was not issued for this path, a record that is not sized by the wire or a
layout value outside its mask/range/alignment all refuse here, before any
native command is issued.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from types import MappingProxyType

from myfuzz.integration.compiled_candidate_layout import (
    CandidateLayout,
    CandidateLayoutError,
    LAYOUT_SCHEMA,
    compile_candidate_layout,
)
from myfuzz.integration.generated_register_writer import declare_writer
from myfuzz.scenario.batch import BatchAdvance
from myfuzz.scenario.rfuzz_decoder import RECORD_BYTES
from myfuzz.scenario.session_runtime import OnlineCase, OnlineInstruction

DECODER_SCHEMA = 'compiled_online_decoder.v1'
CANDIDATE_SCHEMA = 'compiled_online_candidate.v1'

#: The RFuzz decision wire allocates whole eight byte records per test.
WIRE_RECORD_BYTES = RECORD_BYTES


class CompiledCandidateRefused(ValueError):
    """One raw record is not the candidate the admitted layout declares."""

    def __init__(self, code, pointer='', detail=None):
        self.code = code
        self.pointer = pointer
        self.detail = detail
        super().__init__(f'{code}:{pointer}' if pointer else code)


@dataclass(frozen=True)
class CompiledProjection:
    """The declared candidate bytes of one wire record and its decoded values."""

    candidate_bytes: bytes
    values: MappingProxyType
    unbound_bytes: bytes


@dataclass(frozen=True)
class CompiledCandidate:
    """One decoded candidate together with the evidence that selected it."""

    case: OnlineCase
    raw: bytes
    candidate_bytes: bytes
    values: MappingProxyType
    unbound_bytes: bytes
    source_id: str
    path_id: str
    direction: str
    register: str
    register_offset: int
    address: int
    value: int
    declaration: MappingProxyType
    compiled_sha256: str
    layout_digest: str
    candidate_sha256: str
    case_id: str

    def document(self) -> dict:
        """The reviewable identity of this decode; no native result is claimed."""
        return {
            'schema_version': CANDIDATE_SCHEMA,
            'case_id': self.case_id,
            'path_id': self.path_id,
            'direction': self.direction,
            'source_id': self.source_id,
            'register': self.register,
            'register_offset': self.register_offset,
            'address': self.address,
            'value': self.value,
            'source_values': {key: self.values[key]
                              for key in sorted(self.values)},
            'compiled_sha256': self.compiled_sha256,
            'layout_digest': self.layout_digest,
            'candidate_sha256': self.candidate_sha256,
            'candidate_bytes_hex': self.candidate_bytes.hex(),
            'wire_bytes': len(self.raw),
            'raw_sha256': sha256(self.raw).hexdigest(),
            'unbound_wire_bytes_hex': self.unbound_bytes.hex(),
            'instruction_sha256': self.declaration['code_sha256'],
            'instruction_address': self.case.source.address,
            'candidate_access': dict(self.declaration['candidate']['access']),
        }


def compiled_document_sha256(compiled) -> str:
    """Canonical digest of the whole compiled document the decoder consumes."""
    if not isinstance(compiled, dict):
        raise ValueError('compiled-document-required')
    try:
        encoded = json.dumps(compiled, sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, RecursionError) as error:
        raise ValueError('compiled-document-not-json') from error
    return sha256(encoded.encode('utf-8')).hexdigest()


def _layout_document(layout: CandidateLayout) -> dict:
    from dataclasses import asdict

    return {
        'schema_version': LAYOUT_SCHEMA,
        'digest': layout.digest,
        'byte_length': layout.byte_length,
        'bit_length': layout.bit_length,
        'derived_image_source_id': layout.derived_image_source_id,
        'slices': [asdict(row) for row in layout.slices],
    }


def project_wire_record(layout: CandidateLayout, raw, *,
                        wire_bytes: int = WIRE_RECORD_BYTES) -> CompiledProjection:
    """Project one exact wire record onto the declared candidate layout.

    The layout's own ``decode`` is the only value validator: it enforces the
    source width, mask, range, alignment, padding and source set.  This function
    only supplies the exact declared byte prefix and records the unreferenced
    transport lanes; it never pads or widens the candidate.
    """
    if not isinstance(layout, CandidateLayout):
        raise CompiledCandidateRefused('layout-required')
    if type(wire_bytes) is not int or wire_bytes != WIRE_RECORD_BYTES:
        raise CompiledCandidateRefused('wire-record-size-unsupported')
    if layout.byte_length > wire_bytes:
        raise CompiledCandidateRefused('layout-wider-than-wire',
                                       detail={'layout_bytes': layout.byte_length,
                                               'wire_bytes': wire_bytes})
    if type(raw) is not bytes:
        raise CompiledCandidateRefused('record-type')
    if len(raw) != wire_bytes:
        raise CompiledCandidateRefused(
            'record-length', detail={'observed': len(raw), 'required': wire_bytes})
    candidate = raw[:layout.byte_length]
    try:
        values = layout.decode(candidate)
    except CandidateLayoutError as error:
        raise CompiledCandidateRefused(
            error.code, error.pointer,
            {'layout_digest': layout.digest,
             'candidate_bytes_hex': candidate.hex()}) from error
    return CompiledProjection(candidate, MappingProxyType(dict(values)),
                              raw[layout.byte_length:])


class CompiledOnlineDecoder:
    """One admitted F4 path's exact raw-record decoder.

    Construction is deliberately separate from a runtime runner: it only
    consumes declarations.  ``from_request`` recompiles D3 from the typed
    compile request and refuses any edited compiled document; ``from_runtime``
    prefers the runtime's own already-issued layout object and checks it is the
    same object that ``compile_candidate_layout`` issues now, so a copied or
    stale layout can never be consumed.
    """

    def __init__(self, *, request, compiled, path, layout, run_id, cpu_id,
                 schedule, rounds, instruction_start, instruction_end,
                 result_address, compiled_sha256=None, cursor_provider=None):
        if not isinstance(compiled, dict) or not isinstance(path, dict):
            raise CompiledCandidateRefused('declaration-required')
        if not isinstance(layout, CandidateLayout):
            raise CompiledCandidateRefused('layout-required')
        issued = compile_candidate_layout(path)
        if layout.digest != issued.digest or layout != issued:
            raise CompiledCandidateRefused(
                'layout-not-issued-for-path',
                detail={'observed': layout.digest, 'issued': issued.digest})
        if layout.byte_length > WIRE_RECORD_BYTES:
            raise CompiledCandidateRefused(
                'compiled-layout-wider-than-wire',
                detail={'layout_bytes': layout.byte_length,
                        'wire_bytes': WIRE_RECORD_BYTES})
        executable = [row for row in compiled.get('paths', ())
                      if row.get('flow_id') == 'F4'
                      and row.get('status') == 'executable']
        if len(executable) != 1:
            raise CompiledCandidateRefused('f4-executable-path-required')
        if executable[0] != path:
            raise CompiledCandidateRefused('compiled-path-mismatch',
                                           detail={'path_id': path.get('path_id')})
        digest = compiled_document_sha256(compiled)
        if compiled_sha256 is not None and compiled_sha256 != digest:
            raise CompiledCandidateRefused(
                'compiled-digest-mismatch',
                detail={'declared': compiled_sha256, 'actual': digest})
        sources = path.get('sources')
        streams = [row for row in sources if row.get('kind') == 'cpu_mmio_stream']
        images = [row for row in sources if row.get('kind') == 'instruction_image']
        if len(streams) != 1 or len(images) != 1:
            raise CompiledCandidateRefused('f4-source-shape-unsupported')
        if path.get('direction') not in ('CPU_TO_IP',):
            raise CompiledCandidateRefused('f4-direction-unsupported')
        if type(run_id) is not str or not run_id:
            raise CompiledCandidateRefused('run-id-required')
        if type(cpu_id) is not str or not cpu_id:
            raise CompiledCandidateRefused('cpu-identity-required')
        if (not isinstance(schedule, tuple) or not schedule
                or any(type(name) is not str or not name for name in schedule)
                or len(set(schedule)) != len(schedule) or cpu_id not in schedule):
            raise CompiledCandidateRefused('schedule-invalid')
        if type(rounds) is not int or not 1 <= rounds <= 4096:
            raise CompiledCandidateRefused('rounds-invalid')
        if any(type(value) is not int or value < 0 or value % 4
               for value in (instruction_start, instruction_end, result_address)):
            raise CompiledCandidateRefused('instruction-reservation-invalid')
        if not (instruction_start <= result_address
                <= instruction_end <= 1 << 32):
            raise CompiledCandidateRefused('instruction-reservation-invalid')
        self.request = request
        self.compiled = compiled
        self.path = path
        self.layout = layout
        self.run_id = run_id
        self.cpu_id = cpu_id
        self.schedule = schedule
        self.rounds = rounds
        self.instruction_start = instruction_start
        self.instruction_end = instruction_end
        self.result_address = result_address
        self.compiled_sha256 = digest
        self.path_id = path['path_id']
        self.direction = path['direction']
        self.stream = streams[0]
        self.image = images[0]
        self.source_id = streams[0]['source_id']
        self.register = streams[0].get('register')
        self.register_offset = streams[0].get('register_access', {}).get(
            'register_offset')
        self.address = streams[0].get('register_access', {}).get('address')
        self.candidate_bytes = layout.byte_length
        self.wire_bytes = WIRE_RECORD_BYTES
        self.unbound_bytes = self.wire_bytes - self.candidate_bytes
        self.max_input_bytes = self.wire_bytes
        self.max_records = 1
        self._cursor_provider = cursor_provider

    @classmethod
    def from_request(cls, *, request, compiled, path, run_id, cpu_id, schedule,
                     rounds, instruction_start, instruction_end, result_address,
                     compiled_sha256=None, cursor_provider=None):
        """Recompile D3 from the trusted request, then bind its exact layout."""
        from myfuzz.scenario.compiled_paths import compile_paths

        try:
            recompiled = compile_paths(request)
        except Exception as error:
            raise CompiledCandidateRefused(
                'compiled-document-recompilation-failed',
                detail={'error_type': type(error).__name__, 'error': str(error)}
            ) from error
        if recompiled != compiled:
            raise CompiledCandidateRefused('compiled-document-mismatch')
        layout = compile_candidate_layout(path)
        return cls(request=request, compiled=compiled, path=path, layout=layout,
                   run_id=run_id, cpu_id=cpu_id, schedule=schedule,
                   rounds=rounds, instruction_start=instruction_start,
                   instruction_end=instruction_end,
                   result_address=result_address,
                   compiled_sha256=compiled_sha256,
                   cursor_provider=cursor_provider)

    @classmethod
    def from_runtime(cls, runtime, *, run_id=None):
        """Bind the runtime's already-issued layout object, never a copy."""
        if getattr(runtime, 'layout', None) is None or getattr(runtime, 'path', None) is None:
            raise CompiledCandidateRefused('runtime-layout-required')
        if getattr(runtime, 'inputs', None) is None:
            raise CompiledCandidateRefused('runtime-inputs-required')
        request = runtime.inputs['request']
        compiled = runtime.inputs['compiled']
        schedule = tuple(runtime.runner.sessions)
        return cls.from_request(
            request=request, compiled=compiled, path=runtime.path,
            run_id=runtime.run_id if run_id is None else run_id,
            cpu_id=runtime.cpu_id, schedule=schedule, rounds=runtime.rounds,
            instruction_start=runtime.start,
            instruction_end=runtime.end,
            result_address=runtime.result,
            compiled_sha256=runtime.compiled_digest,
            cursor_provider=lambda: runtime.cursor)

    def verify(self) -> None:
        """Refuse a stale, edited or replaced declaration before a decode."""
        issued = compile_candidate_layout(self.path)
        if self.layout != issued or self.layout.digest != issued.digest:
            raise CompiledCandidateRefused('layout-identity-changed')
        executable = [row for row in self.compiled.get('paths', ())
                      if row.get('flow_id') == 'F4'
                      and row.get('status') == 'executable']
        if len(executable) != 1 or executable[0] != self.path:
            raise CompiledCandidateRefused('compiled-path-identity-changed')
        if compiled_document_sha256(self.compiled) != self.compiled_sha256:
            raise CompiledCandidateRefused('compiled-digest-identity-changed')

    def decode_candidate(self, raw, *, cursor, case_index, case_id=None
                         ) -> CompiledCandidate:
        """Decode one raw record into the exact declared candidate."""
        self.verify()
        if type(cursor) is not int or cursor % 4:
            raise CompiledCandidateRefused('cursor-invalid')
        if not self.instruction_start <= cursor < self.instruction_end:
            raise CompiledCandidateRefused('cursor-outside-image')
        if self._cursor_provider is not None and cursor != self._cursor_provider():
            raise CompiledCandidateRefused('cursor-not-the-declared-cursor',
                                           detail={'cursor': cursor})
        if type(case_index) is not int or case_index < 0:
            raise CompiledCandidateRefused('case-index-invalid')
        projection = project_wire_record(self.layout, raw,
                                         wire_bytes=self.wire_bytes)
        value = projection.values[self.source_id]
        declaration = declare_writer(
            self.request, self.compiled, source_id=self.source_id, value=value,
            result_address=self.result_address)
        code = bytes.fromhex(declaration['code_hex'])
        if cursor + len(code) > self.result_address:
            raise CompiledCandidateRefused(
                'slot-budget-exhausted',
                detail={'cursor': cursor, 'instruction_bytes': len(code),
                        'result_address': self.result_address})
        identity = f'{self.run_id}:{case_index}' if case_id is None else case_id
        case = OnlineCase(
            identity, self.direction, self.path_id,
            OnlineInstruction(f'{self.image["source_id"]}:{case_index}',
                              self.cpu_id, cursor, code.hex()),
            tuple(BatchAdvance(self.schedule) for _ in range(self.rounds)))
        access = declaration['candidate']['access']
        return CompiledCandidate(
            case=case, raw=raw,
            candidate_bytes=projection.candidate_bytes,
            values=projection.values, unbound_bytes=projection.unbound_bytes,
            source_id=self.source_id, path_id=self.path_id,
            direction=self.direction, register=access['register'],
            register_offset=access['register_offset'], address=access['address'],
            value=value, declaration=MappingProxyType(dict(declaration)),
            compiled_sha256=self.compiled_sha256,
            layout_digest=self.layout.digest,
            candidate_sha256=sha256(projection.candidate_bytes).hexdigest(),
            case_id=identity)

    def document(self) -> dict:
        """Stable decoder manifest; it declares no runtime-path contract."""
        return {
            'schema_version': DECODER_SCHEMA,
            'path_id': self.path_id,
            'flow_id': 'F4',
            'direction': self.direction,
            'source_id': self.source_id,
            'register': self.register,
            'register_offset': self.register_offset,
            'address': self.address,
            'compiled_sha256': self.compiled_sha256,
            'candidate_layout': _layout_document(self.layout),
            'candidate_bytes': self.candidate_bytes,
            'wire_record_bytes': self.wire_bytes,
            'unbound_wire_bytes': self.unbound_bytes,
            'unbound_lane_semantics': (
                'bytes after layout.byte_length are transport lanes the '
                'compiled layout does not reference; they never reach the RTL'),
            'source_values': [row.source_id for row in self.layout.slices],
            'sources': [{'source_id': row.source_id, 'kind': row.kind,
                         'component': row.component,
                         'endpoint_id': row.endpoint_id,
                         'port': row.port, 'width': row.width,
                         'mask': row.mask, 'minimum': row.minimum,
                         'maximum': row.maximum, 'alignment': row.alignment}
                        for row in self.layout.slices],
            'instruction_source_id': self.image['source_id'],
            'instruction_address_range': [self.instruction_start,
                                          self.result_address],
            'max_input_bytes': self.wire_bytes,
            'max_records': 1,
            'from_document_replay_only': False,
            'trusted_for_search': True,
            'runtime_contract': None,
        }
