"""Persistent, isolated BOOM RTL simulation with one measured rising edge per step.

This is a coherent RAM simulation, not an admitted generic CPU/router artifact.
"""
from __future__ import annotations

import fcntl
import json
from collections.abc import Mapping
from pathlib import Path
import subprocess
import time
import uuid
import tempfile

from myfuzz.scenario.protocol_io import (
    BoundedLineReader, command_deadline, end_local_process, write_local_command, _deadline,
)
from .tilelink_coherent_cpu_session import digest
from .boom_irq_generation import generate_irq, AUXILIARY, generated_symbol_files
from .boom_irq_contract import validate_probe_inventory, validate_probe_values, validate_irq_inputs


class GeneratedBoomIrqCpuSession:
    """Keep one real Verilated BoomTile process alive across bounded commands.

    Reset creates a fresh CPU and manager; memory must be loaded again. Program
    bytes are not silently rewritten after execution starts. Cached memory is
    internal to the native coherent manager; an optional uncached address range
    permits an external scheduler to complete accepted single-beat Get/Put.
    """
    artifact_kind = 'tilelink_coherent_cpu_irq'
    max_transaction_events_per_step = 4
    max_local_ticks_per_step = 1
    max_mmio_target_accesses_per_step = 0

    def __init__(self, output: Path, *, repo: Path, command_timeout_seconds: float = 10.0,
                 external_range: tuple[int, int] | None = None):
        if not 0 < command_timeout_seconds < float('inf'):
            raise ValueError('command timeout must be finite and positive')
        self.output = output.resolve()
        self.artifact = json.loads((self.output / 'irq-session-artifact.json').read_text())
        if self.artifact.get('schema_version') != 'generated_boom_irq_session.v1':
            raise ValueError('BOOM persistent session artifact required')
        # Re-run the canonical source/port authentication independently of the
        # mutable build artifact. A local executable hash is integrity evidence,
        # not signed build provenance or generic runtime admission.
        with tempfile.TemporaryDirectory(prefix='boom-source-check-') as temporary:
            expected = generate_irq(repo, Path(temporary))
            expected_aux = {name:digest(Path(temporary)/name) for name in AUXILIARY}
            expected_source_files = {
                Path(argument).name: digest(Path(argument))
                for argument in expected['command'] if argument.endswith('.v')}
            expected_source_files['tl_ram.h'] = expected['manager_sha256']
        for key in ('source_revision', 'source_manifest_sha256', 'profile_sha256',
                    'manager_sha256', 'trace_verifier_sha256', 'driver_sha256',
                    'scenario_factory_sha256', 'base_profile_sha256'):
            if self.artifact.get(key) != expected[key]:
                raise ValueError('BOOM authenticated source identity mismatch')
        if self.artifact.get('implementation_source_hashes') != expected['implementation_source_hashes']:
            raise ValueError('BOOM IRQ implementation identity mismatch')
        if self.artifact.get('auxiliary_hashes') != expected_aux:
            raise ValueError('BOOM IRQ auxiliary identity mismatch')
        if self.artifact.get('probes_runtime_confirmed') is not True:
            raise ValueError('actual generated BOOM IRQ probes were not confirmed')
        validate_probe_inventory(self.artifact.get('generated_probes'))
        if json.loads((self.output/'generated-probes.json').read_text()) != self.artifact['generated_probes']:
            raise ValueError('BOOM probe descriptor crosslink mismatch')
        if self.artifact['session_files'].get('driver.cpp') != self.artifact['driver_sha256']:
            raise ValueError('BOOM driver closure mismatch')
        expected_source_files.update(expected_aux)
        symbols = generated_symbol_files(self.output)
        if self.artifact.get('generated_symbol_files') != list(symbols):
            raise ValueError('BOOM generated registry layout crosslink mismatch')
        expected_file_set = {*expected_source_files, 'driver.cpp', 'obj/VBoomTile',
                             *symbols, 'generated-probes.json'}
        if set(self.artifact['session_files']) != expected_file_set:
            raise ValueError('BOOM session manifest file set mismatch')
        for name, expected_hash in expected_source_files.items():
            if self.artifact['session_files'][name] != expected_hash:
                raise ValueError('BOOM session authenticated source closure mismatch')
        self.timeout = command_timeout_seconds
        self.external_range = external_range
        if external_range is not None:
            lo, hi = external_range
            if type(lo) is not int or type(hi) is not int or not 0x4000 <= lo < hi <= 0x5000:
                raise ValueError('invalid external range')
        self.reset_epoch = 0
        self._case_id = None
        self._process = None
        self.last_samples = ()
        self._start()

    def _start(self):
        for name, expected in self.artifact['session_files'].items():
            path = (self.output / name).resolve()
            if not path.is_relative_to(self.output) or digest(path) != expected:
                raise ValueError('BOOM session artifact file mismatch')
        self._reader = BoundedLineReader()
        self._process = subprocess.Popen([str(self.output / 'obj/VBoomTile')],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1)
        self.execution_id = str(uuid.uuid4())
        self.ticks = 0
        self._request_sequence = 0
        self._drained = True
        self._external_pending = None
        self._external_response_submitted = False
        try:
            with command_deadline(self._bounded_deadline()):
                ready = self._read()
            if not isinstance(ready,dict) or set(ready) != {'ready','probes'} or ready['ready'] is not True:
                raise RuntimeError('BOOM IRQ session did not become ready')
            validate_probe_inventory(ready['probes'])
            if ready['probes'] != self.artifact['generated_probes']:
                raise RuntimeError('BOOM generated probe inventory changed')
            if self.external_range is not None:
                self._command('EXTERNAL', *self.external_range)
        except BaseException:
            self.close()
            raise

    def _bounded_deadline(self):
        deadline = time.monotonic() + self.timeout
        enclosing = _deadline.get()
        return deadline if enclosing is None else min(deadline, enclosing)

    def _read(self):
        return json.loads(self._reader.readline(self._process.stdout))

    def _command(self, operation, *args):
        if self._process is None:
            raise RuntimeError('BOOM session is closed')
        try:
            with command_deadline(self._bounded_deadline()):
                write_local_command(self._process.stdin,
                                    ' '.join(map(str, (operation, *args))) + '\n')
                return self._read()
        except BaseException:
            self.close()
            raise

    def identity_document(self):
        return {**self.artifact, 'transaction_execution_identity': 'native_session',
                'external_range': self.external_range, 'execution_id': self.execution_id,
                'reset_epoch': self.reset_epoch, 'generic_router_admitted': False}

    def begin_case(self, testcase_id: str):
        if not isinstance(testcase_id, str) or not testcase_id:
            raise ValueError('testcase identity required')
        self.reset_local()
        self._case_id = testcase_id

    @property
    def pending_responses(self):
        return int(not self._drained)

    def reset_local(self):
        cancelled = self.pending_responses
        cancelled_targets = (() if self._external_pending is None else
            ((self.execution_id, self.reset_epoch,
              self._external_pending['request_sequence']),))
        self.close()
        self.reset_epoch += 1
        self.last_samples = ()
        self._start()
        return {'cancelled_responses': cancelled, 'cancelled_target_requests': cancelled_targets}

    def load_program(self, data: bytes, *, address: int = 0x80000000):
        if self.ticks:
            raise RuntimeError('load program before stepping the CPU')
        if not isinstance(data, bytes) or type(address) is not int or not 0 <= address <= (1 << 32) - len(data):
            raise ValueError('invalid BOOM program bytes/address')
        if not 0x80000000 <= address <= address + len(data) <= 0x100000000:
            raise ValueError('program must fit the pinned RAM window')
        for offset, value in enumerate(data):
            self._command('LOAD', address + offset, value)

    def read64(self, address: int) -> int:
        if type(address) is not int or not 0 <= address <= 0xfffffff8:
            raise ValueError('invalid memory address')
        return self._command('READ', address)['value']

    def begin_quiesce(self):
        self._command('QUIESCE')

    def respond_external(self, *, source: int, size: int, request_sequence: int,
                         reset_epoch: int, data: int = 0):
        request = self._external_pending
        if (type(source) is not int or type(size) is not int
                or type(request_sequence) is not int or type(reset_epoch) is not int
                or request is None or self._external_response_submitted
                or reset_epoch != self.reset_epoch
                or request_sequence != request['request_sequence']
                or source != request['source'] or size != request['size']
                or type(data) is not int or not 0 <= data < 1 << 64):
            raise ValueError('external response does not match accepted request')
        self._command('RESPOND', source, size, data)
        self._external_response_submitted = True

    def step_local(self, inputs: Mapping[str, int]):
        irq = validate_irq_inputs(inputs)
        payload = self._command('STEP_IRQ', irq)
        if (payload.get('kind') != self.artifact_kind or payload.get('new_ticks') != 1
                or payload.get('cycle') != self.ticks + 1
                or type(payload.get('drained')) is not bool
                or type(payload.get('reset')) is not bool
                or not isinstance(payload.get('events'), list)
                or len(payload['events']) > 4):
            self.close()
            raise RuntimeError('invalid BOOM one-edge receipt')
        try:
            validate_probe_values(payload.get('probes_pre'))
            validate_probe_values(payload.get('probes_post'))
            if (type(payload.get('irq_input')) is not int or payload['irq_input'] != irq
                    or payload['probes_pre']['meip'] != irq or payload['probes_post']['meip'] != irq):
                raise ValueError('actual BOOM MEIP input/connection mismatch')
        except BaseException:
            self.close()
            raise
        self.ticks += 1
        self._drained = payload['drained']
        self.last_samples = (payload,)
        for event in payload['events']:
            if event['channel'] == 'D' and event.get('external'):
                self._external_pending = None
                self._external_response_submitted = False
            if event['channel'] == 'A' and self.external_range is not None:
                lo, hi = self.external_range
                if lo <= event['address'] < hi:
                    self._request_sequence += 1
                    self._external_pending = dict(event, request_sequence=self._request_sequence,
                                                  reset_epoch=self.reset_epoch)
        return {'accepted_events': tuple(payload['events']),
                'external_request': None if self._external_pending is None else dict(self._external_pending),
                'driver_samples': self.last_samples, 'reset': payload['reset'],
                'drained': self._drained, 'probes_pre': payload['probes_pre'],
                'probes_post': payload['probes_post'], 'irq_input': payload['irq_input']}

    def close(self):
        if self._process is not None:
            end_local_process(self._process)
            self._process = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
