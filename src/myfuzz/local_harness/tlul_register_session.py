"""Component-neutral persistent TL-UL register and pin-observation session."""
from __future__ import annotations

from collections import deque
from collections.abc import Mapping

from .session import GeneratedLocalSession


class GeneratedTlulRegisterSession(GeneratedLocalSession):
    artifact_kind = 'tlul_register_observe'

    def __init__(self, artifact, *, base_dir, cache_dir, setup_writes=(),
                 probe_offsets=(), **kwargs):
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir, **kwargs)
        if self._expected_ready()[3] != self.artifact_kind:
            raise ValueError('generic TL-UL register artifact required')
        window = artifact.plan.profile.address.window_size
        def offset_ok(value):
            return type(value) is int and 0 <= value < window and value % 4 == 0
        if (type(setup_writes) is not tuple or len(setup_writes) > 16 or
                any(type(row) is not tuple or len(row) != 2 or not offset_ok(row[0]) or
                    type(row[1]) is not int or not 0 <= row[1] <= 0xffffffff
                    for row in setup_writes) or
                type(probe_offsets) is not tuple or len(probe_offsets) > 16 or
                any(not offset_ok(offset) for offset in probe_offsets)):
            raise ValueError('invalid generic TL-UL register scenario')
        self.setup_writes = setup_writes
        self.probe_offsets = probe_offsets
        self._window = window
        self._started = False
        self._samples = deque()
        self.local_transactions = []
        self._outputs = {}
        for row in artifact.runtime_document['physical_exports']:
            if row['direction'] != 'output':
                continue
            name = row['physical_port']
            if name in self._outputs:
                raise ValueError('ambiguous generic TL-UL physical observation')
            self._outputs[name] = (row['runtime_name'], row['width'])
        wait = artifact.runtime_document['effective_max_wait_cycles']
        self.max_local_ticks_per_register_access = 2 * wait + 5
        self.max_local_ticks_per_step = 1 + (
            len(setup_writes) + len(probe_offsets)) * self.max_local_ticks_per_register_access

    def identity_document(self):
        return {**super().identity_document(),
                'tlul_register_service_schema_version': 'generated_tlul_register_observe.v1',
                'setup_writes': [list(row) for row in self.setup_writes],
                'probe_offsets': list(self.probe_offsets)}

    def begin_case(self, testcase_id):
        super().begin_case(testcase_id)
        self._started = False
        self._samples.clear()
        self.local_transactions.clear()

    @property
    def pending_responses(self):
        return 0

    @property
    def pending_events(self):
        return 0

    def begin_quiesce(self):
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('generic TL-UL process is not running')

    def max_transaction_events_for_step(self, inputs):
        return 0 if self._started else len(self.setup_writes) + len(self.probe_offsets)

    def _take(self, reply, *, step=False):
        if reply.status != 'result' or reply.payload is None:
            raise RuntimeError('generic TL-UL transport error: ' + str(reply.error_code))
        payload = reply.payload
        samples = payload['samples']
        if (not 1 <= len(samples) <= self.max_local_ticks_per_register_access or
                step and len(samples) != 1 or len(self._samples) + len(samples) > 65536):
            raise ValueError('invalid generic TL-UL tick evidence')
        for sample in samples:
            self._samples.append({**sample, 'local_tick': self._tick_base + sample['local_tick']})
        physical = payload['observations']['physical']
        observations = {}
        for name, (runtime_name, width) in self._outputs.items():
            value = physical[runtime_name]
            if width > 64 and type(value) is str:
                value = int(value, 16)
            if type(value) is not int or not 0 <= value < 1 << width:
                raise ValueError('invalid generic TL-UL physical observation: ' + name)
            observations[name] = value
        observations['rdata'] = payload['rdata']
        observations['error'] = payload['error']
        return observations

    def drain_tick_samples(self):
        samples = list(self._samples)
        self._samples.clear()
        return samples

    def _access(self, write, offset, value=0, be=15):
        if (type(offset) is not int or offset % 4 or not 0 <= offset < self._window or
                type(value) is not int or not 0 <= value <= 0xffffffff or
                type(be) is not int or not 0 <= be <= 15):
            raise ValueError('invalid generic TL-UL access')
        result = self._take(self.command('ACCESS_TLUL_REG', (int(write), offset, value, be)))
        if result['error']:
            raise RuntimeError(f'real TL-UL error at offset {offset:#x}')
        return result['rdata']

    def write_register(self, offset, value, *, be=15):
        self._access(True, offset, value, be)

    def read_register(self, offset):
        return self._access(False, offset)

    def step_local(self, inputs: Mapping[str, int]):
        if not isinstance(inputs, Mapping) or inputs:
            raise ValueError('generic TL-UL fixed inputs cannot be overwritten')
        probes = {}
        if not self._started:
            self._started = True
            for offset, value in self.setup_writes:
                self.write_register(offset, value)
                self.local_transactions.append(dict(offset=offset, write=True,
                    write_value=value, byte_enable=15))
            for offset in self.probe_offsets:
                read_value = self.read_register(offset)
                self.local_transactions.append(dict(offset=offset, write=False,
                    read_value=read_value))
                probes[f'reg_{offset:03x}'] = read_value
        return {**self._take(self.command('STEP_TLUL_REG', ()), step=True), **probes}

    def reset_local(self):
        result = super().reset_local()
        self._started = False
        self._samples.clear()
        self.local_transactions.clear()
        return result
