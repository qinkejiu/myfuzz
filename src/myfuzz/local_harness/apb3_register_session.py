"""Component-neutral persistent APB3 register and pin-observation session."""
from __future__ import annotations

from collections import deque
from collections.abc import Mapping

from .session import GeneratedLocalSession


class GeneratedApb3RegisterSession(GeneratedLocalSession):
    artifact_kind = 'apb3_register_observe'

    def __init__(self, artifact, *, base_dir, cache_dir, setup_writes=(),
                 probe_offsets=(), **kwargs):
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir, **kwargs)
        if self._expected_ready()[3] != self.artifact_kind:
            raise ValueError('generic APB3 register artifact required')
        window = artifact.plan.profile.address.window_size
        def offset_ok(value):
            return type(value) is int and 0 <= value < window and value % 4 == 0
        if (type(setup_writes) is not tuple or len(setup_writes) > 16 or
                any(type(row) is not tuple or len(row) != 2 or not offset_ok(row[0]) or
                    type(row[1]) is not int or not 0 <= row[1] <= 0xffffffff
                    for row in setup_writes) or
                type(probe_offsets) is not tuple or len(probe_offsets) > 16 or
                any(not offset_ok(offset) for offset in probe_offsets)):
            raise ValueError('invalid generic APB3 register scenario')
        self.setup_writes = setup_writes
        self.probe_offsets = probe_offsets
        self._window = window
        self._started = False
        self._samples = deque()
        self.local_transactions = []
        self._dynamic = {}
        for index, row in enumerate(artifact.runtime_document['dynamic_physical_inputs']):
            name = row['input_name']
            if name in self._dynamic or not 1 <= row['width'] <= 64:
                raise ValueError('invalid generic APB3 dynamic input')
            self._dynamic[name] = (index, row['width'], row['source_id'])
        self._dynamic_values = {name: 0 for name in self._dynamic}
        self._bound = {}
        for index, row in enumerate(artifact.runtime_document['bound_physical_inputs']):
            name = row['input_name']
            if name in self._dynamic or name in self._bound or not 1 <= row['width'] <= 64:
                raise ValueError('invalid generic APB3 bound input')
            self._bound[name] = (index, row['width'], row['producer_ref'])
        self._bound_values = {name: 0 for name in self._bound}
        self._outputs = {}
        for row in artifact.runtime_document['physical_exports']:
            if row['direction'] != 'output':
                continue
            name = row['physical_port']
            if name in self._outputs:
                raise ValueError('ambiguous generic APB3 physical observation')
            self._outputs[name] = (row['runtime_name'], row['width'])
        wait = artifact.runtime_document['effective_max_wait_cycles']
        self.max_local_ticks_per_register_access = 2 * wait + 5
        self.max_local_ticks_per_step = 1 + len(self._dynamic) + len(self._bound) + (
            len(setup_writes) + len(probe_offsets)) * self.max_local_ticks_per_register_access

    def identity_document(self):
        return {**super().identity_document(),
                'apb3_register_service_schema_version': 'generated_apb3_register_observe.v1',
                'setup_writes': [list(row) for row in self.setup_writes],
                'probe_offsets': list(self.probe_offsets),
                'dynamic_input_initial_policy': 'zero_until_first_source_event',
                'bound_input_initial_policy': 'zero_until_first_real_output'}

    def validate_scenario_ownership(self, component_id, ownership):
        """Require the ScenarioRunner's bit owners to match this physical ABI."""
        document = ownership.document()
        fields = {row['port']: row['width'] for row in document['fields']
                  if row['component_id'] == component_id}
        expected = {row['input_name']: row for row in
                    self.artifact.runtime_document['dynamic_physical_inputs']}
        bound = {row['input_name']: row for row in
                 self.artifact.runtime_document['bound_physical_inputs']}
        fixed = {row['endpoint_id'] + '.' + row['role'] for row in
                 self.artifact.runtime_document['fixed_physical_inputs']}
        if (set(fields) - set(expected) - set(bound) - fixed or
                set(expected) - set(fields) or set(bound) - set(fields)):
            raise ValueError('generic APB3 scenario ownership fields mismatch physical inputs')
        for name, width in fields.items():
            expected_width = (expected[name]['width'] if name in expected else
                              bound[name]['width'] if name in bound else next(
                row['width'] for row in self.artifact.runtime_document['fixed_physical_inputs']
                if row['endpoint_id'] + '.' + row['role'] == name))
            if width != expected_width:
                raise ValueError('generic APB3 scenario ownership width mismatch')
            bits = [None] * width
            for owner in document['owners']:
                if owner['component_id'] != component_id or owner['port'] != name:
                    continue
                kind = 'source' if name in expected else 'bound' if name in bound else 'fixed'
                identity = (expected[name]['source_id'] if name in expected else
                            bound[name]['producer_ref'] if name in bound else None)
                if (owner['kind'] != kind or identity is not None and
                        owner['producer_ref'] != identity):
                    raise ValueError('generic APB3 source identity or fixed ownership mismatch')
                for bit in range(owner['bit_offset'], owner['bit_offset'] + owner['width']):
                    if bit >= width or bits[bit] is not None:
                        raise ValueError('generic APB3 overlapping scenario input ownership')
                    bits[bit] = owner['producer_ref']
            if any(bit is None for bit in bits):
                raise ValueError('generic APB3 incomplete scenario input ownership')

    def validate_scenario_bindings(self, component_id, bindings):
        """A declared bound field needs one whole-field real output route."""
        for row in bindings:
            if row.source_component == component_id:
                observed = self._outputs.get(row.source_port)
                if observed is None or row.source_bit_offset + row.width > observed[1]:
                    raise ValueError('generic APB3 route source is not an observed RTL output')
        for name, (_, width, producer_ref) in self._bound.items():
            routes = [row for row in bindings if row.target_component == component_id
                      and row.target_port == name]
            if (len(routes) != 1 or routes[0].target_bit_offset != 0 or
                    routes[0].width != width or
                    f'{routes[0].source_component}.{routes[0].source_port}' != producer_ref):
                raise ValueError('generic APB3 bound input lacks exact real output route')

    def begin_case(self, testcase_id):
        super().begin_case(testcase_id)
        self._started = False
        self._samples.clear()
        self.local_transactions.clear()
        self._dynamic_values = {name: 0 for name in self._dynamic}
        self._bound_values = {name: 0 for name in self._bound}

    @property
    def pending_responses(self):
        return 0

    @property
    def routed_input_names(self):
        return frozenset(self._bound)

    @property
    def pending_events(self):
        return 0

    def begin_quiesce(self):
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('generic APB3 process is not running')

    def max_transaction_events_for_step(self, inputs):
        return 0 if self._started else len(self.setup_writes) + len(self.probe_offsets)

    def _take(self, reply, *, step=False):
        if reply.status != 'result' or reply.payload is None:
            raise RuntimeError('generic APB3 transport error: ' + str(reply.error_code))
        payload = reply.payload
        samples = payload['samples']
        if (not 1 <= len(samples) <= self.max_local_ticks_per_register_access or
                step and len(samples) != 1 or len(self._samples) + len(samples) > 65536):
            raise ValueError('invalid generic APB3 tick evidence')
        for sample in samples:
            phases = {}
            for phase in ('pre', 'post'):
                observed = dict(sample[phase])
                physical_sample = observed['physical']
                for name, (runtime_name, width) in self._outputs.items():
                    value = physical_sample[runtime_name]
                    if width > 64 and type(value) is str:
                        value = int(value, 16)
                    if type(value) is not int or not 0 <= value < 1 << width:
                        raise ValueError('invalid generic APB3 tick output: ' + name)
                    observed[name] = value
                phases[phase] = observed
            self._samples.append({**sample, **phases,
                                  'local_tick': self._tick_base + sample['local_tick']})
        physical = payload['observations']['physical']
        observations = {}
        for name, (runtime_name, width) in self._outputs.items():
            value = physical[runtime_name]
            if width > 64 and type(value) is str:
                value = int(value, 16)
            if type(value) is not int or not 0 <= value < 1 << width:
                raise ValueError('invalid generic APB3 physical observation: ' + name)
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
                type(be) is not int or be != 15):
            raise ValueError('invalid generic APB3 access')
        result = self._take(self.command('ACCESS_APB3_REG', (int(write), offset, value, be)))
        if result['error']:
            raise RuntimeError(f'real APB3 error at offset {offset:#x}')
        return result['rdata']

    def write_register(self, offset, value, *, be=15):
        self._access(True, offset, value, be)

    def read_register(self, offset):
        return self._access(False, offset)

    def step_local(self, inputs: Mapping[str, int]):
        return self._step_with_inputs(inputs, {})

    def step_local_routed(self, source_inputs: Mapping[str, int],
                          bound_inputs: Mapping[str, int]):
        """ScenarioRunner supplies only values captured from declared real bindings."""
        return self._step_with_inputs(source_inputs, bound_inputs)

    def _step_with_inputs(self, inputs: Mapping[str, int], bound_inputs: Mapping[str, int]):
        if not isinstance(inputs, Mapping) or set(inputs) - set(self._dynamic):
            raise ValueError('generic APB3 undeclared or fixed input cannot be overwritten')
        if not isinstance(bound_inputs, Mapping) or set(bound_inputs) - set(self._bound):
            raise ValueError('generic APB3 undeclared routed bound input')
        for name, value in inputs.items():
            _, width, _ = self._dynamic[name]
            if type(value) is not int or not 0 <= value < 1 << width:
                raise ValueError('generic APB3 dynamic source value exceeds physical width')
        for name, value in bound_inputs.items():
            _, width, _ = self._bound[name]
            if type(value) is not int or not 0 <= value < 1 << width:
                raise ValueError('generic APB3 routed bound value exceeds physical width')
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
        for name in sorted(inputs):
            value = inputs[name]
            if self._dynamic_values[name] != value:
                index, _, _ = self._dynamic[name]
                self._take(self.command('SOURCE_APB3_REG', (index, value)))
                self._dynamic_values[name] = value
        for name in sorted(bound_inputs):
            value = bound_inputs[name]
            if self._bound_values[name] != value:
                index, _, _ = self._bound[name]
                self._take(self.command('BIND_APB3_REG', (index, value)))
                self._bound_values[name] = value
        return {**self._take(self.command('STEP_APB3_REG', ()), step=True), **probes}

    def reset_local(self):
        result = super().reset_local()
        self._started = False
        self._samples.clear()
        self.local_transactions.clear()
        self._dynamic_values = {name: 0 for name in self._dynamic}
        self._bound_values = {name: 0 for name in self._bound}
        return result
