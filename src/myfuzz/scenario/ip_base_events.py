"""Component-neutral events derived from immutable local raw observations."""
from __future__ import annotations

from collections.abc import Mapping, Sequence


_SCHEMA_VERSION = 'ip_base_event.v1'


class IpBaseEventNormalizer:
    """Project declared profile physical exports into source-linked events.

    This normalizer consumes existing ``local_tick_sample`` records. It never
    edits those records or infers a register/function meaning from a name.
    """

    def __init__(self, *, component_id: str, instance_id: str,
                 endpoint_clock_domains: Mapping[str, str],
                 physical_exports: Sequence[Mapping[str, object]],
                 bound_physical_inputs: Sequence[Mapping[str, object]] = ()):
        if (type(component_id) is not str or not component_id
                or type(instance_id) is not str or not instance_id):
            raise ValueError('base-event-component-identity-required')
        if not isinstance(endpoint_clock_domains, Mapping):
            raise ValueError('base-event-clock-domain-map-required')
        clocks = {}
        for endpoint_id, domain in endpoint_clock_domains.items():
            if (type(endpoint_id) is not str or not endpoint_id
                    or type(domain) is not str or not domain):
                raise ValueError('base-event-clock-domain-map-invalid')
            clocks[endpoint_id] = domain
        if not isinstance(physical_exports, Sequence) or isinstance(
                physical_exports, (str, bytes, bytearray)):
            raise ValueError('base-event-physical-exports-required')

        exports = []
        seen = set()
        for row in physical_exports:
            if not isinstance(row, Mapping):
                raise ValueError('base-event-physical-output-invalid')
            endpoint_id = row.get('endpoint_id')
            role = row.get('role')
            direction = row.get('direction')
            if direction not in ('input', 'output'):
                raise ValueError('base-event-physical-output-invalid')
            if endpoint_id is None and role is None:
                # Private passive probes have no declared endpoint/role and
                # remain visible only in the raw local_tick_sample record.
                continue
            if (type(endpoint_id) is not str or not endpoint_id
                    or type(role) is not str or not role
                    or type(row.get('physical_port')) is not str
                    or not row['physical_port']):
                raise ValueError('base-event-physical-output-invalid')
            runtime_name = row.get('runtime_name')
            if type(runtime_name) is not str or not runtime_name:
                raise ValueError('base-event-physical-export-runtime-name-invalid')
            low, high, width = row.get('bit_lo'), row.get('bit_hi'), row.get('width')
            if (type(low) is not int or type(high) is not int
                    or type(width) is not int or low < 0 or high < low
                    or high - low + 1 != width or width < 1):
                raise ValueError('base-event-physical-output-range-invalid')
            key = (endpoint_id, role)
            if key in seen:
                raise ValueError('base-event-physical-output-duplicate')
            seen.add(key)
            exports.append({
                'endpoint_id': endpoint_id, 'role': role,
                'physical_port': row['physical_port'], 'bit_lo': low,
                'runtime_name': runtime_name, 'width': width,
                'direction': direction,
                'clock_domain': clocks.get(endpoint_id),
                'encoding': row.get('encoding', 'integer'),
            })
        self.component_id = component_id
        self.instance_id = instance_id
        self._exports = tuple(exports)
        self._exports_by_port = {
            (export['direction'], export['physical_port']): export
            for export in exports
        }
        if (not isinstance(bound_physical_inputs, Sequence)
                or isinstance(bound_physical_inputs, (str, bytes, bytearray))):
            raise ValueError('base-event-bound-inputs-required')
        self._bound_inputs = {}
        self._bound_exports = {}
        for row in bound_physical_inputs:
            if not isinstance(row, Mapping):
                raise ValueError('base-event-bound-input-invalid')
            endpoint_id = row.get('endpoint_id')
            role = row.get('role')
            input_name = row.get('input_name')
            width = row.get('width')
            producer_ref = row.get('producer_ref')
            export = next((item for item in exports
                           if item['direction'] == 'input'
                           and item['endpoint_id'] == endpoint_id
                           and item['role'] == role), None)
            if (type(endpoint_id) is not str or not endpoint_id
                    or type(role) is not str or not role
                    or input_name != endpoint_id + '.' + role
                    or type(width) is not int or width < 1
                    or type(producer_ref) is not str or not producer_ref
                    or export is None or export['width'] != width
                    or input_name in self._bound_inputs):
                raise ValueError('base-event-bound-input-invalid')
            self._bound_inputs[input_name] = dict(row)
            self._bound_exports[input_name] = export
        self._reset_epoch: int | None = None
        self._last_values: dict[tuple[str, str, str], int] = {}
        self._binding_deliveries: dict[tuple[str, str], dict[str, object]] = {}

    def bound_input_contract(self, input_name: str) -> dict[str, object] | None:
        """Return the exact profile contract for a declared bound input."""
        if type(input_name) is not str:
            return None
        bound = self._bound_inputs.get(input_name)
        export = self._bound_exports.get(input_name)
        if bound is None or export is None:
            return None
        return {**bound, **export}

    def project_binding_delivery(self, *, event_id: int,
                                 dataflow_delivery_event_id: int,
                                 source_component: str, source_port: str,
                                 source_tick: int,
                                 source_phase: str, source_epoch: int,
                                 source_value: int, source_bit_offset: int,
                                 target: Mapping[str, object],
                                 target_value: int, target_bit_offset: int,
                                 width: int) -> dict[str, object] | None:
        """Project one explicit route from an observed profile output."""
        export = self._exports_by_port.get(('output', source_port))
        if export is None:
            return None
        if (type(event_id) is not int or event_id < 1
                or type(dataflow_delivery_event_id) is not int
                or dataflow_delivery_event_id < 1
                or type(source_component) is not str or not source_component
                or type(source_tick) is not int or source_tick < 1
                or source_phase not in ('pre', 'post')
                or type(source_epoch) is not int or source_epoch < 0
                or type(source_value) is not int or source_value < 0
                or type(source_bit_offset) is not int or source_bit_offset < 0
                or type(target_bit_offset) is not int or target_bit_offset < 0
                or type(width) is not int or width < 1
                or source_bit_offset + width > export['width']
                or source_value >= 1 << width
                or type(target_value) is not int or target_value < 0
                or not isinstance(target, Mapping)):
            raise ValueError('base-event-binding-delivery-invalid')
        required_target = ('component', 'component_id', 'instance_id',
                           'input_name', 'endpoint_id', 'role', 'physical_port',
                           'runtime_name', 'width', 'reset_epoch')
        if (any(type(target.get(key)) is not str or not target.get(key)
                for key in required_target[:-2])
                or type(target.get('width')) is not int or target['width'] < 1
                or type(target.get('reset_epoch')) is not int
                or target['reset_epoch'] < 0
                or type(target_value) is not int
                or target_value >= 1 << target['width']
                or target_bit_offset + width > target['width']):
            raise ValueError('base-event-binding-target-invalid')
        source_endpoint = export['endpoint_id']
        source_role = export['role']
        local_id = (f'{self.instance_id}|{source_epoch}|{source_tick}|'
                    f'{source_phase}|{source_endpoint}|{source_role}|'
                    f'binding_delivery|{dataflow_delivery_event_id}')
        return {
            'schema_version': _SCHEMA_VERSION,
            'event_type': 'binding_delivery',
            'component_id': self.component_id,
            'instance_id': self.instance_id,
            'endpoint_id': source_endpoint,
            'role': source_role,
            'physical_port': export['physical_port'],
            'direction': 'output',
            'raw_event_refs': [event_id],
            'clock_domain': export['clock_domain'],
            'tick': source_tick,
            'reset_epoch': source_epoch,
            'transaction_key': None,
            'action_ref': None,
            'observation_mapping_id': None,
            'observation_property': 'explicit_physical_binding_delivery',
            'local_event_id': local_id,
            'payload': {
                'source_component': source_component,
                'source_port': source_port,
                'source_value': source_value,
                'source_bit_offset': source_bit_offset,
                'source_phase': source_phase,
                'target_component': target['component'],
                'target_component_id': target['component_id'],
                'target_instance_id': target['instance_id'],
                'target_port': target['input_name'],
                'target_endpoint_id': target['endpoint_id'],
                'target_role': target['role'],
                'target_physical_port': target['physical_port'],
                'target_runtime_name': target['runtime_name'],
                'target_value': target_value,
                'target_bit_offset': target_bit_offset,
                'target_width': target['width'],
                'width': width,
                'target_reset_epoch': target['reset_epoch'],
                'dataflow_delivery_event_id': dataflow_delivery_event_id,
            },
        }

    def register_binding_delivery(self, *, event_id: int,
                                  source_component: str, source_port: str,
                                  target_port: str, target_epoch: int,
                                  target_value: int, width: int,
                                  target_bit_offset: int = 0) -> None:
        """Keep the latest delivered value for later physical input matching."""
        contract = self._bound_inputs.get(target_port)
        export = self._bound_exports.get(target_port)
        if (contract is None or export is None
                or contract['producer_ref'] != source_component + '.' + source_port
                or type(event_id) is not int or event_id < 1
                or type(target_epoch) is not int or target_epoch < 0
                or type(target_value) is not int or target_value < 0
                or type(width) is not int or width != export['width']
                or target_bit_offset != 0
                or target_value >= 1 << export['width']):
            raise ValueError('base-event-binding-delivery-contract-mismatch')
        key = (export['endpoint_id'], export['role'])
        self._binding_deliveries[key] = {
            'event_id': event_id, 'target_epoch': target_epoch,
            'target_value': target_value, 'width': width,
        }

    def consume_local_tick(self, raw_event: Mapping[str, object], *,
                           reset_epoch: int) -> tuple[dict[str, object], ...]:
        """Return port samples and observed transitions linked to one raw row."""
        if (not isinstance(raw_event, Mapping)
                or raw_event.get('kind') != 'local_tick_sample'
                or type(raw_event.get('event_id')) is not int
                or raw_event['event_id'] < 1
                or type(raw_event.get('local_tick')) is not int
                or raw_event['local_tick'] < 1
                or raw_event.get('phase') not in ('pre', 'post')
                or not isinstance(raw_event.get('outputs'), Mapping)
                or type(reset_epoch) is not int or reset_epoch < 0):
            raise ValueError('base-event-raw-sample-invalid')
        if self._reset_epoch != reset_epoch:
            self._reset_epoch = reset_epoch
            self._last_values.clear()
            self._binding_deliveries = {
                key: delivery for key, delivery in self._binding_deliveries.items()
                if delivery['target_epoch'] == reset_epoch
            }

        event_id = raw_event['event_id']
        tick = raw_event['local_tick']
        phase = raw_event['phase']
        outputs = raw_event['outputs']
        projected = []
        for export in self._exports:
            port = export['physical_port']
            direction = export['direction']
            physical = outputs.get('physical')
            runtime_name = export['runtime_name']
            if 'physical' in outputs:
                if not isinstance(physical, Mapping) or runtime_name not in physical:
                    missing = ('base-event-input-missing:' if direction == 'input'
                               else 'base-event-output-missing:')
                    raise ValueError(missing + port)
                # The generated runtime signal is already the selected ABI
                # slice. ``bit_lo`` locates it on the physical port; shifting
                # this snapshot again would corrupt nonzero-offset exports.
                raw_value = physical[runtime_name]
            elif direction == 'input':
                raise ValueError('base-event-input-missing:' + port)
            elif port in outputs:
                # Compatibility for older hand-built raw fixtures. Runtime
                # producers include the canonical nested physical snapshot;
                # never mask a missing key in a present snapshot with an alias.
                raw_value = outputs[port]
            else:
                raise ValueError('base-event-output-missing:' + port)
            if type(raw_value) is str and export['encoding'] == 'fixed_width_hex':
                try:
                    raw_value = int(raw_value, 16)
                except ValueError as error:
                    raise ValueError('base-event-output-value-invalid:' + port) from error
            if (type(raw_value) is not int or raw_value < 0
                    or raw_value >= 1 << export['width']):
                raise ValueError('base-event-output-value-invalid:' + port)
            width = export['width']
            value = raw_value
            endpoint_id, role = export['endpoint_id'], export['role']
            local_prefix = (f'{self.instance_id}|{reset_epoch}|{tick}|{phase}|'
                            f'{endpoint_id}|{role}|{direction}')
            common = {
                'schema_version': _SCHEMA_VERSION,
                'component_id': self.component_id,
                'instance_id': self.instance_id,
                'endpoint_id': endpoint_id,
                'role': role,
                'physical_port': port,
                'bit_lo': export['bit_lo'],
                'direction': direction,
                'raw_event_refs': [event_id],
                'clock_domain': export['clock_domain'],
                'tick': tick,
                'reset_epoch': reset_epoch,
                'transaction_key': None,
                'action_ref': None,
                'observation_mapping_id': None,
            }
            projected.append({
                **common,
                'event_type': 'port_sample',
                'local_event_id': local_prefix + '|port_sample',
                'observation_property': ('physical_input_sample'
                                         if direction == 'input'
                                         else 'physical_output_sample'),
                'payload': {'value': value, 'width': width, 'phase': phase},
            })
            key = (endpoint_id, role, direction)
            previous = self._last_values.get(key)
            if previous is not None and previous != value:
                projected.append({
                    **common,
                    'event_type': 'signal_change',
                    'local_event_id': local_prefix + '|signal_change',
                    'observation_property': ('physical_input_transition'
                                             if direction == 'input'
                                             else 'physical_output_transition'),
                    'payload': {'previous_value': previous, 'value': value,
                                'width': width, 'phase': phase},
                })
            self._last_values[key] = value
            if direction == 'input' and phase == 'pre':
                delivery = self._binding_deliveries.get((endpoint_id, role))
                if (delivery is not None
                        and delivery['target_epoch'] == reset_epoch
                        and delivery['target_value'] == value):
                    projected.append({
                        **common,
                        'event_type': 'input_sample',
                        'local_event_id': (local_prefix + '|input_sample|'
                                           + str(delivery['event_id'])),
                        'binding_delivery_event_id': delivery['event_id'],
                        'observation_property': 'actual_bound_input_sample',
                        'payload': {
                            'value': value, 'width': width, 'phase': phase,
                            'binding_delivery_event_id': delivery['event_id'],
                        },
                    })
        return tuple(projected)
