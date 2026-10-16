"""Authenticate L1 binding projections against bounded raw journal evidence.

No functional meaning is inferred. The existing base-event normalizer rebuilds
both projections from the trusted physical contract and measured raw receipts.
"""
from collections.abc import Mapping
from copy import deepcopy
import json

from .ip_base_events import IpBaseEventNormalizer


def _same_projection(actual, expected):
    if (not isinstance(actual, Mapping) or expected is None
            or not set(expected) <= set(actual)):
        return False
    # JSON comparison distinguishes bool from int, and checks every projected
    # field. Journal provenance and global IDs are additional envelope fields.
    try:
        left = json.dumps({key: actual.get(key) for key in expected}, sort_keys=True,
                          allow_nan=False)
        right = json.dumps(expected, sort_keys=True, allow_nan=False)
    except (ValueError, TypeError):
        return False
    return left == right


def _positive(value):
    return type(value) is int and value > 0


class IpBindingEvidenceVerifier:
    def __init__(self, configurations):
        if not isinstance(configurations, Mapping) or len(configurations) > 1024:
            raise ValueError('binding-evidence-component-contracts-required')
        self._configurations = {}
        for alias, configuration in configurations.items():
            if type(alias) is not str or not alias or not isinstance(configuration, Mapping):
                raise ValueError('binding-evidence-component-contract-invalid')
            saved = deepcopy(dict(configuration))
            normalizer = IpBaseEventNormalizer(**saved)
            if len(normalizer._exports) > 1024:
                raise ValueError('binding-evidence-export-limit')
            self._configurations[alias] = saved

    def match(self, *, event, event_id, records, endpoints, declares_key):
        if (event.get('kind') != 'input_sample'
                or event.get('event_type') != 'input_sample'):
            return None
        source, target = endpoints.source, endpoints.target
        if source.component not in self._configurations or target.component not in self._configurations:
            return None
        source_normalizer = IpBaseEventNormalizer(**self._configurations[source.component])
        target_normalizer = IpBaseEventNormalizer(**self._configurations[target.component])
        bound = target_normalizer.bound_input_contract(target.port)
        if bound is None or bound['producer_ref'] != source.component + '.' + source.port:
            return None
        base_id = event.get('binding_delivery_event_id')
        raw_refs = event.get('raw_event_refs')
        if (not _positive(base_id) or type(raw_refs) is not list or len(raw_refs) != 1
                or not _positive(raw_refs[0])):
            return None
        projection = records.get(base_id)
        sampled = records.get(raw_refs[0])
        if not isinstance(projection, Mapping) or not isinstance(sampled, Mapping):
            return None
        payload = projection.get('payload')
        if (projection.get('kind') != 'binding_delivery' or not isinstance(payload, Mapping)):
            return None
        delivery_id = payload.get('dataflow_delivery_event_id')
        if not _positive(delivery_id):
            return None
        delivery = records.get(delivery_id)
        if (not isinstance(delivery, Mapping) or delivery.get('kind') != 'dataflow_delivery'
                or not declares_key(delivery)
                or delivery.get('source') not in ([source.component, source.port],
                                                (source.component, source.port))
                or delivery.get('target') not in ([target.component, target.port],
                                                (target.component, target.port))
                or (delivery.get('source_bit_offset'), delivery.get('target_bit_offset'),
                    delivery.get('width')) != (source.bit_offset, target.bit_offset, target.width)):
            return None
        driver_id = delivery.get('producer_event_id')
        if not _positive(driver_id):
            return None
        driver = records.get(driver_id)
        if (not isinstance(driver, Mapping)
                or not driver_id < delivery_id < base_id < raw_refs[0] < event_id):
            return None
        for raw, component in ((driver, source.component), (sampled, target.component)):
            if (raw.get('kind') != 'local_tick_sample' or raw.get('component') != component
                    or raw.get('observation_schema_version') != 'ip_raw_observation.v1'
                    or type(raw.get('reset_epoch')) is not int
                    or not 0 <= raw['reset_epoch'] < 1 << 64):
                return None
        if sampled.get('phase') != 'pre':
            return None
        # A newer delivery (even the same value), reset, or epoch transition
        # supersedes this active witness before the actual input measurement.
        for record_id, record in records.items():
            if not driver_id < record_id < event_id:
                continue
            if record.get('kind') == 'reset_barrier':
                return None
            if record.get('kind') == 'local_tick_sample':
                component = record.get('component')
                if component == source.component and record.get('reset_epoch') != driver['reset_epoch']:
                    return None
                if component == target.component and record.get('reset_epoch') != sampled['reset_epoch']:
                    return None
            if (delivery_id < record_id and record.get('kind') == 'dataflow_delivery'
                    and record.get('target') in ([target.component, target.port],
                                                (target.component, target.port))):
                return None
        try:
            source_samples = source_normalizer.consume_local_tick(driver, reset_epoch=driver['reset_epoch'])
            observed = next((row for row in source_samples
                             if row['event_type'] == 'port_sample'
                             and row['direction'] == 'output' and row['physical_port'] == source.port), None)
            if observed is None or source.bit_offset + source.width > observed['payload']['width']:
                return None
            value = observed['payload']['value'] >> source.bit_offset & ((1 << source.width) - 1)
            if type(delivery.get('value')) is not int or delivery['value'] != value:
                return None
            target_value = delivery.get('target_value')
            if (type(target_value) is not int or target_value < 0
                    or (target_value >> target.bit_offset
                        & ((1 << target.width) - 1)) != value):
                return None
            if source.width != target.width:
                return None
            identity = dict(component=target.component, component_id=target_normalizer.component_id,
                instance_id=target_normalizer.instance_id, input_name=target.port,
                endpoint_id=bound['endpoint_id'], role=bound['role'],
                physical_port=bound['physical_port'], runtime_name=bound['runtime_name'],
                width=bound['width'], reset_epoch=sampled['reset_epoch'])
            expected_delivery = source_normalizer.project_binding_delivery(
                event_id=driver_id, dataflow_delivery_event_id=delivery_id,
                source_component=source.component, source_port=source.port,
                source_tick=driver['local_tick'], source_phase=driver['phase'],
                source_epoch=driver['reset_epoch'], source_value=value,
                source_bit_offset=source.bit_offset, target=identity,
                target_value=delivery.get('target_value'),
                target_bit_offset=target.bit_offset, width=target.width)
            if not _same_projection(projection, expected_delivery):
                return None
            target_normalizer.register_binding_delivery(event_id=base_id,
                source_component=source.component, source_port=source.port,
                target_port=target.port, target_epoch=sampled['reset_epoch'],
                target_value=delivery.get('target_value'), width=target.width,
                target_bit_offset=target.bit_offset)
            expected_sample = next((row for row in target_normalizer.consume_local_tick(
                sampled, reset_epoch=sampled['reset_epoch'])
                if row['event_type'] == 'input_sample'), None)
            if not _same_projection(event, expected_sample):
                return None
        except (ValueError, TypeError, KeyError):
            return None
        return dict(delivery_event_id=delivery_id, delivery=delivery,
                    driver_event_id=driver_id, driver=driver, value=value, rows=1,
                    base_delivery_event_id=base_id, raw_input_event_id=raw_refs[0])
