"""Bounded exact-receipt native UART level IRQ joins; no ISR/operand inference.

Accepted retention certificates are supplied only by the authenticated UART
consumption engine, never by external source input. Historical raw facts remain
immutable; delayed certificates append proofs for previously defined resources.
"""
from collections import OrderedDict
from copy import deepcopy
import json


def _uint(value):
    return type(value) is int and 0 <= value < 1 << 64


def _ident(value):
    return type(value) is str and bool(value.strip()) or _uint(value)


def _same(left, right):
    return json.dumps(left, sort_keys=True, allow_nan=False) == json.dumps(right, sort_keys=True, allow_nan=False)


def _entry(value, component, epoch):
    return (type(value) is list and len(value) == 4 and value[0] == component
            and type(value[1]) is int and value[1] == epoch
            and all(_uint(item) for item in value[2:]))


class UartNativeIrqJoin:
    def __init__(self, *, ownership, admission_registry, edge_index=None,
                 max_components=16, max_entry_refs=1024):
        from .ownership import OwnershipMap
        from .source_provenance import AdmissionRegistry
        from .runtime_edge_index import RuntimeEdgeIndex
        if not isinstance(ownership, OwnershipMap) or not isinstance(admission_registry, AdmissionRegistry):
            raise ValueError('IRQ join requires source and ownership authority')
        if edge_index is not None and not isinstance(edge_index, RuntimeEdgeIndex):
            raise ValueError('invalid IRQ graph authority')
        if any(type(value) is not int or value < 1 for value in (max_components, max_entry_refs)):
            raise ValueError('IRQ capacities must be positive integers')
        self.ownership, self.registry, self.edge_index = ownership, admission_registry, edge_index
        self.max_components, self.max_entry_refs = max_components, max_entry_refs
        self._sources = {}
        self._cpus = {}
        self._outputs = OrderedDict()
        self._definitions = OrderedDict()
        self._entries = OrderedDict()
        self._deliveries = OrderedDict()
        self._samples = OrderedDict()
        self._takes = OrderedDict()
        self._seen = OrderedDict()
        self._global_bad = False
        self._owner_components = {field['component_id'] for field in ownership.document()['fields']
                                  if field['port'] in ('irq', 'uart_rx_byte')}
        self._bad_components = set()
        self._bad_epochs = {}
        self._global_pending = set()
        self._cause_proven = set()
        self._take_proven = set()

    def _record(self, event, kind='uart_consumption_match', **fields):
        return deepcopy(dict(kind=kind, schema_version=kind + '.v1',
            component=event.get('component', event.get('source_component')),
            reset_epoch=event.get('reset_epoch', event.get('source_epoch')),
            local_tick=event.get('local_tick', event.get('source_local_tick')),
            observation_event_id=event.get('event_id'), **fields))

    def _fail(self, event, reason):
        component = event.get('component', event.get('source_component'))
        if type(component) is str and component in self._sources:
            self._sources[component]['bad'] = True
        elif type(component) is str and component in self._cpus:
            self._cpus[component]['bad'] = True
        elif type(component) is str and component in self._owner_components:
            self._bad_components.add(component)
            epoch = event.get('reset_epoch', event.get('source_epoch'))
            if _uint(epoch): self._bad_epochs[component] = max(epoch, self._bad_epochs.get(component, -1))
        else:
            self._global_bad = True
            self._global_pending = set(self._owner_components)
        return (self._record(event, status='incomplete', reason=reason,
                             proof_scope='native_irq_witness_join'),)

    def _bounded(self, collection, key, value, *, history=False):
        if not history and len(collection) >= self.max_entry_refs and key not in collection:
            self._gc()
        collection[key] = value
        limit = (self.max_entry_refs if collection is self._outputs
                 else self.max_entry_refs * (2 if history else 1))
        if len(collection) > limit:
            if history:
                collection.popitem(last=False)
            else:
                self._global_bad = True
                self._global_pending = set(self._sources) | set(self._cpus) or set(self._owner_components)
                collection.clear()

    def _gc(self):
        """Collect only caches with no live view/input/unresolved-take reference."""
        for identity in list(self._takes):
            if identity in self._take_proven:
                del self._takes[identity]
                self._take_proven.discard(identity)
        sample_ids = {state.get('sample_id') for state in self._cpus.values()}
        sample_ids.update(take['sample_event_id'] for take in self._takes.values())
        for identity in list(self._samples):
            if identity not in sample_ids: del self._samples[identity]
        delivery_ids = {state['latest'] for state in self._cpus.values()}
        delivery_ids.update(sample.get('binding_delivery_event_id') for sample in self._samples.values())
        for identity in list(self._deliveries):
            if identity not in delivery_ids: del self._deliveries[identity]
        definitions = {tuple(view['source_output_key']) for view in self._outputs.values()}
        definitions.update(tuple(state['previous']['source_output_key']) for state in self._sources.values()
                           if state['previous'] is not None)
        definitions.update(tuple(delivery['source_output_key']) for delivery in self._deliveries.values())
        for identity in list(self._definitions):
            if identity not in definitions:
                del self._definitions[identity]
                self._cause_proven.discard(identity)
        entries = {tuple(entry) for definition in self._definitions.values()
                   for entry in definition['pre_entry_ids']}
        for identity in list(self._entries):
            if identity not in entries: del self._entries[identity]

    def _scope(self, event):
        component, epoch, tick = (event.get(key) for key in ('component', 'reset_epoch', 'local_tick'))
        scope = event.get('command_scope')
        return (type(component) is str and bool(component.strip()) and _uint(epoch) and _uint(tick)
            and type(scope) is dict and set(scope) == {'component', 'reset_epoch', 'command_sequence'}
            and scope['component'] == component and type(scope['reset_epoch']) is int
            and scope['reset_epoch'] == epoch and _uint(scope['command_sequence']))

    def _receipt(self, event):
        receipt = event.get('receipt_id')
        return (type(receipt) is dict and set(receipt) == {'execution', 'sequence'}
            and type(receipt['execution']) is str and bool(receipt['execution'].strip())
            and _uint(receipt['sequence']) and receipt['sequence'] == event['command_scope']['command_sequence'])

    def consume(self, event):
        if type(event) is not dict:
            return self._fail({}, 'malformed_native_irq_event')
        try:
            event = json.loads(json.dumps(event, allow_nan=False))
        except (TypeError, ValueError, RecursionError):
            return self._fail({}, 'malformed_native_irq_event')
        if not _ident(event.get('event_id')):
            return self._fail(event, 'missing_native_irq_event_identity')
        kind = event.get('kind')
        supported = {'uart_tick_observation', 'uart_irq_update', 'uart_consumption_match',
            'native_irq_binding_delivery', 'cpu_external_irq_sample', 'cpu_external_irq_taken',
            'uart_reset', 'cpu_reset'}
        if kind not in supported:
            return ()
        signature = json.dumps(event, sort_keys=True, allow_nan=False)
        identity = event['event_id']
        if identity in self._seen:
            return () if self._seen[identity] == signature else self._fail(event, 'conflicting_native_irq_event_identity')
        self._bounded(self._seen, identity, signature, history=True)
        if kind == 'uart_tick_observation': return self._tick(event)
        if kind == 'uart_irq_update': return self._update(event)
        if kind == 'uart_consumption_match': return self._retention(event)
        if kind == 'native_irq_binding_delivery': return self._delivery(event)
        if kind == 'cpu_external_irq_sample': return self._sample(event)
        if kind == 'cpu_external_irq_taken': return self._taken(event)
        return self._reset(event, kind)

    def _tick(self, event):
        from myfuzz.local_harness.opentitan_uart_fifo_contract import UART_FIFO_PROBES, uart_fifo_observation_contract
        if not self._scope(event) or not self._receipt(event):
            return self._fail(event, 'malformed_uart_irq_receipt_scope')
        if not _same(event.get('observation_contract'), uart_fifo_observation_contract()):
            return self._fail(event, 'unauthenticated_uart_irq_contract')
        a, b = event.get('pre'), event.get('post')
        if (type(a) is not dict or type(b) is not dict or any(
                type(phase.get('probe_uart_' + name)) is not int
                or not 0 <= phase['probe_uart_' + name] < 1 << width
                for phase in (a, b) for name, (width, _) in UART_FIFO_PROBES.items())):
            return self._fail(event, 'malformed_uart_irq_probe')
        for phase in (a, b):
            value = phase['probe_uart_irq_rx_watermark']
            if (type(phase.get('intr_rx_watermark_o')) is not int or phase['intr_rx_watermark_o'] != value
                    or 'uart_rx_watermark' in phase and
                    (type(phase['uart_rx_watermark']) is not int or phase['uart_rx_watermark'] != value)):
                return self._fail(event, 'uart_irq_alias_mismatch')
        p = lambda name: a['probe_uart_' + name]
        if (p('fifo_depth') > 64 or p('watermark_threshold') !=
                (127 if p('watermark_level') > 6 else 62 if p('watermark_level') == 6 else 1 << p('watermark_level'))
                or p('event_rx_watermark') != int(p('fifo_depth') >= p('watermark_threshold'))
                or b['probe_uart_irq_rx_watermark'] != int(bool(
                    (p('event_rx_watermark') or p('watermark_test')) and p('intr_enable_rx_watermark')))):
            return self._fail(event, 'uart_watermark_native_transition_mismatch')
        component, epoch = event['component'], event['reset_epoch']
        if component not in self._sources:
            if len(self._sources) + len(self._cpus) >= self.max_components:
                return self._fail(event, 'native_irq_component_capacity')
            self._sources[component] = dict(epoch=epoch, tick=None, previous=None,
                raw=None, dep=None, version=0, execution=None, command=None,
                bad=component in self._bad_components)
        state = self._sources[component]
        if (state['epoch'] != epoch or state['tick'] is not None and event['local_tick'] != state['tick'] + 1
                or state['execution'] is not None and state['execution'] != event['receipt_id']['execution']
                or state['command'] is not None and event['receipt_id']['sequence'] < state['command']):
            return self._fail(event, 'uart_irq_receipt_discontinuity')
        if state['previous'] is not None and state['previous']['value'] != p('irq_rx_watermark'):
            return self._fail(event, 'uart_irq_pre_post_discontinuity')
        previous = state['previous'] or dict(source_output_key=[component, epoch, 'rx_watermark', 0],
            definition_observation_event_id=event['event_id'], value=p('irq_rx_watermark'), pre_entry_ids=[],
            dependencies=None, trusted_definition=False)
        self._store_view(event, 'pre', previous)
        old_raw = state['raw']
        state.update(tick=event['local_tick'], raw=event, execution=event['receipt_id']['execution'],
                     command=event['receipt_id']['sequence'])
        # Unchanged compressed engine updates can reuse a definition only if
        # exact observed dependencies and the prior queue transition agree.
        if (state['dep'] is not None and self._snapshot(event) == state['dep']['snapshot']
                and old_raw is not None and not any(old_raw['pre']['probe_uart_' + field]
                    for field in ('fifo_incr_wptr', 'fifo_incr_rptr', 'fifo_clear'))):
            self._store_view(event, 'post', state['previous'])
        return ()

    def _snapshot(self, event):
        a, b = event['pre'], event['post']
        names = ('event_rx_watermark', 'intr_state_rx_watermark', 'intr_enable_rx_watermark',
            'intr_test_rx_watermark', 'intr_test_qe_rx_watermark', 'watermark_test', 'watermark_threshold',
            'watermark_level', 'fifo_depth', 'irq_rx_watermark')
        return [a['probe_uart_' + name] for name in names] + [b['probe_uart_' + name]
            for name in ('irq_rx_watermark', 'intr_state_rx_watermark', 'watermark_test')]

    def _store_view(self, event, phase, definition):
        view = dict(definition, source_observation_event_id=event['event_id'],
            source_receipt_ref=dict(command_scope=event['command_scope'], receipt_id=event['receipt_id'],
                                    local_tick=event['local_tick'], phase=phase))
        key = (event['component'], event['reset_epoch'], event['local_tick'], phase, 'rx_watermark')
        self._bounded(self._outputs, key, deepcopy(view), history=True)

    def output_at(self, component, epoch, local_tick, phase, irq_class):
        if (type(component) is not str or not _uint(epoch) or not _uint(local_tick)
                or phase not in ('pre', 'post') or irq_class != 'rx_watermark'):
            return None
        return deepcopy(self._outputs.get((component, epoch, local_tick, phase, irq_class)))

    def _update(self, event):
        if event.get('irq_class') != 'rx_watermark': return ()
        component = event.get('component')
        state = self._sources.get(component) if type(component) is str else None
        raw = state['raw'] if state else None
        if (raw is None or event.get('schema_version') != 'uart_irq_update.v1'
                or event.get('reset_epoch') != raw['reset_epoch'] or type(event.get('reset_epoch')) is not int
                or event.get('local_tick') != raw['local_tick'] or type(event.get('local_tick')) is not int
                or not _same(event.get('observation_event_id'), raw['event_id'])):
            return self._fail(event, 'missing_exact_uart_irq_update_receipt')
        a, b = raw['pre'], raw['post']
        fields = dict(pre_output=a['probe_uart_irq_rx_watermark'], post_output=b['probe_uart_irq_rx_watermark'],
            pre_event=a['probe_uart_event_rx_watermark'], pre_state=a['probe_uart_intr_state_rx_watermark'],
            post_state=b['probe_uart_intr_state_rx_watermark'], pre_enable=a['probe_uart_intr_enable_rx_watermark'],
            pre_test=a['probe_uart_intr_test_rx_watermark'], pre_test_qe=a['probe_uart_intr_test_qe_rx_watermark'],
            pre_watermark_test=a['probe_uart_watermark_test'], post_watermark_test=b['probe_uart_watermark_test'],
            watermark_threshold=a['probe_uart_watermark_threshold'], watermark_level=a['probe_uart_watermark_level'],
            pre_depth=a['probe_uart_fifo_depth'])
        entries = event.get('pre_entry_ids')
        if (any(not _same(event.get(name), value) for name, value in fields.items())
                or type(entries) is not list or len(entries) != fields['pre_depth']
                or any(not _entry(entry, component, raw['reset_epoch']) for entry in entries)
                or len({tuple(entry) for entry in entries}) != len(entries)):
            return self._fail(event, 'uart_irq_snapshot_or_queue_mismatch')
        state['version'] += 1
        definition = dict(source_output_key=[component, raw['reset_epoch'], 'rx_watermark', state['version']],
            definition_observation_event_id=raw['event_id'], irq_update_event_id=event['event_id'],
            value=fields['post_output'], pre_entry_ids=deepcopy(entries), dependencies=fields,
            trusted_definition=True)
        state.update(previous=definition, dep=dict(snapshot=self._snapshot(raw), entries=deepcopy(entries)))
        self._bounded(self._definitions, tuple(definition['source_output_key']), deepcopy(definition))
        self._store_view(raw, 'post', definition)
        records = [self._record(raw, 'uart_irq_output_definition', **definition)]
        return tuple(records + self._promote(event))

    def _retention(self, event):
        if event.get('status') == 'incomplete' and event.get('reason') not in {
                'unproven_uart_source_authority', 'uart_unknown_entry_origin',
                'uart_empty_read', 'unrouted_uart_access'}:
            return self._fail(event, 'upstream_uart_certainty_barrier')
        if event.get('status') != 'accepted' or event.get('proof_scope') != 'uart_fifo_retention': return ()
        from .source_provenance import SourceAdmission
        component, epoch = event.get('component'), event.get('reset_epoch')
        try:
            admission = SourceAdmission.from_document(event.get('source_admission'))
            selected_owner = (admission.source_id if self.edge_index is None else
                self.edge_index.source_owner_ref(admission.source_id, admission.path_id,
                    admission.direction, component, 'uart_rx_byte', 0, 8))
            valid = (type(component) is str and _uint(epoch)
                and _entry(event.get('entry_id'), component, epoch) and event.get('retained_at_push') is True
                and admission == self.registry.get(admission.action_id) and admission.component == component
                and admission.input_kind == 'source_event'
                and self.ownership.mutation_source(component, 'uart_rx_byte', 0, 8,
                    direction=admission.direction) == selected_owner
                and type(event.get('frame_id')) is str and bool(event['frame_id'])
                and all(_ident(event.get(field)) for field in
                    ('receiver_start_event', 'completion_event', 'push_event', 'validation_event')))
        except (TypeError, ValueError, KeyError): valid = False
        if not valid: return self._fail(event, 'untrusted_uart_irq_entry_certificate')
        key = tuple(event['entry_id'])
        if key in self._entries and not _same(self._entries[key], event):
            return self._fail(event, 'conflicting_uart_irq_entry_certificate')
        self._bounded(self._entries, key, event)
        return tuple(self._promote(event))

    def _source_good(self, definition):
        component, epoch, _, _ = definition['source_output_key']
        state = self._sources.get(component)
        fields = definition['dependencies']
        return (not self._global_bad and state is not None and not state['bad'] and state['epoch'] == epoch
            and fields is not None and definition['value'] == 1 and fields['pre_event'] == 1
            and fields['pre_enable'] == 1 and fields['pre_watermark_test'] == 0
            and not (fields['pre_test_qe'] and fields['pre_test'])
            and len(definition['pre_entry_ids']) >= fields['watermark_threshold']
            and bool(definition['pre_entry_ids']) and all(tuple(entry) in self._entries
                for entry in definition['pre_entry_ids']))

    def _cause_fields(self, definition):
        certificates = [self._entries[tuple(entry)] for entry in definition['pre_entry_ids']]
        certified = self.edge_index is not None and all(self.edge_index.source_owner_ref(
            cert['source_admission']['source_id'], cert['source_admission']['path_id'],
            cert['source_admission']['direction'], cert['component'], 'uart_rx_byte', 0, 8) is not None
            for cert in certificates)
        return dict(source_output_key=definition['source_output_key'],
            source_definition_event=definition['definition_observation_event_id'],
            source_entry_ids=definition['pre_entry_ids'],
            retention_proof_event_ids=[cert['event_id'] for cert in certificates],
            source_admissions=[cert['source_admission'] for cert in certificates],
            causal_kind='watermark_qualified_queue_set', graph_path_certified=certified,
            path_id=certificates[0]['source_admission']['path_id'] if certified and len(certificates) == 1 else None,
            generic_isr_origin='unknown', operand_origin='unknown')

    def _promote(self, event):
        records = []
        for key, definition in self._definitions.items():
            if key not in self._cause_proven and self._source_good(definition):
                self._cause_proven.add(key)
                records.append(self._record(event, status='accepted', proof_scope='native_irq_cause',
                                             **self._cause_fields(definition)))
        for take_id, take in self._takes.items():
            if take_id in self._take_proven: continue
            sample = self._samples.get(take['sample_event_id'])
            delivery = self._deliveries.get(sample['binding_delivery_event_id']) if sample else None
            definition = self._definitions.get(tuple(delivery['source_output_key'])) if delivery else None
            cpu = self._cpus.get(take['component'])
            if (definition is None or cpu is None or cpu['bad'] or cpu['epoch'] != take['reset_epoch']
                    or not self._source_good(definition)): continue
            self._take_proven.add(take_id)
            cause_fields = self._cause_fields(definition)
            graph_edges = () if self.edge_index is None else self.edge_index.match_event(dict(
                kind='dataflow_delivery', source=(delivery['source_component'], delivery['source_port']),
                target=(delivery['target_component'], delivery['target_port']), width=1,
                source_bit_offset=0, target_bit_offset=0))
            if cause_fields['graph_path_certified'] and not all(any(
                    admission['path_id'] in edge['path_ids'] for edge in graph_edges)
                    for admission in cause_fields['source_admissions']):
                cause_fields.update(graph_path_certified=False, path_id=None)
            records.append(self._record(event, status='accepted', proof_scope='cpu_external_irq_taken',
                cpu_take_event_id=take_id, cpu_sample_event_id=sample['event_id'],
                binding_delivery_event_id=delivery['event_id'],
                dataflow_delivery_event_id=delivery['dataflow_delivery_event_id'],
                cpu_component=take['component'], cpu_epoch=take['reset_epoch'],
                cpu_command_scope=sample['command_scope'], cpu_receipt_id=sample['receipt_id'],
                graph_edge_refs=list(graph_edges) if cause_fields['graph_path_certified'] else [],
                **cause_fields))
        return records

    def _delivery(self, event):
        required = ('source_component', 'source_epoch', 'source_local_tick', 'source_phase',
            'irq_class', 'target_component', 'target_epoch', 'target_port', 'source_port')
        if (event.get('schema_version') != 'native_irq_binding_delivery.v1'
                or any(name not in event for name in required)):
            return self._fail(event, 'malformed_native_irq_binding')
        if (not _uint(event['source_epoch']) or not _uint(event['target_epoch'])
                or not _uint(event['source_local_tick']) or event['irq_class'] != 'rx_watermark'
                or event['source_port'] != 'uart_rx_watermark' or event['target_port'] != 'irq'
                or any(type(event.get(name)) is not int or event[name] != expected
                    for name, expected in (('width', 1), ('source_bit_offset', 0), ('target_bit_offset', 0)))
                or type(event.get('value')) is not int or event['value'] not in (0, 1)
                or 'target_value' in event and not _same(event['target_value'], event['value'])
                or not _ident(event.get('dataflow_delivery_event_id'))):
            return self._fail(event, 'native_irq_binding_shape_mismatch')
        resource = self.output_at(event['source_component'], event['source_epoch'],
            event['source_local_tick'], event['source_phase'], event['irq_class'])
        if resource is None or any(not _same(event.get(field), resource[field]) for field in
                ('source_output_key', 'source_observation_event_id', 'source_receipt_ref', 'value')):
            return self._fail(event, 'missing_exact_native_irq_binding_resource')
        try:
            owner = self.ownership.binding_producer(event['target_component'], 'irq', 0, 1)
        except (TypeError, ValueError): owner = None
        if owner != event['source_component'] + '.uart_rx_watermark':
            return self._fail(event, 'native_irq_binding_owner_mismatch')
        component = event['target_component']
        if component not in self._cpus:
            if len(self._sources) + len(self._cpus) >= self.max_components:
                return self._fail(event, 'native_irq_component_capacity')
            self._cpus[component] = dict(epoch=event['target_epoch'], latest=None, tick=None,
                execution=None, command=None, bad=component in self._bad_components)
        cpu = self._cpus[component]
        if cpu['epoch'] != event['target_epoch']: return self._fail(event, 'native_irq_binding_cpu_epoch_mismatch')
        cpu['latest'] = event['event_id']
        self._bounded(self._deliveries, event['event_id'], event)
        return ()

    def _sample(self, event):
        from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
        if (event.get('schema_version') != 'cpu_external_irq_sample.v1'
                or not self._scope(event) or not self._receipt(event)
                or not _same(event.get('observation_contract'), ibex_irq_receipt_contract())
                or any(type(event.get(name)) is not int or event[name] not in (0, 1) for name in
                    ('expected_input', 'actual_pre_input', 'actual_post_input', 'irq_masked_pre', 'irq_taken_pre'))):
            return self._fail(event, 'malformed_actual_cpu_irq_sample')
        component = event['component']
        if component not in self._cpus:
            try: declared = self.ownership.field_width(component, 'irq') == 1
            except ValueError: declared = False
            if not declared or len(self._sources) + len(self._cpus) >= self.max_components:
                return self._fail(event, 'unknown_actual_irq_cpu_component')
            self._cpus[component] = dict(epoch=event['reset_epoch'], latest=None, tick=None,
                execution=None, command=None, bad=component in self._bad_components)
        cpu = self._cpus[component]
        if (cpu['epoch'] != event['reset_epoch']
                or cpu['tick'] is not None and event['local_tick'] != cpu['tick'] + 1
                or cpu['execution'] is not None and cpu['execution'] != event['receipt_id']['execution']
                or cpu['command'] is not None and event['receipt_id']['sequence'] <= cpu['command']):
            return self._fail(event, 'actual_cpu_irq_receipt_discontinuity')
        cpu.update(tick=event['local_tick'], execution=event['receipt_id']['execution'],
                   command=event['receipt_id']['sequence'], sample_id=event['event_id'])
        if ('binding_delivery_event_id' not in event and 'source_output_key' not in event
                and 'input_context' in event and event['input_context'] is None):
            self._bounded(self._samples, event['event_id'], event)
            self._gc()
            return (self._record(event, status='incomplete', reason='unproven_native_irq_binding',
                                 proof_scope='cpu_external_irq_input'),)
        if not _ident(event.get('binding_delivery_event_id')):
            return self._fail(event, 'missing_actual_irq_binding_identity')
        delivery = self._deliveries.get(event['binding_delivery_event_id'])
        if (delivery is None or cpu is None or cpu['epoch'] != event['reset_epoch']
                or delivery['target_component'] != event['component']
                or cpu['latest'] != delivery['event_id']
                or any(event[name] != delivery['value'] for name in
                    ('expected_input', 'actual_pre_input', 'actual_post_input'))):
            return self._fail(event, 'unproven_or_overwritten_actual_irq_delivery')
        context = event.get('input_context')
        if (type(context) is not dict
                or set(context) != {'schema_version', 'binding_delivery_event_id', 'expected_input',
                    'source_output_key', 'target_component', 'target_epoch'}
                or any(not _same(context.get(field), expected)
                for field, expected in dict(schema_version='native_irq_input_context.v1',
                    binding_delivery_event_id=delivery['event_id'], expected_input=delivery['value'],
                    source_output_key=delivery['source_output_key'], target_component=event['component'],
                    target_epoch=event['reset_epoch']).items())):
            return self._fail(event, 'actual_irq_input_context_mismatch')
        if not _same(event.get('source_output_key'), delivery['source_output_key']):
            return self._fail(event, 'actual_irq_input_version_mismatch')
        self._bounded(self._samples, event['event_id'], event)
        self._gc()
        return ()

    def _taken(self, event):
        from myfuzz.local_harness.ibex_irq_receipt_contract import ibex_irq_receipt_contract
        if (not self._ident_taken(event) or not self._scope(event) or not self._receipt(event)
                or event.get('schema_version') != 'cpu_external_irq_taken.v1'
                or not _same(event.get('observation_contract'), ibex_irq_receipt_contract())):
            return self._fail(event, 'unauthenticated_actual_native_irq_taken')
        sample = self._samples.get(event['sample_event_id'])
        if (sample is None or any(not _same(event.get(field), sample[field]) for field in
                ('component', 'reset_epoch', 'local_tick', 'command_scope'))
                or sample['actual_pre_input'] != 1 or sample['irq_taken_pre'] != 1
                or sample['irq_masked_pre'] != 0
                or not _same(event['receipt_id'], sample['receipt_id'])
                or not _same(event.get('sample_ref'),
                    dict(command_scope=sample['command_scope'], local_tick=sample['local_tick']))):
            return self._fail(event, 'missing_actual_native_irq_taken_receipt')
        if any(take['sample_event_id'] == sample['event_id'] for take in self._takes.values()):
            return self._fail(event, 'reused_actual_native_irq_taken_sample')
        cpu = self._cpus[event['component']]
        if event['take_key'][2] <= cpu.get('take_sequence', 0):
            return self._fail(event, 'regressed_actual_native_irq_take_sequence')
        cpu['take_sequence'] = event['take_key'][2]
        if sample.get('binding_delivery_event_id') is None:
            return (self._record(event, status='incomplete', reason='unproven_native_irq_binding',
                                 proof_scope='cpu_external_irq_taken'),)
        self._bounded(self._takes, event['event_id'], event)
        records = tuple(self._promote(event))
        self._gc()
        return records

    @staticmethod
    def _ident_taken(event):
        key = event.get('take_key')
        return (_ident(event.get('sample_event_id')) and type(key) is list and len(key) == 3
            and key[0] == event.get('component') and type(key[1]) is int
            and key[1] == event.get('reset_epoch') and _uint(key[2]) and key[2] > 0)

    def _reset_role(self, component, kind):
        if type(component) is not str or not component.strip(): return False
        try:
            if kind == 'cpu_reset':
                if self.ownership.field_width(component, 'irq') != 1: return False
                producer = self.ownership.binding_producer(component, 'irq', 0, 1)
                source, separator, port = producer.rpartition('.')
                if not separator or port != 'uart_rx_watermark': return False
                component = source
            return (self.ownership.field_width(component, 'uart_rx_byte') == 8
                and bool(self.ownership.mutation_source(component, 'uart_rx_byte', 0, 8,
                    direction='IP_TO_CPU')))
        except (TypeError, ValueError, AttributeError):
            return False

    def _reset(self, event, kind):
        component, epoch = event.get('component'), event.get('reset_epoch')
        collection = self._sources if kind == 'uart_reset' else self._cpus
        state = collection.get(component) if type(component) is str else None
        if (type(component) is not str or not component.strip() or not _uint(epoch)
                or not self._reset_role(component, kind)
                or event.get('physical_reset') is not True or state is not None and epoch <= state['epoch']
                or epoch <= self._bad_epochs.get(component, -1)
                or state is None and len(self._sources) + len(self._cpus) >= self.max_components):
            return self._fail(event, 'unproven_native_irq_hardware_reset')
        self._bad_components.discard(component)
        self._bad_epochs.pop(component, None)
        self._global_pending.discard(component)
        if self._global_bad and not self._global_pending: self._global_bad = False
        if kind == 'uart_reset':
            collection[component] = dict(epoch=epoch, tick=None, previous=None, raw=None,
                dep=None, version=0, execution=None, command=None, bad=False)
            for values in (self._definitions, self._entries, self._outputs):
                for key in list(values):
                    if key[0] == component:
                        self._cause_proven.discard(key)
                        del values[key]
            obsolete = {identity for identity, delivery in self._deliveries.items()
                        if delivery['source_component'] == component}
            obsolete_samples = {identity for identity, sample in self._samples.items()
                                if sample.get('binding_delivery_event_id') in obsolete}
            for cpu in self._cpus.values():
                if cpu['latest'] in obsolete: cpu['latest'] = None
                if cpu.get('sample_id') in obsolete_samples: cpu['sample_id'] = None
            for identity in obsolete: del self._deliveries[identity]
            for identity in obsolete_samples: del self._samples[identity]
            for identity, take in list(self._takes.items()):
                if take['sample_event_id'] in obsolete_samples:
                    del self._takes[identity]; self._take_proven.discard(identity)
        else:
            collection[component] = dict(epoch=epoch, latest=None, tick=None, execution=None, command=None, bad=False)
            for values in (self._samples, self._takes):
                for key, record in list(values.items()):
                    if record['component'] == component:
                        self._take_proven.discard(key)
                        del values[key]
        return (self._record(event, 'native_irq_reset', physical_reset=True),)
