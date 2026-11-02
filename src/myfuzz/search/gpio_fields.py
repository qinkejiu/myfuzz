"""Documentary GPIOEN bit resources, deliberately without execution authority.

The production consumer validates journal continuity and recomputes factual
tracker records. Its protected record hook is an extension seam, not a public
live-current issuer. This adapter copies only resources in those output records;
it neither reads tracker internals nor synthesizes versions from values/counts.
Replaying saved events remains documentary, even when every check passes.
"""
from copy import deepcopy

from myfuzz.scenario.gpio_register_evidence import GpioRegisterEvidenceConsumer

from .model import natural


def _unknown(reason):
    return dict(schema_version='research_gpioen_field_state.v1', status='unknown',
        reason=reason, proof_scope='documentary_gpioen_resources_only',
        execution_authority=False, bit_resources=[])


class GpioFieldDocuments(GpioRegisterEvidenceConsumer):
    """Bounded factual view of one GPIOEN slice after observed APB access.

    An initial tick alone cannot establish a resource: tracker tick outputs do
    not publish current GPIOEN resources. Reset and certainty barriers discard
    the view. ``observed`` describes documentary completeness, never trusted
    current state or a completed writer-to-consumer relation.
    """

    def __init__(self, *, component, bit_lo, width, runtime_contract_sha256,
                 **bounds):
        self._field_document = None
        self._irq_candidates = []
        self._field_slice = (bit_lo, width)
        self._field_runtime_contract = runtime_contract_sha256
        super().__init__(component=component, register='gpioen', bit_lo=bit_lo,
            width=width, runtime_contract_sha256=runtime_contract_sha256, **bounds)

    def _clear_additional_resources(self):
        self._field_document = None
        self._irq_candidates = []

    def _process_records(self, records, raw, event_id):
        super()._process_records(records, raw, event_id)
        lo, width = self._field_slice
        for record in records:
            if (record.get('kind') == 'gpio_irq_trigger'
                    and record.get('status') == 'observed'
                    and lo == 8 and width == 1):
                for cause in record.get('causes', ()):
                    if cause.get('pin') != lo:
                        continue
                    resources = cause.get('configuration', {}).get('gpioen', [])
                    writer = self._writers.get(lo)
                    if (len(resources) != 1 or writer is None
                            or writer['resource'] != resources[0]
                            or resources[0]['value'] != 1
                            or not 0 < event_id - resources[0]['observation_event_id'] <= self._max_gap
                            or len(self._irq_candidates) >= self._max_records):
                        continue
                    self._irq_candidates.append(dict(
                        component=raw['component'], register='gpioen', bit_lo=lo,
                        width=width, reset_epoch=raw['reset_epoch'],
                        endpoint='native_gpio_irq_configuration_consumption',
                        proof_scope='native_gpio_irq_configuration_consumption',
                        bit_resources=deepcopy(resources),
                        writer_event_ids=[resources[0]['observation_event_id']],
                        writer_transactions=[deepcopy(writer['transaction'])],
                        consumer_event_id=event_id,
                        trigger_id=record['trigger_id'], phase=record['phase'],
                        configuration=deepcopy(cause['configuration']),
                        status='verified', reward_eligible=False,
                        native_authority=False, cpu_delivery_status='unknown',
                        isr_status='unknown'))
        for record in records:
            if (record.get('status') == 'observed'
                    and record.get('register') == 'gpioen'
                    and record.get('kind') in ('gpio_register_commit',
                                               'gpio_register_read')):
                resources = deepcopy(record['bit_resources'][lo:lo + width])
                self._field_document = dict(
                    schema_version='research_gpioen_field_state.v1',
                    status='observed', reason='actual_apb_resource_document',
                    proof_scope='documentary_gpioen_resources_only',
                    execution_authority=False, component=raw['component'],
                    register='gpioen', bit_lo=lo, width=width,
                    runtime_contract_sha256=self._field_runtime_contract,
                    observation_contract=deepcopy(raw['observation_contract']),
                    reset_epoch=raw['reset_epoch'], bit_resources=resources,
                    value=sum(r['value'] << i for i, r in enumerate(resources)))
        if self._field_document is not None:
            mask = (1 << width) - 1
            if ((raw['post']['gpio_probe_gpioen'] >> lo) & mask
                    != self._field_document['value']):
                self._clear_additional_resources()
            else:
                self._field_document['local_tick'] = raw['local_tick']
                self._field_document['observation_event_id'] = event_id
                scope = raw.get('command_scope')
                self._field_document['command_sequence'] = (
                    scope['command_sequence'] if scope is not None else None)

    def documentary_irq_report(self):
        """Historical exact native configuration consumption; never authority."""
        report = self.report()
        valid = (report['journal_integrity'] and not report['awaiting_native_reset']
                 and not self._incomplete)
        return dict(schema_version='research_gpio_irq_consumption.v1',
                    journal_integrity=valid, reward_eligible=False,
                    relations=deepcopy(tuple(self._irq_candidates)) if valid else ())

    def documentary_state(self, *, expected_epoch):
        natural(expected_epoch)
        report = self.report()
        if (not report['journal_integrity'] or report['awaiting_native_reset']
                or report['register_status'] == 'incomplete'):
            return _unknown(report['reason'])
        if self._field_document is None:
            return _unknown('missing_current_resource_document')
        if self._field_document['reset_epoch'] != expected_epoch:
            return _unknown('expected_epoch_mismatch')
        return deepcopy(self._field_document)


def read_gpio_field_current(source, *, expected_epoch):
    """Query only the installed consumer's live-bound state; otherwise unknown.

    The exact installation handle authenticates build/process scope, drains its
    runner journal and binds the documentary resources to that current scope.
    A standalone consumer or saved report cannot replace it. This adapter does
    not consult authority registries, step RTL or manufacture native authority.
    """
    natural(expected_epoch)
    from .gpio_relations import _Installation
    if type(source) is not _Installation:
        return _unknown('missing_live_gpioen_consumer_installation')
    try:
        return source.field_state(expected_epoch=expected_epoch)
    except (KeyError, ValueError, TypeError, RuntimeError, AttributeError):
        return _unknown('live_gpioen_consumer_state_unavailable')
