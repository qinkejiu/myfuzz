"""Session-local coherent raw journal and observation projections.

Runner runtime streams assign their own event_id when importing records. All
raw_event_refs here explicitly name this stream's raw_event_id namespace, not
those later runner IDs. The wrapper does not authenticate driver receipts.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from uuid import uuid4

from .coherent_protocol_events import CoherentProtocolEventNormalizer


class CoherentAcceptedEventStream:
    """Bound an append-only runtime observation stream for one CPU session.

    Feed only native accepted-event rows from a measured receipt. Caller owns
    provenance and closes the native transport if this consumer raises. A
    failed batch may retain already journaled raw rows and projections; its
    poisoned report makes the incomplete prefix explicit.
    """

    def __init__(self, *, component_id: str, instance_id: str,
                 endpoint_id: str, clock_domain: str,
                 max_records: int = 200000, max_events_per_step: int = 4,
                 **checker_options):
        if (type(max_records) is not int or max_records < 2
                or type(max_events_per_step) is not int or max_events_per_step < 1):
            raise ValueError('coherent-stream-bounds-invalid')
        self._normalizer = CoherentProtocolEventNormalizer(
            component_id=component_id, instance_id=instance_id,
            endpoint_id=endpoint_id, clock_domain=clock_domain, **checker_options)
        self._records: list[dict] = []
        self._max_records = max_records
        self._max_step = max_events_per_step
        self.stream_id = str(uuid4())
        self._raw_sequence = 0
        self._failed = False
        self._checker_failed = False
        self._execution = None
        self._epoch = None
        self._tick = 0

    @property
    def runtime_events(self):
        """Stable borrowed list for runner offset tracking; callers must not mutate."""
        return self._records

    def _fail(self, reason):
        self._failed = True
        raise ValueError('coherent-stream-' + reason)

    def _append(self, record):
        if len(self._records) >= self._max_records:
            self._fail('record-bound-exceeded')
        self._records.append(record)

    def consume_step(self, accepted_events: Sequence[Mapping[str, object]], *,
                     execution_id: str, reset_epoch: int, local_tick: int):
        if self._failed:
            raise ValueError('coherent-stream-already-invalid')
        if (type(execution_id) is not str or not execution_id
                or type(reset_epoch) is not int or reset_epoch < 0
                or type(local_tick) is not int or local_tick < 1
                or not isinstance(accepted_events, (tuple, list))
                or len(accepted_events) > self._max_step
                or any(not isinstance(row, Mapping) for row in accepted_events)):
            self._fail('receipt-shape-invalid')
        if self._epoch is not None:
            if reset_epoch < self._epoch:
                self._fail('epoch-regressed')
            if reset_epoch == self._epoch:
                if execution_id != self._execution or local_tick <= self._tick:
                    self._fail('execution-or-tick-changed-within-epoch')
        self._execution, self._epoch, self._tick = execution_id, reset_epoch, local_tick
        before = len(self._records)
        for row in accepted_events:
            self._raw_sequence += 1
            ref = self._raw_sequence
            context = {'raw_event_scope': self.stream_id,
                       'execution_id': execution_id, 'reset_epoch': reset_epoch,
                       'local_tick': local_tick, 'authority': 'observation_only',
                       'source_authority': False, 'runtime_accepted': False,
                       'semantic_accepted': False}
            self._append({**context, 'kind': 'coherent_accepted_raw',
                          'schema_version': 'coherent_accepted_raw.v1',
                          'raw_event_id': ref, 'native_event': deepcopy(dict(row))})
            if self._checker_failed:
                continue
            try:
                events = self._normalizer.consume_accepted(
                    row, raw_event_ref=ref, reset_epoch=reset_epoch)
            except ValueError as error:
                self._checker_failed = True
                self._append({**context, 'kind': 'coherent_normalization_error',
                    'schema_version': 'coherent_normalization_error.v1',
                    'raw_event_refs': [ref], 'reason': str(error),
                    'scope': 'single_client_no_external_probes_fifo_manager'})
                continue
            for event in events:
                projected = {**context, **event, 'kind': event['event_type']}
                projected['local_event_id'] = self.stream_id + '|' + event['local_event_id']
                self._append(projected)
        return tuple(deepcopy(self._records[before:]))

    def report(self):
        return {**self._normalizer.report(), 'stream_id': self.stream_id,
                'stream_poisoned': self._failed, 'runtime_record_count': len(self._records),
                'stream_closed': not self._failed and not self._checker_failed and self._normalizer.report()['stream_closed'],
                'normalization_poisoned': self._checker_failed,
                'structural_error': self._failed or self._checker_failed or self._normalizer.report()['structural_error']}

    def coverage(self):
        return {**self._normalizer.coverage(), 'raw_event_scope': self.stream_id,
                'stream_poisoned': self._failed, 'normalization_poisoned': self._checker_failed}
