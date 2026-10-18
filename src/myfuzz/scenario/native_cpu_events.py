"""Live native bus observations. No instruction retirement or source grant."""
from copy import deepcopy
from dataclasses import asdict


class NativeBusObserver:
    """Single outstanding actual adapter request, response and CPU transfer.

    Only the generated native session supplies verified receipts. Backend
    response consumption is not CPU completion: the latter needs a later PRE
    native valid/ready handshake. Read snapshots are references to actual host
    service results; source-byte matching is deliberately a separate stage.
    """
    def __init__(self, session):
        from myfuzz.local_harness.native_contract import verify_native_completion_observation
        verify_native_completion_observation(session.artifact)
        self.session = session
        doc = session.artifact.runtime_document
        self.contract = deepcopy(doc['native_completion_observation'])
        self.trace = deepcopy(doc['base_protocol_traces']['traces'][0])
        self.pending = None
        self.epoch = None
        self.execution = None
        self.sequence = 0
        self.tick = None
        self.memory_sequence = 0
        self.samples = []
        self.offered = None
        self.failed = False

    def _native(self, phase):
        result = {}
        for role, signal in self.trace['signals'].items():
            value = phase['protocol_taps'][signal]
            width = self.trace['signal_widths'][role]
            if type(value) is not int or not 0 <= value < 1 << width:
                raise ValueError('native-bus-signal-width:' + role)
            result[role] = value
        marker = phase['physical'][self.contract['instruction_marker']['signal']]
        if type(marker) is not int or marker not in (0, 1):
            raise ValueError('native-bus-marker-width')
        result['instruction'] = marker
        return result

    @staticmethod
    def _stable(actual, saved):
        return (actual['valid'] == 1 and all(actual[k] == saved[k]
                for k in ('addr', 'wstrb', 'instruction'))
                and (not saved['wstrb'] or actual['wdata'] == saved['wdata']))

    def observe(self, receipt, pending_response):
        if self.failed:
            raise ValueError('native-bus-observer-terminal')
        owner = self.session
        epoch = owner.reset_epoch
        if (receipt.status != 'result' or receipt.new_ticks != 1
                or receipt.execution != owner._execution
                or receipt.sequence != owner._sequence):
            raise ValueError('native-bus-live-receipt-scope')
        if self.epoch != epoch:
            self.pending = None  # explicit reset cancels, never completes
            self.offered = None
            self.memory_sequence = owner._sequence_memory
            self.sequence = 0
            self.tick = None
            self.execution = receipt.execution
            self.epoch = epoch
        if (receipt.execution != self.execution or receipt.sequence <= self.sequence
                or (self.tick is not None and receipt.tick_before != self.tick)
                or receipt.tick_after != receipt.tick_before + 1):
            raise ValueError('native-bus-receipt-order')
        sample = deepcopy(receipt.payload['samples'][0])
        if len(receipt.payload['samples']) != 1 or sample['local_tick'] != receipt.tick_after:
            raise ValueError('native-bus-sample-tick')
        scope = dict(execution=receipt.execution, command_sequence=receipt.sequence,
                     reset_epoch=epoch, local_tick=owner._tick_base + receipt.tick_after)
        records = []
        if len(self.samples) >= 4096:
            raise ValueError('native-bus-raw-sample-capacity')
        # Keep the complete verified frame even if later semantic validation
        # fails. No successful projection is synthesized for the failure.
        sample.update(local_tick=scope['local_tick'], native_driver_scope=scope,
                      native_bus_events=records)
        self.samples.append(sample)
        pre, post = self._native(sample['pre']), self._native(sample['post'])
        backend = sample['pre']['backend']
        def record(kind, **fields):
            records.append(dict(schema_version='native_bus_observation.v1', kind=kind,
                proof_scope='native_bus_transfer_only', grants_source_authority=False,
                retirement=False, phase='pre',
                artifact_digest=owner.artifact.runtime_document['artifact_digest'],
                endpoint_id=self.contract['endpoint_id'],
                clock_domain=self.contract['clock_domain'], **scope, **fields))
        current = self.pending
        if self.offered is None and pre['valid']:
            self.offered = pre
        if self.offered is not None and not self._stable(pre, self.offered):
            raise ValueError('native-bus-offered-request-changed')
        if current is not None:
            if not self._stable(pre, current['native']):
                raise ValueError('native-bus-request-or-marker-changed')
            if receipt.tick_after - current['accepted_tick'] > 2 * self.trace['max_wait_cycles'] + 4:
                raise ValueError('native-bus-observation-wait-bound')
        if pre['valid'] and pre['ready']:
            if (current is None or current['state'] != 'response'
                    or receipt.tick_after != current['response_tick'] + 1
                    or pre['rdata'] != current['response']):
                raise ValueError('native-bus-completion-without-matching-response')
            record('native_bus_completed', transaction=deepcopy(current['transaction']),
                   native=pre, accepted_scope=current['accepted_scope'],
                   response_scope=current['response_scope'],
                   memory_read_snapshot=current.get('memory_read_snapshot'),
                   transfer_type=('instruction_bus_transfer' if pre['instruction']
                                  else 'data_bus_transfer'))
            self.pending = None
            current = None
            self.offered = post if post['valid'] else None
            # Completion POST may already carry the next CPU tuple.
        elif current is not None and not self._stable(post, current['native']):
            raise ValueError('native-bus-post-request-or-marker-changed')
        if not (pre['valid'] and pre['ready']):
            if self.offered is not None and not self._stable(post, self.offered):
                raise ValueError('native-bus-post-offered-request-changed')
            if self.offered is None and post['valid']:
                self.offered = post
        accepted = backend['m_req_valid'] and backend['m_req_ready']
        consumed = backend['m_rsp_valid'] and backend['m_rsp_ready']
        if accepted:
            if current is not None or consumed or pre['ready'] or not pre['valid']:
                raise ValueError('native-bus-concurrent-acceptance')
            if (backend['m_req_addr'] != pre['addr']
                    or backend['m_req_write'] != int(bool(pre['wstrb']))
                    or backend['m_req_be'] != (pre['wstrb'] or 15)
                    or (pre['wstrb'] and backend['m_req_wdata'] != pre['wdata'])
                    or (pre['instruction'] and pre['wstrb'])
                    or not self._stable(post, pre)):
                raise ValueError('native-bus-backend-request-mismatch')
            self.memory_sequence += 1
            if self.memory_sequence != owner._sequence_memory + 1:
                raise ValueError('native-bus-memory-sequence-drift')
            from .ledger import TransactionKey
            key = TransactionKey('local-execution', owner._case_id,
                owner.artifact.plan.request.instance_id, epoch, 'memory', self.memory_sequence)
            self.pending = dict(state='accepted', native=pre, transaction=asdict(key),
                accepted_tick=receipt.tick_after, accepted_scope=scope)
            record('native_backend_request_accepted', transaction=asdict(key), native=pre)
        if consumed:
            current = self.pending
            if (current is None or current['state'] != 'accepted'
                    or pre['ready']
                    or pending_response is None
                    or pending_response[1] != current['transaction']['source_sequence']
                    or backend['m_rsp_error'] != 0
                    or backend['m_rsp_rdata'] != pending_response[0]
                    or not post['ready'] or post['rdata'] != pending_response[0]):
                raise ValueError('native-bus-backend-response-mismatch')
            current.update(state='response', response=pending_response[0],
                           response_tick=receipt.tick_after, response_scope=scope)
            record('native_backend_response_consumed', transaction=deepcopy(current['transaction']),
                   value=pending_response[0], native_post_is_offer_only=True)
        self.sequence, self.tick = receipt.sequence, receipt.tick_after

    def bind_read_snapshot(self, key, snapshot):
        if (self.pending is None or asdict(key) != self.pending['transaction']
                or snapshot.transaction_id != str(key) or len(snapshot.data) != 4):
            raise ValueError('native-bus-read-snapshot-key')
        row = asdict(snapshot)
        row['data_hex'] = row.pop('data').hex()
        self.pending['memory_read_snapshot'] = row

    def drain(self):
        result, self.samples = self.samples, []
        return result
