"""PULP GPIO's native APB3 and external pins over a generated local driver."""
from __future__ import annotations

from collections import deque
from types import MappingProxyType
from dataclasses import asdict
import copy
import json
from typing import Mapping

from .session import GeneratedLocalSession
from .wire import DriverReceipt
from .pulp_gpio_probe_contract import pulp_gpio_observation_contract, PULP_GPIO_PROBES


_WORD = (1 << 32) - 1
_MAX_PENDING_SAMPLES = 65_536
_GPIO_FIELDS = ('gpio_out', 'gpio_dir', 'gpio_in_sync', 'interrupt')


def _word(value: object, name: str) -> int:
    if type(value) is not int or not 0 <= value <= _WORD:
        raise ValueError('invalid RTL GPIO observation: ' + name)
    return value


class GeneratedPulpGpioSession(GeneratedLocalSession):
    """One actual PULP apb_gpio process, reset only on testcase/reset policy."""

    artifact_kind = 'apb_gpio'
    max_local_ticks_per_step = 1

    def __init__(self, artifact, *, base_dir, cache_dir, **kwargs):
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir, **kwargs)
        if self._expected_ready()[3] != 'apb_gpio':
            raise ValueError('generated GPIO session requires apb_gpio artifact')
        contract = self._artifact_document.get('gpio_observation_contract')
        if 'gpio_observation_contract' in self._artifact_document and contract != pulp_gpio_observation_contract():
            raise ValueError('invalid GPIO observation contract')
        wait = self._artifact_document.get('effective_max_wait_cycles')
        if type(wait) is not int or wait < 1:
            raise ValueError('invalid APB wait bound')
        # Match the generator's conservative per-command sample reservation.
        self.max_local_ticks_per_register_access = 2 * wait + 5
        self.gpio_events = []
        self._gpio_access_sequence = 0
        self._gpio_active_context = None
        self._next_gpio_input_context = None
        self._active_gpio_input_context = None
        self._active_gpio_input_value = None
        self._gpio_step_scope = None
        self._gpio_in = 0
        self._pin_settle_until = 0
        self._samples: deque[dict[str, object]] = deque()
        self._ordinary_apb_receipts = None

    def configure_ordinary_apb_access_receipts(self, *, max_records=256):
        if self._ordinary_apb_receipts is not None:
            raise ValueError('ordinary-access-already-configured')
        from .ordinary_apb_access_receipts import OrdinaryApbAccessReceipts
        self._ordinary_apb_receipts = OrdinaryApbAccessReceipts(self,max_records=max_records)

    @property
    def ordinary_apb_access_receipts_enabled(self):
        if self._ordinary_apb_receipts is None:
            return False
        self._ordinary_apb_receipts.validate()
        return True

    @property
    def ordinary_apb_access_events(self):
        return self._ordinary_apb_receipts.events if self._ordinary_apb_receipts is not None else ()

    def execute_observed_register_access(self, key, *, delivery_context):
        if self._ordinary_apb_receipts is None:
            raise ValueError('ordinary-access-not-configured')
        return self._ordinary_apb_receipts.execute(key,delivery_context)

    def ordinary_apb_access_receipt(self, access_id):
        if self._ordinary_apb_receipts is None:
            raise ValueError('ordinary-access-not-configured')
        return self._ordinary_apb_receipts.lookup(access_id)

    def ordinary_apb_sample_digest(self, access_id, local_tick, phase):
        if self._ordinary_apb_receipts is None:
            raise ValueError('ordinary-access-not-configured')
        return self._ordinary_apb_receipts.sample_digest(access_id,local_tick,phase)

    def ordinary_apb_delivery_failed(self, key, access_id):
        if self._ordinary_apb_receipts is None:
            raise ValueError('ordinary-access-not-configured')
        self._ordinary_apb_receipts.delivery_failed(key,access_id)

    def identity_document(self) -> dict[str, object]:
        identity = super().identity_document()
        if self._ordinary_apb_receipts is not None:
            identity['ordinary_apb_access_receipts'] = self._ordinary_apb_receipts.configuration()
        if self.routed_register_access_enabled:
            identity.update(
                gpio_target_context_schema_version='pulp_gpio_routed_access.v1',
                gpio_observation_contract=copy.deepcopy(
                    self._artifact_document['gpio_observation_contract']))
        return identity

    @property
    def routed_register_access_enabled(self) -> bool:
        self._check_artifact_stable()
        return 'gpio_observation_contract' in self._artifact_document

    def dma_master_target_provider_identity_document(self):
        """Version the PULP DMA adapter and the native observation it needs."""
        if not self.routed_register_access_enabled:
            raise ValueError('PULP GPIO DMA provider requires observation variant')
        return {
            'schema_version': 'pulp_gpio_dma_target_provider.v1',
            'api_schema_version': 'dma_master_target_access.v1',
            'implementation_profile': 'pulp_gpio_padout_apb3.v1',
            'observation_contract': copy.deepcopy(
                self._artifact_document['gpio_observation_contract']),
            'operations': [{'operation': 'write', 'register': 'PADOUT',
                'offset': 12, 'byte_enable': 15}],
        }

    def routed_register_access(self, source_transaction, *, address, offset,
                               write, value, be, delivery_context):
        from myfuzz.scenario.ledger import TransactionKey
        if not self.routed_register_access_enabled:
            raise ValueError('GPIO routed context requires observation variant')
        if not isinstance(source_transaction, TransactionKey):
            raise ValueError('invalid GPIO transaction context')
        expected = {'source_transaction': asdict(source_transaction),
                    'address': address, 'offset': offset, 'write': write,
                    'value': value, 'be': be}
        if (not isinstance(delivery_context, dict)
                or any(delivery_context.get(k) != v for k, v in expected.items())
                or self._gpio_active_context is not None):
            raise ValueError('GPIO routed context mismatch')
        self._offset(offset)
        _word(value, 'write value')
        if write and (type(be) is not int or be != 15):
            raise ValueError('PULP GPIO APB3 requires a full-word write')
        self._gpio_access_sequence += 1
        scope = {'component': delivery_context.get('device_id'),
                 'reset_epoch': self.reset_epoch,
                 'command_sequence': self._sequence + 1}
        access_id = (f"gpio-access:{scope['component']}:{self.reset_epoch}:"
                     f"{self._gpio_access_sequence}")
        common = {'schema_version': 'gpio_target_observation.v1',
                  'component': scope['component'],
                  'reset_epoch': self.reset_epoch, 'source_epoch': self.reset_epoch,
                  'source_transaction': asdict(source_transaction),
                  'command_scope': scope, 'access_id': access_id,
                  'raw_offset': offset, 'decoded_offset': ((offset >> 2) & 31) << 2,
                  'write': write, 'wdata': value if write else None,
                  'observation_contract': copy.deepcopy(
                      self._artifact_document['gpio_observation_contract'])}
        self._gpio_active_context = copy.deepcopy({**expected, 'command_scope': scope})
        try:
            reply = self.command('ACCESS_GPIO',
                                 (self._gpio_in, int(write), offset, value if write else 0, 15))
            raw = copy.deepcopy(reply.payload)
            self.gpio_events.append({**common, 'kind': 'gpio_target_receipt',
                                     'status': 'received', 'raw_payload': raw,
                                     'transport_sequence': reply.sequence})
            command_events_start = len(self.gpio_events)
            result = self._take(reply)
            witnesses = []
            for sample in reply.payload['samples']:
                pre = self._normalized_physical(sample['pre'])
                post = self._normalized_physical(sample['post'])
                if pre.get('gpio_probe_psel') == 1 and pre.get('gpio_probe_penable') == 1:
                    witnesses.append((sample, pre, post))
            apb_access = {**common, 'kind': 'gpio_apb_access', 'status': 'incomplete', 'phase': 'pre'}
            status = 'incomplete'
            if len(witnesses) == 1:
                sample, pre, post = witnesses[0]
                complete = all(
                    type(state.get('gpio_probe_' + name)) is int
                    and 0 <= state['gpio_probe_' + name] < (1 << width)
                    for state in (pre, post)
                    for name, (width, _) in PULP_GPIO_PROBES.items())
                valid = (complete and pre.get('gpio_probe_apb_addr') == offset
                         and pre.get('gpio_probe_pwrite') == int(write)
                         and (not write or pre.get('gpio_probe_pwdata') == value)
                         and pre.get('gpio_probe_pready') == 1
                         and pre.get('gpio_probe_pslverr') == 0
                         and (write or pre.get('gpio_probe_prdata') == result['rdata']))
                status = 'observed' if valid else 'context_mismatch'
                apb_access = copy.deepcopy({**common,
                    'kind': 'gpio_apb_access', 'status': status,
                    'local_tick': self._tick_base + sample['local_tick'],
                    'phase': 'pre', 'pre': pre, 'post': post,
                    'read_rdata': pre.get('gpio_probe_prdata') if not write else None,
                    'target_response': {'rdata': result['rdata'], 'error': result['error']}})
                if not write and common['decoded_offset'] == 36:
                    apb_access['status_read_outcome'] = (
                        'new_event_priority' if (pre.get('gpio_probe_native_irq') == 1
                            and post.get('gpio_probe_status') ==
                            (pre.get('gpio_probe_status', 0) | pre.get('gpio_probe_irq_trigger_mask', 0)))
                        else 'cleared' if post.get('gpio_probe_status') == 0
                        else 'unknown')
                if status == 'observed':
                    matches = [index for index in range(command_events_start, len(self.gpio_events))
                               if self.gpio_events[index].get('kind') == 'gpio_tick_observation'
                               and self.gpio_events[index].get('command_scope') == scope
                               and self.gpio_events[index].get('local_tick') == apb_access['local_tick']]
                    if len(matches) != 1:
                        raise ValueError('GPIO ACCESS paired tick identity mismatch')
                    # This command's facts are unpublished until callback return.
                    # Only the exact matching tick moves behind its ACCESS fact.
                    self.gpio_events.insert(matches[0], copy.deepcopy(apb_access))
                else:
                    self.gpio_events.append(copy.deepcopy(apb_access))
            if result['error']:
                raise RuntimeError('generated GPIO APB access error')
            if status != 'observed':
                self.gpio_events.append({**common, 'kind': 'gpio_access_terminal',
                                         'status': status})
            transport = {}
            for name, valid_name, ready_name in (
                    ('target_request', 'gpio_req_valid', 'gpio_req_ready'),
                    ('target_response', 'gpio_rsp_valid', 'gpio_rsp_ready')):
                accepted = [sample for sample in reply.payload['samples']
                            if sample['pre'].get('backend', {}).get(valid_name) == 1
                            and sample['pre'].get('backend', {}).get(ready_name) == 1]
                witness = {**common, 'schema_version': 'gpio_target_transport.v1',
                           'status': 'incomplete', 'phase': 'pre'}
                if len(accepted) == 1:
                    sample = accepted[0]
                    backend = sample['pre']['backend']
                    if name == 'target_request':
                        valid = all(backend.get(k) == v for k, v in {
                            'gpio_req_addr': offset, 'gpio_req_write': int(write),
                            'gpio_req_wdata': value if write else 0,
                            'gpio_req_be': 15}.items())
                    else:
                        valid = (backend.get('gpio_rsp_rdata') == result['rdata']
                                 and backend.get('gpio_rsp_error') == result['error'])
                    witness.update(status='observed' if valid else 'context_mismatch',
                                   local_tick=self._tick_base + sample['local_tick'],
                                   backend=copy.deepcopy(backend))
                transport[name] = witness
            if (status == 'observed'
                    and transport['target_request']['status'] == 'observed'
                    and transport['target_response']['status'] == 'observed'):
                ticks = (transport['target_request']['local_tick'],
                         self._tick_base + witnesses[0][0]['local_tick'],
                         transport['target_response']['local_tick'])
                if not ticks[0] < ticks[1] < ticks[2]:
                    for name in transport:
                        transport[name] = {**transport[name], 'status': 'context_mismatch'}
            else:
                for name in transport:
                    transport[name] = {**transport[name], 'status': 'incomplete'}
            for name, witness in transport.items():
                self.gpio_events.append(copy.deepcopy({**witness, 'kind': name}))
            return {'rdata': result['rdata'], 'target_access_id': access_id,
                    'target_apb_access': copy.deepcopy(apb_access), **transport}
        except BaseException:
            self.gpio_events.append({**common, 'kind': 'gpio_access_terminal',
                                     'status': 'uncertain'})
            raise
        finally:
            self._gpio_active_context = None

    def dma_master_target_access(self, source_transaction, *, address, offset,
                                 write, value, byte_enable, delivery_context):
        """Prove one DMA word write reached this instance's real PADOUT RTL."""
        from myfuzz.scenario.ledger import TransactionKey

        if not self.routed_register_access_enabled:
            raise ValueError('PULP GPIO DMA target requires observation variant')
        if type(source_transaction) is not TransactionKey:
            raise ValueError('invalid PULP GPIO DMA transaction key')
        if (type(write) is not bool or not write):
            raise ValueError('PULP GPIO DMA target supports PADOUT write only')
        if type(offset) is not int or offset != 12:
            raise ValueError('PULP GPIO DMA target supports PADOUT offset 12 only')
        if (type(address) is not int or not 0 <= address < 1 << 64
                or address % 4):
            raise ValueError('invalid PULP GPIO DMA target address')
        _word(value, 'DMA PADOUT value')
        if type(byte_enable) is not int or byte_enable != 15:
            raise ValueError('PULP GPIO DMA target requires a full-word write')

        context_fields = {
            'source_transaction', 'device_id', 'window_base', 'window_size',
            'address', 'offset', 'write', 'value', 'be'}
        expected = {
            'source_transaction': asdict(source_transaction),
            'address': address, 'offset': offset, 'write': True,
            'value': value, 'be': byte_enable,
        }
        if (type(delivery_context) is not dict
                or set(delivery_context) != context_fields
                or any(delivery_context.get(name) != actual
                       for name, actual in expected.items())):
            raise ValueError('PULP GPIO DMA delivery context mismatch')
        context_key = delivery_context['source_transaction']
        key_fields = {'execution_id', 'testcase_id', 'source_component',
                      'source_epoch', 'channel_id', 'source_sequence'}
        if (type(context_key) is not dict or set(context_key) != key_fields
                or any(type(context_key[name]) is not str
                       for name in ('execution_id', 'testcase_id',
                                    'source_component', 'channel_id'))
                or any(type(context_key[name]) is not int
                       for name in ('source_epoch', 'source_sequence'))
                or type(delivery_context['address']) is not int
                or type(delivery_context['offset']) is not int
                or type(delivery_context['write']) is not bool
                or type(delivery_context['value']) is not int
                or type(delivery_context['be']) is not int):
            raise ValueError('PULP GPIO DMA delivery context types are invalid')
        component = self._artifact_document.get('plan', {}).get('instance_id')
        base, size = delivery_context['window_base'], delivery_context['window_size']
        if (type(component) is not str or not component
                or delivery_context['device_id'] != component
                or type(base) is not int or not 0 <= base < 1 << 64
                or base % 0x1000 != 0
                or type(size) is not int or size < 4 or size % 4 != 0
                or base + size > 1 << 64
                or address != base + offset or address + 4 > base + size):
            raise ValueError('PULP GPIO DMA window context mismatch')

        request = {
            'address': address, 'offset': offset, 'write': True,
            'value': value, 'byte_enable': byte_enable,
        }
        key_document = asdict(source_transaction)
        called = False
        try:
            # This is the sole APB entry point. It retains the native tick,
            # target access, request, and response facts under the exact key.
            called = True
            routed = self.routed_register_access(
                source_transaction, address=address, offset=offset,
                write=True, value=value, be=byte_enable,
                delivery_context=copy.deepcopy(delivery_context))
            if type(routed) is not dict:
                raise ValueError('PULP GPIO DMA target access receipt is invalid')

            access = routed.get('target_apb_access')
            target_request = routed.get('target_request')
            target_response = routed.get('target_response')
            access_id = routed.get('target_access_id')
            if (type(access) is not dict or type(access.get('pre')) is not dict
                    or type(access.get('post')) is not dict):
                raise ValueError('PULP GPIO DMA APB access was not observed')
            pre, post = access['pre'], access['post']
            if pre.get('gpio_probe_pslverr') != 0:
                raise ValueError('PULP GPIO DMA APB error was observed')
            apb_matches = all(
                type(pre.get(name)) is int and pre[name] == actual
                for name, actual in {
                    'gpio_probe_psel': 1,
                    'gpio_probe_penable': 1,
                    'gpio_probe_apb_addr': offset,
                    'gpio_probe_pwrite': 1,
                    'gpio_probe_pwdata': value,
                    'gpio_probe_pready': 1,
                    'gpio_probe_pslverr': 0,
                }.items())
            if not apb_matches:
                raise ValueError('PULP GPIO DMA APB request/access mismatch')
            access_ok = (
                access.get('schema_version') == 'gpio_target_observation.v1'
                and access.get('status') == 'observed'
                and access.get('source_transaction') == key_document
                and access.get('component') == component
                and access.get('raw_offset') == offset
                and access.get('decoded_offset') == offset
                and access.get('write') is True
                and access.get('wdata') == value
                and type(access_id) is str and bool(access_id)
                and access.get('access_id') == access_id
                and type(access.get('local_tick')) is int)
            if not access_ok:
                raise ValueError('PULP GPIO DMA APB access was not observed')

            request_backend = (target_request.get('backend')
                               if type(target_request) is dict else None)
            request_identity_ok = (
                type(target_request) is dict
                and target_request.get('schema_version') == 'gpio_target_transport.v1'
                and target_request.get('source_transaction') == key_document
                and target_request.get('access_id') == access_id
                and type(target_request.get('local_tick')) is int
                and type(request_backend) is dict)
            if not request_identity_ok:
                raise ValueError('PULP GPIO DMA target request was not observed')
            request_matches = all(
                type(request_backend.get(name)) is int
                and request_backend[name] == actual
                for name, actual in {
                    'gpio_req_valid': 1,
                    'gpio_req_ready': 1,
                    'gpio_req_addr': offset,
                    'gpio_req_write': 1,
                    'gpio_req_wdata': value,
                    'gpio_req_be': byte_enable,
                }.items())
            if not request_matches:
                raise ValueError('PULP GPIO DMA target request was not observed')

            access_response = access.get('target_response')
            response_backend = (target_response.get('backend')
                                if type(target_response) is dict else None)
            response_identity_ok = (
                type(target_response) is dict
                and target_response.get('schema_version') == 'gpio_target_transport.v1'
                and target_response.get('source_transaction') == key_document
                and target_response.get('access_id') == access_id
                and type(target_response.get('local_tick')) is int
                and type(response_backend) is dict
                and type(access_response) is dict)
            if not response_identity_ok:
                raise ValueError('PULP GPIO DMA target response was not observed or had APB error')
            response_matches = (
                type(access_response.get('rdata')) is int
                and 0 <= access_response['rdata'] <= _WORD
                and type(access_response.get('error')) is int
                and access_response['error'] == 0
                and type(response_backend.get('gpio_rsp_rdata')) is int
                and response_backend['gpio_rsp_rdata'] == access_response['rdata']
                and type(response_backend.get('gpio_rsp_error')) is int
                and response_backend['gpio_rsp_error'] == 0
                and type(response_backend.get('gpio_rsp_valid')) is int
                and response_backend['gpio_rsp_valid'] == 1
                and type(response_backend.get('gpio_rsp_ready')) is int
                and response_backend['gpio_rsp_ready'] == 1
                and routed.get('rdata') == access_response['rdata'])
            if (not response_matches
                    or target_response.get('status') != 'observed'):
                raise ValueError('PULP GPIO DMA target response was not observed or had APB error')
            if target_request.get('status') != 'observed':
                raise ValueError('PULP GPIO DMA target request was not observed')

            tick = access['local_tick']
            if not (target_request['local_tick'] < tick
                    < target_response['local_tick']):
                raise ValueError('PULP GPIO DMA APB request/response order mismatch')
            post_value = post.get('gpio_probe_out')
            if type(post_value) is not int or post_value != value:
                raise ValueError('PULP GPIO DMA PADOUT effect was not observed')

            effect = {
                'schema_version': 'pulp_gpio_padout_effect.v1',
                'status': 'observed',
                'source_transaction': copy.deepcopy(key_document),
                'request': copy.deepcopy(request),
                'register': 'PADOUT', 'offset': offset,
                'accepted_value': value, 'post_probe_value': post_value,
                'access_id': access_id, 'local_tick': tick,
            }
            return {
                'schema_version': 'dma_master_target_access.v1',
                'status': 'observed',
                'source_transaction': copy.deepcopy(key_document),
                'request': copy.deepcopy(request),
                'response': {'rdata': access_response['rdata'], 'error': 0},
                'target_access_id': access_id,
                'target_access': copy.deepcopy(access),
                'target_request': copy.deepcopy(target_request),
                'target_response': copy.deepcopy(target_response),
                'target_effect': effect,
            }
        except BaseException:
            if called:
                self.gpio_events.append({
                    'schema_version': 'pulp_gpio_dma_target_terminal.v1',
                    'kind': 'gpio_dma_target_terminal', 'status': 'uncertain',
                    'source_transaction': copy.deepcopy(key_document),
                    'request': copy.deepcopy(request),
                    'delivery_context': copy.deepcopy(delivery_context),
                    'reset_epoch': self.reset_epoch,
                })
            raise

    def _normalized_physical(self, snapshot):
        raw = snapshot.get('physical', {})
        return {row['physical_port']: raw[row['runtime_name']]
                for row in self._artifact_document.get('physical_exports', ())
                if row['runtime_name'] in raw}

    def set_next_gpio_input_context(self, context) -> None:
        if not self.routed_register_access_enabled:
            raise ValueError('GPIO input context requires observation variant')
        if not isinstance(context, dict) or not isinstance(context.get('segments'), list):
            raise ValueError('invalid GPIO input context')
        used = 0
        for segment in context['segments']:
            if not isinstance(segment, dict):
                raise ValueError('invalid GPIO input segment')
            lo, width, value = (segment.get(n) for n in ('bit_lo', 'width', 'value'))
            if (type(lo) is not int or type(width) is not int or not 0 <= lo < 32
                    or not 1 <= width <= 32-lo or type(value) is not int
                    or not 0 <= value < 1 << width or not isinstance(segment.get('origin'), dict)):
                raise ValueError('invalid GPIO input segment')
            mask = ((1 << width)-1) << lo
            if used & mask:
                raise ValueError('overlapping GPIO input context')
            used |= mask
        try:
            self._next_gpio_input_context = json.loads(json.dumps(context, allow_nan=False))
        except (TypeError, ValueError) as exc:
            raise ValueError('GPIO input context is not JSON-safe') from exc

    def _record_gpio_ticks(self, reply):
        active = self._gpio_active_context
        scope = (active.get('command_scope') if active else self._gpio_step_scope)
        if scope is None:
            scope = {'component': self._artifact_document.get('plan', {}).get('instance_id'),
                     'reset_epoch': self.reset_epoch, 'command_sequence': reply.sequence}
        for sample in reply.payload['samples']:
            pre = self._normalized_physical(sample['pre'])
            post = self._normalized_physical(sample['post'])
            if (self._active_gpio_input_context is not None
                    and any(state.get('gpio_in') != self._active_gpio_input_value
                            for state in (pre, post))):
                self._active_gpio_input_context = None
                self._active_gpio_input_value = None
            self.gpio_events.append(copy.deepcopy({
                'schema_version': 'gpio_tick_observation.v1', 'kind': 'gpio_tick_observation',
                'component': scope['component'], 'source_epoch': self.reset_epoch,
                'reset_epoch': self.reset_epoch, 'local_tick': self._tick_base + sample['local_tick'],
                'command_scope': scope, 'observation_contract':
                    self._artifact_document['gpio_observation_contract'],
                'pre': pre, 'post': post,
                'active_input_context': self._active_gpio_input_context}))

    def routed_delivery_failed(self, source_transaction, access_id) -> None:
        self.gpio_events.append({'schema_version': 'gpio_target_observation.v1',
                                 'kind': 'gpio_access_terminal',
                                 'status': 'uncertain_source_response',
                                 'source_transaction': asdict(source_transaction),
                                 'access_id': access_id, 'reset_epoch': self.reset_epoch})

    @property
    def pending_responses(self) -> int:
        return 0

    @property
    def pending_events(self) -> int:
        # This only schedules remaining synchronizer clocks; it predicts no IRQ.
        return max(0, self._pin_settle_until - self.local_ticks)

    def begin_quiesce(self) -> None:
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('generated GPIO process is not running')

    def _take(self, reply: DriverReceipt) -> dict[str, int]:
        try:
            return self._take_impl(reply)
        except BaseException:
            if self._native_reset_observation is not None:
                self._native_reset_observation._consumer_failed(self, 'gpio_take_failed_after_parse')
            raise

    def _take_impl(self, reply: DriverReceipt) -> dict[str, int]:
        if reply.status != 'result' or reply.payload is None:
            raise RuntimeError('generated GPIO protocol error: ' + str(reply.error_code))
        payload = reply.payload
        observed = payload['observations']
        if not isinstance(observed, dict):
            raise ValueError('invalid generated GPIO observations')
        values = {name: _word(observed.get(name), name) for name in _GPIO_FIELDS}
        padcfg = observed.get('gpio_padcfg')
        if (type(padcfg) is not str or len(padcfg) != 32
                or any(character not in '0123456789abcdef' for character in padcfg)):
            raise ValueError('invalid RTL GPIO padcfg observation')
        values['gpio_padcfg'] = int(padcfg, 16)
        values['irq'] = values['interrupt']
        values['rdata'] = _word(payload['rdata'], 'rdata')
        values['error'] = payload['error']
        samples = payload['samples']
        if self.routed_register_access_enabled:
            self._record_gpio_ticks(reply)
        if len(self._samples) + len(samples) > _MAX_PENDING_SAMPLES:
            raise RuntimeError('generated GPIO tick evidence capacity exceeded')
        for sample in samples:
            # The wire tick is process-local; public sample ticks are lifetime
            # local ticks, including explicit component reset epochs.
            self._samples.append({**copy.deepcopy(sample),
                                  'local_tick': self._tick_base + sample['local_tick']})
        return values

    def drain_tick_samples(self) -> list[dict[str, object]]:
        result = list(self._samples)
        self._samples.clear()
        return result

    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, int]:
        if not isinstance(inputs, Mapping) or set(inputs) - {'gpio_in'}:
            raise ValueError('undeclared generated GPIO input')
        value = inputs.get('gpio_in', self._gpio_in)
        _word(value, 'gpio_in')
        if value != self._gpio_in:
            self._pin_settle_until = self.local_ticks + 4
        self._gpio_in = value
        if not self.routed_register_access_enabled:
            return self._take(self.command('STEP_GPIO', (value,)))
        context = self._next_gpio_input_context
        self._next_gpio_input_context = None
        component = self._artifact_document.get('plan', {}).get('instance_id')
        scope = {'component': component, 'reset_epoch': self.reset_epoch,
                 'command_sequence': self._sequence + 1}
        self._gpio_step_scope = scope
        try:
            reply = self.command('STEP_GPIO', (value,))
            physical = [self._normalized_physical(sample[phase])
                        for sample in reply.payload['samples'] for phase in ('pre','post')]
            matches = len(reply.payload['samples']) == 1 and all(type(p.get('gpio_in')) is int
                                             and p['gpio_in'] == value for p in physical)
            if context is None and (not matches or value != self._active_gpio_input_value):
                self._active_gpio_input_context = None
                self._active_gpio_input_value = None
            if context is not None:
                matches = matches and all(
                    ((value >> seg['bit_lo']) & ((1 << seg['width'])-1)) == seg['value']
                    for seg in context['segments'])
                self._active_gpio_input_context = copy.deepcopy(context) if matches else None
                self._active_gpio_input_value = value if matches else None
            result = self._take(reply)
            if context is not None:
                tick = self._tick_base + reply.payload['samples'][0]['local_tick'] if physical else None
                self.gpio_events.append(copy.deepcopy({
                    'schema_version': 'gpio_input_applied.v1',
                    'kind': 'gpio_input_applied' if matches else 'gpio_input_context_terminal',
                    'status': 'observed' if matches else 'context_mismatch',
                    'component': component, 'reset_epoch': self.reset_epoch,
                    'source_epoch': self.reset_epoch, 'local_tick': tick,
                    'command_scope': scope, 'actual_receipt_ref':
                        {'command_scope': scope, 'local_tick': tick},
                    'actual_input_value': value if matches else None,
                    'requested_input_value': value, 'segments': context['segments'],
                    'observation_contract': self._artifact_document['gpio_observation_contract']}))
            return result
        except BaseException:
            self._active_gpio_input_context = None
            raise
        finally:
            self._gpio_step_scope = None

    @staticmethod
    def _offset(offset: int) -> None:
        if type(offset) is not int or not 0 <= offset <= 4092 or offset % 4:
            raise ValueError('invalid generated GPIO register offset')

    def write_register(self, offset: int, value: int, *, be: int = 15) -> None:
        self._offset(offset)
        _word(value, 'write value')
        if be != 15 or type(be) is not int:
            raise ValueError('PULP GPIO APB3 requires a full-word write')
        result = self._take(self.command('ACCESS_GPIO',
                                         (self._gpio_in, 1, offset, value, be)))
        if result['error']:
            if self._native_reset_observation is not None:
                self._native_reset_observation._consumer_failed(self, 'gpio_write_error_after_parse')
            raise RuntimeError(f'generated GPIO APB write error at {offset:#x}')

    def read_register(self, offset: int) -> int:
        self._offset(offset)
        result = self._take(self.command('ACCESS_GPIO',
                                         (self._gpio_in, 0, offset, 0, 15)))
        if result['error']:
            if self._native_reset_observation is not None:
                self._native_reset_observation._consumer_failed(self, 'gpio_read_error_after_parse')
            raise RuntimeError(f'generated GPIO APB read error at {offset:#x}')
        return result['rdata']

    def reset_local(self) -> dict[str, int]:
        enabled = self.routed_register_access_enabled
        previous_epoch = self.reset_epoch
        result = super().reset_local()
        self._samples.clear()
        self._active_gpio_input_context = None
        self._active_gpio_input_value = None
        self._next_gpio_input_context = None
        self._gpio_step_scope = None
        self._gpio_in = 0
        self._pin_settle_until = self.local_ticks
        if enabled:
            if self.reset_epoch <= previous_epoch:
                raise ValueError('GPIO reset receipt did not advance epoch')
            component = self._artifact_document.get('plan', {}).get('instance_id')
            scope = {'component': component, 'reset_epoch': self.reset_epoch,
                     'command_sequence': self._sequence}
            self.gpio_events.append({
                'schema_version': 'gpio_reset.v1', 'kind': 'gpio_reset',
                'status': 'observed', 'component': component,
                'reset_epoch': self.reset_epoch, 'source_epoch': self.reset_epoch,
                'previous_reset_epoch': previous_epoch, 'local_tick': self.local_ticks,
                'command_scope': scope,
                'observation_contract': copy.deepcopy(self._artifact_document['gpio_observation_contract']),
                'reset_receipt': {'kind': 'authenticated_generated_driver_ready',
                                  'driver_identity': list(self._expected_ready()),
                                  'process_sequence': self._sequence,
                                  'outcome': copy.deepcopy(result)}})
        return result

_NATIVE_RESET_GPIO_FUNCTIONS = MappingProxyType({name: (getattr(GeneratedPulpGpioSession,name),
    getattr(GeneratedPulpGpioSession,name).__code__) for name in
    ('_take','_take_impl','_normalized_physical','write_register','read_register','step_local','reset_local')})
_NATIVE_RESET_GPIO_FUNCTIONS_PIN = _NATIVE_RESET_GPIO_FUNCTIONS

# Exact declaration/resolved code baseline established at class definition time.
from types import MappingProxyType as _ResetMappingProxyType
_NATIVE_RESET_GPIO_CLASS = GeneratedPulpGpioSession
_NATIVE_RESET_GPIO_DECLARATIONS = _ResetMappingProxyType(dict(vars(GeneratedPulpGpioSession)))
_NATIVE_RESET_GPIO_DECLARATIONS_PIN = _NATIVE_RESET_GPIO_DECLARATIONS
_NATIVE_RESET_GPIO_RESOLVED = _ResetMappingProxyType({name: (getattr(GeneratedPulpGpioSession,name), getattr(GeneratedPulpGpioSession,name).__code__)
    for name in dir(GeneratedPulpGpioSession) if hasattr(getattr(GeneratedPulpGpioSession,name), '__code__')})
_NATIVE_RESET_GPIO_RESOLVED_PIN = _NATIVE_RESET_GPIO_RESOLVED

from .native_reset_producer_contract import _seal_code_owned_producer
_seal_code_owned_producer(GeneratedPulpGpioSession)
