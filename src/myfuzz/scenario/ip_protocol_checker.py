"""Protocol-contract checks over declared generic IP boundary samples."""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
import hashlib
import json


_SCHEMA_VERSION = 'ip_base_event.v1'
_TRACE_SCHEMA_VERSION = 'ip_protocol_trace.v1'
_REQUIRED_SIGNALS = {
    'obi': ('req', 'gnt', 'addr', 'rvalid', 'rdata'),
    'tl-ul': ('a_valid', 'a_ready', 'a_source', 'a_opcode', 'a_size',
              'a_address', 'a_mask', 'a_data', 'd_valid', 'd_ready', 'd_source',
              'd_opcode', 'd_size', 'd_data', 'd_error'),
    'apb3': ('psel', 'penable', 'pwrite', 'paddr', 'pwdata', 'pready',
             'prdata', 'pslverr'),
    'wishbone': ('cyc', 'stb', 'we', 'ack', 'stall', 'dat_w', 'sel', 'dat_r'),
    'axi4-lite': ('awvalid', 'awready', 'awaddr', 'awprot',
                  'wvalid', 'wready', 'wdata', 'wstrb',
                  'bvalid', 'bready', 'bresp',
                  'arvalid', 'arready', 'araddr', 'arprot',
                  'rvalid', 'rready', 'rdata', 'rresp'),
    'ahb-lite': ('haddr', 'hwdata', 'hsel', 'hwrite', 'hreadyin',
                 'htrans', 'hsize', 'hresp', 'hreadyout', 'hrdata'),
}
_BOOLEAN_SIGNALS = frozenset((
    'req', 'gnt', 'rvalid', 'we', 'error',
    'a_valid', 'a_ready', 'd_valid', 'd_ready', 'd_error',
    'psel', 'penable', 'pwrite', 'pready', 'pslverr',
    'cyc', 'stb', 'we', 'ack', 'stall', 'err',
    'awvalid', 'awready', 'wvalid', 'wready',
    'bvalid', 'bready', 'arvalid', 'arready', 'rvalid', 'rready',
    'hsel', 'hwrite', 'hreadyin', 'hresp', 'hreadyout'))


class IpProtocolChecker:
    """Check handshakes and transaction-level invariants without IP semantics.

    The checker consumes only pre-edge samples of the declared passive protocol
    tap. It reports protocol facts and does not infer the meaning of any
    register operation or compare unknown IP write/read values.
    """

    def __init__(self, *, component_id: str, instance_id: str,
                 protocol_trace: Mapping[str, object]):
        if (type(component_id) is not str or not component_id
                or type(instance_id) is not str or not instance_id):
            raise ValueError('protocol-checker-component-identity-required')
        if not isinstance(protocol_trace, Mapping):
            raise ValueError('protocol-checker-trace-contract-required')
        protocol = protocol_trace.get('protocol')
        endpoint_id = protocol_trace.get('endpoint_id')
        clock_domain = protocol_trace.get('clock_domain')
        max_wait = protocol_trace.get('max_wait_cycles')
        signals = protocol_trace.get('signals')
        widths = protocol_trace.get('signal_widths')
        if (protocol_trace.get('schema_version') != _TRACE_SCHEMA_VERSION
                or type(protocol) is not str
                or protocol not in _REQUIRED_SIGNALS
                or type(endpoint_id) is not str or not endpoint_id
                or type(clock_domain) is not str or not clock_domain
                or type(max_wait) is not int or max_wait < 1
                or not isinstance(signals, Mapping)
                or not isinstance(widths, Mapping)):
            raise ValueError('protocol-checker-trace-contract-invalid')
        required = set(_REQUIRED_SIGNALS[protocol])
        wishbone_byte_enable = protocol_trace.get('byte_enable')
        wishbone_no_select = protocol == 'wishbone' and 'sel' not in signals
        if (protocol == 'wishbone' and wishbone_no_select
                and (not isinstance(wishbone_byte_enable, Mapping)
                     or wishbone_byte_enable.get('signal') != 'absent')):
            raise ValueError('protocol-checker-wishbone-byte-enable-contract-required')
        if (protocol == 'wishbone' and not wishbone_no_select
                and isinstance(wishbone_byte_enable, Mapping)
                and wishbone_byte_enable.get('signal') == 'absent'):
            raise ValueError('protocol-checker-wishbone-no-select-shape-invalid')
        if wishbone_no_select:
            required.discard('sel')
        if protocol == 'obi':
            if protocol_trace.get('max_outstanding') != 1 or type(protocol_trace.get('max_outstanding')) is not int:
                raise ValueError('obi-single-outstanding-contract-required')
            if set(signals) - required - {'we', 'wdata', 'be', 'error'} or (
                    set(signals) & {'we', 'wdata', 'be'} not in (set(), {'we', 'wdata', 'be'})):
                raise ValueError('obi-read-write-shape-invalid')
        if protocol == 'wishbone' and 'adr' in signals:
            required.add('adr')
        if (not required <= set(signals)
                or set(signals) != set(widths)
                or any(type(role) is not str or not role
                       or type(name) is not str or not name
                       for role, name in signals.items())
                or any(type(role) is not str or not role
                       or type(width) is not int or width < 1
                       or role in _BOOLEAN_SIGNALS and width != 1
                       for role, width in widths.items())
                or protocol == 'tl-ul'
                and (widths.get('a_data', 0) % 8 != 0
                     or widths.get('a_data', 0) // 8
                     != widths.get('a_mask', 0)
                     or widths.get('a_data', 0) // 8 < 1
                     or (widths.get('a_data', 0) // 8)
                     & ((widths.get('a_data', 0) // 8) - 1)
                     or widths.get('a_size', 0)
                     < (widths.get('a_data', 0) // 8).bit_length() - 1)
                or protocol == 'wishbone'
                and (widths.get('dat_w', 0) % 8 != 0
                     or (wishbone_no_select and (
                         'sel' in signals
                         or set(signals) - {'cyc', 'stb', 'we', 'adr', 'dat_w',
                                            'stall', 'ack', 'dat_r', 'err'}
                         or type(protocol_trace.get('max_outstanding')) is not int
                         or protocol_trace.get('max_outstanding') != 1
                         or protocol_trace.get('same_edge_accept_completion') is not False
                         or wishbone_byte_enable.get('partial_write') is not False
                         or set(wishbone_byte_enable) not in (
                             {'signal', 'partial_write'},
                             {'signal', 'partial_write', 'fixed_value', 'basis'}
                         )
                         or 'fixed_value' in wishbone_byte_enable
                         and (type(wishbone_byte_enable.get('fixed_value')) is not int
                              or wishbone_byte_enable['fixed_value']
                              != (1 << (widths.get('dat_w', 0) // 8)) - 1
                              or wishbone_byte_enable.get('basis')
                              != 'profile.capabilities.master_fixed_byte_enable')
                         or 'fixed_value' not in wishbone_byte_enable
                         and 'basis' in wishbone_byte_enable))
                     or (not wishbone_no_select
                         and widths.get('sel', 0) != widths.get('dat_w', 0) // 8))
                or protocol == 'axi4-lite'
                and (widths.get('wstrb', 0) < 1
                     or widths.get('wdata', 0) != widths.get('rdata', 0)
                     or widths.get('wdata', 0) % 8 != 0
                     or widths.get('wstrb', 0) != widths.get('wdata', 0) // 8
                     or widths.get('bresp', 0) != 2
                     or widths.get('rresp', 0) != 2
                     or widths.get('awaddr', 0) != widths.get('araddr', 0))
                or protocol == 'obi'
                and (widths.get('addr', 0) not in (32, 64)
                     or widths.get('rdata', 0) not in (32, 64)
                     or 'we' in signals and (widths.get('wdata') != widths.get('rdata')
                          or widths.get('be') != widths.get('rdata') // 8))
                or protocol == 'ahb-lite'
                and any(widths.get(role) != expected for role, expected in (
                    ('haddr', 32), ('hwdata', 32), ('hsel', 1),
                    ('hwrite', 1), ('hreadyin', 1), ('htrans', 2),
                    ('hsize', 3), ('hresp', 1), ('hreadyout', 1),
                    ('hrdata', 32)))
                or len(set(signals.values())) != len(signals)):
            raise ValueError('protocol-checker-trace-signals-invalid')
        self.component_id = component_id
        self.instance_id = instance_id
        self.protocol = protocol
        self.endpoint_id = endpoint_id
        self.clock_domain = clock_domain
        self.max_wait_cycles = max_wait
        self._sample_group = protocol_trace.get('sample_group', 'backend')
        if self._sample_group not in ('backend', 'protocol_taps'):
            raise ValueError('protocol-trace-sample-group-invalid')
        self._signals = dict(signals)
        self._widths = dict(widths)
        self._wishbone_no_select = wishbone_no_select
        self._wishbone_max_outstanding = (
            protocol_trace.get('max_outstanding')
            if protocol == 'wishbone' and wishbone_no_select else None)
        self._wishbone_same_edge_completion = (
            protocol_trace.get('same_edge_accept_completion')
            if protocol == 'wishbone' and wishbone_no_select else None)
        self._reset_epoch: int | None = None
        self._tl_offer: dict[str, object] | None = None
        self._tl_outstanding: dict[int, dict[str, object]] = {}
        self._tl_d_offer: dict[str, object] | None = None
        self._apb_active: dict[str, object] | None = None
        self._wb_offer: dict[str, object] | None = None
        self._wb_outstanding: list[dict[str, object]] = []
        self._ahb_active: dict[str, object] | None = None
        self._obi_offer = None
        self._obi_pending = None
        # AXI4-Lite keeps one state per channel group. AW and W are checked
        # separately because their handshake order is not fixed.
        self._axil_aw: dict[str, object] | None = None
        self._axil_w: dict[str, object] | None = None
        self._axil_b: dict[str, object] | None = None
        self._axil_ar: dict[str, object] | None = None
        self._axil_r: dict[str, object] | None = None
        # An accepted write is only complete once *both* halves were accepted,
        # so each half is latched on its own handshake.
        self._axil_aw_accepted: dict[str, object] | None = None
        self._axil_w_accepted: dict[str, object] | None = None

    def _event(self, raw, epoch, code, details, *, state=None,
               native_identity=None, transaction_key=None):
        if state is not None:
            reported = state.setdefault('reported_codes', set())
            if code in reported:
                return None
            reported.add(code)
        request_ref = state.get('request_event_ref') if state is not None else None
        tick = raw['local_tick']
        return {
            'schema_version': _SCHEMA_VERSION,
            'event_type': 'protocol_violation',
            'component_id': self.component_id,
            'instance_id': self.instance_id,
            'endpoint_id': self.endpoint_id,
            'role': 'protocol_transaction',
            'raw_event_refs': [raw['event_id']],
            'related_request_event_refs': ([request_ref]
                                            if type(request_ref) is int else []),
            'local_event_id': ((f'{len(self.endpoint_id)}:{self.endpoint_id}|'
                                if self._sample_group == 'protocol_taps' else '') +
                               f'{self.instance_id}|{epoch}|{self.protocol}|'
                               f'{tick}|pre|protocol_violation|{code}|'
                               f'{raw["event_id"]}'),
            'clock_domain': self.clock_domain,
            'tick': tick,
            'reset_epoch': epoch,
            'transaction_key': transaction_key,
            'native_identity': native_identity,
            'action_ref': None,
            'source_ref': None,
            'observation_mapping_id': None,
            'observation_property': 'protocol_contract_violation',
            'payload': {'protocol': self.protocol,
                        'violation_code': code, **details},
        }

    def _emit(self, raw, epoch, emitted, code, details, *, state=None,
              native_identity=None, transaction_key=None):
        event = self._event(raw, epoch, code, details, state=state,
                            native_identity=native_identity,
                            transaction_key=transaction_key)
        if event is not None:
            event['local_event_id'] += '|' + str(len(emitted))
            emitted.append(event)

    def _read_signals(self, raw):
        outputs = raw.get('outputs')
        backend = outputs.get(self._sample_group) if isinstance(outputs, Mapping) else None
        if not isinstance(backend, Mapping):
            raise ValueError('protocol-checker-backend-sample-required')
        values = {}
        for role, name in self._signals.items():
            value = backend.get(name)
            if type(value) is not int or value < 0:
                raise ValueError('protocol-checker-signal-invalid:' + role)
            values[role] = value
        return values

    def _key(self, source, epoch):
        return {'protocol': 'tl-ul', 'endpoint_id': self.endpoint_id,
                'reset_epoch': epoch, 'source': source}

    def consume_local_tick(self, raw_event: Mapping[str, object], *,
                           reset_epoch: int) -> tuple[dict[str, object], ...]:
        if (not isinstance(raw_event, Mapping)
                or raw_event.get('kind') != 'local_tick_sample'
                or type(raw_event.get('event_id')) is not int
                or raw_event['event_id'] < 1
                or type(raw_event.get('local_tick')) is not int
                or raw_event['local_tick'] < 1
                or raw_event.get('phase') not in ('pre', 'post')
                or type(reset_epoch) is not int or reset_epoch < 0):
            raise ValueError('protocol-checker-raw-sample-invalid')
        if raw_event['phase'] == 'post':
            return ()
        emitted: list[dict[str, object]] = []
        if self._reset_epoch is not None and self._reset_epoch != reset_epoch:
            self._tl_offer = None
            self._tl_outstanding.clear()
            self._tl_d_offer = None
            self._apb_active = None
            self._wb_offer = None
            self._wb_outstanding.clear()
            self._ahb_active = None
            self._obi_offer = self._obi_pending = None
            self._axil_aw = None
            self._axil_w = None
            self._axil_b = None
            self._axil_ar = None
            self._axil_r = None
            self._axil_aw_accepted = None
            self._axil_w_accepted = None
        self._reset_epoch = reset_epoch
        signals = self._read_signals(raw_event)
        for role, value in signals.items():
            limit = 1 << self._widths[role]
            if value >= limit or role in _BOOLEAN_SIGNALS and value not in (0, 1):
                self._emit(raw_event, reset_epoch, emitted,
                           self.protocol.replace('-', '') + '_signal_out_of_range',
                           {'signal_role': role, 'observed': value,
                            'width': self._widths[role],
                            'maximum': limit - 1})
        if emitted:
            return tuple(emitted)
        if self.protocol == 'obi':
            self._consume_obi(raw_event, reset_epoch, signals, emitted)
        elif self.protocol == 'tl-ul':
            self._consume_tlul(raw_event, reset_epoch, signals, emitted)
        elif self.protocol == 'apb3':
            self._consume_apb3(raw_event, reset_epoch, signals, emitted)
        elif self.protocol == 'axi4-lite':
            self._consume_axi4_lite(raw_event, reset_epoch, signals, emitted)
        elif self.protocol == 'ahb-lite':
            self._consume_ahb_lite(raw_event, reset_epoch, signals, emitted)
        else:
            self._consume_wishbone(raw_event, reset_epoch, signals, emitted)
        return tuple(emitted)

    def _consume_ahb_lite(self, raw, epoch, signals, emitted):
        offer = signals['hsel'] == 1 and bool(signals['htrans'] & 2)
        active = self._ahb_active
        if active is not None and active['phase'] == 'data':
            if offer:
                self._emit(raw, epoch, emitted, 'ahb_single_outstanding_overlap',
                    {'address': signals['haddr']}, state=active)
            if signals['hreadyout'] == 1:
                self._ahb_active = None
            else:
                active['wait_count'] += 1
                if active['wait_count'] >= self.max_wait_cycles:
                    self._emit(raw, epoch, emitted, 'ahb_data_wait_budget_exceeded',
                        {'wait_cycles': active['wait_count'],
                         'limit': self.max_wait_cycles}, state=active)
            return
        if not offer:
            if active is not None:
                self._emit(raw, epoch, emitted, 'ahb_address_withdrawn_before_acceptance',
                    {'expected': active['payload']}, state=active)
                self._ahb_active = None
            return
        payload = {role: signals[role] for role in
                   ('haddr', 'hwrite', 'htrans', 'hsize')}
        if signals['htrans'] != 2:
            self._emit(raw, epoch, emitted, 'ahb_unsupported_transfer_type',
                {'htrans': signals['htrans']}, state=active)
        if signals['hsize'] != 2 or signals['haddr'] & 3:
            self._emit(raw, epoch, emitted, 'ahb_unaligned_or_nonword_transfer',
                {'haddr': signals['haddr'], 'hsize': signals['hsize']}, state=active)
        if active is None:
            active = {'request_event_ref': raw['event_id'], 'phase': 'address',
                'payload': payload, 'wait_count': 0, 'reported_codes': set()}
            self._ahb_active = active
        elif payload != active['payload']:
            self._emit(raw, epoch, emitted, 'ahb_address_changed_while_waiting',
                {'expected': active['payload'], 'observed': payload}, state=active)
        if signals['hreadyin'] == 1:
            active['phase'] = 'data'
            active['wait_count'] = 0
        else:
            active['wait_count'] += 1
            if active['wait_count'] >= self.max_wait_cycles:
                self._emit(raw, epoch, emitted, 'ahb_address_wait_budget_exceeded',
                    {'wait_cycles': active['wait_count'],
                     'limit': self.max_wait_cycles}, state=active)

    def _consume_tlul(self, raw, epoch, signals, emitted):
        # Match D offers against a request outstanding before this sample or
        # one accepted on this edge. TL-UL permits combinational responses.
        outstanding_before = dict(self._tl_outstanding)
        accepted_this_tick = {}
        a_valid, a_ready = signals['a_valid'] == 1, signals['a_ready'] == 1
        if a_valid:
            source = signals['a_source']
            payload = {role: value for role, value in signals.items()
                       if role.startswith('a_')
                       and role not in ('a_valid', 'a_ready')}
            offer = self._tl_offer
            if offer is None:
                offer = {'source': source, 'payload': payload,
                         'request_event_ref': raw['event_id'],
                         'wait_count': 0, 'timed_out': False,
                         'reported_codes': set()}
                self._tl_offer = offer
            elif payload != offer['payload']:
                self._emit(raw, epoch, emitted,
                           'tlul_a_payload_changed_while_stalled',
                           {'expected': offer['payload'], 'observed': payload},
                           state=offer, native_identity={
                               'channel': 'A', 'source': offer['source']},
                           transaction_key=self._key(offer['source'], epoch))
            opcode = signals['a_opcode']
            data_bytes = self._widths['a_data'] // 8
            transfer_bytes = 1 << signals['a_size']
            address = signals['a_address']
            if opcode not in (0, 1, 4):
                self._emit(raw, epoch, emitted,
                           'tlul_unsupported_opcode', {'opcode': opcode},
                           state=offer,
                           native_identity={'channel': 'A', 'source': source},
                           transaction_key=self._key(source, epoch))
            if transfer_bytes > data_bytes:
                self._emit(raw, epoch, emitted,
                           'tlul_size_exceeds_data_width',
                           {'size': signals['a_size'],
                            'data_bytes': data_bytes}, state=offer,
                           native_identity={'channel': 'A', 'source': source},
                           transaction_key=self._key(source, epoch))
            elif address % transfer_bytes:
                self._emit(raw, epoch, emitted,
                           'tlul_address_misaligned_for_size',
                           {'address': address, 'size': signals['a_size']},
                           state=offer,
                           native_identity={'channel': 'A', 'source': source},
                           transaction_key=self._key(source, epoch))
            else:
                first_lane = address % data_bytes
                last_lane = first_lane + transfer_bytes
                allowed_mask = ((1 << transfer_bytes) - 1) << first_lane
                mask = signals['a_mask']
                if opcode == 4 and mask.bit_count() > transfer_bytes:
                    self._emit(raw, epoch, emitted,
                               'tlul_mask_exceeds_size',
                               {'mask': mask, 'size': signals['a_size'],
                                'maximum_bytes': transfer_bytes}, state=offer,
                               native_identity={
                                   'channel': 'A', 'source': source},
                               transaction_key=self._key(source, epoch))
                elif last_lane > data_bytes or mask & ~allowed_mask:
                    self._emit(raw, epoch, emitted,
                               'tlul_mask_outside_transfer',
                               {'mask': mask,
                                'allowed_mask': allowed_mask,
                                'size': signals['a_size'],
                                'address': address}, state=offer,
                               native_identity={
                                   'channel': 'A', 'source': source},
                               transaction_key=self._key(source, epoch))
                elif opcode == 0 and mask != allowed_mask:
                    self._emit(raw, epoch, emitted,
                               'tlul_mask_mismatch',
                               {'mask': mask,
                                'expected_mask': allowed_mask,
                                'opcode': opcode,
                                'size': signals['a_size'],
                                'address': address}, state=offer,
                               native_identity={
                                   'channel': 'A', 'source': source},
                               transaction_key=self._key(source, epoch))
                elif opcode == 4 and mask:
                    low_lane = (mask & -mask).bit_length() - 1
                    contiguous_mask = mask >> low_lane
                    if contiguous_mask & (contiguous_mask + 1):
                        self._emit(raw, epoch, emitted,
                                   'tlul_noncontiguous_mask',
                                   {'mask': mask, 'opcode': opcode},
                                   state=offer,
                                   native_identity={
                                       'channel': 'A', 'source': source},
                                   transaction_key=self._key(source, epoch))
            if a_ready:
                if offer['source'] != source:
                    self._emit(raw, epoch, emitted,
                               'tlul_source_changed_before_acceptance',
                               {'expected': offer['source'], 'observed': source},
                               state=offer, native_identity={
                                   'channel': 'A', 'source': offer['source']},
                               transaction_key=self._key(offer['source'], epoch))
                elif source in self._tl_outstanding:
                    self._emit(raw, epoch, emitted,
                               'tlul_source_already_outstanding',
                               {'source': source}, state=offer,
                               native_identity={'channel': 'A', 'source': source},
                               transaction_key=self._key(source, epoch))
                else:
                    accepted = {
                        **offer, 'wait_count': 0, 'timed_out': False,
                        'reported_codes': set(),
                        'accepted_tick': raw['local_tick'],
                    }
                    self._tl_outstanding[source] = accepted
                    accepted_this_tick[source] = accepted
                self._tl_offer = None
            else:
                offer['wait_count'] += 1
                if (offer['wait_count'] >= self.max_wait_cycles
                        and not offer['timed_out']):
                    offer['timed_out'] = True
                    self._emit(raw, epoch, emitted,
                               'tlul_a_wait_budget_exceeded',
                               {'wait_cycles': offer['wait_count'],
                                'limit': self.max_wait_cycles},
                               state=offer, native_identity={
                                   'channel': 'A', 'source': offer['source']},
                               transaction_key=self._key(offer['source'], epoch))
        elif self._tl_offer is not None:
            offer = self._tl_offer
            self._emit(raw, epoch, emitted,
                       'tlul_a_request_withdrawn_before_acceptance',
                       {'source': offer['source']}, state=offer,
                       native_identity={'channel': 'A', 'source': offer['source']},
                       transaction_key=self._key(offer['source'], epoch))
            self._tl_offer = None

        d_valid, d_ready = signals['d_valid'] == 1, signals['d_ready'] == 1
        d_payload = {role: value for role, value in signals.items()
                     if role.startswith('d_')
                     and role not in ('d_valid', 'd_ready')}
        completed_request = None
        if d_valid:
            offer = self._tl_d_offer
            if offer is None:
                matched_request = outstanding_before.get(signals['d_source'])
                if matched_request is None:
                    matched_request = accepted_this_tick.get(signals['d_source'])
                offer = {
                    'source': signals['d_source'], 'payload': d_payload,
                    'matched_request': matched_request,
                    'request_event_ref': (matched_request['request_event_ref']
                                          if matched_request is not None else None),
                    'reported_codes': set(),
                }
                if matched_request is None:
                    self._emit(raw, epoch, emitted,
                               'tlul_response_without_outstanding_request',
                               {'source': signals['d_source']}, state=offer,
                               native_identity={'channel': 'D',
                                                'source': signals['d_source']},
                               transaction_key=self._key(signals['d_source'], epoch))
            elif d_payload != offer['payload']:
                self._emit(raw, epoch, emitted,
                           'tlul_d_payload_changed_while_stalled',
                           {'expected': offer['payload'], 'observed': d_payload},
                           state=offer, native_identity={
                               'channel': 'D', 'source': offer['source']},
                           transaction_key=self._key(offer['source'], epoch))

            matched_request = offer['matched_request']
            if matched_request is not None:
                request_payload = matched_request['payload']
                request_opcode = request_payload['a_opcode']
                if request_opcode in (0, 1, 4):
                    expected_d_opcode = 1 if request_opcode == 4 else 0
                    if signals['d_opcode'] != expected_d_opcode:
                        self._emit(raw, epoch, emitted,
                                   'tlul_response_opcode_mismatch',
                                   {'request_opcode': request_opcode,
                                    'expected_d_opcode': expected_d_opcode,
                                    'observed_d_opcode': signals['d_opcode']},
                                   state=offer, native_identity={
                                       'channel': 'D', 'source': offer['source']},
                                   transaction_key=self._key(offer['source'], epoch))
                    expected_d_size = request_payload['a_size']
                    if signals['d_size'] != expected_d_size:
                        self._emit(raw, epoch, emitted,
                                   'tlul_response_size_mismatch',
                                   {'expected_d_size': expected_d_size,
                                    'observed_d_size': signals['d_size']},
                                   state=offer, native_identity={
                                       'channel': 'D', 'source': offer['source']},
                                   transaction_key=self._key(offer['source'], epoch))

            if d_ready:
                if (offer['matched_request'] is not None
                        and signals['d_source'] == offer['source']):
                    completed_request = offer['matched_request']
                self._tl_d_offer = None
            else:
                self._tl_d_offer = offer
        elif self._tl_d_offer is not None:
            offer = self._tl_d_offer
            self._emit(raw, epoch, emitted,
                       'tlul_d_response_withdrawn_before_acceptance',
                       {'source': offer['source']}, state=offer,
                       native_identity={'channel': 'D', 'source': offer['source']},
                       transaction_key=self._key(offer['source'], epoch))
            self._tl_d_offer = None

        if completed_request is not None:
            source = completed_request.get('source')
            if self._tl_outstanding.get(source) is completed_request:
                del self._tl_outstanding[source]

        # A response for one source must not pause timeout accounting for
        # other requests that are still waiting on the D channel.
        if d_ready:
            for source, state in tuple(self._tl_outstanding.items()):
                if state.get('accepted_tick') == raw['local_tick']:
                    continue
                state['wait_count'] += 1
                if (state['wait_count'] >= self.max_wait_cycles
                        and not state['timed_out']):
                    state['timed_out'] = True
                    self._emit(raw, epoch, emitted,
                               'tlul_response_wait_budget_exceeded',
                               {'source': source,
                                'wait_cycles': state['wait_count'],
                                'limit': self.max_wait_cycles},
                               state=state, native_identity={
                                   'channel': 'D', 'source': source},
                               transaction_key=self._key(source, epoch))

    def _consume_apb3(self, raw, epoch, signals, emitted):
        selected, enable = signals['psel'] == 1, signals['penable'] == 1
        setup = selected and not enable
        access = selected and enable
        payload = {role: signals[role] for role in ('paddr', 'pwrite', 'pwdata')}
        active = self._apb_active
        if setup:
            if active is None:
                self._apb_active = {
                    'request_event_ref': raw['event_id'], 'payload': payload,
                    'wait_count': 0, 'timed_out': False,
                    'reported_codes': set(),
                }
            else:
                self._emit(raw, epoch, emitted,
                           'apb_setup_repeated_before_access',
                           {'expected': active['payload'], 'observed': payload},
                           state=active)
                if payload != active['payload']:
                    self._emit(raw, epoch, emitted,
                               'apb_payload_changed_before_completion',
                               {'expected': active['payload'], 'observed': payload},
                               state=active)
            return
        if access:
            if active is None:
                self._emit(raw, epoch, emitted, 'apb_access_without_setup',
                           {'observed': payload})
                return
            if payload != active['payload']:
                self._emit(raw, epoch, emitted,
                           'apb_payload_changed_during_access',
                           {'expected': active['payload'], 'observed': payload},
                           state=active)
            if signals['pready']:
                self._apb_active = None
            else:
                active['wait_count'] += 1
                if (active['wait_count'] >= self.max_wait_cycles
                        and not active['timed_out']):
                    active['timed_out'] = True
                    self._emit(raw, epoch, emitted, 'apb_wait_budget_exceeded',
                               {'wait_cycles': active['wait_count'],
                                'limit': self.max_wait_cycles}, state=active)
            return
        if active is not None and not selected:
            self._emit(raw, epoch, emitted,
                       'apb_select_withdrawn_before_completion',
                       {'expected': active['payload']}, state=active)
            self._apb_active = None

    def _consume_axi4_lite(self, raw, epoch, signals, emitted):
        """Check the AXI4-Lite channel rules that need no IP semantics.

        Every rule here is a property of the declared pins and the protocol the
        endpoint claims, never of a register map: payload stability, the
        requirement that a response only follows its own accepted request,
        single outstanding, and the response codes the slave actually drove.
        """
        def payload(roles):
            return {role: signals[role] for role in roles}

        # Responses settle before requests, so a response that completes on
        # this very edge is already gone when a new request is evaluated. The
        # outstanding-ness of a *previous* transaction is therefore snapshotted
        # here, otherwise a legal back-to-back handoff would be reported as a
        # second outstanding transaction.
        # A response settles before the requests of the same edge are judged,
        # so an outstanding transaction that completes on this very edge is no
        # longer outstanding. Snapshotting only the pre-edge state would report
        # a legal back-to-back handoff as a second outstanding transaction.
        b_outstanding_before = (self._axil_b is not None
                                and not (signals['bvalid'] == 1
                                         and signals['bready'] == 1))
        r_outstanding_before = (self._axil_r is not None
                                and not (signals['rvalid'] == 1
                                         and signals['rready'] == 1))

        def place_offer(state, key, fields, native):
            if state is None:
                state = {'request_event_ref': raw['event_id'], 'payload': fields,
                         'wait_count': 0, 'timed_out': False,
                         'reported_codes': set(), 'key': key}
                return state
            if fields != state['payload']:
                self._emit(raw, epoch, emitted, self.protocol.replace('-', '')
                           + '_payload_changed_while_stalled',
                           {'expected': state['payload'], 'observed': fields},
                           state=state, native_identity=native,
                           transaction_key=state['key'])
            return state

        # -- B ----------------------------------------------------------------
        b_valid, b_ready = signals['bvalid'] == 1, signals['bready'] == 1
        if b_valid and self._axil_b is None:
            self._emit(raw, epoch, emitted, 'axi4lite_write_response_without_request',
                       {'bresp': signals['bresp']},
                       native_identity={'channel': 'b', 'direction': 'write'})
        if b_valid and b_ready:
            self._axil_b = None
        elif b_valid and self._axil_b is not None:
            self._axil_b['wait_count'] += 1

        # -- R -----------------------------------------------------------------
        r_valid, r_ready = signals['rvalid'] == 1, signals['rready'] == 1
        if r_valid and self._axil_r is None:
            self._emit(raw, epoch, emitted, 'axi4lite_read_response_without_request',
                       {'rresp': signals['rresp']},
                       native_identity={'channel': 'r', 'direction': 'read'})
        if r_valid and r_ready:
            self._axil_r = None
        elif r_valid and self._axil_r is not None:
            self._axil_r['wait_count'] += 1

        # -- AW ---------------------------------------------------------------
        aw_valid, aw_ready = signals['awvalid'] == 1, signals['awready'] == 1
        if aw_valid:
            self._axil_aw = place_offer(
                self._axil_aw, None, payload(('awaddr', 'awprot')),
                {'channel': 'aw', 'direction': 'write'})
        elif self._axil_aw is not None:
            self._emit(raw, epoch, emitted, 'axi4lite_awvalid_withdrawn_before_ready',
                       {'expected': self._axil_aw['payload']}, state=self._axil_aw,
                       native_identity={'channel': 'aw', 'direction': 'write'})
            self._axil_aw = None

        # -- W ----------------------------------------------------------------
        w_valid, w_ready = signals['wvalid'] == 1, signals['wready'] == 1
        if w_valid:
            self._axil_w = place_offer(
                self._axil_w, None, payload(('wdata', 'wstrb')),
                {'channel': 'w', 'direction': 'write'})
        elif self._axil_w is not None:
            self._emit(raw, epoch, emitted, 'axi4lite_wvalid_withdrawn_before_ready',
                       {'expected': self._axil_w['payload']}, state=self._axil_w,
                       native_identity={'channel': 'w', 'direction': 'write'})
            self._axil_w = None

        aw_take = aw_valid and aw_ready
        w_take = w_valid and w_ready
        if aw_take:
            if self._axil_aw_accepted is not None:
                # A second accepted address before the first write completed
                # would silently replace the outstanding one, so the write the
                # slave eventually answers could no longer be identified.
                self._emit(raw, epoch, emitted,
                           'axi4lite_address_reaccepted_before_completion',
                           {'accepted_address':
                                self._axil_aw_accepted['payload']['awaddr'],
                            'observed_address': signals['awaddr']},
                           state=self._axil_aw_accepted,
                           native_identity={'channel': 'aw', 'direction': 'write'})
            # Latch the accepted address half; the write itself only exists
            # once the data half has also been accepted, in either order.
            self._axil_aw_accepted = {'request_event_ref': raw['event_id'],
                                      'payload': payload(('awaddr', 'awprot'))}
            self._axil_aw = None
        if w_take:
            self._axil_w_accepted = {'request_event_ref': raw['event_id'],
                                     'payload': payload(('wdata', 'wstrb'))}
            self._axil_w = None
        if self._axil_aw_accepted is not None and self._axil_w_accepted is not None:
            if b_outstanding_before:
                # A second write completed while one response is still pending.
                self._emit(raw, epoch, emitted,
                           'axi4lite_write_accepted_with_response_outstanding',
                           {'address': self._axil_aw_accepted['payload']['awaddr']},
                           state=self._axil_b,
                           native_identity={'channel': 'aw+w', 'direction': 'write'})
            else:
                self._axil_b = {
                    'request_event_ref': self._axil_aw_accepted['request_event_ref'],
                    'payload': {**self._axil_aw_accepted['payload'],
                                **self._axil_w_accepted['payload']},
                    'wait_count': 0, 'timed_out': False,
                    'reported_codes': set(),
                    'key': None, 'accepted': True}
            self._axil_aw_accepted = None
            self._axil_w_accepted = None

        # -- AR ---------------------------------------------------------------
        ar_valid, ar_ready = signals['arvalid'] == 1, signals['arready'] == 1
        if ar_valid:
            self._axil_ar = place_offer(
                self._axil_ar, None, payload(('araddr', 'arprot')),
                {'channel': 'ar', 'direction': 'read'})
        elif self._axil_ar is not None:
            self._emit(raw, epoch, emitted, 'axi4lite_arvalid_withdrawn_before_ready',
                       {'expected': self._axil_ar['payload']}, state=self._axil_ar,
                       native_identity={'channel': 'ar', 'direction': 'read'})
            self._axil_ar = None
        ar_take = ar_valid and ar_ready
        if ar_take:
            if r_outstanding_before:
                self._emit(raw, epoch, emitted,
                           'axi4lite_read_accepted_with_response_outstanding',
                           {'address': signals['araddr']}, state=self._axil_r,
                           native_identity={'channel': 'ar', 'direction': 'read'})
            else:
                self._axil_r = {'request_event_ref': raw['event_id'],
                                'payload': payload(('araddr', 'arprot')),
                                'wait_count': 0, 'timed_out': False,
                                'reported_codes': set(),
                                'key': None, 'accepted': True}
            self._axil_ar = None

        # -- wait budgets ------------------------------------------------------
        # Only a request channel that never completes is a contract violation.
        # A held response is reported as a protocol error once, never as a
        # violation of a rule the protocol does not state.
        for state, channel, direction in ((self._axil_aw, 'aw', 'write'),
                                          (self._axil_w, 'w', 'write'),
                                          (self._axil_ar, 'ar', 'read')):
            if state is None or state['timed_out']:
                continue
            state['wait_count'] += 1
            if state['wait_count'] >= self.max_wait_cycles:
                state['timed_out'] = True
                self._emit(raw, epoch, emitted,
                           'axi4lite_request_wait_budget_exceeded',
                           {'channel': channel, 'direction': direction,
                            'wait_cycles': state['wait_count'],
                            'limit': self.max_wait_cycles}, state=state,
                           native_identity={'channel': channel, 'direction': direction})

    def _consume_wishbone(self, raw, epoch, signals, emitted):
        request = signals['cyc'] == 1 and signals['stb'] == 1
        terminal = signals['ack'] == 1 or signals.get('err', 0) == 1
        payload = {role: value for role, value in signals.items()
                   if role in ('we', 'adr', 'sel')
                   or (role == 'dat_w' and signals['we'] == 1)}
        if request:
            if (signals['we'] and 'sel' in signals
                    and signals['sel'] == 0):
                self._emit(raw, epoch, emitted, 'wishbone_zero_write_mask',
                           {'signal_role': 'sel', 'observed': 0})
            if signals['stall']:
                offer = self._wb_offer
                if offer is None:
                    self._wb_offer = {
                        'request_event_ref': raw['event_id'], 'payload': payload,
                        'wait_count': 0, 'timed_out': False,
                        'reported_codes': set(),
                    }
                elif payload != offer['payload']:
                    self._emit(raw, epoch, emitted,
                               'wishbone_request_changed_while_stalled',
                               {'expected': offer['payload'], 'observed': payload},
                               state=offer)
                self._wb_offer['wait_count'] += 1
                if (self._wb_offer['wait_count'] >= self.max_wait_cycles
                        and not self._wb_offer['timed_out']):
                    self._wb_offer['timed_out'] = True
                    self._emit(raw, epoch, emitted,
                               'wishbone_request_wait_budget_exceeded',
                               {'wait_cycles': self._wb_offer['wait_count'],
                                'limit': self.max_wait_cycles},
                               state=self._wb_offer)
            else:
                offer = self._wb_offer
                if offer is not None and payload != offer['payload']:
                    self._emit(raw, epoch, emitted,
                               'wishbone_request_changed_while_stalled',
                               {'expected': offer['payload'], 'observed': payload},
                               state=offer)
                if (self._wishbone_max_outstanding is not None
                        and len(self._wb_outstanding)
                        >= self._wishbone_max_outstanding):
                    self._emit(raw, epoch, emitted,
                               'wishbone_single_outstanding_overlap',
                               {'pending_requests': len(self._wb_outstanding),
                                'limit': self._wishbone_max_outstanding},
                               state=self._wb_outstanding[0])
                else:
                    self._wb_outstanding.append({
                        'request_event_ref': (offer['request_event_ref']
                                              if offer is not None
                                              else raw['event_id']),
                        'payload': payload, 'wait_count': 0,
                        'reported_codes': set(),
                        'accepted_tick': raw['local_tick'],
                    })
                self._wb_offer = None
        elif self._wb_offer is not None:
            offer = self._wb_offer
            self._emit(raw, epoch, emitted,
                       'wishbone_request_withdrawn_while_stalled',
                       {'expected': offer['payload']}, state=offer)
            self._wb_offer = None

        if terminal:
            if not signals['cyc']:
                self._emit(raw, epoch, emitted,
                           'wishbone_response_without_active_cycle',
                           {'ack': signals['ack'], 'err': signals.get('err', 0)})
            elif not self._wb_outstanding:
                self._emit(raw, epoch, emitted,
                           'wishbone_response_without_request',
                           {'ack': signals['ack'], 'err': signals.get('err', 0)})
            elif (self._wishbone_same_edge_completion is False
                    and self._wb_outstanding[-1].get('accepted_tick')
                    == raw['local_tick']):
                self._emit(raw, epoch, emitted,
                           'wishbone_same_edge_accept_response',
                           {'ack': signals['ack'], 'err': signals.get('err', 0)},
                           state=self._wb_outstanding[-1])
            else:
                self._wb_outstanding.pop(0)
        elif signals['cyc'] and self._wb_outstanding:
            for state in self._wb_outstanding:
                if state.get('accepted_tick') == raw['local_tick']:
                    continue
                state['wait_count'] += 1
                if (state['wait_count'] >= self.max_wait_cycles
                        and 'wishbone_response_wait_budget_exceeded'
                        not in state['reported_codes']):
                    self._emit(raw, epoch, emitted,
                               'wishbone_response_wait_budget_exceeded',
                               {'wait_cycles': state['wait_count'],
                                'limit': self.max_wait_cycles}, state=state)
        elif not signals['cyc'] and self._wb_outstanding:
            state = self._wb_outstanding.pop(0)
            self._emit(raw, epoch, emitted,
                       'wishbone_cycle_withdrawn_before_response',
                       {'pending_requests': 1}, state=state)
            self._wb_outstanding.clear()

    def _consume_obi(self, raw, epoch, signals, emitted):
        pending = self._obi_pending
        if signals['rvalid']:
            if pending is None:
                self._emit(raw, epoch, emitted, 'obi_response_without_prior_grant', {})
            self._obi_pending = None
        elif pending is not None:
            self._obi_wait(raw, epoch, emitted, pending, 'response')
        active = self._obi_offer
        if not signals['req']:
            # OBI permits speculative GNT without REQ; it accepts nothing.
            if active is not None:
                self._emit(raw, epoch, emitted, 'obi_request_withdrawn_before_grant', {}, state=active)
                self._obi_offer = None
            return
        control = {name:signals[name] for name in ('addr','we','be') if name in signals}
        if signals.get('we', 0):
            control['wdata'] = signals['wdata']
        if active is None:
            active = {'request_event_ref':raw['event_id'], 'control':control, 'wait_count':0}
            self._obi_offer = active
        elif active['control'] != control:
            self._emit(raw, epoch, emitted, 'obi_request_changed_while_waiting',
                       {'expected':active['control'], 'observed':control}, state=active)
        if signals['gnt']:
            if self._obi_pending is not None:
                self._emit(raw, epoch, emitted, 'obi_single_outstanding_overlap', {}, state=active)
            else:
                active['wait_count'] = 0
                self._obi_pending = active
            self._obi_offer = None
        else:
            self._obi_wait(raw, epoch, emitted, active, 'request')

    def _obi_wait(self, raw, epoch, emitted, active, phase):
        active['wait_count'] += 1
        if active['wait_count'] >= self.max_wait_cycles:
            self._emit(raw, epoch, emitted, 'obi_'+phase+'_wait_budget_exceeded',
                {'wait_cycles':active['wait_count']}, state=active)

    def pending_state(self):
        """Return bounded pending Wishbone state for authenticated reports."""
        if self.protocol != 'wishbone':
            return {'offers': 0, 'outstanding': 0}
        return {'offers': int(self._wb_offer is not None),
                'outstanding': len(self._wb_outstanding)}


class WishboneDmaProtocolChecker:
    """Run independent no-SEL Wishbone checkers over one dual-endpoint DMA tap.

    The checker accepts only an explicit two-endpoint pipelined DMA trace set.
    No SEL value is invented; each endpoint's byte-enable statement is part of
    the admitted trace contract and checked by ``IpProtocolChecker``.
    """

    _SCHEMA = 'wishbone_dma_protocol_checker.v1'
    _REPORT_SCHEMA = 'wishbone_dma_protocol_checker_report.v1'

    def __init__(self, *, component_id: str, instance_id: str,
                 trace_set: Mapping[str, object],
                 artifact_identity: Mapping[str, object] | None = None):
        if (type(component_id) is not str or not component_id
                or type(instance_id) is not str or not instance_id
                or not isinstance(trace_set, Mapping)
                or set(trace_set) != {'schema_version', 'sampling',
                                      'sample_group', 'traces'}
                or trace_set.get('schema_version') != self._SCHEMA
                or trace_set.get('sampling') != 'pre_post'
                or trace_set.get('sample_group') != 'backend'
                or not isinstance(trace_set.get('traces'), (list, tuple))
                or len(trace_set['traces']) != 2):
            raise ValueError('wishbone-dma-trace-set-invalid')
        traces = [deepcopy(dict(row)) if isinstance(row, Mapping) else None
                  for row in trace_set['traces']]
        if any(row is None for row in traces):
            raise ValueError('wishbone-dma-trace-set-invalid')
        if ({row.get('endpoint_role') for row in traces}
                != {'control_target', 'memory_master'}
                or len({row.get('endpoint_id') for row in traces}) != 2
                or any(type(row.get('reset_domain')) is not str
                       or not row['reset_domain']
                       or row.get('sample_group') != 'backend'
                       or row.get('max_outstanding') != 1
                       or row.get('same_edge_accept_completion') is not False
                       for row in traces)):
            raise ValueError('wishbone-dma-dual-endpoint-identity-invalid')
        ordered = sorted(traces, key=lambda row: row['endpoint_role'])
        self.component_id = component_id
        self.instance_id = instance_id
        if artifact_identity is not None and (
                not isinstance(artifact_identity, Mapping)
                or set(artifact_identity) != {'component_id', 'instance_id',
                    'artifact_digest', 'profile_fingerprint',
                    'source_verification_sha256', 'runtime_artifact_sha256'}
                or artifact_identity.get('component_id') != component_id
                or artifact_identity.get('instance_id') != instance_id
                or any(type(artifact_identity.get(key)) is not str
                       or len(artifact_identity[key]) != 64
                       or any(ch not in '0123456789abcdef'
                              for ch in artifact_identity[key])
                       for key in ('artifact_digest',
                                   'source_verification_sha256',
                                   'runtime_artifact_sha256'))
                or type(artifact_identity.get('profile_fingerprint')) is not str
                or not artifact_identity['profile_fingerprint'].startswith('sha256:')
                or len(artifact_identity['profile_fingerprint']) != 71
                or any(ch not in '0123456789abcdef'
                       for ch in artifact_identity['profile_fingerprint'][7:])):
            raise ValueError('wishbone-dma-artifact-identity-invalid')
        self._artifact_identity = (deepcopy(dict(artifact_identity))
                                   if artifact_identity is not None else None)
        self._trace_set = deepcopy(dict(trace_set))
        self._trace_set_sha256 = hashlib.sha256(json.dumps(
            self._trace_set, sort_keys=True, separators=(',', ':'),
            allow_nan=False).encode()).hexdigest()
        self._checkers = {}
        self._sample_counts = {}
        self._last_raw_ids = {}
        self._finding_rows = []
        for trace in ordered:
            endpoint_id = trace.get('endpoint_id')
            checker = IpProtocolChecker(component_id=component_id,
                instance_id=instance_id, protocol_trace=trace)
            self._checkers[endpoint_id] = checker
            self._sample_counts[endpoint_id] = 0
            self._last_raw_ids[endpoint_id] = None

    def consume_local_tick(self, raw_event: Mapping[str, object], *,
                           reset_epoch: int):
        findings = []
        is_pre = (isinstance(raw_event, Mapping)
                  and raw_event.get('kind') == 'local_tick_sample'
                  and raw_event.get('phase') == 'pre')
        for endpoint_id, checker in self._checkers.items():
            endpoint_findings = checker.consume_local_tick(
                raw_event, reset_epoch=reset_epoch)
            if is_pre:
                self._sample_counts[endpoint_id] += 1
                self._last_raw_ids[endpoint_id] = raw_event['event_id']
            for finding in endpoint_findings:
                row = deepcopy(finding)
                row['endpoint_id'] = endpoint_id
                row['raw_event_id'] = raw_event['event_id']
                self._finding_rows.append(row)
                findings.append(finding)
        return tuple(findings)

    def snapshot(self):
        return {'pre_sample_counts': dict(self._sample_counts),
                'finding_count': len(self._finding_rows)}

    def report(self, *, since=None):
        if since is not None and (not isinstance(since, Mapping)
                or set(since) != {'pre_sample_counts', 'finding_count'}
                or not isinstance(since['pre_sample_counts'], Mapping)
                or type(since['finding_count']) is not int
                or since['finding_count'] < 0
                or since['finding_count'] > len(self._finding_rows)
                or set(since['pre_sample_counts']) != set(self._sample_counts)):
            raise ValueError('wishbone-dma-report-snapshot-invalid')
        lower_counts = (since['pre_sample_counts'] if since is not None else {})
        start_findings = since['finding_count'] if since is not None else 0
        counts, pending, endpoints = {}, {}, []
        for endpoint_id, checker in self._checkers.items():
            start = lower_counts.get(endpoint_id, 0)
            if type(start) is not int or start < 0 or start > self._sample_counts[endpoint_id]:
                raise ValueError('wishbone-dma-report-snapshot-invalid')
            counts[endpoint_id] = self._sample_counts[endpoint_id] - start
            pending[endpoint_id] = checker.pending_state()
            endpoints.append({
                'endpoint_id': endpoint_id,
                'endpoint_role': next(row['endpoint_role']
                    for row in self._trace_set['traces']
                    if row['endpoint_id'] == endpoint_id),
                'trace': deepcopy(next(row for row in self._trace_set['traces']
                    if row['endpoint_id'] == endpoint_id)),
                'pre_sample_count': counts[endpoint_id],
                'last_raw_sample_event_id': self._last_raw_ids[endpoint_id],
                'reset_epoch': checker._reset_epoch,
                'pending': deepcopy(pending[endpoint_id]),
            })
        findings = deepcopy(self._finding_rows[start_findings:])
        if findings:
            status = 'violation'
        elif any(count <= 0 for count in counts.values()
                 ) or any(state['offers'] or state['outstanding']
                          for state in pending.values()):
            status = 'incomplete'
        else:
            status = 'clean'
        return {
            'schema_version': self._REPORT_SCHEMA,
            'component_id': self.component_id,
            'instance_id': self.instance_id,
            'artifact_identity': deepcopy(self._artifact_identity),
            'trace_set_sha256': self._trace_set_sha256,
            'installed_endpoint_ids': sorted(self._checkers),
            'pre_sample_counts': counts,
            'findings': findings,
            'pending': pending,
            'endpoints': endpoints,
            'status': status,
        }
