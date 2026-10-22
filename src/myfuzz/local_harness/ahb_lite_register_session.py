"""Full-word persistent AHB-Lite register session on the shared beat transport."""
from copy import deepcopy

from .apb3_register_session import GeneratedApb3RegisterSession


class GeneratedAhbLiteRegisterSession(GeneratedApb3RegisterSession):
    artifact_kind = 'ahb_lite_register_observe'
    access_operation = 'ACCESS_AHB_REG'
    step_operation = 'STEP_AHB_REG'
    source_operation = 'SOURCE_AHB_REG'
    bind_operation = 'BIND_AHB_REG'
    transport_error_label = 'generic AHB-Lite'
    error_response_label = 'AHB-Lite target/transport'

    DMA_CTRL_OFFSET = 0x10
    DMA_CTRL_START_VALUE = 5

    def __init__(self, artifact, *, base_dir, cache_dir, **kwargs):
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir,
                         **kwargs)
        self._dma_target_events = []
        self._dma_target_poisoned = False

    def dma_master_target_provider_identity_document(self):
        """Pin the narrow DMA write accepted by this Caliptra AHB adapter."""
        self._check_artifact_stable()
        document = self._artifact_document
        trace = document.get('base_protocol_trace')
        digest = document.get('artifact_digest')
        endpoint = getattr(getattr(self.artifact, 'plan', None), 'request', None)
        if (document.get('kind') != self.artifact_kind
                or type(trace) is not dict
                or trace.get('schema_version') != 'ip_protocol_trace.v1'
                or trace.get('protocol') != 'ahb-lite'
                or trace.get('endpoint_id') != 'sha256.bus'
                or type(trace.get('signals')) is not dict
                or type(digest) is not str or len(digest) != 64
                or any(character not in '0123456789abcdef' for character in digest)
                or getattr(endpoint, 'instance_id', None) != 'sha'):
            raise ValueError('Caliptra SHA256 AHB DMA provider requires its pinned AHB artifact')
        return {
            'schema_version': 'caliptra_sha256_dma_target_provider.v1',
            'api_schema_version': 'dma_master_target_access.v1',
            'implementation_profile': 'caliptra_sha256_ctrl_ahb_write_completion.v1',
            'artifact_digest': digest,
            'endpoint_id': 'sha256.bus',
            'operation': 'write', 'register': 'CTRL',
            'offset': self.DMA_CTRL_OFFSET,
            'value': self.DMA_CTRL_START_VALUE, 'byte_enable': 15,
            'observation_contract_schema_version': trace['schema_version'],
        }

    def dma_master_target_access(self, source_transaction, *, address, offset,
                                 write, value, byte_enable, delivery_context):
        """Join one DMA CTRL-start write to its actual AHB address/data phases.

        The provider is intentionally narrower than the AHB session: only the
        single known CTRL start value can be routed. A waveform or transport
        mismatch after issuing ACCESS_AHB_REG leaves the target uncertain and
        poisons further DMA provider access for this session lifetime.
        """
        from dataclasses import asdict
        from myfuzz.scenario.ledger import TransactionKey

        if self._dma_target_poisoned:
            raise ValueError('Caliptra SHA256 DMA target provider is poisoned')
        if type(source_transaction) is not TransactionKey:
            raise ValueError('invalid Caliptra SHA256 DMA transaction key')
        if (type(write) is not bool or not write
                or type(offset) is not int or offset != self.DMA_CTRL_OFFSET
                or type(value) is not int or value != self.DMA_CTRL_START_VALUE
                or type(byte_enable) is not int or byte_enable != 15
                or type(address) is not int or address % 4):
            raise ValueError('Caliptra SHA256 DMA target supports only full-word CTRL start')
        self._check_artifact_stable()
        trace = self._artifact_document.get('base_protocol_trace')
        signals = trace.get('signals') if type(trace) is dict else None
        required_roles = {'haddr', 'hwdata', 'hsel', 'hwrite', 'hreadyin',
                          'htrans', 'hsize', 'hresp', 'hreadyout', 'hrdata'}
        if (self._artifact_document.get('kind') != self.artifact_kind
                or type(signals) is not dict or set(signals) != required_roles
                or trace.get('schema_version') != 'ip_protocol_trace.v1'
                or trace.get('protocol') != 'ahb-lite'
                or trace.get('endpoint_id') != 'sha256.bus'):
            raise ValueError('Caliptra SHA256 AHB trace contract is incomplete')

        key_document = asdict(source_transaction)
        component = self.artifact.plan.request.instance_id
        base = (delivery_context.get('window_base')
                if type(delivery_context) is dict else None)
        size = (delivery_context.get('window_size')
                if type(delivery_context) is dict else None)
        expected_context = {
            'source_transaction': key_document,
            'device_id': component,
            'address': address, 'offset': offset, 'write': True,
            'value': value, 'be': byte_enable,
            'window_base': base, 'window_size': self._window,
        }

        def exact_document(actual, expected):
            if type(actual) is not type(expected):
                return False
            if type(expected) is dict:
                return (set(actual) == set(expected)
                        and all(exact_document(actual[name], wanted)
                                for name, wanted in expected.items()))
            if type(expected) is list:
                return (len(actual) == len(expected)
                        and all(exact_document(left, right)
                                for left, right in zip(actual, expected)))
            if type(expected) is tuple:
                return (len(actual) == len(expected)
                        and all(exact_document(left, right)
                                for left, right in zip(actual, expected)))
            return actual == expected

        if (source_transaction.testcase_id != self._case_id
                or type(base) is not int or base < 0 or base % 0x1000
                or type(size) is not int or size != self._window
                or base + size > 1 << 32
                or address != base + offset or address + 4 > base + size
                or not exact_document(delivery_context, expected_context)):
            raise ValueError('Caliptra SHA256 DMA delivery context mismatch')

        request = {
            'address': address, 'offset': offset, 'write': True,
            'value': value, 'byte_enable': byte_enable,
        }
        trace_fields = ('haddr', 'hwdata', 'hsel', 'hwrite', 'hreadyin',
                        'htrans', 'hsize', 'hresp', 'hreadyout', 'hrdata')
        sequence = self._sequence + 1
        access_id = f'caliptra-ahb:{self._execution}:{sequence}'
        if len(self._dma_target_events) >= 65536:
            raise ValueError('Caliptra SHA256 DMA target evidence capacity exhausted')
        command_issued = False
        try:
            sample_start = len(self._samples)
            command_issued = True
            reply = self.command(self.access_operation,
                (1, offset, value, byte_enable))
            result = self._take(reply)
            expected_result_keys = set(self._outputs) | {'rdata', 'error'}
            if (type(result) is not dict
                    or set(result) != expected_result_keys
                    or type(result.get('rdata')) is not int
                    or not 0 <= result['rdata'] <= 0xffffffff
                    or type(result.get('error')) is not int
                    or result['error'] != 0):
                raise RuntimeError('Caliptra SHA256 AHB response was not successful: '
                    + repr({'type': type(result).__name__,
                        'keys': sorted(result) if type(result) is dict else None,
                        'expected_keys': sorted(expected_result_keys),
                        'rdata_type': type(result.get('rdata')).__name__
                            if type(result) is dict else None,
                        'error': result.get('error') if type(result) is dict else None}))
            samples = list(self._samples)[sample_start:]
            accepted = []
            observed_phases = []
            for index, sample in enumerate(samples):
                phase = sample.get('pre') if type(sample) is dict else None
                backend = phase.get('backend') if type(phase) is dict else None
                if type(backend) is not dict:
                    raise ValueError('Caliptra SHA256 AHB tick lacks backend observations')
                pins = {}
                for role in trace_fields:
                    signal = signals[role]
                    value_at_pin = backend.get(signal)
                    if type(value_at_pin) is not int:
                        raise ValueError('Caliptra SHA256 AHB tick lacks typed trace pin: ' + role)
                    pins[role] = value_at_pin
                tick = sample.get('local_tick')
                if type(tick) is not int or tick < 0:
                    raise ValueError('Caliptra SHA256 AHB tick identity is invalid')
                observed_phases.append((tick, pins))
                if (pins['hsel'] == 1 and pins['hreadyin'] == 1
                        and pins['htrans'] in (2, 3)):
                    accepted.append(index)

            if len(accepted) != 1:
                raise ValueError('Caliptra SHA256 AHB request acceptance is missing or ambiguous')
            request_index = accepted[0]
            request_tick, request_pins = observed_phases[request_index]
            if (request_pins['haddr'] != offset
                    or request_pins['hwrite'] != 1
                    or request_pins['hsize'] != 2):
                raise ValueError('Caliptra SHA256 AHB accepted request differs from DMA CTRL write')

            response_index = None
            response_tick = None
            response_pins = None
            for tick, pins in observed_phases[request_index + 1:]:
                if (pins['htrans'] != 0 or pins['hwdata'] != value
                        or pins['hresp'] != 0):
                    raise ValueError('Caliptra SHA256 AHB data phase differs from DMA CTRL write')
                if pins['hreadyout'] == 1:
                    response_tick, response_pins = tick, pins
                    response_index = next(index for index, item in
                        enumerate(observed_phases) if item[0] == tick)
                    break
                if pins['hreadyout'] != 0:
                    raise ValueError('Caliptra SHA256 AHB HREADYOUT is not binary')
            if response_index is None:
                raise ValueError('Caliptra SHA256 AHB data phase response is missing')
            if response_pins['hrdata'] != result['rdata']:
                raise ValueError('Caliptra SHA256 AHB response differs from parsed driver result')

            request_witness = {
                'schema_version': 'caliptra_sha256_ahb_dma_request.v1',
                'status': 'observed',
                'source_transaction': deepcopy(key_document),
                'access_id': access_id,
                'local_tick': request_tick,
                'backend': deepcopy(request_pins),
            }
            response_witness = {
                'schema_version': 'caliptra_sha256_ahb_dma_response.v1',
                'status': 'observed',
                'source_transaction': deepcopy(key_document),
                'access_id': access_id,
                'local_tick': response_tick,
                'backend': deepcopy(response_pins),
                'rdata': result['rdata'], 'error': 0,
            }
            access_witness = {
                'schema_version': 'caliptra_sha256_ahb_dma_access.v1',
                'status': 'observed',
                'source_transaction': deepcopy(key_document),
                'access_id': access_id,
                'component': component, 'register': 'CTRL',
                'offset': offset, 'write': True, 'wdata': value,
                'request_local_tick': request_tick,
                'response_local_tick': response_tick,
                'target_request': deepcopy(request_witness),
                'target_response': deepcopy(response_witness),
            }
            effect = {
                'schema_version': 'caliptra_sha256_ctrl_ahb_write_completion.v1',
                'status': 'observed',
                'effect': 'ctrl_write_transfer_completed',
                'proof_scope': 'ahb_write_data_phase_completion',
                'source_transaction': deepcopy(key_document),
                'request': deepcopy(request),
                'access_id': access_id, 'local_tick': response_tick,
                'register': 'CTRL', 'offset': offset,
                'accepted_value': value,
                'physical_write_data': response_pins['hwdata'],
            }
            receipt = {
                'schema_version': 'dma_master_target_access.v1',
                'status': 'observed',
                'source_transaction': deepcopy(key_document),
                'request': request,
                'response': {'rdata': result['rdata'], 'error': 0},
                'target_access_id': access_id,
                'target_access': access_witness,
                'target_request': request_witness,
                'target_response': response_witness,
                'target_effect': effect,
            }
            self._dma_target_events.append(deepcopy(receipt))
            return receipt
        except BaseException as error:
            if command_issued:
                self._dma_target_poisoned = True
                self._dma_target_events.append({
                    'schema_version': 'caliptra_sha256_dma_target_terminal.v1',
                    'kind': 'caliptra_sha256_dma_target_terminal',
                    'status': 'uncertain',
                    'source_transaction': deepcopy(key_document),
                    'request': deepcopy(request),
                    'delivery_context': deepcopy(delivery_context),
                    'command_sequence': sequence,
                    'error': type(error).__name__ + ': ' + str(error),
                })
            raise

    def identity_document(self):
        document = super().identity_document()
        document.pop('apb3_register_service_schema_version')
        document['ahb_lite_register_service_schema_version'] = 'generated_ahb_lite_register_observe.v1'
        return document
