"""Finite typed GPIOEN and pin8 requests; no native authority.

The installed common runtime prepares and admits every request. This catalog
only declares shared domains and constructs closed typed inputs; it does not
lower instruction bytes, reserve support slots or certify consumption.
"""
from dataclasses import asdict
from hashlib import sha256

from .actions import Action, Catalog, Decision
from .model import canonical, identifier


def validate_pin_session(session):
    """Refuse unsupported mixed input before registering any source or NOP.

    ScenarioSession's installed RegisterProgramRuntime owns all submissions in
    its mode. Inspecting the attachment is only a capability preflight: this
    function never calls its submission guard, alters active submissions, or
    constructs register-program history. Passing grants no source admission;
    the original gate and session still perform their complete checks.
    """
    from myfuzz.scenario.session_runtime import ScenarioSession
    if (type(session) is not ScenarioSession
            or '_register_program_runtime' not in vars(session)):
        raise ValueError('actual-scenario-session-required')
    runtime = session._register_program_runtime
    if runtime is not None:
        from myfuzz.scenario.register_program_runtime import RegisterProgramRuntime
        if type(runtime) is not RegisterProgramRuntime or not getattr(runtime, 'external_sources', ()):
            raise ValueError('mixed-pin-session-unsupported-register-program-exclusive')
        runtime.validate()


class GpioActionSpace:
    def __init__(self, *, result_address, values=(0, 0x100, 0x101)):
        if type(result_address) is not int or not 0 <= result_address < 1 << 32 or result_address % 4:
            raise ValueError('aligned uint32 result address required')
        self.result_address = result_address
        self.catalog = Catalog((
            Action('gpioen:write', 'declarative_register_program', 'register_write',
                   ('gpioen:configured',), (), values),
            Action('gpioen:read', 'declarative_register_program', 'register_read',
                   ('gpioen:observed',), (), (result_address,)),
            Action('pin8:event', 'gpio_b.external_pin8', 'external_pin_event',
                   ('pin8:proposed',), (), (0, 1)),
        ))

    def document(self):
        bindings = {
            'gpioen:write': dict(component='cpu', target='gpio_b', endpoint='gpio.bus',
                register='GPIOEN', field='value', ownership='fuzzable',
                source='declarative_register_program', path='register_program', flow='F4',
                lowerer='RegisterProgramRuntime.prepare/submit', writes=['gpio_b.GPIOEN.value'], reads=[]),
            'gpioen:read': dict(component='cpu', target='gpio_b', endpoint='gpio.bus',
                register='GPIOEN', field='value', ownership='fuzzable',
                source='declarative_register_program', path='register_program', flow='F4',
                lowerer='RegisterProgramRuntime.prepare/submit', writes=['cpu.result_slot'], reads=['gpio_b.GPIOEN.value']),
            'pin8:event': dict(component='gpio_b', port='gpio_in', bit_offset=8, width=1,
                ownership='source', producer='external_b.pin8', source='gpio_b.external_pin8',
                path='ip_to_cpu_to_ip.closed_loop', direction='IP_TO_CPU_TO_IP',
                lowerer='RegisterProgramRuntime.prepare_external/submit_external', writes=['gpio_b.gpio_in[8]'], reads=[]),
        }
        return dict(schema_version='dependency_search_gpio_actions.v1', native_authority=False,
                    catalog_identity=self.catalog.identity,
                    actions=[asdict(a) for a in self.catalog.actions], bindings=bindings)

    @property
    def identity(self):
        return sha256(canonical(self.document())).hexdigest()

    def _selected(self, decision):
        if type(decision) is not Decision:
            raise ValueError('typed Decision required')
        action = self.catalog.get(decision.action_id)
        if decision.value not in action.values:
            raise ValueError('decision outside shared GPIO domain')
        return action

    def request(self, decision, *, case_id):
        action = self._selected(decision)
        if action.operator not in ('register_write', 'register_read'):
            raise ValueError('CPU register action required')
        identifier(case_id)
        write = action.operator == 'register_write'
        from myfuzz.scenario.register_program_runtime import validate_register_request
        return validate_register_request(dict(schema_version='register_program_request.v1',
            case_id=case_id, action_id=case_id + ':' + action.id,
            target_instance='gpio_b', endpoint_id='gpio.bus', register='GPIOEN', field='value',
            operation=action.operator, value=decision.value if write else None,
            result_address=None if write else decision.value, allow_side_effect=False,
            read_modify_write=False))


    def external_request(self, decision, *, case_id):
        action = self._selected(decision)
        if action.operator != 'external_pin_event':
            raise ValueError('external pin action required')
        identifier(case_id)
        from myfuzz.scenario.mixed_external_runtime import validate_external_request
        return validate_external_request(dict(schema_version='external_pin_request.v1',
            case_id=case_id, action_id=case_id + ':' + action.id,
            source_id=action.source_id, value=decision.value))
