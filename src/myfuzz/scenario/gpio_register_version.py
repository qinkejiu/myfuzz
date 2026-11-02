"""Live GPIOEN versions from the registered, source pinned physical probe.

Reports are not authority. Tokens are process local, single use and revoked by
every command, epoch change, process replacement or uncertain observation.
"""
from copy import deepcopy
import hashlib
import inspect
from pathlib import Path
from weakref import WeakKeyDictionary

from myfuzz.local_harness.pulp_gpio_probe_contract import (
    pulp_gpio_observation_contract, pulp_gpio_probe_document, verify_pulp_gpio_source_contract)

_AUTHORITIES = WeakKeyDictionary()
_ISSUANCES = WeakKeyDictionary()
_LIVE = WeakKeyDictionary()
_AUTHORITY_REGISTRY_PIN = _AUTHORITIES
_ISSUANCE_REGISTRY_PIN = _ISSUANCES
_LIVE_REGISTRY_PIN = _LIVE
_SOURCE_SHA256 = pulp_gpio_probe_document()['source']['sha256']


def _advance_padin_sample(previous, pre, post, *, tick, sequence, identity, context):
    """Reduce measured synchronizer edges; this helper issues no live token."""
    from myfuzz.scenario.gpio_consumption import _physical
    if not _physical(pre) or not _physical(post):
        raise ValueError('PADIN-probe-width')
    names = ('sync0', 'sync1', 'padin_latch')
    old = {name: pre['gpio_probe_' + name] for name in names}
    new = {name: post['gpio_probe_' + name] for name in names}
    if previous is not None and (previous['tick'] + 1 != tick or previous['post'] != old):
        raise ValueError('PADIN-continuity-lost')
    enabled = sum(15 << (4*g) for g in range(8)
        if pre['gpio_probe_input_clock_enable'] & (1 << g))
    for name, value in (('sync0', pre['gpio_in']), ('sync1', old['sync0']),
                        ('padin_latch', old['sync1'])):
        if new[name] != ((old[name] & ~enabled) | (value & enabled)):
            raise ValueError('PADIN-native-transition-mismatch')
    version = previous['version'] if previous is not None else 0
    origins = (previous['origins'] if previous is not None else
        {name: [dict(kind='first_measured_state', pin=pin, local_tick=tick)
                for pin in range(32)] for name in names})
    read = previous['read'] if previous is not None else None
    if (pre['gpio_probe_psel'] == pre['gpio_probe_penable'] == pre['gpio_probe_pready'] == 1
            and pre['gpio_probe_pwrite'] == 0 and pre['gpio_probe_decoded_word'] == 2):
        if pre['gpio_probe_prdata'] != old['padin_latch']:
            raise ValueError('PADIN-native-read-mismatch')
        read = dict(schema_version='gpio_PADIN_native_read_receipt.v1', register='PADIN',
            reset_epoch=identity[1], value=old['padin_latch'], field_version=version, local_tick=tick,
            command_sequence=sequence, raw_pre=deepcopy(pre), raw_post=deepcopy(post),
            pin_origins=deepcopy(origins['padin_latch']))
    advanced = {name: list(rows) for name, rows in origins.items()}
    source_context = None
    if isinstance(context, dict) and isinstance(context.get('segments'), list):
        if all(((pre['gpio_in'] >> segment['bit_lo']) & ((1 << segment['width']) - 1))
               == segment['value'] for segment in context['segments']):
            source_context = deepcopy(context)
    for pin in range(32):
        if enabled & (1 << pin):
            advanced['sync0'][pin] = dict(kind='native_pin_sample', pin=pin,
                value=(pre['gpio_in'] >> pin) & 1, local_tick=tick,
                source_context=source_context)
            advanced['sync1'][pin] = origins['sync0'][pin]
            advanced['padin_latch'][pin] = origins['sync1'][pin]
    return dict(identity=identity, tick=tick, sequence=sequence, post=new,
        version=version + int(bool(enabled)), read=read, origins=advanced,
        input_sample=dict(value=pre['gpio_in'], local_tick=tick,
            enabled_mask=enabled, source_context=source_context),
        bad=False)


_PADIN_ADVANCE_PIN = (_advance_padin_sample, _advance_padin_sample.__code__)


class GpioRegisterVersionAuthority:
    def __init__(self, target, *, max_writes=4096, max_tokens=16):
        from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
        if type(target) is not GeneratedPulpGpioSession or target.process is not None:
            raise ValueError('register-version-fresh-actual-target-required')
        if target in _AUTHORITIES:
            raise ValueError('register-version-already-installed')
        if any(type(n) is not int or not 1<=n<=65536 for n in (max_writes,max_tokens)):
            raise ValueError('register-version-capacity-invalid')
        from myfuzz.local_harness.session import _NATIVE_RESET_CHECK_PRODUCERS
        _NATIVE_RESET_CHECK_PRODUCERS[0](target)
        if target.artifact.runtime_document.get('gpio_observation_contract') != pulp_gpio_observation_contract():
            raise ValueError('register-version-producer-unsupported')
        verify_pulp_gpio_source_contract(target.artifact.plan.profile, base_dir=target.base_dir)
        from myfuzz.scenario.contracts import _verify_generated_session
        if _verify_generated_session(target.identity_document()) != target.artifact:
            raise ValueError('register-version-artifact-reconstruction-mismatch')
        if target._native_reset_observation is None:
            target.configure_native_reset_observation()
        self.target=target
        from myfuzz.local_harness.session import GeneratedLocalSession
        from myfuzz.local_harness.session import _NATIVE_RESET_SESSION_FUNCTIONS
        self._producer,self._producer_code=_NATIVE_RESET_SESSION_FUNCTIONS['_command_impl']
        self.artifact=target.artifact
        self._source=Path(target.base_dir)/'third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv'
        self._source_digest=hashlib.sha256(self._source.read_bytes()).digest()
        _AUTHORITIES[target]=self
        _ISSUANCES[self]={}
        _LIVE[self]=dict(state=None,writes=[],bad=False,limits=(max_writes,max_tokens),padin=None)

    def _validate(self):
        t=self.target
        from myfuzz.local_harness.session import _NATIVE_RESET_CHECK_PRODUCERS
        _NATIVE_RESET_CHECK_PRODUCERS[0](t)
        from myfuzz.local_harness.execution_validation import static_validation
        source_sha = static_validation(('gpio-register-authority-source', self),
            lambda: hashlib.sha256(self._source.read_bytes()).hexdigest())
        if (_AUTHORITIES is not _AUTHORITY_REGISTRY_PIN or _ISSUANCES is not _ISSUANCE_REGISTRY_PIN or _LIVE is not _LIVE_REGISTRY_PIN
                or type(self) is not _AUTHORITY_TYPE
                or any(name in vars(self) or getattr(_AUTHORITY_TYPE,name) is not method
                       or method.__code__ is not code for name,(method,code) in _METHOD_PINS.items())
                or _LIVE[self]['bad'] or _AUTHORITIES.get(t) is not self or t.artifact is not self.artifact
                or self._source_digest.hex()!=_SOURCE_SHA256
                or source_sha!=_SOURCE_SHA256):
            raise ValueError('register-version-authority-invalid')
        t._check_artifact_stable()

    def _actual_command(self, target, operation, fields, receipt):
        from myfuzz.local_harness.session import GeneratedLocalSession
        frame=inspect.currentframe().f_back
        if (GeneratedLocalSession._command_impl is not self._producer
                or self._producer.__code__ is not self._producer_code
                or frame.f_code is not self._producer_code
                or frame.f_locals.get('self') is not target
                or frame.f_locals.get('receipt') is not receipt or target is not self.target):
            _LIVE[self]['bad']=True
            raise ValueError('register-version-actual-producer-required')
        _ISSUANCES[self].clear()
        try:
            _METHOD_PINS['_validate'][0](self)
            from myfuzz.local_harness.session import _NATIVE_RESET_NATIVE_ELIGIBLE
            if _NATIVE_RESET_NATIVE_ELIGIBLE[0](target)[0] is not True:
                raise ValueError('register-version-actual-build-required')
            if receipt.status!='result' or receipt.payload is None:
                raise ValueError('register-version-command-incomplete')
            identity=(target.process,target.reset_epoch)
            previous=_LIVE[self]['state']
            if previous is not None and previous['identity']!=identity:
                previous=None
            samples=receipt.payload['samples']
            if not samples:
                raise ValueError('register-version-command-samples-missing')
            for sample in samples:
                tick=target._tick_base+sample['local_tick']
                pre=target._normalized_physical(sample['pre'])
                post=target._normalized_physical(sample['post'])
                old=pre['gpio_probe_gpioen'];new=post['gpio_probe_gpioen']
                if any(type(v) is not int or not 0<=v<=0xffffffff for v in (old,new)):
                    raise ValueError('register-version-probe-width')
                if previous is not None and (tick!=previous['tick']+1 or old!=previous['value']):
                    raise ValueError('register-version-continuity-lost')
                write=(pre['gpio_probe_psel']==1 and pre['gpio_probe_penable']==1
                       and pre['gpio_probe_pready']==1 and pre['gpio_probe_pwrite']==1
                       and pre['gpio_probe_decoded_word']==1)
                expected=pre['gpio_probe_pwdata'] if write else old
                if new!=expected or pre['gpio_probe_pslverr']!=0:
                    raise ValueError('register-version-RTL-transition-mismatch')
                if write:
                    if len(_LIVE[self]['writes'])>=_LIVE[self]['limits'][0]:
                        raise ValueError('register-version-write-capacity')
                    context=deepcopy(target._gpio_active_context)
                    _LIVE[self]['writes'].append(dict(epoch=target.reset_epoch,tick=tick,
                        before=old,after=new,command_sequence=receipt.sequence,
                        context=context))
                padin = _LIVE[self]['padin']
                if padin is not None and padin.get('identity') != identity:
                    padin = None
                if padin is None or not padin.get('bad'):
                    try:
                        _LIVE[self]['padin'] = _PADIN_ADVANCE_PIN[0](padin, pre, post,
                            tick=tick, sequence=receipt.sequence, identity=identity,
                            context=target._active_gpio_input_context)
                    except (ValueError, KeyError, TypeError):
                        # PADIN certainty is separate from unchanged GPIOEN token
                        # semantics. A damaged PADIN stream cannot issue PADIN.
                        _LIVE[self]['padin'] = dict(identity=identity,bad=True)
                previous=dict(identity=identity,tick=tick,value=new,
                    sequence=receipt.sequence)
            _LIVE[self]['state']=previous
        except BaseException:
            _LIVE[self]['bad']=True
            raise

    def issue(self, *, register='GPIOEN', reset_epoch):
        _METHOD_PINS['_validate'][0](self)
        t=self.target;s=_LIVE[self]['state']
        if (register not in ('GPIOEN','PADIN') or type(reset_epoch) is not int or s is None
                or s['identity']!=(t.process,reset_epoch) or reset_epoch!=t.reset_epoch
                or t.process is None or t.process.poll() is not None
                or s['sequence']!=t._sequence):
            raise ValueError('register-version-current-state-unavailable')
        token=object()
        if len(_ISSUANCES[self])>=_LIVE[self]['limits'][1]:
            _LIVE[self]['bad']=True
            raise ValueError('register-version-token-capacity')
        _ISSUANCES[self][token]=dict(register=register,reset_epoch=reset_epoch,
            value=s['value'],local_tick=s['tick'],command_sequence=s['sequence'],
            process_scope=dict(pid=t.process.pid,execution=t._execution),
            source_sha256=self._source_digest.hex(),
            artifact_digest=t.artifact.runtime_document['artifact_digest'],
            observation_contract=pulp_gpio_observation_contract())
        if register == 'PADIN':
            if (_advance_padin_sample is not _PADIN_ADVANCE_PIN[0]
                    or _advance_padin_sample.__code__ is not _PADIN_ADVANCE_PIN[1]):
                _ISSUANCES[self].pop(token, None)
                raise ValueError('register-version-PADIN-producer-drift')
            state = _LIVE[self]['padin']
            if (state is None or state.get('bad') or state['identity'] != (t.process, reset_epoch)
                    or state['sequence'] != t._sequence or state['tick'] != s['tick']):
                _ISSUANCES[self].pop(token, None)
                raise ValueError('register-version-PADIN-current-state-unavailable')
            _ISSUANCES[self][token].update(value=state['post']['padin_latch'],
                native_sample_version=state['version'],
                current_origins=deepcopy(state['origins']['padin_latch']),
                input_sample=deepcopy(state['input_sample']),
                read_receipt=deepcopy(state['read']))
        return token

    def consume(self, token):
        _METHOD_PINS['_validate'][0](self)
        t=self.target;s=_LIVE[self]['state']
        if (s is None or s['identity']!=(t.process,t.reset_epoch)
                or t.process is None or t.process.poll() is not None
                or s['sequence']!=t._sequence):
            _ISSUANCES[self].clear()
            raise ValueError('register-version-current-state-unavailable')
        witness=_ISSUANCES[self].pop(token,None)
        if witness is None:
            raise ValueError('register-version-token-invalid-or-revoked')
        return deepcopy(witness)

    def writes(self):
        _METHOD_PINS['_validate'][0](self)
        return deepcopy(_LIVE[self]['writes'])


_AUTHORITY_TYPE = GpioRegisterVersionAuthority
_METHOD_PINS = {name:(method,method.__code__) for name,method in
    vars(GpioRegisterVersionAuthority).items() if callable(method) and hasattr(method,'__code__')}
