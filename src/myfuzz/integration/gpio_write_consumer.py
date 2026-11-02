"""The existing GPIO F4 native write/current-version join, shared by callers.

This consumer issues no DUT command. It reuses the directed writer observer and
actual GPIO authority; current readback alone is never the commit witness.
"""
from .generated_register_writer import check_writer_observation
from .gpio_f2_consumer import validate_gpio_authority


def check_gpio_write_observation(declaration, receipt, *, target_artifact, authority,
        access, target_component, register, reset_epoch, before, prior_writes):
    """Return (observation, native commit, current witness) or refuse.

    ``access`` is the caller's admitted compiled register access, independently
    of the declaration's candidate. The issuer is consumed only after all
    native event/context joins have passed, preserving the original ordering.
    """
    validate_gpio_authority(authority)
    if (authority.target.artifact != target_artifact or register != 'GPIOEN'
            or type(reset_epoch) is not int or reset_epoch != before['reset_epoch']
            or type(prior_writes) is not int or prior_writes < 0):
        raise ValueError('compiled-F4-GPIO-consumer-argument-mismatch')
    value=declaration['candidate']['value']
    observed=check_writer_observation(declaration,receipt,target_artifact=target_artifact)
    writes=authority.writes()[prior_writes:]
    if len(writes)!=1:raise ValueError('compiled-F4-bound-commit-count')
    commit=writes[0];context=commit['context']
    delivery=next(e for e in receipt.events if e.get('event_id')==observed['joins'][0]['delivery_event'])
    if (not context or context['source_transaction']!=delivery['source_transaction']
            or context['address']!=access['address'] or context['offset']!=access['register_offset']
            or context['write'] is not True or context['value']!=value or context['be']!=15
            or commit['before']!=before['value'] or commit['after']!=value or commit['epoch']!=before['reset_epoch']):
        raise ValueError('compiled-F4-bound-commit-join-mismatch')
    physical=next(e for e in receipt.events if e.get('event_id')==observed['joins'][0]['native_APB_event'])
    if commit['tick']!=physical['local_tick'] or context['command_scope']!={
            'component':target_component,'reset_epoch':commit['epoch'],'command_sequence':commit['command_sequence']}:
        raise ValueError('compiled-F4-native-commit-identity-mismatch')
    after=authority.consume(authority.issue(register=register,reset_epoch=reset_epoch))
    if after['value']!=value:raise ValueError('compiled-F4-live-register-mismatch')
    return observed,commit,after
