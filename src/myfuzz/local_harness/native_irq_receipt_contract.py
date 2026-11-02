"""Code-owned CPU IRQ adapter selection; no capability from RVFI port names."""
from .ibex_irq_receipt_contract import (ibex_irq_receipt_contract,
    verify_ibex_irq_receipt_artifact,ibex_irq_serial_observation)
from .cv32e20_irq_receipt_contract import (cv32e20_irq_receipt_contract,
    verify_cv32e20_irq_receipt_artifact, uses_cv32e20_irq_adapter)
from .cv32e40p_irq_receipt_contract import (cv32e40p_irq_receipt_contract,
    verify_cv32e40p_irq_receipt_artifact)


def native_irq_receipt_contract_for_profile(profile):
    if 'native_irq_adapter' in profile.evidence:
        if uses_cv32e20_irq_adapter(profile):return cv32e20_irq_receipt_contract()
    if 'native_irq_observation' in profile.evidence:
        from .profile_native_irq import profile_irq_contract
        return profile_irq_contract(profile)
    profile=profile.component_id
    if profile=='ibex_rvfi_local':return ibex_irq_receipt_contract()
    if profile=='cv32e20':return cv32e20_irq_receipt_contract()
    if profile=='cv32e40p_rvfi_local':return cv32e40p_irq_receipt_contract()
    raise ValueError('unregistered-native-IRQ-CPU-adapter')



def native_irq_receipt_contract(artifact):
    return native_irq_receipt_contract_for_profile(artifact.plan.profile)


def verify_native_irq_cpu_source(profile,*,base_dir):
    """Source-backed CPU adapter, independent of any attached IP."""
    native_irq_receipt_contract_for_profile(profile)
    if 'native_irq_observation' in profile.evidence:
        from .profile_native_irq import verify_profile_irq_source
        return verify_profile_irq_source(profile, base_dir=base_dir)
    if uses_cv32e20_irq_adapter(profile):
        from .cv32e20_irq_receipt_contract import verify_cv32e20_irq_source_contract
        return verify_cv32e20_irq_source_contract(profile,base_dir=base_dir)
    if profile.component_id=='ibex_rvfi_local':
        from .ibex_rvfi_contract import verify_ibex_rvfi_source_contract
        return verify_ibex_rvfi_source_contract(profile,base_dir=base_dir)
    if profile.component_id=='cv32e40p_rvfi_local':
        from .cv32e40p_irq_receipt_contract import verify_cv32e40p_irq_source_contract
        return verify_cv32e40p_irq_source_contract(profile,base_dir=base_dir)
    from .cv32e20_irq_receipt_contract import verify_cv32e20_irq_source_contract
    return verify_cv32e20_irq_source_contract(profile,base_dir=base_dir)


def verify_native_irq_receipt_artifact(artifact,*,base_dir):
    native_irq_receipt_contract_for_profile(artifact.plan.profile)
    if 'native_irq_observation' in artifact.plan.profile.evidence:
        from .profile_native_irq import verify_profile_irq_artifact
        return verify_profile_irq_artifact(artifact,base_dir=base_dir)
    if uses_cv32e20_irq_adapter(artifact.plan.profile):
        return verify_cv32e20_irq_receipt_artifact(artifact,base_dir=base_dir)
    profile=artifact.plan.profile.component_id
    if profile=='ibex_rvfi_local':return verify_ibex_irq_receipt_artifact(artifact,base_dir=base_dir)
    if profile=='cv32e20':return verify_cv32e20_irq_receipt_artifact(artifact,base_dir=base_dir)
    if profile=='cv32e40p_rvfi_local':return verify_cv32e40p_irq_receipt_artifact(artifact,base_dir=base_dir)
    raise ValueError('unregistered-native-IRQ-CPU-adapter')


def validate_native_irq_receipt_contract(value):
    if isinstance(value, dict) and value.get('schema_version')=='profile_native_irq_receipts.v1':
        from .profile_native_irq import validate_profile_irq_contract
        return validate_profile_irq_contract(value)
    if (value!=ibex_irq_receipt_contract() and value!=cv32e20_irq_receipt_contract()
            and value!=cv32e40p_irq_receipt_contract()):
        raise ValueError('unregistered-native-IRQ-receipt-contract')


def native_irq_decision_probes(contract):
    """Contract-declared pre-edge decision probes as name -> physical width.

    Ibex and CV32E20 declare only their two 1-bit acceptance probes; CV32E40P
    additionally declares the real ack/id/entry-PC and redirect observations,
    so the session never hardcodes a CPU's probe names or widths.
    """
    validate_native_irq_receipt_contract(contract)
    declared=dict(contract.get('decision_probe_widths') or {})
    names=set(contract['decision_probes'])|set(contract.get('decision_probes_all') or {})
    if not declared:
        if set(contract['decision_probes'])!=names:
            raise ValueError('unregistered-native-IRQ-decision-probes')
        declared={name:1 for name in contract['decision_probes']}
    if (set(declared)!=names or any(type(width) is not int or width<1
            for width in declared.values())):
        raise ValueError('unregistered-native-IRQ-decision-probes')
    return declared


def native_irq_acceptance(contract):
    """Real ack/id/entry-PC acceptance cross-checks, or None if not declared."""
    validate_native_irq_receipt_contract(contract)
    if 'decision_acceptance' not in contract:return None
    acceptance=dict(contract['decision_acceptance'])
    widths=native_irq_decision_probes(contract)
    for key in ('ack_probe','id_probe','entry_pc_probe'):
        if acceptance.get(key) not in widths:
            raise ValueError('unregistered-native-IRQ-acceptance-probe')
    if acceptance.get('id_width')!=widths[acceptance['id_probe']]:
        raise ValueError('unregistered-native-IRQ-acceptance-width')
    return acceptance


def native_irq_redirect_probes(contract):
    """Real non-IRQ exception redirect probes as {'taken','cause'}, or None."""
    validate_native_irq_receipt_contract(contract)
    if 'redirect_probes' not in contract:return None
    probes=dict(contract['redirect_probes'])
    widths=native_irq_decision_probes(contract)
    if (set(probes)!={'taken','cause'}
            or any(name not in widths for name in probes.values())):
        raise ValueError('unregistered-native-IRQ-redirect-probes')
    return probes


def native_irq_serial_observable(contract):
    """Whether this adapter owns an exact serial measurement at all.

    The legacy Ibex adapter owns its serial sideband as a separate registered
    contract, CV32E20 declares one inside its receipt contract, and CV32E40P
    declares none: its retirement join is PC/instruction/order based, so it must
    never emit a serial document.
    """
    validate_native_irq_receipt_contract(contract)
    return contract==ibex_irq_receipt_contract() or 'serial_observation' in contract


def native_irq_serial_observation(contract,*,sampling,decision_value,retirement_value,
        decision_phase,retirement_phase):
    validate_native_irq_receipt_contract(contract)
    if contract==ibex_irq_receipt_contract():
        return ibex_irq_serial_observation(sampling=sampling,decision_value=decision_value,
            retirement_value=retirement_value,decision_phase=decision_phase,retirement_phase=retirement_phase)
    if 'serial_observation' not in contract:
        # CV32E40P has no exact serial token: its retirement join is
        # PC/instruction/order based, so no serial document may be minted.
        raise ValueError('native-IRQ-contract-declares-no-serial-observation')
    if sampling not in ('pre_post_rising','post_rising'):
        raise ValueError('invalid-native-IRQ-serial-sampling')
    roles={}
    for name,phase,value in (('decision',decision_phase,decision_value),('retirement',retirement_phase,retirement_value)):
        if phase not in ('pre','post') or (value is not None and (type(value) is not int or not 0<=value<1<<64)):
            raise ValueError('invalid-native-IRQ-serial-measurement')
        roles[name]=dict(physical_port='irq_'+name+'_serial',phase=phase,value=value,
            status='unobservable' if value is None else 'observed')
    return dict(schema_version='cpu_irq_serial_observation.v1',sampling=sampling,width_bits=64,
        zero_semantics='no_provable_source_lineage',**roles)


def native_irq_notification_observed(contract,fields):
    """Actual notification only; neither RVFI predicate grants IRQ source.

    CV32E40P's ``irq_ack_o``/``irq_id_o`` are pre-edge combinational outputs and
    the local top leaves ``rvfi_intr`` undriven, so no post-edge notification is
    observable.  Its acceptance is carried by the ``cpu_external_irq_taken``
    event with the real ack/id/entry-PC probes; reporting a post notification
    here would fabricate one.
    """
    validate_native_irq_receipt_contract(contract)
    if contract.get('schema_version')=='profile_native_irq_receipts.v1':return False
    if contract==ibex_irq_receipt_contract():
        return fields['rvfi_ext_irq_valid']==1
    if contract==cv32e40p_irq_receipt_contract():return False
    return fields['rvfi_valid']==1 and fields['rvfi_intr']==1


def native_irq_retirement_diversion_fields(contract):
    """Required actual diversion observations of one registered CPU adapter."""
    validate_native_irq_receipt_contract(contract)
    if contract==ibex_irq_receipt_contract():
        return ('rvfi_ext_debug_mode','rvfi_ext_debug_req','rvfi_halt')
    if (contract==cv32e40p_irq_receipt_contract()
            or contract.get('schema_version')=='profile_native_irq_receipts.v1'):
        return tuple(contract['retirement_diversion_fields'])
    return ('rvfi_ext_debug_req','rvfi_ext_nmi','rvfi_halt')


def native_irq_retirement_diversion_scope(contract):
    """'unobservable' when no real diversion field exists; else the field set."""
    validate_native_irq_receipt_contract(contract)
    declared=contract.get('retirement_diversion_scope')
    if type(declared) is str:return declared
    return 'observed_fields' if native_irq_retirement_diversion_fields(contract) else 'unobservable'


def native_irq_retirement_diverted(contract,physical):
    """Inspect real registered fields; missing observations refuse.

    E20's source-backed lineage also clears on internal debug/NMI. Its absent
    Ibex debug-mode extension is never fabricated.  CV32E40P exports no
    debug/NMI/halt retirement field, so its contract declares
    ``retirement_diversion_scope='unobservable'``: this answers False while the
    caller must record that unknown scope.  Anything else refuses rather than
    claiming an inspection it cannot make.
    """
    validate_native_irq_receipt_contract(contract)
    fields=native_irq_retirement_diversion_fields(contract)
    if not fields:
        if contract.get('retirement_diversion_scope')!='unobservable':
            raise ValueError('unregistered-native-IRQ-retirement-diversion-scope')
        return False
    return any(physical.get(name)!=0 for name in fields)


def native_irq_serial_schema(contract):
    """Keep legacy Ibex contract bytes; name the registered serial extension."""
    validate_native_irq_receipt_contract(contract)
    if contract==ibex_irq_receipt_contract():return 'ibex_irq_serial_observation.v1'
    if 'serial_observation' not in contract:
        raise ValueError('native-IRQ-contract-declares-no-serial-observation')
    return contract['serial_observation']['schema_version']
