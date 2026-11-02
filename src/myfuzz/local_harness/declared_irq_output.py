"""Declared native output transport; no IP-internal IRQ cause authority.

Select an existing generated target sampler by protocol, then authenticate one
actual observed output bit. CPU acceptance/serial stay with its own provider.
"""
from .apb3_register_session import GeneratedApb3RegisterSession
from .wishbone_register_session import GeneratedWishboneRegisterSession
from .ahb_lite_register_session import GeneratedAhbLiteRegisterSession
from .source_lock import verify_local_source_lock
from .runtime_artifact import LocalRuntimeArtifact

_CLASSES={'apb3_register_observe':GeneratedApb3RegisterSession,
          'wishbone_register_observe':GeneratedWishboneRegisterSession,
          'ahb_lite_register_observe':GeneratedAhbLiteRegisterSession}
_METHODS={cls:{name:(getattr(cls,name),getattr(cls,name).__code__) for name in
    ('step_local','step_local_routed','_step_with_inputs','_take','_take_impl',
     'drain_tick_samples','_check_artifact_stable') if hasattr(cls,name)} for cls in _CLASSES.values()}


def declared_irq_target_session_type(artifact):
    """Choose an existing protocol sampler, without admitting an IRQ source."""
    if type(artifact) is not LocalRuntimeArtifact:raise ValueError('declared-IRQ-actual-artifact-required')
    cls=_CLASSES.get(artifact.runtime_document.get('kind'))
    if cls is None:raise ValueError('declared-IRQ-protocol-session-unsupported')
    return cls


def declared_irq_runtime_mapping(session,*,physical_port,source_bit_offset):
    """Bind configured routing intent to real ABI and the original raw sampler."""
    artifact=getattr(session,'artifact',None)
    cls=declared_irq_target_session_type(artifact)
    document=artifact.runtime_document
    if type(session) is not cls:raise ValueError('declared-IRQ-protocol-session-unsupported')
    if (type(physical_port) is not str or not physical_port or type(source_bit_offset) is not int
            or not 0<=source_bit_offset<64):raise ValueError('declared-IRQ-output-bit-invalid')
    for name,(method,code) in _METHODS[cls].items():
        if name in vars(session) or getattr(cls,name) is not method or method.__code__ is not code:
            raise ValueError('declared-IRQ-original-native-sampler-required')
    session._check_artifact_stable()
    verify_local_source_lock(artifact.plan.profile,base_dir=session.base_dir)
    exports=[row for row in document['physical_exports'] if row.get('physical_port')==physical_port
        and row.get('direction')=='output' and row.get('disposition') in ('observe','functional')
        and type(row.get('bit_lo')) is int and type(row.get('bit_hi')) is int
        and row['bit_lo']<=source_bit_offset<=row['bit_hi']]
    if len(exports)!=1:raise ValueError('declared-IRQ-unique-real-output-required')
    export=exports[0];width=export['width']
    # Existing target samplers expose one complete vector per physical port.
    # A sliced/ambiguous projection needs its own protocol sampler adaptation.
    if (type(width) is not int or not 1<=width<=64 or export['bit_lo']!=0 or export['bit_hi']!=width-1
            or session._outputs.get(physical_port)!=(export['runtime_name'],width)):
        raise ValueError('declared-IRQ-native-output-projection-mismatch')
    names=('physical_port','endpoint_id','role','direction','bit_lo','bit_hi','width','disposition')
    if sum(all(row.get(k)==export.get(k) for k in names) for row in artifact.structural.abi_document['ports'])!=1:
        raise ValueError('declared-IRQ-output-ABI-mismatch')
    return dict(adapter_id='declared-output.v1',physical_port=physical_port,runtime_name=export['runtime_name'],
        source_width=width,raw_bit_offset=source_bit_offset,transport_only=True,
        source_profile_fingerprint=artifact.plan.profile.profile_fingerprint,
        cause='unknown',internal_version='unknown',case_origin='unknown',reward_eligible=False,grants_prerequisites=False)
