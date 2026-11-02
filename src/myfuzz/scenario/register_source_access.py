"""Exact target-word register source declarations and a pure candidate validator.

Validation grants no runtime/path authority and never writes a register. A real
CPU writer, prerequisite witnesses and checker projection are separate gates.
"""
from copy import deepcopy


def register_source_access(*,cpu,master,device,endpoint,window,field,write):
    registers=[r for r in device.profile.address.registers if r.name==field.register]
    if len(registers)!=1:
        raise ValueError('register-source-offset-undeclared')
    register=registers[0]
    # This slice declares a target word, not CPU native bus lanes. Wider/narrower
    # targets require a separate admitted access contract; never infer from field width.
    if register.width!=32 or register.offset%4 or register.offset+4>window.size:
        raise ValueError('register-source-access-shape-unsupported')
    return dict(schema_version='register_source_access.v1',
        source_component=cpu.instance_id,source_endpoint=master.endpoint_id,
        target_component=device.instance_id,target_endpoint=endpoint.endpoint_id,
        device_id=window.device_id,register=register.name,field=field.field,
        register_offset=register.offset,address=window.base+register.offset,
        window_base=window.base,window_size=window.size,
        window_alignment=device.profile.address.alignment,
        access_alignment=4,width_bytes=4,byte_enable_domain='target_word_lanes',
        allowed_byte_enables=[15],operation='write' if write else 'read',
        value_origin='cpu_transaction_wdata' if write else 'bound_target_rdata',
        register_origin='bound_target_register_commit',
        value_mask=(field.write_mask if write else field.read_mask)<<field.lsb)


def validate_register_candidate(request,compiled,*,source_id,source_component,
        source_endpoint,target_component,address,write,value=0,byte_enable=15):
    """Validate an explicit candidate against freshly recompiled declarations.

    Ownership is CPU transaction ownership, never permission to drive native IP
    state or rdata. No partial write/merge policy is invented for masked fields.
    """
    from .compiled_paths import compile_paths
    from myfuzz.local_harness.compiled_artifact_admission import _difference
    difference=_difference(compile_paths(request),compiled)
    if difference is not None:
        raise ValueError('register-candidate-compiled-document-mismatch:'+difference)
    sources=[s for p in compiled['paths'] if p['status']=='executable'
             for s in p['sources'] if s['source_id']==source_id and 'register_access' in s]
    if len(sources)!=1:
        raise ValueError('register-candidate-source-undeclared-or-ambiguous')
    source=sources[0];access=source['register_access']
    if (source_component,source_endpoint)!=(access['source_component'],access['source_endpoint']):
        raise ValueError('register-candidate-source-owner-mismatch')
    if target_component!=access['target_component']:
        raise ValueError('register-candidate-target-mismatch')
    if type(address) is not int or address!=access['address']:
        raise ValueError('register-candidate-address-mismatch')
    if type(write) is not bool or write!=(access['operation']=='write'):
        raise ValueError('register-candidate-operation-mismatch')
    if type(byte_enable) is not int or byte_enable not in access['allowed_byte_enables']:
        raise ValueError('register-candidate-partial-access')
    if type(value) is not int or not 0<=value<=0xffffffff:
        raise ValueError('register-candidate-value-invalid')
    if not write and value!=0:
        raise ValueError('register-candidate-read-response-is-bound')
    if write and value&~access['value_mask']:
        raise ValueError('register-candidate-reserved-value-bits')
    if write and access['value_mask']!=0xffffffff:
        capability=request.component(target_component).capability
        fields=[f for f in capability.register_semantics
                if (f.register,f.field)==(access['register'],access['field'])]
        if (len(fields)!=1 or fields[0].write_policy!='full_word_reserved_zero'
                or fields[0].lsb!=0 or fields[0].width!=32
                or fields[0].read_mask!=fields[0].write_mask):
            raise ValueError('register-candidate-masked-merge-policy-undeclared')
        # The declared policy authorizes this exact full-word value: every
        # non-fuzzable bit is zero (already checked above against value_mask).
        # There is no host merge and no host register read.
        profile=request.component(target_component).profile
        registers=([r for r in profile.address.registers if r.name==access['register']]
                   if profile.address is not None else [])
        # The write's real side effect is an independent dimension: it must be
        # the declared one, and it is recorded rather than assumed to be 'none'
        # and never inferred from the masked write policy.
        if (len(registers)!=1
                or registers[0].side_effect!=fields[0].side_effect):
            raise ValueError('register-candidate-masked-write-side-effect-mismatch')

    return dict(schema_version='validated_register_candidate.v1',validated=True,
        runtime_admitted=False,source_id=source_id,access=deepcopy(access),
        value=value,byte_enable=byte_enable,
        remaining=['actual CPU writer/target receipt join','prerequisite witnesses',
                   'compiled assertion checker bindings'])
