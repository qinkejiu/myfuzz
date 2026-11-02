"""Declared APB transport facts for an unprobed shared target.

The declaration proves no internal register writer, current version, reset
value or source attribution.  Live execution still checks CPU and APB hops.
"""
from hashlib import sha256
import json


def shared_mmio_source(request, declaration):
    component = request.device(declaration['component'])
    if component is None or component.profile.address is None or component.capability is None:
        raise ValueError('shared-MMIO-target-profile-required')
    windows = [w for w in request.wiring.windows if w.target_instance == component.instance_id]
    if len(windows) != 1:
        raise ValueError('shared-MMIO-target-window-required')
    window = windows[0]
    endpoint = component.endpoint(window.endpoint_id)
    if endpoint is None or endpoint.function != 'mmio_slave' or endpoint.protocol != ('apb', '3'):
        raise ValueError('shared-MMIO-APB3-endpoint-required')
    register = declaration['register']
    regs = [r for r in component.profile.address.registers if r.name == register]
    semantics = [r for r in component.capability.register_semantics if r.register == register]
    ops = [e for e in component.capability.endpoint_capabilities if e.endpoint_id == endpoint.endpoint_id]
    if (len(regs) != 1 or len(semantics) != 1 or len(ops) != 1
            or not {'read', 'write'} <= set(ops[0].operations)
            or regs[0].width != 32 or regs[0].access != 'rw' or regs[0].side_effect != 'none'
            or semantics[0].width != 32 or semantics[0].lsb != 0
            or semantics[0].access != 'rw' or semantics[0].side_effect != 'none'
            or not semantics[0].read_mask or not semantics[0].write_mask
            or (semantics[0].write_mask != 0xffffffff
                and semantics[0].write_policy != 'full_word_reserved_zero')):
        raise ValueError('shared-MMIO-register-capability-required')
    if regs[0].offset % 4 or regs[0].offset + 4 > window.size:
        raise ValueError('shared-MMIO-register-outside-window')
    body = dict(schema_version='shared_apb_mmio_transport.v1', component=component.instance_id,
        profile_fingerprint=component.profile.profile_fingerprint, endpoint=endpoint.endpoint_id,
        device_id=window.device_id, base=window.base, size=window.size,
        register=register, offset=regs[0].offset, read_mask=semantics[0].read_mask,
        write_mask=semantics[0].write_mask, internal_storage_version='unknown',
        cross_case_origin='unknown', reward_eligible=False)
    body['digest'] = sha256(json.dumps(body, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return body
