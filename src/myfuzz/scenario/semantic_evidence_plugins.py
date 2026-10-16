"""Explicit versioned optional evidence providers; no component-name dispatch.

Only this code-owned catalog selects executable rules. Configuration supplies
data parameters, never a module path, callback, expression or computation.
"""

_PROVIDERS = {
    'gpio_register_version.v1': ('L2', 'register_version'),
    'gpio_sync_consumption.v1': ('L3', 'functional_consumption'),
}


def provider_spec(name):
    return _PROVIDERS.get(name)


def capability_binding_supported(name, parameters, *, profile, sidecar, key, base_dir):
    if provider_spec(name) is None:
        return False, 'missing-semantic-provider'
    # The internal sync0->sync1 observation covers no complete externally
    # declared operation yet; it must not certify completion or pad sampling.
    if name == 'gpio_sync_consumption.v1':
        return False, 'evidence-scope-does-not-cover-declared-operation'
    from .gpio_register_evidence import validate_capability_binding
    validate_capability_binding(parameters, profile=profile, sidecar=sidecar,
                                key=key, base_dir=base_dir)
    return True, None


def capability_certificate_supported(name, parameters, key, certificate):
    if name != 'gpio_register_version.v1':
        return False
    offsets = {'dir': 0, 'gpioen': 4, 'out': 12, 'inten': 24,
        'inttype': 32 if parameters['bit_lo'] >= 32 else 28}
    offset = offsets.get(parameters['register'])
    if key[1] == 'register_read':
        return certificate.get('read_access', {}).get('decoded_offset') == offset
    accesses = certificate.get('write_accesses')
    return (key[1] == 'register_write' and bool(accesses) and all(
        access['decoded_offset'] == offset and access['operation'] in ('overwrite', 'low', 'high')
        for access in accesses))


def create_provider(name, parameters, *, runtime_contract_sha256, **bounds):
    if name == 'gpio_sync_consumption.v1':
        if set(parameters) != {'component', 'bit_lo', 'width'}:
            raise ValueError('semantic-provider-parameters-invalid')
        from .gpio_sync_evidence import GpioSyncConsumptionEvidenceConsumer
        return GpioSyncConsumptionEvidenceConsumer(**parameters,
            runtime_contract_sha256=runtime_contract_sha256, **bounds)
    if name == 'gpio_register_version.v1':
        if set(parameters) != {'component', 'register', 'bit_lo', 'width'}:
            raise ValueError('semantic-provider-parameters-invalid')
        from .gpio_register_evidence import GpioRegisterEvidenceConsumer
        return GpioRegisterEvidenceConsumer(**parameters,
            runtime_contract_sha256=runtime_contract_sha256, **bounds)
    raise ValueError('semantic-provider-unavailable')
