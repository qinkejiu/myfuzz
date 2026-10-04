"""Typed runtime admission for completion memory; no component-name inference."""
from .template_contracts import select_template_contract


def native_completion_contract(endpoint, capabilities):
    required = dict(completion_semantics='completion', address_units='byte',
                    address_width=32, data_width=32, byte_enable=True,
                    max_outstanding=1, error_response=False)
    for name, expected in required.items():
        if type(capabilities.get(name)) is not type(expected) or capabilities[name] != expected:
            raise ValueError('runtime-native-typed-fact-required:' + name)
    return select_template_contract(endpoint, capabilities, template_id='cpu.native-memory',
        template_version='1', variant_id='completion-no-error')
