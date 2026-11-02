"""Evidence-bound Wishbone probe verification; prospective by default.

A ``wishbone_storage_probe.v1`` document describes one reviewed source storage
expression and the nine target-interface roles it is sampled with.  It does
not, by itself, prove that the expression resolves to a live variable in an
elaborated model, and no committed Wishbone hierarchy/native proof exists in
this repository.  This module therefore re-derives everything that *can* be
checked from the generated artifact:

* the probe digest over the exact document (including the source contract),
* the closed reviewed source contract, its bytes and parameters,
* the selection/profile/endpoint identity,
* every port name, role, width and expression against the runtime bytes,
* the Wishbone trace roles and widths (no ``err`` role exists on this row).

A document that claims hierarchy/native proof is refused because there is no
registered Wishbone proof to bind it to.  A fully documented prospective probe
returns ``None``: no evidence, and no false claim.  Nothing here issues reset,
version or source authority.
"""
from __future__ import annotations

import hashlib
import json

from .runtime_artifact import LocalRuntimeArtifact
from .wishbone_storage_probe_contract import (
    AUTHORITY_FLAGS, DOCUMENT_KEYS, PORT_KEYS, ROLES, SAMPLE_GROUP,
    SCHEMA_VERSION, SCOPE, SELECTION_KEYS, wishbone_probe_widths,
    wishbone_storage_probe_digest)
from .wishbone_storage_source_contract import (
    validate_wishbone_storage_source_contract)

#: Schema a future committed Wishbone hierarchy proof must use.  No such proof
#: is registered, so ``REGISTERED_PROOFS`` is empty and every claim is refused.
PROOF_SCHEMA = 'wishbone_storage_probe_hierarchy_proof.v1'
EVIDENCE_SCHEMA = 'wishbone_storage_hierarchy_evidence.v1'
REGISTERED_PROOFS = {}
#: Prospective documents must not carry these keys at all.
EVIDENCE_KEYS = frozenset({'hierarchy_evidence', 'native_proof',
                           'proof_digest', 'hierarchy_proof'})


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      allow_nan=False)


def _single_endpoint(artifact):
    endpoints = [endpoint for endpoint in artifact.plan.binding.endpoints
                 if endpoint.protocol is not None]
    if (len(endpoints) != 1
            or tuple(endpoints[0].protocol) != ('wishbone', 'classic')
            or endpoints[0].function != 'mmio_slave'):
        raise ValueError('wishbone-storage-probe-endpoint-unsupported')
    return endpoints[0]


def _check_ports(document, contract, endpoint, runtime, runtime_sv):
    widths = wishbone_probe_widths(contract)
    ports = document.get('ports')
    if (type(ports) is not list or len(ports) != len(widths)):
        raise ValueError('wishbone-storage-observation-port-shape')
    expected_order = ['storage_value', 'storage_reset']
    expected_order += ['storage_' + role for role in ROLES]
    if [row.get('name') if isinstance(row, dict) else None
            for row in ports] != expected_order:
        raise ValueError('wishbone-storage-observation-port-shape')
    for row in ports:
        if not isinstance(row, dict) or set(row) != PORT_KEYS:
            raise ValueError('wishbone-storage-observation-port-shape')
        name, role = row['name'], row['role']
        if name != 'storage_' + role or name not in widths:
            raise ValueError('wishbone-storage-observation-port-shape')
        if (row['direction'] != 'output' or row['width'] != widths[name]
                or type(row['expression']) is not str or not row['expression']):
            raise ValueError('wishbone-storage-observation-port-shape')
    by_name = {row['name']: row for row in ports}
    if (by_name['storage_value']['expression']
            != contract['storage_expression']['expression']
            or by_name['storage_reset']['expression'] != 'reset'):
        raise ValueError('wishbone-storage-observation-expression-mismatch')
    runtime_ports = {
        (row.get('name'), row.get('direction'), row.get('width'))
        for row in runtime.get('runtime_ports') or [] if isinstance(row, dict)}
    for row in ports:
        if (row['name'], 'output', row['width']) not in runtime_ports:
            raise ValueError('wishbone-storage-observation-runtime-port-mismatch')
        if f'assign {row["name"]} = {row["expression"]};' not in runtime_sv:
            raise ValueError(
                'wishbone-storage-observation-runtime-expression-mismatch')
    trace = runtime.get('base_protocol_trace')
    signals = trace.get('signals') if isinstance(trace, dict) else None
    trace_widths = trace.get('signal_widths') if isinstance(trace, dict) else None
    if (not isinstance(trace, dict) or trace.get('protocol') != 'wishbone'
            or trace.get('endpoint_id') != endpoint.endpoint_id
            or not isinstance(signals, dict) or set(signals) != set(ROLES)
            or 'err' in signals
            or not isinstance(trace_widths, dict)
            or set(trace_widths) != set(ROLES)):
        raise ValueError('wishbone-storage-observation-trace-mismatch')
    for role in ROLES:
        width = widths['storage_' + role]
        if trace_widths[role] != width:
            raise ValueError('wishbone-storage-observation-trace-mismatch')
        if (signals[role], 'output', width) not in runtime_ports:
            raise ValueError('wishbone-storage-observation-trace-mismatch')
        if f'assign {signals[role]} =' not in runtime_sv:
            raise ValueError('wishbone-storage-observation-trace-mismatch')
    return ports


def verified_wishbone_storage_observation(document, artifact, *, base_dir):
    """Re-derive a Wishbone probe against its artifact; return ``None`` or raise.

    ``None`` means "prospective and internally consistent": every documentary
    field was re-derived from the artifact bytes and the reviewed source
    bytes, and no verification is claimed.  Any claim of hierarchy/native
    proof, any tampered digest/port/contract/selection/trace, and any
    non-Wishbone artifact is refused rather than downgraded.
    """
    if not isinstance(document, dict):
        raise ValueError('wishbone-storage-observation-shape')
    if not isinstance(artifact, LocalRuntimeArtifact):
        raise ValueError('wishbone-storage-observation-artifact-required')
    if set(document) != DOCUMENT_KEYS:
        raise ValueError('wishbone-storage-observation-contract-mismatch')
    if (document.get('schema_version') != SCHEMA_VERSION
            or document.get('scope') != SCOPE
            or document.get('sample_group') != SAMPLE_GROUP):
        raise ValueError('wishbone-storage-observation-contract-mismatch')
    for flag in AUTHORITY_FLAGS:
        if document.get(flag) is not False:
            raise ValueError('wishbone-storage-observation-proof-unavailable')
    if EVIDENCE_KEYS & set(document):
        raise ValueError('wishbone-storage-observation-proof-unavailable')
    if document.get('digest') != wishbone_storage_probe_digest(document):
        raise ValueError('wishbone-storage-observation-digest-mismatch')
    runtime = artifact.runtime_document
    if not isinstance(runtime, dict) or runtime.get('kind') != (
            'wishbone_register_observe'):
        raise ValueError('wishbone-storage-observation-artifact-required')
    if runtime.get('storage_observation') != document:
        raise ValueError('wishbone-storage-observation-runtime-mismatch')
    if runtime.get('storage_probe_ports') != document.get('ports'):
        raise ValueError('wishbone-storage-observation-runtime-mismatch')
    if runtime.get('runtime_sv_sha256') != hashlib.sha256(
            artifact.runtime_sv.encode()).hexdigest():
        raise ValueError('wishbone-storage-observation-runtime-bytes-mismatch')
    try:
        contract = validate_wishbone_storage_source_contract(
            document['source_contract'], artifact.plan.profile,
            base_dir=base_dir)
    except ValueError as error:
        raise ValueError(
            'wishbone-storage-observation-contract-mismatch') from error
    if _canonical(document['source_contract']) != _canonical(contract):
        raise ValueError('wishbone-storage-observation-contract-mismatch')
    endpoint = _single_endpoint(artifact)
    selection = document.get('selection')
    if (not isinstance(selection, dict) or set(selection) != SELECTION_KEYS
            or any(type(selection[key]) is not str or not selection[key]
                   for key in SELECTION_KEYS)):
        raise ValueError('wishbone-storage-observation-selection-mismatch')
    if (selection['endpoint_id'] != endpoint.endpoint_id
            or selection['contract_id'] != contract['contract_id']
            or selection['register'] != contract['register']['name']):
        raise ValueError('wishbone-storage-observation-selection-mismatch')
    if document.get('protocol') != ['wishbone', 'classic']:
        raise ValueError('wishbone-storage-observation-contract-mismatch')
    if document.get('address_units') != contract['decode']['address_units']:
        raise ValueError('wishbone-storage-observation-contract-mismatch')
    _check_ports(document, contract, endpoint, runtime, artifact.runtime_sv)
    return None
