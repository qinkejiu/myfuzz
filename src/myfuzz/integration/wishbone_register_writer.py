"""Wishbone word-index projection of the registered CPU writer declaration.

A D3 ``cpu_mmio_stream`` source declares a full target word.  The registered
Wishbone storage row (``zipcpu-wbuart.setup.storage.v1``) is word addressed and
its reviewed ``SETUP`` write mask is ``0x7fffffff``: bit 31 is never stored and
always reads 0.  :func:`myfuzz.integration.generated_register_writer.declare_writer`
refuses every masked write because no partial-write/merge policy is declared.

This module does not relax that policy.  It adds one *closed, row-keyed* policy
for a masked **full-word** write whose value contains only writable bits -- a
caller never supplies a merge, a read-modify-write or extra bits -- and it adds
the Wishbone address-unit projection (``candidate.access.word_index``).  A
full ``0xffffffff`` mask stays on the exact ``declare_writer`` path; its bytes
are only re-validated and re-projected here.

Both outcomes are declarations only: no runtime admission, register version,
native eligibility, reset prerequisite or storage authority is granted.
"""
from __future__ import annotations

from hashlib import sha256
import json
from types import MappingProxyType
import sys

from myfuzz.integration.generated_register_writer import declare_writer
from myfuzz.local_harness.compiled_artifact_admission import _difference
from myfuzz.local_harness.wishbone_storage_source_contract import (
    registered_wishbone_storage_source_contracts,
    select_wishbone_storage_source_contract,
    validate_wishbone_storage_source_contract, wishbone_setup_matches,
    wishbone_word_index)
from myfuzz.scenario.compiled_paths import compile_paths
from myfuzz.scenario.rv32i_sources import (
    Rv32iInstruction, _split_address, fragment_bytes)

DECLARATION_SCHEMA = 'generated_register_writer.v1'
CANDIDATE_SCHEMA = 'validated_register_candidate.v1'
POLICY_SCHEMA = 'register_write_policy.v1'
POLICY_KIND = 'declared_masked_full_word_write'
POLICY_KEYS = frozenset({'schema_version', 'kind', 'value_mask', 'stored_bits',
                         'not_claimed'})
POLICY_NOT_CLAIMED = (
    'bits outside value_mask are not written',
    'WBUART SETUP bit 31 always reads 0')
SCOPE = 'directed_CPU_writer_and_readback_only'
UNSUPPORTED_FLOWS = ['F1', 'F2', 'F3']
REFUSALS = ['ip-register-version-prerequisite-not-authenticated',
            'compiled-chain-certificate-checker-not-installed']
MASKED_REFUSAL = 'register-candidate-masked-merge-policy-undeclared'
FULL_MASK = 0xffffffff
REGISTER = 'SETUP'
WORD_INDEX = 0
WINDOW_BYTES = 16
FULL_WORD_BYTES = 4
BYTE_ENABLE = 15
_WB_PROTOCOL = ('wishbone', 'classic')
_WB_ENDPOINT_FUNCTION = 'mmio_slave'


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      allow_nan=False)


def _digest(value):
    return sha256(_canonical(value).encode()).hexdigest()


def _pin(value):
    return (value, getattr(value, '__code__', None))


# Import-time pins: every dependency is captured once, before any declaration
# can be requested.  A later module/function replacement is a drift refusal,
# never a re-baseline.
_DEPENDENCIES = {
    'declare_writer': declare_writer,
    '_difference': _difference,
    'compile_paths': compile_paths,
    'Rv32iInstruction': Rv32iInstruction,
    'fragment_bytes': fragment_bytes,
    '_split_address': _split_address,
    'registered_wishbone_storage_source_contracts':
        registered_wishbone_storage_source_contracts,
    'select_wishbone_storage_source_contract':
        select_wishbone_storage_source_contract,
    'validate_wishbone_storage_source_contract':
        validate_wishbone_storage_source_contract,
    'wishbone_setup_matches': wishbone_setup_matches,
    'wishbone_word_index': wishbone_word_index,
}
_PINNED = MappingProxyType({name: _pin(value) for name, value in _DEPENDENCIES.items()})
_ORIGINS = MappingProxyType({name: value.__module__ for name, value in _DEPENDENCIES.items()})


def _check_pins():
    if (_DECLARATION_PIN[0] is not declare_wishbone_writer
            or _DECLARATION_PIN[1] is not declare_wishbone_writer.__code__
            or _VALIDATOR_PIN[0] is not validate_wishbone_masked_candidate
            or _VALIDATOR_PIN[1] is not validate_wishbone_masked_candidate.__code__):
        raise ValueError('wishbone-writer-declaration-drift:entry')
    for name, (value, code) in _PINNED.items():
        current = globals().get(name)
        if current is not value or (code is not None
                                    and getattr(value, '__code__', None) is not code):
            raise ValueError('wishbone-writer-declaration-drift:' + name)
        origin = sys.modules.get(_ORIGINS[name])
        if origin is not None and getattr(
                origin, value.__qualname__.split('.')[0], None) is not value:
            raise ValueError('wishbone-writer-declaration-drift:' + name)


# ---------------------------------------------------------------------------
# closed D3/contract cross-checks
# ---------------------------------------------------------------------------

def _source_access(compiled, source_id):
    """The single declared cpu_mmio_stream access, or ``None``."""
    if not isinstance(compiled, dict):
        return None
    paths = compiled.get('paths')
    if not isinstance(paths, (list, tuple)):
        return None
    rows = [source for path in paths if isinstance(path, dict)
            and path.get('flow_id') == 'F4' and path.get('status') == 'executable'
            for source in (path.get('sources') or ()) if isinstance(source, dict)
            and source.get('source_id') == source_id
            and source.get('kind') == 'cpu_mmio_stream']
    if len(rows) != 1:
        return None
    access = rows[0].get('register_access')
    return access if isinstance(access, dict) else None


def _target_profile(request, access):
    component = getattr(request, 'component', None)
    target = access.get('target_component') if isinstance(access, dict) else None
    row = component(target) if callable(component) else None
    if row is None or getattr(row, 'profile', None) is None:
        raise ValueError('wishbone-writer-target-unsupported')
    return row.profile


def _wishbone_endpoint(profile, access):
    endpoint_id = access.get('target_endpoint') if isinstance(access, dict) else None
    rows = [endpoint for endpoint in getattr(profile, 'endpoints', ())
            if endpoint.endpoint_id == endpoint_id]
    if (type(endpoint_id) is not str or not endpoint_id or len(rows) != 1
            or rows[0].protocol is None
            or tuple(rows[0].protocol) != _WB_PROTOCOL
            or rows[0].function != _WB_ENDPOINT_FUNCTION):
        raise ValueError('wishbone-writer-target-unsupported')
    return rows[0]


def _base_dir(request):
    base = getattr(request, 'base_dir', None)
    if type(base) is not str or not base:
        raise ValueError('wishbone-writer-source-inputs-required')
    return base


def _registered_contract(request, access):
    """Load the one registered source row for this exact Wishbone target."""
    profile = _target_profile(request, access)
    _wishbone_endpoint(profile, access)
    base_dir = _base_dir(request)
    contract_ids = registered_wishbone_storage_source_contracts()
    if (type(contract_ids) is not tuple or len(contract_ids) != 1
            or type(contract_ids[0]) is not str or not contract_ids[0]):
        raise ValueError('wishbone-writer-contract-mismatch')
    try:
        contract = select_wishbone_storage_source_contract(
            profile, base_dir=base_dir,
            selection={'contract_id': contract_ids[0], 'register': REGISTER})
        contract = validate_wishbone_storage_source_contract(
            contract, profile, base_dir=base_dir)
    except ValueError as error:
        raise ValueError('wishbone-writer-contract-mismatch') from error
    return profile, contract


def _project_access(access, contract):
    """Re-derive the word-addressed geometry and add exactly ``word_index``."""
    register = contract.get('register') if isinstance(contract, dict) else None
    decode = contract.get('decode') if isinstance(contract, dict) else None
    if (not isinstance(access, dict) or not isinstance(register, dict)
            or not isinstance(decode, dict)):
        raise ValueError('wishbone-writer-contract-mismatch')
    if (register.get('name') != REGISTER
            or register.get('word_index') != WORD_INDEX
            or register.get('width') != 32
            or type(register.get('write_mask')) is not int
            or type(register.get('read_mask')) is not int
            or decode.get('window_bytes') != WINDOW_BYTES
            or decode.get('address_units') != 'word'):
        raise ValueError('wishbone-writer-contract-mismatch')
    if 'word_index' in access:
        raise ValueError('wishbone-writer-declaration-mismatch')
    if (access.get('operation') != 'write'
            or access.get('width_bytes') != FULL_WORD_BYTES):
        raise ValueError('wishbone-writer-register-mismatch')
    offset = access.get('register_offset')
    window = access.get('window_size')
    if (type(offset) is not int or type(window) is not int
            or window != WINDOW_BYTES or not 0 <= offset < window
            or offset % FULL_WORD_BYTES or offset + FULL_WORD_BYTES > window):
        raise ValueError('wishbone-writer-register-mismatch')
    try:
        word_index = wishbone_word_index(offset)
        matches = wishbone_setup_matches(contract, offset)
    except ValueError as error:
        raise ValueError('wishbone-writer-contract-mismatch') from error
    if (access.get('register') != register['name']
            or word_index != register['word_index'] or matches is not True):
        raise ValueError('wishbone-writer-register-mismatch')
    projected = dict(access)
    projected['word_index'] = word_index
    return projected


# ---------------------------------------------------------------------------
# declared masked full-word write policy
# ---------------------------------------------------------------------------

def _masked_policy(access):
    return dict(schema_version=POLICY_SCHEMA, kind=POLICY_KIND,
                value_mask=access['value_mask'],
                stored_bits=access['value_mask'],
                not_claimed=list(POLICY_NOT_CLAIMED))


def _require_policy(document):
    policy = document.get('write_policy') if isinstance(document, dict) else None
    if not isinstance(policy, dict) or set(policy) != POLICY_KEYS:
        raise ValueError('wishbone-writer-policy-invalid')
    if (policy.get('schema_version') != POLICY_SCHEMA
            or policy.get('kind') != POLICY_KIND
            or type(policy.get('value_mask')) is not int
            or not 0 < policy['value_mask'] < FULL_MASK
            or policy.get('stored_bits') != policy['value_mask']
            or not isinstance(policy.get('not_claimed'), list)
            or not policy['not_claimed']
            or any(type(row) is not str or not row for row in policy['not_claimed'])
            or document.get('write_policy_digest') != _digest(policy)):
        raise ValueError('wishbone-writer-policy-invalid')
    return policy


def validate_wishbone_masked_candidate(request, compiled, *, source_id,
                                       source_component, source_endpoint,
                                       target_component, address, write, value,
                                       byte_enable):
    """Validate one masked full-word write against freshly recompiled D3.

    The recompile-and-compare rule is the same as
    ``scenario.register_source_access.validate_register_candidate``.  This is a
    *declared* policy, never a relaxation: the value may only contain bits that
    the registered source row already stores, the byte enable is the exact
    full word, and the access mask must equal the registered contract mask.
    """
    _check_pins()
    if not isinstance(compiled, dict) or not isinstance(
            compiled.get('paths'), (list, tuple)):
        raise ValueError('wishbone-writer-candidate-source-undeclared-or-ambiguous')
    try:
        recompiled = compile_paths(request)
    except (TypeError, ValueError) as error:
        raise ValueError(
            'wishbone-writer-candidate-compiled-document-mismatch') from error
    difference = _difference(recompiled, compiled)
    if difference is not None:
        raise ValueError(
            'wishbone-writer-candidate-compiled-document-mismatch:' + difference)
    sources = [source for path in compiled['paths'] if isinstance(path, dict)
               and path.get('status') == 'executable'
               for source in (path.get('sources') or ()) if isinstance(source, dict)
               and source.get('source_id') == source_id
               and 'register_access' in source]
    if len(sources) != 1 or not isinstance(sources[0].get('register_access'), dict):
        raise ValueError('wishbone-writer-candidate-source-undeclared-or-ambiguous')
    access = sources[0]['register_access']
    if (source_component, source_endpoint) != (
            access.get('source_component'), access.get('source_endpoint')):
        raise ValueError('wishbone-writer-candidate-source-owner-mismatch')
    if target_component != access.get('target_component'):
        raise ValueError('wishbone-writer-candidate-target-mismatch')
    if type(address) is not int or address != access.get('address'):
        raise ValueError('wishbone-writer-candidate-address-mismatch')
    if write is not True or access.get('operation') != 'write':
        raise ValueError('wishbone-writer-candidate-operation-mismatch')
    if (type(byte_enable) is not int or byte_enable != BYTE_ENABLE
            or access.get('allowed_byte_enables') != [BYTE_ENABLE]):
        raise ValueError('wishbone-writer-candidate-partial-access')
    if (access.get('width_bytes') != FULL_WORD_BYTES
            or access.get('byte_enable_domain') != 'target_word_lanes'
            or access.get('access_alignment') != FULL_WORD_BYTES
            or access.get('value_origin') != 'cpu_transaction_wdata'
            or access.get('register_origin') != 'bound_target_register_commit'):
        raise ValueError('wishbone-writer-candidate-word-shape-unsupported')
    access_mask = access.get('value_mask')
    if type(access_mask) is not int or not 0 < access_mask < FULL_MASK:
        raise ValueError(
            'wishbone-writer-candidate-masked-policy-unsupported')
    if type(value) is not int or not 0 <= value <= FULL_MASK:
        raise ValueError('wishbone-writer-candidate-value-invalid')
    if value & ~access_mask:
        raise ValueError('wishbone-writer-candidate-reserved-value-bits')
    _profile, contract = _registered_contract(request, access)
    register = contract['register']
    if (access.get('register') != register['name']
            or access.get('register_offset') != register['canonical_offset']
            or access_mask != register.get('write_mask')
            or type(register.get('write_mask')) is not int
            or type(register.get('read_mask')) is not int):
        raise ValueError('wishbone-writer-register-mismatch')
    offset = access.get('register_offset')
    window = access.get('window_size')
    if (type(offset) is not int or type(window) is not int
            or window != contract['decode'].get('window_bytes')
            or not 0 <= offset < window
            or offset % FULL_WORD_BYTES or offset + FULL_WORD_BYTES > window):
        raise ValueError('wishbone-writer-register-mismatch')
    try:
        word_index = wishbone_word_index(offset)
        matches = wishbone_setup_matches(contract, offset)
    except ValueError as error:
        raise ValueError('wishbone-writer-contract-mismatch') from error
    if word_index != register.get('word_index') or matches is not True:
        raise ValueError('wishbone-writer-register-mismatch')
    projected = dict(access)
    projected['word_index'] = word_index
    policy = _masked_policy(projected)
    return dict(schema_version=CANDIDATE_SCHEMA, validated=True,
        runtime_admitted=False, source_id=source_id, access=projected,
        value=value, byte_enable=byte_enable,
        write_policy=policy, write_policy_digest=_digest(policy),
        remaining=['actual CPU writer/target receipt join',
                   'prerequisite witnesses',
                   'compiled assertion checker bindings',
                   'declared masked full-word write: bits outside '
                   'value_mask are not written'])


# ---------------------------------------------------------------------------
# declaration code (identical instruction stream to declare_writer)
# ---------------------------------------------------------------------------

def _writer_code(address, value, result_address):
    address_high, address_low = _split_address(address)
    value_high, value_low = _split_address(value)
    result_high, result_low = _split_address(result_address)
    return fragment_bytes((
        Rv32iInstruction('LUI', rd=1, immediate=address_high),
        Rv32iInstruction('ADDI', rd=1, rs1=1, immediate=address_low),
        Rv32iInstruction('LUI', rd=2, immediate=value_high),
        Rv32iInstruction('ADDI', rd=2, rs1=2, immediate=value_low),
        Rv32iInstruction('SW', rs1=1, rs2=2),
        Rv32iInstruction('LW', rd=3, rs1=1),
        Rv32iInstruction('LUI', rd=4, immediate=result_high),
        Rv32iInstruction('SW', rs1=4, rs2=3, immediate=result_low),
        *(Rv32iInstruction('NOP') for _ in range(4))))


def _result_checks(request, access, result_address):
    if (type(result_address) is not int or not 0 <= result_address <= 0xfffffffc
            or result_address % FULL_WORD_BYTES):
        raise ValueError('wishbone-writer-result-address-invalid')
    cpu = request.component(access['source_component']).profile.cpu
    if cpu is None or cpu.xlen != 32 or 'I' not in {e.upper()
                                                     for e in cpu.extensions}:
        raise ValueError('wishbone-writer-RV32I-required')
    resources = [resource for resource in request.wiring.resources
                 if resource.component_instance == access['source_component']
                 and resource.write is True and resource.base is not None
                 and resource.size is not None
                 and resource.base <= result_address
                 and result_address + FULL_WORD_BYTES <= resource.base + resource.size]
    if len(resources) != 1:
        raise ValueError('wishbone-writer-result-RAM-undeclared')
    if any(window.base <= result_address < window.base + window.size
           for window in request.wiring.windows):
        raise ValueError('wishbone-writer-result-overlaps-MMIO')


def _masked_declaration(request, compiled, *, source_id, access, value,
                        result_address):
    candidate = validate_wishbone_masked_candidate(
        request, compiled, source_id=source_id,
        source_component=access.get('source_component'),
        source_endpoint=access.get('source_endpoint'),
        target_component=access.get('target_component'),
        address=access.get('address'), write=True, value=value,
        byte_enable=BYTE_ENABLE)
    policy = _require_policy(candidate)
    projected = candidate['access']
    _result_checks(request, projected, result_address)
    code = _writer_code(projected['address'], value, result_address)
    body = {key: candidate[key] for key in candidate
            if key not in ('write_policy', 'write_policy_digest')}
    return dict(schema_version=DECLARATION_SCHEMA, candidate=body,
        result_address=result_address, code_hex=code.hex(),
        code_sha256=sha256(code).hexdigest(),
        compiled_sha256=sha256(json.dumps(compiled, sort_keys=True).encode()).hexdigest(),
        runtime_admitted=False, scope=SCOPE,
        unsupported_flows=list(UNSUPPORTED_FLOWS), refusals=list(REFUSALS),
        write_policy=policy,
        write_policy_digest=candidate['write_policy_digest'])


def declare_wishbone_writer(request, compiled, *, source_id, value,
                            result_address=0x30000):
    """Declare one Wishbone-target CPU writer, or refuse by name.

    ``result_address`` must be a writable in-RAM word; the default is kept only
    for signature parity with :func:`declare_writer` and must be overridden by
    a caller whose memory map does not contain it.
    """
    _check_pins()
    access = _source_access(compiled, source_id)
    if access is not None:
        profile = _target_profile(request, access)
        _wishbone_endpoint(profile, access)
        if (type(value) is int and type(access.get('value_mask')) is int
                and 0 < access['value_mask'] < FULL_MASK
                and value & ~access['value_mask']):
            raise ValueError('wishbone-writer-candidate-reserved-value-bits')
    try:
        document = declare_writer(request, compiled, source_id=source_id,
                                  value=value, result_address=result_address)
    except ValueError as error:
        if str(error) != MASKED_REFUSAL:
            raise
        if access is None:
            raise
        return _masked_declaration(request, compiled, source_id=source_id,
            access=access, value=value, result_address=result_address)
    if (not isinstance(document, dict)
            or document.get('schema_version') != DECLARATION_SCHEMA
            or not isinstance(document.get('candidate'), dict)
            or not isinstance(document['candidate'].get('access'), dict)):
        raise ValueError('wishbone-writer-declaration-mismatch')
    returned = document['candidate']['access']
    _profile, contract = _registered_contract(request, returned)
    if access is not None and returned != access:
        raise ValueError('wishbone-writer-declaration-mismatch')
    projected = _project_access(returned, contract)
    document = dict(document)
    document['candidate'] = dict(document['candidate'], access=projected)
    return document


_DECLARATION_PIN = (declare_wishbone_writer, declare_wishbone_writer.__code__)
_VALIDATOR_PIN = (validate_wishbone_masked_candidate,
                  validate_wishbone_masked_candidate.__code__)
