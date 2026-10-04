"""Explicit pinned-source gate, separate from planning and pure rendering."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

from myfuzz.composition.component_profile import ComponentProfile, _source_locator


def verify_local_source_lock(profile: ComponentProfile, *, base_dir: Path) -> dict[str, object]:
    """Verify one profile against the lock and pinned closure without lint replay.

    This is an explicit API; no artifact builder invokes it automatically yet.
    It requires a repository checkout containing scripts/verify_soc_sources.py
    beside src/; an installed package alone cannot provide this gate.

    Call at the artifact acceptance/build boundary. Planning and rendering remain
    usable for deliberate profile mutations; their output alone carries no
    trusted-source claim. The returned identity describes this verification's
    bytes and must be refreshed before using changed source or lock artifacts.
    """
    if not isinstance(profile, ComponentProfile):
        raise ValueError('local-source-lock-profile-required')
    # Reuse the profile loader's canonical parsing, including elaboration.
    # Builders consume source, so matching only its retained JSON is insufficient.
    if profile.source != _source_locator(profile.source_document):
        raise ValueError('local-source-lock-profile-source-inconsistent')
    if profile.component_id == 'opentitan_gpio_local':
        from .opentitan_gpio_contract import verify_opentitan_gpio_source_contract
        return verify_opentitan_gpio_source_contract(profile, base_dir=base_dir)
    if profile.component_id == 'opentitan_i2c_local':
        from .opentitan_i2c_contract import verify_opentitan_i2c_source_contract
        return verify_opentitan_i2c_source_contract(profile, base_dir=base_dir)
    if profile.component_id == 'opentitan_spi_device_local':
        from .opentitan_spi_device_contract import verify_opentitan_spi_device_source_contract
        return verify_opentitan_spi_device_source_contract(profile, base_dir=base_dir)
    if profile.component_id == 'opentitan_rv_timer_local':
        from .opentitan_rv_timer_contract import verify_opentitan_rv_timer_source_contract
        return verify_opentitan_rv_timer_source_contract(profile, base_dir=base_dir)
    if profile.component_id == 'opentitan_spi_host_local':
        from .opentitan_spi_host_contract import verify_opentitan_spi_host_source_contract
        return verify_opentitan_spi_host_source_contract(profile, base_dir=base_dir)
    if profile.component_id == 'opentitan_uart_local':
        from .opentitan_uart_contract import verify_opentitan_uart_source_contract
        return verify_opentitan_uart_source_contract(profile, base_dir=base_dir)
    if profile.component_id == 'pulp_spi':
        # The selected APB top has one separately owned RTL dependency. Its
        # profile names exactly the authenticated elaboration union, while the
        # lock keeps the two original git owners separate. The SPI verifier
        # checks both records, the closure pin, and every union byte.
        from .pulp_spi_contract import verify_pulp_spi_source_contract
        facts = verify_pulp_spi_source_contract(profile, base_dir=base_dir)
        return {
            'schema_version': 'local_source_lock_verification.v1',
            'source_status': 'source_verified',
            'elaboration_status': 'elaboration_verified',
            'lock_sha256': facts['lock_sha256'],
            'closure_sha256': facts['closure_sha256'],
            'profile_union_revision': facts['profile_union_revision'],
            'source_records': facts['source_records'],
        }
    root = Path(base_dir).resolve()
    raw = (root / 'configs/soc/sources.lock.json').read_bytes()
    document = json.loads(raw)
    if not isinstance(document, dict):
        raise ValueError('invalid-lock-document')
    # Load trusted implementation beside this package, never a caller-supplied
    # script from base_dir (which may be a temporary source verification root).
    script = Path(__file__).resolve().parents[3] / 'scripts/verify_soc_sources.py'
    spec = importlib.util.spec_from_file_location('_myfuzz_local_source_verifier', script)
    if spec is None or spec.loader is None:
        raise ValueError('local-source-verifier-unavailable')
    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)
    verifier.validate_document(document)
    matches = [record for record in document['components'] if record['id'] == profile.component_id]
    if not matches:
        raise ValueError('local-source-lock-missing-component:' + profile.component_id)
    record = matches[0]
    source = dict(profile.source_document)
    locked = record['source']
    defaults = {'files': [], 'filelist': None, 'include_roots': [],
                'repositories': [], 'filelist_variables': [], 'top_port_selection': 'all'}
    for name in ('root', 'revision', 'top_module', *defaults):
        if source.get(name, defaults.get(name)) != locked.get(name, defaults.get(name)):
            raise ValueError('local-source-lock-source-mismatch:' + name)
    settings = source.get('elaboration', {})
    locked_settings = locked.get('elaboration', {})
    if settings.get('frontend', 'verilator-json') != 'verilator-json':
        raise ValueError('local-source-lock-frontend-mismatch')
    for name in ('frontend', 'warning_policy'):
        if name in locked_settings and settings.get(name) != locked_settings[name]:
            raise ValueError('local-source-lock-source-mismatch:' + name)
    parameters = {item['name']: item['value'] for item in settings.get('parameters', [])}
    locked_parameters = {item['name']: item['value'] for item in record.get('typed_parameters', [])}
    if parameters != locked_parameters:
        raise ValueError('local-source-lock-parameter-mismatch')
    for declared in (settings, locked_settings):
        if 'parameters' in declared and {item['name']: item['value'] for item in declared['parameters']} != locked_parameters:
            raise ValueError('local-source-lock-parameter-mismatch')
    defines = {item['name']: item.get('value') for item in settings.get('defines', [])}
    locked_defines = {}
    for token in record.get('defines', []):
        name, separator, value = token.partition('=')
        locked_defines[name] = value if separator else None
    if defines != locked_defines:
        raise ValueError('local-source-lock-define-mismatch')
    if (record['closure_status'], record['source_status'], record['elaboration_status']) != (
            'selected', 'source_verified', 'elaboration_verified'):
        raise ValueError('local-source-lock-unverified:' + profile.component_id)
    result = verifier.verify_record(
        record, root, owners=verifier.document_owners(document, root),
        allowed_roots=verifier.document_roots(document)[record['id']], replay=False)
    # The verifier authenticated this evidence's hash, closure bytes and command.
    evidence_raw = (root / record['elaboration']['evidence']).read_bytes()
    if hashlib.sha256(evidence_raw).hexdigest() != record['elaboration']['evidence_sha256']:
        raise ValueError('local-source-lock-evidence-changed')
    evidence = json.loads(evidence_raw)
    evidence_parameters = {item['name']: item['value'] for item in evidence.get('parameters', [])}
    evidence_defines = {}
    for token in evidence.get('defines', []):
        name, separator, value = token.partition('=')
        evidence_defines[name] = value if separator else None
    if parameters != evidence_parameters or defines != evidence_defines:
        raise ValueError('local-source-lock-elaboration-settings-mismatch')
    return {
        **result,
        'schema_version': 'local_source_lock_verification.v1',
        'lock_sha256': hashlib.sha256(raw).hexdigest(),
    }
