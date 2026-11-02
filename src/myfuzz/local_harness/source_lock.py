"""Explicit pinned-source gate, separate from planning and pure rendering."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

from myfuzz.composition.component_profile import ComponentProfile, _source_locator


def verify_local_source_lock(profile: ComponentProfile, *, base_dir: Path,
                             allow_source_only: bool = False) -> dict[str, object]:
    from .execution_validation import execution_validation_active, static_validation
    if not execution_validation_active() or not isinstance(profile, ComponentProfile) or type(allow_source_only) is not bool:
        return _verify_local_source_lock(profile, base_dir=base_dir, allow_source_only=allow_source_only)
    root = Path(base_dir).resolve()
    key = ('local-source-lock', profile.profile_fingerprint, str(root), allow_source_only)
    return static_validation(key, lambda: _verify_local_source_lock(
        profile, base_dir=root, allow_source_only=allow_source_only))


def _verify_local_source_lock(profile: ComponentProfile, *, base_dir: Path,
                              allow_source_only: bool = False) -> dict[str, object]:
    """Verify one profile against the lock and pinned closure without lint replay.

    This is an explicit API; no artifact builder invokes it automatically yet.
    It requires a repository checkout containing scripts/verify_soc_sources.py
    beside src/; an installed package alone cannot provide this gate.

    Call at the artifact acceptance/build boundary. Planning and rendering remain
    usable for deliberate profile mutations; their output alone carries no
    trusted-source claim. The returned identity describes this verification's
    bytes and must be refreshed before using changed source or lock artifacts.

    ``allow_source_only`` is a narrow opt-in for the exact ``rvx_core`` source
    selection while its lock has no elaboration evidence. It authenticates the
    selected source but preserves ``elaboration_unverified``; all other calls
    retain the strict selected-and-elaboration-verified requirement.
    """
    if type(allow_source_only) is not bool:
        raise ValueError('local-source-lock-allow-source-only-bool-required')
    if not isinstance(profile, ComponentProfile):
        raise ValueError('local-source-lock-profile-required')
    # A component can carry its own source manifest, rather than requiring a
    # row in the global component registry. It is a profile declaration, not
    # an independent runtime or behavioral attestation: reuse the very same
    # Git, source-closure and elaboration evidence checks as the central lock.
    if 'local_source_manifest' in profile.evidence:
        if allow_source_only:
            raise ValueError('local-source-lock-profile-manifest-source-only-unsupported')
        if profile.source != _source_locator(profile.source_document):
            raise ValueError('local-source-lock-profile-source-inconsistent')
        document = profile.evidence['local_source_manifest']
        if not isinstance(document, dict):
            raise ValueError('local-source-lock-profile-manifest-invalid')
        raw = json.dumps(document, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
        return _verify_lock_document(profile, Path(base_dir).resolve(), document, raw,
                                     allow_source_only=False)
    if allow_source_only and profile.component_id != 'rvx_core':
        raise ValueError('local-source-lock-source-only-component-unsupported')
    if profile.component_id == 'zipdma_selected_wishbone':
        if profile.source != _source_locator(profile.source_document):
            raise ValueError('local-source-lock-profile-source-inconsistent')
        from .zipdma_profile_session import verify_zipdma_profile
        return verify_zipdma_profile(profile, base_dir=base_dir)
    # Reuse the profile loader's canonical parsing, including elaboration.
    # Builders consume source, so matching only its retained JSON is insufficient.
    if profile.source != _source_locator(profile.source_document):
        raise ValueError('local-source-lock-profile-source-inconsistent')
    if allow_source_only and (
            profile.source_document.get('root') != 'external_designs/rvx'
            or profile.source_document.get('top_module') != 'rvx_core'
            or profile.source_document.get('files') != ['hardware/rvx_core.v']):
        raise ValueError('local-source-lock-source-only-scope-mismatch')
    if profile.component_id == 'pulp_gpio_causal_local':
        from .pulp_gpio_probe_contract import verify_pulp_gpio_source_contract
        return verify_pulp_gpio_source_contract(profile, base_dir=base_dir)
    if profile.component_id == 'vexiiriscv':
        from .vexii_source_contract import verify_vexii_source_contract
        return verify_vexii_source_contract(profile, base_dir=base_dir)
    if profile.component_id == 'vexiiriscv_irq':
        # A declared, validated delta of the pinned baseline profile over the
        # same generated RTL bytes.  The baseline closure is re-verified here,
        # so this variant cannot outlive or diverge from its baseline pin.
        from .vexii_irq_contract import verify_vexii_irq_source_contract
        return verify_vexii_irq_source_contract(profile, base_dir=base_dir)
    if profile.component_id == 'cvw':
        # CORE-V Wally is a local component (root ".", content pin) whose typed top
        # is repository-authored, so its upstream half cannot be a git-pinned lock
        # record of its own; see cvw_contract.py for the split.
        from .cvw_contract import verify_cvw_source_contract
        return verify_cvw_source_contract(profile, base_dir=base_dir)
    if profile.component_id == 'cv32e40p_rvfi_local':
        from .cv32e40p_rvfi_contract import verify_cv32e40p_rvfi_source_contract
        return verify_cv32e40p_rvfi_source_contract(profile, base_dir=base_dir)
    if profile.component_id == 'ibex_rvfi_local':
        from .ibex_rvfi_contract import verify_ibex_rvfi_source_contract
        return verify_ibex_rvfi_source_contract(profile, base_dir=base_dir)
    if profile.component_id == 'opentitan_pattgen_local':
        from .opentitan_pattgen_contract import verify_opentitan_pattgen_source_contract
        return verify_opentitan_pattgen_source_contract(profile, base_dir=base_dir)
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
    if profile.component_id == 'opentitan_sysrst_ctrl_local':
        from .opentitan_sysrst_ctrl_contract import verify_opentitan_sysrst_ctrl_source_contract
        return verify_opentitan_sysrst_ctrl_source_contract(profile, base_dir=base_dir)
    if profile.component_id == 'opentitan_uart_fifo_local':
        from .opentitan_uart_fifo_contract import verify_opentitan_uart_fifo_source_contract
        return verify_opentitan_uart_fifo_source_contract(profile, base_dir=base_dir)
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
    return _verify_lock_document(profile, root, document, raw, allow_source_only)


def _verify_lock_document(profile, root, document, raw, allow_source_only):
    """Apply the same source/evidence verifier to either manifest location."""
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
    source_only_rvx = allow_source_only
    if source_only_rvx and (
            locked.get('root') != 'external_designs/rvx'
            or locked.get('top_module') != 'rvx_core'
            or locked.get('files') != ['hardware/rvx_core.v']):
        raise ValueError('local-source-lock-source-only-scope-mismatch')
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
    if source_only_rvx:
        if ((record['closure_status'], record['source_status'], record['elaboration_status']) !=
                ('selected', 'source_verified', 'elaboration_unverified')
                or 'elaboration' in record):
            raise ValueError('local-source-lock-unverified:' + profile.component_id)
    elif (record['closure_status'], record['source_status'], record['elaboration_status']) != (
            'selected', 'source_verified', 'elaboration_verified'):
        raise ValueError('local-source-lock-unverified:' + profile.component_id)
    closures = document.get('elaboration_closures', {})
    if not isinstance(closures, dict):
        raise ValueError('local-source-lock-inline-closures-invalid')
    inline = closures.get(profile.component_id)
    result = verifier.verify_record(
        record, root, owners=verifier.document_owners(document, root),
        allowed_roots=verifier.document_roots(document)[record['id']], replay=False,
        inline_elaboration=inline)
    if source_only_rvx:
        # verify_record authenticated selected source bytes and Git provenance;
        # its no-evidence result deliberately keeps elaboration unverified.
        return {
            **result,
            'schema_version': 'local_source_lock_verification.v1',
            'lock_sha256': hashlib.sha256(raw).hexdigest(),
        }
    # The verifier authenticated this evidence's hash, closure bytes and command.
    evidence_raw = ((root / record['elaboration']['evidence']).read_bytes() if inline is None
        else json.dumps(inline, sort_keys=True, separators=(',', ':'), allow_nan=False).encode())
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
