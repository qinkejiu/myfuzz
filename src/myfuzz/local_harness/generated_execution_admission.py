"""P7 factory artifact consumption and explicit fixed-runtime admission boundary."""
from collections.abc import Mapping
from pathlib import Path

from myfuzz.composition.component_profile import load_component_profile
from .compiled_artifact_admission import admit_compiled_artifacts
from .runtime_artifact import LocalRuntimeArtifact


class GeneratedExecutionRefused(ValueError):
    def __init__(self, code, pointer, detail=None):
        self.code, self.pointer, self.detail = code, pointer, detail
        super().__init__(f'{code} at {pointer or "/"}')


def select_factory_artifacts(artifacts, *, expected, base_dir,
                             physical_observations=False, observation_modes=None):
    """Validate and return supplied objects; never regenerate default artifacts.

    expected maps topology instances to (declared profile path, session kind).
    Selection follows explicit declarations and fingerprints, never names that
    merely resemble the configured component.
    """
    if not isinstance(artifacts, Mapping) or set(artifacts) != set(expected):
        raise GeneratedExecutionRefused('generated-runtime-instance-set-mismatch', '/artifacts')
    if type(physical_observations) is not bool:
        raise GeneratedExecutionRefused("generated-runtime-observation-mode-invalid", "/physical_observations")
    if observation_modes is not None and (not isinstance(observation_modes, Mapping)
            or set(observation_modes) != set(expected)
            or any(type(mode) is not bool for mode in observation_modes.values())):
        raise GeneratedExecutionRefused("generated-runtime-observation-mode-invalid", "/observation_modes")
    modes = observation_modes if observation_modes is not None else dict.fromkeys(expected, physical_observations)
    admitted = {}
    for instance, (profile_path, kind) in expected.items():
        artifact = artifacts[instance]
        pointer = '/artifacts/' + instance
        if not isinstance(artifact, LocalRuntimeArtifact):
            raise GeneratedExecutionRefused('generated-runtime-artifact-required', pointer)
        profile = load_component_profile(Path(base_dir) / profile_path)
        if artifact.plan.profile.profile_fingerprint != profile.profile_fingerprint:
            raise GeneratedExecutionRefused('generated-runtime-profile-mismatch', pointer)
        if artifact.plan.request.instance_id != instance:
            raise GeneratedExecutionRefused('generated-runtime-instance-mismatch', pointer)
        if artifact.runtime_document.get('kind') != kind:
            raise GeneratedExecutionRefused('generated-runtime-kind-mismatch', pointer)
        observed = 'native_physical_observation_contract' in artifact.runtime_document
        if observed != modes[instance]:
            raise GeneratedExecutionRefused('generated-runtime-observation-mode-mismatch', pointer)
        admitted[instance] = artifact
    return admitted


def require_runtime_projection(*, artifacts, compiled_inputs):
    """Fail before startup until actual decoder/checker semantic mapping exists.

    A D3 consistency verdict is insufficient: the fixed online decoder uses a
    different source/ownership graph and the checker does not implement every
    compiled assertion. No caller-supplied boolean or digest grants permission.
    """
    required = {'request', 'compiled', 'ownership', 'physical_port_map'}
    if (not isinstance(compiled_inputs, Mapping)
            or set(compiled_inputs) != required or artifacts is None):
        raise GeneratedExecutionRefused('compiled-runtime-input-required', '/compiled_inputs')
    admission = admit_compiled_artifacts(artifacts=artifacts, **compiled_inputs)
    if admission['status'] != 'compatible':
        raise GeneratedExecutionRefused('compiled-runtime-input-refused', '/compiled_inputs', admission)
    raise GeneratedExecutionRefused('compiled-runtime-projection-undeclared', '/compiled_inputs',
        {'admission': admission, 'path_gaps':runtime_projection_gaps(compiled_inputs['compiled']),
         'missing': ['compiled bound-producer delivery mapping',
                     'compiled source/seed to online decoder mapping',
                     'compiled assertions to actual checker mapping'],
         'runtime_started': False})


def select_execution_artifacts(*, artifacts, compiled_inputs, scope='compiled_paths'):
    """Select an explicit execution scope, never dropping supplied D3 semantics.

    loaded_artifacts is only the already-declared fixed factory's D2 object
    consumption scope. The factory still checks topology/profile/observation
    fingerprints; this selector grants no profile selection or D3 enforcement.
    """
    if scope not in ('compiled_paths','loaded_artifacts'):
        raise GeneratedExecutionRefused('generated-runtime-scope-invalid','/execution_scope')
    if scope == 'loaded_artifacts':
        if compiled_inputs is not None:
            raise GeneratedExecutionRefused('compiled-inputs-not-executed','/compiled_inputs',
                {'requires':'compiled_paths scope; loaded_artifacts cannot ignore supplied D3 semantics'})
        if not isinstance(artifacts,Mapping) or not artifacts:
            raise GeneratedExecutionRefused('generated-runtime-input-required','/artifacts')
        return artifacts
    require_runtime_projection(artifacts=artifacts,compiled_inputs=compiled_inputs)


def runtime_projection_gaps(compiled):
    """Located semantic obligations missing from the fixed runtime adapter.

    This inventory is a refusal explanation, never a supported-path assertion.
    Even familiar source/expectation names need an actual execution mapping.
    """
    rows=[]
    for index,path in enumerate(compiled['paths']):
        if path['status'] != 'executable':
            continue
        base=f'/paths/{index}'
        gaps=[]
        for field,identity in (('sources','source_id'),('bound_inputs','input_id'),
                               ('prerequisites','kind'),('assertions','expectation_id')):
            for item_index,item in enumerate(path[field]):
                gaps.append(dict(pointer=f'{base}/{field}/{item_index}',
                    obligation=field,identity=item[identity],status='execution_mapping_undeclared'))
        if path['seed'] is not None:
            gaps.append(dict(pointer=base+'/seed',obligation='seed',
                identity=path['seed']['kind'],status='execution_mapping_undeclared'))
        gaps.append(dict(pointer=base+'/constraints',obligation='constraints',
            identity=path['constraints']['policy_hash'],status='execution_mapping_undeclared'))
        rows.append(dict(path_id=path['path_id'],flow_id=path['flow_id'],
            runtime_admitted=False,gaps=gaps))
    return rows


def create_compiled_execution(*, artifacts, compiled_inputs, executor, **runtime_options):
    """Construct the explicitly selected code-owned compiled executor.

    Unlike the fixed factories this route consumes compiled source, constraint,
    prerequisite and checker mappings. Constructor startup is authorized by the
    caller; unsupported executors retain the default refusal.
    """
    if executor in ('compiled_mmio', 'compiled_mmio_obi_apb'):
        from myfuzz.integration.compiled_mmio import CompiledMmioRuntime
        return CompiledMmioRuntime(artifacts=artifacts,compiled_inputs=compiled_inputs,
            **runtime_options)
    if executor=='compiled_f4_obi_apb':
        from myfuzz.integration.compiled_f4 import CompiledF4Runtime
        return CompiledF4Runtime(artifacts=artifacts,compiled_inputs=compiled_inputs,
            **runtime_options)
    if executor=='compiled_f2_obi_apb':
        from myfuzz.integration.compiled_f2 import CompiledF2Runtime
        return CompiledF2Runtime(artifacts=artifacts,compiled_inputs=compiled_inputs,
            **runtime_options)
    if executor=='compiled_f4_wishbone':
        from myfuzz.integration.compiled_wishbone_f4 import WishboneF4Runtime
        return WishboneF4Runtime(artifacts=artifacts,compiled_inputs=compiled_inputs,
            **runtime_options)
    raise GeneratedExecutionRefused('compiled-executor-unsupported','/executor')


def assess_compiled_f6_support(*, artifacts, compiled_inputs, base_dir):
    """Pure closed F6 source/D2/D3 admission, without starting any runtime."""
    from copy import deepcopy
    import hashlib
    from myfuzz.scenario.f6_execution_contract import (
        F6ContractRefused, compile_f6_execution_contract, require_exact)
    from myfuzz.local_harness.ibex_irq_receipt_contract import verify_ibex_irq_receipt_artifact
    from myfuzz.local_harness.wbdmac_source_contract import verify_wbdmac_source_contract
    from myfuzz.local_harness.dma_artifact_endpoint_links import _artifact_link
    result = dict(schema_version='compiled_F6_support.v1', status='unsupported',
        refusals=[], runtime_started=False, runtime_enforcement='not_admitted',
        not_claimed=['native execution', 'live topology binding', 'IRQ/ISR certification'])
    try:
        if not isinstance(compiled_inputs, Mapping) or set(compiled_inputs) != {
                'request','compiled','ownership','physical_port_map'}:
            raise F6ContractRefused('f6-compiled-input-required','/compiled_inputs')
        request = compiled_inputs['request']
        contract = compile_f6_execution_contract(request, base_dir=base_dir)
        admission = admit_compiled_artifacts(artifacts=artifacts, **compiled_inputs)
        if admission['status'] != 'compatible':
            result['refusals'] = deepcopy(admission['refusals'])
            return result
        # Authenticate actual supplied D2 objects without elaborating or startup.
        import json
        from myfuzz.composition.component_profile import bind_profile
        from .renderer import render_local_harness
        for role in ('cpu','dma'):
            instance = contract[role]['instance_id']
            artifact = artifacts[instance]
            at = '/artifacts/' + instance
            from .source_lock import verify_local_source_lock
            verified = verify_local_source_lock(artifact.plan.profile, base_dir=Path(base_dir))
            require_exact(verified, artifact.source_verification, pointer=at+'/source_verification')
            document = artifact.runtime_document
            def sha(value):
                return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),
                    ensure_ascii=False,allow_nan=False).encode()).hexdigest()
            if (document.get('artifact_digest') != sha({k:v for k,v in document.items() if k!='artifact_digest'})
                    or document.get('runtime_sv_sha256') != hashlib.sha256(artifact.runtime_sv.encode()).hexdigest()
                    or document.get('cpp_sha256') != hashlib.sha256(artifact.cpp_text.encode()).hexdigest()
                    or document.get('kind') != contract[role]['artifact_kind']):
                raise F6ContractRefused('f6-generated-artifact-drift',at)
            require_exact(artifact.plan.document(),document.get('plan'),pointer=at+'/plan')
            require_exact(verified,document.get('source_verification'),pointer=at+'/runtime_document/source_verification')
            if bind_profile(artifact.plan.profile,artifact.plan.facts) != artifact.plan.binding:
                raise F6ContractRefused('f6-physical-binding-drift',at+'/binding')
            if render_local_harness(artifact.plan) != artifact.structural:
                raise F6ContractRefused('f6-structural-artifact-drift',at+'/structural')
            require_exact(artifact.structural.abi_document,document.get('structural_abi'),pointer=at+'/structural_abi')
            require_exact(artifact.structural.build_document,document.get('structural_build'),pointer=at+'/structural_build')
            if role == 'cpu':
                verify_ibex_irq_receipt_artifact(artifact, base_dir=Path(base_dir))
                required = dict(rvfi_valid=1,rvfi_order=64,rvfi_insn=32,rvfi_trap=1,rvfi_mode=2,rvfi_halt=1,
                    rvfi_pc_rdata=32,rvfi_pc_wdata=32,irq_decision_serial=64,irq_retirement_serial=64)
                for port,width in required.items():
                    exports = [r for r in document.get('physical_exports', [])
                        if r.get('physical_port') == port]
                    if (len(exports) != 1 or exports[0].get('direction') != 'output'
                            or type(exports[0].get('width')) is not int or exports[0]['width'] != width
                            or type(exports[0].get('bit_lo')) is not int or exports[0]['bit_lo'] != 0
                            or type(exports[0].get('bit_hi')) is not int or exports[0]['bit_hi'] != width-1):
                        raise F6ContractRefused('f6-native-isr-observation-required',
                            at+'/physical_exports/'+port)
                # Reproduce only the code-owned software projection after the
                # actual source, bound facts and structural object passed above.
                # Self-consistent hashes/exports cannot authenticate swapped wires.
                from .runtime_renderer import _render_admitted_runtime
                from .native_physical_observation import native_physical_observation_requested
                projected = _render_admitted_runtime(artifact.plan, artifact.structural,
                    verified, Path(base_dir).resolve(),
                    native_raw=native_physical_observation_requested(artifact.plan.request))
                if projected.runtime_sv != artifact.runtime_sv:
                    raise F6ContractRefused('f6-runtime-physical-projection-mismatch',
                        at+'/runtime_sv/u_component')
                require_exact(projected.runtime_document['physical_exports'],
                    document.get('physical_exports'),pointer=at+'/physical_exports')
            else:
                verify_wbdmac_source_contract(artifact.plan.profile, base_dir=base_dir)
                require_exact(contract['dma']['master_endpoint_link'], _artifact_link(artifact),
                    pointer=at+'/master_endpoint_link')
                irq_exports = [r for r in document.get('physical_exports', [])
                    if r.get('physical_port') == 'o_interrupt']
                if (len(irq_exports) != 1 or irq_exports[0].get('direction') != 'output'
                        or type(irq_exports[0].get('width')) is not int or irq_exports[0]['width'] != 1
                        or type(irq_exports[0].get('bit_lo')) is not int or irq_exports[0]['bit_lo'] != 0
                        or type(irq_exports[0].get('bit_hi')) is not int or irq_exports[0]['bit_hi'] != 0
                        or irq_exports[0].get('role') != 'irq'
                        or irq_exports[0].get('endpoint_id') != contract['irq']['producer_endpoint_id']):
                    raise F6ContractRefused('f6-native-irq-export-required',at+'/physical_exports')
        result.update(status='supported',execution_contract=deepcopy(contract),
            artifact_digests=deepcopy(admission['artifact_digests']))
    except (ValueError, TypeError, KeyError, AttributeError, OSError) as error:
        result['refusals'].append(dict(code=getattr(error,'code','f6-source-admission-refused'),
            pointer=getattr(error,'pointer','/compiled_inputs'), detail=str(error)))
    return result
