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
