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
                             physical_observations=False):
    """Validate and return supplied objects; never regenerate default artifacts.

    expected maps topology instances to (declared profile path, session kind).
    Selection follows explicit declarations and fingerprints, never names that
    merely resemble the configured component.
    """
    if not isinstance(artifacts, Mapping) or set(artifacts) != set(expected):
        raise GeneratedExecutionRefused('generated-runtime-instance-set-mismatch', '/artifacts')
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
        if observed != physical_observations:
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
        {'admission': admission,
         'missing': ['compiled bound-producer delivery mapping',
                     'compiled source/seed to online decoder mapping',
                     'compiled assertions to actual checker mapping'],
         'runtime_started': False})
