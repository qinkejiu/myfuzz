"""Full pinned source facts and ownership for one local component."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from myfuzz.composition.component_profile import (
    ComponentProfile, PhysicalFacts, ProfileBinding, bind_profile,
    elaborate_profile, load_component_profile,
)
from myfuzz.composition.interface_description import SourceLocator
from myfuzz.composition.soc_port_dispositions import (
    DispositionEntry, build_port_dispositions,
)
from .request import LocalHarnessRequest, LocalHarnessRequestV2, load_local_harness_request


def _local_target(entry: DispositionEntry) -> str | None:
    target = entry.target
    targets = {
        'clock_reset': 'local_clock_reset',
        'processor_adapter': 'local_protocol',
        'fabric_target': 'local_protocol',
        'interrupt_controller': 'local_interrupt',
        'const': 'constant',
    }
    if target in targets:
        return targets[target]
    if target == 'soc_top':
        if entry.disposition in ('external', 'fuzz'):
            return 'environment_pin'
        if entry.disposition == 'observe':
            return 'observation'
    if isinstance(target, str) and target.startswith('peer:') and target[5:]:
        return 'local_peer:' + target[5:]
    if target is None and entry.disposition == 'unconnected' and entry.direction == 'output':
        return None
    raise ValueError(f'unsupported-local-target:{entry.port}:{target}')


@dataclass(frozen=True, slots=True)
class LocalHarnessPlan:
    request: LocalHarnessRequest | LocalHarnessRequestV2
    profile: ComponentProfile
    facts: PhysicalFacts
    binding: ProfileBinding
    dispositions: tuple[DispositionEntry, ...]
    profile_sha256: str
    elaborated_source: SourceLocator
    parameter_sources: tuple[tuple[str, str], ...] = ()

    def document(self) -> dict[str, object]:
        ports = []
        for entry in sorted(self.dispositions, key=lambda item: (item.port, item.bit_lo)):
            row = entry.document()
            row['target'] = _local_target(entry)
            ports.append(row)
        document = {
            'schema_version': 'local_harness_plan.v1',
            'scope': 'single_component',
            'component_id': self.profile.component_id,
            'instance_id': self.request.instance_id,
            'profile_path': self.request.profile_path,
            'profile_sha256': self.profile_sha256,
            'source_revision': self.facts.revision,
            'source_content_hash': self.facts.content_hash,
            'source_files': list(self.facts.files),
            'top': self.facts.top_module,
            'parameter_source_sha256': {name: hashlib.sha256(text.encode()).hexdigest()
                                        for name, text in self.parameter_sources},
            'timing': {
                'reset_assert_ticks': self.request.reset_assert_ticks,
                'reset_release_ticks': self.request.reset_release_ticks,
                'max_wait_cycles': self.request.max_wait_cycles,
            },
            'protocol_endpoint_ids': sorted(
                endpoint.endpoint_id for endpoint in self.binding.endpoints
                if endpoint.protocol is not None),
            'ports': ports,
        }
        if isinstance(self.request, LocalHarnessRequestV2):
            document['request_schema_version'] = 'local_harness.v2'
            document['tuning'] = self.request.tuning.document()
            document['tuning_sha256'] = self.request.tuning.identity_sha256
        return document


def plan_local_harness(request: LocalHarnessRequest | LocalHarnessRequestV2, *, base_dir: Path) -> LocalHarnessPlan:
    if not isinstance(request, (LocalHarnessRequest, LocalHarnessRequestV2)):
        raise ValueError('local-harness-request-required')
    if isinstance(request, LocalHarnessRequestV2) and not request.tuning.records:
        raise ValueError('local-harness-request-required')
    # Revalidate direct dataclass construction as well as parsed requests.
    load_local_harness_request(request.document())
    root = Path(base_dir).resolve()
    configs = root / 'configs'
    profile_path = (root / request.profile_path).resolve()
    if not profile_path.is_relative_to(configs):
        raise ValueError('invalid-profile-path:outside-configs')
    profile_bytes = profile_path.read_bytes()
    profile = load_component_profile(json.loads(profile_bytes))
    parameter_sources = ()
    if (profile.source.filelist is None and profile.source.elaboration is not None
            and profile.source.elaboration.parameters):
        source_root = (root / profile.source.source_root).resolve()
        if not source_root.is_relative_to(root):
            raise ValueError('parameter-source-outside-root')
        snapshots = []
        for name in profile.source.files:
            path = (source_root / name).resolve()
            if not path.is_relative_to(source_root):
                raise ValueError('parameter-source-outside-root')
            snapshots.append((name, path.read_bytes().decode('utf-8')))
        parameter_sources = tuple(snapshots)
    facts = elaborate_profile(profile, base_dir=root)
    for name, text in parameter_sources:
        if (source_root / name).read_bytes().decode('utf-8') != text:
            raise ValueError('parameter-source-changed-during-elaboration')
    if facts.selection != 'all':
        raise ValueError('full-top-required')
    binding = bind_profile(profile, facts)
    dispositions = build_port_dispositions(
        request.instance_id, binding, clock_domain='local_clock',
        reset_domain='local_reset', profile_port_actions=profile.port_actions,
    )
    for entry in dispositions:
        _local_target(entry)
    plan = LocalHarnessPlan(
        request, profile, facts, binding, dispositions,
        hashlib.sha256(profile_bytes).hexdigest(), profile.source, parameter_sources)
    if isinstance(request, LocalHarnessRequestV2):
        protocols = {endpoint.protocol for endpoint in binding.endpoints
                     if endpoint.protocol is not None}
        if protocols == {('tl-ul', '1')}:
            from .tlul_register_template import register_observe_policy
        elif protocols == {('apb', '3')}:
            from .apb3_register_template import register_observe_policy
        else:
            raise ValueError('v2-register-template-protocol-unsupported')
        register_observe_policy(plan)
    return plan
