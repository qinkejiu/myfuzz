"""Full pinned source facts and ownership for one local component."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from myfuzz.composition.component_profile import (
    ComponentProfile, PhysicalFacts, ProfileBinding, bind_profile,
    elaborate_profile, load_component_profile,
)
from myfuzz.composition.soc_port_dispositions import (
    DispositionEntry, build_port_dispositions,
)
from .request import LocalHarnessRequest, load_local_harness_request


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
    request: LocalHarnessRequest
    profile: ComponentProfile
    facts: PhysicalFacts
    binding: ProfileBinding
    dispositions: tuple[DispositionEntry, ...]

    def document(self) -> dict[str, object]:
        ports = []
        for entry in sorted(self.dispositions, key=lambda item: (item.port, item.bit_lo)):
            row = entry.document()
            row['target'] = _local_target(entry)
            ports.append(row)
        return {
            'schema_version': 'local_harness_plan.v1',
            'scope': 'single_component',
            'component_id': self.profile.component_id,
            'instance_id': self.request.instance_id,
            'profile_path': self.request.profile_path,
            'source_revision': self.facts.revision,
            'source_content_hash': self.facts.content_hash,
            'source_files': list(self.facts.files),
            'top': self.facts.top_module,
            'timing': {
                'reset_assert_ticks': self.request.reset_assert_ticks,
                'reset_release_ticks': self.request.reset_release_ticks,
                'max_wait_cycles': self.request.max_wait_cycles,
            },
            'protocol_endpoint_ids': sorted(endpoint.endpoint_id for endpoint in self.binding.endpoints),
            'ports': ports,
        }


def plan_local_harness(request: LocalHarnessRequest, *, base_dir: Path) -> LocalHarnessPlan:
    if not isinstance(request, LocalHarnessRequest):
        raise ValueError('local-harness-request-required')
    # Revalidate direct dataclass construction as well as parsed requests.
    load_local_harness_request(request.document())
    root = Path(base_dir).resolve()
    configs = root / 'configs'
    profile_path = (root / request.profile_path).resolve()
    if not profile_path.is_relative_to(configs):
        raise ValueError('invalid-profile-path:outside-configs')
    profile = load_component_profile(profile_path)
    facts = elaborate_profile(profile, base_dir=root)
    if facts.selection != 'all':
        raise ValueError('full-top-required')
    binding = bind_profile(profile, facts)
    dispositions = build_port_dispositions(
        request.instance_id, binding, clock_domain='local_clock',
        reset_domain='local_reset', profile_port_actions=profile.port_actions,
    )
    for entry in dispositions:
        _local_target(entry)
    return LocalHarnessPlan(request, profile, facts, binding, dispositions)
