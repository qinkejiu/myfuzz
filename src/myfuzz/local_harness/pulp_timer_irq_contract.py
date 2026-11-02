"""Source-backed PULP Timer pulse declaration, independent of its CPU peer.

These facts identify a native output and a legal APB trigger. They confer no
CPU delivery, acceptance, serial, retirement or storage-version authority.
"""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path

from myfuzz.composition.component_profile import load_component_profile
from .execution_validation import static_validation

_PROFILE = 'configs/peripherals/pulp_timer_irq/component_profile.json'
_PROFILE_SHA256 = '4890d71cc523a0d41f340b2c42ceae002ad9a04219089313b4ab7b23042b755a'
_SOURCES = {
    'third_party/soc-pulp-apb-timer/src/timer.sv': 'd352fc4476da83658d361e8f500b5a73f857f0a11e9436ab47d5bf0ba0bc7fce',
    'third_party/soc-pulp-apb-timer/src/apb_timer.sv': '22dce4e3ff8328bdd6e1621c20e2877e7f44cfecccc07203d09e994632cc1778',
}


def _source_profile(root):
    for relative, expected in {_PROFILE: _PROFILE_SHA256, **_SOURCES}.items():
        path = root / relative
        if path.is_symlink() or not path.is_file() or sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('timer-irq-source-changed:' + relative)
    return load_component_profile(json.loads((root / _PROFILE).read_text()))


def timer_irq_source_contract(profile, *, base_dir):
    root = Path(base_dir).resolve()
    registered = static_validation(('pulp-timer-irq-source', root), lambda: _source_profile(root))
    if profile != registered:
        raise ValueError('timer-irq-unregistered-profile')
    return dict(schema_version='pulp_timer.native-pulses.v1',
        profile_sha256=_PROFILE_SHA256, source_sha256=deepcopy(_SOURCES),
        endpoint_id='timer.interrupts', native_port='irq_o', width=4,
        channels=('timer0_overflow', 'timer0_compare', 'timer1_overflow', 'timer1_compare'),
        native_trigger='equality_at_prescaler_point', native_pulse_width_cycles=1,
        selected_bit=0, selected_channel='timer0_overflow',
        # Disable counting and comparison, then write the actual overflow value.
        # The output is observed from RTL, never synthesized from these writes.
        trigger_writes=((4, 0), (8, 0), (0, 0xFFFFFFFF)),
        clear='automatic_counter_reset_next_source_edge',
        delivery='unknown', acceptance='unknown', serial='unknown', isr_mmio='unknown',
        reward_eligible=False)


def timer_irq_runtime_mapping(session):
    """Bind the registered Timer source to the original generic APB sampler."""
    from .apb3_register_session import GeneratedApb3RegisterSession
    if type(session) is not GeneratedApb3RegisterSession:
        raise ValueError('timer-irq-actual-generic-apb-session-required')
    for name, (method, code) in _APB_SAMPLE_METHODS.items():
        if (name in vars(session) or getattr(GeneratedApb3RegisterSession, name) is not method
                or method.__code__ is not code):
            raise ValueError('timer-irq-original-apb-sampler-required')
    artifact = session.artifact
    facts = timer_irq_source_contract(artifact.plan.profile, base_dir=session.base_dir)
    document = artifact.runtime_document
    if document.get('kind') != 'apb3_register_observe' or session._artifact_document != document:
        raise ValueError('timer-irq-native-artifact-mismatch')
    exports = [row for row in document['physical_exports']
        if (row.get('endpoint_id'), row.get('role'), row.get('direction'),
            row.get('physical_port'), row.get('width'), row.get('bit_lo'), row.get('bit_hi'))
        == (facts['endpoint_id'], 'irq', 'output', facts['native_port'], 4, 0, 3)]
    if len(exports) != 1:
        raise ValueError('timer-irq-native-vector-export-required')
    export = exports[0]
    names = ('endpoint_id', 'role', 'direction', 'physical_port', 'width', 'bit_lo', 'bit_hi')
    if (sum(all(row.get(k) == export.get(k) for k in names)
            for row in artifact.structural.abi_document['ports']) != 1
            or session._outputs.get('irq_o') != (export['runtime_name'], 4)):
        raise ValueError('timer-irq-native-vector-projection-mismatch')
    return dict(adapter_id='pulp_timer.apb-native-pulses.v1', physical_port='irq_o',
                runtime_name=export['runtime_name'], source_width=4)


from .apb3_register_session import GeneratedApb3RegisterSession as _APB
_APB_SAMPLE_METHODS = {name: (getattr(_APB, name), getattr(_APB, name).__code__)
    for name in ('_take', '_take_impl', 'step_local', 'drain_tick_samples')}
