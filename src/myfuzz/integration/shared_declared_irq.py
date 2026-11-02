"""Attach an explicitly planned output to an actual shared IRQ group.

This only binds existing CPU and target sessions. It does not install the
group, generate an ISR, or establish that either source was consumed.
"""
from dataclasses import replace

from myfuzz.scenario.irq_delivery_group import IrqDeliveryMember, verify_group_sessions


def compile_declared_irq_slot(contract, slot_index):
    """Compile phase selection and the real declared MMIO trigger into one slot."""
    from hashlib import sha256
    from .rv32_fixed_firmware import _addi, _lui_addi_load, _sw
    if (type(contract) is not dict or contract.get('schema_version') != 'shared_declared_irq_contract.v1'
            or type(slot_index) is not int or not 0 <= slot_index < contract['slot_count']):
        raise ValueError('shared-declared-IRQ-slot-contract-required')
    phase = contract['phase_address']
    words = [*_lui_addi_load(6, phase), *_lui_addi_load(7, 1), _sw(7, 6, 0)]
    code = b''.join(word.to_bytes(4, 'little') for word in words)
    code += bytes.fromhex(contract['trigger_instruction_hex'])
    code += b''.join(word.to_bytes(4, 'little') for word in (_addi(10, 0, 1), _addi(11, 0, 1)))
    if len(code) > 128 or len(code) % 4:
        raise ValueError('shared-declared-IRQ-slot-prefix-overflow')
    code += b'\x13\x00\x00\x00' * ((128 - len(code)) // 4)
    return dict(schema_version='shared_declared_irq_slot.v1',
        address=contract['slot_base'] + 256 * slot_index, code_hex=code.hex(),
        code_sha256=sha256(code).hexdigest(), phase_value=1,
        source_origin='unknown', reward_eligible=False)


def compile_declared_irq(request, declaration, program, *, base_dir):
    """Compile declared trigger and source against this composition's wiring.

    The result is configuration authority only; IRQ source and consumption
    still require the live group and native event joins.
    """
    from pathlib import Path
    from types import SimpleNamespace
    from myfuzz.composition.component_profile import load_component_profile
    from scripts.generate_shared_dma_scenario import _declared_irq_shared_slot_plan
    keys = {'component', 'behavior', 'cpu_profile', 'base', 'phase_address',
            'scratch_address', 'result_address', 'dma_handler_address',
            'target_handler_address', 'group_id'}
    if type(declaration) is not dict or set(declaration) != keys:
        raise ValueError('shared-declared-IRQ-fields-invalid')
    root = Path(base_dir).resolve()
    cpu_path = (root / declaration['cpu_profile']).resolve()
    if not cpu_path.is_relative_to(root) or load_component_profile(cpu_path) != request.cpu.profile:
        raise ValueError('shared-declared-IRQ-cpu-profile-mismatch')
    plan = _declared_irq_shared_slot_plan(SimpleNamespace(profile_path=declaration['cpu_profile']),
        declaration['behavior'], program, root, declaration['base'])
    target = request.device(declaration['component'])
    if (target is None or target.profile.profile_fingerprint != plan['source']['profile_fingerprint']
            or plan['irq_group_member']['source_component'] != declaration['component']):
        raise ValueError('shared-declared-IRQ-target-profile-mismatch')
    windows = [w for w in request.wiring.windows if w.target_instance == target.instance_id]
    if len(windows) != 1 or (windows[0].base, windows[0].size) != (
            plan['target_window']['base'], plan['target_window']['size']):
        raise ValueError('shared-declared-IRQ-target-window-mismatch')
    deliveries = [d for d in request.wiring.deliveries
                  if d.producer_instance == target.instance_id and d.consumer_instance == request.cpu.instance_id]
    if len(deliveries) != 1 or deliveries[0].trigger != 'pulse':
        raise ValueError('shared-declared-IRQ-delivery-required')
    for key in ('phase_address', 'scratch_address', 'result_address',
                'dma_handler_address', 'target_handler_address'):
        value = declaration[key]
        if type(value) is not int or not 0 <= value <= 0xffffff00 or value % 4:
            raise ValueError('shared-declared-IRQ-address-invalid:' + key)
    if type(declaration['group_id']) is not str or not declaration['group_id'].strip():
        raise ValueError('shared-declared-IRQ-group-id-required')
    return {**plan, **declaration, 'schema_version': 'shared_declared_irq_contract.v1'}


def bind_declared_irq_group(group, plan, sessions):
    if (type(plan) is not dict or plan.get('schema_version') not in (
            'shared_declared_irq_slot_plan.v1', 'shared_declared_irq_contract.v1')
            or plan.get('runtime_status') != 'not_integrated'):
        raise ValueError('declared IRQ shared plan required')
    member = IrqDeliveryMember(**plan['irq_group_member'])
    target = sessions.get(member.source_component)
    artifact = getattr(target, 'artifact', None)
    profile = getattr(getattr(artifact, 'plan', None), 'profile', None)
    request = getattr(getattr(artifact, 'plan', None), 'request', None)
    if (profile is None or request is None or request.instance_id != member.source_component
            or profile.profile_fingerprint != plan['source']['profile_fingerprint']):
        raise ValueError('declared IRQ target profile or instance mismatch')
    bound = replace(group, members=(*group.members, member))
    mappings = verify_group_sessions(bound, sessions)
    return bound, mappings


def submit_declared_irq(runtime, raw, mapping, declaration):
    """Run a typed CPU trigger and require actual IRQ/ISR consumption evidence."""
    from copy import deepcopy
    from .shared_slot_consumers import declare_slot
    from .shared_f6_slots import execute_fragment, seal_case
    from .compiled_f4 import _borrow_exact_events, _cpu_error_policy, _cpu_traces
    from .declared_irq_consumption import observe_declared_irq_consumption
    from .shared_f6_assembly import shared_irq_group
    if mapping['flow'] != 'F5' or declaration != declare_slot(runtime.compiled_inputs,
            runtime.contract['program_contract']['shared_slots'], runtime.runtime_path_admission,
            flow='F5', raw=raw, slot_index=mapping['slot_index'],
            instruction_isa=getattr(runtime.memory, 'instruction_isa', None)):
        raise ValueError('shared-declared-IRQ-slot-declaration-mismatch')
    plan = runtime.contract['program_contract']['declared_irq']
    timer = runtime.runner.sessions[plan['component']]
    windows = [w for w in runtime.cpu.router.windows if w.target is timer
               and w.device_id == plan['component'] and w.base == plan['base']]
    if len(windows) != 1 or windows[0].size != plan['target_window']['size']:
        raise ValueError('shared-declared-IRQ-live-target-route-mismatch')
    dispatch = runtime.program.document().get('irq_dispatch') or {}
    firmware = dispatch.get('declared_firmware')
    if not isinstance(firmware, dict):
        raise ValueError('shared-declared-IRQ-handler-evidence-unavailable')
    path, = [p for p in runtime.compiled_inputs['compiled']['paths'] if p['flow_id'] == 'F5']
    image, = [s for s in path['sources'] if s['kind'] == 'instruction_image']
    stream = {'register_access': {'source_endpoint': runtime.contract['cpu']['data_endpoint_id']}}
    traces = _cpu_traces(runtime.cpu.artifact, image, stream)
    error_policy = _cpu_error_policy(runtime.cpu.artifact, image, stream)
    receipt, address, action, boundary = execute_fragment(runtime, mapping, declaration)
    observed = observe_declared_irq_consumption(events=_borrow_exact_events(runtime.runner),
        receipt=receipt, traces=traces, error_policy=error_policy, cpu_id=runtime.cpu_id,
        target_id=plan['component'], access=dict(device_id=plan['component'],
            target_component=plan['component'], window_base=plan['base'],
            window_size=plan['target_window']['size'], offset=plan['status_offsets'][0]),
        firmware=firmware, group=shared_irq_group(runtime.contract, runtime.artifacts,
            base_dir=runtime.base_dir),
        target_trace=timer.artifact.runtime_document['base_protocol_trace'],
        successor_range=(runtime.contract['memory']['resource']['base'],
                         runtime.contract['memory']['resource']['base'] + runtime.contract['memory']['resource']['size']),
        reset_epoch=timer.reset_epoch,
        cpu_contract=runtime.contract['irq']['native_take_provider'])
    if observed.get('status') != 'verified':
        detail = observed.get('refusals') or observed.get('consumption', {}).get('reason')
        raise ValueError('shared-declared-IRQ-actual-consumption-unverified:' + str(detail))
    certificate = dict(schema_version='compiled_shared_declared_F5_slot_case.v1', flow_id='F5',
        status='certified', case_id=mapping['case_id'], runtime_path_id=mapping['path_id']
        if 'path_id' in mapping else runtime.runtime_path_admission['shared_flow_paths']['F5']['path_id'],
        execution_binding_sha256=runtime.execution_binding_sha256, instruction_address=address,
        instruction_action=action, observation=observed, next_fetch=boundary,
        internal_cause='unknown', cross_case_origin='unknown', reward_eligible=False)
    seal_case(runtime, mapping['case_id'], certificate, boundary)
    runtime._drain_observer_view()
    return deepcopy(certificate)
