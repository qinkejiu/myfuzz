"""Reuse the native GPIO ISR checker with the shared fixed firmware stages."""
from types import SimpleNamespace


def _gpio_irq_access(runtime, gpio):
    """Resolve the ISR's GPIO route independently of the F4 MMIO target."""
    component = gpio['component']
    declared = [w for w in runtime.compiled_inputs['request'].wiring.windows
                if w.target_instance == component and w.base == gpio['gpio_base']]
    if len(declared) != 1:
        raise ValueError('shared-GPIO-IRQ-declared-route-not-unique')
    window = declared[0]
    cpu = runtime.runner.sessions[runtime.cpu_id]
    target = runtime.runner.sessions[component]
    actual = [w for w in cpu.router.windows if w.device_id == window.device_id
              and w.base == window.base and w.size == window.size and w.target is target]
    if len(actual) != 1:
        raise ValueError('shared-GPIO-IRQ-live-route-mismatch')
    return {'device_id': window.device_id}


def _firmware_view(program):
    document=program.document();dispatch=document['irq_dispatch'];stages=dispatch['stages']
    entry=dispatch['entry_address'];code=program.initial_images[entry]
    path=stages['gpio_dispatch_path']+stages['gpio']['instruction_addresses']
    words={pc:int.from_bytes(code[pc-entry:pc-entry+4],'little') for pc in path}
    child=stages['gpio']['address']
    reads={8:child+28,36:stages['gpio_status_ack']}
    writes={0:child+40,4:stages['gpio_status_store']}
    memory_pcs=[pc for pc in path if words[pc]&127 in (3,35)]
    gpio=document['program_contract'].get('gpio_irq') or {}
    return dict(handler=entry,vector=entry-44,
        segments=[dict(name='handler',address=entry,data_hex=code.hex())],
        retirement_path=[(pc,words[pc]) for pc in path],
        read_retirement_pcs=reads,write_retirement_pcs=writes,
        scratch=gpio.get('scratch_address'),
        transaction_sequence_offsets=[memory_pcs.index(pc) for pc in
            (reads[8],writes[0],reads[36],writes[4])])


def observe_shared_gpio_irq(runtime,receipt,mapping,declaration):
    """Return observations only; original support/admission remains authoritative."""
    from myfuzz.scenario.f6_instruction_fetch_receipt import validate_shared_fixed_support
    from .shared_irq_firmware import observe_irq_isr
    from .compiled_f4 import _cpu_error_policy,_cpu_traces
    unknown=dict(status='unknown',proof_scope='shared_GPIO_native_IRQ_ISR',
        reward_eligible=False,grants_prerequisites=False,certificates=[])
    try:
        fixed=validate_shared_fixed_support(runtime.cpu,case_id=receipt.case_id)
        if (mapping['flow']!='F5' or mapping['case_id']!=receipt.case_id
                or fixed['session_case_index']!=mapping['session_case_index']
                or fixed['slot_index']!=mapping['slot_index']
                or fixed['support_path_id']!=declaration['support_path_id']
                or fixed['support_source_id']!=declaration['support_source_id']):
            raise ValueError('shared-GPIO-current-fixed-support-mismatch')
        path,=[p for p in runtime.compiled_inputs['compiled']['paths']
            if p['flow_id']=='F4' and p['status']=='executable']
        image,=[s for s in path['sources'] if s['kind']=='instruction_image']
        stream,=[s for s in path['sources'] if s['kind']=='cpu_mmio_stream']
        p=runtime.contract['program_contract'];gpio=p['gpio_irq']
        firmware=_firmware_view(runtime.program)
        firmware.update(gpio=dict(base=gpio['gpio_base'],pin=gpio['pin']),
            result=gpio['result_address'],dynamic_start=p['slot_base'])
        facade=SimpleNamespace(_irq_firmware_enabled=True,irq_firmware=firmware,
            artifacts=runtime.artifacts,
            runner=runtime.runner,session=runtime.session,cpu_id=runtime.cpu_id,
            target_id=gpio['component'],image=image,
            result=p['slot_base']+p['slot_bytes']*p['slot_count'],
            access=_gpio_irq_access(runtime,gpio),
            traces=_cpu_traces(runtime.artifacts[runtime.cpu_id],image,stream),
            error_policy=_cpu_error_policy(runtime.artifacts[runtime.cpu_id],image,stream),
            f5_binding=SimpleNamespace(path={'runtime_path_identity':{'path_id':declaration['path_id']}}))
        result=observe_irq_isr(facade,receipt)
        result['proof_scope']=unknown['proof_scope']
        result['fixed_support']=fixed
        return result
    except (ValueError,KeyError,TypeError,AttributeError) as error:
        return dict(unknown,reason=str(error))
