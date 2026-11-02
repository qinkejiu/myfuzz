#!/usr/bin/env python3
"""Assemble the existing F1–F6 GPIO/DMA prototype from adapted profiles.

The GPIO companion, RAM layout and eight records are the existing shared
prototype. CPU boot and DMA endpoints, bus shape and IRQ come from each
component's validated profile; no CPU/DMA pair-specific executor is generated.
This does not infer missing DMA semantics or claim native execution.
"""
import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'src'))

from scripts.profile_scenario_inputs import _member, _request, _component_request, _capability
from scripts.run_shared_all_flows import RECORDS
from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.test_capability import load_ip_test_capability
from myfuzz.local_harness.request import load_local_harness_request
from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
from myfuzz.runtime.generic_campaign import load_descriptor
from myfuzz.scenario.f6_dma_source_provider import select_f6_dma_source_provider

_BASE = 'configs/scenarios/compiled-f1-f6-ibex-gpio-dma-shared'
_GPIO_REQUEST = 'configs/scenarios/compiled-f4-obi-apb-ibex/requests/peripheral.json'
_GPIO_CAPABILITY = 'configs/scenarios/compiled-f4-obi-apb-ibex/test_capability.json'


def _dma_variants(capabilities):
    from myfuzz.local_harness.wishbone_dma_fields import dma_select_modes
    control, master = dma_select_modes(capabilities)
    return tuple('dma-selected' if selected else 'dma-full-word-no-select'
                 for selected in (control, master))


def _declared_irq_shared_slot_plan(cpu_request, behavior_path, program, base, address):
    """Compile a candidate only; the shared executor cannot consume it yet."""
    from scripts.generate_declared_irq_f5_config import generate
    from scripts.run_declared_irq_f5 import trigger_words
    from dataclasses import asdict
    from myfuzz.scenario.irq_delivery_group import IrqDeliveryMember
    behavior = json.loads(_member(base, behavior_path).read_text())
    if type(address) is not int or not 0 <= address < 1 << 32:
        raise ValueError('declared IRQ target base required')
    config = generate(cpu_request.profile_path, behavior, base=base, active_base=address)
    words = trigger_words(config['active_base'], config['trigger_writes'],
                          config['target_window']['size'])
    if len(words) * 4 > 128:
        raise ValueError('declared IRQ trigger exceeds shared slot prefix')
    _, source_request, source_profile = _request(base, config['source_request'])
    member = IrqDeliveryMember(source_component=source_request.instance_id,
        source_port=config['source_port'], mode='pulse',
        pulse_width_ticks=config['pulse_width_ticks'], source_bit_offset=config['source_bit_offset'],
        source_adapter=config['source_adapter'])
    return dict(schema_version='shared_declared_irq_slot_plan.v1',
        runtime_status='not_integrated', scope='planning_only_not_shared_execution',
        source=dict(request=config['source_request'], adapter=config['source_adapter'],
                    port=config['source_port'], bit_offset=config['source_bit_offset'],
                    pulse_width_ticks=config['pulse_width_ticks'],
                    profile_fingerprint=source_profile.profile_fingerprint),
        irq_group_member=asdict(member), target_window=config['target_window'], slot_base=program['slot_base'],
        slot_count=program['slot_count'], trigger_writes=config['trigger_writes'],
        trigger_instruction_hex=b''.join(word.to_bytes(4, 'little') for word in words).hex(),
        status_offsets=config['status_offsets'], status_registers=config['status_registers'],
        clear_writes=config['clear_writes'], status_cause_bits=config['status_cause_bits'],
        internal_cause='unknown', reward_eligible=False,
        remaining=['shared_firmware_and_slot_executor', 'shared_irq_group_and_session',
                   'native_irq_isr_consumption_and_replay'])


def generate_scenario(declaration, *, base_dir, output):
    base = Path(base_dir).resolve()
    out = Path(output).resolve()
    if not out.is_relative_to(base) or out == base or out.exists():
        raise ValueError('output must be a new directory under base_dir')
    cpu_path, cpu_request, cpu, cpu_generated = _component_request(declaration, 'cpu', base, out)
    dma_path, dma_request, dma, dma_generated = _component_request(declaration, 'dma', base, out)
    capability, _, dma_capability_generated = _capability(
        dma, declaration.get('dma_capability'), 'dma', base, out)
    if cpu_request.instance_id != 'cpu' or dma_request.instance_id in {'cpu', 'peripheral'}:
        raise ValueError('shared prototype requires cpu and a distinct DMA instance ID')
    if (cpu.kind != 'cpu' or cpu.cpu is None or cpu.cpu.xlen != 32
            or cpu.cpu.family.lower() != 'riscv' or dma.kind != 'peripheral'):
        raise ValueError('shared prototype requires an RV32 CPU and DMA peripheral')
    custom_bit = declaration.get('custom_irq_bit')
    custom_gpio_bit = declaration.get('custom_gpio_irq_bit')
    if custom_gpio_bit is not None and custom_bit is None:
        raise ValueError('custom GPIO IRQ bit requires custom CPU IRQ')
    if custom_bit is not None:
        from myfuzz.local_harness.profile_custom_irq import verify_custom_irq_source
        verify_custom_irq_source(cpu, base_dir=base)
        if type(custom_bit) is not int or not 3 <= custom_bit < 32:
            raise ValueError('custom IRQ bit must be an external vector bit 3..31')
        if custom_gpio_bit is not None and (type(custom_gpio_bit) is not int
                or not 3 <= custom_gpio_bit < 32 or custom_gpio_bit==custom_bit):
            raise ValueError('custom GPIO IRQ bit must be a distinct external vector bit')
        if 'declared_irq_behavior' in declaration:
            raise ValueError('custom IRQ multiple sources are not integrated')
        data = [e for e in cpu.endpoints if e.function == 'memory_master'
                and e.protocol == ('wishbone', 'classic')]
    else:
        data = [e for e in cpu.endpoints if e.function == 'data_memory_master' and e.protocol == ('obi', '1')]
    if len(data) != 1 or cpu.cpu.irq_entry_endpoint is None:
        raise ValueError('shared prototype requires a supported data endpoint and CPU IRQ entry')
    boot = source_backed_boot_fetch(cpu, base_dir=base, configured_boot_base=cpu.cpu.reset_vector)
    provider = select_f6_dma_source_provider(dma, base_dir=base)
    control_variant, master_variant = _dma_variants(dma.capabilities)
    template_dir = _member(base, _BASE + '/compose.json').parent
    compose = json.loads((template_dir / 'compose.json').read_text())
    supplement = json.loads((template_dir / 'execution_supplement.json').read_text())
    descriptor = json.loads((template_dir / 'generic_scenario.json').read_text())
    compose['cpu'].update(request=os.path.relpath(cpu_path, out), data_endpoint=data[0].endpoint_id)
    device = compose['devices'][0]
    device.update(device_id=dma_request.instance_id, instance_id=dma_request.instance_id,
                  request=os.path.relpath(dma_path, out), bus_endpoint=provider.control_endpoint_id,
                  size=dma.address.window_size)
    device['template']['variant_id'] = control_variant
    compose['devices'][1]['request'] = os.path.relpath(_member(base, _GPIO_REQUEST), out)
    for route in compose['dma_master_routes']['routes']:
        route['initiator_instance'] = dma_request.instance_id
        route['initiator_endpoint_id'] = provider.master_endpoint_id
    for binding in compose['dma_master_route_bindings']:
        binding['initiator_template']['variant_id'] = master_variant
    deliveries = supplement['request_supplements']['deliveries']
    deliveries[0].update(producer_instance=dma_request.instance_id,
                         producer_endpoint_id=provider.irq_endpoint_id,
                         producer_signal=provider.irq_port, trigger=provider.irq_trigger)
    for delivery in deliveries:
        delivery['consumer_endpoint_id'] = cpu.cpu.irq_entry_endpoint
    supplement['request_supplements']['f6_execution']['program']['boot_address'] = boot
    if custom_bit is not None:
        # A unified Wishbone CPU fetches its reset vector through the same RAM
        # object used by DMA. Preserve the old upper bound while including it.
        memory = compose['memory'][0]
        end = memory['base'] + memory['size']
        if boot > memory['base'] or boot % 4 or end <= boot:
            raise ValueError('custom IRQ reset vector outside supported RAM layout')
        memory['base'] = boot
        memory['size'] = end - boot
        for route in compose['dma_master_routes']['routes']:
            route.update(base=memory['base'], size=memory['size'])
        execution = supplement['request_supplements']['f6_execution']
        execution['custom_irq_bit'] = custom_bit
        if custom_gpio_bit is not None:
            execution['gpio_irq']['irq_bit']=custom_gpio_bit
            for delivery in deliveries:
                delivery['consumer_bit_offset'] = (custom_gpio_bit if delivery['producer_instance']=='peripheral' else custom_bit)
            fixed=supplement['request_supplements'].setdefault('fixed_inputs', [])
            for start,end in ((0,custom_gpio_bit),(custom_gpio_bit+1,32)):
                if start<end:
                    fixed.append(dict(component_instance=cpu_request.instance_id,port='irq',
                        bit_offset=start,width=end-start,constant=0))
        else:
            execution.pop('gpio_irq', None)
            execution['shared_slots']['flows'] = [flow for flow in execution['shared_slots']['flows'] if flow != 'F5']
            deliveries[:] = [row for row in deliveries if row['producer_instance'] != 'peripheral']
            supplement['request_supplements']['environment_links'] = [link for link in
                supplement['request_supplements']['environment_links'] if link['component_instance'] != 'peripheral']
            for owner in supplement['ownership']['owners']:
                if owner['component_id'] == 'peripheral' and owner['kind'] == 'source':
                    owner.update(kind='fixed', producer_ref='constant_zero')
            supplement['request_supplements'].setdefault('fixed_inputs', []).append(
                dict(component_instance='peripheral',port='gpio_in',bit_offset=0,width=32,constant=0))
            descriptor['flow_ids'] = [flow for flow in descriptor['flow_ids'] if flow != 'F5']
            descriptor['executors'].pop('F5', None)
            descriptor.pop('f5_records', None)
    irq_plan = None
    if 'declared_irq_behavior' in declaration:
        if (declaration.get('declared_irq_plan_only') is not True
                and type(declaration.get('declared_irq_prepare_only')) is not dict):
            raise ValueError('shared declared IRQ runtime unsupported; request planning or preparation only')
        irq_plan = _declared_irq_shared_slot_plan(cpu_request, declaration['declared_irq_behavior'],
            supplement['request_supplements']['f6_execution']['program'], base,
            declaration.get('declared_irq_base'))
    relative = lambda path: str(path.relative_to(base))
    records = list(RECORDS)
    if custom_bit is not None and custom_gpio_bit is None:
        records = [row for row in records if not row.startswith('F5:')]
    capabilities = [relative(capability), _GPIO_CAPABILITY]
    target = declaration.get('target')
    generated_target_request = None
    target_capability_generated = None
    if target is not None:
        if ('request' in target) == ('profile' in target):
            raise ValueError('target requires exactly one of request or profile')
        if 'request' in target:
            target_path, target_request, target_profile = _request(base, target['request'])
        else:
            profile_path = _member(base, target['profile'])
            target_profile = load_component_profile(profile_path)
            endpoints = [e for e in target_profile.endpoints if e.function == 'mmio_slave'
                         and e.protocol == ('apb', '3')]
            if len(endpoints) != 1:
                raise ValueError('target requires one APB endpoint')
            generated_target_request = dict(schema_version='local_harness.v2',
                profile_path=relative(profile_path), instance_id='target', reset_assert_ticks=2,
                reset_release_ticks=3, max_wait_cycles=target_profile.capabilities.get('max_wait_cycles', 16),
                tuning={'endpoint_policies': [dict(endpoint_id=endpoints[0].endpoint_id,
                    template_id='target.apb3', template_version='1', variant_id='full-word', max_outstanding=1)]})
            target_request = load_local_harness_request(generated_target_request)
            target_path = out / 'target_request.json'
        target_capability, target_semantics, target_capability_generated = _capability(
            target_profile, target.get('capability'), 'target', base, out)
        if target_profile.kind != 'peripheral' or target_request.instance_id in {'cpu',dma_request.instance_id,'peripheral'}:
            raise ValueError('target requires a distinct peripheral instance')
        rows = [r.document() for r in target_request.tuning.records
                if r.kind == 'apb_storage_observations']
        if len(rows) > 1:
            raise ValueError('target requires at most one APB storage observation')
        if rows:
            selection = rows[0]
        else:
            endpoints = [e for e in target_profile.endpoints if e.function == 'mmio_slave'
                         and e.protocol == ('apb', '3')]
            semantics = [r for r in target_semantics.register_semantics
                         if r.width == 32 and r.lsb == 0 and r.access == 'rw'
                         and r.side_effect == 'none' and r.read_mask and r.write_mask
                         and (r.write_mask == 0xffffffff or r.write_policy == 'full_word_reserved_zero')]
            selected = target.get('register')
            if selected is not None:
                semantics = [r for r in semantics if r.register == selected]
            if len(endpoints) != 1 or len(semantics) != 1:
                raise ValueError('target requires one APB endpoint and one selected read/write register')
            selection = dict(endpoint_id=endpoints[0].endpoint_id,
                register=semantics[0].register, contract_id='apb3.mmio.bus.v1')
        endpoints = [e for e in target_profile.endpoints if e.endpoint_id == selection['endpoint_id']
                     and e.function == 'mmio_slave' and e.protocol == ('apb', '3')]
        registers = [r for r in target_profile.address.registers if r.name == selection['register']]
        semantics = [r for r in target_semantics.register_semantics if r.register == selection['register']]
        if (len(endpoints) != 1 or len(registers) != 1 or len(semantics) != 1
                or registers[0].width != 32 or registers[0].access != 'rw'
                or semantics[0].width != 32 or semantics[0].lsb != 0
                or semantics[0].access != 'rw' or semantics[0].side_effect != 'none'
                or not semantics[0].read_mask or not semantics[0].write_mask
                or (semantics[0].write_mask != 0xffffffff
                    and semantics[0].write_policy != 'full_word_reserved_zero')):
            raise ValueError('target requires one declared word read/write register')
        address = target['base']
        values = target['write_values']
        size = target_profile.address.window_size
        if (type(address) is not int or address < 0 or address % target_profile.address.alignment
                or address + size > 1 << 32 or type(values) is not list or len(values) < 1
                or any(type(value) is not int or not 0 <= value <= 0xffffffff
                       or value & ~semantics[0].write_mask for value in values)):
            raise ValueError('invalid target address or write values')
        # Order the requested MMIO target before the GPIO IRQ companion; the
        # shared compiler uses this declared window for both F2 and F4.
        compose['devices'].insert(1, dict(device_id=target_request.instance_id,
            instance_id=target_request.instance_id,request=os.path.relpath(target_path,out),
            bus_endpoint=selection['endpoint_id'],base=address,size=size))
        capabilities.insert(1, relative(target_capability))
        slots = supplement['request_supplements']['f6_execution']['shared_slots']
        slots.update(component=target_request.instance_id, contract_id=selection['contract_id'],
                     register=selection['register'], read_register=selection['register'])
        if not rows:
            slots['observation_mode'] = 'bus'
        f2 = (address+registers[0].offset).to_bytes(4,'little').hex()
        writes = [value.to_bytes(4,'little').hex() for value in values]
        descriptor['f2_records'] = [f2]
        descriptor['f4_records'] = writes
        records = [('F2:'+f2 if record.startswith('F2:') else
                    'F4:'+writes[0] if record.startswith('F4:') else record) for record in records]
    if irq_plan is not None and type(declaration.get('declared_irq_prepare_only')) is dict:
        irq_path, irq_request, irq_profile = _request(base, irq_plan['source']['request'])
        used = {cpu_request.instance_id, *(d['instance_id'] for d in compose['devices'])}
        if irq_request.instance_id in used:
            raise ValueError('declared IRQ instance collides with an existing component')
        irq_capability = _member(base, declaration['declared_irq_capability'])
        load_ip_test_capability(irq_capability, profile=irq_profile)
        bus = [e for e in irq_profile.endpoints if e.function == 'mmio_slave' and e.protocol == ('apb', '3')]
        irq = [e for e in irq_profile.endpoints if e.function == 'interrupt_source'
               and any(irq_plan['source']['port'] in f.aliases for f in e.fields)]
        if len(bus) != 1 or len(irq) != 1:
            raise ValueError('declared IRQ requires unique APB and interrupt endpoints')
        compose['devices'].append(dict(device_id=irq_request.instance_id, instance_id=irq_request.instance_id,
            request=os.path.relpath(irq_path, out), bus_endpoint=bus[0].endpoint_id,
            base=irq_plan['target_window']['base'], size=irq_plan['target_window']['size']))
        deliveries.append(dict(delivery_id='declared_irq', producer_instance=irq_request.instance_id,
            producer_endpoint_id=irq[0].endpoint_id, producer_signal=irq_plan['source']['port'],
            consumer_instance=cpu_request.instance_id, consumer_endpoint_id=cpu.cpu.irq_entry_endpoint,
            trigger='pulse'))
        capabilities.append(relative(irq_capability))
        marker = dict(declaration['declared_irq_prepare_only'])
        marker.update(component=irq_request.instance_id, behavior=declaration['declared_irq_behavior'],
                      cpu_profile=cpu_request.profile_path, base=irq_plan['target_window']['base'])
        supplement['request_supplements']['f6_execution']['declared_irq'] = marker
        # This F5 uses CPU-written trigger instructions, so the old GPIO pin
        # is no longer a fuzz source. Keep the real companion quiescent.
        supplement['request_supplements']['f6_execution'].pop('gpio_irq', None)
        # GPIO remains available for MMIO, but is not a member of the new
        # declared-output IRQ group; remove its obsolete delivery as well.
        deliveries[:] = [row for row in deliveries if row['producer_instance'] != 'peripheral']
        supplement['request_supplements']['environment_links'] = [
            link for link in supplement['request_supplements']['environment_links']
            if link['component_instance'] != 'peripheral']
        for owner in supplement['ownership']['owners']:
            if owner['component_id'] == 'peripheral' and owner['kind'] == 'source':
                owner.update(kind='fixed', producer_ref='constant_zero')
        supplement['request_supplements'].setdefault('fixed_inputs', []).append(
            dict(component_instance='peripheral',port='gpio_in',bit_offset=0,width=32,constant=0))
        # The combined dispatcher and target ISR may extend past the legacy
        # park location. Keep the pending park fetch immediately before the
        # slot arena; normal F6 span checks reject any remaining collision.
        program = supplement['request_supplements']['f6_execution']['program']
        if type(program['slot_base']) is not int or program['slot_base'] < 4:
            raise ValueError('declared IRQ requires space before the slot arena')
        program['park_address'] = program['slot_base'] - 4
    descriptor.update(scenario_id=declaration['name'], root='.',
        compose=relative(out / 'compose.json'),
        supplement=relative(out / 'execution_supplement.json'),
        capability=capabilities)
    search = {'schema_version': 'dependency_search_scenario.v1',
              'name': declaration['name']+'-search', 'backend': 'descriptor',
              'descriptor': relative(out / 'generic_scenario.json'), 'flow': 'mixed',
              'records': records,
              'goal': {'id': 'shared-six-flow-execution',
                       'description': 'Explore declared shared CPU, RAM, target, IRQ and DMA flows.'}}
    out.mkdir(parents=True)
    for name, generated in (('cpu', cpu_generated), ('dma', dma_generated)):
        if generated is not None:
            (out / (name + '_request.json')).write_text(json.dumps(generated, indent=2) + '\n')
    for name, generated in (('dma', dma_capability_generated), ('target', target_capability_generated)):
        if generated is not None:
            (out / (name + '_test_capability.json')).write_text(json.dumps(generated, indent=2) + '\n')
    if generated_target_request is not None:
        (out / 'target_request.json').write_text(json.dumps(generated_target_request, indent=2) + '\n')
    if irq_plan is not None:
        (out / 'declared_irq_shared_slot_plan.json').write_text(json.dumps(irq_plan, indent=2) + '\n')
    for name, value in (('compose.json', compose), ('execution_supplement.json', supplement),
                        ('generic_scenario.json', descriptor), ('acceptance_sequence.json', records),
                        ('search_scenario.json', search)):
        (out / name).write_text(json.dumps(value, indent=2) + '\n')
    result = out / 'generic_scenario.json'
    load_descriptor(result, base_dir=base)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--base-dir', type=Path, default=ROOT)
    args = parser.parse_args(argv)
    try:
        result = generate_scenario(json.loads(args.config.read_text()), base_dir=args.base_dir, output=args.output)
    except (KeyError, TypeError, ValueError, OSError) as error:
        parser.exit(1, f'{error}\n')
    print(result)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
