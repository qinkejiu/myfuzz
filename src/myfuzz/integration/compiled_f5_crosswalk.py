"""Closed PULP/Ibex F5 physical-to-runtime topology crosswalk.

This checks declarations and the runner that will be started. It does not
assert that an interrupt was delivered, accepted, or serviced by the CPU.
"""
from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy

from myfuzz.local_harness.compiled_artifact_admission import admit_compiled_artifacts
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.local_harness.generated_execution_admission import select_factory_artifacts
from myfuzz.local_harness.session import GeneratedLocalSession
from myfuzz.scenario.compiled_paths import compiled_document_sha256
from myfuzz.scenario.ibex_pulp_dual_source import (
    ROOT, CPU_PROFILE, CAUSAL_GPIO_PROFILE, dual_source_ownership,
)
from myfuzz.scenario.irq import IrqPulseDelivery
from myfuzz.scenario.runner import Binding, ScenarioRunner


def _require(condition, reason):
    if not condition:
        raise ValueError('compiled-f5-crosswalk-' + reason)


def _one(rows, reason):
    _require(len(rows) == 1, reason)
    return rows[0]


def _physical(artifact, *, port, endpoint, role, direction, bit, width):
    def candidates(rows):
        return [r for r in rows if type(r) is dict and r.get('physical_port') == port
                and r.get('endpoint_id') == endpoint and r.get('role') == role
                and r.get('direction') == direction and type(r.get('bit_lo')) is int
                and type(r.get('bit_hi')) is int and type(r.get('width')) is int
                and r['width'] == r['bit_hi'] - r['bit_lo'] + 1
                and r['bit_lo'] <= bit and bit + width - 1 <= r['bit_hi']]
    abi = _one(candidates(artifact.structural.abi_document['ports']), 'physical-abi')
    export = _one(candidates(artifact.runtime_document['physical_exports']), 'physical-export')
    _require(all(abi.get(k) == export.get(k) for k in
                 ('bit_lo','bit_hi','width','direction','role','endpoint_id'))
             and type(export.get('runtime_name')) is str and bool(export['runtime_name']),
             'physical-export-mismatch')
    return export['runtime_name']


def validate_live_f5_crosswalk(*, preparation, runner, path, binding,
                               pulse_width_ticks):
    """Check an F5 path against live prepared artifacts and actual wiring.

    ``binding`` and pulse width are the component adapter's declared runtime
    mapping; they are compared with actual Runner objects, never installed.
    This function grants no source authority and produces no consumption fact.
    """
    from myfuzz.runtime.preparation import PreparationContext
    _require(type(preparation) is PreparationContext, 'live-preparation-required')
    preparation.assert_current()
    artifacts = preparation.artifacts
    for artifact in artifacts.values():
        preparation.assert_artifact_current(artifact)
    inputs = preparation.compiled_inputs()
    return _validate_f5_topology(compiled_inputs=inputs, artifacts=artifacts,
        runner=runner, path=path, binding=binding, pulse_width_ticks=pulse_width_ticks)


def _validate_f5_topology(*, compiled_inputs, artifacts, runner, path, binding,
                          pulse_width_ticks):
    request, compiled = compiled_inputs['request'], compiled_inputs['compiled']
    _require(type(path) is dict and path.get('flow_id') == 'F5'
             and path.get('status') == 'executable'
             and sum(row == path for row in compiled['paths']) == 1, 'selected-path')
    _require(type(runner) is ScenarioRunner and set(runner.sessions) == set(artifacts), 'runner')
    for name, artifact in artifacts.items():
        session = runner.sessions[name]
        _require(isinstance(session, GeneratedLocalSession) and session.artifact is artifact
                 and session._artifact_document == artifact.runtime_document, 'runner-artifact')
    admission = admit_compiled_artifacts(artifacts=artifacts, **compiled_inputs, flow_ids=('F5',))
    _require(admission['status'] == 'compatible', 'compiled-admission')
    source = _one([s for s in path['sources'] if s['kind'] == 'external_pin'], 'source')
    producer = _one([s for s in path['bound_inputs'] if s['kind'] == 'ip_irq'], 'producer')
    target = _one([s for s in path['bound_inputs'] if s['kind'] == 'cpu_irq_input'], 'target')
    delivery = _one([d for d in request.wiring.deliveries
        if (d.producer_instance, d.producer_endpoint_id, d.consumer_instance, d.consumer_endpoint_id)
        == (producer['component'], producer['endpoint_id'], target['component'], target['endpoint_id'])], 'delivery')
    _require(delivery.trigger == 'pulse', 'delivery-trigger')
    _require(type(binding) is Binding and binding in runner.bindings
             and binding.source_component == producer['component']
             and binding.target_component == target['component']
             and binding.width == 1, 'runtime-binding')
    pulse = runner._irq_pulses.get(binding)
    _require(type(pulse) is IrqPulseDelivery and type(pulse_width_ticks) is int
             and 1 <= pulse_width_ticks <= 4096
             and type(pulse.width_ticks) is int and pulse.width_ticks == pulse_width_ticks, 'runtime-pulse')
    nodes = compiled['runtime_path_contract']['nodes']
    identity = path['runtime_path_identity']
    node_ids = set(identity['source_ids'])
    for edge in identity['edges']:
        node_ids.update((edge['prerequisite'], edge['target']))
    def node(component, port=None):
        return _one([n for n in nodes if n['node_id'] in node_ids and n['kind'] == 'physical'
                     and n['component'] == component and (port is None or n['port'] == port)], 'physical-node')
    pin = node(source['component'], source['port'])
    ip = node(producer['component'], delivery.producer_signal)
    cpu = node(target['component'])
    if delivery.consumer_bit_offset is not None:
        _require(delivery.consumer_bit_offset == cpu['bit_offset'], 'delivery-bit')
    # Contract node offsets are DUT-vector coordinates. The host-facing
    # binding/ownership coordinate is the same line inside the artifact's
    # declared one-bit IRQ input export, i.e. port-local.
    from .shared_f5_runtime import shared_f5_irq_host_offset
    cpu_host_bit = shared_f5_irq_host_offset(artifacts[target['component']],
        port=cpu['port'], dut_offset=cpu['bit_offset'])
    _require((pin['bit_offset'], pin['width']) == (source['bit_offset'], source['width'])
             and source['origin'] == 'fuzzable' and source['width'] == 1, 'source-shape')
    _require(binding.source_bit_offset == ip['bit_offset']
             and binding.target_bit_offset == cpu_host_bit
             and ip['width'] == cpu['width'] == 1, 'runtime-binding-range')
    cpu_role = artifacts[target['component']].plan.profile.cpu.irq_entry_role
    pin_runtime = _physical(artifacts[source['component']], port=pin['port'],
        endpoint=source['endpoint_id'], role='in', direction='input', bit=pin['bit_offset'], width=1)
    ip_runtime = _physical(artifacts[producer['component']], port=ip['port'],
        endpoint=producer['endpoint_id'], role='irq', direction='output', bit=ip['bit_offset'], width=1)
    cpu_runtime = _physical(artifacts[target['component']], port=cpu['port'],
        endpoint=target['endpoint_id'], role=cpu_role, direction='input', bit=cpu['bit_offset'], width=1)
    ownership = compiled_inputs['ownership']
    _require(ownership.mutation_source(source['component'], pin['port'], pin['bit_offset'], 1,
        direction=path['direction']) == source['source_id'], 'physical-source-owner')
    runtime_owner = runner.ownership.mutation_source(source['component'], binding_port :=
        compiled_inputs['physical_port_map'].get((source['component'], pin['port']), pin['port']),
        pin['bit_offset'], 1, direction=path['direction'])
    _require(ownership.binding_producer(target['component'], cpu['port'], cpu_host_bit, 1)
             == producer['input_id'], 'physical-irq-owner')
    _require(runner.ownership.binding_producer(binding.target_component, binding.target_port,
        binding.target_bit_offset, binding.width)
        == f'{binding.source_component}.{binding.source_port}', 'runtime-irq-owner')
    return dict(schema_version='live_f5_crosswalk.v1', status='compatible',
        runtime_enforcement='topology_only', compiled_sha256=compiled_document_sha256(compiled),
        path_identity=deepcopy(identity), artifact_digests=dict(admission['artifact_digests']),
        source=dict(component=source['component'], compiled_source_id=source['source_id'],
            runtime_owner=runtime_owner, physical_port=pin['port'], runtime_port=binding_port,
            physical_bit_offset=pin['bit_offset'], width=1, runtime_name=pin_runtime),
        irq=dict(compiled_producer_id=producer['input_id'], delivery_id=delivery.delivery_id,
            physical_producer=ip['port'], physical_consumer=cpu['port'],
            producer_runtime_name=ip_runtime, consumer_runtime_name=cpu_runtime,
            logical_producer=f'{binding.source_component}.{binding.source_port}',
            logical_consumer=f'{binding.target_component}.{binding.target_port}'),
        pulse_width_cpu_ticks=pulse_width_ticks,
        not_claimed=['IRQ delivered', 'CPU IRQ acceptance', 'ISR execution'])


def validate_compiled_f5_crosswalk(*, compiled_inputs, artifacts, runner, preparation=None):
    """Validate same-preparation D3 and actual PULP/Ibex Runner before begin.

    The returned documentary identity is stable across fresh Runner instances.
    The caller remains responsible for preparation issuance/currentness and
    revalidating this crosswalk whenever constructing a new Runner.
    """
    _require(isinstance(compiled_inputs, Mapping) and set(compiled_inputs) ==
             {'request','compiled','ownership','physical_port_map'}, 'inputs')
    _require(isinstance(artifacts, Mapping) and set(artifacts) == {'cpu','gpio_a','gpio_b'}, 'artifacts')
    # The fixed factory only accepts these source-locked profiles/session kinds.
    modes = {name: 'native_physical_observation_contract' in artifact.runtime_document
             for name, artifact in artifacts.items()}
    select_factory_artifacts(artifacts, expected={
        'cpu': (CPU_PROFILE, 'obi_cpu'),
        'gpio_a': (CAUSAL_GPIO_PROFILE, 'apb_gpio'),
        'gpio_b': (CAUSAL_GPIO_PROFILE, 'apb_gpio')}, base_dir=ROOT,
        observation_modes=modes)
    admission = admit_compiled_artifacts(artifacts=artifacts, **compiled_inputs, flow_ids=('F5',))
    _require(admission['status'] == 'compatible', 'compiled-admission')
    request, compiled = compiled_inputs['request'], compiled_inputs['compiled']
    path = _one([p for p in compiled['paths'] if p['flow_id'] == 'F5' and p['status'] == 'executable'], 'path')
    source = _one([s for s in path['sources'] if s['kind'] == 'external_pin'], 'source')
    _require(all(source.get(k) == v for k,v in {
        'component':'gpio_b', 'endpoint_id':'gpio.pins', 'port':'gpio_in',
        'bit_offset':8, 'width':1, 'mask':1}.items()), 'source-shape')
    producer = _one([s for s in path['bound_inputs'] if s['kind'] == 'ip_irq'], 'producer')
    target = _one([s for s in path['bound_inputs'] if s['kind'] == 'cpu_irq_input'], 'target')
    _require((producer['component'], producer['endpoint_id'], target['component'], target['endpoint_id']) ==
             ('gpio_b','gpio.interrupts','cpu','processor.interrupts'), 'endpoint')
    delivery = _one(list(request.wiring.deliveries), 'delivery-count')
    _require((delivery.producer_instance,delivery.producer_endpoint_id,delivery.producer_signal,
              delivery.consumer_instance,delivery.consumer_endpoint_id,delivery.trigger) ==
             ('gpio_b','gpio.interrupts','interrupt','cpu','processor.interrupts','pulse'), 'delivery')
    fixed = request.wiring.fixed_inputs
    _require(all(type(row.bit_offset) is int and type(row.width) is int
                 and type(row.constant) is int for row in fixed)
             and sorted((row.component_instance,row.port,row.bit_offset,row.width,row.constant)
                        for row in fixed) == [
                 ('gpio_a','gpio_in',0,32,0), ('gpio_b','gpio_in',0,8,0),
                 ('gpio_b','gpio_in',9,23,0)], 'fixed-inputs')
    contract = compiled['runtime_path_contract']
    for name, component, port, offset in (
            ('F5.pin_event','gpio_b','gpio_in',8), ('F5.ip_irq','gpio_b','interrupt',0),
            ('F5.cpu_irq_entry','cpu','irq_external_i',0)):
        node = _one([n for n in contract['nodes'] if n['node_id']==name], 'node')
        _require(node == dict(node_id=name, component=component, kind='physical', port=port,
                              bit_offset=offset, width=1), 'node-shape')
    pin_runtime = _physical(artifacts['gpio_b'],port='gpio_in',endpoint='gpio.pins',role='in',direction='input',bit=8,width=1)
    ip_runtime = _physical(artifacts['gpio_b'],port='interrupt',endpoint='gpio.interrupts',role='irq',direction='output',bit=0,width=1)
    cpu_runtime = _physical(artifacts['cpu'],port='irq_external_i',endpoint='processor.interrupts',role='external',direction='input',bit=0,width=1)
    _require(type(runner) is ScenarioRunner and set(runner.sessions) == set(artifacts), 'runner')
    for name, cls in (('cpu',GeneratedCve2Session),('gpio_a',GeneratedPulpGpioSession),('gpio_b',GeneratedPulpGpioSession)):
        session = runner.sessions[name]
        _require(type(session) is cls and session.artifact is artifacts[name]
                 and session._artifact_document == artifacts[name].runtime_document, 'runner-artifact')
    _require(runner.ownership.document() == dual_source_ownership(f5_only=True).document(), 'runtime-ownership')
    binding = Binding('gpio_b','irq','cpu','irq',1)
    _require(runner.bindings == (binding,) and set(runner._irq_pulses) == {binding}
             and type(runner._irq_pulses[binding]) is IrqPulseDelivery
             and type(runner._irq_pulses[binding].width_ticks) is int
             and runner._irq_pulses[binding].width_ticks == 4, 'runtime-pulse')
    if preparation is not None:
        _require(all(artifacts[name] is preparation.artifacts.get(name) for name in artifacts)
                 and compiled_inputs == preparation.compiled_inputs(), 'preparation-inputs')
        validate_live_f5_crosswalk(preparation=preparation, runner=runner, path=path,
            binding=binding, pulse_width_ticks=4)
    else:
        _validate_f5_topology(compiled_inputs=compiled_inputs, artifacts=artifacts,
            runner=runner, path=path, binding=binding, pulse_width_ticks=4)
    # Check the physical owner and the fixed bits as well as the logical ones.
    physical = compiled_inputs['ownership'].document()
    owners = physical['owners']
    expected = [
        ('cpu','irq_external_i',0,1,'bound',producer['input_id']),
        ('gpio_a','gpio_in',0,32,'fixed','constant_zero'),
        ('gpio_b','gpio_in',0,8,'fixed','constant_zero'),
        ('gpio_b','gpio_in',8,1,'source',source['source_id']),
        ('gpio_b','gpio_in',9,23,'fixed','constant_zero'),
    ]
    keys = ('component_id','port','bit_offset','width','kind','producer_ref')
    relevant = [tuple(r[k] for k in keys) for r in owners if
                (r['component_id'], r['port']) in {('cpu','irq_external_i'),('gpio_a','gpio_in'),('gpio_b','gpio_in')}]
    _require(sorted(relevant) == sorted(expected), 'physical-ownership')
    _require(all(compiled_inputs['physical_port_map'].get((c,p)) == p for c,p in
                 (('cpu','irq_external_i'),('gpio_a','gpio_in'),('gpio_b','gpio_in'))), 'physical-map')
    return dict(schema_version='compiled_f5_crosswalk.v1', status='compatible',
        runtime_enforcement='topology_only', compiled_sha256=compiled_document_sha256(compiled),
        graph_sha256=contract['graph_sha256'], path_identity=deepcopy(path['runtime_path_identity']),
        artifact_digests=dict(admission['artifact_digests']),
        source=dict(compiled_source_id=source['source_id'], runtime_owner='external_b.pin8',
                    physical_port='gpio_in',physical_bit_offset=8,width=1,runtime_name=pin_runtime),
        irq=dict(compiled_producer_id=producer['input_id'], delivery_id=delivery.delivery_id,
                 physical_producer='interrupt',physical_consumer='irq_external_i',
                 producer_runtime_name=ip_runtime,consumer_runtime_name=cpu_runtime,
                 logical_producer='gpio_b.irq',logical_consumer='cpu.irq'),
        pulse_width_cpu_ticks=4,
        not_claimed=['IRQ delivered','CPU IRQ acceptance','ISR execution'])
