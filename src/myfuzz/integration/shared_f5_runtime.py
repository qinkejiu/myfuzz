"""Actual F5 pin/delivery adapter for a persistent storage session.

The supported component adapters are the generated OBI CPU and causal GPIO.
No saved crosswalk grants source ownership, and no IRQ event is a consumer proof.
"""
from dataclasses import dataclass, asdict
from copy import deepcopy

from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from myfuzz.scenario.dependency import DependencyGraph, DependencyPath, DependencyEdge
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import Binding
from myfuzz.scenario.runtime_path_contract import RuntimePathContract, PreparedRuntimePathContract
from .compiled_f5_crosswalk import _physical, _one, _require, _validate_f5_topology


# Compatibility alias: the component adapter keeps its original exact class.
PhysicalIrqCpuSession = GeneratedCve2Session


@dataclass(frozen=True)
class SharedF5Binding:
    preparation: object
    artifacts: object
    compiled_inputs: object
    path: dict
    binding: Binding
    ownership: object
    prepared: object
    input_identity: str

    def validate(self, runner):
        from .compiled_f4 import _input_identity
        self.preparation.assert_current()
        for artifact in self.preparation.artifacts.values():
            self.preparation.assert_artifact_current(artifact)
        if (_input_identity(self.preparation.compiled_inputs(), self.preparation.artifacts) != self.input_identity
                or _input_identity(self.compiled_inputs, self.artifacts) != self.input_identity):
            raise ValueError('shared-F5-preparation-identity-changed')
        return _validate_f5_topology(compiled_inputs=self.compiled_inputs,artifacts=self.artifacts,
            runner=runner,path=self.path,binding=self.binding,pulse_width_ticks=4)


def prepare_shared_f5(*, preparation, artifacts, compiled_inputs, cpu_id, target_id, cpu, target):
    from myfuzz.runtime.preparation import PreparationContext
    from .compiled_f4 import _input_identity
    _require(type(preparation) is PreparationContext, 'live-preparation-required')
    preparation.assert_current()
    if type(cpu) not in (PhysicalIrqCpuSession, GeneratedWishboneCpuSession) or type(target) is not GeneratedPulpGpioSession:
        raise ValueError('shared-F5-component-IRQ-adapter-unsupported')
    if type(cpu) is GeneratedWishboneCpuSession:
        from myfuzz.local_harness.profile_custom_irq import verify_custom_irq_artifact
        contract = verify_custom_irq_artifact(artifacts[cpu_id],base_dir=preparation.base_dir)
        if cpu._custom_irq_contract != contract:
            raise ValueError('shared-F5-custom-IRQ-observation-required')
    identity = _input_identity(compiled_inputs,artifacts)
    if identity != _input_identity(preparation.compiled_inputs(), preparation.artifacts):
        raise ValueError('shared-F5-preparation-input-mismatch')
    compiled = compiled_inputs['compiled']
    path = _one([p for p in compiled['paths'] if p['flow_id']=='F5' and p['status']=='executable'], 'path')
    producer = _one([s for s in path['bound_inputs'] if s['kind']=='ip_irq'], 'producer')
    consumer = _one([s for s in path['bound_inputs'] if s['kind']=='cpu_irq_input'], 'target')
    if (producer['component'], consumer['component']) != (target_id,cpu_id):
        raise ValueError('shared-F5-storage-component-mismatch')
    contract = RuntimePathContract.from_document(compiled['runtime_path_contract'])
    graph = DependencyGraph.from_edge_document(compiled['runtime_dependency_graph'])
    declared = path['runtime_path_identity']
    chain = DependencyPath(path['target']['node'],tuple(declared['source_ids']),
                           tuple(DependencyEdge(**row) for row in declared['edges']))
    if graph.path_identity(chain,direction=path['direction']) != declared['path_id']:
        raise ValueError('shared-F5-runtime-path-mismatch')
    prepared = PreparedRuntimePathContract(graph,contract,((path['direction'],chain),))
    nodes = {n.node_id:n for n in contract.nodes}
    relations = {(e.rule_index,e.prerequisite_index):e.relation for e in contract.edges}
    direct = _one([e for e in chain.edges if relations.get((e.rule_index,e.prerequisite_index))=='direct_binding'
                   and nodes[e.prerequisite].component==target_id
                   and nodes[e.target].component==cpu_id], 'irq-edge')
    ip,entry = nodes[direct.prerequisite],nodes[direct.target]
    cpu_port = cpu.irq_input_port if type(cpu) is PhysicalIrqCpuSession else 'irq'
    if cpu_port != entry.port:
        raise ValueError('shared-F5-CPU-physical-port-mismatch')
    # The compiled node offset is the DUT-vector offset. Host delivery is
    # port-local: the runner drives 0/1 on the declared one-bit input port.
    host_offset = shared_f5_irq_host_offset(artifacts[cpu_id], port=entry.port,
        dut_offset=entry.bit_offset)
    if type(cpu) is GeneratedWishboneCpuSession and not 3 <= host_offset < 32:
        raise ValueError('shared-F5-custom-IRQ-external-line-required')
    binding = Binding(target_id,ip.port,cpu_id,entry.port,1,ip.bit_offset,host_offset)
    document = shared_f5_ownership_document(compiled_inputs['ownership'].document(),
        cpu_id=cpu_id, port=entry.port, host_offset=host_offset,
        expected_producer_ref=producer['input_id'],
        producer_ref=f'{target_id}.{ip.port}')
    ownership = compile_ownership(tuple(InputField(**r) for r in document['fields']),
                                  tuple(InputOwner(**r) for r in document['owners']))
    return SharedF5Binding(preparation,artifacts,compiled_inputs,path,binding,ownership,prepared,identity)


def shared_f5_irq_host_offset(artifact, *, port, dut_offset):
    """Port-local host bit of a declared one-bit CPU IRQ input.

    ``dut_offset`` is the compiled node's DUT-vector bit. The host-facing
    ownership/binding coordinate is the same line inside the artifact's
    one-bit input export, which is always 0 for Ibex, CV32E20 and CV32E40P and
    stays unchanged for a CPU whose export already starts at bit 0.
    """
    document = getattr(artifact, 'runtime_document', None)
    if type(document) is not dict:
        raise ValueError('shared-F5-CPU-artifact-document-required')
    rows = [row for row in document.get('physical_exports', ())
            if row.get('physical_port') == port]
    _require(len(rows) == 1 and rows[0].get('direction') == 'input'
             and type(rows[0].get('width')) is int and rows[0]['width'] in (1,32)
             and type(rows[0].get('bit_lo')) is int
             and rows[0].get('bit_hi') == rows[0]['bit_lo'] + rows[0]['width'] - 1
             and type(dut_offset) is int
             and rows[0]['bit_lo'] <= dut_offset <= rows[0]['bit_hi'],
             'single-irq-input-export')
    host_offset = dut_offset - rows[0]['bit_lo']
    _require(type(host_offset) is int and host_offset >= 0, 'port-local-irq-offset')
    return host_offset


def shared_f5_ownership_document(document, *, cpu_id, port, host_offset,
                                expected_producer_ref, producer_ref):
    """Rewrite the CPU IRQ owner in port-local coordinates, or refuse."""
    _require(type(document) is dict and type(document.get('owners')) is list,
             'ownership-document')
    document = deepcopy(document)
    matched = []
    for owner in document['owners']:
        if (owner.get('component_id'), owner.get('port')) != (cpu_id, port):
            continue
        if owner.get('kind') == 'fixed':
            continue
        matched.append(owner)
        if (owner.get('kind'), owner.get('bit_offset'), owner.get('width'),
                owner.get('producer_ref')) != ('bound', host_offset, 1,
                                               expected_producer_ref):
            raise ValueError('shared-F5-IRQ-physical-ownership-mismatch')
        owner['producer_ref'] = producer_ref
    if len(matched) != 1:
        raise ValueError('shared-F5-IRQ-physical-ownership-mismatch')
    return document


def submit_shared_f5(runtime, raw, *, testcase_id=None):
    """Submit pin entropy and fixed NOP support into the existing session."""
    from myfuzz.scenario.batch import BatchSourceEvent, BatchAdvance
    from myfuzz.scenario.session_runtime import OnlineCase, OnlineInstruction
    from myfuzz.scenario.ledger import TransactionKey
    if type(raw) is not bytes or len(raw) != 8:
        raise ValueError('shared-F5-raw8-required')
    runtime._stable()
    if len(runtime.records) >= runtime.max_cases:
        raise ValueError('shared-F5-case-budget-exhausted')
    cpu = runtime.runner.sessions[runtime.cpu_id]
    waiting = cpu._waiting_fetch if type(cpu) is GeneratedWishboneCpuSession else cpu._waiting_instr
    if (type(waiting) is not tuple or len(waiting)!=2 or type(waiting[0]) is not TransactionKey
            or cpu.waiting_instruction_address != runtime.cursor
            or waiting[0].source_component != runtime.cpu_id
            or waiting[0].source_epoch != cpu.reset_epoch or waiting[0].channel_id != 'instr'
            or (type(cpu) is not GeneratedWishboneCpuSession and (
                cpu._request_evidence.get('instr',{}).get('transaction') != asdict(waiting[0])
                or cpu._request_evidence.get('instr',{}).get('aligned_address') != runtime.cursor))):
        raise ValueError('shared-F5-real-waiting-instruction-required')
    code = b'\x13\x00\x00\x00' * 4
    memory = cpu.memory
    if (runtime.cursor+len(code) > runtime.result-(4 if runtime._memory_flows else 0)
            or any(not memory.instruction_slot_unmaterialized(a)
                   for a in range(runtime.cursor,runtime.cursor+len(code),4))):
        raise ValueError('shared-F5-support-slot-exhausted')
    path = runtime.f5_binding.path
    pin = _one([s for s in path['sources'] if s['kind']=='external_pin'],'source')
    case_id = testcase_id or f'{runtime.run_id}:{len(runtime.records)}'
    value = raw[3] & 1  # same payload entropy bit as the standalone raw8 decoder
    case = OnlineCase(case_id,path['direction'],path['runtime_path_identity']['path_id'],
        BatchSourceEvent(case_id+':pin',pin['component'],pin['port'],value,pin['bit_offset'],pin['width']),
        tuple(BatchAdvance(tuple(runtime.runner.sessions)) for _ in range(runtime.rounds)),
        support_instructions=(OnlineInstruction(case_id+':fixed-support',runtime.cpu_id,runtime.cursor,code.hex()),))
    receipt = runtime.session.submit_case(case)
    if receipt.violations or receipt.status != 'running':
        raise ValueError('shared-F5-session-failed')
    result = dict(schema_version='compiled_shared_F5_case.v1',flow_id='F5',case_id=case_id,
        status='submitted',value=value,instruction_address=runtime.cursor,instruction_hex=code.hex(),
        irq_consumption='unknown')
    if getattr(runtime,'_irq_firmware_enabled',False) and type(cpu) is PhysicalIrqCpuSession:
        from .shared_irq_firmware import observe_irq_isr
        result['irq_isr']=observe_irq_isr(runtime,receipt)
        result['irq_consumption']=result['irq_isr']['status']
    runtime.records.append(dict(raw=raw.hex(),flow='F5',certificate=result))
    runtime.cursor += len(code)
    from myfuzz.search.pin_read import register_pin_writer
    register_pin_writer(runtime,case,receipt)
    return deepcopy(result)


def admit_shared_f5_declaration(*, artifacts, compiled_inputs):
    """Static component admission; actual runtime still needs the live binding."""
    request, compiled = compiled_inputs['request'],compiled_inputs['compiled']
    path = _one([p for p in compiled['paths'] if p['flow_id']=='F5' and p['status']=='executable'],'path')
    pin = _one([s for s in path['sources'] if s['kind']=='external_pin'],'source')
    producer = _one([s for s in path['bound_inputs'] if s['kind']=='ip_irq'],'producer')
    consumer = _one([s for s in path['bound_inputs'] if s['kind']=='cpu_irq_input'],'target')
    delivery = _one([d for d in request.wiring.deliveries if
        (d.producer_instance,d.producer_endpoint_id,d.consumer_instance,d.consumer_endpoint_id) ==
        (producer['component'],producer['endpoint_id'],consumer['component'],consumer['endpoint_id'])], 'delivery')
    _require((delivery.producer_instance,delivery.producer_endpoint_id,delivery.consumer_instance,
              delivery.consumer_endpoint_id,delivery.trigger) ==
             (producer['component'],producer['endpoint_id'],consumer['component'],consumer['endpoint_id'],'pulse'), 'delivery')
    _require(artifacts[producer['component']].runtime_document['kind']=='apb_gpio'
             and artifacts[consumer['component']].runtime_document['kind'] in ('obi_cpu','wishbone_cpu')
             and pin['component']==producer['component'] and pin['width']==1,'IRQ-components')
    nodes = compiled['runtime_path_contract']['nodes']
    ip = _one([n for n in nodes if n['node_id']=='F5.ip_irq'],'ip-node')
    cpu = _one([n for n in nodes if n['node_id']=='F5.cpu_irq_entry'],'cpu-node')
    _physical(artifacts[pin['component']],port=pin['port'],endpoint=pin['endpoint_id'],
              role='in',direction='input',bit=pin['bit_offset'],width=pin['width'])
    _physical(artifacts[producer['component']],port=ip['port'],endpoint=producer['endpoint_id'],
              role='irq',direction='output',bit=ip['bit_offset'],width=1)
    _physical(artifacts[consumer['component']],port=cpu['port'],endpoint=consumer['endpoint_id'],
              role=artifacts[consumer['component']].plan.profile.cpu.irq_entry_role,
              direction='input',bit=cpu['bit_offset'],width=1)
    if delivery.consumer_bit_offset is not None:
        _require(delivery.consumer_bit_offset == cpu['bit_offset'], 'IRQ-declared-bit')
    host_offset = shared_f5_irq_host_offset(artifacts[consumer['component']],
                                            port=cpu['port'], dut_offset=cpu['bit_offset'])
    bound = [o for o in compiled_inputs['ownership'].document()['owners']
             if (o['kind'],o['component_id'],o['port'],o['bit_offset'],o['width'],o['producer_ref']) ==
                ('bound',consumer['component'],cpu['port'],host_offset,1,producer['input_id'])]
    _require(len(bound)==1, 'IRQ-bound-owner')
    return cpu['port']
