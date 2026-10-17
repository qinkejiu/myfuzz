"""Execution feasibility of capability-compiled paths against explicit runtime facts.

A negative projection is separate from capability-only compilation. This module
never starts RTL and never grants execution, including when producer ABI facts
or caller-supplied diagnostic observations match a target.
"""
from copy import deepcopy

from .compiled_artifact_admission import admit_compiled_artifacts


def assess_compiled_execution(*,artifacts,compiled_inputs,runtime_declaration,
                              producer_events=()):
    admission=admit_compiled_artifacts(artifacts=artifacts,**compiled_inputs)
    report=dict(schema_version='compiled_execution_projection.v1',
        scope='execution_feasibility_no_runtime_authority',runtime_admitted=False,
        capability_executable=0,execution_supported=0,paths=[],
        input_admission=admission,source_evidence_scope='loaded_D2_source_and_ABI',
        observed_evidence_scope='diagnostic_only_no_grants')
    # Analysis of a stale/edited document would itself misrepresent the request.
    wiring_refusals={'ownership-bound-producer-not-admitted','ownership-source-uncompiled',
                    'compiled-physical-source-unowned'}
    if any(r['code'] not in wiring_refusals for r in admission['refusals']):
        report['status']='input_refused'
        return report
    if not isinstance(runtime_declaration,dict) or runtime_declaration.get('schema_version')!='fixed_runtime_execution_declaration.v1':
        report['status']='runtime_declaration_missing'
        return report
    required={'schema_version','decoder','authenticated_retirement_contract',
              'source_projection','bound_projection','compiled_prerequisite_handlers',
              'compiled_assertion_handlers','compiled_seed_projection'}
    if set(runtime_declaration)!=required or not isinstance(runtime_declaration['decoder'],dict):
        report['status']='runtime_declaration_invalid'
        return report
    compiled=compiled_inputs['compiled']
    request=compiled_inputs['request']
    declaration=deepcopy(runtime_declaration)
    report['runtime_declaration']=declaration
    decoder=declaration['decoder']
    windows=decoder['mmio_windows']
    for index,path in enumerate(compiled['paths']):
        if path['status']!='executable':continue
        report['capability_executable']+=1
        base=f'/paths/{index}'
        row=dict(path_id=path['path_id'],flow_id=path['flow_id'],
            capability_status=path['status'],status='unsupported',runtime_admitted=False,
            register_targets=[],refusals=[])
        def refuse(code,pointer,detail=None):
            row['refusals'].append(dict(code=code,pointer=pointer,detail=detail))
        if path['flow_id']=='F1' and declaration['authenticated_retirement_contract'] is None:
            refuse('authenticated-retirement-observation-missing',base+'/termination_observation',
                dict(required=path['termination_observation'],
                     available_contract=None,source_component=request.cpu.instance_id))
        for number,source in enumerate(path['sources']):
            pointer=f'{base}/sources/{number}'
            # The current fixed source ids are different declarations. A name,
            # overlapping range or shared CPU cannot invent a projection join.
            if source['source_id'] not in declaration['source_projection']:
                refuse('compiled-source-execution-map-missing',pointer,
                    dict(source_id=source['source_id'],kind=source['kind'],
                         runtime_sources=[s['source_id'] for s in decoder['sources']]))
            if source['kind'] not in ('cpu_mmio_stream','cpu_load_stream'):continue
            role='mmio_control_target' if source['kind']=='cpu_mmio_stream' else 'read_response_producer'
            targets=[e for e in path['endpoints'] if e['declared_role']==role]
            if len(targets)!=1:
                refuse('compiled-register-producer-ambiguous',pointer)
                continue
            endpoint=targets[0]
            component=request.component(endpoint['instance_id'])
            registers=component.profile.address.registers if component.profile.address else ()
            registers=[r for r in registers if r.name==source['register']]
            if len(registers)!=1:
                refuse('compiled-register-offset-undeclared',pointer+'/register')
                continue
            register=registers[0]
            routes=[w for w in request.wiring.windows if w.target_instance==component.instance_id
                    and (w.endpoint_id is None or w.endpoint_id==endpoint['endpoint_id'])]
            if len(routes)!=1:
                refuse('compiled-register-route-ambiguous',pointer)
                continue
            route=routes[0]
            address=route.base+register.offset
            artifact=artifacts[component.instance_id]
            abi=[p for p in artifact.structural.abi_document['ports']
                 if p['endpoint_id']==endpoint['endpoint_id']]
            observed=[dict(event_id=e.get('event_id'),write=e.get('write'),
                write_value=e.get('write_value'),read_value=e.get('read_value'),
                provenance=deepcopy(e.get('provenance')))
                for e in producer_events if e.get('kind')=='mmio_delivery'
                and e.get('device_id')==route.device_id and e.get('offset')==register.offset]
            target=dict(source_id=source['source_id'],producer_component=component.instance_id,
                endpoint_id=endpoint['endpoint_id'],register=register.name,offset=register.offset,
                address=address,register_width=register.width,
                artifact_digest=artifact.runtime_document['artifact_digest'],
                profile_fingerprint=component.profile.profile_fingerprint,
                source_verification=deepcopy(artifact.source_verification),
                physical_bus_outputs=[dict(port=p['physical_port'],role=p['role'],width=p['width'])
                                      for p in abi if p['direction']=='output'],
                diagnostic_matching_deliveries=observed,
                register_access=deepcopy(source.get('register_access')),
                candidate_source_certified=False)
            row['register_targets'].append(target)
            access=source.get('register_access')
            if access is None:
                refuse('compiled-register-access-contract-missing',pointer+'/register_access')
            else:
                target['constraint_mapping']='exact_register_access_declared'
                refuse('compiled-register-writer-checker-binding-missing',pointer+'/register_access',
                    dict(address=access['address'],source_owner=access['source_component'],
                         requires=['actual CPU writer receipt join','IP register version witness',
                                   'compiled assertion checker binding']))
            operation='SW' if source['kind']=='cpu_mmio_stream' else 'LW'
            if operation not in decoder['allowed_mmio_operations'] or not any(
                    w['base']<=address and address+4<=w['base']+w['size'] for w in windows):
                refuse('compiled-register-outside-runtime-candidate-windows',pointer,
                    dict(address=address,offset=register.offset,operation=operation,
                         runtime_windows=windows))
            # D3 currently carries window alignment on a register stream. If
            # interpreted as access alignment it excludes its own offset. Do not
            # silently substitute beat alignment or discard that constraint.
            if address%source['alignment']:
                refuse('compiled-register-address-alignment-unresolved',pointer+'/alignment',
                    dict(address=address,compiled_alignment=source['alignment'],
                         window_alignment=component.profile.address.alignment,
                         requires='declare separate window and access alignment semantics'))
        for number,bound in enumerate(path['bound_inputs']):
            if bound['input_id'] not in declaration['bound_projection']:
                refuse('compiled-bound-producer-map-missing',f'{base}/bound_inputs/{number}',bound)
        for number,pre in enumerate(path['prerequisites']):
            if pre['kind'] not in declaration['compiled_prerequisite_handlers']:
                refuse('compiled-prerequisite-handler-missing',f'{base}/prerequisites/{number}',pre)
        for number,assertion in enumerate(path['assertions']):
            if assertion['expectation_id'] not in declaration['compiled_assertion_handlers']:
                refuse('compiled-assertion-checker-map-missing',f'{base}/assertions/{number}',assertion)
        if path['seed'] is not None and path['path_id'] not in declaration['compiled_seed_projection']:
            refuse('compiled-seed-execution-map-missing',base+'/seed',path['seed'])
        # Presence of a caller's handler name is not an implementation or a
        # trusted registration. No positive projection executor is installed.
        refuse('compiled-path-executor-not-installed',base,
            'declarations and diagnostic matching deliveries cannot grant execution')
        report['paths'].append(row)
    report['status']='unsupported'
    return report


def _storage_consumer_support(*, binding, artifacts):
    """One indirection so the report mapping itself stays unit-testable."""
    from myfuzz.integration.generated_storage_consumer import (
        storage_consumer_support)
    return storage_consumer_support(binding=binding, artifacts=artifacts)


def assess_compiled_f4_support(*,artifacts,compiled_inputs,base_dir=None):
    """Inspect the installed executor without granting live execution authority."""
    from myfuzz.integration.compiled_f4 import admit_f4
    from myfuzz.integration.compiled_storage_producer import (
        ROW_GPIO_CAUSAL,select_storage_producer)
    try:
        selected=admit_f4(artifacts=artifacts,compiled_inputs=compiled_inputs,base_dir=base_dir)
        binding=select_storage_producer(artifacts=artifacts,compiled_inputs=compiled_inputs,
            base_dir=base_dir)
    except ValueError as error:
        return dict(schema_version='compiled_F4_support.v1',execution_supported=0,
            runtime_admitted=False,status='unsupported',reason=str(error))
    if binding.row!=ROW_GPIO_CAUSAL:
        # The generic APB storage row is executable only after the in-row
        # consumer and all four live receipt joins are installed.  This report
        # is source/code identity only; runtime admission still requires the
        # actual native startup and opaque version token.
        support=_storage_consumer_support(binding=binding,artifacts=artifacts)
        unsupported_paths=[dict(path_id=p['path_id'],flow_id=p['flow_id'],
            reason='compiled-executor-flow-unsupported') for p in compiled_inputs['compiled']['paths']
            if p['path_id']!=selected['path_id']]
        if support['complete'] is not True:
            missing=','.join(row['element'] for row in support['refusals'])
            return dict(schema_version='compiled_F4_support.v1',execution_supported=0,
                runtime_admitted=False,status='unsupported',
                reason='compiled-F4-generic-receipt-join-incomplete:'+missing,
                executor='compiled_f4_obi_apb',path_id=selected['path_id'],
                producer_binding=binding.document(),receipt_elements=support,
                support_scope='generic_APB_storage_receipt_join_incomplete',
                unsupported_paths=unsupported_paths)
        return dict(schema_version='compiled_F4_support.v1',execution_supported=1,
            runtime_admitted=False,status='supported_requires_actual_startup',
            executor='compiled_f4_obi_apb',path_id=selected['path_id'],
            producer_binding=binding.document(),receipt_elements=support,
            support_scope='experimental_RV32I_writer_generic_APB_storage_with_live_version_token',
            startup_requires=['native_first_fetch_inside_instruction_image',
                              'exact_private_input_readmission',
                              'writable_instruction_image_result_word',
                              'actual_native_APB_storage_version_token'],
            unsupported_paths=unsupported_paths)
    return dict(schema_version='compiled_F4_support.v1',execution_supported=1,
        runtime_admitted=False,status='supported_requires_actual_startup',
        executor='compiled_f4_obi_apb',path_id=selected['path_id'],
        support_scope='experimental_RV32I_writer_GPIOEN_with_native_OBI_APB_and_live_versions',
        startup_requires=['native_first_fetch_inside_instruction_image',
                          'exact_private_input_readmission', 'writable_instruction_image_result_word'],
        unsupported_paths=[dict(path_id=p['path_id'],flow_id=p['flow_id'],
            reason='compiled-executor-flow-unsupported') for p in compiled_inputs['compiled']['paths']
            if p['path_id']!=selected['path_id']])
