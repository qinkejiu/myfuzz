"""Static scenario inspection using the same preparation as execution.

This report does not construct a runtime or establish runtime admission.
"""
from .contracts import GenericRuntimeRefused
from .generic_campaign import FLOWS
from .preparation import create_preparation


def _declared_candidates(context, descriptor):
    """Validate the descriptor's own F4/F2 records with the runtime declarations.

    The same decode + ``declare_writer``/``declare_reader`` pair the executor
    calls is used, on the same prepared request: a record the runtime would
    refuse is refused here too.  Nothing is executed and no runtime is built.
    """
    from myfuzz.integration.compiled_candidate_layout import compile_candidate_layout
    from myfuzz.integration.compiled_f2_layout import compile_f2_candidate_layout
    from myfuzz.integration.generated_register_reader import declare_reader
    from myfuzz.integration.generated_register_writer import declare_writer
    inputs = context.compiled_inputs()
    request, compiled = inputs['request'], inputs['compiled']
    report = {}
    for flow in ('F4', 'F2'):
        records = descriptor.records(flow)
        if not records:
            continue
        paths = [path for path in compiled['paths']
                 if path['flow_id'] == flow and path['status'] == 'executable']
        if len(paths) != 1:
            report[flow] = [dict(record=raw, ok=False,
                                 refusal='candidate-path-undeclared-or-ambiguous')
                            for raw in records]
            continue
        path = paths[0]
        stream = next((source for source in path['sources']
                       if source['kind'] in ('cpu_mmio_stream', 'cpu_load_stream')), None)
        image = next((source for source in path['sources']
                      if source['kind'] == 'instruction_image'), None)
        bounds = image.get('range') if image is not None else None
        result = (bounds[1] - 3) & ~3 if bounds else None
        rows = []
        for raw in records:
            try:
                if stream is None or result is None:
                    raise ValueError('candidate-stream-or-result-address-undeclared')
                data = bytes.fromhex(raw)
                if flow == 'F4':
                    value = compile_candidate_layout(path).decode(data)[stream['source_id']]
                    declaration = declare_writer(request, compiled,
                        source_id=stream['source_id'], value=value, result_address=result)
                    rows.append(dict(record=raw, ok=True, value=value,
                        address=declaration['candidate']['access']['address']))
                else:
                    classified = compile_f2_candidate_layout(path).classify(data)
                    if not classified.accepted:
                        raise ValueError('F2-candidate:' + str(classified.reason))
                    declaration = declare_reader(request, compiled,
                        source_id=stream['source_id'], address=classified.address,
                        result_address=result)
                    rows.append(dict(record=raw, ok=True, address=classified.address))
            except Exception as error:  # one bad record never hides the others
                rows.append(dict(record=raw, ok=False, refusal=str(error)[:200]))
        report[flow] = rows
    return report


def inspect_descriptor(descriptor, *, base_dir, generated_dir):
    rows = {
        flow: {
            'declared': flow in descriptor.flow_ids,
            'configured_executor': descriptor.executors.get(flow),
            'runtime_admission': 'not_checked',
            'reason': None if flow in descriptor.flow_ids else 'flow-not-declared-by-descriptor',
        }
        for flow in FLOWS
    }
    report = dict(schema_version='descriptor_preflight.v1', scenario=descriptor.scenario_id,
                  preparation='not_started', native_executed=False, flows=rows)
    capabilities = descriptor.capability if isinstance(descriptor.capability, tuple) else (descriptor.capability,)
    try:
        context = create_preparation(base_dir=base_dir, compose_path=descriptor.compose,
            capability_paths=capabilities, supplement_path=descriptor.supplement,
            generated_dir=generated_dir, flow_ids=descriptor.flow_ids)
    except GenericRuntimeRefused as error:
        report['preparation'] = 'refused'
        report['refusal'] = dict(code=error.code, pointer=error.pointer, detail=error.detail)
        for flow in descriptor.flow_ids:
            rows[flow]['reason'] = 'preparation-refused'
        return report
    try:
        report['preparation'] = 'complete'
        paths = context.d3_document().get('paths', [])
        for flow in descriptor.flow_ids:
            rows[flow]['compiled_paths'] = [p for p in paths if p['flow_id'] == flow]
            rows[flow]['static_support'] = context.flow_support(flow)
        # The descriptor's own records are the candidates a campaign would run;
        # validate them now instead of only describing static support.
        for flow, candidates in _declared_candidates(context, descriptor).items():
            rows[flow]['candidates'] = candidates
    finally:
        context.close()
    return report
