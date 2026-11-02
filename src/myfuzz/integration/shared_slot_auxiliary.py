"""Typed F4 candidate pin actions on the existing session, before its CPU slot."""


def auxiliary_sources(compiled,admission,*,flow,raw):
    if flow!='F4':
        return []
    from .compiled_candidate_layout import compile_candidate_layout
    row, = [row for row in compiled['paths'] if row['flow_id']=='F4' and row['status']=='executable']
    values = compile_candidate_layout(row).decode(raw)
    result = []
    for source in row['sources']:
        if source['kind']!='external_pin':
            continue
        selected = admission.get('shared_flow_paths',{}).get('F5')
        if selected is None or any(selected['pin'][key]!=source[key] for key in ('component','port','bit_offset','width')):
            raise ValueError('shared-slot-auxiliary-pin-typed-path-required')
        if source['source_id']!=selected['logical_source_id']:
            raise ValueError('shared-slot-auxiliary-pin-source-mismatch')
        result.append(dict(source_id=selected['source_id'],logical_source_id=source['source_id'],component=source['component'],port=source['port'],
            bit_offset=source['bit_offset'],width=source['width'],value=values[source['source_id']],
            path_id=selected['path_id'],direction=selected['direction']))
    return result


def expected_auxiliary_rows(compiled,admission,*,flow,raw,case_id,first_session_index):
    return [dict(source,case_id=case_id+':external:'+str(index),
        action_id=source['source_id']+':auxiliary:'+case_id+':'+str(index),
        session_case_index=first_session_index+index)
        for index,source in enumerate(auxiliary_sources(compiled,admission,flow=flow,raw=raw))]


def source_value(row):
    return {key:row[key] for key in ('action_id','component','port','value','bit_offset','width')}
