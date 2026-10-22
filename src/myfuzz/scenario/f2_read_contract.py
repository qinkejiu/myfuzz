"""Canonical static F2 read selector; grants no live register authority."""
import json
from copy import deepcopy


def _canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',', ':'),allow_nan=False)


def build_f2_read_contract(path):
    try:
        if path['flow_id'] != 'F2' or path['status'] != 'executable':
            raise ValueError('executable-F2-required')
        images=[s for s in path['sources'] if s['kind']=='instruction_image']
        loads=[s for s in path['sources'] if s['kind']=='cpu_load_stream']
        if len(images)!=1 or len(loads)!=1 or len(path['sources'])!=2:
            raise ValueError('source-set')
        image,load=images[0],loads[0]; access=load['register_access']
        if (load['width'],load['bit_offset'],load['mask']) != (32,0,0xffffffff):
            raise ValueError('address-dimensions')
        if access['operation']!='read' or access['value_origin']!='bound_target_rdata':
            raise ValueError('read-operation')
        edges=path['runtime_path_identity']['edges']
        if len(edges)!=3:raise ValueError('three-edges-required')
        return dict(schema_version='compiled_F2_read_contract.v1',
            instruction_source_id=image['source_id'],load_source_id=load['source_id'],
            **{key:deepcopy(access[key]) for key in ('source_component','source_endpoint','target_component',
                'target_endpoint','device_id','address','register','field','width_bytes','allowed_byte_enables')},
            window={'base':access['window_base'],'size':access['window_size']},
            response_mask=access['value_mask'],
            version_selector={'kind':'ip_register_version','component':access['target_component'],
                'register':access['register'],'epoch_policy':'current_live_epoch'},
            nodes={'image':edges[0]['prerequisite'],'request':edges[0]['target'],
                'response':edges[1]['target'],'consumed':edges[2]['target']},
            consumption_mode='native_read_then_dependent_ram_store',
            expectation_ids=sorted(a['expectation_id'] for a in path['assertions']))
    except (KeyError,TypeError,IndexError,ValueError) as error:
        raise ValueError('compiled-F2-read-contract:'+str(error)) from error


def validate_f2_read_contract(path):
    expected=build_f2_read_contract(path)
    if _canonical(path.get('execution_contract'))!=_canonical(expected):
        raise ValueError('compiled-F2-read-contract:marker-mismatch')
    return expected
