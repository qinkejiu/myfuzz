"""Narrow READ saved data stays closed and fresh compilation is authoritative."""
from copy import deepcopy
import hashlib
import json
import pytest
from tests.scenario.test_register_program_runtime import factory, installed, request
from myfuzz.scenario.session_runtime import _validate_register_manifest


def prepared(factory):
    runtime,_,_=installed(factory,max_program_bytes=64)
    row=request(target_instance='gpio_a',register='PADCFG_0',field='pin7',
        operation='register_read',value=None,result_address=0x10004,allow_side_effect=False)
    return runtime,runtime.prepare(row).document()


def resign(program):
    program['identity_sha256']=hashlib.sha256(json.dumps(
        {k:v for k,v in program.items() if k!='identity_sha256'},
        sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def test_actual_narrow_read_manifest_is_accepted_without_restoring_authority(factory):
    runtime,document=prepared(factory)
    _validate_register_manifest(document,runtime.configuration())
    assert len(bytes.fromhex(document['program']['source']['data_hex']))==24
    assert document['program']['result_storage']['field_extraction']['lsb']==28
    assert runtime._records==[]


@pytest.mark.parametrize('mutation',['width_bool','lsb','extra','missing','fragment'])
def test_self_consistently_rehashed_extraction_or_length_is_rejected(factory,mutation):
    runtime,document=prepared(factory);document=deepcopy(document)
    program=document['program'];extraction=program['result_storage']['field_extraction']
    if mutation=='width_bool':extraction['width']=True
    elif mutation=='lsb':extraction['lsb']=0
    elif mutation=='extra':extraction['caller_authority']=True
    elif mutation=='missing':program['result_storage'].pop('field_extraction')
    else:
        program['source']['data_hex']+='13000000'
        program['fragment_sha256']=hashlib.sha256(bytes.fromhex(program['source']['data_hex'])).hexdigest()
    resign(program)
    with pytest.raises(ValueError):_validate_register_manifest(document,runtime.configuration())
    assert runtime._records==[]
