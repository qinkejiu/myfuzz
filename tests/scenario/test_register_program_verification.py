"""Saved register programs cannot substitute for current compilation inputs."""
import copy
import hashlib
import json

import pytest

from myfuzz.scenario import register_program
from myfuzz.scenario.memory import MemoryRegion
from myfuzz.scenario.rv32i_sources import MmioWindow
from tests.composition.test_pulp_gpio_test_capability import loaded


def arguments(**changes):
    profile, capability = loaded()
    args = dict(register='PADOUT', field='value', operation='register_write',
        value=0x80000000, address_base=0x40000000,
        windows=(MmioWindow(0x40000000, profile.address.window_size),),
        cpu_component='cpu', action_id='register-write',
        program_address=0x20000, program_size=64,
        program_regions=(MemoryRegion('program', 0x20000, 64),))
    args.update(changes)
    return profile, capability, args


def resign(document):
    body = {key: value for key, value in document.items() if key != 'identity_sha256'}
    document['identity_sha256'] = hashlib.sha256(json.dumps(body, sort_keys=True,
        separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    return document


@pytest.mark.parametrize('read', [False, True])
def test_fresh_compilation_matches_saved_program_without_granting_authority(read):
    changes = (dict(operation='register_read', value=None, result_address=0x21000,
        result_regions=(MemoryRegion('result', 0x21000, 64),)) if read else {})
    profile, capability, args = arguments(**changes)
    saved = register_program.compile_register_program(profile, capability, **args).document()
    actual = register_program.verify_register_program_document(profile, capability, saved, **args)
    assert actual.document() == saved
    assert actual.document()['grants_prerequisites'] is False
    saved['source']['data_hex'] = 'bad'
    assert actual.source.data == actual.fragment


@pytest.mark.parametrize('changes', [dict(value=0), dict(program_address=0x20004,
    program_size=60), dict(action_id='other'), dict(address_base=0x50000000,
    windows=(MmioWindow(0x50000000, 4096),))])
def test_self_consistent_saved_program_cannot_replace_current_context(changes):
    profile, capability, old_args = arguments()
    saved = register_program.compile_register_program(profile, capability, **old_args).document()
    _, _, current_args = arguments(**changes)
    with pytest.raises(ValueError, match='saved-program-mismatch'):
        register_program.verify_register_program_document(profile, capability, saved, **current_args)


@pytest.mark.parametrize('path,value', [
    (('grants_prerequisites',), 0),
    (('access_context', 'allow_side_effect'), 0),
    (('operation_plan', 'bus_value'), 0),
    (('profile_fingerprint',), 'sha256:' + '0'*64),
    (('source', 'data_hex'), '13000000'),
    (('extra',), 'unrecognized'),
])
def test_rehashed_tampering_is_rejected_by_current_compilation(path, value):
    profile, capability, args = arguments()
    saved = copy.deepcopy(register_program.compile_register_program(profile, capability, **args).document())
    parent = saved
    for key in path[:-1]: parent = parent[key]
    parent[path[-1]] = value
    resign(saved)
    with pytest.raises(ValueError, match='saved-program-mismatch'):
        register_program.verify_register_program_document(profile, capability, saved, **args)


@pytest.mark.parametrize('saved', [None, [], {'unexpected': float('nan')}])
def test_malformed_saved_document_is_rejected(saved):
    profile, capability, args = arguments()
    with pytest.raises(ValueError, match='saved-program'):
        register_program.verify_register_program_document(profile, capability, saved, **args)


def test_matching_saved_regions_cannot_bypass_invalid_current_slot():
    profile, capability, args = arguments()
    saved = register_program.compile_register_program(profile, capability, **args).document()
    args['program_regions'] = (MemoryRegion('other', 0x30000, 64),)
    with pytest.raises(ValueError, match='slot-outside'):
        register_program.verify_register_program_document(profile, capability, saved, **args)
