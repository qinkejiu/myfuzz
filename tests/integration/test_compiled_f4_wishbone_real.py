"""One real certified classic Wishbone F4 case through the sibling executor.

Gated by ``MYFUZZ_SCENARIO_REAL=1``: it builds the pinned PicoRV32 Wishbone
master and the pinned WBUART ``SETUP`` storage target with Verilator, runs one
directed write/readback case through ``WishboneF4Runtime.submit`` and then a
second persistent case, and reproduces the prefix in a fresh process.  It is
not a three-case campaign, not a saved bundle and not a G8.1 PASS.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / 'configs/scenarios/compiled-f4-obi-wb-uart-setup'
VALUE = 0x55
RESET_VALUE = 0x19

pytestmark = pytest.mark.skipif(
    os.environ.get('MYFUZZ_SCENARIO_REAL') != '1',
    reason='set MYFUZZ_SCENARIO_REAL=1 for pinned real RTL')


def _prepared_inputs(directory):
    """The real same-pass D2/D3 preparation, including fixed-input ownership."""
    from myfuzz.integration.compiled_execution_files import (
        prepare_compiled_execution_inputs)
    prepared = prepare_compiled_execution_inputs(base_dir=ROOT,
        compose_path=CONFIG / 'compose.json',
        capability_paths=(CONFIG / 'test_capability.json',),
        supplement_path=CONFIG / 'execution_supplement.json',
        generated_dir=Path(directory) / 'generated', flow_ids=('F4',))
    return dict(prepared.artifacts), prepared.inputs


def test_one_real_certified_wishbone_case_then_persistent_second_case(tmp_path):
    from myfuzz.integration.compiled_wishbone_f4 import WishboneF4Runtime

    artifacts, inputs = _prepared_inputs(tmp_path)
    runtime = WishboneF4Runtime(artifacts=artifacts, compiled_inputs=inputs,
        base_dir=ROOT, cache_dir=tmp_path / 'cache',
        run_id='compiled-f4-wishbone-real', max_cases=4)
    pids = {name: session.process.pid
            for name, session in runtime.runner.sessions.items()}
    assert set(pids) == {'processor', 'peripheral'}
    assert all(type(pid) is int and pid > 0 for pid in pids.values())
    # The native first fetch is observed and stalled before any byte exists.
    assert runtime.cursor == 0
    assert runtime.first_fetch == {'address': 0,
                                   'event_id': runtime.first_fetch['event_id']}
    assert type(runtime.first_fetch['event_id']) is int
    try:
        raw = VALUE.to_bytes(4, 'little')
        certificate = runtime.submit(raw)

        # --- the certified chain -------------------------------------
        assert certificate['schema_version'] == 'compiled_F4_wishbone_chain.v1'
        assert certificate['status'] == 'certified'
        assert certificate['runtime_admitted'] is True
        assert certificate['case_id'] == 'compiled-f4-wishbone-real:0'
        assert certificate['path_id'] == 'F4:ram.image'
        assert certificate['source_id'] == 'peripheral.SETUP.value.mmio'
        assert certificate['bound_input_id'] == (
            'peripheral.uart.bus.register.SETUP.value')
        assert certificate['instruction_source_id'] == 'ram.image'
        assert certificate['instruction_address'] == 0
        from myfuzz.integration.wishbone_register_writer import (
            declare_wishbone_writer)
        stream = next(source for source in runtime.path['sources']
                      if source['kind'] == 'cpu_mmio_stream')
        declaration = declare_wishbone_writer(inputs['request'],
            inputs['compiled'], source_id=stream['source_id'], value=VALUE,
            result_address=0x2FFFC)
        assert certificate['instruction_sha256'] == declaration['code_sha256']
        assert len(bytes.fromhex(declaration['code_hex'])) == 48
        assert certificate['execution_binding_sha256'] == (
            runtime.execution_binding.digest)
        assert certificate['runtime_path_id'] == (
            runtime.runtime_path_admission.runtime_path_id)
        assert certificate['runtime_path_admission_sha256'] == (
            runtime.runtime_path_admission.digest)

        # The live pre-state is the measured reset value, not a claimed one.
        assert certificate['prerequisite']['value'] == RESET_VALUE
        assert certificate['prerequisite']['write_count'] == 0
        assert certificate['prerequisite']['register'] == 'SETUP'
        assert certificate['prerequisite']['version_basis'] == (
            'all_measured_SETUP_word_writes_since_first_command')
        assert certificate['prerequisite']['grants_reset_prerequisite'] is False
        assert certificate['prerequisite']['routed_context_authenticated'] is False

        # The write itself is the only journalled commit of this case.
        commit = certificate['commit']
        assert commit['schema_version'] == 'wishbone_storage_commit.v1'
        assert commit['before'] == RESET_VALUE
        assert commit['after'] == VALUE
        assert commit['word_index'] == 0
        assert commit['context']['write'] is True
        assert commit['context']['byte_enable'] == 15
        assert commit['context']['value'] == VALUE
        assert commit['context']['offset'] == 0
        assert commit['context']['address'] == 0x60000000
        assert commit['context']['source_authenticated'] is False

        postcondition = certificate['postcondition']
        assert postcondition['value'] == VALUE
        assert postcondition['write_count'] == 1
        assert postcondition['field_version'] == 1
        assert postcondition['register'] == 'SETUP'
        assert postcondition['schema_version'] == (
            'wishbone_storage_register_version.v1')

        # Opaque, single-use, process-owned token summary.
        token = certificate['token']
        assert token == {
            'schema_version': 'wishbone_storage_register_version_token.v1',
            'consumed': True, 'single_use': True, 'opaque': True,
            'issuer': ('myfuzz.scenario.wishbone_storage_register_version.'
                       'WishboneStorageRegisterVersionAuthority'),
            'register': 'SETUP', 'reset_epoch': 0, 'write_count': 1}

        # --- the exact native joins ----------------------------------
        hops = certificate['exact_hops']
        assert hops['schema_version'] == 'compiled_F4_wishbone_exact_hops.v1'
        assert hops['proof_scope'] == (
            'selected_F4_image_consumption_native_wishbone_route_native_'
            'wishbone_storage_and_CPU_readback_RAM')
        assert len(hops['instruction_hops']) == 8
        assert len(hops['data_hops']) == 2
        assert len(hops['edges']) == 2
        assert [edge['status'] for edge in hops['edges']] == [
            'certified', 'certified']
        assert [edge['relation'] for edge in hops['edges']] == [
            'persistent_state', 'mmio_route']
        assert [hop['address'] for hop in hops['instruction_hops']] == [
            0, 4, 8, 12, 16, 20, 24, 28]
        assert all(hop['channel'] == 'instr'
                   for hop in hops['instruction_hops'])
        # The SW and LW fetches precede their real data acceptances.
        assert (hops['instruction_hops'][4]['response_event']
                < hops['data_hops'][0]['native_acceptance_event'])
        assert (hops['instruction_hops'][5]['response_event']
                < hops['data_hops'][1]['native_acceptance_event'])
        write_hop, read_hop = hops['data_hops']
        assert (write_hop['write'], read_hop['write']) == (True, False)
        assert write_hop['native_wishbone']['value'] == VALUE
        assert write_hop['native_wishbone']['byte_enable'] == 15
        assert read_hop['native_wishbone']['rdata'] == VALUE
        for hop in hops['data_hops']:
            assert hop['acceptance_event'] < hop['delivery_event']
            assert hop['delivery_event'] < hop['native_response_event']
            assert hop['native_wishbone']['address'] == 0x60000000
            assert hop['source_transaction']['channel_id'] == 'data'
            assert hop['source_transaction']['source_epoch'] == 0
        ram = hops['ram_write_hop']
        assert ram['address'] == 0x2FFFC
        assert ram['value'] == VALUE
        assert ram['byte_enable'] == 15
        assert ram['memory_id'] == 'ram'
        assert ram['version'][1] >= 1
        assert ram['transaction']['channel_id'] == 'data'
        assert (ram['transaction']['source_sequence']
                == read_hop['source_transaction']['source_sequence'] + 1)
        assert ram['producer_event_id'] == ram['native_acceptance_event']
        assert read_hop['native_response_event'] < ram['native_acceptance_event']
        assert (ram['native_acceptance_event'] < ram['memory_write_event']
                < ram['native_response_event'])
        # The declared native storage probes are the measured Wishbone shape.
        write_join, read_join = certificate['joins']
        assert (write_join['write'], read_join['write']) == (True, False)
        assert write_join['native_ack_event'] > write_join['native_wishbone_event']
        assert read_join['native_ack_event'] > read_join['native_wishbone_event']
        assert [row['expectation_id'] for row in certificate['assertions']] == [
            'protocol_checker.receipt_violations',
            'cross_component.declared_edge_hops',
            'cross_component.chain_certificate_hops',
            'cross_component.readback_ram_write_hop']
        assert all(row['status'] == 'passed'
                   for row in certificate['assertions'])
        assert 'APB' not in json.dumps(certificate)
        assert 'OBI' not in json.dumps(certificate)

        # --- the same persistent chain, one more case -----------------
        assert {name: session.process.pid
                for name, session in runtime.runner.sessions.items()} == pids
        second = runtime.submit(raw)
        assert second['schema_version'] == 'compiled_F4_wishbone_chain.v1'
        assert second['runtime_admitted'] is True
        assert second['prerequisite']['value'] == VALUE
        assert second['prerequisite']['write_count'] == 1
        assert second['postcondition']['value'] == VALUE
        assert second['postcondition']['write_count'] == 2
        assert second['commit']['before'] == VALUE
        assert second['commit']['after'] == VALUE
        assert second['case_id'] == 'compiled-f4-wishbone-real:1'
        assert second['instruction_address'] == 48
        assert {name: session.process.pid
                for name, session in runtime.runner.sessions.items()} == pids
        assert runtime.feedback() == {
            'cases': 2, 'certified': 2, 'distinct_values': 1,
            'changed_versions': 1}

        # --- the prefix and its fresh-process reproduction ------------
        prefix = runtime.finish()
        assert prefix['schema_version'] == 'compiled_F4_wishbone_prefix.v1'
        assert prefix['run_id'] == 'compiled-f4-wishbone-real'
        assert prefix['rounds_per_case'] == 128
        assert prefix['max_cases'] == 4
        assert len(prefix['records']) == 2
        assert [record['value'] for record in prefix['records']] == [
            VALUE, VALUE]
        assert [record['raw'] for record in prefix['records']] == [
            raw.hex(), raw.hex()]
        assert prefix['producer_binding']['row'] == (
            'generic_wishbone_storage_abi')
        assert prefix['execution_binding']['protocol'] == 'wishbone'
        assert prefix['execution_binding_sha256'] == (
            runtime.execution_binding.digest)
        assert prefix['feedback'] == runtime.feedback()
        assert prefix['artifact_digests'] == {
            name: artifact.runtime_document['artifact_digest']
            for name, artifact in runtime.artifacts.items()}
        assert type(prefix['semantic_hash']) is str
        assert len(prefix['semantic_hash']) == 64
        assert prefix['online_plan']['instruction_slots'] == [
            ['processor', 0, (0x2FFFC - 0) // 4]]
        assert len(prefix['online_plan']['cases']) == 2
        assert [case['source']['address'] for case in
                prefix['online_plan']['cases']] == [0, 48]
        assert all(case['source']['kind'] == 'bound_instruction'
                   for case in prefix['online_plan']['cases'])

        replay = runtime.replay(prefix)
        assert replay['matches'] is True
        assert replay['verification_scope'] == 'full'
        assert replay['expected_semantic_hash'] == prefix['semantic_hash']
        assert replay['actual_semantic_hash'] == prefix['semantic_hash']
        assert replay['actual_prefix']['schema_version'] == (
            'compiled_F4_wishbone_prefix.v1')
        assert [record['certificate']['postcondition']['write_count']
                for record in replay['actual_prefix']['records']] == [1, 2]
        # A fresh process really is fresh: new pids, new execution nonces.
        original = runtime.execution_audit()['identities']
        fresh = replay['fresh_build']['execution_audit']['identities']
        assert set(fresh) == set(original)
        assert {row['pid'] for row in fresh.values()}.isdisjoint(
            {row['pid'] for row in original.values()})
        assert {row['execution_nonce'] for row in fresh.values()}.isdisjoint(
            {row['execution_nonce'] for row in original.values()})

        # The process-local routed access nonce is normalised, not rewritten.
        from myfuzz.integration.compiled_wishbone_f4 import (
            wishbone_normalized_semantic_sha256)
        assert wishbone_normalized_semantic_sha256(
            'complete', (), {}) != wishbone_normalized_semantic_sha256(
            'complete', ({'target_access_id': 'wishbone-storage:a:1'},), {})
        assert wishbone_normalized_semantic_sha256(
            'complete', ({'target_access_id': 'wishbone-storage:a:1'},),
            {}) == wishbone_normalized_semantic_sha256(
            'complete', ({'target_access_id': 'wishbone-storage:b:1'},), {})
    finally:
        for session in runtime.runner.sessions.values():
            if session.process is not None:
                session.end_case()
