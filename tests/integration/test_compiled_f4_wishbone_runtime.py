"""Software-only G8.1 Wishbone F4 executor: admission, support, dispatch, kernel.

These controls exercise the sibling ``compiled_f4_wishbone`` executor on the
real ``compiled-f4-obi-wb-uart-setup`` D2/D3 documents and on the APB fixtures
the existing APB executor already owns.  No RTL command is executed: the
admission/support/dispatch checks never start a native process, and the one
construction control explicitly defers ``begin`` so no session is begun.

The executor id is not a claim: this file is not a G8.1 PASS and never records
one.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
WB_CONFIG = ROOT / 'configs/scenarios/compiled-f4-obi-wb-uart-setup'
TIMER_CONFIG = ROOT / 'configs/scenarios/compiled-f4-obi-apb-timer'
SPI_CONFIG = ROOT / 'configs/scenarios/compiled-f4-obi-apb-spi-cv32e40p'
REGISTER = 'SETUP'
CONTRACT = 'zipcpu-wbuart.setup.storage.v1'
VALUE = 0x0055A5A5
RESULT_ADDRESS = 0x2FFFC


def _generate(config, output):
    """The source-only D2/D3 path used by the sibling real-source tests."""
    from myfuzz.local_harness.auto_harness_test import (
        build_path_compile_request, load_composition)
    from myfuzz.local_harness.generated_artifact_admission import (
        load_generated_artifacts)
    from myfuzz.local_harness.harness_set import generate_harness_set, load_compose
    from myfuzz.scenario.compiled_paths import compile_paths, load_path_compile_request
    from myfuzz.scenario.ownership import compile_ownership

    generated = Path(output) / 'generated'
    compose = load_compose(config / 'compose.json', base_dir=ROOT)
    generate_harness_set(compose, base_dir=ROOT, compose_base=config,
                         output_root=generated)
    composition = load_composition(config / 'compose.json', base_dir=ROOT)
    document, sidecars = build_path_compile_request(composition,
        wiring_path=generated / 'wiring_contract.json',
        ip_capabilities=[config / 'test_capability.json'])
    request = load_path_compile_request(document, base_dir=ROOT)
    compiled = compile_paths(request)
    artifacts = load_generated_artifacts(generated_root=generated, base_dir=ROOT)
    inputs = dict(request=request, compiled=compiled,
                  ownership=compile_ownership((), ()), physical_port_map={})
    return generated, sidecars, artifacts, inputs


@pytest.fixture(scope='module')
def wishbone_d2_d3(tmp_path_factory):
    return _generate(WB_CONFIG, tmp_path_factory.mktemp('compiled-f4-wb-runtime'))


@pytest.fixture(scope='module')
def timer_d2_d3(tmp_path_factory):
    return _generate(TIMER_CONFIG, tmp_path_factory.mktemp('compiled-f4-apb-timer'))


@pytest.fixture(scope='module')
def spi_d2_d3(tmp_path_factory):
    return _generate(SPI_CONFIG, tmp_path_factory.mktemp('compiled-f4-apb-spi'))


def _f4_path(compiled):
    paths = [path for path in compiled['paths']
             if path['flow_id'] == 'F4' and path['status'] == 'executable']
    assert len(paths) == 1
    return paths[0]


def _admit(generated, *, artifacts=None, compiled_inputs=None):
    from myfuzz.integration.compiled_wishbone_f4 import admit_wishbone_f4
    _generated, _sidecars, loaded, inputs = generated
    return admit_wishbone_f4(
        artifacts=loaded if artifacts is None else artifacts,
        compiled_inputs=inputs if compiled_inputs is None else compiled_inputs,
        base_dir=ROOT)


def _refused(generated, expected, *, artifacts=None, compiled_inputs=None):
    _generated, _sidecars, loaded, inputs = generated
    with pytest.raises(ValueError, match=expected):
        _admit(generated, artifacts=artifacts, compiled_inputs=compiled_inputs)


# --- the real documents ----------------------------------------------------

def test_admits_the_real_wishbone_d2_d3_documents(wishbone_d2_d3):
    from myfuzz.integration.compiled_wishbone_f4 import (
        PROOF_SCOPE, WishboneF4ExecutionBinding,
        derive_wishbone_f4_execution_binding, wishbone_admission,
        wishbone_cpu_traces)
    from myfuzz.integration.compiled_storage_producer import (
        ROW_GENERIC_WISHBONE_STORAGE)

    generated, sidecars, artifacts, inputs = wishbone_d2_d3
    assert sidecars == [{
        'instance_id': 'peripheral',
        'profile': 'configs/peripherals/zipcpu_uart_storage/component_profile.json',
        'test_capability':
            'configs/scenarios/compiled-f4-obi-wb-uart-setup/test_capability.json',
        'source': 'declared-option'}]
    assert artifacts['processor'].runtime_document['kind'] == 'wishbone_cpu'
    assert artifacts['peripheral'].runtime_document['kind'] == (
        'wishbone_register_observe')

    admitted = wishbone_admission(artifacts=artifacts, compiled_inputs=inputs,
                                  base_dir=ROOT)
    path = admitted['path']
    layout = admitted['layout']
    binding = admitted['producer_binding']
    assert path['path_id'] == 'F4:ram.image'
    assert binding.row == ROW_GENERIC_WISHBONE_STORAGE
    assert binding.document()['template'] == {
        'template_id': 'target.wishbone', 'template_version': '1',
        'variant_id': 'word-addressed-registered-ack'}
    assert [(source['kind'], source['source_id']) for source in path['sources']] == [
        ('instruction_image', 'ram.image'),
        ('cpu_mmio_stream', 'peripheral.SETUP.value.mmio')]
    access = path['sources'][1]['register_access']
    assert access['register'] == REGISTER
    assert access['address'] == 0x60000000
    assert access['register_offset'] == 0
    assert access['window_base'] == 0x60000000
    assert access['window_size'] == 16
    assert access['allowed_byte_enables'] == [15]
    assert access['value_mask'] == 0x7FFFFFFF
    assert path['bound_inputs'][0]['kind'] == 'ip_register_commit'
    assert path['bound_inputs'][0]['input_id'] == (
        'peripheral.uart.bus.register.SETUP.value')
    assert [row['kind'] for row in path['prerequisites']] == [
        'ip_register_version']
    assert {row['expectation_id'] for row in path['assertions']} == {
        'protocol_checker.receipt_violations',
        'cross_component.declared_edge_hops',
        'cross_component.chain_certificate_hops'}
    assert path['seed'] is None
    assert path['termination_observation']['kind'] == 'consumption'
    # Candidate layout: one full target word, no pin bits.
    assert layout.byte_length == 4
    assert layout.bit_length == 32
    assert [row.source_id for row in layout.slices] == [
        'peripheral.SETUP.value.mmio']

    image = path['sources'][0]
    stream = path['sources'][1]
    traces = wishbone_cpu_traces(artifacts['processor'], image, stream)
    assert set(traces) == {'instr', 'data'}
    for channel in ('instr', 'data'):
        assert traces[channel] == {
            'cyc': 'wb_cyc', 'stb': 'wb_stb', 'we': 'wb_we', 'adr': 'wb_adr',
            'dat_w': 'wb_dat_w', 'sel': 'wb_sel', 'ack': 'wb_ack',
            'dat_r': 'wb_dat_r'}
        # There is no error role and no stall pin at this CPU boundary.
        assert 'err' not in traces[channel]
        assert 'stall' not in traces[channel]
    assert PROOF_SCOPE == ('selected_F4_image_consumption_native_wishbone_route_'
                           'native_wishbone_storage_and_CPU_readback_RAM')

    execution_binding = derive_wishbone_f4_execution_binding(
        artifacts=artifacts, compiled_inputs=inputs, base_dir=ROOT)
    assert type(execution_binding) is WishboneF4ExecutionBinding
    document = execution_binding.document()
    assert document['schema_version'] == (
        'compiled_F4_wishbone_execution_binding.v1')
    assert document['protocol'] == 'wishbone'
    assert document['binding_sha256'] == execution_binding.digest
    assert 'cpu_error_policy' not in document
    assert 'error_policy' not in document['cpu']
    assert document['cpu']['protocol'] == 'wishbone'
    assert document['cpu']['error_observation'] is False
    assert document['cpu']['wishbone_trace_contract'] == traces
    assert (generated / 'harness_set.json').is_file()


def test_wishbone_target_has_no_error_role_and_no_error_capability(wishbone_d2_d3):
    artifacts = wishbone_d2_d3[2]
    trace = artifacts['peripheral'].runtime_document['base_protocol_trace']
    assert trace['protocol'] == 'wishbone'
    assert set(trace['signals']) == {
        'cyc', 'stb', 'we', 'adr', 'sel', 'dat_w', 'ack', 'dat_r', 'stall'}
    assert 'err' not in trace['signals']
    capabilities = artifacts['processor'].plan.profile.capabilities
    assert capabilities['error_response'] is False
    assert capabilities['address_units'] == 'byte'


# --- named refusals --------------------------------------------------------

@pytest.mark.parametrize(('mutation', 'expected'), (
    ('cpu_kind', 'compiled-F4-wishbone-CPU-artifact-kind-required'),
    ('target_kind', 'compiled-F4-wishbone-target-artifact-kind-required'),
    ('target_protocol', 'compiled-F4-wishbone-target-protocol-unsupported'),
    ('target_error_role', 'compiled-F4-wishbone-error-role-unsupported'),
    ('cpu_error_fact', 'compiled-F4-wishbone-CPU-policy-contract-mismatch'),
    ('template_variant',
     'compiled-F4-wishbone-endpoint-template-unsupported'),
    ('template_outstanding',
     'compiled-F4-wishbone-endpoint-template-unsupported'),
    ('template_id', 'compiled-F4-wishbone-endpoint-template-unsupported'),
))
def test_named_refusals_for_mutated_artifacts(wishbone_d2_d3, mutation,
                                              expected):
    from myfuzz.local_harness.tuning import load_local_harness_tuning

    artifacts = wishbone_d2_d3[2]
    if mutation in ('cpu_kind', 'cpu_error_fact'):
        artifact = artifacts['processor']
        document = deepcopy(artifact.runtime_document)
        if mutation == 'cpu_kind':
            document['kind'] = 'obi_cpu'
            forged = replace(artifact, runtime_document=document)
        else:
            document['selected_template']['executor']['binding'][
                'declared_profile_facts']['error_response'] = True
            forged = replace(artifact, runtime_document=document)
        _refused(wishbone_d2_d3, expected,
                 artifacts={**artifacts, 'processor': forged})
        return
    artifact = artifacts['peripheral']
    if mutation in ('template_variant', 'template_outstanding', 'template_id'):
        tuning = deepcopy(artifact.plan.request.tuning.document())
        policy = tuning['endpoint_policies'][0]
        if mutation == 'template_variant':
            policy['variant_id'] = 'addressless-select-ignored'
        elif mutation == 'template_outstanding':
            policy['max_outstanding'] = 2
        else:
            policy['template_id'] = 'target.apb3'
        forged_plan = replace(artifact.plan,
            request=replace(artifact.plan.request,
                            tuning=load_local_harness_tuning(tuning)))
        _refused(wishbone_d2_d3, expected,
                 artifacts={**artifacts, 'peripheral': replace(
                     artifact, plan=forged_plan)})
        return
    document = deepcopy(artifact.runtime_document)
    if mutation == 'target_kind':
        document['kind'] = 'apb3_register_observe'
    elif mutation == 'target_protocol':
        document['base_protocol_trace']['protocol'] = 'apb3'
    else:
        document['base_protocol_trace']['signals']['err'] = 'trace_err'
        document['base_protocol_trace']['signal_widths']['err'] = 1
    _refused(wishbone_d2_d3, expected,
             artifacts={**artifacts, 'peripheral': replace(
                 artifact, runtime_document=document)})


def test_no_apb_or_obi_fallback_is_ever_used(wishbone_d2_d3, spi_d2_d3):
    """Every Wishbone refusal is this row's own name, never the APB executor's."""
    wishbone_artifacts = wishbone_d2_d3[2]
    spi_artifacts = spi_d2_d3[2]
    # A foreign artifact mapping is refused by the artifact-identity gate
    # before any kind/row check can even run.
    _refused(wishbone_d2_d3, 'compiled-F4-wishbone-runtime-input-refused',
             artifacts={**wishbone_artifacts,
                        'peripheral': spi_artifacts['peripheral']})
    # The exact APB/OBI kinds are refused with this row's named refusals, and
    # the APB admission's own code never appears.
    for artifact_key, kind, expected in (
            ('processor', 'obi_cpu',
             'compiled-F4-wishbone-CPU-artifact-kind-required'),
            ('peripheral', 'apb3_register_observe',
             'compiled-F4-wishbone-target-artifact-kind-required')):
        artifact = wishbone_artifacts[artifact_key]
        document = deepcopy(artifact.runtime_document)
        document['kind'] = kind
        with pytest.raises(ValueError) as refused:
            _admit(wishbone_d2_d3, artifacts={
                **wishbone_artifacts,
                artifact_key: replace(artifact, runtime_document=document)})
        assert expected in str(refused.value)
        assert 'compiled-F4-CPU-protocol-unsupported' not in str(refused.value)
        assert 'compiled-F4-producer' not in str(refused.value)


def test_external_pin_rule_refuses_any_external_source():
    from myfuzz.integration.compiled_wishbone_f4 import _require_no_external_pins
    _require_no_external_pins({'sources': [
        {'kind': 'instruction_image'}, {'kind': 'cpu_mmio_stream'}]})
    with pytest.raises(ValueError, match='compiled-F4-wishbone-external-pin'):
        _require_no_external_pins({'sources': [
            {'kind': 'instruction_image'},
            {'kind': 'cpu_mmio_stream'},
            {'kind': 'external_pin', 'source_id': 'peripheral.rx.external'}]})


def test_missing_receipt_element_is_named(wishbone_d2_d3, monkeypatch):
    from myfuzz.integration import compiled_wishbone_f4 as module
    from myfuzz.integration.compiled_storage_producer import (
        AdmittedStorageProducerBinding, select_storage_producer)

    artifacts, inputs = wishbone_d2_d3[2], wishbone_d2_d3[3]
    binding = select_storage_producer(artifacts=artifacts,
        compiled_inputs=inputs, base_dir=ROOT)
    forged = AdmittedStorageProducerBinding.build({
        **binding.document(),
        'producer': {**binding.document()['producer'],
                     'commit_consumer': 'pending_D2_wishbone_commit_join'}})
    monkeypatch.setattr(module, 'select_storage_producer',
                        lambda **kwargs: forged)
    with pytest.raises(ValueError,
                       match='compiled-F4-wishbone-receipt-join-incomplete:'
                             'cpu_acceptance'):
        module.admit_wishbone_f4(artifacts=artifacts,
                                 compiled_inputs=inputs, base_dir=ROOT)


def test_masked_write_corpus_and_declaration_refusals(wishbone_d2_d3):
    """The reviewed SETUP row stores bits [30:0]: bit 31 is refused first."""
    from myfuzz.integration.wishbone_register_writer import (
        declare_wishbone_writer)

    artifacts, inputs = wishbone_d2_d3[2], wishbone_d2_d3[3]
    stream = next(source for source in _f4_path(inputs['compiled'])['sources']
                  if source['kind'] == 'cpu_mmio_stream')
    declaration = declare_wishbone_writer(inputs['request'],
        inputs['compiled'], source_id=stream['source_id'], value=VALUE,
        result_address=RESULT_ADDRESS)
    assert declaration['candidate']['access']['word_index'] == 0
    assert declaration['candidate']['access']['value_mask'] == 0x7FFFFFFF
    assert declaration['candidate']['value'] == VALUE
    assert declaration['write_policy']['kind'] == (
        'declared_masked_full_word_write')
    assert len(bytes.fromhex(declaration['code_hex'])) == 48
    # A value whose bit 31 is outside the reviewed mask is refused before any
    # native command (the W3 record-corpus constraint).
    with pytest.raises(ValueError,
                       match='wishbone-writer-candidate-reserved-value-bits'):
        declare_wishbone_writer(inputs['request'], inputs['compiled'],
            source_id=stream['source_id'], value=0xAA000000,
            result_address=RESULT_ADDRESS)
    # A tampered compiled document never reaches a declaration.
    tampered = deepcopy(inputs['compiled'])
    next(source for source in _f4_path(tampered)['sources']
         if source['kind'] == 'cpu_mmio_stream')['register_access'][
             'address'] += 8
    with pytest.raises(ValueError, match='compiled-document-mismatch'):
        declare_wishbone_writer(inputs['request'], tampered,
            source_id=stream['source_id'], value=VALUE,
            result_address=RESULT_ADDRESS)
    # The result word must stay inside the declared writable image.
    with pytest.raises(ValueError, match='wishbone-writer-result'):
        declare_wishbone_writer(inputs['request'], inputs['compiled'],
            source_id=stream['source_id'], value=VALUE,
            result_address=0x7FFFFFFC)


# --- support report --------------------------------------------------------

def test_support_report_selects_the_wishbone_executor(wishbone_d2_d3):
    from myfuzz.local_harness.compiled_execution_projection import (
        assess_compiled_f4_support)

    artifacts, inputs = wishbone_d2_d3[2], wishbone_d2_d3[3]
    support = assess_compiled_f4_support(artifacts=artifacts,
        compiled_inputs=inputs, base_dir=ROOT)
    assert support['schema_version'] == 'compiled_F4_support.v1'
    assert support['execution_supported'] == 1
    assert support['runtime_admitted'] is False
    assert support['status'] == 'supported_requires_actual_startup'
    assert support['executor'] == 'compiled_f4_wishbone'
    assert support['path_id'] == 'F4:ram.image'
    assert support['producer_binding']['row'] == 'generic_wishbone_storage_abi'
    assert support['producer_binding']['register']['name'] == REGISTER
    assert support['producer_binding']['template'] == {
        'template_id': 'target.wishbone', 'template_version': '1',
        'variant_id': 'word-addressed-registered-ack'}
    assert support['support_scope'] == (
        'experimental_RV32I_writer_generic_Wishbone_storage_with_live_version_token')
    assert support['startup_requires'] == [
        'native_first_fetch_inside_instruction_image',
        'exact_private_input_readmission',
        'writable_instruction_image_result_word',
        'actual_native_wishbone_storage_version_token']
    assert support['receipt_elements']['complete'] is True
    assert support['receipt_elements']['elements']['version_token']['present'] is True
    assert support['receipt_elements']['row'] == 'generic_wishbone_storage_abi'
    assert [row['path_id'] for row in support['unsupported_paths']] == [
        'F1:ram.image', 'F2:ram.image', 'F3:ram.image', 'F5:processor',
        'F6:processor']
    assert all(row['reason'] == 'compiled-executor-flow-unsupported'
               for row in support['unsupported_paths'])


def test_support_report_refuses_without_the_receipt_join(wishbone_d2_d3,
                                                         monkeypatch):
    from myfuzz.integration import compiled_wishbone_f4 as executor
    from myfuzz.local_harness.compiled_execution_projection import (
        assess_compiled_f4_support)
    from myfuzz.integration.compiled_storage_producer import (
        AdmittedStorageProducerBinding, select_storage_producer)

    artifacts, inputs = wishbone_d2_d3[2], wishbone_d2_d3[3]
    binding = select_storage_producer(artifacts=artifacts,
        compiled_inputs=inputs, base_dir=ROOT)
    forged = AdmittedStorageProducerBinding.build({
        **binding.document(),
        'producer': {**binding.document()['producer'],
                     'commit_consumer': 'pending_D2_wishbone_commit_join'}})
    from myfuzz.integration.generated_wishbone_storage_consumer import (
        wishbone_storage_consumer_support)
    incomplete = wishbone_storage_consumer_support(binding=forged,
                                                   artifacts=artifacts)
    assert incomplete['complete'] is False
    assert [row['element'] for row in incomplete['refusals']] == [
        'cpu_acceptance', 'router_delivery']
    monkeypatch.setattr(executor, 'select_storage_producer',
                        lambda **kwargs: forged)
    support = assess_compiled_f4_support(artifacts=artifacts,
        compiled_inputs=inputs, base_dir=ROOT)
    assert support['execution_supported'] == 0
    assert support['status'] == 'unsupported'
    assert support['executor'] == 'compiled_f4_wishbone'
    assert support['reason'].startswith(
        'compiled-F4-wishbone-receipt-join-incomplete:')
    assert 'cpu_acceptance' in support['reason']
    assert 'version_token' not in support['reason']
    assert support['runtime_admitted'] is False


@pytest.mark.parametrize('fixture_name', ('timer_d2_d3', 'spi_d2_d3'))
def test_apb_fixtures_keep_the_apb_executor(request, fixture_name):
    from myfuzz.local_harness.compiled_execution_projection import (
        assess_compiled_f4_support)
    generated = request.getfixturevalue(fixture_name)
    artifacts, inputs = generated[2], generated[3]
    support = assess_compiled_f4_support(artifacts=artifacts,
        compiled_inputs=inputs, base_dir=ROOT)
    assert support['execution_supported'] == 1
    assert support['executor'] == 'compiled_f4_obi_apb'
    assert support['runtime_admitted'] is False
    assert support['producer_binding']['row'] == 'generic_apb_storage_abi'
    assert support['startup_requires'][-1] == (
        'actual_native_APB_storage_version_token')
    assert 'wishbone' not in json.dumps(support).lower()


# --- dispatch --------------------------------------------------------------

@pytest.fixture(scope='module')
def wishbone_prepared(tmp_path_factory):
    """The real same-pass preparation, including declared fixed-input ownership."""
    from myfuzz.integration.compiled_execution_files import (
        prepare_compiled_execution_inputs)
    directory = tmp_path_factory.mktemp('compiled-f4-wb-prepared')
    prepared = prepare_compiled_execution_inputs(base_dir=ROOT,
        compose_path=WB_CONFIG / 'compose.json',
        capability_paths=(WB_CONFIG / 'test_capability.json',),
        supplement_path=WB_CONFIG / 'execution_supplement.json',
        generated_dir=directory / 'generated', flow_ids=('F4',))
    return directory, prepared


def test_create_compiled_execution_defers_begin_without_a_process(
        wishbone_prepared):
    from myfuzz.integration.compiled_wishbone_f4 import WishboneF4Runtime
    from myfuzz.local_harness.generated_execution_admission import (
        create_compiled_execution)

    directory, prepared = wishbone_prepared
    runtime = create_compiled_execution(
        artifacts=dict(prepared.artifacts),
        compiled_inputs=prepared.inputs,
        executor='compiled_f4_wishbone',
        base_dir=ROOT, cache_dir=directory / 'cache',
        run_id='compiled-f4-wishbone-dispatch', max_cases=4,
        defer_begin=True)
    try:
        assert type(runtime) is WishboneF4Runtime
        assert runtime._begun is False
        assert runtime.first_fetch is None
        assert runtime.cursor is None
        assert set(runtime.runner.sessions) == {'processor', 'peripheral'}
        assert all(session.process is None
                   for session in runtime.runner.sessions.values())
        assert runtime.execution_binding.document()['protocol'] == 'wishbone'
        assert runtime.online_identity_configuration()['producer_row'] == (
            'generic_wishbone_storage_abi')
        assert runtime.feedback() == dict(cases=0, certified=0,
            distinct_values=0, changed_versions=0)
    finally:
        for session in runtime.runner.sessions.values():
            if session.process is not None:
                session.end_case()


def test_create_compiled_execution_refuses_wishbone_for_an_apb_scenario(
        timer_d2_d3, tmp_path):
    from myfuzz.local_harness.generated_execution_admission import (
        create_compiled_execution)

    artifacts, inputs = timer_d2_d3[2], timer_d2_d3[3]
    with pytest.raises(ValueError, match='compiled-F4-wishbone-CPU-artifact-kind'):
        create_compiled_execution(artifacts=artifacts,
            compiled_inputs=inputs, executor='compiled_f4_wishbone',
            base_dir=ROOT, cache_dir=tmp_path / 'cache', defer_begin=True)


def test_unknown_executor_still_refused(wishbone_d2_d3, tmp_path):
    from myfuzz.local_harness.generated_execution_admission import (
        create_compiled_execution)
    artifacts, inputs = wishbone_d2_d3[2], wishbone_d2_d3[3]
    with pytest.raises(Exception) as refused:
        create_compiled_execution(artifacts=artifacts,
            compiled_inputs=inputs, executor='compiled_f4_wishbone_v2',
            base_dir=ROOT, cache_dir=tmp_path / 'cache')
    assert getattr(refused.value, 'code', '') == 'compiled-executor-unsupported'


# --- plan kernel -----------------------------------------------------------

def test_flow_support_and_the_plan_kernel_record_the_wishbone_executor():
    from myfuzz.runtime.compiler import _flow_kernel
    from myfuzz.runtime.preparation import create_preparation
    import tempfile

    with tempfile.TemporaryDirectory(prefix='wb-plan-') as directory:
        context = create_preparation(base_dir=ROOT,
            compose_path=WB_CONFIG / 'compose.json',
            capability_paths=(WB_CONFIG / 'test_capability.json',),
            supplement_path=WB_CONFIG / 'execution_supplement.json',
            generated_dir=Path(directory) / 'generated', flow_ids=('F4',))
        support = context.flow_support('F4')
        assert support['execution_supported'] == 1
        assert support['executor'] == 'compiled_f4_wishbone'
        assert support['runtime_admitted'] is False
        assert support['producer_binding']['row'] == (
            'generic_wishbone_storage_abi')
        kernel = _flow_kernel(context, 'F4', 'F4:ram.image')
        assert kernel['executor'] == 'compiled_f4_wishbone'
        assert kernel['flow_id'] == 'F4'
        assert kernel['support_status'] == 'supported_requires_actual_startup'
        assert kernel['startup_requires'] == [
            'actual_native_wishbone_storage_version_token',
            'exact_private_input_readmission',
            'native_first_fetch_inside_instruction_image',
            'writable_instruction_image_result_word']


def test_flow_executor_rows_keep_the_apb_mapping_and_add_the_sibling():
    from myfuzz.runtime.flows.storage import (
        EXECUTOR_FLOWS, FLOW_EXECUTORS, WISHBONE_FLOW_EXECUTORS,
        CompiledFlowSpec, StorageFlowBackend)

    assert FLOW_EXECUTORS == {'F2': 'compiled_f2_obi_apb',
                              'F4': 'compiled_f4_obi_apb'}
    assert WISHBONE_FLOW_EXECUTORS == {'F4': 'compiled_f4_wishbone'}
    assert EXECUTOR_FLOWS['compiled_f4_obi_apb'] == 'F4'
    assert EXECUTOR_FLOWS['compiled_f4_wishbone'] == 'F4'
    assert EXECUTOR_FLOWS['compiled_f2_obi_apb'] == 'F2'
    assert CompiledFlowSpec(artifacts={}, compiled_inputs={},
        executor='compiled_f4_wishbone', base_dir=ROOT,
        cache_dir=ROOT).flow_id == 'F4'
    with pytest.raises(Exception) as refused:
        StorageFlowBackend(spec=CompiledFlowSpec(artifacts={},
            compiled_inputs={}, executor='compiled_f6_obi_apb',
            base_dir=ROOT, cache_dir=ROOT))
    assert getattr(refused.value, 'code', '') == 'generic-adapter-missing'


def test_plan_compiles_with_word_index_width_for_the_wishbone_row():
    """The plan reports the word-index width, not the byte-window width.

    A word-addressed target publishes only the width of its word index; the
    compiler now derives that width in the endpoint's declared address units
    (16-byte window / 4-byte word = 4 words -> 2 bits) instead of using the
    byte window's own bit count.  The plan must therefore compile, carry
    ``address_width == 2`` on the target endpoint and select the Wishbone
    executor for the F4 kernel.  Byte-addressed rows are covered by the APB
    plan tests and stay unchanged.
    """
    from myfuzz.runtime.compiler import plan_bindings
    from myfuzz.runtime.preparation import create_preparation
    import tempfile

    from myfuzz.runtime.admission import verify_component
    from myfuzz.runtime.compiler import (
        compile_execution_plan, requirement_for_binding)
    from myfuzz.runtime.registry import select_adapter

    with tempfile.TemporaryDirectory(prefix='wb-plan-gap-') as directory:
        context = create_preparation(base_dir=ROOT,
            compose_path=WB_CONFIG / 'compose.json',
            capability_paths=(WB_CONFIG / 'test_capability.json',),
            supplement_path=WB_CONFIG / 'execution_supplement.json',
            generated_dir=Path(directory) / 'generated', flow_ids=('F4',))
        bindings = plan_bindings(context)
        assert [row.role for row in bindings] == ['target', 'cpu'] or \
            [row.role for row in bindings] == ['cpu', 'target']
        components = []
        selections = []
        requirements = []
        by_instance = {}
        for binding in bindings:
            component = by_instance.get(binding.instance_id)
            if component is None:
                component = verify_component(
                    context.artifact(binding.instance_id),
                    preparation=context, base_dir=ROOT)
                by_instance[binding.instance_id] = component
                components.append(component)
            requirement = requirement_for_binding(component, binding)
            requirements.append(requirement)
            selections.append(select_adapter(component, requirement,
                                             preparation=context))
        plan = compile_execution_plan(context, components=tuple(components),
            selections=tuple(selections),
            requirements=tuple(requirements))
        document = plan.document()
        target_rows = [row for component in document['components']
                       for row in component['descriptor']['endpoints']
                       if row['endpoint_id'] == 'uart.bus']
        assert len(target_rows) == 1
        assert target_rows[0]['address_width'] == 2
        assert target_rows[0]['address_units'] == 'word'
        f4_rows = [row for row in document['paths'] if row['flow_id'] == 'F4']
        assert len(f4_rows) == 1
        assert f4_rows[0]['kernel']['executor'] == 'compiled_f4_wishbone'
        assert f4_rows[0]['kernel']['support_status'] == (
            'supported_requires_actual_startup')
        assert plan.identity_sha256
