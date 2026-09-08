"""Contract plan identity and deterministic coherent execution."""

from dataclasses import replace
import json

import pytest

from myfuzz.composition.contract_transducer import (
    ContractRuntime,
    compile_contract_transducer,
)
from myfuzz.composition.cycle_input import TestHeader
from myfuzz.composition.protocol_transducer import ProcessorBeatRequest
from myfuzz.contracts import content_hash
from myfuzz.isa.constraints import IsaContract
from myfuzz.isa.transducer import RiscvInstructionTransducer


def plan_for(**kwargs):
    values = dict(
        isa=IsaContract(32, ("I", "M", "C"), instruction_alignment=2),
        protocol=("processor-memory-beat", "1"),
        address_width=32, data_width=32,
        memory_domains={"instruction_memory_master": "main", "data_memory_master": "main"},
    )
    values.update(kwargs)
    return compile_contract_transducer(**values)


def header_for(plan, **kwargs):
    values = dict(schema_version="test_header.v1", layout_hash=plan.cycle_layout.layout_hash,
                  contract_hash=plan.contract_hash, reset_cycles=2, execution_cycles=100,
                  boot_address=0x80, hart_id=0)
    values.update(kwargs)
    return TestHeader(**values)


def raw(plan, **fields):
    assert set(fields) <= {field.name for field in plan.cycle_layout.fields}
    return sum(fields.get(field.name, 0) << field.raw_lo for field in plan.cycle_layout.fields)


def request(address=0x80, function="instruction_memory_master", domain="main", **kwargs):
    return ProcessorBeatRequest(address=address, function=function, domain=domain, **kwargs)


def runtime_for(plan=None):
    plan = plan or plan_for()
    runtime = ContractRuntime(plan)
    runtime.begin_test(header_for(plan))
    return runtime


def transact(runtime, req, **fields):
    accepted = runtime.step(raw(runtime.plan, response_choice=1), req)
    assert accepted.req_ready and not accepted.rsp_valid
    return runtime.step(raw(runtime.plan, response_choice=2, **fields), None)


def test_instruction_initializes_from_response_cycle_and_repeats_stored_word():
    runtime = runtime_for()
    runtime.step(raw(runtime.plan, response_choice=1, instruction_payload=0x1234), request())
    first = runtime.step(raw(runtime.plan, response_choice=2,
                             instruction_selector=32, instruction_payload=0xABCD1234), None)
    expected = RiscvInstructionTransducer(runtime.plan.isa).repair(32, 0xABCD1234).word
    assert first.rsp_valid and first.response_data == expected
    assert first.response_data_source == "stored"
    second = transact(runtime, request(), instruction_selector=255, instruction_payload=0xFFFFFFFF)
    assert second.response_data == first.response_data


def test_data_reads_use_raw_response_data_and_shared_domain_preserves_instruction():
    runtime = runtime_for()
    first = transact(runtime, request(), instruction_payload=0xABCDE000)
    data = transact(runtime, request(function="data_memory_master"), response_data=0x11111111)
    assert data.response_data == first.response_data
    new_data = transact(runtime, request(0x90, "data_memory_master"), response_data=0xDEADBEEF)
    assert new_data.response_data == 0xDEADBEEF
    instruction = transact(runtime, request(0x90), instruction_payload=0)
    assert instruction.response_data == 0xDEADBEEF


def test_data_writes_update_enabled_bytes_only_on_successful_response():
    runtime = runtime_for()
    req = request(function="data_memory_master")
    transact(runtime, req, response_data=0x11223344)
    write = replace(req, write=True, write_data=0xAABBCCDD, byte_enable=0b0101)
    transact(runtime, write)
    assert transact(runtime, req).response_data == 0x11BB33DD
    runtime.step(raw(runtime.plan, response_choice=1), replace(write, write_data=0))
    failure = runtime.step(raw(runtime.plan, response_choice=6), None)
    assert failure.rsp_error
    assert transact(runtime, req).response_data == 0x11BB33DD


def test_error_read_does_not_initialize_memory():
    runtime = runtime_for()
    req = request(function="data_memory_master")
    runtime.step(raw(runtime.plan, response_choice=1), req)
    failure = runtime.step(raw(runtime.plan, response_choice=6, response_data=10), None)
    assert failure.rsp_error and failure.response_data_source == "error"
    assert transact(runtime, req, response_data=20).response_data == 20


def test_reset_preserves_memory_while_begin_test_clears_memory_and_protocol():
    runtime = runtime_for()
    req = request(function="data_memory_master")
    transact(runtime, req, response_data=10)
    runtime.step(raw(runtime.plan, response_choice=1), request(0x90))
    reset_result = runtime.step(0, {"reset": True})
    assert not reset_result.rsp_valid
    assert not runtime.step(raw(runtime.plan, response_choice=2), None).rsp_valid
    assert transact(runtime, req, response_data=20).response_data == 10
    runtime.step(raw(runtime.plan, response_choice=1), req)
    runtime.begin_test(header_for(runtime.plan))
    assert not runtime.step(raw(runtime.plan, response_choice=2), None).rsp_valid
    assert transact(runtime, req, response_data=20).response_data == 20


def test_external_functional_inputs_have_independent_contiguous_fields():
    plan = plan_for(external_inputs={"interrupt": 5, "debug": 1})
    fields = {field.name: field for field in plan.cycle_layout.fields}
    assert fields["instruction_selector"].width == 8
    assert fields["instruction_selector"].raw_hi < fields["instruction_payload"].raw_lo
    result = runtime_for(plan).step(raw(plan, **{"external.interrupt": 21, "external.debug": 1}), None)
    assert result.external_inputs == {"interrupt": 21, "debug": 1}
    assert plan.contract_hash == plan_for(external_inputs={"debug": 1, "interrupt": 5}).contract_hash


def test_plan_hash_is_canonical_cpu_name_independent_and_covers_semantics():
    profiles = [dict(name=name, xlen=32, extensions=("I", "M", "C"), alignment=2)
                for name in ("cpu_a", "totally_renamed_cpu")]
    plans = [plan_for(isa=IsaContract(profile["xlen"], profile["extensions"],
                                    instruction_alignment=profile["alignment"]))
             for profile in profiles]
    assert plans[0].document() == plans[1].document()
    assert all(profile["name"] not in json.dumps(plans[0].document()) for profile in profiles)
    document = plans[0].document()
    assert document.pop("contract_hash") == content_hash(document)
    assert plan_for(max_wait_cycles=3).contract_hash != plans[0].contract_hash
    assert plan_for(allow_error=False).contract_hash != plans[0].contract_hash
    assert plan_for(isa=IsaContract(32, ("C", "M", "I"), instruction_alignment=2)).contract_hash == plans[0].contract_hash
    assert plan_for(memory_domains=dict(reversed(plans[0].memory_domains))).contract_hash == plans[0].contract_hash


def test_equal_input_produces_equal_trace():
    def trace():
        runtime = runtime_for(plan_for(max_wait_cycles=2))
        return [runtime.step(value, req) for value, req in (
            (0, request()), (0, request()), (0, None), (0, None),
            (raw(runtime.plan, response_choice=1), request()),
            (raw(runtime.plan, response_choice=6), None),
        )]
    assert trace() == trace()


def test_capacity_exhaustion_errors_without_evicting_and_test_boundary_frees_entries():
    runtime = runtime_for(plan_for(memory_capacity_entries=1, allow_error=False))
    req = request(function="data_memory_master")
    assert transact(runtime, req, response_data=10).response_data == 10
    for new_req in (replace(req, address=0x90),
                    replace(req, address=0x90, write=True, write_data=20)):
        full = transact(runtime, new_req, response_data=20)
        assert full.rsp_valid and full.rsp_error and full.rsp_data == 0
        assert full.response_data_source == "capacity_error"
    assert transact(runtime, req, response_data=30).response_data == 10
    runtime.reset_dut()
    assert transact(runtime, replace(req, address=0x90)).rsp_error
    runtime.begin_test(header_for(runtime.plan))
    assert transact(runtime, replace(req, address=0x90), response_data=40).response_data == 40
    assert runtime.plan.contract_hash != plan_for(memory_capacity_entries=2, allow_error=False).contract_hash
    assert runtime.plan.document()["memory_addressing"] == "aligned_beat_base_byte_enable_lanes"


def test_memory_keys_align_beats_and_domains_are_isolated():
    plan = plan_for(memory_capacity_entries=2, memory_domains={
        "instruction_memory_master": "code", "data_memory_master": "data",
    })
    runtime = runtime_for(plan)
    data = request(0x81, "data_memory_master", "data")
    assert transact(runtime, data, response_data=0x11223344).response_data == 0x11223344
    assert transact(runtime, replace(data, address=0x83), response_data=0).response_data == 0x11223344
    transact(runtime, replace(data, address=0x82, write=True, write_data=0xAA0000, byte_enable=4))
    assert transact(runtime, data).response_data == 0x11AA3344
    instruction = transact(runtime, request(0x80, domain="code"), instruction_payload=0)
    assert not instruction.rsp_error and instruction.response_data != 0x11AA3344
    assert transact(runtime, replace(data, address=0xFFFFFFFF), response_data=1).rsp_error


def test_protocol_error_does_not_consume_capacity():
    runtime = runtime_for(plan_for(memory_capacity_entries=1))
    req = request(function="data_memory_master")
    runtime.step(raw(runtime.plan, response_choice=1), req)
    assert runtime.step(raw(runtime.plan, response_choice=6), None).rsp_error
    assert not transact(runtime, replace(req, address=0x90)).rsp_error


def test_64_bit_beats_preserve_upper_raw_response_bits_and_share_bytes():
    runtime = runtime_for(plan_for(data_width=64))
    value = transact(runtime, request(), instruction_payload=0x123400,
                     response_data=0x12345678_DEADBEEF).response_data
    assert value >> 32 == 0x12345678
    assert transact(runtime, request(0x84, "data_memory_master")).response_data == value


def test_illegal_header_flag_selects_illegal_template_only_when_requested():
    runtime = runtime_for()
    runtime.begin_test(header_for(runtime.plan, illegal_instruction=True))
    response = transact(runtime, request(), instruction_selector=255, instruction_payload=0xFFFFFFFF)
    assert not runtime.instruction.provider.is_legal_word(response.response_data)


@pytest.mark.parametrize("capacity", [0, -1, True, 1.5])
def test_capacity_must_be_positive_integer(capacity):
    with pytest.raises(ValueError):
        plan_for(memory_capacity_entries=capacity)


@pytest.mark.parametrize("changes", [{"protocol": ("OBI", "1")},
                                       {"protocol": ("processor-memory-beat", "2")},
                                       {"address_width": 0}, {"data_width": 24},
                                       {"memory_domains": {}},
                                       {"memory_domains": {"unknown": "main"}},
                                       {"external_inputs": {"irq": 0}}])
def test_compiler_rejects_unsupported_or_incomplete_contract(changes):
    with pytest.raises(ValueError):
        plan_for(**changes)


def test_rejects_missing_begin_test_invalid_headers_and_raw_width():
    plan = plan_for()
    runtime = ContractRuntime(plan)
    with pytest.raises(ValueError, match="begin_test"):
        runtime.step(0, None)
    for changes in ({"layout_hash": "wrong"}, {"contract_hash": "wrong"},
                    {"boot_address": 1 << 32}, {"boot_address": 1}):
        with pytest.raises(ValueError):
            runtime.begin_test(header_for(plan, **changes))
    runtime.begin_test(header_for(plan))
    for value in (-1, True, 1 << plan.cycle_layout.raw_width):
        with pytest.raises(ValueError):
            runtime.step(value, None)


@pytest.mark.parametrize("req", [request(domain="other"), request(function="unknown"),
                                request(1 << 32),
                                request(write=True), request(write_data=1 << 32),
                                request(byte_enable=16)])
def test_runtime_rejects_invalid_request_before_changing_state(req):
    runtime = runtime_for()
    with pytest.raises(ValueError):
        runtime.step(raw(runtime.plan, response_choice=1), req)
    assert runtime.protocol.state.pending is None
