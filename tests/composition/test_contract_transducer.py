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
    values = dict(schema_version="cycle_test.v1", layout_hash=plan.cycle_layout.layout_hash,
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
    assert instruction.rsp_error and instruction.response_data == 0
    assert instruction.response_data_source == "provenance_error"
    assert transact(runtime, request(0x90, "data_memory_master")).response_data == 0xDEADBEEF


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


def test_64_bit_instruction_beats_fill_both_slots_and_share_bytes():
    runtime = runtime_for(plan_for(data_width=64))
    value = transact(runtime, request(), instruction_payload=0x123400,
                     response_data=0x12345678_DEADBEEF).response_data
    assert runtime.instruction.provider.is_legal_word(value >> 32)
    assert runtime.instruction.provider.is_legal_word(value & 0xFFFFFFFF)
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


@pytest.mark.parametrize("data_width", [32, 64])
@pytest.mark.parametrize("has_c", [False, True])
@pytest.mark.parametrize("compressed", [False, True])
def test_full_instruction_beat_has_independently_repaired_legal_slots(data_width, has_c, compressed):
    isa = IsaContract(32, ("I", "M", "C") if has_c else ("I", "M"),
                      instruction_alignment=2 if has_c else 4)
    runtime = runtime_for(plan_for(isa=isa, data_width=data_width))
    width = 16 if has_c and compressed else 32
    payload = 0xA55ADEAD1234BCDE & ((1 << data_width) - 1)
    fields = {"instruction_payload": payload}
    selectors = (19, 92, 177, 238)
    for index in range(data_width // (16 if has_c else 32)):
        fields["instruction_selector" if index == 0 else f"instruction_selector_{index}"] = selectors[index]
    if has_c:
        fields["instruction_compressed"] = int(compressed)
    for field_name in fields:
        assert field_name in {field.name for field in runtime.plan.cycle_layout.fields}
    result = transact(runtime, request(), **fields)
    for index in range(data_width // width):
        word = (result.response_data >> (index * width)) & ((1 << width) - 1)
        slot_payload = (payload >> (index * width)) & ((1 << width) - 1)
        expected = runtime.instruction.repair(selectors[index], slot_payload, width=width).word
        assert word == expected
        assert runtime.instruction.provider.is_legal_word(word, compressed=width == 16)
    assert transact(runtime, request(), instruction_payload=0).response_data == result.response_data


@pytest.mark.parametrize("data_width", [32, 64])
@pytest.mark.parametrize("raw_mode", [0, 1])
def test_halfword_boot_address_forces_complete_compressed_beat(data_width, raw_mode):
    runtime = runtime_for(plan_for(data_width=data_width))
    runtime.begin_test(header_for(runtime.plan, boot_address=0x82))
    assert "instruction_compressed" in {field.name for field in runtime.plan.cycle_layout.fields}
    result = transact(runtime, request(0x82), instruction_compressed=raw_mode,
                      instruction_payload=(1 << data_width) - 1)
    assert not result.rsp_error
    for offset in range(0, data_width, 16):
        assert runtime.instruction.provider.is_legal_word(
            (result.response_data >> offset) & 0xFFFF, compressed=True)
    assert transact(runtime, request(0x82), instruction_payload=0).response_data == result.response_data


def test_provenance_conflict_error_survives_reset_and_ignores_random_error_disable():
    runtime = runtime_for(plan_for(allow_error=False))
    data = request(function="data_memory_master")
    transact(runtime, data, response_data=0xDEADBEEF)
    runtime.reset_dut()
    result = transact(runtime, request())
    assert result.rsp_error and result.response_data == 0
    assert runtime.memory_provenance[("main", 0x80)] == "data_generated"
    assert transact(runtime, data).response_data == 0xDEADBEEF
    runtime.begin_test(header_for(runtime.plan))
    assert not runtime.memory_provenance
    instruction = transact(runtime, request())
    assert not instruction.rsp_error
    assert runtime.memory_provenance[("main", 0x80)] == "instruction_generated"


@pytest.mark.parametrize("initialize_first", [False, True])
def test_cpu_written_memory_returns_exact_contents_when_executed(initialize_first):
    runtime = runtime_for()
    data = request(function="data_memory_master")
    if initialize_first:
        transact(runtime, data, response_data=0xDEADBEEF)
    transact(runtime, replace(data, write=True, write_data=0x12345678))
    fetched = transact(runtime, request(), instruction_payload=0)
    assert not fetched.rsp_error and fetched.response_data == 0x12345678
    assert runtime.memory_provenance[("main", 0x80)] == "cpu_written"


def test_partial_cpu_write_keeps_unwritten_instruction_bytes():
    runtime = runtime_for()
    initial = transact(runtime, request()).response_data
    transact(runtime, request(function="data_memory_master", write=True,
                              write_data=0xAA00, byte_enable=2))
    fetched = transact(runtime, request())
    assert not fetched.rsp_error and fetched.response_data == (initial & ~0xFF00) | 0xAA00
    assert runtime.memory_provenance[("main", 0x80)] == "cpu_written"


def test_zero_lane_write_does_not_bypass_data_provenance_error():
    runtime = runtime_for()
    data = request(function="data_memory_master")
    transact(runtime, data, response_data=0xDEADBEEF)
    transact(runtime, replace(data, write=True, byte_enable=0))
    assert transact(runtime, request()).rsp_error


def test_zero_lane_write_to_new_address_does_not_allocate_or_consume_capacity():
    runtime = runtime_for(plan_for(memory_capacity_entries=1))
    transact(runtime, request(function="data_memory_master", write=True, byte_enable=0))
    assert not runtime.memory_provenance
    result = transact(runtime, request(0x90))
    assert not result.rsp_error
    assert runtime.memory_provenance == {("main", 0x90): "instruction_generated"}


def test_new_partial_cpu_write_never_repairs_written_bytes_on_fetch():
    runtime = runtime_for()
    transact(runtime, request(function="data_memory_master", write=True,
                              write_data=0xAA00, byte_enable=2))
    first = transact(runtime, request(), response_data=0x12345678)
    assert not first.rsp_error and first.response_data == 0x1234AA78
    assert transact(runtime, request(), response_data=0xFFFFFFFF).response_data == 0x1234AA78


@pytest.mark.parametrize("version", ["test_header.v1", "cycle_test.v2", "unknown"])
def test_begin_test_rejects_unsupported_header_version_without_clearing_memory(version):
    runtime = runtime_for()
    data = request(function="data_memory_master")
    transact(runtime, data, response_data=7)
    header = header_for(runtime.plan)
    object.__setattr__(header, "schema_version", version)
    with pytest.raises(ValueError, match="schema version"):
        runtime.begin_test(header)
    assert transact(runtime, data, response_data=9).response_data == 7


@pytest.mark.parametrize("data_width,has_c,count", [(32, False, 1), (32, True, 2),
                                                   (64, False, 2), (64, True, 4)])
def test_slot_selectors_are_separate_declared_hash_bound_fields(data_width, has_c, count):
    isa = IsaContract(32, ("I", "C") if has_c else ("I",),
                      instruction_alignment=2 if has_c else 4)
    plan = plan_for(isa=isa, data_width=data_width, external_inputs={"external_signal": 5})
    selectors = [field for field in plan.cycle_layout.fields if field.name.startswith("instruction_selector")]
    assert len(selectors) == count and all(field.width == 8 for field in selectors)
    fields = {field.name: field for field in plan.cycle_layout.fields}
    assert fields["instruction_payload"].width == data_width
    assert ("instruction_compressed" in fields) == has_c
    assert len(plan.document()["cycle_layout"]["fields"]) == len(fields)
    assert all(field.raw_hi < fields["external.external_signal"].raw_lo for field in selectors)
