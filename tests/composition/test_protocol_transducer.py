"""Normalized processor beat acceptance, response and bounded progress."""

import pytest

from myfuzz.composition.protocol_transducer import (
    ProcessorBeatRequest,
    ProcessorBeatTransducer,
    ProtocolState,
)


def request(address=0x80):
    return ProcessorBeatRequest(
        address=address, function="data_memory_master", domain="main"
    )


def test_response_cannot_precede_an_accepted_request():
    tx = ProcessorBeatTransducer(data_width=32, max_wait_cycles=16)
    idle = tx.step(raw_choice=0b111, raw_data=7, request=None)
    assert not idle.req_ready and not idle.rsp_valid and not idle.rsp_error
    accepted = tx.step(0b111, 7, request())
    assert accepted.req_ready and not accepted.rsp_valid
    assert tx.state.pending == request()


def test_single_outstanding_retains_original_request_until_response():
    tx = ProcessorBeatTransducer(data_width=32, max_wait_cycles=4)
    tx.step(1, 3, request())
    stalled = tx.step(1, 4, request(0x84))
    assert not stalled.req_ready and not stalled.rsp_valid
    assert tx.state.pending == request()
    response = tx.step(3, 99, request(0x84))
    assert response.rsp_valid and response.rsp_data == 99
    assert response.response_request == request()
    assert not response.req_ready
    assert tx.state == ProtocolState()
    assert not tx.step(2, 100, None).rsp_valid


def test_response_error_is_contract_controlled():
    for allow_error in (True, False):
        tx = ProcessorBeatTransducer(data_width=32, allow_error=allow_error)
        tx.step(1, 0, request())
        response = tx.step(6, 0xFFFFFFFF, None)
        assert response.rsp_valid and response.rsp_error == allow_error


def test_zero_choices_force_acceptance_and_then_response_within_bound():
    tx = ProcessorBeatTransducer(data_width=32, max_wait_cycles=3)
    assert not tx.step(0, 0, request()).req_ready
    assert not tx.step(0, 0, request()).req_ready
    accepted = tx.step(0, 0, request())
    assert accepted.req_ready and not accepted.rsp_valid
    assert not tx.step(0, 0, None).rsp_valid
    assert not tx.step(0, 0, None).rsp_valid
    assert tx.step(0, 0x123, None).rsp_data == 0x123
    assert tx.state == ProtocolState()


def test_reset_cancels_pending_request_and_acceptance_wait():
    tx = ProcessorBeatTransducer(data_width=32, max_wait_cycles=2)
    tx.step(1, 0, request())
    tx.reset()
    assert tx.state == ProtocolState()
    assert not tx.step(2, 1, None).rsp_valid
    tx.step(0, 0, request())
    tx.step(0, 0, None)
    assert not tx.step(0, 0, request()).req_ready


@pytest.mark.parametrize("kwargs", [{"data_width": 7}, {"data_width": True},
                                    {"data_width": 32, "max_wait_cycles": 0}])
def test_rejects_invalid_configuration(kwargs):
    with pytest.raises(ValueError):
        ProcessorBeatTransducer(**kwargs)


@pytest.mark.parametrize("choice,data", [(-1, 0), (8, 0), (True, 0), (0, -1),
                                         (0, 1 << 32)])
def test_invalid_raw_values_do_not_change_state(choice, data):
    tx = ProcessorBeatTransducer(data_width=32)
    tx.step(1, 0, request())
    previous = tx.state
    with pytest.raises(ValueError):
        tx.step(choice, data, None)
    assert tx.state == previous


@pytest.mark.parametrize("kwargs", [{"address": -1}, {"function": ""},
                                    {"domain": ""}, {"write": 1}])
def test_request_requires_explicit_valid_semantics(kwargs):
    values = dict(address=0, function="data_memory_master", domain="main")
    values.update(kwargs)
    with pytest.raises(ValueError):
        ProcessorBeatRequest(**values)
