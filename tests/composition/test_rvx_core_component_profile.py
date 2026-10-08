"""Source-backed physical profile for the standalone RVX core."""

import json
import subprocess
from pathlib import Path

import pytest

from myfuzz.composition.component_profile import (
    ComponentProfileError,
    bind_profile,
    elaborate_profile,
    load_component_profile,
)
from myfuzz.composition.soc_port_dispositions import (
    PortDispositionError,
    build_port_dispositions,
)


ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "configs/cpus/rvx_core/component_profile.json"
SOURCE_ROOT = ROOT / "external_designs/rvx"
LOCK = ROOT / "configs/soc/sources.lock.json"

MEMORY_FIELDS = {
    "addr": ("rw_address", "output", 32),
    "read_request": ("read_request", "output", 1),
    "read_response": ("read_response", "input", 1),
    "read_data": ("read_data", "input", 32),
    "write_request": ("write_request", "output", 1),
    "write_response": ("write_response", "input", 1),
    "write_data": ("write_data", "output", 32),
    "write_strobe": ("write_strobe", "output", 4),
}
INACTIVE_INPUTS = {"halt", "irq_external", "irq_timer", "irq_software", "irq_fast", "real_time_clock"}
OBSERVED_OUTPUTS = {"irq_external_response", "irq_timer_response", "irq_software_response", "irq_fast_response"}


def _bound_profile():
    profile = load_component_profile(PROFILE)
    facts = elaborate_profile(profile, base_dir=ROOT)
    return profile, facts, bind_profile(profile, facts)


def test_rvx_core_uses_one_pinned_standalone_source_and_rv32i_facts():
    profile, facts, binding = _bound_profile()
    revision = subprocess.check_output(
        ["git", "-C", str(SOURCE_ROOT), "rev-parse", "HEAD"], text=True
    ).strip()
    assert profile.component_id == "rvx_core"
    assert profile.kind == "cpu"
    assert profile.source.source_root == "external_designs/rvx"
    assert profile.source.revision == f"git:{revision}"
    assert profile.source.top_module == facts.top_module == "rvx_core"
    assert profile.source.files == ("hardware/rvx_core.v",)
    assert facts.selection == "all"
    assert len(facts.ports) == 20
    assert profile.cpu.family == "riscv"
    assert profile.cpu.xlen == 32
    assert profile.cpu.extensions == ("i",)
    assert profile.cpu.reset_vector == 0
    assert profile.cpu.master_endpoints == ("processor.memory",)
    assert binding.endpoint("processor.memory").function == "memory_master"
    assert "instruction_identity" not in json.dumps(json.loads(PROFILE.read_text()))


def test_rvx_core_memory_roles_bind_to_exact_physical_ports():
    profile, facts, binding = _bound_profile()
    endpoint = binding.endpoint("processor.memory")
    assert endpoint.protocol == ("pipelined-completion-memory", "1")
    assert set(MEMORY_FIELDS) == {field.role for field in endpoint.fields}
    for role, (port, direction, width) in MEMORY_FIELDS.items():
        field = binding.field("processor.memory", role)
        assert (field.port, field.direction, field.width) == (port, direction, width)


def test_rvx_core_every_physical_pin_has_one_disposition():
    profile, facts, binding = _bound_profile()
    assert [(clock.port, clock.domain) for clock in profile.clocks] == [("clock", "core")]
    assert [(reset.port, reset.domain, reset.polarity, reset.synchronous)
            for reset in profile.resets] == [("reset", "sys_rst", "active_high", True)]
    ledger = build_port_dispositions(
        "rvx0", binding, clock_domain="core", reset_domain="sys_rst",
        profile_port_actions=profile.port_actions,
    )
    assert {entry.port for entry in ledger} == {port.name for port in facts.ports}
    assert sum(entry.bit_hi - entry.bit_lo + 1 for entry in ledger) == sum(
        port.width for port in facts.ports
    )
    constants = {entry.port: entry.value for entry in ledger if entry.disposition == "constant"}
    assert constants == {port: 0 for port in INACTIVE_INPUTS}
    assert {entry.port for entry in ledger if entry.disposition == "observe"} == OBSERVED_OUTPUTS
    assert {entry.port for entry in ledger if entry.disposition == "functional"} == (
        {port for port, _, _ in MEMORY_FIELDS.values()} | {"clock", "reset"}
    )


def test_rvx_core_missing_inactive_input_fails_closed():
    profile, _, binding = _bound_profile()
    actions = tuple(action for action in profile.port_actions if action.port != "halt")
    with pytest.raises(PortDispositionError, match="undisposed-port-bits:rvx0:halt"):
        build_port_dispositions(
            "rvx0", binding, clock_domain="core", reset_domain="sys_rst",
            profile_port_actions=actions,
        )


def test_rvx_core_wrong_source_revision_is_rejected():
    document = json.loads(PROFILE.read_text())
    document["source"]["revision"] = "git:" + "0" * 40
    with pytest.raises(ComponentProfileError, match="git-revision-mismatch"):
        elaborate_profile(load_component_profile(document), base_dir=ROOT)


def test_rvx_core_lock_pins_selected_bytes_without_untracked_closure_claim():
    records = json.loads(LOCK.read_text())["components"]
    record = next(item for item in records if item["id"] == "rvx_core")
    assert record["source"]["files"] == ["hardware/rvx_core.v"]
    assert record["source"]["revision"] == json.loads(PROFILE.read_text())["source"]["revision"]
    assert record["closure_status"] == "selected"
    assert record["source_status"] == "source_verified"
    assert record["runtime_status"] == "runtime_unverified"
    assert record["elaboration_status"] == "elaboration_unverified"
    assert "elaboration" not in record
    assert {item["path"] for item in record["artifacts"] if item["kind"] == "source"} == {
        "hardware/rvx_core.v"
    }
