"""Compile a validated soc_plan.v1 into a frozen soc_stimulus.v1 document.

The compiler is the P7 input layer: it never invents device behaviour, it only
records the raw fuzz input ABI, the address derivation, the driver rules and the
reset semantics that the generated RTL implements.  Every returned document is
validated again with soc_contracts.validate_soc_stimulus before it is handed to
a renderer, and every rejection fails closed with a stable reason prefix.

Fixed three-segment ABI
-----------------------
The document always contains the same three raw segments in the same order:

    instruction   memory initialization candidates (P8)
    mmio          the independent MMIO offer consumed by fuzz_mmio_master (P7)
    environment   external pin candidates (P9)

The bit layout (base, offsets, widths, padding, enumerations and validity bits)
is identical for cpu_only, mmio_only and mixed.  A mode only masks entries: a
mode_masked field keeps its bits and its mapping, records why it is disabled in
that mode, and is never re-laid-out.

Address strategies
------------------
Two derivations of the MMIO address are selectable through the policy and are
both recorded in the document:

    bias_off   addr = offset & (2**address_width - 1), then decoded against the
               plan address map; an address outside every window is recorded as
               an error and is never rounded into a window.
    biased     index = target_selector; region = windows[index];
               addr = region.base + (offset & (region.size - 1)); every valid
               selector therefore lands inside a declared window.

The protocol base state (raw layout, drivers, consumption, error classes and
reset semantics) is identical for both strategies; only the address derivation
differs.

Errors are recorded, never retried
----------------------------------
An offer whose target_selector is not a declared target, whose resolved address
is unmapped, whose target is not reachable from the fuzz master, or that
requests an unsupported operation (read, write or partial byte-enable) completes
exactly once with error=1, zero read data, no side effect and a recorded reason.
The raw offer is never rewritten into a valid request.
"""
from __future__ import annotations

import copy
from collections.abc import Mapping

from myfuzz.contracts import content_hash

from .soc_contracts import (
    CPU_MASTER_KINDS,
    SOC_MODES,
    SOC_STIMULUS_SCHEMA,
    SocContractError,
    soc_plan_hash,
    validate_soc_plan,
    validate_soc_stimulus,
)

#: The frozen stimulus schema id.
STIMULUS_SCHEMA = SOC_STIMULUS_SCHEMA

RAW_LAYOUT_VERSION = "soc_raw_layout.v1"
ADDRESS_STRATEGIES = ("bias_off", "biased")
ADDRESS_STRATEGY_CODES = {"bias_off": 0, "biased": 1}
#: Every segment is padded to a whole RFuzz word.
SEGMENT_ALIGNMENT_BITS = 32
SEGMENT_ORDER = ("instruction", "mmio", "environment")
#: The functional MMIO fields the driver consumes, in raw-bit order.
MMIO_FIELD_ORDER = ("offer", "target_selector", "offset", "write", "wdata", "be")
#: The payload fields sampled when an offer is accepted in idle.
MMIO_LATCHED_FIELDS = ("target_selector", "offset", "write", "wdata", "be")
LOCAL_PIN_FIELDS = (("uart_rx", 1), ("spi_miso", 1), ("gpio_in", 8))
DRIVER_MODULE = "fuzz_mmio_master"
DRIVER_SOURCE = "src/myfuzz/protocols/rtl/fuzz_mmio_master.sv"
RULE_IDS = ("protocol_base", "isa_legal", "mmio_reachability_bias")
ERROR_IDS = (
    "invalid_target_selector",
    "unmapped_address",
    "unsupported_source",
    "unsupported_operation",
)


class SocStimulusError(ValueError):
    """Raised when a plan/policy pair cannot become a safe soc_stimulus.v1."""


def compile_soc_stimulus(plan: dict, policy: dict) -> dict:
    """Compile a validated soc_plan.v1 and a stimulus policy into a document.

    policy requires:
      mode              one of soc_contracts.SOC_MODES, available in the plan
      address_strategy  "bias_off" or "biased"
    and accepts:
      rules             optional mapping of rule_id -> bool for the P8 toggles

    Unknown policy keys, missing keys and invalid values are rejected.  The
    returned document is deterministic, JSON-serializable, self-identifying
    (layout_hash) and validated with validate_soc_stimulus.
    """
    if not isinstance(plan, dict):
        raise SocStimulusError("invalid-plan:plan must be a soc_plan.v1 JSON object")
    try:
        validate_soc_plan(plan)
    except SocContractError as error:
        raise SocStimulusError(f"invalid-plan:{error}") from error

    selection = _selection(policy, plan)
    facts = _plan_facts(plan)
    plan_hash = soc_plan_hash(plan)

    masks = {
        "instruction": _participation(facts, selection["mode"], CPU_MASTER_KINDS),
        "mmio": _participation(facts, selection["mode"], ("fuzz_mmio",)),
        "environment": (False, None),
    }
    layout = _build_layout(facts, masks)
    environment_contract = _environment_contract(plan)
    strategy = _build_address_strategy(
        facts,
        selection["address_strategy"],
        selection["rules"]["mmio_reachability_bias"],
    )
    document = {
        "schema_version": STIMULUS_SCHEMA,
        "plan_hash": plan_hash,
        "mode": selection["mode"],
        "mode_selection": {"selected_at": "test_begin", "source": "soc_plan.v1#/stimulus"},
        "raw_layout": layout,
        "mode_masking": _mode_masking(selection["mode"], masks),
        "address_strategy": strategy,
        "drivers": _build_drivers(facts, environment_contract),
        "consumption": _consumption(),
        "error_recording": _error_recording(facts),
        "rule_classes": _rule_classes(selection),
        "reset_semantics": _reset_semantics(plan, selection["mode"]),
        "cpu_isolation": _cpu_isolation(),
        "environment_contract": environment_contract,
        "rtl_projection": _rtl_projection(facts, strategy),
        "provenance": {
            "plan": "soc_plan.v1",
            "plan_hash": plan_hash,
            "address_map": "soc_plan.v1#/address_map",
            "reset": "soc_plan.v1#/reset",
            "target_capabilities": "soc_plan.v1#/target_capabilities",
            "peripheral_facts": "configs/soc/closures",
            "contract": "soc_contracts.validate_soc_stimulus",
            "generator": "myfuzz.composition.soc_stimulus.compile_soc_stimulus",
        },
    }
    document["layout_hash"] = content_hash(
        {key: value for key, value in document.items() if key != "layout_hash"}
    )
    try:
        validate_soc_stimulus(document)
    except SocContractError as error:  # pragma: no cover - internal invariant
        raise SocStimulusError(f"invalid-document:{error}") from error
    return document


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------


def _selection(policy: object, plan: Mapping[str, object]) -> dict:
    if not isinstance(policy, Mapping):
        raise SocStimulusError("invalid-policy:policy must be a JSON object")
    unknown = sorted(str(key) for key in set(policy) - {"mode", "address_strategy", "rules"})
    if unknown:
        raise SocStimulusError(f"unknown-policy-key:{unknown[0]}")
    for key in ("mode", "address_strategy"):
        if key not in policy:
            raise SocStimulusError(f"missing-policy-key:{key}")
    mode = policy["mode"]
    if not isinstance(mode, str) or mode not in SOC_MODES:
        raise SocStimulusError("invalid-policy-field:mode")
    strategy = policy["address_strategy"]
    if not isinstance(strategy, str) or strategy not in ADDRESS_STRATEGIES:
        raise SocStimulusError("invalid-policy-field:address_strategy")
    available = plan["stimulus"]["available_modes"]  # type: ignore[index]
    if mode not in available:
        raise SocStimulusError(f"mode-not-declared:{mode}")
    return {
        "mode": mode,
        "address_strategy": strategy,
        "rules": _rule_selection(policy.get("rules"), mode, strategy),
    }


def _rule_selection(value: object, mode: str, strategy: str) -> dict:
    overrides: dict[str, bool] = {}
    if value is not None:
        if not isinstance(value, Mapping):
            raise SocStimulusError("invalid-policy-field:rules")
        for rule_id, enabled in value.items():
            if rule_id not in RULE_IDS:
                raise SocStimulusError(f"unknown-rule-id:{rule_id}")
            if not isinstance(enabled, bool):
                raise SocStimulusError(f"invalid-policy-field:rules/{rule_id}")
            overrides[str(rule_id)] = enabled
    if overrides.get("protocol_base") is False:
        raise SocStimulusError("unsupported-rule-disable:protocol_base")
    return {
        "protocol_base": True,
        "isa_legal": overrides.get("isa_legal", True),
        "mmio_reachability_bias": overrides.get(
            "mmio_reachability_bias", strategy == "biased" and mode != "cpu_only"
        ),
    }


# ---------------------------------------------------------------------------
# plan facts
# ---------------------------------------------------------------------------


def _integer(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def _pick_width(groups: list, key: str, default: int) -> int:
    for group in groups:
        values = [_integer(item.get(key)) for item in group]
        widths = [width for width in values if width is not None]
        if widths:
            return max(widths)
    return default


def _ingress_masters(plan: Mapping[str, object]) -> list:
    stimulus = plan.get("stimulus", {})
    mode_records = stimulus.get("modes", {}) if isinstance(stimulus, Mapping) else {}
    participants_by_mode = {
        str(mode): set(record.get("participants", []))
        for mode, record in mode_records.items()
        if isinstance(record, Mapping)
    }
    masters = []
    for net in plan["nets"]:  # type: ignore[index]
        if net.get("kind") != "master_ingress":
            continue
        driver = net.get("driver", {})
        source_id = driver.get("source_id", net.get("net_id"))
        masters.append({
            "source_id": source_id,
            "kind": driver.get("kind"),
            "component_id": driver.get("component_id"),
            "port": driver.get("port"),
            "protocol": list(net.get("protocol", [])),
            "address_width": net.get("address_width"),
            "data_width": net.get("data_width"),
            "test_modes": sorted(
                mode for mode, participants in participants_by_mode.items()
                if source_id in participants
            ),
        })
    masters.sort(key=lambda item: str(item["source_id"]))
    return masters


def _windows(plan: Mapping[str, object]) -> list:
    windows = []
    for entry in plan["address_map"]["windows"]:  # type: ignore[index]
        window = entry["window"]
        windows.append({
            "target_id": entry["target_id"],
            "component_id": entry.get("component_id"),
            "port": entry.get("port"),
            "protocol": list(entry.get("protocol", [])),
            "base": window["base"],
            "size": window["size"],
            "byte_enable": bool(entry.get("byte_enable")),
            "request_sources": sorted(entry.get("request_sources", [])),
        })
    windows.sort(key=lambda item: (item["base"], item["target_id"]))
    return windows


def _capabilities(plan: Mapping[str, object]) -> dict:
    capabilities = {}
    for target_id, record in plan["target_capabilities"].items():  # type: ignore[index]
        declared = record.get("capabilities", {})
        capabilities[target_id] = {
            "read": declared.get("read") is True,
            "write": declared.get("write") is True,
            "partial_write": declared.get("partial_write") is True,
        }
    return capabilities


def _declared_capabilities(plan: Mapping[str, object]) -> dict:
    return {
        target_id: copy.deepcopy(record.get("capabilities", {}))
        for target_id, record in plan["target_capabilities"].items()  # type: ignore[index]
    }


def _environment_contract(plan: Mapping[str, object]) -> dict:
    """Return the plan-owned external-pin and IRQ contract verbatim.

    P9 inputs are constrained by declared links/routes.  This helper only
    copies those records and adds the fixed driver ownership metadata; it never
    turns a component name or an arbitrary signal name into a pin mapping.
    """
    raw = plan.get("environment_contract")
    if isinstance(raw, Mapping):
        contract = copy.deepcopy(dict(raw))
    else:
        links = plan.get("environment_links", [])
        routes = plan.get("interrupt_routes", [])
        contract = {
            "schema_version": "soc_environment_contract.v1",
            "links": copy.deepcopy(links) if isinstance(links, list) else [],
            "interrupt_routes": copy.deepcopy(routes) if isinstance(routes, list) else [],
            "environment_driver": {
                "driver_id": "environment_pins",
                "ownership": "external_pins_only",
                "accepts_only_declared_links": True,
                "max_pending": 1,
            },
            "irq_router": {
                "module": "soc_irq_router",
                "capture": "per_source_pending",
                "claim": "priority_ordered",
                "completion": "explicit_complete",
                "simultaneous_sources": "retained_independently",
            },
            "provenance": {
                "links": "soc_plan.v1#/environment_links",
                "interrupt_routes": "soc_plan.v1#/interrupt_routes",
            },
        }
    for field in ("links", "interrupt_routes"):
        values = contract.get(field)
        if not isinstance(values, list):
            raise SocStimulusError(f"invalid-environment-contract:{field}")
        contract[field] = sorted(
            (copy.deepcopy(value) for value in values),
            key=lambda value: str(value.get("link_id", value.get("route_id", "")))
            if isinstance(value, Mapping) else "",
        )
    return contract


def _plan_facts(plan: Mapping[str, object]) -> dict:
    masters = _ingress_masters(plan)
    cpu = [master for master in masters if master["kind"] in CPU_MASTER_KINDS]
    fuzz = [master for master in masters if master["kind"] == "fuzz_mmio"]
    mmio_address_width = _pick_width([fuzz, cpu, masters], "address_width", 32)
    mmio_data_width = _pick_width([fuzz, cpu, masters], "data_width", 32)
    instruction_address_width = _pick_width([cpu, fuzz, masters], "address_width", mmio_address_width)
    instruction_data_width = _pick_width([cpu, fuzz, masters], "data_width", mmio_data_width)
    for label, width in (("mmio", mmio_data_width), ("instruction", instruction_data_width)):
        if width < 8 or width % 8:
            raise SocStimulusError(f"unsupported-data-width:{label}:{width}")
    windows = _windows(plan)
    selector_width = max(1, len(windows).bit_length())
    return {
        "masters": masters,
        "mmio_address_width": mmio_address_width,
        "mmio_data_width": mmio_data_width,
        "instruction_address_width": instruction_address_width,
        "instruction_data_width": instruction_data_width,
        "be_width": mmio_data_width // 8,
        "instruction_be_width": instruction_data_width // 8,
        "windows": windows,
        "capabilities": _capabilities(plan),
        "declared_capabilities": _declared_capabilities(plan),
        "fuzz_sources": sorted(master["source_id"] for master in fuzz),
        "selector_width": selector_width,
        "selector_invalid": len(windows),
    }


def _participation(facts: Mapping[str, object], mode: str, kinds) -> tuple:
    masters = [master for master in facts["masters"] if master["kind"] in kinds]
    if not masters:
        return True, f"the plan declares no master of kind {'/'.join(sorted(kinds))}"
    if not any(mode in master.get("test_modes", []) for master in masters):
        return (
            True,
            f"mode {mode} does not participate in a master of kind "
            f"{'/'.join(sorted(kinds))} according to soc_plan stimulus participants",
        )
    return False, None


# ---------------------------------------------------------------------------
# raw layout
# ---------------------------------------------------------------------------


def _pad_to(value: int, granularity: int) -> int:
    remainder = value % granularity
    return value if remainder == 0 else value + granularity - remainder


def _field(name: str, lsb: int, width: int, role: str, *, encoding: str = "uint",
           values: list | None = None, padding: bool = False, validity: bool = False,
           consumed_when: str = "", description: str = "", port: str | None = None) -> dict:
    return {
        "name": name,
        "lsb": lsb,
        "width": width,
        "role": role,
        "padding": padding,
        "port": port,
        "bit_offset": None,
        "encoding": encoding,
        "values": [dict(entry) for entry in (values or [])],
        "validity_bit": validity,
        "consumed_when": consumed_when,
        "description": description,
        "mode_masked": False,
        "mode_mask_reason": None,
    }


def _validity_values() -> list:
    return [
        {"value": 0, "name": "inactive"},
        {"value": 1, "name": "active"},
    ]


def _write_values() -> list:
    return [
        {"value": 0, "name": "read"},
        {"value": 1, "name": "write"},
    ]


def _selector_values(facts: Mapping[str, object]) -> list:
    values = [
        {
            "value": index,
            "name": window["target_id"],
            "target_id": window["target_id"],
            "base": window["base"],
            "size": window["size"],
        }
        for index, window in enumerate(facts["windows"])
    ]
    values.append({
        "value": facts["selector_invalid"],
        "name": "invalid",
        "target_id": None,
        "base": None,
        "size": None,
    })
    return values


def _segment(segment_id: str, base_bit: int, fields: list, mask: tuple) -> dict:
    used = sum(field["width"] for field in fields)
    bit_width = _pad_to(used, SEGMENT_ALIGNMENT_BITS)
    if bit_width > used:
        fields.append(_field(
            f"{segment_id}_reserved", used, bit_width - used, "padding", padding=True,
            consumed_when="never; reserved bits keep their defined zero mapping",
            description="word alignment padding; the bits exist in every mode",
        ))
    for field in fields:
        field["bit_offset"] = base_bit + field["lsb"]
        if not field["padding"]:
            field["mode_masked"] = mask[0]
            field["mode_mask_reason"] = mask[1]
    return {
        "segment_id": segment_id,
        "base_bit": base_bit,
        "bit_width": bit_width,
        "reserved_bits": bit_width - used,
        "fields": fields,
    }


def _build_layout(facts: Mapping[str, object], masks: Mapping[str, tuple]) -> dict:
    segments = []
    base_bit = 0

    instruction = [
        _field("init_offer", 0, 1, "valid", encoding="bool", values=_validity_values(),
               validity=True,
               consumed_when="when the instruction initializer samples the segment",
               description="validity bit for the instruction initialization candidate"),
        _field("init_address", 1, facts["instruction_address_width"], "address",
               consumed_when="when init_offer is active",
               description="initialization address"),
        _field("init_data", 1 + facts["instruction_address_width"],
               facts["instruction_data_width"], "data",
               consumed_when="when init_offer is active",
               description="initialization data word"),
        _field("init_be", 1 + facts["instruction_address_width"] + facts["instruction_data_width"],
               facts["instruction_be_width"], "byte_enable",
               consumed_when="when init_offer is active",
               description="initialization byte enables"),
    ]
    segment = _segment("instruction", base_bit, instruction, masks["instruction"])
    segments.append(segment)
    base_bit += segment["bit_width"]

    selector_lsb = 1
    offset_lsb = selector_lsb + facts["selector_width"]
    write_lsb = offset_lsb + facts["mmio_address_width"]
    wdata_lsb = write_lsb + 1
    be_lsb = wdata_lsb + facts["mmio_data_width"]
    mmio = [
        _field("offer", 0, 1, "valid", encoding="bool", values=_validity_values(),
               validity=True, port="stim_offer",
               consumed_when="sampled every cycle; accepted only in idle",
               description="validity bit of the MMIO offer"),
        _field("target_selector", selector_lsb, facts["selector_width"], "target_selector",
               encoding="enum", values=_selector_values(facts), port="stim_target_selector",
               consumed_when="on acceptance",
               description="declared target index plus the explicit invalid value"),
        _field("offset", offset_lsb, facts["mmio_address_width"], "address",
               port="stim_offset",
               consumed_when="on acceptance; address (bias_off) or in-window offset (biased)",
               description="raw address bits or region offset, per the recorded strategy"),
        _field("write", write_lsb, 1, "write", encoding="bool", values=_write_values(),
               port="stim_write",
               consumed_when="on acceptance",
               description="0 selects a read, 1 selects a write"),
        _field("wdata", wdata_lsb, facts["mmio_data_width"], "data", port="stim_wdata",
               consumed_when="on acceptance when write is 1; ignored for reads but always latent",
               description="write data"),
        _field("be", be_lsb, facts["be_width"], "byte_enable", port="stim_be",
               consumed_when="on acceptance when write is 1; a partial value needs target partial_write",
               description="write byte enables"),
    ]
    segment = _segment("mmio", base_bit, mmio, masks["mmio"])
    segments.append(segment)
    base_bit += segment["bit_width"]

    environment = [
        _field("env_offer", 0, 1, "valid", encoding="bool", values=_validity_values(),
               validity=True, consumed_when="when the environment driver samples the segment",
               description="validity bit of the environment candidate"),
    ]
    pin_lsb = 1
    for name, width in LOCAL_PIN_FIELDS:
        environment.append(_field(name, pin_lsb, width, "pin",
                                  consumed_when="when env_offer is active",
                                  description="external pin candidate"))
        pin_lsb += width
    segment = _segment("environment", base_bit, environment, masks["environment"])
    segments.append(segment)
    base_bit += segment["bit_width"]

    return {
        "version": RAW_LAYOUT_VERSION,
        "total_bits": base_bit,
        "segment_alignment_bits": SEGMENT_ALIGNMENT_BITS,
        "segment_order": list(SEGMENT_ORDER),
        "segments": segments,
    }


def _mode_masking(mode: str, masks: Mapping[str, tuple]) -> dict:
    return {
        "mode": mode,
        "masked_segments": [name for name in SEGMENT_ORDER if masks[name][0]],
        "segments": {
            name: {"mode_masked": masks[name][0], "reason": masks[name][1]}
            for name in SEGMENT_ORDER
        },
        "disabled_entry_rule": (
            "a mode_masked entry keeps its bits, width, padding, enumeration and mapping; "
            "only its consumption is disabled in this mode"
        ),
        "statement": (
            "the three test modes share one raw field table; a mode never re-lays-out bits"
        ),
    }


# ---------------------------------------------------------------------------
# address strategy and reference resolution
# ---------------------------------------------------------------------------


def _fuzz_reachable(facts: Mapping[str, object], window: Mapping[str, object]) -> bool:
    return bool(set(facts["fuzz_sources"]) & set(window["request_sources"]))


def _decode(windows: list, address: int):
    for window in windows:
        if window["base"] <= address < window["base"] + window["size"]:
            return window
    return None


def _resolve_offer(facts: Mapping[str, object], strategy: str, offer: Mapping[str, object]) -> dict:
    """Reference resolution of one raw MMIO offer, exactly as documented."""
    windows = facts["windows"]
    selector = offer["target_selector"]
    offset = offer["offset"]
    write = bool(offer["write"])
    be = offer["be"]
    full_be = (1 << facts["be_width"]) - 1
    outcome = {
        "result": "error",
        "error_id": None,
        "reason": None,
        "target_id": None,
        "selector_target_id": None,
        "address": None,
        "request_issued": False,
        "side_effects": "none",
        "write": write,
        "wdata": offer["wdata"],
        "be": be,
    }
    if not isinstance(selector, int) or isinstance(selector, bool) or not 0 <= selector < len(windows):
        outcome["error_id"] = "invalid_target_selector"
        outcome["reason"] = (
            f"target_selector {selector!r} is not one of the {len(windows)} declared targets; "
            "the offer is completed with an error and is not remapped"
        )
        return outcome
    window = windows[selector]
    outcome["selector_target_id"] = window["target_id"]
    if strategy == "biased":
        address = window["base"] + (offset & (window["size"] - 1))
        target = window
    else:
        address = offset & ((1 << facts["mmio_address_width"]) - 1)
        target = _decode(windows, address)
    if target is None:
        outcome["address"] = address
        outcome["error_id"] = "unmapped_address"
        outcome["reason"] = (
            f"address {address:#x} is outside every declared window; the offer is completed "
            "with an error and the address is not rounded into a window"
        )
        return outcome
    outcome["address"] = address
    if not _fuzz_reachable(facts, target):
        outcome["error_id"] = "unsupported_source"
        outcome["reason"] = (
            f"target {target['target_id']} does not list a fuzz MMIO source in request_sources"
        )
        return outcome
    capabilities = facts["capabilities"].get(target["target_id"], {})
    if write:
        if capabilities.get("write") is not True:
            outcome["error_id"] = "unsupported_operation"
            outcome["reason"] = f"target {target['target_id']} does not support writes"
            return outcome
        if be != full_be and (
            capabilities.get("partial_write") is not True or not target["byte_enable"]
        ):
            outcome["error_id"] = "unsupported_operation"
            outcome["reason"] = (
                f"target {target['target_id']} cannot express a partial byte-enable write"
            )
            return outcome
    elif capabilities.get("read") is not True:
        outcome["error_id"] = "unsupported_operation"
        outcome["reason"] = f"target {target['target_id']} does not support reads"
        return outcome
    outcome["result"] = "request"
    outcome["target_id"] = target["target_id"]
    outcome["request_issued"] = True
    outcome["side_effects"] = "target_defined"
    return outcome


def _witness(facts: Mapping[str, object], strategy: str, name: str, selector: int,
             offset: int, write: bool, be: int, operation: str) -> dict:
    offer = {
        "target_selector": selector,
        "offset": offset,
        "write": bool(write),
        "wdata": 0,
        "be": be,
    }
    outcome = _resolve_offer(facts, strategy, offer)
    return {
        "name": name,
        "kind": "error" if outcome["result"] == "error" else "request",
        "operation": operation,
        "offer": offer,
        "outcome": outcome,
    }


def _impossible(name: str, reason: str) -> dict:
    return {"name": name, "kind": "error", "possible": False, "reason": reason}


def _first_index(windows: list, predicate) -> int | None:
    for index, window in enumerate(windows):
        if predicate(window):
            return index
    return None


def _unmapped_probe(windows: list, address_width: int) -> int | None:
    if not windows:
        return 0
    probe = max(window["base"] + window["size"] for window in windows)
    return probe if probe <= (1 << address_width) - 1 else None


def _biased_probe_offset(address_width: int, size: int) -> int:
    mask = (1 << address_width) - 1
    if size > mask:
        return mask
    raw = 0xDEADBEEF & mask
    if raw >= size:
        return raw
    candidate = raw + size
    return candidate if candidate <= mask else size


def _forbidden_operation(window: Mapping[str, object], capabilities: Mapping[str, object]):
    if capabilities.get("read") is not True:
        return "read", False, (1 << 0) * 0 + (1 << 8) - 1
    if capabilities.get("write") is not True:
        return "write", True, (1 << 8) - 1
    if capabilities.get("partial_write") is not True or not window["byte_enable"]:
        return "partial_write", True, 1
    return None


def _witnesses(facts: Mapping[str, object], strategy: str) -> list:
    windows = facts["windows"]
    full_be = (1 << facts["be_width"]) - 1
    invalid = facts["selector_invalid"]
    witnesses = [
        _witness(facts, strategy, "invalid_target_selector", invalid, 0, False, full_be, "select"),
    ]

    if strategy == "bias_off":
        probe = _unmapped_probe(windows, facts["mmio_address_width"])
        if probe is None:
            witnesses.append(_impossible(
                "unmapped_address",
                "the declared windows cover the whole plan address width",
            ))
        else:
            selector = 0 if windows else invalid
            witnesses.append(_witness(
                facts, strategy, "unmapped_address", selector, probe, False, full_be, "read",
            ))
    else:
        witnesses.append(_impossible(
            "unmapped_address",
            "biased addressing derives every address inside the selected window; only an "
            "invalid selector is rejected",
        ))

    source_index = _first_index(windows, lambda window: not _fuzz_reachable(facts, window))
    if source_index is None:
        witnesses.append(_impossible(
            "unsupported_source",
            "every declared window lists a fuzz MMIO source",
        ))
    else:
        window = windows[source_index]
        offset = window["base"] if strategy == "bias_off" else 0
        witnesses.append(_witness(
            facts, strategy, "unsupported_source", source_index, offset, False, full_be, "read",
        ))

    operation_index = None
    operation = None
    for index, window in enumerate(windows):
        if not _fuzz_reachable(facts, window):
            continue
        forbidden = _forbidden_operation(window, facts["capabilities"].get(window["target_id"], {}))
        if forbidden is not None:
            operation_index, operation = index, forbidden
            break
    if operation_index is None:
        witnesses.append(_impossible(
            "unsupported_operation",
            "every fuzz-reachable target supports the recorded read, write and partial-write set",
        ))
    else:
        window = windows[operation_index]
        offset = window["base"] if strategy == "bias_off" else 0
        witnesses.append(_witness(
            facts, strategy, "unsupported_operation", operation_index, offset,
            operation[1], operation[2], operation[0],
        ))

    address_index = _first_index(
        windows,
        lambda window: _fuzz_reachable(facts, window)
        and facts["capabilities"].get(window["target_id"], {}).get("read") is True,
    )
    if address_index is None:
        witnesses.append(_impossible(
            "region_biased_address" if strategy == "biased" else "raw_address",
            "no fuzz-reachable window supports reads",
        ))
    elif strategy == "biased":
        window = windows[address_index]
        witnesses.append(_witness(
            facts, strategy, "region_biased_address", address_index,
            _biased_probe_offset(facts["mmio_address_width"], window["size"]),
            False, full_be, "read",
        ))
    else:
        window = windows[address_index]
        witnesses.append(_witness(
            facts, strategy, "raw_address", address_index,
            window["base"] + window["size"] // 2, False, full_be, "read",
        ))
    return witnesses


def _build_address_strategy(
    facts: Mapping[str, object], strategy: str, bias_enabled: bool
) -> dict:
    effective = "biased" if strategy == "biased" and bias_enabled else "bias_off"
    if effective == "biased":
        for window in facts["windows"]:
            size = window["size"]
            if size < 1 or size & (size - 1):
                raise SocStimulusError(
                    f"unsupported-address-strategy:biased:{window['target_id']}:"
                    f"window size {size:#x} is not a power of two"
                )
    windows = [
        {
            "index": index,
            "target_id": window["target_id"],
            "component_id": window["component_id"],
            "port": window["port"],
            "protocol": list(window["protocol"]),
            "base": window["base"],
            "size": window["size"],
            "byte_enable": window["byte_enable"],
            "request_sources": list(window["request_sources"]),
            "fuzz_mmio_requester": _fuzz_reachable(facts, window),
        }
        for index, window in enumerate(facts["windows"])
    ]
    return {
        "selected": strategy,
        "effective": effective,
        "bias_enabled": bool(bias_enabled and strategy == "biased"),
        "options": list(ADDRESS_STRATEGIES),
        "address_width": facts["mmio_address_width"],
        "address_field": "mmio/offset",
        "selector_field": "mmio/target_selector",
        "windows": windows,
        "target_selector": {
            "field": "mmio/target_selector",
            "segment": "mmio",
            "width": facts["selector_width"],
            "invalid_value": facts["selector_invalid"],
            "invalid_name": "invalid",
            "undefined_values": (
                "every value outside the enumeration is invalid and is recorded as "
                "invalid_target_selector"
            ),
            "values": _selector_values(facts),
        },
        "rules": {
            "bias_off": (
                "addr = offset & (2**address_width - 1); the region is the window that "
                "contains addr"
            ),
            "biased": (
                "index = target_selector; region = windows[index]; "
                "addr = region.base + (offset & (region.size - 1))"
            ),
        },
        "bias_off": {
            "region_bias": False,
            "mask": (1 << facts["mmio_address_width"]) - 1,
            "unmapped": "recorded as unmapped_address; never rounded into a window",
            "selector_role": "validity gate; the address decode is authoritative for routing",
        },
        "biased": {
            "region_bias": True,
            "offset_reduction": "mask_to_window_size",
            "requires_power_of_two_window": True,
            "unmapped": "cannot occur: every valid selector resolves inside its window",
            "selector_role": "selects the region before the offset is applied",
        },
        "decode_order": "windows sorted by (base, target_id)",
        "protocol_base": (
            "both strategies share the same raw layout, drivers, consumption, error classes "
            "and reset semantics; only this address derivation differs"
        ),
        "witnesses": _witnesses(facts, effective),
    }


# ---------------------------------------------------------------------------
# drivers, consumption and error recording
# ---------------------------------------------------------------------------


def _build_drivers(facts: Mapping[str, object], environment_contract: Mapping[str, object] | None = None) -> list:
    environment_contract = environment_contract or {
        "links": [],
        "interrupt_routes": [],
    }
    links = environment_contract.get("links", [])
    routes = environment_contract.get("interrupt_routes", [])
    link_ids = [str(link.get("link_id")) for link in links if isinstance(link, Mapping)]
    route_ids = [str(route.get("route_id")) for route in routes if isinstance(route, Mapping)]
    return [
        {
            "driver_id": "instruction_init",
            "segment_id": "instruction",
            "status": "planned:P8",
            "module": None,
            "rtl_source": None,
            "accept_condition": "init_offer && state == idle",
            "latch_policy": "latch_until_completion",
            "busy_policy": {
                "rule": "deterministic_drop_counted",
                "counter": "instruction_drop_count",
                "condition": "init_offer while busy",
                "effect": "drop the candidate without changing the in-flight initialization",
            },
            "max_pending": 1,
            "queue_depth": 0,
            "notes": "the instruction initializer only writes memory state; it never drives a CPU response",
        },
        {
            "driver_id": "fuzz_mmio_master",
            "segment_id": "mmio",
            "status": "implemented",
            "module": DRIVER_MODULE,
            "rtl_source": DRIVER_SOURCE,
            "accept_condition": "offer && state == idle",
            "latch_policy": "latch_until_completion",
            "busy_policy": {
                "rule": "deterministic_drop_counted",
                "counter": "busy_drop_count",
                "condition": "offer while state != idle",
                "effect": "drop the offer; no latched field changes and no request is issued",
            },
            "state_machine": {
                "states": ["idle", "request", "response"],
                "initial_state": "idle",
                "busy_states": ["request", "response"],
                "accept": {
                    "state": "idle",
                    "condition": "offer",
                    "trigger_field": "offer",
                    "latched_fields": list(MMIO_LATCHED_FIELDS),
                    "next_state": "request",
                    "effect": "latch every payload field and start exactly one request",
                },
                "latch": {
                    "fields": list(MMIO_LATCHED_FIELDS),
                    "until": "completion",
                    "raw_input_sampled_in": ["idle"],
                    "effect": "new raw bits cannot change an in-flight transaction",
                },
                "drop": {
                    "states": ["request", "response"],
                    "condition": "offer",
                    "effect": "drop the offer, change no latched field and issue no request",
                    "counter": "busy_drop_count",
                    "increment": 1,
                },
                "complete": {
                    "condition": "rsp_valid && rsp_ready",
                    "completions_per_accepted": 1,
                    "next_state": "idle",
                    "internal_error_completion": (
                        "an offer with an invalid target_selector completes exactly once with "
                        "error_code=invalid_target_selector and no fabric request"
                    ),
                },
                "raw_input_sampled_only_in_idle": True,
                "max_pending": 1,
                "queue_depth": 0,
            },
            "counters": [
                {
                    "name": "busy_drop_count",
                    "width": 32,
                    "increments_when": "offer is present while state != idle",
                    "cleared_by": "test_reset",
                },
                {
                    "name": "error_count",
                    "width": 32,
                    "increments_when": "an accepted offer completes with a recorded error",
                    "cleared_by": "test_reset",
                },
                {
                    "name": "completion_count",
                    "width": 32,
                    "increments_when": "an accepted offer completes exactly once",
                    "cleared_by": "test_reset",
                },
            ],
            "status_register": {
                "name": "error_code",
                "width": 4,
                "codes": {"0": "none", "1": "invalid_target_selector", "2": "fabric_response_error"},
                "cleared_by": "test_reset",
            },
            "max_pending": 1,
            "queue_depth": 0,
        },
        {
            "driver_id": "environment_pins",
            "segment_id": "environment",
            "status": "implemented",
            "module": "environment_pins",
            "rtl_source": "src/myfuzz/protocols/rtl/fuzz_uart_peer.sv + fuzz_spi_peer.sv",
            "rtl_sources": [
                "src/myfuzz/protocols/rtl/fuzz_uart_peer.sv",
                "src/myfuzz/protocols/rtl/fuzz_spi_peer.sv",
            ],
            "contract": "soc_plan.v1#/environment_contract",
            "declared_links": sorted(link_ids),
            "declared_interrupt_routes": sorted(route_ids),
            "accept_condition": "env_offer && state == idle",
            "latch_policy": "latch_until_completion",
            "busy_policy": {
                "rule": "deterministic_drop_counted",
                "counter": "environment_drop_count",
                "condition": "env_offer while busy",
                "effect": "drop the candidate without changing the driven pins",
            },
            "max_pending": 1,
            "queue_depth": 0,
            "notes": "drives declared external pins only; it never drives CPU or peripheral responses",
        },
    ]


def _consumption() -> list:
    return [
        {
            "segment_id": "instruction",
            "driver": "instruction_init",
            "latch_policy": "latch_until_completion",
            "busy_policy": "deterministic_drop_counted",
            "max_pending": 1,
            "queue_depth": 0,
            "implemented_by": "instruction_init (P8)",
        },
        {
            "segment_id": "mmio",
            "driver": "fuzz_mmio_master",
            "latch_policy": "latch_until_completion",
            "busy_policy": "deterministic_drop_counted",
            "max_pending": 1,
            "queue_depth": 0,
            "implemented_by": DRIVER_MODULE,
        },
        {
            "segment_id": "environment",
            "driver": "environment_pins",
            "latch_policy": "latch_until_completion",
            "busy_policy": "deterministic_drop_counted",
            "max_pending": 1,
            "queue_depth": 0,
            "implemented_by": "environment_pins (P9)",
        },
    ]


def _error_recording(facts: Mapping[str, object]) -> dict:
    classes = [
        {
            "error_id": "invalid_target_selector",
            "detected_by": "fuzz_mmio_master",
            "condition": "the offer target_selector is not one of the declared target values",
            "reason": "an invalid selector has no address mapping and is never remapped to a valid target",
            "side_effects": "none",
            "recorded_as": "error_count += 1; error_code = invalid_target_selector; no fabric request",
        },
        {
            "error_id": "unmapped_address",
            "detected_by": "soc_fabric_decode",
            "condition": "the resolved address is outside every declared window",
            "reason": "an unmapped address is not memory and is never rounded into a window",
            "side_effects": "none",
            "recorded_as": "the offer completes with error=1, rdata=0 and error_count += 1",
        },
        {
            "error_id": "unsupported_source",
            "detected_by": "soc_fabric_decode",
            "condition": "the decoded target does not list a fuzz MMIO source in request_sources",
            "reason": "ownership is explicit; a source never gains access by retrying",
            "side_effects": "none",
            "recorded_as": "the offer completes with error=1, rdata=0 and error_count += 1",
        },
        {
            "error_id": "unsupported_operation",
            "detected_by": "soc_fabric_target_capability",
            "condition": (
                "a read on a target without read capability, a write without write capability, "
                "or a partial byte-enable write without partial_write capability"
            ),
            "reason": "caps become explicit errors instead of read-modify-write or silent truncation",
            "side_effects": "none",
            "recorded_as": "the offer completes with error=1, rdata=0 and error_count += 1",
        },
    ]
    operations = []
    for window in facts["windows"]:
        capabilities = facts["capabilities"].get(window["target_id"], {})
        operations.append({
            "target_id": window["target_id"],
            "component_id": window["component_id"],
            "port": window["port"],
            "protocol": list(window["protocol"]),
            "window": {"base": window["base"], "size": window["size"]},
            "byte_enable": window["byte_enable"],
            "read": capabilities.get("read") is True,
            "write": capabilities.get("write") is True,
            "partial_write": capabilities.get("partial_write") is True,
            "fuzz_mmio_requester": _fuzz_reachable(facts, window),
            "capabilities": copy.deepcopy(
                facts["declared_capabilities"].get(window["target_id"], {})
            ),
            "source": "soc_plan.v1#/target_capabilities + soc_plan.v1#/address_map/windows",
        })
    return {
        "policy": "record_no_retry",
        "retry": "never",
        "rewrite": "forbidden",
        "counter": "error_count",
        "status": "error_code",
        "completion_on_error": {
            "rsp_error": True,
            "rdata": 0,
            "side_effects": "none",
            "completion_count": 1,
            "statement": (
                "an errored offer completes exactly once with error=1 and zero read data; it is "
                "never rewritten into a valid request"
            ),
        },
        "classes": classes,
        "target_operations": operations,
    }


# ---------------------------------------------------------------------------
# rules, reset semantics and RTL projection
# ---------------------------------------------------------------------------


def _rule_classes(selection: Mapping[str, object]) -> list:
    rules = selection["rules"]
    return [
        {
            "rule_id": "protocol_base",
            "class": "protocol_base",
            "category": "constraint",
            "enabled": rules["protocol_base"],
            "scope": "instruction,mmio,environment",
            "effect": "raw fields keep their recorded protocol meaning in every mode",
        },
        {
            "rule_id": "isa_legal",
            "class": "isa_legal",
            "category": "constraint",
            "enabled": rules["isa_legal"],
            "scope": "instruction",
            "effect": "instruction candidates are repaired to implemented encodings (P8)",
        },
        {
            "rule_id": "mmio_reachability_bias",
            "class": "mmio_reachability_bias",
            "category": "bias",
            "enabled": rules["mmio_reachability_bias"],
            "scope": "mmio",
            "effect": "biased addressing resolves selector and offset inside declared windows",
        },
    ]


def _reset_semantics(plan: Mapping[str, object], mode: str) -> dict:
    reset = plan["reset"]
    cpu = reset["cpu_reset"]
    test = reset["test_reset"]
    peripheral_sinks = sorted(
        instance["instance_id"] for instance in plan["instances"]
        if instance.get("kind") == "peripheral"
    )
    cpu_sinks = list(cpu["sinks"])
    return {
        "mode": mode,
        "cpu_reset": {
            "held_in_reset_whole_test": mode == "mmio_only",
            "released_at": "test_begin",
            "signal": cpu["name"],
            "domain": cpu["domain"],
            "polarity": cpu["polarity"],
            "synchronous": cpu["synchronous"],
            "sinks": cpu_sinks,
            "shared_with_peripheral_ip_reset": False,
        },
        "peripheral_reset": {
            "held_in_reset_whole_test": False,
            "released_at": "test_begin",
            "signal": test["name"],
            "domain": test["domain"],
            "sinks": peripheral_sinks,
            "wired_to_cpu_reset": False,
        },
        "test_reset": {
            "asserted_at": list(test["asserted_at"]),
            "clears": list(test["clears"]),
            "separate_from_cpu_reset": True,
            "signal": test["name"],
            "domain": test["domain"],
            "clears_driver_state": True,
        },
        "reset_wiring": {
            "cpu_reset_net": cpu["name"],
            "cpu_reset_sinks": cpu_sinks,
            "peripheral_ip_reset_net": test["name"],
            "peripheral_ip_reset_sinks": peripheral_sinks,
            "cpu_reset_wired_to_peripheral_ip_reset": False,
            "peripheral_ip_reset_wired_to_cpu_reset": False,
            "shared_reset_net": False,
            "cpu_reset_held_in_reset_whole_test": mode == "mmio_only",
            "peripheral_ip_held_in_reset_whole_test": False,
            "peripheral_ip_released_at": "test_begin",
            "statement": (
                "the CPU reset net only sinks the CPU instance; the peripheral IP reset comes "
                "from the test reset and is released at test_begin in every mode, including "
                "mmio_only"
            ),
        },
    }


def _cpu_isolation() -> dict:
    return {
        "random_drive_cpu_internal_responses": False,
        "stimulus_drives_cpu_responses": False,
        "cpu_response_sources": ["cpu_adapters", "memory_model", "real_peripheral_adapters"],
        "statement": (
            "the stimulus layer only drives raw segment bits and the fuzz MMIO beat initiator; "
            "CPU instruction and data responses come from the generated adapters, the memory "
            "model and the real peripheral IP, never from random stimulus bits"
        ),
    }


def _rtl_projection(facts: Mapping[str, object], strategy: Mapping[str, object]) -> dict:
    selector = strategy["target_selector"]
    return {
        "module": DRIVER_MODULE,
        "source": DRIVER_SOURCE,
        "role": "beat_initiator",
        "segment_id": "mmio",
        "parameters": {
            "ADDRESS_WIDTH": facts["mmio_address_width"],
            "DATA_WIDTH": facts["mmio_data_width"],
            "SELECTOR_WIDTH": selector["width"],
            "SELECTOR_INVALID": selector["invalid_value"],
            "NUM_WINDOWS": max(1, len(facts["windows"])),
            "ADDRESS_STRATEGY": ADDRESS_STRATEGY_CODES[strategy["effective"]],
            "WINDOW_BASE": [window["base"] for window in facts["windows"]],
            "WINDOW_SIZE": [window["size"] for window in facts["windows"]],
        },
        "parameters_encoding": {
            "ADDRESS_STRATEGY": dict(ADDRESS_STRATEGY_CODES),
            "WINDOW_BASE": (
                "flat packed vector; window i occupies bits [i*ADDRESS_WIDTH +: ADDRESS_WIDTH]"
            ),
            "WINDOW_SIZE": "flat packed vector packed like WINDOW_BASE",
        },
        "ports": {
            "clk": "input",
            "reset": "input",
            "stim_offer": "input",
            "stim_target_selector": "input",
            "stim_offset": "input",
            "stim_write": "input",
            "stim_wdata": "input",
            "stim_be": "input",
            "req_valid": "output",
            "req_ready": "input",
            "write": "output",
            "addr": "output",
            "wdata": "output",
            "be": "output",
            "rsp_valid": "input",
            "rsp_ready": "output",
            "rdata": "input",
            "error": "input",
            "busy_drop_count": "output",
            "error_count": "output",
            "completion_count": "output",
            "error_code": "output",
        },
    }


__all__ = ["STIMULUS_SCHEMA", "SocStimulusError", "compile_soc_stimulus"]
