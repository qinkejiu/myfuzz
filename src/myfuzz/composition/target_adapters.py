"""Resolve target-side adapters from beat requests to real peripheral protocols.

Direction (fixed):
    processor-memory-beat initiator  ->  adapter  ->  peripheral target

The initiator is the SoC arbiter/router output (or the synthetic MMIO master).
The adapter drives a real peripheral target protocol: APB, TL-UL or Wishbone.
These modules are *not* the CPU-side *_processor_memory_adapter modules reused
backwards.  The CPU-side adapters consume a CPU memory protocol
(obi/axi4/ready-valid-memory/tl-ul) and *produce* beat requests; the target
adapters *consume* beat requests and produce peripheral transactions.  Reusing
a CPU-side adapter here would invert latching, ownership and error semantics,
so a CPU memory protocol is rejected with "not-a-target-protocol:<proto>".

Resolution is fail-closed.  Every capability that the caller records for the
target must carry evidence, and a capability combination the RTL cannot honour
is rejected instead of being flattened into a configuration that would be
silently wrong (for example an APB3 target that claims partial writes).
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "TargetAdapterError",
    "resolve_target_adapter",
]


class TargetAdapterError(ValueError):
    """Raised when a target cannot be driven by the beat initiator contract."""


#: CPU memory protocols that must never be used as a target-side protocol.
_CPU_MEMORY_PROTOCOLS = frozenset(
    {"obi", "axi4", "ready-valid-memory", "processor-memory-beat"}
)

_PROTOCOL_ALIASES = {
    "tlul": "tl-ul",
    "tl-ul": "tl-ul",
    "apb": "apb",
    "apb3": "apb",
    "apb4": "apb",
    "wishbone": "wishbone",
    "wb": "wishbone",
}

_IMPLIED_VERSIONS = {"apb3": "3", "apb4": "4"}

#: Canonical versions accepted for each supported target protocol.
_TARGET_VERSIONS: dict[str, tuple[str, ...]] = {
    "apb": ("3", "4"),
    "tl-ul": ("1",),
    "wishbone": ("classic", "1"),
}

_KNOWN_CAPABILITIES: dict[str, frozenset[str]] = {
    "apb": frozenset(
        {
            "byte_enable",
            "partial_write",
            "has_error",
            "data_width",
            "address_width",
        }
    ),
    "tl-ul": frozenset(
        {
            "byte_enable",
            "partial_write",
            "has_error",
            "data_width",
            "address_width",
            "integrity",
            "source_width",
            "sink_width",
            "user_width",
            "size_width",
        }
    ),
    "wishbone": frozenset(
        {
            "byte_enable",
            "partial_write",
            "has_error",
            "data_width",
            "address_width",
            "has_address_port",
            "address_units",
            "sel_implemented",
            "wishbone_flavour",
            "ack_requires_cyc",
        }
    ),
}

_WISHBONE_FLAVOURS = {
    "classic": 0,
    "registered-ack": 1,
    "registered-ack-cyc-ignored": 2,
}

_BEAT_FIELDS = (
    "req_valid",
    "req_ready",
    "write",
    "addr",
    "wdata",
    "be",
    "rsp_valid",
    "rsp_ready",
    "rdata",
    "error",
)

_HANDSHAKE_DETAILS = {
    "req_valid": "accepted only in the IDLE state with no response outstanding",
    "req_ready": "asserted in IDLE while no response is pending and reset is released",
    "rsp_valid": "asserted after the target completes and held until rsp_ready",
    "rsp_ready": "consumes the latched response; one outstanding transaction",
}


def _field(status: str, detail: str) -> dict[str, str]:
    return {"status": status, "detail": detail}


def _normalise_protocol(raw: Any) -> tuple[str, str | None]:
    text = str(raw).strip().lower().replace("_", "-")
    return _PROTOCOL_ALIASES.get(text, text), _IMPLIED_VERSIONS.get(text)


def _component_id(target: dict) -> str:
    return str(
        target.get("component_id")
        or target.get("target_id")
        or target.get("id")
        or "<unnamed-target>"
    )


def _capability_error(capability: str, component: str, detail: str = "") -> TargetAdapterError:
    suffix = f":{component}" if component else ""
    text = f"unsupported-target-capability:{capability}{suffix}"
    if detail:
        text = f"{text}:{detail}"
    return TargetAdapterError(text)


def _bool_fact(
    capabilities: dict, evidence: dict, component: str, name: str, *, default: bool
) -> bool:
    if name not in capabilities:
        return default
    value = capabilities[name]
    if not isinstance(value, bool):
        raise _capability_error(name.replace("_", "-"), component, "expected-boolean")
    if name not in evidence:
        raise _capability_error("missing-evidence", component, name)
    return value


def _int_fact(
    capabilities: dict, evidence: dict, component: str, name: str, *, default: int
) -> int:
    if name not in capabilities:
        return default
    value = capabilities[name]
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _capability_error(
            name.replace("_", "-"), component, "expected-non-negative-integer"
        )
    if name not in evidence:
        raise _capability_error("missing-evidence", component, name)
    return value


def _text_fact(
    capabilities: dict, evidence: dict, component: str, name: str, *, default: str
) -> str:
    if name not in capabilities:
        return default
    value = capabilities[name]
    if not isinstance(value, str) or not value:
        raise _capability_error(name.replace("_", "-"), component, "expected-non-empty-string")
    if name not in evidence:
        raise _capability_error("missing-evidence", component, name)
    return value


def _window(target: dict, component: str) -> tuple[int, int]:
    window = target.get("window") or {}
    if not isinstance(window, dict):
        raise _capability_error("window", component, "expected-object")
    base = window.get("base", 0)
    size = window.get("size", 0)
    for name, value in (("base", base), ("size", size)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise _capability_error("window", component, f"invalid-{name}")
    return base, size


def _window_alignment(base: int, size: int, data_width: int, component: str) -> None:
    if size == 0:
        return
    granularity = data_width // 8
    if base % granularity or size % granularity:
        raise _capability_error(
            "window-alignment", component, f"base={base}:size={size}:granularity={granularity}"
        )


def _evidence_map(target: dict) -> dict[str, dict]:
    """Index recorded evidence by the capability fact it documents.

    Two shapes are accepted: a list of records carrying a 'fact' key (the shape
    used by this module's callers) and a mapping of fact name to record, which
    is how soc_plan target contracts record evidence.  A record may be a path
    string or an object with 'topic'/'evidence_path'/'provenance'.
    """
    evidence = target.get("evidence") or []
    mapped: dict[str, dict] = {}
    if isinstance(evidence, dict):
        for fact, record in evidence.items():
            if isinstance(record, str):
                mapped[str(fact)] = {"topic": None, "evidence_path": record, "provenance": None}
            elif isinstance(record, dict):
                mapped[str(fact)] = record
        return mapped
    if not isinstance(evidence, list):
        raise ValueError("invalid-target-evidence:expected-list-or-object")
    for item in evidence:
        if isinstance(item, dict) and isinstance(item.get("fact"), str):
            mapped.setdefault(item["fact"], item)
    return mapped


def _capability_evidence(
    capabilities: dict, evidence: dict[str, dict], component: str
) -> dict[str, dict]:
    resolved: dict[str, dict] = {}
    for fact, value in capabilities.items():
        record = evidence.get(fact)
        if record is None:
            raise _capability_error("missing-evidence", component, fact)
        resolved[fact] = {
            "value": value,
            "topic": record.get("topic"),
            "evidence_path": record.get("evidence_path"),
            "provenance": record.get("provenance"),
        }
    return resolved


def _parameter(name: str, value: Any) -> dict[str, Any]:
    return {"name": name, "value": value}


def _beat_fields(
    *,
    protocol: str,
    partial_write: bool,
    byte_enable: bool,
    has_address_port: bool,
    address_units: str,
    error_pin: bool,
    integrity: bool = False,
) -> dict[str, dict[str, str]]:
    fields = {
        name: _field("honoured", "handled by the beat request/response handshake")
        for name in _BEAT_FIELDS
    }
    for name, detail in _HANDSHAKE_DETAILS.items():
        fields[name] = _field("honoured", detail)

    if protocol == "apb":
        fields["addr"] = _field(
            "honoured",
            "driven as paddr in SETUP and ACCESS; the declared window is checked before any "
            "transfer and an out-of-window request returns an error response with psel low",
        )
        fields["wdata"] = _field(
            "honoured", "driven as pwdata and held stable through APB wait states"
        )
        fields["write"] = _field(
            "honoured", "driven as pwrite with the SETUP then ACCESS phase sequence"
        )
        fields["rdata"] = _field(
            "honoured", "sampled from prdata on PREADY and returned only for reads"
        )
        fields["error"] = _field(
            "honoured",
            "pslverr maps to the beat error response"
            if error_pin
            else "this target has no PSLVERR pin; only adapter-side rejections set the beat error",
        )
        if byte_enable and partial_write:
            fields["be"] = _field(
                "honoured",
                "APB4 PSTRB is driven from be for writes; reads return the full word and clear "
                "PSTRB because APB has no read strobe",
            )
        else:
            fields["be"] = _field(
                "qualified",
                "APB3 has no PSTRB and this IP has no per-byte write enable: only writes whose "
                "be is all ones are issued; any partial write is answered with a beat error "
                "response and zero APB transfers, and no read-modify-write is synthesised",
            )
    elif protocol == "tl-ul":
        fields["addr"] = _field(
            "honoured",
            "driven as a_address; the declared window is checked before the A channel and an "
            "out-of-window request returns an error response with a_valid low",
        )
        fields["wdata"] = _field("honoured", "driven as a_data and held until the A handshake")
        fields["write"] = _field(
            "honoured",
            "Get for reads, PutFullData for full writes, PutPartialData for masked writes",
        )
        fields["rdata"] = _field(
            "honoured",
            "taken from d_data only when d_valid and not d_error; writes and errored reads "
            "return zero",
        )
        fields["error"] = _field(
            "honoured",
            "d_error, a D-channel shape violation or an adapter timeout becomes the beat error",
        )
        fields["be"] = _field(
            "honoured", "drives a_mask for writes and the full byte mask for reads"
        )
        if integrity:
            fields["addr"]["detail"] += (
                "; a_user command integrity covers {addr, opcode, mask, instr_type} and data "
                "integrity covers a_data"
            )
    else:
        fields["wdata"] = _field("honoured", "driven as dat_w and held stable for the bus cycle")
        fields["write"] = _field("honoured", "driven as we for the whole bus cycle")
        fields["rdata"] = _field(
            "honoured", "sampled from dat_r on ACK; writes and ERR completions return zero"
        )
        if byte_enable and partial_write:
            fields["be"] = _field("honoured", "driven as sel and honoured by the target")
        else:
            fields["be"] = _field(
                "qualified",
                "sel is driven, but partial writes are rejected with a beat error response and "
                "zero bus cycles because i_wb_sel is unimplemented or register-specific in this "
                "target",
            )
        if has_address_port:
            fields["addr"] = _field(
                "honoured",
                "beat byte address is converted to the target address port "
                f"({address_units} units) inside the declared window",
            )
        else:
            fields["addr"] = _field(
                "qualified",
                "the target has no address port: the beat address is only decoded against the "
                "declared single-register window and is never forwarded",
            )
        fields["error"] = _field(
            "honoured" if error_pin else "qualified",
            "err is a real target pin and maps to the beat error response"
            if error_pin
            else "the target has no error output; the fabric must drive err with its own decode "
            "error (HAS_ERR=0) and no target pin is invented",
        )
    return fields


def _resolve_apb(
    backend: dict, target: dict, capabilities: dict, evidence: dict[str, dict], component: str
) -> dict:
    version = str(target.get("version", "")).strip()
    byte_enable = _bool_fact(capabilities, evidence, component, "byte_enable", default=False)
    partial_write = _bool_fact(capabilities, evidence, component, "partial_write", default=False)
    has_error = _bool_fact(capabilities, evidence, component, "has_error", default=False)
    if partial_write and (version == "3" or not byte_enable):
        raise _capability_error(
            "partial-write", component, f"apb{version}:byte_enable={byte_enable}"
        )
    has_pstrb = int(version == "4")
    data_width = _int_fact(
        capabilities, evidence, component, "data_width", default=int(target.get("data_width", 32))
    )
    base, size = _window(target, component)
    _window_alignment(base, size, data_width, component)
    return {
        "adapter_id": f"beat-to-apb{version}",
        "rtl_module": "beat_to_apb",
        "rtl_source": "src/myfuzz/protocols/rtl/beat_to_apb.sv",
        "parameters": [
            _parameter("ADDRESS_WIDTH", int(backend["address_width"])),
            _parameter("DATA_WIDTH", data_width),
            _parameter("HAS_PSTRB", has_pstrb),
            _parameter("SUPPORTS_PARTIAL_WRITE", int(partial_write and byte_enable and has_pstrb)),
            _parameter("HAS_PSLVERR", int(has_error)),
            _parameter("MAX_WAIT_CYCLES", int(target.get("max_wait_cycles", 16))),
            _parameter("WINDOW_BASE", base),
            _parameter("WINDOW_SIZE", size),
        ],
        "target_side_ports": [
            {"role": role, "port": role, "direction": direction}
            for role, direction in (
                ("paddr", "output"),
                ("psel", "output"),
                ("penable", "output"),
                ("pwrite", "output"),
                ("pwdata", "output"),
                ("pstrb", "output"),
                ("pready", "input"),
                ("prdata", "input"),
                ("pslverr", "input"),
            )
        ],
        "error_source": "target_pin" if has_error else "none",
        "unsupported": []
        if (byte_enable and partial_write)
        else [
            {
                "capability": "partial_write",
                "reason": "APB3 has no PSTRB and this target has no per-byte write enable; "
                "partial writes are rejected with an error response and no APB transfer",
            }
        ],
        "beat_fields": _beat_fields(
            protocol="apb",
            partial_write=partial_write,
            byte_enable=byte_enable,
            has_address_port=True,
            address_units="byte",
            error_pin=has_error,
        ),
    }


def _resolve_tlul(
    backend: dict, target: dict, capabilities: dict, evidence: dict[str, dict], component: str
) -> dict:
    byte_enable = _bool_fact(capabilities, evidence, component, "byte_enable", default=True)
    partial_write = _bool_fact(capabilities, evidence, component, "partial_write", default=False)
    has_error = _bool_fact(capabilities, evidence, component, "has_error", default=True)
    integrity = _text_fact(capabilities, evidence, component, "integrity", default="required")
    if integrity not in ("required", "none"):
        raise _capability_error("integrity", component, integrity)
    if partial_write and not byte_enable:
        raise _capability_error("partial-write", component, "byte_enable=False")
    data_width = _int_fact(
        capabilities, evidence, component, "data_width", default=int(target.get("data_width", 32))
    )
    generate_integrity = integrity == "required"
    if generate_integrity and data_width != 32:
        # OpenTitan TL-UL data integrity is the 7-bit inv-39/32 code over a
        # 32-bit data bus; no wider code fits tl_a_user_t.data_intg.
        raise _capability_error(
            "integrity-width", component, f"data_width={data_width}:tl_data_intg_width=7"
        )
    source_width = _int_fact(capabilities, evidence, component, "source_width", default=8)
    sink_width = _int_fact(capabilities, evidence, component, "sink_width", default=1)
    user_width = _int_fact(capabilities, evidence, component, "user_width", default=23)
    size_width = _int_fact(capabilities, evidence, component, "size_width", default=2)
    if source_width < 1:
        raise _capability_error("source-width", component, str(source_width))
    if sink_width < 1:
        raise _capability_error("sink-width", component, str(sink_width))
    if size_width < 2:
        raise _capability_error("size-width", component, str(size_width))
    if generate_integrity and user_width < 18:
        raise _capability_error("integrity-user-width", component, str(user_width))
    source_id = int(backend.get("source_id", 0))
    if source_id >= (1 << source_width):
        raise _capability_error(
            "source-id", component, f"source_id={source_id}:source_width={source_width}"
        )
    base, size = _window(target, component)
    _window_alignment(base, size, data_width, component)
    return {
        "adapter_id": "beat-to-tlul",
        "rtl_module": "beat_to_tlul",
        "rtl_source": "src/myfuzz/protocols/rtl/beat_to_tlul.sv",
        "parameters": [
            _parameter("ADDRESS_WIDTH", int(backend["address_width"])),
            _parameter("DATA_WIDTH", data_width),
            _parameter("SIZE_WIDTH", size_width),
            _parameter("SOURCE_WIDTH", source_width),
            _parameter("SINK_WIDTH", sink_width),
            _parameter("USER_WIDTH", user_width),
            _parameter("DUSER_WIDTH", 14),
            _parameter("GEN_INTEGRITY", int(generate_integrity)),
            _parameter("SOURCE_ID", source_id),
            _parameter("MAX_WAIT_CYCLES", int(target.get("max_wait_cycles", 16))),
            _parameter("WINDOW_BASE", base),
            _parameter("WINDOW_SIZE", size),
        ],
        "target_side_ports": [
            {"role": role, "port": role, "direction": direction}
            for role, direction in (
                ("a_valid", "output"),
                ("a_ready", "input"),
                ("a_opcode", "output"),
                ("a_param", "output"),
                ("a_size", "output"),
                ("a_source", "output"),
                ("a_address", "output"),
                ("a_mask", "output"),
                ("a_data", "output"),
                ("a_user", "output"),
                ("d_valid", "input"),
                ("d_ready", "output"),
                ("d_opcode", "input"),
                ("d_param", "input"),
                ("d_size", "input"),
                ("d_source", "input"),
                ("d_sink", "input"),
                ("d_data", "input"),
                ("d_user", "input"),
                ("d_error", "input"),
            )
        ],
        "error_source": "target_pin" if has_error else "none",
        "unsupported": []
        if generate_integrity
        else [
            {
                "capability": "integrity",
                "reason": "recorded as not required for this target; the adapter drives the "
                "TL_A_USER_DEFAULT integrity fields (all ones) and the fabric owns integrity",
            }
        ],
        "beat_fields": _beat_fields(
            protocol="tl-ul",
            partial_write=partial_write,
            byte_enable=byte_enable,
            has_address_port=True,
            address_units="byte",
            error_pin=has_error,
            integrity=generate_integrity,
        ),
    }


def _resolve_wishbone(
    backend: dict, target: dict, capabilities: dict, evidence: dict[str, dict], component: str
) -> dict:
    byte_enable = _bool_fact(capabilities, evidence, component, "byte_enable", default=False)
    partial_write = _bool_fact(capabilities, evidence, component, "partial_write", default=False)
    has_error = _bool_fact(capabilities, evidence, component, "has_error", default=False)
    has_address_port = _bool_fact(
        capabilities, evidence, component, "has_address_port", default=True
    )
    sel_implemented = _bool_fact(
        capabilities, evidence, component, "sel_implemented", default=True
    )
    address_units = _text_fact(capabilities, evidence, component, "address_units", default="byte")
    if address_units not in ("byte", "word"):
        raise _capability_error("address-units", component, address_units)
    flavour = _text_fact(capabilities, evidence, component, "wishbone_flavour", default="classic")
    if flavour not in _WISHBONE_FLAVOURS:
        raise _capability_error("wishbone-flavour", component, flavour)
    if "ack_requires_cyc" in capabilities:
        ack_requires_cyc = _bool_fact(
            capabilities, evidence, component, "ack_requires_cyc", default=True
        )
        if ack_requires_cyc != (flavour != "registered-ack-cyc-ignored"):
            raise _capability_error(
                "ack-requires-cyc",
                component,
                f"flavour={flavour}:ack_requires_cyc={ack_requires_cyc}",
            )
    if partial_write and (not byte_enable or not sel_implemented):
        raise _capability_error(
            "partial-write",
            component,
            f"byte_enable={byte_enable}:sel_implemented={sel_implemented}",
        )
    data_width = _int_fact(
        capabilities, evidence, component, "data_width", default=int(target.get("data_width", 32))
    )
    base, size = _window(target, component)
    if not has_address_port and size == 0:
        raise _capability_error(
            "window", component, "target has no address port and no explicit window"
        )
    _window_alignment(base, size, data_width, component)
    target_address_width = _int_fact(
        capabilities,
        evidence,
        component,
        "address_width",
        default=0
        if not has_address_port
        else int(target.get("address_width", backend["address_width"])),
    )
    if has_address_port and target_address_width < 1:
        raise _capability_error("address-width", component, str(target_address_width))
    if not has_address_port:
        target_address_width = 0
    flavour_code = _WISHBONE_FLAVOURS[flavour]
    return {
        "adapter_id": f"beat-to-wishbone-{flavour}",
        "rtl_module": "beat_to_wishbone",
        "rtl_source": "src/myfuzz/protocols/rtl/beat_to_wishbone.sv",
        "parameters": [
            _parameter("ADDRESS_WIDTH", int(backend["address_width"])),
            _parameter("DATA_WIDTH", data_width),
            _parameter("WB_FLAVOUR", flavour_code),
            _parameter("TARGET_ADDRESS_WIDTH", target_address_width),
            _parameter("ADDRESS_UNITS", int(address_units == "word")),
            _parameter(
                "SUPPORTS_PARTIAL_WRITE", int(partial_write and byte_enable and sel_implemented)
            ),
            _parameter("HAS_ERR", int(has_error)),
            _parameter("MAX_WAIT_CYCLES", int(target.get("max_wait_cycles", 16))),
            _parameter("WINDOW_BASE", base),
            _parameter("WINDOW_SIZE", size),
        ],
        "target_side_ports": [
            {"role": role, "port": role, "direction": direction}
            for role, direction in (
                ("cyc", "output"),
                ("stb", "output"),
                ("we", "output"),
                ("adr", "output"),
                ("dat_w", "output"),
                ("sel", "output"),
                ("ack", "input"),
                ("err", "input"),
                ("stall", "input"),
                ("dat_r", "input"),
            )
        ],
        "error_source": "target_pin" if has_error else "fabric",
        "wishbone": {
            "flavour": flavour,
            "flavour_code": flavour_code,
            "stb_pulse_cycles": None if flavour == "classic" else 1,
            "cyc_hold_after_stb_cycles": 1
            if flavour == "registered-ack"
            else (0 if flavour == "registered-ack-cyc-ignored" else None),
            "target_has_address_port": has_address_port,
            "target_address_width": target_address_width,
            "address_units": address_units,
            "sel_implemented": sel_implemented,
            "ack_requires_cyc": flavour != "registered-ack-cyc-ignored",
        },
        "unsupported": (
            []
            if partial_write
            else [
                {
                    "capability": "partial_write",
                    "reason": "i_wb_sel is unimplemented or register-specific in this target; "
                    "sub-word writes are rejected with a beat error response and zero bus cycles, "
                    "and no read-modify-write is synthesised",
                }
            ]
        )
        + (
            []
            if has_error
            else [
                {
                    "capability": "has_error",
                    "reason": "the target has no error output; the fabric must drive err with its "
                    "own decode error and HAS_ERR=0, no target pin is invented",
                }
            ]
        ),
        "beat_fields": _beat_fields(
            protocol="wishbone",
            partial_write=partial_write,
            byte_enable=byte_enable,
            has_address_port=has_address_port,
            address_units=address_units,
            error_pin=has_error,
        ),
    }


def resolve_target_adapter(backend: dict, target: dict) -> dict:
    """Resolve the target-side adapter that drives one real peripheral.

    backend describes the beat initiator: protocol (must be
    processor-memory-beat), version (1), address_width, data_width and an
    optional source_id.

    target describes the peripheral: component_id, protocol and version,
    widths, an optional window (byte base/size), a capabilities mapping of
    recorded facts and the evidence list those facts were recorded from.
    Every recorded capability must carry evidence.

    Returns a JSON-compatible dict with the RTL module and parameters, the
    covered window, the capability evidence and the disposition of every beat
    field.

    Raises:
        TargetAdapterError: for unsupported-initiator-protocol,
            unsupported-beat-width, not-a-target-protocol,
            unsupported-target-protocol, unsupported-target-width and
            unsupported-target-capability rejections.
    """
    if not isinstance(backend, dict):
        raise TypeError("backend must be a dict")
    if not isinstance(target, dict):
        raise TypeError("target must be a dict")

    backend_protocol, _ = _normalise_protocol(backend.get("protocol", ""))
    backend_version = str(backend.get("version", "")).strip()
    if backend_protocol != "processor-memory-beat" or backend_version != "1":
        raise TargetAdapterError(
            "unsupported-initiator-protocol:"
            + (backend_protocol or "missing")
            + "@"
            + (backend_version or "missing")
        )
    try:
        address_width = int(backend["address_width"])
        data_width = int(backend["data_width"])
    except (KeyError, TypeError, ValueError) as error:
        raise TargetAdapterError(f"unsupported-beat-width:{error}") from error
    if address_width < 1:
        raise TargetAdapterError(f"unsupported-beat-width:address_width:{address_width}")
    if data_width != 32:
        raise TargetAdapterError(
            f"unsupported-beat-width:data_width:{data_width}:first-release-supports-32"
        )

    raw_protocol = target.get("protocol", "")
    sequence_version: str | None = None
    if isinstance(raw_protocol, (list, tuple)):
        # soc_plan target contracts carry protocol as a (protocol, version) pair.
        if len(raw_protocol) != 2:
            raise TargetAdapterError(f"unsupported-target-protocol:{raw_protocol!r}")
        sequence_version = str(raw_protocol[1])
        raw_protocol = raw_protocol[0]
    protocol, implied_version = _normalise_protocol(raw_protocol)
    if protocol in _CPU_MEMORY_PROTOCOLS:
        raise TargetAdapterError(f"not-a-target-protocol:{protocol}")
    if protocol not in _TARGET_VERSIONS:
        raise TargetAdapterError(f"unsupported-target-protocol:{protocol or 'missing'}")
    version = str(target.get("version", sequence_version or implied_version or "")).strip()
    if not version:
        version = "classic" if protocol == "wishbone" else _TARGET_VERSIONS[protocol][0]
    if version not in _TARGET_VERSIONS[protocol]:
        raise TargetAdapterError(f"unsupported-target-protocol:{protocol}@{version}")
    if protocol == "wishbone":
        version = "classic"

    component = _component_id(target)
    capabilities = target.get("capabilities") or {}
    if not isinstance(capabilities, dict):
        raise _capability_error("capabilities", component, "expected-object")
    unknown = sorted(set(capabilities) - _KNOWN_CAPABILITIES[protocol])
    if unknown:
        raise _capability_error("unknown", component, unknown[0])
    evidence = _evidence_map(target)

    target_data_width = capabilities.get("data_width", target.get("data_width", data_width))
    if target_data_width != data_width:
        raise TargetAdapterError(
            f"unsupported-target-width:data_width:{target_data_width}:beat_data_width:{data_width}"
        )

    if protocol == "apb":
        resolved = _resolve_apb(backend, target, capabilities, evidence, component)
    elif protocol == "tl-ul":
        resolved = _resolve_tlul(backend, target, capabilities, evidence, component)
    else:
        resolved = _resolve_wishbone(backend, target, capabilities, evidence, component)

    base, size = _window(target, component)
    result = {
        "schema_version": "target_adapter.v1",
        "direction": "beat-initiator-to-peripheral-target",
        "initiator_protocol": {"protocol": "processor-memory-beat", "version": "1"},
        "target_protocol": {"protocol": protocol, "version": version},
        "component_id": component,
        "clock": "clk",
        "reset": {"port": "reset", "polarity": "active_high", "synchrony": "synchronous"},
        "max_outstanding": 1,
        "window": {"base": base, "size": size},
        "capability_evidence": _capability_evidence(capabilities, evidence, component),
    }
    result.update(resolved)
    return result
