"""Direct structural harness projection."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .abi import RawBitAbi, _canonical, build_raw_abi, content_hash, control_declarations, manifest_ports


@dataclass(frozen=True, slots=True)
class HarnessArtifact:
    mode: str
    raw_width: int
    coverage_universe_id: str
    candidate_id: str | None
    abi: RawBitAbi
    source_text: str
    content_hash: str

    @property
    def kind(self) -> str:
        return self.mode

    @property
    def raw_abi(self) -> RawBitAbi:
        return self.abi

    @property
    def coverage_universe(self) -> str:
        return self.coverage_universe_id

    @property
    def cycles_per_sample(self) -> int:
        return 1

    def manifest_fragment(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "candidate_id": self.candidate_id,
            "coverage_universe_id": self.coverage_universe_id,
            "raw_width": self.raw_width,
            "abi_hash": self.abi.abi_hash,
            "content_hash": self.content_hash,
            "destinations": [
                {
                    "destination_id": item.destination_id,
                    "component_id": item.component_id,
                    "port_id": item.port_id,
                    "width": item.width,
                }
                for item in self.abi.destinations
            ],
            "mapping": [
                {
                    "raw_lo": item.raw_lo,
                    "raw_hi": item.raw_hi,
                    "destination_id": item.destination_id,
                    "destination_lo": item.destination_lo,
                    "action": item.action,
                    "category": item.category,
                }
                for item in self.abi.uses
            ],
        }


def coverage_id(manifest: object) -> str:
    if isinstance(manifest, Mapping):
        explicit = manifest.get("coverage_universe_id", manifest.get("coverage_universe_hash"))
        if isinstance(explicit, str) and explicit:
            return explicit
        universe = manifest.get("coverage_universe", ())
        if not isinstance(universe, (list, tuple)):
            raise ValueError("manifest.coverage_universe must be an array")
        return content_hash(tuple(sorted(universe, key=_canonical)))
    raise ValueError("manifest must be an object")


def candidate_id(manifest: Mapping[str, object]) -> str | None:
    value = manifest.get("candidate_id")
    if not isinstance(value, str):
        candidate = manifest.get("candidate")
        value = candidate.get("candidate_id") if isinstance(candidate, Mapping) else None
    return value if isinstance(value, str) and value else None


def _identifier(value: object, fallback: str) -> str:
    return value if isinstance(value, str) and value else fallback


def _sv_identifier(value: object, fallback: str) -> str:
    identifier = _identifier(value, fallback)
    if identifier[0].isalpha() or identifier[0] == "_":
        if all(character.isalnum() or character in {"_", "$"} for character in identifier[1:]):
            return identifier
    return f"\\{identifier} "


def _logic(width: int, name: str) -> str:
    return f"    logic {name};" if width == 1 else f"    logic [{width - 1}:0] {name};"


def _constant(width: int, value: int) -> str:
    return f"{width}'h{value:x}"


def emit_direct(
    manifest: object,
    mode: str,
    abi: RawBitAbi,
    *,
    gated_port_ids: frozenset[int] = frozenset(),
) -> str:
    if not isinstance(manifest, Mapping):
        raise ValueError("manifest must be an object")
    top = manifest.get("top", {})
    if not isinstance(top, Mapping) or not isinstance(top.get("module"), str) or not top["module"]:
        raise ValueError("manifest.top.module is required for generated port mapping")
    module = top["module"]
    controls = control_declarations(manifest)
    clock = controls.get("clock")
    reset = controls.get("reset")
    has_io_meta_reset = bool(reset and reset.get("io_meta_reset") is True)
    header_ports = []
    if clock is not None:
        header_ports.append("    input logic clock")
    if reset is not None:
        header_ports.append("    input logic reset")
        if has_io_meta_reset:
            header_ports.append("    input logic io_meta_reset")
    header_ports.append(f"    input logic [{abi.raw_width - 1}:0] rfuzz_input_bits")
    module_name = f"myfuzz_{mode}_{abi.abi_hash[:12]}"
    lines = [
        f"module {module_name} (",
        *[f"{port}," if index + 1 < len(header_ports) else port for index, port in enumerate(header_ports)],
        ");",
        (
            f"    // protocol_projection of {module}; groups marked gate retain their raw slices"
            if mode == "candidate_depaware"
            else f"    // direct structural projection of {module}"
        ),
    ]
    destinations = {item.port_id: item for item in abi.destinations}
    uses = {abi.destinations[item.destination_id].port_id: item for item in abi.uses}
    ports = manifest_ports(manifest)
    for port in ports:
        port_id, width = port["port_id"], port["width"]
        signal = f"port_{port_id}"
        lines.append(_logic(width, signal))
        role = port.get("semantic_role")
        if role == "clock":
            active_level = controls["clock"]["active_level"]
            clock_expression = "clock" if active_level == 1 else "~clock"
            lines.append(f"    assign {signal} = {{{width}{{{clock_expression}}}}};")
        elif role == "reset":
            active_level = controls["reset"]["active_level"]
            reset_expression = "reset | io_meta_reset" if has_io_meta_reset else "reset"
            expression = reset_expression if active_level == 1 else f"~({reset_expression})"
            lines.append(f"    assign {signal} = {expression};")
        elif port_id in destinations:
            use = uses[port_id]
            if port_id in gated_port_ids:
                lines.append(f"    // gate dependency group for port {port_id}")
                reset_value = port.get("reset_value")
                lines.append(f"    assign {signal} = {_constant(width, reset_value if isinstance(reset_value, int) else 0)};")
            else:
                lines.append(f"    assign {signal} = rfuzz_input_bits[{use.raw_hi}:{use.raw_lo}];")
        elif port["direction"] in {"input", "inout"}:
            value = port.get("constant_value", port.get("reset_value"))
            assert isinstance(value, int)
            lines.append(f"    assign {signal} = {_constant(width, value)};")
    lines.append(f"    {_sv_identifier(module, 'generated_top')} dut (")
    for index, port in enumerate(ports):
        comma = "," if index + 1 < len(ports) else ""
        pin = _sv_identifier(port.get("emitted_name"), f"port_{port['port_id']}")
        lines.append(f"        .{pin}(port_{port['port_id']}){comma}")
    lines.append("    );")
    lines.append("endmodule")
    return "\n".join(lines) + "\n"


def build_direct(manifest: object, mode: str) -> HarnessArtifact:
    abi = build_raw_abi(manifest)
    source = emit_direct(manifest, mode, abi)
    assert isinstance(manifest, Mapping)
    return HarnessArtifact(mode, abi.raw_width, coverage_id(manifest), candidate_id(manifest), abi, source, content_hash({"source_text": source}))
