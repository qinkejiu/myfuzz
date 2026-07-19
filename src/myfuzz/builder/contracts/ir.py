"""Small, strict v1 IR contracts shared by all future backends."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping

from ..input_model import InputValidationError


CONTRACT_SCHEMAS: dict[str, Mapping[str, Any]] = {
    "system_ir_v1": {
        "required": ("schema", "name", "modules", "connections", "address_windows"),
        "schema": "myfuzz.system-ir/v1",
    },
    "protocol_backend_v1": {
        "required": ("schema", "backend_id", "version", "protocol", "capabilities"),
        "schema": "myfuzz.protocol-backend/v1",
    },
    "constraint_ir_v1": {
        "required": ("schema", "layout_digest", "cycle_width", "constraints"),
        "schema": "myfuzz.constraint-ir/v1",
    },
    "coverage_abi_v1": {
        "required": ("schema", "manifest_digest", "port_name", "width", "points"),
        "schema": "myfuzz.coverage-abi/v1",
    },
    "cpu_execution_profile_v1": {
        "required": ("schema", "cpu_id", "isa", "data_width", "address_width", "reset_vector",
                     "rom_window", "mailbox_window", "watchdog_window", "reset",
                     "rom_install_backend", "startup_fragment_digest"),
        "schema": "myfuzz.cpu-execution-profile/v1",
    },
    "rom_install_backend_v1": {
        "required": ("schema", "kind", "loader_interface", "verification"),
        "schema": "myfuzz.rom-install-backend/v1",
    },
    "access_record_v1": {
        "required": ("schema", "ip_select", "read_write", "offset", "data"),
        "schema": "myfuzz.access-record/v1",
    },
    "record_terminal_ack_v1": {
        "required": ("schema", "sequence", "status", "route", "address", "direction",
                     "response", "cycles"),
        "schema": "myfuzz.record-terminal-ack/v1",
    },
    "experiment_variant_v1": {
        "required": ("schema", "name", "generated_soc", "constraints"),
        "schema": "myfuzz.experiment-variant/v1",
    },
    "coverage_abi_v2": {
        "required": ("schema", "catalog_digest", "port_name", "width", "epoch_width", "points",
                     "transport_width", "writer", "sampling"),
        "schema": "myfuzz.coverage-abi/v2",
    },
    "experiment_manifest_v1": {
        "required": ("schema", "experiment_id", "cpu_profile", "variants", "components",
                     "ip_instances", "rawbits_layout_digest", "access_record_layout",
                     "coverage_abi_digest", "transaction_slots", "cycle_budget", "digest"),
        "schema": "myfuzz.experiment-manifest/v1",
    },
    "experiment_result_v1": {
        "required": ("schema", "experiment_digest", "cpu_id", "variant", "repeat", "seed",
                     "wall_seconds", "testcase_count", "consumed_inputs", "coverage_points_hit",
                     "coverage_points_total", "coverage_trace", "terminal_counts", "artifact_digests"),
        "schema": "myfuzz.experiment-result/v1",
    },
    "rfuzz_dependency_v1": {
        "required": ("schema", "source_url", "revision", "license_file", "license_sha256", "files",
                     "patches", "build_tools"),
        "schema": "myfuzz.rfuzz-dependency/v1",
    },
    "transaction_server_v1": {
        "required": ("schema", "protocol", "rawbits_schema", "access_record_schema",
                     "ready_valid_consume", "operations", "terminal_events", "epoch_width"),
        "schema": "myfuzz.transaction-server/v1",
    },
    "soc_ir_v2": {
        "required": ("schema", "name", "logical_modules", "instances", "endpoints",
                     "port_bindings", "protocol_edges", "address_views", "clock_domains",
                     "reset_domains", "interrupt_edges", "external_boundaries", "service_nodes",
                     "adapters", "unknown_port_decisions", "provenance", "digest"),
        "schema": "myfuzz.soc-ir/v2",
    },
    "register_model_ir_v1": {
        "required": ("schema", "name", "blocks", "provenance", "digest"),
        "schema": "myfuzz.register-model-ir/v1",
    },
    "control_plane_ir_v1": {
        "required": ("schema", "soc_digest", "cpu_profile_digest", "register_model_digests",
                     "fields", "operations", "provenance", "digest"),
        "schema": "myfuzz.control-plane-ir/v1",
    },
    "temporal_constraint_ir_v2": {
        "required": ("schema", "rawbits_layout_digest", "soc_digest", "specification_digest",
                     "constraints", "provenance", "digest"),
        "schema": "myfuzz.temporal-constraint-ir/v2",
    },
    "experiment_manifest_v2": {
        "required": ("schema", "experiment_id", "cpu_profile_digest", "soc_digest",
                     "control_plane_digest", "constraint_digest", "rawbits_layout_digest",
                     "rom_digest", "coverage_abi_digest", "variants", "components",
                     "provenance", "digest"),
        "schema": "myfuzz.experiment-manifest/v2",
    },
    "rawbits_layout_v3": {
        "required": ("schema", "fields", "cycle_width", "bytes_per_cycle", "digest",
                     "byte_order", "bit_order", "cycle_order"),
        "schema": "myfuzz.rawbits-layout/v3",
    },
    "rawbits_layout_v5": {
        "required": ("schema", "fields", "record_width_bits", "record_width_bytes",
                     "max_testcase_bytes", "max_steps", "digest", "byte_order",
                     "bit_order", "step_order", "partial_record"),
        "schema": "myfuzz.rawbits-layout/v5",
    },
    "rawbits_opaque_envelope_v3": {
        "required": ("schema", "legacy_schema", "legacy_sha256", "payload_encoding",
                     "payload", "provenance", "digest"),
        "schema": "myfuzz.rawbits-opaque-envelope/v3",
    },
    "compose_v5_manifest_v1": {
        "required": ("schema", "name", "sources", "components", "digest"),
        "schema": "myfuzz.compose-v5-manifest/v1",
    },
    "compose_v5_qualification_v1": {
        "required": ("schema", "manifest_digest", "eligible", "components",
                     "failure_codes", "digest"),
        "schema": "myfuzz.compose-v5-qualification/v1",
    },
    "compose_v5_target_audit_v1": {
        "required": ("schema", "targets", "all_eligible", "digest"),
        "schema": "myfuzz.compose-v5-target-audit/v1",
    },
    "compose_v5_contract_discovery_v1": {
        "required": (
            "schema", "grammar_version", "top_module", "manifest_digest", "frontend_schema",
            "module_reports", "missing_behavior_modules", "extra_behavior_modules",
            "binding_conflict_modules", "module_count", "matched_count", "unique_count",
            "ambiguous_count", "empty_count", "status", "digest",
        ),
        "schema": "myfuzz.contract-system-discovery/v5",
    },
    "compose_v5_fusesoc_recipe_v1": {
        "required": ("schema", "name", "mappings", "components", "digest"),
        "schema": "myfuzz.compose-v5-fusesoc-recipe/v1",
    },
    "compose_v5_fusesoc_materialization_v1": {
        "required": ("schema", "recipe_digest", "source_root", "manifest_digest",
                     "mappings", "components", "digest"),
        "schema": "myfuzz.compose-v5-fusesoc-materialization/v1",
    },
}


def _tuple_of_mappings(value: object, path: str) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, (tuple, list)):
        raise InputValidationError(f"{path}: expected an array")
    result = tuple(value)
    if any(not isinstance(item, Mapping) for item in result):
        raise InputValidationError(f"{path}: every item must be an object")
    return result


def _tuple_of_strings(value: object, path: str) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)):
        raise InputValidationError(f"{path}: expected an array")
    result = tuple(value)
    if any(not isinstance(item, str) or not item for item in result):
        raise InputValidationError(f"{path}: every item must be a non-empty string")
    return result


@dataclass(frozen=True)
class SystemIR:
    name: str
    modules: tuple[Mapping[str, Any], ...]
    connections: tuple[Mapping[str, Any], ...]
    address_windows: tuple[Mapping[str, Any], ...]
    schema: str = "myfuzz.system-ir/v1"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ProtocolBackend:
    backend_id: str
    version: str
    protocol: str
    capabilities: tuple[str, ...]
    schema: str = "myfuzz.protocol-backend/v1"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ConstraintIR:
    layout_digest: str
    cycle_width: int
    constraints: tuple[Mapping[str, Any], ...]
    schema: str = "myfuzz.constraint-ir/v1"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class CoverageABI:
    manifest_digest: str
    port_name: str
    width: int
    points: tuple[Mapping[str, Any], ...]
    schema: str = "myfuzz.coverage-abi/v1"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_contract(value: Mapping[str, Any], contract: str) -> None:
    """Validate the locked outer shape without silently accepting extra fields."""
    try:
        definition = CONTRACT_SCHEMAS[contract]
    except KeyError as exc:
        raise InputValidationError(f"unknown contract {contract!r}") from exc
    required = set(definition["required"])
    unknown = set(value) - required
    missing = required - set(value)
    if missing:
        raise InputValidationError(f"{contract}: missing field(s): {', '.join(sorted(missing))}")
    if unknown:
        raise InputValidationError(f"{contract}: unknown field(s): {', '.join(sorted(unknown))}")
    if value["schema"] != definition["schema"]:
        raise InputValidationError(
            f"{contract}.schema: expected {definition['schema']!r}, got {value['schema']!r}"
        )
    array_fields = {
        "system_ir_v1": ("modules", "connections", "address_windows"),
        "constraint_ir_v1": ("constraints",),
        "coverage_abi_v1": ("points",),
        "coverage_abi_v2": ("points",),
        "experiment_manifest_v1": ("variants", "components", "ip_instances"),
        "experiment_result_v1": ("coverage_trace", "artifact_digests"),
        "rfuzz_dependency_v1": ("files", "patches", "build_tools"),
        "soc_ir_v2": ("logical_modules", "instances", "endpoints", "port_bindings",
                      "protocol_edges", "address_views", "clock_domains", "reset_domains",
                      "interrupt_edges", "external_boundaries", "service_nodes", "adapters",
                      "unknown_port_decisions"),
        "register_model_ir_v1": ("blocks",),
        "control_plane_ir_v1": ("register_model_digests", "fields", "operations"),
        "temporal_constraint_ir_v2": ("constraints",),
        "experiment_manifest_v2": ("variants", "components"),
        "rawbits_layout_v3": ("fields",),
        "rawbits_layout_v5": ("fields",),
        "compose_v5_manifest_v1": ("sources", "components"),
        "compose_v5_qualification_v1": ("components",),
        "compose_v5_fusesoc_recipe_v1": ("components",),
        "compose_v5_fusesoc_materialization_v1": ("components",),
        "compose_v5_target_audit_v1": ("targets",),
        "compose_v5_contract_discovery_v1": ("module_reports",),
    }
    for key in array_fields.get(contract, ()):
        if key in value:
            _tuple_of_mappings(value[key], f"{contract}.{key}")
    string_array_fields = {
        "compose_v5_contract_discovery_v1": (
            "missing_behavior_modules", "extra_behavior_modules", "binding_conflict_modules",
        ),
    }
    for key in string_array_fields.get(contract, ()):
        if key in value:
            _tuple_of_strings(value[key], f"{contract}.{key}")
    if "cycle_width" in value and (
        isinstance(value["cycle_width"], bool)
        or not isinstance(value["cycle_width"], int)
        or value["cycle_width"] <= 0
    ):
        raise InputValidationError(f"{contract}.cycle_width: expected an integer greater than zero")
    if "width" in value and (
        isinstance(value["width"], bool) or not isinstance(value["width"], int) or value["width"] < 0
    ):
        raise InputValidationError(f"{contract}.width: expected a non-negative integer")
