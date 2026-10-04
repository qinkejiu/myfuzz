"""Versioned, canonical preflight contract for independent scenario harnesses.

This module validates declarations before any RTL process starts. Runtime budget
accounting remains the responsibility of the runner and evidence writer.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import hashlib
from importlib import import_module
import json
from pathlib import Path
import re
from typing import Any

from .genome import Action, ResetAction, ScenarioGenome
from .host_identity import verify_host_source_identity
from .ownership import InputField, InputOwner, compile_ownership


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ROOT = Path(__file__).resolve().parents[3]
_RESET_LOOP = re.compile(r"for\s*\(\s*int\s+i\s*=\s*0\s*;\s*i\s*<\s*(\d+)\s*;\s*\+\+i\s*\)\s*tick\s*\(\s*dut\s*\)\s*;")


class ProtocolEnvironmentError(RuntimeError):
    """The local driver violated a DUT-facing protocol or response rule."""


def _generated_session_class_kind(class_path: str) -> str:
    """Resolve an audited generated session class in the local harness package."""
    if (type(class_path) is not str or
            re.fullmatch(r'myfuzz\.local_harness\.[a-z][a-z0-9_]*\.Generated[A-Za-z0-9_]+Session',
                         class_path) is None):
        raise ValueError('generated session type is not registered')
    module_name, class_name = class_path.rsplit('.', 1)
    try:
        cls = getattr(import_module(module_name), class_name)
    except (ImportError, AttributeError) as exc:
        raise ValueError('generated session type is not registered') from exc
    from myfuzz.local_harness.session import GeneratedLocalSession
    kind = getattr(cls, 'artifact_kind', None)
    if (not isinstance(cls, type) or cls.__module__ != module_name
            or cls is GeneratedLocalSession or not issubclass(cls, GeneratedLocalSession)
            or 'artifact_kind' not in cls.__dict__ or type(kind) is not str
            or re.fullmatch(r'[a-z][a-z0-9_]*', kind) is None):
        raise ValueError('generated session type is not registered')
    return kind


def _verify_local_reset_timing(component: str, timing: dict) -> None:
    """Check the selected, hashed local C++ wrapper's READY reset sequence."""
    source_path = timing["source_path"]
    if not re.fullmatch(r"src/myfuzz/scenario/rtl/local_[a-z0-9_]+_main\.cpp",
                        source_path):
        raise ValueError(f"reset_timings.{component}.source_path is not a local wrapper")
    source = (_ROOT / source_path).read_bytes()
    if hashlib.sha256(source).hexdigest() != timing["source_sha256"]:
        raise ValueError(f"reset_timings.{component}.source_sha256 differs from current wrapper")
    text = source.decode("utf-8")
    main = text.find("int main(")
    ready = text.find("std::cout << \"READY", main)
    if main < 0 or ready < 0:
        raise ValueError(f"reset_timings.{component} wrapper READY sequence is unavailable")
    startup = text[main:ready]
    asserted = startup.rfind("dut.reset = 1;")
    released = startup.find("dut.reset = 0;", asserted)
    if asserted < 0 or released < 0:
        raise ValueError(f"reset_timings.{component} reset edges are unavailable")
    hold = _RESET_LOOP.findall(startup[asserted:released])
    release = _RESET_LOOP.findall(startup[released:])
    if len(hold) != 1 or len(release) > 1:
        raise ValueError(f"reset_timings.{component} reset cycle count is ambiguous")
    observed = (int(hold[0]), int(release[0]) if release else 0)
    for name, count in zip(("hold_cycles", "release_cycles"), observed):
        if timing[name] != count:
            raise ValueError(f"reset_timings.{component}.{name} disagrees with wrapper")


def _verify_generated_session(identity: dict):
    """Regenerate authenticated bytes and build identity without starting RTL."""
    from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
        render_local_harness, render_local_runtime, verify_local_source_lock)
    from myfuzz.local_harness.driver_renderer import render_local_driver
    from myfuzz.local_harness.build import local_build_identity
    base_fields = {'schema_version', 'runtime_artifact', 'build_identity',
                   'command_timeout_seconds'}
    cpu_fields = {'cpu_service_schema_version', 'source_component', 'defer_mmio'}
    native_fields = {'native_service_schema_version', 'source_component', 'memory_policy'}
    axi_lite_fields = {'axi_lite_service_schema_version', 'source_component', 'memory_policy'}
    spi_fields = {'spi_peer_schema_version', 'source_component', 'chip_select',
                  'source_hex', 'startup_writes', 'read_rx_on_eot'}
    axi4_fields = {'cpu_service_schema_version', 'source_component'}
    tlul_gpio_fields = {'tlul_gpio_service_schema_version', 'source_component', 'startup_writes'}
    if not isinstance(identity, dict) or set(identity) not in (
            base_fields, base_fields | cpu_fields, base_fields | native_fields,
            base_fields | axi_lite_fields, base_fields | spi_fields,
            base_fields | axi4_fields, base_fields | tlul_gpio_fields):

        raise ValueError('generated session identity has unknown or missing fields')
    if identity['schema_version'] != 'generated_local_session_identity.v1':
        raise ValueError('unsupported generated session schema')
    timeout = identity['command_timeout_seconds']
    if type(timeout) not in (int, float) or not 0 < timeout <= 3600:
        raise ValueError('invalid generated command timeout')
    document = identity['runtime_artifact']
    plan_doc = document['plan']
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=plan_doc['profile_path'], instance_id=plan_doc['instance_id'],
        **plan_doc['timing']))
    plan = plan_local_harness(request, base_dir=_ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=_ROOT), base_dir=_ROOT)
    artifact = render_local_driver(top, base_dir=_ROOT)
    if document != artifact.runtime_document:
        raise ValueError('generated runtime artifact identity mismatch')
    if artifact.runtime_document['kind'] == 'native_memory_cpu':
        _exact(identity, base_fields | native_fields, 'generated native service identity')
        if (identity['native_service_schema_version'] != 'generated_native_memory_service.v1'
                or identity['source_component'] != artifact.plan.request.instance_id
                or identity['memory_policy'] != 'ram-rom-only'):
            raise ValueError('generated native service identity mismatch')
    elif artifact.runtime_document['kind'] == 'axi4_lite_cpu':
        _exact(identity, base_fields | axi_lite_fields, 'generated AXI4-Lite service identity')
        if (identity['axi_lite_service_schema_version'] != 'generated_axi4_lite_memory_service.v1'
                or identity['source_component'] != artifact.plan.request.instance_id
                or identity['memory_policy'] != 'ram-rom-only'):
            raise ValueError('generated AXI4-Lite service identity mismatch')
    elif artifact.runtime_document['kind'] == 'axi4_cpu':
        _exact(identity, base_fields | axi4_fields, 'generated AXI4 CPU service identity')
        if (identity['cpu_service_schema_version'] != 'generated_axi4_cpu_service.v1'
                or identity['source_component'] != artifact.plan.request.instance_id):
            raise ValueError('generated AXI4 CPU service identity mismatch')
    elif artifact.runtime_document['kind'] in ('obi_cpu', 'wishbone_cpu'):
        _exact(identity, base_fields | cpu_fields, 'generated CPU service identity')
        service_versions = {'obi_cpu': 'generated_obi_cpu_service.v1',
                            'wishbone_cpu': 'generated_wishbone_cpu_service.v1'}
        if (identity['cpu_service_schema_version'] != service_versions[artifact.runtime_document['kind']]
                or identity['source_component'] != artifact.plan.request.instance_id
                or type(identity['defer_mmio']) is not bool):
            raise ValueError('generated CPU service identity mismatch')
    elif artifact.runtime_document['kind'] == 'apb_spi':
        _exact(identity, base_fields | spi_fields, 'generated SPI service identity')
        source = identity['source_hex']
        writes = identity['startup_writes']
        if (identity['spi_peer_schema_version'] != 'pulp_spi_mode0_source.v1'
                or identity['source_component'] != artifact.plan.request.instance_id
                or type(identity['chip_select']) is not int
                or not 0 <= identity['chip_select'] < 4
                or type(source) is not str or len(source) > 1024 or len(source) % 2
                or any(character not in '0123456789abcdef' for character in source)
                or type(writes) is not list or len(writes) > 16
                or any(type(row) is not list or len(row) != 2
                       or type(row[0]) is not int or type(row[1]) is not int
                       or row[0] < 0 or row[0] > 4092 or row[0] % 4
                       or row[1] < 0 or row[1] > 0xffffffff for row in writes)
                or type(identity['read_rx_on_eot']) is not bool):
            raise ValueError('generated SPI service identity mismatch')
    elif artifact.runtime_document['kind'] == 'tlul_gpio':
        _exact(identity, base_fields | tlul_gpio_fields, 'generated TL-UL GPIO service identity')
        writes = identity['startup_writes']
        if (identity['tlul_gpio_service_schema_version'] != 'generated_tlul_gpio_service.v1'
                or identity['source_component'] != artifact.plan.request.instance_id
                or type(writes) is not list or len(writes) > 16
                or any(type(row) is not list or len(row) != 2
                       or type(row[0]) is not int or row[0] < 0 or row[0] > 124
                       or row[0] % 4 or type(row[1]) is not int
                       or not 0 <= row[1] <= 0xffffffff for row in writes)):
            raise ValueError('generated TL-UL GPIO service identity mismatch')
    else:
        _exact(identity, base_fields, 'generated IP service identity')
    if identity['build_identity'] != local_build_identity(artifact, base_dir=_ROOT):
        raise ValueError('generated build identity mismatch')
    return artifact


def _verify_generated_reset_timing(component: str, timing: dict, identity: dict) -> None:
    _exact(timing, {'schema_version', 'artifact_digest', 'driver_sha256',
                    'hold_cycles', 'release_cycles'}, 'generated reset timing')
    document = identity['runtime_artifact']
    reset = document['driver_reset']
    expected = dict(schema_version='generated_local_reset.v1',
        artifact_digest=document['artifact_digest'], driver_sha256=document['cpp_sha256'],
        hold_cycles=reset['reset_assert_ticks'], release_cycles=reset['reset_release_ticks'])
    if timing != expected or any(type(timing[name]) is not int for name in ('hold_cycles', 'release_cycles')):
        raise ValueError(f'reset_timings.{component} disagrees with generated driver')


def _exact(record: Any, names: set[str], label: str) -> dict:
    if not isinstance(record, dict):
        raise ValueError(f"{label} must be an object")
    missing, unknown = names - record.keys(), record.keys() - names
    if missing or unknown:
        raise ValueError(f"{label} missing {sorted(missing)}; unknown {sorted(unknown)}")
    return record


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be nonempty text")
    return value


def _digest(value: Any, label: str) -> None:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{label} must be an integer >= {minimum}")
    return value


def _list(value: Any, label: str, *, nonempty: bool = False) -> list:
    if not isinstance(value, list) or (nonempty and not value):
        raise ValueError(f"{label} must be a {'nonempty ' if nonempty else ''}list")
    return value


@dataclass(frozen=True)
class ResourceBudget:
    max_local_cycles_per_component: int = 65_536
    max_scheduler_steps: int = 262_144
    max_materialized_bytes_per_memory: int = 65_536
    max_source_actions: int = 4_096
    max_transactions: int = 16_384
    max_semantic_records: int = 1_000_000
    max_evidence_bytes: int = 256 * 1024 * 1024
    evidence_termination_reserve_bytes: int = 8 * 1024 * 1024
    max_wall_time_ms: int = 60_000
    max_quiesce_steps: int = 4_096
    build_workers: int = 1
    waveform_enabled: bool = False

    def __post_init__(self) -> None:
        for field in fields(self):
            if field.name == "waveform_enabled":
                if not isinstance(getattr(self, field.name), bool):
                    raise ValueError("waveform_enabled must be boolean")
            else:
                _integer(getattr(self, field.name), field.name,
                         0 if field.name in ("max_quiesce_steps", "max_source_actions")
                         else 1)
        if self.evidence_termination_reserve_bytes >= self.max_evidence_bytes:
            raise ValueError("evidence_termination_reserve_bytes must be below max_evidence_bytes")
        if self.max_quiesce_steps > 4_096:
            raise ValueError("max_quiesce_steps exceeds first-stage limit")

    def to_document(self) -> dict:
        return asdict(self)

    @classmethod
    def from_document(cls, document: Any) -> ResourceBudget:
        return cls(**_exact(document, set(cls.__dataclass_fields__), "budget"))

    def check_usage(self, usage: ResourceUsage, *, terminating: bool = False,
                    allow_wall_overrun: bool = False) -> None:
        """Reject before admitting an operation that would exceed a budget.

        Normal events may use only the evidence capacity below the reserved tail.
        Finalization records may use the full capacity.
        """
        if not isinstance(usage, ResourceUsage):
            raise ValueError("ResourceUsage is required")
        for component, count in usage.local_cycles.items():
            if count > self.max_local_cycles_per_component:
                raise ValueError(f"max_local_cycles_per_component exceeded for {component}")
        for memory_id, count in usage.materialized_bytes.items():
            if count > self.max_materialized_bytes_per_memory:
                raise ValueError(f"max_materialized_bytes_per_memory exceeded for {memory_id}")
        pairs = (("max_scheduler_steps", usage.scheduler_steps),
                 ("max_source_actions", usage.source_actions),
                 ("max_transactions", usage.transactions),
                 ("max_semantic_records", usage.semantic_records),
                 ("max_wall_time_ms", usage.wall_time_ms),
                 ("max_quiesce_steps", usage.quiesce_steps))
        for name, used in pairs:
            if name == "max_wall_time_ms" and allow_wall_overrun:
                continue
            if used > getattr(self, name):
                raise ValueError(f"{name} exceeded")
        evidence_limit = (self.max_evidence_bytes if terminating else
                          self.max_evidence_bytes - self.evidence_termination_reserve_bytes)
        if usage.evidence_bytes > evidence_limit:
            raise ValueError("max_evidence_bytes exceeded")


@dataclass(frozen=True)
class ResourceUsage:
    local_cycles: dict[str, int]
    materialized_bytes: dict[str, int]
    scheduler_steps: int
    source_actions: int
    transactions: int
    semantic_records: int
    evidence_bytes: int
    wall_time_ms: int
    quiesce_steps: int

    def __post_init__(self) -> None:
        for name in ("local_cycles", "materialized_bytes"):
            values = getattr(self, name)
            if not isinstance(values, dict):
                raise ValueError(f"{name} must be a mapping")
            for key, count in values.items():
                _text(key, f"{name} key")
                _integer(count, f"{name}.{key}")
        for name in ("scheduler_steps", "source_actions", "transactions",
                     "semantic_records", "evidence_bytes", "wall_time_ms",
                     "quiesce_steps"):
            _integer(getattr(self, name), name)

    def to_document(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ScenarioManifest:
    """Immutable canonical bytes are the authority for replay identity."""

    _canonical: bytes

    @classmethod
    def from_document(cls, document: Any) -> ScenarioManifest:
        if isinstance(document, dict) and document.get("schema_version") == "scenario_runtime_manifest.v1":
            return cls._from_runtime_document(document)
        names = {"schema_version", "scenario_id", "components", "toolchain",
                 "ownership", "bindings", "schedule_order", "scheduler_policy_id",
                 "reset_policy", "initializer_id", "address_map", "budget"}
        document = _exact(document, names, "manifest")
        if document["schema_version"] != "scenario_manifest.v1":
            raise ValueError("unsupported schema_version")
        _text(document["scenario_id"], "scenario_id")
        components = _list(document["components"], "components", nonempty=True)
        component_ids: set[str] = set()
        for index, item in enumerate(components):
            item = _exact(item, {"component_id", "harness_kind", "source_sha256",
                                 "harness_sha256", "profile_sha256"}, f"components[{index}]")
            component = _text(item["component_id"], "component_id")
            if component in component_ids:
                raise ValueError("duplicate component_id")
            component_ids.add(component)
            if item["harness_kind"] != "independent_rtl":
                raise ValueError("harness_kind must be independent_rtl")
            for name in ("source_sha256", "harness_sha256", "profile_sha256"):
                _digest(item[name], name)
        toolchain = _exact(document["toolchain"],
                           {"verilator", "compiler", "rfuzz", "identity_sha256"}, "toolchain")
        for name in ("verilator", "compiler", "rfuzz"):
            _text(toolchain[name], f"toolchain.{name}")
        _digest(toolchain["identity_sha256"], "toolchain.identity_sha256")
        order = _list(document["schedule_order"], "schedule_order", nonempty=True)
        if len(order) != len(set(order)) or set(order) != component_ids:
            raise ValueError("schedule_order must list each component exactly once")
        _text(document["scheduler_policy_id"], "scheduler_policy_id")
        _text(document["initializer_id"], "initializer_id")
        reset = _exact(document["reset_policy"],
                       {"initial", "allowed", "scope", "hold_cycles", "release_cycles"},
                       "reset_policy")
        if reset["scope"] != "all":
            raise ValueError("unsupported_reset_scope")
        allowed = _list(reset["allowed"], "reset_policy.allowed", nonempty=True)
        if (len(allowed) != len(set(allowed))
                or any(policy not in ("warm_all", "cold_all") for policy in allowed)
                or reset["initial"] != "cold_all" or "cold_all" not in allowed):
            raise ValueError("reset_policy contains an unknown or unsupported policy")
        _integer(reset["hold_cycles"], "reset_policy.hold_cycles", 1)
        _integer(reset["release_cycles"], "reset_policy.release_cycles", 1)
        ownership = _exact(document["ownership"], {"fields", "owners"}, "ownership")
        field_records = _list(ownership["fields"], "ownership.fields")
        owner_records = _list(ownership["owners"], "ownership.owners")
        field_names = set(InputField.__dataclass_fields__)
        owner_names = set(InputOwner.__dataclass_fields__)
        fields_ = tuple(InputField(**_exact(item, field_names, "ownership.field"))
                        for item in field_records)
        owners = tuple(InputOwner(**_exact(item, owner_names, "ownership.owner"))
                       for item in owner_records)
        if any(item.component_id not in component_ids for item in (*fields_, *owners)):
            raise ValueError("ownership references unknown component")
        owner_map = compile_ownership(fields_, owners)
        bindings = _list(document["bindings"], "bindings")
        bound_segments = {(owner.component_id, owner.port, owner.bit_offset,
                           owner.width, owner.producer_ref)
                          for owner in owners if owner.kind == "bound"}
        declared_segments = set()
        for item in bindings:
            item = _exact(item, {"producer_ref", "target_component", "target_port",
                                 "bit_offset", "width"}, "binding")
            target = _text(item["target_component"], "binding.target_component")
            port = _text(item["target_port"], "binding.target_port")
            producer = _text(item["producer_ref"], "binding.producer_ref")
            offset = _integer(item["bit_offset"], "binding.bit_offset")
            width = _integer(item["width"], "binding.width", 1)
            if target not in component_ids:
                raise ValueError("binding target component is unknown")
            if owner_map.binding_producer(target, port, offset, width) != producer:
                raise ValueError("binding producer does not match ownership")
            declared_segments.add((target, port, offset, width, producer))
        if declared_segments != bound_segments or len(bindings) != len(declared_segments):
            raise ValueError("bindings must cover each bound input range exactly once")
        maps = _list(document["address_map"], "address_map")
        seen_memory = set()
        for item in maps:
            item = _exact(item, {"memory_id", "base", "size", "permissions",
                                 "owner_component"}, "address_map entry")
            memory_id = _text(item["memory_id"], "memory_id")
            if memory_id in seen_memory:
                raise ValueError("duplicate memory_id")
            seen_memory.add(memory_id)
            _integer(item["base"], "address_map.base")
            _integer(item["size"], "address_map.size", 1)
            if item["permissions"] not in ("r", "rw", "rx", "rwx"):
                raise ValueError("address_map.permissions is invalid")
            if item["owner_component"] not in component_ids:
                raise ValueError("address_map.owner_component is unknown")
        ResourceBudget.from_document(document["budget"])
        try:
            canonical = json.dumps(document, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("manifest must contain JSON values") from exc
        return cls(canonical)

    @classmethod
    def from_runner_identity(cls, runner_identity: dict, *, scenario_id: str,
                             schedule_order: tuple[str, ...], scheduler_policy_id: str,
                             budget: ResourceBudget,
                             reset_timings: dict[str, dict] | None = None) -> ScenarioManifest:
        """Bind the exact runner identity to explicit campaign declarations.

        The runner identity does not contain reset cycle counts, scheduler policy,
        or a campaign budget. Those must be supplied, never inferred from a
        different harness or substituted with a global reset duration.
        """
        if reset_timings is None:
            raise ValueError("reset_timings are required for every component")
        if not isinstance(budget, ResourceBudget):
            raise ValueError("ResourceBudget is required")
        return cls.from_document({
            "schema_version": "scenario_runtime_manifest.v1",
            "scenario_id": scenario_id,
            "runner_identity": runner_identity,
            "schedule_order": list(schedule_order),
            "scheduler_policy_id": scheduler_policy_id,
            "reset_policy": {"initial": "cold_all", "allowed": ["warm_all", "cold_all"],
                             "scope": "all", "component_timings": reset_timings},
            "budget": budget.to_document(),
        })

    @classmethod
    def _from_runtime_document(cls, document: dict) -> ScenarioManifest:
        _exact(document, {"schema_version", "scenario_id", "runner_identity",
                          "schedule_order", "scheduler_policy_id", "reset_policy",
                          "budget"}, "runtime manifest")
        _text(document["scenario_id"], "scenario_id")
        _text(document["scheduler_policy_id"], "scheduler_policy_id")
        identity = document["runner_identity"]
        if isinstance(identity, dict):
            if "irq_pulses" in identity:
                _list(identity["irq_pulses"], "runner_identity.irq_pulses")
            if "host_sources" in identity:
                generated = tuple(record['identity'] for record in identity.get('sessions', {}).values()
                    if record.get('identity', {}).get('schema_version') == 'generated_local_session_identity.v1')
                verify_host_source_identity(identity["host_sources"], harness_identities=generated)
            identity_core = {key: value for key, value in identity.items()
                             if key not in ("irq_pulses", "host_sources")}
        else:
            identity_core = identity
        _exact(identity_core, {"schema_version", "sessions", "memories", "windows",
                               "ownership", "bindings"}, "runner_identity")
        if identity["schema_version"] not in ("scenario_manifest_identity.v1", "scenario_manifest_identity.v2"):
            raise ValueError("runner_identity.schema_version is unsupported")
        sessions = identity["sessions"]
        has_generated = isinstance(sessions, dict) and any(
            isinstance(record, dict) and isinstance(record.get('identity'), dict)
            and record['identity'].get('schema_version') == 'generated_local_session_identity.v1'
            for record in sessions.values())
        if ((identity['schema_version'] == 'scenario_manifest_identity.v2') != has_generated
                or (has_generated and 'host_sources' not in identity)):
            raise ValueError('generated runner requires complete v2 host identity')
        if not isinstance(sessions, dict) or not sessions:
            raise ValueError("runner_identity.sessions must be nonempty")
        order = _list(document["schedule_order"], "schedule_order", nonempty=True)
        if any(not isinstance(name, str) or not name for name in order):
            raise ValueError("schedule_order contains an invalid component")
        if len(order) != len(set(order)) or set(order) != set(sessions):
            raise ValueError("schedule_order must list each runner session once")
        for component, session in sessions.items():
            _text(component, "session component")
            session = _exact(session, {"type", "identity"}, f"sessions.{component}")
            if session['identity'].get('schema_version') == 'generated_local_session_identity.v1':
                if identity['schema_version'] != 'scenario_manifest_identity.v2':
                    raise ValueError('generated session type or runner schema mismatch')
                expected_kind = _generated_session_class_kind(session['type'])
                artifact = _verify_generated_session(session['identity'])
                if artifact.runtime_document['kind'] != expected_kind:
                    raise ValueError('generated session type disagrees with artifact kind')
                continue
            if not isinstance(session["type"], str) or not session["type"].startswith(
                    "myfuzz.scenario."):
                raise ValueError(f"sessions.{component}.type must be an independent harness")
            sid = _exact(session["identity"], {"sources", "revision", "toolchain"},
                         f"sessions.{component}.identity")
            _text(sid["revision"], f"sessions.{component}.revision")
            bundle = _exact(sid["sources"], {"schema_version", "files"},
                            f"sessions.{component}.sources")
            if bundle["schema_version"] != "source_bundle.v1":
                raise ValueError(f"sessions.{component}.sources schema is unsupported")
            paths = set()
            for file in _list(bundle["files"], f"sessions.{component}.sources.files",
                              nonempty=True):
                file = _exact(file, {"path", "sha256"}, "source file")
                path = _text(file["path"], "source path")
                _digest(file["sha256"], f"source {path} sha256")
                if path in paths:
                    raise ValueError(f"duplicate source path for {component}")
                paths.add(path)
            tools = _exact(sid["toolchain"], {"verilator", "c++"},
                           f"sessions.{component}.toolchain")
            for name, tool in tools.items():
                tool = _exact(tool, {"available", "version"}, f"toolchain.{name}")
                if tool["available"] is not True:
                    raise ValueError(f"toolchain.{name} is unavailable")
                _text(tool["version"], f"toolchain.{name}.version")
        reset = _exact(document["reset_policy"],
                       {"initial", "allowed", "scope", "component_timings"}, "reset_policy")
        if reset["scope"] != "all":
            raise ValueError("unsupported_reset_scope")
        allowed = _list(reset["allowed"], "reset_policy.allowed", nonempty=True)
        if (reset["initial"] != "cold_all" or set(allowed) != {"warm_all", "cold_all"}
                or len(allowed) != 2):
            raise ValueError("reset_policy must declare cold_all and warm_all")
        timings = reset["component_timings"]
        if not isinstance(timings, dict) or set(timings) != set(sessions):
            raise ValueError("reset_timings must cover every component")
        for component, timing in timings.items():
            sid = sessions[component]['identity']
            if sid.get('schema_version') == 'generated_local_session_identity.v1':
                _verify_generated_reset_timing(component, timing, sid)
                continue
            timing = _exact(timing, {"hold_cycles", "release_cycles", "source_path",
                                     "source_sha256"}, f"reset_timings.{component}")
            _integer(timing["hold_cycles"], f"reset_timings.{component}.hold_cycles", 1)
            _integer(timing["release_cycles"],
                     f"reset_timings.{component}.release_cycles")
            source_path = _text(timing["source_path"],
                                f"reset_timings.{component}.source_path")
            source_files = sessions[component]["identity"]["sources"]["files"]
            matched = [file for file in source_files if file["path"] == source_path]
            if len(matched) != 1 or timing["source_sha256"] != matched[0]["sha256"]:
                raise ValueError(f"reset_timings.{component}.source_sha256 does not match source bundle")
            _verify_local_reset_timing(component, timing)
        ownership = _exact(identity["ownership"], {"fields", "owners"},
                           "runner_identity.ownership")
        owner_map = compile_ownership(
            tuple(InputField(**_exact(item, set(InputField.__dataclass_fields__),
                                      "ownership.field")) for item in ownership["fields"]),
            tuple(InputOwner(**_exact(item, set(InputOwner.__dataclass_fields__),
                                      "ownership.owner")) for item in ownership["owners"]))
        for binding in _list(identity["bindings"], "runner_identity.bindings"):
            binding = _exact(binding, {"source_bit_offset", "source_component",
                                       "source_port", "target_bit_offset",
                                       "target_component", "target_port", "width"}, "binding")
            producer = f"{binding['source_component']}.{binding['source_port']}"
            if owner_map.binding_producer(binding["target_component"],
                                          binding["target_port"],
                                          binding["target_bit_offset"],
                                          binding["width"]) != producer:
                raise ValueError("binding producer does not match ownership")
        if not isinstance(identity["memories"], dict) or not isinstance(identity["windows"], dict):
            raise ValueError("runner_identity memories and windows must be objects")
        for component, memory in identity["memories"].items():
            if component not in sessions:
                raise ValueError("memory owner is not a session")
            _text(memory.get("initialization_algorithm"), "initialization_algorithm")
            _integer(memory.get("max_initialized_bytes"), "max_initialized_bytes", 1)
            _list(memory.get("regions"), "memory.regions", nonempty=True)
        ResourceBudget.from_document(document["budget"])
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False).encode("utf-8")
        return cls(canonical)

    @classmethod
    def from_bytes(cls, raw: bytes) -> ScenarioManifest:
        if not isinstance(raw, bytes):
            raise ValueError("manifest must be bytes")
        try:
            document = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid manifest JSON") from exc
        manifest = cls.from_document(document)
        if raw != manifest._canonical:
            raise ValueError("manifest JSON is not canonical")
        return manifest

    def canonical_bytes(self) -> bytes:
        return self._canonical

    def to_document(self) -> dict:
        return json.loads(self._canonical)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self._canonical).hexdigest()

    @property
    def budget(self) -> ResourceBudget:
        return ResourceBudget.from_document(self.to_document()["budget"])

    def component_epoch(self, component_index: int, epoch: int) -> tuple[str, int]:
        components = self.to_document()["schedule_order"]
        _integer(component_index, "component_index")
        _integer(epoch, "component_epoch")
        if component_index >= len(components):
            raise ValueError("component_index is out of range")
        return components[component_index], epoch

    def memory_generation(self, memory_id: str, generation: int) -> tuple[str, int]:
        if memory_id not in {item["memory_id"] for item in self.to_document()["address_map"]}:
            raise ValueError("unknown memory_id")
        return memory_id, _integer(generation, "memory_generation")

    def preflight_genome(self, genome: ScenarioGenome) -> None:
        if not isinstance(genome, ScenarioGenome):
            raise ValueError("ScenarioGenome is required")
        document = self.to_document()
        if document["schema_version"] == "scenario_runtime_manifest.v1":
            identity = document["runner_identity"]
            address_map = []
            for component, memory in identity["memories"].items():
                for region in memory["regions"]:
                    if not region["writable"]:
                        permissions = "r" if region["readable"] else ""
                    else:
                        permissions = "rw" if region["readable"] else "w"
                    address_map.append({"memory_id": region["memory_id"],
                                        "base": region["base"], "size": region["size"],
                                        "permissions": permissions,
                                        "owner_component": component})
            document = {**document, "ownership": identity["ownership"],
                        "address_map": address_map}
        budget = self.budget
        if tuple(document["schedule_order"]) != genome.schedule_order:
            raise ValueError("genome schedule_order differs from manifest")
        if genome.max_steps > budget.max_scheduler_steps:
            raise ValueError("max_scheduler_steps budget exceeded")
        if len(genome.actions) > budget.max_source_actions:
            raise ValueError("max_source_actions budget exceeded")
        if genome.quiesce_steps > budget.max_quiesce_steps:
            raise ValueError("max_quiesce_steps budget exceeded")
        if len(genome.initial_images) > budget.max_source_actions:
            raise ValueError("initial image count exceeds source budget")
        ownership = document["ownership"]
        owner_map = compile_ownership(
            tuple(InputField(**item) for item in ownership["fields"]),
            tuple(InputOwner(**item) for item in ownership["owners"]))
        for action in genome.actions:
            if action.direction != genome.direction:
                raise ValueError(f"action {action.action_id} direction differs from genome")
            if action.width is None:
                raise ValueError(f"action {action.action_id} requires explicit width")
            owner_map.mutation_source(action.component, action.port,
                                      action.bit_offset, action.width,
                                      direction=genome.direction)
            if action.value >= 1 << action.width:
                raise ValueError(f"action {action.action_id} value exceeds width")
        allowed = set(document["reset_policy"]["allowed"])
        for action in genome.reset_actions:
            if action.policy not in allowed:
                raise ValueError(f"reset_policy disallows {action.policy}")
        image_bytes: dict[str, set[int]] = {}
        for image in genome.initial_images:
            windows = [item for item in document["address_map"]
                       if item["owner_component"] == image.component
                       and "w" in item["permissions"]
                       and item["base"] <= image.address
                       and image.address + len(image.data) <= item["base"] + item["size"]]
            if len(windows) != 1:
                raise ValueError(f"image {image.image_id} is not in one writable address_map window")
            window = windows[0]
            used = image_bytes.setdefault(window["memory_id"], set())
            offsets = set(range(image.address - window["base"],
                                image.address - window["base"] + len(image.data)))
            if used & offsets:
                raise ValueError("initial images overlap within one memory generation")
            used.update(offsets)
            if len(used) > budget.max_materialized_bytes_per_memory:
                raise ValueError("max_materialized_bytes_per_memory budget exceeded")


__all__ = ["Action", "ResetAction", "ResourceBudget", "ResourceUsage",
           "ScenarioManifest"]
