"""Config-driven real RFuzz build for generated source-backed SoCs (P14).

This module is the production build hook behind
:func:'myfuzz.integration.soc_campaign.run_soc_campaign'.  It performs the
missing real path end to end:

1. load the cell config named by the campaign task config (or the embedded
   'base_cell' document) and build the 'soc_plan.v1' plan plus the
   'soc_stimulus.v1' document for the configured mode,
2. render the cell with :func:'myfuzz.composition.soc_renderer.render_soc' and
   publish every rendered file under 'build_dir',
3. derive the RFuzz input layout from the compiled stimulus raw ABI, build the
   pinned transport with
   :func:'myfuzz.composition.rfuzz_transport.build_rfuzz_transport' and publish
   'rfuzz_input_transport.sv' / 'rfuzz_input_transport.json',
4. generate the persistent harness testbench that speaks the internal simulator
   protocol of :mod:'myfuzz.integration.rfuzz_simulator' (version 2), compile it
   with Verilator through the same supervised command path 'build_simulator'
   uses, and return a :class:'SimulatorArtifact' that 'rfuzz_live.run_live' can
   drive through the official RFuzz FIFO/shared-memory channel.

Every step is fail closed.  A missing Verilator, a missing closure source, an
unsupported cell or a compiler failure raises :class:'SocBuildError'; no
behavioural CPU/peripheral model is ever substituted and no artifact is
returned unless the executable was actually produced.

The peripheral capability facts below are the pinned task P1 closure readings
('configs/soc/closures/*.json'); they are overlaid, when the cell config
declares them, by that config's own protocol/window/parameters so the cell
document stays the source of truth.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from myfuzz.contracts import canonical_bytes, content_hash
from myfuzz.composition.input_layout import (
    InputLayout,
    LayoutField,
    input_layout_document,
)
from myfuzz.composition.rfuzz_transport import build_rfuzz_transport
from myfuzz.composition.soc_plan import build_soc_plan
from myfuzz.composition.soc_renderer import render_soc
from myfuzz.composition.soc_stimulus import compile_soc_stimulus
from myfuzz.composition.target_adapters import resolve_target_adapter
from myfuzz.composition.soc_peer_replay import (
    PeerRawReplayError,
    decode_peer_raw_events,
)

from .campaign import CampaignLimits, CampaignOptions, run_supervised_command
from .rtl_execution_monitor import monitor_output, monitor_rtl
from .soc_coverage import (
    coverage_observation_plan,
    universe_from_instance_bits,
)
from .riscv_execution import (
    RiscvExecutionFacts,
    RiscvExecutionProvenance,
    build_minimal_boot_image,
)
from .rfuzz_simulator import (
    MAX_CYCLES,
    SIMULATOR_PROTOCOL_VERSION,
    SimulatorArtifact,
)
from .rfuzz_toolchain import (
    RfuzzToolchainError,
    resolve_rfuzz_verilator_toolchain,
)
from myfuzz.rfuzz_compat import resolve_rfuzz_verilator, validate_rfuzz_verilator_version


ROOT = Path(__file__).resolve().parents[3]
BUILD_SCHEMA = "soc_campaign_build.v1"
CLOSURE_DIR = "configs/soc/closures"
SOURCES_LOCK = "configs/soc/sources.lock.json"
COUNTER_LIMIT = 128
#: A branch-instrumented cell is a much larger design than the bare render, so
#: the build phase gets an explicit, documented budget instead of the 512 MiB
#: campaign default that terminates a CVA6+OpenTitan compile.  The simulator
#: itself keeps the conservative default.
BUILD_MEMORY_LIMITS = CampaignLimits(soft_memory_bytes=3 * 1024 * 1024 * 1024,
                                     hard_memory_bytes=4 * 1024 * 1024 * 1024)
COUNTER_BITS_PER_PORT = 16
#: The instrumenter's hierarchical coverage output port on the rendered top.
COVERAGE_SIGNAL = "__vi_coverage"
#: Real RTL branch feedback, not sampled event counters.
COVERAGE_KIND = "source-instrumented-rtl-branch-u8-saturating"
_COVERAGE_INSTRUMENTER_SCHEMA = "source_branch_instrumenter.v1"
_COVERAGE_INSTRUMENTER_SETTINGS = {"runtime": {"single_statement": True}}
PROBE_TIMEOUT_SECONDS = 60
BUILD_TIMEOUT_SECONDS = 600
#: CPUs whose first fetch is not at the reset vector itself.  Ibex documents
#: 'boot_addr_i + 0x80' as the first instruction address; CVA6 starts at
#: 'boot_addr_i'.  A cell config may override this with 'cpu.fetch_offset'.
_CPU_FETCH_OFFSETS = {"ibex": 0x80, "cva6": 0x0}
#: Inputs the harness holds at a defined idle level when the compiled raw ABI
#: does not drive them.
_IDLE_INPUTS = {"spi_cs_i": 1, "spi_cs": 1}

_TLUL_EVIDENCE = {
    "byte_enable": "tlul_channel_structure",
    "partial_write": "tlul_opcodes",
    "has_error": "d_error_production",
    "integrity": "integrity_check_path",
    "source_width": "tlul_widths",
    "sink_width": "tlul_widths",
    "user_width": "tlul_widths",
    "size_width": "tlul_widths",
}
_APB_EVIDENCE = {
    "byte_enable": "byte_strobes",
    "partial_write": "byte_strobes",
    "has_error": "pslverr_handling",
}
_ZIPCPU_UART_EVIDENCE = {
    "byte_enable": "byte_enable_setup_register",
    "partial_write": "generic_byte_masked_word_write",
    "has_error": "wishbone_error_retry_and_burst",
    "has_address_port": "address_unit",
    "address_units": "address_unit",
    "sel_implemented": "byte_enable_tx_register",
    "wishbone_flavour": "wishbone_subset",
    "ack_requires_cyc": "cyc_stb_semantics",
}
_ZIPCPU_TIMER_EVIDENCE = {
    "byte_enable": "byte_enable_and_partial_writes",
    "partial_write": "partial_write",
    "has_error": "wishbone_error_retry_and_burst",
    "has_address_port": "address_unit_and_single_register_window",
    "address_units": "address_unit_and_single_register_window",
    "sel_implemented": "byte_enable_and_partial_writes",
    "wishbone_flavour": "wishbone_subset",
    "ack_requires_cyc": "cyc_stb_semantics",
}

#: Capability facts recorded from the pinned task P1 closures.  'spot_check' is
#: the real IP source the closure records; the campaign build test asserts that
#: file is part of the rendered closure.
PERIPHERAL_FACTS = {
    "opentitan_uart": {
        "source_lock": "opentitan_uart",
        "top_module": "uart",
        "protocol": ["tl-ul", "1"],
        "window": {"base": 0x4000_0000, "size": 0x1000},
        "data_width": 32,
        "capabilities": {
            "byte_enable": True, "partial_write": True, "has_error": True,
            "integrity": "required", "source_width": 8, "sink_width": 1,
            "user_width": 23, "size_width": 2,
        },
        "evidence_topics": _TLUL_EVIDENCE,
        "irq": {"signal": "intr_rx_watermark_o", "trigger": "level"},
        "environment": {"protocol": ["uart-serial", "1"],
                        "parameters": {"bits": 8, "baud_div": 1, "frame_bits": 10}},
        "spot_check": "third_party/soc-opentitan/hw/ip/uart/rtl/uart.sv",
    },
    "opentitan_gpio": {
        "source_lock": "opentitan_gpio",
        "top_module": "gpio",
        "protocol": ["tl-ul", "1"],
        "window": {"base": 0x4000_1000, "size": 0x1000},
        "data_width": 32,
        "capabilities": {
            "byte_enable": True, "partial_write": True, "has_error": True,
            "integrity": "required", "source_width": 8, "sink_width": 1,
            "user_width": 23, "size_width": 2,
        },
        "evidence_topics": _TLUL_EVIDENCE,
        "irq": {"signal": "intr_gpio_o", "trigger": "level"},
        "environment": {"protocol": ["gpio-event", "1"],
                        "parameters": {"width": 8, "synchronizer_stages": 3,
                                       "event_kind": "edge"}},
        "spot_check": "third_party/soc-opentitan/hw/top_earlgrey/ip_autogen/gpio/rtl/gpio.sv",
    },
    "pulp_gpio": {
        "source_lock": "pulp_gpio",
        "top_module": "apb_gpio",
        "protocol": ["apb", "3"],
        # Pinned fact; a cell config that declares its own window (the ibex-pulp
        # and cva6-pulp profiles do) overrides this value.
        "window": {"base": 0x5000_0000, "size": 0x1000},
        "data_width": 32,
        "capabilities": {"byte_enable": False, "partial_write": False,
                         "has_error": False},
        "evidence_topics": _APB_EVIDENCE,
        "irq": {"signal": "interrupt", "trigger": "edge"},
        "environment": {"protocol": ["gpio-event", "1"],
                        "parameters": {"width": 8, "synchronizer_stages": 3,
                                       "event_kind": "edge"}},
        "spot_check": "third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv",
    },
    "pulp_spi": {
        "source_lock": "pulp_spi",
        "top_module": "apb_spi_master",
        "protocol": ["apb", "3"],
        # Pinned fact; overridden by a cell config's own window when declared.
        "window": {"base": 0x5000_1000, "size": 0x1000},
        "data_width": 32,
        "capabilities": {"byte_enable": False, "partial_write": False,
                         "has_error": False},
        "evidence_topics": _APB_EVIDENCE,
        "irq": {"signal": "events_o", "trigger": "edge"},
        "environment": {"protocol": ["spi-miso", "1"],
                        "parameters": {"bits": 8, "cpol": 0, "cpha": 0,
                                       "msb_first": True}},
        "spot_check": "third_party/soc-pulp-apb-spi/apb_spi_master.sv",
    },
    "zipcpu_uart": {
        "source_lock": "zipcpu_uart",
        "top_module": "wbuart",
        "protocol": ["wishbone", "classic"],
        "window": {"base": 0x6000_0000, "size": 0x10},
        "data_width": 32,
        "capabilities": {
            "byte_enable": True, "partial_write": False, "has_error": False,
            "has_address_port": True, "address_units": "word",
            "sel_implemented": True, "wishbone_flavour": "registered-ack",
            "ack_requires_cyc": True,
        },
        "evidence_topics": _ZIPCPU_UART_EVIDENCE,
        "irq": {"signal": "o_uart_rx_int", "trigger": "level"},
        "environment": {"protocol": ["uart-serial", "1"],
                        "parameters": {"bits": 8, "baud_div": 1, "frame_bits": 10}},
        "spot_check": "third_party/soc-zipcpu-wbuart/rtl/wbuart.v",
    },
    "zipcpu_timer": {
        "source_lock": "zipcpu_timer",
        "top_module": "ziptimer",
        "protocol": ["wishbone", "classic"],
        "window": {"base": 0x6000_0010, "size": 4},
        "data_width": 32,
        "capabilities": {
            "byte_enable": False, "partial_write": False, "has_error": False,
            "has_address_port": False, "address_units": "word",
            "sel_implemented": False,
            "wishbone_flavour": "registered-ack-cyc-ignored",
            "ack_requires_cyc": False,
        },
        "evidence_topics": _ZIPCPU_TIMER_EVIDENCE,
        "irq": {"signal": "o_int", "trigger": "edge"},
        "environment": None,
        "spot_check": "third_party/soc-zipcpu/rtl/peripherals/ziptimer.v",
    },
}

#: The execution monitor every profile artifact carries: the generated fabric's
#: own request/completion handshake is the source/target transaction evidence a
#: campaign report has to publish, and it is the same boundary for a fresh build
#: and for a cache hit.
PROFILE_FABRIC_MONITOR = {"mode": "profile_fabric"}

_TOP_MODULE_RE = re.compile(r"^module\s+([A-Za-z_]\w*)\b", re.MULTILINE)
_PORT_RE = re.compile(
    r"\b(input|output|inout)\s+(?:wire|logic|reg)?\s*(\[[^\]]*\])?\s*([A-Za-z_]\w*)"
)
_SAFE_WIDTH_RE = re.compile(r"\A[0-9+\-*/() ]+\Z")
_WIDTH_IDENTIFIERS = {"ADDRESS_WIDTH", "DATA_WIDTH"}


class SocBuildError(RuntimeError):
    """A real source-backed campaign artifact could not be built."""


@dataclass(frozen=True)
class SocCampaignArtifact(SimulatorArtifact):
    """A Verilator SoC artifact plus the exact build evidence behind it."""

    build_document: Mapping[str, object] = None
    rendered_files: tuple[tuple[str, str], ...] = ()
    #: The projection arms this artifact can execute: one projector per arm of
    #: the three-arm comparison over this exact build (direct input, constrained
    #: baseline, dependency repair).  Empty when the build does not declare them.
    projection_arms: Mapping[str, object] = field(default_factory=dict)


def _provisional_record_width(plan, image) -> int:
    """The width of the raw record a candidate program will be projected from.

    The combined ABI places the image segment, then the synthetic master's
    stimulus and the attached peers' request fields; the concrete layout is built
    later, but its width is already determined by the plan and the image plan.  A
    declared program owns only its own image bits, so it has to be told this
    width or it would refuse a record that legally carries those later bits.
    """
    from myfuzz.composition.soc_image import _stimulus_reserved_bits

    width = int(image.raw_width)
    if plan.synthetic:
        width = max(width, int(plan.raw_layout.get("raw_width", 0))
                    + _stimulus_reserved_bits(plan))
    for peer in plan.peers:
        for slot in peer.slots:
            for signal in slot.signals:
                width += int(signal.width)
    return width


def build_projection_arms(*, layout, constraint_hash, special_width, policy, image,
                          image_address_policy="repair",
                          candidate_program=None, peer_slots=()) -> dict[str, object]:
    """The three input-projection arms over one compiled profile artifact.

    Every arm shares the layout, the executable and the coverage instrumentation;
    only the projection differs, which is what makes the comparison a comparison
    of projection policies rather than of builds.  When the plan declares several
    candidate slots, the dependency-repair arm places and checks them through the
    declared candidate program (:mod:`myfuzz.composition.soc_candidate_program`)
    instead of the single-candidate legacy path.
    """
    if image_address_policy not in ("repair", "strict"):
        raise SocBuildError("profile-image-address-policy-invalid")
    return {
        "direct_input": SocRawProjector(layout, constraint_hash),
        "constrained_baseline": ProfileCampaignProjector(
            layout, constraint_hash, special_width, policy=policy, image_plan=None,
            peer_slots=peer_slots),
        "dependency_repair": ProfileCampaignProjector(
            layout, constraint_hash, special_width, policy=policy, image_plan=image,
            image_address_policy=image_address_policy,
            candidate_program=candidate_program, peer_slots=peer_slots),
    }


def _peer_projection_slots(plan, layout, *, base_dir=None):
    """Return the peer slot ABI records used by projection and replay.

    The renderer and layout are the source of the actual top-level port names;
    the peer plan supplies only the timing contract.  Keeping the two records
    joined here prevents a model slot from silently validating a different raw
    field after a layout change.  ``pulse_ports`` is retained for the existing
    spacing checker; ``signals`` carries the complete raw offsets so a campaign
    can save a semantic event trace beside its raw corpus.
    """
    if not plan.peers:
        return ()
    fields = {field.port: field for field in layout.fields if field.owner == "soc_peer"}
    records = []
    for peer in plan.peers:
        peer_source_hash = None
        if base_dir is not None:
            source_path = Path(base_dir) / str(peer.source)
            if source_path.is_file():
                peer_source_hash = _file_hash(source_path)
        for slot in peer.slots:
            pulse_ports = []
            signals = []
            for signal in slot.signals:
                field = fields.get(signal.top_port)
                if field is None:
                    raise SocBuildError(
                        f"peer-layout-field-missing:{peer.instance_id}:{slot.slot}:{signal.top_port}")
                if field.width != signal.width:
                    raise SocBuildError(
                        f"peer-layout-width-mismatch:{peer.instance_id}:{slot.slot}:"
                        f"{signal.top_port}:{field.width}!={signal.width}")
                signals.append({
                    "peer_port": signal.peer_port,
                    "top_port": signal.top_port,
                    "source": signal.source,
                    "width": int(signal.width),
                    "raw_lo": int(field.raw_lo),
                    "raw_hi": int(field.raw_hi),
                })
                if signal.source == "pulse":
                    pulse_ports.append(signal.top_port)
            records.append({
                "index": len(records),
                "instance_id": peer.instance_id,
                "peer_id": peer.peer_id,
                "peer_source": peer.source,
                "peer_source_hash": peer_source_hash,
                "peer_module": peer.module,
                "peer_protocol": list(peer.protocol),
                "slot": slot.slot,
                "kind": slot.kind,
                "width": int(slot.width),
                "minimum_gap_cycles": int(slot.minimum_gap_cycles),
                "pulse_ports": tuple(pulse_ports),
                "signals": tuple(signals),
            })
    records.sort(key=lambda item: (str(item["instance_id"]), str(item["slot"])))
    for index, item in enumerate(records):
        item["index"] = index
    return tuple(records)


class SocRawProjector:
    """Identity projection: one RFuzz record *is* one raw stimulus sample.

    ``project_records`` is the record-level entry point every arm shares: the
    three-arm comparison hands the same raw sequence to each arm, so an arm that
    only implemented the per-word ``project`` would be executed through a
    different code path from the other two.  The identity arm's record
    projection is the identity on every word.
    """

    instruction_mode = "soc-raw-stimulus-abi"

    def __init__(self, layout, constraint_hash):
        self.layout = layout
        self.constraint_hash = constraint_hash

    def project(self, raw):
        if type(raw) is not int or not 0 <= raw < 1 << self.layout.raw_width:
            raise ValueError("raw sample outside the compiled stimulus layout")
        return raw

    def project_records(self, raw_values):
        """Project a whole raw sequence; the identity arm returns it unchanged."""
        return [self.project(raw) for raw in raw_values]


def _require_mapping(value, label):
    if not isinstance(value, Mapping):
        raise SocBuildError("%s:mapping-required" % label)
    return value


def _read_json(path, label):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SocBuildError("%s-unreadable:%s: %s" % (label, path, error)) from error


def _hash_bytes(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _file_hash(path):
    return _hash_bytes(Path(path).read_bytes())


def _coverage_instrumenter_identity():
    path = ROOT / "scripts/source_branch_instrumenter.py"
    try:
        source_hash = _file_hash(path)
    except OSError as error:
        raise SocBuildError(f"coverage-instrumenter-unavailable:{path}") from error
    return {
        "schema_version": _COVERAGE_INSTRUMENTER_SCHEMA,
        "source_sha256": source_hash,
        "settings": copy.deepcopy(_COVERAGE_INSTRUMENTER_SETTINGS),
    }


def _profile_build_cache_key(base_identity, instrumenter_identity,
                            instrumented_output_sha256):
    if not isinstance(base_identity, Mapping) or not isinstance(instrumenter_identity, Mapping):
        raise SocBuildError("profile-build-cache-identity-invalid")
    if not isinstance(instrumented_output_sha256, str) or not instrumented_output_sha256:
        raise SocBuildError("profile-build-cache-instrumented-output-identity-invalid")
    return content_hash({
        "base_identity": dict(base_identity),
        "coverage_instrumenter": dict(instrumenter_identity),
        "instrumented_output_sha256": instrumented_output_sha256,
    })


def _instrumented_output_sha256(instrumented_root, instrumented_flist, *, path_aliases=()):
    """Hash all compiler inputs while removing build-directory-specific paths."""
    root = Path(instrumented_root).resolve()
    flist = Path(instrumented_flist).resolve()
    if not root.is_dir() or not flist.is_file() or not flist.is_relative_to(root):
        raise SocBuildError("coverage-instrumented-output-incomplete")
    aliases = {root.as_posix()}
    aliases.update(str(item) for item in path_aliases if isinstance(item, str) and item)
    aliases = sorted(aliases, key=len, reverse=True)
    records = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise SocBuildError("coverage-instrumented-output-symlink-unsupported")
        if not path.is_file() or path.name == "instrumentation.json":
            continue
        payload = path.read_bytes()
        if path.resolve() == flist:
            for alias in aliases:
                payload = payload.replace(alias.encode("utf-8"), b"<INSTRUMENTED_ROOT>")
        records.append({
            "path": path.relative_to(root).as_posix(),
            "sha256": _hash_bytes(payload),
        })
    return content_hash({
        "schema_version": "source_instrumented_output.v1",
        "files": records,
    })


def _cached_instrumentation_matches(cache_entry, document, instrumenter_identity):
    coverage = (document.get("coverage_instrumentation") or document.get("coverage")
                if isinstance(document, Mapping) else None)
    sources = document.get("sources") if isinstance(document, Mapping) else None
    if not isinstance(coverage, Mapping) or not isinstance(sources, Mapping):
        return False
    if coverage.get("instrumenter") != instrumenter_identity:
        return False
    expected = coverage.get("instrumented_output_sha256")
    old_root = coverage.get("instrumented_root", sources.get("instrumented_root"))
    if not isinstance(expected, str) or not expected or not isinstance(old_root, str):
        return False
    root = Path(cache_entry) / "instrumentation/instrumented"
    try:
        actual = _instrumented_output_sha256(
            root, root / "instrumented_sources.f", path_aliases=(old_root,))
    except (OSError, SocBuildError, TypeError, ValueError):
        return False
    return actual == expected


def _mode(config):
    mode = config.get("mode", "mixed")
    if mode not in ("cpu_only", "mmio_only", "mixed"):
        raise SocBuildError("unsupported campaign mode: %r" % (mode,))
    return mode


def _tool_version(tool):
    try:
        result = subprocess.run(
            (str(tool), "--version"), capture_output=True, text=True,
            timeout=30, check=False)
    except OSError as error:
        raise SocBuildError("tool-unavailable:%s: %s" % (tool, error)) from error
    text = (result.stdout or result.stderr or "").strip().splitlines()
    if result.returncode != 0 or not text:
        raise SocBuildError("tool-version-failed:%s" % (tool,))
    return text[0]


def _cell_config(config, root, build):
    """Resolve (config path, effective cell document) for this task."""
    reference = config.get("cell_config", config.get("render_config"))
    if reference is None:
        cell_id = config.get("cell_id") or config.get("config_id")
        candidate = root / "configs/soc" / ("%s.json" % cell_id)
        if cell_id and candidate.is_file():
            reference = candidate
    if reference is not None:
        path = Path(str(reference))
        if not path.is_absolute():
            path = root / path
        path = path.resolve()
        if not path.is_file() or path.is_symlink():
            raise SocBuildError("cell config is missing: %s" % path)
        document = _read_json(path, "cell-config")
    elif isinstance(config.get("base_cell"), Mapping):
        document = copy.deepcopy(dict(config["base_cell"]))
        build.parent.mkdir(parents=True, exist_ok=True)
        path = build.with_name(build.name + "-cell_config.json").absolute()
        path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    else:
        raise SocBuildError(
            "campaign config must name 'cell_config' or embed 'base_cell'")
    effective = _merge_base_profile(document, path, root)
    if not isinstance(effective.get("cpu"), Mapping):
        raise SocBuildError("cell config must declare a cpu mapping: %s" % path)
    if not isinstance(effective.get("peripherals"), list) or not effective["peripherals"]:
        raise SocBuildError("cell config must declare peripherals: %s" % path)
    if not isinstance(effective.get("memory_regions"), list) or not effective["memory_regions"]:
        raise SocBuildError("cell config must declare memory_regions: %s" % path)
    return path, effective


def _merge_base_profile(document, path, root):
    """Merge a 'base_profile' exactly like the renderer's own profile merge."""
    base_reference = document.get("base_profile")
    if not isinstance(base_reference, str) or not base_reference:
        return document
    base_path = Path(base_reference)
    if not base_path.is_absolute():
        base_path = root / base_path
    base = _read_json(base_path.resolve(), "base-profile")
    if not isinstance(base, Mapping):
        raise SocBuildError("base profile is not an object: %s" % base_path)
    merged = copy.deepcopy(dict(base))
    merged["cell_id"] = document.get("cell_id", merged.get("cell_id"))
    merged["families"] = list(document.get("families", merged.get("families", [])))
    merged["peripherals"] = copy.deepcopy(document["peripherals"])
    merged["matrix_cell"] = copy.deepcopy(dict(document))
    merged["base_profile"] = base_reference
    return merged


def _peripheral_records(cell, root):
    """Normalise the cell config's peripheral declarations into full records."""
    records = []
    for entry in cell["peripherals"]:
        if isinstance(entry, Mapping):
            source_lock = entry.get("source_lock", entry.get("id"))
        elif isinstance(entry, str):
            source_lock = entry
        else:
            raise SocBuildError("peripheral declaration must be a string or object")
        facts = PERIPHERAL_FACTS.get(str(source_lock))
        if facts is None:
            raise SocBuildError(
                "peripheral %r has no pinned capability facts; refusing to invent them"
                % (source_lock,))
        record = copy.deepcopy(facts)
        if isinstance(entry, Mapping):
            record.update(copy.deepcopy(dict(entry)))
        record["source_lock"] = str(source_lock)
        record.setdefault("id", str(source_lock))
        record.setdefault("target_id", "%s_win" % record["id"])
        record.setdefault("closure", "%s/%s.json" % (CLOSURE_DIR, record["source_lock"]))
        record.setdefault("runtime_status", "runtime_unverified")
        closure_path = Path(str(record["closure"]))
        if not closure_path.is_absolute():
            closure_path = root / closure_path
        if not closure_path.is_file() or closure_path.is_symlink():
            raise SocBuildError("peripheral closure is missing: %s" % closure_path)
        closure = _read_json(closure_path, "peripheral-closure")
        if (closure.get("component") != record["source_lock"]
                or closure.get("top_module") != record["top_module"]):
            raise SocBuildError(
                "closure identity mismatch for %s: %s" % (record["id"], closure_path))
        record["closure_document"] = closure
        if not record.get("parameters"):
            # The cell config may name a peripheral by source lock only; the
            # pinned closure then records the parameter values that elaborated.
            record["parameters"] = {
                str(item["name"]): item["value"]
                for item in closure.get("parameters", [])
                if isinstance(item, Mapping) and isinstance(item.get("name"), str)
                and item["name"].isidentifier()
            }
        topics = {item.get("topic") for item in closure.get("capability_findings", [])
                  if isinstance(item, Mapping)}
        record["unverified_evidence_topics"] = sorted(
            topic for topic in set(record["evidence_topics"].values())
            if topic not in topics)
        records.append(record)
    ids = [record["id"] for record in records]
    if len(set(ids)) != len(ids):
        raise SocBuildError("duplicate peripheral ids in the cell config")
    return records


def _cpu_facts(cell, cell_id):
    cpu = cell.get("cpu")
    if not isinstance(cpu, Mapping):
        raise SocBuildError("%s: cpu mapping required" % cell_id)
    protocol = cpu.get("protocol")
    if (not isinstance(protocol, Sequence) or isinstance(protocol, (str, bytes))
            or len(protocol) != 2 or not all(isinstance(item, str) and item
                                             for item in protocol)):
        raise SocBuildError("%s: cpu protocol must be a (name, version) pair" % cell_id)
    xlen = cpu.get("xlen")
    if xlen not in (32, 64):
        raise SocBuildError("%s: cpu xlen must be 32 or 64" % cell_id)
    if not isinstance(cpu.get("source_lock"), str) or not isinstance(cpu.get("top_module"), str):
        raise SocBuildError("%s: cpu source_lock/top_module required" % cell_id)
    return cpu


def _evidence(record):
    """Evidence keyed by capability fact (the shape soc_plan records)."""
    return {
        fact: {"topic": record["evidence_topics"][fact],
               "evidence_path": record["closure"], "provenance": "rtl_read"}
        for fact in sorted(record["capabilities"])
        if fact in record["evidence_topics"]
    }


def _cell_spec(cell, cpu, records, cell_id, config_path, root):
    width = 64 if cpu["xlen"] == 64 else 32
    is_unified = list(cpu["protocol"])[0] == "axi4"

    components = [{
        "component_id": "cpu",
        "kind": "cpu",
        "source_lock": cpu["source_lock"],
        "top_module": cpu["top_module"],
        "clock_domain": "core",
        "reset_domain": "cpu_rst",
        "instances": [{"instance_id": "cpu0",
                       "parameters": dict(cpu.get("parameters", {}))}],
        "capability_evidence": {"isa": "rv%d" % cpu["xlen"],
                                "provenance": cpu.get("source_provenance", str(config_path))},
    }]
    for region in cell["memory_regions"]:
        writable = bool(region["permissions"]["write"])
        components.append({
            "component_id": region["region_id"],
            "kind": "memory",
            "source_lock": "soc_%s_model" % ("ram" if writable else "rom"),
            "top_module": "riscv_boot_memory_%d" % width,
            "clock_domain": "core",
            "reset_domain": "sys_rst",
            "instances": [{"instance_id": region["region_id"],
                           "parameters": {"BASE_ADDR": region["base"],
                                          "BYTES": region["size"]}}],
            "capability_evidence": {"model": "byte image memory model",
                                    "provenance": "src/myfuzz/integration/rtl/riscv_boot_memory.sv"},
        })
    for record in records:
        components.append({
            "component_id": record["id"],
            "kind": "peripheral",
            "source_lock": record["source_lock"],
            "top_module": record["top_module"],
            "clock_domain": "core",
            "reset_domain": "sys_rst",
            "instances": [{"instance_id": record["id"],
                           "parameters": dict(record.get("parameters") or {})}],
            "capability_evidence": {
                "protocol": list(record["protocol"]),
                "closure": record["closure"],
                "provenance": record["closure"],
            },
        })
    components.append({
        "component_id": "harness",
        "kind": "clock_reset",
        "source_lock": "soc_clock_reset_harness",
        "top_module": "soc_harness",
        "clock_domain": "core",
        "reset_domain": "sys_rst",
        "instances": [{"instance_id": "harness0", "parameters": {"CYCLES": MAX_CYCLES}}],
        "capability_evidence": {"model": "clock/reset/environment harness",
                                "provenance": "P7"},
    })

    masters = []
    if is_unified:
        masters.append({
            "source_id": "cpu_unified", "kind": "cpu_unified", "component_id": "cpu",
            "port": "noc", "protocol": list(cpu["protocol"]), "data_width": width,
            "address_width": width, "test_modes": ["cpu_only", "mixed"],
        })
    else:
        masters.append({
            "source_id": "cpu_ifetch", "kind": "cpu_instruction", "component_id": "cpu",
            "port": "instr", "protocol": list(cpu["protocol"]), "data_width": width,
            "address_width": width, "test_modes": ["cpu_only", "mixed"],
        })
        masters.append({
            "source_id": "cpu_data", "kind": "cpu_data", "component_id": "cpu",
            "port": "data", "protocol": list(cpu["protocol"]), "data_width": width,
            "address_width": width, "test_modes": ["cpu_only", "mixed"],
        })
    masters.append({
        "source_id": "fuzz_mmio", "kind": "fuzz_mmio", "component_id": "harness",
        "port": "mmio", "protocol": ["processor-memory-beat", "1"],
        "data_width": width, "address_width": width,
        "test_modes": ["mmio_only", "mixed"],
    })

    memory_targets = []
    for region in cell["memory_regions"]:
        writable = bool(region["permissions"]["write"])
        sources = ["cpu_unified"] if is_unified else ["cpu_ifetch", "cpu_data"]
        if writable:
            sources = sources + ["fuzz_mmio"]
        memory_targets.append({
            "target_id": "%s_win" % region["region_id"],
            "component_id": region["region_id"],
            "port": "mem",
            "protocol": ["ready-valid-memory", "1"],
            "window": {"base": region["base"], "size": region["size"]},
            "request_sources": sources,
            "response_owner": "soc_fabric",
            "byte_enable": writable,
        })

    mmio_sources = ["cpu_unified"] if is_unified else ["cpu_data"]
    mmio_sources = mmio_sources + ["fuzz_mmio"]
    peripheral_targets = [{
        "target_id": record["target_id"],
        "component_id": record["id"],
        "port": record["protocol"][0],
        "protocol": list(record["protocol"]),
        "window": copy.deepcopy(record["window"]),
        "request_sources": list(mmio_sources),
        "response_owner": "soc_fabric",
        # The planner's byte_enable flag means "this target really accepts
        # partial byte writes"; an IP with a byte-enable pin but register-specific
        # semantics (ZipCPU wbuart) records partial_write False and keeps the
        # fail-closed adapter rejection.
        "byte_enable": bool(record["capabilities"].get("partial_write", False)),
        "data_width": record["data_width"],
        "width_conversion": {"spanning_write": "reject", "spanning_read": "reject"},
    } for record in records]

    interrupt_routes = []
    irq = 3
    for record in sorted(records, key=lambda item: item["id"]):
        route = record.get("irq")
        if not route:
            continue
        interrupt_routes.append({
            "route_id": "%s_irq" % record["id"],
            "source": {"component_id": record["id"], "signal": route["signal"],
                       "trigger": route["trigger"]},
            "sink": {"master_id": "cpu_unified" if is_unified else "cpu_data",
                     "irq": irq},
            "mask_ack": {"register": "%s.intr_state" % record["id"],
                         "semantics": "write-1-to-clear"},
        })
        irq += 1

    environment_links = []
    for record in sorted(records, key=lambda item: item["id"]):
        link = record.get("environment")
        if not link:
            continue
        environment_links.append({
            "link_id": "%s_pins" % record["id"],
            "component_id": record["id"],
            "protocol": list(link["protocol"]),
            "parameters": copy.deepcopy(link["parameters"]),
        })

    source_locks = sorted({"soc_ram_model", "soc_rom_model", "soc_clock_reset_harness",
                           str(cpu["source_lock"])}
                          | {record["source_lock"] for record in records})
    return {
        "schema_version": "soc_spec.v1",
        "spec_id": cell_id,
        "source_locks": source_locks,
        "components": components,
        "memory_regions": [{
            "region_id": region["region_id"],
            "component_id": region["region_id"],
            "base": region["base"],
            "size": region["size"],
            "permissions": copy.deepcopy(region["permissions"]),
            "physical_memory_id": region["physical_memory_id"],
            "initialization_policy": region["initialization_policy"],
        } for region in cell["memory_regions"]],
        "masters": masters,
        "targets": memory_targets + peripheral_targets,
        "interrupt_routes": interrupt_routes,
        "environment_links": environment_links,
        "resources": {
            "clock_domains": [{"name": "core", "frequency_hz": 50000000}],
            "resets": [
                {"name": "rst_sys_ni", "domain": "sys_rst", "polarity": "active_low",
                 "synchronous": True},
                {"name": "rst_cpu_ni", "domain": "cpu_rst", "polarity": "active_low",
                 "synchronous": True},
            ],
            "clock_adapters": [],
            "limits": {"build_timeout_s": BUILD_TIMEOUT_SECONDS, "run_timeout_s": 120,
                       "rss_limit_mb": 2048, "cycles_per_sample": MAX_CYCLES},
        },
        "assumptions": [{
            "assumption_id": "single_runtime_clock",
            "statement": "Every selected IP runs on the single runtime clock domain.",
            "provenance": str(config_path),
        }],
        "provenance": {
            "render_config": str(config_path),
            "cell": cell_id,
            "closures": CLOSURE_DIR,
            "sources": SOURCES_LOCK,
            "root": str(root),
        },
    }


def _processor_execution(cpu, cell_id):
    protocol = list(cpu["protocol"])
    width = 64 if cpu["xlen"] == 64 else 32
    is_unified = protocol[0] == "axi4"
    module = "axi4_processor_memory_adapter" if is_unified else "obi_processor_memory_adapter"
    source = "src/myfuzz/protocols/rtl/%s.sv" % module
    route = {
        "source_protocol": protocol,
        "target_protocol": ["processor-memory-beat", "1"],
        "adapter_id": "%s_beat" % protocol[0],
        "rtl_module": module,
        "rtl_source": source,
        "parameters": {"ADDRESS_WIDTH": width, "READ_ONLY": 0},
        "widths": {"address": width, "data": width},
        "field_connections": [],
        "extension_policies": [],
        "reset_contract": {"polarity": "active_low", "synchrony": "sync"},
        "backend_contract": {
            "mode": "single_outstanding_request_response",
            "protocol": ["processor-memory-beat", "1"],
            "capabilities": {"max_outstanding": 1, "max_wait_cycles": 64},
        },
    }
    routes = []
    if is_unified:
        routes.append(dict(route, route_id=1, function="memory_master"))
    else:
        routes.append(dict(route, route_id=1, function="instruction_memory_master",
                           parameters={"ADDRESS_WIDTH": width, "READ_ONLY": 1}))
        routes.append(dict(route, route_id=2, function="data_memory_master"))
    return {
        "schema_version": "processor_execution.v1",
        "adapter_sources": [source],
        "classification": None,
        "routes": routes,
        "execution_hash": content_hash({"cell": cell_id, "routes": routes,
                                        "module": module}),
    }


def _target_contracts(cell, records, cpu, cell_id):
    width = 64 if cpu["xlen"] == 64 else 32
    contracts = []
    for region in cell["memory_regions"]:
        writable = bool(region["permissions"]["write"])
        model = "riscv_boot_memory_%d" % width
        contracts.append({
            "target_id": "%s_win" % region["region_id"],
            "component_id": region["region_id"],
            "port": "mem",
            "protocol": ["ready-valid-memory", "1"],
            "adapter_module": model,
            "adapter_source": "src/myfuzz/integration/rtl/riscv_boot_memory.sv",
            "capabilities": {"partial_write": writable, "read": True,
                             "write": writable, "data_width": width},
            "evidence": {"provenance": "src/myfuzz/integration/rtl/riscv_boot_memory.sv"},
        })
    for record in records:
        target_record = {
            "component_id": record["id"],
            "target_id": record["target_id"],
            "protocol": list(record["protocol"]),
            "version": record["protocol"][1] if len(record["protocol"]) > 1 else None,
            "data_width": record["data_width"],
            "window": copy.deepcopy(record["window"]),
            "capabilities": copy.deepcopy(record["capabilities"]),
            "evidence": _evidence(record),
        }
        try:
            resolved = resolve_target_adapter(
                {"protocol": "processor-memory-beat", "version": "1",
                 "address_width": width, "data_width": record["data_width"]},
                target_record,
            )
        except ValueError as error:
            raise SocBuildError(
                "%s:%s:target-adapter-unresolved: %s" % (cell_id, record["id"], error)
            ) from error
        contracts.append({
            "target_id": record["target_id"],
            "component_id": record["id"],
            "port": record["protocol"][0],
            "protocol": list(record["protocol"]),
            "adapter_module": resolved["rtl_module"],
            "adapter_source": resolved["rtl_source"],
            # data_width is a declared target fact, not a capability fact: the
            # P5 resolver reads it from the target record, and every recorded
            # capability fact must carry evidence.
            "capabilities": copy.deepcopy(record["capabilities"]),
            "evidence": _evidence(record),
        })
    return contracts


def load_profile_campaign_request(config, root):
    """Read profile inputs without invoking elaboration or the legacy registry.

    The declared drive profile is admitted only when ``input_constraints``
    declares it, and the requested mode must be one of that profile's own legacy
    modes: the bus owner, the CPU reset hold and the mode are one declaration, so
    a mismatched pair is refused before anything is built.  An unknown profile
    name is still a build error, never a fallback to the CPU-owned default.
    """
    from myfuzz.composition.component_profile import (
        load_component_profile, load_composition_request,
    )
    from myfuzz.composition.input_constraints import DRIVE_PROFILES
    drive_profile = config.get("drive_profile", "cpu_execute")
    if not isinstance(drive_profile, str) or drive_profile not in DRIVE_PROFILES:
        raise SocBuildError(f"profile-drive-unsupported:{drive_profile}")
    legacy_modes = tuple(str(item) for item in DRIVE_PROFILES[drive_profile]["legacy_modes"])
    mode = config.get("mode", legacy_modes[0])
    if mode not in legacy_modes:
        raise SocBuildError(f"profile-drive-mode-mismatch:{drive_profile}:{mode}")
    paths = config.get("component_profiles")
    if not isinstance(paths, (list, tuple)) or not paths:
        raise SocBuildError("profile-inputs-required: component_profiles")
    profiles = {}
    for value in paths:
        path = Path(value)
        path = path if path.is_absolute() else root / path
        profile = load_component_profile(path)
        profiles[str(value)] = profile
        profiles[str(path)] = profile
        if path.is_relative_to(root):
            profiles[str(path.relative_to(root))] = profile
        profiles[profile.component_id] = profile
    request = config["composition_request"]
    if isinstance(request, (str, Path)):
        path = Path(request)
        request = path if path.is_absolute() else root / path
    return load_composition_request(request, profiles=profiles)


class ProfileCampaignProjector(SocRawProjector):
    """Project special inputs and bounded pre-reset memory overlays."""
    instruction_mode = "profile-pre-reset-single-code-data-image"

    def __init__(self, layout, constraint_hash, special_width, *, policy, image_plan=None,
                 image_address_policy="repair", candidate_program=None, peer_slots=()):
        super().__init__(layout, constraint_hash)
        self.special_width = special_width
        self.policy = policy
        self.image_plan = image_plan
        if image_address_policy not in ("repair", "strict"):
            raise SocBuildError("profile-image-address-policy-invalid")
        self.image_address_policy = image_address_policy
        if candidate_program is not None and image_plan is None:
            raise SocBuildError("profile-candidate-program-without-an-image-plan")
        self.candidate_program = candidate_program
        if not isinstance(peer_slots, Sequence) or isinstance(peer_slots, (str, bytes)):
            raise SocBuildError("profile-peer-slots-invalid")
        self.peer_slots = tuple(dict(item) for item in peer_slots)
        self._runtime_external_mask = 0
        for field in getattr(layout, "fields", ()):
            if str(getattr(field, "owner", "")) not in {"soc_peer", "soc_stimulus"}:
                continue
            self._runtime_external_mask |= ((1 << int(field.width)) - 1) << int(field.raw_lo)
        for item in self.peer_slots:
            if (not isinstance(item.get("instance_id"), str)
                    or not isinstance(item.get("slot"), str)
                    or isinstance(item.get("minimum_gap_cycles"), bool)
                    or not isinstance(item.get("minimum_gap_cycles"), int)
                    or item["minimum_gap_cycles"] < 0
                    or not isinstance(item.get("pulse_ports"), Sequence)
                    or isinstance(item.get("pulse_ports"), (str, bytes))):
                raise SocBuildError("profile-peer-slot-contract-invalid")
            signals = item.get("signals", ())
            if (isinstance(signals, (str, bytes))
                    or not isinstance(signals, Sequence)
                    or (not item["pulse_ports"] and not signals)):
                raise SocBuildError("profile-peer-slot-contract-invalid")
        #: The record of the last repaired test (its placements, dependency
        #: edges, bounded unknowns and counters), so a campaign run can publish
        #: what the projection really did instead of only its counters.
        self.last_repaired_test = None
        #: Semantic peer events decoded from the last projected sequence.  The
        #: raw ABI remains the source of truth; this is replay evidence only.
        self.last_peer_events = ()
        self.repair_counts = {"address_repair": 0}

    def project(self, raw):
        super().project(raw)
        # The constraint-only arm has no image plan, but the combined profile
        # ABI may still carry synthetic-master and peer fields above the
        # profile-owned prefix.  Only image-owned bits are dynamic-image input;
        # environment-owned runtime fields must remain usable in this arm.
        if self.image_plan is None:
            high = raw & ~((1 << self.special_width) - 1)
            if high & ~self._runtime_external_mask:
                raise SocBuildError("profile-dynamic-image-loading-unsupported")
        from myfuzz.composition.input_constraints import project_sample_values
        # The combined image segment is not part of this projection's write
        # authority. A policy targeting it must fail the special-width bound.
        if self.special_width:
            mask = (1 << self.special_width) - 1
            raw = (raw & ~mask) | project_sample_values(
                self.policy, raw & mask, raw_width=self.special_width)
        if self.image_plan is not None:
            image = self.image_plan
            def value(name):
                field = image.segment(name)
                return (raw >> field.raw_lo) & ((1 << (field.raw_hi-field.raw_lo+1))-1)
            if self.image_address_policy == "repair":
                for prefix, base, size in (("init", image.base, image.size),
                                           ("data", image.data_base, image.data_size)):
                    if not value(prefix + "_offer"):
                        continue
                    old = value(prefix + "_address")
                    first = (base + 3) & ~3
                    slots = (base + size - first) // 4
                    if slots < 1:
                        raise SocBuildError("profile-image-no-full-word-slot")
                    legal = base <= old and old + 4 <= base + size
                    if prefix == "init":
                        legal = legal and old % 4 == 0
                    if not legal:
                        address = first + ((old // 4) % slots) * 4
                        lo = image.segment(prefix + "_address").raw_lo
                        raw = (raw & ~(0xffffffff << lo)) | (address << lo)
                        self.repair_counts["address_repair"] += 1
            if value("init_offer"):
                # A declared instruction candidate is one full 32-bit word, so a
                # byte enable narrower than the full word cannot be honoured: an
                # instruction is fetched as a word and a half-written word is not
                # a program.  The image projection has authority over the
                # *candidate* fields -- they are environment input that the CPU
                # has not been released against -- so it repairs the enable to the
                # full word and records the repair, exactly as it already repairs
                # a misplaced address.  Refusing here made every real RFuzz
                # campaign fail on its first corpus entry, because the mutator
                # legitimately explores byte enables.
                enable = value("init_be")
                if enable != 15:
                    field = image.segment("init_be")
                    raw = (raw & ~(0xF << field.raw_lo)) | (0xF << field.raw_lo)
                    self.repair_counts["byte_enable_repair"] = \
                        self.repair_counts.get("byte_enable_repair", 0) + 1
                    value = lambda name, _raw=raw: (  # noqa: E731 - re-read the field
                        (_raw >> image.segment(name).raw_lo)
                        & ((1 << (image.segment(name).raw_hi
                                  - image.segment(name).raw_lo + 1)) - 1))
                if value("init_address") % 4:
                    # The address repair above already moved a misplaced address
                    # onto a full-word slot; an unaligned one that survived it can
                    # only mean the repair was not applicable, and silently
                    # rounding it here would place the candidate somewhere the
                    # caller never asked for.
                    raise SocBuildError("profile-image-full-aligned-instruction-required")
            # The combined RFuzz word may carry synthetic-master or peer input
            # bits beyond the image plan. Image materialisation owns only its
            # declared segment; mask the combined word before passing it to the
            # image layer so external requests cannot be mistaken for image
            # overflow or alter the frozen boot state.
            materialized = image.materialize(raw & ((1 << image.raw_width) - 1))
            if value("init_offer"):
                corrected = materialized.initialization_records[0]["corrected_candidate"]
                if corrected["width"] != 32:
                    raise SocBuildError("profile-compressed-image-unsupported")
                field = image.segment("init_data")
                raw = (raw & ~(0xffffffff << field.raw_lo)) | (int(corrected["data"]) << field.raw_lo)
        return raw

    def project_records(self, raw_values):
        values = tuple(raw_values)
        if self.candidate_program is not None:
            return self._project_declared_program(values)
        if self.image_plan is not None:
            for name in ("init_offer", "data_offer"):
                lo = self.image_plan.segment(name).raw_lo
                if sum((raw >> lo) & 1 for raw in values) > 1:
                    raise SocBuildError("multiple-image-candidates-unsupported")
        projected = [self.project(raw) for raw in values]
        self._validate_peer_spacing(projected)
        if self.image_plan is not None:
            image_width = self.image_plan.raw_width
            self.image_plan.materialize_many(
                [raw & ((1 << image_width) - 1) for raw in projected])
        return projected

    def _validate_peer_spacing(self, values):
        """Decode peer events and reject requests closer than the model accepts."""
        if not self.peer_slots:
            self.last_peer_events = ()
            return
        try:
            self.last_peer_events = decode_peer_raw_events(
                values, self.layout, self.peer_slots, validate_spacing=True)
        except PeerRawReplayError as error:
            raise SocBuildError(str(error)) from error

    def _project_declared_program(self, values):
        """Place a whole test through the plan's declared candidate program.

        The declaration is the plan's; the repairer is the lifetime of one test,
        so a raw word may not change a slot the test already committed.  Every
        repair, dependency edge and bounded unknown is recorded and the counters
        are folded into this projector's own repair counts.
        """
        from myfuzz.composition.soc_candidate_program import CandidateProgramError
        try:
            repaired = self.candidate_program.repairer().repair_test(values)
        except CandidateProgramError as error:
            # A refusal is a named capability gap of the declared program, so it
            # reaches the caller as a build error with the exact reason.
            raise SocBuildError(str(error)) from error
        for name, value in repaired.counters.items():
            if type(value) is int:
                self.repair_counts[name] = self.repair_counts.get(name, 0) + value
        self.last_repaired_test = repaired
        request = list(repaired.request)
        self._validate_peer_spacing(request)
        return request


def _write_candidate_program_image(directory: Path, program) -> Path:
    """Stage the declared candidate program's static image as a `$readmemh` file.

    It is written beside the (not yet created) build directory and copied into it
    as ``boot_image.hex`` like any other fixed image, so the cache key and the
    published artifact see the same file.
    """
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "candidate_program.hex"
    path.write_text("".join(f"{byte:02x}\n" for byte in program.static_image()),
                    encoding="utf-8")
    return path


def _build_profile_campaign_artifact(config, build_dir):
    """Compose profile RTL and publish the same protocol-2 artifact as the matrix path."""
    from myfuzz.composition.soc_composition import build_composition, composition_document
    from myfuzz.composition.soc_profile_renderer import render_composition, source_list
    from myfuzz.composition.input_constraints import compile_input_constraints, input_constraint_document
    from myfuzz.composition.soc_image import build_image_plan, combined_input_layout
    from myfuzz.composition.soc_candidate_program import (
        CandidateProgramError, CandidateProgramPolicy, build_candidate_program)

    root = Path(config.get("root") or ROOT).resolve()
    request = load_profile_campaign_request(config, root)
    build = Path(build_dir).absolute()
    if build.exists() or build.is_symlink():
        raise SocBuildError("campaign build directory must be new")
    try:
        injected_env = config.get("environment")
        if injected_env is not None and not isinstance(injected_env, Mapping):
            raise ValueError("rfuzz-verilator-environment-invalid")
        toolchain = resolve_rfuzz_verilator_toolchain(
            root, config, environment=(None if injected_env is None else dict(injected_env)))
    except RfuzzToolchainError as error:
        raise SocBuildError(str(error)) from error
    except (OSError, TypeError, ValueError) as error:
        raise SocBuildError(f"rfuzz-verilator-unavailable: {error}") from error
    tool_identity = dict(toolchain["verilator"])
    tool = str(tool_identity["path"])
    tool_version = str(tool_identity["version"])
    tool_env = dict(toolchain["environment"])
    drive_profile = str(config.get("drive_profile", "cpu_execute"))
    plan = build_composition(request, base_dir=root, drive_profile=drive_profile)
    policy = compile_input_constraints(plan, drive_profile=drive_profile)
    instruction_candidates = config.get("instruction_candidates", 1)
    data_candidates = config.get("data_candidates", 1)
    for value, label in ((instruction_candidates, "instruction_candidates"),
                         (data_candidates, "data_candidates")):
        if type(value) is not int or isinstance(value, bool) or value < 1:
            raise SocBuildError("profile-candidate-count-invalid:" + label)
    candidate_program = None
    candidate_image = build_image_plan(
        plan, instruction_candidates=instruction_candidates,
        data_candidates=data_candidates)
    if instruction_candidates > 1 or data_candidates > 1:
        # Several candidates per test only mean something inside a declared
        # program: the plan's own slot addresses, the generated prologue and the
        # dependency policy are what a test composes.
        try:
            candidate_program = build_candidate_program(
                plan, instruction_candidates=instruction_candidates,
                data_candidates=data_candidates,
                policy=CandidateProgramPolicy(**dict(config.get("candidate_policy") or {})),
                # The record this program will be projected from is the combined
                # ABI, which is wider than the image segment whenever the
                # composition appends a peer's request fields or a synthetic
                # master's stimulus.  Without this the program refuses a legal
                # record that carries those bits.
                raw_width=int(_provisional_record_width(plan, candidate_image)))
        except CandidateProgramError as error:
            raise SocBuildError(str(error)) from error
        image = candidate_program.image
    else:
        image = build_image_plan(plan)
    address_policy = config.get("image_address_policy", "repair")
    if address_policy not in ("repair", "strict"):
        raise SocBuildError("profile-image-address-policy-invalid")
    image_targets = {}
    for kind, base, size in (("instruction", image.base, image.size),
                             ("data", image.data_base, image.data_size)):
        matches = [int(target["index"]) for target in plan.plan["fabric"]["targets"]
                   if target.get("backing_kind") == "memory"
                   for row in plan.plan["fabric"]["decode"]["windows"]
                   if int(row["target_index"]) == int(target["index"])
                   and int(row["base"]) == base and int(row["size"]) == size]
        if len(matches) != 1:
            raise SocBuildError("profile-image-memory-target-ambiguous:" + kind)
        image_targets[kind] = (matches[0], base, size)
    rendered = render_composition(plan)
    top_name, top_module = "myfuzz_soc_top.sv", "myfuzz_soc_top"
    # The generated profile header uses numeric widths, but the shared parser
    # still requires the legacy parameter document for symbolic expressions.
    rendered["soc_parameters.json"] = json.dumps(plan.plan["fabric"]["rtl"]["parameters"])
    ports = _parse_ports(rendered[top_name], rendered, request.request_id)
    special_width = int(plan.raw_layout["raw_width"])
    layout = combined_input_layout(plan, image)
    peer_slots = _peer_projection_slots(plan, layout, base_dir=root)
    fields = layout.fields
    transport = build_rfuzz_transport(layout)
    driven = {field.port for field in fields if field.port}
    required = {p["name"]: p["width"] for p in ports
                if p["direction"] == "input" and p["name"] not in driven | {"clk_i", "rst_ni"}}
    defaults = config.get("external_input_defaults", {})
    if not isinstance(defaults, Mapping) or set(defaults) != set(required):
        raise SocBuildError("profile-external-defaults-required:" + ",".join(sorted(required)))
    for name, width in required.items():
        if type(defaults[name]) is not int or not 0 <= defaults[name] < 1 << width:
            raise SocBuildError("profile-external-default-invalid:" + name)
    if candidate_program is not None:
        # The fixed image is the declared program's static part (entry trampoline
        # plus generated prologue); a test overlays its slots on top of it.  An
        # explicit boot_image that disagrees is refused rather than preferred.
        generated = _write_candidate_program_image(build.parent, candidate_program)
        declared = config.get("boot_image")
        if declared is not None:
            declared_path = Path(declared)
            declared_path = declared_path if declared_path.is_absolute() \
                else root / declared_path
            if not declared_path.is_file():
                raise SocBuildError("profile-boot-image-missing")
            if _file_hash(declared_path) != _file_hash(generated):
                raise SocBuildError(
                    "profile-boot-image-does-not-match-candidate-program:"
                    + _file_hash(declared_path) + "!=" + _file_hash(generated))
        boot = generated
    else:
        boot = config.get("boot_image")
        if boot is None:
            raise SocBuildError("profile-boot-image-required: fixed image must be explicit")
        boot = Path(boot)
        boot = boot if boot.is_absolute() else root / boot
        if not boot.is_file():
            raise SocBuildError("profile-boot-image-missing")
    records = source_list(plan)
    closure = {"source_files": [], "include_dirs": [], "defines": []}
    for item in records:
        path = (root / item["path"]).resolve()
        if not path.is_relative_to(root):
            raise SocBuildError("profile-source-outside-root-unsupported:" + str(path))
        key = "include_dirs" if item["role"] == "include_root" else "source_files"
        relative = str(path.relative_to(root))
        if relative not in closure[key]:
            closure[key].append(relative)
    for instance in plan.instances:
        options = instance.profile.source.elaboration
        if options is not None:
            for name, value in options.defines:
                define = f"{name}={value}"
                if define not in closure["defines"]:
                    closure["defines"].append(define)
    instrumenter_identity = _coverage_instrumenter_identity()
    # Instrumentation is cheap compared with compiling Verilator and produces
    # the output digest used by the cache identity. Generate it in an owned
    # temporary tree before deciding whether the compiled artifact is reusable.
    instrumentation_stage = tempfile.TemporaryDirectory(
        prefix="myfuzz-soc-instrumentation-")
    instrumentation_stage_root = Path(instrumentation_stage.name).resolve()
    cpu = next(instance for instance in plan.instances if instance.kind == "cpu")
    instrumentation = _instrument_coverage(
        instrumentation_stage_root, root, request.request_id, closure, rendered,
        top_name, top_module,
        {"peripherals": {i.instance_id: {} for i in plan.instances
                          if i.kind != "cpu"}},
        cpu_instance="u_" + cpu.instance_id,
        instrumenter_identity=instrumenter_identity)

    # A profile build is expensive (coverage instrumentation plus Verilator),
    # while a new RFuzz sample must never invalidate the RTL artifact.  The
    # optional cache is content-addressed by the complete generated ABI and
    # source closure.  It is deliberately opt-in so existing callers that
    # expect a private build directory retain their old behaviour.
    cache_root = toolchain.get("build_cache_dir")
    cache_entry = None
    cache_key = ""
    if cache_root is not None:
        if not isinstance(cache_root, (str, Path)):
            raise SocBuildError("profile-build-cache-dir-invalid")
        cache_root = Path(cache_root)
        cache_root = cache_root if cache_root.is_absolute() else root / cache_root
        cache_root = cache_root.resolve()
        if cache_root == build or build.is_relative_to(cache_root) \
                or cache_root.is_relative_to(build):
            raise SocBuildError("profile-build-cache-overlaps-build-directory")
        cache_key = _profile_build_cache_key({
            "schema_version": "soc_profile_build_cache.v1",
            "generator_schema": BUILD_SCHEMA,
            "composition_hash": plan.plan_hash,
            "layout_hash": layout.layout_hash,
            "policy_hash": policy.policy_hash,
            "image_hash": image.image_hash,
            "candidate_program_hash": (None if candidate_program is None else
                                       content_hash(candidate_program.document())),
            "image_address_policy": address_policy,
            "boot_image": _file_hash(boot),
            "external_input_defaults": dict(defaults),
            "closure": closure,
            "verilator": tool_identity,
        }, instrumenter_identity, instrumentation["instrumented_output_sha256"])
        cache_entry = cache_root / cache_key
        cached_provenance = cache_entry / "artifact_provenance.json"
        if (cache_entry.is_dir() and not cache_entry.is_symlink()
                and cached_provenance.is_file()):
            try:
                cached_document = _read_json(cached_provenance, "cached-artifact-provenance")
                cached_audit = _read_json(
                    cache_entry / "soc_structure_audit.json", "cached-structure-audit")
                cached_ports = tuple(
                    (str(item[0]), int(item[1]))
                    for item in cached_document.get("coverage_ports", [])
                    if isinstance(item, (list, tuple)) and len(item) == 2)
                valid_cache = (
                    cached_document.get("composition_hash") == plan.plan_hash
                    and cached_document.get("layout_hash") == layout.layout_hash
                    and cached_document.get("policy_hash") == policy.policy_hash
                    and cached_document.get("image_hash") == image.image_hash
                    and cached_document.get("tool_identity") == tool_identity
                    and _cached_instrumentation_matches(
                        cache_entry, cached_document, instrumenter_identity)
                    and cached_ports
                    and isinstance(cached_document.get("structure_audit"), Mapping)
                    and cached_document["structure_audit"].get("status") == "pass"
                    and isinstance(cached_audit.get("summary"), Mapping)
                    and cached_audit["summary"].get("status") == "pass"
                    and cached_document["structure_audit"].get("hash")
                        == content_hash(cached_audit)
                    and (cache_entry / "obj_dir" / "Vmyfuzz_live_tb").is_file())
            except (OSError, TypeError, ValueError, KeyError, SocBuildError):
                valid_cache = False
            if valid_cache:
                shutil.copytree(cache_entry, build)
                if not _cached_instrumentation_matches(
                        build, cached_document, instrumenter_identity):
                    raise SocBuildError("profile-build-cache-copy-instrumentation-drift")
                executable = build / "obj_dir" / "Vmyfuzz_live_tb"
                simulator_args = (f"+riscv_boot_image={build / 'boot_image.hex'}",)
                if _file_hash(executable) != cached_document.get("executable_sha256"):
                    raise SocBuildError("profile-build-cache-executable-drift")
                _probe_executable(executable, simulator_args, request.request_id)
                cached_coverage = (cached_document.get("coverage_instrumentation")
                                   or cached_document.get("coverage"))
                if isinstance(cached_coverage, dict):
                    old_root = cached_coverage.get(
                        "instrumented_root",
                        (cached_document.get("sources") or {}).get("instrumented_root"))
                    if not isinstance(old_root, str) or not old_root:
                        raise SocBuildError(
                            "profile-build-cache-instrumented-root-missing")
                    old_build_root = Path(old_root).parent.parent
                    new_build_root = build.resolve()
                    for relative in (
                            Path("instrumentation/instrumented/instrumented_sources.f"),
                            Path("instrumentation/instrumented/instrumentation.json")):
                        path = build / relative
                        if path.is_file():
                            payload = path.read_bytes().replace(
                                old_build_root.as_posix().encode("utf-8"),
                                new_build_root.as_posix().encode("utf-8"))
                            path.write_bytes(payload)
                    from scripts.source_branch_instrumenter import validate_closed_flist
                    instrumented_root = build / "instrumentation/instrumented"
                    instrumented_flist = instrumented_root / "instrumented_sources.f"
                    validate_closed_flist(
                        instrumented_flist.read_text(encoding="utf-8").splitlines(),
                        instrumented_root)
                    if _instrumented_output_sha256(
                            instrumented_root, instrumented_flist) != \
                            cached_coverage.get("instrumented_output_sha256"):
                        raise SocBuildError(
                            "profile-build-cache-relocated-instrumentation-drift")
                cached_document["cache_hit"] = True
                cached_document["cache_key"] = cache_key
                cached_document["cache_source"] = str(cache_entry)
                cached_document["peer_event_mode"] = (
                    "raw-abi-derived-v1" if peer_slots else None)
                cached_document["peer_event_slots"] = [dict(item) for item in peer_slots]
                if isinstance(cached_document.get("sources"), dict):
                    cached_document["sources"]["instrumented_root"] = str(
                        build / "instrumentation/instrumented")
                    cached_document["sources"]["instrumented_flist"] = str(
                        build / "instrumentation/instrumented/instrumented_sources.f")
                cached_coverage = (cached_document.get("coverage_instrumentation")
                                   or cached_document.get("coverage"))
                if isinstance(cached_coverage, dict):
                    cached_coverage["instrumented_root"] = str(
                        build / "instrumentation/instrumented")
                    cached_coverage["instrumented_flist"] = str(
                        build / "instrumentation/instrumented/instrumented_sources.f")
                cached_document["build_hash"] = content_hash(cached_document)
                (build / "artifact_provenance.json").write_bytes(
                    canonical_bytes(cached_document))
                constraint_hash = str(cached_document["constraint_hash"])
                arms = build_projection_arms(
                    layout=layout, constraint_hash=constraint_hash,
                    special_width=special_width, policy=policy, image=image,
                    image_address_policy=address_policy,
                    candidate_program=candidate_program,
                    peer_slots=peer_slots)
                instrumentation_stage.cleanup()
                return SocCampaignArtifact(
                    # The monitor is part of the published artifact, not of the
                    # compile: a cache hit has to carry the same transaction
                    # evidence a fresh build would, or a cached campaign would
                    # silently report fewer facts than an uncached one.
                    execution_monitor=dict(PROFILE_FABRIC_MONITOR),
                    layout=layout, transport=transport, executable=executable,
                    coverage_ports=cached_ports, projector=arms["dependency_repair"],
                    coverage_kind=COVERAGE_KIND,
                    simulator="verilator", simulator_args=simulator_args,
                    isolate_tests=True, build_document=cached_document,
                    projection_arms=arms, peer_slots=peer_slots)
    # Re-elaborate the generated top before compiling it.  This is deliberately
    # independent of the renderer bookkeeping: the audit reads the published
    # source closure and verifies the actual netlist against the plan.  A
    # structural failure is a build failure, never a later DUT anomaly.
    from myfuzz.composition.soc_structure_audit import audit_structure
    audit_sources = [str(item["path"]) for item in records
                     if item.get("role") != "include_root"]
    audit_include_roots = [str(item["path"]) for item in records
                           if item.get("role") == "include_root"]
    try:
        structure_audit = audit_structure(
            plan, top_text=rendered[top_name], source_files=audit_sources,
            base_dir=root, include_roots=audit_include_roots)
    except Exception as error:
        raise SocBuildError(f"profile-structure-audit-failed: {error}") from error
    summary = structure_audit.get("summary")
    if not isinstance(summary, Mapping) or summary.get("status") != "pass":
        raise SocBuildError("profile-structure-audit-failed: generated netlist does not match plan")

    build.mkdir(parents=True)
    for name, text in rendered.items():
        (build / name).write_text(text, encoding="utf-8")
    shutil.copyfile(boot, build / "boot_image.hex")
    simulator_args = (f"+riscv_boot_image={build / 'boot_image.hex'}",)
    staged_instrumentation_dir = instrumentation_stage_root / "instrumentation"
    final_instrumentation_dir = build / "instrumentation"
    shutil.copytree(staged_instrumentation_dir, final_instrumentation_dir)
    final_root = (final_instrumentation_dir / "instrumented").resolve()
    for relative in (Path("instrumented/instrumented_sources.f"),
                     Path("instrumented/instrumentation.json")):
        path = final_instrumentation_dir / relative
        if path.is_file():
            payload = path.read_bytes().replace(
                instrumentation_stage_root.as_posix().encode("utf-8"),
                build.resolve().as_posix().encode("utf-8"))
            path.write_bytes(payload)
    instrumentation = dict(instrumentation)
    instrumentation["instrumented_root"] = str(final_root)
    instrumentation["flist"] = str(final_root / "instrumented_sources.f")
    relocated_output_sha256 = _instrumented_output_sha256(
        final_root, instrumentation["flist"])
    if relocated_output_sha256 != instrumentation["instrumented_output_sha256"]:
        raise SocBuildError("profile-instrumented-output-changed-during-relocation")
    instrumentation_stage.cleanup()
    coverage_ports = tuple((COVERAGE_SIGNAL, int(item["bit"]))
                           for item in instrumentation["plan"]["observed"])
    (build / "rfuzz_input_transport.sv").write_text(transport.render_systemverilog())
    (build / "live_tb.sv").write_text(_testbench(
        layout, {"unmapped": [field.field_id for field in fields if not field.port]},
        ports, top_module, coverage_ports,
        coverage_width=instrumentation["vector_width"], input_defaults=defaults,
        image_plan=image, image_targets=image_targets,
        execution_monitor=dict(PROFILE_FABRIC_MONITOR)))
    documents = {"soc_composition.json": composition_document(plan),
                 **({} if candidate_program is None else {
                     "candidate_program.json": candidate_program.document()}),
                 "input_layout.json": input_layout_document(layout),
                 "input_policy.json": input_constraint_document(policy),
                 "image_plan.json": image.document(),
                 "rfuzz_input_transport.json": transport.document(),
                 "soc_structure_audit.json": structure_audit,
                 "soc_coverage_universe.json": instrumentation["universe"],
                 "soc_coverage_plan.json": instrumentation["plan"]}
    for name, value in documents.items():
        (build / name).write_bytes(canonical_bytes(value))
    command = _compile_command(tool, build, closure, root, top_name,
                               flist=instrumentation["flist"])
    result = run_supervised_command(CampaignOptions(
        command=command, output_dir=build / "build", duration_seconds=BUILD_TIMEOUT_SECONDS,
        checkpoint_seconds=1, limits=BUILD_MEMORY_LIMITS,
        env={**tool_env, "JOBS": "1", "MAKEFLAGS": "-j1"}))
    if result.get("status") != "completed" or result.get("returncode") != 0:
        raise SocBuildError(f"profile-verilator-build-failed: see {build / 'compiler.log'}")
    executable = build / "obj_dir" / "Vmyfuzz_live_tb"
    _probe_executable(executable, simulator_args, request.request_id)
    constraint_hash = content_hash({"policy_hash": policy.policy_hash,
                                    "layout_hash": layout.layout_hash,
                                    "image_plan_hash": image.image_hash,
                                    "image_address_policy": address_policy,
                                    "fixed_image": _file_hash(build / "boot_image.hex"),
                                    "external_defaults": dict(defaults)})
    # A declared candidate program really places several image candidates per
    # test and really repairs their declared dependencies, so those two
    # capability gaps close exactly when the plan declares one; the legacy
    # single-candidate path keeps both declared as gaps.
    unsupported = ["multi_candidate_images", "compressed_instruction_images",
                   "external_protocol_peers", "general_dependency_repair"]
    if plan.peers:
        # Peer request fields are now part of the combined layout and are wired
        # by the persistent harness through the same raw word. Event-plan
        # validation/replay remains a separate runtime capability, but the
        # generated profile artifact no longer drops peer requests at idle.
        unsupported.remove("external_protocol_peers")
    if candidate_program is not None:
        unsupported = [name for name in unsupported
                       if name not in ("multi_candidate_images",
                                       "general_dependency_repair")]
    if not plan.synthetic:
        unsupported += ["bfm_isolated", "contention"]
    document = {"schema_version": BUILD_SCHEMA, "composition_hash": plan.plan_hash,
                "layout_hash": layout.layout_hash, "policy_hash": policy.policy_hash,
                "constraint_hash": constraint_hash,
                "policy_scope": "finite special-input projection; generated RTL temporal drivers; single instruction ISA repair and bounded data initialization",
                "candidate_program": (None if candidate_program is None else {
                    "schema_version": "soc_candidate_program.v1",
                    "instruction_candidates": candidate_program.slots.instruction_count,
                    "data_candidates": candidate_program.slots.data_count,
                    "program_base": candidate_program.program_base,
                    "program_size": candidate_program.program_size,
                    "prologue_words": len(candidate_program.prologue_words),
                    "register_bindings": {
                        name: int(binding["value"]) for name, binding
                        in candidate_program.register_bindings.items()},
                    "policy": candidate_program.policy.document(),
                    "document_hash": content_hash(candidate_program.document()),
                    "image_loading": "each declared slot is overlaid into the memory "
                                     "model's initial_memory while the CPU is held in "
                                     "reset; the static image carries the entry trampoline "
                                     "and the generated prologue",
                }),
                "image_loading": "buffer test records; overlay environment initial_memory; reset copies test-local image to memory before CPU release; process isolation restores fixed base between tests; no runtime image writes",
                "image_address_policy": address_policy,
                "image_address_repair": "deterministic declared-window word-slot mapping; projector.repair_counts[address_repair]",
                "image_hash": image.image_hash, "drive_profile": drive_profile,
                "mode": str(plan.stimulus.get("mode", "cpu_only")),
                "synthetic_master": (dict(plan.synthetic) if plan.synthetic else None),
                "peer_inputs": [
                    {"field_id": field.field_id, "port": field.port,
                     "width": field.width, "raw_lo": field.raw_lo,
                     "raw_hi": field.raw_hi, "role": field.role,
                     "minimum_gap_cycles": (
                         field.provenance.get("minimum_gap_cycles")
                         if isinstance(field.provenance, Mapping) else None)}
                    for field in fields if field.owner == "soc_peer"],
                "peer_input_mode": ("per-cycle-raw-fields" if plan.peers else None),
                "peer_event_mode": ("raw-abi-derived-v1" if plan.peers else None),
                "peer_event_slots": [dict(item) for item in peer_slots],
                "coverage_kind": COVERAGE_KIND,
                "coverage_instrumentation": {
                    "instrumenter": instrumentation["instrumenter_identity"],
                    "instrumented_output_sha256": (
                        instrumentation["instrumented_output_sha256"]),
                    "instrumented_root": instrumentation["instrumented_root"],
                    "instrumented_flist": instrumentation["flist"],
                },
                "structure_audit": {
                    "schema_version": structure_audit.get("schema_version"),
                    "status": summary["status"],
                    "summary": dict(summary),
                    "document": "soc_structure_audit.json",
                    "hash": content_hash(structure_audit),
                },
                "external_input_defaults": dict(defaults),
                "sources": {
                    "runtime_top": top_name,
                    "harness_top": "myfuzz_live_tb",
                    "defines": list(closure["defines"]),
                    "include_dirs": list(closure["include_dirs"]),
                    "source_count": len(closure["source_files"]),
                    "source_files": [
                        {"path": item, "sha256": _file_hash(root / item)}
                        for item in closure["source_files"]
                    ],
                },
                "unsupported_capabilities": unsupported,
                "boot_image_sha256": _file_hash(build / "boot_image.hex"),
                "test_isolation": "restart process: source instrumentation contains sticky branch hits",
                "executable_sha256": _file_hash(executable),
                "tool": {"simulator_protocol_version": SIMULATOR_PROTOCOL_VERSION,
                         "verilator": tool_version},
                "tool_identity": tool_identity,
                "coverage_ports": [[name, bit] for name, bit in coverage_ports],
                "cache_hit": False,
                "cache_key": cache_key}
    document["build_hash"] = content_hash(document)
    (build / "artifact_provenance.json").write_bytes(canonical_bytes(document))
    if cache_entry is not None:
        cache_entry.parent.mkdir(parents=True, exist_ok=True)
        if not cache_entry.exists():
            shutil.copytree(build, cache_entry)
    arms = build_projection_arms(
        layout=layout, constraint_hash=constraint_hash, special_width=special_width,
        policy=policy, image=image, image_address_policy=address_policy,
        candidate_program=candidate_program,
        peer_slots=peer_slots)
    return SocCampaignArtifact(
        execution_monitor=dict(PROFILE_FABRIC_MONITOR),
        layout=layout, transport=transport, executable=executable,
        coverage_ports=coverage_ports, projector=arms["dependency_repair"],
        coverage_kind=COVERAGE_KIND, simulator="verilator", simulator_args=simulator_args,
        isolate_tests=True, build_document=document, projection_arms=arms,
        peer_slots=peer_slots)


def build_soc_campaign_artifact(config, build_dir):
    """Render, generate the RFuzz transport and compile one real SoC cell.

    'config' is the campaign task config; 'build_dir' must be a new directory.
    The returned artifact is a :class:'SimulatorArtifact' subclass carrying the
    full 'soc_campaign_build.v1' provenance document.
    """
    config = _require_mapping(config, "config")
    if "composition_request" in config:
        return _build_profile_campaign_artifact(config, build_dir)
    build = Path(build_dir).absolute()
    if build.exists() or build.is_symlink():
        raise SocBuildError("campaign build directory must be new")
    root = Path(config.get("root") or ROOT).resolve()
    mode = _mode(config)
    seed = config.get("seed", 0)
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise SocBuildError("campaign seed must be a nonnegative integer")
    bias_off = config.get("bias_off") is True

    try:
        requested_verilator = config.get("verilator", "bundled")
        verilator = (resolve_rfuzz_verilator(root)
                     if requested_verilator == "bundled" else str(Path(requested_verilator)))
        validate_rfuzz_verilator_version(_tool_version(verilator))
    except (OSError, ValueError, TypeError) as error:
        raise SocBuildError(f"rfuzz-verilator-unavailable: {error}") from error

    cell_path, cell = _cell_config(config, root, build)
    cell_id = str(cell.get("cell_id") or config.get("cell_id") or config.get("config_id"))
    cpu = _cpu_facts(cell, cell_id)
    records = _peripheral_records(cell, root)

    spec = _cell_spec(cell, cpu, records, cell_id, cell_path, root)
    execution = _processor_execution(cpu, cell_id)
    contracts = _target_contracts(cell, records, cpu, cell_id)
    plan = build_soc_plan(spec, execution, contracts)
    stimulus = compile_soc_stimulus(
        plan, {"mode": mode, "address_strategy": "bias_off" if bias_off else "biased"})

    rendered = render_soc(plan, stimulus)
    if not isinstance(rendered, Mapping) or "soc_top.sv" not in rendered:
        raise SocBuildError("%s: renderer did not produce soc_top.sv" % cell_id)
    build.mkdir(parents=True, exist_ok=False)
    rendered_records = []
    for name in sorted(rendered):
        if (not isinstance(name, str) or not name or "/" in name or "\\" in name
                or name.startswith(".")):
            raise SocBuildError("%s:unsafe-rendered-filename:%r" % (cell_id, name))
        text = rendered[name]
        if not isinstance(text, str):
            raise SocBuildError("%s:rendered-file-not-text:%s" % (cell_id, name))
        payload = text.encode("utf-8")
        (build / name).write_bytes(payload)
        rendered_records.append({"file": name, "sha256": _hash_bytes(payload),
                                 "bytes": len(payload)})

    manifest = _read_json(build / "soc_manifest.json", "%s:manifest" % cell_id)
    modules = _rendered_modules(rendered)
    top_module, top_name = _top_module(manifest, modules, cell_id)
    ports = _parse_ports(rendered[top_name], rendered, cell_id)
    rendered_boot_address = _rendered_boot_address(rendered[top_name])

    layout, mapping = _input_layout(stimulus, ports, cell_id)
    transport = build_rfuzz_transport(layout)
    (build / "rfuzz_input_transport.json").write_bytes(
        canonical_bytes(transport.document()))
    (build / "rfuzz_input_transport.sv").write_text(
        transport.render_systemverilog(), encoding="utf-8")
    (build / "input_layout.json").write_bytes(
        canonical_bytes(input_layout_document(layout)))

    source_closure = _source_closure(manifest, root, cell_id)
    instrumentation = _instrument_coverage(
        build, root, cell_id, source_closure, rendered, top_name, top_module, manifest)
    coverage_ports = tuple(
        (COVERAGE_SIGNAL, int(item["bit"]))
        for item in instrumentation["plan"]["observed"])
    simulator_args = ()
    boot_document = None
    preloaded = [region for region in plan["address_map"]["memory_regions"]
                 if str(region.get("initialization_policy", "")) in {"preload", "rom"}]
    source_requires_image = _sources_require_boot_image(source_closure, root)
    if source_requires_image and not preloaded:
        raise SocBuildError(
            "%s: compiled harness preloads a memory image the plan does not declare"
            % cell_id)
    if preloaded:
        reset_vector = int(cpu.get("reset_vector", 0))
        if rendered_boot_address is not None and rendered_boot_address != reset_vector:
            raise SocBuildError(
                "%s: rendered harness boots at 0x%x but the cell config declares "
                "0x%x; the render config and the plan disagree, so no boot image "
                "can be placed safely" % (cell_id, rendered_boot_address, reset_vector))
        boot_document, simulator_args = _boot_image(
            build, plan, cell, cell_path, cpu, cell_id, mode, config, stimulus,
            preloaded)

    (build / "live_tb.sv").write_text(
        _testbench(layout, mapping, ports, top_module, coverage_ports,
                   coverage_width=instrumentation["vector_width"]),
        encoding="utf-8")
    (build / "soc_coverage_universe.json").write_bytes(
        canonical_bytes(instrumentation["universe"]))
    (build / "soc_coverage_plan.json").write_bytes(
        canonical_bytes(instrumentation["plan"]))

    command = _compile_command(verilator, build, source_closure, root, top_name,
                               flist=instrumentation["flist"])
    result = run_supervised_command(CampaignOptions(
        command=command, output_dir=build / "build",
        duration_seconds=BUILD_TIMEOUT_SECONDS, checkpoint_seconds=1,
        limits=BUILD_MEMORY_LIMITS,
        env={"JOBS": "1", "MAKEFLAGS": "-j1"}))
    log_path = build / "compiler.log"
    if result.get("status") != "completed" or result.get("returncode") != 0:
        raise SocBuildError(
            "%s:verilator-build-failed:status=%s:rc=%s: see %s"
            % (cell_id, result.get("status"), result.get("returncode"), log_path))
    executable = build / "obj_dir" / "Vmyfuzz_live_tb"
    if not executable.is_file():
        raise SocBuildError("%s:verilator-did-not-emit:%s" % (cell_id, executable))
    _probe_executable(executable, simulator_args, cell_id)

    constraint_hash = content_hash({
        "schema_version": "soc_campaign_constraints.v1",
        "cell_id": cell_id,
        "mode": mode,
        "bias_off": bias_off,
        "layout_hash": layout.layout_hash,
        "plan_hash": stimulus["plan_hash"],
    })
    coverage_kind = COVERAGE_KIND
    document = {
        "schema_version": BUILD_SCHEMA,
        "cell_id": cell_id,
        "config_id": str(config.get("config_id") or cell_id),
        "mode": mode,
        "seed": seed,
        "bias_off": bias_off,
        "root": str(root),
        "render_config": str(cell_path),
        "plan_hash": stimulus["plan_hash"],
        "stimulus": {
            "schema_version": stimulus.get("schema_version"),
            "mode": stimulus.get("mode"),
            "layout_hash": layout.layout_hash,
            "raw_width": layout.raw_width,
            "total_bits": int(stimulus["raw_layout"]["total_bits"]),
            "masked_segments": list(
                stimulus.get("mode_masking", {}).get("masked_segments", [])),
        },
        "render_hash": (manifest.get("render_hash")
                        if isinstance(manifest, Mapping) else None),
        "rendered_files": rendered_records,
        "input_layout": {
            "raw_width": layout.raw_width,
            "layout_hash": layout.layout_hash,
            "fields": len(layout.fields),
            "mapped_fields": sorted(mapping["mapped"]),
            "unmapped_fields": sorted(mapping["unmapped"]),
            "port_bindings": dict(sorted(mapping["bindings"].items())),
            "unmapped_reason": (
                "the rendered harness exposes no compatible input port for these "
                "declared raw fields; the bits stay part of the ABI and are recorded "
                "here instead of being silently re-mapped"),
        },
        "transport": transport.document(),
        "coverage": {
            "kind": coverage_kind,
            "transport": "sysv-shared-memory-rfuzz-coverage-buffer",
            "instrumenter": instrumentation["instrumenter_identity"],
            "instrumented_output_sha256": instrumentation["instrumented_output_sha256"],
            "instrumented_root": instrumentation["instrumented_root"],
            "instrumented_flist": instrumentation["flist"],
            "counter_count": len(coverage_ports),
            "observations": [list(item) for item in coverage_ports],
            "signal": COVERAGE_SIGNAL,
            "vector_width": instrumentation["vector_width"],
            "branch_point_count": instrumentation["point_count"],
            "universe_hash": instrumentation["universe"]["universe_hash"],
            "universe_categories": {
                name: len(ids) for name, ids in
                instrumentation["universe"]["categories"].items()},
            "observed_by_category": instrumentation["plan"]["observed_by_category"],
            "unobserved_branch_points": instrumentation["plan"]["unobserved_count"],
            "universe_document": "soc_coverage_universe.json",
            "observation_plan": "soc_coverage_plan.json",
        },
        "sources": {
            "runtime_top": source_closure["runtime_top"],
            "harness_top": top_module,
            "defines": list(source_closure["defines"]),
            "include_dirs": list(source_closure["include_dirs"]),
            "source_count": len(source_closure["source_files"]),
            "instrumented_flist": instrumentation["flist"],
            "instrumented_flist_sha256": _file_hash(Path(instrumentation["flist"])),
            "instrumented_root": instrumentation["instrumented_root"],
            "source_files": [{"path": item, "sha256": _file_hash(root / item)}
                             for item in source_closure["source_files"]],
        },
        "peripherals": [{
            "id": record["id"],
            "source_lock": record["source_lock"],
            "top_module": record["top_module"],
            "protocol": list(record["protocol"]),
            "window": dict(record["window"]),
            "closure": record["closure"],
            "capabilities": dict(record["capabilities"]),
            "spot_check": record["spot_check"],
            "unverified_evidence_topics": list(record["unverified_evidence_topics"]),
        } for record in records],
        "boot_image": boot_document,
        "executable": {"path": str(executable), "sha256": _file_hash(executable)},
        "constraint_hash": constraint_hash,
        "tool": {
            "verilator": _tool_version(verilator),
            "verilator_path": verilator,
            "simulator_protocol_version": SIMULATOR_PROTOCOL_VERSION,
            "max_cycles_per_test": MAX_CYCLES,
        },
        "build_command": list(command),
        "test_isolation": "restart process: source instrumentation contains sticky branch hits",
        "policy": (
            "fail-closed: no behavioural CPU/peripheral fallback; the artifact is "
            "returned only after Verilator produced the executable and the protocol "
            "probe accepted it"),
    }
    document["build_hash"] = content_hash(document)
    (build / "artifact_provenance.json").write_bytes(canonical_bytes(document))
    return SocCampaignArtifact(
        layout=layout,
        transport=transport,
        executable=executable,
        coverage_ports=coverage_ports,
        projector=SocRawProjector(layout, constraint_hash),
        coverage_kind=coverage_kind,
        control_defaults={"mode": mode, "bias_off": bias_off},
        randomized_controls=(),
        simulator_args=simulator_args,
        simulator="verilator",
        isolate_tests=True,
        execution_monitor=None,
        build_document=document,
        rendered_files=tuple((item["file"], item["sha256"]) for item in rendered_records),
    )


def _rendered_boot_address(top_text):
    """The literal BOOT_ADDR the rendered harness passes to the CPU core."""
    match = re.search(r"\.BOOT_ADDR\(\s*[0-9]+'h([0-9a-fA-F]+)\s*\)", top_text)
    return int(match.group(1), 16) if match else None


def _rendered_modules(rendered):
    """Map every module name defined by the rendered document to its file."""
    modules = {}
    for name in sorted(rendered):
        text = rendered[name]
        if not isinstance(text, str):
            continue
        for match in _TOP_MODULE_RE.finditer(text):
            modules.setdefault(match.group(1), name)
    return modules


def _top_module(manifest, modules, cell_id):
    elaboration = manifest.get("real_elaboration") if isinstance(manifest, Mapping) else None
    if not isinstance(elaboration, Mapping):
        raise SocBuildError(
            "%s: rendered manifest has no real_elaboration closure" % cell_id)
    for key in ("wrapper_top", "runtime_top", "harness_top"):
        name = elaboration.get(key)
        if isinstance(name, str) and name in modules:
            return name, modules[name]
    for fallback in ("myfuzz_soc_top",):
        if fallback in modules:
            return fallback, modules[fallback]
    raise SocBuildError("%s: no rendered file defines the harness top" % cell_id)


def _parse_ports(text, rendered, cell_id):
    """Parse the ANSI port list of the generated harness top."""
    match = _TOP_MODULE_RE.search(text)
    if match is None:
        raise SocBuildError("%s: harness top has no module declaration" % cell_id)
    start = text.index("(", match.end()) if "(" in text[match.end():] else -1
    if start < 0:
        raise SocBuildError("%s: harness top has no port list" % cell_id)
    end = text.find("\n);", start)
    if end < 0:
        raise SocBuildError("%s: harness top port list is not terminated" % cell_id)
    header = text[start:end]
    parameters = _render_parameters(rendered, cell_id)
    ports = []
    names = set()
    for port in _PORT_RE.finditer(header):
        direction, packed, name = port.group(1), port.group(2), port.group(3)
        if name in names:
            raise SocBuildError("%s: duplicate harness port: %s" % (cell_id, name))
        names.add(name)
        ports.append({"name": name, "direction": direction,
                      "width": _packed_width(packed, parameters, cell_id, name)})
    if not ports:
        raise SocBuildError("%s: harness top port list is empty" % cell_id)
    inouts = [port["name"] for port in ports if port["direction"] == "inout"]
    if inouts:
        raise SocBuildError("%s: inout harness ports are unsupported: %s"
                            % (cell_id, ", ".join(inouts)))
    return ports


def _render_parameters(rendered, cell_id):
    document = rendered.get("soc_parameters.json")
    if not isinstance(document, str):
        raise SocBuildError("%s: rendered soc_parameters.json is missing" % cell_id)
    try:
        values = json.loads(document)
    except ValueError as error:
        raise SocBuildError("%s: rendered soc_parameters.json is invalid" % cell_id) from error
    parameters = {}
    for key, value in values.items():
        if isinstance(value, bool) or not isinstance(value, int):
            raise SocBuildError("%s: rendered parameter %s is not an integer"
                                % (cell_id, key))
        parameters[str(key).upper()] = value
    for required in ("ADDRESS_WIDTH", "DATA_WIDTH"):
        if required not in parameters:
            raise SocBuildError("%s: rendered parameter %s is missing"
                                % (cell_id, required))
    return parameters


def _packed_width(packed, parameters, cell_id, port):
    if packed is None:
        return 1
    body = packed.strip()[1:-1].strip()
    if ":" not in body:
        raise SocBuildError("%s: unsupported packed dimension on %s: %s"
                            % (cell_id, port, packed))
    msb, _, lsb = body.rpartition(":")
    return (_width_value(msb, parameters, cell_id, port)
            - _width_value(lsb, parameters, cell_id, port) + 1)


def _width_value(expression, parameters, cell_id, port):
    substituted = expression
    for name, value in parameters.items():
        substituted = re.sub(r"\b%s\b" % re.escape(name), str(int(value)), substituted)
    if not _SAFE_WIDTH_RE.match(substituted):
        raise SocBuildError("%s: unsupported width expression on %s: %s"
                            % (cell_id, port, expression))
    # The substituted text is digits and arithmetic operators only; evaluating it
    # keeps the harness correct for parameterized generated ports.
    return int(eval(substituted, {"__builtins__": {}}, {}))  # noqa: S307


def _field_port(item, name, inputs, taken):
    """Return the harness input port a declared raw field drives, if any."""
    candidates = []
    declared = item.get("port")
    if isinstance(declared, str) and declared:
        candidates.append(declared)
    candidates.append(name)
    for candidate in candidates:
        for suffix in ("", "_i"):
            port = candidate + suffix
            if port in inputs and port not in taken:
                return port
    return None


def _input_layout(stimulus, ports, cell_id):
    """Build the input layout from the compiled 'soc_stimulus.v1' raw ABI."""
    raw_layout = stimulus.get("raw_layout")
    if not isinstance(raw_layout, Mapping):
        raise SocBuildError("%s: stimulus has no raw_layout" % cell_id)
    raw_width = raw_layout.get("total_bits")
    if isinstance(raw_width, bool) or not isinstance(raw_width, int) or raw_width <= 0:
        raise SocBuildError("%s: stimulus raw width is invalid" % cell_id)
    inputs = {port["name"] for port in ports if port["direction"] == "input"}
    taken = set()
    fields = []
    mapped, unmapped, bindings = [], [], {}
    for segment in raw_layout.get("segments", []):
        segment_id = str(segment["segment_id"])
        base_bit = int(segment["base_bit"])
        for item in segment["fields"]:
            name = str(item["name"])
            width = int(item["width"])
            raw_lo = base_bit + int(item["lsb"])
            if width <= 0 or raw_lo < 0 or raw_lo + width > raw_width:
                raise SocBuildError("%s: raw field outside the layout: %s.%s"
                                    % (cell_id, segment_id, name))
            port = None
            if not item.get("padding"):
                port = _field_port(item, name, inputs, taken)
            label = "%s.%s" % (segment_id, name)
            if port is None:
                unmapped.append(label)
            else:
                taken.add(port)
                mapped.append(label)
                bindings[label] = port
            fields.append(LayoutField(
                field_id=label,
                owner=segment_id,
                role=str(item.get("role", "data")),
                width=width,
                raw_lo=raw_lo,
                raw_hi=raw_lo + width - 1,
                encoding=str(item.get("encoding", "uint")),
                constraint={} if item.get("padding") else {"randomizable": True},
                port=port or "",
                direction="input",
                provenance={"segment_id": segment_id, "bit_offset": raw_lo},
            ))
    fields.sort(key=lambda field: field.raw_lo)
    provisional = InputLayout("input_layout.v1", raw_width, tuple(fields), "pending")
    document = input_layout_document(provisional)
    document.pop("layout_hash")
    for entry in document["fields"]:
        entry.pop("provenance", None)
    # Bare sha256 hex, matching myfuzz.composition.input_layout's own layout
    # identity convention.
    layout = replace(provisional,
                     layout_hash=hashlib.sha256(canonical_bytes(document)).hexdigest())
    return layout, {"mapped": mapped, "unmapped": unmapped, "bindings": bindings}


def _instrument_coverage(build, root, cell_id, closure, rendered, top_name,
                         top_module, manifest, *, cpu_instance="u_cpu",
                         instrumenter_identity=None):
    """Branch-instrument the cell closure and plan the observed coverage bits.

    P13 feedback has to be real RTL branch evidence.  A sampled input or output
    bit is an event, not a branch, so a closure that cannot be instrumented
    fails closed here instead of relabelling samples as branch coverage.
    """
    try:
        from scripts.source_branch_instrumenter import instrument_project
    except ImportError as error:  # pragma: no cover - packaging failure
        raise SocBuildError(
            "%s:coverage-instrumenter-unavailable:%s" % (cell_id, error)) from error
    area = build / "instrumentation"
    instrumenter_identity = (instrumenter_identity or
                             _coverage_instrumenter_identity())
    project = area / "project"
    if project.exists():
        shutil.rmtree(project)
    project.mkdir(parents=True)
    for item in closure["source_files"]:
        target = project / item
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(root / item, target)
    # Include roots must exist in the staging tree: the instrumenter copies them
    # into its output and rewrites the flist's +incdir+ lines onto that copy.
    for item in closure["include_dirs"]:
        source = root / item
        if source.is_dir():
            shutil.copytree(source, project / item, dirs_exist_ok=True)
    (project / top_name).write_text(rendered[top_name], encoding="utf-8")
    flist = project / "sources.f"
    flist.write_text("\n".join([
        *["+incdir+" + item for item in closure["include_dirs"]],
        *closure["source_files"],
        top_name,
    ]) + "\n", encoding="utf-8")
    try:
        result = instrument_project(
            project, area / "instrumented", flist=flist,
            top_module=top_module, force=True,
            # Terse Verilog-2001 writes 'always @(posedge clk) if (...) begin'
            # with a single-statement body; without this the whole block is
            # uninstrumented and a peripheral family yields no IP points.
            settings=_COVERAGE_INSTRUMENTER_SETTINGS)
    except (ValueError, SystemExit) as error:
        raise SocBuildError(
            "%s:coverage-instrumentation-failed:%s" % (cell_id, error)) from error
    bits = result.get("coverage_bits") or []
    if not bits:
        raise SocBuildError(
            "%s:coverage-instrumentation-found-no-branch-points" % cell_id)
    if not result.get("instrumented_flist"):
        raise SocBuildError("%s:coverage-instrumentation-has-no-flist" % cell_id)
    output_sha256 = _instrumented_output_sha256(
        result["out_dir"], result["instrumented_flist"])
    universe = universe_from_instance_bits(
        bits, cpu_instance=cpu_instance,
        ip_instances=["u_%s" % name for name in manifest.get("peripherals", {})])
    plan_document = coverage_observation_plan(universe, bits, COUNTER_LIMIT)
    observed = plan_document["observed_by_category"]
    if int(observed.get("cpu", 0)) + int(observed.get("ip", 0)) == 0:
        raise SocBuildError(
            "%s:coverage-instrumentation-observed-no-cpu-or-ip-point:%s"
            % (cell_id, sorted(observed)))
    return {
        "universe": universe,
        "plan": plan_document,
        "flist": str(result["instrumented_flist"]),
        "vector_width": int(result["coverage_vector_width"]),
        "point_count": int(result["coverage_point_count"]),
        "instrumented_root": str(area / "instrumented"),
        "instrumenter_identity": instrumenter_identity,
        "instrumented_output_sha256": output_sha256,
    }


def _coverage_ports(ports, cell_id):
    observations = []
    for port in ports:
        if port["direction"] != "output":
            continue
        for bit in range(min(port["width"], COUNTER_BITS_PER_PORT)):
            observations.append((port["name"], bit))
            if len(observations) >= COUNTER_LIMIT:
                return tuple(observations)
    if not observations:
        raise SocBuildError("%s: harness top has no observable output port" % cell_id)
    return tuple(observations)


def _source_closure(manifest, root, cell_id):
    elaboration = manifest.get("real_elaboration") if isinstance(manifest, Mapping) else None
    if not isinstance(elaboration, Mapping):
        raise SocBuildError(
            "%s: rendered manifest has no real_elaboration closure" % cell_id)
    files = elaboration.get("source_files")
    includes = elaboration.get("include_dirs", [])
    defines = elaboration.get("defines", [])
    for label, value in (("source_files", files), ("include_dirs", includes),
                         ("defines", defines)):
        if (not isinstance(value, Sequence) or isinstance(value, (str, bytes))
                or not all(isinstance(item, str) and item for item in value)):
            raise SocBuildError("%s: rendered %s is invalid" % (cell_id, label))
    if not files:
        raise SocBuildError("%s: rendered closure has no source files" % cell_id)
    missing = [item for item in files if not (root / item).is_file()]
    if missing:
        raise SocBuildError(
            "%s: closure source missing: %s" % (cell_id, ", ".join(sorted(missing)[:5])))
    return {
        "runtime_top": elaboration.get("runtime_top"),
        "source_files": [str(item) for item in files],
        "include_dirs": [str(item) for item in includes],
        "defines": [str(item) for item in defines],
    }


def _sources_require_boot_image(closure, root):
    for relative in closure["source_files"]:
        path = root / relative
        if path.suffix not in (".sv", ".v"):
            continue
        if ".LOAD_IMAGE(1)" in path.read_text(encoding="utf-8", errors="replace"):
            return True
    return False


def _boot_image(build, plan, cell, cell_path, cpu, cell_id, mode, config, stimulus,
                preloaded):
    """Build the deterministic campaign boot image for one preloaded region.

    The image places a real RV32I/RV64I pass-and-loop program at the CPU's first
    fetch address inside the preloaded region, so the real CPU executes from the
    pinned memory model.  It is not a behavioural CPU and it never substitutes
    for RFuzz mutation: the mutator still drives the MMIO/environment ABI.
    """
    if len(preloaded) != 1:
        raise SocBuildError(
            "%s: exactly one preloaded memory region is supported, found %d"
            % (cell_id, len(preloaded)))
    region = preloaded[0]
    base = int(region["base"])
    size = int(region["size"])
    reset_vector = int(cpu.get("reset_vector", 0))
    fetch_offset = cpu.get("fetch_offset")
    if fetch_offset is None:
        fetch_offset = config.get("boot_image_fetch_offset")
    if fetch_offset is None:
        fetch_offset = _CPU_FETCH_OFFSETS.get(str(cpu.get("id") or cpu.get("source_lock")))
    if fetch_offset is None:
        raise SocBuildError(
            "%s: unknown first-fetch offset for cpu %s"
            % (cell_id, cpu.get("source_lock")))
    image_offset = reset_vector + int(fetch_offset) - base
    if image_offset < 0 or image_offset % 4 or image_offset + 4 > size:
        raise SocBuildError(
            "%s: boot image offset %d is outside the preloaded region at %d"
            % (cell_id, image_offset, base))
    writable = [item for item in plan["address_map"]["memory_regions"]
                if item.get("permissions", {}).get("write")]
    pass_address = int(writable[0]["base"]) if writable else 0
    xlen = int(cpu["xlen"])
    extensions = "".join(str(item).lower() for item in cpu.get("extensions", [])
                         if str(item).isalnum())
    isa = "rv%d%s" % (xlen, extensions or "i")
    facts = RiscvExecutionFacts(
        isa=isa, xlen=xlen, reset_vector=image_offset,
        pass_address=pass_address, pass_value=0x600DCAFE,
        protocol=tuple(cpu["protocol"]), max_cycles=MAX_CYCLES,
        provenance=RiscvExecutionProvenance(
            source_identity="%s:boot-stub" % cell_id,
            source_hash=content_hash({"cell_config": str(cell_path),
                                      "cell": copy.deepcopy(dict(cell))}),
            profile_identity="%s:%s:campaign-boot-stub" % (cell_id, mode),
            profile_hash=content_hash({"cell": cell_id, "mode": mode,
                                       "image_offset": image_offset,
                                       "isa": isa}),
            interface_identity=str(stimulus["plan_hash"]),
            interface_hash=str(stimulus["plan_hash"]),
            isa=isa, xlen=xlen, reset_vector=image_offset))
    try:
        image = build_minimal_boot_image(facts, build / "boot")
    except (OSError, ValueError, RuntimeError) as error:
        raise SocBuildError("%s:boot-image-build-failed:%s" % (cell_id, error)) from error
    document = {
        "role": ("campaign boot stub: real CPU execution from the pinned memory model; "
                 "RFuzz still mutates the MMIO/environment raw ABI"),
        "region": {"region_id": region["region_id"], "base": base, "size": size,
                   "initialization_policy": region.get("initialization_policy")},
        "image_offset": image_offset,
        "cpu_reset_vector": reset_vector,
        "cpu_fetch_offset": int(fetch_offset),
        "pass_address": pass_address,
        "pass_value": "0x600dcafe",
        "isa": isa,
        "compiler": image.compiler,
        "command": list(image.command),
        "memory_hex": image.memory_hex_path.name,
        "memory_hex_sha256": image.memory_hex_hash,
        "binary_size": image.binary_size,
    }
    return document, ("+riscv_boot_image=%s" % image.memory_hex_path,)


_RESERVED_TB_NAMES = frozenset((
    "raw_bits", "counters", "count", "scan", "i", "j", "request_id",
    "last_request_id", "clk", "reset",
))


def _clock_and_reset(ports, cell_id):
    names = {port["name"] for port in ports}
    clock = next((name for name in ("clk", "clk_i", "clock", "clock_i") if name in names), None)
    reset = next((name for name in ("reset", "reset_i", "rst", "rst_i", "reset_ni",
                                    "rst_ni", "resetn") if name in names), None)
    if clock is None or reset is None:
        raise SocBuildError("%s: harness top must expose a clock and a reset" % cell_id)
    active_low = reset.endswith("_ni") or reset.endswith("_n")
    return clock, reset, ("1'b0" if active_low else "1'b1"), ("1'b1" if active_low else "1'b0")


def _testbench(layout, mapping, ports, top_module, coverage_ports,
               coverage_width=None, input_defaults=None, image_plan=None,
               image_targets=None, execution_monitor=None):
    """Generate the persistent harness that speaks simulator protocol 2."""
    clock, reset, reset_active, reset_inactive = _clock_and_reset(ports, top_module)
    driven = {}
    for field in layout.fields:
        if field.port:
            driven[field.port] = (field.raw_lo, field.raw_hi)
    widths = {port["name"]: port["width"] for port in ports}
    if coverage_width is not None:
        widths[COVERAGE_SIGNAL] = int(coverage_width)
    lines = []
    add = lines.append
    add("// Generated by myfuzz.integration.soc_builder (%s)." % BUILD_SCHEMA)
    add("// Persistent RFuzz harness: one raw %d-bit stimulus sample per cycle," % layout.raw_width)
    add("// %d saturating 8-bit counters over instrumented RTL branch points."
        % len(coverage_ports))
    add("module myfuzz_live_tb;")
    add("  localparam integer RAW_WIDTH = %d;" % layout.raw_width)
    add("  localparam integer COUNTER_COUNT = %d;" % len(coverage_ports))
    add("  logic clk = 1'b0;")
    add("  logic reset = %s;" % reset_inactive)
    add("  logic [RAW_WIDTH-1:0] raw_bits = '0;")
    add("  logic [7:0] counters [0:COUNTER_COUNT-1];")
    add("  logic [COUNTER_COUNT*8-1:0] counter_bits = '0;")
    add("  integer count, scan, i, j;")
    if image_plan is not None:
        add("  logic [RAW_WIDTH-1:0] sample_words [0:%d];" % (MAX_CYCLES-1))
        add("  logic [31:0] image_address, image_value, image_readback;")
        add("  logic [3:0] image_be;")
        add("  integer image_lane;")
    add("  logic [63:0] request_id, last_request_id = 64'd0;")
    for port in ports:
        name = port["name"]
        width = port["width"]
        packed = "" if width == 1 else "[%d:0] " % (width - 1)
        if name in (clock, reset):
            continue
        if name in _RESERVED_TB_NAMES:
            raise SocBuildError("harness port collides with the harness internals: %s" % name)
        if port["direction"] == "output":
            add("  wire %s%s;" % (packed, name))
        elif name in driven:
            add("  wire %s%s;" % (packed, name))
        else:
            idle = (input_defaults[name] if input_defaults is not None and name in input_defaults
                    else _IDLE_INPUTS.get(name, 0))
            add("  logic %s%s = %d'd%d;" % (packed, name, width, idle))
    add("  %s dut(" % top_module)
    connections = [".%s(clk)" % clock, ".%s(reset)" % reset]
    connections.extend(".%s(%s)" % (port["name"], port["name"])
                       for port in ports if port["name"] not in (clock, reset))
    add("    " + ",\n    ".join(connections))
    add("  );")
    for name in sorted(driven):
        raw_lo, raw_hi = driven[name]
        if raw_lo == raw_hi:
            add("  assign %s = raw_bits[%d];" % (name, raw_lo))
        else:
            add("  assign %s = raw_bits[%d:%d];" % (name, raw_hi, raw_lo))
    for label in sorted(mapping["unmapped"]):
        add("  // raw field %s has no matching harness input port and stays unmapped." % label)
    add("  task tick; begin #5 clk=1'b1; #5 clk=1'b0; end endtask")
    # The harness drives the DUT through its own ``clk``/``reset`` nets, so the
    # monitor samples those; ``clock``/``reset`` are the *DUT port* names and do
    # not exist in this module's scope.
    for statement in monitor_rtl("clk", "reset", reset_active, execution_monitor):
        for line in statement.splitlines():
            add(line)
    add("  initial begin")
    add("    clk=1'b0; reset=%s;" % reset_inactive)
    add('    $display("RFUZZ_READY %d"); $fflush();' % SIMULATOR_PROTOCOL_VERSION)
    # The request loop is a while loop, not ``forever``: the publication probe
    # starts this binary with no input at all and needs only the readiness line,
    # so end of stream has to leave the loop.  A ``forever`` kept running after
    # the ``$finish`` in its body (the clock generator never stops), which made
    # every probe hang instead of exiting.
    add("    scan=1;")
    add("    while (scan > 0) begin")
    add('      scan=$fscanf(32\'h80000000,"%h %d",request_id,count);')
    add("      if (scan <= 0) begin")
    add('        $display("RFUZZ_DONE no-request scan=%0d", scan); $fflush();')
    add("      end else begin")
    add('        if (request_id == 0 || request_id <= last_request_id) $fatal(1,"request id");')
    add("        last_request_id=request_id;")
    add('      if (count < 1 || count > %d) $fatal(1,"cycle count");' % MAX_CYCLES)
    add("      raw_bits='0;")
    # Two reset clocks clear the CPU, fabric, IRQ and coverage state at every
    # sample boundary.  The pinned memory models rewrite their whole array on
    # each clock while reset is asserted, so a longer hold multiplies the
    # per-sample cost without adding reset coverage.
    if image_plan is None:
        add("      reset=%s; repeat (2) tick(); reset=%s;" % (reset_active, reset_inactive))
    else:
        add("      for (i=0;i<count;i=i+1) begin")
        add('        scan=$fscanf(32\'h80000000,"%h",sample_words[i]);')
        add('        if (scan != 1) $fatal(1,"raw sample");')
        add("      end")
        add("      reset=%s; repeat (2) tick();" % reset_active)
        add("      for (i=0;i<count;i=i+1) begin")
        def segment(name):
            field = image_plan.segment(name)
            return "sample_words[i][%d:%d]" % (field.raw_hi, field.raw_lo)
        for slot in image_plan.candidates.slots():
            kind = slot.kind
            prefix = slot.prefix
            value_name = "data" if kind == "instruction" else "value"
            target, base, size = image_targets[kind]
            memory = "dut.u_mem_%d.memory" % target
            add("        if (%s) begin" % segment(prefix + "_offer"))
            add("          image_address=%s; image_value=%s; image_be=%s;" %
                (segment(prefix + "_address"), segment(prefix + "_" + value_name),
                 segment(prefix + "_be")))
            add("          image_readback='0;")
            add("          for (image_lane=0;image_lane<4;image_lane=image_lane+1) begin")
            add("            if (image_be[image_lane]) begin")
            add('              if ({1\'b0,image_address}+image_lane < 33\'d%d || {1\'b0,image_address}+image_lane >= 33\'d%d) $fatal(1,"image address");' % (base, base+size))
            add("              dut.u_mem_%d.initial_memory[image_address-32'd%d+image_lane]=image_value[image_lane*8+:8];" % (target, base))
            add("            end")
            add("          end")
            add("          repeat (1) tick(); // restore candidate image while CPU is held in reset")
            add("          for (image_lane=0;image_lane<4;image_lane=image_lane+1) begin")
            add("            if (image_be[image_lane]) image_readback[image_lane*8+:8]=%s[image_address-32'd%d+image_lane];" % (memory, base))
            add("          end")
            # The slot name is appended so every declared slot reports which
            # one it overlaid; the legacy two-slot line keeps its exact shape.
            add('          $display("MYFUZZ_IMAGE kind=%s addr=%%08h value=%%08h reset=%%0b slot=%s",image_address,image_readback,reset);' % (kind, prefix))
            add("        end")
        add("      end")
        add("      reset=%s;" % reset_inactive)
    add("      for (j=0;j<COUNTER_COUNT;j=j+1) counters[j]=8'h00;")
    add("      for (i=0;i<count;i=i+1) begin")
    if image_plan is None:
        add('        scan=$fscanf(32\'h80000000,"%h",raw_bits);')
        add('        if (scan != 1) $fatal(1,"raw sample");')
    else:
        add("        raw_bits=sample_words[i];")
    add("        tick();")
    for index, (name, bit) in enumerate(coverage_ports):
        expression = ("dut.%s" % name if widths[name] == 1
                      else "dut.%s[%d]" % (name, bit))
        add('        if (%s !== 1\'b0 && %s !== 1\'b1) $fatal(1,"unknown observation");'
            % (expression, expression))
        add("        if (%s && counters[%d] != 8'hff) counters[%d] = counters[%d] + 1'b1;"
            % (expression, index, index, index))
    add("      end")
    # Pack the counters into one wide vector: a single %h conversion keeps the
    # reply exactly COUNTER_COUNT*2 lowercase hex digits and avoids one slow
    # $write formatting call per counter, which otherwise dominates runtime.
    add("      counter_bits='0;")
    add("      for (j=0;j<COUNTER_COUNT;j=j+1) counter_bits=(counter_bits<<8)|{56'd0,counters[j]};")
    add('      $write("RFUZZ_COUNTERS %016h %h",request_id,counter_bits);')
    for statement in monitor_output(execution_monitor):
        add("      " + statement)
    add('      $write("\\n");')
    add("      $fflush();")
    add("      end")          # close the "scan > 0" branch opened above
    add("    end")            # close the while loop
    add("  end")
    add("endmodule")
    return "\n".join(lines) + "\n"


def _compile_command(verilator, build, closure, root, top_name, flist=None):
    warnings = ("-Wno-fatal", "-Wno-PINMISSING", "-Wno-WIDTHEXPAND", "-Wno-WIDTHTRUNC",
                "-Wno-MULTIDRIVEN", "-Wno-UNSIGNED", "-Wno-CASEINCOMPLETE", "-Wno-LATCH",
                "-Wno-UNOPTFLAT")
    if flist is not None:
        # The instrumented flist already carries the mapped +incdir+ roots and
        # the instrumented copy of the rendered top, which has the coverage port.
        sources = ("-f", str(flist))
    else:
        sources = (
            *("-I" + str((root / item).resolve()) for item in closure["include_dirs"]),
            *[str((root / item).resolve()) for item in closure["source_files"]],
            str(build / top_name))
    command = ("nice", "-n15", str(verilator), "--binary", "--timing",
               "--top-module", "myfuzz_live_tb", "-j", "1",
               "--Mdir", str(build / "obj_dir"), *warnings,
               *("-D" + item for item in closure["defines"]),
               *sources,
               str(build / "rfuzz_input_transport.sv"),
               str(build / "live_tb.sv"))
    log_path = build / "compiler.log"
    return (sys.executable, "-c",
            "import subprocess,sys; "
            "log=open(sys.argv[1],'wb'); "
            "result=subprocess.call(sys.argv[2:],stdout=log,stderr=subprocess.STDOUT); "
            "log.close(); sys.exit(result)", str(log_path), *command)


def _probe_executable(executable, simulator_args, cell_id):
    """Refuse to publish an executable that cannot speak protocol 2."""
    try:
        result = subprocess.run((str(executable), *simulator_args),
                                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                timeout=PROBE_TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SocBuildError("%s:executable-probe-failed:%s" % (cell_id, error)) from error
    output = (result.stdout or "") + (result.stderr or "")
    expected = "RFUZZ_READY %d" % SIMULATOR_PROTOCOL_VERSION
    if result.returncode != 0 or expected not in output:
        raise SocBuildError(
            "%s:executable-protocol-probe-failed:rc=%s:output=%s"
            % (cell_id, result.returncode, output[-2000:].replace("\n", " | ")))


__all__ = [
    "BUILD_SCHEMA",
    "CLOSURE_DIR",
    "PERIPHERAL_FACTS",
    "SocBuildError",
    "SocCampaignArtifact",
    "build_soc_campaign_artifact",
]
