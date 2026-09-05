#!/usr/bin/env python3
"""Validate the Ibex protocol-composition fixture without running RTL tools."""

from __future__ import annotations

import sys
from pathlib import Path


SCRIPT = Path(__file__).resolve()
ROOT = SCRIPT.parents[4]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from myfuzz.composition.protocol_manifest import (  # noqa: E402
    ProtocolCompositionError,
    load_protocol_composition,
    validate_protocol_composition,
)
from myfuzz.composition.registry import default_component_registry  # noqa: E402
from myfuzz.protocols.catalog import load_protocol_catalog  # noqa: E402


DESIGN = ROOT / "configs/designs/ibex_protocol_composition"
MANIFEST = DESIGN / "manifest.json"
PLUGIN_DIR = ROOT / "src/myfuzz/protocols/plugins"
UPSTREAM_RELATIVE = "third_party/rfuzz/upstream/ibex"

LOCAL_SOURCE_FILES = (
    "configs/designs/ibex_multicomponent_ip/rtl/ibex_mcip_ram.sv",
    "configs/designs/ibex_multicomponent_ip/rtl/ibex_mcip_timer.sv",
    "configs/designs/ibex_multicomponent_ip/rtl/ibex_mcip_gpio.sv",
    "configs/designs/ibex_multicomponent_ip/rtl/ibex_mcip_uart.sv",
    "configs/designs/ibex_multicomponent_ip/rtl/ibex_mcip_spi.sv",
    "src/myfuzz/protocols/rtl/apb4_mmio_bridge.sv",
    "src/myfuzz/protocols/rtl/apb4_mmio_target.sv",
    "src/myfuzz/protocols/rtl/axi4_lite_mmio_bridge.sv",
    "src/myfuzz/protocols/rtl/axi4_lite_mmio_target.sv",
    "src/myfuzz/protocols/rtl/tl_ul_mmio_bridge.sv",
    "src/myfuzz/protocols/rtl/tl_ul_mmio_target.sv",
)

EXPECTED_COMPONENTS = {
    "ram0": ("ram", "tl-ul", "1", 0x00000000, 0x10000, None),
    "timer0": ("timer", "apb", "4", 0x80010000, 0x1000, 1),
    "gpio0": ("gpio", "apb", "4", 0x80020000, 0x1000, 2),
    "uart0": ("uart", "axi4-lite", "1", 0x80030000, 0x1000, 3),
    "spi0": ("spi", "axi4-lite", "1", 0x80040000, 0x1000, 4),
}


class LocalCheckError(RuntimeError):
    """Raised when a local fixture invariant is not satisfied."""


def _check_local_sources() -> None:
    for relative_path in LOCAL_SOURCE_FILES:
        if not (ROOT / relative_path).is_file():
            raise LocalCheckError(f"missing local source: {relative_path}")


def _check_manifest():
    try:
        manifest = load_protocol_composition(MANIFEST)
        validate_protocol_composition(
            manifest,
            load_protocol_catalog(PLUGIN_DIR),
            default_component_registry(ROOT),
        )
    except (OSError, ProtocolCompositionError, ValueError) as error:
        raise LocalCheckError(str(error)) from error

    actual = {
        component.component_id: (
            component.component_type,
            component.protocol_id,
            component.protocol_version,
            component.base,
            component.size,
            component.irq,
        )
        for component in manifest.components
    }
    if actual != EXPECTED_COMPONENTS:
        raise LocalCheckError("manifest components do not match the approved map")
    if manifest.target_kind != "ibex_core":
        raise LocalCheckError(f"unexpected target kind: {manifest.target_kind}")
    if manifest.seed != 7 or manifest.duration_seconds != 3600 or manifest.checkpoint_seconds != 30:
        raise LocalCheckError("manifest runtime defaults do not match the approved campaign")
    return manifest


def _upstream_available() -> bool:
    upstream = ROOT / UPSTREAM_RELATIVE
    if not upstream.is_dir() or not (upstream / "sources.f").is_file():
        print(f"dependency-unavailable: {UPSTREAM_RELATIVE}")
        return False
    return True


def main() -> int:
    try:
        _check_local_sources()
        _check_manifest()
    except LocalCheckError as error:
        print(f"configuration-error: {error}", file=sys.stderr)
        return 1

    if not _upstream_available():
        return 2
    print("ok: ibex_protocol_composition local checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
