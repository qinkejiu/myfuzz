"""P12 runtime half: render, build and run every matrix cell in every mode.

This module is the executable half of P12.  It turns one matrix cell config
into the same soc_plan/stimulus/render documents the renderer half uses
(tests/integration/test_soc_renderer_cells.py cross-checks that identity),
generates a deterministic boot program from the plan's own address map,
generates a testbench for the rendered myfuzz_soc_top, builds it with
verilator --binary --timing and runs one test mode.

Generated boot program
----------------------

The program is a pure function of the plan (plus the pinned IP register
semantics recorded below), never a per-cell hardcoded image:

* the directed target is the *first writable MMIO window* in the plan's
  address map, that is the peripheral window with the lowest base address
  (RAM/ROM windows are not MMIO targets);
* for that pinned peripheral the program runs an ordered list of operations
  from PERIPHERAL_PROGRAMS: register writes (the recognisable probe value and,
  where the pinned IP needs it, the documented setup/side-effect writes)
  followed by a read of the register the IP really implements;
* it then records a completion flag in the plan's writable RAM region: a match
  flag when the value read back equals the pinned IP expectation, a mismatch
  flag otherwise, plus the read-back word itself;
* it spins forever afterwards.

Only 32-bit, non-compressed RV32I/RV64I instructions are emitted (a small
two-pass assembler in this module) and 64-bit addresses are materialised
zero-extended, so the same generator serves Ibex and CVA6.  The image is a
plain readmemh byte image loaded at the region base, which for every cell is
also the declared CPU reset vector.  The image starts with an entry
trampoline: a jump at offset 0 and the program at offset 0x80.  The pinned
Ibex enters at {boot_addr_i[31:8], 8'h80} (ibex_if_stage.sv:243) while CVA6
enters at boot_addr_i, so both land on the same program without any per-CPU
branch in this module.

The testbench the module generates is equally data-driven: it connects every
port the rendered top declares, drives the raw stimulus fields only for the
mode under test (cpu_only: none; mmio_only and mixed: the synthetic program
that mirrors the CPU's operations, lane-placed for a 64-bit beat), observes
the pinned peripheral outputs, the fabric source attribution, the CPU
completion record in RAM and the synthetic master's accepted/completed
counters, and prints one MYFUZZ_SOC_MATRIX_RUN line per run.

Fail-closed boundary
--------------------

run_cell_mode raises SocMatrixSmokeError naming the exact missing file,
module, port, wire or tool.  It never substitutes a behavioural CPU or
peripheral model, never skips and never renders from a plan it could not
validate.

Structural limits this module surfaces instead of hiding
-------------------------------------------------------

* The pinned TL-UL target adapter refuses a 64-bit address width:
  beat_to_tlul.sv fatals with "command integrity covers at most 32 address
  bits" when GEN_INTEGRITY=1 (the OpenTitan closures require integrity) and
  ADDRESS_WIDTH > 32, so the two OpenTitan cells cannot be combined with the
  CVA6 address width at all.
* The pinned CVA6 core stops requesting after its first two two-beat line
  fills through the generated arbiter/router path: the fabric returns the
  correct instruction words (verified with the memory parameter
  normalization below), yet the core never reaches the program entry, so the
  CPU modes of the CVA6 cells report status=TIMEOUT with the measured
  transaction counts.  The same core runs in the hand-written P11 wrapper, so
  this is a generic-fabric gap, not a source problem.
* The pinned zipcpu UART wrapper ties i_cts_n high while the closure pins
  HARDWARE_FLOW_CONTROL_PRESENT=1 and txuart derives ck_cts from it
  (txuart.v:147,190), so that transmitter can never leave IDLE; see the
  program table for the evidence and for the register round trip this smoke
  observes instead.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from myfuzz.composition.soc_plan import build_soc_plan
from myfuzz.composition.soc_renderer import render_soc
from myfuzz.composition.soc_stimulus import compile_soc_stimulus
from myfuzz.composition.target_adapters import resolve_target_adapter
from myfuzz.contracts import content_hash


SMOKE_SCHEMA = "soc_matrix_smoke.v1"
MODES = ("cpu_only", "mmio_only", "mixed")
MODE_CODES = {"cpu_only": 0, "mmio_only": 1, "mixed": 2}
DEFAULT_SEED = 0
DEFAULT_CYCLE_BUDGET = 200000
DEFAULT_BUILD_TIMEOUT_S = 1800
DEFAULT_RUN_TIMEOUT_S = 300
DEFAULT_ELABORATE_TIMEOUT_S = 1800
RUNTIME_TOP = "myfuzz_soc_top"
TESTBENCH_TOP = "soc_matrix_tb"

#: Completion flags the generated program records in RAM.
FLAG_OK = 0xF00D_0001
FLAG_MISMATCH = 0xF00D_0002

#: RAM record layout (byte offsets inside the writable memory region).  The
#: offsets are 8-byte aligned so a 32-bit access from a 64-bit CPU or a 64-bit
#: synthetic beat selects the low lane (see mmio_width_adapter lane rules).
FLAG_OFFSET = 0x100
READBACK_OFFSET = 0x108

#: Offset of the program entry inside the boot image.  Ibex fetches its first
#: instruction at {boot_addr_i[31:8], 8'h80} (ibex_if_stage.sv:243) and CVA6
#: fetches at boot_addr_i; a jump at offset 0 and the program at 0x80 enter the
#: same code on both.
ENTRY_OFFSET = 0x80

ROOT = Path(__file__).resolve().parents[3]
MATRIX_PATH = ROOT / "configs/soc/matrix.json"
CLOSURE_DIR = "configs/soc/closures"


class SocMatrixSmokeError(RuntimeError):
    """A cell/mode could not be run for a structural reason."""


# ---------------------------------------------------------------------------
# frozen P12 cell facts (the same facts the renderer half records)
# ---------------------------------------------------------------------------

#: Capability facts and the closure finding each one was read from.  They are
#: the pinned P1 elaboration facts; the renderer test records the same table,
#: and the cross-check test asserts both halves plan the same document.
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

#: Directed register program per pinned peripheral.  Every offset, value and
#: expectation below is read from the pinned real IP the closure names; the
#: evidence field records where.  "$probe" is replaced by probe_value.
#:
#:   op ("write", offset, value)  - store a 32-bit word
#:   op ("read",  offset, None)   - load a 32-bit word (the read-back)
PERIPHERAL_PROGRAMS = {
    "opentitan_uart": {
        # uart_reg_top.sv: CTRL F[tx] 0:0, F[rx] 1:1, F[nco] 31:16.  uart_core
        # line 177 tick_baud_x16 = nco_sum_q[16], so nco must be non-zero for
        # the real transmitter to shift a frame out.  WDATA (0x1c) is the
        # write-only transmit FIFO port, so CTRL is the read-back register.
        "probe_value": 0xC0DE_0003,
        "ops": [
            ("write", 0x10, "$probe"),      # CTRL: tx+rx enable, nco=0xc0de
            ("write", 0x1C, 0x0000_005A),   # WDATA: transmit one byte
            ("read", 0x10, None),           # CTRL read back
        ],
        "readback_expected": "$probe",
        "side_effect": "uart_tx_activity",
        "observations": ("uart_tx", "uart_tx_level"),
        "evidence": (
            "third_party/soc-opentitan/hw/ip/uart/rtl/uart_reg_top.sv:896,1112",
            "third_party/soc-opentitan/hw/ip/uart/rtl/uart_core.sv:177",
        ),
    },
    "opentitan_gpio": {
        # gpio.sv:119,131 cio_gpio_o = cio_gpio_q loaded from DIRECT_OUT;
        # gpio_reg_pkg.sv:234 GPIO_DIRECT_OUT_OFFSET = 0x14.
        "probe_value": 0xA5A5_0001,
        "ops": [
            ("write", 0x14, "$probe"),      # DIRECT_OUT
            ("read", 0x14, None),           # DIRECT_OUT read back
        ],
        "readback_expected": "$probe",
        "side_effect": "gpio_out_register",
        "observations": ("gpio_out", "gpio_dir"),
        "evidence": (
            "third_party/soc-opentitan/hw/top_earlgrey/ip_autogen/gpio/rtl/gpio.sv:119,131",
            "third_party/soc-opentitan/hw/top_earlgrey/ip_autogen/gpio/rtl/gpio_reg_pkg.sv:234",
        ),
    },
    "pulp_gpio": {
        # apb_gpio.sv:14 REG_PADOUT_00_31 = 0x0C; the write sets r_gpio_out for
        # all 32 pads and the read mux returns r_gpio_out.
        "probe_value": 0x5A5A_0002,
        "ops": [
            ("write", 0x0C, "$probe"),      # PADOUT
            ("read", 0x0C, None),           # PADOUT read back
        ],
        "readback_expected": "$probe",
        "side_effect": "gpio_out_register",
        "observations": ("gpio_out", "gpio_dir"),
        "evidence": (
            "third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv:14,285-291,570-577",
        ),
    },
    "pulp_spi": {
        # spi_master_apb_if.sv:13-22 SPILEN 0x10 / TXFIFO 0x18 / STATUS 0x00.
        # SPILEN reads back {data_len,2'b00,addr_len,2'b00,cmd_len}; writing
        # STATUS with spi_wr + csreg starts a real transfer.
        "probe_value": 0x0008_0000,
        "ops": [
            ("write", 0x10, "$probe"),      # SPILEN: 8 data bits
            ("write", 0x18, 0x0000_003C),   # TXFIFO payload byte
            ("write", 0x00, 0x0000_0102),   # STATUS: spi_wr=1, csreg=1
            ("read", 0x10, None),           # SPILEN read back
        ],
        "readback_expected": "$probe",
        "side_effect": "spi_activity",
        "observations": ("spi_clk", "spi_cs0_level", "spi_sdo0"),
        "evidence": (
            "third_party/soc-pulp-apb-spi/spi_master_apb_if.sv:13-22,115-145,180-200",
        ),
    },
    "zipcpu_uart": {
        # wbuart.v:79-82 UART_SETUP 0x00 / UART_TXREG 0x0C; a write to TXREG
        # with sel[0] enqueues i_wb_data[7:0] into the transmit FIFO, and
        # reading TXREG returns the transmit status plus the latched byte
        # (wbuart.v:458).  The probe writes the documented INITIAL_SETUP 8N1
        # divider 25 to SETUP and enqueues one byte through TXREG.
        #
        # Structural limitation of this pinned combination: the source-backed
        # wrapper ties i_cts_n to 1'b1 while the closure pins
        # HARDWARE_FLOW_CONTROL_PRESENT=1, and txuart.v:190 derives
        # ck_cts = !qq_cts_n || !hw_flow_control with hw_flow_control =
        # !r_setup[30] (txuart.v:147).  With setup[30]=0 and cts_n=1 the
        # transmitter latches r_busy high and never leaves IDLE, while r_setup
        # is only reloaded while !o_busy (txuart.v:275), so neither a SETUP
        # write of bit 30 nor the queued byte can start a frame: the real TX
        # line provably stays idle (verified standalone and through the
        # rendered fabric).  The observed side effect of the write is the real
        # transmit register state instead: the queued byte in txf_wb_data and
        # the busy/not-empty status selected by (tx_busy|txf_status[0]).
        # Because that transmit path is provably stuck, the directed side
        # effect this cell can observe is the register round trip of the real
        # IP: the write lands in uart_setup and the read returns it.
        "probe_value": 25,
        "ops": [
            ("write", 0x00, "$probe"),      # SETUP: 25 clocks/baud, 8N1
            ("write", 0x0C, 0x0000_005A),   # TXREG: enqueue one byte
            ("read", 0x00, None),           # SETUP read back
        ],
        "readback_expected": "$probe",
        "side_effect": "register_write_readback",
        "observations": ("uart_tx", "uart_tx_level"),
        "evidence": (
            "third_party/soc-zipcpu-wbuart/rtl/wbuart.v:79-82,125-135,330,513",
            "third_party/soc-zipcpu-wbuart/rtl/txuart.v:147,190,275",
            "src/myfuzz/composition/rtl/soc_zipcpu_uart_target.sv:cts_n tie-off",
        ),
    },
    "zipcpu_timer": {
        # ziptimer.v: the single-register window loads r_value from
        # i_wb_data[VW-1:0] and returns {auto_reload, r_value}, so the read
        # back is the running counter and never equals the written value.
        "probe_value": 0x00FF_FFFF,
        "ops": [
            ("write", 0x00, "$probe"),      # load the counter
            ("read", 0x00, None),           # read the running counter
        ],
        "readback_expected": None,
        "side_effect": "timer_readback",
        "observations": (),
        "evidence": (
            "third_party/soc-zipcpu/rtl/peripherals/ziptimer.v:150,170,220-222",
        ),
    },
}

#: Closure capability topic documenting the register read path and the
#: register write path of each pinned peripheral.  The runtime plan declares
#: read/write capabilities (the router turns them into window permissions), and
#: the adapter resolver requires one evidence record per declared fact.
PERIPHERAL_RW_TOPICS = {
    "opentitan_uart": ("tlul_opcodes", "tlul_opcodes"),
    "opentitan_gpio": ("tlul_opcodes", "tlul_opcodes"),
    "pulp_gpio": ("address_decode", "address_decode"),
    "pulp_spi": ("read_data_not_gated_by_select", "address_decode"),
    "zipcpu_uart": ("read_side_effects", "byte_enable_tx_register"),
    "zipcpu_timer": ("read_data_layout", "write_semantics"),
}

#: Peripheral observation output -> (top-level wire suffix, kind).  A "level"
#: observation is sampled at the end of the run, an "edges" observation counts
#: transitions of the real IP output.
OBSERVATION_SIGNALS = {
    "gpio_out": ("obs_gpio_out", "level"),
    "gpio_dir": ("obs_gpio_dir", "level"),
    "uart_tx": ("obs_uart_tx", "edges"),
    "uart_tx_level": ("obs_uart_tx", "level"),
    "spi_clk": ("obs_spi_clk", "edges"),
    "spi_cs0_level": ("obs_spi_cs0", "level"),
    "spi_sdo0": ("obs_spi_sdo0", "edges"),
}

#: Cycles the testbench observes after the last MMIO transaction before it
#: checks the side effect.  A UART frame or an SPI transfer takes real time on
#: the pinned IP: wbuart transmits at the documented INITIAL_SETUP 25
#: clocks/baud and the OpenTitan UART at the nco=0xc0de baud tick, so a 10-bit
#: frame finishes well inside 600 cycles.  A plain register write needs none.
SIDE_EFFECT_SETTLE_CYCLES = {
    "gpio_out_register": 8,
    "uart_tx_activity": 600,
    "spi_activity": 300,
    "timer_readback": 8,
    "register_write_readback": 8,
}

#: Every port the generated testbench connects, with the width expression it
#: declares.  A rendered port that is not in this map is a structural error.
_TOP_PORT_WIDTHS = {
    "clk_i": ("1", "input"),
    "reset_i": ("1", "input"),
    "env_offer_i": ("1", "input"),
    "env_data_i": ("DATA_WIDTH", "input"),
    "spi_sck_i": ("1", "input"),
    "spi_cs_i": ("1", "input"),
    "gpio_in_i": ("8", "input"),
    "irq_claim_i": ("1", "input"),
    "irq_complete_i": ("1", "input"),
    "stim_offer_i": ("1", "input"),
    "stim_target_selector_i": ("SELECTOR_WIDTH", "input"),
    "stim_offset_i": ("ADDRESS_WIDTH", "input"),
    "stim_write_i": ("1", "input"),
    "stim_wdata_i": ("DATA_WIDTH", "input"),
    "stim_be_i": ("DATA_WIDTH/8", "input"),
    "uart_rx_o": ("1", "output"),
    "spi_miso_o": ("1", "output"),
    "irq_o": ("1", "output"),
    "env_drop_count_o": ("32", "output"),
    "cpu_irq_o": ("1", "output"),
    "gpio_out_o": ("32", "output"),
    "gpio_dir_o": ("32", "output"),
    "gpio_irq_o": ("1", "output"),
    "spi_clk_o": ("1", "output"),
    "spi_cs0_o": ("1", "output"),
    "spi_sdo0_o": ("1", "output"),
    "cpu_mmio_transaction_o": ("1", "output"),
    "fuzz_mmio_transaction_o": ("1", "output"),
    "cpu_transaction_count_o": ("32", "output"),
    "fuzz_transaction_count_o": ("32", "output"),
    "cpu_completion_count_o": ("32", "output"),
    "fuzz_completion_count_o": ("32", "output"),
    "fabric_protocol_error_o": ("1", "output"),
}

#: Internal top-level wires the testbench observes for source attribution.
_TOP_REQUIRED_WIRES = (
    "fabric_addr", "fabric_source_id", "fabric_rsp_source_id", "fabric_rdata",
    "fabric_req_valid", "fabric_req_ready", "fabric_rsp_valid",
    "fabric_rsp_ready",
)

_PORT_DECLARATION = re.compile(
    r"^\s*(input|output)\s+logic\s*(\[[^\]]*\])?\s*([A-Za-z_][A-Za-z0-9_]*)\s*,?\s*$",
    re.M,
)
_MEMORY_TARGET = re.compile(r"//\s*Memory target\s+(\w+)")
_MEMORY_INSTANCE_LINE = re.compile(r"\bu_mem_(\d+)\s*\(")
_MEMORY_INSTANTIATION_LINE = re.compile(
    r"^\s*riscv_boot_memory_(?P<width>32|64)\s*#\((?P<parameters>.*)\)\s*"
    r"u_mem_(?P<index>\d+)\s*\($")
_BASE_ADDR_OVERRIDE = re.compile(r"\.BASE_ADDR\((?P<value>[^)]*)\)")


# ---------------------------------------------------------------------------
# cell config -> spec -> plan -> stimulus (the renderer half's identity)
# ---------------------------------------------------------------------------


def _read_json(path: Path, label: str) -> dict:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise SocMatrixSmokeError("%s is missing: %s" % (label, path)) from error
    except json.JSONDecodeError as error:
        raise SocMatrixSmokeError("%s is not valid JSON (%s): %s"
                                  % (label, error, path)) from error
    if not isinstance(document, dict):
        raise SocMatrixSmokeError("%s must be a JSON object: %s" % (label, path))
    return document


def load_matrix(path: Path = MATRIX_PATH) -> dict:
    matrix = _read_json(Path(path), "soc matrix")
    cells = matrix.get("cells")
    if not isinstance(cells, list) or not cells:
        raise SocMatrixSmokeError("soc matrix declares no cells: %s" % path)
    modes = matrix.get("modes")
    if sorted(modes or []) != sorted(MODES):
        raise SocMatrixSmokeError("soc matrix modes %r do not match %r"
                                  % (modes, list(MODES)))
    return matrix


def _matrix_cell_for(config_path: Path) -> dict:
    """The matrix entry that names this config (its recorded path string)."""
    resolved = Path(config_path).resolve()
    matrix = load_matrix()
    for cell in matrix["cells"]:
        if (ROOT / cell["config"]).resolve() == resolved:
            return cell
    config = _read_json(resolved, "cell config")
    return {"cell_id": config.get("cell_id", resolved.stem),
            "config": str(resolved)}


def load_cell_config(config_path: Path) -> dict:
    """Load a cell config and merge the base profile it declares."""
    path = Path(config_path)
    config = _read_json(path, "cell config")
    base_path = config.get("base_profile")
    if base_path:
        base = _read_json(ROOT / base_path, "cell base profile")
        merged = copy.deepcopy(base)
        merged["cell_id"] = config.get("cell_id", merged.get("cell_id"))
        merged["families"] = list(config.get("families", base.get("families", [])))
        merged["peripherals"] = copy.deepcopy(config["peripherals"])
        merged["base_profile_config"] = base_path
        merged["matrix_cell"] = config
        return merged
    return config


def _closure_parameters(closure_path: str) -> dict:
    document = _read_json(ROOT / closure_path, "peripheral closure")
    return {item["name"]: item["value"] for item in document.get("parameters", [])
            if item["name"].isidentifier()}


def peripheral_records(config: dict) -> list:
    """Normalise the cell config's peripheral declarations into full records."""
    records = []
    for entry in config["peripherals"]:
        if isinstance(entry, dict):
            facts = PERIPHERAL_FACTS[entry["source_lock"]]
            record = copy.deepcopy(facts)
            record.update(copy.deepcopy(entry))
            record.setdefault("id", entry["source_lock"])
            record.setdefault("closure", "%s/%s.json" % (CLOSURE_DIR, record["source_lock"]))
            record.setdefault("runtime_status", "runtime_unverified")
            records.append(record)
            continue
        facts = copy.deepcopy(PERIPHERAL_FACTS[entry])
        facts["id"] = entry
        facts["closure"] = "%s/%s.json" % (CLOSURE_DIR, facts["source_lock"])
        facts["runtime_status"] = "runtime_unverified"
        facts["parameters"] = _closure_parameters(facts["closure"])
        records.append(facts)
    return records


def _evidence(record: dict) -> dict:
    """Evidence keyed by capability fact (the shape soc_plan records)."""
    return {
        fact: {"topic": record["evidence_topics"][fact],
               "evidence_path": record["closure"], "provenance": "rtl_read"}
        for fact in sorted(record["capabilities"])
    }


def build_spec(cell: dict, config: dict, records: list) -> dict:
    cpu = config["cpu"]
    cpu_lock = cpu["source_lock"]
    width = 64 if cpu["xlen"] == 64 else 32
    address_width = width
    is_unified = list(cpu["protocol"])[0] == "axi4"

    components = [{
        "component_id": "cpu",
        "kind": "cpu",
        "source_lock": cpu_lock,
        "top_module": cpu["top_module"],
        "clock_domain": "core",
        "reset_domain": "cpu_rst",
        "instances": [{"instance_id": "cpu0",
                       "parameters": dict(cpu.get("parameters", {}))}],
        "capability_evidence": {"isa": "rv%d" % cpu["xlen"],
                                "provenance": cpu.get("source_provenance", cell["config"])},
    }]
    for region in config["memory_regions"]:
        component_id = region["region_id"]
        components.append({
            "component_id": component_id,
            "kind": "memory",
            "source_lock": "soc_%s_model" % ("rom" if not region["permissions"]["write"] else "ram"),
            "top_module": "riscv_boot_memory_%d" % width,
            "clock_domain": "core",
            "reset_domain": "sys_rst",
            "instances": [{"instance_id": component_id,
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
        "instances": [{"instance_id": "harness0", "parameters": {"CYCLES": 100000}}],
        "capability_evidence": {"model": "clock/reset/environment harness",
                                "provenance": "P7"},
    })

    masters = []
    if is_unified:
        masters.append({
            "source_id": "cpu_unified", "kind": "cpu_unified", "component_id": "cpu",
            "port": "noc", "protocol": list(cpu["protocol"]), "data_width": width,
            "address_width": address_width, "test_modes": ["cpu_only", "mixed"],
        })
    else:
        masters.append({
            "source_id": "cpu_ifetch", "kind": "cpu_instruction", "component_id": "cpu",
            "port": "instr", "protocol": list(cpu["protocol"]), "data_width": width,
            "address_width": address_width, "test_modes": ["cpu_only", "mixed"],
        })
        masters.append({
            "source_id": "cpu_data", "kind": "cpu_data", "component_id": "cpu",
            "port": "data", "protocol": list(cpu["protocol"]), "data_width": width,
            "address_width": address_width, "test_modes": ["cpu_only", "mixed"],
        })
    masters.append({
        "source_id": "fuzz_mmio", "kind": "fuzz_mmio", "component_id": "harness",
        "port": "mmio", "protocol": ["processor-memory-beat", "1"],
        "data_width": width, "address_width": address_width,
        "test_modes": ["mmio_only", "mixed"],
    })

    memory_targets = []
    for region in config["memory_regions"]:
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
        "target_id": record.get("target_id", "%s_win" % record["id"]),
        "component_id": record["id"],
        "port": record["protocol"][0],
        "protocol": list(record["protocol"]),
        "window": copy.deepcopy(record["window"]),
        "request_sources": list(mmio_sources),
        "response_owner": "soc_fabric",
        # The planner's byte_enable flag means "this target really accepts
        # partial byte writes"; an IP with a sel pin but register-specific
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
                           cpu_lock} | {record["source_lock"] for record in records})
    return {
        "schema_version": "soc_spec.v1",
        "spec_id": config.get("cell_id", cell["cell_id"]),
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
        } for region in config["memory_regions"]],
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
            "limits": {"build_timeout_s": 600, "run_timeout_s": 120,
                       "rss_limit_mb": 2048, "cycles_per_sample": 100000},
        },
        "assumptions": [{
            "assumption_id": "single_runtime_clock",
            "statement": "Every selected IP runs on the single runtime clock domain.",
            "provenance": records[0]["closure"] if records else cell["config"],
        }],
        "provenance": {
            "render_config": cell["config"],
            "cell": config.get("cell_id", cell["cell_id"]),
            "closures": CLOSURE_DIR,
            "sources": "configs/soc/sources.lock.json",
        },
    }


def build_execution(cpu: dict) -> dict:
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
        "execution_hash": "sha256:" + "b" * 64,
    }


def build_contracts(records: list, config: dict, width: int) -> list:
    contracts = []
    for region in config["memory_regions"]:
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
        target_id = record.get("target_id", "%s_win" % record["id"])
        try:
            resolved = resolve_target_adapter(
                {"protocol": "processor-memory-beat", "version": "1",
                 "address_width": width, "data_width": 32},
                {
                    "component_id": record["id"], "target_id": target_id,
                    "protocol": list(record["protocol"]),
                    "version": record["protocol"][1],
                    "data_width": record["data_width"],
                    "window": copy.deepcopy(record["window"]),
                    "capabilities": copy.deepcopy(record["capabilities"]),
                    "evidence": _evidence(record),
                },
            )
        except ValueError as error:
            raise SocMatrixSmokeError(
                "target adapter could not be resolved for %s: %s"
                % (record["id"], error)) from error
        # The P3 planner turns a target's declared read/write capability into
        # the router's window permissions.  Every pinned peripheral implements
        # both a read and a write path (the adapters reject only unsupported
        # *shapes* such as partial writes), so the runtime plan declares them;
        # without this every MMIO window would be decoded as read/write=false
        # and the router would answer error without touching the real IP.
        capabilities = copy.deepcopy(record["capabilities"])
        capabilities["read"] = True
        capabilities["write"] = True
        topics = PERIPHERAL_RW_TOPICS.get(record["source_lock"])
        if topics is None:
            raise SocMatrixSmokeError(
                "%s: no read/write evidence topic recorded for %s"
                % (record["id"], record["source_lock"]))
        evidence = _evidence(record)
        evidence["read"] = {"topic": topics[0], "evidence_path": record["closure"],
                            "provenance": "rtl_read"}
        evidence["write"] = {"topic": topics[1], "evidence_path": record["closure"],
                             "provenance": "rtl_read"}
        contracts.append({
            "target_id": target_id,
            "component_id": record["id"],
            "port": record["protocol"][0],
            "protocol": list(record["protocol"]),
            "adapter_module": resolved["rtl_module"],
            "adapter_source": resolved["rtl_source"],
            # data_width stays a declared target fact (soc_spec target), not a
            # capability fact: the P5 resolver reads it from the target record.
            "capabilities": capabilities,
            "evidence": evidence,
        })
    return contracts


def _sorted_windows(plan: dict) -> list:
    return sorted(plan["address_map"]["windows"],
                  key=lambda item: (item["window"]["base"], item["target_id"]))


def _resolve_target(plan: dict, records: list, stimulus: dict) -> dict:
    """The first writable MMIO window of the plan plus its register program."""
    by_component = {record["id"]: record for record in records}
    for window in _sorted_windows(plan):
        component = window.get("component_id")
        if component not in by_component:
            continue                      # RAM/ROM windows are not MMIO targets
        record = by_component[component]
        program = PERIPHERAL_PROGRAMS.get(record["source_lock"])
        if program is None:
            raise SocMatrixSmokeError(
                "%s: no directed register program for the first writable MMIO "
                "target %s (source lock %s)"
                % (plan["plan_id"], record["id"], record["source_lock"]))
        if "fuzz_mmio" not in list(window.get("request_sources", [])):
            raise SocMatrixSmokeError(
                "%s: first writable MMIO target %s is not reachable from the "
                "synthetic fuzz_mmio master" % (plan["plan_id"], record["id"]))
        projection = stimulus["rtl_projection"]["parameters"]
        bases = list(projection["WINDOW_BASE"])
        base = int(window["window"]["base"])
        if base not in bases:
            raise SocMatrixSmokeError(
                "%s: stimulus window table does not expose the plan window 0x%x"
                % (plan["plan_id"], base))
        probe = int(program["probe_value"])
        expected = program["readback_expected"]
        expected = probe if expected == "$probe" else expected
        ops = []
        readback_offset = None
        probe_offset = None
        for kind, offset, value in program["ops"]:
            if kind == "write":
                if value == "$probe":
                    probe_offset = int(offset)
                ops.append({"kind": "write", "offset": int(offset),
                            "value": probe if value == "$probe" else int(value)})
            else:
                ops.append({"kind": "read", "offset": int(offset), "value": None})
                readback_offset = int(offset)
        if probe_offset is None:
            raise SocMatrixSmokeError(
                "%s: the register program for %s never writes the probe value"
                % (plan["plan_id"], record["id"]))
        return {
            "peripheral_id": record["id"],
            "source_lock": record["source_lock"],
            "top_module": record["top_module"],
            "window_target_id": window["target_id"],
            "window_base": base,
            "window_size": int(window["window"]["size"]),
            "window_index": bases.index(base),
            "probe_offset": int(probe_offset),
            "probe_value": probe,
            "readback_offset": readback_offset,
            "readback_expected": expected,
            "side_effect": program["side_effect"],
            "side_effect_key": "side_effect",
            "side_effect_pattern": program.get("side_effect_pattern"),
            "observations": list(program["observations"]),
            "ops": ops,
            "evidence": list(program["evidence"]),
        }
    raise SocMatrixSmokeError(
        "%s: no writable MMIO target window is declared" % plan["plan_id"])


def _lane_place(value: int, byte_offset: int, width: int):
    """Place a 32-bit word in the beat lane the address selects."""
    value &= 0xFFFF_FFFF
    if width <= 32:
        return value, 0xF
    lane = (byte_offset >> 2) & 1
    return (value << (32 * lane)) & 0xFFFF_FFFF_FFFF_FFFF, 0x0F << (4 * lane)


def cell_documents(config_path, mode: str) -> dict:
    """Build the plan, stimulus, target and generated program for one cell."""
    if mode not in MODES:
        raise ValueError("unsupported mode %r" % (mode,))
    path = Path(config_path)
    if not path.is_absolute():
        path = ROOT / path
    if not path.is_file():
        raise SocMatrixSmokeError("cell config is missing: %s" % path)
    cell = _matrix_cell_for(path)
    config = load_cell_config(path)
    records = peripheral_records(config)
    spec = build_spec(cell, config, records)
    spec["provenance"]["render_config"] = cell["config"]
    width = 64 if config["cpu"]["xlen"] == 64 else 32
    plan = build_soc_plan(spec, build_execution(config["cpu"]),
                          build_contracts(records, config, width))
    stimulus = compile_soc_stimulus(plan, {"mode": mode, "address_strategy": "biased"})
    target = _resolve_target(plan, records, stimulus)
    ram = _ram_region(config)
    peripherals = [{"id": record["id"],
                    "observations": list(PERIPHERAL_PROGRAMS.get(
                        record["source_lock"], {}).get("observations", ()))}
                   for record in records]
    documents = {
        "schema_version": SMOKE_SCHEMA,
        "config_path": str(path),
        "cell_id": config.get("cell_id", path.stem),
        "config": config,
        "records": records,
        "spec": spec,
        "plan": plan,
        "stimulus": stimulus,
        "mode": mode,
        "plan_hash": stimulus["plan_hash"],
        "layout_hash": stimulus["layout_hash"],
        "width": width,
        "address_width": int(stimulus["rtl_projection"]["parameters"]["ADDRESS_WIDTH"]),
        "selector_width": int(stimulus["rtl_projection"]["parameters"]["SELECTOR_WIDTH"]),
        "target": target,
        "ram": ram,
        "peripherals": peripherals,
        "cpu_source_ids": _source_ids(plan, ("cpu_instruction", "cpu_data", "cpu_unified")),
        "cpu_source_id": _source_ids(plan, ("cpu_instruction", "cpu_data", "cpu_unified"))[0],
        "fuzz_source_ids": _source_ids(plan, ("fuzz_mmio",)),
        "fuzz_source_id": _source_ids(plan, ("fuzz_mmio",))[0],
    }
    documents["program"] = _build_program(documents)
    documents["fuzz_ops"] = _fuzz_ops(documents)
    return documents


def _ram_region(config: dict) -> dict:
    for region in config["memory_regions"]:
        if region["permissions"]["write"]:
            return {"region_id": region["region_id"],
                    "base": int(region["base"]), "size": int(region["size"]),
                    "physical_memory_id": region["physical_memory_id"]}
    raise SocMatrixSmokeError("%s: no writable memory region for the RAM record"
                              % config.get("cell_id"))


def _source_ids(plan: dict, kinds) -> list:
    ids = sorted(int(source["index"]) for source in plan["fabric"]["sources"]
                 if source.get("kind") in kinds)
    if not ids:
        raise SocMatrixSmokeError("%s: no fabric source of kind %r"
                                  % (plan.get("plan_id"), tuple(kinds)))
    if ids != list(range(ids[0], ids[-1] + 1)):
        raise SocMatrixSmokeError(
            "%s: fabric source indexes for %r are not contiguous: %s"
            % (plan.get("plan_id"), tuple(kinds), ids))
    return ids


def _fuzz_ops(documents: dict) -> list:
    """The synthetic master's program: the same operations as the CPU's."""
    target = documents["target"]
    width = documents["width"]
    ops = []
    for op in target["ops"]:
        data, be = _lane_place(op["value"] or 0, op["offset"], width)
        ops.append({"selector": target["window_index"], "offset": op["offset"],
                    "write": 1 if op["kind"] == "write" else 0,
                    "data": data, "be": be})
    return ops



# ---------------------------------------------------------------------------
# deterministic boot program (RV32I / RV64I, no compressed encodings)
# ---------------------------------------------------------------------------


def _enc_u(imm20: int, rd: int, opcode: int) -> int:
    return ((imm20 & 0xFFFFF) << 12) | ((rd & 0x1F) << 7) | opcode


def _enc_i(imm: int, rs1: int, funct3: int, rd: int, opcode: int) -> int:
    return ((imm & 0xFFF) << 20) | ((rs1 & 0x1F) << 15) | (funct3 << 12) \
        | ((rd & 0x1F) << 7) | opcode


def _enc_s(imm: int, rs2: int, rs1: int, funct3: int, opcode: int) -> int:
    value = imm & 0xFFF
    return (((value >> 5) & 0x7F) << 25) | ((rs2 & 0x1F) << 20) | ((rs1 & 0x1F) << 15) \
        | (funct3 << 12) | ((value & 0x1F) << 7) | opcode


def _enc_b(imm: int, rs2: int, rs1: int, funct3: int, opcode: int) -> int:
    value = imm & 0x1FFF
    return (((value >> 12) & 1) << 31) | (((value >> 5) & 0x3F) << 25) \
        | ((rs2 & 0x1F) << 20) | ((rs1 & 0x1F) << 15) | (funct3 << 12) \
        | (((value >> 1) & 0xF) << 8) | (((value >> 11) & 1) << 7) | opcode


def _enc_j(imm: int, rd: int, opcode: int) -> int:
    value = imm & 0x1FFFFF
    return (((value >> 20) & 1) << 31) | (((value >> 1) & 0x3FF) << 21) \
        | (((value >> 11) & 1) << 20) | (((value >> 12) & 0xFF) << 12) \
        | ((rd & 0x1F) << 7) | opcode


class _Assembler:
    """Two-pass 32-bit RV32I/RV64I assembler (no compressed encodings)."""

    def __init__(self, xlen: int):
        self.xlen = xlen
        self.items: list = []
        self.labels: dict = {}
        self.notes: dict = {}

    # -- structure ---------------------------------------------------------

    def label(self, name: str) -> None:
        self.labels[name] = len(self.items)

    def comment(self, text: str) -> None:
        self.notes[len(self.items)] = text

    def _add(self, text: str, *, word=None, kind="plain", rs1=None, rs2=None,
             funct3=None, label=None, rd=None) -> None:
        self.items.append({"text": text, "word": word, "kind": kind, "rs1": rs1,
                           "rs2": rs2, "funct3": funct3, "label": label, "rd": rd})

    # -- instructions ------------------------------------------------------

    def addi(self, rd: int, rs1: int, imm: int) -> None:
        self._add("addi x%d, x%d, %d" % (rd, rs1, imm),
                  word=_enc_i(imm, rs1, 0, rd, 0x13))

    def lui(self, rd: int, imm20: int) -> None:
        self._add("lui x%d, 0x%x" % (rd, imm20 & 0xFFFFF),
                  word=_enc_u(imm20, rd, 0x37))

    def sw(self, rs2: int, rs1: int, imm: int) -> None:
        self._add("sw x%d, %d(x%d)" % (rs2, imm, rs1),
                  word=_enc_s(imm, rs2, rs1, 0b010, 0x23))

    def lw(self, rd: int, rs1: int, imm: int) -> None:
        self._add("lw x%d, %d(x%d)" % (rd, imm, rs1),
                  word=_enc_i(imm, rs1, 0b010, rd, 0x03))

    def slli(self, rd: int, rs1: int, shamt: int) -> None:
        self._add("slli x%d, x%d, %d" % (rd, rs1, shamt),
                  word=_enc_i(shamt, rs1, 0b001, rd, 0x13))

    def srli(self, rd: int, rs1: int, shamt: int) -> None:
        self._add("srli x%d, x%d, %d" % (rd, rs1, shamt),
                  word=_enc_i(shamt, rs1, 0b101, rd, 0x13))

    def beq(self, rs1: int, rs2: int, label: str) -> None:
        self._add("beq x%d, x%d, %s" % (rs1, rs2, label), kind="branch",
                  rs1=rs1, rs2=rs2, funct3=0b000, label=label)

    def jal(self, rd: int, label: str) -> None:
        self._add("jal x%d, %s" % (rd, label), kind="jal", rd=rd, label=label)

    def li32(self, rd: int, value: int) -> None:
        """Materialise a 32-bit constant, zero-extended on RV64."""
        value &= 0xFFFF_FFFF
        signed = value - 0x1_0000_0000 if value & 0x8000_0000 else value
        if -2048 <= signed <= 2047:
            self.addi(rd, 0, signed)
        else:
            hi = ((value + 0x800) >> 12) & 0xFFFFF
            self.lui(rd, hi)
            self.addi(rd, rd, value - (hi << 12))
        if self.xlen == 64 and (value & 0x8000_0000):
            # lui sign-extends on RV64; keep the address zero-extended so it
            # matches the plan's 64-bit window bases.
            self.slli(rd, rd, 32)
            self.srli(rd, rd, 32)

    # -- output ------------------------------------------------------------

    def assemble(self) -> list:
        words = []
        for index, item in enumerate(self.items):
            if item["kind"] == "plain":
                words.append(item["word"] & 0xFFFF_FFFF)
                continue
            target = self.labels[item["label"]]
            offset = (target - index) * 4
            if item["kind"] == "branch":
                words.append(_enc_b(offset, item["rs2"], item["rs1"],
                                    item["funct3"], 0x63))
            else:
                words.append(_enc_j(offset, item["rd"], 0x6F))
        return words

    def listing(self, base_address: int) -> list:
        words = self.assemble()
        lines = []
        for index, item in enumerate(self.items):
            for name, position in self.labels.items():
                if position == index:
                    lines.append("%08x  %-34s %s:" % (base_address + index * 4, "",
                                                      name))
            note = self.notes.get(index)
            if note:
                lines.append("%08x  %-34s # %s" % (base_address + index * 4, "",
                                                   note))
            lines.append("%08x  %08x  %s"
                         % (base_address + index * 4, words[index], item["text"]))
        for name, position in self.labels.items():
            if position >= len(self.items):
                lines.append("%08x  %-34s %s:" % (base_address + position * 4, "",
                                                  name))
        return lines


def _build_program(documents: dict) -> dict:
    """Generate the directed boot program from the plan's address map."""
    xlen = documents["width"]
    target = documents["target"]
    ram = documents["ram"]
    asm = _Assembler(xlen)

    asm.comment("x10 = first writable MMIO window base 0x%08x (%s)"
                % (target["window_base"], target["window_target_id"]))
    asm.li32(10, target["window_base"])
    asm.comment("x11 = writable RAM region base 0x%08x" % ram["base"])
    asm.li32(11, ram["base"])
    asm.comment("x12 = recognisable probe value 0x%08x" % target["probe_value"])
    asm.li32(12, target["probe_value"])
    asm.label("_start")
    for op in target["ops"]:
        if op["kind"] == "write":
            asm.comment("write 0x%08x <- 0x%08x" % (op["offset"], op["value"]))
            asm.li32(16, op["value"])
            asm.sw(16, 10, op["offset"])
        else:
            asm.comment("read 0x%08x -> x13 (real IP register)" % op["offset"])
            asm.lw(13, 10, op["offset"])
            if xlen == 64:
                # lw sign-extends on RV64, while li32 materialises the expected
                # value zero-extended.  Without this the comparison fails for
                # every probe value whose bit 31 is set, and the run reports a
                # mismatch even though the real IP returned the right word.
                asm.slli(13, 13, 32)
                asm.srli(13, 13, 32)
    expected = target["readback_expected"]
    if expected is not None:
        asm.comment("completion flag: 0x%08x match / 0x%08x mismatch"
                    % (FLAG_OK, FLAG_MISMATCH))
        asm.li32(15, expected)
        asm.li32(14, FLAG_MISMATCH)
        asm.beq(13, 15, "flag_ok")
        asm.jal(0, "store_flag")
        asm.label("flag_ok")
        asm.li32(14, FLAG_OK)
        asm.label("store_flag")
    else:
        asm.comment("completion flag: 0x%08x (read-back is a running counter)"
                    % FLAG_OK)
        asm.li32(14, FLAG_OK)
    asm.comment("RAM record: flag @ +0x%x, read-back @ +0x%x"
                % (FLAG_OFFSET, READBACK_OFFSET))
    asm.sw(14, 11, FLAG_OFFSET)
    asm.sw(13, 11, READBACK_OFFSET)
    asm.label("spin")
    asm.jal(0, "spin")

    words = asm.assemble()
    # Entry trampoline: the pinned Ibex PC_BOOT vector is
    # {boot_addr_i[31:8], 8'h80} (ibex_if_stage.sv:243), while CVA6 starts
    # fetching at boot_addr_i itself.  A jump at offset 0 and the program at
    # offset 0x80 therefore enter the same program on both CPUs without any
    # per-CPU branch; the reset vector stays the region base the plan declares.
    trampoline = _enc_j(ENTRY_OFFSET, 0, 0x6F)
    entry_words = [trampoline] + [0] * (ENTRY_OFFSET // 4 - 1)
    words = entry_words + words
    body = "".join("%08x\n" % word for word in words)
    image = "".join("%02x\n" % byte
                    for word in words
                    for byte in (word & 0xFF, (word >> 8) & 0xFF,
                                 (word >> 16) & 0xFF, (word >> 24) & 0xFF))
    base = int(documents["config"]["cpu"]["reset_vector"])
    header = [
        "# myfuzz P12 generated cell boot program (RV%dI, no compressed "
        "encodings)" % xlen,
        "# cell: %s   mode: %s" % (documents["cell_id"], documents["mode"]),
        "# MMIO probe window: %s (%s) base 0x%08x size 0x%x, ops %d"
        % (target["window_target_id"], target["peripheral_id"],
           target["window_base"], target["window_size"], len(target["ops"])),
        "# register program evidence:",
    ]
    header.extend("#   %s" % item for item in target["evidence"])
    header.append("# RAM: %s base 0x%08x; flag @ 0x%08x, read-back @ 0x%08x"
                  % (ram["region_id"], ram["base"], ram["base"] + FLAG_OFFSET,
                     ram["base"] + READBACK_OFFSET))
    header.append("# image base address 0x%08x (CPU reset vector)" % base)
    entry = [
        "%08x  %08x  jal x0, +0x%x   (entry trampoline)" % (base, trampoline,
                                                            ENTRY_OFFSET),
        "%08x  %-34s # 0x0 padding to the 0x%x entry the pinned CPUs fetch"
        % (base + 4, "", ENTRY_OFFSET),
    ]
    assembly = "\n".join(header + entry + asm.listing(base + ENTRY_OFFSET)) + "\n"
    return {
        "assembly": assembly,
        "listing": asm.listing(base),
        "words": len(words),
        "hex": image,
        "word_hex": body,
        "program_hash": content_hash({"assembly": assembly, "hex": image}),
        "base_address": base,
        "flag_address": ram["base"] + FLAG_OFFSET,
        "readback_address": ram["base"] + READBACK_OFFSET,
    }



# ---------------------------------------------------------------------------
# generated testbench
# ---------------------------------------------------------------------------


def _parse_ports(top_text: str) -> list:
    header = top_text.split("\n);", 1)[0]
    ports = [(direction, name)
             for direction, _width, name in _PORT_DECLARATION.findall(header)]
    if not ports:
        raise SocMatrixSmokeError("could not parse a port list from the rendered top")
    return ports


def _memory_index(top_text: str, backing_id: str) -> int:
    """The u_mem_<n> instance index the renderer emitted for a region."""
    pending = None
    for line in top_text.splitlines():
        marker = _MEMORY_TARGET.search(line)
        if marker:
            pending = marker.group(1)
            continue
        if pending is None:
            continue
        found = _MEMORY_INSTANCE_LINE.search(line)
        if found:
            if pending == backing_id:
                return int(found.group(1))
            pending = None
    raise SocMatrixSmokeError(
        "rendered top has no memory instance for region %s" % backing_id)


def validate_top_requirements(top_text: str, *, ports=(), wires=()) -> None:
    """Fail closed naming every missing port or internal wire."""
    header = top_text.split("\n);", 1)[0]
    declared = {name for _direction, _width, name in _PORT_DECLARATION.findall(header)}
    missing_ports = [name for name in ports if name not in declared]
    missing_wires = [name for name in wires
                     if not re.search(r"\b%s\b" % re.escape(name), top_text)]
    if missing_ports or missing_wires:
        raise SocMatrixSmokeError(
            "rendered %s is missing: ports %s; internal wires %s"
            % (RUNTIME_TOP, missing_ports, missing_wires))


def normalize_memory_parameters(top_text: str) -> tuple:
    """Rewrite riscv_boot_memory_* BASE_ADDR overrides as sized literals.

    Verilator 5.051 sign-extends an unsized decimal literal above 2**31-1 when
    it is passed as a parameter override for the 'longint BASE_ADDR' of
    riscv_boot_memory_64, so the rendered
    'riscv_boot_memory_64 #(.BASE_ADDR(2147483648))' decodes every address as
    outside the region and answers error for the CVA6 reset vector.  The
    rewrite keeps the exact value and changes only the literal form; it is
    fail-closed (restoring the original literals must reproduce the rendered
    document byte for byte) and every rewrite is recorded in the run identity.
    """
    records: list = []
    lines = []
    for line in top_text.splitlines():
        match = _MEMORY_INSTANTIATION_LINE.match(line)
        if match:
            width = int(match.group("width"))
            index = int(match.group("index"))

            def replace(item, width=width, index=index):
                raw = item.group("value").strip()
                if not raw.isdigit():
                    return item.group(0)
                value = int(raw)
                if width != 64 or value < 2 ** 31:
                    return item.group(0)
                sized = "%d'h%016x" % (width, value)
                records.append({"module": "riscv_boot_memory_%d" % width,
                                "instance": "u_mem_%d" % index,
                                "parameter": "BASE_ADDR", "decimal": raw,
                                "sized": sized, "value": value})
                return ".BASE_ADDR(%s)" % sized

            line = _BASE_ADDR_OVERRIDE.sub(replace, line)
        lines.append(line)
    normalized = "\n".join(lines) + ("\n" if top_text.endswith("\n") else "")
    restored = normalized
    for record in records:
        restored = restored.replace(".BASE_ADDR(%s)" % record["sized"],
                                    ".BASE_ADDR(%s)" % record["decimal"])
    if restored != top_text:
        raise SocMatrixSmokeError(
            "memory parameter normalization changed more than the BASE_ADDR "
            "literal of the rendered top")
    return normalized, records


def _observation_wires(documents: dict) -> list:
    wires = []
    for peripheral in documents["peripherals"]:
        for name in peripheral["observations"]:
            suffix = OBSERVATION_SIGNALS[name][0]
            wires.append("%s_%s" % (peripheral["id"], suffix))
    return wires


def _edge_counter(identifier: str, observation: str) -> str:
    """The generated transition counter for an "edges" observation."""
    return "obs_%s_%s_edges" % (identifier, observation)


def _side_effect(documents: dict):
    """(observation expression, printf format) for the directed target."""
    target = documents["target"]
    identifier = target["peripheral_id"]
    kind = target["side_effect"]
    if kind == "gpio_out_register":
        return "dut.%s_obs_gpio_out" % identifier, "0x%08x"
    if kind == "uart_tx_activity":
        return _edge_counter(identifier, "uart_tx"), "%0d"
    if kind == "spi_activity":
        return _edge_counter(identifier, "spi_clk"), "%0d"
    if kind in ("timer_readback", "register_write_readback"):
        return "(MODE == 0) ? window_rdata_cpu[31:0] : window_rdata_fuzz[31:0]", "0x%08x"
    raise SocMatrixSmokeError("unknown side effect %r for %s" % (kind, identifier))


def _side_effect_check(documents: dict) -> str:
    target = documents["target"]
    identifier = target["peripheral_id"]
    kind = target["side_effect"]
    if kind == "gpio_out_register":
        return ('      if (dut.' + identifier + '_obs_gpio_out !== PROBE_VALUE) begin\n'
                '        failures = failures + 1;\n'
                '        $display("MYFUZZ_SOC_MATRIX_CHECK ' + identifier
                + '_gpio_out=0x%08x expected=0x%08x", dut.' + identifier
                + '_obs_gpio_out, PROBE_VALUE);\n'
                '      end')
    if kind == "uart_tx_activity":
        counter = _edge_counter(identifier, "uart_tx")
        return ('      if (' + counter + ' < 2) begin\n'
                '        failures = failures + 1;\n'
                '        $display("MYFUZZ_SOC_MATRIX_CHECK ' + identifier
                + '_uart_tx_edges=%0d", ' + counter + ');\n'
                '      end')
    if kind == "spi_activity":
        counter = _edge_counter(identifier, "spi_clk")
        return ('      if (' + counter + ' < 2) begin\n'
                '        failures = failures + 1;\n'
                '        $display("MYFUZZ_SOC_MATRIX_CHECK ' + identifier
                + '_spi_clk_edges=%0d", ' + counter + ');\n'
                '      end')
    if kind == "timer_readback":
        return ('      if (MODE == 0) begin\n'
                '        if (!(window_rdata_cpu[31:0] > 0 && window_rdata_cpu[31:0] <= PROBE_VALUE)) begin\n'
                '          failures = failures + 1;\n'
                '          $display("MYFUZZ_SOC_MATRIX_CHECK ' + identifier
                + '_readback=0x%08x limit=0x%08x", window_rdata_cpu[31:0], PROBE_VALUE);\n'
                '        end\n'
                '      end else begin\n'
                '        if (!(window_rdata_fuzz[31:0] > 0 && window_rdata_fuzz[31:0] <= PROBE_VALUE)) begin\n'
                '          failures = failures + 1;\n'
                '          $display("MYFUZZ_SOC_MATRIX_CHECK ' + identifier
                + '_readback=0x%08x limit=0x%08x", window_rdata_fuzz[31:0], PROBE_VALUE);\n'
                '        end\n'
                '      end')
    if kind == "register_write_readback":
        return ('      if (MODE == 0) begin\n'
                '        if (window_rdata_cpu[31:0] !== EXPECTED_READBACK) begin\n'
                '          failures = failures + 1;\n'
                '          $display("MYFUZZ_SOC_MATRIX_CHECK ' + identifier
                + '_register=0x%08x expected=0x%08x", window_rdata_cpu[31:0], EXPECTED_READBACK);\n'
                '        end\n'
                '      end else begin\n'
                '        if (window_rdata_fuzz[31:0] !== EXPECTED_READBACK) begin\n'
                '          failures = failures + 1;\n'
                '          $display("MYFUZZ_SOC_MATRIX_CHECK ' + identifier
                + '_register=0x%08x expected=0x%08x", window_rdata_fuzz[31:0], EXPECTED_READBACK);\n'
                '        end\n'
                '      end')
    raise SocMatrixSmokeError("unknown side effect %r for %s" % (kind, identifier))


def build_testbench(documents: dict, top_text: str, *,
                    cycle_budget: int = DEFAULT_CYCLE_BUDGET) -> str:
    """Generate the testbench for one cell+mode from the rendered top."""
    if not isinstance(cycle_budget, int) or cycle_budget <= 0:
        raise ValueError("cycle_budget must be a positive integer")
    cell = documents["cell_id"]
    mode = documents["mode"]
    width = documents["width"]
    address_width = documents["address_width"]
    selector_width = documents["selector_width"]
    target = documents["target"]
    ram = documents["ram"]
    ports = _parse_ports(top_text)
    port_names = [name for _direction, name in ports]
    unknown = [name for name in port_names if name not in _TOP_PORT_WIDTHS]
    if unknown:
        raise SocMatrixSmokeError(
            "generated testbench does not know the rendered top ports %s" % unknown)
    missing = [name for name in _TOP_PORT_WIDTHS if name not in port_names]
    if missing:
        raise SocMatrixSmokeError(
            "rendered %s does not declare ports %s" % (RUNTIME_TOP, missing))
    memory_index = _memory_index(top_text, ram["physical_memory_id"])
    if "u_fuzz_mmio" not in top_text:
        raise SocMatrixSmokeError(
            "rendered %s has no synthetic master instance u_fuzz_mmio" % RUNTIME_TOP)
    expected = target["readback_expected"]
    readback_lane = ((target["readback_offset"] or 0) >> 2) & 1 if width > 32 else 0
    side_expression, side_format = _side_effect(documents)
    fuzz_ops = documents["fuzz_ops"]

    lines: list = []

    def add(text: str = "") -> None:
        lines.append(text)

    add("// Generated by myfuzz.integration.soc_matrix_smoke (%s)." % SMOKE_SCHEMA)
    add("// cell %s mode %s xlen %d window 0x%08x probe 0x%08x fuzz_ops %d"
        % (cell, mode, width, target["window_base"], target["probe_value"],
           len(fuzz_ops)))
    add("`timescale 1ns/1ps")
    add("module %s;" % TESTBENCH_TOP)
    localparams = [
        ("ADDRESS_WIDTH", address_width), ("DATA_WIDTH", width),
        ("SELECTOR_WIDTH", selector_width), ("MODE", MODE_CODES[mode]),
        ("CPU_SOURCE_LO", documents["cpu_source_ids"][0]),
        ("CPU_SOURCE_HI", documents["cpu_source_ids"][-1]),
        ("FUZZ_SOURCE_LO", documents["fuzz_source_ids"][0]),
        ("FUZZ_SOURCE_HI", documents["fuzz_source_ids"][-1]),
        ("FUZZ_OPS", len(fuzz_ops)), ("CYCLE_BUDGET", cycle_budget),
        ("FLAG_OFFSET", FLAG_OFFSET), ("READBACK_OFFSET", READBACK_OFFSET),
        ("READBACK_LANE", readback_lane),
        ("HAS_READBACK_EXPECTATION", 1 if expected is not None else 0),
    ]
    for name, value in localparams:
        add("  localparam integer %s = %d;" % (name, value))
    add('  localparam string CELL = "%s";' % cell)
    add('  localparam string MODE_NAME = "%s";' % mode)
    add("  localparam [31:0] PROBE_VALUE = 32'h%08x;" % target["probe_value"])
    add("  localparam [31:0] EXPECTED_READBACK = 32'h%08x;" % (expected or 0))
    add("  localparam [31:0] FLAG_OK = 32'h%08x;" % FLAG_OK)
    add("  localparam [63:0] WINDOW_BASE = 64'h%016x;" % target["window_base"])
    add("  localparam [63:0] WINDOW_SIZE = 64'h%016x;" % target["window_size"])

    add("")
    add("  // Driven ports: the raw stimulus fields and the environment pins.")
    for name in port_names:
        width_text, direction = _TOP_PORT_WIDTHS[name]
        if direction != "input":
            continue
        if name == "clk_i":
            add("  logic clk_i = 1'b0;")
        elif name == "reset_i":
            add("  logic reset_i = 1'b1;")
        elif name == "spi_cs_i":
            add("  logic spi_cs_i = 1'b1;")
        elif width_text == "1":
            add("  logic %s = 1'b0;" % name)
        else:
            add("  logic [%s-1:0] %s = '0;" % (width_text, name))
    add("")
    add("  // Observed ports.")
    for name in port_names:
        width_text, direction = _TOP_PORT_WIDTHS[name]
        if direction != "output":
            continue
        if width_text == "1":
            add("  logic %s;" % name)
        else:
            add("  logic [%s-1:0] %s;" % (width_text, name))
    add("  integer cycles = 0;")

    add("")
    add("  always #1 clk_i = ~clk_i;")
    add("  always @(posedge clk_i) cycles = cycles + 1;")

    add("")
    add("  // Rendered source-backed top (%s)." % RUNTIME_TOP)
    add("  %s dut (" % RUNTIME_TOP)
    connections = [".%s(%s)" % (name, name) for name in port_names]
    for position, connection in enumerate(connections):
        comma = "," if position + 1 < len(connections) else ""
        add("    %s%s" % (connection, comma))
    add("  );")

    if documents["peripherals"]:
        add("")
        add("  // Real peripheral side-effect observations.")
        for peripheral in documents["peripherals"]:
            identifier = peripheral["id"]
            for name in peripheral["observations"]:
                suffix, kind = OBSERVATION_SIGNALS[name]
                wire = "dut.%s_%s" % (identifier, suffix)
                if kind == "level":
                    continue
                add("  logic [63:0] obs_%s_%s_edges;" % (identifier, name))
                add("  logic obs_%s_%s_prev;" % (identifier, name))
                add("  always_ff @(posedge clk_i) begin")
                add("    if (reset_i) begin")
                add("      obs_%s_%s_prev <= 1'b0;" % (identifier, name))
                add("      obs_%s_%s_edges <= 64'd0;" % (identifier, name))
                add("    end else begin")
                add("      obs_%s_%s_prev <= %s;" % (identifier, name, wire))
                add("      if (%s != obs_%s_%s_prev)" % (wire, identifier, name))
                add("        obs_%s_%s_edges <= obs_%s_%s_edges + 64'd1;"
                    % (identifier, name, identifier, name))
                add("    end")
                add("  end")

    add("")
    add("  // Transaction source attribution at the fabric boundary.")
    add("  wire [ADDRESS_WIDTH-1:0] fabric_addr_w = dut.fabric_addr;")
    add("  wire window_hit = (fabric_addr_w >= WINDOW_BASE[ADDRESS_WIDTH-1:0]) &&")
    add("                    ((fabric_addr_w - WINDOW_BASE[ADDRESS_WIDTH-1:0]) <")
    add("                     WINDOW_SIZE[ADDRESS_WIDTH-1:0]);")
    add("  logic window_req_hit;")
    # The recorded read-back is the register READ, not whatever window
    # transaction happened to finish last: CVA6 defers its stores, so its last
    # window transaction can be the write that follows the read.
    add("  logic window_req_write;")
    add("  logic [31:0] window_done_cpu, window_done_fuzz;")
    add("  logic [63:0] window_rdata_cpu, window_rdata_fuzz;")
    add("  logic [7:0] window_src_cpu, window_src_fuzz;")
    add("  logic window_error_seen;")
    add("  logic [ADDRESS_WIDTH-1:0] window_last_addr;")
    add("  always_ff @(posedge clk_i or posedge reset_i) begin")
    add("    if (reset_i) begin")
    add("      window_req_hit <= 1'b0;")
    add("      window_req_write <= 1'b0;")
    add("      window_done_cpu <= 32'd0;")
    add("      window_done_fuzz <= 32'd0;")
    add("      window_rdata_cpu <= 64'd0;")
    add("      window_rdata_fuzz <= 64'd0;")
    add("      window_src_cpu <= 8'd0;")
    add("      window_src_fuzz <= 8'd0;")
    add("      window_error_seen <= 1'b0;")
    add("      window_last_addr <= '0;")
    add("    end else begin")
    add("      if (dut.fabric_req_valid && dut.fabric_req_ready) begin")
    add("        window_req_hit <= window_hit;")
    add("        window_req_write <= dut.fabric_write;")
    add("        if (window_hit) window_last_addr <= dut.fabric_addr;")
    add("      end")
    add("      if (dut.fabric_rsp_valid && dut.fabric_rsp_ready && window_req_hit")
    add("          && dut.fabric_error)")
    add("        window_error_seen <= 1'b1;")
    add("      if (dut.fabric_rsp_valid && dut.fabric_rsp_ready && window_req_hit) begin")
    add("        if ((dut.fabric_rsp_source_id >= CPU_SOURCE_LO[7:0]) &&")
    add("            (dut.fabric_rsp_source_id <= CPU_SOURCE_HI[7:0])) begin")
    add("          window_done_cpu <= window_done_cpu + 32'd1;")
    add("          if (!window_req_write) window_rdata_cpu <= dut.fabric_rdata;")
    add("          window_src_cpu <= dut.fabric_rsp_source_id;")
    add("        end else if ((dut.fabric_rsp_source_id >= FUZZ_SOURCE_LO[7:0]) &&")
    add("                     (dut.fabric_rsp_source_id <= FUZZ_SOURCE_HI[7:0])) begin")
    add("          window_done_fuzz <= window_done_fuzz + 32'd1;")
    add("          if (!window_req_write) window_rdata_fuzz <= dut.fabric_rdata;")
    add("          window_src_fuzz <= dut.fabric_rsp_source_id;")
    add("        end else begin")
    add('          print_line("FAIL");')
    add("          $fatal(1, \"window response attributed to undeclared source id %0d\",")
    add("                 dut.fabric_rsp_source_id);")
    add("        end")
    add("      end")
    add("    end")
    add("  end")

    add("")
    add("  // CPU record written by the generated boot program.")
    add("  function automatic [31:0] ram_word(input integer offset);")
    add("    ram_word = {dut.u_mem_%d.memory[offset+3], dut.u_mem_%d.memory[offset+2],"
        % (memory_index, memory_index))
    add("                dut.u_mem_%d.memory[offset+1], dut.u_mem_%d.memory[offset]};"
        % (memory_index, memory_index))
    add("  endfunction")

    add("")
    add("  // One machine-readable observation line per run.")
    tokens = [
        ("cycles", "%0d", "cycles"),
        ("cpu_tx", "%0d", "dut.cpu_transaction_count_o"),
        ("cpu_done", "%0d", "dut.cpu_completion_count_o"),
        ("fuzz_tx", "%0d", "dut.fuzz_transaction_count_o"),
        ("fuzz_done", "%0d", "dut.fuzz_completion_count_o"),
        ("fuzz_dropped", "%0d", "dut.u_fuzz_mmio.busy_drop_count"),
        ("window_done_cpu", "%0d", "window_done_cpu"),
        ("window_done_fuzz", "%0d", "window_done_fuzz"),
        ("window_src_cpu", "%0d", "window_src_cpu"),
        ("window_src_fuzz", "%0d", "window_src_fuzz"),
        ("cpu_source_id", "%0d", "CPU_SOURCE_LO"),
        ("fuzz_source_id", "%0d", "FUZZ_SOURCE_LO"),
        ("cpu_source_hi", "%0d", "CPU_SOURCE_HI"),
        ("fuzz_source_hi", "%0d", "FUZZ_SOURCE_HI"),
        ("window_rdata_cpu", "0x%016x", "window_rdata_cpu"),
        ("window_rdata_fuzz", "0x%016x", "window_rdata_fuzz"),
        ("window_error", "%0d", "window_error_seen"),
        ("window_addr", "0x%08x", "window_last_addr"),
        ("probe_beat_error", "%0d", "dut.%s_beat_error" % target["peripheral_id"]),
        ("probe_beat_rdata", "0x%08x", "dut.%s_beat_rdata" % target["peripheral_id"]),
        ("cpu_flag", "0x%08x", "ram_word(FLAG_OFFSET)"),
        ("cpu_readback", "0x%08x", "ram_word(READBACK_OFFSET)"),
        ("fuzz_rdata", "0x%08x", "(window_rdata_fuzz >> (32*READBACK_LANE))"),
        ("side_effect", side_format, side_expression),
        ("fabric_error", "%0d", "dut.fabric_protocol_error_o"),
        ("irq", "%0d", "dut.irq_o"),
        ("cpu_irq", "%0d", "dut.cpu_irq_o"),
        ("env_drop", "%0d", "dut.env_drop_count_o"),
        ("gpio_out", "0x%08x", "dut.gpio_out_o"),
        ("gpio_dir", "0x%08x", "dut.gpio_dir_o"),
        ("spi_clk", "%0d", "dut.spi_clk_o"),
        ("spi_cs0", "%0d", "dut.spi_cs0_o"),
        ("uart_rx_line", "%0d", "dut.uart_rx_o"),
    ]
    for peripheral in documents["peripherals"]:
        identifier = peripheral["id"]
        for name in peripheral["observations"]:
            suffix, kind = OBSERVATION_SIGNALS[name]
            if kind == "level":
                expression = "dut.%s_%s" % (identifier, suffix)
                fmt = "0x%08x" if name in ("gpio_out", "gpio_dir") else "%0d"
            else:
                expression = "obs_%s_%s_edges" % (identifier, name)
                fmt = "%0d"
            tokens.append(("obs_%s_%s" % (identifier, name), fmt, expression))

    format_parts = ["MYFUZZ_SOC_MATRIX_RUN", "cell=%s", "mode=%s", "status=%s"]
    arguments = ["CELL", "MODE_NAME", "status"]
    for name, fmt, expression in tokens:
        format_parts.append(name + "=" + fmt)
        arguments.append(expression)
    add("  task automatic print_line(input string status);")
    add("    begin")
    add('      $display("' + " ".join(format_parts) + '",')
    add("               " + ", ".join(arguments) + ");")
    add("    end")
    add("  endtask")

    add("")
    add("  task automatic wait_ram_word(input integer offset, input [31:0] value,")
    add("                               input string label);")
    add("    begin")
    add("      while (ram_word(offset) !== value) begin")
    add("        if (cycles >= CYCLE_BUDGET) begin")
    add('          print_line("TIMEOUT");')
    add('          $fatal(1, "%s: RAM record +%0d never became 0x%08x '
        + '(last 0x%08x, cpu_tx=%0d cpu_done=%0d gpio=0x%08x)",')
    add("                 label, offset, value, ram_word(offset),")
    add("                 dut.cpu_transaction_count_o, dut.cpu_completion_count_o,")
    add("                 dut.gpio_out_o);")
    add("        end")
    add("        @(posedge clk_i);")
    add("      end")
    add("    end")
    add("  endtask")

    add("")
    add("  // Independent synthetic MMIO transaction: latch the raw fields, hold")
    add("  // the offer across one clock and wait for the recorded completion.")
    add("  task automatic fuzz_op(input integer selector, input integer offset,")
    add("                         input bit wr, input [DATA_WIDTH-1:0] data,")
    add("                         input [DATA_WIDTH/8-1:0] be);")
    add("    integer expected;")
    add("    begin")
    add("      if (cycles >= CYCLE_BUDGET) begin")
    add('        print_line("TIMEOUT");')
    add('        $fatal(1, "cycle budget exhausted before a synthetic MMIO operation");')
    add("      end")
    add("      expected = dut.fuzz_completion_count_o + 1;")
    add("      @(negedge clk_i);")
    add("      stim_target_selector_i = selector[SELECTOR_WIDTH-1:0];")
    add("      stim_offset_i = offset[ADDRESS_WIDTH-1:0];")
    add("      stim_write_i = wr;")
    add("      stim_wdata_i = data;")
    add("      stim_be_i = be;")
    add("      stim_offer_i = 1'b1;")
    add("      @(negedge clk_i);")
    add("      stim_offer_i = 1'b0;")
    add("      @(posedge clk_i);")
    add("      while (dut.fuzz_completion_count_o < expected) begin")
    add("        if (cycles >= CYCLE_BUDGET) begin")
    add('          print_line("TIMEOUT");')
    add('          $fatal(1, "synthetic MMIO operation did not complete (done=%0d)",')
    add("                 dut.fuzz_completion_count_o);")
    add("        end")
    add("        @(posedge clk_i);")
    add("      end")
    add("      repeat (2) @(posedge clk_i);")
    add("    end")
    add("  endtask")

    add("")
    add("  // Every check is reported as its own CHECK line; the machine-readable")
    add("  // observation line is printed for passing and failing runs alike.")
    add("  task automatic check_and_report();")
    add("    integer failures;")
    add("    begin")
    add("      failures = 0;")
    add('      if (dut.fabric_protocol_error_o) begin')
    add("        failures = failures + 1;")
    add('        $display("MYFUZZ_SOC_MATRIX_CHECK fabric_protocol_error=1");')
    add("      end")
    add("      if (window_error_seen) begin")
    add("        failures = failures + 1;")
    add('        $display("MYFUZZ_SOC_MATRIX_CHECK window_error=1 addr=0x%08x", window_last_addr);')
    add("      end")
    add("      if (MODE != 1) begin")
    add("        if (ram_word(FLAG_OFFSET) !== FLAG_OK) begin")
    add("          failures = failures + 1;")
    add('          $display("MYFUZZ_SOC_MATRIX_CHECK cpu_flag=0x%08x expected=0x%08x", ram_word(FLAG_OFFSET), FLAG_OK);')
    add("        end")
    add("        if (dut.cpu_transaction_count_o < 32'd2) begin")
    add("          failures = failures + 1;")
    add('          $display("MYFUZZ_SOC_MATRIX_CHECK cpu_transactions=%0d", dut.cpu_transaction_count_o);')
    add("        end")
    add("        if (dut.cpu_completion_count_o == 32'd0) begin")
    add("          failures = failures + 1;")
    add('          $display("MYFUZZ_SOC_MATRIX_CHECK cpu_completions=0");')
    add("        end")
    add("        if (window_done_cpu == 32'd0) begin")
    add("          failures = failures + 1;")
    add('          $display("MYFUZZ_SOC_MATRIX_CHECK cpu_window_transactions=0");')
    add("        end")
    add("        if (HAS_READBACK_EXPECTATION &&")
    add("            (ram_word(READBACK_OFFSET) !== EXPECTED_READBACK)) begin")
    add("          failures = failures + 1;")
    add('          $display("MYFUZZ_SOC_MATRIX_CHECK cpu_readback=0x%08x expected=0x%08x", ram_word(READBACK_OFFSET), EXPECTED_READBACK);')
    add("        end")
    add("      end else begin")
    add("        if (dut.cpu_transaction_count_o != 0 || dut.cpu_completion_count_o != 0) begin")
    add("          failures = failures + 1;")
    add('          $display("MYFUZZ_SOC_MATRIX_CHECK cpu_ran_while_held_in_reset tx=%0d done=%0d", dut.cpu_transaction_count_o, dut.cpu_completion_count_o);')
    add("        end")
    add("        if (ram_word(FLAG_OFFSET) != 0) begin")
    add("          failures = failures + 1;")
    add('          $display("MYFUZZ_SOC_MATRIX_CHECK cpu_flag_while_held_in_reset=0x%08x", ram_word(FLAG_OFFSET));')
    add("        end")
    add("      end")
    add("      if (MODE != 0) begin")
    add("        if (dut.fuzz_transaction_count_o != FUZZ_OPS) begin")
    add("          failures = failures + 1;")
    add('          $display("MYFUZZ_SOC_MATRIX_CHECK fuzz_accepted=%0d expected=%0d", dut.fuzz_transaction_count_o, FUZZ_OPS);')
    add("        end")
    add("        if (dut.fuzz_completion_count_o != FUZZ_OPS) begin")
    add("          failures = failures + 1;")
    add('          $display("MYFUZZ_SOC_MATRIX_CHECK fuzz_completed=%0d expected=%0d", dut.fuzz_completion_count_o, FUZZ_OPS);')
    add("        end")
    add("        if (dut.u_fuzz_mmio.busy_drop_count != 0) begin")
    add("          failures = failures + 1;")
    add('          $display("MYFUZZ_SOC_MATRIX_CHECK fuzz_dropped=%0d", dut.u_fuzz_mmio.busy_drop_count);')
    add("        end")
    add("        if (window_done_fuzz == 32'd0) begin")
    add("          failures = failures + 1;")
    add('          $display("MYFUZZ_SOC_MATRIX_CHECK fuzz_window_transactions=0");')
    add("        end")
    add("        if (HAS_READBACK_EXPECTATION &&")
    add("            (((window_rdata_fuzz >> (32*READBACK_LANE)) & 64'hFFFFFFFF)")
    add("             !== EXPECTED_READBACK)) begin")
    add("          failures = failures + 1;")
    add('          $display("MYFUZZ_SOC_MATRIX_CHECK fuzz_readback=0x%08x expected=0x%08x", window_rdata_fuzz >> (32*READBACK_LANE), EXPECTED_READBACK);')
    add("        end")
    add("      end else begin")
    add("        if (dut.fuzz_transaction_count_o != 0 || dut.fuzz_completion_count_o != 0) begin")
    add("          failures = failures + 1;")
    add('          $display("MYFUZZ_SOC_MATRIX_CHECK fuzz_ran_in_cpu_only tx=%0d done=%0d", dut.fuzz_transaction_count_o, dut.fuzz_completion_count_o);')
    add("        end")
    add("      end")
    add(_side_effect_check(documents))
    add("      if (failures != 0) begin")
    add('        print_line("FAIL");')
    add('        $fatal(1, "soc matrix run reported %0d failed check(s)", failures);')
    add("      end")
    add('      print_line("OK");')
    add("      $finish;")
    add("    end")
    add("  endtask")

    add("")
    add("  initial begin")
    add("    reset_i = 1'b1;")
    add("    repeat (8) @(posedge clk_i);")
    add("    reset_i <= 1'b0;")
    add("    repeat (4) @(posedge clk_i);")
    if mode in ("cpu_only", "mixed"):
        add('    wait_ram_word(FLAG_OFFSET, FLAG_OK, "cpu completion flag");')
        if expected is not None:
            # The program stores the read-back record after the flag; wait for
            # it instead of racing the second store.
            add('    wait_ram_word(READBACK_OFFSET, EXPECTED_READBACK,')
            add('                   "cpu read-back record");')
        else:
            add("    repeat (64) @(posedge clk_i);")
    if mode in ("mmio_only", "mixed"):
        for op in fuzz_ops:
            add("    fuzz_op(%d, %d, 1'b%d, %d'h%x, %d'h%x);"
                % (op["selector"], op["offset"], op["write"], width, op["data"],
                   width // 8, op["be"]))
    add("    // Let a real UART frame or SPI transfer finish before reporting.")
    add("    repeat (%d) @(posedge clk_i);"
        % SIDE_EFFECT_SETTLE_CYCLES[target["side_effect"]])
    add("    check_and_report();")
    add("  end")
    add("endmodule")
    return "\n".join(lines) + "\n"



# ---------------------------------------------------------------------------
# fail-closed validation and the run entry point
# ---------------------------------------------------------------------------

#: Verilator warning suppressions used for the generated runtime build.  The
#: renderer half lints the rendered top with a stricter list; these extra
#: suppressions are the ones the pinned OpenTitan/CVA6 closures need to build.
_BUILD_WARNINGS = (
    "-Wno-fatal", "-Wno-PINMISSING", "-Wno-WIDTHEXPAND", "-Wno-WIDTHTRUNC",
    "-Wno-MULTIDRIVEN", "-Wno-UNSIGNED", "-Wno-CASEINCOMPLETE", "-Wno-LATCH",
    "-Wno-UNOPTFLAT", "-Wno-MODDUP", "-Wno-DECLFILENAME", "-Wno-UNUSED",
    "-Wno-IMPLICIT", "-Wno-CASEWITHX", "-Wno-WIDTH", "-Wno-SELRANGE",
    "-Wno-VARHIDDEN", "-Wno-TIMESCALEMOD",
)

_VERILATOR = None


def _verilator() -> tuple:
    """(path, version) or a fail-closed error naming the missing tool."""
    global _VERILATOR
    if _VERILATOR is not None:
        return _VERILATOR
    tool = shutil.which("verilator")
    if tool is None:
        raise SocMatrixSmokeError(
            "verilator is required for the real SoC matrix runtime and is not "
            "on PATH; no behavioural substitute is used")
    result = subprocess.run([tool, "--version"], text=True, capture_output=True,
                            timeout=120)
    version = (result.stdout + result.stderr).strip() or "unknown"
    _VERILATOR = (tool, version)
    return _VERILATOR


def validate_closure_files(root, manifest: dict) -> None:
    """Fail closed naming every missing file of the real source closure."""
    root = Path(root)
    elaboration = manifest.get("real_elaboration") or {}
    real_cpu = manifest.get("real_cpu") or {}
    missing: list = []

    def require(value, label: str) -> None:
        if not isinstance(value, str) or not value:
            missing.append("%s:<unrecorded>" % label)
        elif not (root / value).exists():
            missing.append("%s:%s" % (label, value))

    for item in elaboration.get("source_files") or []:
        require(item, "source")
    for item in elaboration.get("include_dirs") or []:
        require(item, "include")
    require(real_cpu.get("core_source"), "cpu-core")
    for name, record in sorted((manifest.get("peripherals") or {}).items()):
        if not isinstance(record, dict):
            missing.append("peripheral:%s:<unrecorded>" % name)
            continue
        require(record.get("wrapper_source"), "wrapper:%s" % name)
        require(record.get("adapter_source"), "adapter:%s" % name)
        require(record.get("closure"), "closure:%s" % name)
        for item in record.get("elaboration_files") or []:
            require(item, "ip:%s" % name)
    if elaboration.get("runtime_top") != RUNTIME_TOP:
        missing.append("runtime-top:%s" % (elaboration.get("runtime_top"),))
    if real_cpu.get("core_module") and real_cpu["core_module"] not in (elaboration.get("cpu_core"), ""):
        missing.append("cpu-core-module:%s" % real_cpu["core_module"])
    if missing:
        raise SocMatrixSmokeError(
            "real SoC closure is incomplete, refusing to substitute a model: "
            + ", ".join(sorted(set(missing))))


def _source_digest(manifest: dict) -> str:
    digest = hashlib.sha256()
    for item in sorted(manifest.get("real_elaboration", {}).get("source_files") or []):
        path = ROOT / item
        try:
            stat = path.stat()
            digest.update(("%s:%d:%d\n" % (item, stat.st_size, stat.st_mtime_ns)).encode())
        except OSError:
            digest.update(("%s:missing\n" % item).encode())
    return digest.hexdigest()


def _observation_line(output: str):
    lines = [line.strip() for line in output.splitlines()
             if line.strip().startswith("MYFUZZ_SOC_MATRIX_RUN")]
    return lines[-1] if lines else None


def _parse_observation_line(line: str) -> dict:
    tokens = line.split()
    if not tokens or tokens[0] != "MYFUZZ_SOC_MATRIX_RUN":
        raise SocMatrixSmokeError("malformed observation line: %r" % line)
    observations: dict = {}
    for token in tokens[1:]:
        if "=" not in token:
            raise SocMatrixSmokeError("malformed observation token %r" % token)
        name, value = token.split("=", 1)
        if name in observations:
            raise SocMatrixSmokeError("duplicate observation %r" % name)
        if name in ("cell", "mode", "status"):
            observations[name] = value
        else:
            try:
                observations[name] = int(value, 0)
            except ValueError as error:
                raise SocMatrixSmokeError(
                    "observation %s is not numeric: %r" % (name, value)) from error
    return observations


def _expectations(documents: dict) -> dict:
    target = documents["target"]
    side_expected = {
        "gpio_out_register": target["probe_value"],
        "uart_tx_activity": 2,
        "spi_activity": 2,
        "timer_readback": target["probe_value"],
        # The pinned zipcpu wrapper cannot start a frame (see the program
        # table); the observed side effect is the real register round trip.
        "register_write_readback": target["readback_expected"],
    }[target["side_effect"]]
    return {
        "mode": documents["mode"],
        "cpu_required": documents["mode"] != "mmio_only",
        "fuzz_required": documents["mode"] != "cpu_only",
        "fuzz_transactions": len(documents["fuzz_ops"]),
        "fuzz_completions": len(documents["fuzz_ops"]),
        "flag_ok": FLAG_OK,
        "probe_value": target["probe_value"],
        "readback_offset": target["readback_offset"],
        "readback_expected": target["readback_expected"],
        "cpu_source_id": documents["cpu_source_id"],
        "fuzz_source_id": documents["fuzz_source_id"],
        "side_effect_pattern": target.get("side_effect_pattern"),
        "side_effect": {
            "kind": target["side_effect"],
            "key": target["side_effect_key"],
            "expected": side_expected,
            "peripheral_id": target["peripheral_id"],
            "window_target_id": target["window_target_id"],
        },
    }


def _structural_reason(observations, documents: dict) -> str:
    """A one-line, factual diagnosis for a failing run (never a guess)."""
    if not observations:
        return "; the testbench printed no observation line"
    if observations.get("status") != "TIMEOUT":
        return ""
    expected_cpu = documents["mode"] != "mmio_only"
    detail = [
        "cpu transactions=%s completions=%s" % (observations.get("cpu_tx"),
                                                observations.get("cpu_done")),
        "CPU-attributed MMIO window transactions=%s"
        % observations.get("window_done_cpu"),
        "RAM completion record flag=0x%08x readback=0x%08x"
        % (observations.get("cpu_flag", 0), observations.get("cpu_readback", 0)),
    ]
    if expected_cpu:
        detail.append("the real CPU never reached the generated program "
                      "(program entry 0x%08x at reset vector 0x%08x)"
                      % (documents["program"]["base_address"]
                         + ENTRY_OFFSET,
                         documents["program"]["base_address"]))
    return "; cycle budget exhausted: " + ", ".join(detail)


def run_cell_mode(config_path, mode: str, output_dir, *,
                  seed: int = DEFAULT_SEED,
                  cycle_budget: int = DEFAULT_CYCLE_BUDGET,
                  rebuild: bool = False,
                  jobs=None,
                  build_timeout_s: int = DEFAULT_BUILD_TIMEOUT_S,
                  run_timeout_s: int = DEFAULT_RUN_TIMEOUT_S,
                  elaborate_timeout_s: int = DEFAULT_ELABORATE_TIMEOUT_S) -> dict:
    """Render, elaborate, build and run one matrix cell in one test mode.

    Fails closed (SocMatrixSmokeError) when a closure file, the CPU source or
    Verilator is missing, when the rendered top does not expose a port or wire
    this harness needs, or when the run does not report status=OK.  The build
    cache lives under output_dir/obj_dir and is keyed by the render hash, the
    generated testbench, the program, the Verilator version and the source
    digest, so a repeated call only re-runs the binary.
    """
    started = time.monotonic()
    if mode not in MODES:
        raise ValueError("unsupported mode %r" % (mode,))
    if isinstance(seed, bool) or not isinstance(seed, int) or seed < 0:
        raise ValueError("seed must be a non-negative integer")
    if jobs is not None and (isinstance(jobs, bool) or not isinstance(jobs, int)
                             or jobs < 1):
        raise ValueError("jobs must be a positive integer")

    documents = cell_documents(config_path, mode)
    plan = documents["plan"]
    rendered = render_soc(plan, documents["stimulus"])
    manifest = json.loads(rendered["soc_manifest.json"])
    validate_closure_files(ROOT, manifest)
    top_text = rendered["soc_top.sv"]
    raw_top_text = top_text
    top_text, memory_normalizations = normalize_memory_parameters(top_text)
    port_names = [name for _direction, name in _parse_ports(top_text)]
    ram_index = _memory_index(top_text, documents["ram"]["physical_memory_id"])
    validate_top_requirements(
        top_text, ports=port_names,
        wires=list(_TOP_REQUIRED_WIRES) + _observation_wires(documents)
        + ["u_mem_%d" % ram_index, "u_fuzz_mmio"])
    testbench = build_testbench(documents, top_text, cycle_budget=cycle_budget)
    tool, version = _verilator()

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    render_dir = out / "render"
    program_dir = out / "program"
    render_dir.mkdir(parents=True, exist_ok=True)
    program_dir.mkdir(parents=True, exist_ok=True)
    for name, text in rendered.items():
        if name == "soc_top.sv":
            # Keep the renderer's own document next to the normalized one the
            # smoke elaborates, so the difference is auditable.
            (render_dir / "soc_top.rendered.sv").write_text(text, encoding="utf-8")
            text = top_text
        (render_dir / name).write_text(text, encoding="utf-8")
    top_path = render_dir / "soc_top.sv"
    tb_path = out / "soc_matrix_tb.sv"
    tb_path.write_text(testbench, encoding="utf-8")
    image_path = program_dir / "boot.hex"
    image_path.write_text(documents["program"]["hex"], encoding="utf-8")
    (program_dir / "boot.S").write_text(documents["program"]["assembly"],
                                        encoding="utf-8")
    (out / "soc_plan.json").write_text(
        json.dumps(documents["plan"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    (out / "soc_stimulus.json").write_text(
        json.dumps(documents["stimulus"], indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    obj_dir = out / "obj_dir"
    binary = obj_dir / ("V" + TESTBENCH_TOP)

    stamp = {
        "schema_version": SMOKE_SCHEMA,
        "render_hash": manifest["render_hash"],
        "normalizations": memory_normalizations,
        "testbench_hash": content_hash({"testbench": testbench}),
        "program_hash": documents["program"]["program_hash"],
        "verilator": version,
        "sources": _source_digest(manifest),
        "top": TESTBENCH_TOP,
        "cycle_budget": cycle_budget,
    }
    stamp_path = out / "build_stamp.json"
    cache_hit = False
    if not rebuild and stamp_path.is_file() and binary.is_file():
        try:
            cache_hit = json.loads(stamp_path.read_text(encoding="utf-8")) == stamp
        except json.JSONDecodeError:
            cache_hit = False

    elaboration = manifest["real_elaboration"]
    include_dirs = [str(ROOT / item) for item in elaboration["include_dirs"]]
    sources = [str(ROOT / item) for item in elaboration["source_files"]]
    defines = ["-D" + item for item in elaboration["defines"]]
    elaborate_s = build_s = 0.0
    if not cache_hit:
        mark = time.monotonic()
        command = [tool, "--lint-only", "--top-module", TESTBENCH_TOP,
                   "--language", "1800-2012", *_BUILD_WARNINGS, *defines]
        command.extend("-I" + item for item in include_dirs)
        command.extend(sources)
        command.extend([str(top_path), str(tb_path)])
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                                timeout=elaborate_timeout_s)
        elaborate_s = time.monotonic() - mark
        if result.returncode != 0:
            raise SocMatrixSmokeError(
                "%s/%s: rendered top plus generated testbench do not elaborate "
                "(verilator --lint-only, %s):\n%s"
                % (documents["cell_id"], mode, version,
                   (result.stdout + result.stderr)[-6000:]))
        mark = time.monotonic()
        command = [tool, "--binary", "--timing", "--top-module", TESTBENCH_TOP,
                   "-j", str(jobs or 2), "--Mdir", str(obj_dir),
                   "--language", "1800-2012", *_BUILD_WARNINGS, *defines]
        command.extend("-I" + item for item in include_dirs)
        command.extend(sources)
        command.extend([str(top_path), str(tb_path)])
        result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                                timeout=build_timeout_s)
        build_s = time.monotonic() - mark
        if result.returncode != 0 or not binary.is_file():
            raise SocMatrixSmokeError(
                "%s/%s: verilator --binary --timing failed (rc=%s, binary=%s, "
                "%s):\n%s"
                % (documents["cell_id"], mode, result.returncode,
                   binary.is_file(), version,
                   (result.stdout + result.stderr)[-6000:]))
        stamp_path.write_text(json.dumps(stamp, indent=2, sort_keys=True) + "\n",
                              encoding="utf-8")

    mark = time.monotonic()
    result = subprocess.run([str(binary), "+riscv_boot_image=" + str(image_path)],
                            cwd=ROOT, text=True, capture_output=True,
                            timeout=run_timeout_s)
    run_s = time.monotonic() - mark
    output = result.stdout + result.stderr
    line = _observation_line(output)
    observations = _parse_observation_line(line) if line else None
    expectations = _expectations(documents)
    identity = {
        "config": documents["config_path"],
        "cell_id": documents["cell_id"],
        "render_config": manifest["render_config"],
        "plan_hash": documents["plan_hash"],
        "layout_hash": documents["layout_hash"],
        "render_hash": manifest["render_hash"],
        "stimulus_hash": manifest["stimulus_layout_hash"],
        "mode": mode,
        "seed": seed,
        "cpu": {
            "source_lock": manifest["real_cpu"]["source_lock"],
            "top_module": manifest["real_cpu"]["top_module"],
            "core_module": manifest["real_cpu"]["core_module"],
            "core_source": manifest["real_cpu"]["core_source"],
            "closure_files": list(manifest["real_cpu"]["closure_files"]),
            "reset_vector": manifest["real_cpu"]["reset_vector"],
        },
        "peripherals": {
            name: {
                "source_lock": record["source_lock"],
                "top_module": record["top_module"],
                "protocol": list(record["protocol"]),
                "window": dict(record["window"]),
                "adapter_module": record["adapter_module"],
                "wrapper_module": record["wrapper_module"],
                "wrapper_source": record["wrapper_source"],
                "closure": record["closure"],
                "runtime_status": record["runtime_status"],
            }
            for name, record in sorted(manifest["peripherals"].items())
        },
        "closure_sources": list(elaboration["source_files"]),
        "include_dirs": list(elaboration["include_dirs"]),
        "defines": list(elaboration["defines"]),
        "verilator": version,
        "verilator_path": tool,
        "target": documents["target"],
        "rendered_top_hash": content_hash({"rendered_top": raw_top_text}),
        "built_top_hash": content_hash({"built_top": top_text}),
        "memory_parameter_normalizations": memory_normalizations,
    }
    observations_document = {
        "schema_version": SMOKE_SCHEMA,
        "identity": identity,
        "expectations": expectations,
        "program_hash": documents["program"]["program_hash"],
        "program_words": documents["program"]["words"],
        "fuzz_ops": documents["fuzz_ops"],
        "observation_line": line,
        "observations": observations,
        "artifacts": {
            "dir": str(out),
            "render": str(render_dir),
            "program": str(program_dir),
            "testbench": str(tb_path),
            "binary": str(binary),
            "cache_hit": cache_hit,
        },
        "timings": {"elaborate_s": elaborate_s, "build_s": build_s,
                    "run_s": run_s},
    }
    (out / "observations.json").write_text(
        json.dumps(observations_document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8")

    if result.returncode != 0 or observations is None \
            or observations.get("status") != "OK":
        raise SocMatrixSmokeError(
            "%s/%s failed (rc=%s status=%s)%s:\n%s"
            % (documents["cell_id"], mode, result.returncode,
               (observations or {}).get("status"),
               _structural_reason(observations, documents), output[-4000:]))

    return {
        "schema_version": SMOKE_SCHEMA,
        "cell_id": documents["cell_id"],
        "mode": mode,
        "seed": seed,
        "config": documents["config_path"],
        "identity": identity,
        "target": documents["target"],
        "expectations": expectations,
        "program": {
            "assembly": documents["program"]["assembly"],
            "hex": documents["program"]["hex"],
            "words": documents["program"]["words"],
            "program_hash": documents["program"]["program_hash"],
            "base_address": documents["program"]["base_address"],
            "flag_address": documents["program"]["flag_address"],
            "readback_address": documents["program"]["readback_address"],
            "hex_path": str(image_path),
            "asm_path": str(program_dir / "boot.S"),
        },
        "fuzz_ops": documents["fuzz_ops"],
        "artifacts": {
            "dir": str(out),
            "obj_dir": str(obj_dir),
            "binary": str(binary),
            "soc_top": str(render_dir / "soc_top.sv"),
            "testbench": str(tb_path),
            "manifest": str(render_dir / "soc_manifest.json"),
            "cache_hit": cache_hit,
        },
        "timings": {
            "render_s": 0.0,
            "elaborate_s": elaborate_s,
            "build_s": build_s,
            "run_s": run_s,
            "total_s": time.monotonic() - started,
        },
        "observations": observations,
        "observation_line": line,
        "stdout_tail": output[-2000:],
    }


__all__ = [
    "DEFAULT_CYCLE_BUDGET",
    "DEFAULT_SEED",
    "FLAG_MISMATCH",
    "FLAG_OK",
    "MATRIX_PATH",
    "MODES",
    "OBSERVATION_SIGNALS",
    "PERIPHERAL_FACTS",
    "PERIPHERAL_PROGRAMS",
    "ROOT",
    "SMOKE_SCHEMA",
    "SocMatrixSmokeError",
    "build_testbench",
    "cell_documents",
    "load_cell_config",
    "load_matrix",
    "run_cell_mode",
    "validate_closure_files",
    "validate_top_requirements",
]

