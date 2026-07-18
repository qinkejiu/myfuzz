"""Frozen qualified IP set shared by both CPU experiment backends."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .level1_rom import Level1IPWindow


@dataclass(frozen=True)
class QualifiedAxiLiteIP:
    instance_id: str
    type_id: str
    module: str
    base: int
    size: int
    filelist: str
    license: str
    primary_point_count: int

    @property
    def window(self) -> Level1IPWindow:
        return Level1IPWindow(self.instance_id, self.base, self.size)


FORMAL_AXI_LITE_IPS = (
    QualifiedAxiLiteIP("ram0", "verilog_axi.axil_ram", "verilog_axi_ram_wrapper",
                       0x20000000, 0x10000, "qualification/axi_lite/cases/verilog_axi_ram.f", "MIT", 5),
    QualifiedAxiLiteIP("ram1", "verilog_axi.axil_ram", "verilog_axi_ram_wrapper",
                       0x20010000, 0x10000, "qualification/axi_lite/cases/verilog_axi_ram.f", "MIT", 5),
    QualifiedAxiLiteIP("dp_ram0", "verilog_axi.axil_dp_ram", "verilog_axi_dp_ram_wrapper",
                       0x20020000, 0x1000, "qualification/axi_lite/cases/verilog_axi_dp_ram.f", "MIT", 10),
    QualifiedAxiLiteIP("regs0", "pulp.axi_lite_regs", "pulp_axi_lite_regs_wrapper",
                       0x20030000, 0x1000, "qualification/axi_lite/cases/pulp_axi_lite_regs.f", "SHL-0.51", 16),
    QualifiedAxiLiteIP("regs1", "pulp.axi_lite_regs", "pulp_axi_lite_regs_wrapper",
                       0x20031000, 0x1000, "qualification/axi_lite/cases/pulp_axi_lite_regs.f", "SHL-0.51", 16),
    QualifiedAxiLiteIP("lfsr0", "pulp.axi_lite_lfsr", "pulp_axi_lite_lfsr_wrapper",
                       0x20032000, 0x1000, "qualification/axi_lite/cases/pulp_axi_lite_lfsr.f", "SHL-0.51", 6),
    QualifiedAxiLiteIP("gpio0", "zipcpu.axilgpio", "zipcpu_axilgpio_wrapper",
                       0x20033000, 0x1000, "capability/axi_lite/cases/zipcpu_axilgpio.f", "Apache-2.0", 20),
    QualifiedAxiLiteIP("apb0", "zipcpu.axil2apb", "zipcpu_axil2apb_wrapper",
                       0x20034000, 0x1000, "capability/axi_lite/cases/zipcpu_axil2apb.f", "Apache-2.0", 19),
)


def formal_axi_lite_ip_set() -> tuple[QualifiedAxiLiteIP, ...]:
    return FORMAL_AXI_LITE_IPS


def formal_ip_windows() -> tuple[Level1IPWindow, ...]:
    return tuple(ip.window for ip in FORMAL_AXI_LITE_IPS)


def validate_formal_ip_sources(materials_root: str | Path) -> None:
    root = Path(materials_root)
    missing = sorted(ip.filelist for ip in FORMAL_AXI_LITE_IPS if not (root / ip.filelist).is_file())
    if missing:
        raise FileNotFoundError("missing formal IP filelist(s): " + ", ".join(missing))
