"""Machine-readable CPU and ISA profile catalog."""

from .catalog import CpuCatalog, load_builtin_cpu_catalog, load_cpu_catalog
from .constraints import IsaContract, RiscvInstructionProvider
from .model import CpuDefinitionError, CpuProfile
from .transducer import InstructionChoice, InstructionTemplate, RiscvInstructionTransducer

__all__ = [
    "CpuCatalog",
    "CpuDefinitionError",
    "CpuProfile",
    "IsaContract",
    "InstructionChoice",
    "InstructionTemplate",
    "RiscvInstructionProvider",
    "RiscvInstructionTransducer",
    "load_builtin_cpu_catalog",
    "load_cpu_catalog",
]
