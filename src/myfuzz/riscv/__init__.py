"""Profile-driven RISC-V instruction encoding and straight-line program generation.

This package is intentionally independent of ``myfuzz.isa`` and of the
certificate/retirement layers.  It turns a CPU component profile into legal
RISC-V instruction words and four-byte F1 records:

    profile -> catalog -> encoding -> program -> ``--record F1:<hex>``

Only legal instruction generation is implemented here; retirement evidence and
coverage belong to the existing runtime.
"""

from .catalog import CATALOG, InstructionSpec
from .encoding import EncodingError, encode, format_assembly, pack_compressed_pair
from .profile import RiscvProfile, load_profile, profile_from_mapping
from .program import (
    InstructionNotAvailable,
    Program,
    ProgramInstruction,
    generate_program,
    make_instruction,
)

__all__ = [
    "CATALOG",
    "EncodingError",
    "InstructionNotAvailable",
    "InstructionSpec",
    "Program",
    "ProgramInstruction",
    "RiscvProfile",
    "encode",
    "format_assembly",
    "generate_program",
    "load_profile",
    "make_instruction",
    "pack_compressed_pair",
    "profile_from_mapping",
]
