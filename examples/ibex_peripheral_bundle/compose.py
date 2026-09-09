#!/usr/bin/env python3
"""Generate the Ibex + five real-peripheral bundle from its five input groups."""

from __future__ import annotations

import json
from pathlib import Path

from myfuzz.components import load_real_component_catalog
from myfuzz.composition import (
    GenericCompositionRequest,
    load_interface_description,
    plan_generic_composition,
    write_generic_composition,
)
from myfuzz.isa.constraints import IsaContract


ROOT = Path(__file__).resolve().parents[2]
BUNDLE = Path(__file__).resolve().parent
INPUT = BUNDLE / "input/05_isa_test/ibex-rv32imc-real-peripherals.json"
OUTPUT = BUNDLE / "output"


def main() -> int:
    config = json.loads(INPUT.read_text(encoding="utf-8"))
    interface_path = BUNDLE / "input/01_cpu_interface/official_core_interface_description.json"
    isa = IsaContract(int(config["isa"]["xlen"]), tuple(config["isa"]["extensions"]))
    components = tuple(config["components"])
    description = load_interface_description(interface_path)
    plan = plan_generic_composition(
        GenericCompositionRequest(
            description,
            components,
            (("processor-memory-beat", "1"),),
            isa=isa,
            seed=20260909,
        ),
        base_dir=ROOT,
        component_catalog=load_real_component_catalog(),
    )
    summary = write_generic_composition(
        plan,
        OUTPUT,
        base_dir=ROOT,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
