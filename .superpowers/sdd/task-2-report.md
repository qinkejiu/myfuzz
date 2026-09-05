# Task 2 Report: Peripheral Capability and Dependency Catalog

## Scope and result

Implemented Task 2 from base commit `e091679` on branch
`feature/ibex-protocol-longrun`.

Implementation commit: `8ee4395` (`feat: add peripheral capability catalog`).

The change is self-contained under `myfuzz.components`. It does not modify
existing composition, harness, protocol, or campaign implementation files.
Reference-only profiles remain metadata and cannot be returned by
`ComponentCatalog.available()`.

## Changed paths

Task 2 implementation and test paths:

- `src/myfuzz/components/__init__.py`
- `src/myfuzz/components/model.py`
- `src/myfuzz/components/catalog.py`
- `src/myfuzz/components/profiles/ram.json`
- `src/myfuzz/components/profiles/timer.json`
- `src/myfuzz/components/profiles/gpio.json`
- `src/myfuzz/components/profiles/uart.json`
- `src/myfuzz/components/profiles/spi.json`
- `src/myfuzz/components/profiles/pwm.json`
- `src/myfuzz/components/profiles/i2c.json`
- `src/myfuzz/components/profiles/dma.json`
- `src/myfuzz/components/profiles/clint.json`
- `src/myfuzz/components/profiles/plic.json`
- `src/myfuzz/components/profiles/ethernet_mac.json`
- `tests/components/__init__.py`
- `tests/components/test_catalog.py`

This report is the separately requested evidence path:

- `.superpowers/sdd/task-2-report.md`

## Implementation details

- Added frozen, slotted `PeripheralProfile` records with tuple-backed
  collections and a read-only `parameter_limits` mapping.
- Added `ComponentDefinitionError` as the typed fail-closed catalog error.
- Added strict directory loading through `load_component_catalog()` and a
  cached `load_builtin_component_catalog()`.
- The loader rejects missing/unknown fields, duplicate JSON keys, duplicate
  component types, malformed or duplicate protocol tuples, invalid numeric or
  boolean values, inconsistent `source_status`/`implemented` pairs, duplicate
  dependencies, invalid parameter ranges, and normalized-path violations.
- Catalog records are sorted by `component_type`, and dependencies must refer
  to a declared component type.
- `available()` accepts only declared protocol/version pairs, requires an
  implemented local profile and an implemented runtime protocol, resolves
  source paths relative to the explicit `root`, rejects paths escaping that
  root (including symlink escapes), and rejects missing source files.
- Bundled implemented profiles use the existing local Ibex RTL for RAM,
  Timer, GPIO, UART, and SPI. Their runtime bindings are respectively
  TL-UL, APB4, APB4, AXI4-Lite, and AXI4-Lite.
- PWM, I2C, DMA, CLINT, PLIC, and Ethernet MAC are declared as
  `source_status: "reference"` with `implemented: false`; their descriptive
  source paths are never treated as executable.
- DMA depends on RAM and Ethernet MAC depends on DMA. All dependency names
  are unique and closed over the bundled component set.

## TDD evidence

### RED: focused tests before implementation

After adding only `tests/components/__init__.py` and
`tests/components/test_catalog.py`, ran:

```text
$ PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.components.test_catalog -v
exit_code=1
ImportError: Failed to import test module: test_catalog
ModuleNotFoundError: No module named 'myfuzz.components'
Ran 1 test in 0.000s
FAILED (errors=1)
```

This was the expected missing-module failure from the brief.

### GREEN: focused tests after implementation

Ran:

```text
$ PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.components.test_catalog -v
Ran 11 tests in 0.005s
OK
```

The focused tests cover profile inventory and ordering, runtime bindings and
source availability, metadata-only references, dependency closure,
unsupported protocols, duplicate types, unknown fields, malformed protocol
records, path traversal, typed lookup failures, and canonical JSON/hash
stability.

## Final regression evidence

All commands below were rerun after the final implementation edit and before
handoff:

```text
$ PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/protocols -t .
Ran 36 tests in 0.099s
OK

$ PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.contracts.test_contracts
Ran 9 tests in 0.002s
OK

$ PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/composition -t .
Ran 130 tests in 0.712s
OK

$ PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_ibex_protocol_composition_config
Ran 3 tests in 0.057s
OK
```

Also verified the staged Task 2 paths with:

```text
$ git diff --cached --check
exit_code=0
```

## Scope audit and concerns

The implementation commit contains exactly the 16 Task 2 package/profile/test
paths listed above. No Task 1, Task 3, or Task 4 files were staged or
committed. At handoff, other concurrent task work was present in the same
forked worktree as unstaged/untracked state (`src/myfuzz/isa/**`, related
`tests/isa/**`, Task 4 campaign files, and a modification to
`src/myfuzz/integration/campaign.py`); it was preserved and not touched.

No functional concerns remain for the Task 2 scope. The real upstream Ibex
dependency is intentionally outside this catalog; reference profiles do not
claim that dependency is present or executable.
