# Task 2 Report: Peripheral Capability and Dependency Catalog

## Scope and result

Implemented Task 2 from base commit `e091679` on branch
`feature/ibex-protocol-longrun`.

Implementation commit: `8ee4395` (`feat: add peripheral capability catalog`).
Reviewer fix commits: `20c1626` (`fix: harden component source path validation`)
and `bdf5fb9` (`fix: reject current-directory component paths`).

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

## Reviewer follow-up fix evidence

The reviewer-requested fix is committed as `20c1626` and `bdf5fb9`. It
preserves the runtime protocol allowlist and the existing Ibex component
ABI/source bindings.

### Path validation fix

`_parse_source_path()` now rejects a NUL byte before path processing and
requires the original string to equal `PurePosixPath(path).as_posix()` after
the existing relative-path checks. This rejects `./file.sv`, repeated
separators such as `dir//file.sv`, trailing-separator aliases, and equivalent
non-canonical forms before `source_paths` duplicate checks. NUL input raises
the same typed `ComponentDefinitionError` used for all other profile errors.
The follow-up boundary fix also rejects the standalone current-directory path
`.` by requiring at least one path component.

### Strengthened focused tests

The focused suite now compares every field of all 11 built-in profiles against
an exact expected inventory, including protocols, source status, implemented
flag, dependencies, source paths, and parameter limits. It also covers
duplicate JSON keys, invalid booleans and numeric values, invalid source
status, invalid parameter ranges, missing sources, portable symlink escapes,
non-normalized aliases, and NUL-containing source paths.

### Reviewer-fix TDD evidence

After adding the reviewer tests but before the implementation fix, ran:

```text
$ PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.components.test_catalog -v
Ran 18 tests in 0.012s
FAILED (failures=4)
```

The four expected failures were the three non-normalized-alias subtests
(`./fixture.sv`, `dir//fixture.sv`, and the aliased duplicate pair) and the
NUL-path test. The other 14 tests passed.

To close the remaining current-directory alias edge, added the `.` case and
reran before `bdf5fb9`:

```text
$ PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.components.test_catalog -v
Ran 18 tests in 0.013s
FAILED (failures=1)
```

The only failure was the new `source_paths=["."]` subtest; the other tests
passed. After `bdf5fb9`, the focused suite was GREEN:

```text
$ PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.components.test_catalog -v
Ran 18 tests in 0.012s
OK
```

After `20c1626`, ran:

```text
$ PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.components.test_catalog -v
Ran 18 tests in 0.012s
OK

$ PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/protocols -t . -v
Ran 36 tests in 0.104s
OK

$ PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.contracts.test_contracts -v
Ran 9 tests in 0.002s
OK

$ PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/composition -t . -v
Ran 130 tests in 0.738s
OK

$ PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_ibex_protocol_composition_config -v
Ran 3 tests in 0.062s
OK
```

The complete relevant regression set was rerun after `bdf5fb9` as well:

```text
$ PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/protocols -t . -v
Ran 36 tests in 0.100s
OK

$ PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.contracts.test_contracts -v
Ran 9 tests in 0.002s
OK

$ PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest discover -s tests/composition -t . -v
Ran 130 tests in 0.781s
OK

$ PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src:. python3 -m unittest tests.integration.test_ibex_protocol_composition_config -v
Ran 3 tests in 0.066s
OK
```

The fix commit contains no Task 1, Task 3, or Task 4 files. The report update
itself is the only remaining Task 2 evidence change after that fix commit.
