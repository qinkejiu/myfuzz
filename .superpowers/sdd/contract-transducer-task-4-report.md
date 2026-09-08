# Contract Transducer Task 4 Report: Per-Test Coherent Memory

## Status

DONE_WITH_CONCERNS

## Implementation commit

`25515b5b2f93e300f7aab9d3ab39a5becee7b43b` (`feat: add coherent per-test RFuzz memory`)

## RED evidence

The requested `python` executable is not installed in this environment:

```text
$ python -m pytest tests/composition/test_coherent_memory.py -q
/bin/bash: line 1: python: command not found
```

The equivalent available command failed for the expected missing-module reason:

```text
$ PYTHONPATH=src python3 -m pytest tests/composition/test_coherent_memory.py -q
E   ModuleNotFoundError: No module named 'myfuzz.composition.coherent_memory'
1 error during collection
```

## GREEN evidence

Focused memory tests:

```text
$ PYTHONPATH=src python3 -m pytest tests/composition/test_coherent_memory.py -q
.........                                                                [100%]
9 passed in 0.06s
```

Focused memory plus related cycle-input/transport regression (excluding the
pre-existing environment-dependent generic publication test):

```text
$ PYTHONPATH=src python3 -m pytest tests/composition/test_coherent_memory.py tests/composition/test_cycle_input.py tests/composition/test_rfuzz_transport.py -q -k 'not generic_publication'
.........................                                                [100%]
25 passed, 1 deselected, 19 subtests passed in 0.12s
```

Additional verification passed: `py_compile` for the implementation and test,
and `git diff --check` for the implementation commit.

## Self-review

- Storage is sparse and keyed by `(domain, address)`, so domains are isolated.
- Reads invoke the initializer once only when a span has missing bytes, fill
  only those missing bytes, and assemble little-endian values afterward.
- Writes honor each byte-enable bit; `seed` fills a complete span, and
  `reset_test` clears all per-test state.
- Addresses/spans, widths, values, and byte-enable masks are validated before
  mutation.
- Only the Task 4 implementation and behavior-test files were included in the
  implementation commit; the existing Task 2 report and `third_party/` files
  were not changed.

## Concerns

- The environment lacks the `python` executable, so all evidence uses the
  equivalent `python3` command.
- The full transport suite's generic publication test was excluded from the
  related regression because its existing Verilator/supervision startup path is
  environment-dependent; no Task 4 test failure was observed.
- The memory address bound is currently 64 bits; a future contract with a
  different address width would need an explicit bound parameter.
