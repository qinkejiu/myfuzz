# Analysis-Driven Generic CPU/Peripheral Composition Design

**Date:** 2026-09-07  
**Status:** Proposed for review  
**Scope:** Replace the fixed Ibex protocol-composition path with a generic, evidence-driven composition platform.

## Goal

Build a CPU-independent composition path that analyzes HDL interfaces, infers typed endpoint facts, matches CPU and peripheral capabilities through protocol contracts, synthesizes adapters and a top-level module, and generates a versioned RFuzz input layout without hard-coded CPU-specific signal slices.

The current Ibex composition remains a compatibility fixture. CVA6 and BOOM become validation targets for the generic path rather than reasons to add CPU-specific generator branches.

## Problem and boundaries

The existing composition path is useful but over-fitted: it accepts only `ibex_core`, requires exactly one RAM/timer/GPIO/UART/SPI set, fixes 32-bit widths, selects three runtime adapters from a local table, and maps a fixed 395-bit harness directly to named Ibex ports. The new path must move those decisions into declarative contracts and analyzed evidence.

This design does not promise that arbitrary RTL can be understood with no evidence. Protocol and ISA semantics that cannot be reliably recovered from syntax must be supplied as machine-readable contracts or generic boundary annotations. Such annotations describe interface roles and capabilities; they must not select a CPU-specific implementation template.

## Design principles

1. **Facts before generation.** The generator consumes normalized HDL facts and contracts, never raw name heuristics alone.
2. **No CPU-specific renderer branches.** CPU IDs identify artifacts and select declarative ISA metadata; they do not select top-level generation code.
3. **Explicit uncertainty.** Every inferred role and protocol candidate carries evidence and confidence. Ambiguous required endpoints fail closed with diagnostics.
4. **Capability intersection.** A connection is legal only when endpoint fields, directions, widths, timing semantics, clock/reset domains, and adapter capabilities are compatible.
5. **Versioned exchange documents.** Facts, composition IR, input layouts, and generated manifests are versioned and path-independent.
6. **Compatibility first.** The current Ibex v1 manifest and generated behavior remain supported while the generic v2 path is introduced.
7. **Low-resource execution.** Analysis and generation are deterministic and bounded; Verilator builds remain serialized by default and fuzzing uses explicit process-group RSS limits.

## Architecture

```text
HDL sources and optional generic boundary annotations
                    |
                    v
          HDL facts v3 / endpoint candidates
                    |
                    +---- CPU ISA contract (XLEN/extensions)
                    +---- peripheral capability profiles
                    +---- protocol definitions and adapters
                    v
       capability matching and dependency graph
                    |
                    v
             composition IR v2
             /       |        \
            /        |         \
           v         v          v
   top-level SV   input layout   source file list
           |         |
           v         v
   coverage insertion -> RFuzz harness -> Verilator/RFuzz runtime
```

### HDL analysis and endpoint facts

The frontend keeps its existing module, port, instance, hierarchy, source-file, and branch facts and adds a normalized endpoint layer. An endpoint contains:

- stable owner/module identity;
- candidate role such as `instruction_master`, `memory_master`, `mmio_target`, `stream_source`, `interrupt_source`, `clock`, or `reset`;
- candidate protocol families and versions;
- fields with semantic role, direction relative to the endpoint, width expression, signedness, and source port evidence;
- clock and reset domain IDs;
- handshake and request/response relations;
- evidence records and confidence scores.

The inference engine recognizes structural patterns rather than CPU names. Examples include valid/ready pairs, request/grant/response pairs, APB setup/access phases, AXI channel groups, TileLink A/D channel pairs, OBI request/grant/response signals, and Wishbone cycle/strobe/ack signals. A protocol candidate is retained only when the required fields and relations are present. A generic annotation may add missing semantic role information at a boundary, but it cannot name or invoke a CPU-specific renderer.

### Contract catalogs

Four catalogs are independent:

- **CPU/ISA profiles:** XLEN, ISA extensions, native endpoint capabilities, supported reset/interrupt roles, source evidence, and the machine-readable ISA constraint provider.
- **Peripheral profiles:** module, endpoint roles, supported protocols, address/alignment requirements, parameters, dependencies, interrupt capability, external pins, and source evidence.
- **Protocol definitions:** fields, directions, widths, required/runtime-required status, channel relations, temporal rules, errors, and legal adapter families.
- **Adapter capabilities:** source and target endpoint kinds, protocol transformation, supported widths, bursts/IDs/ordering semantics, clock/reset assumptions, and maximum transaction latency.

The catalogs are data contracts. Python code loads, validates, canonicalizes, and queries them; it does not contain one branch per CPU design.

### Canonical transaction model

The composition IR uses normalized transactions so that a CPU endpoint and a peripheral endpoint do not need matching signal names. The initial canonical model contains:

```text
MemoryRequest: valid, ready, address, write, write_data, byte_enable, attributes
MemoryResponse: valid, ready, read_data, error, denied, attributes
StreamTransfer: valid, ready, payload, last, metadata
InterruptSource: level or pulse, width, target role, clock/reset domain
```

Adapters must declare which canonical features they preserve. A burst-capable AXI4 endpoint cannot silently be reduced to a single-beat peripheral transaction unless the adapter contract explicitly permits that projection. Unsupported features produce a rejected candidate and a diagnostic.

### Capability matching and dependency resolution

The matcher creates candidate edges between analyzed CPU endpoints, adapter endpoints, and peripheral endpoints. It checks:

- endpoint role compatibility;
- protocol and version compatibility or a declared adapter path;
- field direction and width compatibility;
- address/data/byte-enable semantics;
- clock and reset domain compatibility;
- required dependencies and acyclic dependency order;
- interrupt width, numbering, and target compatibility;
- address allocation, alignment, and non-overlap.

Candidates are ranked deterministically by exact protocol match, complete evidence, fewer adapters, fewer width projections, and lower uncertainty. The selected graph and all rejected reasons are retained in the IR for reproducibility.

### Adapter and top-level synthesis

The renderer consumes only composition IR v2. It creates opaque stable identifiers, declares wires from field widths, instantiates the selected generic adapter modules, connects endpoint fields according to the IR, allocates address regions and interrupt routes, and emits clock/reset handling. It must not inspect `cpu_id` to choose a template.

The generated source list includes all selected CPU source evidence, peripheral sources, protocol adapters, and the generated top. Before publication, every path is checked to remain inside the supplied repository root and every generated module is parsed or linted with the selected frontend/toolchain.

## Generic input mapping

The input mapper consumes endpoint facts and a declarative constraint provider and emits `input_layout.v1`. Each field has a stable ID, owner endpoint, semantic role, width, encoding, source bytes/bits, dependency group, and projection rules.

```json
{
  "field_id": "endpoint_17.address",
  "owner": "endpoint_17",
  "role": "address",
  "width": 64,
  "encoding": "little_endian",
  "constraint": {"kind": "aligned", "value": 8}
}
```

The mapper performs these steps:

1. Collect required and optional input-capable fields from analyzed endpoints and external component pins.
2. Add CPU instruction/data memory and interrupt fields only when those endpoint roles are present.
3. Apply protocol projections such as address alignment, byte-enable width, valid/ready gating, and bounded response timing.
4. Apply component constraints such as FIFO depth, register width, and parameter-derived address ranges.
5. Apply ISA constraints to instruction words through an ISA provider, separate from bus protocol constraints.
6. Pack fields deterministically into an RFuzz byte layout and emit the layout hash and field map.

The RFuzz raw input width is therefore generated from the layout. The current 395-bit Ibex harness is retained as a legacy layout fixture, while new compositions use the generated layout and a versioned harness ABI. Structural correctness is checked by generated width assertions, field-name validation, and a layout-to-top interface check.

## RISC-V and ISA separation

RISC-V instruction legality is an ISA concern, not a CPU adapter concern. A shared RV32 or RV64 instruction provider consumes XLEN, enabled extensions, alignment, privilege assumptions, and optional implementation constraints. It generates legal instruction words or constrained mutations for any CPU that declares the same ISA contract.

The CPU endpoint analyzer separately identifies instruction fetch and data access interfaces. Consequently, CVA6 and BOOM can share an RV64IMAFDC constraint provider while using different inferred memory endpoints and protocol adapter paths. If only a raw instruction memory endpoint is known and no ISA contract is available, the system may run unconstrained words but must mark the layout as syntactic/raw rather than claiming ISA legality.

## Initial implementation slices

The implementation is intentionally staged:

### Slice A: generic platform core

- Define endpoint facts, evidence, confidence, canonical transactions, adapter capabilities, composition IR v2, and input layout v1.
- Add inference and matching tests using synthetic HDL facts and small protocol fixtures.
- Migrate the existing Ibex five-component composition through a generic path while preserving the v1 path.

### Slice B: protocol coverage

- Preserve APB4, AXI4-Lite, and TileLink-UL runtime adapters behind the generic adapter contract.
- Add APB3, OBI, Wishbone Classic, and AXI4 runtime definitions and adapters in independently testable increments.
- Reject burst/ID/ordering projections unless explicitly represented by an adapter capability.

### Slice C: CPU validation targets

- Use the generic analyzer and input mapper against Ibex, CVA6, and BOOM source/configuration fixtures.
- Validate that no renderer branch or fixed input slice is selected by CPU ID.
- Run low-resource source/instrumentation and RTL smoke tests where complete upstream/generated sources are available.

### Slice D: peripheral expansion

- Convert the existing RAM, timer, GPIO, UART, and SPI profiles to the generic endpoint contract.
- Add reusable CLINT, PLIC, PWM, I2C, DMA, watchdog, and FIFO profiles and RTL one at a time, with source and protocol evidence.
- Exercise dependency-aware combinations rather than requiring one fixed set of component types.

## Error handling and safety

The system fails closed before file publication for unknown protocol versions, missing evidence, ambiguous required endpoints, unsupported adapter features, invalid widths, unsafe source paths, address overlap, dependency cycles, duplicate interrupt routes, and incompatible clock/reset domains. Diagnostics include the candidate edge, evidence, and rejected constraint.

Generated artifacts are written to a temporary staging directory and atomically published only after IR validation, source-list validation, and top-level syntax/lint checks. Original RTL remains untouched.

## Verification strategy

- Unit tests validate facts normalization, protocol fingerprints, capability matching, width projections, adapter feature rejection, address/IRQ allocation, input layout packing, and deterministic hashes.
- Contract tests validate that semantically reordered JSON produces identical IR/layout hashes and that unsafe or ambiguous inputs fail closed.
- Synthetic integration fixtures cover generic CPU endpoints connected to multiple peripheral types without CPU-specific names.
- Regression tests verify the existing Ibex v1 manifest and generated behavior remain available.
- CVA6 and BOOM tests first validate analysis and layout generation, then source instrumentation, then low-resource Verilator/RFuzz smoke when dependencies exist.
- Full fuzz campaigns are reported separately from RTL smoke; missing upstream or RFuzz dependencies remain explicit `dependency-unavailable` results.

## Resource policy

All new test and campaign entrypoints default to one frontend/build worker, one active Verilator build, no waveform output, bounded queues, and process-group RSS limits. Parallelism is opt-in and must not be required for correctness.

