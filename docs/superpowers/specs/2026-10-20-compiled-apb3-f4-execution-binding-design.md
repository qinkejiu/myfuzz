# Compiled APB3 F4 execution binding

Date: 2026-10-20

## Goal

Make the bounded compiled F4 executor's admission identity explicit and
reproducible across a second OBI CPU instance. The executor consumes the
compiled path and its closed, source-reviewed APB3 storage producer; it does
not infer register semantics from names or protocol labels alone.

## Existing capabilities retained

- D1–D3 produce reviewed component artifacts, a compiled F4 path, source
  layout, prerequisites and assertions.
- `compiled-f4-rfuzz` selects the code-owned F4 executor without a
  `--runtime` family.
- The executor admits RV32I plus the generated single-outstanding OBI CPU
  contract and one APB3 target with a closed producer row.
- The generic APB storage row currently has one registered RTL storage
  contract: PULP `TIMER0_CTRL`. PULP GPIO has its separate source-reviewed
  causal row. Neither row implies arbitrary APB3 semantic inference.

## Design

Create a canonical `compiled_F4_execution_binding.v1` from the exact selected
F4 path, compiled D3 digest, generated CPU and IP artifact digests plus hashes
of every generated wrapper/runtime/driver/ABI/artifact/source-verification file, CPU OBI
error/trace contract, candidate layout, target APB3 protocol/template/window,
source producer binding, prerequisite, and assertion identities. Compute the
binding from private admitted inputs and re-compute it on every stability
check. Include it in the checker identity, each certificate, saved prefix, and
fresh replay comparison. Any mismatch refuses before accepting a testcase.

Derive proof-scope labels from the selected producer row and register identity.
The generic APB storage path must not emit a GPIOEN-specific label.

For the real sibling gate, instantiate the same PULP timer APB3 source using
the CV32E40P OBI CPU profile. Run the existing `compiled-f4-rfuzz` entry with
no runtime family and require certified cases plus complete fresh replay.
Add a software negative for a similarly named target whose APB endpoint
protocol or template shape differs; the closed source/endpoint contract must
refuse it before any native process starts.

## Identity and refusal rules

- A component name, filename, or `evidence_ref` never selects a producer.
- The target must match a code-owned producer row and its exact source
  contract, endpoint protocol, registered APB3 template, address window,
  register geometry, candidate layout and bound input.
- The CPU must match the declared RV32I/OBI trace and error-response policy.
- D3's full compiled digest binds the prerequisites, constraints and
  assertions; the execution binding also records the selected F4 projection.
- Primary and fresh runs must recompute the same semantic binding while
  retaining distinct process identities and live version tokens.
- Unknown APB3 sources, unregistered registers, altered endpoint shape,
  target window, ownership, source layout or assertions fail closed.

## Scope limits

This slice proves re-use of the existing registered APB3 F4 executor on a
second OBI CPU instance and makes its exact admission identity reviewable. It
does not add a second APB register source contract, support arbitrary APB3
RTL, implement F1/F2/F3/F5/F6, close P7, or claim P6/P8 completion. A later
source-contract expansion must add a separately reviewed RTL semantic
contract and evidence.

## Acceptance evidence

1. Focused unit tests prove the execution binding changes when generated
   artifact bytes change and refuses when the compiled path/assertions, layout,
   producer source, target window or protocol/template identity changes.
2. A wrong-shape similarly named APB candidate is refused before native
   startup.
3. CV32E40P + PULP timer runs through `compiled-f4-rfuzz` without a runtime
   family; all issued records are certified and a full fresh prefix matches.
4. Reports describe only this bounded execution and keep overall P7 open.
