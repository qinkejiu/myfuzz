# Compiled F4 second APB3 storage source: PULP SPI SPICMD

Date: 2026-10-22

## Goal

Extend the existing `compiled-f4-rfuzz` APB3 storage path to a second,
source-reviewed APB3 peripheral contract using PULP SPI's `SPICMD` register,
without selecting behavior from a component name or weakening the existing
PULP Timer contract.

## Verified scope

The source contract is limited to the pinned PULP `apb_spi_master` profile at
`BUFFER_DEPTH=10` and `APB_ADDR_WIDTH=12`, and to the `SPICMD` word at
canonical offset `0x08`. Its profile uses source root `third_party`, revision
`sha256:c653811843b453f0689a8f6942934ff9d551734aa4bc4e197d8b9acbfb020230`,
top `apb_spi_master`, and the exact seven-file closure in the profile. The
source contract pins those closure bytes as well as the exact profile
parameters. `spi_master_apb_if.sv` decodes `PADDR[5:2]`, assigns
the full `PWDATA` to `spi_cmd` on an APB write to slot 2, resets `spi_cmd` to
zero, and returns `spi_cmd` through the `SPICMD` read mux. Its storage decode
therefore uses mask `0x3c`, value `0x08`, and aliases every 64 bytes within the
12-bit address input (256 raw aliases, 64 word-aligned aliases). `apb_spi_master.sv`
wires that register to the SPI controller but does not start a transfer from
an SPICMD write; transfer commands are strobed separately by writes to
`STATUS`.

The evidence proves only the APB register write/read storage chain. It does
not exercise serial pins, TX/RX FIFOs, `STATUS` command strobes, transfer
completion, interrupt behavior, arbitrary PULP SPI registers, or arbitrary
APB3 devices.

## Design

1. Add a second immutable code-owned source contract, identified by a versioned
   contract ID. Select it by exact pinned source bytes, source/profile shape,
   APB endpoint contract, and the declared `SPICMD` register geometry. A
   caller-provided name, evidence reference, digest, or serialized contract
   cannot register or modify a source contract.
2. Carry the selected contract's address decode, register geometry, reset and
   storage facts through probe generation, hierarchy proof validation,
   producer binding, and the live version authority. Replace Timer-only
   address/register constants in shared code with values revalidated from the
   admitted immutable source contract. Keep both contracts in the closed
   registry; unknown contract/source/register combinations refuse. The
   decode predicate validates that a physical sample addresses the registered
   storage, while receipt joins still require exact equality with the declared
   transaction address; a different decode alias cannot stand in for it.
3. Add a separate digest-bound native hierarchy proof for the exact PULP SPI
   storage expression and generated runtime/wrapper. The proof must sample
   reset, an APB full-word SPICMD write, the resulting storage value, and APB
   readback; it must include wrong-register/address and altered-expression
   refusal controls. Generate that proof directly from a `local_harness.v2`
   PULP SPI request with the generic `target.apb3` register policy; do not make
   the proof depend on the later compiled-F4 composition or live version
   consumer. The SPI proof uses its own evidence path and contract-specific
   sample checks. The existing Timer proof remains independently pinned.
4. Keep authority boundaries unchanged: a documentary source contract grants
   no reset prerequisite, live version, native eligibility, or functional
   claim. Only the existing in-process native observer and opaque single-use
   token may certify a measured write. Fresh replay uses a different native
   process and execution identity while comparing only the explicitly stable
   semantic projection.
5. Exercise one exact D2→D3→D4 call for CV32E40P OBI plus the new PULP SPI
   source, without `--runtime`. Require CPU instruction source, APB commit and
   version token, CPU readback/RAM result, a complete fresh prefix, and a
   similarly named wrong-shape CPU/profile refusal before native startup.

## Required refusal cases

- Any changed or symlinked reviewed source byte, source root/revision/top,
  elaboration parameter, APB endpoint, clock/reset shape, or register offset,
  width, access, side effect, or reset/write mask.
- A Timer contract paired with the SPI profile, an SPI contract paired with a
  Timer profile, and any caller-authored contract/evidence or unknown
  contract/register ID.
- Decode-mask/value, source-contract digest, probe expression, hierarchy proof,
  generated runtime/wrapper, target window, APB3 template, CPU profile,
  producer identity, prerequisite, assertion, or version-token drift.
- Missing CPU acceptance, Router delivery, physical APB sample, or opaque
  version-token join. Every failure must happen before accepting a certified
  testcase; wrong-shape profile admission must fail before native process
  creation.
- Partial-word writes, non-SPICMD offsets, STATUS/FIFO accesses, serialized
  transfers, and unknown APB3 sources remain unsupported by this storage row.

## Acceptance

- Source-contract, probe, hierarchy-proof, version, consumer, and compiled-F4
  software tests pass with all refusal cases above.
- A native first run and a distinct fresh native run both exit successfully,
  preserve complete raw receipts, and produce equal normalized semantic
  prefixes. Actual accepted APB writes/readbacks must match the SPICMD address,
  full-word value, storage state, version token and CPU RAM result.
- The previously accepted Timer F4 gate and the existing GPIO producer row
  retain their behavior and evidence identity.
- Documentation records this as a second registered APB3 storage source and
  one bounded onboarding slice. It does not mark P7-E, P6, P8, arbitrary APB3,
  serial SPI, or the aggregate six-CPU/four-IP goal complete.
