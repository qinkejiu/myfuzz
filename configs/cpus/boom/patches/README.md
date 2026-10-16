# Derived Chipyard compatibility patches

Apply these patches with `patch -p1` at the Chipyard source root, in order:

1. `published-dependencies.patch` replaces unavailable Chisel/FIRRTL/iotesters
   snapshots with published 3.5.0/1.5.0/2.5.0 versions in all relevant nested
   build definitions.
2. `explicit-metadata-io.patch` changes Rocket Chip `L1MetadataArray` to use
   `chisel3.Module` and explicitly bind its IO. Its existing superclass was
   `Chisel.Module`, through `L1HellaCacheModule`. The module evaluates
   `onReset()` before defining `io`. With published Chisel 3.5.0,
   `ClientMetadata.apply` constructs a Wire whose reference triggers legacy
   automatic IO wrapping before that `io` value exists. The original trace
   reaches `reflectivelyFindValIO` and throws `NullPointerException`.

The second patch preserves the reset expression, parameter trait, IO fields,
metadata storage, and handshakes. Only this module's IO binding mechanism
changes. The fixed source tree and original failing logs remain preserved;
these patches define a derived generator, not the unmodified upstream pin.

The base source identities and archive hashes are in
`../chipyard_source_manifest.json`. Generation results and their scope are in
`../generation_evidence_20261017.md`.
