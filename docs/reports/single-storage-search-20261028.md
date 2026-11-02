# Single-flow registered storage search

`configs/search/wishbone-current.json` selects a live current-state strategy
adapter for the registered `compiled_f4_wishbone` executor. Capability selection
uses the executor's code-owned contract and single F4 flow shape, without CPU,
component, IP or register-name dispatch. The existing generic storage kernel,
registered Wishbone runtime, admission checks and replay execute every case.

`search/single_storage.py` reuses the common `CaseAdapter` interface and
`storage.read_current` / `CurrentVersion` projection. The production
WishboneStorageRegisterVersionAuthority issues and consumes a fresh current
version token without a host register write or RTL advance. Missing authority
state remains unknown. Finite public F4 word records form the action catalog;
all policies use that same catalog. Current-state queries condition the written
value frontier. Only the actual runtime's certified F4 readback certificate
matching the current version can settle a written-stage feature.

The registered Wishbone runtime has no read-only F2 operation and rejects it;
it also has no mixed-flow constructor option. This adapter does not invent
those capabilities or change the mixed StorageSearch semantics. Same-case
certified CPU readback is reported separately from current register state.
Cross-testcase consumption is `unsupported-no-read-only-flow`, relation rewards
are absent, and unified certified interaction metrics remain unknown for this
adapter. A future native read-only Wishbone runtime/consumer is required before
extending cross-testcase consumption search to this protocol.

Fresh recreates the actual runtime and current authority and reruns every
selected F4 case. It recomputes current version and certificate matching, while
original policy costs normalize deterministic strategy replay. Saved state
cannot restore authority. No native validation is claimed by the implementation
or software-only tests.

Suggested native acceptance after source freeze:

```sh
python3 scripts/run_dependency_search.py --scenario configs/search/wishbone-current.json --mode original --execution-mode search --policy state --cases 2 --seed 7 --output /tmp/wishbone-current-check --cache /tmp/wishbone-current-cache
python3 scripts/run_dependency_search.py --scenario configs/search/wishbone-current.json --mode fresh --execution-mode search --policy state --cases 2 --seed 7 --output /tmp/wishbone-current-check --cache /tmp/wishbone-current-cache
```

Inspect `search-manifest.json` selection transitions for actual current values,
versions and same-case readback status; inspect the runtime campaign/prefix for
the existing native Wishbone chain. `search_backend` must be
`live-storage-single-flow` and cross-testcase consumption must remain unsupported.
