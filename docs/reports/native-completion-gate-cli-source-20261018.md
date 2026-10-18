# Native completion directed-gate CLI source wiring

Source-only change to `scripts/verify_picorv32_native_online.py` adds `--native-completion-observation` with argparse `store_true` and default False. `run_gate` accepts the matching default-False keyword, forwards it to native runtime construction, and records it in each result. Both positive and controlled-response calls pass the same parsed boolean; the final summary records that selection.

The retained runtime factory captures the selected observation option. The existing capture/corruption wrapper calls that same factory for fresh construction, so original/fresh and positive/controlled use consistent artifact selection. The omitted option preserves default-False construction. CLI selection alone grants no native completion, source consumption, retirement or feedback authority.

No raw observation checker was added. Guarded fresh and typed normalization source work is undergoing separate review; this CLI increment does not establish their correctness. The [next real gate prerequisites](native-completion-next-real-gate-20261018.md) still require review and a new independently frozen actual gate; its previously proposed CLI option is now wired at source level. No new actual gate has run, and old frozen results do not validate these changes. P6/P7/P8 remain OPEN.

Validation was limited to reading the diff and `git diff --check`. No tests, project imports, models, builds or remote commands were executed.
