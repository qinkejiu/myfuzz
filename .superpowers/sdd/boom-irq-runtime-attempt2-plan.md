# BOOM IRQ runtime attempt2: source-only controls

Metadata recovery is independently archived in commit 64026db and root-reviewed in 84551b4. Actual recovery worker267241 exited0. Its new manifest SHA is `3f405a57322a697f0dfee4004ef15e9c3c5c849bf1fc360b0dd0d087f2bbf89d`; historical binary remains `6367b592b743f935cb2de04bc6dfc4ac54c9ec8cf5dce4eb6545b140971e6c90`.

## Paths and immutable boundary

Future new base: `/root/fanzehui/boom-irq-runtime-attempt2-20261017`.
`control/prepare.py` copies the exact 2567-file source from `/root/fanzehui/boom-irq-factory-fix-20261017/project-finalized` into new `project` using independent copies and an atomic rename. No overlay is applied. Full before/destination/after byte maps and zero shared inodes are required. The actual PULP `.git` directory and object closure remain included. Any source mismatch, existing destination, symlink or shared inode fails.

Artifact remains read-only at `/root/fanzehui/boom-irq-factory-fix-20261017/artifact-finalized`. It is neither relocated nor re-signed. The existing constructor will authenticate the copied repo against the manifest's new factory identity and unchanged implementation closure during a future explicitly authorized native operation. No constructor is used for preparation.

Old finalized source/artifact and runtime attempt1 remain immutable. Attempt1 failed the real ScenarioRunner ownership validator before any CPU/GPIO model existed. The factory-only `gpio_irq` to `gpio.irq` fix has pure validator coverage; no IRQ semantic success follows from it.

## Preparation and operation

After source review and parent authorization, create a fresh base/state/logs/control and upload the frozen control files plus `baseline-source-files.json` (new finalized2567) and `baseline-artifact-files.json` (new finalized88). Run only `python3 control/prepare.py` with source-first PYTHONPATH and bytecode disabled. It copies/hashes, imports reviewed Python, produces source-freeze and ready receipts, and hashes already-pinned tools. It performs no version query, constructor, model, describe or build.

Ready pins every control, both baseline maps, copied maps, source freeze and preparation/import receipts. Parent independently compares remote ready/control/source/artifact hashes and unused operation state before any native GO.

Future exact argv, only after separate root GO: `bash /root/fanzehui/boom-irq-runtime-attempt2-20261017/control/launch.sh`. The launcher/controller claim the operation exclusively; existing PID/claim/exit/stage/output/cache refuses reuse. Actual child PID/argv/log/exit are retained, and inputs/tools are audited before and after. No automatic restart, arbitrary kill, or old-state overwrite occurs.

The unchanged gate retains fixed6000+512 edges, fixed64 actual MEIP input ticks, actual trap/CSR/ISR/status/clear/stores/qualifiedMRET/foreground ordering, two complete fresh prefixes and delivery-suppression control. Actual lifecycle records distinguish constructor setup processes from measured processes. No retirement/source authority is granted.

## Software evidence and current boundary

Copied controller unsafe receipt regression was RED; missing preparation module was RED. Native-log symlink-parent expression also has an isolated RED→GREEN regression; it evaluates the actual controller open expression without launching a child. Final focused suite:22passed0.08s. This includes one-shot refusal, actual child-exit propagation using software fake subprocesses, receipt/state symlink refusal, exact independent source copy, mismatched source rejection and protected destination-parent refusal. These are software controls, not native execution evidence.

Only local control source/tests were prepared in this step. No remote attempt2 snapshot, constructor, model, build, describe or native gate has run. A final actual ready hash does not exist yet.
