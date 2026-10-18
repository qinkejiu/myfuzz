# OpenTitan metadata attempt1: independent failure diagnosis

Read-only two-hop stdlib observation of `/root/fanzehui/myfuzz/operations/p8-source-opentitan-metadata-20261018-attempt1/control`. The failed attempt remains unchanged. No Git subprocess, model, source repair, upload, rerun or predicate change occurred during this diagnosis; large object stdout/pack data was not transferred.

Parent PID257434 terminated returncode1 with `working-tree-not-full-snapshot`; all124 retained Git child terminal receipts have returncode0. Controller SHA is `ab600cfd5362fdaa2d8036f695731cb0851c3ac779e9fb5cfde444f82da205a0`. The parent spans 2026-10-18 09:12:27–09:14:06 UTC. These child successes do not grant materialization success: rejection occurs at the complete working-tree path-set predicate before clean pack/store/stage construction.

Independent set comparison found13870 snapshot paths /14732 snapshot objects versus13805 working-tree leaves (13838 source files including metadata): **65 missing, zero extra, zero common-path content size/SHA256 mismatch**. Every one of the65 missing paths was independently lstat-checked and is absent. Source file dictionaries and directory dictionaries are each identical before/after. No gitlinks were recorded.

Missing groups:59 paths under vendored `google_riscv-dv` target directories;5 paths under `util/openocd/target` (BUILD and four cfg files);1 `prebuilts/nop.o`. This pattern suggests earlier transfer/exclusion policy as a possible explanation, but no provenance of their removal was inspected and the cause is not established. They cannot be omitted from a claimed complete snapshot or reclassified as untracked build products: they are paths in the exact pinned snapshot map. No filesystem restoration is performed here.

The actual checked traversal produced pins for those missing blobs, so a later separately reviewed offline reconstruction may be possible from already captured object bytes; that requires its own verification and new operation. Existing closure pins alone are not an independently rehashed full pack/object audit or a ready clean metadata store. P8 scalar/project preparation and P6/P7/P8 remain OPEN.

[Read-only receipt](evidence/p8-opentitan-metadata-attempt1-20261018/readonly-setdiff.json) retains exact missing mode/OID/size/SHA256 rows, actual lstat results, source equality/counts, parent/last-child receipts, child exit counts, and SHA/byte sizes of each consumed remote map/receipt. Receipt SHA256: `37334070cd765e3f9be6d0b605c6b66cd55d5c133b6b918a2b91093ed4efd690`.

## Exact missing paths

- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/euvm/riscv/gen/target/ml/riscv_core_setting.d`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/euvm/riscv/gen/target/multi_harts/riscv_core_setting.d`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/euvm/riscv/gen/target/package.d`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/euvm/riscv/gen/target/rv32i/riscv_core_setting.d`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/euvm/riscv/gen/target/rv32imafdc/riscv_core_setting.d`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/euvm/riscv/gen/target/rv32imc/riscv_core_setting.d`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/euvm/riscv/gen/target/rv32imc_sv32/riscv_core_setting.d`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/euvm/riscv/gen/target/rv32imcb/riscv_core_setting.d`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/euvm/riscv/gen/target/rv64gc/riscv_core_setting.d`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/euvm/riscv/gen/target/rv64gcv/riscv_core_setting.d`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/euvm/riscv/gen/target/rv64imc/riscv_core_setting.d`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/euvm/riscv/gen/target/rv64imcb/riscv_core_setting.d`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/pygen/pygen_src/target/multi_harts/riscvOVPsim.ic`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/pygen/pygen_src/target/multi_harts/riscv_core_setting.py`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/pygen/pygen_src/target/rv32i/riscvOVPsim.ic`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/pygen/pygen_src/target/rv32i/riscv_core_setting.py`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/pygen/pygen_src/target/rv32imafdc/riscvOVPsim.ic`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/pygen/pygen_src/target/rv32imafdc/riscv_core_setting.py`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/pygen/pygen_src/target/rv32imc/riscvOVPsim.ic`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/pygen/pygen_src/target/rv32imc/riscv_core_setting.py`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/pygen/pygen_src/target/rv32imcb/riscvOVPsim.ic`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/pygen/pygen_src/target/rv32imcb/riscv_core_setting.py`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/pygen/pygen_src/target/rv64imafdc/riscv_core_setting.py`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/pygen/pygen_src/target/rv64imc/riscv_core_setting.py`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/ml/riscvOVPsim.ic`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/ml/riscv_core_setting.sv`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/ml/testlist.yaml`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/multi_harts/riscvOVPsim.ic`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/multi_harts/riscv_core_setting.sv`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/multi_harts/testlist.yaml`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv32i/riscvOVPsim.ic`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv32i/riscv_core_setting.sv`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv32i/testlist.yaml`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv32imafdc/riscv_core_setting.sv`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv32imafdc/testlist.yaml`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv32imc/riscvOVPsim.ic`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv32imc/riscv_core_setting.sv`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv32imc/testlist.yaml`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv32imc_sv32/riscvOVPsim.ic`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv32imc_sv32/riscv_core_setting.sv`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv32imc_sv32/testlist.yaml`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv32imcb/riscvOVPsim.ic`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv32imcb/riscv_core_setting.sv`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv32imcb/testlist.yaml`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv64gc/riscvOVPsim.ic`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv64gc/riscv_core_setting.sv`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv64gc/testlist.yaml`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv64gcv/riscvOVPsim.ic`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv64gcv/riscv_core_setting.sv`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv64gcv/testlist.yaml`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv64imafdc/riscvOVPsim.ic`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv64imafdc/riscv_core_setting.sv`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv64imafdc/testlist.yaml`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv64imc/riscvOVPsim.ic`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv64imc/riscv_core_setting.sv`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv64imc/testlist.yaml`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv64imcb/riscvOVPsim.ic`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv64imcb/riscv_core_setting.sv`
- `hw/vendor/lowrisc_ibex/vendor/google_riscv-dv/target/rv64imcb/testlist.yaml`
- `sw/device/silicon_creator/rom_ext/imm_section/prebuilts/nop.o`
- `util/openocd/target/BUILD`
- `util/openocd/target/lowrisc-earlgrey-fpga-backdoor.cfg`
- `util/openocd/target/lowrisc-earlgrey-lc.cfg`
- `util/openocd/target/lowrisc-earlgrey-z1-silicon.cfg`
- `util/openocd/target/lowrisc-earlgrey.cfg`
