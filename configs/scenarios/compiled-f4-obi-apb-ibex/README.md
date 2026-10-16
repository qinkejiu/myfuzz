# Experimental compiled F4 with Ibex

This declarative variant selects `configs/cpus/ibex_obi_local/component_profile.json` for the existing `compiled_f4_obi_apb` executor. It requires the same exact compiled-artifact admission, ownership/physical mapping, native OBI/APB hop consumers and live GPIOEN authority as the original fixture. No runtime component-name branch is needed.

The profile declares RV32IMC with RVFI disabled and native instruction/data error inputs (`instr_err_i`, `data_err_i`). The generated renderer exposes these actual inputs as the OBI trace `error` role at `cpu_physical_abi`. The executor uses its fixed RV32I writer subset; this configuration does not claim instruction retirement or arbitrary instruction search.

The configured boot base is `0x10000`. Ibex's declared `PC_BOOT` expression `{boot_addr_i[31:8], 8'h80}` predicts the first fetch at `0x10080`. The executor must observe the actual native first acceptance and install the first candidate there. The prediction is not accepted as runtime evidence.

The declared `ram` resource belongs to `processor` and spans `0x10000..0x3ffff`, with read, write and execute permission and `preload` initialization. Its final word `0x3fffc..0x3ffff` is reserved for CPU readback. A 48-byte writer beginning at `0x10080` fits; 64 contiguous writers would end at exclusive address `0x10c80`, below the result word. The unmaterialized gap before the observed fetch is not executable candidate content. An actual first fetch outside the admitted image or an exhausted instruction arena is refused.

The GPIO peripheral, `0x40001000..0x40001fff` aperture, capability sidecar and ownership requirements are shared in meaning with the original fixture. GPIOEN is at `0x40001004`. The sidecar is copied into this directory so consumers can pass this configuration's explicit `test_capability.json` to `build_path_compile_request`; it is not implicitly loaded by `compose.json`. External environment links and ownership must still be supplied explicitly by the caller.

Select the explicit executor through `create_compiled_execution(..., executor='compiled_f4_obi_apb')` only after constructing this fixture's admitted artifacts and exact compiled inputs. `assess_compiled_f4_support` is a pure support inspection and never grants runtime admission. Do not reuse a generated harness set or prefix from the CV32 fixture: the CPU source/profile/artifact identity differs.

The original `../compiled-f4-obi-apb` CV32E40P configuration now has a separate legal success-only no-error ABI policy, verified in software for this increment. Its native OBI trace has no error role, and native CPU error observation remains unsupported. A synthetic adapter error constant cannot substitute for a physical CPU error input.

Status: frozen source bdeee0b established three continuous Ibex cases and two matching fresh prefixes; see `docs/reports/compiled-f4-ibex-verification-20261017.md` for exact source pins and receipts. This newer candidate-layout/audit increment has software verification only and has not run native. Older CV32 evidence does not validate either source. Any future heavy gate must hold `.superpowers/heavy-worker.lock`; remote operations must follow `agent.md` and remain under `/root/fanzehui` through `jumpserver`.

## Public file entry

`example_records.json` supplies three explicit eight-byte input records. The
low four bytes select GPIOEN (`0x55`, `0xaa`, `0x12345678`); the high four bytes
supply the declared GPIO input pins (`0x12345678`). These are candidate inputs,
not expected native results or live authority. The code-owned D3 candidate layout
sets record length and independent source slices; these declarations happen to
produce 32+32 bits. Narrow pins and additional declared pins have their own slices.
All records are decoded before native startup. Each fresh replay saves its full
prefix, events, role-to-PID/nonce map, actual child return codes, and comparison.

The following command is provided for a future authorized execution; it has
not been run. The output directory must not exist:

```bash
python3 scripts/run_compiled_dataflow.py \
  --compose configs/scenarios/compiled-f4-obi-apb-ibex/compose.json \
  --ip-capability configs/scenarios/compiled-f4-obi-apb-ibex/test_capability.json \
  --supplement configs/scenarios/compiled-f4-obi-apb-ibex/execution_supplement.json \
  --records configs/scenarios/compiled-f4-obi-apb-ibex/example_records.json \
  --executor compiled_f4_obi_apb \
  --output runs/compiled-f4-ibex-file-entry \
  --cache-dir .superpowers/compiled-f4-ibex-cache \
  --heavy-lock .superpowers/heavy-worker.lock \
  --replays 2
```

For a remote frozen snapshot, pass the canonical shared lock
`/root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock` instead
of the snapshot's local lock. Follow `agent.md` for transport and file scope.
The entry writes exact declarations, compiled paths, native events, prefix,
replay conclusions and timing reports. It remains an experimental directed
entry, with no coverage-guided search or full P7 acceptance claim.
