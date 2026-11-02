# cv32e20 (OBI) + Caliptra SHA256 through the AHB-Lite MMIO target

This is a configuration-only F2 combination. It uses the existing cv32e20 OBI
processor request, the pinned `caliptra_sha256` profile and the
`target.ahb-lite@1/full-word-single` generated target. It adds no IP executor,
no AHB peer and no internal-state probe.

The selected register is `NAME0` at window offset 0 (absolute `0x40000000`), a
32-bit read-only constant: the real RTL drives `SHA256_CORE_NAME0 = 0x61327368`
("sha2") from `sha256.sv:377` / `sha256_params_pkg.sv:19`, and the register
readback path is `sha256_reg.sv:1524`. The F2 corpus is the little-endian
window address `00000040`.

## F4 gap (explicit)

The profile has **no 32-bit read/write register**. Its writable registers
`CTRL` and `BLOCK0..15` are declared `wo`; the RTL readback for them is zero
(`sha256_reg.sv` has no readback entry for `CTRL`, and the pinned report
`docs/reports/caliptra-sha256-ahb-target-20261017.md` records "CTRL/BLOCK are
software write-only ... their reads return zero"). The existing F4 flow writes
and then reads back the same word, so it cannot certify a stored value here.

A capability declaration is refused earlier as well: the profile side effects
`algorithm_control` and `hash_block_input` are not in the sidecar's supported
side-effect vocabulary, so `load_ip_test_capability` raises
`unsupported-register-field-side-effect`. The prepared F4 path is therefore
`unsupported` with `writable-field-undeclared`, and this descriptor intentionally
declares only F2. F4 on this IP requires either a real read/write register or an
explicit write-only policy; neither is invented here.

## Commands

```sh
PYTHONPATH=src:. python3 -m pytest tests/integration/test_target_ahb_lite.py -q

PYTHONPATH=src python3 scripts/run_generic_scenario.py \
  --descriptor configs/scenarios/compiled-f2-ahb-sha256-mmio/generic_scenario.json \
  --flow F2 --mode original --case NEW_OUTPUT --cache CACHE \
  --records-file configs/scenarios/compiled-f2-ahb-sha256-mmio/acceptance_sequence.json
```

The runtime is `compiled_mmio`; actual evidence must be a real CPU OBI read plus
the AHB address acceptance and data-phase completion. The public certificate is
`compiled_mmio_case.v1` with `native_cpu_protocol = obi` and
`target_protocol = ahb-lite`. Internal storage version, instruction operand
origin and cross-case consumption authority remain unknown; no reward is
justified from MMIO completion alone.
