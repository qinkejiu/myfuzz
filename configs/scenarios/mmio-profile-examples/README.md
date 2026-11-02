# Generate a basic APB MMIO scenario

Start with already-adapted CPU and IP request files and an IP capability
sidecar. Provide their endpoint names, a side-effect-free read/write register,
the mapped base address, executable RAM range and legal write values.

```sh
python3 scripts/generate_mmio_scenario.py \
  --config configs/scenarios/mmio-profile-examples/spi-ibex.json \
  --output runs/my-spi-scenario
python3 scripts/preflight_generic_scenario.py \
  --descriptor runs/my-spi-scenario/generic_scenario.json
```

The output contains the compose, empty execution supplement, public
`compiled_mmio` descriptor and a write/read sequence. Original and fresh
executions can use `scripts/run_generic_scenario.py` with that descriptor and
the generated `acceptance_sequence.json`. Generation and static preflight do
not run the RTL. The IP profile and sidecar must describe the register and its
write mask; pin values and reset behavior come from the existing request.

The first version supports one APB3 target, a 32-bit side-effect-free rw
register and F2/F4. It does not create interrupt, DMA, internal register
version or CPU retirement evidence.
