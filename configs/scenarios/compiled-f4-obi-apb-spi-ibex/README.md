# Ibex OBI / PULP SPI generic F2/F4 configuration

This configuration reuses the SPI compose, peripheral request, capability,
execution supplement and read records from `compiled-f4-obi-apb-spi-cv32e40p`
without changing their bytes. The processor request is the existing Ibex OBI
request from `compiled-f4-obi-apb-timer`, with instance `processor` and reset
assert/release 2/3 ticks. No CPU/IP-specific Python executor is added.

The admitted APB storage word is SPICMD at offset 8 (`0x40001008`);
`F2:08100040` reads it. F4 uses the same three full-word values as the source
configuration. The SPI input pins remain fixed as declared by its existing
request. This does not exercise a serial transfer.

On 2026-10-28 the actual generated preparation, component verification,
registered adapter selection and generic F2/F4 execution-plan compilation
passed. CPU binding is `cpu.obi/1/read-write`; target binding is
`target.apb3/1/full-word`, `storage.rw.v1`. No DUT/native run was performed for
this configuration on the current source tree. Native original/fresh evidence
remains pending and is not inherited from another pairing.

The shared search entry is `configs/search/spi-ibex.json`.
