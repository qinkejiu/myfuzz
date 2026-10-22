# CV32E40P OBI → PULP SPI APB3 `SPICMD` compiled F4 candidate

This sibling composition declares the CV32E40P split-OBI profile, the pinned
PULP SPI APB3 profile, and the registered `SPICMD` storage source contract.
Its APB window is `0x40001000`–`0x40001fff`; the only compiled register word is
the full-word `SPICMD` access at `0x40001008`. The D3 input stream writes that
word, reads it back through the target response, and stores the returned value
to the declared CPU RAM region. The CPU uses the existing 8/8 reset request.

The peripheral request pins `spi.pins.sdi0..sdi3` to zero and supplies no
external candidate sources. It selects `target.apb3` version 1, `full-word`,
with one outstanding transaction and the versioned
`pulp-apb-spi.spicmd.source.v1` / `SPICMD` observation declaration. It does not
write `STATUS` or start a serial transfer. Use `--executor compiled-f4-rfuzz`
without a `--runtime` family; the composition does not select execution by a
CPU or peripheral name.

This configuration is a software D2/D3 declaration and source selection. The
native first/fresh acceptance is recorded separately under
`docs/reports/compiled-f4-cv32e40p-pulp-spi-spicmd-20261022.md` after that gate
has completed. It is one registered APB3 storage source, not arbitrary APB3,
serial SPI, F6/DMA, P6, P7-E, or aggregate CPU/IP acceptance.
