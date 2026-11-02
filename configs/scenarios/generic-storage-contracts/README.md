# Generic APB storage contract matrix

Each JSON file declares one reviewed APB3 stable-storage row. It is a
*selection* document: the source contract, register and aliasing facts remain
code-owned in `src/myfuzz/local_harness/apb_storage_source_contract.py`. No
consumer selects an adapter, kernel or template by component or instance name.

| scenario | source contract | register | offset | APB decode | flows | instance |
|---|---|---|---|---|---|---|
| `timer` | `pulp-apb-timer.ctrl0.source.v1` | `TIMER0_CTRL` | 4 | `PADDR[4:2]==1` | F2, F4 | `peripheral` |
| `spi` | `pulp-apb-spi.spicmd.source.v1` | `SPICMD` | 8 | `PADDR[5:2]==2` | F2, F4 | `peripheral` |
| `gpio` (G7) | `pulp-apb-gpio.paddir.source.v1` | `PADDIR` | 0 | `PADDR[6:2]==0` (128-byte alias) | F2, F4 | `peripheral` |
| `renamed-gpio` (G7) | `pulp-apb-gpio.paddir.source.v1` | `PADDIR` | 0 | same | F2, F4 | `gpio0` |
| `wishbone` (G8.1a) | `zipcpu-wbuart.setup.storage.v1` | `SETUP` | 0 (word 0) | `i_wb_addr==2'b00`, 16-B window | F2, F4 | `peripheral` |

The GPIO row reuses the existing pinned `pulp_gpio` source-lock record and its
elaboration closure (`configs/soc/closures/pulp_gpio.json`); only the storage
profile, capability sidecar, scenario fixtures and the closed source-contract
document are new. `PADDIR` is the only claimed row: `PADOUT`, `PADOUTSET`,
`PADOUTCLR`, `PADIN`, `PADCFG*`, `INTEN`, `INTTYPE*`, `INTSTATUS`, `interrupt`
and the pins are explicitly outside this contract. `PADOUTSET`/`PADOUTCLR` are
refused as non-storage selections.

`non_alias_register_offset` is used by the real refusal probe; for GPIO it is 4
(`GPIOEN`), which is not a `PADDIR` alias. `alias_register_offsets` is
documentary (0, 128, 256, 384 are PADDIR aliases).
