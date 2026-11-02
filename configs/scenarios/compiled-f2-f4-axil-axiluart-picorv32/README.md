# AXI4-Lite IP target (F2 read / F4 write): PicoRV32-AXI x ZipCPU axiluart

This descriptor drives the pinned ZipCPU `axiluart` AXI4-Lite slave as an IP
target through the protocol-independent `compiled_mmio` executor.  The CPU is
the pinned PicoRV32 AXI4-Lite core; the target artifact kind is
`axi4lite_register_observe`, selected by
`myfuzz.integration.target_axi4lite.target_adapter`.

## Selected register

`SETUP` at window offset `0`, 32 bits, `rw` (`configs/peripherals/zipcpu_axiluart/component_profile.json`).

* Read (`F2`): `axiluart.v:662-672` returns `{1'b0, uart_setup}` and has no
  read side effect.
* Write (`F4`): `axiluart.v:337-349` stores `new_setup[30:0]`, so a full-word
  write stores bits `30:0` and bit 31 is dropped.  The sidecar therefore
  declares `read_mask = write_mask = 0x7fffffff` with the explicit
  `full_word_reserved_zero` policy and the profile's declared
  `write_resets_uart_state` side effect.  The fuzzed F4 records must have bit
  31 clear, which the descriptor's records do.
* `FIFO_STATUS` is read-only; `RXREG`/`TXREG` read back status/flow state, not
  the written word, so none of them is an honest full-word readback register.

The write side effect (UART state reset) is a declared register property, not a
bus effect: AW/W/B and AR/R stay independent of it.

## Files

| file | purpose |
| --- | --- |
| `generic_scenario.json` | descriptor: `compiled_mmio` for F2/F4 |
| `compose.json` | CPU `cpu` + device `peripheral`, window base `0x40001000`, size 16 |
| `requests/cpu.json` | PicoRV32 AXI4-Lite CPU (v1) |
| `requests/uart.json` | axiluart target (v2): `target.axi4-lite` v1 `single-outstanding-error-codes`, `rx=1`/`cts_n=0` fixed pins |
| `test_capability.json` | `ip_test_capability.v3`, SETUP semantics only |
| `execution_supplement.json` | empty supplement (no extra sources/ownership) |
| `acceptance_sequence.json` | `F4`, `F2`, `F4`, `F2` |

## Static verification (no RTL run here)

`create_preparation` on this descriptor produces executable F2/F4 paths and
`flow_support == supported` for both, with the bank template
`target.axi4-lite/1/single-outstanding-error-codes`, `internal_storage_version
= unknown` and `reward_eligible = false`.  `tests/integration/test_target_axi4lite.py`
also decodes every `f2_records`/`f4_records` entry against the compiled
candidate layouts.

## Not verified here

The real native AXI4-Lite AW/W/B and AR/R handshakes, the readback value and
the dependent RAM store are produced by the remote execution the main agent
owns; this checkout only contains the static selection and synthetic joins.
