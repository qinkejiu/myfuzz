# Generated CVE2 → PULP SPI → RAM chain

The generated CVE2 CPU executes a real RV32 program from persistent RAM. Its
OBI data master writes PULP SPI CLKDIV `1`, SPILEN `0x00200000`, and STATUS
`0x101` through the declared APB3 router window at `0x40000000`. The program
polls the RTL STATUS RX FIFO fill count, reads RXFIFO at `0x20`, and stores
the returned word to RAM at `0x20000`. The external mode-0 peer starts with
the literal `A5 C3 96 F0`; it drives SDI1 per HCLK from actual SCK/CS pin
observations. SDI0/2/3 are zero. No register value is substituted by the host.

The real run observed the three CPU MMIO writes in order, a CPU RXFIFO read
returning `0xA5C396F0`, 32 selected SPI rises, a native EOT pulse, and a CPU
memory write of the same value to `0x20000`. The CPU IRQ input is fixed zero:
this accepted SPI profile exports native event pulses for observation and
does not declare a level interrupt path to the CPU. No IRQ delivery is claimed.

`save_evidence_bundle` ran with a concrete `ResourceBudget`; a fresh RTL
`replay_evidence_bundle` matched the saved trace and RAM result. The generated
v2 manifest pins both artifacts and the SPI literal source before execution.
The test also changes the literal source to `A5 C3 96 F1` in another budgeted
run and requires the actual RAM result and semantic trace to change.

Run from a checkout with the pinned CVE2 and PULP SPI submodules populated:

```bash
MYFUZZ_SCENARIO_REAL=1 PYTHONPATH=src python3 -m unittest tests.integration.test_scenario_cve2_pulp_spi_real -v
```

This acceptance covers CLKDIV=1 single-line mode 0. CLKDIV=0 RX, quad mode,
command/address/dummy framing, threshold IRQ rearm, and repeated SPI transfers
in one reset epoch remain outside the accepted runtime scope.
