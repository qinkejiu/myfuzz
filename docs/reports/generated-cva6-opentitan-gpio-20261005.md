# Generated CVA6 to OpenTitan GPIO acceptance

## Scope

This acceptance connects the generated CVA6 packed 64-bit/ID4 AXI4 CPU
session to a separate generated OpenTitan GPIO TL-UL session. The CPU and GPIO
run in independent RTL harnesses. `DataflowRouter` accepts a CVA6 AXI
transaction and later delivers it to the GPIO's actual TL-UL register service;
it does not emulate a bus, bridge, arbiter, or global SoC clock.

The route supports aligned, single-beat, 32-bit MMIO accesses. AXI address,
data lane, byte strobe, ID, and response handshake are checked at the CPU
boundary. The router maps the selected 32-bit lane and byte enables to the
GPIO register transaction. RAM traffic continues through its own persistent
memory service and transaction ledger. MMIO uses a separate source sequence
ledger, so an unresolved peripheral transaction cannot create a sequence gap
in the RAM ledger. The AXI service still permits only one outstanding request
on each read/write channel; a waiting MMIO request can backpressure later
requests on its own channel until the target response arrives.

The GPIO scenario itself uses full 32-bit byte enables (`WSTRB=0xf`). Legal
partial-strobe lane mapping is covered by unit-level Router/protocol checks,
but partial-byte writes through CVA6 into the real GPIO CSR were not tested.

## Test scenario

The pinned CVA6 RTL executes a program which:

1. writes `0xa5` to GPIO `DOUT` at offset `0x14`;
2. writes `0xff` to GPIO `DOE` at offset `0x20`;
3. reads `DOUT` from the real GPIO RTL;
4. stores the returned value to persistent RAM at `0x20000`.

The testcase records the two CPU-originated MMIO writes, the GPIO RTL output
(`gpio_out=0xa5`, `gpio_dir=0xff`), the lane-positioned 64-bit AXI read
response, and the CPU's decoded 32-bit RAM write (`0xa5`). No source input
overrides a bound MMIO response or fabricates GPIO output.

## Evidence

Command:

```sh
PYTHONPATH=src:. python3 -m unittest \
  tests.integration.test_scenario_cva6_generated_opentitan_gpio_real -v
```

Result: 1/1 passed in 81.930 seconds, including evidence-bundle replay using
fresh CPU and GPIO harness instances. Additional protocol, Router, and
continuous-runner regressions passed 19/19. `py_compile` and `git diff --check`
passed.

## Limits

This is one CVA6-specific packed AXI4 CPU and one OpenTitan GPIO target. It does
not establish profile-only reuse for other AXI4 CPUs. Burst MMIO, sub-word
MMIO, GPIO IRQ delivery into CVA6, and an ISR-driven reverse chain are not part
of this acceptance. RAM AXI bursts and byte strobes remain handled by the
existing memory service. If a target MMIO effect becomes uncertain, the CVA6
session refuses a local reset and preserves the uncertain transaction record;
recovery requires replaying the testcase from its initial state. No claim is
made about global cycle-accurate SoC timing.
