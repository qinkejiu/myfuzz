# CV32E40P ↔ OpenTitan UART RX watermark interrupt

## Scope

This directed testcase runs the pinned OpenHW CV32E40P CPU and pinned OpenTitan
UART RTL in separate generated local harnesses. It checks this cross-component
path:

```text
Genome RX byte 0x5a
→ local 8N1 UART peer
→ real OpenTitan UART RX FIFO and watermark output
→ bound CV32E40P irq_i[11]
→ real MEI acknowledgement and CPU ISR
→ real INTR_STATE/RDATA reads and persistent RAM writes
→ FIFO pop lowers the real UART IRQ
```

The testcase retains the CPU and UART state throughout one scenario and uses a
fresh pair of harnesses to replay the evidence. It does not build a SoC, bus
fabric, bridge, arbiter, PLIC, or shared cycle-accurate clock.

## Setup and local constraints

The CPU program configures UART `CTRL` at offset `0x10` and
`INTR_ENABLE.RX_WATERMARK` at offset `0x04`. The testcase asserts that the CPU
produces exactly those two writes once, in that order. The RX value is owned by
the scenario source at `uart.uart_rx_byte`; the CPU `irq` input is bound to the
UART's real `uart_rx_watermark` output. The Fuzzer does not write the CPU IRQ
after that binding is installed.

The UART peer starts the serial frame after its declared idle delay and drives
the real UART RX pin. The local UART session does not permit TL-UL accesses
while the serial waveform is active, because such an access would add UART
local ticks and distort the frame. The CPU ISR therefore executes 64 real NOP
instructions after interrupt entry before accessing the UART. This preserves
the UART's own sampling schedule without imposing a global SoC clock model.

CV32E40P stores the `mtvec` base in bits `[31:8]`; the low address bits are
discarded. The program therefore writes `mtvec=0x10100`. The vector table
starts there: its direct-mode entry jumps to the delay block at `0x10200`,
while the IRQ 11 vectored slot at `0x1012c` loops forever. The ISR instructions
start at `0x10300` after 64 real NOPs, allowing the serial peer's local waveform to
finish without placing a NOP sled at the trap vector. The test also checks that
the first accepted instruction fetch after CPU acknowledgement is `0x10100`.
The initial attempt used `0x1012c`; the pinned RTL redirected the trap to
`0x10100`, so that attempt executed uninitialized memory and did not reach the
ISR. Aligning the vector and making the other vector slots fail closed fixed
the testcase. This was a firmware-fixture error, not a UART or CPU RTL defect.

## Observed RTL behavior and assertions

The trace checks that:

- The Genome injects exactly `0x5a` as the RX source value.
- UART receives the byte without frame, parity, or overflow errors and its
  native `uart_rx_watermark` output becomes high.
- The high UART output is delivered to the CPU's bound `irq` input, and a real
  CPU sample asserts `irq_ack_o=1` with `irq_id_o=11`.
- The CPU executes its ISR and reads UART `INTR_STATE` (watermark bit set) and
  `RDATA` (low byte `0x5a`) in that order.
- The ISR writes the real received byte and observed status word to persistent
  RAM at `0x20000` and `0x20004`.
- Reading `RDATA` pops the single-byte FIFO; the UART's native watermark output
  then becomes low and that low value is delivered to the CPU.
- MMIO transaction identities are unique, both sessions remain in reset epoch
  zero, and the testcase contains no reset barrier.

The evidence replay uses fresh CPU and UART session objects. It must match the
saved trace and reproduce both RAM words.

## Verification

Command:

```sh
MYFUZZ_SCENARIO_REAL=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src JOBS=1 \
  pytest -q tests/integration/test_scenario_cv32e40p_opentitan_uart_irq_real.py
```

Result: `1 passed in 35.60s`, including saved-evidence replay. Python syntax
compilation also passed with `python3 -m py_compile` on the integration test.

## Limits

This proves one CV32E40P/OpenTitan UART configuration, one 8N1 byte, one RX
watermark interrupt, and one fresh replay. It does not establish generic
interrupt support for every OBI CPU profile, arbitrary UART compatibility,
concurrent TL-UL access during an active RX frame, PLIC behavior, a concrete
SoC topology, or coverage-guided bug discovery. The OpenTitan source-lock
`runtime_status` remains `runtime_unverified`.
