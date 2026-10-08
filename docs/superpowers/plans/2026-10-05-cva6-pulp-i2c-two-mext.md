# CVA6 + PULP I2C two-round M_EXT plan

## Goal

Prove one continuous testcase can run the existing generated CVA6 AXI4 and
PULP I2C APB3 harnesses independently while real transactions, serial data,
native interrupt levels, and persistent CPU memory form a two-round chain:

```text
CPU writes I2C address command
→ PULP I2C RTL completes the address phase and raises its native IRQ
→ CVA6 M_EXT handler records STATUS/mcause and IACKs
→ main resumes and issues CMD=0x68
→ I2C RTL clocks the selected peer byte and raises its read-completion IRQ
→ CVA6 M_EXT handler reads RX/STATUS/mcause, IACKs, and returns
→ main resumes and writes the final RAM marker
```

The only fuzzable source is the external `peer_response` byte. It changes
`0x5a→0xa6`; firmware and memory images remain fixed. The event graph must keep
this mutable data route separate from the two completion IRQs, which are
caused by the fixed CPU I2C commands.

## Implementation

1. Reuse the generated CVA6 session, generated PULP I2C session, abstract
   `DataflowRouter`, persistent RAM, dependency/mutation APIs, and evidence
   replay. Keep the DUTs in their own harness processes.
2. Route the real CVA6 AXI4 MMIO transactions through the I2C device window at
   `0x40000000`. Bind the I2C RTL's native `interrupt_o` to CVA6
   `irq_external`; hold `irq_timer` fixed low.
3. Use fixed program images at RAM/ROM and direct M_EXT vector `0x10100`. The
   first ISR entry reads STATUS/cause, issues CMD IACK, writes a marker, and
   MRETs. Main then starts the read command. The second ISR reads RX,
   STATUS/cause, issues a second CMD IACK, writes a marker, and MRETs.
4. Select the byte through one START Genome action. Reverse dependency search
   for the persistent RX result must select only
   `external_i2c_peer→i2c.rxdata→cpu.mmio_rdata→cpu.peer_result_ram`.
   Represent fixed command-to-completion-to-ISR events separately so the
   mutable peer byte is not incorrectly credited with causing an IRQ.
5. Assert exact MMIO order, I2C wire bits, two native IRQ high/low transitions,
   both M_EXT causes, ACK/NACK status, RX/RAM values, MRET continuation,
   unique once-only transaction identities, epoch-zero continuity, and full
   fresh evidence replay.
6. Record the first firmware assertion failure and its correction, the
   focused session-FSM test result, the final real-RTL run, and the bounded
   profile in the report and runtime matrix.

## Acceptance criteria

- Only `peer_response` changes between the `0x5a` and `0xa6` genomes.
- CPU MMIO writes commit in order: PRESCALER=2, CTRL=`0xc0`, TX=`0x85`,
  CMD=`0x90`, first CMD IACK=1, CMD=`0x68`, second CMD IACK=1.
- RTL wire samples between the committed read command and second IRQ rise
  contain the selected byte MSB first on SDA at SCL rising edges.
- The native IRQ sequence is high→low twice, with each real IACK before its
  low transition; the first low precedes the read command.
- The two real M_EXT handlers record `mcause=0x800000000000000b`; the first
  status reports address ACK (`STATUS[7]=0`) and the second reports master
  NACK (`STATUS[7]=1`).
- RX, both handler markers, and the post-MRET marker persist in testcase RAM
  and match the real MMIO/RAM evidence.
- Every routed MMIO transaction is delivered once with epoch zero. Each
  source-byte genome fully replays in new harness sessions without a reset
  barrier.
- The focused test passes with `MYFUZZ_SCENARIO_REAL=1`; no claim is made
  about complete SoC construction, global cycle timing, broad I2C mode
  coverage, or bug discovery.

## Verification record

- Parallel PULP I2C FSM work: its focused session contract test failed before
  the second-IACK extension and finished at **22 passed, 5 subtests passed**.
- Initial integration RED: both payload subtests exposed a duplicate STATUS
  read caused by sharing the ISR's first STATUS read before branching. The
  firmware was reorganized to branch first; no RTL change was made for this
  test correction.
- Final integration: **1 passed, 2 subtests passed in 72.12s**, including
  peer-byte wire sampling, ACK/NACK, both M_EXT handlers, both fresh replays.
- Independent root rerun of the same frozen code: **1 passed, 2 subtests
  passed in 71.65s**; `git diff --check` was clean.
- Trace `event_id` means receipt append order. It supports the asserted
  cross-transaction precedence and does not claim cycle-accurate ordering
  inside an APB access.
- Exact command and scope are recorded in
  [the acceptance report](../../reports/generated-cva6-pulp-i2c-two-mext-irq-20261005.md).
