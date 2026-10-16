# BOOM machine external interrupt variant

This opt-in artifact preserves the frozen `configs/cpus/boom` profile and native
passes. It uses the same authenticated four RTL sources and 47 physical ports.
Only `auto_int_local_in_2_0` is released from its constant-zero action and assigned
to a separate interrupt endpoint. It is the real MEIP input through IntXbar_1.

Status: software contracts passed; no IRQ native build or runtime gate yet.
`probe_contract.json` contains required candidate instance paths from actual RTL.
These are **not confirmed generated symbols**. The separate build uses read-only
VPI probes and refuses missing names, wrong full names, or incorrect widths. It
stores the actual inventory, generated symbol source and executable hashes.
The session checks this closure again before executing a testcase.

After explicit heavy-window allocation, use a fresh IRQ output directory:

```sh
python -m myfuzz.local_harness.boom_irq_generation \
  --repo "$PWD" --output /root/fanzehui/boom-irq-verification-20261017/artifact \
  --heavy-lock /root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock
```

Use the target's prescribed `environment.sh`/Python library environment. Remote
operations must follow `agent.md` through the SSH transit. The builder takes the
canonical lock nonblocking, writes actual build/probe-describe exit files, and
will not overwrite an output containing a baseline `session-artifact.json`.
No command above has been run for this variant.

`make_boom_gpio_irq_runner` / `make_boom_gpio_irq_genome` use the ordinary Runner,
queued DataflowRouter and actual generated PULP GPIO. A real GPIO IRQ rising edge
is mapped to a declared fixed 64 CPU tick pulse; a second overlapping edge is
unsupported and never extends the first pulse. The input pin action waits for
actual CPU ready RAM and observed CSR enable state. RAM is not initialized with
expected handler results.

The static RV64 image installs mtvec=0x80000400, initializes mie/mideleg, enables
MEIE/global MIE and configures the GPIO rising edge. ISR reads actual mcause/mepc,
disables MEIE, reads real read-clear status twice, stores these values and handler
completion, then executes MRET. Foreground writes a separate resumed marker.
RAM: 0x3000 ready; 0x3010 cause64; 0x3018 mepc64; 0x3020 status32;
0x3024 cleared status32; 0x3028 handler done32; 0x302c resumed32.

All passive samples are observation-only. `insn_ret` alone does not identify
MRET: decoding requires actual `io_rw_cmd==4`, `io_rw_addr==0x302` and the return
signal. SRET/DRET do not satisfy that contract. A runtime acceptance gate must
also inspect actual CSR transition, return PC and foreground recovery, actual
GPIO status/read-clear evidence and coherent A/D delivery. None is established
by software tests or schedule completion. Fresh full-prefix equality and
missing/changed IRQ/status controls remain required before runtime claims.
