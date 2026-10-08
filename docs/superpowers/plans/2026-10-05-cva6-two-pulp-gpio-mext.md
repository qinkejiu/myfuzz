# Generated CVA6 and two PULP GPIO M_EXT acceptance

1. Write a dedicated real-RTL acceptance with assertions for CPU image mutation,
   committed setup, A output, B synchronized input/PADIN and native IRQ, CVA6
   M_EXT ISR/RAM/MRET, exactly-once transactions, epoch zero and fresh replay.
2. Run RED with the CPU output store absent, then add that store to the test
   firmware and run GREEN. Existing generated sessions/router remain the runtime.
3. Mutate only the eight immediate bits of the CPU memory image using
   DependencyGraph, choose_mutation and mutate_genome: 0x01 -> 0x81.
4. Keep GPIOs in separate generated APB3 harnesses. Bind A.gpio_out[7:0] to
   B.gpio_in[7:0], and B.irq to cpu.irq_external with a finite four-CPU-tick
   irq_pulses policy. irq_timer and unrelated GPIO input bits remain zero.
5. Verify source-accurate INTSTATUS read-to-clear at 0x24, not W1C; decode CVA6
   64-bit MMIO and RAM write lanes and require full-word APB writes.
6. Record the focused command/result and scope in a report and a short runtime
   documentation addition. No staging, commit or pre-existing tree cleanup.

Scope: pinned CVA6 packed AXI4 profile and pinned PULP GPIO PAD_NUM=32,
NBIT_PADCFG=4, APB_ADDR_WIDTH=12. No PLIC/full SoC/global cycle timing or
bug-found claim. Evidence bundles are generated in the test temporary directory.
