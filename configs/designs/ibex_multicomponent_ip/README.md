# Ibex Multi-Component IP Target

This is the first-stage target for the CPU + common-IP experiment.

```text
ibex_core
  + instruction RAM model
  + data RAM model
  + timer
  + GPIO
  + UART
  + SPI
```

The CPU is the real `ibex_core` from `third_party/rfuzz/upstream/ibex` on the
remote machine.  The first IP set is intentionally lightweight and local to this
directory so the comparison framework can be tested before replacing any IP with
larger third-party cores.

## Schemes

```text
baseline_direct_slice/config.json
depaware_projection/config.json
```

Both use the same top, same generated filelist, same instrumentation settings,
same 512-bit RFuzz input width, and same coverage denominator.  The only intended
difference is the harness mapping from `rfuzz_input_bits` to wrapper inputs.

## Running

Local machine:

```bash
python3 configs/designs/ibex_multicomponent_ip/scripts/run_local_smoke.py
```

Remote machine:

```bash
ssh inner70
cd /root/fanzehui/myfuzz
bash configs/designs/ibex_multicomponent_ip/scripts/run_remote_smoke.sh
```

Do not run RFuzz server/fuzz locally for this target.

## Current smoke status

Last checked on the remote server under `/root/fanzehui/myfuzz`:

```text
frontend/instrument/toml/harness: passed for both schemes
server build: passed for both schemes
short fuzz smoke: 10 seconds per scheme, passed for both schemes
instrumented HDL files: 36
instrumentation coverage points: 1123
generated harness coverage width: 1194 bits (IBEX_MCIP_COVERAGE_MSB=1193)
```

The 10-second fuzz smoke is only a sanity check, not a formal coverage result:

```text
baseline_direct_slice: queue_entries=1, crashes=0, first interesting input newly covered 122 points
depaware_projection:   queue_entries=1, crashes=0, first interesting input newly covered 158 points
```
