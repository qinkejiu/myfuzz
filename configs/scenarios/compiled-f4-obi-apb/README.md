# Compiled F4: legal OBI ABI without CPU error pins

This original CV32E40P profile is a success-only positive candidate for the same
`compiled_f4_obi_apb` executor. Its physical instruction/data endpoints have no
error role. The runtime records error observation as `null`; it never inserts
an error=0 tap. Code-owned selected no-error contracts require the explicit
`error_response=false` profile fact and reviewed backend ERR fail-stop adapter.
A requirement for native CPU error observation is unsupported on this ABI.

The existing receipt violations, exact declared edge hops and chain hop
assertions remain required. They check successful consumption, actual native
OBI/APB joins and authoritative GPIOEN versions, and make no CPU trap/error
observation claim. Native APB failures are still rejected, while backend ERR
must terminate this CPU boundary with a real nonzero process exit.

The declared read/write/preload RAM arena is `0x10000..0x3ffff`; `0x3fffc` is
reserved for CPU readback. The profile's boot base is `0x10000`; execution must
observe the actual first accepted native fetch before materializing writer
slots. No Ibex boot-offset assumption is reused. The example records remain
32-bit GPIOEN plus the separately declared 32-bit external pin slice.

This increment has software verification only. Older frozen CV32 evidence and
Ibex bdeee native evidence do not validate the new error-policy source closure.
Future gates must use a new independent full snapshot and explicit canonical
heavy lock. The generated boundary ERR command below is **provided, not run**:

```bash
python3 scripts/check_compiled_obi_no_error_boundary.py \
  --base-dir "$PWD" \
  --compose configs/scenarios/compiled-f4-obi-apb/compose.json \
  --ip-capability configs/scenarios/compiled-f4-obi-apb/test_capability.json \
  --supplement configs/scenarios/compiled-f4-obi-apb/execution_supplement.json \
  --output-dir /path/to/NEW-boundary-evidence \
  --cache-dir /path/to/cache \
  --heavy-lock /root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock
```

The diagnostic admits actual generated artifacts, waits for a native first
fetch/backend acceptance, injects one instruction backend ERR and requires
both native fatal text and actual nonzero child exit. It saves source hashes,
raw commands/replies, accepted physical taps, PID/nonce, stderr and exit receipt.
It proves only that generated boundary's fail-stop behavior. Also run the
existing focused adapter RTL test when a native verification window is granted:
`tests/protocols/test_obi_processor_memory_adapter_rtl.py::ObiProcessorMemoryAdapterRtlTests::test_backend_error_fail_stops_when_cpu_has_no_obi_error_channel`.
Both CPU profiles still need new continuous three-candidate/two-fresh gates;
this source increment makes no P7 or arbitrary instruction-search claim.
