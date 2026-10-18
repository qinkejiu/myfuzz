# Native packet session independent source review

Reviewed freeze: `d5b8191177d76ca5dc661db517df85f5b05e88ed`.

| File | SHA-256 |
|---|---|
| `src/myfuzz/scenario/native_packet_session.py` | `36d6588cc45e90dfc9987daedc1a433b10394dbdd1209e505ca51931602dc942` |
| `src/myfuzz/integration/picorv32_native_online.py` | `799d1b5e9cfe8bdb2aad85a46d2effb61d9f70dca191ffc1ed4d9a08e3ecf07b` |

## Result: source-only CLEAN

No blocking High/Medium finding in this bounded guard increment. Independent
read-only review; no tests, project imports, frontend, build, model or remote run.

- Actual session submission checks the current offered instruction address and
  drained pending state before inherited input effects, then checks the next
  address and drained state before returning success (session lines147–173).
- Exactly one four-byte ADDI x10,x0,u8 source, or one GPIO byte plus exact fixed
  NOP support, is admitted. The fixed128-round schedule,96 packets,32-byte
  stride and97 reserved source/guard slots are retained (lines43–57,117–145).
- A successful duplicate uses inherited exact case/source-role comparison and
  authoritative event-slice receipt recovery, without clocks or cursor advance.
  A terminal failure blocks cache revival (lines148–153; base session1557–1566).
- Pre/post/effect failures poison the session and retain the first failure.
  Cleanup is attempted once; cleanup/collection errors do not replace the
  primary exception (lines87–115). Runner finalization is idempotent. The
  directed wrapper also sends decoder-commit failures through this abort path.
- Construction starts no DUT subprocess: generated sessions initialize their
  process handle to None; startup occurs in begin. Construction failure therefore
  does not leave a started DUT from this factory.

## Remaining boundaries

Generic fresh replay still reconstructs a generic ScenarioSession, rather than
the guarded subclass. Executor-side decoder commit-failure notification is also
not integrated here. Both are explicit follow-on requirements before safe RFuzz
assembly; this review does not approve either absent integration.

Inherited finish/export can preserve a failed prefix marked uncertain_effect;
that is not a successful packet result. No new source authority, instruction
retirement, native bus-completion feedback or closed-loop grant is established.
The new guard and passive taps have no runtime pass from this review and cannot
inherit the older c924aac directed gate result.
