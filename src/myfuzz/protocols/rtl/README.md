# Bounded protocol-to-MMIO bridges

This directory contains synthesizable, bounded bridges and target adapters for
APB4, AXI4-Lite, and TileLink-UL.  Every pair uses the same native MMIO
boundary:

```text
valid, write, addr, wdata, be, rdata, ready, error
```

The bridge owns protocol handshakes and translates a completed request to one
MMIO transaction.  The target adapter exposes that transaction to a local
component and translates its `ready`, `rdata`, and `error` result back to the
protocol response.  At most one transaction is outstanding in each bridge.

## Protocol limits

- **APB4** requests always use the required setup then access sequence.  The
  bridge holds `PSEL`, address, direction, write data, and strobe fields stable
  throughout the access wait.
- **AXI4-Lite** supports one single-beat read or write transaction at a time;
  it does not implement bursts.  AW and W may arrive independently, but a write
  reaches MMIO only after both handshakes have completed.
- **TL-UL** supports single-beat `Get`, `PutFullData`, and `PutPartialData`
  requests with one source at a time.  It does not implement multibeat
  transactions or bursts.

## Progress, timeout, and responses

The three protocol bridges bound their request-side and target-side waits to
16 cycles.  A `ready` response on the native MMIO boundary completes the
transaction; otherwise the 16th wait cycle creates a deterministic protocol
error.  For AXI4-Lite, the bridge also bounds incomplete AW/W collection and
the B/R response wait.  The TL-UL bridge bounds both A and D waits.  The APB4
target adapter is intentionally combinational and relies on the APB4 bridge
for this bound; the AXI4-Lite target stores a partial AW/W pair in fixed
registers and its bound starts after the unified MMIO request is accepted.

Responses follow normal valid/ready backpressure semantics.  Once a response
is available, its valid signal, payload, and error status remain stable until
the initiator accepts it.  Response backpressure never restarts or advances a
request timeout.

## Error mapping

All errors are deterministic.  The bridge side maps a protocol response or
internal timeout to the native MMIO `rsp_error_o` result (and zero read data):
APB4 observes `PSLVERR`, AXI4-Lite observes `BRESP`/`RRESP = SLVERR`, and
TL-UL observes denied/corrupt D-channel responses.  The target side maps native
MMIO `error_i` and a target wait timeout back to a protocol error response.
In short: bridge: protocol response and timeout -> native `rsp_error_o`;
target: native MMIO `error_i` and timeout -> protocol error response.
On the TL-UL target, those errors set `d_denied`; malformed or unsupported
A-channel requests set `d_corrupt`.  A denied Get returns `AccessAckData` with
both `d_denied` and `d_corrupt` set, while a denied write returns `AccessAck`
with deterministic zero data.  The public TL-UL interface has no `d_error`
signal.

## Resource constraints

The implementation uses only fixed-width registers and explicit FSM states:
there are no queues, dynamic allocation, unbounded counters, `$random`, or
waveform generation.  This keeps runtime resource use predictable and supports
low-resource fuzzing campaigns alongside other processes.
