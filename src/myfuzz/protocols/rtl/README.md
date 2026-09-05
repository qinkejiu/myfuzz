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

An accepted request can wait for its MMIO target for at most 16 cycles.  A
`ready` response on that boundary completes the transaction; otherwise the
16th wait cycle creates a deterministic error response.  The same bounded
counter also applies to incomplete protocol request handshakes where relevant.

Responses follow normal valid/ready backpressure semantics.  Once a response
is available, its valid signal, payload, and error status remain stable until
the initiator accepts it.  Response backpressure never restarts or advances a
request timeout.

## Error mapping

All errors are deterministic.  MMIO `error` and a bounded timeout map to
`PSLVERR` for APB4, `BRESP`/`RRESP = SLVERR` for AXI4-Lite, and `d_error` for
TL-UL.  Unsupported TL-UL opcodes follow the same `d_error` path.

## Resource constraints

The implementation uses only fixed-width registers and explicit FSM states:
there are no queues, dynamic allocation, unbounded counters, `$random`, or
waveform generation.  This keeps runtime resource use predictable and supports
low-resource fuzzing campaigns alongside other processes.
