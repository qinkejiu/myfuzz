"""Single-pass first-step acceptance metrics for one online run directory.

The analyzer reads every artifact at most once and never materializes an event
stream: JSONL events are parsed line by line, ``MFZ1`` zlib chunk blocks are
inflated one block at a time, and a monolithic ``online_final_trace.json``
document is decoded value by value behind a sliding text buffer. Quantities
that the artifacts cannot prove are reported as ``null`` with an explicit
reason in ``limits``; they are never reported as zero.

Chain certificate accounting is delegated to the frozen producer protocol
(``ingest``/``flush``/``pending_count``). The producer is imported lazily and
may be injected, so this analyzer neither depends on that module landing nor
re-implements its causal rules.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
import hashlib
import json
import math
from pathlib import Path
import statistics
import struct
import zlib


SCHEMA_VERSION = "first_step_acceptance_report.v1"
CERTIFICATE_SCHEMA_VERSION = "runtime_chain_certificate.v1"
CHAIN_DIRECTIONS = ("IP_TO_CPU_TO_IP", "CPU_TO_IP_TO_CPU")
CERTIFIED_STATUS = "certified"
INCOMPLETE_STATUS = "incomplete"
CERTIFICATE_STATUSES = (CERTIFIED_STATUS, INCOMPLETE_STATUS)

DEFAULT_MAX_CERTIFICATES = 200_000
DEFAULT_INGEST_BATCH_SIZE = 256
DEFAULT_CHUNK_CHARS = 1 << 20
MAX_VALUE_CHARS = 32 << 20

PHASE_KEYS = ("selection_decode", "rtl_submit", "trace_digest",
              "interaction_ingest", "checker", "feedback_credit",
              "receipt_build", "total")
RUNNER_PHASE_KEYS = ("scheduler_batch", "runner_step", "router_enqueue",
                     "router_drain", "router_transact",
                     "observed_output_route")
TIMING_FIELDS = ("online_phase_timing_seconds", "online_runner_timing_seconds")

COMPLETE_STATUSES = frozenset({"complete"})
#: Case statuses that count as an invalid/timeout outcome.  ``input_invalid`` is
#: the status the live writer actually emits for a candidate refused before any
#: RTL command (a decode or declared-prerequisite refusal), so it must be
#: classified here: leaving it out made the invalid/timeout ratio uncomputable
#: for every run that refused a candidate, which reads as a missing blind spot
#: instead of the refusal it is.
INVALID_STATUSES = frozenset({"invalid", "invalid_input", "input_invalid",
                              "invalid_case", "invalid_request",
                              "environment_error", "uncertain_effect",
                              "harness_error", "error"})
TIMEOUT_STATUSES = frozenset({"timeout", "timed_out", "budget_exhausted"})
FINDING_STATUSES = frozenset({"dut_violation", "finding", "assertion_failure"})
CLASSIFIED_STATUSES = (COMPLETE_STATUSES | INVALID_STATUSES | TIMEOUT_STATUSES
                       | FINDING_STATUSES)

_TRACE_SCHEMAS = {
    "online_trace_jsonl.v1": ("jsonl.v1", "online_events.jsonl"),
    "online_trace_zlib_chunks.v1": ("zlib_chunks.v1", "online_events.zlib"),
}

_ZLIB_MAGIC = b"MFZ1"
_ZLIB_HEADER = struct.Struct("<IIII")
_ZLIB_MAX_RAW = 8 * 1024 * 1024


class ChainProducerUnavailable(RuntimeError):
    """Raised when no chain certificate producer can be resolved."""


class TraceUnavailable(ValueError):
    """Raised when a run directory holds no streamable event artifact."""


def _load_chain_certificates() -> type:
    """Import the frozen chain certificate producer lazily with a clear error."""
    try:
        from myfuzz.scenario.chain_certificates import ChainCertificates
    except ImportError as exc:  # pragma: no cover - depends on the other module
        raise ChainProducerUnavailable(
            "myfuzz.scenario.chain_certificates could not be imported "
            f"({exc}); land that module or inject chain_producer=") from exc
    return ChainCertificates


def _chain_certificates_available() -> bool:
    """Report whether the default chain certificate producer can be imported."""
    try:
        _load_chain_certificates()
    except (ChainProducerUnavailable, ImportError):
        return False
    return True


def _producer_module_identity() -> dict | None:
    """Identify the default producer bytes, so certificate counts are pinned."""
    try:
        from myfuzz.scenario import chain_certificates
    except ImportError:
        return None
    path = Path(getattr(chain_certificates, "__file__", "") or "")
    identity = {"module": "myfuzz.scenario.chain_certificates",
                "path": str(path), "sha256": None}
    try:
        identity["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        pass
    return identity


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _reject_json_constant(name: str) -> object:
    raise ValueError(f"non-finite JSON constant {name!r} is not accepted")


def _finite_non_negative(value: object) -> float | None:
    if type(value) is int or type(value) is float:
        if math.isfinite(value) and value >= 0:
            return float(value)
    return None


def _finite_positive(value: object) -> float | None:
    if type(value) is int or type(value) is float:
        if math.isfinite(value) and value > 0:
            return float(value)
    return None


class _IncrementalJsonReader:
    """Decode one huge JSON document value by value with a bounded buffer."""

    def __init__(self, path: Path, *, chunk_chars: int) -> None:
        self.path = Path(path)
        self._chunk_chars = chunk_chars
        self._decoder = json.JSONDecoder(parse_constant=_reject_json_constant)
        self._handle = self.path.open("r", encoding="utf-8")
        self._buffer = ""
        self._position = 0
        self._offset = 0
        self._eof = False

    def close(self) -> None:
        self._handle.close()

    def __enter__(self) -> "_IncrementalJsonReader":
        return self

    def __exit__(self, *exception: object) -> None:
        self.close()

    def _fill(self) -> bool:
        if self._eof:
            return False
        chunk = self._handle.read(self._chunk_chars)
        if not chunk:
            self._eof = True
            return False
        self._buffer += chunk
        return True

    def _compact(self) -> None:
        if self._position > 4 * self._chunk_chars:
            self._offset += self._position
            self._buffer = self._buffer[self._position:]
            self._position = 0

    def _skip_whitespace(self) -> None:
        while True:
            while (self._position < len(self._buffer)
                   and self._buffer[self._position] in " \t\r\n"):
                self._position += 1
            if self._position < len(self._buffer) or not self._fill():
                return

    def _location(self) -> int:
        return self._offset + self._position

    def peek(self) -> str | None:
        self._skip_whitespace()
        if self._position >= len(self._buffer):
            return None
        return self._buffer[self._position]

    def expect(self, character: str) -> None:
        found = self.peek()
        if found != character:
            raise ValueError(
                f"invalid JSON in {self.path.name} near character "
                f"{self._location()}: expected {character!r}, found {found!r}")
        self._position += 1

    def decode_value(self) -> object:
        while True:
            self._skip_whitespace()
            try:
                value, end = self._decoder.raw_decode(self._buffer, self._position)
            except json.JSONDecodeError as exc:
                pending = len(self._buffer) - self._position
                if not self._eof and pending < MAX_VALUE_CHARS and self._fill():
                    continue
                raise ValueError(
                    f"invalid JSON in {self.path.name} near character "
                    f"{self._location()}: {exc.msg}") from exc
            self._position = end
            self._compact()
            return value


class TraceEventStream:
    """Lazy bounded-memory reader for one terminal online event artifact.

    ``events()`` may be consumed once. After exhaustion the stream exposes the
    recomputed canonical event digest, which is the same rule the frozen
    writers used for ``semantic_sha256``.
    """

    def __init__(self, run_dir: str | Path, *,
                 chunk_chars: int = DEFAULT_CHUNK_CHARS,
                 verify_semantic: bool = True) -> None:
        if type(chunk_chars) is not int or chunk_chars < 4096:
            raise ValueError("chunk_chars must be an integer of at least 4096")
        if type(verify_semantic) is not bool:
            raise ValueError("verify_semantic must be boolean")
        self.run_dir = Path(run_dir)
        if not self.run_dir.is_dir():
            raise ValueError(f"run directory does not exist: {self.run_dir}")
        self._chunk_chars = chunk_chars
        self._verify_semantic = verify_semantic
        self._digest = hashlib.sha256(b'{"events":[')
        self._event_count = 0
        self._exhausted = False
        self._consumed = False
        self._document: dict = {}
        self._digest_value: str | None = None
        self.descriptor = self._describe()
        self.path = Path(self.descriptor["path"])

    # -- artifact discovery -------------------------------------------------
    def _describe(self) -> dict:
        meta_path = self.run_dir / "online_final_trace.meta.json"
        if meta_path.is_file():
            metadata = json.loads(meta_path.read_text(encoding="utf-8"))
            if not isinstance(metadata, dict):
                raise ValueError("online_final_trace.meta.json is not a JSON object")
            schema = metadata.get("schema_version")
            if schema not in _TRACE_SCHEMAS:
                raise TraceUnavailable(
                    f"unsupported trace metadata schema {schema!r} in "
                    f"{meta_path.name}: no streaming rule is defined for it")
            trace_format, events_file = _TRACE_SCHEMAS[schema]
            if metadata.get("events_file") != events_file:
                raise ValueError(
                    f"online_final_trace.meta.json declares events_file "
                    f"{metadata.get('events_file')!r}, expected {events_file!r}")
            path = self.run_dir / events_file
            if not path.is_file():
                raise TraceUnavailable(
                    f"{meta_path.name} declares {events_file}, but that file "
                    "does not exist")
            return {
                "format": trace_format,
                "events_file": events_file,
                "path": str(path),
                "bytes": path.stat().st_size,
                "meta_schema_version": schema,
                "declared_event_count": metadata.get("event_count"),
                "declared_semantic_sha256": metadata.get("semantic_sha256"),
                "declared_status": metadata.get("status"),
                "declared_local_ticks": metadata.get("local_ticks"),
            }
        monolithic = self.run_dir / "online_final_trace.json"
        if monolithic.is_file():
            return {
                "format": "json.v1",
                "events_file": "online_final_trace.json",
                "path": str(monolithic),
                "bytes": monolithic.stat().st_size,
                "meta_schema_version": None,
                "declared_event_count": None,
                "declared_semantic_sha256": None,
                "declared_status": None,
                "declared_local_ticks": None,
            }
        raise TraceUnavailable(
            f"no online_final_trace.meta.json, online_events.jsonl, "
            f"online_events.zlib or online_final_trace.json in {self.run_dir}")

    # -- iteration ----------------------------------------------------------
    def events(self) -> Iterator[dict]:
        """Yield trace events in artifact order, then validate the count."""
        if self._consumed:
            raise ValueError("TraceEventStream.events() may only be consumed once")
        self._consumed = True
        for event in self._read_events():
            if self._event_count:
                self._digest.update(b",")
            self._digest.update(_canonical_bytes(event))
            self._event_count += 1
            yield event
        self._exhausted = True
        declared = self.descriptor["declared_event_count"]
        if type(declared) is int and declared != self._event_count:
            raise ValueError(
                f"event count mismatch in {self.path.name}: declared {declared}, "
                f"read {self._event_count}")

    def _read_events(self) -> Iterator[dict]:
        trace_format = self.descriptor["format"]
        if trace_format == "jsonl.v1":
            yield from self._read_jsonl()
        elif trace_format == "zlib_chunks.v1":
            yield from self._read_zlib_chunks()
        else:
            yield from self._read_monolithic()

    def _read_jsonl(self) -> Iterator[dict]:
        with self.path.open("r", encoding="utf-8") as handle:
            for number, line in enumerate(handle, 1):
                if not line.endswith("\n"):
                    raise ValueError(
                        f"unterminated JSONL event on line {number} of "
                        f"{self.path.name}")
                if not line.strip():
                    raise ValueError(
                        f"blank line {number} in {self.path.name}")
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        f"invalid JSON on line {number} of {self.path.name}: "
                        f"{exc.msg}") from exc
                if type(event) is not dict:
                    raise ValueError(
                        f"non-object JSON value on line {number} of "
                        f"{self.path.name}")
                yield event

    def _read_zlib_chunks(self) -> Iterator[dict]:
        with self.path.open("rb") as handle:
            if handle.read(4) != _ZLIB_MAGIC:
                raise ValueError(
                    f"invalid compressed event magic in {self.path.name}")
            block = 0
            while True:
                header = handle.read(_ZLIB_HEADER.size)
                if not header:
                    break
                if len(header) != _ZLIB_HEADER.size:
                    raise ValueError(
                        f"truncated compressed event header in {self.path.name}")
                compressed_size, raw_size, count, crc = _ZLIB_HEADER.unpack(header)
                if not 0 < compressed_size <= _ZLIB_MAX_RAW + 65536:
                    raise ValueError(
                        f"invalid compressed event block size in {self.path.name}")
                if not 0 < raw_size <= _ZLIB_MAX_RAW:
                    raise ValueError(
                        f"invalid compressed event raw size in {self.path.name}")
                payload = handle.read(compressed_size)
                if len(payload) != compressed_size:
                    raise ValueError(
                        f"truncated compressed event block in {self.path.name}")
                try:
                    decompressor = zlib.decompressobj()
                    raw = decompressor.decompress(payload, raw_size + 1)
                except zlib.error as exc:
                    raise ValueError(
                        f"invalid compressed event payload in {self.path.name} "
                        f"block {block}: {exc}") from exc
                if (not decompressor.eof or decompressor.unused_data
                        or decompressor.unconsumed_tail or len(raw) != raw_size):
                    raise ValueError(
                        f"invalid compressed event payload in {self.path.name} "
                        f"block {block}")
                if zlib.crc32(raw) != crc:
                    raise ValueError(
                        f"compressed event CRC mismatch in {self.path.name} "
                        f"block {block}")
                if not raw.endswith(b"\n"):
                    raise ValueError(
                        f"unterminated compressed event in {self.path.name} "
                        f"block {block}")
                decoded = 0
                for line in raw.splitlines():
                    if not line.strip():
                        raise ValueError(
                            f"blank compressed event in {self.path.name} "
                            f"block {block}")
                    try:
                        event = json.loads(line)
                    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                        raise ValueError(
                            f"invalid compressed event JSON in {self.path.name} "
                            f"block {block}: {exc}") from exc
                    if type(event) is not dict:
                        raise ValueError(
                            f"non-object compressed event in {self.path.name} "
                            f"block {block}")
                    decoded += 1
                    yield event
                if decoded != count:
                    raise ValueError(
                        f"compressed event block count mismatch in "
                        f"{self.path.name} block {block}")
                block += 1

    def _read_monolithic(self) -> Iterator[dict]:
        with _IncrementalJsonReader(self.path, chunk_chars=self._chunk_chars) as reader:
            reader.expect("{")
            if reader.peek() == "}":
                raise ValueError(f"{self.path.name} contains no events array")
            found = False
            while True:
                key = reader.decode_value()
                if type(key) is not str:
                    raise ValueError(
                        f"invalid object key in {self.path.name} near character "
                        f"{reader._location()}")
                reader.expect(":")
                if key == "events":
                    if found:
                        raise ValueError(f"duplicate events array in {self.path.name}")
                    found = True
                    reader.expect("[")
                    if reader.peek() == "]":
                        reader.expect("]")
                    else:
                        while True:
                            event = reader.decode_value()
                            if type(event) is not dict:
                                raise ValueError(
                                    f"non-object value inside the events array of "
                                    f"{self.path.name}")
                            yield event
                            following = reader.peek()
                            if following == ",":
                                reader.expect(",")
                                continue
                            reader.expect("]")
                            break
                elif key in ("local_ticks", "status", "semantic_sha256",
                             "genome_sha256", "manifest_sha256"):
                    self._document[key] = reader.decode_value()
                else:
                    reader.decode_value()
                following = reader.peek()
                if following == ",":
                    reader.expect(",")
                    continue
                reader.expect("}")
                break
            if not found:
                raise ValueError(f"{self.path.name} contains no events array")

    # -- evidence -----------------------------------------------------------
    @property
    def event_count(self) -> int:
        """Number of events read; only final once iteration has finished."""
        return self._event_count

    @property
    def exhausted(self) -> bool:
        return self._exhausted

    def declared_semantic_sha256(self) -> str | None:
        declared = self.descriptor["declared_semantic_sha256"]
        if declared is None:
            declared = self._document.get("semantic_sha256")
        return declared if isinstance(declared, str) else None

    def declared_status(self) -> str | None:
        declared = self.descriptor["declared_status"]
        if declared is None:
            declared = self._document.get("status")
        return declared if isinstance(declared, str) else None

    def semantic_sha256(self) -> str | None:
        """Recompute the frozen canonical digest; ``None`` while incomplete."""
        if not self._exhausted:
            return None
        if self._digest_value is None:
            local_ticks = self.descriptor["declared_local_ticks"]
            if local_ticks is None:
                local_ticks = self._document.get("local_ticks")
            status = self.descriptor["declared_status"]
            if status is None:
                status = self._document.get("status")
            if not isinstance(local_ticks, dict) or not isinstance(status, str):
                return None
            digest = self._digest.copy()
            digest.update(b'],"local_ticks":')
            digest.update(_canonical_bytes(local_ticks))
            digest.update(b',"status":')
            digest.update(_canonical_bytes(status))
            digest.update(b"}")
            self._digest_value = digest.hexdigest()
        return self._digest_value

    def semantic_sha256_verified(self) -> bool | None:
        """``None`` when the artifact declares no digest to compare against."""
        if not self._verify_semantic:
            return None
        declared = self.declared_semantic_sha256()
        recomputed = self.semantic_sha256()
        if declared is None or recomputed is None:
            return None
        return declared == recomputed


# --------------------------------------------------------------------------
# certificate accounting
# --------------------------------------------------------------------------


def _hop_identifier(hop: object) -> str | None:
    if isinstance(hop, str) and hop:
        return hop
    if isinstance(hop, Mapping):
        for key in ("hop_id", "id", "name", "kind", "stage", "node_id"):
            value = hop.get(key)
            if isinstance(value, str) and value:
                return value
    return None


def _chain_signature(direction: str, hops: object) -> str | None:
    if not isinstance(hops, (list, tuple)) or not hops:
        return None
    identifiers = []
    for hop in hops:
        identifier = _hop_identifier(hop)
        if identifier is None:
            return None
        identifiers.append(identifier)
    return direction + "|" + ">".join(identifiers)


def _first_missing_hop(missing_hops: object) -> str | None:
    if not isinstance(missing_hops, (list, tuple)) or not missing_hops:
        return None
    return _hop_identifier(missing_hops[0])


class _CertificateCollector:
    """Deduplicate certificates by id and keep only bounded aggregates."""

    def __init__(self, max_certificates: int) -> None:
        self.max_certificates = max_certificates
        self.cap_reached = False
        self.statuses: dict[str, str] = {}
        self.certified_count = 0
        self.incomplete_count = 0
        self.direction_counts: dict[str, int] = {}
        self.same_case = 0
        self.cross_case = 0
        self.unresolved_case_indexes = 0
        self.signatures: set[str] = set()
        self.unresolvable_signatures = 0
        self.certified_admissions: set[str] = set()
        self.incomplete_admission_counts: dict[str, int] = {}
        self.certified_without_admission = 0
        self.incomplete_without_admission = 0
        self.first_missing_hops: dict[str, int] = {}
        self.unresolvable_missing_hops = 0
        self._incomplete_meta: dict[str, tuple[str | None, str | None]] = {}
        self.conflicting_status = 0
        self.duplicates = 0

    def add(self, certificate: object) -> None:
        if not isinstance(certificate, Mapping):
            raise ValueError(
                "chain certificate producer returned a non-mapping certificate")
        schema = certificate.get("schema_version")
        if schema != CERTIFICATE_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported chain certificate schema_version {schema!r}; "
                f"expected {CERTIFICATE_SCHEMA_VERSION!r}")
        certificate_id = certificate.get("certificate_id")
        if not isinstance(certificate_id, str) or not certificate_id:
            raise ValueError("chain certificate has no non-empty certificate_id")
        status = certificate.get("status")
        if status not in CERTIFICATE_STATUSES:
            raise ValueError(
                f"chain certificate {certificate_id} has invalid status {status!r}")
        direction = certificate.get("direction")
        if direction not in CHAIN_DIRECTIONS:
            raise ValueError(
                f"chain certificate {certificate_id} has invalid direction "
                f"{direction!r}")
        previous = self.statuses.get(certificate_id)
        if previous is not None:
            self.duplicates += 1
            if previous == status:
                return
            self.conflicting_status += 1
            if status != CERTIFIED_STATUS:
                return
            self._drop(certificate_id, previous)
        elif len(self.statuses) >= self.max_certificates:
            self.cap_reached = True
            return
        self.statuses[certificate_id] = status
        if status == CERTIFIED_STATUS:
            self._add_certified(certificate, certificate_id)
        else:
            admission = certificate.get("source_admission_id")
            admission = (admission if isinstance(admission, str) and admission
                         else None)
            missing_hop = _first_missing_hop(certificate.get("missing_hops"))
            self._incomplete_meta[certificate_id] = (admission, missing_hop)
            self.incomplete_count += 1
            if admission is not None:
                self.incomplete_admission_counts[admission] = (
                    self.incomplete_admission_counts.get(admission, 0) + 1)
            else:
                self.incomplete_without_admission += 1
            if missing_hop is not None:
                self.first_missing_hops[missing_hop] = (
                    self.first_missing_hops.get(missing_hop, 0) + 1)
            else:
                self.unresolvable_missing_hops += 1

    def _drop(self, certificate_id: str, status: str) -> None:
        """Remove a superseded incomplete certificate from the aggregates."""
        del self.statuses[certificate_id]
        self.incomplete_count -= 1
        admission, missing_hop = self._incomplete_meta.pop(
            certificate_id, (None, None))
        if admission is not None:
            remaining = self.incomplete_admission_counts.get(admission, 0) - 1
            if remaining > 0:
                self.incomplete_admission_counts[admission] = remaining
            else:
                self.incomplete_admission_counts.pop(admission, None)
        else:
            self.incomplete_without_admission -= 1
        if missing_hop is not None:
            remaining = self.first_missing_hops.get(missing_hop, 0) - 1
            if remaining > 0:
                self.first_missing_hops[missing_hop] = remaining
            else:
                self.first_missing_hops.pop(missing_hop, None)
        else:
            self.unresolvable_missing_hops -= 1

    def _add_certified(self, certificate: Mapping, certificate_id: str) -> None:
        self.certified_count += 1
        direction = certificate["direction"]
        self.direction_counts[direction] = self.direction_counts.get(direction, 0) + 1
        source_index = certificate.get("source_case_index")
        endpoint_index = certificate.get("endpoint_case_index")
        if type(source_index) is int and type(endpoint_index) is int:
            if source_index == endpoint_index:
                self.same_case += 1
            else:
                self.cross_case += 1
        else:
            self.unresolved_case_indexes += 1
        signature = _chain_signature(direction, certificate.get("hops"))
        if signature is None:
            self.unresolvable_signatures += 1
        else:
            self.signatures.add(signature)
        admission = certificate.get("source_admission_id")
        if isinstance(admission, str) and admission:
            self.certified_admissions.add(admission)
        else:
            self.certified_without_admission += 1


def _resolve_producer(chain_producer: object, *, max_pending: int,
                      max_event_gap: int, require_native_receipts: bool):
    """Instantiate the injected producer or the lazily imported default."""
    factory = chain_producer
    kind = "injected"
    if factory is None:
        factory = _load_chain_certificates()
        kind = "default"
    if isinstance(factory, type) or not hasattr(factory, "ingest"):
        try:
            producer = factory(max_pending=max_pending,
                               max_event_gap=max_event_gap,
                               require_native_receipts=require_native_receipts)
        except TypeError as exc:
            raise ValueError(
                "chain producer factory rejected the frozen keyword arguments "
                "max_pending/max_event_gap/require_native_receipts: "
                f"{exc}") from exc
    else:
        producer = factory
    if not callable(getattr(producer, "ingest", None)):
        raise ValueError("chain producer must implement ingest(events)")
    if not callable(getattr(producer, "flush", None)):
        raise ValueError("chain producer must implement flush()")
    return producer, kind


# --------------------------------------------------------------------------
# artifact scans
# --------------------------------------------------------------------------


def _read_json_object(path: Path, *, required: bool) -> dict | None:
    if not path.is_file():
        if required:
            raise ValueError(f"required artifact is missing: {path.name}")
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON in {path.name}: {exc.msg}") from exc
    if not isinstance(document, dict):
        raise ValueError(f"{path.name} is not a JSON object")
    return document


def _scan_receipts(path: Path) -> dict:
    """Scan receipts.jsonl once; keep aggregates only, never the rows."""
    phases: dict[str, list[float]] = {name: [] for name in PHASE_KEYS}
    runner: dict[str, list[float]] = {name: [] for name in RUNNER_PHASE_KEYS}
    timing_fields = {
        "online_phase_timing_seconds": (phases, "cases_with_phase_timing"),
        "online_runner_timing_seconds": (runner, "cases_with_runner_timing"),
    }
    scan = {
        "rows": 0,
        "status_counts": {},
        "cases_with_phase_timing": 0,
        "cases_with_runner_timing": 0,
        "invalid_timing_values": 0,
        "coverage_widths": set(),
        "first_seen_target_slots": set(),
        "first_seen_target_bits": set(),
    }
    if not path.is_file():
        return {**scan, "available": False, "phases": phases, "runner": runner}
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"invalid JSON on line {number} of {path.name}: {exc.msg}") from exc
            if type(row) is not dict:
                raise ValueError(
                    f"non-object JSON value on line {number} of {path.name}")
            scan["rows"] += 1
            status = row.get("status")
            status = status if isinstance(status, str) and status else "unknown"
            scan["status_counts"][status] = scan["status_counts"].get(status, 0) + 1
            for field, (samples, cases_key) in timing_fields.items():
                timing = row.get(field)
                if not isinstance(timing, Mapping):
                    continue
                valid = 0
                for name, value in timing.items():
                    if not isinstance(name, str) or not name:
                        scan["invalid_timing_values"] += 1
                        continue
                    number_value = _finite_non_negative(value)
                    if number_value is None:
                        scan["invalid_timing_values"] += 1
                        continue
                    samples.setdefault(name, []).append(number_value)
                    valid += 1
                if valid:
                    scan[cases_key] += 1
            coverage = row.get("coverage_hex")
            if not isinstance(coverage, str) or not coverage:
                raise ValueError(
                    f"invalid coverage_hex on line {number} of {path.name}")
            try:
                flags = bytes.fromhex(coverage)
            except ValueError as exc:
                raise ValueError(
                    f"invalid coverage_hex on line {number} of {path.name}: "
                    f"{coverage!r}") from exc
            if len(coverage) != 2 * len(flags):
                raise ValueError(
                    f"invalid coverage_hex on line {number} of {path.name}: "
                    f"{coverage!r}")
            scan["coverage_widths"].add(len(flags))
            for index, flag in enumerate(flags):
                if flag:
                    scan["first_seen_target_slots"].add(index)
                    for bit in range(8):
                        if flag & (1 << bit):
                            scan["first_seen_target_bits"].add(index * 8 + bit)
    scan["available"] = True
    scan["phases"] = phases
    scan["runner"] = runner
    return scan


def _scan_edges(event: object, edges: set, counters: dict) -> None:
    provenance = event.get("provenance")
    if not isinstance(provenance, Mapping):
        counters["events_without_provenance"] += 1
        return
    candidates = provenance.get("edge_candidates")
    if not isinstance(candidates, (list, tuple)):
        counters["invalid_candidate_records"] += 1
        return
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            counters["invalid_candidate_records"] += 1
            continue
        graph = candidate.get("graph_sha256")
        path_ids = candidate.get("path_ids")
        relation = candidate.get("relation")
        rule_index = candidate.get("rule_index")
        scope = candidate.get("scope")
        if (not isinstance(graph, str) or not graph
                or not isinstance(path_ids, (list, tuple))
                or any(not isinstance(item, str) for item in path_ids)
                or not isinstance(relation, str) or not relation
                or type(rule_index) is not int
                or not isinstance(scope, str) or not scope):
            counters["invalid_candidate_records"] += 1
            continue
        counters["candidate_observations"] += 1
        edges.add((graph, tuple(path_ids), relation, rule_index, scope))


def _percentiles(values: Sequence[float],
                 fractions: Iterable[float]) -> dict[str, float | None]:
    if not values:
        return {f"p{int(fraction * 100)}": None for fraction in fractions}
    if len(values) == 1:
        only = float(values[0])
        return {f"p{int(fraction * 100)}": (only if fraction == 0.5 else None)
                for fraction in fractions}
    ordered = sorted(values)
    cuts = statistics.quantiles(ordered, n=100, method="inclusive")
    result = {}
    for fraction in fractions:
        index = max(0, min(len(cuts) - 1, int(round(fraction * 100)) - 1))
        result[f"p{int(fraction * 100)}"] = float(cuts[index])
    return result


def _timing_report(samples: Mapping[str, Sequence[float]],
                   canonical: Sequence[str]) -> dict:
    names = list(canonical)
    names.extend(sorted(name for name in samples if name not in set(canonical)))
    entries = {}
    for name in names:
        values = samples.get(name, ())
        entry = {"count": len(values)}
        entry.update(_percentiles(values, (0.5, 0.95)))
        entries[name] = entry
    return entries


def _trace_evidence(stream: TraceEventStream | None, descriptor: dict | None,
                    events_ingested: int | None) -> dict:
    if stream is None:
        return {
            "format": None,
            "events_file": None,
            "path": None,
            "bytes": None,
            "meta_schema_version": None,
            "declared_event_count": None,
            "declared_semantic_sha256": None,
            "declared_status": None,
            "events_ingested": None,
            "event_count_match": None,
            "semantic_sha256_recomputed": None,
            "semantic_sha256_verified": None,
        }
    declared = descriptor["declared_event_count"]
    recomputed = stream.semantic_sha256()
    return {
        "format": descriptor["format"],
        "events_file": descriptor["events_file"],
        "path": descriptor["path"],
        "bytes": descriptor["bytes"],
        "meta_schema_version": descriptor["meta_schema_version"],
        "declared_event_count": declared,
        "declared_semantic_sha256": stream.declared_semantic_sha256(),
        "declared_status": stream.declared_status(),
        "events_ingested": events_ingested,
        "event_count_match": (None if type(declared) is not int
                              else declared == events_ingested),
        "semantic_sha256_recomputed": recomputed,
        "semantic_sha256_verified": stream.semantic_sha256_verified(),
    }


# --------------------------------------------------------------------------
# replay comparison
# --------------------------------------------------------------------------


def _resolve_replay(replay_dir: str | Path) -> tuple[str, Path, dict | None]:
    """Classify a replay target as a run directory or a saved comparison."""
    path = Path(replay_dir)
    if path.is_dir():
        return "run_dir", path, None
    if path.is_file():
        document = _read_json_object(path, required=True)
        if not isinstance(document.get("matches"), bool):
            raise ValueError(
                f"replay comparison {path.name} has no boolean 'matches' field")
        return "comparison_json", path, document
    raise ValueError(f"replay target does not exist: {path}")


def _compare_replay(run_dir: Path, replay_dir: str | Path, *,
                    run_descriptor: dict | None, run_events: int | None,
                    run_chains: int | None, producer_factory,
                    chunk_chars: int, verify_semantic: bool,
                    ingest_batch_size: int, max_certificates: int,
                    max_pending: int, max_event_gap: int,
                    require_native_receipts: bool) -> dict:
    kind, path, comparison = _resolve_replay(replay_dir)
    report = {
        "kind": kind,
        "replay_source": str(path),
        "run_event_count": run_events,
        "replay_event_count": None,
        "event_count_match": None,
        "run_semantic_sha256": (None if run_descriptor is None
                                else run_descriptor["declared_semantic_sha256"]),
        "replay_semantic_sha256": None,
        "semantic_sha256_match": None,
        "run_status": (None if run_descriptor is None
                       else run_descriptor["declared_status"]),
        "replay_status": None,
        "status_match": None,
        "run_certified_chains": run_chains,
        "replay_certified_chains": None,
        "certified_chains_match": None,
        "comparison_matches": None,
        "first_difference": None,
        "verified": False,
        "unverified_items": [],
    }
    if kind == "comparison_json":
        report["comparison_matches"] = comparison.get("matches")
        report["first_difference"] = comparison.get("first_difference")
        report["unverified_items"] = ["event_count", "semantic_sha256", "status",
                                      "certified_chains"]
        report["verified"] = False
        return report
    try:
        stream = TraceEventStream(path, chunk_chars=chunk_chars,
                                  verify_semantic=verify_semantic)
    except TraceUnavailable as exc:
        raise ValueError(
            f"replay directory {path} holds no streamable trace artifact: "
            f"{exc}") from exc
    try:
        producer, _ = _resolve_producer(
            producer_factory, max_pending=max_pending,
            max_event_gap=max_event_gap,
            require_native_receipts=require_native_receipts)
    except (ChainProducerUnavailable, ImportError):
        producer = None
    collector = _CertificateCollector(max_certificates)
    batch: list[dict] = []
    ingested = 0
    for event in stream.events():
        ingested += 1
        if producer is None or collector.cap_reached:
            continue
        batch.append(event)
        if len(batch) >= ingest_batch_size:
            for certificate in producer.ingest(tuple(batch)):
                collector.add(certificate)
            batch.clear()
    if producer is not None:
        if batch:
            for certificate in producer.ingest(tuple(batch)):
                collector.add(certificate)
        for certificate in producer.flush():
            collector.add(certificate)
    report["replay_event_count"] = ingested
    report["replay_semantic_sha256"] = stream.declared_semantic_sha256()
    report["replay_status"] = stream.declared_status()
    report["replay_certified_chains"] = (
        None if producer is None or collector.cap_reached
        else collector.certified_count)
    report["event_count_match"] = (
        None if run_events is None
        else ingested == run_events)
    report["semantic_sha256_match"] = (
        None if report["run_semantic_sha256"] is None
        or report["replay_semantic_sha256"] is None
        else report["run_semantic_sha256"] == report["replay_semantic_sha256"])
    report["status_match"] = (
        None if report["run_status"] is None or report["replay_status"] is None
        else report["run_status"] == report["replay_status"])
    report["certified_chains_match"] = (
        None if run_chains is None or report["replay_certified_chains"] is None
        else run_chains == report["replay_certified_chains"])
    report["unverified_items"] = sorted(
        name for name in ("event_count", "semantic_sha256", "status",
                          "certified_chains")
        if report[f"{name}_match"] is None)
    report["verified"] = (
        not report["unverified_items"]
        and all(report[f"{name}_match"] is True
                for name in ("event_count", "semantic_sha256", "status",
                             "certified_chains")))
    return report


# --------------------------------------------------------------------------
# analysis entry point
# --------------------------------------------------------------------------


def analyze_run(run_dir: str | Path, *, chain_producer: object = None,
                replay_dir: str | Path | None = None,
                max_certificates: int = DEFAULT_MAX_CERTIFICATES,
                max_pending: int = 128, max_event_gap: int = 4096,
                require_native_receipts: bool = True,
                ingest_batch_size: int = DEFAULT_INGEST_BATCH_SIZE,
                chunk_chars: int = DEFAULT_CHUNK_CHARS,
                verify_semantic: bool = True) -> dict:
    """Analyze one online run directory with a single streaming pass.

    ``chain_producer`` is a factory accepting the frozen keyword arguments
    ``max_pending``, ``max_event_gap`` and ``require_native_receipts``; when it
    is omitted the producer is imported lazily and its absence is reported as a
    limit instead of a zero chain count.
    """
    if type(max_certificates) is not int or max_certificates < 1:
        raise ValueError("max_certificates must be a positive integer")
    if type(ingest_batch_size) is not int or ingest_batch_size < 1:
        raise ValueError("ingest_batch_size must be a positive integer")
    if type(max_pending) is not int or max_pending < 1:
        raise ValueError("max_pending must be a positive integer")
    if type(max_event_gap) is not int or max_event_gap < 1:
        raise ValueError("max_event_gap must be a positive integer")
    if type(require_native_receipts) is not bool:
        raise ValueError("require_native_receipts must be boolean")
    directory = Path(run_dir)
    if not directory.is_dir():
        raise ValueError(f"run directory does not exist: {directory}")

    limits: list[dict] = []

    report_document = _read_json_object(directory / "report.json", required=False)
    effective_seconds = None
    if report_document is None:
        limits.append({
            "quantity": "effective_search_seconds",
            "reason": "report.json is missing, so the effective search window "
                      "is unknown"})
    else:
        effective_seconds = _finite_positive(
            report_document.get("effective_search_seconds"))
        if effective_seconds is None:
            limits.append({
                "quantity": "effective_search_seconds",
                "reason": "report.json has no finite positive "
                          "effective_search_seconds value"})
    elapsed_seconds = None
    if report_document is not None:
        elapsed_seconds = _finite_non_negative(report_document.get("elapsed_seconds"))
        if elapsed_seconds is None:
            limits.append({
                "quantity": "elapsed_seconds",
                "reason": "report.json has no finite non-negative "
                          "elapsed_seconds value"})

    plan = _read_json_object(directory / "online_plan.json", required=False)
    admissions_total = None
    fuzz_source_admissions = None
    fuzz_source_ids: set[str] = set()
    admissions_by_role: dict[str, int] = {}
    if plan is None:
        limits.append({
            "quantity": "chain_completion_by_admission",
            "reason": "online_plan.json is missing, so the declared source "
                      "admission total is unknown"})
    else:
        registry = plan.get("source_admissions")
        admissions = (registry.get("admissions")
                      if isinstance(registry, Mapping) else None)
        if not isinstance(admissions, list):
            limits.append({
                "quantity": "chain_completion_by_admission",
                "reason": "online_plan.json has no source_admissions.admissions "
                          "list, so the declared source admission total is unknown"})
        else:
            admissions_total = len(admissions)
            for entry in admissions:
                if not isinstance(entry, Mapping):
                    continue
                role = entry.get("role")
                role = role if isinstance(role, str) and role else "unknown"
                admissions_by_role[role] = admissions_by_role.get(role, 0) + 1
                admission_id = entry.get("admission_id")
                if role == "fuzz_source" and isinstance(admission_id, str):
                    fuzz_source_ids.add(admission_id)
            fuzz_source_admissions = sum(
                1 for entry in admissions
                if isinstance(entry, Mapping) and entry.get("role") == "fuzz_source")

    rows = _scan_receipts(directory / "receipts.jsonl")
    test_counts = dict(rows["status_counts"]) if rows["available"] else None
    test_counts_total = rows["rows"] if rows["available"] else None
    if not rows["available"]:
        limits.append({
            "quantity": "test_counts",
            "reason": "receipts.jsonl is missing, so per-status case counts and "
                      "the invalid/timeout ratio are unknown"})
    unclassified = sorted(status for status in (test_counts or {})
                          if status not in CLASSIFIED_STATUSES)
    if unclassified:
        limits.append({
            "quantity": "invalid_or_timeout_ratio",
            "reason": "receipt statuses without a local classification are "
                      f"present: {unclassified}"})
    invalid_count = sum(count for status, count in (test_counts or {}).items()
                        if status in INVALID_STATUSES)
    timeout_count = sum(count for status, count in (test_counts or {}).items()
                        if status in TIMEOUT_STATUSES)
    complete_count = sum(count for status, count in (test_counts or {}).items()
                         if status in COMPLETE_STATUSES)
    finding_count = sum(count for status, count in (test_counts or {}).items()
                        if status in FINDING_STATUSES)
    invalid_ratio = None
    if test_counts is not None and test_counts_total and not unclassified:
        invalid_ratio = (invalid_count + timeout_count) / test_counts_total
    complete_rate = None
    if test_counts is not None and effective_seconds is not None:
        complete_rate = complete_count / effective_seconds

    reported_tests = None
    reported_statuses = None
    if report_document is not None:
        candidate = report_document.get("tests")
        reported_tests = candidate if type(candidate) is int else None
        candidate = report_document.get("statuses")
        reported_statuses = (dict(candidate) if isinstance(candidate, Mapping)
                             else None)
        if (test_counts is not None
                and (reported_tests != test_counts_total
                     or reported_statuses != test_counts)):
            limits.append({
                "quantity": "test_counts",
                "reason": "report.json tests/statuses disagree with the receipt "
                          "stream; both values are reported"})

    finalization = None
    finalization_reason = None
    if report_document is None:
        finalization_reason = "report.json is missing"
    else:
        candidate = report_document.get("finalization_timing_seconds")
        if isinstance(candidate, Mapping) and candidate and all(
                _finite_non_negative(value) is not None
                for value in candidate.values()):
            finalization = {name: float(value) for name, value in candidate.items()}
        else:
            finalization_reason = ("report.json has no finite non-negative "
                                   "finalization_timing_seconds mapping")
    if finalization is None:
        limits.append({"quantity": "finalization_timing_seconds",
                       "reason": finalization_reason})

    # -- chain certificate producer resolution -----------------------------
    producer = None
    producer_kind = "unavailable"
    producer_reason = None
    try:
        producer, producer_kind = _resolve_producer(
            chain_producer, max_pending=max_pending, max_event_gap=max_event_gap,
            require_native_receipts=require_native_receipts)
    except (ChainProducerUnavailable, ImportError) as exc:
        producer_reason = str(exc)
    collector = _CertificateCollector(max_certificates)
    pending_after_flush = None
    producer_error = None

    # -- single streaming pass over the trace ------------------------------
    stream = None
    descriptor = None
    events_ingested = None
    edges: set[tuple] = set()
    edge_counters = {"candidate_observations": 0, "invalid_candidate_records": 0,
                     "events_without_provenance": 0}
    try:
        stream = TraceEventStream(directory, chunk_chars=chunk_chars,
                                  verify_semantic=verify_semantic)
        descriptor = stream.descriptor
    except TraceUnavailable as exc:
        limits.append({"quantity": "trace_events",
                       "reason": f"no streamable trace artifact: {exc}"})
    if stream is not None:
        batch: list[dict] = []
        ingested = 0
        try:
            for event in stream.events():
                ingested += 1
                _scan_edges(event, edges, edge_counters)
                if producer is not None and not collector.cap_reached:
                    batch.append(event)
                    if len(batch) >= ingest_batch_size:
                        for certificate in producer.ingest(tuple(batch)):
                            collector.add(certificate)
                        batch.clear()
            if producer is not None:
                if batch:
                    for certificate in producer.ingest(tuple(batch)):
                        collector.add(certificate)
                    batch.clear()
                for certificate in producer.flush():
                    collector.add(certificate)
                pending_after_flush = getattr(producer, "pending_count", None)
                if type(pending_after_flush) is not int:
                    pending_after_flush = None
        except Exception as exc:
            producer_error = exc
            raise
        finally:
            events_ingested = ingested
            if producer_error is not None and producer is not None:
                close = getattr(producer, "close", None)
                if callable(close):
                    close()

    chains_measurable = (producer is not None and stream is not None
                         and not collector.cap_reached)
    chains_reason = None
    if producer is None:
        chains_reason = f"chain certificate producer unavailable: {producer_reason}"
    elif stream is None:
        chains_reason = "trace events are unavailable, so no certificate could be derived"
    elif collector.cap_reached:
        chains_reason = (f"certificate cap max_certificates={max_certificates} was "
                         "reached; certificate counts are lower bounds")
    if chains_reason is not None:
        limits.append({"quantity": "certified_chains", "reason": chains_reason})

    if chains_measurable:
        by_direction = {direction: collector.direction_counts.get(direction, 0)
                        for direction in CHAIN_DIRECTIONS}
        same_case = (None if collector.unresolved_case_indexes
                     else collector.same_case)
        cross_case = (None if collector.unresolved_case_indexes
                      else collector.cross_case)
        if collector.unresolved_case_indexes:
            limits.append({
                "quantity": "certified_chains.same_case",
                "reason": f"{collector.unresolved_case_indexes} certified "
                          "certificates lack integer source/endpoint case indexes"})
    else:
        by_direction = None
        same_case = None
        cross_case = None
    certified_chains = {
        "total": collector.certified_count if chains_measurable else None,
        "by_direction": by_direction,
        "same_case": same_case,
        "cross_case": cross_case,
        "incomplete_total": collector.incomplete_count if chains_measurable else None,
        "cap_reached": collector.cap_reached,
        "duplicate_certificate_ids": collector.duplicates,
        "conflicting_status_certificate_ids": collector.conflicting_status,
        "unresolved_case_index_certificates": collector.unresolved_case_indexes,
    }
    if producer is not None and collector.conflicting_status:
        limits.append({
            "quantity": "certified_chains.total",
            "reason": f"{collector.conflicting_status} certificate ids were "
                      "reported with conflicting statuses; certified wins"})
    certified_rate = None
    certified_rate_reason = None
    if not chains_measurable:
        certified_rate_reason = chains_reason
    elif effective_seconds is None:
        certified_rate_reason = ("effective_search_seconds is unknown, so a "
                                 "per-second rate cannot be computed")
    else:
        certified_rate = collector.certified_count / effective_seconds
    if certified_rate is None:
        limits.append({"quantity": "certified_chains_per_second",
                       "reason": certified_rate_reason})
    if (chains_measurable and collector.certified_count == 0
            and collector.incomplete_count):
        summary = ", ".join(f"{hop}={count}" for hop, count
                            in sorted(collector.first_missing_hops.items()))
        limits.append({
            "quantity": "certified_chains.total",
            "reason": (f"the producer certified none of the "
                       f"{collector.incomplete_count} admission certificates; "
                       f"first missing hops: {summary or 'unresolved'}. This "
                       "states that the artifact certifies no complete chain, "
                       "not that the DUT never completed one")})
    certified_chains_semantics = (
        "unique certificate_id values the injected producer certified for this "
        "artifact; when incomplete certificates dominate, the value states "
        "artifact capability rather than DUT chain occurrence")

    if chains_measurable:
        certified_admissions = (None if collector.certified_without_admission
                                else len(collector.certified_admissions))
        incomplete_admissions = (None if collector.incomplete_without_admission
                                 else len(collector.incomplete_admission_counts))
        if collector.certified_without_admission:
            limits.append({
                "quantity": "chain_completion_by_admission.certified_admissions",
                "reason": f"{collector.certified_without_admission} certified "
                          "certificates have no source_admission_id"})
    else:
        certified_admissions = None
        incomplete_admissions = None
    certified_ratio = None
    certified_ratio_reason = None
    fuzz_source_ratio = None
    accounted_admissions = None
    unaccounted_fuzz_source = None
    if chains_measurable:
        accounted_ids = collector.certified_admissions | set(
            collector.incomplete_admission_counts)
        accounted_admissions = len(accounted_ids)
        if fuzz_source_admissions is not None:
            unaccounted_fuzz_source = len(fuzz_source_ids - accounted_ids)
            if unaccounted_fuzz_source:
                limits.append({
                    "quantity": "certified_chains.total",
                    "reason": (f"{unaccounted_fuzz_source} of "
                               f"{fuzz_source_admissions} declared fuzz-source "
                               "admissions produced no certificate at all, so "
                               "the certified numerator is a lower bound rather "
                               "than a complete enumeration of this run")})
    if admissions_total is None:
        certified_ratio_reason = ("the declared source admission total is "
                                  "unknown from online_plan.json")
    elif admissions_total == 0:
        certified_ratio_reason = ("online_plan.json declares an empty source "
                                  "admission list, so no ratio is defined")
    elif not chains_measurable:
        certified_ratio_reason = chains_reason
    elif certified_admissions is None:
        certified_ratio_reason = ("certified certificates without an admission "
                                  "id make the numerator a lower bound")
    else:
        certified_ratio = certified_admissions / admissions_total
        if fuzz_source_admissions:
            fuzz_source_ratio = certified_admissions / fuzz_source_admissions
    chain_completion = {
        "admissions_total": admissions_total,
        "admissions_total_source": ("online_plan.json:"
                                    "source_admissions.admissions"
                                    if admissions_total is not None else None),
        "fuzz_source_admissions": fuzz_source_admissions,
        "admissions_by_role": dict(sorted(admissions_by_role.items())),
        "accounted_admissions": accounted_admissions,
        "unaccounted_fuzz_source_admissions": unaccounted_fuzz_source,
        "certified_admissions": certified_admissions,
        "incomplete_admissions": incomplete_admissions,
        "certified_ratio": certified_ratio,
        "certified_ratio_denominator": "admissions_total",
        "certified_fuzz_source_ratio": fuzz_source_ratio,
        "certified_ratio_reason": certified_ratio_reason,
        "certificates_without_admission_id": (
            collector.certified_without_admission + collector.incomplete_without_admission
            if chains_measurable else None),
    }
    if certified_ratio is None and certified_ratio_reason:
        limits.append({"quantity": "chain_completion_by_admission.certified_ratio",
                       "reason": certified_ratio_reason})

    chain_gap_evidence = {
        "incomplete_certificates": (collector.incomplete_count
                                    if chains_measurable else None),
        "first_missing_hop_counts": (
            dict(sorted(collector.first_missing_hops.items()))
            if chains_measurable else None),
        "unresolvable_missing_hops": (collector.unresolvable_missing_hops
                                      if chains_measurable else None),
        "interpretation": ("incomplete certificates name their first unwitnessed "
                           "hop; a dominant missing hop means the run lacks that "
                           "hop evidence rather than proving the DUT never "
                           "completed a chain"),
    }

    signature_rate = None
    signature_reason = None
    unique_signatures = None
    if not chains_measurable:
        signature_reason = chains_reason
    elif collector.unresolvable_signatures:
        signature_reason = (f"{collector.unresolvable_signatures} certified "
                            "certificates have no resolvable ordered hop ids")
    elif effective_seconds is None:
        signature_reason = ("effective_search_seconds is unknown, so a "
                            "per-second rate cannot be computed")
    else:
        unique_signatures = len(collector.signatures)
        signature_rate = unique_signatures / effective_seconds
    if signature_reason:
        limits.append({"quantity": "chain_signature_novelty",
                       "reason": signature_reason})
    chain_signature_novelty = {
        "signature_definition": "direction + ordered hop ids",
        "unique_signatures": unique_signatures,
        "new_signatures_per_second": signature_rate,
        "unresolvable_certified_certificates": collector.unresolvable_signatures,
        "reason": signature_reason,
    }

    widths = rows["coverage_widths"]
    target_reason = None
    if not rows["available"]:
        target_reason = "receipts.jsonl is missing"
    elif not widths:
        target_reason = "receipts.jsonl has no coverage observations"
    elif len(widths) > 1:
        target_reason = (f"coverage_hex widths are inconsistent across receipts: "
                         f"{sorted(widths)}")
    elif effective_seconds is None:
        target_reason = ("effective_search_seconds is unknown, so a per-second "
                         "rate cannot be computed")
    target_slots = None if target_reason else len(rows["first_seen_target_slots"])
    target_bits = None if target_reason else len(rows["first_seen_target_bits"])
    local_target_novelty = {
        "coverage_width_bytes": (sorted(widths)[0] if len(widths) == 1 else None),
        "first_seen_target_slots": target_slots,
        "first_seen_target_bits": target_bits,
        "new_target_slots_per_second": (None if target_reason
                                        else target_slots / effective_seconds),
        "new_target_bits_per_second": (None if target_reason
                                       else target_bits / effective_seconds),
        "reason": target_reason,
    }
    if target_reason:
        limits.append({"quantity": "local_target_novelty",
                       "reason": target_reason})

    edges_reason = None
    unique_edges = None
    if stream is None:
        edges_reason = "trace events are unavailable"
    elif edge_counters["invalid_candidate_records"]:
        edges_reason = (f"{edge_counters['invalid_candidate_records']} "
                        "provenance edge candidate records did not match "
                        "event_source_provenance.v1, so the unique edge count is "
                        "a lower bound")
    elif effective_seconds is None:
        edges_reason = ("effective_search_seconds is unknown, so a per-second "
                        "rate cannot be computed")
    else:
        unique_edges = len(edges)
    witnessed_edge_novelty = {
        "edge_definition": ("(graph_sha256, tuple(path_ids), relation, "
                            "rule_index, scope)"),
        "candidate_observations": (edge_counters["candidate_observations"]
                                   if stream is not None else None),
        "unique_edges": unique_edges,
        "new_edges_per_second": (None if edges_reason
                                 else unique_edges / effective_seconds),
        "invalid_candidate_records": edge_counters["invalid_candidate_records"],
        "events_without_provenance": edge_counters["events_without_provenance"],
        "reason": edges_reason,
    }
    if edges_reason:
        limits.append({"quantity": "witnessed_edge_novelty",
                       "reason": edges_reason})

    phase_timing = {
        "cases_total": test_counts_total,
        "cases_with_online_phase_timing_seconds": (
            rows["cases_with_phase_timing"] if rows["available"] else None),
        "cases_with_online_runner_timing_seconds": (
            rows["cases_with_runner_timing"] if rows["available"] else None),
        "invalid_timing_values": (rows["invalid_timing_values"]
                                  if rows["available"] else None),
        "online_phase_timing_seconds": _timing_report(rows["phases"], PHASE_KEYS),
        "online_runner_timing_seconds": _timing_report(rows["runner"],
                                                       RUNNER_PHASE_KEYS),
    }
    if not rows["cases_with_phase_timing"]:
        limits.append({
            "quantity": "phase_timing_seconds.online_phase_timing_seconds",
            "reason": "no receipt carries a valid online_phase_timing_seconds "
                      "mapping; p50 and p95 stay null"})
    if not rows["cases_with_runner_timing"]:
        limits.append({
            "quantity": "phase_timing_seconds.online_runner_timing_seconds",
            "reason": "no receipt carries a valid online_runner_timing_seconds "
                      "mapping; p50 and p95 stay null"})

    limits.append({
        "quantity": "novelty_time_series",
        "reason": "receipts and chain certificates carry no per-item completion "
                  "timestamps, so first-seen rates cover the whole scanned window "
                  "and no per-second novelty curve can be reconstructed"})
    limits.append({
        "quantity": "certified_chain_completeness",
        "reason": "this analyzer counts certificates emitted by the injected "
                  "producer; it does not independently re-derive hop evidence "
                  "from raw events"})

    run_id = None
    identity = _read_json_object(directory / "online_run_identity.json",
                                 required=False)
    if identity is not None:
        inner = identity.get("identity")
        if isinstance(inner, Mapping):
            config = inner.get("run_config")
            if isinstance(config, Mapping) and isinstance(config.get("run_id"), str):
                run_id = config["run_id"]

    report = {
        "schema_version": SCHEMA_VERSION,
        "run_dir": str(directory),
        "run_id": run_id,
        "effective_search_seconds": effective_seconds,
        "effective_search_seconds_reason": (
            None if effective_seconds is not None
            else next((item["reason"] for item in limits
                       if item["quantity"] == "effective_search_seconds"), None)),
        "elapsed_seconds": elapsed_seconds,
        "elapsed_seconds_reason": (
            None if elapsed_seconds is not None
            else next((item["reason"] for item in limits
                       if item["quantity"] == "elapsed_seconds"), None)),
        "test_counts": test_counts,
        "test_counts_total": test_counts_total,
        "test_counts_reason": (
            None if rows["available"]
            else next((item["reason"] for item in limits
                       if item["quantity"] == "test_counts"), None)),
        "reported_tests": reported_tests,
        "reported_statuses": reported_statuses,
        "invalid_or_timeout_ratio": invalid_ratio,
        "invalid_or_timeout_ratio_reason": (
            None if invalid_ratio is not None
            else next((item["reason"] for item in limits
                       if item["quantity"] == "invalid_or_timeout_ratio"), None)),
        "invalid_or_timeout_detail": {
            "complete": complete_count if test_counts is not None else None,
            "invalid": invalid_count if test_counts is not None else None,
            "timeout": timeout_count if test_counts is not None else None,
            "findings": finding_count if test_counts is not None else None,
            "unclassified_statuses": unclassified,
            "invalid_statuses": sorted(INVALID_STATUSES),
            "timeout_statuses": sorted(TIMEOUT_STATUSES),
            "definition": ("a case is invalid or timed out when its receipt status "
                           "is in the reported invalid/timeout sets; findings and "
                           "complete cases are excluded"),
        },
        "complete_cases_per_second": complete_rate,
        "complete_cases_per_second_reason": (
            None if complete_rate is not None
            else "complete case count or effective_search_seconds is unknown"),
        "certified_chains": certified_chains,
        "certified_chains_reason": chains_reason,
        "certified_chains_per_second": certified_rate,
        "certified_chains_per_second_reason": certified_rate_reason,
        "certified_chains_semantics": certified_chains_semantics,
        "chain_completion_by_admission": chain_completion,
        "chain_gap_evidence": chain_gap_evidence,
        "chain_signature_novelty": chain_signature_novelty,
        "local_target_novelty": local_target_novelty,
        "witnessed_edge_novelty": witnessed_edge_novelty,
        "phase_timing_seconds": phase_timing,
        "finalization_timing_seconds": finalization,
        "finalization_timing_seconds_reason": finalization_reason,
        "replay": None,
        "trace_evidence": _trace_evidence(stream, descriptor, events_ingested),
        "chain_producer": {
            "available": producer is not None,
            "kind": producer_kind,
            "reason": producer_reason,
            "producer_module": (_producer_module_identity()
                                if producer_kind == "default" else None),
            "max_pending": max_pending,
            "max_event_gap": max_event_gap,
            "require_native_receipts": require_native_receipts,
            "ingest_batch_size": ingest_batch_size,
            "pending_after_flush": pending_after_flush,
        },
        "limits": limits,
    }
    if replay_dir is not None:
        report["replay"] = _compare_replay(
            directory, replay_dir, run_descriptor=descriptor,
            run_events=report["trace_evidence"]["events_ingested"],
            run_chains=certified_chains["total"],
            producer_factory=chain_producer, chunk_chars=chunk_chars,
            verify_semantic=verify_semantic, ingest_batch_size=ingest_batch_size,
            max_certificates=max_certificates, max_pending=max_pending,
            max_event_gap=max_event_gap,
            require_native_receipts=require_native_receipts)
    return report


# --------------------------------------------------------------------------
# markdown rendering
# --------------------------------------------------------------------------


def _format_value(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, float):
        return f"{value:.6g}"
    if isinstance(value, dict):
        return ", ".join(f"{name}={_format_value(item)}"
                         for name, item in value.items())
    return str(value)


def render_markdown(report: Mapping) -> str:
    """Render a short summary whose first section states the evidence boundary."""
    lines = [f"# First-step acceptance: `{report.get('run_dir')}`", ""]
    lines.append(f"- schema_version: `{report.get('schema_version')}`")
    lines.append(f"- run_id: `{report.get('run_id')}`")
    lines.append("")
    lines.append("## Evidence boundary")
    lines.append("")
    lines.append("Measured by this single-pass analysis:")
    lines.append("")
    chains = report.get("certified_chains") or {}
    measured = [
        ("effective_search_seconds", report.get("effective_search_seconds")),
        ("elapsed_seconds", report.get("elapsed_seconds")),
        ("test_counts", report.get("test_counts")),
        ("complete_cases_per_second", report.get("complete_cases_per_second")),
        ("certified_chains.total", chains.get("total")),
        ("certified_chains.by_direction", chains.get("by_direction")),
        ("certified_chains_per_second", report.get("certified_chains_per_second")),
        ("chain_completion_by_admission.certified_ratio",
         (report.get("chain_completion_by_admission") or {}).get("certified_ratio")),
        ("chain_signature_novelty.unique_signatures",
         (report.get("chain_signature_novelty") or {}).get("unique_signatures")),
        ("local_target_novelty.first_seen_target_bits",
         (report.get("local_target_novelty") or {}).get("first_seen_target_bits")),
        ("witnessed_edge_novelty.unique_edges",
         (report.get("witnessed_edge_novelty") or {}).get("unique_edges")),
        ("trace_evidence.events_ingested",
         (report.get("trace_evidence") or {}).get("events_ingested")),
        ("trace_evidence.semantic_sha256_verified",
         (report.get("trace_evidence") or {}).get("semantic_sha256_verified")),
        ("replay.verified", (report.get("replay") or {}).get("verified")),
    ]
    for name, value in measured:
        lines.append(f"- `{name}` = {_format_value(value)}")
    lines.append("")
    limits = list(report.get("limits") or ())
    lines.append("Not provable from these artifacts (reported as null, never as zero):")
    lines.append("")
    if limits:
        for item in limits:
            lines.append(f"- `{item['quantity']}`: {item['reason']}")
    else:
        lines.append("- none recorded")
    lines.append("")
    lines.append("## Timing")
    lines.append("")
    lines.append("| quantity | value |")
    lines.append("| --- | --- |")
    lines.append(f"| effective search seconds | {_format_value(report.get('effective_search_seconds'))} |")
    lines.append(f"| elapsed seconds | {_format_value(report.get('elapsed_seconds'))} |")
    lines.append(f"| complete cases/s | {_format_value(report.get('complete_cases_per_second'))} |")
    lines.append(f"| certified chains/s | {_format_value(report.get('certified_chains_per_second'))} |")
    lines.append(f"| invalid or timeout ratio | {_format_value(report.get('invalid_or_timeout_ratio'))} |")
    lines.append(f"| finalization seconds | {_format_value(report.get('finalization_timing_seconds'))} |")
    lines.append("")
    lines.append("### Per-case phase percentiles (seconds)")
    lines.append("")
    timing = report.get("phase_timing_seconds") or {}
    for field in TIMING_FIELDS:
        entries = timing.get(field) or {}
        lines.append(f"`{field}` (cases with timing: "
                     f"{_format_value(timing.get('cases_with_' + field[7:]))})")
        lines.append("")
        lines.append("| phase | count | p50 | p95 |")
        lines.append("| --- | ---: | ---: | ---: |")
        for name, entry in entries.items():
            lines.append(f"| {name} | {entry['count']} | "
                         f"{_format_value(entry['p50'])} | "
                         f"{_format_value(entry['p95'])} |")
        lines.append("")
    lines.append("## Novelty")
    lines.append("")
    lines.append("| quantity | value |")
    lines.append("| --- | --- |")
    signatures = report.get("chain_signature_novelty") or {}
    targets = report.get("local_target_novelty") or {}
    edges = report.get("witnessed_edge_novelty") or {}
    lines.append(f"| unique chain signatures | {_format_value(signatures.get('unique_signatures'))} |")
    lines.append(f"| new chain signatures/s | {_format_value(signatures.get('new_signatures_per_second'))} |")
    lines.append(f"| first-seen target bits | {_format_value(targets.get('first_seen_target_bits'))} |")
    lines.append(f"| new target bits/s | {_format_value(targets.get('new_target_bits_per_second'))} |")
    lines.append(f"| unique witnessed edges | {_format_value(edges.get('unique_edges'))} |")
    lines.append(f"| new witnessed edges/s | {_format_value(edges.get('new_edges_per_second'))} |")
    lines.append("")
    if report.get("replay") is not None:
        lines.append("## Replay comparison")
        lines.append("")
        for name, value in (report["replay"] or {}).items():
            lines.append(f"- `{name}` = {_format_value(value)}")
        lines.append("")
    lines.append("## Limits")
    lines.append("")
    lines.append("| quantity | reason |")
    lines.append("| --- | --- |")
    for item in limits:
        lines.append(f"| `{item['quantity']}` | {item['reason']} |")
    lines.append("")
    return "\n".join(lines)
