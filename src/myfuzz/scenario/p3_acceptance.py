"""P3 acceptance report: one saved run judged against the plan's P3 condition.

The P3 acceptance condition (see
``docs/superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md``,
P3 section) asks one real RTL session to do all of the following from a single
initialization:

1. run at least three testcases with independent IDs and independent feedback
   while initializing, starting and resetting exactly once, with no harness
   rebuild in between;
2. carry ``Store M[A]=X`` in one case and ``Load M[A]`` in a later case such
   that the load returns ``X`` -- an exact address *and* byte-version match
   between the committing write and the later read snapshot, with a partial
   ``byte_enable`` covering only its own lanes, and reuse of a first-touched
   unknown byte after it was materialized once;
3. complete ``CPU -> IP -> CPU`` and ``IP -> CPU -> IP`` chains across case
   boundaries;
4. let per-case feedback change the next case's input;
5. stop accepting testcases after an injected assertion finding while keeping
   the saved prefix replayable into the same failure in a fresh harness;
6. keep normalized events/final state unchanged under RFuzz chunk splits;
7. refuse saved receipts under a different execution ID.

Nothing here re-implements an existing consumer.  This module streams the trace
once through :class:`myfuzz.scenario.acceptance_metrics.TraceEventStream` for the
case/memory evidence, and :func:`myfuzz.scenario.cross_case_chains.cross_case_chain_report`
(the real ``ChainCertificates`` producer) streams it a second time for the
chain evidence, so a large run is read twice; chunk assembly is recomputed with the
real :class:`myfuzz.scenario.genome.ChunkAssembler`; and the execution-identity
verdict is produced by the real
:meth:`myfuzz.scenario.runner.ScenarioRunner.execute_step` receipt cache driven
by a declaration-only stub harness.

Evidence rules enforced by the report itself:

* a criterion the artifacts cannot prove is ``measured: false`` with ``met:
  null`` and a reason -- never a pass and never a fabricated zero;
* ``Store M[A]=X -> Load M[A]`` requires the *exact* frozen identities the
  writers recorded (``byte_offset`` + ``versions`` + ``writer_event_ids`` for
  reads, the committing transaction key/version for writes) and the read byte
  value; a string placeholder never counts as a match;
* cross-case chains require a certified certificate whose
  ``endpoint_case_index`` differs from its ``source_case_index``, per direction;
* the whole criterion is only ``met`` when it is measured **and** its exact
  evidence holds; a criterion measured on a truncated/evicted table stays
  ``null``;
* the gate exit code is ``0`` only when every critical key was measured and its
  criterion holds, ``2`` otherwise.  ``chunk_split_invariance.rtl_event_level``
  is reported as an explicit non-critical null: the real-RTL event/final-state
  half of the chunk criterion is not observable from a saved run.

This module never renders a harness, never starts a process and never touches
RTL.  Everything it computes comes from saved artifacts plus declaration-only
checks; the one in-process gate it drives (``execution_identity``) uses a stub
harness that cannot build, start or tick anything.
"""

from __future__ import annotations

from collections.abc import Mapping
import hashlib
import importlib
import json
from pathlib import Path

from .acceptance_metrics import (
    DEFAULT_CHUNK_CHARS,
    DEFAULT_INGEST_BATCH_SIZE,
    TraceEventStream,
    TraceUnavailable,
)
from .cross_case_chains import (
    DIRECTIONS as CHAIN_DIRECTIONS,
    cross_case_chain_report,
)

SCHEMA_VERSION = "p3_acceptance_report.v1"
MANIFEST_NAME = "online_session_manifest.json"
RUN_IDENTITY_NAME = "online_run_identity.json"
RECEIPTS_NAME = "receipts.jsonl"
REPORT_NAME = "report.json"
PLAN_NAME = "online_plan.json"
REPLAY_ARTIFACT_NAME = "minimal_replay.json"

#: The plan's own minimum: "at least three testcases with independent IDs".
MINIMUM_CASES = 3

EXIT_READY = 0
EXIT_NOT_READY = 2

#: Receipt statuses that stop the session and save its prefix.
FINDING_STATUSES = frozenset(("dut_violation", "finding", "assertion_failure"))

#: The plan wording of each criterion, so a verdict states what it judged.
CRITERIA = {
    "single_initialization": (
        "one session runs at least three testcases with independent case_id "
        "values from a single initialization/start/reset, with no harness "
        "rebuild between them"),
    "store_then_load": (
        "a Store M[A]=X committed in one case is read back as X by a Load M[A] "
        "snapshot in a later case, joined by the exact byte address, byte "
        "version and writer identity the artifact records"),
    "cross_case_chains": (
        "certified CPU->IP->CPU and IP->CPU->IP chains whose endpoint case "
        "index differs from their source case index"),
    "feedback_changes_next_input": (
        "feedback recorded for one case changes the next case's selected "
        "source/selection reason"),
    "finding_stops_and_replays": (
        "a finding stops case acceptance, the executed prefix is saved, and a "
        "fresh harness replays it into the same finding"),
    "chunk_split_invariance": (
        "RFuzz chunk splitting does not change the normalized input (measured "
        "here); the real-RTL normalized event/final-state half is reported "
        "separately and stays null for a saved run"),
    "chunk_split_invariance.rtl_event_level": (
        "real-RTL normalized event stream and final state are unchanged by "
        "RFuzz chunk splitting (requires the real-RTL chunk/batch equivalence "
        "test, not a saved run)"),
    "execution_identity": (
        "a STEP receipt issued under one execution_id is never accepted under "
        "a different execution_id"),
}

#: The real-RTL test that owns the event/final-state half of chunk invariance.
CHUNK_RTL_TEST = "tests/integration/test_scenario_irq_chunk_batch_equivalence_real.py"
CHUNK_RTL_REQUIRES = "MYFUZZ_SCENARIO_REAL=1 (a real RTL harness process)"

#: Chunk splits recomputed through the real assembler for one raw payload.
SPLIT_PATTERNS = ("single_chunk", "one_byte_chunks", "irregular_7_1_29_2_13",
                  "fixed_3_5_11", "half_and_halves")

#: Chain gaps are bounded the same way the dedicated consumer bounds them.
DEFAULT_MAX_GAP_CASES = 64
DEFAULT_MAX_MEMORY_LANES = 200_000
DEFAULT_MAX_CASE_IDS = 200_000
DEFAULT_MAX_MATCH_SAMPLES = 64
DEFAULT_MAX_LIMIT_ROWS = 64

#: The plan's controlled-fault run: the only saved artifact known to carry a
#: finding together with its saved prefix and reproduction record.
CONTROLLED_FAULT_RUN = "runs/current-dataflow-p5-fault-calibration-20261007-online"
#: The interventional A/B artifact that proves feedback *causality* (P4).
FEEDBACK_CAUSAL_ARTIFACT = "runs/current-dataflow-p4-feedback-causal-20261007-summary.json"
STALE_EXECUTION_REASON = "stale_execution: STEP belongs to another testcase run"


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def _limit(limits: list[dict], quantity: str, reason: str) -> None:
    limits.append({"quantity": quantity, "reason": reason})


def _module_identity(name: str) -> dict | None:
    """Path and sha256 of one module file, so a verdict names its producer."""
    try:
        module = importlib.import_module(name)
        path = Path(getattr(module, "__file__", "") or "")
        if not path.is_file():
            return None
        return {"module": name, "path": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    except Exception:  # pragma: no cover - import topology change
        return None


def _read_json_object(path: Path) -> dict | None:
    if not path.is_file():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError, OSError):
        return None
    return document if isinstance(document, dict) else None


def _read_json_lines(path: Path, *, maximum: int
                     ) -> tuple[list[dict], int, bool, str | None]:
    """(rows, malformed_count, truncated, reason) for one JSON-lines artifact.

    ``maximum + 1`` rows are read so that truncation is *observed* instead of
    inferred from the row count; the caller must downgrade any verdict that
    consumed a truncated table.
    """
    if not path.is_file():
        return [], 0, False, f"run directory has no {path.name}"
    rows: list[dict] = []
    malformed = 0
    truncated = False
    try:
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                if not line.strip():
                    continue
                try:
                    document = json.loads(line)
                except json.JSONDecodeError:
                    malformed += 1
                    continue
                if isinstance(document, dict):
                    rows.append(document)
                else:
                    malformed += 1
                if len(rows) > maximum:
                    truncated = True
                    break
    except (UnicodeDecodeError, OSError) as exc:
        return rows, malformed, False, f"{path.name} is not readable: {exc}"
    return rows[:maximum], malformed, truncated, None


def _case_of(event: Mapping) -> tuple[str | None, int | None]:
    """The exact ``observed_case`` identity one trace event carries, if any."""
    provenance = event.get("provenance")
    if not isinstance(provenance, Mapping):
        return None, None
    case = provenance.get("observed_case")
    if not isinstance(case, Mapping):
        return None, None
    case_id = case.get("case_id")
    case_index = case.get("case_index")
    if not isinstance(case_id, str) or not case_id:
        return None, None
    if type(case_index) is not int or case_index < 0:
        return None, None
    return case_id, case_index


def _event_id(value: object) -> int | None:
    return value if type(value) is int and value >= 0 else None


def _finite_number(value: object) -> float | int | None:
    """A JSON number that is finite; NaN/Infinity never reach the report."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float):
        import math
        return value if math.isfinite(value) else None
    return value


def _transaction_key(transaction: object) -> str | None:
    """The frozen writer identity of one committing transaction.

    ``myfuzz.scenario.memory_service`` records ``str(TransactionKey(**key))`` as
    the per-byte writer identity, so the same real type is used here instead of
    rebuilding that string from a template.
    """
    if not isinstance(transaction, Mapping):
        return None
    try:
        from .ledger import TransactionKey
        return str(TransactionKey(**dict(transaction)))
    except (TypeError, ValueError, KeyError):
        return None


def _integer_pair(value: object) -> tuple[int, int] | None:
    if (not isinstance(value, (list, tuple)) or len(value) != 2
            or any(type(item) is not int or item < 0 for item in value)):
        return None
    return int(value[0]), int(value[1])


def _payload_bytes(value: object) -> bytes | None:
    if not isinstance(value, str) or not value or len(value) % 2:
        return None
    try:
        return bytes.fromhex(value)
    except ValueError:
        return None


def _clip(rows: list, maximum: int = DEFAULT_MAX_LIMIT_ROWS) -> list:
    return rows[:maximum]


# ---------------------------------------------------------------------------
# single-pass trace observation: cases, boot markers, memory effects
# ---------------------------------------------------------------------------


class _TraceObserver:
    """One streaming pass: case identities, boot/reset markers, memory joins.

    The memory join follows the frozen writer/reader contract of
    ``myfuzz.scenario.memory_service``: a committing write registers one record
    per enabled lane (``memory_write_commit`` cells when the commit stream is
    enabled, otherwise the ``memory_write`` event), and a ``memory_read``
    snapshot matches a lane only when its recorded ``versions[lane]`` and
    ``writer_event_ids[lane]`` are exactly the registered pair.  The read byte
    must additionally equal the committed byte value.
    """

    def __init__(self, *, max_lanes: int = DEFAULT_MAX_MEMORY_LANES,
                 max_case_ids: int = DEFAULT_MAX_CASE_IDS,
                 max_samples: int = DEFAULT_MAX_MATCH_SAMPLES) -> None:
        if type(max_lanes) is not int or max_lanes < 1:
            raise ValueError("max_lanes must be a positive integer")
        if type(max_case_ids) is not int or max_case_ids < 1:
            raise ValueError("max_case_ids must be a positive integer")
        self.max_lanes = max_lanes
        self.max_case_ids = max_case_ids
        self.max_samples = max_samples
        self.cases: dict[str, dict] = {}
        self.case_indexes: list[int] = []
        self.unattributed_events = 0
        self.event_count = 0
        self.exhausted = False
        # boot / reset / interruption markers
        self.initial_image_events: list[dict] = []
        self.native_startup_events = 0
        self.memory_initialization_events = 0
        self.harness_failure_events = 0
        self.begin_failure_events = 0
        self.reset_epochs: set[int] = set()
        self.reset_epoch_events = 0
        # transaction identities
        self.execution_ids: set[str] = set()
        self.testcase_ids: set[str] = set()
        # memory tables
        self.writers: dict[tuple, dict] = {}
        self.materialized: dict[tuple, dict] = {}
        self.memory_write = 0
        self.memory_write_commit = 0
        self.memory_read = 0
        self.lane_matches = 0
        self.cross_case_matches = 0
        self.same_case_matches = 0
        self.unattributed_matches = 0
        self.value_conflicts = 0
        self.value_conflict_samples: list[dict] = []
        self.unresolved_writer_identities = 0
        self.cross_case_rows: list[dict] = []
        self.partial_writes = 0
        self.full_writes = 0
        self.non_enabled_lane_checks = 0
        self.non_enabled_lane_adoptions = 0
        self.reused_lanes = 0
        self.rematerialized_lanes = 0
        self.lane_table_truncated = False
        self.case_table_truncated = False
        self.duplicate_case_ids: list[dict] = []

    # -- case identity ------------------------------------------------------

    def _observe_case(self, event: Mapping, case_id: str, case_index: int) -> None:
        event_id = _event_id(event.get("event_id"))
        row = self.cases.get(case_id)
        if row is None:
            if len(self.cases) >= self.max_case_ids:
                self.case_table_truncated = True
                return
            row = {"case_id": case_id, "case_index": case_index,
                   "first_event_id": event_id, "last_event_id": event_id,
                   "events": 0}
            self.cases[case_id] = row
            self.case_indexes.append(case_index)
        elif row["case_index"] != case_index:
            self.duplicate_case_ids.append(
                {"case_id": case_id, "first_case_index": row["case_index"],
                 "later_case_index": case_index, "event_id": event_id})
        row["events"] += 1
        if event_id is not None:
            first = row["first_event_id"]
            row["first_event_id"] = event_id if first is None else min(first, event_id)
            last = row["last_event_id"]
            row["last_event_id"] = event_id if last is None else max(last, event_id)

    # -- memory -------------------------------------------------------------

    def _register_lane(self, key: tuple, record: dict) -> None:
        if len(self.writers) >= self.max_lanes and key not in self.writers:
            self.lane_table_truncated = True
            return
        self.writers[key] = record

    def _observe_memory_write(self, event: Mapping) -> None:
        self.memory_write += 1
        transaction = event.get("transaction")
        writer_id = _transaction_key(transaction)
        if writer_id is None:
            self.unresolved_writer_identities += 1
            return
        version = _integer_pair(event.get("version"))
        byte_enable = event.get("byte_enable")
        width_bytes = event.get("width_bytes")
        byte_offset = event.get("byte_offset")
        value = event.get("value")
        memory_id = event.get("memory_id")
        generation = event.get("generation")
        if (version is None or type(byte_enable) is not int or byte_enable < 0
                or type(width_bytes) is not int or width_bytes < 1
                or type(byte_offset) is not int or byte_offset < 0
                or type(value) is not int or value < 0
                or not isinstance(memory_id, str) or not memory_id
                or type(generation) is not int or generation < 0):
            self.unresolved_writer_identities += 1
            return
        if byte_enable == (1 << width_bytes) - 1:
            self.full_writes += 1
        else:
            self.partial_writes += 1
        case_id, case_index = _case_of(event)
        for lane in range(width_bytes):
            if not (byte_enable >> lane) & 1:
                continue
            self._register_lane(
                (memory_id, generation, byte_offset + lane),
                {"writer_id": writer_id, "version": version,
                 "value": (value >> (8 * lane)) & 0xFF,
                 "event_id": _event_id(event.get("event_id")),
                 "case_id": case_id, "case_index": case_index,
                 "byte_enable": byte_enable, "width_bytes": width_bytes,
                 "byte_offset": byte_offset, "kind": "memory_write"})

    def _observe_memory_write_commit(self, event: Mapping) -> None:
        self.memory_write_commit += 1
        document = event.get("commit_document")
        if not isinstance(document, Mapping):
            self.unresolved_writer_identities += 1
            return
        memory_id = document.get("memory_id")
        generation = document.get("generation")
        byte_offset = document.get("byte_offset")
        width_bytes = document.get("width_bytes")
        byte_enable = document.get("byte_enable")
        if (not isinstance(memory_id, str) or not memory_id
                or type(generation) is not int or generation < 0
                or type(byte_offset) is not int or byte_offset < 0
                or type(width_bytes) is not int or width_bytes < 1
                or type(byte_enable) is not int or byte_enable < 0):
            self.unresolved_writer_identities += 1
            return
        if byte_enable == (1 << width_bytes) - 1:
            self.full_writes += 1
        else:
            self.partial_writes += 1
        cells = document.get("enabled_byte_cells")
        if not isinstance(cells, list):
            self.unresolved_writer_identities += 1
            return
        case_id, case_index = _case_of(event)
        for cell in cells:
            if not isinstance(cell, Mapping):
                self.unresolved_writer_identities += 1
                continue
            cell_offset = cell.get("byte_offset")
            version = _integer_pair(cell.get("version"))
            writer_id = cell.get("writer_event_id")
            value = cell.get("value")
            if (type(cell_offset) is not int or cell_offset < 0 or version is None
                    or not isinstance(writer_id, str) or not writer_id
                    or type(value) is not int or not 0 <= value < 256):
                self.unresolved_writer_identities += 1
                continue
            self._register_lane(
                (memory_id, generation, cell_offset),
                {"writer_id": writer_id, "version": version, "value": value,
                 "event_id": _event_id(event.get("event_id")),
                 "case_id": case_id, "case_index": case_index,
                 "byte_enable": byte_enable, "width_bytes": width_bytes,
                 "byte_offset": byte_offset, "kind": "memory_write_commit"})

    def _observe_memory_read(self, event: Mapping) -> None:
        self.memory_read += 1
        versions = event.get("versions")
        writer_ids = event.get("writer_event_ids")
        byte_offset = event.get("byte_offset")
        memory_id = event.get("memory_id")
        generation = event.get("generation")
        raw = _payload_bytes(event.get("data_hex"))
        if (not isinstance(versions, list) or not isinstance(writer_ids, list)
                or len(versions) != len(writer_ids) or raw is None
                or type(byte_offset) is not int or byte_offset < 0
                or not isinstance(memory_id, str) or not memory_id
                or type(generation) is not int or generation < 0):
            return
        case_id, case_index = _case_of(event)
        read_event_id = _event_id(event.get("event_id"))
        matches: list[tuple[int, dict]] = []
        for lane, (version, writer_id) in enumerate(zip(versions, writer_ids)):
            version_pair = _integer_pair(version)
            if version_pair is None or not isinstance(writer_id, str):
                continue
            offset = byte_offset + lane
            key = (memory_id, generation, offset)
            read_value = raw[lane] if lane < len(raw) else None
            record = self.writers.get(key)
            if (record is not None and record["version"] == version_pair
                    and record["writer_id"] == writer_id):
                self.lane_matches += 1
                if read_value is None or read_value != record["value"]:
                    self.value_conflicts += 1
                    if len(self.value_conflict_samples) < self.max_samples:
                        self.value_conflict_samples.append({
                            "read_event_id": read_event_id,
                            "write_event_id": record["event_id"],
                            "byte_offset": offset,
                            "version": list(version_pair),
                            "writer_event_id": writer_id,
                            "read_value": read_value,
                            "committed_value": record["value"]})
                    matches.append((lane, record))
                    continue
                matches.append((lane, record))
                self._record_match(record, event, case_id, case_index, lane,
                                   offset, version_pair, writer_id, read_value)
            materialized = self.materialized.get(key)
            if (materialized is not None
                    and materialized["version"] == version_pair
                    and materialized["writer_id"] == writer_id):
                self.reused_lanes += 1
        self._check_lane_selectivity(event, byte_offset, versions, writer_ids,
                                     matches)

    def _record_match(self, record: Mapping, event: Mapping, case_id, case_index,
                      lane: int, offset: int, version, writer_id,
                      read_value) -> None:
        record_index = record["case_index"]
        read_index = case_index
        if record_index is None or read_index is None:
            self.unattributed_matches += 1
            return
        if record_index < read_index:
            self.cross_case_matches += 1
            row = {
                "write_event_id": record["event_id"],
                "read_event_id": _event_id(event.get("event_id")),
                "write_case_id": record["case_id"],
                "write_case_index": record_index,
                "read_case_id": case_id, "read_case_index": read_index,
                "address": event.get("address"),
                "lane": lane, "byte_offset": offset,
                "version": list(version), "writer_event_id": writer_id,
                "value": record["value"], "read_value": read_value,
                "writer_kind": record["kind"]}
            self._append_cross_case(row)
        elif record_index == read_index:
            self.same_case_matches += 1
        else:
            self.unattributed_matches += 1

    def _append_cross_case(self, row: dict) -> None:
        """Group lane rows of one write/read pair into one sampled match."""
        for existing in self.cross_case_rows:
            if (existing["write_event_id"] == row["write_event_id"]
                    and existing["read_event_id"] == row["read_event_id"]):
                existing["lanes"].append(self._lane_row(row))
                return
        if len(self.cross_case_rows) >= self.max_samples:
            return
        self.cross_case_rows.append({
            "write_event_id": row["write_event_id"],
            "read_event_id": row["read_event_id"],
            "write_case_id": row["write_case_id"],
            "write_case_index": row["write_case_index"],
            "read_case_id": row["read_case_id"],
            "read_case_index": row["read_case_index"],
            "address": row["address"],
            "writer_kind": row["writer_kind"],
            "lanes": [self._lane_row(row)]})

    @staticmethod
    def _lane_row(row: Mapping) -> dict:
        return {"lane": row["lane"], "byte_offset": row["byte_offset"],
                "version": row["version"],
                "writer_event_id": row["writer_event_id"],
                "value": row["value"], "read_value": row["read_value"]}

    def _check_lane_selectivity(self, event: Mapping, byte_offset: int,
                                versions: list, writer_ids: list,
                                matches: list) -> None:
        """A partially enabled write must not adopt its version elsewhere.

        For every matching lane whose committing write enabled only some of its
        own lanes, each read lane inside the write's byte span that the write
        did *not* enable must carry a different ``(version, writer)`` pair; a
        read that carries the write's pair on a lane the write never covered
        would falsify byte-enable lane selectivity.
        """
        if not matches:
            return
        for lane, record in matches:
            byte_enable = record.get("byte_enable")
            width_bytes = record.get("width_bytes")
            write_offset = record.get("byte_offset")
            if (type(byte_enable) is not int or type(width_bytes) is not int
                    or type(write_offset) is not int):
                continue
            if byte_enable == (1 << width_bytes) - 1:
                continue
            for other_lane in range(len(versions)):
                relative = byte_offset + other_lane - write_offset
                if not 0 <= relative < width_bytes:
                    continue
                if (byte_enable >> relative) & 1:
                    continue
                self.non_enabled_lane_checks += 1
                other_version = _integer_pair(versions[other_lane])
                if (other_version == record["version"]
                        and writer_ids[other_lane] == record["writer_id"]):
                    self.non_enabled_lane_adoptions += 1

    def _observe_memory_initialization(self, event: Mapping) -> None:
        self.memory_initialization_events += 1
        memory_id = event.get("memory_id")
        generation = event.get("generation")
        byte_offset = event.get("byte_offset")
        version = _integer_pair(event.get("version"))
        writer_id = event.get("writer_event_id")
        value = event.get("value")
        if (not isinstance(memory_id, str) or not memory_id
                or type(generation) is not int or generation < 0
                or type(byte_offset) is not int or byte_offset < 0
                or version is None or not isinstance(writer_id, str)
                or not writer_id or type(value) is not int):
            return
        key = (memory_id, generation, byte_offset)
        if key in self.materialized:
            self.rematerialized_lanes += 1
            return
        if len(self.materialized) >= self.max_lanes:
            self.lane_table_truncated = True
            return
        case_id, case_index = _case_of(event)
        self.materialized[key] = {
            "version": version, "writer_id": writer_id, "value": value,
            "event_id": _event_id(event.get("event_id")),
            "case_id": case_id, "case_index": case_index}

    # -- one event ----------------------------------------------------------

    def observe(self, event: Mapping) -> None:
        self.event_count += 1
        kind = event.get("kind")
        case_id, case_index = _case_of(event)
        if case_id is not None and case_index is not None:
            self._observe_case(event, case_id, case_index)
        else:
            self.unattributed_events += 1
        transaction = event.get("transaction")
        if isinstance(transaction, Mapping):
            execution_id = transaction.get("execution_id")
            testcase_id = transaction.get("testcase_id")
            if isinstance(execution_id, str) and execution_id:
                self.execution_ids.add(execution_id)
            if isinstance(testcase_id, str) and testcase_id:
                self.testcase_ids.add(testcase_id)
        if kind == "initial_image":
            self.initial_image_events.append({
                "event_id": _event_id(event.get("event_id")),
                "component": event.get("component"),
                "image_id": event.get("image_id"),
                "case_id": case_id, "case_index": case_index})
        elif kind == "cpu_native_startup":
            self.native_startup_events += 1
        elif kind in ("harness_failure", "begin_failure"):
            if kind == "harness_failure":
                self.harness_failure_events += 1
            else:
                self.begin_failure_events += 1
        if "reset_epoch" in event and type(event.get("reset_epoch")) is int:
            self.reset_epoch_events += 1
            self.reset_epochs.add(event["reset_epoch"])
        if kind == "memory_write":
            self._observe_memory_write(event)
        elif kind == "memory_write_commit":
            self._observe_memory_write_commit(event)
        elif kind == "memory_read":
            self._observe_memory_read(event)
        elif kind == "memory_initialization":
            self._observe_memory_initialization(event)

    # -- report -------------------------------------------------------------

    def case_report(self) -> dict:
        indexes = list(self.case_indexes)
        sorted_indexes = sorted(set(indexes))
        monotone = all(left <= right for left, right in zip(indexes, indexes[1:]))
        contiguous = (bool(sorted_indexes)
                      and sorted_indexes == list(range(sorted_indexes[0],
                                                      sorted_indexes[-1] + 1)))
        first_case_event = min((row["first_event_id"] for row in self.cases.values()
                                if row["first_event_id"] is not None), default=None)
        initial_image_after_case = [
            row for row in self.initial_image_events
            if (row["case_id"] is not None
                or (first_case_event is not None and row["event_id"] is not None
                    and row["event_id"] > first_case_event))]
        rebuild: list[str] = []
        if initial_image_after_case:
            rebuild.append("initial_image_written_after_the_first_case")
        if self.native_startup_events > 1:
            rebuild.append("more_than_one_native_startup_marker")
        if self.harness_failure_events:
            rebuild.append("harness_failure_event")
        if self.begin_failure_events:
            rebuild.append("begin_failure_event")
        if not monotone:
            rebuild.append("case_index_regression")
        if self.duplicate_case_ids:
            rebuild.append("duplicate_case_id_with_a_different_index")
        if len(self.reset_epochs) > 1:
            rebuild.append("reset_epoch_changed_mid_session")
        return {
            "event_count": self.event_count if self.exhausted else None,
            "unattributed_event_count": (self.unattributed_events
                                         if self.exhausted else None),
            "case_count": len(self.cases) if self.exhausted else None,
            "case_ids": sorted(self.cases) if self.exhausted else None,
            "case_ids_sample": _clip(sorted(self.cases)) if self.exhausted else None,
            "case_index_by_id": ({case_id: row["case_index"]
                                  for case_id, row in self.cases.items()}
                                 if self.exhausted else None),
            "case_indexes": indexes if self.exhausted else None,
            "case_index_monotone": monotone if self.exhausted else None,
            "case_index_contiguous": contiguous if self.exhausted else None,
            "first_case_event_id": first_case_event if self.exhausted else None,
            "cases": _clip([dict(self.cases[key]) for key in sorted(self.cases)])
            if self.exhausted else None,
            "initialization": {
                "initial_image_count": len(self.initial_image_events),
                "initial_image_ids": _clip(sorted({
                    str(row["image_id"]) for row in self.initial_image_events})),
                "initial_image_events": _clip(self.initial_image_events),
                "initial_image_after_first_case": len(initial_image_after_case),
                "native_startup_count": self.native_startup_events,
                "memory_initialization_count": self.memory_initialization_events,
            },
            "reset_epochs": (sorted(self.reset_epochs)
                             if self.reset_epoch_events else None),
            "reset_epoch_events": self.reset_epoch_events,
            "rebuild_evidence": rebuild if self.exhausted else None,
            "rebuild_evidence_measured": bool(self.exhausted),
            "harness_failure_events": self.harness_failure_events,
            "begin_failure_events": self.begin_failure_events,
            "duplicate_case_ids": _clip(self.duplicate_case_ids),
            "case_table_truncated": self.case_table_truncated,
            "lane_table_truncated": self.lane_table_truncated,
        }

    def memory_report(self) -> dict:
        byte_enable_measured = (self.partial_writes > 0
                                and self.non_enabled_lane_checks > 0)
        lane_selectivity_met = None
        lane_selectivity_reason = None
        if self.partial_writes == 0:
            lane_selectivity_reason = (
                "no write with a partial byte_enable is recorded in this "
                "artifact, so lane selectivity could not be falsified here")
        elif self.non_enabled_lane_checks == 0:
            lane_selectivity_reason = (
                "no partially enabled write was matched by a read snapshot, so "
                "no non-enabled lane could be checked")
        else:
            lane_selectivity_met = self.non_enabled_lane_adoptions == 0
            if lane_selectivity_met is False:
                lane_selectivity_reason = (
                    f"{self.non_enabled_lane_adoptions} read lane(s) adopted the "
                    "version of a write whose byte_enable never covered them")
        reuse = {
            "measured": self.memory_initialization_events > 0,
            "met": None, "materialized_lanes": len(self.materialized),
            "reused_lanes": self.reused_lanes,
            "rematerialized_lanes": self.rematerialized_lanes,
            "reason": None}
        if self.memory_initialization_events == 0:
            reuse["reason"] = ("no memory_initialization event is recorded in "
                               "this artifact, so no first-touch byte could be "
                               "observed being materialized once")
        elif self.rematerialized_lanes:
            reuse["met"] = False
            reuse["reason"] = (f"{self.rematerialized_lanes} byte(s) were "
                               "materialized more than once")
        elif self.reused_lanes == 0:
            reuse["met"] = False
            reuse["reason"] = ("first-touch bytes were materialized but no later "
                               "read snapshot carried the materialized "
                               "version/writer identity, so reuse was not "
                               "observed")
        else:
            reuse["met"] = True
        return {
            "event_kinds": {
                "memory_write": self.memory_write,
                "memory_write_commit": self.memory_write_commit,
                "memory_read": self.memory_read,
                "memory_initialization": self.memory_initialization_events},
            "lane_matches": self.lane_matches,
            "cross_case_matches": self.cross_case_matches,
            "same_case_matches": self.same_case_matches,
            "unattributed_matches": self.unattributed_matches,
            "value_conflicts": self.value_conflicts,
            "value_conflict_samples": _clip(self.value_conflict_samples),
            "cross_case_match_samples": _clip(self.cross_case_rows),
            "first_cross_case_match": (self.cross_case_rows[0]
                                       if self.cross_case_rows else None),
            "unresolved_writer_identities": self.unresolved_writer_identities,
            "lane_table_truncated": self.lane_table_truncated,
            "byte_enable": {
                "partial_byte_enable_writes": self.partial_writes,
                "full_byte_enable_writes": self.full_writes,
                "enabled_lane_matches": self.lane_matches,
                "non_enabled_lane_checks": self.non_enabled_lane_checks,
                "non_enabled_lane_adoptions": self.non_enabled_lane_adoptions,
                "lane_selectivity": {
                    "measured": byte_enable_measured,
                    "met": lane_selectivity_met,
                    "reason": lane_selectivity_reason}},
            "first_unknown_read_reuse": reuse,
        }


# ---------------------------------------------------------------------------
# artifact readers
# ---------------------------------------------------------------------------


def _manifest_section(directory: Path, limits: list[dict]) -> dict:
    path = directory / MANIFEST_NAME
    section = {"name": MANIFEST_NAME, "available": False, "reason": None,
               "file_sha256": None, "identity_sha256": None,
               "schema_version": None, "session_manifest_count": None,
               "components": None, "component_identities": None,
               "memory_initialization_seed": None, "instruction_slot_count": None,
               "bindings": None, "irq_pulses": None, "host_source_file_count": None}
    if not path.is_file():
        section["reason"] = f"run directory has no {MANIFEST_NAME}"
        _limit(limits, "manifest", section["reason"])
        return section
    try:
        raw = path.read_bytes()
    except OSError as exc:
        section["reason"] = f"{MANIFEST_NAME} is not readable: {exc}"
        _limit(limits, "manifest", section["reason"])
        return section
    section["file_sha256"] = hashlib.sha256(raw).hexdigest()
    document = _read_json_object(path)
    if document is None:
        section["reason"] = f"{MANIFEST_NAME} is not a JSON object"
        _limit(limits, "manifest", section["reason"])
        return section
    # The frozen writer hashes the canonical document; the file adds one LF.
    section["identity_sha256"] = hashlib.sha256(
        raw[:-1] if raw.endswith(b"\n") else raw).hexdigest()
    section["available"] = True
    section["schema_version"] = document.get("schema_version")
    runner = document.get("runner")
    if not isinstance(runner, Mapping):
        section["reason"] = "the manifest has no runner identity document"
        _limit(limits, "manifest.runner", section["reason"])
        return section
    sessions = runner.get("sessions")
    if isinstance(sessions, Mapping) and sessions:
        # One manifest document is written by the session's single begin();
        # every receipt carries its identity hash, which is what binds the
        # run to one initialization.  The document itself lists components,
        # not sessions, so no session *count* is invented from it.
        section["session_manifest_count"] = 1
        section["components"] = sorted(str(name) for name in sessions)
        identities = {}
        for name, entry in sessions.items():
            build = None
            if isinstance(entry, Mapping):
                identity = entry.get("identity")
                if isinstance(identity, Mapping):
                    build = identity.get("build_identity")
            identities[str(name)] = {
                "artifact_digest": (build.get("artifact_digest")
                                    if isinstance(build, Mapping) else None),
                "build_digest": (build.get("build_digest")
                                 if isinstance(build, Mapping) else None)}
        section["component_identities"] = identities
    else:
        section["reason"] = "the runner identity document declares no session"
        _limit(limits, "manifest.runner.sessions", section["reason"])
    memories = runner.get("memories")
    if isinstance(memories, Mapping):
        seeds = {str(name): (value.get("initialization_seed")
                             if isinstance(value, Mapping) else None)
                 for name, value in memories.items()}
        section["memory_initialization_seed"] = seeds
        slots = 0
        for value in memories.values():
            if isinstance(value, Mapping) and isinstance(
                    value.get("instruction_slots"), list):
                slots += len(value["instruction_slots"])
        section["instruction_slot_count"] = slots
    section["bindings"] = len(runner.get("bindings") or ())
    section["irq_pulses"] = len(runner.get("irq_pulses") or ())
    host_sources = document.get("online_source_files")
    section["host_source_file_count"] = (len(host_sources)
                                         if isinstance(host_sources, list) else None)
    return section


def _run_identity_section(directory: Path, manifest: Mapping,
                          limits: list[dict]) -> dict:
    path = directory / RUN_IDENTITY_NAME
    section = {"name": RUN_IDENTITY_NAME, "available": False, "reason": None,
               "sha256": None, "schema_version": None, "run_id": None,
               "execution_mode": None, "manifest_sha256": None,
               "manifest_identity_matches": None}
    if not path.is_file():
        section["reason"] = f"run directory has no {RUN_IDENTITY_NAME}"
        _limit(limits, "run_identity", section["reason"])
        return section
    document = _read_json_object(path)
    if document is None:
        section["reason"] = f"{RUN_IDENTITY_NAME} is not a JSON object"
        _limit(limits, "run_identity", section["reason"])
        return section
    section["available"] = True
    section["sha256"] = document.get("sha256")
    identity = document.get("identity")
    if not isinstance(identity, Mapping):
        section["reason"] = "the run identity document has no identity body"
        _limit(limits, "run_identity", section["reason"])
        return section
    section["schema_version"] = identity.get("schema_version")
    section["execution_mode"] = identity.get("execution_mode")
    config = identity.get("run_config")
    if isinstance(config, Mapping):
        run_id = config.get("run_id")
        section["run_id"] = run_id if isinstance(run_id, str) and run_id else None
    session = identity.get("session")
    if isinstance(session, Mapping):
        recorded = session.get("manifest_sha256")
        section["manifest_sha256"] = recorded
        if isinstance(recorded, str) and manifest.get("identity_sha256"):
            section["manifest_identity_matches"] = (
                recorded == manifest["identity_sha256"])
    return section


def _receipts_section(directory: Path, manifest: Mapping, *,
                      maximum: int, limits: list[dict]) -> dict:
    path = directory / RECEIPTS_NAME
    rows, malformed, truncated, reason = _read_json_lines(path, maximum=maximum)
    section = {"name": RECEIPTS_NAME, "available": False, "reason": reason,
               "count": len(rows), "malformed_lines": malformed,
               "truncated": truncated, "case_ids": None,
               "case_count": None, "duplicate_case_ids": [], "statuses": {},
               "finding_rows": [], "manifest_sha256_values": None,
               "run_id_values": None, "manifest_identity_matches": None,
               "selection_reasons": {}, "missing_case_id_rows": None,
               "rows": None}
    if reason is not None:
        _limit(limits, "receipts", reason)
        return section
    section["available"] = True
    if truncated:
        _limit(limits, "receipts",
               f"more than {maximum} receipt rows exist; every criterion that "
               "consumed this table is a lower bound and stays unmeasured")
    statuses: dict[str, int] = {}
    reasons: dict[str, int] = {}
    case_ids: list[str] = []
    seen: set[str] = set()
    duplicates: list[str] = []
    identities: set[str] = set()
    run_ids: set[str] = set()
    finding_rows: list[dict] = []
    kept: list[dict] = []
    missing_case_ids = 0
    for index, row in enumerate(rows):
        case_id = row.get("case_id")
        if isinstance(case_id, str) and case_id:
            case_ids.append(case_id)
            if case_id in seen:
                duplicates.append(case_id)
            seen.add(case_id)
        else:
            missing_case_ids += 1
        status = row.get("status")
        statuses[str(status)] = statuses.get(str(status), 0) + 1
        selection = row.get("source_selection_reason")
        if isinstance(selection, str) and selection:
            reasons[selection] = reasons.get(selection, 0) + 1
        manifest_sha = row.get("manifest_sha256")
        if isinstance(manifest_sha, str) and manifest_sha:
            identities.add(manifest_sha)
        run_id = row.get("run_id")
        if isinstance(run_id, str) and run_id:
            run_ids.add(run_id)
        gains = row.get("interaction_source_gains")
        features = row.get("interaction_new_features")
        violations = row.get("violations")
        summary = {
            "receipt_index": index, "case_id": case_id, "status": status,
            "violations": (list(violations) if isinstance(violations, list)
                           else []),
            "source_selection_reason": (selection
                                        if isinstance(selection, str) else None),
            "applied_source_ids": (list(row.get("applied_source_ids"))
                                   if isinstance(row.get("applied_source_ids"),
                                                 list) else None),
            "interaction_source_gains": (dict(gains)
                                         if isinstance(gains, Mapping) else None),
            "interaction_new_features": (list(features)
                                         if isinstance(features, list) else None),
            "interaction_deferred": row.get("interaction_deferred"),
            "closed_loop_status": row.get("closed_loop_status"),
            "closed_loop_source_weights": (
                dict(row.get("closed_loop_source_weights"))
                if isinstance(row.get("closed_loop_source_weights"), Mapping)
                else None),
            "candidate_disposition": row.get("candidate_disposition"),
            "slot": row.get("slot"), "buffer_id": row.get("buffer_id"),
            "online_raw_records_hex": (
                list(row.get("online_raw_records_hex"))
                if isinstance(row.get("online_raw_records_hex"), list) else None),
            "run_id": run_id if isinstance(run_id, str) else None,
            "manifest_sha256": (manifest_sha
                                if isinstance(manifest_sha, str) else None),
        }
        if isinstance(status, str) and status in FINDING_STATUSES:
            finding_rows.append(summary)
        kept.append(summary)
    section["case_ids"] = case_ids
    section["case_ids_sample"] = _clip(case_ids)
    section["case_count"] = len(seen)
    section["missing_case_id_rows"] = missing_case_ids
    section["duplicate_case_ids"] = _clip(duplicates)
    section["statuses"] = dict(sorted(statuses.items()))
    section["selection_reasons"] = dict(sorted(reasons.items()))
    section["finding_rows"] = _clip(finding_rows)
    section["manifest_sha256_values"] = sorted(identities)
    section["run_id_values"] = sorted(run_ids)
    section["rows"] = kept
    if manifest.get("identity_sha256") is not None and identities:
        section["manifest_identity_matches"] = identities == {
            manifest["identity_sha256"]}
    return section


def _plan_section(directory: Path, limits: list[dict]) -> dict:
    path = directory / PLAN_NAME
    section = {"name": PLAN_NAME, "available": False, "reason": None,
               "schema_version": None, "case_ids": None, "case_count": None,
               "terminal_failure": None}
    if not path.is_file():
        section["reason"] = f"run directory has no {PLAN_NAME}"
        _limit(limits, "online_plan", section["reason"])
        return section
    document = _read_json_object(path)
    if document is None:
        section["reason"] = f"{PLAN_NAME} is not a JSON object"
        _limit(limits, "online_plan", section["reason"])
        return section
    section["available"] = True
    section["schema_version"] = document.get("schema_version")
    cases = document.get("cases")
    if isinstance(cases, list):
        section["case_count"] = len(cases)
        section["case_ids"] = [row.get("case_id") for row in cases
                               if isinstance(row, Mapping)]
        section["case_ids_sample"] = _clip(section["case_ids"])
    failure = document.get("terminal_failure")
    if isinstance(failure, Mapping):
        section["terminal_failure"] = {
            "phase": failure.get("phase"),
            "case_id": failure.get("case_id"),
            "case_index": failure.get("case_index"),
            "error_type": failure.get("error_type")}
    return section


def _report_section(directory: Path, limits: list[dict]) -> dict:
    path = directory / REPORT_NAME
    section = {"name": REPORT_NAME, "available": False, "reason": None,
               "session_status": None, "statuses": None, "tests": None,
               "effective_search_seconds": None, "elapsed_seconds": None}
    if not path.is_file():
        section["reason"] = f"run directory has no {REPORT_NAME}"
        _limit(limits, "report", section["reason"])
        return section
    document = _read_json_object(path)
    if document is None:
        section["reason"] = f"{REPORT_NAME} is not a JSON object"
        _limit(limits, "report", section["reason"])
        return section
    section["available"] = True
    section["session_status"] = document.get("session_status")
    statuses = document.get("statuses")
    section["statuses"] = (dict(statuses) if isinstance(statuses, Mapping)
                           else None)
    section["tests"] = document.get("tests")
    section["effective_search_seconds"] = _finite_number(
        document.get("effective_search_seconds"))
    section["elapsed_seconds"] = _finite_number(document.get("elapsed_seconds"))
    return section


def _trace_section(stream, reason: str | None, observer: _TraceObserver) -> dict:
    if stream is None:
        return {"available": False, "reason": reason, "events_file": None,
                "format": None, "path": None, "bytes": None,
                "meta_schema_version": None, "declared_event_count": None,
                "declared_status": None, "declared_local_ticks": None,
                "events_ingested": None, "event_count_match": None,
                "semantic_sha256_verified": None}
    descriptor = stream.descriptor
    declared = descriptor["declared_event_count"]
    ingested = observer.event_count if observer.exhausted else None
    return {
        "available": True, "reason": reason,
        "events_file": descriptor["events_file"],
        "format": descriptor["format"], "path": descriptor["path"],
        "bytes": descriptor["bytes"],
        "meta_schema_version": descriptor["meta_schema_version"],
        "declared_event_count": declared,
        "declared_status": descriptor["declared_status"],
        "declared_local_ticks": descriptor["declared_local_ticks"],
        "events_ingested": ingested,
        "event_count_match": (None if type(declared) is not int or ingested is None
                              else declared == ingested),
        "semantic_sha256_verified": (stream.semantic_sha256_verified()
                                     if observer.exhausted else None)}


# ---------------------------------------------------------------------------
# criteria
# ---------------------------------------------------------------------------


def _item(criterion_key: str, *, measured: bool, met, evidence: dict | None,
          reason: str | None) -> dict:
    return {"criterion": CRITERIA[criterion_key], "measured": bool(measured),
            "met": met, "evidence": evidence, "reason": reason}


def _single_initialization(manifest: Mapping, run_identity: Mapping,
                           receipts: Mapping, trace: Mapping, plan: Mapping,
                           cases: Mapping | None, limits: list[dict]) -> dict:
    """One session manifest binds every receipt; the case sequence is one run.

    The P3 plan names the evidence for this criterion: the session/runner
    identity and the ``case_id`` sequence.  Three parts are reported
    explicitly:

    * ``session_identity`` -- one session manifest whose identity every receipt
      carries, at least ``MINIMUM_CASES`` distinct executed case ids, and a run
      identity document that agrees;
    * ``case_sequence`` -- the observed case indexes are monotone and
      contiguous, and every attributed trace case is an executed case or a
      declared plan/bootstrap case;
    * ``no_rebuild`` -- none of the recorded contradictions (a second image load
      after the first case, more than one native startup, a case-index
      regression, a harness/begin failure, a mid-session reset epoch, a case id
      reused with another index).

    ``boot_markers`` is reported separately: when the trace carries no startup
    or reset marker at all, that half stays ``null`` with a reason instead of
    being folded into a pass.
    """
    if not manifest.get("available"):
        reason = manifest.get("reason") or "the run has no session manifest"
        return _item("single_initialization", measured=False, met=None,
                     evidence={"manifest": None, "case_count": None},
                     reason=f"a single initialized session cannot be shown: {reason}")
    if manifest.get("session_manifest_count") is None:
        reason = (manifest.get("reason")
                  or "the manifest declares no runner session identity")
        return _item("single_initialization", measured=False, met=None,
                     evidence={"manifest": None, "case_count": None},
                     reason=("a single initialized session cannot be shown: "
                             + reason))
    if not receipts.get("available"):
        reason = receipts.get("reason") or "the run has no receipts"
        return _item("single_initialization", measured=False, met=None,
                     evidence={"manifest": None, "case_count": None},
                     reason=f"per-case identities cannot be shown: {reason}")
    if receipts.get("truncated"):
        reason = ("the receipt table was truncated by max_case_ids, so the case "
                  "sequence is a lower bound")
        _limit(limits, "single_initialization", reason)
        return _item("single_initialization", measured=False, met=None,
                     evidence=None, reason=reason)
    if not receipts.get("case_count"):
        reason = ("the receipts carry no usable case_id "
                  f"({receipts.get('missing_case_id_rows')} row(s) without one), "
                  "so per-case identity is unmeasured")
        _limit(limits, "single_initialization", reason)
        return _item("single_initialization", measured=False, met=None,
                     evidence=None, reason=reason)
    if not trace.get("available") or cases is None:
        reason = trace.get("reason") or "the run has no streamable trace"
        return _item("single_initialization", measured=False, met=None,
                     evidence={"manifest": None, "case_count": None},
                     reason=f"case order cannot be shown: {reason}")

    receipt_ids = [case_id for case_id in (receipts.get("case_ids") or ())
                   if isinstance(case_id, str)]
    receipt_set = set(receipt_ids)
    trace_ids = set(cases.get("case_ids") or ())
    plan_ids = [case_id for case_id in (plan.get("case_ids") or ())
                if isinstance(case_id, str)]
    if plan_ids and receipt_ids and plan_ids[-len(receipt_ids):] == receipt_ids:
        leading = plan_ids[:-len(receipt_ids)]
    else:
        # The plan does not end in the executed sequence; no plan case may then
        # excuse an unattributed trace case.
        leading = []
    unexpected_trace = sorted(trace_ids - receipt_set - set(leading))
    missing_trace = sorted(receipt_set - trace_ids)
    attribution_measured = bool(trace_ids)
    identity_bound = receipts.get("manifest_identity_matches")
    run_identity_ok = run_identity.get("manifest_identity_matches")
    initialization = cases.get("initialization") or {}
    startup_count = initialization.get("native_startup_count")
    startup_observed = (type(startup_count) is int and startup_count > 0)
    reset_epochs = cases.get("reset_epochs")
    reset_observed = reset_epochs is not None
    boot_problems: list[str] = []
    if startup_observed and startup_count != 1:
        boot_problems.append(
            f"the trace records {startup_count} native startup marker(s), not "
            "exactly one")
    if reset_observed and len(reset_epochs) != 1:
        boot_problems.append(
            f"the trace records reset epochs {reset_epochs}, not exactly one")
    boot_unobserved = [
        name for name, observed in (("native startup marker", startup_observed),
                                    ("reset epoch", reset_observed))
        if not observed]
    boot_measured = bool(startup_observed and reset_observed)
    boot_met = None if boot_problems or boot_unobserved else True
    if boot_problems:
        boot_met = False
    if boot_unobserved:
        _limit(limits, "single_initialization.boot_markers",
               "the trace records no " + " and no ".join(boot_unobserved)
               + ", so 'started and initially reset exactly once' rests on the "
                 "session manifest identity alone and stays null")

    session_problems: list[str] = []
    if manifest.get("session_manifest_count") != 1:
        session_problems.append(
            "the artifact does not declare exactly one session manifest")
    if identity_bound is not True:
        session_problems.append(
            "the receipts do not all carry this manifest's identity")
    if identity_bound is None:
        session_problems.append(
            "the manifest identity could not be compared with the receipts")
    if run_identity.get("available") and run_identity_ok is False:
        session_problems.append(
            "the run identity document names a different session manifest than "
            "this artifact")
    if receipts.get("case_count", 0) < MINIMUM_CASES:
        session_problems.append(
            f"the session executed {receipts.get('case_count')} case(s); at "
            f"least {MINIMUM_CASES} are required")
    if receipts.get("duplicate_case_ids"):
        session_problems.append("a case_id is repeated across receipts")

    sequence_problems: list[str] = []
    if not attribution_measured:
        pass
    elif cases.get("case_table_truncated"):
        sequence_problems.append("the case table was truncated, so the case "
                                 "sequence is a lower bound")
    else:
        if not cases.get("case_index_monotone"):
            sequence_problems.append("the observed case indexes are not monotone")
        if not cases.get("case_index_contiguous"):
            sequence_problems.append("the observed case indexes are not contiguous")
    if attribution_measured and unexpected_trace:
        sequence_problems.append(
            "the trace carries case ids that are neither executed cases nor "
            f"declared plan/bootstrap cases: {_clip(unexpected_trace)}")

    rebuild_evidence = cases.get("rebuild_evidence")
    no_rebuild_problems: list[str] = []
    if rebuild_evidence:
        no_rebuild_problems.append(
            "single-initialization contradictions were observed: "
            + ", ".join(rebuild_evidence)
            + "; a re-initialization/rebuild between cases is exactly what the "
              "single-initialization criterion forbids")
    if boot_met is False:
        no_rebuild_problems.extend(boot_problems)
    if not attribution_measured:
        _limit(limits, "single_initialization.case_sequence",
               "no trace event carries an observed_case identity, so the case "
               "index sequence could not be read from this artifact")

    measured = attribution_measured
    met = (None if not measured else
           not session_problems and not sequence_problems
           and not no_rebuild_problems)
    evidence = {
        "manifest_identity_sha256": manifest.get("identity_sha256"),
        "run_identity_manifest_matches": run_identity_ok,
        "session_manifest_count": manifest.get("session_manifest_count"),
        "components": manifest.get("components"),
        "component_identities": manifest.get("component_identities"),
        "case_count": receipts.get("case_count"),
        "trace_case_count": cases.get("case_count"),
        "distinct_case_count": receipts.get("case_count"),
        "receipt_count": receipts.get("count"),
        "case_ids": cases.get("case_ids"),
        "case_indexes": cases.get("case_indexes"),
        "case_index_monotone": cases.get("case_index_monotone"),
        "case_index_contiguous": cases.get("case_index_contiguous"),
        "receipts_bind_manifest_identity": identity_bound,
        "receipt_manifest_sha256_values": receipts.get("manifest_sha256_values"),
        "trace_case_ids_without_receipt": unexpected_trace,
        "receipt_case_ids_without_trace_events": missing_trace,
        "plan_leading_case_ids": leading,
        "initialization": initialization,
        "reset_epochs": cases.get("reset_epochs"),
        "rebuild_evidence": rebuild_evidence,
        "rebuild_evidence_measured": cases.get("rebuild_evidence_measured"),
        "harness_failure_events": cases.get("harness_failure_events"),
        "begin_failure_events": cases.get("begin_failure_events"),
        "duplicate_case_ids": cases.get("duplicate_case_ids"),
        "boot_markers": {
            "measured": boot_measured, "met": boot_met,
            "native_startup_count": initialization.get("native_startup_count"),
            "reset_epochs": cases.get("reset_epochs"),
            "reason": ("; ".join(boot_problems) if boot_problems else
                       None if boot_measured else
                       "the trace records no " + " and no ".join(boot_unobserved)
                       + ", so 'started and initially reset exactly once' rests "
                         "on the session manifest identity alone and stays null")},
        "parts": {
            "session_identity": {
                "measured": True, "met": not session_problems,
                "reason": ("; ".join(session_problems)
                           if session_problems else None)},
            "case_sequence": {
                "measured": attribution_measured,
                "met": (not sequence_problems if attribution_measured else None),
                "attributed_trace_case_count": len(trace_ids),
                "reason": ("; ".join(sequence_problems) if sequence_problems
                           else None if attribution_measured else
                           "no trace event carries an observed_case identity")},
            "no_rebuild": {
                "measured": True, "met": not no_rebuild_problems,
                "reason": ("; ".join(no_rebuild_problems)
                           if no_rebuild_problems else None)},
        },
    }
    problems = list(session_problems) + list(sequence_problems)         + list(no_rebuild_problems)
    if not attribution_measured:
        problems.append("the trace carries no observed_case identity, so the "
                        "case index sequence is unmeasured")
    reason = "; ".join(problems) if problems else None
    return _item("single_initialization", measured=measured, met=met,
                 evidence=evidence, reason=reason)


def _store_then_load(trace: Mapping, memory: Mapping | None,
                     limits: list[dict]) -> dict:
    """Exact cross-case store/load join *and* its two required companions.

    The P3 acceptance sentence requires three things of this criterion: the
    exact version/address join, ``byte_enable`` covering only its own lanes, and
    reuse of a first-touched unknown byte.  All three are reported as explicit
    parts; the item is only ``met`` when every part is positively verified, and a
    part the artifact cannot show stays ``null`` (never a silent pass).
    """
    if not trace.get("available") or memory is None:
        reason = trace.get("reason") or "the run has no streamable trace"
        return _item("store_then_load", measured=False, met=None,
                     evidence=None,
                     reason=f"the memory event stream cannot be read: {reason}")
    kinds = memory["event_kinds"]
    if memory["lane_table_truncated"]:
        _limit(limits, "store_then_load.lane_table",
               "the per-byte writer table was truncated, so the stored/loaded "
               "join is a lower bound and no verdict is issued")
        return _item("store_then_load", measured=False, met=None,
                     evidence=memory,
                     reason="the per-byte writer table was truncated, so no "
                            "exact store/load join can be settled")
    writes = kinds["memory_write"] + kinds["memory_write_commit"]
    evidence = dict(memory)
    evidence["committing_event_kinds"] = [
        kind for kind in ("memory_write", "memory_write_commit")
        if kinds[kind]]
    if writes == 0:
        return _item("store_then_load", measured=False, met=None,
                     evidence=evidence,
                     reason="no memory_write/memory_write_commit event is "
                            "recorded in this artifact, so no Store M[A]=X was "
                            "observed; not observed is not a pass")

    selectivity = memory["byte_enable"]["lane_selectivity"]
    reuse = memory["first_unknown_read_reuse"]
    conflicts = memory["value_conflicts"]
    cross_problems: list[str] = []
    if conflicts:
        cross_problems.append(f"{conflicts} read lane(s) carry a matching "
                              "version/writer but a different byte value")
    if kinds["memory_read"] == 0:
        cross_problems.append("no memory_read snapshot is recorded in this "
                              "artifact, so no load could be joined")
    elif not memory["cross_case_matches"] and not cross_problems:
        if memory["same_case_matches"]:
            cross_problems.append(
                f"{memory['same_case_matches']} lane(s) match exactly but only "
                "inside the committing case, not across a case boundary")
        else:
            cross_problems.append(
                "no later memory_read snapshot carries the exact "
                "address/version/writer identity of a committed store")
    cross_measured = kinds["memory_read"] > 0
    parts = {
        "cross_case_exact_match": {
            "measured": cross_measured, "met": (not cross_problems
                                                if cross_measured else None),
            "cross_case_matches": memory["cross_case_matches"],
            "same_case_matches": memory["same_case_matches"],
            "value_conflicts": conflicts,
            "reason": "; ".join(cross_problems) if cross_problems else None},
        "byte_enable_lane_selectivity": {
            "measured": selectivity["measured"], "met": selectivity["met"],
            "partial_byte_enable_writes": memory["byte_enable"][
                "partial_byte_enable_writes"],
            "non_enabled_lane_checks": memory["byte_enable"][
                "non_enabled_lane_checks"],
            "non_enabled_lane_adoptions": memory["byte_enable"][
                "non_enabled_lane_adoptions"],
            "reason": selectivity["reason"]},
        "first_unknown_read_reuse": {
            "measured": reuse["measured"], "met": reuse["met"],
            "materialized_lanes": reuse["materialized_lanes"],
            "reused_lanes": reuse["reused_lanes"],
            "rematerialized_lanes": reuse["rematerialized_lanes"],
            "reason": reuse["reason"]},
    }
    evidence["parts"] = parts
    problems = [f"{name}: {part['reason']}" for name, part in parts.items()
                if part["measured"] and part["met"] is False]
    unobserved = [name for name, part in parts.items() if not part["measured"]]
    for name in unobserved:
        _limit(limits, f"store_then_load.{name}",
               parts[name]["reason"] or "the part is not observable here")
    met = not problems and not unobserved
    reason = None
    if problems or unobserved:
        parts_reason = list(problems)
        for name in unobserved:
            parts_reason.append(f"{name} was not observed in this artifact "
                                f"({parts[name]['reason']})")
        reason = "; ".join(parts_reason)
    return _item("store_then_load", measured=True, met=met, evidence=evidence,
                 reason=reason)


def _cross_case_chains(directory: Path, trace: Mapping, *,
                       chain_producer, max_gap_cases: int,
                       max_pending: int, max_event_gap: int,
                       require_native_receipts: bool,
                       ingest_batch_size: int, verify_semantic: bool,
                       limits: list[dict]) -> dict:
    if not trace.get("available"):
        reason = trace.get("reason") or "the run has no streamable trace"
        return _item("cross_case_chains", measured=False, met=None, evidence=None,
                     reason=f"no chain certificate can be derived: {reason}")
    try:
        report = cross_case_chain_report(
            directory, max_gap_cases=max_gap_cases, chain_producer=chain_producer,
            max_pending=max_pending, max_event_gap=max_event_gap,
            require_native_receipts=require_native_receipts,
            ingest_batch_size=ingest_batch_size, verify_semantic=verify_semantic)
    except Exception as exc:  # fail closed: no counts are better than wrong ones
        reason = (f"cross_case_chain_report failed: {type(exc).__name__}: {exc}")
        _limit(limits, "cross_case_chains", reason)
        return _item("cross_case_chains", measured=False, met=None,
                     evidence=None, reason=reason)
    evidence = {
        "source": "myfuzz.scenario.cross_case_chains.cross_case_chain_report",
        "certified_count": report.get("certified_count"),
        "incomplete_count": report.get("incomplete_count"),
        "cross_case_count": report.get("cross_case_count"),
        "same_case_count": report.get("same_case_count"),
        "unresolved_case_count": report.get("unresolved_case_count"),
        "duplicate_certificate_count": report.get("duplicate_certificate_count"),
        "truncated": report.get("truncated"),
        "max_case_gap_seen": report.get("max_case_gap_seen"),
        "all_directions_have_cross_case": report.get(
            "all_directions_have_cross_case"),
        "directions_without_cross_case": report.get(
            "directions_without_cross_case"),
        "by_direction": report.get("by_direction"),
        "chains": _clip(list(report.get("chains") or ())),
        "producer": report.get("producer"),
        "trace": report.get("trace"),
        "analyzer_limits": list(report.get("limits") or ()),
    }
    for limit in report.get("limits") or ():
        _limit(limits, f"cross_case_chains.{limit.get('quantity')}",
               str(limit.get("reason")))
    if report.get("truncated"):
        return _item("cross_case_chains", measured=False, met=None,
                     evidence=evidence,
                     reason="max_gap_cases truncated certified cross-case "
                            "chains, so the per-direction counts are lower "
                            "bounds and no verdict is issued")
    met = report.get("all_directions_have_cross_case") is True
    reason = None
    if not met:
        without = list(report.get("directions_without_cross_case") or ())
        counts = {direction: (report.get("by_direction", {}).get(direction, {})
                              .get("cross_case_count"))
                  for direction in CHAIN_DIRECTIONS}
        reason = ("no certified chain crossed a case boundary for "
                  f"{without or list(CHAIN_DIRECTIONS)}; per-direction "
                  f"cross-case counts: {counts}")
    return _item("cross_case_chains", measured=True, met=met, evidence=evidence,
                 reason=reason)


def _feedback_changes_next_input(receipts: Mapping, *,
                                 limits: list[dict]) -> dict:
    if not receipts.get("available"):
        reason = receipts.get("reason") or "the run has no receipts"
        return _item("feedback_changes_next_input", measured=False, met=None,
                     evidence=None,
                     reason=f"per-case feedback cannot be read: {reason}")
    if receipts.get("truncated"):
        reason = ("the receipt table was truncated by max_case_ids, so the "
                  "feedback sequence is a lower bound")
        _limit(limits, "feedback_changes_next_input", reason)
        return _item("feedback_changes_next_input", measured=False, met=None,
                     evidence=None, reason=reason)
    rows = receipts.get("rows") or []
    feedback_indexes = []
    deferred_indexes = []
    for row in rows:
        gains = row.get("interaction_source_gains") or {}
        features = row.get("interaction_new_features") or []
        weights = row.get("closed_loop_source_weights") or {}
        if not (gains or features or weights):
            continue
        if row.get("interaction_deferred") is True:
            # Batch feedback that is still deferred was not ingested before the
            # next case, so it cannot have changed that case's input.
            deferred_indexes.append(row["receipt_index"])
            continue
        feedback_indexes.append(row["receipt_index"])
    evidence = {
        "receipt_count": receipts.get("count"),
        "selection_reasons": receipts.get("selection_reasons"),
        "feedback_case_indexes": feedback_indexes,
        "deferred_feedback_case_indexes": deferred_indexes,
        "feedback_signal_definition": (
            "a receipt whose interaction_source_gains / "
            "interaction_new_features / closed_loop_source_weights is non-empty "
            "and whose interaction_deferred is not true (deferred batch feedback "
            "was not ingested before the next case and is reported separately)"),
        "first_transition": None,
        "transitions_with_change": 0,
        "transitions_checked": 0,
        "interaction_source_gains": None,
        "interaction_new_features": None,
        "closed_loop_statuses": sorted({
            str(row.get("closed_loop_status")) for row in rows
            if row.get("closed_loop_status") is not None}),
        "causal_artifact": _causal_feedback_artifact(receipts, limits),
        "causal_scope": (
            "this artifact measures the recorded order (feedback ingested for "
            "case k, next case k+1 selects a different source/reason); the "
            "interventional proof that the gain itself caused the change is "
            "the separate P4 branch artifact"),
    }
    if not feedback_indexes:
        if deferred_indexes:
            reason = (f"{len(deferred_indexes)} receipt(s) record deferred batch "
                      "feedback (interaction_deferred true), which was not "
                      "ingested before the next case; no ingested feedback can "
                      "be shown to change an input from this artifact")
        else:
            reason = ("no receipt records interaction feedback "
                      "(interaction_source_gains/new_features/"
                      "closed_loop_source_weights), so no feedback-driven input "
                      "change can be shown from this artifact")
        return _item("feedback_changes_next_input", measured=False, met=None,
                     evidence=evidence, reason=reason)
    by_index = {row["receipt_index"]: row for row in rows}
    for index in feedback_indexes:
        following = by_index.get(index + 1)
        if following is None:
            continue
        source_row = by_index[index]
        evidence["transitions_checked"] += 1
        before_reason = source_row.get("source_selection_reason")
        after_reason = following.get("source_selection_reason")
        before_sources = source_row.get("applied_source_ids")
        after_sources = following.get("applied_source_ids")
        changed = (before_reason != after_reason
                   or before_sources != after_sources)
        transition = {
            "feedback_case_index": index,
            "feedback_case_id": source_row.get("case_id"),
            "next_case_index": following["receipt_index"],
            "next_case_id": following.get("case_id"),
            "source_selection_reason_before": before_reason,
            "source_selection_reason_after": after_reason,
            "applied_source_ids_before": before_sources,
            "applied_source_ids_after": after_sources,
            "selection_changed": changed}
        if changed:
            evidence["transitions_with_change"] += 1
        if evidence["first_transition"] is None:
            evidence["first_transition"] = transition
            evidence["interaction_source_gains"] = source_row.get(
                "interaction_source_gains")
            evidence["interaction_new_features"] = source_row.get(
                "interaction_new_features")
    met = evidence["transitions_with_change"] > 0
    reason = None
    if not met:
        if evidence["transitions_checked"] == 0:
            reason = ("the feedback record is the last receipt, so no following "
                      "input exists inside this artifact")
        else:
            reason = ("the case after a recorded feedback kept the same source "
                      "selection and the same selection reason; feedback did not "
                      "change the next input in this artifact")
    return _item("feedback_changes_next_input", measured=True, met=met,
                 evidence=evidence, reason=reason)


def _causal_feedback_artifact(receipts: Mapping, limits: list[dict]) -> dict:
    """The P4 interventional A/B artifact, when it sits next to the run."""
    section = {"path": FEEDBACK_CAUSAL_ARTIFACT, "available": False,
               "reason": None, "branches": None, "same_prefix": None}
    entries = receipts.get("rows") or []
    if not entries:
        section["reason"] = "the run has no receipts to locate the artifact from"
        return section
    candidates = []
    run_dir = receipts.get("run_dir")
    if isinstance(run_dir, str) and run_dir:
        candidates.append(Path(run_dir).resolve().parent
                          / Path(FEEDBACK_CAUSAL_ARTIFACT).name)
    candidates.append(Path(FEEDBACK_CAUSAL_ARTIFACT))
    for candidate in candidates:
        if not candidate.is_file():
            continue
        document = _read_json_object(candidate)
        if document is None:
            section["reason"] = f"{candidate} is not a JSON object"
            return section
        branches = document.get("branches")
        if not isinstance(branches, Mapping):
            section["reason"] = f"{candidate} has no branches document"
            return section
        section["path"] = str(candidate)
        section["available"] = True
        section["branches"] = {
            name: {"case17_applied_source_ids": row.get("case17_applied_source_ids"),
                   "selected_source": row.get("selected_source"),
                   "case15_gain": row.get("case15_gain")}
            for name, row in branches.items() if isinstance(row, Mapping)}
        section["reason"] = None
        return section
    section["reason"] = ("the P4 interventional feedback artifact is not "
                         "present next to this run; the correlation recorded in "
                         "the receipts is reported instead")
    _limit(limits, "feedback_changes_next_input.causality", section["reason"])
    return section


def _finding_stops_and_replays(directory: Path, report: Mapping,
                               receipts: Mapping, plan: Mapping,
                               cases: Mapping | None, compare: Mapping | None,
                               limits: list[dict]) -> dict:
    """The stop point, the saved prefix, and a *separate-run* reproduction.

    A run's own ``minimal_replay.json`` is the declared replay *input*, not
    proof that a fresh harness reproduced the finding, so it is reported as
    ``declared_replay_input`` and never satisfies the reproduction half by
    itself.  The reproduction is measured from a comparison run directory whose
    own receipts record the same finding on the same ``case_id`` (and whose
    identity differs from this run's).
    """
    if not receipts.get("available"):
        reason = receipts.get("reason") or "the run has no receipts"
        return _item("finding_stops_and_replays", measured=False, met=None,
                     evidence=None,
                     reason=f"no finding can be located: {reason}")
    if receipts.get("truncated"):
        reason = ("the receipt table was truncated by max_case_ids, so a finding "
                  "after the bound cannot be ruled out")
        _limit(limits, "finding_stops_and_replays", reason)
        return _item("finding_stops_and_replays", measured=False, met=None,
                     evidence=None, reason=reason)
    finding_rows = receipts.get("finding_rows") or []
    if not finding_rows:
        run_status = report.get("session_status")
        return _item(
            "finding_stops_and_replays", measured=False, met=None,
            evidence={"report_session_status": run_status,
                      "report_statuses": report.get("statuses"),
                      "receipt_statuses": receipts.get("statuses"),
                      "finding_rows": []},
            reason=("no finding/dut_violation receipt exists in this artifact "
                    f"(report session_status={run_status!r}); this criterion "
                    "requires the controlled-fault run "
                    f"{CONTROLLED_FAULT_RUN} or a run of its own finding"))
    first = finding_rows[0]
    finding_index = first["receipt_index"]
    rows = receipts.get("rows") or []
    after = [row["receipt_index"] for row in rows
             if row["receipt_index"] > finding_index]
    lookup = (cases or {}).get("case_index_by_id") or {}
    case_index = lookup.get(first["case_id"])
    trace_after = sorted(case_id for case_id, index in lookup.items()
                         if isinstance(index, int) and isinstance(case_index, int)
                         and index > case_index)
    plan_ids = [case_id for case_id in (plan.get("case_ids") or ())
                if isinstance(case_id, str)]
    executed_ids = [row.get("case_id") for row in rows
                    if isinstance(row.get("case_id"), str)]
    if plan_ids and executed_ids:
        prefix_matches = plan_ids[-len(executed_ids):] == executed_ids
        plan_leading = plan_ids[:-len(executed_ids)]
    else:
        prefix_matches = False
        plan_leading = []
    saved_prefix = {
        "plan_available": bool(plan.get("available")),
        "plan_cases": plan.get("case_count"),
        "plan_case_ids": plan.get("case_ids"),
        "plan_case_ids_sample": plan.get("case_ids_sample"),
        "plan_last_case_id": plan_ids[-1] if plan_ids else None,
        "plan_leading_case_ids": plan_leading,
        "prefix_matches_executed_cases": prefix_matches,
        "prefix_rule": ("the plan's last N case ids must equal the N executed "
                        "receipt case ids, so a declared plan/bootstrap prefix "
                        "is allowed but a missing or reordered case is not"),
        "executed_case_ids": executed_ids,
        "terminal_failure": plan.get("terminal_failure"),
        "manifest_sha256": first.get("manifest_sha256"),
    }
    declared_input = _in_run_replay_artifact(directory, first)
    compare_section = _compare_finding(compare, first)
    compare_ok = (compare_section.get("available") is True
                  and compare_section.get("same_case_id") is True
                  and compare_section.get("same_violations") is True
                  and compare_section.get("different_run") is True)
    fresh_replay = {
        "measured": compare_section.get("available") is True,
        "met": (compare_ok if compare_section.get("available") is True else None),
        "declared_replay_input": declared_input,
        "compare_run": compare_section,
        "reproduction_rule": (
            "only a comparison run directory whose own receipts record the same "
            "finding id on the same case_id, under a different run identity, "
            "counts as a fresh-harness reproduction; the in-run replay artifact "
            "is the declared input a replay consumes and is never proof"),
        "reason": None}
    if not fresh_replay["measured"]:
        if compare is not None:
            fresh_replay["reason"] = (
                "the comparison run cannot show a fresh-harness reproduction: "
                + str(compare_section.get("reason")
                      or "its receipts carry no matching finding"))
        else:
            fresh_replay["reason"] = (
                "no comparison run was supplied, so the fresh-harness "
                "reproduction is unmeasured; the in-run replay artifact is only "
                "the declared replay input. Pass --compare-run with the "
                "reproduced run directory (a real RTL replay is out of scope "
                "for this software gate)")
        _limit(limits, "finding_stops_and_replays.fresh_replay",
               fresh_replay["reason"])
    evidence = {
        "report_session_status": report.get("session_status"),
        "report_statuses": report.get("statuses"),
        "finding_rows": finding_rows,
        "finding_case_ids": [row.get("case_id") for row in finding_rows],
        "finding_case_indexes": ([case_index] if case_index is not None else []),
        "first_finding_receipt_index": finding_index,
        "receipts_after_finding": len(after),
        "receipts_after_finding_indexes": _clip(after),
        "trace_case_indexes_after_finding": _clip(trace_after),
        "saved_prefix": saved_prefix,
        "fresh_replay": fresh_replay,
    }
    problems: list[str] = []
    if after:
        problems.append(f"the session accepted another case after the finding "
                        f"(receipt indexes {_clip(after)})")
    if trace_after:
        problems.append("the trace carries events attributed to a case index "
                        f"after the finding at {case_index}: {_clip(trace_after)}")
    if not saved_prefix["plan_available"]:
        problems.append(f"the saved prefix ({PLAN_NAME}) is missing")
    elif not prefix_matches:
        problems.append("the saved prefix does not end in the executed case "
                        "sequence")
    if fresh_replay["measured"] and fresh_replay["met"] is not True:
        problems.append("the comparison run does not record the same finding on "
                        "the same case_id")
    if not fresh_replay["measured"]:
        problems.append(fresh_replay["reason"])
    met = not problems
    reason = "; ".join(problems) if problems else None
    return _item("finding_stops_and_replays", measured=True, met=met,
                 evidence=evidence, reason=reason)


def _in_run_replay_artifact(directory: Path, finding: Mapping) -> dict:
    section = {"name": REPLAY_ARTIFACT_NAME, "available": False, "reason": None,
               "case_id": None, "detected_by": None, "same_case_id": None,
               "same_finding": None, "findings": []}
    document = _read_json_object(directory / REPLAY_ARTIFACT_NAME)
    if document is None:
        section["reason"] = (f"{directory / REPLAY_ARTIFACT_NAME} is missing or "
                             "not a JSON object")
        return section
    findings = document.get("findings")
    if not isinstance(findings, list):
        section["reason"] = "the in-run replay artifact declares no findings list"
        return section
    section["available"] = True
    section["findings"] = _clip([dict(row) for row in findings
                                 if isinstance(row, Mapping)])
    for row in findings:
        if not isinstance(row, Mapping):
            continue
        section["case_id"] = row.get("case_id")
        section["detected_by"] = row.get("detected_by")
        break
    violations = list(finding.get("violations") or ())
    section["same_case_id"] = section["case_id"] == finding.get("case_id")
    section["same_finding"] = (section["detected_by"] in violations
                               if violations else None)
    return section


def _compare_finding(compare: Mapping | None, finding: Mapping) -> dict:
    section = {"available": False, "reason": None, "run_dir": None,
               "same_case_id": None, "same_violations": None,
               "different_run": None, "run_identity_sha256": None,
               "finding_run_identity_sha256": None,
               "run_statuses": None, "finding_case_ids": None}
    if compare is None:
        section["reason"] = "no comparison run was supplied"
        return section
    compared = compare.get("run_dir")
    section["run_dir"] = compared
    section["run_identity_sha256"] = compare.get("run_identity_sha256")
    section["finding_run_identity_sha256"] = compare.get(
        "finding_run_identity_sha256")
    section["different_run"] = compare.get("different_run")
    if compare.get("different_run") is False:
        section["reason"] = ("the comparison run directory is the finding run "
                             "itself, so it cannot reproduce anything")
        return section
    receipts = compare.get("receipts")
    if not isinstance(receipts, Mapping) or not receipts.get("available"):
        section["reason"] = (receipts or {}).get("reason") or (
            "the comparison run has no readable receipts")
        return section
    if receipts.get("truncated"):
        section["reason"] = ("the comparison run's receipt table was truncated "
                             "by max_case_ids")
        return section
    rows = receipts.get("finding_rows") or []
    section["run_statuses"] = receipts.get("statuses")
    section["finding_case_ids"] = [row.get("case_id") for row in rows]
    section["available"] = True
    section["same_case_id"] = any(row.get("case_id") == finding.get("case_id")
                                  for row in rows)
    expected = set(finding.get("violations") or ())
    section["same_violations"] = any(
        expected and expected.issubset(set(row.get("violations") or ()))
        for row in rows)
    if not rows:
        section["reason"] = "the comparison run records no finding"
    return section


# ---------------------------------------------------------------------------
# chunk split invariance
# ---------------------------------------------------------------------------


def _chunk_payload(plan: Mapping, directory: Path,
                   receipts: Mapping) -> tuple[bytes | None, str | None, str | None]:
    """(raw genome bytes, source label, reason) for the chunk-split check."""
    template = _plan_template(directory)
    if template is not None:
        try:
            from .genome import GenomeCodec
        except ImportError as exc:  # pragma: no cover - import topology change
            return None, None, f"the genome codec is unavailable: {exc}"
        try:
            raw = GenomeCodec.encode(GenomeCodec.decode(_canonical_bytes(template)))
        except (ValueError, TypeError, KeyError) as exc:
            return None, None, (f"{PLAN_NAME} template is not a decodable "
                                f"genome document: {exc}")
        return raw, f"{PLAN_NAME}:template", None
    for entry in sorted((directory / "corpus").glob("entry_*.json")):
        document = _read_json_object(entry)
        if document is None:
            continue
        payload = (document.get("entry") or {}).get("inputs") \
            if isinstance(document.get("entry"), Mapping) else None
        if (not isinstance(payload, list) or not payload
                or any(type(value) is not int or not 0 <= value <= 255
                       for value in payload)):
            continue
        raw = bytes(payload)
        try:
            from .genome import GenomeCodec
            GenomeCodec.decode(raw)
        except (ValueError, TypeError, KeyError, ImportError):
            continue
        return raw, f"corpus/{entry.name}:entry.inputs", None
    for row in receipts.get("rows") or ():
        source = row.get("online_raw_records_hex")
        if not isinstance(source, list) or not source:
            continue
        raw = b"".join(part for part in
                       (_payload_bytes(item) for item in source) if part)
        if not raw:
            continue
        try:
            from .genome import GenomeCodec
            GenomeCodec.decode(raw)
        except (ValueError, TypeError, KeyError, ImportError):
            continue
        return raw, "receipts.jsonl:online_raw_records_hex", None
    return None, None, ("no normalized genome payload is available: the run has "
                        f"no {PLAN_NAME} template, no decodable corpus entry and "
                        "no receipt raw record that decodes as a genome")


def _plan_template(directory: Path) -> dict | None:
    document = _read_json_object(directory / PLAN_NAME)
    if document is None:
        return None
    template = document.get("template")
    return template if isinstance(template, dict) else None


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _split_sizes(pattern: str, total: int) -> tuple[int, ...]:
    if pattern == "single_chunk":
        return (total,)
    if pattern == "one_byte_chunks":
        return (1,)
    if pattern == "irregular_7_1_29_2_13":
        return (7, 1, 29, 2, 13)
    if pattern == "fixed_3_5_11":
        return (3, 5, 11)
    if pattern == "half_and_halves":
        half = max(1, total // 2)
        return (half, max(1, half // 2))
    raise ValueError(f"unknown split pattern {pattern!r}")


def _chunk_split_invariance(plan: Mapping, directory: Path, receipts: Mapping,
                            trace: Mapping, limits: list[dict]) -> dict:
    rtl_level = {
        "measured": False, "met": None,
        "existing_real_test": CHUNK_RTL_TEST,
        "requires": CHUNK_RTL_REQUIRES,
        "reason": ("the normalized event stream and final state of a real RTL "
                   "session under different RFuzz chunk splits are owned by "
                   f"{CHUNK_RTL_TEST}, which needs {CHUNK_RTL_REQUIRES}; a saved "
                   "run carries no chunk-split trace pair, and this software "
                   "gate never runs RTL, so this half stays null")}
    _limit(limits, "chunk_split_invariance.rtl_event_level", rtl_level["reason"])
    if not trace.get("available"):
        reason = ("the run has no streamable trace, so no chunk-split verdict is "
                  "issued for it")
        _limit(limits, "chunk_split_invariance", reason)
        return _item("chunk_split_invariance", measured=False, met=None,
                     evidence={"normalized_input_level": None,
                               "rtl_event_level": rtl_level},
                     reason=reason)
    raw, source, reason = _chunk_payload(plan, directory, receipts)
    if raw is None:
        normalized = {"measured": False, "met": None, "raw_payload_source": None,
                      "payload_bytes": None, "split_patterns_checked": 0,
                      "identical": None, "normalized_sha256": None,
                      "failures": []}
        _limit(limits, "chunk_split_invariance", reason)
        return _item("chunk_split_invariance", measured=False, met=None,
                     evidence={"normalized_input_level": normalized,
                               "rtl_event_level": rtl_level},
                     reason=reason)
    try:
        from .genome import ChunkAssembler, GenomeCodec
    except ImportError as exc:  # pragma: no cover - import topology change
        reason = f"the chunk assembler is unavailable: {exc}"
        _limit(limits, "chunk_split_invariance", reason)
        return _item("chunk_split_invariance", measured=False, met=None,
                     evidence={"normalized_input_level": None,
                               "rtl_event_level": rtl_level},
                     reason=reason)
    digest = hashlib.sha256(raw).hexdigest()
    normalized_sha256 = None
    identical = True
    checked = 0
    failures: list[dict] = []
    for pattern in SPLIT_PATTERNS:
        sizes = _split_sizes(pattern, len(raw))
        try:
            assembly = ChunkAssembler(len(raw), digest)
            offset = index = 0
            while offset < len(raw):
                size = min(sizes[index % len(sizes)], len(raw) - offset)
                assembly.accept(offset, raw[offset:offset + size])
                offset += size
                index += 1
            genome = assembly.finish()
            encoded = GenomeCodec.encode(genome)
        except (ValueError, TypeError, KeyError) as exc:
            identical = False
            failures.append({"pattern": pattern, "error": f"{type(exc).__name__}: {exc}"})
            continue
        checked += 1
        if encoded != raw:
            identical = False
            failures.append({"pattern": pattern,
                             "error": "normalized genome bytes differ"})
        normalized_sha256 = hashlib.sha256(encoded).hexdigest()
    normalized = {
        "measured": checked > 0, "met": (identical if checked else None),
        "raw_payload_source": source, "payload_bytes": len(raw),
        "raw_sha256": digest,
        "split_patterns": list(SPLIT_PATTERNS),
        "split_patterns_checked": checked,
        "identical": identical if checked else None,
        "normalized_sha256": normalized_sha256,
        "failures": failures,
        "semantics": ("the run's own declared genome is reassembled through the "
                      "real ChunkAssembler under different chunk splits and must "
                      "decode back to byte-identical normalized genome bytes")}
    if not normalized["measured"]:
        reason = ("no chunk split could reassemble the payload: "
                  f"{failures}")
        _limit(limits, "chunk_split_invariance", reason)
        return _item("chunk_split_invariance", measured=False, met=None,
                     evidence={"normalized_input_level": normalized,
                               "rtl_event_level": rtl_level},
                     reason=reason)
    met = identical
    reason = None
    if not met:
        reason = f"chunk splits changed the normalized genome: {failures}"
    return _item("chunk_split_invariance", measured=True, met=met,
                 evidence={"normalized_input_level": normalized,
                           "rtl_event_level": rtl_level},
                 reason=reason)


# ---------------------------------------------------------------------------
# execution identity (real receipt cache, declaration-only stub harness)
# ---------------------------------------------------------------------------


class _StubHarness:
    """A declaration-only local harness: it can only count its own steps."""

    schema_version = "p3_acceptance_stub_harness.v1"

    def __init__(self) -> None:
        self.local_ticks = 0
        self.reset_epoch = 0
        self.steps = 0
        self.testcase_id = None

    def prepare_local(self) -> None:
        return None

    def begin_case(self, testcase_id: str) -> None:
        self.testcase_id = testcase_id

    def end_case(self) -> None:
        return None

    def step_local(self, inputs: Mapping[str, int]) -> Mapping[str, int]:
        self.steps += 1
        return {"stub_step": self.steps}


def _execution_identity(cases: Mapping | None, receipts: Mapping,
                        manifest: Mapping, limits: list[dict]) -> dict:
    artifact = {
        "trace_execution_ids": (sorted(cases.get("execution_ids") or ())
                                if cases is not None else None),
        "trace_testcase_ids": (sorted(cases.get("testcase_ids") or ())
                               if cases is not None else None),
        "receipt_run_ids": receipts.get("run_id_values"),
        "receipt_manifest_sha256_values": receipts.get("manifest_sha256_values"),
        "manifest_identity_sha256": manifest.get("identity_sha256")}
    gate = {"available": False, "reason": None,
            "same_execution_id_reused_receipt": None,
            "additional_harness_steps": None,
            "other_execution_id_rejected": None,
            "rejection_reason": None,
            "other_execution_id_harness_steps": None,
            "harness_steps_total": None}
    evidence = {
        "source": ("myfuzz.scenario.runner.ScenarioRunner.execute_step receipt "
                   "cache driven by a declaration-only stub harness (no RTL "
                   "process, no factory)"),
        "gate": gate, **artifact}
    try:
        from .ownership import compile_ownership
        from .runner import ScenarioRunner
        harness = _StubHarness()
        runner = ScenarioRunner(sessions={"cpu": harness},
                                ownership=compile_ownership((), ()),
                                bindings=())
        runner.begin_test("p3-acceptance-execution-identity")
        execution_id = runner.execution_id
        if not isinstance(execution_id, str) or not execution_id:
            raise ValueError("the runner issued no execution identity")
        first = runner.execute_step("cpu", execution_id=execution_id,
                                    command_sequence=1, epoch=0,
                                    expected_inputs={})
        steps_after_first = harness.steps
        again = runner.execute_step("cpu", execution_id=execution_id,
                                    command_sequence=1, epoch=0,
                                    expected_inputs={})
        steps_after_again = harness.steps
        rejected = False
        rejection_reason = None
        other = f"{execution_id}-other"
        try:
            runner.execute_step("cpu", execution_id=other, command_sequence=2,
                                epoch=0, expected_inputs={})
        except ValueError as exc:
            rejected = str(exc) == STALE_EXECUTION_REASON or str(exc).startswith(
                "stale_execution")
            rejection_reason = str(exc)
        steps_after_other = harness.steps
    except Exception as exc:  # fail closed: no gate is better than a wrong one
        gate["reason"] = (f"the real runner receipt gate could not be driven: "
                          f"{type(exc).__name__}: {exc}")
        _limit(limits, "execution_identity", gate["reason"])
        return _item("execution_identity", measured=False, met=None,
                     evidence=evidence, reason=gate["reason"])
    gate.update({
        "available": True,
        "execution_id": execution_id,
        "same_execution_id_reused_receipt": bool(again == first),
        "additional_harness_steps": steps_after_again - steps_after_first,
        "other_execution_id_rejected": rejected,
        "rejection_reason": rejection_reason,
        "other_execution_id_harness_steps": steps_after_other - steps_after_again,
        "harness_steps_total": harness.steps,
        "harness_step_count_bound": (
            "the stub harness can only count steps; it cannot build, start or "
            "tick any RTL"),
        "artifact_identities": {
            "trace_execution_id_count": (
                None if cases is None else len(artifact["trace_execution_ids"] or ())),
            "receipt_run_id_count": len(artifact["receipt_run_ids"] or ()),
            "receipt_manifest_identity_count": len(
                artifact["receipt_manifest_sha256_values"] or ()),
            "receipts_bind_one_manifest": bool(
                artifact["receipt_manifest_sha256_values"]
                and manifest.get("identity_sha256")
                and artifact["receipt_manifest_sha256_values"]
                == [manifest["identity_sha256"]])}})
    problems = []
    if not gate["same_execution_id_reused_receipt"]:
        problems.append("a retried STEP with the same execution_id did not "
                        "return the cached receipt")
    if gate["additional_harness_steps"] != 0:
        problems.append("a retried STEP re-executed the harness")
    if not gate["other_execution_id_rejected"]:
        problems.append("a STEP carrying a different execution_id was accepted")
    if gate["other_execution_id_harness_steps"] != 0:
        problems.append("a STEP carrying a different execution_id reached the "
                        "harness")
    # The saved artifact must itself carry one execution identity; otherwise the
    # in-process gate proves nothing about this run.
    trace_ids = artifact["trace_execution_ids"]
    receipt_runs = artifact["receipt_run_ids"]
    artifact_measured = bool(trace_ids)
    if not artifact_measured:
        problems.append("no trace transaction carries an execution identity, so "
                        "the saved artifact cannot be bound to one execution")
        _limit(limits, "execution_identity.artifact",
               "no trace transaction carries an execution_id in this artifact")
    elif len(trace_ids) > 1:
        problems.append(f"the trace carries {len(trace_ids)} execution "
                        f"identities: {_clip(trace_ids)}")
    if len(receipt_runs) > 1:
        problems.append(f"the receipts carry {len(receipt_runs)} run ids: "
                        f"{_clip(receipt_runs)}")
    identities = artifact["receipt_manifest_sha256_values"] or []
    if len(identities) > 1:
        problems.append(f"the receipts carry {len(identities)} session manifest "
                        f"identities: {_clip(identities)}")
    met = not problems
    return _item("execution_identity", measured=artifact_measured, met=met,
                 evidence=evidence,
                 reason="; ".join(problems) if problems else None)


# ---------------------------------------------------------------------------
# gate
# ---------------------------------------------------------------------------


def _gate_item(key: str, *, measured: bool, met, value, reason: str | None,
               critical: bool = True) -> dict:
    return {"key": key, "critical": bool(critical), "measured": bool(measured),
            "met": met, "value": value, "reason": reason}


def _first_match_identity(match: object) -> dict | None:
    if not isinstance(match, Mapping):
        return None
    return {"write_event_id": match.get("write_event_id"),
            "read_event_id": match.get("read_event_id"),
            "write_case_index": match.get("write_case_index"),
            "read_case_index": match.get("read_case_index"),
            "lanes": len(match.get("lanes") or ())}


def _gate(*, manifest: Mapping, receipts: Mapping, trace: Mapping,
          items: Mapping[str, Mapping], chunk_rtl: Mapping) -> dict:
    rows = [
        _gate_item("manifest", measured=bool(manifest.get("available")),
                   met=None, value=manifest.get("identity_sha256"),
                   reason=manifest.get("reason")),
        _gate_item("receipts", measured=bool(receipts.get("available")),
                   met=None, value=receipts.get("count"),
                   reason=receipts.get("reason")),
        _gate_item("trace",
                   measured=bool(trace.get("available")
                                 and trace.get("events_ingested") is not None),
                   met=None, value=trace.get("events_ingested"),
                   reason=trace.get("reason")),
    ]
    values = {
        "store_then_load": _first_match_identity(
            (items["store_then_load"]["evidence"] or {}).get(
                "first_cross_case_match")),
        "cross_case_chains": {
            "cross_case_count": (items["cross_case_chains"]["evidence"] or {}
                                 ).get("cross_case_count"),
            "directions_without_cross_case": (
                items["cross_case_chains"]["evidence"] or {}
            ).get("directions_without_cross_case")},
        "chunk_split_invariance": (
            (items["chunk_split_invariance"]["evidence"] or {})
            .get("normalized_input_level") or {}).get("identical"),
    }
    for key in ("single_initialization", "store_then_load", "cross_case_chains",
                "feedback_changes_next_input", "finding_stops_and_replays",
                "chunk_split_invariance", "execution_identity"):
        item = items[key]
        rows.append(_gate_item(
            key, measured=bool(item["measured"]), met=item["met"],
            value=values.get(key), reason=item.get("reason")))
    rows.append(_gate_item(
        "chunk_split_invariance.rtl_event_level",
        measured=bool(chunk_rtl.get("measured")), met=chunk_rtl.get("met"),
        value=None, reason=chunk_rtl.get("reason"), critical=False))
    missing = [row["key"] for row in rows
               if row["critical"] and not row["measured"]]
    unmet = [row["key"] for row in rows
             if row["critical"] and row["measured"] and row["met"] is False]
    informational = [row["key"] for row in rows
                     if not row["critical"] and not row["measured"]]
    ready = not missing and not unmet
    if ready:
        summary = "all critical P3 keys are measured and their criteria hold"
    else:
        parts = []
        if missing:
            parts.append("missing evidence: " + ", ".join(missing))
        if unmet:
            parts.append("criteria not met: " + ", ".join(unmet))
        summary = "; ".join(parts)
    if informational:
        summary += ("; informational (non-critical, never a pass): "
                    + ", ".join(informational))
    return {"items": rows, "critical_missing": missing, "critical_unmet": unmet,
            "informational_unmeasured": informational, "ready": ready,
            "exit_code": EXIT_READY if ready else EXIT_NOT_READY,
            "summary": summary,
            "exit_code_semantics": (
                "0 = every critical key was measured and its criterion holds; "
                "2 = evidence missing (null) or a criterion is not met; the gate "
                "never reports a null key as a pass. Non-critical informational "
                "keys are listed separately and cannot turn the gate ready")}


# ---------------------------------------------------------------------------
# the report
# ---------------------------------------------------------------------------


def _run_id(run_identity: Mapping) -> str | None:
    run_id = run_identity.get("run_id")
    return run_id if isinstance(run_id, str) and run_id else None


def p3_acceptance_report(run_dir, *, compare_run=None, chain_producer=None,
                         max_gap_cases: int = DEFAULT_MAX_GAP_CASES,
                         max_pending: int = 128, max_event_gap: int = 4096,
                         require_native_receipts: bool = True,
                         ingest_batch_size: int = DEFAULT_INGEST_BATCH_SIZE,
                         verify_semantic: bool = True,
                         max_memory_lanes: int = DEFAULT_MAX_MEMORY_LANES,
                         max_case_ids: int = DEFAULT_MAX_CASE_IDS) -> dict:
    """Judge one saved run directory against the P3 acceptance condition.

    ``compare_run`` is the companion run that reproduces a finding in a fresh
    harness: when both runs record the same finding on the same ``case_id`` the
    ``finding_stops_and_replays`` criterion counts as reproduced.  Nothing here
    starts RTL, renders a harness or touches a simulator; the whole verdict is
    derived from saved artifacts plus declaration-only checks.
    """
    directory = Path(run_dir)
    if not directory.is_dir():
        raise ValueError(f"run directory does not exist: {directory}")
    limits: list[dict] = []
    for name, value in (("max_gap_cases", max_gap_cases),
                        ("max_pending", max_pending),
                        ("max_event_gap", max_event_gap),
                        ("ingest_batch_size", ingest_batch_size),
                        ("max_memory_lanes", max_memory_lanes),
                        ("max_case_ids", max_case_ids)):
        if type(value) is not int or value < 1:
            raise ValueError(f"{name} must be a positive integer")

    manifest = _manifest_section(directory, limits)
    run_identity = _run_identity_section(directory, manifest, limits)
    report = _report_section(directory, limits)
    plan = _plan_section(directory, limits)
    receipts = _receipts_section(directory, manifest, maximum=max_case_ids,
                                 limits=limits)
    receipts["run_dir"] = str(directory.resolve())

    compare_directory = None
    compare_document = None
    if compare_run is not None:
        compare_directory = Path(compare_run)
        if not compare_directory.is_dir():
            raise ValueError(f"comparison run directory does not exist: "
                             f"{compare_directory}")
        if compare_directory.resolve() == directory.resolve():
            raise ValueError("the comparison run must be a different run "
                             "directory than the run under analysis")
        compare_manifest = _manifest_section(compare_directory, limits)
        compare_identity = _run_identity_section(compare_directory,
                                                 compare_manifest, limits)
        different_run = compare_directory.resolve() != directory.resolve()
        if (different_run and run_identity.get("sha256")
                and compare_identity.get("sha256")):
            # A copied run identity is not a fresh harness session.
            different_run = (run_identity["sha256"]
                             != compare_identity["sha256"])
        compare_document = {
            "run_dir": str(compare_directory),
            "manifest": compare_manifest,
            "run_identity": compare_identity,
            "different_run": different_run,
            "run_identity_sha256": compare_identity.get("sha256"),
            "finding_run_identity_sha256": run_identity.get("sha256"),
            "receipts": _receipts_section(compare_directory, compare_manifest,
                                          maximum=max_case_ids, limits=limits)}
        compare_document["receipts"]["run_dir"] = str(compare_directory.resolve())
        if not different_run:
            _limit(limits, "compare_run",
                   "the comparison run is not a different run identity from the "
                   "run under analysis, so it cannot reproduce anything")

    observer = _TraceObserver(max_lanes=max_memory_lanes,
                              max_case_ids=max_case_ids)
    trace_reason = None
    stream = None
    try:
        stream = TraceEventStream(directory, chunk_chars=DEFAULT_CHUNK_CHARS,
                                  verify_semantic=verify_semantic)
    except (TraceUnavailable, ValueError) as exc:
        trace_reason = f"no streamable trace artifact: {exc}"
        _limit(limits, "trace", trace_reason)
    if stream is not None:
        try:
            for event in stream.events():
                observer.observe(event)
            observer.exhausted = True
        except Exception as exc:
            trace_reason = (f"the event stream was rejected before it could be "
                            f"read to the end: {type(exc).__name__}: {exc}")
            _limit(limits, "trace", trace_reason)
    trace = _trace_section(stream, trace_reason, observer)
    if trace.get("semantic_sha256_verified") is False:
        # A digest the artifact itself declares does not match the recomputed
        # one: fail closed instead of judging criteria from unauthenticated
        # events.
        trace_reason = ("the trace declares a semantic digest that does not "
                        "match the recomputed one, so no criterion is derived "
                        "from it")
        _limit(limits, "trace", trace_reason)
        trace["available"] = False
        trace["reason"] = trace_reason
        observer.exhausted = False
    cases = observer.case_report() if observer.exhausted else None
    if cases is not None:
        cases["execution_ids"] = sorted(observer.execution_ids)
        cases["testcase_ids"] = sorted(observer.testcase_ids)
    memory = observer.memory_report() if observer.exhausted else None

    items = {
        "single_initialization": _single_initialization(
            manifest, run_identity, receipts, trace, plan, cases, limits),
        "store_then_load": _store_then_load(trace, memory, limits),
        "cross_case_chains": _cross_case_chains(
            directory, trace, chain_producer=chain_producer,
            max_gap_cases=max_gap_cases, max_pending=max_pending,
            max_event_gap=max_event_gap,
            require_native_receipts=require_native_receipts,
            ingest_batch_size=ingest_batch_size,
            verify_semantic=verify_semantic, limits=limits),
        "feedback_changes_next_input": _feedback_changes_next_input(
            receipts, limits=limits),
        "finding_stops_and_replays": _finding_stops_and_replays(
            directory, report, receipts, plan, cases, compare_document, limits),
        "chunk_split_invariance": _chunk_split_invariance(plan, directory,
                                                          receipts, trace,
                                                          limits),
        "execution_identity": _execution_identity(cases, receipts, manifest,
                                                  limits),
    }
    chunk_rtl = items["chunk_split_invariance"]["evidence"]["rtl_event_level"]
    gate = _gate(manifest=manifest, receipts=receipts, trace=trace, items=items,
                 chunk_rtl=chunk_rtl)

    _limit(limits, "scope",
           "every verdict in this report is derived from the saved artifacts of "
           "this run plus declaration-only checks; this report executes no RTL, "
           "renders no harness and starts no process")
    _limit(limits, "store_then_load.identity",
           "a stored byte is joined to a later read only by the exact "
           "byte_offset/generation/version and the writer identity the frozen "
           "memory service recorded (memory_write_commit cells when the commit "
           "stream is enabled, otherwise the committing transaction key); the "
           "read byte value must match as well")
    _limit(limits, "execution_identity.scope",
           "the execution-identity gate drives the real ScenarioRunner receipt "
           "cache with a declaration-only stub harness in this process; it "
           "proves the receipt cache refuses another execution_id, not that any "
           "particular saved receipt came from that harness")

    return {
        "schema_version": SCHEMA_VERSION,
        "run_dir": str(directory),
        "run_id": _run_id(run_identity),
        "run_identity_sha256": run_identity.get("sha256"),
        "compare_run_dir": (None if compare_directory is None
                            else str(compare_directory)),
        "compare_run": (None if compare_document is None else {
            "run_dir": compare_document["run_dir"],
            "manifest_available": compare_document["manifest"].get("available"),
            "manifest_identity_sha256": compare_document["manifest"].get(
                "identity_sha256"),
            "different_run": compare_document.get("different_run"),
            "run_identity_sha256": compare_document.get("run_identity_sha256"),
            "receipt_count": compare_document["receipts"].get("count"),
            "receipt_statuses": compare_document["receipts"].get("statuses"),
            "finding_case_ids": [row.get("case_id") for row in
                                 compare_document["receipts"].get("finding_rows")
                                 or ()]}),
        "bounds": {
            "cross_case_chains": {"max_gap_cases": max_gap_cases,
                                  "max_pending": max_pending,
                                  "max_event_gap": max_event_gap,
                                  "require_native_receipts": require_native_receipts,
                                  "ingest_batch_size": ingest_batch_size,
                                  "verify_semantic": verify_semantic},
            "trace_observer": {"max_memory_lanes": max_memory_lanes,
                               "max_case_ids": max_case_ids,
                               "max_match_samples": DEFAULT_MAX_MATCH_SAMPLES,
                               "max_evidence_rows": DEFAULT_MAX_LIMIT_ROWS},
            "chunk_split": {"split_patterns": list(SPLIT_PATTERNS),
                            "chunk_chars": DEFAULT_CHUNK_CHARS}},
        "engine": {
            "p3_acceptance": _module_identity("myfuzz.scenario.p3_acceptance"),
            "acceptance_metrics": _module_identity(
                "myfuzz.scenario.acceptance_metrics"),
            "cross_case_chains": _module_identity(
                "myfuzz.scenario.cross_case_chains"),
            "chain_certificates": _module_identity(
                "myfuzz.scenario.chain_certificates"),
            "genome": _module_identity("myfuzz.scenario.genome"),
            "runner": _module_identity("myfuzz.scenario.runner"),
            "memory_service": _module_identity("myfuzz.scenario.memory_service")},
        "manifest": manifest,
        "run_identity": run_identity,
        "report": report,
        "plan": plan,
        "receipts": {key: value for key, value in receipts.items()
                     if key != "rows"},
        "trace": trace,
        "cases": (None if cases is None
                  else {key: value for key, value in cases.items()
                        if key != "case_index_by_id"}),
        "memory": memory,
        "single_initialization": items["single_initialization"],
        "store_then_load": items["store_then_load"],
        "cross_case_chains": items["cross_case_chains"],
        "feedback_changes_next_input": items["feedback_changes_next_input"],
        "finding_stops_and_replays": items["finding_stops_and_replays"],
        "chunk_split_invariance": items["chunk_split_invariance"],
        "execution_identity": items["execution_identity"],
        "gate": gate,
        "limits": limits,
    }


# ---------------------------------------------------------------------------
# markdown
# ---------------------------------------------------------------------------


def _cell(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return f"{value:.6g}"
    return str(value)


def _note(value: object) -> str:
    """A dash for an empty note, so a 'null' cannot be read as evidence."""
    return "—" if value is None else _cell(value)


def _verdict(item: Mapping) -> str:
    if not item.get("measured"):
        return "null (not measured)"
    if item.get("met") is True:
        return "met"
    if item.get("met") is False:
        return "not met"
    return "measured (no criterion)"


def render_markdown(report: Mapping) -> str:
    """Render one P3 acceptance report, evidence boundary first."""
    lines: list[str] = []
    add = lines.append
    add("# P3 acceptance report")
    add("")
    add(f"- schema: `{report.get('schema_version')}`")
    add(f"- run directory: `{report.get('run_dir')}`")
    if report.get("run_id") is not None:
        add(f"- run id: `{report.get('run_id')}`")
    if report.get("compare_run_dir") is not None:
        add(f"- comparison run directory: `{report.get('compare_run_dir')}`")
    gate = report.get("gate") or {}
    add(f"- gate: **exit code {_cell(gate.get('exit_code'))}** -- "
        f"{_cell(gate.get('summary'))}")
    add("")

    items = list(gate.get("items") or ())
    measured = [row for row in items
                if row.get("measured") and row.get("key") not in (
                    "single_initialization", "store_then_load",
                    "cross_case_chains", "feedback_changes_next_input",
                    "finding_stops_and_replays", "chunk_split_invariance",
                    "execution_identity")]
    add("## 证据边界 (evidence boundary)")
    add("")
    add("### 实测 (measured)")
    add("")
    if measured:
        add("| key | value | note |")
        add("|---|---|---|")
        for row in measured:
            add(f"| `{row['key']}` | `{_cell(row.get('value'))}` | "
                f"{_note(row.get('reason'))} |")
    else:
        add("none: no artifact-level key could be measured")
    add("")
    add("### null / unknown 与原因 (null, unknown, and why)")
    add("")
    unmeasured = [row for row in items if not row.get("measured")]
    if unmeasured:
        for row in unmeasured:
            add(f"- `{row['key']}` = null -- {_cell(row.get('reason'))}")
    else:
        add("- none: every gate key carries a measured value")
    add("")
    add("### 限制 (limits)")
    add("")
    for limit in report.get("limits") or ():
        add(f"- `{_cell(limit.get('quantity'))}`: {_cell(limit.get('reason'))}")
    add("")
    add("### 判据 (criteria)")
    add("")
    for key in ("single_initialization", "store_then_load", "cross_case_chains",
                "feedback_changes_next_input", "finding_stops_and_replays",
                "chunk_split_invariance", "execution_identity"):
        item = report.get(key) or {}
        reason = item.get("reason")
        add(f"- `{key}` = **{_verdict(item)}**"
            + ("" if reason is None else f" -- {_cell(reason)}"))
    add("")

    add("## 逐条验收 (per-criterion)")
    add("")

    initialization = report.get("single_initialization") or {}
    add("### 1. 单次初始化、逐例独立 ID、无 harness 重建 (single initialization)")
    add("")
    evidence = initialization.get("evidence") or {}
    add(f"- verdict: **{_verdict(initialization)}**")
    add(f"- session manifest count: "
        f"`{_cell(evidence.get('session_manifest_count'))}`; components: "
        f"`{_cell(evidence.get('components'))}`; boot markers: "
        f"measured `{_cell((evidence.get('boot_markers') or {}).get('measured'))}`"
        f" / met `{_cell((evidence.get('boot_markers') or {}).get('met'))}`")
    add(f"- cases: `{_cell(evidence.get('case_count'))}` "
        f"(distinct receipt case ids "
        f"`{_cell(evidence.get('distinct_case_count'))}`)")
    add(f"- case indexes: `{_cell(evidence.get('case_indexes'))}` "
        f"(monotone `{_cell(evidence.get('case_index_monotone'))}`, contiguous "
        f"`{_cell(evidence.get('case_index_contiguous'))}`)")
    initialization_evidence = evidence.get("initialization") or {}
    add(f"- initial images: "
        f"`{_cell(initialization_evidence.get('initial_image_count'))}` "
        f"(after the first case: "
        f"`{_cell(initialization_evidence.get('initial_image_after_first_case'))}`); "
        f"native startup markers: "
        f"`{_cell(initialization_evidence.get('native_startup_count'))}`; "
        f"reset epochs: `{_cell(evidence.get('reset_epochs'))}`")
    add(f"- receipts bind the manifest identity: "
        f"`{_cell(evidence.get('receipts_bind_manifest_identity'))}`; "
        f"unattributed trace case ids: "
        f"`{_cell(evidence.get('trace_case_ids_without_receipt'))}`; executed "
        f"cases without trace events: "
        f"`{_cell(evidence.get('receipt_case_ids_without_trace_events'))}`; "
        f"plan/bootstrap prefix: "
        f"`{_cell(evidence.get('plan_leading_case_ids'))}`")
    add(f"- single-initialization contradictions: "
        f"`{_cell(evidence.get('rebuild_evidence'))}`")
    add(f"- reason: {_cell(initialization.get('reason'))}")
    add("")

    store = report.get("store_then_load") or {}
    add("### 2. 跨例 Store M[A]=X → Load M[A] (store then load)")
    add("")
    memory = store.get("evidence") or {}
    add(f"- verdict: **{_verdict(store)}**")
    add(f"- event kinds: `{_cell(memory.get('event_kinds'))}`")
    add(f"- exact lane matches: `{_cell(memory.get('lane_matches'))}` "
        f"(cross-case `{_cell(memory.get('cross_case_matches'))}`, same-case "
        f"`{_cell(memory.get('same_case_matches'))}`, value conflicts "
        f"`{_cell(memory.get('value_conflicts'))}`)")
    match = memory.get("first_cross_case_match")
    if isinstance(match, Mapping):
        add(f"- first cross-case match: write event "
            f"`{_cell(match.get('write_event_id'))}` (case "
            f"`{_cell(match.get('write_case_index'))}` "
            f"`{_cell(match.get('write_case_id'))}`) -> read event "
            f"`{_cell(match.get('read_event_id'))}` (case "
            f"`{_cell(match.get('read_case_index'))}` "
            f"`{_cell(match.get('read_case_id'))}`) at address "
            f"`{_cell(match.get('address'))}`")
        add("")
        add("| lane | byte_offset | version | writer_event_id | committed | read |")
        add("|---|---|---|---|---|---|")
        for lane in match.get("lanes") or ():
            add(f"| {_cell(lane.get('lane'))} | {_cell(lane.get('byte_offset'))} | "
                f"`{_cell(lane.get('version'))}` | "
                f"`{_cell(lane.get('writer_event_id'))}` | "
                f"{_cell(lane.get('value'))} | {_cell(lane.get('read_value'))} |")
    else:
        add("- first cross-case match: null")
    byte_enable = memory.get("byte_enable") or {}
    selectivity = byte_enable.get("lane_selectivity") or {}
    add(f"- byte_enable: partial writes "
        f"`{_cell(byte_enable.get('partial_byte_enable_writes'))}`, lane "
        f"selectivity measured `{_cell(selectivity.get('measured'))}` / met "
        f"`{_cell(selectivity.get('met'))}`, non-enabled lane adoptions "
        f"`{_cell(byte_enable.get('non_enabled_lane_adoptions'))}`")
    reuse = memory.get("first_unknown_read_reuse") or {}
    add(f"- first unknown read reuse: measured `{_cell(reuse.get('measured'))}` / "
        f"met `{_cell(reuse.get('met'))}`, materialized "
        f"`{_cell(reuse.get('materialized_lanes'))}`, reused "
        f"`{_cell(reuse.get('reused_lanes'))}`, rematerialized "
        f"`{_cell(reuse.get('rematerialized_lanes'))}`")
    parts = memory.get("parts") or {}
    if parts:
        add("")
        add("| part | measured | met | note |")
        add("|---|---|---|---|")
        for name, part in sorted(parts.items()):
            add(f"| `{name}` | `{_cell(part.get('measured'))}` | "
                f"`{_cell(part.get('met'))}` | {_note(part.get('reason'))} |")
    add(f"- reason: {_cell(store.get('reason'))}")
    add("")

    chains = report.get("cross_case_chains") or {}
    add("### 3. 跨例认证链 (cross-case chains)")
    add("")
    chain_evidence = chains.get("evidence") or {}
    add(f"- verdict: **{_verdict(chains)}**")
    add(f"- certified `{_cell(chain_evidence.get('certified_count'))}`, "
        f"cross-case `{_cell(chain_evidence.get('cross_case_count'))}`, "
        f"same-case `{_cell(chain_evidence.get('same_case_count'))}`, "
        f"incomplete `{_cell(chain_evidence.get('incomplete_count'))}`")
    by_direction = chain_evidence.get("by_direction") or {}
    if by_direction:
        add("")
        add("| direction | certified | cross-case | same-case | case gap p50 | "
            "representative source → endpoint |")
        add("|---|---:|---:|---:|---:|---|")
        for direction, row in sorted(by_direction.items()):
            representative = row.get("representative_cross_case_chain") or {}
            add(f"| `{direction}` | `{_cell(row.get('certified_count'))}` | "
                f"`{_cell(row.get('cross_case_count'))}` | "
                f"`{_cell(row.get('same_case_count'))}` | "
                f"`{_cell((row.get('case_gap') or {}).get('p50'))}` | "
                f"`{_cell(representative.get('source_case_index'))}` → "
                f"`{_cell(representative.get('endpoint_case_index'))}` |")
    add(f"- directions without a cross-case chain: "
        f"`{_cell(chain_evidence.get('directions_without_cross_case'))}`")
    add(f"- reason: {_cell(chains.get('reason'))}")
    add("")

    feedback = report.get("feedback_changes_next_input") or {}
    add("### 4. 逐例反馈改变下一例输入 (feedback changes the next input)")
    add("")
    feedback_evidence = feedback.get("evidence") or {}
    add(f"- verdict: **{_verdict(feedback)}**")
    add(f"- ingested feedback receipts: "
        f"`{_cell(feedback_evidence.get('feedback_case_indexes'))}` (deferred "
        f"batch feedback excluded: "
        f"`{_cell(feedback_evidence.get('deferred_feedback_case_indexes'))}`); "
        f"selection reasons: "
        f"`{_cell(feedback_evidence.get('selection_reasons'))}`")
    transition = feedback_evidence.get("first_transition")
    if isinstance(transition, Mapping):
        add(f"- first transition: case "
            f"`{_cell(transition.get('feedback_case_index'))}` → "
            f"`{_cell(transition.get('next_case_index'))}`, selection changed "
            f"`{_cell(transition.get('selection_changed'))}`")
        add(f"  - reason: `{_cell(transition.get('source_selection_reason_before'))}`"
            f" → `{_cell(transition.get('source_selection_reason_after'))}`")
        add(f"  - source: `{_cell(transition.get('applied_source_ids_before'))}`"
            f" → `{_cell(transition.get('applied_source_ids_after'))}`")
    else:
        add("- first transition: null")
    add(f"- interaction gains: "
        f"`{_cell(feedback_evidence.get('interaction_source_gains'))}`; new "
        f"features: `{_cell(feedback_evidence.get('interaction_new_features'))}`")
    causal = feedback_evidence.get("causal_artifact") or {}
    add(f"- interventional P4 artifact: available "
        f"`{_cell(causal.get('available'))}` -- {_cell(causal.get('reason'))}")
    add(f"- reason: {_cell(feedback.get('reason'))}")
    add("")

    finding = report.get("finding_stops_and_replays") or {}
    add("### 5. finding 停止接纳并可从保存前缀复现 (finding stop and replay)")
    add("")
    finding_evidence = finding.get("evidence") or {}
    add(f"- verdict: **{_verdict(finding)}**")
    add(f"- report session status: "
        f"`{_cell(finding_evidence.get('report_session_status'))}`; statuses "
        f"`{_cell(finding_evidence.get('report_statuses'))}`")
    add(f"- finding cases: `{_cell(finding_evidence.get('finding_case_ids'))}` "
        f"(case indexes `{_cell(finding_evidence.get('finding_case_indexes'))}`); "
        f"receipts after the finding: "
        f"`{_cell(finding_evidence.get('receipts_after_finding'))}`; trace cases "
        f"after the finding: "
        f"`{_cell(finding_evidence.get('trace_case_indexes_after_finding'))}`")
    prefix = finding_evidence.get("saved_prefix") or {}
    add(f"- saved prefix: plan available `{_cell(prefix.get('plan_available'))}`, "
        f"cases `{_cell(prefix.get('plan_cases'))}`, prefix matches executed "
        f"cases `{_cell(prefix.get('prefix_matches_executed_cases'))}`")
    replay = finding_evidence.get("fresh_replay") or {}
    declared = replay.get("declared_replay_input") or {}
    add(f"- declared replay input: available `{_cell(declared.get('available'))}` "
        f"(case `{_cell(declared.get('case_id'))}`, detected by "
        f"`{_cell(declared.get('detected_by'))}`); it is the input a replay "
        "consumes, never proof of a reproduction")
    compare_run = replay.get("compare_run") or {}
    add(f"- fresh-harness reproduction from a compare run: measured "
        f"`{_cell(replay.get('measured'))}` / met `{_cell(replay.get('met'))}` "
        f"(different run `{_cell(compare_run.get('different_run'))}`, same case "
        f"`{_cell(compare_run.get('same_case_id'))}`, same violations "
        f"`{_cell(compare_run.get('same_violations'))}`)")
    if replay.get("reason") is not None:
        add(f"- reproduction reason: {_cell(replay.get('reason'))}")
    add(f"- reason: {_cell(finding.get('reason'))}")
    add("")

    chunk = report.get("chunk_split_invariance") or {}
    add("### 6. RFuzz chunk 切分不改变规范化事件/末态 (chunk split invariance)")
    add("")
    chunk_evidence = chunk.get("evidence") or {}
    normalized = chunk_evidence.get("normalized_input_level") or {}
    rtl = chunk_evidence.get("rtl_event_level") or {}
    add(f"- verdict: **{_verdict(chunk)}**")
    add(f"- normalized input level: measured "
        f"`{_cell(normalized.get('measured'))}` / met "
        f"`{_cell(normalized.get('met'))}`, payload "
        f"`{_cell(normalized.get('payload_bytes'))}` byte(s) from "
        f"`{_cell(normalized.get('raw_payload_source'))}`, splits "
        f"`{_cell(normalized.get('split_patterns_checked'))}`, identical "
        f"`{_cell(normalized.get('identical'))}`, normalized sha256 "
        f"`{_cell(normalized.get('normalized_sha256'))}`")
    add(f"- real-RTL event/final-state level: measured "
        f"`{_cell(rtl.get('measured'))}` / met `{_cell(rtl.get('met'))}` -- "
        f"{_cell(rtl.get('reason'))}")
    add(f"- reason: {_cell(chunk.get('reason'))}")
    add("")

    identity = report.get("execution_identity") or {}
    add("### 7. 换 execution ID 不接受旧回执 (execution identity)")
    add("")
    identity_evidence = identity.get("evidence") or {}
    identity_gate = identity_evidence.get("gate") or {}
    add(f"- verdict: **{_verdict(identity)}**")
    add(f"- real runner gate: available `{_cell(identity_gate.get('available'))}`, "
        f"same execution_id reused its receipt "
        f"`{_cell(identity_gate.get('same_execution_id_reused_receipt'))}` "
        f"(extra harness steps "
        f"`{_cell(identity_gate.get('additional_harness_steps'))}`), other "
        f"execution_id rejected "
        f"`{_cell(identity_gate.get('other_execution_id_rejected'))}` "
        f"(`{_cell(identity_gate.get('rejection_reason'))}`) with harness steps "
        f"`{_cell(identity_gate.get('other_execution_id_harness_steps'))}`")
    add(f"- trace execution ids: "
        f"`{_cell(identity_evidence.get('trace_execution_ids'))}`; trace testcase "
        f"ids: `{_cell(identity_evidence.get('trace_testcase_ids'))}`")
    add(f"- reason: {_cell(identity.get('reason'))}")
    add("")

    add("## 门禁 (gate)")
    add("")
    add(f"- exit code: **{_cell(gate.get('exit_code'))}**")
    add(f"- critical missing: `{_cell(gate.get('critical_missing'))}`")
    add(f"- critical not met: `{_cell(gate.get('critical_unmet'))}`")
    add(f"- informational (non-critical, never a pass): "
        f"`{_cell(gate.get('informational_unmeasured'))}`")
    add(f"- summary: {_cell(gate.get('summary'))}")
    add("")
    add("| key | critical | measured | met | reason |")
    add("|---|---|---|---|---|")
    for row in items:
        add(f"| `{row['key']}` | `{_cell(row['critical'])}` | "
            f"`{_cell(row['measured'])}` | `{_cell(row['met'])}` | "
            f"{_note(row.get('reason'))} |")
    add("")
    return "\n".join(lines) + "\n"


__all__ = [
    "SCHEMA_VERSION",
    "DEFAULT_MAX_CASE_IDS",
    "DEFAULT_MAX_GAP_CASES",
    "DEFAULT_MAX_LIMIT_ROWS",
    "DEFAULT_MAX_MATCH_SAMPLES",
    "DEFAULT_MAX_MEMORY_LANES",
    "MANIFEST_NAME",
    "RUN_IDENTITY_NAME",
    "RECEIPTS_NAME",
    "REPORT_NAME",
    "PLAN_NAME",
    "REPLAY_ARTIFACT_NAME",
    "MINIMUM_CASES",
    "CHUNK_RTL_TEST",
    "CONTROLLED_FAULT_RUN",
    "FEEDBACK_CAUSAL_ARTIFACT",
    "SPLIT_PATTERNS",
    "EXIT_READY",
    "EXIT_NOT_READY",
    "p3_acceptance_report",
    "render_markdown",
]
