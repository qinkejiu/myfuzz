"""Persistent campaign lifecycle over one bound plan and one existing runtime.

``PersistentCampaignRuntime`` is the single lifecycle owner of a campaign:
``CREATED -> PREPARED -> RUNNING -> QUIESCING -> CLOSED`` with ``FAULTED``
reachable only from ``RUNNING``/``QUIESCING`` (a fault while quiescing keeps the
run faulted and only settlement/save remains).  It owns exactly

* one ``BoundExecutionPlan`` (the live authority; ``assert_current()`` is called
  before the begin and before every case effect),
* the one ``ScenarioRunner``/``ScenarioSession`` set of that binding,
* one flow kernel session (a ``FlowContext`` produced by the kernel's
  ``prepare``), and
* one existing persistent case channel (the existing ``CompiledF2Runtime``/
  ``CompiledF4Runtime`` or a structural stand-in) whose ``submit(raw)`` loop is
  forwarded unchanged.

It never builds, starts, resets or replaces a runner, session, memory or
ledger: the first construction/begin/bootstrap is performed once by the channel
and verified to have happened exactly once; every later case reuses the same
live objects and the same native processes.  A change of any of them is a
``generic-binding-drift`` fault, never a silent rebuild.

Failure policy (design section 5.3): a refusal raised *before* any case effect
(budget, wall clock, lowered-case shape, unbound source, path mismatch) is
recorded and leaves the run running.  Any exception at or after a case effect
keeps the already-effective records, preserves pending/uncertain transaction
keys, marks the case uncertain, enters ``FAULTED`` and is re-raised; nothing is
retried, reset or dropped.
"""
from __future__ import annotations

from collections.abc import Mapping
from hashlib import sha256
import time

from .contracts import GenericRuntimeRefused

LIFECYCLE_STATES = ("CREATED", "PREPARED", "RUNNING", "QUIESCING", "CLOSED",
                    "FAULTED")
TRANSITIONS = {
    "CREATED": ("PREPARED", "CLOSED"),
    "PREPARED": ("RUNNING", "CLOSED"),
    "RUNNING": ("QUIESCING", "FAULTED"),
    "QUIESCING": ("CLOSED", "FAULTED"),
    "FAULTED": ("QUIESCING", "CLOSED"),
    "CLOSED": (),
}
_KEY_FIELDS = ("execution_id", "testcase_id", "source_component",
               "source_epoch", "channel_id", "source_sequence")


def _refuse(code: str, pointer: str = "", detail=None) -> None:
    raise GenericRuntimeRefused(code, pointer, detail)


def _type_name(value) -> str | None:
    if value is None:
        return None
    return f"{type(value).__module__}.{type(value).__qualname__}"


def _jsonable(value):
    """Best-effort JSON-safe copy used for documentary fields only."""
    if value is None or type(value) in (bool, int, float, str):
        return value
    if type(value) is bytes:
        return value.hex()
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return repr(value)[:200]


def _key_document(key) -> dict:
    if all(hasattr(key, name) for name in _KEY_FIELDS):
        return {name: _jsonable(getattr(key, name)) for name in _KEY_FIELDS}
    return {"repr": str(key)[:200]}


class PersistentCampaignRuntime:
    """One persistent campaign: one bound plan, one runner, N cases."""

    runtime_schema = "generic_persistent_campaign.v1"

    def __init__(self, bound_plan, *, kernel, channel, path_id,
                 run_id: str = "generic-campaign", max_cases: int = 64,
                 max_wall_seconds: float | None = None, clock=time.monotonic):
        for name in ("assert_current", "documentary", "close"):
            if not callable(getattr(bound_plan, name, None)):
                _refuse("generic-contract-type", "/bound_plan",
                        {"reason": "bound-plan-surface-incomplete",
                         "missing": name})
        plan = getattr(bound_plan, "plan", None)
        if plan is None or not callable(getattr(plan, "document", None)):
            _refuse("generic-contract-type", "/bound_plan/plan",
                    {"reason": "bound-plan-exposes-no-plan-document"})
        if getattr(bound_plan, "runner", None) is None:
            _refuse("generic-binding-drift", "/bound_plan/runner",
                    {"reason": "bound-plan-exposes-no-runner"})
        if not isinstance(getattr(bound_plan, "sessions", None), Mapping):
            _refuse("generic-binding-drift", "/bound_plan/sessions",
                    {"reason": "bound-plan-exposes-no-session-mapping"})
        plan_sha256 = getattr(bound_plan, "plan_sha256", None)
        if type(plan_sha256) is not str or len(plan_sha256) != 64:
            _refuse("generic-binding-drift", "/bound_plan/plan_sha256",
                    {"reason": "bound-plan-digest-required"})
        for name in ("prepare", "lower", "capture", "feedback"):
            if not callable(getattr(kernel, name, None)):
                _refuse("generic-contract-type", "/kernel",
                        {"reason": "flow-kernel-surface-incomplete",
                         "missing": name})
        for name in ("begin_once", "submit", "finish", "counters"):
            if not callable(getattr(channel, name, None)):
                _refuse("generic-contract-type", "/channel",
                        {"reason": "persistent-case-channel-surface-incomplete",
                         "missing": name})
        if (getattr(channel, "accepts_lowered_case", False)
                and not callable(getattr(channel, "submit_lowered", None))):
            _refuse("generic-contract-type", "/channel",
                    {"reason": "case-aware-channel-surface-incomplete",
                     "missing": "submit_lowered"})
        if type(path_id) is not str or not path_id:
            _refuse("generic-contract-type", "/path_id")
        if type(max_cases) is not int or isinstance(max_cases, bool) or max_cases < 1:
            _refuse("generic-contract-type", "/max_cases",
                    {"expected": "positive int"})
        if max_wall_seconds is not None and (
                type(max_wall_seconds) not in (int, float)
                or isinstance(max_wall_seconds, bool) or max_wall_seconds <= 0):
            _refuse("generic-contract-type", "/max_wall_seconds",
                    {"expected": "positive seconds or None"})
        self.bound_plan = bound_plan
        self.kernel = kernel
        self.channel = channel
        self.path_id = path_id
        self.run_id = run_id
        self.max_cases = max_cases
        self.max_wall_seconds = max_wall_seconds
        self._clock = clock
        self._state = "CREATED"
        self._transitions: list[dict] = []
        self.counts = {"build": 0, "start": 0, "begin": 0, "init": 0}
        self.context = None
        self.cases: list[dict] = []
        self.claims: list = []
        self.refusals: list[dict] = []
        self.faults: list[dict] = []
        self.cleanup_notes: list[dict] = []
        self.process_identities: dict = {}
        self.terminal_records: dict = {}
        self.pending: list[dict] = []
        self.uncertain: list[dict] = []
        self.aborted: str | None = None
        self._runner = None
        self._sessions: dict = {}
        self._memory = None
        self._session = None
        self._authority_kind = None
        self._finish_result = None
        self._report: dict | None = None
        self._released = False
        self._prepare_record: dict | None = None
        self._started_seconds = self._clock()
        self._finished_seconds: float | None = None

    # ------------------------------------------------------------------
    # documentary views
    # ------------------------------------------------------------------
    @property
    def state(self) -> str:
        return self._state

    @property
    def started(self) -> bool:
        return self._state in ("RUNNING", "QUIESCING", "FAULTED", "CLOSED") \
            and self.counts["start"] == 1

    @property
    def finished(self) -> bool:
        return self._state == "CLOSED"

    @property
    def case_count(self) -> int:
        return len(self.cases)

    @property
    def report(self) -> dict:
        if self._report is None:
            self._report = self._build_report()
        return self._report

    def _seconds(self) -> float:
        return round(self._clock() - self._started_seconds, 6)

    # ------------------------------------------------------------------
    # explicit lifecycle
    # ------------------------------------------------------------------
    def _require_state(self, allowed, operation: str) -> None:
        if self._state not in allowed:
            _refuse("generic-lifecycle-refused", "/state",
                    {"operation": operation, "state": self._state,
                     "allowed": list(allowed)})

    def _transition(self, target: str, reason: str) -> None:
        if target not in TRANSITIONS[self._state]:
            _refuse("generic-lifecycle-refused", "/state",
                    {"from": self._state, "to": target, "reason": reason})
        self._transitions.append({"from": self._state, "to": target,
                                  "reason": reason,
                                  "at_seconds": self._seconds()})
        self._state = target

    def prepare(self) -> dict:
        """CREATED -> PREPARED: kernel requirements/context; no RTL effect."""
        self._require_state(("CREATED",), "prepare")
        self._assert_bound_current("/prepare")
        try:
            context = self.kernel.prepare(self.bound_plan, self.path_id)
        except BaseException as error:
            self._record_refusal(None, error, stage="prepare")
            raise
        self.context = context
        self._prepare_record = context.document()
        self._transition("PREPARED", "kernel-prepared")
        return self._prepare_record

    def start(self) -> dict:
        """CREATED|PREPARED -> RUNNING: one begin, verified to happen once."""
        self._require_state(("CREATED", "PREPARED"), "start")
        if self._state == "CREATED":
            self.prepare()
        self._assert_bound_current("/start")
        begun = False
        try:
            self.channel.begin_once()
            begun = True
            counters = self._read_counters()
            self._adopt_live_objects()
            self._verify_binding_identity("/start")
        except BaseException as error:
            self._fault("begin", error)
            session = getattr(self.channel, "session", None)
            if begun or getattr(session, "_begun", False):
                # The session really began, so this campaign can never be
                # started again: settle it without any new effect.
                try:
                    self.channel.finish()
                except BaseException as cleanup:
                    self._note("begin-drain", cleanup)
                    error.add_note("campaign begin cleanup: " + repr(cleanup))
                try:
                    self._record_terminal_children()
                except BaseException as cleanup:
                    self._note("begin-settle", cleanup)
                self._settle("start-failed-after-begin")
            raise
        self.counts = {"build": counters["build"], "start": 1,
                       "begin": counters["begin"], "init": counters["init"]}
        self._transition("RUNNING", "begin-once")
        return {"initialization_counts": dict(self.counts),
                "process_identities": _jsonable(self.process_identities)}

    def _read_counters(self) -> dict:
        raw = self.channel.counters()
        if not isinstance(raw, Mapping):
            _refuse("generic-binding-drift", "/counters",
                    {"reason": "initialization-counts-required"})
        counters = {}
        for name in ("build", "begin", "init"):
            value = raw.get(name)
            if type(value) is not int or isinstance(value, bool):
                _refuse("generic-binding-drift", "/counters/" + name,
                        {"expected": "int count"})
            counters[name] = value
            if value != 1:
                _refuse("generic-binding-drift", "/counters/" + name,
                        {"expected": 1, "actual": value,
                         "reason": "campaign-initialization-must-happen-once",
                         "counters": {key: counters[key] for key in counters}})
        return counters

    def _adopt_live_objects(self) -> None:
        runner = getattr(self.channel, "runner", None)
        sessions = getattr(self.channel, "sessions", None)
        if runner is None or not isinstance(sessions, Mapping) or not sessions:
            _refuse("generic-binding-drift", "/channel",
                    {"reason": "existing-runtime-exposes-no-sessions"})
        self._runner = runner
        self._sessions = dict(sessions)
        self._memory = getattr(self.channel, "memory", None)
        self._session = getattr(self.channel, "session", None)
        self._authority_kind = _type_name(getattr(self.channel, "authority", None))
        self.process_identities = self._capture_process_identities(self._sessions)

    # ------------------------------------------------------------------
    # per-case work
    # ------------------------------------------------------------------
    def validate(self, case):
        """Pure lowering of one case; nothing is admitted and no RTL runs."""
        self._require_state(("PREPARED", "RUNNING"), "validate")
        context = self.context
        if context is None:
            _refuse("generic-lifecycle-refused", "/context",
                    {"reason": "kernel-not-prepared"})
        lowered = self.kernel.lower(context, case)
        records = getattr(lowered, "raw_records", None)
        if type(records) is not tuple or not records or any(
                type(row) is not bytes or not row for row in records):
            _refuse("generic-contract-type", "/lowered/raw_records",
                    {"expected": "nonempty tuple of bytes; never truncated"})
        return lowered

    def submit(self, case):
        """Run one case on the existing persistent runtime."""
        self._require_state(("RUNNING",), "submit")
        budget = self._budget_refusal()
        if budget is not None:
            self._record_refusal(case, budget, stage="budget")
            raise budget
        self._guarded("submit-bound-current", self._assert_bound_current,
                      "/submit")
        self._guarded("submit-identity", self._verify_binding_identity,
                      "/submit")
        try:
            lowered = self.validate(case)
        except GenericRuntimeRefused as refusal:
            self._record_refusal(case, refusal, stage="lower")
            raise
        record = {
            "case_index": len(self.cases),
            "testcase_id": getattr(lowered, "testcase_id", None),
            "path_id": getattr(lowered, "path_id", None),
            "source_id": getattr(lowered, "source_id", None),
            "flow_id": getattr(lowered, "flow_id", None),
            "raw_records_hex": [raw.hex() for raw in lowered.raw_records],
            "status": "in-flight",
            "records": [],
            "evidence": [],
            "started_at_seconds": self._seconds(),
        }
        self.cases.append(record)
        index = None
        all_records_evidenced = True
        try:
            for index, raw in enumerate(lowered.raw_records):
                self._assert_bound_current(
                    f"/submit/raw_records_hex/{index}")
                self._verify_binding_identity(
                    f"/submit/raw_records_hex/{index}")
                if getattr(self.channel, "accepts_lowered_case", False):
                    receipt = self.channel.submit_lowered(lowered, index)
                elif getattr(self.channel, "accepts_flow", False):
                    receipt = self.channel.submit(
                        raw, flow_id=getattr(lowered, "flow_id", None))
                else:
                    receipt = self.channel.submit(raw)
                evidence = self.kernel.capture(self.context, receipt)
                if not evidence or any(item.document().get('status') != 'certified'
                                       for item in evidence):
                    all_records_evidenced = False
                record["records"].append({
                    "raw_index": index,
                    "raw_hex": raw.hex(),
                    "certificate": _jsonable(receipt),
                })
                for item in evidence:
                    record["evidence"].append(item.document())
                    self.claims.append(item)
            record["status"] = "effective" if all_records_evidenced else "submitted"
            record["finished_at_seconds"] = self._seconds()
            record["process_identity_sha256"] = self._digest_identities(
                self.process_identities)
            self._guarded("submit-post-identity",
                          self._verify_binding_identity, "/submit")
        except BaseException as error:
            record["status"] = "uncertain"
            record["uncertain"] = {
                "raw_index": index,
                "error_type": type(error).__name__,
                "code": getattr(error, "code", None),
                "pointer": getattr(error, "pointer", None),
                "effect_possible": True,
                "retried": False,
            }
            record["finished_at_seconds"] = self._seconds()
            try:
                self._collect_pending_uncertain()
            except BaseException as drain_error:
                self._note("submit-pending", drain_error)
            self._fault("submit", error)
            raise
        return record

    def _guarded(self, stage: str, action, pointer: str) -> None:
        try:
            action(pointer)
        except BaseException as error:
            self._fault(stage, error)
            raise

    def _budget_refusal(self) -> GenericRuntimeRefused | None:
        if len(self.cases) >= self.max_cases:
            return GenericRuntimeRefused(
                "generic-budget-refused", "/max_cases",
                {"reason": "case-budget-exhausted",
                 "max_cases": self.max_cases})
        if self.max_wall_seconds is not None and \
                self._seconds() >= self.max_wall_seconds:
            return GenericRuntimeRefused(
                "generic-budget-refused", "/max_wall_seconds",
                {"reason": "wall-clock-budget-exhausted",
                 "max_wall_seconds": self.max_wall_seconds})
        return None

    # ------------------------------------------------------------------
    # termination
    # ------------------------------------------------------------------
    def finish(self):
        """RUNNING|FAULTED -> QUIESCING -> CLOSED, draining and recording."""
        self._require_state(("RUNNING", "FAULTED"), "finish")
        if self._state == "RUNNING":
            self._transition("QUIESCING", "finish")
        primary = None
        try:
            self._finish_result = self.channel.finish()
        except BaseException as error:
            primary = error
            self._fault("finish", error)
        for stage, action in (
                ("drain-pending", self._collect_pending_uncertain),
                ("terminal-records", self._record_terminal_children),
                ("counts", self._verify_counts_unchanged)):
            try:
                action()
            except BaseException as error:
                if primary is None:
                    primary = error
                self._fault(stage, error)
        self._settle("finish")
        self._report = self._build_report()
        if primary is not None:
            raise primary
        return self._report

    def abort(self, reason: str):
        """Stop the run, keep every effective/pending record, then close."""
        if type(reason) is not str or not reason:
            _refuse("generic-contract-type", "/reason",
                    {"expected": "nonempty abort reason"})
        self._require_state(("CREATED", "PREPARED", "RUNNING", "FAULTED"),
                            "abort")
        self.aborted = reason
        if self._state in ("CREATED", "PREPARED"):
            self._finish_result = None
            self._settle("abort")
            self._report = self._build_report()
            return self._report
        self._transition("QUIESCING", "abort:" + reason[:64])
        try:
            self._finish_result = self.channel.finish()
        except BaseException as error:
            self._note("abort-drain", error)
        for stage, action in (
                ("drain-pending", self._collect_pending_uncertain),
                ("terminal-records", self._record_terminal_children)):
            try:
                action()
            except BaseException as error:
                self._note("abort-" + stage, error)
        self._settle("abort")
        self._report = self._build_report()
        return self._report

    def close(self) -> None:
        """Release the bound handle; never the way out of an active run."""
        if self._state == "RUNNING":
            _refuse("generic-lifecycle-refused", "/state",
                    {"operation": "close", "state": self._state,
                     "allowed": ["finish", "abort"],
                     "reason": "close-cannot-abandon-an-active-run"})
        if self._state == "FAULTED":
            for stage, action in (
                    ("drain-pending", self._collect_pending_uncertain),
                    ("terminal-records", self._record_terminal_children)):
                try:
                    action()
                except BaseException as error:
                    self._note("close-" + stage, error)
            self._settle("close")
        elif self._state in ("CREATED", "PREPARED"):
            self._settle("close")
        if self._report is None:
            self._report = self._build_report()
        if not self._released:
            self._released = True
            for name, accessor in (
                    ("channel", getattr(self.channel, "close", None)),
                    ("bound-plan", getattr(self.bound_plan, "close", None))):
                if not callable(accessor):
                    continue
                try:
                    accessor()
                except BaseException as error:
                    self._note("release-" + name, error)

    def __enter__(self):
        return self

    def __exit__(self, error_type, error, traceback):
        if self._state == "CLOSED":
            return False
        try:
            if self._state == "RUNNING":
                self.abort("context-exit-with-error" if error is not None
                           else "context-exit-without-finish")
            else:
                self.close()
        except BaseException as cleanup:
            self._note("context-exit", cleanup)
        return False

    def _settle(self, reason: str) -> None:
        if self._state == "CLOSED":
            return
        if self._state == "RUNNING":
            self._transition("QUIESCING", "settle:" + reason)
        if self._state in ("QUIESCING", "FAULTED", "CREATED", "PREPARED"):
            self._transition("CLOSED", reason)
        self._finished_seconds = round(self._clock() - self._started_seconds, 6)

    # ------------------------------------------------------------------
    # identity and evidence plumbing
    # ------------------------------------------------------------------
    def _assert_bound_current(self, pointer: str) -> None:
        try:
            self.bound_plan.assert_current()
        except GenericRuntimeRefused:
            raise
        except BaseException as error:
            raise GenericRuntimeRefused(
                "generic-binding-drift", pointer,
                {"reason": "bound-plan-assert-current-failed",
                 "error_type": type(error).__name__}) from error

    def _verify_binding_identity(self, pointer: str) -> None:
        bound_runner = getattr(self.bound_plan, "runner", None)
        if bound_runner is not self._runner:
            _refuse("generic-binding-drift", pointer,
                    {"reason": "bound-plan-runner-is-not-the-live-runner",
                     "bound_runner": _type_name(bound_runner),
                     "live_runner": _type_name(self._runner)})
        bound_sessions = getattr(self.bound_plan, "sessions", None)
        if isinstance(bound_sessions, Mapping) and bound_sessions:
            if set(bound_sessions) != set(self._sessions):
                _refuse("generic-binding-drift", pointer,
                        {"reason": "bound-session-names-differ",
                         "bound": sorted(bound_sessions),
                         "live": sorted(self._sessions)})
            for name in sorted(bound_sessions):
                if bound_sessions[name] is not self._sessions[name]:
                    _refuse("generic-binding-drift", pointer,
                            {"reason": "bound-session-is-not-the-live-session",
                             "session": name})
        runner = getattr(self.channel, "runner", None)
        if runner is not self._runner:
            _refuse("generic-binding-drift", pointer,
                    {"reason": "runner-replaced-after-begin"})
        sessions = getattr(self.channel, "sessions", None)
        if not isinstance(sessions, Mapping) or set(sessions) != set(self._sessions):
            _refuse("generic-binding-drift", pointer,
                    {"reason": "session-set-changed-after-begin"})
        for name in sorted(sessions):
            if sessions[name] is not self._sessions[name]:
                _refuse("generic-binding-drift", pointer,
                        {"reason": "session-replaced-after-begin",
                         "session": name})
        if getattr(self.channel, "memory", None) is not self._memory:
            _refuse("generic-binding-drift", pointer,
                    {"reason": "persistent-memory-replaced-after-begin"})
        if _type_name(getattr(self.channel, "authority", None)) != self._authority_kind:
            _refuse("generic-binding-drift", pointer,
                    {"reason": "native-authority-replaced-after-begin"})
        current = self._capture_process_identities(sessions)
        if current != self.process_identities:
            changed = sorted(
                name for name in set(current) | set(self.process_identities)
                if current.get(name) != self.process_identities.get(name))
            _refuse("generic-binding-drift", pointer,
                    {"reason": "process-identity-changed-after-begin",
                     "sessions": changed})

    def _capture_process_identities(self, sessions: Mapping) -> dict:
        rows: dict[str, dict] = {}
        for name in sorted(sessions):
            session = sessions[name]
            process = getattr(session, "process", None)
            row = {"session": name, "pid": None, "process_type": None,
                   "alive": None, "returncode": None, "unavailable": []}
            if process is None:
                row["unavailable"].append("session-exposes-no-process")
                rows[name] = row
                continue
            row["process_type"] = _type_name(process)
            pid = getattr(process, "pid", None)
            if type(pid) is int and not isinstance(pid, bool) and pid > 0:
                row["pid"] = pid
            else:
                row["unavailable"].append("process-exposes-no-pid")
            poll = getattr(process, "poll", None)
            if callable(poll):
                try:
                    returncode = poll()
                except Exception:
                    row["unavailable"].append("process-poll-failed")
                    returncode = None
                if type(returncode) is int and not isinstance(returncode, bool):
                    row["returncode"] = returncode
                    row["alive"] = False
                else:
                    row["alive"] = True
            else:
                row["unavailable"].append("process-exposes-no-poll")
            rows[name] = row
        return rows

    @staticmethod
    def _digest_identities(identities: Mapping) -> str:
        material = []
        for name in sorted(identities):
            row = identities[name]
            material.append([name, row.get("pid"), row.get("process_type"),
                             row.get("alive"), row.get("returncode")])
        return sha256(repr(material).encode("utf-8")).hexdigest()

    def _collect_pending_uncertain(self) -> None:
        for row in self._ledger_keys():
            sink = self.pending if row["kind"] == "pending_keys" else self.uncertain
            if row not in sink:
                sink.append(row)

    def _ledger_keys(self) -> list[dict]:
        rows: list[dict] = []
        for name in sorted(self._sessions):
            session = self._sessions[name]
            ledgers = (
                ("service.ledger",
                 getattr(getattr(session, "service", None), "ledger", None)),
                ("mmio_ledger", getattr(session, "mmio_ledger", None)),
            )
            for label, ledger in ledgers:
                if ledger is None:
                    continue
                for attribute in ("pending_keys", "uncertain_keys"):
                    # Real ledgers expose these as properties; a structural
                    # stand-in may expose a plain sequence.  Both are read,
                    # never created or cleared here.
                    value = getattr(ledger, attribute, None)
                    try:
                        keys = tuple(value() if callable(value) else value)
                    except BaseException as error:
                        self._note("ledger-read:" + label, error)
                        continue
                    if not isinstance(keys, tuple):
                        self._note("ledger-read:" + label,
                                   ValueError("ledger keys are not a sequence"))
                        continue
                    for key in keys:
                        rows.append({"session": name, "ledger": label,
                                     "kind": attribute,
                                     "key": _key_document(key)})
        return rows

    def _record_terminal_children(self) -> None:
        audit = None
        accessor = getattr(self.channel, "execution_audit", None)
        if callable(accessor):
            try:
                audit = accessor()
            except BaseException as error:
                self._note("execution-audit", error)
        exits = audit.get("exits") if isinstance(audit, Mapping) else None
        for name in sorted(self._sessions):
            session = self._sessions[name]
            process = getattr(session, "process", None)
            row = {"session": name, "pid": None, "terminal": "unverified",
                   "returncode": None, "basis": None}
            if process is None:
                row["basis"] = "session-exposes-no-process"
                self.terminal_records[name] = row
                continue
            pid = getattr(process, "pid", None)
            if type(pid) is int and not isinstance(pid, bool):
                row["pid"] = pid
            poll = getattr(process, "poll", None)
            returncode = None
            if callable(poll):
                try:
                    returncode = poll()
                except BaseException as error:
                    self._note("terminal-poll", error)
            if type(returncode) is int and not isinstance(returncode, bool):
                row.update(terminal="exited", returncode=returncode,
                           basis="process-poll")
            elif isinstance(exits, Mapping) and isinstance(exits.get(name),
                                                           Mapping):
                value = exits[name].get("returncode")
                if type(value) is int and not isinstance(value, bool):
                    row.update(terminal="exited", returncode=value,
                               basis="existing-execution-audit")
                else:
                    row["basis"] = "execution-audit-without-returncode"
            else:
                row["basis"] = "no-terminal-status-exposed"
            self.terminal_records[name] = row

    def _verify_counts_unchanged(self) -> None:
        if self.counts["start"] != 1:
            _refuse("generic-binding-drift", "/counters",
                    {"reason": "campaign-start-count-not-one",
                     "counts": dict(self.counts)})
        counters = self.channel.counters()
        for name in ("build", "begin", "init"):
            value = counters.get(name) if isinstance(counters, Mapping) else None
            if value != 1:
                _refuse("generic-binding-drift", "/counters/" + name,
                        {"reason": "initialization-repeated-during-campaign",
                         "expected": 1, "actual": value})

    # ------------------------------------------------------------------
    # records
    # ------------------------------------------------------------------
    def _record_refusal(self, case, error, *, stage: str) -> None:
        row = {
            "stage": stage,
            "at_seconds": self._seconds(),
            "code": getattr(error, "code", None),
            "pointer": getattr(error, "pointer", None),
            "detail": _jsonable(getattr(error, "detail", None)),
            "effect": False,
            "testcase_id": None,
            "path_id": None,
        }
        if isinstance(case, Mapping):
            row["testcase_id"] = case.get("testcase_id")
            row["path_id"] = case.get("path_id")
            row["source_id"] = case.get("source_id")
        if row not in self.refusals:
            self.refusals.append(row)

    def _fault(self, stage: str, error) -> None:
        row = {
            "stage": stage,
            "at_seconds": self._seconds(),
            "state_before": self._state,
            "error_type": type(error).__name__,
            "code": getattr(error, "code", None),
            "pointer": getattr(error, "pointer", None),
            "detail": _jsonable(getattr(error, "detail", None)),
        }
        self.faults.append(row)
        if self._state in ("RUNNING", "QUIESCING"):
            self._transition("FAULTED", "fault:" + stage)

    def _note(self, stage: str, error) -> None:
        self.cleanup_notes.append({
            "stage": stage,
            "at_seconds": self._seconds(),
            "error_type": type(error).__name__,
            "code": getattr(error, "code", None),
            "message": str(error)[:200],
        })

    def _bound_documentary(self) -> dict | None:
        accessor = getattr(self.bound_plan, "documentary", None)
        if not callable(accessor):
            return None
        try:
            value = accessor()
        except BaseException as error:
            self._note("bound-documentary", error)
            return None
        return _jsonable(value) if isinstance(value, Mapping) else None

    def _build_report(self) -> dict:
        feedback = None
        accessor = getattr(self.channel, "feedback", None)
        if callable(accessor):
            try:
                value = accessor()
            except BaseException as error:
                self._note("channel-feedback", error)
                value = None
            if isinstance(value, Mapping):
                feedback = _jsonable(value)
        return {
            "schema_version": self.runtime_schema,
            "run_id": self.run_id,
            "plan_sha256": getattr(self.bound_plan, "plan_sha256", None),
            "path_id": self.path_id,
            "kernel_id": getattr(self.kernel, "kernel_id", None),
            "flow_id": (self._prepare_record or {}).get("flow_id"),
            "state": self._state,
            "aborted": self.aborted,
            "lifecycle": _jsonable(self._transitions),
            "initialization_counts": dict(self.counts),
            "case_count": len(self.cases),
            "cases": _jsonable(self.cases),
            "evidence": [claim.document() for claim in self.claims],
            "evidence_count": len(self.claims),
            "process_identities": _jsonable(self.process_identities),
            "terminal_records": _jsonable(self.terminal_records),
            "pending": _jsonable(self.pending),
            "uncertain": _jsonable(self.uncertain),
            "refusals": _jsonable(self.refusals),
            "faults": _jsonable(self.faults),
            "cleanup_notes": _jsonable(self.cleanup_notes),
            "existing_runtime_submissions": getattr(self.channel, "submissions",
                                                    None),
            "existing_runtime_feedback": feedback,
            "context": _jsonable(self._prepare_record),
            "bound_documentary": self._bound_documentary(),
            "native_certification": {
                "claimed": False,
                "reason": "G5 is the software layer: no native token, process "
                          "or effect is certified here; persistent native "
                          "evidence belongs to G6",
            },
        }
