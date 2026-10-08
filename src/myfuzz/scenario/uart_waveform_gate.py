"""Fail-closed admission gate for the UART RX-waveform interleaving limit.

The OpenTitan UART session drives a queued RX frame bit by bit, and its own
``_access`` refuses a TL-UL register access whose window overlaps that frame
(``TL-UL access during serial source waveform is unsupported``).  On the online
path that refusal happens *inside* a submitted case, so it stops the whole
session with ``uncertain_effect`` and the search cannot continue.

This module moves the same decision **before the RTL command**: the executor
already registers every candidate's declared source action with a prerequisite
gate and treats a refusal as a pre-RTL, non-consuming rejection.  The gate below
implements that interface and refuses exactly the candidates the session would
have crashed on -- an instruction-source case whose own words issue a load or
store into the declared UART window while a source waveform is still in flight --
so the session keeps running and the search simply picks another candidate.

Nothing is inferred from names: the UART window is a caller declaration, the
waveform state comes from the session itself through the same
``peer.source_overlaps`` predicate the harness raises on, and the fragment's
accesses are decoded from its own bytes.
"""

from __future__ import annotations

from typing import Mapping

#: Stable refusal reason recorded on the candidate decision.
UART_WAVEFORM_CONFLICT_REASON = "uart_rx_waveform_conflict"
#: The declared prerequisite kind this gate reports as unsatisfied: the UART
#: transport (its RX waveform) must be idle before the access is admitted.
UART_WAVEFORM_PREREQUISITE_KIND = "transport_idle"
#: The declared transport identity used in the prerequisite subject.
UART_TRANSPORT_ID = "uart_rx_waveform"
#: How many per-candidate decisions the gate retains (older ones are counted as
#: omitted rather than dropped silently).
DEFAULT_DECISION_LIMIT = 256

#: opcode -> {funct3: operation}; only the operations the shipped generator
#: emits for MMIO fragments are recognised.
_LOADS = {0x03: {2: "LW"}}
_STORES = {0x23: {2: "SW", 0: "SB"}}


def _signed(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def fragment_mmio_accesses(data: bytes) -> tuple[dict, ...]:
    """Every load/store a fragment's own words perform, with its address.

    Only the shapes the shipped generator emits are recognised: ``LUI rd, high``
    followed by ``LW/SW/SB rs, low(rd)``.  A word that is not such an access is
    skipped rather than guessed, and a register whose base is unknown is left
    alone, so an unrecognised fragment yields no access (never a fabricated one).
    """
    if not isinstance(data, bytes) or len(data) % 4:
        raise ValueError("a fragment must be whole 32-bit words")
    bases: dict[int, int] = {}
    accesses = []
    for offset in range(0, len(data), 4):
        word = int.from_bytes(data[offset:offset + 4], "little")
        opcode = word & 0x7F
        rd = (word >> 7) & 0x1F
        rs1 = (word >> 15) & 0x1F
        funct3 = (word >> 12) & 0x7
        # The two shapes carry their 12-bit offset differently: a load uses the
        # I-type layout (bits 31:20), while a store splits it into S-type
        # imm[11:5] (bits 31:25) and imm[4:0] (bits 11:7) with rs2 in between.
        # Reading a store as I-type folds rs2 into the address and drops
        # imm[4:0], which is exactly the offset the shipped generator selects.
        immediate_i = (word >> 20) & 0xFFF
        immediate_s = (((word >> 25) & 0x7F) << 5) | ((word >> 7) & 0x1F)
        if opcode == 0x37:  # LUI: the 20-bit immediate is the address' upper bits
            bases[rd] = ((word >> 12) & 0xFFFFF) << 12
            continue
        stored = _STORES.get(opcode, {}).get(funct3)
        operation = stored or _LOADS.get(opcode, {}).get(funct3)
        if operation is None or rs1 not in bases:
            continue
        immediate = immediate_s if stored else immediate_i
        accesses.append({"operation": operation,
                         "address": bases[rs1] + _signed(immediate, 12),
                         "word_offset": offset})
    return tuple(accesses)


class UartWaveformAdmissionGate:
    """Refuse a CPU MMIO candidate while the UART RX waveform is in flight.

    ``session`` must expose ``register_access_conflict()`` returning ``None`` or
    a detail mapping (the session's own overlap query).  ``window`` is the
    declared ``(base, size)`` range of the UART registers this wiring exposes;
    only accesses inside it are considered, because only they reach the UART.
    """

    def __init__(self, *, session: object, window: tuple[int, int],
                 component: str = "cpu", enforce: bool = True,
                 decision_limit: int = DEFAULT_DECISION_LIMIT) -> None:
        self.session = session
        self.window = window
        self.component = component
        self.enforce = enforce
        self._refusals = 0
        self._last_action = None
        if (not isinstance(window, tuple) or len(window) != 2
                or type(window[0]) is not int or type(window[1]) is not int
                or window[0] < 0 or window[1] < 1):
            raise ValueError("the UART window must be a declared (base, size) tuple")
        if type(enforce) is not bool:
            raise ValueError("gate enforce must be boolean")
        if not callable(getattr(session, "register_access_conflict", None)):
            raise ValueError(
                "the UART waveform gate needs a session that reports "
                "register_access_conflict()")
        if type(decision_limit) is not int or decision_limit < 1:
            raise ValueError("the UART waveform gate decision limit must be a "
                             "positive integer")
        self.decision_limit = decision_limit
        self._decisions: list[dict] = []
        self._decision_count = 0
        self._admitted = 0

    # -- the executor's prerequisite-gate interface --------------------------

    def register(self, action):
        """Register the candidate action; the action itself is unchanged.

        The executor registers an action and then asks about the case, so the
        registered action is kept as the one ``require_case`` judges -- the gate
        never re-derives it from the case by a second, divergent rule.
        """
        self._last_action = action
        return action

    def evaluate(self, action):
        """The gate's answer for one action, in the shipped evaluation shape."""
        evaluation, _accesses = self._evaluation(action)
        return evaluation

    def _evaluation(self, action):
        """(evaluation, declared in-window accesses) for one action.

        The session predicate is asked exactly once per call: the declared
        accesses are decoded from the candidate's own bytes and returned beside
        the evaluation instead of being re-derived by a second query.
        """
        from myfuzz.scenario.source_actions import PrerequisiteEvaluation

        detail, accesses = self._conflict(action)
        if detail is None:
            return PrerequisiteEvaluation(
                action_id=action.action_id, satisfied=True, missing=(),
                matched=(), reason="satisfied"), accesses
        from myfuzz.scenario.source_actions import Prerequisite

        prerequisite = Prerequisite.create(
            UART_WAVEFORM_PREREQUISITE_KIND,
            {"transport": UART_TRANSPORT_ID,
             "local_tick": int(detail.get("local_tick") or 0),
             "horizon_tick": int(detail.get("horizon_tick") or 0)},
            f"uart-waveform-idle:{int(detail.get('local_tick') or 0)}")
        return PrerequisiteEvaluation(
            action_id=action.action_id, satisfied=False,
            missing=(prerequisite,), matched=(),
            reason=UART_WAVEFORM_CONFLICT_REASON), accesses

    def require_case(self, case) -> None:
        """Refuse the case before any RTL command, with the exact overlap."""
        action = self._action_of(case)
        if action is None:
            return
        evaluation, accesses = self._evaluation(action)
        refused = not evaluation.satisfied
        if refused:
            self._refusals += 1
        self._record_decision(case=case, action=action, evaluation=evaluation,
                              accesses=accesses)
        if refused:
            from myfuzz.scenario.source_actions import SourceActionPrerequisiteError

            raise SourceActionPrerequisiteError(evaluation)

    def decisions(self) -> dict:
        """The bounded per-candidate decision log this gate itself made.

        One record per candidate the gate actually judged (candidates of another
        component are out of scope and are not judged at all).  A refused
        candidate issues no RTL command, so its in-window accesses are recorded
        as *declared* from the fragment's own bytes, never as measured RTL.
        """
        return {
            "schema_version": "uart_waveform_admission_decisions.v1",
            "component": self.component,
            "count": self._decision_count,
            "admitted": self._admitted,
            "refused": self._refusals,
            "limit": self.decision_limit,
            "records": [dict(row) for row in self._decisions],
            "truncated": self._decision_count > len(self._decisions),
            "omitted": max(0, self._decision_count - len(self._decisions)),
            "basis": ("one record per candidate this gate judged before any RTL "
                      "command; candidates of another component are never judged "
                      "by this gate"),
        }

    def observe(self, receipt) -> None:
        """A stateless admission query needs no observations."""

    def document(self) -> dict:
        return {"schema_version": "uart_waveform_admission_gate.v1",
                "kind": "uart_rx_waveform_idle",
                "component": self.component,
                "window": {"base": self.window[0], "size": self.window[1]},
                "enforce": self.enforce, "refusals": self._refusals,
                "decisions": {"count": self._decision_count,
                              "admitted": self._admitted,
                              "refused": self._refusals,
                              "retained": len(self._decisions),
                              "limit": self.decision_limit,
                              "truncated": self._decision_count > len(self._decisions),
                              "omitted": max(0, self._decision_count
                                             - len(self._decisions))},
                "basis": ("the session's own peer.source_overlaps query over the "
                          "declared UART window; a conflict is refused before any "
                          "RTL command instead of stopping the session")}

    # -- internals ----------------------------------------------------------

    def _record_decision(self, *, case, action, evaluation, accesses) -> dict:
        """Retain one bounded decision record; the log is never unbounded."""
        missing = evaluation.missing[0] if evaluation.missing else None
        subject = getattr(missing, "subject", None)
        record = {
            "case_id": getattr(case, "case_id", None),
            "action_id": action.action_id,
            "component": action.component,
            "decision": "admitted" if evaluation.satisfied else "refused",
            "reason": evaluation.reason,
            "evidence_ref": (missing.evidence_ref if missing is not None else None),
            "prerequisite_kind": (missing.kind if missing is not None else None),
            "subject": (dict(subject) if isinstance(subject, Mapping) else None),
            "window": {"base": self.window[0], "size": self.window[1]},
            "declared_window_accesses": [dict(item) for item in accesses],
            "declared_accesses_basis": (
                "decoded from the candidate fragment's own bytes; a refused "
                "candidate issues no RTL command, so these are declared rather "
                "than measured"),
        }
        self._decision_count += 1
        if evaluation.satisfied:
            self._admitted += 1
        if len(self._decisions) < self.decision_limit:
            self._decisions.append(record)
        return record

    def _action_of(self, case):
        action = self._last_action
        if action is None:
            return None
        if getattr(action, "component", None) != self.component:
            return None
        return action

    def _conflict(self, action):
        """(detail, accesses) when this action would hit the UART guard."""
        payload = getattr(action, "payload", None)
        if not isinstance(payload, Mapping):
            return None, ()
        words_hex = payload.get("words_hex")
        if not isinstance(words_hex, str):
            return None, ()
        try:
            data = bytes.fromhex(words_hex)
        except ValueError:
            return None, ()
        base, size = self.window
        accesses = tuple(
            item for item in fragment_mmio_accesses(data)
            if base <= item["address"] < base + size)
        if not accesses:
            return None, ()
        detail = self.session.register_access_conflict()
        if detail is None:
            return None, accesses
        return detail, accesses
