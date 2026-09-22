"""Task 2 of ``docs/superpowers/plans/2026-09-22-soc-peer-criteria-implementation.md``.

Frozen SPI peer scope: for every admitted behaviour an independent expectation, a
complete four-wire trajectory and an error injection; for everything else a
specific reason, and a recorded classification whenever the shipped criterion
does not produce the status the plan's rule requires.

What is frozen
--------------
``SPI_SCOPE`` is the scope table.  Every behaviour carries ``admitted`` (whether
an independent criterion exists for it), ``expectation`` (where the compared
words come from), ``trajectory`` (how the complete four-wire trajectory is
built), ``injection`` (the error this module injects for it), ``observed`` (the
status the shipped criterion really produces), ``required`` (the status the
plan's rule requires) and ``reason`` (the specific reason, never empty).

``observed`` is not documentation.  ``SpiScopeFreezeTests`` re-runs every probe
and fails when the shipped criterion stops producing the recorded status, so a
change of behaviour cannot pass unnoticed; where ``observed != required`` the
entry is named in ``FROZEN_GAPS`` and the gap is a defect of the criterion, not a
claim about the peer.

Independence
------------
No expectation is read from the peer, from the component under test or from any
success counter.  Every word compared here is a literal this module wrote (the
byte it put in the component's TXDATA register and the byte it armed in the
peer), and every trajectory is either built by :func:`spi_trajectory` - which
changes the data wires only on the edge the declared mode assigns to the shifter,
exactly as ``soc_spi_peer.sv``/``novaspi.sv`` do - or is the runtime's own
recording of the component's real ``sck``/``cs``/``mosi``/``miso`` pins.

Read-only reuse
---------------
``spi_wire_expectation``/``audit_peer_run`` from
``src/myfuzz/composition/soc_peer_oracle.py`` (Task 1 owns that file),
``_frame`` from ``tests/integration/test_soc_spi_wire_oracle.py``, and
``_PeerRuntimeFixture``/``SpiPeerRuntimeTests``/``SpiMode3PeerRuntimeTests``/
``spi_mode_profiles``/``spi_mode_document`` from
``tests/integration/test_soc_peer_models.py``.  Nothing outside this file is
modified.
"""
from __future__ import annotations

import unittest
from types import SimpleNamespace

from myfuzz.composition.soc_peer_oracle import audit_peer_run, spi_wire_expectation

from tests.integration import test_soc_peer_models as peer_models
from tests.integration.test_soc_peer_models import (
    SPI_COMPONENT_BYTE,
    SPI_CTRL,
    SPI_PEER_BYTE,
    SPI_RXDATA,
    SPI_STATUS,
    SPI_TXDATA,
)
from tests.integration.test_soc_spi_wire_oracle import _frame as incumbent_trajectory

OPT_IN = peer_models.OPT_IN

#: The four declared SPI modes, as ``(CPOL, CPHA)``.
SPI_MODES = ((0, 0), (0, 1), (1, 0), (1, 1))

#: The words this module writes and expects back.  ``(mosi, miso)`` per frame,
#: most significant bit first, taken from nothing but this module's own literals.
FRAME_ONE = (0xA5, 0x5A)
FRAME_TWO = (0x3C, 0xC3)
FRAME_THREE = (0x0F, 0xF0)
MULTI_WORDS = (FRAME_ONE, FRAME_TWO)
THREE_WORDS = (FRAME_ONE, FRAME_TWO, FRAME_THREE)

#: The same, for the real component: the byte written to TXDATA is what the
#: master shifts out and the byte armed in the peer is what it shifts back.
REAL_FRAME_ONE = (SPI_COMPONENT_BYTE, SPI_PEER_BYTE)
REAL_WORDS = ((SPI_COMPONENT_BYTE, 0x5A), (0x3C, 0xC3))

#: Register offsets and the independent register norm used by the run audit.
SPI_TXDATA_ADDRESS = 0x1008
SPI_WIRE_BASIS = "independent fixture register norm"
SPI_PARAMETERS = {"BITS": 8, "CPOL": 0, "CPHA": 0, "CS_ACTIVE_LOW": 1}
SPI_SLOT = {"index": 0, "instance_id": "spi0", "peer_id": "spi",
            "slot": "spi.arm_byte", "parameters": SPI_PARAMETERS}


# ---------------------------------------------------------------------------
# trajectories and expectations
# ---------------------------------------------------------------------------


def spi_trajectory(words, *, bits=8, cpol=0, cpha=0, cs_active_low=1,
                   one_selection=False, start=0):
    """A complete four-wire trajectory plus the rows the decoder samples.

    Returns ``(trace, sampled_rows)``.  The values mirror the RTL: with CPHA=0
    the shifter changes the data on the trailing edge (so the row reached by the
    trailing edge already carries the next bit) and the decoder samples the
    leading edge; with CPHA=1 the shifter changes on the leading edge and the
    decoder samples the trailing edge.  An idealized trajectory that holds every
    bit across both edges cannot see a CPHA declaration error at all, which is
    exactly why this builder does not do that.

    ``one_selection`` keeps the chip select asserted for every word, which is the
    continuous-select behaviour the scope table refuses; ``start`` moves the
    first row so a run-audit probe can place its register writes before it.
    """
    if bits < 1 or cpol not in (0, 1) or cpha not in (0, 1) or cs_active_low not in (0, 1):
        raise AssertionError("spi-trajectory-parameters-invalid")
    idle, active = str(cpol), str(1 - cpol)
    deselected, selected = str(cs_active_low), str(1 - cs_active_low)

    def bits_of(word: int) -> list[int]:
        return [(int(word) >> shift) & 1 for shift in range(bits - 1, -1, -1)]

    def following(sequence: list[int], index: int) -> int:
        return sequence[index + 1] if index + 1 < len(sequence) else 0

    trace = [{"cycle": start, "sck": idle, "cs": deselected, "mosi": "0", "miso": "0"}]
    cycle = start + 1
    for word_index, (mosi_word, miso_word) in enumerate(words):
        mosi_bits, miso_bits = bits_of(mosi_word), bits_of(miso_word)
        if word_index == 0 or not one_selection:
            # CPHA=0 presents the first bit when the selection starts; CPHA=1
            # presents it on the first leading edge and nothing before it.
            trace.append({"cycle": cycle, "sck": idle, "cs": selected,
                          "mosi": str(mosi_bits[0] if cpha == 0 else 0),
                          "miso": str(miso_bits[0] if cpha == 0 else 0)})
            cycle += 1
        for index in range(bits):
            trace.append({"cycle": cycle, "sck": active, "cs": selected,
                          "mosi": str(mosi_bits[index]),
                          "miso": str(miso_bits[index])})
            cycle += 1
            if cpha == 0:
                next_mosi, next_miso = following(mosi_bits, index), following(miso_bits, index)
            else:
                next_mosi, next_miso = mosi_bits[index], miso_bits[index]
            trace.append({"cycle": cycle, "sck": idle, "cs": selected,
                          "mosi": str(next_mosi), "miso": str(next_miso)})
            cycle += 1
        if not one_selection:
            trace.append({"cycle": cycle, "sck": idle, "cs": deselected,
                          "mosi": "0", "miso": "0"})
            cycle += 1
    trace.append({"cycle": cycle, "sck": idle, "cs": deselected, "mosi": "0", "miso": "0"})
    return trace, sampling_rows(trace, cpol=cpol, cpha=cpha, cs_active_low=cs_active_low)


def sampling_rows(trace, *, cpol, cpha, cs_active_low=1):
    """Indices of the rows the frozen decoder samples under these parameters.

    This is not a second decoder: it only locates the edges, so an injection can
    be aimed at a sampling edge or deliberately away from every one of them.
    """
    deselected = str(cs_active_low)
    rows: list[int] = []
    for index, (before, after) in enumerate(zip(trace, trace[1:]), start=1):
        if before["cs"] == deselected or after["cs"] == deselected:
            continue
        if before["sck"] == after["sck"]:
            continue
        if (str(before["sck"]) == str(cpol)) == (cpha == 0):
            rows.append(index)
    return rows


def decode(trace, words, *, bits=8, cpol=0, cpha=0, cs_active_low=1):
    """The frozen independent expectation for ``words`` on ``trace``."""
    return spi_wire_expectation(
        trace, bits=bits, cpol=cpol, cpha=cpha, cs_active_low=cs_active_low,
        mosi_words=[word[0] for word in words], miso_words=[word[1] for word in words])


def one_word(verdict):
    """The single decoded word pair, so a test can name what the wire really said."""
    return (verdict["observed_mosi_words"], verdict["observed_miso_words"])


# ---------------------------------------------------------------------------
# run-audit evidence, built here so the layer's own boundary can be probed
# ---------------------------------------------------------------------------


def audit_build(*, contract=True, cpu_sources=(0,), parameters=None):
    return SimpleNamespace(
        peer_slots=(dict(SPI_SLOT, parameters=dict(parameters or SPI_PARAMETERS)),),
        peer_observations=(),
        cpu_data_sources=tuple(cpu_sources),
        spi_wire_contracts=({"spi0": {"txdata_address": SPI_TXDATA_ADDRESS,
                                      "basis": SPI_WIRE_BASIS}} if contract else {}))


def audit_result(trace, *, writes=(), arms=(), cycles=400, truncated=False, status=None):
    rows = status if status is not None else (
        {"instance_id": "spi0", "count": len(trace), "truncated": truncated},)
    return SimpleNamespace(
        cycles=cycles,
        peer_applied=tuple({"cycle": cycle, "instance": "spi0", "slot": "spi.arm_byte",
                            "value": payload} for cycle, payload in arms),
        peer_wire_trace=tuple(dict(row, instance_id="spi0") for row in trace),
        peer_wire_status=tuple(rows),
        requests=tuple(writes),
        counters={},
        observations={})


def audit_sample(arms):
    return SimpleNamespace(peer_events=tuple(
        {"slot": 0, "cycle": cycle, "payload": payload} for cycle, payload in arms))


def cpu_write(cycle, wdata, *, be=0xF, addr=SPI_TXDATA_ADDRESS, source=0):
    return {"cycle": cycle, "addr": addr, "write": 1, "wdata": wdata,
            "be": be, "source": source}


def spi_verdict(audit):
    """The run audit's SPI verdict, whether it is a check or an unassessed entry.

    A check carries its reason in ``note`` and an unassessed entry in ``reason``;
    both are returned under ``reason`` so a probe has one shape to assert on.
    """
    for check in audit["checks"]:
        if check["check_id"] == "spi-transfer-wire":
            return dict(check, reason=str(check.get("note", "")))
    for entry in audit["unassessed"]:
        if entry["check_id"] == "spi-transfer-wire":
            return {"check_id": "spi-transfer-wire", "status": "not_assessed",
                    "reason": entry["reason"], "expected": None, "observed": None,
                    "note": entry["reason"]}
    raise AssertionError("the run audit made no SPI claim at all: %s" % (audit,))


def run_audit(trace, *, writes=(), arms=(), build=None, **kwargs):
    return spi_verdict(audit_peer_run(
        build or audit_build(), audit_sample(arms),
        audit_result(trace, writes=writes, arms=arms, **kwargs)))


# ---------------------------------------------------------------------------
# one probe per scope entry
# ---------------------------------------------------------------------------


def _probe_single_word():
    trace, _ = spi_trajectory((FRAME_ONE,))
    return decode(trace, (FRAME_ONE,))


def _probe_multi_word():
    trace, _ = spi_trajectory(MULTI_WORDS)
    return decode(trace, MULTI_WORDS)


def _probe_four_modes():
    verdict = None
    for cpol, cpha in SPI_MODES:
        trace, _ = spi_trajectory((FRAME_ONE,), cpol=cpol, cpha=cpha)
        verdict = decode(trace, (FRAME_ONE,), cpol=cpol, cpha=cpha)
        if verdict["status"] != "pass":
            return verdict
    return verdict


def _probe_both_cs_polarities():
    verdict = None
    for cs_active_low in (0, 1):
        trace, _ = spi_trajectory((FRAME_ONE,), cs_active_low=cs_active_low)
        verdict = decode(trace, (FRAME_ONE,), cs_active_low=cs_active_low)
        if verdict["status"] != "pass":
            return verdict
    return verdict


def _probe_multi_word_run_audit():
    trace, _ = spi_trajectory(MULTI_WORDS, start=10)
    return run_audit(trace, writes=(cpu_write(6, FRAME_ONE[0]), cpu_write(106, FRAME_TWO[0])),
                     arms=((8, FRAME_ONE[1]), (108, FRAME_TWO[1])))


def _probe_continuous_selection():
    trace, _ = spi_trajectory(MULTI_WORDS, one_selection=True)
    return decode(trace, MULTI_WORDS)


def _probe_cpha_one_declared_as_zero():
    trace, _ = spi_trajectory((FRAME_ONE,), cpha=1)
    return decode(trace, (FRAME_ONE,), cpha=0)


def _probe_cpol_inversion():
    trace, _ = spi_trajectory((FRAME_ONE,), cpol=0)
    return decode(trace, (FRAME_ONE,), cpol=1)


def _probe_cs_polarity_inversion():
    trace, _ = spi_trajectory((FRAME_ONE,), cs_active_low=0)
    return decode(trace, (FRAME_ONE,), cs_active_low=1)


def _probe_frame_shorter_than_declared():
    trace, sampled = spi_trajectory((FRAME_ONE,))
    cut = [dict(row) for index, row in enumerate(trace) if index != sampled[-1]]
    cut.append({"cycle": trace[-1]["cycle"] + 1, "sck": "0", "cs": "1",
                "mosi": "0", "miso": "0"})
    return decode(cut, (FRAME_ONE,))


def _probe_frame_wider_than_declared():
    trace, _ = spi_trajectory((FRAME_ONE,), bits=9)
    return decode(trace, (FRAME_ONE,), bits=8)


def _probe_declared_width_smaller_than_the_frame():
    trace, _ = spi_trajectory((FRAME_ONE,))
    return decode(trace, (FRAME_ONE,), bits=4)


def _closing_row(trace, *, cs_active_low=1):
    """The index of the row that ends the first selection."""
    selected = str(1 - cs_active_low)
    opened = next(index for index, row in enumerate(trace) if row["cs"] == selected)
    return next(index for index in range(opened + 1, len(trace))
                if trace[index]["cs"] != selected)


def _probe_clock_edge_while_deselected():
    trace, _ = spi_trajectory(MULTI_WORDS)
    closing = _closing_row(trace)
    rows = ([dict(row) for row in trace[:closing + 1]] +
            [{"sck": "1", "cs": trace[closing]["cs"], "mosi": "0", "miso": "0"},
             {"sck": "0", "cs": trace[closing]["cs"], "mosi": "0", "miso": "0"}] +
            [dict(row) for row in trace[closing + 1:]])
    for index, row in enumerate(rows):
        row["cycle"] = index
    return decode(rows, MULTI_WORDS)


def _probe_unknown_wire_level():
    trace, _ = spi_trajectory((FRAME_ONE,))
    trace[3]["mosi"] = "x"
    return decode(trace, (FRAME_ONE,))


def _probe_selection_not_closed():
    trace, _ = spi_trajectory((FRAME_ONE,))
    return decode(trace[:6], (FRAME_ONE,))


def _probe_wire_trace_missing():
    return decode([], (FRAME_ONE,))


def _probe_wire_trace_truncated():
    trace, _ = spi_trajectory((FRAME_ONE,), start=10)
    return run_audit(trace, writes=(cpu_write(6, FRAME_ONE[0]),), arms=((8, FRAME_ONE[1]),),
                     truncated=True)


def _probe_wire_trace_status_absent():
    trace, _ = spi_trajectory((FRAME_ONE,), start=10)
    return run_audit(trace, writes=(cpu_write(6, FRAME_ONE[0]),), arms=((8, FRAME_ONE[1]),),
                     status=())


def _probe_contract_norm_missing():
    trace, _ = spi_trajectory((FRAME_ONE,), start=10)
    return run_audit(trace, writes=(cpu_write(6, FRAME_ONE[0]),), arms=((8, FRAME_ONE[1]),),
                     build=audit_build(contract=False))


def _probe_cpu_source_not_owned():
    trace, _ = spi_trajectory((FRAME_ONE,), start=10)
    return run_audit(trace, writes=(cpu_write(6, FRAME_ONE[0]),), arms=((8, FRAME_ONE[1]),),
                     build=audit_build(cpu_sources=()))


def _probe_cpu_write_missing():
    trace, _ = spi_trajectory((FRAME_ONE,), start=10)
    return run_audit(trace, arms=((8, FRAME_ONE[1]),))


def _probe_cpu_write_after_selection():
    trace, _ = spi_trajectory((FRAME_ONE,), start=10)
    return run_audit(trace, writes=(cpu_write(40, FRAME_ONE[0]),), arms=((8, FRAME_ONE[1]),))


def _probe_write_without_byte_enables():
    trace, _ = spi_trajectory((FRAME_ONE,), start=10)
    return run_audit(trace, writes=(cpu_write(6, FRAME_ONE[0], be=0x0),),
                     arms=((8, FRAME_ONE[1]),))


def _probe_continuous_selection_run_audit():
    trace, _ = spi_trajectory(MULTI_WORDS, one_selection=True, start=10)
    return run_audit(trace, writes=(cpu_write(6, FRAME_ONE[0]),), arms=((8, FRAME_ONE[1]),))


# ---------------------------------------------------------------------------
# the frozen scope table
# ---------------------------------------------------------------------------

SCOPE_KEYS = ("admitted", "expectation", "trajectory", "injection",
              "observed", "required", "reason", "probe")

SPI_SCOPE: dict[str, dict[str, object]] = {
    "single-word-four-wire": {
        "admitted": True,
        "expectation": "the caller's literal words (mosi from the TXDATA write, miso from the arm)",
        "trajectory": "spi_trajectory((FRAME_ONE,)) - one complete selection, four wires",
        "injection": "sampling-edge bit flip, short frame, word substitution",
        "observed": "pass", "required": "pass",
        "reason": "one frame per chip-select assertion is the incumbent admitted behaviour",
        "probe": _probe_single_word,
    },
    "multi-word-consecutive-transfers": {
        "admitted": True,
        "expectation": "both words this module wrote, in selection order",
        "trajectory": "spi_trajectory(MULTI_WORDS) - two complete selections, decoded in order",
        "injection": "second-word bit flip, word-order swap, dropped second selection, "
                     "chip select released mid-word, clock edge between words, unknown level",
        "observed": "pass", "required": "pass",
        "reason": "the frozen decoder decodes exactly one frame per selection and concatenates them",
        "probe": _probe_multi_word,
    },
    "four-cpol-cpha-modes": {
        "admitted": True,
        "expectation": "the same two literals per mode, with the mode's own sampling edge",
        "trajectory": "spi_trajectory(..., cpol=m, cpha=m) for each of the four declared modes",
        "injection": "declared CPHA inverted, declared CPOL inverted",
        "observed": "pass", "required": "pass",
        "reason": "each mode is a declared parameter with its own shift/sample edge discipline",
        "probe": _probe_four_modes,
    },
    "both-chip-select-polarities": {
        "admitted": True,
        "expectation": "the same literals under CS_ACTIVE_LOW=0 and CS_ACTIVE_LOW=1",
        "trajectory": "spi_trajectory(..., cs_active_low=p) for both p",
        "injection": "declared CS polarity inverted",
        "observed": "pass", "required": "pass",
        "reason": "the peer declares CS_ACTIVE_LOW as a parameter and the decoder is given it",
        "probe": _probe_both_cs_polarities,
    },
    "multi-word-at-the-run-audit-layer": {
        "admitted": False,
        "expectation": "none - the run audit refuses to build one",
        "trajectory": "a complete two-selection trajectory with two TXDATA writes and two arms",
        "injection": "a second accepted write and arm in the same run",
        "observed": "not_assessed", "required": "not_assessed",
        "reason": "only one accepted write and one peer arm are supported",
        "probe": _probe_multi_word_run_audit,
    },
    "continuous-cs-multi-word-one-selection": {
        "admitted": False,
        "expectation": "none - refused by the frozen decoder",
        "trajectory": "spi_trajectory(MULTI_WORDS, one_selection=True)",
        "injection": "two words clocked inside a single chip-select assertion",
        "observed": "mismatch", "required": "not_assessed",
        "reason": "the frozen decoder decodes exactly one frame per chip-select assertion, so a "
                  "second word inside the same selection exceeds the declared width and is "
                  "reported as the defect spi-too-many-sample-edges; the admitted component "
                  "deasserts its chip select per frame, so no admitted producer creates this "
                  "stream either",
        "probe": _probe_continuous_selection,
    },
    "cpha-one-frame-declared-as-cpha-zero": {
        "admitted": False,
        "expectation": "none - the frozen decoder cannot separate the two",
        "trajectory": "spi_trajectory((FRAME_ONE,), cpha=1) decoded with cpha=0",
        "injection": "a CPHA=1 master with a CPHA=0 declaration",
        "observed": "pass", "required": "not_assessed",
        "reason": "a CPHA=1 frame holds every data bit across both clock edges, so a leading-edge "
                  "sampler reads exactly the bits a trailing-edge sampler reads; the frozen "
                  "data-comparison criterion cannot see this declaration error (the opposite "
                  "direction, a CPHA=0 frame declared CPHA=1, is a mismatch)",
        "probe": _probe_cpha_one_declared_as_zero,
    },
    "cpol-inversion": {
        "admitted": False,
        "expectation": "none - the wire never leaves the declared idle level contract",
        "trajectory": "spi_trajectory((FRAME_ONE,), cpol=0) decoded with cpol=1",
        "injection": "a master that idles the clock at the wrong level",
        "observed": "not_assessed", "required": "not_assessed",
        "reason": "spi-wire-initial-idle-missing: the frozen decoder refuses to assess a trace "
                  "that does not start at the declared idle level, so it makes no defect claim "
                  "for a wrongly inverted clock either",
        "probe": _probe_cpol_inversion,
    },
    "cs-polarity-inversion": {
        "admitted": False,
        "expectation": "none - the first row is not at the declared deselected level",
        "trajectory": "spi_trajectory((FRAME_ONE,), cs_active_low=0) decoded with cs_active_low=1",
        "injection": "a chip select wired with the opposite polarity",
        "observed": "not_assessed", "required": "not_assessed",
        "reason": "spi-wire-initial-idle-missing: the decoder refuses the trace instead of "
                  "claiming a defect",
        "probe": _probe_cs_polarity_inversion,
    },
    "frame-shorter-than-the-declared-width": {
        "admitted": False,
        "expectation": "the declared BITS against a selection that carried fewer sample edges",
        "trajectory": "a complete selection with its final sampling edge removed",
        "injection": "seven sample edges in a selection declared as eight bits",
        "observed": "mismatch", "required": "mismatch",
        "reason": "spi-incomplete-frame: a selection that ends with a partial frame is a defect",
        "probe": _probe_frame_shorter_than_declared,
    },
    "frame-wider-than-the-declared-width": {
        "admitted": False,
        "expectation": "the declared BITS against a selection that carried more sample edges",
        "trajectory": "spi_trajectory((FRAME_ONE,), bits=9) decoded with bits=8",
        "injection": "nine sample edges in a selection declared as eight bits",
        "observed": "mismatch", "required": "mismatch",
        "reason": "spi-too-many-sample-edges: the selection is over-clocked for the declared frame",
        "probe": _probe_frame_wider_than_declared,
    },
    "declared-width-smaller-than-the-wire-frame": {
        "admitted": False,
        "expectation": "the declared BITS against an eight-bit wire frame",
        "trajectory": "spi_trajectory((FRAME_ONE,)) decoded with bits=4",
        "injection": "a profile whose declared BITS is not the frame on the wire",
        "observed": "mismatch", "required": "mismatch",
        "reason": "spi-too-many-sample-edges: the declared width is not approximated, the "
                  "disagreement is reported",
        "probe": _probe_declared_width_smaller_than_the_frame,
    },
    "clock-edge-while-deselected": {
        "admitted": False,
        "expectation": "no transfer is defined between two selections",
        "trajectory": "the two-word trajectory with a clock edge spliced in while deselected",
        "injection": "a clock glitch between the two words",
        "observed": "mismatch", "required": "mismatch",
        "reason": "spi-deselected-clock: a clock transition outside a selection is a defect",
        "probe": _probe_clock_edge_while_deselected,
    },
    "unknown-wire-level": {
        "admitted": False,
        "expectation": "none - an unknown level cannot be compared with a literal",
        "trajectory": "a complete trajectory with one wire reading x",
        "injection": "an unrepresentable level on a data wire",
        "observed": "not_assessed", "required": "not_assessed",
        "reason": "spi-wire-unknown:<row>:mosi - an unknown level never becomes a passing transfer",
        "probe": _probe_unknown_wire_level,
    },
    "selection-not-closed": {
        "admitted": False,
        "expectation": "none - no frame boundary exists to compare against",
        "trajectory": "a trajectory truncated inside its first selection",
        "injection": "the recorded trace ends while the chip select is still asserted",
        "observed": "not_assessed", "required": "not_assessed",
        "reason": "spi-selection-not-closed: a selection that never ends is not assessed",
        "probe": _probe_selection_not_closed,
    },
    "wire-trace-missing": {
        "admitted": False,
        "expectation": "none - there are no wire samples",
        "trajectory": "the empty trajectory",
        "injection": "the runtime records no SPI wires at all",
        "observed": "not_assessed", "required": "not_assessed",
        "reason": "spi-wire-trace-missing: without a waveform nothing is claimed",
        "probe": _probe_wire_trace_missing,
    },
    "wire-trace-truncated": {
        "admitted": False,
        "expectation": "none - the recorded trace is incomplete",
        "trajectory": "a complete trajectory whose status row is marked truncated",
        "injection": "the wire recorder overflows and says so",
        "observed": "not_assessed", "required": "not_assessed",
        "reason": "SPI wire trace is missing, truncated or incomplete",
        "probe": _probe_wire_trace_truncated,
    },
    "wire-trace-status-absent": {
        "admitted": False,
        "expectation": "none - the completeness of the trace cannot be established",
        "trajectory": "a complete trajectory with no status row at all",
        "injection": "the runtime omits the wire summary",
        "observed": "not_assessed", "required": "not_assessed",
        "reason": "SPI wire trace is missing, truncated or incomplete",
        "probe": _probe_wire_trace_status_absent,
    },
    "spi-contract-norm-missing": {
        "admitted": False,
        "expectation": "none - no independent TXDATA register norm was supplied",
        "trajectory": "a complete trajectory with an empty spi_wire_contracts",
        "injection": "a build without the independent register norm",
        "observed": "not_assessed", "required": "not_assessed",
        "reason": "independent SPI TXDATA register norm is missing",
        "probe": _probe_contract_norm_missing,
    },
    "cpu-data-source-not-owned": {
        "admitted": False,
        "expectation": "none - ownership of the accepted write is not recorded",
        "trajectory": "a complete trajectory with no cpu_data source in the fabric",
        "injection": "a write whose source the plan does not own",
        "observed": "not_assessed", "required": "not_assessed",
        "reason": "CPU data source ownership is not recorded",
        "probe": _probe_cpu_source_not_owned,
    },
    "cpu-write-missing": {
        "admitted": False,
        "expectation": "none - the word the master was told to send is not recorded",
        "trajectory": "a complete trajectory with no accepted TXDATA write",
        "injection": "the accepted-write trace does not contain the transfer",
        "observed": "not_assessed", "required": "not_assessed",
        "reason": "accepted CPU TXDATA write is not recorded",
        "probe": _probe_cpu_write_missing,
    },
    "cpu-write-after-selection-starts": {
        "admitted": False,
        "expectation": "none - the write cannot have caused this selection",
        "trajectory": "a complete trajectory whose TXDATA write lands after the selection opened",
        "injection": "a write that does not precede the selection it is compared with",
        "observed": "not_assessed", "required": "not_assessed",
        "reason": "CPU write or peer arm did not precede selection",
        "probe": _probe_cpu_write_after_selection,
    },
    "cpu-write-without-byte-enables": {
        "admitted": False,
        "expectation": "none - the write did not drive any byte of the declared word",
        "trajectory": "a complete trajectory with a TXDATA write whose byte enables are zero",
        "injection": "a TXDATA write that enables none of the word's bytes",
        "observed": "not_assessed", "required": "not_assessed",
        "reason": "CPU TXDATA byte enables do not cover the word",
        "probe": _probe_write_without_byte_enables,
    },
    "continuous-selection-at-the-run-audit-layer": {
        "admitted": False,
        "expectation": "none - refused before the decoder is reached",
        "trajectory": "one continuous selection with a single write and a single arm",
        "injection": "a burst of two words declared as a single transfer",
        "observed": "mismatch", "required": "not_assessed",
        "reason": "the run audit has one write and one arm, so it does reach the decoder, and the "
                  "decoder reports the legitimate burst as the defect "
                  "spi-too-many-sample-edges: a whole-package defect claim where the honest "
                  "answer is not_assessed",
        "probe": _probe_continuous_selection_run_audit,
    },
    "word-select-framing-daisy-chain-wait-states-fifo-electrical": {
        "admitted": False,
        "expectation": "none - no criterion is registered for any of them",
        "trajectory": "none - they are outside the four recorded wires",
        "injection": "none - nothing observes them",
        "observed": "not_assessed", "required": "not_assessed",
        "reason": "soc_spi_peer.sv declares word sizes above one parameterized frame with a word "
                  "select, daisy chains, dual-edge or delayed modes, wait states, FIFOs and every "
                  "electrical property of the pins deliberately not modelled, and neither the "
                  "runtime nor the oracle records evidence for them",
        "probe": None,
    },
}

#: Scope entries whose shipped classification is not the status the plan requires.
#: Every label is a verbatim fragment of the entry's own ``reason``.
FROZEN_GAPS = {
    "continuous-cs-multi-word-one-selection":
        "reported as the defect spi-too-many-sample-edges",
    "cpha-one-frame-declared-as-cpha-zero":
        "cannot see this declaration error",
    "continuous-selection-at-the-run-audit-layer":
        "a whole-package defect claim where the honest answer is not_assessed",
}


# ---------------------------------------------------------------------------
# the scope freeze
# ---------------------------------------------------------------------------


class SpiScopeFreezeTests(unittest.TestCase):
    """Every scope decision is recorded, re-checked and (if wrong) named."""

    def test_the_scope_is_frozen_with_one_well_formed_entry_per_behaviour(self) -> None:
        self.assertTrue(SPI_SCOPE)
        for name, entry in SPI_SCOPE.items():
            with self.subTest(behaviour=name):
                self.assertEqual(set(SCOPE_KEYS), set(entry), entry)
                self.assertIsInstance(entry["admitted"], bool)
                self.assertIn(entry["observed"], ("pass", "mismatch", "not_assessed"))
                self.assertIn(entry["required"], ("pass", "mismatch", "not_assessed"))
                self.assertTrue(str(entry["reason"]).strip(), entry)
                self.assertTrue(str(entry["expectation"]).strip(), entry)
                self.assertTrue(str(entry["trajectory"]).strip(), entry)
                self.assertTrue(str(entry["injection"]).strip(), entry)
                if entry["admitted"]:
                    self.assertEqual("pass", entry["required"], entry)
                    self.assertIsNotNone(entry["probe"], entry)

    def test_every_admitted_behaviour_names_a_criterion_a_trajectory_and_an_injection(self) -> None:
        admitted = [name for name, entry in SPI_SCOPE.items() if entry["admitted"]]
        self.assertEqual(
            ["single-word-four-wire", "multi-word-consecutive-transfers",
             "four-cpol-cpha-modes", "both-chip-select-polarities"], admitted)

    def test_every_refused_behaviour_names_a_specific_reason(self) -> None:
        for name, entry in SPI_SCOPE.items():
            if entry["admitted"]:
                continue
            with self.subTest(behaviour=name):
                self.assertTrue(str(entry["reason"]).strip(), entry)
                # A refusal may not be recorded as a passing behaviour unless the
                # gap is named: that is the whole point of the table.
                if entry["observed"] == "pass":
                    self.assertIn(name, FROZEN_GAPS, entry)

    def test_the_scope_classification_still_matches_the_frozen_criterion(self) -> None:
        for name, entry in SPI_SCOPE.items():
            probe = entry["probe"]
            if probe is None:
                continue
            with self.subTest(behaviour=name):
                verdict = probe()
                self.assertEqual(entry["observed"], verdict["status"],
                                 "%s: %s" % (name, verdict))

    def test_every_refused_probe_carries_a_reason(self) -> None:
        for name, entry in SPI_SCOPE.items():
            probe = entry["probe"]
            if probe is None or entry["observed"] == "pass":
                continue
            with self.subTest(behaviour=name):
                self.assertTrue(str(probe()["reason"]).strip(), entry)

    def test_every_deviation_from_the_plan_rule_is_a_named_gap(self) -> None:
        deviations = {name for name, entry in SPI_SCOPE.items()
                      if entry["observed"] != entry["required"]}
        self.assertEqual(deviations, set(FROZEN_GAPS))
        for name, reason in FROZEN_GAPS.items():
            with self.subTest(behaviour=name):
                self.assertIn(name, SPI_SCOPE)
                self.assertTrue(str(reason).strip())
                self.assertIn(str(reason), str(SPI_SCOPE[name]["reason"]))

    def test_the_expected_words_are_this_modules_literals_not_the_wire(self) -> None:
        trace, _ = spi_trajectory((FRAME_ONE,))
        right = decode(trace, (FRAME_ONE,))
        wrong = decode(trace, ((FRAME_ONE[0] ^ 0xFF, FRAME_ONE[1]),))
        self.assertEqual("pass", right["status"], right)
        self.assertEqual("mismatch", wrong["status"], wrong)
        # The wire said the same thing both times: only the caller's literal moved.
        self.assertEqual(one_word(right), one_word(wrong))
        self.assertEqual([FRAME_ONE[0]], wrong["observed_mosi_words"])

    def test_the_run_audit_spi_check_ignores_the_peers_own_counters(self) -> None:
        trace, _ = spi_trajectory((FRAME_ONE,), start=10)
        base = audit_peer_run(audit_build(), audit_sample(((8, FRAME_ONE[1]),)),
                              audit_result(trace, writes=(cpu_write(6, FRAME_ONE[0]),),
                                           arms=((8, FRAME_ONE[1]),)))
        noisy = audit_result(trace, writes=(cpu_write(6, FRAME_ONE[0]),),
                             arms=((8, FRAME_ONE[1]),))
        noisy.counters = {"peer.spi0.rx_count_o": 99, "peer.spi0.clock_count_o": 0}
        noisy.observations = {"spi0__rx_count_o": 99, "spi0__rx_data_o": 0x00}
        other = audit_peer_run(audit_build(), audit_sample(((8, FRAME_ONE[1]),)), noisy)
        self.assertEqual(spi_verdict(base), spi_verdict(other))
        self.assertEqual({"mosi": [FRAME_ONE[0]], "miso": [FRAME_ONE[1]]},
                         spi_verdict(base)["expected"])

    def test_the_byte_enable_guard_is_not_dead_code(self) -> None:
        """``&`` binds tighter than ``!=`` in Python, so the guard really fires.

        Reviewed because the obvious C reading of this expression is the opposite
        one, and a dead guard would silently accept a write that drove no byte.
        """
        required = 0xFF
        self.assertTrue(bool(0x01 & required != required),
                        "a byte enable outside the required mask must trip the guard")
        self.assertFalse(bool(required & required != required))


# ---------------------------------------------------------------------------
# multi-word trajectories
# ---------------------------------------------------------------------------


class SpiMultiWordTrajectoryTests(unittest.TestCase):
    """A complete multi-word trajectory, its independent expectation and injections."""

    def test_a_two_word_trajectory_decodes_both_words_in_order_in_every_mode(self) -> None:
        for cpol, cpha in SPI_MODES:
            with self.subTest(cpol=cpol, cpha=cpha):
                trace, sampled = spi_trajectory(MULTI_WORDS, cpol=cpol, cpha=cpha)
                verdict = decode(trace, MULTI_WORDS, cpol=cpol, cpha=cpha)
                self.assertEqual("pass", verdict["status"], verdict)
                self.assertEqual(2 * 8, len(sampled))
                self.assertEqual(one_word(verdict),
                                 ([word[0] for word in MULTI_WORDS],
                                  [word[1] for word in MULTI_WORDS]))

    def test_a_three_word_trajectory_decodes_all_three_words(self) -> None:
        trace, sampled = spi_trajectory(THREE_WORDS)
        verdict = decode(trace, THREE_WORDS)
        self.assertEqual("pass", verdict["status"], verdict)
        self.assertEqual(3 * 8, len(sampled))
        self.assertEqual([word[0] for word in THREE_WORDS], verdict["observed_mosi_words"])
        self.assertEqual([word[1] for word in THREE_WORDS], verdict["observed_miso_words"])

    def test_the_word_order_is_the_selection_order_not_the_expected_order(self) -> None:
        trace, _ = spi_trajectory(MULTI_WORDS)
        verdict = decode(trace, (FRAME_TWO, FRAME_ONE))
        self.assertEqual("mismatch", verdict["status"], verdict)
        self.assertEqual("spi-transfer-data", verdict["reason"], verdict)

    def test_a_wrong_word_count_on_either_side_is_a_mismatch(self) -> None:
        two, _ = spi_trajectory(MULTI_WORDS)
        self.assertEqual("mismatch", decode(two, (FRAME_ONE,))["status"])
        self.assertEqual("mismatch", decode(two, THREE_WORDS)["status"])
        one, _ = spi_trajectory((FRAME_ONE,))
        self.assertEqual("mismatch", decode(one, MULTI_WORDS)["status"])

    def test_a_bit_flip_on_a_sampling_edge_in_the_second_word_is_a_mismatch(self) -> None:
        for cpol, cpha in SPI_MODES:
            with self.subTest(cpol=cpol, cpha=cpha):
                trace, sampled = spi_trajectory(MULTI_WORDS, cpol=cpol, cpha=cpha)
                injected = [dict(row) for row in trace]
                target = sampled[8 + 2]           # the third bit of the second word
                injected[target]["mosi"] = "1" if injected[target]["mosi"] == "0" else "0"
                verdict = decode(injected, MULTI_WORDS, cpol=cpol, cpha=cpha)
                self.assertEqual("mismatch", verdict["status"], verdict)
                self.assertEqual("spi-transfer-data", verdict["reason"], verdict)
                self.assertNotEqual(FRAME_TWO[0], verdict["observed_mosi_words"][1], verdict)

    def test_a_flip_away_from_every_sampling_edge_is_not_sampled(self) -> None:
        trace, sampled = spi_trajectory(MULTI_WORDS)
        selected = str(1 - 1)
        outside = [index for index, row in enumerate(trace)
                   if index not in sampled and row["cs"] == selected]
        self.assertTrue(outside)
        injected = [dict(row) for row in trace]
        injected[outside[1]]["miso"] = "1" if injected[outside[1]]["miso"] == "0" else "0"
        verdict = decode(injected, MULTI_WORDS)
        self.assertEqual("pass", verdict["status"], verdict)

    def test_releasing_the_chip_select_mid_word_is_an_incomplete_frame(self) -> None:
        for cpol, cpha in SPI_MODES:
            with self.subTest(cpol=cpol, cpha=cpha):
                trace, sampled = spi_trajectory(MULTI_WORDS, cpol=cpol, cpha=cpha)
                cut = [dict(row) for row in trace[:sampled[6]]]
                cut.append({"cycle": trace[-1]["cycle"] + 1, "sck": str(cpol), "cs": "1",
                            "mosi": "0", "miso": "0"})
                verdict = decode(cut, MULTI_WORDS, cpol=cpol, cpha=cpha)
                self.assertEqual("mismatch", verdict["status"], verdict)
                self.assertEqual("spi-incomplete-frame", verdict["reason"], verdict)

    def test_dropping_the_second_selection_is_a_mismatch(self) -> None:
        trace, _ = spi_trajectory(MULTI_WORDS)
        trimmed = [dict(row) for row in trace[:_closing_row(trace) + 1]]
        trimmed.append({"cycle": trace[-1]["cycle"] + 1, "sck": "0", "cs": "1",
                        "mosi": "0", "miso": "0"})
        verdict = decode(trimmed, MULTI_WORDS)
        self.assertEqual("mismatch", verdict["status"], verdict)
        self.assertEqual([FRAME_ONE[0]], verdict["observed_mosi_words"])

    def test_a_clock_edge_between_the_two_words_is_a_mismatch(self) -> None:
        verdict = _probe_clock_edge_while_deselected()
        self.assertEqual("mismatch", verdict["status"], verdict)
        self.assertEqual("spi-deselected-clock", verdict["reason"], verdict)

    def test_an_unknown_level_in_the_second_word_is_not_assessed(self) -> None:
        trace, sampled = spi_trajectory(MULTI_WORDS)
        trace[sampled[9]]["miso"] = "x"
        verdict = decode(trace, MULTI_WORDS)
        self.assertEqual("not_assessed", verdict["status"], verdict)
        self.assertTrue(verdict["reason"].startswith("spi-wire-unknown:"), verdict)

    def test_a_trajectory_that_never_ends_its_selection_is_not_assessed(self) -> None:
        trace, sampled = spi_trajectory((FRAME_ONE,))
        verdict = decode(trace[:sampled[3]], (FRAME_ONE,))
        self.assertEqual("not_assessed", verdict["status"], verdict)
        self.assertEqual("spi-selection-not-closed", verdict["reason"], verdict)


# ---------------------------------------------------------------------------
# the four CPOL/CPHA modes
# ---------------------------------------------------------------------------


class SpiModeCriterionTests(unittest.TestCase):
    """Each mode has its own expectation, and its own detectable declaration error."""

    def test_each_declared_mode_has_its_own_expectation_and_complete_trajectory(self) -> None:
        for cpol, cpha in SPI_MODES:
            with self.subTest(cpol=cpol, cpha=cpha):
                trace, sampled = spi_trajectory((FRAME_ONE,), cpol=cpol, cpha=cpha)
                verdict = decode(trace, (FRAME_ONE,), cpol=cpol, cpha=cpha)
                self.assertEqual("pass", verdict["status"], verdict)
                self.assertEqual(8, len(sampled))
                self.assertEqual([FRAME_ONE[0]], verdict["observed_mosi_words"])
                self.assertEqual([FRAME_ONE[1]], verdict["observed_miso_words"])
                # the trajectory really is that mode's: it idles at its own level
                self.assertEqual(str(cpol), trace[0]["sck"])

    def test_the_same_wire_decodes_differently_under_each_declared_cpha(self) -> None:
        trace, _ = spi_trajectory((FRAME_ONE,), cpol=0, cpha=0)
        right = decode(trace, (FRAME_ONE,), cpol=0, cpha=0)
        shifted = decode(trace, (FRAME_ONE,), cpol=0, cpha=1)
        self.assertEqual("pass", right["status"], right)
        self.assertEqual("mismatch", shifted["status"], shifted)
        self.assertEqual("spi-transfer-data", shifted["reason"], shifted)
        # Sampling one edge later reads the bit the shifter presents next.
        self.assertEqual([0x4A], shifted["observed_mosi_words"], shifted)
        self.assertEqual([0xB4], shifted["observed_miso_words"], shifted)

    def test_a_cpha_declaration_that_disagrees_with_a_cpha_zero_frame_is_a_mismatch(self) -> None:
        for cpol in (0, 1):
            with self.subTest(cpol=cpol):
                trace, _ = spi_trajectory((FRAME_ONE,), cpol=cpol, cpha=0)
                verdict = decode(trace, (FRAME_ONE,), cpol=cpol, cpha=1)
                self.assertEqual("mismatch", verdict["status"], verdict)

    def test_a_cpha_one_frame_declared_as_cpha_zero_is_not_detected_known_gap(self) -> None:
        """Pins the recorded gap: this direction really is indistinguishable."""
        verdict = _probe_cpha_one_declared_as_zero()
        self.assertEqual("pass", verdict["status"], verdict)
        self.assertEqual([FRAME_ONE[0]], verdict["observed_mosi_words"])
        self.assertEqual("cpha-one-frame-declared-as-cpha-zero",
                         next(name for name, entry in SPI_SCOPE.items()
                              if entry["probe"] is _probe_cpha_one_declared_as_zero))
        self.assertIn("holds every data bit across both clock edges",
                      SPI_SCOPE["cpha-one-frame-declared-as-cpha-zero"]["reason"])

    def test_a_cpol_declaration_that_disagrees_with_the_idle_level_is_not_assessed(self) -> None:
        for cpol in (0, 1):
            with self.subTest(cpol=cpol):
                trace, _ = spi_trajectory((FRAME_ONE,), cpol=cpol)
                verdict = decode(trace, (FRAME_ONE,), cpol=1 - cpol)
                self.assertEqual("not_assessed", verdict["status"], verdict)
                self.assertEqual("spi-wire-initial-idle-missing", verdict["reason"], verdict)

    def test_a_chip_select_polarity_that_disagrees_with_the_wire_is_not_assessed(self) -> None:
        for cs_active_low in (0, 1):
            with self.subTest(cs_active_low=cs_active_low):
                trace, _ = spi_trajectory((FRAME_ONE,), cs_active_low=cs_active_low)
                verdict = decode(trace, (FRAME_ONE,), cs_active_low=1 - cs_active_low)
                self.assertEqual("not_assessed", verdict["status"], verdict)
                self.assertEqual("spi-wire-initial-idle-missing", verdict["reason"], verdict)

    def test_both_chip_select_polarities_decode_the_same_words(self) -> None:
        for cs_active_low in (0, 1):
            with self.subTest(cs_active_low=cs_active_low):
                trace, _ = spi_trajectory(MULTI_WORDS, cs_active_low=cs_active_low)
                verdict = decode(trace, MULTI_WORDS, cs_active_low=cs_active_low)
                self.assertEqual("pass", verdict["status"], verdict)
                self.assertEqual([word[0] for word in MULTI_WORDS],
                                 verdict["observed_mosi_words"])

    def test_the_incumbent_idealized_trajectory_cannot_see_a_cpha_error(self) -> None:
        """Why this module needs an edge-realistic builder instead of ``_frame``."""
        idealized = incumbent_trajectory(mosi=FRAME_ONE[0], miso=FRAME_ONE[1], cpol=0)
        self.assertEqual("pass", decode(idealized, (FRAME_ONE,), cpol=0, cpha=0)["status"])
        self.assertEqual("pass", decode(idealized, (FRAME_ONE,), cpol=0, cpha=1)["status"])
        realistic, _ = spi_trajectory((FRAME_ONE,), cpol=0, cpha=0)
        self.assertEqual("mismatch", decode(realistic, (FRAME_ONE,), cpol=0, cpha=1)["status"])


# ---------------------------------------------------------------------------
# continuous chip select
# ---------------------------------------------------------------------------


class SpiContinuousSelectionTests(unittest.TestCase):
    """The one behaviour the plan admits that the frozen criterion does not."""

    def test_a_continuous_selection_is_never_a_pass(self) -> None:
        for cpol, cpha in SPI_MODES:
            with self.subTest(cpol=cpol, cpha=cpha):
                trace, sampled = spi_trajectory(MULTI_WORDS, cpol=cpol, cpha=cpha,
                                                one_selection=True)
                verdict = decode(trace, MULTI_WORDS, cpol=cpol, cpha=cpha)
                self.assertNotEqual("pass", verdict["status"], verdict)
                self.assertEqual(2 * 8, len(sampled))

    def test_a_continuous_selection_is_reported_as_a_defect_not_as_unassessed(self) -> None:
        verdict = _probe_continuous_selection()
        self.assertEqual("mismatch", verdict["status"], verdict)
        self.assertEqual("spi-too-many-sample-edges", verdict["reason"], verdict)

    def test_the_scope_records_the_continuous_selection_gap_with_a_specific_reason(self) -> None:
        entry = SPI_SCOPE["continuous-cs-multi-word-one-selection"]
        self.assertFalse(entry["admitted"])
        self.assertEqual("not_assessed", entry["required"])
        self.assertEqual("mismatch", entry["observed"])
        self.assertIn("exactly one frame per chip-select assertion", entry["reason"])
        self.assertIn("deasserts its chip select per frame", entry["reason"])
        self.assertIn("continuous-cs-multi-word-one-selection", FROZEN_GAPS)

    def test_the_run_audit_refuses_a_continuous_selection_declared_by_two_writes(self) -> None:
        trace, _ = spi_trajectory(MULTI_WORDS, one_selection=True, start=10)
        verdict = run_audit(trace,
                            writes=(cpu_write(6, FRAME_ONE[0]), cpu_write(106, FRAME_TWO[0])),
                            arms=((8, FRAME_ONE[1]), (108, FRAME_TWO[1])))
        self.assertEqual("not_assessed", verdict["status"], verdict)
        self.assertEqual("only one accepted write and one peer arm are supported",
                         verdict["reason"], verdict)

    def test_a_continuous_selection_with_one_write_becomes_a_package_defect_claim(self) -> None:
        verdict = _probe_continuous_selection_run_audit()
        self.assertEqual("mismatch", verdict["status"], verdict)
        self.assertEqual("spi-too-many-sample-edges", verdict["reason"], verdict)


# ---------------------------------------------------------------------------
# the run-audit layer's admission boundary
# ---------------------------------------------------------------------------


class SpiRunAuditAdmissionTests(unittest.TestCase):
    """What the run audit admits, and the specific reason it gives for the rest."""

    def test_one_accepted_write_and_one_arm_passes_the_wire_check(self) -> None:
        verdict = run_audit(spi_trajectory((FRAME_ONE,), start=10)[0],
                            writes=(cpu_write(6, FRAME_ONE[0]),), arms=((8, FRAME_ONE[1]),))
        self.assertEqual("pass", verdict["status"], verdict)
        self.assertEqual("spi-transfer-verified", verdict["reason"], verdict)
        self.assertEqual({"mosi": [FRAME_ONE[0]], "miso": [FRAME_ONE[1]]}, verdict["expected"])

    def test_two_accepted_writes_are_refused_with_the_multi_word_reason(self) -> None:
        verdict = _probe_multi_word_run_audit()
        self.assertEqual("not_assessed", verdict["status"], verdict)
        self.assertEqual("only one accepted write and one peer arm are supported",
                         verdict["reason"], verdict)

    def test_the_run_layer_reasons_are_the_specific_ones_the_scope_requires(self) -> None:
        cases = (
            ("wire-trace-truncated", _probe_wire_trace_truncated()),
            ("wire-trace-status-absent", _probe_wire_trace_status_absent()),
            ("spi-contract-norm-missing", _probe_contract_norm_missing()),
            ("cpu-data-source-not-owned", _probe_cpu_source_not_owned()),
            ("cpu-write-missing", _probe_cpu_write_missing()),
            ("cpu-write-after-selection-starts", _probe_cpu_write_after_selection()),
            ("cpu-write-without-byte-enables", _probe_write_without_byte_enables()),
        )
        for name, verdict in cases:
            with self.subTest(behaviour=name):
                self.assertEqual("not_assessed", verdict["status"], verdict)
                self.assertEqual(SPI_SCOPE[name]["reason"], verdict["reason"], verdict)

    def test_a_declared_mode_that_disagrees_with_the_wire_is_a_mismatch_here(self) -> None:
        trace, _ = spi_trajectory((FRAME_ONE,), start=10)
        build = audit_build(parameters={"BITS": 8, "CPOL": 0, "CPHA": 1, "CS_ACTIVE_LOW": 1})
        verdict = run_audit(trace, writes=(cpu_write(6, FRAME_ONE[0]),),
                            arms=((8, FRAME_ONE[1]),), build=build)
        self.assertEqual("mismatch", verdict["status"], verdict)
        self.assertEqual("spi-transfer-data", verdict["reason"], verdict)

    def test_the_wire_check_is_the_only_spi_claim_the_run_layer_makes(self) -> None:
        trace, _ = spi_trajectory((FRAME_ONE,), start=10)
        audit = audit_peer_run(audit_build(), audit_sample(((8, FRAME_ONE[1]),)),
                               audit_result(trace, writes=(cpu_write(6, FRAME_ONE[0]),),
                                            arms=((8, FRAME_ONE[1]),)))
        claimed = [check["check_id"] for check in audit["checks"]
                   if str(check["check_id"]).startswith("spi")]
        self.assertEqual(["spi-transfer-wire"], claimed)
        self.assertEqual([], [entry["check_id"] for entry in audit["unassessed"]
                              if str(entry["check_id"]).startswith("spi")])


# ---------------------------------------------------------------------------
# the incumbent idealized trajectory still holds
# ---------------------------------------------------------------------------


class SpiIncumbentTrajectoryTests(unittest.TestCase):
    """The already-covered single-word behaviour keeps its verdicts."""

    def check(self, trace, words=(FRAME_ONE,), **kwargs):
        return decode(trace, words, **kwargs)

    def test_the_incumbent_trajectory_passes_in_all_four_modes(self) -> None:
        for cpol, cpha in SPI_MODES:
            with self.subTest(cpol=cpol, cpha=cpha):
                trace = incumbent_trajectory(mosi=FRAME_ONE[0], miso=FRAME_ONE[1], cpol=cpol)
                verdict = self.check(trace, cpol=cpol, cpha=cpha)
                self.assertEqual("pass", verdict["status"], verdict)
                self.assertEqual([FRAME_ONE[0]], verdict["observed_mosi_words"])
                self.assertEqual([FRAME_ONE[1]], verdict["observed_miso_words"])

    def test_the_incumbent_negatives_still_hold(self) -> None:
        flipped = incumbent_trajectory(mosi=FRAME_ONE[0] ^ 0x01, miso=FRAME_ONE[1], cpol=0)
        self.assertEqual("mismatch", self.check(flipped, cpol=0, cpha=0)["status"])
        deselected = incumbent_trajectory(mosi=FRAME_ONE[0], miso=FRAME_ONE[1], cpol=0)
        deselected.append({"cycle": 999, "sck": "1", "cs": "1", "mosi": "0", "miso": "0"})
        self.assertEqual("mismatch", self.check(deselected, cpol=0, cpha=0)["status"])
        self.assertEqual("not_assessed", self.check([], cpol=0, cpha=0)["status"])
        partial = incumbent_trajectory(mosi=FRAME_ONE[0], miso=FRAME_ONE[1], cpol=0)[:-5]
        self.assertNotEqual("pass", self.check(partial, cpol=0, cpha=0)["status"])


# ---------------------------------------------------------------------------
# the real RTL in every declared mode
# ---------------------------------------------------------------------------


class _SpiModeRealRuntimeMixin:
    """Independent criteria evaluated on the RTL's own recorded wires.

    The fixture builds one audited SoC per declared mode.  Every test here reads
    ``result.peer_wire_trace`` - the generated testbench's recording of the
    component's real ``sck``/``cs``/``mosi``/``miso`` pins - and compares it with
    words this test wrote, never with a peer counter.
    """

    # -- samples ------------------------------------------------------------

    def one_word_sample(self):
        return self.sample({
            4: ("spi0_win", SPI_TXDATA, 1, REAL_FRAME_ONE[0]),
            20: ("spi0_win", SPI_CTRL, 1, 0x1),
            120: ("spi0_win", SPI_STATUS, 0, 0),
            140: ("spi0_win", SPI_RXDATA, 0, 0),
        }, 180, events=(self.event("spi0", "spi.arm_byte", 10, REAL_FRAME_ONE[1]),),
            request_id=901)

    def two_word_sample(self):
        return self.sample({
            4: ("spi0_win", SPI_TXDATA, 1, REAL_WORDS[0][0]),
            20: ("spi0_win", SPI_CTRL, 1, 0x1),
            100: ("spi0_win", SPI_TXDATA, 1, REAL_WORDS[1][0]),
            120: ("spi0_win", SPI_CTRL, 1, 0x1),
            300: ("spi0_win", SPI_STATUS, 0, 0),
            320: ("spi0_win", SPI_RXDATA, 0, 0),
        }, 360, events=(self.event("spi0", "spi.arm_byte", 10, REAL_WORDS[0][1]),
                        self.event("spi0", "spi.arm_byte", 110, REAL_WORDS[1][1])),
            request_id=902)

    # -- helpers ------------------------------------------------------------

    def recorded_wires(self, result):
        return [dict(row) for row in result.peer_wire_trace
                if row.get("instance_id") == "spi0"]

    def recorded_status(self, result):
        return [dict(row) for row in result.peer_wire_status
                if row.get("instance_id") == "spi0"]

    def decode_recorded(self, trace, words, **overrides):
        parameters = {"bits": 8, "cpol": self.cpol, "cpha": self.cpha, "cs_active_low": 1}
        parameters.update(overrides)
        return decode(trace, words, **parameters)

    def sampled(self, trace):
        return sampling_rows(trace, cpol=self.cpol, cpha=self.cpha, cs_active_low=1)

    def closing_row(self, trace):
        """The index of the row that ends the first selection (active-low CS)."""
        opened = next(index for index, row in enumerate(trace) if row["cs"] == "0")
        return next(index for index in range(opened + 1, len(trace))
                    if trace[index]["cs"] != "0")

    def trimmed(self, trace, index):
        rows = [dict(row) for row in trace[:index + 1]]
        rows.append({"cycle": trace[-1]["cycle"] + 1, "sck": str(self.cpol),
                     "cs": "1", "mosi": "0", "miso": "0"})
        return rows

    # -- tests --------------------------------------------------------------

    def test_the_plan_declares_the_mode_this_class_built(self) -> None:
        peer = self.plan.peer("spi0")
        self.assertEqual(self.cpol, int(peer.parameter_values["CPOL"]))
        self.assertEqual(self.cpha, int(peer.parameter_values["CPHA"]))

    def test_one_word_run_records_a_complete_never_truncated_wire_trace(self) -> None:
        result = self.run_sample(self.one_word_sample())
        trace, status = self.recorded_wires(result), self.recorded_status(result)
        self.assertEqual(1, len(status), status)
        self.assertFalse(bool(status[0]["truncated"]), status)
        self.assertEqual(len(trace), int(status[0]["count"]), status)
        self.assertEqual(str(self.cpol), trace[0]["sck"], trace[:2])
        self.assertEqual("1", trace[0]["cs"], trace[:2])

    def test_the_recorded_trace_passes_the_independent_decoder_in_this_mode(self) -> None:
        result = self.run_sample(self.one_word_sample())
        trace = self.recorded_wires(result)
        self.assertEqual(8, len(self.sampled(trace)), trace)
        verdict = self.decode_recorded(trace, (REAL_FRAME_ONE,))
        self.assertEqual("pass", verdict["status"], verdict)
        self.assertEqual([REAL_FRAME_ONE[0]], verdict["observed_mosi_words"])
        self.assertEqual([REAL_FRAME_ONE[1]], verdict["observed_miso_words"])
        # the component's own receive register agrees, and is not the expectation
        self.assertEqual(REAL_FRAME_ONE[1],
                         self.reads(result, "spi0_win")[SPI_RXDATA])

    def test_two_word_run_decodes_both_words_and_ends_each_selection(self) -> None:
        result = self.run_sample(self.two_word_sample())
        trace = self.recorded_wires(result)
        verdict = self.decode_recorded(trace, REAL_WORDS)
        self.assertEqual("pass", verdict["status"], verdict)
        self.assertEqual([word[0] for word in REAL_WORDS], verdict["observed_mosi_words"])
        self.assertEqual([word[1] for word in REAL_WORDS], verdict["observed_miso_words"])
        # the admitted component ends every frame: two separate CS assertions,
        # which is why the continuous-select behaviour has no admitted producer
        selections = sum(1 for before, after in zip(trace, trace[1:])
                         if before["cs"] != "0" and after["cs"] == "0")
        self.assertEqual(2, selections, trace)

    def test_the_run_layer_makes_no_spi_claim_for_this_build_and_names_the_gap(self) -> None:
        """The incumbent fixture supplies no independent register norm.

        This is the honest state of the run layer for this build.  When the
        fixture (or another task) starts supplying a norm and a CPU data source,
        this test fails and the scope record has to be revisited.
        """
        self.assertEqual({}, dict(self.build.spi_wire_contracts))
        self.assertEqual((), tuple(self.build.cpu_data_sources))
        sample = self.one_word_sample()
        result = self.run_sample(sample)
        audit = audit_peer_run(self.build, sample, result)
        verdict = spi_verdict(audit)
        self.assertEqual("not_assessed", verdict["status"], verdict)
        self.assertEqual("independent SPI TXDATA register norm is missing",
                         verdict["reason"], verdict)
        self.assertNotIn("spi-transfer-wire", [check["check_id"] for check in audit["checks"]])

    def test_a_sample_edge_flip_on_the_recorded_trace_is_a_mismatch(self) -> None:
        trace = self.recorded_wires(self.run_sample(self.one_word_sample()))
        rows = self.sampled(trace)
        injected = [dict(row) for row in trace]
        target = rows[3]
        injected[target]["mosi"] = "1" if injected[target]["mosi"] == "0" else "0"
        verdict = self.decode_recorded(injected, (REAL_FRAME_ONE,))
        self.assertEqual("mismatch", verdict["status"], verdict)
        self.assertEqual("spi-transfer-data", verdict["reason"], verdict)

    def test_deleting_the_second_frame_from_the_recorded_trace_is_a_mismatch(self) -> None:
        trace = self.recorded_wires(self.run_sample(self.two_word_sample()))
        verdict = self.decode_recorded(self.trimmed(trace, self.closing_row(trace)), REAL_WORDS)
        self.assertEqual("mismatch", verdict["status"], verdict)
        self.assertEqual("spi-transfer-data", verdict["reason"], verdict)
        self.assertEqual([REAL_WORDS[0][0]], verdict["observed_mosi_words"])

    def test_a_short_frame_cut_from_the_recorded_trace_is_an_incomplete_frame(self) -> None:
        trace = self.recorded_wires(self.run_sample(self.one_word_sample()))
        rows = self.sampled(trace)
        verdict = self.decode_recorded(self.trimmed(trace, rows[-1] - 1), (REAL_FRAME_ONE,))
        self.assertEqual("mismatch", verdict["status"], verdict)
        self.assertEqual("spi-incomplete-frame", verdict["reason"], verdict)

    def test_the_verdict_follows_this_modules_literals_not_the_peer_observation(self) -> None:
        result = self.run_sample(self.one_word_sample())
        trace = self.recorded_wires(result)
        right = self.decode_recorded(trace, (REAL_FRAME_ONE,))
        wrong_word = (REAL_FRAME_ONE[0] ^ 0xFF, REAL_FRAME_ONE[1])
        wrong = self.decode_recorded(trace, (wrong_word,))
        self.assertEqual("pass", right["status"], right)
        self.assertEqual("mismatch", wrong["status"], wrong)
        self.assertEqual(one_word(right), one_word(wrong))
        # the peer's own count exists in the evidence and is deliberately not the
        # expectation: the verdict above came from the wire and the literal
        self.assertEqual(1, self.observation(result, "spi0__rx_count_o"))
        self.assertEqual(REAL_FRAME_ONE[0], self.observation(result, "spi0__rx_data_o"))

    def test_a_declared_cpha_that_disagrees_with_a_cpha_zero_run_is_a_mismatch(self) -> None:
        if self.cpha != 0:
            self.skipTest("this direction is only defined for a CPHA=0 build")
        trace = self.recorded_wires(self.run_sample(self.one_word_sample()))
        verdict = self.decode_recorded(trace, (REAL_FRAME_ONE,), cpha=1)
        self.assertEqual("mismatch", verdict["status"], verdict)
        self.assertEqual("spi-transfer-data", verdict["reason"], verdict)

    def test_a_declared_cpol_that_disagrees_with_the_idle_level_is_not_assessed(self) -> None:
        trace = self.recorded_wires(self.run_sample(self.one_word_sample()))
        verdict = self.decode_recorded(trace, (REAL_FRAME_ONE,), cpol=1 - self.cpol)
        self.assertEqual("not_assessed", verdict["status"], verdict)
        self.assertEqual("spi-wire-initial-idle-missing", verdict["reason"], verdict)


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real peer runtime")
class SpiMode0RealRuntimeTests(_SpiModeRealRuntimeMixin, peer_models.SpiPeerRuntimeTests):
    """CPOL=0/CPHA=0, reusing the incumbent mode-0 fixture and its own tests."""


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real peer runtime")
class SpiMode1RealRuntimeTests(_SpiModeRealRuntimeMixin, peer_models._PeerRuntimeFixture):
    """CPOL=0/CPHA=1."""

    cpol = 0
    cpha = 1


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real peer runtime")
class SpiMode2RealRuntimeTests(_SpiModeRealRuntimeMixin, peer_models._PeerRuntimeFixture):
    """CPOL=1/CPHA=0."""

    cpol = 1
    cpha = 0


@unittest.skipUnless(OPT_IN, "set MYFUZZ_SOC_REAL=1 for the real peer runtime")
class SpiMode3RealRuntimeTests(_SpiModeRealRuntimeMixin, peer_models.SpiMode3PeerRuntimeTests):
    """CPOL=1/CPHA=1, reusing the incumbent mode-3 fixture and its own test."""


if __name__ == "__main__":
    unittest.main()
