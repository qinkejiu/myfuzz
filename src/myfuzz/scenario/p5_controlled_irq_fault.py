"""Explicit calibration fault at the online checker's event delivery boundary.

The real RTL event journal is untouched. The selected checker receives a copy
of one witnessed GPIO B IRQ output with its two IRQ aliases forced low. This
is a deliberately corrupted observation, not a DUT failure or a causal-chain
certificate. Its static mode is included in the online checker identity.
"""

from __future__ import annotations

from dataclasses import replace
from collections.abc import Mapping

from .ibex_pulp_online_checker import IbexPulpOnlineChecker
from .session_runtime import OnlineCaseReceipt


class ControlledIrqOutputFaultChecker:
    """Calibrate the witnessed GPIO B IRQ-to-CPU source contradiction."""

    def __init__(self) -> None:
        self.fault_mode = "checker_input_irq_output_zero.v1"
        self._checker: IbexPulpOnlineChecker | None = None
        self._fault: dict | None = None

    @property
    def fault(self) -> dict | None:
        return None if self._fault is None else dict(self._fault)

    def __call__(self, receipt: OnlineCaseReceipt) -> tuple[str, ...]:
        if not isinstance(receipt, OnlineCaseReceipt):
            raise ValueError("OnlineCaseReceipt is required")
        if self._checker is None:
            self._checker = IbexPulpOnlineChecker()
        if self._fault is not None:
            return self._checker(receipt)

        last_irq_index: int | None = None
        trigger_ticks: set[int] = set()
        admissions: list[str] = []
        for index, event in enumerate(receipt.events):
            if not isinstance(event, Mapping):
                raise ValueError("online receipt contains a non-event")
            if event.get("kind") == "source_admission":
                admission = event.get("admission")
                if isinstance(admission, Mapping) and isinstance(
                        admission.get("admission_id"), str):
                    admissions.append(admission["admission_id"])
            if event.get("kind") == "gpio_irq_trigger" and event.get("component") == "gpio_b":
                tick = event.get("local_tick")
                if type(tick) is int:
                    trigger_ticks.add(tick)
            if event.get("component") == "gpio_b" and isinstance(event.get("outputs"), Mapping):
                outputs = event["outputs"]
                if type(outputs.get("irq", outputs.get("interrupt"))) is int:
                    last_irq_index = index
            if (event.get("kind") != "source_start"
                    or event.get("source") not in (["gpio_b", "irq"], ("gpio_b", "irq"))
                    or event.get("target") not in (["cpu", "irq"], ("cpu", "irq"))):
                continue
            tick = event.get("source_tick")
            if (last_irq_index is None or type(tick) is not int
                    or tick not in trigger_ticks):
                continue
            observed = receipt.events[last_irq_index]
            outputs = observed["outputs"]
            if (observed.get("local_tick") != tick
                    or outputs.get("irq", outputs.get("interrupt")) != 1
                    or ("irq" in outputs and "interrupt" in outputs
                        and outputs["irq"] != outputs["interrupt"])):
                continue
            mutated = list(receipt.events)
            altered = dict(observed)
            altered["outputs"] = {**outputs, **{name: 0 for name in ("irq", "interrupt")
                                                 if name in outputs}}
            mutated[last_irq_index] = altered
            provenance = event.get("provenance")
            provenance = provenance if isinstance(provenance, Mapping) else {}
            self._fault = {
                "mode": self.fault_mode,
                "observed_case_id": receipt.case_id,
                "observed_event_id": observed["event_id"],
                "source_start_event_id": event["event_id"],
                "source_tick": tick,
                "same_case_admission_ids": tuple(admissions),
                "source_origin_status": provenance.get("origin_status"),
                "source_origin_admission_ids": tuple(provenance.get("origin_admission_ids", ())),
                "original_irq": 1,
                "checker_input_irq": 0,
            }
            findings = self._checker(replace(receipt, events=tuple(mutated)))
            if "gpio_b_irq_source_mismatch" not in findings:
                raise ValueError("controlled IRQ fault did not reach expected checker invariant")
            return findings
        return self._checker(receipt)
