"""Calibrate a real UART read check by corrupting only checker input.

The persistent RTL journal and saved trace retain the actual CPU response.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace

from .ibex_uart_online_checker import IbexUartOnlineChecker
from .session_runtime import OnlineCaseReceipt


class ControlledUartReadFaultChecker:
    """Flip one witnessed CPU response after a matching UART RXDATA read."""

    def __init__(self) -> None:
        self.fault_mode = "checker_input_cpu_uart_rxdata_xor1.v1"
        self._checker: IbexUartOnlineChecker | None = None
        self._reads: dict[tuple[int, int], dict] = {}
        self._fault: dict | None = None

    @property
    def fault(self) -> dict | None:
        return None if self._fault is None else dict(self._fault)

    def __call__(self, receipt: OnlineCaseReceipt) -> tuple[str, ...]:
        if not isinstance(receipt, OnlineCaseReceipt):
            raise ValueError("OnlineCaseReceipt is required")
        if self._checker is None:
            self._checker = IbexUartOnlineChecker()
        if self._fault is not None:
            return self._checker(receipt)
        for index, event in enumerate(receipt.events):
            if not isinstance(event, Mapping):
                raise ValueError("online receipt contains a non-event")
            if event.get("kind") == "reset_barrier":
                self._reads.clear()
            if (event.get("kind") == "mmio_delivery"
                    and event.get("device_id") == "uart"
                    and event.get("write") is False
                    and event.get("offset") == 0x18
                    and type(event.get("read_value")) is int):
                transaction = event.get("source_transaction")
                if isinstance(transaction, Mapping):
                    epoch = transaction.get("source_epoch")
                    sequence = transaction.get("source_sequence")
                    if type(epoch) is int and type(sequence) is int:
                        self._reads[(epoch, sequence)] = dict(event)
            outputs = event.get("outputs")
            if (event.get("component") != "cpu" or event.get("kind") is not None
                    or not isinstance(outputs, Mapping)
                    or outputs.get("data_rsp_consumed") != 1):
                continue
            epoch = outputs.get("data_rsp_source_epoch")
            sequence = outputs.get("data_rsp_source_sequence")
            if type(epoch) is not int or type(sequence) is not int:
                continue
            read = self._reads.pop((epoch, sequence), None)
            value = outputs.get("data_rsp_rdata")
            if (read is None or type(value) is not int
                    or value != read["read_value"]):
                continue
            changed = list(receipt.events)
            copy = dict(event)
            copy["outputs"] = {**outputs, "data_rsp_rdata": value ^ 1}
            changed[index] = copy
            self._fault = {
                "mode": self.fault_mode,
                "observed_case_id": receipt.case_id,
                "read_event_id": read["event_id"],
                "cpu_response_event_id": event["event_id"],
                "source_epoch": epoch,
                "source_sequence": sequence,
                "original_rdata": value,
                "checker_input_rdata": value ^ 1,
            }
            findings = self._checker(replace(receipt, events=tuple(changed)))
            if "cpu_uart_rxdata_response_mismatch" not in findings:
                raise ValueError("controlled UART fault missed the checker invariant")
            return findings
        return self._checker(receipt)
