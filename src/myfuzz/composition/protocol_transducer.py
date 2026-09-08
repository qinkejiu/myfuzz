"""Stateful, single-outstanding processor-memory-beat@1 projection."""

from __future__ import annotations

from dataclasses import dataclass, field


def _unsigned(value: object, width: int, label: str) -> None:
    if type(value) is not int or not 0 <= value < 1 << width:
        raise ValueError(f"{label} must fit {width} unsigned bits")


@dataclass(frozen=True, slots=True)
class ProcessorBeatRequest:
    """An already-normalized DUT request with explicit memory semantics."""

    address: int
    function: str
    domain: str
    write: bool = False
    write_data: int = 0
    byte_enable: int | None = None

    def __post_init__(self) -> None:
        _unsigned(self.address, 64, "request address")
        for label in ("function", "domain"):
            value = getattr(self, label)
            if not isinstance(value, str) or not value:
                raise ValueError(f"request {label} must be an explicit nonempty string")
        if type(self.write) is not bool:
            raise ValueError("request write must be boolean")
        for label in ("write_data", "byte_enable"):
            value = getattr(self, label)
            if value is None and label == "byte_enable":
                continue
            if type(value) is not int or value < 0:
                raise ValueError(f"request {label} must be a nonnegative integer")


@dataclass(frozen=True, slots=True)
class ProcessorBeatInputs:
    req_ready: bool = False
    rsp_valid: bool = False
    rsp_data: int = 0
    rsp_error: bool = False
    response_request: ProcessorBeatRequest | None = None
    response_data_source: str = "none"
    external_inputs: dict[str, int] = field(default_factory=dict)

    @property
    def response_data(self) -> int:
        return self.rsp_data


@dataclass(frozen=True, slots=True)
class ProtocolState:
    pending: ProcessorBeatRequest | None = None
    age: int = 0
    accept_age: int = 0


class ProcessorBeatTransducer:
    """Grant and respond in separate cycles, bounding both wait phases.

    Choice bits 0/1/2 request acceptance, response, and response error.
    A response always belongs to the request pending *before* this step;
    the response cycle cannot accept a replacement request. The Nth held
    request cycle forces acceptance, and the Nth subsequent pending cycle
    forces response. With no request, ready stays low.
    """

    def __init__(
        self, data_width: int, max_wait_cycles: int = 16, *, allow_error: bool = True
    ) -> None:
        if type(data_width) is not int or data_width <= 0 or data_width % 8:
            raise ValueError("data_width must be a positive multiple of eight")
        if type(max_wait_cycles) is not int or max_wait_cycles <= 0:
            raise ValueError("max_wait_cycles must be positive")
        if type(allow_error) is not bool:
            raise ValueError("allow_error must be boolean")
        self.data_width = data_width
        self.max_wait_cycles = max_wait_cycles
        self.allow_error = allow_error
        self.state = ProtocolState()

    def reset(self) -> None:
        self.state = ProtocolState()

    def step(
        self, raw_choice: int, raw_data: int, request: ProcessorBeatRequest | None
    ) -> ProcessorBeatInputs:
        _unsigned(raw_choice, 3, "raw_choice")
        _unsigned(raw_data, self.data_width, "raw_data")
        if request is not None and not isinstance(request, ProcessorBeatRequest):
            raise ValueError("request must be a ProcessorBeatRequest or None")
        pending = self.state.pending
        if pending is not None:
            if raw_choice & 2 or self.state.age >= self.max_wait_cycles - 1:
                self.state = ProtocolState()
                return ProcessorBeatInputs(
                    rsp_valid=True,
                    rsp_data=raw_data,
                    rsp_error=self.allow_error and bool(raw_choice & 4),
                    response_request=pending,
                    response_data_source="raw",
                )
            self.state = ProtocolState(pending, self.state.age + 1)
            return ProcessorBeatInputs()
        if request is None:
            self.state = ProtocolState()
            return ProcessorBeatInputs()
        if raw_choice & 1 or self.state.accept_age >= self.max_wait_cycles - 1:
            self.state = ProtocolState(pending=request)
            return ProcessorBeatInputs(req_ready=True)
        self.state = ProtocolState(accept_age=self.state.accept_age + 1)
        return ProcessorBeatInputs()


__all__ = ["ProcessorBeatRequest", "ProcessorBeatInputs", "ProtocolState", "ProcessorBeatTransducer"]
