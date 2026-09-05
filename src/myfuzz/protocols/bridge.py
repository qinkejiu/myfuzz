"""Bounded executable models for the supported single-beat protocol bridges."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MmioRequest:
    address: int
    write: bool
    wdata: int = 0
    byte_enable: int = 0xF


@dataclass(frozen=True, slots=True)
class MmioResponse:
    done: bool
    rdata: int = 0
    error: bool = False


@dataclass(frozen=True, slots=True)
class BridgeCycle:
    phase: str
    protocol_fields: Mapping[str, int]
    target_valid: bool
    target_request: MmioRequest | None
    response: MmioResponse | None
    error: str | None


class _BoundedBridgeModel:
    def __init__(
        self,
        address_width: int = 32,
        data_width: int = 32,
        max_wait_cycles: int = 16,
    ) -> None:
        if isinstance(address_width, bool) or not isinstance(address_width, int) or address_width <= 0:
            raise ValueError("address_width must be positive")
        if isinstance(data_width, bool) or not isinstance(data_width, int) or data_width <= 0:
            raise ValueError("data_width must be positive")
        if (
            isinstance(max_wait_cycles, bool)
            or not isinstance(max_wait_cycles, int)
            or not 1 <= max_wait_cycles <= 16
        ):
            raise ValueError("max_wait_cycles must be in 1..16")
        self.address_width = address_width
        self.data_width = data_width
        self.max_wait_cycles = max_wait_cycles
        self._data_bytes = data_width // 8
        self._alignment = max(1, self._data_bytes)
        self._full_byte_enable = (1 << self._data_bytes) - 1
        self.reset()

    def reset(self) -> None:
        self._phase = "idle"
        self._request: MmioRequest | None = None
        self._response: MmioResponse | None = None
        self._error: str | None = None
        self._wait_cycles = 0
        self._aw_seen = False
        self._w_seen = False

    def _request_error(self, request: object) -> str | None:
        if not isinstance(request, MmioRequest):
            return "request must be an MmioRequest"
        if (
            isinstance(request.address, bool)
            or not isinstance(request.address, int)
            or request.address < 0
            or request.address >= 1 << self.address_width
        ):
            return f"MMIO address exceeds {self.address_width} bits: {request.address!r}"
        if request.address % self._alignment:
            return f"misaligned MMIO address: {request.address:#x}"
        if not isinstance(request.write, bool):
            return "MMIO write flag must be boolean"
        if (
            isinstance(request.wdata, bool)
            or not isinstance(request.wdata, int)
            or request.wdata < 0
            or request.wdata >= 1 << self.data_width
        ):
            return f"MMIO write data exceeds {self.data_width} bits: {request.wdata!r}"
        if isinstance(request.byte_enable, bool) or not isinstance(request.byte_enable, int):
            return f"byte_enable must be an integer mask: {request.byte_enable!r}"
        if request.byte_enable < 0 or request.byte_enable & ~self._full_byte_enable:
            return f"byte_enable exceeds {self._data_bytes} data bytes: {request.byte_enable:#x}"
        return None

    def _accept_request(self, request: object, phase: str) -> BridgeCycle | None:
        error = self._request_error(request)
        if error is not None:
            return self._enter_error(error)
        assert isinstance(request, MmioRequest)
        self._request = request
        self._phase = phase
        self._wait_cycles = 0
        return None

    def _enter_error(self, error: str) -> BridgeCycle:
        self._phase = "error"
        self._response = MmioResponse(done=True, error=True)
        self._error = error
        return self._error_cycle(response_ready=False)

    def _timeout(self, response_ready: bool) -> BridgeCycle:
        cycle = self._enter_error(f"protocol timeout after {self.max_wait_cycles} cycles")
        if response_ready:
            self.reset()
        return cycle

    def _tick(self, response_ready: bool) -> BridgeCycle | None:
        self._wait_cycles += 1
        if self._wait_cycles >= self.max_wait_cycles:
            return self._timeout(response_ready)
        return None

    def _error_cycle(self, response_ready: bool) -> BridgeCycle:
        cycle = BridgeCycle("error", {}, False, None, self._response, self._error)
        if response_ready:
            self.reset()
        return cycle

    def _idle_cycle(self) -> BridgeCycle:
        return BridgeCycle("idle", {}, False, None, None, None)


class Apb4BridgeModel(_BoundedBridgeModel):
    def _fields(
        self, *, enable: bool, ready: bool = False, selected: bool = True
    ) -> dict[str, int]:
        assert self._request is not None
        response = self._response
        return {
            "paddr": self._request.address,
            "pprot": 0,
            "psel": int(selected),
            "penable": int(enable),
            "pwrite": int(self._request.write),
            "pwdata": self._request.wdata,
            "pstrb": self._request.byte_enable if self._request.write else 0,
            "pready": int(ready),
            "prdata": response.rdata if response is not None else 0,
            "pslverr": int(response.error) if response is not None else 0,
        }

    def step(
        self,
        request: MmioRequest | None = None,
        *,
        target_ready: bool = True,
        target_rdata: int = 0,
        target_error: bool = False,
        response_ready: bool = True,
    ) -> BridgeCycle:
        if self._phase == "error":
            return self._error_cycle(response_ready)
        if self._phase == "idle":
            if request is None:
                return self._idle_cycle()
            rejected = self._accept_request(request, "setup")
            if rejected is not None:
                if response_ready:
                    self.reset()
                return rejected
            cycle = BridgeCycle("setup", self._fields(enable=False), False, None, None, None)
            return self._tick(response_ready) or cycle
        if self._phase == "setup":
            self._phase = "access"

        assert self._request is not None
        if self._phase == "response":
            cycle = BridgeCycle(
                "response",
                self._fields(enable=False, selected=False),
                False,
                None,
                self._response,
                self._error,
            )
            if response_ready:
                self.reset()
                return cycle
            return cycle

        if self._response is None:
            if not target_ready:
                cycle = BridgeCycle(
                    "access", self._fields(enable=True), True, self._request, None, None
                )
                return self._tick(response_ready) or cycle
            self._response = MmioResponse(
                done=True,
                rdata=0 if self._request.write else target_rdata,
                error=bool(target_error),
            )
            self._error = "APB target error" if target_error else None
            cycle = BridgeCycle(
                "access",
                self._fields(enable=True, ready=True),
                True,
                self._request,
                self._response,
                self._error,
            )
            if response_ready:
                self.reset()
                return cycle
            self._phase = "response"
            self._wait_cycles = 0
        return cycle


class Axi4LiteBridgeModel(_BoundedBridgeModel):
    @staticmethod
    def _write_ready_values(
        target_ready: bool | Mapping[str, object],
    ) -> tuple[tuple[bool, bool] | None, str | None]:
        if isinstance(target_ready, bool):
            return (target_ready, target_ready), None
        if not isinstance(target_ready, Mapping):
            return (
                None,
                f"AXI target_ready must be a bool or an aw/w mapping: {target_ready}",
            )
        if set(target_ready) != {"aw", "w"}:
            return (
                None,
                "AXI target_ready mapping must contain exactly 'aw' and 'w'",
            )
        values = (target_ready["aw"], target_ready["w"])
        for channel, value in zip(("aw", "w"), values):
            if not isinstance(value, bool):
                return (
                    None,
                    f"AXI target_ready['{channel}'] must be boolean: {value}",
                )
        return (values[0], values[1]), None

    def _fields(self) -> dict[str, int]:
        fields = {
            "awaddr": 0,
            "awprot": 0,
            "awvalid": 0,
            "awready": 0,
            "wdata": 0,
            "wstrb": 0,
            "wvalid": 0,
            "wready": 0,
            "bresp": 0,
            "bvalid": 0,
            "bready": 0,
            "araddr": 0,
            "arprot": 0,
            "arvalid": 0,
            "arready": 0,
            "rdata": 0,
            "rresp": 0,
            "rvalid": 0,
            "rready": 0,
        }
        if self._request is not None:
            fields.update(
                awaddr=self._request.address,
                wdata=self._request.wdata,
                wstrb=self._request.byte_enable,
                araddr=self._request.address,
            )
        return fields

    def step(
        self,
        request: MmioRequest | None = None,
        *,
        target_ready: bool | Mapping[str, object] = True,
        target_rdata: int = 0,
        target_error: bool = False,
        response_ready: bool = True,
    ) -> BridgeCycle:
        if self._phase == "error":
            return self._error_cycle(response_ready)
        if self._phase == "idle":
            if request is None:
                return self._idle_cycle()
            phase = "write_address" if request.write else "read_address"
            rejected = self._accept_request(request, phase)
            if rejected is not None:
                if response_ready:
                    self.reset()
                return rejected

        assert self._request is not None
        fields = self._fields()
        phase = self._phase
        target_valid = False
        target_request = None
        response = None
        error = None

        if phase in {"write_address", "write_data"}:
            ready_values, ready_error = self._write_ready_values(target_ready)
            if ready_error is not None:
                cycle = self._enter_error(ready_error)
                if response_ready:
                    self.reset()
                return cycle
            assert ready_values is not None
            aw_ready, w_ready = ready_values
            aw_valid = not self._aw_seen
            w_valid = not self._w_seen
            fields["awvalid"] = int(aw_valid)
            fields["awready"] = int(aw_ready if aw_valid else False)
            fields["wvalid"] = int(w_valid)
            fields["wready"] = int(w_ready if w_valid else False)

            if aw_valid and aw_ready:
                self._aw_seen = True
            if w_valid and w_ready:
                self._w_seen = True

            if self._aw_seen and self._w_seen:
                target_valid = True
                target_request = self._request
                self._response = MmioResponse(done=True, error=bool(target_error))
                self._error = "AXI write response error" if target_error else None
                self._phase = "write_response"
                self._wait_cycles = 0
            elif self._aw_seen:
                self._phase = "write_data"
            else:
                self._phase = "write_address"
        elif phase == "write_response":
            assert self._response is not None
            fields["bresp"] = 2 if self._response.error else 0
            fields["bvalid"] = 1
            fields["bready"] = int(response_ready)
            response = self._response
            error = self._error
        elif phase == "read_address":
            if not isinstance(target_ready, bool):
                cycle = self._enter_error("AXI read target_ready must be boolean")
                if response_ready:
                    self.reset()
                return cycle
            fields["arvalid"] = 1
            fields["arready"] = int(target_ready)
            if target_ready:
                target_valid = True
                target_request = self._request
                self._response = MmioResponse(
                    done=True, rdata=target_rdata, error=bool(target_error)
                )
                self._error = "AXI read response error" if target_error else None
                self._phase = "read_response"
                self._wait_cycles = 0
        elif phase == "read_response":
            assert self._response is not None
            fields["rdata"] = self._response.rdata
            fields["rresp"] = 2 if self._response.error else 0
            fields["rvalid"] = 1
            fields["rready"] = int(response_ready)
            response = self._response
            error = self._error

        cycle = BridgeCycle(
            phase, fields, target_valid, target_request, response, error
        )
        if response is not None and response_ready:
            self.reset()
            return cycle
        if response is not None:
            return cycle
        if target_valid:
            return cycle
        return self._tick(response_ready) or cycle


class TileLinkUlBridgeModel(_BoundedBridgeModel):
    def _a_fields(self, ready: bool) -> dict[str, int]:
        assert self._request is not None
        if not self._request.write:
            opcode = 4
        elif self._request.byte_enable == self._full_byte_enable:
            opcode = 0
        else:
            opcode = 1
        return {
            "a_valid": 1,
            "a_ready": int(ready),
            "a_opcode": opcode,
            "a_param": 0,
            "a_size": max(0, self._data_bytes.bit_length() - 1),
            "a_source": 0,
            "a_address": self._request.address,
            "a_mask": self._full_byte_enable if not self._request.write else self._request.byte_enable,
            "a_data": self._request.wdata,
            "a_corrupt": 0,
            "d_valid": 0,
            "d_ready": 0,
            "d_opcode": 0,
            "d_param": 0,
            "d_size": 0,
            "d_source": 0,
            "d_sink": 0,
            "d_denied": 0,
            "d_data": 0,
            "d_corrupt": 0,
        }

    def _d_fields(self, response_ready: bool) -> dict[str, int]:
        assert self._request is not None
        assert self._response is not None
        fields = self._a_fields(ready=False)
        fields.update(
            a_valid=0,
            d_valid=1,
            d_ready=int(response_ready),
            d_opcode=0 if self._request.write else 1,
            d_size=max(0, self._data_bytes.bit_length() - 1),
            d_denied=int(self._response.error),
            d_data=self._response.rdata,
        )
        return fields

    def step(
        self,
        request: MmioRequest | None = None,
        *,
        target_ready: bool = True,
        target_rdata: int = 0,
        target_error: bool = False,
        response_ready: bool = True,
    ) -> BridgeCycle:
        if self._phase == "error":
            return self._error_cycle(response_ready)
        if self._phase == "idle":
            if request is None:
                return self._idle_cycle()
            rejected = self._accept_request(request, "a_channel")
            if rejected is not None:
                if response_ready:
                    self.reset()
                return rejected

        assert self._request is not None
        if self._phase == "a_channel":
            cycle = BridgeCycle(
                "a_channel",
                self._a_fields(target_ready),
                bool(target_ready),
                self._request if target_ready else None,
                None,
                None,
            )
            if target_ready:
                self._response = MmioResponse(
                    done=True,
                    rdata=0 if self._request.write else target_rdata,
                    error=bool(target_error),
                )
                self._error = "TileLink response denied" if target_error else None
                self._phase = "d_channel"
                self._wait_cycles = 0
                return cycle
            return self._tick(response_ready) or cycle

        assert self._phase == "d_channel"
        assert self._response is not None
        cycle = BridgeCycle(
            "d_channel",
            self._d_fields(response_ready),
            False,
            None,
            self._response,
            self._error,
        )
        if response_ready:
            self.reset()
            return cycle
        return cycle


__all__ = [
    "Apb4BridgeModel",
    "Axi4LiteBridgeModel",
    "BridgeCycle",
    "MmioRequest",
    "MmioResponse",
    "TileLinkUlBridgeModel",
]
