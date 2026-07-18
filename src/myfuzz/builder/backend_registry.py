"""Capability-driven protocol backend selection without module-name knowledge."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .input_model import InputValidationError


@dataclass(frozen=True)
class BackendSpec:
    backend_id: str
    version: str
    protocols: tuple[str, ...]
    capabilities: tuple[str, ...]
    supported_data_widths: tuple[int, ...] = (32,)
    max_initiators: int = 1
    max_clock_domains: int = 1

    def __post_init__(self) -> None:
        if not self.backend_id or not self.version or not self.protocols:
            raise InputValidationError("backend identity and protocols must be non-empty")
        if self.max_initiators <= 0 or self.max_clock_domains <= 0:
            raise InputValidationError("backend limits must be positive")
        if any(width <= 0 for width in self.supported_data_widths):
            raise InputValidationError("backend data widths must be positive")


class CapabilityMismatch(InputValidationError):
    def __init__(self, protocols: tuple[str, ...], reasons: tuple[str, ...]):
        self.protocols = protocols
        self.reasons = reasons
        super().__init__(f"no backend for {','.join(protocols)}: " + "; ".join(reasons))


class BackendRegistry:
    def __init__(self, backends: Iterable[BackendSpec] = ()) -> None:
        self._backends: list[BackendSpec] = []
        for backend in backends:
            self.register(backend)

    def register(self, backend: BackendSpec) -> None:
        if any(item.backend_id == backend.backend_id and item.version == backend.version for item in self._backends):
            raise InputValidationError(f"duplicate backend {backend.backend_id!r} version {backend.version!r}")
        self._backends.append(backend)

    def select(self, *, protocols: Iterable[str], required_capabilities: Iterable[str] = (),
               data_width: int = 32, initiator_count: int = 1, clock_domain_count: int = 1) -> BackendSpec:
        requested_protocols = tuple(sorted({item.strip().lower() for item in protocols}))
        required = set(required_capabilities)
        candidates = [item for item in self._backends if tuple(sorted(item.protocols)) == requested_protocols]
        reasons: list[str] = []
        eligible: list[BackendSpec] = []
        for item in candidates:
            mismatch = []
            if data_width not in item.supported_data_widths:
                mismatch.append(f"data_width {data_width} not in {item.supported_data_widths}")
            if initiator_count > item.max_initiators:
                mismatch.append(f"initiators {initiator_count} exceed {item.max_initiators}")
            if clock_domain_count > item.max_clock_domains:
                mismatch.append(f"clock domains {clock_domain_count} exceed {item.max_clock_domains}")
            missing = sorted(required - set(item.capabilities))
            if missing:
                mismatch.append("missing capabilities " + ",".join(missing))
            if mismatch:
                reasons.append(f"{item.backend_id}@{item.version}: " + ", ".join(mismatch))
            else:
                eligible.append(item)
        if not eligible:
            if not candidates:
                reasons.append("no registered backend has the requested protocol set")
            raise CapabilityMismatch(requested_protocols, tuple(reasons))
        return sorted(eligible, key=lambda item: (item.backend_id, item.version))[0]


def builtin_backend_registry() -> BackendRegistry:
    return BackendRegistry((
        BackendSpec("axi_lite_fabric", "1", ("axi_lite",), ("decode", "default_error", "single_outstanding")),
        BackendSpec("axi_lite_to_apb", "1", ("apb3", "axi_lite"), ("bridge", "wait_states", "error_response")),
        BackendSpec("axi_lite_to_apb4", "1", ("apb4", "axi_lite"), ("bridge", "wait_states", "error_response", "write_strobes")),
        BackendSpec("apb3_decoder", "1", ("apb3",), ("decode", "default_error")),
        BackendSpec("apb4_decoder", "1", ("apb4",), ("decode", "default_error", "write_strobes")),
    ))
