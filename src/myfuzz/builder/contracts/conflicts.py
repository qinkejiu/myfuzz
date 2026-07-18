"""Typed user/profile/RTL port-fact conflict matrix."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from ..input_model import PortDirection


class ConflictOutcome(str, Enum):
    ACCEPT = "accept"
    ADAPT_LOW_ADDRESS = "adapt_low_address"
    IGNORE_PAYLOAD_SIGNEDNESS = "ignore_payload_signedness"
    REJECT = "reject"


@dataclass(frozen=True)
class PortFacts:
    direction: PortDirection
    width: int
    shape: tuple[int, ...] = ()
    signed: bool = False
    role: str | None = None


@dataclass(frozen=True)
class ConflictDecision:
    outcome: ConflictOutcome
    reason: str


def resolve_port_conflict(
    *,
    rtl: PortFacts,
    expected: PortFacts,
    bitwise_payload: bool = False,
    allow_low_address_truncation: bool = False,
) -> ConflictDecision:
    if rtl.direction is not expected.direction:
        return ConflictDecision(ConflictOutcome.REJECT, "user/profile direction conflicts with RTL fact")
    if rtl.role is not None and expected.role is not None and rtl.role != expected.role:
        return ConflictDecision(ConflictOutcome.REJECT, "protocol role conflict")
    if rtl.shape != expected.shape:
        return ConflictDecision(ConflictOutcome.REJECT, "packed or unpacked shape conflict")
    if rtl.width != expected.width:
        if allow_low_address_truncation and rtl.width < expected.width:
            return ConflictDecision(
                ConflictOutcome.ADAPT_LOW_ADDRESS,
                "profile permits low-address truncation; backend must prove window representability",
            )
        return ConflictDecision(ConflictOutcome.REJECT, "width conflict has no declared adapter")
    if rtl.signed != expected.signed:
        if bitwise_payload:
            return ConflictDecision(
                ConflictOutcome.IGNORE_PAYLOAD_SIGNEDNESS,
                "signedness is immaterial for a bitwise protocol payload",
            )
        return ConflictDecision(ConflictOutcome.REJECT, "signedness conflict is semantically relevant")
    return ConflictDecision(ConflictOutcome.ACCEPT, "RTL and semantic facts agree")
