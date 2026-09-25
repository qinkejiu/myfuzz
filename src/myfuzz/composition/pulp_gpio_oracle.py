"""Pure reference model for the supported PULP APB GPIO contract.

Register storage and the APB-visible PADIN value are modeled independently of
DUT outputs. The three input stages and GPIOEN group-of-four clock enable are
source-derived probes recorded in the PULP GPIO profile, not independent
component guarantees; consumers must label them accordingly.
"""

from __future__ import annotations


class PulpGpioOracleError(ValueError):
    """Refusal with a stable reason suitable for a ``not_assessed`` result."""

    def __init__(self, reason: str, detail: str):
        super().__init__(f"{reason}: {detail}")
        self.reason = reason


class PulpGpioOracle:
    """Cycle-stepped oracle for 32-pad, full-word PULP APB GPIO accesses."""

    PINS = 32
    WORD_MASK = (1 << 32) - 1
    REGISTER_OFFSETS = frozenset((0x00, 0x04, 0x08, 0x0C, 0x10, 0x14,
                                  0x28, 0x2C, 0x30, 0x34))
    NOT_ASSESSED_OFFSETS = frozenset((0x18, 0x1C, 0x20, 0x24))
    SOURCE_DERIVED_PROBES = frozenset(("GPIOEN.group_sampling", "GPIO.input_pipeline"))

    def __init__(self, *, pins: int = 32):
        if pins != self.PINS:
            raise PulpGpioOracleError("unsupported-pin-width", "only PAD_NUM=32 is modeled")
        self.pins = pins
        self.reset()

    def reset(self) -> None:
        """Reset register shadows and all input history to zero."""
        self.paddir = 0
        self.gpioen = 0
        self.padout = 0
        self.padcfg = [0, 0, 0, 0]
        self._sync0 = 0
        self._sync1 = 0
        self._padin = 0

    def apb_access(self, *, address: int, write: bool, wdata: int) -> int | None:
        """Apply one accepted full-word APB access at a word-aligned offset.

        ``address`` is the GPIO window-relative offset; aliasing of addresses
        outside the documented first 64-byte register map is unsupported.
        """
        if not isinstance(address, int) or isinstance(address, bool) or address < 0:
            raise PulpGpioOracleError("invalid-address", "address must be a non-negative integer")
        if address & 0x3:
            raise PulpGpioOracleError("unaligned-access", f"offset 0x{address:x} is not word aligned")
        if not isinstance(write, bool):
            raise PulpGpioOracleError("invalid-direction", "write must be bool")
        if not isinstance(wdata, int) or isinstance(wdata, bool) or not 0 <= wdata <= self.WORD_MASK:
            raise PulpGpioOracleError("invalid-write-data", "wdata must be an unsigned 32-bit integer")
        if address in self.NOT_ASSESSED_OFFSETS:
            raise PulpGpioOracleError(
                "not-assessed-interrupt-status-semantics",
                f"interrupt/status register at 0x{address:02x} lacks independent behavior basis",
            )
        if address not in self.REGISTER_OFFSETS:
            raise PulpGpioOracleError("unsupported-offset", f"offset 0x{address:x} is outside modeled registers")

        if address == 0x08 and write:
            raise PulpGpioOracleError("write-to-read-only-register", "PADIN is read-only")
        if address in (0x10, 0x14) and not write:
            raise PulpGpioOracleError("read-from-write-only-register", "PADOUTSET/PADOUTCLR are write-only")

        if write:
            if address == 0x00:
                self.paddir = wdata
            elif address == 0x04:
                self.gpioen = wdata
            elif address == 0x0C:
                self.padout = wdata
            elif address == 0x10:
                self.padout |= wdata
            elif address == 0x14:
                self.padout &= ~wdata & self.WORD_MASK
            else:
                self.padcfg[(address - 0x28) // 4] = wdata
            return None

        if address == 0x00:
            return self.paddir
        if address == 0x04:
            return self.gpioen
        if address == 0x08:
            return self._padin
        if address == 0x0C:
            return self.padout
        return self.padcfg[(address - 0x28) // 4]

    def sample_pins(self, gpio_in: int) -> dict[str, int]:
        """Advance one HCLK sample and return observable pin-role values.

        The synchronizer stages advance together whenever any GPIOEN bit in
        their four-pad group is set. ``gpio_in_sync`` represents stage two;
        PADIN represents stage three. These timing details are source-derived
        probes from the pinned profile evidence.
        """
        if not isinstance(gpio_in, int) or isinstance(gpio_in, bool) or not 0 <= gpio_in <= self.WORD_MASK:
            raise PulpGpioOracleError("invalid-pin-sample", "gpio_in must be an unsigned 32-bit value")

        old_sync0, old_sync1 = self._sync0, self._sync1
        next_sync0 = old_sync0
        next_sync1 = old_sync1
        next_padin = self._padin
        for group in range(self.PINS // 4):
            group_mask = 0xF << (group * 4)
            if self.gpioen & group_mask:
                next_sync0 = (next_sync0 & ~group_mask) | (gpio_in & group_mask)
                next_sync1 = (next_sync1 & ~group_mask) | (old_sync0 & group_mask)
                next_padin = (next_padin & ~group_mask) | (old_sync1 & group_mask)
        self._sync0, self._sync1, self._padin = next_sync0, next_sync1, next_padin

        packed_padcfg = sum(word << (32 * index) for index, word in enumerate(self.padcfg))
        return {
            "gpio_out": self.padout,
            "gpio_dir": self.paddir,
            "gpio_padcfg": packed_padcfg,
            "gpio_in_sync": self._sync1,
        }
