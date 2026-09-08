"""Layout-derived RFuzz input byte transport (not a coverage-feedback runner).

Matches ekiwi/rfuzz 651f28f1583e14a4aa9d8dfc624b700e6da3a143:
fuzzer/src/config.rs determine_test_size and harness/src/rfuzz/
VerilatorHarness.scala: bytes are concatenated in index order, payload at MSB.
"""
from dataclasses import dataclass
import hashlib

from myfuzz.contracts import canonical_bytes
from .input_layout import InputLayout


@dataclass(frozen=True, slots=True)
class RfuzzInputTransport:
    raw_width: int
    layout_hash: str

    def __post_init__(self):
        if type(self.raw_width) is not int or self.raw_width <= 0:
            raise ValueError("transport requires positive raw width")
        if not isinstance(self.layout_hash, str) or not self.layout_hash:
            raise ValueError("transport requires layout identity")

    @property
    def byte_count(self) -> int:
        return ((self.raw_width + 63) // 64) * 8

    @property
    def padding_bits(self) -> int:
        return self.byte_count * 8 - self.raw_width

    def pack(self, raw_bits: int) -> bytes:
        """Encode one cycle, zeroing transport-only trailing padding."""
        if type(raw_bits) is not int or not 0 <= raw_bits < (1 << self.raw_width):
            raise ValueError("raw bits outside transport width")
        return (raw_bits << self.padding_bits).to_bytes(self.byte_count, "big")

    def unpack(self, record: bytes, *, strict_padding: bool = False) -> int:
        """Decode one cycle; mutator changes to padding have no DUT effect."""
        if not isinstance(record, bytes) or len(record) != self.byte_count:
            raise ValueError("transport record has wrong type or length")
        value = int.from_bytes(record, "big")
        if strict_padding and value & ((1 << self.padding_bits) - 1):
            raise ValueError("transport record contains nonzero padding")
        return value >> self.padding_bits

    def unpack_records(self, payload: bytes, *, max_records: int | None = None) -> tuple[tuple[int, ...], int]:
        """Decode complete records and report bytes left after the final record.

        The payload is intentionally not padded.  ``max_records`` limits the
        decoded prefix while ``truncated_bytes`` still describes the payload's
        incomplete tail, if any.
        """
        if not isinstance(payload, bytes):
            raise ValueError("transport payload must be bytes")
        if max_records is not None and (type(max_records) is not int or max_records < 0):
            raise ValueError("transport max records must be nonnegative")
        count, truncated_bytes = divmod(len(payload), self.byte_count)
        if max_records is not None:
            count = min(count, max_records)
        records = tuple(
            self.unpack(payload[index * self.byte_count:(index + 1) * self.byte_count])
            for index in range(count)
        )
        return records, truncated_bytes

    def document(self) -> dict[str, object]:
        document = {
            "schema_version": "rfuzz_input_transport.v1",
            "layout_hash": self.layout_hash,
            "raw_width": self.raw_width,
            "byte_count": self.byte_count,
            "word_bytes": 8,
            "byte_order": "big",
            "payload_position": "most_significant_bits",
            "padding_bits": self.padding_bits,
            "padding_policy": "ignored_on_input_zero_on_encode",
        }
        return {**document, "transport_hash": hashlib.sha256(canonical_bytes(document)).hexdigest()}

    def render_systemverilog(self) -> str:
        ports = [f"  input logic [7:0] io_input_bytes_{i}" for i in range(self.byte_count)]
        ports.append(f"  output logic [{self.raw_width-1}:0] rfuzz_input_bits")
        concatenation = ", ".join(f"io_input_bytes_{i}" for i in range(self.byte_count))
        return ("module myfuzz_rfuzz_transport(\n" + ",\n".join(ports) + "\n);\n"
                f"  wire [{self.byte_count*8-1}:0] padded_input = {{{concatenation}}};\n"
                f"  assign rfuzz_input_bits = padded_input[{self.byte_count*8-1}:{self.padding_bits}];\n"
                "endmodule\n")


def build_rfuzz_transport(layout: InputLayout) -> RfuzzInputTransport:
    """Require a total, nonoverlapping raw ABI before deriving the record."""
    if not isinstance(layout, InputLayout):
        raise ValueError("transport requires an InputLayout")
    layout.to_raw_abi().validate_total_use()
    return RfuzzInputTransport(layout.raw_width, layout.layout_hash)
