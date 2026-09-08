from dataclasses import replace

import pytest

from myfuzz.composition.cycle_input import (
    CycleField,
    CycleInputError,
    CycleInputLayout,
    TestHeader,
    parse_cycle_payload,
)
from myfuzz.composition.rfuzz_transport import RfuzzInputTransport


def header(layout: CycleInputLayout, *, cycles: int = 2) -> TestHeader:
    return TestHeader(
        schema_version="cycle_test.v1",
        layout_hash=layout.layout_hash,
        contract_hash="sha256:contract",
        reset_cycles=1,
        execution_cycles=cycles,
        boot_address=0x1000,
        hart_id=0,
    )


def test_payload_is_split_into_equal_records_without_padding() -> None:
    layout = CycleInputLayout.build((CycleField("instruction_entropy", 32), CycleField("response", 2)))
    transport = RfuzzInputTransport(layout.raw_width, layout.layout_hash)
    records = (transport.pack(1), transport.pack(2))

    case = parse_cycle_payload(b"".join(records) + b"x", layout, header(layout, cycles=3))

    assert case.raw_cycles == (1, 2)
    assert case.truncated_bytes == 1


def test_header_hash_mismatch_is_rejected() -> None:
    layout = CycleInputLayout.build((CycleField("payload", 7),))
    transport = RfuzzInputTransport(layout.raw_width, layout.layout_hash)
    record = transport.pack(3)

    with pytest.raises(CycleInputError, match="layout hash"):
        parse_cycle_payload(record, layout, replace(header(layout), layout_hash="wrong"))


def test_layout_fields_have_contiguous_offsets_and_stable_hash() -> None:
    layout = CycleInputLayout.build((CycleField("first", 3), CycleField("second", 5)))

    assert layout.raw_width == 8
    assert [(field.name, field.raw_lo, field.raw_hi) for field in layout.fields] == [
        ("first", 0, 2),
        ("second", 3, 7),
    ]
    assert layout.layout_hash == CycleInputLayout.build(
        (CycleField("first", 3), CycleField("second", 5))
    ).layout_hash
    assert layout.layout_hash != CycleInputLayout.build(
        (CycleField("second", 5), CycleField("first", 3))
    ).layout_hash


def test_payload_records_are_capped_at_execution_cycles() -> None:
    layout = CycleInputLayout.build((CycleField("payload", 9),))
    transport = RfuzzInputTransport(layout.raw_width, layout.layout_hash)
    payload = b"".join(transport.pack(value) for value in (4, 5, 6))

    case = parse_cycle_payload(payload, layout, header(layout, cycles=2))

    assert case.raw_cycles == (4, 5)
    assert case.truncated_bytes == 0


def test_invalid_cycle_header_values_are_rejected() -> None:
    layout = CycleInputLayout.build((CycleField("payload", 1),))

    with pytest.raises(CycleInputError, match="execution cycles"):
        parse_cycle_payload(b"", layout, replace(header(layout), execution_cycles=-1))


def test_layout_rejects_duplicate_or_invalid_fields() -> None:
    with pytest.raises(CycleInputError, match="duplicate"):
        CycleInputLayout.build((CycleField("same", 1), CycleField("same", 2)))
    with pytest.raises(CycleInputError, match="width"):
        CycleInputLayout.build((CycleField("zero", 0),))


def test_parse_rejects_layout_with_tampered_raw_width() -> None:
    layout = CycleInputLayout.build((CycleField("payload", 8),))
    tampered = layout
    object.__setattr__(tampered, "raw_width", layout.raw_width + 1)
    transport = RfuzzInputTransport(layout.raw_width, layout.layout_hash)

    with pytest.raises(CycleInputError, match="raw width"):
        parse_cycle_payload(transport.pack(1), tampered, replace(header(layout)))


def test_parse_rejects_layout_with_tampered_field_width_or_offset() -> None:
    layout = CycleInputLayout.build((CycleField("first", 4), CycleField("second", 4)))
    width_tampered = layout
    object.__setattr__(width_tampered.fields[0], "width", 3)
    offset_tampered = CycleInputLayout.build((CycleField("first", 4), CycleField("second", 4)))
    object.__setattr__(offset_tampered.fields[1], "raw_lo", 6)
    transport = RfuzzInputTransport(layout.raw_width, layout.layout_hash)
    record = transport.pack(1)

    with pytest.raises(CycleInputError, match="field|layout"):
        parse_cycle_payload(record, width_tampered, replace(header(layout)))
    with pytest.raises(CycleInputError, match="field|layout"):
        parse_cycle_payload(record, offset_tampered, replace(header(layout)))


def test_parse_rejects_layout_reusing_an_old_hash() -> None:
    original = CycleInputLayout.build((CycleField("payload", 8),))
    changed = CycleInputLayout.build((CycleField("payload", 7), CycleField("extra", 1)))
    reused_hash = changed
    object.__setattr__(reused_hash, "layout_hash", original.layout_hash)
    transport = RfuzzInputTransport(changed.raw_width, changed.layout_hash)

    with pytest.raises(CycleInputError, match="layout hash"):
        parse_cycle_payload(
            transport.pack(1),
            reused_hash,
            replace(header(changed), layout_hash=original.layout_hash),
        )


@pytest.mark.parametrize("version", ["unknown", "cycle_test.v2", "test_header.v1"])
def test_header_rejects_unknown_schema_versions(version):
    layout = CycleInputLayout.build((CycleField("payload", 8),))
    with pytest.raises(CycleInputError, match="schema version"):
        replace(header(layout), schema_version=version)


@pytest.mark.parametrize("attribute,value", (("field_id", 3), ("field_id", ""),
    ("width", True), ("width", 1.0), ("raw_lo", False), ("raw_hi", 0.0)))
def test_revalidation_rejects_mutated_field_types_with_rehashed_layout(attribute, value):
    from myfuzz.composition.cycle_input import _layout_document
    from myfuzz.contracts import content_hash

    layout = CycleInputLayout.build((CycleField("payload", 1),))
    object.__setattr__(layout.fields[0], attribute, value)
    object.__setattr__(layout, "layout_hash", content_hash(_layout_document(
        layout.schema_version, layout.raw_width, layout.fields)))
    with pytest.raises(CycleInputError, match="field"):
        layout.validate()
