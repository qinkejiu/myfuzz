import pytest

from myfuzz.scenario.rejection_codes import RejectionCode, rejection_of
from myfuzz.scenario.rv32i_sources import (
    MmioWindow,
    mmio_access_fragment,
    mutate_mmio_access,
)


def _refusal(call):
    with pytest.raises(ValueError) as failure:
        call()
    rejection = rejection_of(failure.value)
    assert rejection is not None, failure.value
    return rejection


def test_static_store_rejects_read_only_window():
    window = MmioWindow(0x40000000, 4, writable=False)
    with pytest.raises(ValueError, match="not permitted"):
        mmio_access_fragment("SW", 0x40000000, windows=(window,),
                             base_register=1, data_register=2)


def test_static_load_rejects_write_only_window():
    window = MmioWindow(0x40000000, 4, readable=False)
    with pytest.raises(ValueError, match="not permitted"):
        mmio_access_fragment("LW", 0x40000000, windows=(window,),
                             base_register=1, data_register=2)


def test_window_rejects_non_boolean_or_empty_permissions():
    with pytest.raises(ValueError, match="booleans"):
        MmioWindow(0x40000000, 4, readable=1)
    with pytest.raises(ValueError, match="permit"):
        MmioWindow(0x40000000, 4, readable=False, writable=False)


def test_mutation_selects_only_windows_permitted_for_operation():
    windows = (MmioWindow(0x40000000, 4, writable=False),
               MmioWindow(0x40001000, 4, readable=False))
    for first_byte in range(4):
        store = mutate_mmio_access("SW", bytes((first_byte, 0, 0, 0)),
                                   windows=windows, base_register=1,
                                   data_register=2)
        assert store[0].immediate == 0x40001
        load = mutate_mmio_access("LW", bytes((first_byte, 0, 0, 0)),
                                  windows=windows, base_register=1,
                                  data_register=2)
        assert load[0].immediate == 0x40000


def test_mutation_rejects_when_no_window_permits_operation():
    with pytest.raises(ValueError, match="no MMIO window permits"):
        mutate_mmio_access("SB", b"\x00\x00\x00\x00",
                           windows=(MmioWindow(0x40000000, 4, writable=False),),
                           base_register=1, data_register=2)


def test_mutation_skips_window_too_small_for_word_access():
    windows = (MmioWindow(0x40000000, 1), MmioWindow(0x40001000, 4))
    fragment = mutate_mmio_access("LW", b"\x00\x00\x00\x00",
                                  windows=windows, base_register=1,
                                  data_register=2)
    assert fragment[0].immediate == 0x40001


def test_mutation_reports_when_permitted_window_has_no_aligned_word_address():
    with pytest.raises(ValueError, match="no MMIO window has an aligned LW address"):
        mutate_mmio_access("LW", b"\x00\x00\x00\x00",
                           windows=(MmioWindow(0x40000001, 3),),
                           base_register=1, data_register=2)


def test_static_access_rejects_operation_width_disallowed_by_window():
    word_only = MmioWindow(0x40001000, 4, write_widths=(4,))
    with pytest.raises(ValueError, match="access width is not supported"):
        mmio_access_fragment("SB", 0x40001000, windows=(word_only,),
                             base_register=1, data_register=2)
    assert mmio_access_fragment("SW", 0x40001000, windows=(word_only,),
                                base_register=1, data_register=2)[1].operation == "SW"


def test_mutation_skips_window_with_disallowed_write_width():
    windows = (MmioWindow(0x40001000, 4, write_widths=(4,)),
               MmioWindow(0x40002000, 4, write_widths=(1,)))
    for selector in range(4):
        fragment = mutate_mmio_access("SB", bytes((selector, 0, 0, 0)),
                                      windows=windows, base_register=1,
                                      data_register=2)
        assert fragment[0].immediate == 0x40002
    with pytest.raises(ValueError, match="no MMIO window supports SB access width"):
        mutate_mmio_access("SB", b"\x00\x00\x00\x00",
                           windows=windows[:1], base_register=1,
                           data_register=2)


@pytest.mark.parametrize("widths", [(), (2,), (1, 1), [1], (True,)])
def test_mmio_window_rejects_invalid_access_width_declaration(widths):
    with pytest.raises(ValueError, match="write widths"):
        MmioWindow(0x40001000, 4, write_widths=widths)


def test_window_permission_refusals_carry_distinct_directional_codes():
    read_only = _refusal(lambda: mmio_access_fragment(
        "SW", 0x40000000, windows=(MmioWindow(0x40000000, 4, writable=False),),
        base_register=1, data_register=2))
    assert (read_only.code, read_only.pointer) == (
        RejectionCode.MMIO_READ_ONLY, "mmio.address")
    write_only = _refusal(lambda: mmio_access_fragment(
        "LW", 0x40000000, windows=(MmioWindow(0x40000000, 4, readable=False),),
        base_register=1, data_register=2))
    assert (write_only.code, write_only.pointer) == (
        RejectionCode.MMIO_WRITE_ONLY, "mmio.address")


def test_window_range_width_and_window_refusals_carry_their_codes():
    outside = _refusal(lambda: mmio_access_fragment(
        "LW", 0x50000000, windows=(MmioWindow(0x40000000, 0x1000),),
        base_register=1, data_register=2))
    assert (outside.code, outside.pointer) == (
        RejectionCode.MMIO_OUT_OF_WINDOW, "mmio.address")
    width = _refusal(lambda: mmio_access_fragment(
        "SB", 0x40001000, windows=(MmioWindow(0x40001000, 4, write_widths=(4,)),),
        base_register=1, data_register=2))
    assert (width.code, width.pointer) == (
        RejectionCode.MMIO_BAD_WIDTH, "mmio.width")
    denied = _refusal(lambda: mutate_mmio_access(
        "SB", b"\x00\x00\x00\x00",
        windows=(MmioWindow(0x40000000, 4, writable=False),),
        base_register=1, data_register=2))
    assert (denied.code, denied.pointer) == (
        RejectionCode.MMIO_WINDOW_DENIED, "mmio.operation")
    unaligned_window = _refusal(lambda: mutate_mmio_access(
        "LW", b"\x00\x00\x00\x00", windows=(MmioWindow(0x40000001, 3),),
        base_register=1, data_register=2))
    assert (unaligned_window.code, unaligned_window.pointer) == (
        RejectionCode.MMIO_NO_ALIGNED_ADDRESS, "mmio.windows")
