import pytest

from myfuzz.composition.coherent_memory import CoherentMemoryState


def test_first_read_initializes_once_and_repeated_read_is_stable():
    memory = CoherentMemoryState()
    calls = []
    first = memory.read("main", 0x1000, 4, lambda: calls.append(1) or 0x12345678)
    second = memory.read("main", 0x1000, 4, lambda: calls.append(2) or 0)

    assert (first, second, calls) == (0x12345678, 0x12345678, [1])


def test_byte_enable_write_updates_selected_bytes():
    memory = CoherentMemoryState()
    memory.seed("main", 0, 0x11223344, 4)
    memory.write("main", 0, 0xAABBCCDD, 0b0101, 4)

    assert memory.read("main", 0, 4, lambda: 0) == 0x11BB33DD


def test_domains_are_isolated_and_reset_clears_the_test_state():
    memory = CoherentMemoryState()
    memory.seed("main", 0, 0x11223344, 4)
    calls = []

    assert memory.read("other", 0, 4, lambda: calls.append(1) or 0xAABBCCDD) == 0xAABBCCDD
    memory.reset_test()
    assert memory.read("main", 0, 4, lambda: calls.append(2) or 0x55667788) == 0x55667788
    assert calls == [1, 2]


def test_overlapping_read_preserves_written_bytes_and_initializes_missing_bytes_once():
    memory = CoherentMemoryState()
    memory.write("main", 1, 0xAA, 0b1, 1)
    calls = []

    value = memory.read("main", 0, 4, lambda: calls.append(1) or 0x11223344)

    assert (value, calls) == (0x1122AA44, [1])


@pytest.mark.parametrize(
    ("method", "args"),
    [
        ("read", ("main", -1, 1, lambda: 0)),
        ("read", ("main", 0, 0, lambda: 0)),
        ("write", ("main", 0, 1, 0b10, 1)),
        ("write", ("main", 0, 1, -1, 1)),
        ("seed", ("main", 0, 0x100, 1)),
    ],
)
def test_memory_operations_reject_invalid_bounds(method, args):
    memory = CoherentMemoryState()

    with pytest.raises(ValueError):
        getattr(memory, method)(*args)
