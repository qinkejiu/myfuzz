"""UART startup contract behind the continuous boot scheduling regression."""
import pytest

from myfuzz.local_harness.opentitan_uart_session import GeneratedOpentitanUartSession


def test_unadmitted_genome_uart_cannot_be_clocked_during_cpu_boot():
    uart = object.__new__(GeneratedOpentitanUartSession)
    uart.source_mode = 'genome'
    uart._started = False
    # This fails before any transport command or native process is needed.
    with pytest.raises(ValueError, match='UART genome source needs one byte'):
        uart.step_local({})
    assert uart._started is False
