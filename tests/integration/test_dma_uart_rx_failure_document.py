"""Original failure diagnostics must already use their JSON wire types."""
import json
from types import SimpleNamespace

import pytest

from myfuzz.integration import dma_uart_rx_runtime as runtime


def test_actual_failure_builder_preserves_source_bytes_through_json(monkeypatch, tmp_path):
    runner = SimpleNamespace(set_resource_budget=lambda budget: None)

    class Recorder:
        _finished = False
        commands = ()

        def __init__(self, template, selected):
            assert selected is runner

        def begin(self):
            raise RuntimeError('deliberate pre-transport failure')

    def capture(recorder, selected, cases, budget, phase, index, error, source_pins):
        recorder._finished = True
        return SimpleNamespace(error=dict(error))

    monkeypatch.setattr(runtime, 'ScenarioBatchRecorder', Recorder)
    monkeypatch.setattr(runtime, '_capture', capture)
    with pytest.raises(runtime.ContinuousRxFailure) as caught:
        runtime.run_continuous_uart_rx((0x33,), cache_dir=tmp_path, factory=lambda: runner)
    error = caught.value.result.error
    assert error['message'] == 'deliberate pre-transport failure'
    assert error['requested_source_bytes'] == [0x33]
    assert json.loads(json.dumps(error)) == error
