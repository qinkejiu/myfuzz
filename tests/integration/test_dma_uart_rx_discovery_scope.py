"""Public entry scopes reuse AST discovery while retaining byte/probe guards."""
import cProfile
from types import SimpleNamespace

import pytest

from myfuzz.integration.dma_uart_rx_runtime import (
    _source_pins, run_continuous_uart_rx, replay_continuous_uart_rx)
from myfuzz.local_harness import build
from myfuzz.scenario.contracts import ResourceBudget


class ConstructionStopped(Exception):
    pass


@pytest.mark.parametrize('entry', ('run', 'replay'))
def test_runtime_entry_discovers_import_closure_once(entry, tmp_path):
    profile = cProfile.Profile()
    def factory():
        # Real discovery calls inside the public invocation, no native session
        # or method patch. Guarded discovery implementations remain pinned.
        first = build._host_sources()
        assert build._host_sources() == first
        raise ConstructionStopped
    def invoke():
        if entry == 'run':
            run_continuous_uart_rx((0x5a,), cache_dir=tmp_path, factory=factory)
        else:
            reference = SimpleNamespace(source_pins=_source_pins(), budget=ResourceBudget())
            replay_continuous_uart_rx(reference, cache_dir=tmp_path, factory=factory)
    with pytest.raises(ConstructionStopped):
        profile.runcall(invoke)
    stats = [e for e in profile.getstats() if e.code is build._discover_host_sources.__code__]
    assert len(stats) == 1
    print(entry, 'actual_discovery_calls', stats[0].callcount,
        'inclusive_seconds', stats[0].totaltime)
    assert stats[0].callcount == 1
