"""Runtime timing is per-call diagnostic metadata, including failed calls."""

import pytest

from myfuzz.scenario.runner import observe_runtime_timings, timed_runtime_call


def test_runtime_timing_observer_is_scoped_and_preserves_errors():
    samples = []

    @timed_runtime_call("scheduler_batch")
    def run(should_fail=False):
        if should_fail:
            raise RuntimeError("step failed")
        return 7

    with observe_runtime_timings(lambda name, seconds: samples.append((name, seconds))):
        assert run() == 7
        with pytest.raises(RuntimeError, match="step failed"):
            run(True)
    assert len(samples) == 2
    assert all(name == "scheduler_batch" and seconds >= 0 for name, seconds in samples)
    assert run() == 7
    assert len(samples) == 2
