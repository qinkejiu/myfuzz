"""Completion polling reads new events; complete case evidence stays available."""
from types import SimpleNamespace

from myfuzz.integration import dma_uart_rx_runtime as runtime


def test_public_case_loop_advances_poll_cursor_without_discarding_history(monkeypatch, tmp_path):
    class Runner:
        def __init__(self):
            self.rows = []
            self.queries = []
            # The boot records per-case prefix boundaries, so the fake runner
            # carries the same component/execution surface as a real one.
            self.local_ticks = dict(cpu=0, dma=0, uart=0)
            self.execution_id = '4' * 32
            self.sessions = dict(
                cpu=SimpleNamespace(router=SimpleNamespace(ready_targets=(('uart',))),
                    execution='1' * 32, identity_document=lambda: {}, _execution='1' * 32),
                dma=SimpleNamespace(identity_document=lambda: {}, _execution='2' * 32),
                uart=SimpleNamespace(source_events=[], register_access_conflict=lambda: None,
                    identity_document=lambda: {}, _execution='3' * 32))
        def set_resource_budget(self, budget):
            pass
        @property
        def event_count(self):
            return len(self.rows)
        def events_since(self, index):
            self.queries.append(index)
            return self.rows[index:]
    runner = Runner()
    class Recorder:
        _finished = False
        def __init__(self, template, selected):
            assert selected is runner
            self.rounds = 0
            self.commands = ()
        def begin(self):
            pass
        def submit_source_event(self, event):
            runner.rows.append(dict(kind='source_injection', value=event.value))
            runner.sessions['uart'].source_events.append(dict(kind='uart_source_frame_end',
                action_id=event.action_id, waveform_matched=True))
        def advance(self, schedule):
            runner.rows.append(dict(kind='native_progress'))
            for component in schedule:
                runner.local_ticks[component] += 1
            if schedule == ('dma', 'cpu', 'uart'):
                self.rounds += 1
                if self.rounds == 2:
                    runner.rows.append(dict(kind='memory_write', component='cpu',
                        address=runtime.COMPLETED, value=1))
    def capture(recorder, *args, **kwargs):
        recorder._finished = True
        return SimpleNamespace(trace=SimpleNamespace(status='complete'), error=None,
            uncertain_status=dict(source_drift=False))
    checked = []
    def evidence(rows, *args):
        checked.extend(rows)
        return dict(counter=1)
    monkeypatch.setattr(runtime, 'ScenarioBatchRecorder', Recorder)
    monkeypatch.setattr(runtime, '_capture', capture)
    monkeypatch.setattr(runtime, '_case_evidence', evidence)
    runtime.run_continuous_uart_rx((0x5a,), cache_dir=tmp_path, factory=lambda: runner)
    # Two ISR polls and one final full-case causal check. The second poll must
    # skip the already-inspected history; final evidence still sees all rows.
    assert len(runner.queries) == 3
    assert runner.queries[1] > runner.queries[0]
    assert runner.queries[2] == runner.queries[0]
    assert any(e['kind'] == 'source_injection' for e in checked)
    assert any(e.get('address') == runtime.COMPLETED for e in checked)
    assert runner.rows[0]['kind'] == 'native_progress'
