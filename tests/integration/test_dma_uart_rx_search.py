"""Single-boot continuous search skeleton: decisions, corpus and hard criteria.

Every case here runs against a fake boot that only appends attempt6-shaped
journal rows. No native process, no serialized evidence and no firmware byte is
treated as authority; the real gate is a separate opt-in module.
"""
from dataclasses import replace
from types import SimpleNamespace

import pytest

from myfuzz.integration import dma_uart_rx_search as search
from myfuzz.integration.dma_uart_rx_runtime import ContinuousRxResult
from myfuzz.scenario.batch import BatchAdvance, BatchSourceEvent, ScenarioBatchPlan
from myfuzz.scenario.contracts import ResourceBudget
from myfuzz.scenario.dma_chain_feedback import dma_chain_features
from myfuzz.scenario.genome import ScenarioGenome

UART_BASE = 0x50000000
DESTINATION = 0x23000
RESULT = 0x24000
COMPLETED = 0x2400c
MCAUSE = 0x8000000b
SEED = bytes.fromhex('5a000102030405060708090a0b0c0d0e')


def chain_rows(byte, counter, *, host_write=False):
    """Case-sized journal slice with the saved attempt6 field names."""
    rows = []

    def add(**record):
        rows.append({'event_id': len(rows) + 1, **record})
        return rows[-1]

    add(kind='source_injection', action_id=f'dma-search-{counter}', component='uart',
        port='uart_rx_byte', value=byte, execution_id='a' * 32)
    add(kind='uart_frame_validation', action_id=f'dma-search-{counter}', byte=byte,
        waveform_matched=True, frame_id=f'uart-frame:0:{counter}',
        fifo_origin='unknown')
    add(kind='uart_tick_observation', pre={'probe_uart_fifo_depth': 0},
        post={'probe_uart_fifo_wvalid': 1, 'probe_uart_fifo_wready': 1,
              'probe_uart_fifo_depth': 0, 'probe_uart_fifo_data': byte})
    add(kind='mmio_delivery', device_id='uart', offset=0x14, write=False,
        address=UART_BASE + 0x14, read_value=28)
    delivery = {'address': UART_BASE + 0x18, 'offset': 24, 'write': False,
                'value': byte, 'byte_enable': 15, 'target_component': 'uart',
                'source_transaction': {'channel_id': 'dma-memory',
                    'source_component': 'dma', 'source_sequence': 1,
                    'execution_id': 'b' * 32},
                'target_uart_access': {
                    'read_capture': {'pre': {'probe_uart_fifo_rdata_re': 1}},
                    'read_value': byte}}
    add(kind='dma_edge', native_local_tick=10,
        accepted={'address': UART_BASE + 0x18, 'write': False, 'value': 0,
                  'byte_enable': 15, 'target_delivery': delivery},
        target_delivery=delivery,
        payload={'observations': {'physical': {'rt_lh_p_12_0_0': 0}}})
    add(kind='memory_write', component='dma', address=DESTINATION, value=byte,
        transaction={'channel_id': 'dma-memory', 'execution_id': 'b' * 32})
    add(kind='dma_edge', native_local_tick=79,
        payload={'observations': {'physical': {'rt_lh_p_12_0_0': 1}}, 'error': 0})
    add(kind='source_start', source=['dma', 'irq'], target=['cpu', 'irq'],
        source_event_id=1, source_tick=79, cpu_tick=62)
    add(kind='cpu_irq_taken', source=['dma', 'irq'], target=['cpu', 'irq'],
        source_event_id=1, cpu_tick=66, cpu_step_event_id=1)
    add(kind='cpu_external_irq_taken', component='cpu', local_tick=66)
    add(kind='memory_write', component='cpu', address=RESULT, value=MCAUSE)
    add(kind='memory_write', component='cpu', address=RESULT + 4, value=0)
    add(kind='memory_write', component='cpu', address=RESULT + 8, value=byte)
    add(kind='memory_write', component='cpu', address=COMPLETED, value=counter)
    if host_write:
        add(kind='memory_write', component='host', address=DESTINATION, value=0x99)
    return rows


class FakeRunner:
    def __init__(self):
        self.rows = []
        self.local_ticks = {'cpu': 0, 'dma': 0, 'uart': 0}
        self.budgets = []
        self.boots = []

    def set_resource_budget(self, budget):
        self.budgets.append(budget)

    @property
    def events(self):
        return tuple(self.rows)


class FakeBoot:
    """Stands in for _ContinuousRxBoot with the same call surface."""

    fail_at = None
    host_write = False

    def __init__(self, runner, *, budget, template, source_pins):
        assert isinstance(runner, FakeRunner)
        assert isinstance(template, ScenarioGenome)
        self.runner, self.budget, self.template = runner, budget, template
        self.source_pins = source_pins
        self.cases = []
        self.commands = []
        self.phase, self.case_index, self.case_start = 'boot', 0, 0
        self.case_failure = None
        self.recorder = SimpleNamespace(_finished=False)
        runner.boots.append(self)

    def boot(self):
        self.phase = 'boot'

    def run_case(self, source_bytes, *, case_index, action_prefix='continuous-rx',
                 max_source_ticks=2048, max_rounds_per_case=4096, expected=None):
        runner = self.runner
        byte = tuple(source_bytes)[0]
        command_start = len(self.commands)
        event_start = len(runner.rows)
        ticks_before = dict(runner.local_ticks)
        self.phase, self.case_index, self.case_start = 'source', case_index, event_start
        self.commands.append(BatchSourceEvent(f'{action_prefix}-{case_index}', 'uart',
            'uart_rx_byte', byte, width=8))
        self.commands.append(BatchAdvance(('dma', 'cpu', 'uart')))
        if self.fail_at == case_index:
            self.case_failure = dict(phase='isr', command_start=command_start,
                command_end=len(self.commands), event_start=event_start,
                event_end=len(runner.rows), ticks_before=ticks_before,
                ticks_after=dict(runner.local_ticks), prefix_sha256=None,
                fifo_depth_after=0, complete=False)
            self.phase = 'isr'
            raise RuntimeError('fake native ISR completion exceeded per-case bound')
        for name in ('cpu', 'dma', 'uart'):
            runner.local_ticks[name] += 1
        runner.rows.extend(chain_rows(byte, case_index, host_write=self.host_write))
        rows = runner.rows[event_start:]
        features = dma_chain_features(rows, start=0, end=len(rows),
            destination=DESTINATION, uart_base=UART_BASE)
        assert features.completed_chain is True
        return dict(counter=case_index, source_byte=byte,
            action_id=f'{action_prefix}-{case_index}',
            command_start=command_start, command_end=len(self.commands),
            event_start=event_start, event_end=len(runner.rows),
            ticks_before=ticks_before, ticks_after=dict(runner.local_ticks),
            prefix_sha256=f'{byte:02x}' * 32, fifo_depth_after=0)

    def finish(self, *, phase='complete', case_index=None, error=None):
        self.recorder._finished = True
        plan = ScenarioBatchPlan(self.template, tuple(self.commands))
        return ContinuousRxResult(plan, None, tuple(self.cases), {}, {}, self.budget,
            phase, self.case_index if case_index is None else case_index, error,
            tuple(self.runner.rows), dict(self.runner.local_ticks), {},
            self.source_pins)

    def close(self):
        self.recorder._finished = True


@pytest.fixture
def fake_search(monkeypatch):
    FakeBoot.fail_at = None
    FakeBoot.host_write = False
    monkeypatch.setattr(search, '_ContinuousRxBoot', FakeBoot)
    monkeypatch.setattr(search, 'make_continuous_uart_rx_runner',
        lambda **kwargs: FakeRunner())
    monkeypatch.setattr(search, '_source_pins', lambda: {'fake': 'pins'})
    monkeypatch.setattr(search, '_firmware_sha256', lambda: 'f' * 64)
    replayed = []

    def replay(result, **kwargs):
        replayed.append(result)
        return result

    monkeypatch.setattr(search, '_replay_failure', replay)
    return SimpleNamespace(replayed=replayed)


def run_search(*, strategy='guided', seconds=0.0, min_cases=3, max_cases=8,
               mutator=None, seed=SEED):
    return search.search_continuous_dma(cache_dir=None, seconds=seconds, seed=seed,
        strategy=strategy, budget=ResourceBudget(max_wall_time_ms=1000),
        max_cases=max_cases, min_cases=min_cases, factory=lambda: FakeRunner(),
        mutator=mutator)


def feedback(case, *, spec=None, evidence=None, features=None, new_features=()):
    return replace(case, spec=spec if spec is not None else case.spec,
        evidence=dict(case.evidence if evidence is None else evidence),
        features=dict(case.features if features is None else features),
        new_features=tuple(new_features))


def test_guided_search_executes_the_hard_structural_criteria(fake_search):
    result = run_search()
    stats = result.stats
    assert stats['search_status'] == 'ok', stats['findings']
    assert stats['post_seed_cases'] >= 2
    assert stats['distinct_effective_specs'] >= 2
    assert stats['feedback_influenced'] is True
    assert stats['post_seed_completed_chains'] >= 1
    assert [case.status for case in result.cases] == ['complete'] * 3
    assert result.cases[0].spec == search.seed_spec(SEED)
    assert all(entry['prefix_sha256'] for entry in result.corpus['entries'])
    assert all(case.prefix_sha256 for case in result.cases)
    assert result.decisions[0]['operator'] == 'seed'
    assert result.decisions[1]['parent_id'].startswith('corpus-')
    assert result.decisions[1]['energy'] > 1
    assert result.decisions[1]['new_features']
    search._assert_real_search(result)


def test_uniform_control_arm_ignores_feedback(fake_search):
    guided = run_search(strategy='guided')
    uniform = run_search(strategy='uniform')
    assert guided.stats['feedback_influenced'] is True
    assert uniform.stats['feedback_influenced'] is False
    assert uniform.stats['search_status'] == 'ok'
    assert len(uniform.cases) == len(guided.cases)
    assert [decision['strategy'] for decision in guided.decisions] == ['guided'] * 3
    assert [decision['strategy'] for decision in uniform.decisions] == ['uniform'] * 3
    assert all(decision['parent_id'] is None or
               not decision['parent_id'].startswith('corpus-')
               for decision in uniform.decisions[1:])
    assert guided.decisions != uniform.decisions


@pytest.mark.parametrize('strategy', ['guided', 'uniform'])
def test_fixed_seed_reproduces_identical_decisions(fake_search, strategy):
    first = run_search(strategy=strategy)
    second = run_search(strategy=strategy)
    assert first.decisions == second.decisions
    assert [case.spec.source_bytes for case in first.cases] == [
        case.spec.source_bytes for case in second.cases]
    recomputed = search.recompute_decisions(seed=SEED, strategy=strategy,
        cases=tuple(case.to_document() for case in first.cases))
    assert recomputed == first.decisions


def test_not_a_real_search_is_rejected_instead_of_silently_passing(fake_search):
    with pytest.raises(search.DmaSearchNotARealSearch) as caught:
        run_search(min_cases=2)
    result = caught.value.result
    findings = result.stats['findings']
    assert result.stats['search_status'] == 'not_a_search'
    assert 'insufficient_mutation_batches' in findings
    assert 'insufficient_effective_specimen_diversity' in findings
    assert 'no_post_seed_completed_chain' not in findings
    full = run_search()
    tampered = replace(full, decisions=tuple(
        {**decision, 'new_features': []} if decision['case_index'] > 1 else decision
        for decision in full.decisions))
    with pytest.raises(search.DmaSearchNotARealSearch) as rejected:
        search._assert_real_search(tampered)
    assert 'feedback_not_influential' in rejected.value.findings


def test_plan_decision_mismatch_is_a_hard_rejection(fake_search):
    result = run_search()
    plan = result.result.plan
    commands = tuple(
        BatchSourceEvent(command.action_id, command.component, command.port,
            (command.value + 1) & 0xFF, command.bit_offset, command.width)
        if isinstance(command, BatchSourceEvent) else command
        for command in plan.commands)
    tampered = replace(result, result=replace(result.result,
        plan=ScenarioBatchPlan(plan.template, commands)))
    with pytest.raises(search.DmaSearchRejected, match='plan_decision_mismatch'):
        search._assert_real_search(tampered)


def test_host_written_data_is_a_hard_rejection(fake_search):
    FakeBoot.host_write = True
    with pytest.raises(search.DmaSearchRejected, match='host_wrote_data'):
        run_search()


def test_expected_byte_comes_from_the_spec_not_the_host(fake_search):
    result = run_search()
    cases = list(result.cases)
    cases[1] = feedback(cases[1], evidence=dict(cases[1].evidence, source_byte=0x00))
    tampered = replace(result, cases=tuple(cases))
    with pytest.raises(search.DmaSearchRejected, match='expected_from_host'):
        search._assert_real_search(tampered)


def test_mutator_stays_inside_the_declared_eight_bit_window():
    import random
    mutator = search.DmaMutator(windows={'uart_rx_byte': (0, 255)},
        firmware_sha256='f' * 64)
    rng = random.Random(7)
    parent = search.seed_spec(SEED)
    seen = set()
    for _ in range(200):
        spec, decision = mutator.mutate(parent, rng=rng, corpus=None)
        assert isinstance(spec, search.DmaCaseSpec)
        assert 0 <= spec.source_bytes[0] <= 255
        assert spec.descriptor == {'byte': spec.source_bytes[0]}
        assert decision['operator'] in search.DmaMutator.OPERATORS
        spec.validate({'uart_rx_byte': (0, 255)})
        seen.add(spec.source_bytes[0])
    assert len(seen) > 8


def test_mutator_rejects_out_of_window_fields_and_s2_operators():
    import random
    narrow = search.DmaMutator(windows={'uart_rx_byte': (0, 15)},
        firmware_sha256='f' * 64, operators=('descriptor_field',))
    with pytest.raises(ValueError, match='declared window'):
        narrow.mutate(search.seed_spec(SEED), rng=random.Random(1), corpus=None)
    for operator in ('length', 'direction', 'payload'):
        mutator = search.DmaMutator(windows={'uart_rx_byte': (0, 255)},
            firmware_sha256='f' * 64, operators=(operator,))
        with pytest.raises(ValueError, match='S1'):
            mutator.mutate(search.seed_spec(SEED), rng=random.Random(1), corpus=None)
    with pytest.raises(ValueError, match='unknown mutation operator'):
        search.DmaMutator(windows={'uart_rx_byte': (0, 255)},
            firmware_sha256='f' * 64, operators=('nope',))


def test_spec_validation_is_pre_rtl_and_firmware_bound():
    spec = search.DmaCaseSpec('RX_TO_RAM', (0x5a,), {'byte': 0x5a}, 'complete')
    spec.validate({'uart_rx_byte': (0, 255)})
    with pytest.raises(ValueError, match='outside the declared window'):
        search.DmaCaseSpec('RX_TO_RAM', (0x100,), {'byte': 0x100},
            'complete').validate({'uart_rx_byte': (0, 255)})
    with pytest.raises(ValueError, match='declared window'):
        search.DmaCaseSpec('RX_TO_RAM', (0x5a,), {'byte': 0x5a},
            'complete').validate({'other': (0, 255)})
    with pytest.raises(ValueError, match='outcome'):
        search.DmaCaseSpec('RX_TO_RAM', (0x5a,), {'byte': 0x5a}, 'environment_error')
    with pytest.raises(ValueError, match='direction'):
        search.DmaCaseSpec('RAM_TO_TX', (0x5a,), {'byte': 0x5a}, 'complete')
    with pytest.raises(ValueError, match='one serial byte'):
        search.DmaCaseSpec('RX_TO_RAM', (0x5a, 0x00), {'byte': 0x5a}, 'complete')
    assert spec.identity('a' * 64) != spec.identity('b' * 64)
    assert spec.identity('a' * 64) == search.DmaCaseSpec('RX_TO_RAM', (0x5a,),
        {'byte': 0x5a}, 'complete').identity('a' * 64)


def _spec(byte):
    return search.DmaCaseSpec('RX_TO_RAM', (byte,), {'byte': byte}, 'complete')


def _feedback(byte, *, case_index, features, new_features, completed_chain):
    return search.DmaCaseFeedback(case_index=case_index,
        spec_id=_spec(byte).identity('f' * 64), status='complete',
        features=dict(features), new_features=tuple(new_features),
        completed_chain=completed_chain, target_error=False,
        ticks_before={'cpu': 0}, ticks_after={'cpu': 1},
        command_start=case_index - 1, command_end=case_index,
        event_start=0, event_end=1, prefix_sha256='a' * 64,
        evidence={}, error=None, spec=_spec(byte))


def test_corpus_selection_is_energy_weighted():
    corpus = search.DmaCorpus()
    low_id = corpus.add(_spec(0x01), _feedback(0x01, case_index=1,
        features={'payload_01': 1}, new_features=(), completed_chain=False))
    high_id = corpus.add(_spec(0x02), _feedback(0x02, case_index=2,
        features={'payload_02': 1, 'isr_payload': 1, 'uart_frame_matched': 1},
        new_features=('payload_02', 'isr_payload', 'uart_frame_matched'),
        completed_chain=True))
    assert corpus.energy(low_id) == 1
    assert corpus.energy(high_id) == 1 + 3 + 2

    class Stub:
        def __init__(self, draw):
            self.draw = draw

        def random(self):
            return self.draw

    assert corpus.select(Stub(0.05))[1] == low_id
    assert corpus.select(Stub(0.5))[1] == high_id
    assert corpus.select(Stub(0.95))[1] == high_id
    with pytest.raises(ValueError, match='empty corpus'):
        search.DmaCorpus().select(Stub(0.5))
    document = corpus.document()
    assert document['entries'][1]['id'] == high_id
    assert document['entries'][1]['energy'] == 6
    assert document['entries'][1]['prefix_sha256'] == 'a' * 64


def test_corpus_is_bounded_and_records_evictions():
    corpus = search.DmaCorpus(max_entries=2)
    for index in range(3):
        corpus.add(_spec(index), _feedback(index, case_index=index + 1,
            features={f'payload_0{index}': 1},
            new_features=(f'payload_0{index}',), completed_chain=True))
    document = corpus.document()
    assert len(document['entries']) == 2
    assert len(document['evictions']) == 1


def test_rejected_prertl_cases_consume_no_rtl(fake_search):
    class RejectOnce(search.DmaMutator):
        def __init__(self):
            super().__init__(windows={'uart_rx_byte': (0, 255)},
                firmware_sha256='f' * 64)
            self.calls = 0

        def mutate(self, parent, *, rng, corpus=None):
            self.calls += 1
            byte = 0x100 if self.calls == 1 else 0x10 + self.calls
            return (search.DmaCaseSpec('RX_TO_RAM', (byte,), {'byte': byte},
                'complete'), {'operator': 'byte_bitflip'})

    result = run_search(mutator=RejectOnce(), min_cases=4)
    assert result.stats['rejected_prertl'] == 1
    assert result.stats['executed_cases'] == 3
    rejected = [decision for decision in result.decisions
                if decision['status'] == 'rejected_prertl']
    assert len(rejected) == 1
    assert len(result.decisions) == 4
    assert result.stats['search_status'] == 'ok'


def test_session_failure_is_saved_and_fresh_replayed(fake_search):
    FakeBoot.fail_at = 2
    with pytest.raises(search.DmaSearchFailed) as caught:
        run_search()
    result = caught.value.result
    assert result.failure is not None
    assert result.stats['search_status'] == 'failed'
    assert result.stats['failure_replay'] == 'reproduced'
    assert len(fake_search.replayed) == 1
    assert result.decisions[-1]['status'] == 'session_failed'
    assert result.failure['error']['message'].startswith('fake native ISR')


def test_search_bundle_survives_json_roundtrip(fake_search, tmp_path):
    import json
    result = run_search()
    document = result.to_document()
    encoded = json.loads(json.dumps(document, sort_keys=True))
    path = tmp_path / 'search.json'
    result.save_bundle(path)
    assert json.loads(path.read_text()) == encoded
    loaded = search.DmaSearchResult.from_document(encoded)
    assert loaded.decisions == result.decisions
    assert loaded.stats['search_status'] == 'ok'
    assert [case.to_document() for case in loaded.cases] == [
        case.to_document() for case in result.cases]
    assert json.loads(json.dumps(loaded.to_document(), sort_keys=True)) == encoded
    search._assert_real_search(loaded)


def test_seed_spec_is_fixed_and_recorded():
    spec = search.seed_spec(SEED)
    assert spec == search.seed_spec(SEED)
    assert spec.source_bytes == (SEED[0],)
    assert spec.descriptor == {'byte': SEED[0]}
    assert spec.direction == 'RX_TO_RAM'
    assert spec.expect == 'complete'
    with pytest.raises(ValueError, match='seed'):
        search.seed_spec(b'')
