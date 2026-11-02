"""Typed RAM selector over the existing generic campaign submit lifecycle."""
from copy import deepcopy
from dataclasses import asdict
from time import perf_counter_ns

from .ram import install_ram_consumer
from .ram_actions import RamActionSpace, RamCredit, ram_view, semantic_relation
from .policy import Policy


def ram_records(records):
    if not records or any(type(row) is not str for row in records): return False
    stores = [row for row in records if row.startswith('F3:')]
    return (bool(stores) and 'F1:03200000' in records and len(stores) <= 16
            and all(row == 'F1:03200000' or (row.startswith('F3:') and len(row) == 11
                    and all(c in '0123456789abcdefABCDEF' for c in row[3:])) for row in records))


class RamRecordSelector:
    """One live query/choice per real case; native execution stays in campaign.

    Fresh runs query fresh authority and recompute semantic state and ownership;
    recorded original costs only normalize deterministic policy replay. Measured
    fresh costs are retained separately outside the replay identity.
    """
    def __init__(self, descriptor, *, flow, records, policy, seed, cases):
        if flow != 'mixed' or not ram_records(records):
            raise ValueError('explicit typed RAM store/read catalog required')
        self.rows = list(dict.fromkeys(records))
        values = tuple(int.from_bytes(bytes.fromhex(row[3:]), 'little') for row in self.rows if row.startswith('F3:'))
        self.space = RamActionSpace(values=values, write_source='F3', read_source='F1')
        self.catalog = self.space.catalog
        self.scheduler = Policy(seed=seed, mode=policy, max_decisions=max(1, cases))
        self.credit = RamCredit(self.scheduler)
        self.sequence, self.decisions, self.transitions = [], [], []
        self.pending = None
        self._handle, self._runtime = None, None
        self._report = dict(relations=[])
        self._replay_costs = None
        self._measured_costs = []
        self._terminal = None
        self._bound_sources = None
        self._clock, self._clock_started, self._clock_finished = None, None, None
        self._certified_events, self._useful_events, self._decision_seconds = [], [], []
        self._certified_seen = set()

    def start_search_clock(self, clock, started):
        if self._clock is not None or not callable(clock):
            raise ValueError('one actual campaign search clock required')
        self._clock, self._clock_started = clock, started

    def finish_search_clock(self):
        self.finish()  # Terminal pending contribution handling is in this clock.
        if self._clock is None:
            raise ValueError('actual campaign clock missing')
        self._clock_finished = self._clock()

    def measurements(self, *, mode):
        if self._clock_started is None or self._clock_finished is None:
            raise ValueError('completed campaign clock required')
        return deepcopy(dict(schema_version='ram_search_measurements.v1',
            certified_events=self._certified_events, useful_case_events=self._useful_events,
            interaction_status='available', decision_seconds=self._decision_seconds,
            search_seconds=max(0, self._clock_finished - self._clock_started),
            measured_action_cost_ns=self._measured_costs,
            build_seconds=None, init_seconds=None,
            fresh={'status':'verified' if mode == 'fresh' else 'not-run'},
            timing_scope='campaign_execution_clock',
            proof_scope='host_ram_versions_consumed_over_dut_obi',
            retirement='unknown', source_origin='unknown'))

    def attach_runtime(self, runtime):
        if self._runtime is not None: raise ValueError('RAM runtime already attached')
        self._handle, self._runtime = install_ram_consumer(runtime), runtime
        self._bound_sources = {flow: runtime.memory_bindings[flow].document() for flow in ('F1', 'F3')}

    def replay_costs(self, transitions):
        self._replay_costs = [(row['settlement_cost_ns'], row['policy_cost_ns']) for row in transitions]

    def checkpoint(self):
        # Budget refusal occurs before submit, so no provider state is restored.
        return deepcopy((self.scheduler, self.credit))

    def restore(self, checkpoint):
        self.scheduler, self.credit = checkpoint
        self.pending = None

    def choose(self):
        if self.pending is not None or self._handle is None:
            raise ValueError('attached idle RAM selector required')
        self._started = perf_counter_ns()
        self._before = self._handle.current_state()
        goal, snapshot = ram_view(self._before, self._report, values=self.space.values)
        decision = self.scheduler.choose(goal, snapshot, self.catalog)
        row = self.space.record(decision.action_id, decision.value)
        if row not in self.rows: raise ValueError('RAM action outside public catalog')
        self._decision_duration = max(0, perf_counter_ns() - self._started) / 1e9
        self._decision_seconds.append(self._decision_duration)
        self.pending = row, decision
        return row

    def settle(self, row):
        if self.pending is None or row != self.pending[0]:
            raise ValueError('unexpected RAM completed record')
        decision = self.pending[1]
        certificate = self._runtime.records[-1]['certificate']
        case_id = certificate['case_id']
        current = self._handle.current_state()
        report = self._handle.observe_case(case_id)
        measured = max(1, perf_counter_ns() - self._started)
        cost = measured if self._replay_costs is None else self._replay_costs[len(self.sequence)][0]
        settlement = self.credit.observe(decision, case_id, current, report, cost)
        measured_final = max(measured, perf_counter_ns() - self._started)
        final_cost = measured_final if self._replay_costs is None else self._replay_costs[len(self.sequence)][1]
        self.scheduler.finalize_cost(decision.id, final_cost)
        self.credit.costs[decision.id] = final_cost
        if self._clock is None:
            raise ValueError('actual campaign clock missing')
        observed_seconds = max(0, self._clock() - self._clock_started)
        new_keys = set()
        for relation in report.get('relations', ()):
            if (relation.get('status') == 'verified' and relation.get('reward_eligible') is True
                    and relation.get('value') in self.space.values
                    and relation.get('read_case_id') == case_id):
                key = semantic_relation(relation)
                if key not in self._certified_seen: new_keys.add(key)
        self._certified_seen.update(new_keys)
        self._certified_events.extend(dict(seconds=observed_seconds, semantic_key=key) for key in sorted(new_keys))
        if new_keys: self._useful_events.append(dict(seconds=observed_seconds, case_id=case_id))
        # Semantic projection excludes process/event identities from replayed
        # policy state. Exact evidence remains in runtime receipts and journal.
        self.transitions.append(dict(case_id=case_id, state_status=current['status'], state_reason=current.get('reason'),
            value=current.get('value'), writer_case_ids=current.get('writer_case_ids', []),
            writer_attributed=current.get('writer_attributed', False),
            policy_cost_ns=final_cost, settlement_cost_ns=cost, credited_relations=settlement['credited_relations'],
            settlements=settlement['settlements'], pending=settlement['pending']))
        self._measured_costs.append(measured_final)
        self.sequence.append(row)
        self.decisions.append(decision.document())
        self._report = report
        self.pending = None

    def document(self):
        return dict(sequence=list(self.sequence), decisions=list(self.decisions),
            catalog_sha256=self.catalog.identity, catalog=[asdict(a) for a in self.catalog.actions],
            state_observation='live', live_state_conditioned=True,
            search_backend='live-ram', compiled_source_bindings=deepcopy(self._bound_sources), provider='installed_host_ram_versions_with_native_obi_read.v1',
            proof_scope='host_ram_versions_consumed_over_dut_obi', retirement='unknown', source_origin='unknown',
            transitions=deepcopy(self.transitions), terminal_credit=deepcopy(self._terminal), statistics=self.scheduler.statistics())

    def finish(self):
        if self._terminal is None: self._terminal = self.credit.finish()
        return deepcopy(self._terminal)
