"""Registered single-F4 current-state scheduling, without a synthetic F2 flow.

Live current tokens and this case's certified readback remain separate facts.
No cross-testcase consumption relation is inferred or rewarded here.
"""
from copy import deepcopy
from dataclasses import asdict
from time import perf_counter_ns

from .actions import Action, Catalog
from .model import Condition, Goal, Observation, Snapshot
from .policy import Policy
from .storage import read_current


# Explicit code-owned capability, not CPU/IP names or caller-selected imports.
_SINGLE_F4_EXECUTORS = frozenset(('compiled_f4_wishbone',))


def supports_single_storage(descriptor, flow):
    return (flow == 'F4' and tuple(descriptor.flow_ids) == ('F4',)
            and descriptor.executor('F4') in _SINGLE_F4_EXECUTORS)


def single_storage_view(current, target):
    written = f'written:{target:08x}'
    epoch = current.epoch if current is not None else 0
    known = current is not None
    matched = known and current.field_version > 0 and current.value == target
    goal = Goal('single-storage:' + written, written, (Condition(written),))
    return goal, Snapshot(epoch, {written: Observation(
        'satisfied' if matched else 'refuted' if known else 'unknown',
        'target' if matched else 'other' if known else 'unknown',
        (current.evidence_ref,) if known else (), epoch)})


def same_case_readback(certificate, current):
    """Documentary projection; only the actual runtime supplies live receipts."""
    if current is None or not isinstance(certificate, dict): return 'unknown'
    post = certificate.get('postcondition') or {}
    identity = tuple(post.get(k) for k in ('reset_epoch', 'field_version', 'value', 'source_contract_digest'))
    passed = {a.get('expectation_id') for a in certificate.get('assertions', ()) if a.get('status') == 'passed'}
    return ('certified' if certificate.get('schema_version') == 'compiled_F4_wishbone_chain.v1'
        and certificate.get('status') == 'certified' and identity == current.identity
        and certificate.get('exact_hops', {}).get('schema_version') == 'compiled_F4_wishbone_exact_hops.v1'
        and 'cross_component.readback_ram_write_hop' in passed else 'unknown')


class SingleStorageCaseAdapter:
    """Public CaseAdapter over the exact registered Wishbone runtime."""
    def __init__(self, runtime, policy):
        from myfuzz.integration.compiled_wishbone_f4 import WishboneF4Runtime
        if type(runtime) is not WishboneF4Runtime:
            raise ValueError('registered single-flow storage runtime required')
        self.runtime, self.policy = runtime, policy

    def current_state(self):
        self.runtime._stable()
        return read_current(self.runtime)

    def execute(self, decision, context):
        raw = decision.value.to_bytes(4, 'little')
        if context.on_prepared is not None:
            context.on_prepared(dict(flow_id='F4', raw_records_hex=[raw.hex()]))
        return self.runtime.submit(raw, flow='F4')

    def settle(self, decision, context, receipt, current, features, cost_ns):
        observed = same_case_readback(receipt, current)
        features = ({'frontier': (f'written:{decision.value:08x}',)}
                    if observed == 'certified' and current.value == decision.value else {})
        result = self.policy.settle(decision.id, features, cost_ns, censored=not bool(features))
        return dict(settlements=[result], same_case_readback=observed,
            current_observation='live' if current is not None else 'unknown',
            cross_testcase_consumption='unsupported-no-read-only-flow', relation_features=[])


class SingleStorageRecordSelector:
    def __init__(self, descriptor, *, flow, records, policy, seed, cases):
        if not supports_single_storage(descriptor, flow):
            raise ValueError('registered single F4 storage capability required')
        records = records or ['F4:' + row for row in descriptor.records('F4')]
        self.rows = list(dict.fromkeys(row if ':' in row else 'F4:' + row for row in records))
        if (not self.rows or len(self.rows) > 16 or any(not row.startswith('F4:') or len(row) != 11
                or any(c not in '0123456789abcdefABCDEF' for c in row[3:]) for row in self.rows)):
            raise ValueError('1..16 single-word F4 records required')
        self.rows = [row.lower().replace('f4:', 'F4:') for row in self.rows]
        self.values = tuple(int.from_bytes(bytes.fromhex(row[3:]), 'little') for row in self.rows)
        self.catalog = Catalog(tuple(Action(f'storage:write:{value:08x}', 'F4', 'F4',
            (f'written:{value:08x}',), (), (value,)) for value in self.values))
        self.scheduler = Policy(seed=seed, mode=policy, max_decisions=max(cases, 1))
        self.sequence, self.decisions, self.transitions = [], [], []
        self.pending, self.adapter, self.runtime = None, None, None
        self._replay_costs = None

    def attach_runtime(self, runtime):
        if self.adapter is not None: raise ValueError('single storage runtime already attached')
        self.adapter, self.runtime = SingleStorageCaseAdapter(runtime, self.scheduler), runtime

    def replay_costs(self, transitions):
        self._replay_costs = [row['policy_cost_ns'] for row in transitions]

    def checkpoint(self): return deepcopy(self.scheduler)

    def restore(self, checkpoint):
        self.scheduler, self.pending = checkpoint, None
        self.adapter.policy = self.scheduler

    def _current(self):
        try: return self.adapter.current_state()
        except (ValueError, RuntimeError): return None

    def choose(self):
        if self.pending is not None or self.adapter is None: raise ValueError('attached idle selector required')
        self._started = perf_counter_ns()
        current = self._current()
        target = self.values[len(self.sequence) % len(self.values)]
        goal, snapshot = single_storage_view(current, target)
        decision = self.scheduler.choose(goal, snapshot, self.catalog)
        row = 'F4:' + decision.value.to_bytes(4, 'little').hex()
        self.pending = row, decision
        return row

    def settle(self, row):
        from .case_adapter import CaseContext
        if self.pending is None or self.pending[0] != row: raise ValueError('unexpected completed F4 record')
        decision = self.pending[1]
        current = self._current()
        receipt = self.runtime.records[-1]['certificate']
        cost = max(1, perf_counter_ns() - self._started) if self._replay_costs is None else self._replay_costs[len(self.sequence)]
        result = self.adapter.settle(decision, CaseContext(receipt['case_id']), receipt, current, {}, cost)
        self.transitions.append(dict(current_value=current.value if current else None,
            current_version=current.field_version if current else None,
            current_epoch=current.epoch if current else None, policy_cost_ns=cost, **result))
        self.sequence.append(row)
        self.decisions.append(decision.document())
        self.pending = None

    def finish(self): return None

    def document(self):
        return dict(sequence=list(self.sequence), decisions=list(self.decisions),
            catalog_sha256=self.catalog.identity, catalog=[asdict(a) for a in self.catalog.actions],
            state_observation='live', live_state_conditioned=True,
            search_backend='live-storage-single-flow', provider='registered_storage_current_version.v1',
            cross_testcase_consumption='unsupported-no-read-only-flow',
            transitions=deepcopy(self.transitions), statistics=self.scheduler.statistics())
