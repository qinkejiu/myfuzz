"""Finite RAM store/read actions and same-version delayed contribution credit."""
from hashlib import sha256
from .actions import Action, Catalog
from .model import Condition, Goal, Observation, Snapshot, canonical


def ram_identity(field):
    if field.get('status') != 'observed' or len(field.get('byte_resources', ())) != 4:
        return None
    return sha256(canonical([field['component'], field['memory_id'], field['address'],
        field['reset_epoch'], field['byte_resources']])).hexdigest()


def semantic_relation(row):
    return 'ram-write-read:' + sha256(canonical([
        row['component'], row['memory_id'], row['address'], row['value']])).hexdigest()


class RamActionSpace:
    def __init__(self, *, values, write_source, read_source):
        if type(values) is not tuple or not 1 <= len(values) <= 16:
            raise ValueError('1..16 declared RAM values required')
        self.values = values
        self.catalog = Catalog(tuple(Action(f'ram:write:{value:08x}', write_source, 'F3',
            ('ram:written',), (), (value,)) for value in values) + (
            Action('ram:read', read_source, 'F1', ('ram:consumed',), (), (0,)),))

    def record(self, action_id, value):
        action = self.catalog.get(action_id)
        if value not in action.values:
            raise ValueError('RAM decision outside shared domain')
        return ('F1:03200000' if action.operator == 'F1' else
                'F3:' + value.to_bytes(4, 'little').hex())


def ram_view(field, report, *, values):
    epoch = field.get('reset_epoch', 0)
    identity = ram_identity(field)
    written = identity is not None and field.get('writer_attributed') is True and field.get('value') in values
    consumed = written and any(row.get('reward_eligible') is True
        and row.get('status') == 'verified' and row.get('resource_identity') == identity
        for row in report.get('relations', ()))
    goal = Goal('ram:write-read', 'ram:consumed', (
        Condition('ram:written'), Condition('ram:consumed', ('ram:written',))))
    return goal, Snapshot(epoch, {
        'ram:written': Observation('satisfied' if written else 'unknown',
            str(field['value']) if written else 'unknown', ('live:ram-current',) if written else (), epoch),
        'ram:consumed': Observation('satisfied' if consumed else 'unknown',
            'consumed' if consumed else 'unobserved', ('live:ram-consumed',) if consumed else (), epoch)})


class RamCredit:
    """Only live-installed reports enter this helper; documents grant no trust."""
    def __init__(self, policy):
        self.policy = policy
        self.pending, self.writers, self.costs, self.case_decisions = {}, {}, {}, {}

    def observe(self, decision, case_id, field, report, cost_ns):
        identity = ram_identity(field)
        self.costs[decision.id] = cost_ns
        self.case_decisions[case_id] = decision.id
        answers, accepted = [], []
        for key, row in list(self.pending.items()):
            if identity is None or row['resource'] != identity:
                answers.append(self.policy.settle(key, {}, self.costs[key], censored=True))
                del self.pending[key]
        self.writers = {key: row for key, row in self.writers.items() if row['resource'] == identity}
        if decision.action_id.startswith('ram:write:') and identity is not None and field.get('writer_attributed') is True:
            self.pending[decision.id] = dict(case_id=case_id, resource=identity)
            self.writers[decision.id] = dict(case_id=case_id, resource=identity)
        joined = False
        for row in report.get('relations', ()):
            if (row.get('reward_eligible') is not True or row.get('status') != 'verified'
                    or row.get('read_case_id') != case_id
                    or identity is None or row.get('resource_identity') != identity):
                continue
            participants = tuple(sorted(set(self.case_decisions.get(v, '') for v in row['writer_case_ids'])))
            if (not participants or '' in participants
                    or not all(v in self.writers and self.writers[v]['resource'] == identity for v in participants)):
                continue
            participants = tuple(sorted(set(participants + (decision.id,))))
            feature = semantic_relation(row)
            result = self.policy.settle_relation_group(participants, {'relation': (feature,)},
                                                       {v: self.costs[v] for v in participants})
            if result is None:
                continue
            answers.extend(result)
            for key in participants: self.pending.pop(key, None)
            if any(['relation', feature] in result_row.get('novel_features', ()) for result_row in result):
                accepted.append(feature)
            joined = True
            break
        if decision.id not in self.pending and not joined:
            answers.append(self.policy.settle(decision.id, {}, cost_ns))
        return dict(settlements=answers, pending=sorted(self.pending),
                    credited_relations=accepted, native_authority=False)

    def finish(self):
        answers = [self.policy.settle(key, {}, self.costs[key], censored=True) for key in sorted(self.pending)]
        self.pending.clear()
        return dict(settlements=answers, relation_observation='budget-ended', native_authority=False)
