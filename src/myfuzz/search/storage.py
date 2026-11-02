"""R0 semantic view/lowering; current values are supplied by the live runtime.

The view is documentary only. The existing bound kernel and authority still
admit instructions, execute real requests and certify their effects.
"""
from dataclasses import dataclass
from copy import deepcopy
from hashlib import sha256

from .actions import Action, Catalog
from .model import Condition, Goal, Observation, Snapshot, canonical, identifier, natural


@dataclass(frozen=True)
class CurrentVersion:
    value: int
    field_version: int
    epoch: int
    evidence_ref: str
    contract: str

    def __post_init__(self):
        if type(self.value) is not int or not 0 <= self.value < 1 << 32:
            raise ValueError("uint32 current storage value required")
        natural(self.field_version)
        natural(self.epoch)
        identifier(self.evidence_ref)
        identifier(self.contract)

    @property
    def identity(self):
        return self.epoch, self.field_version, self.value, self.contract


def read_current(runtime) -> CurrentVersion:
    """Issue/consume a real current token; never write or step the DUT.

    The issuer itself verifies its exact class, build, native scope, command
    sequence and source. A query failure is propagated, never replaced with a
    saved postcondition. No token registry is read or modified by this module.
    """
    target = runtime.runner.sessions[runtime.target_id]
    witness = runtime.authority.consume(runtime.authority.issue(
        register=runtime.register_name, reset_epoch=target.reset_epoch))
    return CurrentVersion(witness["value"], witness["field_version"],
                          witness["reset_epoch"], "authority:" + sha256(canonical(witness)).hexdigest(),
                          witness["source_contract_digest"])


class StorageSearch:
    def __init__(self, values, *, write_source, read_source, address):
        if type(values) is not tuple or not 1 <= len(values) <= 16:
            raise ValueError("1..16 declared target values required")
        if type(address) is not int or not 0 <= address < 1 << 32 or address % 4:
            raise ValueError("aligned uint32 read address required")
        self.values = values
        self._consumed = None
        self._consume_ref = None
        actions = [Action(f"write:{value:08x}", write_source, "F4",
                          (f"written:{value:08x}",), (), (value,)) for value in values]
        actions.append(Action("read:current", read_source, "F2",
                              tuple(f"consumed:{value:08x}" for value in values), (), (address,)))
        self.catalog = Catalog(tuple(actions))

    def goal(self, target):
        if target not in self.values:
            raise ValueError("undeclared target value")
        written, consumed = f"written:{target:08x}", f"consumed:{target:08x}"
        return Goal(f"storage:{target:08x}", consumed,
                    (Condition(written), Condition(consumed, (written,))))

    def snapshot(self, current: CurrentVersion, target):
        if target not in self.values:
            raise ValueError("undeclared target value")
        written = current.field_version > 0 and current.value == target
        consumed = written and self._consumed == current.identity
        return Snapshot(current.epoch, {
            f"written:{target:08x}": Observation(
                "satisfied" if written else "refuted", "target" if written else "other",
                (current.evidence_ref,), current.epoch),
            f"consumed:{target:08x}": Observation(
                "satisfied" if consumed else "unknown", "current" if consumed else "unobserved",
                (self._consume_ref,) if consumed else (), current.epoch),
        })

    def observe_read(self, certificate, current):
        if (certificate.get("schema_version") != "compiled_F2_chain.v1"
                or certificate.get("status") != "certified"):
            raise ValueError("certified F2 observation required")
        for key in ("version_before", "version_witness"):
            row = certificate.get(key) or {}
            identity = (row.get("reset_epoch"), row.get("field_version"),
                        row.get("value"), row.get("source_contract_digest"))
            if identity != current.identity:
                raise ValueError("read did not witness the current version")
        identifier(certificate.get("case_id"))
        self._consumed = current.identity
        self._consume_ref = "certified-read:" + certificate["case_id"]

    def feedback(self, current, *, target):
        """Count certified declared relations independently of the chosen goal.

        An exploratory write/read of a different declared value is still an
        observed relation. Initial reset reads and overwritten versions are
        excluded. The policy performs session-level semantic deduplication.
        """
        from .frontier import status
        goal = self.goal(target)
        selected_complete = status(goal, self.snapshot(current, target), goal.root) == "satisfied"
        features = {}
        if (current.field_version > 0 and current.value in self.values
                and self._consumed == current.identity):
            features["relation"] = (f"write-read:{current.value:08x}",)
        return features, selected_complete


def lower_storage(decision, catalog, contexts, encoders):
    action = catalog.get(decision.action_id)
    if decision.value not in action.values:
        raise ValueError("decision parameter is outside the public action domain")
    context = contexts[action.operator]
    if context.current_source_id != action.source_id:
        raise ValueError("action does not match the actual compiled source")
    raw = encoders[action.operator].encode(decision.value)
    return {"testcase_id": f"dependency-search:{decision.sequence}",
            "path_id": context.path_id, "source_id": action.source_id,
            "raw_records_hex": [raw.hex()]}


class StorageCaseAdapter:
    """Bind the common case interface to existing storage runtime operations."""
    def __init__(self, runtime, engine, catalog, contexts, encoders, credit):
        self.runtime, self.engine, self.catalog = runtime, engine, catalog
        self.contexts, self.encoders, self.credit = contexts, encoders, credit

    def current_state(self):
        return read_current(self.runtime)

    def execute(self, decision, context):
        case = lower_storage(decision, self.catalog, self.contexts, self.encoders)
        if context.on_prepared is not None:
            context.on_prepared(case)
        return self.engine.submit(case)

    def settle(self, decision, context, receipt, current, features, cost_ns):
        return self.credit.observe(decision.id, receipt['flow_id'], current, features, cost_ns)


class StorageCredit:
    """Retain the producing decision until its version is consumed or replaced."""
    def __init__(self, policy):
        self.policy = policy
        self._pending = None

    def _partial(self):
        pending = self._pending
        answer = self.policy.settle(pending["decision_id"], pending["features"], pending["cost_ns"])
        self._pending = None
        return answer

    def observe(self, decision_id, flow, current, features, cost_ns):
        if flow not in ("F2", "F4") or type(current) is not CurrentVersion or type(cost_ns) is not int or cost_ns <= 0:
            raise ValueError("invalid storage contribution")
        settlements = []
        if flow == "F4":
            if self._pending is not None:
                settlements.append(self._partial())
            self._pending = {"decision_id": decision_id, "version": current.identity,
                             "features": deepcopy(features), "cost_ns": cost_ns}
        elif self._pending is not None and self._pending["version"] == current.identity:
            pending = self._pending
            merged = {kind: tuple(sorted(set(pending["features"].get(kind, ())) | set(features.get(kind, ()))))
                      for kind in sorted(set(pending["features"]) | set(features))}
            settlements.extend(self.policy.settle_group((pending["decision_id"], decision_id), merged,
                {pending["decision_id"]: pending["cost_ns"], decision_id: cost_ns}))
            self._pending = None
        else:
            if self._pending is not None:
                settlements.append(self._partial())
            settlements.append(self.policy.settle(decision_id, features, cost_ns))
        return {"settlements": settlements,
                "pending": None if self._pending is None else self._pending["decision_id"],
                "native_authority": False}

    def finalize_cost(self, decision_id, cost_ns):
        pending = self._pending
        if pending is not None and pending['decision_id'] == decision_id:
            if type(cost_ns) is not int or cost_ns < pending['cost_ns']:
                raise ValueError('final cost precedes execution cost')
            self.policy.finalize_cost(decision_id, cost_ns)
            pending['cost_ns'] = cost_ns
        else:
            self.policy.finalize_cost(decision_id, cost_ns)

    def finish(self):
        # Preserve observed producer-stage features for audit, separately from
        # the unobserved relation. A budget cutoff supplies no ordinary trial
        # or reward and must not consume stage novelty in the policy.
        settlements, producer = [], None
        if self._pending is not None:
            pending = self._pending
            producer = {"decision_id": pending["decision_id"],
                        "features": {kind: list(values)
                                     for kind, values in pending["features"].items()}}
            settlements.append(self.policy.settle(
                pending["decision_id"], {}, pending["cost_ns"], censored=True))
            self._pending = None
        return {"settlements": settlements, "producer_observation": producer,
                "relation_observation": "budget-ended", "native_authority": False}
