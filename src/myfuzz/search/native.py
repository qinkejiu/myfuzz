"""R0 adapter using the existing mixed runtime, kernel and native authority."""
from __future__ import annotations

import argparse
from dataclasses import asdict
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import time
import traceback

from .actions import Decision, context_key
from .case_adapter import CaseAdapter, CaseContext
from .frontier import frontier, status
from .journal import Journal, verify_journal
from .model import canonical
from .policy import Policy
from .storage import StorageSearch, StorageCredit, StorageCaseAdapter, lower_storage

PACKAGE = Path(__file__).resolve().parent
ROOT = Path(os.environ.get("MYFUZZ_SEARCH_BASE_DIR", str(PACKAGE.parents[2]))).resolve()
AUDIT = Path(os.environ.get("MYFUZZ_SEARCH_RESEARCH_DIR", str(ROOT / "research/input-strategy-audit-20261027"))).resolve()


def save(path, value):
    if path.name == 'summary.json':
        from .workflow import candidate_summary
        value = candidate_summary(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n")


def preflight(descriptor_path):
    from myfuzz.runtime.generic_campaign import load_descriptor
    descriptor_path = Path(descriptor_path).resolve()
    if not descriptor_path.is_file():
        raise ValueError("descriptor file missing")
    descriptor = load_descriptor(descriptor_path, base_dir=ROOT)
    if set(descriptor.flow_ids) != {"F2", "F4"} or descriptor.executor("F4") != "compiled_f4_obi_apb":
        raise ValueError("R0 requires the registered OBI/APB F2+F4 executor")
    tool = shutil.which("verilator")
    files = (descriptor_path, descriptor.compose, descriptor.capability, descriptor.supplement)
    return {"scope": "preflight-only", "native_executed": False,
            "scenario": descriptor.scenario_id, "flows": sorted(descriptor.flow_ids),
            "verilator": tool,
            "verilator_version": subprocess.check_output([tool, "--version"], text=True).strip() if tool else None,
            "input_files": [{"path": str(p.relative_to(ROOT)), "sha256": sha256(p.read_bytes()).hexdigest()} for p in files],
            "status": "ready-for-attempt" if tool else "missing-tool"}


def require_new_output(case_root, mode):
    case_root = Path(case_root).resolve()
    if not case_root.is_relative_to(AUDIT):
        raise ValueError("output must stay in the selected research directory")
    if mode not in ("original", "fresh"):
        raise ValueError("invalid execution mode")
    out = case_root / mode
    if out.exists():
        raise ValueError("existing output must never be overwritten")
    return out


def source_files():
    paths = sorted(PACKAGE.glob("*.py"))
    paths += [ROOT / n for n in (
        "src/myfuzz/runtime/generic_campaign.py", "src/myfuzz/runtime/engine.py",
        "src/myfuzz/runtime/flows/storage.py", "src/myfuzz/runtime/flows/mixed.py",
        "src/myfuzz/integration/compiled_f4.py",
        "src/myfuzz/scenario/apb_storage_register_version.py")]
    return [{"base": "research" if p.is_relative_to(AUDIT) else "project",
             "path": str(p.relative_to(AUDIT if p.is_relative_to(AUDIT) else ROOT)),
             "sha256": sha256(p.read_bytes()).hexdigest()} for p in paths]


def _prepare(descriptor, generated):
    from myfuzz.runtime.preparation import create_preparation
    from myfuzz.runtime.admission import verify_component
    from myfuzz.runtime.compiler import plan_bindings, requirement_for_binding, compile_execution_plan
    from myfuzz.runtime.registry import select_adapter
    generated.parent.mkdir(parents=True, exist_ok=True)
    context = create_preparation(base_dir=ROOT, compose_path=descriptor.compose,
        capability_paths=(descriptor.capability,), supplement_path=descriptor.supplement,
        generated_dir=generated, flow_ids=("F2", "F4"))
    try:
        components, selections, requirements, known = [], [], [], {}
        for binding in plan_bindings(context):
            component = known.get(binding.instance_id)
            if component is None:
                component = verify_component(context.artifact(binding.instance_id), preparation=context, base_dir=ROOT)
                known[binding.instance_id] = component
                components.append(component)
            requirement = requirement_for_binding(component, binding)
            selections.append(select_adapter(component, requirement, preparation=context))
            requirements.append(requirement)
        plan = compile_execution_plan(context, components=tuple(components),
                                      selections=tuple(selections), requirements=tuple(requirements))
        return context, plan
    except BaseException as error:
        try:
            context.close()
        except BaseException as cleanup:
            error.add_note("preparation cleanup: " + repr(cleanup))
        raise


def _decision_from_document(row):
    fields = {k: row[k] for k in ("sequence", "goal_id", "context", "action_id", "value", "reason", "entropy")}
    decision = Decision(**fields)
    if decision.document() != row:
        raise ValueError("saved typed decision identity mismatch")
    return decision


def load_replay_inputs(original, reference):
    """Bind replay sidecars to their anchored journal and timing version.

    Missing timing_schema explicitly selects legacy v1 execution-only costs;
    only v2 requires and admits the extended per-action accounting boundary.
    """
    verify_journal(original / "decisions.jsonl", expected_head=reference["journal_head"])
    documents = [json.loads(line)["document"] for line in (original / "decisions.jsonl").read_text().splitlines()]
    timing = reference.get('timing_schema', 'dependency_search_costs.v1')
    if timing not in ('dependency_search_costs.v1', 'dependency_search_costs.v2'):
        raise ValueError('unknown cost timing schema')
    stride = 3 if timing == 'dependency_search_costs.v2' else 2
    cases, states = [], []
    for index in range(reference["cases"]):
        rows = documents[stride * index:stride * (index + 1)]
        if len(rows) != stride:
            raise ValueError('missing cost finalization or decision/settlement order')
        first, second = rows[:2]
        if first.get("kind") != "decision" or second.get("kind") != "settlement":
            raise ValueError("journal decision/settlement order mismatch")
        cases.append({key: first[key] for key in ("target", "decision", "case")})
        states.append({key: value for key, value in second.items() if key != "kind"})
        if stride == 3:
            final = rows[2]
            keys = {'kind', 'schema_version', 'case_index', 'decision_id',
                    'execution_cost_ns', 'action_cost_ns', 'measured_action_cost_ns',
                    'policy_action_cost_ns'}
            if (set(final) != keys or final['kind'] != 'cost_finalization'
                    or final['schema_version'] != 'dependency_search_cost_finalization.v1'
                    or type(final['case_index']) is not int or final['case_index'] != index
                    or type(second.get('case_index')) is not int or second['case_index'] != index
                    or final['decision_id'] != first['decision']['decision_id']
                    or any(type(final[k]) is not int or final[k] <= 0 for k in
                           ('execution_cost_ns', 'action_cost_ns', 'measured_action_cost_ns', 'policy_action_cost_ns'))
                    or final['execution_cost_ns'] != second.get('execution_cost_ns')
                    or final['execution_cost_ns'] != second.get('cost_ns')
                    or final['action_cost_ns'] < final['execution_cost_ns']
                    or final['measured_action_cost_ns'] != final['action_cost_ns']
                    or final['policy_action_cost_ns'] != final['action_cost_ns']):
                raise ValueError('invalid cost finalization binding')
            states[-1]['cost_finalization'] = {k: v for k, v in final.items() if k != 'kind'}
    tail = documents[stride * reference["cases"]:]
    if tail:
        if len(tail) != 1 or tail[0].get("kind") != "terminal":
            raise ValueError("journal has unexpected terminal records")
        if tail[0]["credit"] != json.loads((original / "terminal-credit.json").read_text()):
            raise ValueError("terminal credit does not match the journal")
    if (cases != json.loads((original / "selected_cases.json").read_text())
            or states != json.loads((original / "state-transitions.json").read_text())):
        raise ValueError("replay sidecar does not match the verified journal")
    return cases, states


def validate_fresh_execution_audits(original, fresh):
    """Compare documentary audits of executions already run, never grant authority.

    PID numbers can repeat across namespaces or after reaping. Native launch
    nonces, executable/build bindings and successful cleanup identify replay.
    """
    nonces = set()
    components = None
    bound = ('build_digest', 'binary_sha256', 'artifact_digest',
             'observed_executable_sha256', 'ready_artifact_digest')
    for audit in (original, fresh):
        if (type(audit) is not dict or audit.get('schema_version') != 'compiled_F4_execution_audit.v1'
                or audit.get('closed') is not True
                or type(audit.get('identities')) is not dict or not audit['identities']
                or type(audit.get('exits')) is not dict
                or set(audit['exits']) != set(audit['identities'])):
            raise ValueError('invalid native execution audit')
        if components is None:
            components = set(audit['identities'])
        if components != set(audit['identities']):
            raise ValueError('fresh execution component mismatch')
        for component, row in audit['identities'].items():
            exit_row = audit['exits'][component]
            if (type(row) is not dict or row.get('component') != component
                    or type(row.get('role')) is not str or not row['role']
                    or type(row.get('pid')) is not int or row['pid'] <= 0
                    or type(exit_row) is not dict or exit_row.get('reaped') is not True
                    or type(exit_row.get('returncode')) is not int or exit_row['returncode'] != 0):
                raise ValueError('invalid native execution identity or exit')
            nonce = row.get('execution_nonce')
            if (type(nonce) is not str or len(nonce) != 32
                    or any(c not in '0123456789abcdef' for c in nonce) or nonce in nonces):
                raise ValueError('invalid or reused native execution nonce')
            nonces.add(nonce)
            if any(type(row.get(key)) is not str or len(row[key]) != 64
                   or any(c not in '0123456789abcdef' for c in row[key]) for key in bound):
                raise ValueError('invalid native execution digest')
            if (row['binary_sha256'] != row['observed_executable_sha256']
                    or row['artifact_digest'] != row['ready_artifact_digest']):
                raise ValueError('native executable or ready binding mismatch')
    for component in components:
        a, b = original['identities'][component], fresh['identities'][component]
        if any(a[key] != b[key] for key in bound + ('role',)):
            raise ValueError('fresh native build or artifact mismatch')


def persist_action_cost(*, out, selected_cases, state_rows, journal, credit,
                        decision_id, action_started_ns, replay_action_cost_ns=None,
                        clock_ns=None):
    """Measure major persistence; expose the finite accounting cutoff explicitly.

    credit.observe has already run. Its time, and persistence below, belong to
    the action. Final cost mutation and its own journal record form e2e tail.
    """
    clock_ns = clock_ns or time.monotonic_ns
    state = state_rows[-1]
    journal.append({'kind': 'settlement', **state})
    save(out / 'selected_cases.json', selected_cases)
    save(out / 'state-transitions.json', state_rows)
    action_cost = max(1, clock_ns() - action_started_ns)
    tail_started = clock_ns()
    policy_cost = action_cost if replay_action_cost_ns is None else replay_action_cost_ns
    credit.finalize_cost(decision_id, policy_cost)
    finalization = dict(schema_version='dependency_search_cost_finalization.v1',
        case_index=state['case_index'], decision_id=decision_id,
        execution_cost_ns=state['execution_cost_ns'], action_cost_ns=action_cost,
        measured_action_cost_ns=action_cost, policy_action_cost_ns=policy_cost)
    state['cost_finalization'] = finalization
    journal.append({'kind': 'cost_finalization', **finalization})
    return clock_ns() - tail_started


def cleanup_resources(engine, runtime, bound, context, out):
    """Attempt every finalizer independently; never replace a primary failure."""
    errors = []

    def attempt(stage, function):
        try:
            function()
        except BaseException as error:
            errors.append({"stage": stage, "type": type(error).__name__, "error": str(error)})

    if engine is not None:
        def drain():
            if engine.state in ("RUNNING", "FAULTED"):
                save(out / "partial-campaign.json", engine.abort("r0-primary-error"))
        attempt("engine-drain", drain)
        attempt("engine-close", engine.close)
    if runtime is not None:
        def finish():
            if not runtime.finished:
                runtime.finish()
        attempt("runtime-finish", finish)
    if bound is not None:
        attempt("bound-close", bound.close)
    if context is not None:
        attempt("preparation-close", context.close)
    return errors


def archive_preparation(case_root: Path, mode: str) -> None:
    """Preserve all exclusive preparation outputs, freeing the exact replay path."""
    if mode not in ("original", "fresh"):
        raise ValueError("unknown archive mode")
    destination = case_root / f"work-{mode}-archived"
    if destination.exists() or destination.is_symlink():
        raise ValueError("preparation archive already exists")
    shutil.move(str(case_root / "work"), str(destination))


def fresh_case_count(reference, request):
    """Validate the original request before admitting its actual replay length."""
    expected = reference.get('request')
    if expected is None:
        expected = {key: reference.get(key) for key in request}
        expected['requested_cases'] = reference.get('requested_cases', reference.get('cases'))
    if expected != request:
        raise ValueError('fresh execution request differs from original')
    actual = reference.get('cases')
    if type(actual) is not int or not 0 <= actual <= request['requested_cases']:
        raise ValueError('invalid original actual case count')
    return actual


def execute(*, descriptor_path, case_root, mode, seed=7, cases=6, strategy="state",
            rounds=32, base_dir=None, cache_dir=None, seconds=None,
            restrict_output=True, record_local_commands=False, command_trace=None, execution_mode=None):
    from contextlib import nullcontext
    from myfuzz.local_harness.session import record_local_commands as capture
    if record_local_commands and command_trace is not None:
        raise ValueError('recording must have one context owner')
    with capture() if record_local_commands else nullcontext(command_trace) as trace:
        return _execute(descriptor_path=descriptor_path, case_root=case_root, mode=mode,
            seed=seed, cases=cases, strategy=strategy, rounds=rounds, base_dir=base_dir,
            cache_dir=cache_dir, seconds=seconds, restrict_output=restrict_output,
            command_trace=trace, execution_mode=execution_mode)


def _execute(*, descriptor_path, case_root, mode, seed=7, cases=6, strategy="state", rounds=32, base_dir=None, cache_dir=None, seconds=None, restrict_output=True, command_trace=None, execution_mode=None):
    from myfuzz.search.workflow import requires_replay
    from myfuzz.runtime.generic_campaign import load_descriptor, _verification
    requires_replay(execution_mode, mode)
    from myfuzz.runtime.binding import bind_execution_plan
    from myfuzz.runtime.engine import PersistentCampaignRuntime
    from myfuzz.runtime.flows.mixed import MixedStorageKernel, MixedStorageFlowBackend
    from myfuzz.runtime.campaign import RfuzzDirectedAdapter
    from myfuzz.local_harness.generated_execution_admission import create_compiled_execution

    if base_dir is not None and Path(base_dir).resolve() != ROOT:
        raise ValueError("base_dir must match the installed project root")
    if seconds is not None and (type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds <= 0):
        raise ValueError("seconds must be finite and positive")
    requested_cases = cases
    request = dict(seed=seed, strategy=strategy, rounds=rounds,
                   seconds=seconds, requested_cases=requested_cases)
    if type(cases) is not int or not 1 <= cases <= 65536:
        raise ValueError("requires 1..65536 cases")
    if type(rounds) is not int or not 1 <= rounds <= 1024:
        raise ValueError("R0 requires 1..1024 rounds")
    descriptor_path, case_root = Path(descriptor_path).resolve(), Path(case_root).resolve()
    check = preflight(descriptor_path)
    if check["status"] != "ready-for-attempt":
        raise ValueError("native tool unavailable")
    if restrict_output:
        out = require_new_output(case_root, mode)
    else:
        if mode not in ("original", "fresh"):
            raise ValueError("invalid execution mode")
        out = case_root / mode
        if out.exists() or out.is_symlink():
            raise ValueError("existing output must never be overwritten")
    original = case_root / "original"
    frozen = source_files()
    reference = None
    if mode == "fresh":
        reference = json.loads((original / "summary.json").read_text())
        if reference.get("status") not in ("mechanism-pass", "budget-ended", "observed-uncompleted") or reference["source_files"] != frozen:
            raise ValueError("fresh requires a successful same-source original")
        _require_original_boundary(original, reference)
        cases = fresh_case_count(reference, request)
        saved_decisions, saved_states = load_replay_inputs(original, reference)
    out.mkdir(parents=True)
    save(out / "preflight.json", check)
    save(out / "source-files.json", frozen)
    generated = case_root / "work/generated"
    if generated.exists():
        raise ValueError("generated path already exists; preserve the failed attempt")
    descriptor = load_descriptor(descriptor_path, base_dir=ROOT)
    runtime = engine = context = bound = None
    started = time.monotonic()
    journal = Journal(out / "decisions.jsonl")
    selected_cases, state_rows = [], []
    accounting_tail_ns = 0
    primary_error = None
    failure_phase = "preparation"
    attempted_case_count = 0
    try:
        context, plan = _prepare(descriptor, generated)
        (out / "execution_plan.json").write_bytes(plan.document_bytes)
        if mode == "fresh" and plan.document_bytes != (original / "execution_plan.json").read_bytes():
            raise ValueError("fresh execution plan bytes changed")
        runtime = create_compiled_execution(artifacts=context.artifacts,
            compiled_inputs=context.compiled_inputs(), executor=descriptor.executor("F4"),
            base_dir=ROOT, cache_dir=Path(cache_dir) if cache_dir is not None else case_root / "cache", run_id="dependency-search-r0",
            rounds_per_case=rounds, max_cases=cases + 1, mixed_flows=True, defer_begin=True)
        sessions = dict(runtime.runner.sessions)
        context.attach_runtime(runner=runtime.runner, sessions=sessions)
        admitted = runtime.runtime_path_admission.prepared
        context.register_prepared_paths(prepared=admitted, runtime_paths=admitted.runtime_paths, graph=admitted.graph)
        bound = bind_execution_plan(plan, preparation=context, sessions=sessions,
                                    prepared_paths=admitted, runner=runtime.runner)
        backend, kernel = MixedStorageFlowBackend(runtime=runtime), MixedStorageKernel()
        engine = PersistentCampaignRuntime(bound, kernel=kernel, channel=backend.open(),
            path_id="mixed:F2+F4", run_id="dependency-search-r0", max_cases=requested_cases)
        engine.prepare()
        contexts = engine.context.flows
        encoders = {flow: RfuzzDirectedAdapter(kernel=kernel, context=ctx,
            mutate_source_id=ctx.current_source_id) for flow, ctx in contexts.items()}
        write_values = tuple(dict.fromkeys(int.from_bytes(bytes.fromhex(raw), "little")
                                            for raw in descriptor.f4_records))
        if not write_values:
            raise ValueError("descriptor must expose finite nonempty write values")
        read_domain = next(d for d in contexts["F2"].domains if d.source_id == contexts["F2"].current_source_id)
        search = StorageSearch(write_values, write_source=contexts["F4"].current_source_id,
            read_source=contexts["F2"].current_source_id, address=read_domain.minimum)
        # Use the existing kernel to preflight every public action/value before start.
        for i, action in enumerate(search.catalog.actions):
            for value in action.values:
                probe = Decision(i, "preflight", "preflight", action.id, value, "preflight", 0)
                engine.validate(lower_storage(probe, search.catalog, contexts, encoders))
        save(out / "public-catalog.json", {"sha256": search.catalog.identity,
             "actions": [asdict(a) for a in search.catalog.actions], "native_authority": False})
        policy = Policy(seed=seed, mode=strategy)
        credit = StorageCredit(policy)
        case_adapter: CaseAdapter = StorageCaseAdapter(runtime, engine, search.catalog, contexts, encoders, credit)
        engine.start()
        search_started = time.monotonic()
        deadline = None if seconds is None or mode == "fresh" else search_started + seconds
        target_index = 0
        for index in range(cases):
            if deadline is not None and time.monotonic() >= deadline:
                break
            failure_phase = "decision"
            t0 = time.monotonic_ns()
            target = search.values[target_index % len(search.values)]
            goal = search.goal(target)
            before = case_adapter.current_state()
            view = search.snapshot(before, target)
            decision_started_ns = time.monotonic_ns()
            decision = policy.choose(goal, view, search.catalog)
            decision_seconds = max(0, time.monotonic_ns() - decision_started_ns) / 1e9
            if mode == "fresh":
                expected = saved_decisions[index]
                if target != expected["target"]:
                    raise ValueError("fresh semantic goal sequence changed")
                saved_decision = _decision_from_document(expected["decision"])
                if decision != saved_decision:
                    raise ValueError("fresh policy decision differs from recorded entropy/state/cost replay")
                actual_context = context_key(goal, view, frontier(goal, view),
                                            tuple(a.id for a in search.catalog.eligible(view)))
                if decision.context != actual_context or decision.goal_id != goal.id:
                    raise ValueError("fresh decision state or goal changed")
            def before_submit(row):
                nonlocal failure_phase, attempted_case_count
                if mode == "fresh" and row != expected["case"]:
                    raise ValueError("fresh typed decision lowers to different bytes")
                entry = {"target": target, "decision": decision.document(), "case": row}
                selected_cases.append(entry)
                journal.append({"kind": "decision", **entry,
                                "state": asdict(before), "frontier": frontier(goal, view)})
                failure_phase = "submit"
                attempted_case_count += 1
            case_context = CaseContext(f'dependency-search:{decision.sequence}', on_prepared=before_submit)
            record = case_adapter.execute(decision, case_context)
            if not record["evidence"] or any(e["status"] != "certified" for e in record["evidence"]):
                raise ValueError("runtime did not certify the R0 effect")
            failure_phase = "feedback"
            after = case_adapter.current_state()
            certificate = record["records"][0]["certificate"]
            if record["flow_id"] == "F2":
                search.observe_read(certificate, after)
            new_view = search.snapshot(after, target)
            advanced = tuple(key for key in frontier(goal, view)
                             if new_view.get(key).status == "satisfied")
            features = {"frontier": advanced}
            actual_relations, complete = search.feedback(after, target=target)
            features.update(actual_relations)
            if complete:
                target_index += 1
            observed_seconds = max(0, time.monotonic() - search_started)
            cost = max(1, time.monotonic_ns() - t0)
            replay_cost = cost
            if mode == "fresh":
                original_step = saved_states[index]
                if json.loads(canonical(features)) != original_step["features"]:
                    raise ValueError("fresh semantic feedback changed")
                replay_cost = original_step.get("execution_cost_ns", original_step["cost_ns"])
            settlement = case_adapter.settle(decision, case_context, record, after, features, replay_cost)
            if mode == "fresh" and settlement != original_step["settlement"]:
                raise ValueError("fresh reward/novelty/participant settlement changed")
            state_rows.append({"case_index": index, "target": target, "flow": record["flow_id"],
                "before": asdict(before), "after": asdict(after), "features": features,
                "complete": complete, "observed_seconds": observed_seconds,
                "decision_seconds": decision_seconds, "testcase_id": selected_cases[-1]["case"]["testcase_id"],
                "evidence_certified": True, "cost_ns": cost, "execution_cost_ns": cost, "settlement": settlement})
            original_cost = None
            if mode == 'fresh':
                original_cost = original_step.get('cost_finalization', {}).get('action_cost_ns', replay_cost)
            accounting_tail_ns += persist_action_cost(
                out=out, selected_cases=selected_cases, state_rows=state_rows,
                journal=journal, credit=credit, decision_id=decision.id,
                action_started_ns=t0, replay_action_cost_ns=original_cost)
        failure_phase = "finalization"
        search_seconds = max(0, time.monotonic() - search_started)
        tail_started = time.monotonic_ns()
        save(out / 'selected_cases.json', selected_cases)
        save(out / 'state-transitions.json', state_rows)
        accounting_tail_ns += time.monotonic_ns() - tail_started
        terminal_credit = credit.finish()
        if mode == "fresh" and terminal_credit != json.loads((original / "terminal-credit.json").read_text()):
            raise ValueError("fresh terminal credit differs")
        save(out / "terminal-credit.json", terminal_credit)
        journal.append({"kind": "terminal", "credit": terminal_credit})
        campaign = engine.finish()
        save(out / "campaign.json", campaign)
        prefix = runtime.finish()
        require_replay, replay_reason = _replay_policy(execution_mode, mode, state_rows)
        interesting = any(step['features'].get('relation') for step in state_rows)
        _save_execution_prefix(out, prefix, runtime.trace.events, execution_mode=execution_mode,
            mode=mode, recorded=command_trace is not None, interesting=interesting,
            plan_sha256=plan.identity_sha256, executed_cases=len(state_rows))
        execution_audit = runtime.execution_audit()
        save(out / "execution_audit.json", execution_audit)
        replay = {'matches': None}
        if require_replay:
            replay_audit = {}
            if command_trace is None:
                replay = runtime.replay(prefix)
            else:
                replay = runtime.replay(prefix, audit_sink=replay_audit.update)
                from myfuzz.runtime.recorded_commands import recorded_command_documents
                fresh_audit = replay_audit.get('execution_audit')
                if type(fresh_audit) is not dict:
                    raise ValueError('fresh recording requires actual replay execution audit')
                validate_fresh_execution_audits(execution_audit, fresh_audit)
                documents = recorded_command_documents(command_trace.export_sessions(),
                    executions={'original': execution_audit['identities'],
                                'fresh': fresh_audit['identities']}, scope='storage search', audited=True)
                save(out / 'local_commands.json', documents['original'])
                save(out / 'fresh_local_commands.json', documents['fresh'])
            save(out / "replay.json", {k: v for k, v in replay.items() if k not in ("actual_prefix", "actual_events")})
            if replay.get("matches") is not True:
                raise ValueError("full prefix runtime replay mismatch")
        elif command_trace is not None:
            from myfuzz.runtime.recorded_commands import recorded_command_documents
            documents = recorded_command_documents(command_trace.export_sessions(),
                executions={'original': execution_audit['identities']}, scope='storage search', audited=True)
            save(out / 'local_commands.json', documents['original'])
        identities = campaign["process_identities"]
        if mode == "fresh":
            validate_fresh_execution_audits(
                json.loads((original / 'execution_audit.json').read_text()), execution_audit)
            if prefix["semantic_hash"] != reference["semantic_hash"]:
                raise ValueError("fresh complete prefix semantic hash differs")
        if (mode == 'fresh' or execution_mode not in ('search', 'develop')) and source_files() != frozen:
            raise ValueError("source changed during R0")
        completed = len({feature for step in state_rows for feature in step["features"].get("relation", ())})
        summary = {"schema_version": "dependency_search_r0.v1", "status": ("budget-ended" if len(state_rows) < requested_cases else "mechanism-pass" if completed else "observed-uncompleted"),
            "requested_cases": requested_cases, "seconds": seconds, "request": request,
            "budget": {"max_cases": requested_cases, "max_seconds": seconds,
                       "actual_cases": len(state_rows), "boundary": "before-action",
                       "overshoot": "one in-flight action plus cleanup/replay may exceed wall budget"},
            "scope": "finite storage mechanism only; no useful-search claim",
            "mode": mode, "strategy": strategy, "seed": seed, "cases": len(state_rows), "rounds": rounds,
            "completed_targets": completed, "flows": [r["flow"] for r in state_rows],
            "selected_goal_completions": sum(step["complete"] for step in state_rows),
            "initialization_counts": campaign["initialization_counts"],
            "process_identities": identities, "replay_matches": replay["matches"],
            "execution_mode": execution_mode, "replay_reason": replay_reason, "verification": {**_verification(replay["matches"], mode),
                "cross_invocation": {"status": "verified" if mode == "fresh" else "not-requested",
                    "matches": True if mode == "fresh" else None}},
            "semantic_hash": prefix["semantic_hash"], "plan_sha256": plan.identity_sha256,
            "journal_head": journal.head, "source_files": frozen,
            "statistics": policy.statistics(),
            "metrics": {
                "certified_events": ([{"seconds": step["observed_seconds"], "semantic_key": key}
                    for step in state_rows for key in step["features"].get("relation", ())]
                    if seconds is not None else None),
                "useful_case_events": ([{"seconds": step["observed_seconds"],
                    "case_id": step["testcase_id"]} for step in state_rows
                    if step["features"].get("relation")] if seconds is not None else None),
                "interaction_status": "available" if seconds is not None else "unavailable-no-time-budget",
                "decision_seconds": [step["decision_seconds"] for step in state_rows],
                "search_seconds": search_seconds, "build_seconds": None, "init_seconds": None,
                "fresh": {"status": "verified" if mode == "fresh" else "not-run"}},
            "timing_schema": "dependency_search_costs.v2",
            "policy_cost_basis": (reference.get('timing_schema', 'dependency_search_costs.v1')
                                  if mode == 'fresh' else 'dependency_search_costs.v2'),
            "accounting_tail_ns": accounting_tail_ns,
            "timing_cutoff": "after cleanup/archive; excludes final summary serialization"}
        verify_journal(out / "decisions.jsonl", expected_head=journal.head)
    except BaseException as error:
        primary_error = error
        diagnostics = {}
        if runtime is not None:
            from myfuzz.integration.compiled_f4 import _closure
            current = _closure(ROOT)
            old = runtime.closure
            diagnostics["changed_executor_sources"] = [
                {"path": key, "before": old.get(key), "after": current.get(key)}
                for key in sorted(set(old) | set(current)) if old.get(key) != current.get(key)]
        save(out / "failure.json", {"status": "failed-preserved", "type": type(error).__name__,
            "error": str(error), "traceback": traceback.format_exc(), "effect_possible": runtime is not None,
            "journal_head": journal.head, "source_files": frozen,
            "failure_phase": failure_phase, "attempted_case_count": attempted_case_count, **diagnostics})
        raise
    finally:
        errors = cleanup_resources(engine, runtime, bound, context, out)
        if errors:
            save(out / "cleanup-errors.json", errors)
            if primary_error is None:
                raise RuntimeError("R0 cleanup failed; success not published")
            for error in errors:
                primary_error.add_note("cleanup: " + repr(error))
    # Required finalizers completed before publishing a successful terminal.
    archive_preparation(case_root, mode)
    summary["wall_seconds"] = time.monotonic() - started
    save(out / "summary.json", summary)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--descriptor", type=Path,
        default=ROOT / "configs/scenarios/compiled-f4-obi-apb-timer/generic_scenario.json")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--mode", choices=("original", "fresh"), default="original")
    parser.add_argument("--case", type=Path)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--cases", type=int, default=6)
    parser.add_argument("--strategy", choices=("state", "uniform", "legacy"), default="state")
    parser.add_argument("--rounds", type=int, default=32)
    args = parser.parse_args(argv)
    if args.preflight:
        print(json.dumps(preflight(args.descriptor), ensure_ascii=False))
        return 0
    if args.case is None:
        parser.error("--case is required for real execution")
    from myfuzz.local_harness.build import host_source_discovery_scope
    with host_source_discovery_scope(reuse_nested=True):
        summary = execute(descriptor_path=args.descriptor, case_root=args.case, mode=args.mode,
                          seed=args.seed, cases=args.cases, strategy=args.strategy, rounds=args.rounds)
    print(json.dumps({k: summary[k] for k in ("status", "scope", "mode", "flows", "completed_targets", "replay_matches", "wall_seconds")}))
    return 0


def _require_original_boundary(original, reference):
    """A pending raw candidate needs the public driver's successful boundary."""
    boundary = reference.get('verification', {}).get('session_boundary', {})
    if not boundary:
        return
    if boundary.get('status') == 'verified' and boundary.get('matches') is True:
        return
    if boundary.get('status') != 'pending':
        raise ValueError('fresh original session boundary is unverified')
    try:
        public = json.loads((original / 'search-summary.json').read_text())
    except (OSError, ValueError) as error:
        raise ValueError('fresh original session boundary is unverified') from error
    verified = public.get('verification', {}).get('session_boundary', {})
    if verified.get('status') != 'verified' or verified.get('matches') is not True:
        raise ValueError('fresh original session boundary is unverified')
    fields = ('semantic_hash', 'plan_sha256', 'journal_head', 'source_files', 'request', 'execution_mode')
    if public.get('mode') != 'original' or any(public.get(key) != reference.get(key) for key in fields):
        raise ValueError('fresh original session boundary binding mismatch')


def _replay_policy(execution_mode, mode, state_rows):
    from .workflow import requires_replay
    interesting = any(step['features'].get('relation') for step in state_rows)
    requested = requires_replay(execution_mode, mode, interesting=interesting)
    reason = ('fresh' if mode == 'fresh' else 'acceptance' if execution_mode == 'acceptance'
              else 'new-certified-relation' if execution_mode == 'search' and interesting
              else 'legacy' if requested else 'not-requested')
    return requested, reason


def _save_execution_prefix(out, prefix, events, *, execution_mode, mode, recorded,
                           interesting, plan_sha256, executed_cases):
    lightweight = execution_mode == 'search' and mode == 'original' and not recorded and not interesting
    if lightweight:
        save(out / 'prefix.json', {'schema_version':'dependency_search_prefix_summary.v1',
            'semantic_hash':prefix['semantic_hash'], 'plan_sha256':plan_sha256,
            'executed_case_count':executed_cases, 'full_prefix_saved':False})
    else:
        save(out / 'prefix.json', prefix)
        save(out / 'events.json', list(events))
