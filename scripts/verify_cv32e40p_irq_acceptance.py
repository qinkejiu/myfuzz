#!/usr/bin/env python3
"""Independent audit of a saved CV32E40P IRQ acceptance run.

Reads only saved artifacts (never runs RTL) and re-derives every claim it
accepts: the normalized prefix identity, the raw trace semantic hash, the two
component process identities, the real pre-edge IRQ acceptance probes, the
handler-entry retirement, the MRET retirement and the absence of any fabricated
RVFI field.  Anything it cannot recompute is reported as unavailable, never
estimated.

Scope: archived-artifact consistency.  It grants no live authority and does not
turn a saved journal into a native observation.
"""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'src')]

SCHEMA = 'cv32e40p_irq_acceptance_audit.v1'
FORBIDDEN_RETIREMENT_FIELDS = ('intr', 'pc_wdata', 'trap', 'halt', 'mode',
                               'mem_addr', 'mem_rdata', 'mem_wdata',
                               'mem_rmask', 'mem_wmask')


def _load(path):
    return json.loads(Path(path).read_text())


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False)


def _sha(value):
    return sha256(_canonical(value).encode()).hexdigest()


def _events(prefix):
    events = prefix.get('actual_events') or prefix.get('events') or []
    return events


def _by_id(events):
    return {event['event_id']: event for event in events}


def _retirements(events, cpu_id):
    return [event for event in events if event.get('kind') == 'cpu_retire'
            and event.get('component') == cpu_id]


def _fabrication_check(events, cpu_id):
    offenders = []
    for event in _retirements(events, cpu_id):
        present = [name for name in FORBIDDEN_RETIREMENT_FIELDS if name in event]
        if present:
            offenders.append({'event_id': event.get('event_id'), 'fields': present})
    return offenders


def _acceptance_check(events, provider):
    acceptance = (provider or {}).get('decision_acceptance') or {}
    source_id = acceptance.get('source_id')
    takes = [event for event in events if event.get('kind') == 'cpu_external_irq_taken']
    rows = []
    for take in takes:
        rows.append(dict(event_id=take.get('event_id'),
            irq_taken_pre=take.get('irq_taken_pre'),
            irq_ack_pre=take.get('irq_ack_pre'),
            irq_id_pre=take.get('irq_id_pre'),
            irq_entry_pc=take.get('irq_entry_pc'),
            take_key=take.get('take_key'),
            ok=(take.get('irq_taken_pre') == 1 and take.get('irq_ack_pre') == 1
                and take.get('irq_id_pre') == source_id
                and type(take.get('irq_entry_pc')) is int
                and take['irq_entry_pc'] % 4 == 0)))
    return rows


def _resolve_f5(record, events, by_id):
    certificate = record.get('certificate') or {}
    isr = certificate.get('irq_isr') or {}
    details = []
    for entry in isr.get('certificates', ()):
        authority = entry.get('retirement_authority')
        entry_retirement = entry.get('entry_retirement') or {}
        mret_event_id = entry.get('mret_event')
        mret = by_id.get(mret_event_id, {})
        entry_event = by_id.get(entry_retirement.get('event_id'), {})
        details.append(dict(
            case_id=entry.get('case_id'),
            retirement_authority=authority,
            unobserved_fields=entry.get('unobserved_fields'),
            native_take_event_id=entry.get('native_take_event_id'),
            entry_retirement=entry_retirement,
            entry_event_matches=(type(entry_event) is dict
                and entry_event.get('pc_rdata') == entry_retirement.get('pc')
                and entry_event.get('insn') == entry_retirement.get('insn')
                and entry_event.get('order') == entry_retirement.get('order')
                and entry_event.get('kind') == 'cpu_retire'),
            mret_event=mret_event_id,
            mret_is_architectural=(mret.get('insn') == 0x30200073),
            return_PC=entry.get('return_PC'),
            raw_mret_pc_wdata=entry.get('raw_mret_pc_wdata'),
            return_proof_authority=(entry.get('return_proof') or {}).get('retirement_authority'),
            no_fabricated_claims=(entry.get('raw_mret_pc_wdata') is None
                and 'pc_wdata' not in (entry.get('return_proof') or {})),
        ))
    return dict(case_id=certificate.get('case_id'), status=isr.get('status'),
                reason=isr.get('reason'), authority=isr.get('retirement_authority'),
                certificates=details)


def _resolve_f6(record, events, by_id, inventory=None):
    certificate = record.get('certificate') or {}
    observations = certificate.get('observations') or {}
    statuses = {name: (row or {}).get('status') if isinstance(row, dict) else row
                for name, row in observations.items()}
    refs = [ref for row in observations.values() if isinstance(row, dict)
            for ref in (row.get('evidence_refs') or ())]
    resolved = (None if inventory is None else
                all(ref in inventory and isinstance(inventory[ref], dict)
                    and bool(inventory[ref].get('details')) for ref in refs))
    return dict(case_id=certificate.get('case_id'), statuses=statuses,
                evidence_refs=len(refs), evidence_resolved=resolved,
                all_passed=bool(statuses) and all(v == 'passed' for v in statuses.values()))


def audit_phase(case_root, mode, *, cpu_id='cpu'):
    phase = Path(case_root) / mode
    summary = _load(phase / 'summary.json')
    prefix = _load(phase / 'prefix.json')
    events = _events(prefix)
    by_id = _by_id(events)
    component = None
    sample = next((event for event in events
                   if event.get('kind') == 'cpu_external_irq_sample'), None)
    provider = (sample or {}).get('observation_contract')
    result = dict(mode=mode, summary=summary, event_count=len(events),
        semantic_hash_matches=None, normalized_prefix_sha256=None,
        irq_acceptance=_acceptance_check(events, provider),
        fabricated_retirement_claims=_fabrication_check(events, cpu_id),
        f5=[], f6=[], unavailable=[])
    # Recompute the stored raw-trace semantic hash if the trace fields exist.
    trace_status = prefix.get('trace_status')
    trace_ticks = prefix.get('trace_local_ticks')
    stored = prefix.get('semantic_hash')
    if trace_status is not None and isinstance(trace_ticks, dict) and stored:
        from myfuzz.scenario.session_runtime import _trace_semantic_sha256
        actual = _trace_semantic_sha256(trace_status, events, trace_ticks)
        result['semantic_hash_matches'] = (actual == stored)
        result['recomputed_semantic_hash'] = actual
    else:
        result['unavailable'].append('raw trace semantic hash fields absent')
    from myfuzz.integration.compiled_f6 import _normalized_f6_prefix
    result['normalized_prefix_sha256'] = sha256(
        _canonical(_normalized_f6_prefix(prefix)).encode()).hexdigest()
    records = prefix.get('records') or []
    material = prefix.get('assertion_material') or {}
    inventories = {case.get('case_id'): (case.get('evidence_inventory') or {})
                   for case in (material.get('assertion_evidence') or {}).get('cases') or ()
                   if isinstance(case, dict)}
    for record in prefix.get('flow_records') or []:
        flow = record.get('flow')
        if flow == 'F5':
            result['f5'].append(_resolve_f5(record, events, by_id))
        elif flow == 'F6':
            case_id = (record.get('certificate') or {}).get('case_id')
            result['f6'].append(_resolve_f6(record, events, by_id,
                                            inventories.get(case_id)))
    identities = (prefix.get('original_execution_audit') or {}).get('identities') or {}
    result['identities'] = identities
    result['flow_case_counts'] = {}
    for record in prefix.get('flow_records') or []:
        flow = record.get('flow')
        result['flow_case_counts'][flow] = result['flow_case_counts'].get(flow, 0) + 1
    result['record_count'] = len(records)
    result['local_ticks'] = prefix.get('trace_local_ticks')
    result['declared_status'] = summary.get('status')
    result['replay_matches'] = summary.get('replay_matches')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--case-root', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cpu-id', default='cpu')
    args = parser.parse_args()
    if args.output.exists():
        raise ValueError('audit output must not exist')
    original = audit_phase(args.case_root, 'original', cpu_id=args.cpu_id)
    fresh = audit_phase(args.case_root, 'fresh', cpu_id=args.cpu_id)
    normalized_equal = (original['normalized_prefix_sha256']
                        == fresh['normalized_prefix_sha256'])
    # Two real processes must differ per component.
    independent = True
    detail = {}
    for component in set(original['identities']) & set(fresh['identities']):
        first, second = original['identities'][component], fresh['identities'][component]
        same = (first.get('pid') == second.get('pid')
                or first.get('execution_nonce') == second.get('execution_nonce'))
        detail[component] = dict(original=first, fresh=second, independent=not same)
        independent = independent and not same
    checks = {
        'both_phases_replay_matched': (original.get('replay_matches') is True
                                       and fresh.get('replay_matches') is True),
        'normalized_prefix_matches': normalized_equal,
        'processes_independent': independent,
        'semantic_hash_recomputed': (original.get('semantic_hash_matches') is True
                                     and fresh.get('semantic_hash_matches') is True),
        'no_fabricated_retirement_claims': (not original['fabricated_retirement_claims']
                                            and not fresh['fabricated_retirement_claims']),
        'irq_acceptance_probes_real': bool(original['irq_acceptance'])
            and all(row['ok'] for row in original['irq_acceptance'])
            and bool(fresh['irq_acceptance'])
            and all(row['ok'] for row in fresh['irq_acceptance']),
        'f5_evidence_resolves': bool(original['f5']) and all(
            item['status'] == 'verified'
            and item.get('authority') == 'pc_insn_order_only'
            and item['certificates']
            and all(cert['entry_event_matches'] and cert['mret_is_architectural']
                    and cert['no_fabricated_claims']
                    and cert['retirement_authority'] == 'pc_insn_order_only'
                    for cert in item['certificates'])
            for item in original['f5']) and bool(fresh['f5']) and all(
            item['status'] == 'verified' for item in fresh['f5']),
        'f6_evidence_passed': bool(original['f6']) and all(
            item['all_passed'] and item.get('evidence_resolved') is True
            for item in original['f6']) and bool(fresh['f6'])
            and all(item['all_passed'] and item.get('evidence_resolved') is True
                    for item in fresh['f6']),
    }
    audit = dict(schema_version=SCHEMA,
        scope='saved_artifact_independent_consistency_verification_not_live_authority',
        status='verified' if all(checks.values()) else 'incomplete',
        checks=checks, cross_cli=True,
        phases={'original': original, 'fresh': fresh},
        process_identity=detail,
        unavailable=list(dict.fromkeys(original['unavailable'] + fresh['unavailable'])),
        grants_F5=False, grants_F6=False, native_authority=False,
        reward_eligible=False,
        not_claimed=['live authority', 'internal register version',
                     'cross-case writer attribution', 'online RTL coverage AUC',
                     'strategy superiority'])
    audit['checks']['all_five_flows_covered'] = (
        set(original['flow_case_counts']) == {'F1', 'F2', 'F3', 'F4', 'F5', 'F6'})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(audit, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'status': audit['status'], 'checks': audit['checks']},
                     sort_keys=True, indent=2))
    return 0 if audit['status'] == 'verified' else 1


if __name__ == '__main__':
    raise SystemExit(main())
