"""Recheck saved real Caliptra AHB samples with the generic evidence consumer.

This is an offline audit of a directed local run, not a Runner integration or
an authenticated online testcase-prefix replay.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from myfuzz.scenario.ip_protocol_evidence import IpProtocolEvidenceConsumer
from myfuzz.scenario.ip_protocol_events import IpProtocolEventNormalizer


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _projected_facts(events):
    return [(row['event_type'], row['tick'], row['payload'],
             row['native_identity']) for row in events]


def audit_run(saved: dict, artifact: dict, *, corrupt_response=False) -> dict:
    configuration = {'sha': {
        'component_id': artifact['plan']['component_id'],
        'instance_id': artifact['plan']['instance_id'],
        'protocol_trace': artifact['base_protocol_trace'],
    }}
    assert configuration['sha']['protocol_trace']['protocol'] == 'ahb-lite'
    normalizer = IpProtocolEventNormalizer(**configuration['sha'])
    consumer = IpProtocolEvidenceConsumer(configuration,
        runtime_contract_sha256=artifact['artifact_digest'])
    next_id = 1
    projected = []
    tampered = False
    for access in saved['accesses']:
        for sample in access['samples']:
            raw = {'event_id': next_id, 'kind': 'local_tick_sample',
                   'component': 'sha', 'local_tick': sample['local_tick'],
                   'phase': 'pre', 'reset_epoch': 0,
                   'observation_schema_version': 'ip_raw_observation.v1',
                   'provenance': {'observed_case': {
                       'case_id': 'caliptra-directed', 'case_index': 0}},
                   'outputs': sample['pre']}
            consumer.consume(raw)
            next_id += 1
            for event in normalizer.consume_local_tick(raw, reset_epoch=0):
                projected.append(event)
                observed = deepcopy(event)
                observed['event_id'] = next_id
                observed['kind'] = observed['event_type']
                if (corrupt_response and not tampered
                        and observed['event_type'] == 'transaction_response'):
                    observed['payload']['value'] ^= 1
                    tampered = True
                consumer.consume(observed)
                next_id += 1
    if _projected_facts(projected) != _projected_facts(saved['protocol_events']):
        raise ValueError('saved protocol projections differ from raw AHB samples')
    report = consumer.report()
    return {'accesses': len(saved['accesses']),
            'projected_events': len(projected),
            'verified_certificates': report['counts']['verified'],
            'pending': report['counts']['pending'],
            'diagnostics': report['diagnostics'],
            'journal_integrity': report['journal_integrity'],
            'tampered': tampered}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-dir', type=Path, required=True)
    parser.add_argument('--index', type=Path, required=True)
    args = parser.parse_args()
    index = json.loads(args.index.read_text(encoding='utf-8'))
    if index['schema_version'] != 'caliptra_sha256_local_runtime_acceptance.v1':
        raise ValueError('unexpected Caliptra evidence index')
    for row in index['evidence']:
        path = args.evidence_dir / Path(row['path']).name
        if _sha256(path) != row['sha256']:
            raise ValueError('saved evidence hash mismatch: ' + str(path))
    artifact = json.loads((args.evidence_dir / 'artifact.json').read_text())
    if artifact['artifact_digest'] != index['artifact_digest']:
        raise ValueError('runtime artifact identity mismatch')
    results = {}
    for name in ('first', 'fresh'):
        saved = json.loads((args.evidence_dir / (name + '.json')).read_text())
        result = audit_run(saved, artifact)
        if (result['accesses'] != index['accesses_per_process']
                or result['projected_events'] != sum(
                    index['normalized_events_per_process'].values())
                or result['verified_certificates'] != result['accesses']
                or result['pending'] != 0 or result['diagnostics']
                or not result['journal_integrity']):
            raise ValueError('real AHB transaction evidence incomplete: ' + name)
        results[name] = result
    forged = audit_run(
        json.loads((args.evidence_dir / 'first.json').read_text()),
        artifact, corrupt_response=True)
    if (not forged['tampered'] or forged['verified_certificates']
            or forged['diagnostics'].get('projection_mismatch', 0) < 1):
        raise ValueError('forged AHB response was not rejected')
    print(json.dumps({'schema_version': 'caliptra_ahb_protocol_audit.v1',
                      'scope': 'offline_real_raw_samples_to_protocol_certificates',
                      'artifact_digest': artifact['artifact_digest'],
                      'runs': results, 'forged_response': forged,
                      'online_runner_integrated': False},
                     sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
