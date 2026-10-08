"""Bounded immutable identity for execution of one already compiled Genome.

Full component/profile/build documents remain in manifest.json. This envelope
links those documents and checker/feedback declarations without duplicating
large source closures or interpreting a Genome path name as a dependency graph.
"""
from __future__ import annotations

import hashlib
import json


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _declarations(value: object, field: str, location: str = '') -> list[dict]:
    rows = []
    if isinstance(value, dict):
        if field in value:
            rows.append({'location': location, 'declaration': value[field]})
        for key, child in sorted(value.items()):
            rows.extend(_declarations(child, field, f'{location}.{key}' if location else key))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            rows.extend(_declarations(child, field, f'{location}.{index}'))
    return rows


def evidence_run_identity(manifest: dict, factory: dict, genome: bytes,
                          checker_configuration: object = (),
                          targets: object = ()) -> dict:
    """Create an immutable envelope whose digest fields have bounded size."""
    sessions = manifest['sessions']
    source_files = {row['path']: row['sha256']
                    for row in manifest['host_sources']['files']}
    templates = _declarations(sessions, 'selected_template')
    tools = _declarations(sessions, 'toolchain')
    identity = {
        'schema_version': 'scenario_run_identity.v1',
        'execution_kind': 'fixed_genome_execution',
        'components': {'file': 'manifest.json', 'sha256': _digest(manifest)},
        'profiles': {'file': 'manifest.json', 'location': 'sessions',
                     'sha256': _digest(sessions)},
        'sources': {'file': 'manifest.json', 'location': 'host_sources',
                    'sha256': _digest(manifest['host_sources'])},
        'templates': {'file': 'manifest.json', 'location': 'sessions',
                      'status': 'declared' if templates else 'not_declared',
                      'sha256': _digest(templates)},
        'toolchain': {'file': 'manifest.json', 'location': 'sessions',
                      'status': 'declared' if tools else 'not_declared',
                      'sha256': _digest(tools)},
        'factory': {'file': 'factory_source.json', 'sha256': _digest(factory)},
        'genome': {'file': 'genome.bin', 'sha256': hashlib.sha256(genome).hexdigest()},
        'dependency_graph': {'status': 'not_applicable',
                             'reason': 'fixed_genome_execution_has_no_decoder'},
        'runtime_dataflow': {'file': 'manifest.json',
                             'sha256': _digest({field: manifest[field] for field in
                                               ('ownership', 'bindings', 'windows', 'memories')})},
        'checker': {'configuration_file': 'checks.jsonl',
                    'configuration_sha256': _digest(checker_configuration),
                    'source_file': 'src/myfuzz/scenario/checker.py',
                    'source_sha256': source_files['src/myfuzz/scenario/checker.py']},
        'feedback': {'kind': 'observed_local_rtl_output_predicates.v1',
                     'targets_file': 'coverage.json',
                     'targets_sha256': _digest(targets),
                     'source_file': 'src/myfuzz/scenario/feedback.py',
                     'source_sha256': source_files['src/myfuzz/scenario/feedback.py']},
    }
    return {'schema_version': 'scenario_run_identity_envelope.v1',
            'sha256': _digest(identity), 'identity': identity}
