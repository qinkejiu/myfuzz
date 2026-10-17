#!/usr/bin/env python3
"""Prove the generated PULP APB timer probe hierarchy with Verilator.

This is a bounded instrumentation check, not a campaign.  It:

1. regenerates the committed timer harness (D2 generation only),
2. verifies the 10 ``storage_*`` probe ports and their expressions,
3. elaborates the exact runtime with Verilator (an unbound XMR fails),
4. runs two mutated runtimes as negative controls (an unbound path must fail),
5. builds one native model and samples all ten ports across reset, a timer-1
   write (must not move the probe), two timer-0 writes and readbacks,
6. writes a digest-bound proof only when every check passes.

The proof is consumed by
``myfuzz.local_harness.apb_storage_probe_verification.attach_native_proof``.
A failure never writes a proof and exits non-zero.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

SCENARIO = ROOT / 'configs/scenarios/compiled-f4-obi-apb-timer'
PROOF_DEFAULT = ROOT / ('docs/reports/evidence/'
                        'verilog-probe-pulp-apb-timer/proof.json')
TB_SOURCE = ROOT / 'tests/native/apb_storage_probe_tb.cpp'
LOCK = ROOT / '.superpowers/heavy-worker.lock'
EXPECTED_PORTS = {
    'storage_value': 32, 'storage_reset': 1, 'storage_paddr': 12,
    'storage_psel': 1, 'storage_penable': 1, 'storage_pwrite': 1,
    'storage_pwdata': 32, 'storage_prdata': 32, 'storage_pready': 1,
    'storage_pslverr': 1,
}
LOCK_WAIT = 14400
WRITE_ONE = 0x14
WRITE_ZERO = 0x04
VALUE_ONE = 0xa5c30001
VALUE_TWO = 0x13572468
TIMER_ONE_VALUE = 0x5a5a5a5a


class VerificationError(RuntimeError):
    pass


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      allow_nan=False)


def _digest(value):
    return hashlib.sha256(_json(value).encode()).hexdigest()


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _run(argv, *, cwd, timeout):
    try:
        return subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
                              timeout=timeout)
    except FileNotFoundError as error:
        raise VerificationError(f'tool-unavailable: {argv[0]}') from error
    except subprocess.TimeoutExpired as error:
        raise VerificationError(f'tool-timeout: {argv[0]}') from error


def _locked(argv):
    if not LOCK.is_file():
        raise VerificationError(f'heavy-worker-lock-missing: {LOCK}')
    return ['flock', '-w', str(LOCK_WAIT), '-E', '75', str(LOCK), *argv]


def _run_locked(argv, *, cwd, timeout):
    result = _run(_locked(argv), cwd=cwd, timeout=timeout)
    if result.returncode == 75:
        raise VerificationError('heavy-worker-lock-busy')
    return result


def _clean_cache(path):
    resolved = Path(path).absolute()
    expected = (ROOT / '.superpowers').absolute()
    if (expected not in resolved.parents
            or not resolved.name.startswith('cache-verilog-probe')):
        raise VerificationError('cache-directory-outside-superpowers: '
                                f'{resolved}')
    if resolved.exists():
        shutil.rmtree(resolved)
    resolved.mkdir(parents=True)


def _generate(cache):
    from myfuzz.integration.compiled_execution_files import (
        prepare_compiled_execution_files)
    generated = cache / 'd2/generated'
    generated.parent.mkdir(parents=True)
    prepare_compiled_execution_files(
        base_dir=ROOT, compose_path=SCENARIO / 'compose.json',
        capability_paths=[SCENARIO / 'test_capability.json'],
        supplement_path=SCENARIO / 'execution_supplement.json',
        generated_dir=generated)
    return generated


def _probe_checks(artifact, runtime_sv, source_contract):
    probe = artifact.get('storage_observation')
    ports = artifact.get('storage_probe_ports')
    if not isinstance(probe, dict) or not isinstance(ports, list):
        raise VerificationError('storage-observation-missing')
    rows = {row.get('name'): row for row in ports if isinstance(row, dict)}
    if (len(ports) != len(EXPECTED_PORTS) or set(rows) != set(EXPECTED_PORTS)):
        raise VerificationError('storage-probe-port-set-mismatch')
    for name, width in EXPECTED_PORTS.items():
        row = rows[name]
        if (row.get('direction') != 'output' or row.get('width') != width
                or type(row.get('expression')) is not str
                or not row['expression']):
            raise VerificationError(f'storage-probe-port-shape: {name}')
        assign = f"assign {name} = {row['expression']};"
        if runtime_sv.count(assign) != 1:
            raise VerificationError(f'storage-probe-driver-mismatch: {name}')
    expression = source_contract['storage_expression']['expression']
    if rows['storage_value']['expression'] != expression:
        raise VerificationError('storage-value-expression-mismatch')
    if probe.get('ports') != ports:
        raise VerificationError('storage-probe-observation-port-mismatch')
    if (probe.get('schema_version') != 'apb_storage_probe.v1'
            or probe.get('scope') != 'generated_expression_source_mapped'
            or probe.get('sample_group') != 'storage_probes'):
        raise VerificationError('storage-observation-schema-mismatch')
    if probe.get('source_contract') != source_contract:
        raise VerificationError('storage-source-contract-mismatch')
    return probe, rows


def _negative_controls(work, runtime_sv, wrapper_path, source_paths,
                       adapter_paths, module, expression):
    controls = []
    mutations = {
        'out-of-range-generate-index':
            expression.replace('TIMER_GEN[0]', 'TIMER_GEN[9]'),
        'unknown-instance-name':
            expression.replace('timer_i.regs_q[1]', 'timer_x.regs_q[1]'),
        'unknown-register-name':
            expression.replace('regs_q[1]', 'regs_x[1]'),
    }
    negatives = work / 'negative'
    negatives.mkdir()
    for name, mutated_expression in mutations.items():
        if mutated_expression == expression:
            raise VerificationError(f'negative-control-ineffective: {name}')
        text = runtime_sv.replace(expression, mutated_expression)
        if text == runtime_sv:
            raise VerificationError(f'negative-control-missing: {name}')
        path = negatives / f'{name}.sv'
        path.write_text(text, encoding='utf-8')
        result = _run_locked([
            'verilator', '--lint-only', '-Wno-fatal', '--top-module', module,
            str(path), str(wrapper_path),
            *(str(p) for p in (*source_paths, *adapter_paths))],
            cwd=work, timeout=300)
        if result.returncode == 0:
            raise VerificationError(f'negative-control-not-refused: {name}')
        diagnostics = (result.stderr or '') + (result.stdout or '')
        if "Can't find definition" not in diagnostics:
            raise VerificationError(
                f'negative-control-wrong-failure: {name}')
        controls.append(dict(mutation=name, exit_code=result.returncode,
                             refused=True))
    return controls


def _build_and_sample(work, runtime_path, wrapper_path, source_paths,
                      adapter_paths, module, tb_path):
    obj = work / 'obj'
    build = _run_locked([
        'verilator', '--cc', '--exe', '--build', '-Wno-fatal',
        '--top-module', module, '--prefix', 'Vtop', '--build-jobs', '2',
        '--Mdir', str(obj), str(runtime_path), str(wrapper_path),
        *(str(p) for p in (*source_paths, *adapter_paths)), str(tb_path)],
        cwd=work, timeout=900)
    if build.returncode != 0:
        tail = (build.stderr or build.stdout).strip().splitlines()[-8:]
        raise VerificationError('native-build-failed: ' + ' | '.join(tail))
    binary = obj / 'Vtop'
    if not binary.is_file():
        raise VerificationError('native-binary-missing')
    run = _run([str(binary)], cwd=work, timeout=120)
    if run.returncode != 0:
        tail = (run.stderr or run.stdout).strip().splitlines()[-4:]
        raise VerificationError('native-sample-failed: ' + ' | '.join(tail))
    samples = []
    ok = False
    for line in run.stdout.splitlines():
        if line == 'PROBE-TB-OK' or line.startswith('PROBE-TB-OK '):
            ok = True
        elif line.startswith('PROBE-SAMPLE '):
            samples.append(json.loads(line[len('PROBE-SAMPLE '):]))
    if not ok or not samples:
        raise VerificationError('native-sample-output-missing')
    return samples


def _sample_checks(samples):
    required = {'cycle', 'value', 'paddr', 'psel', 'penable', 'pwrite',
                'pwdata', 'prdata', 'pready', 'pslverr', 'reset'}
    if any(not isinstance(row, dict) or set(row) != required
           or any(type(row[key]) is not int or row[key] < 0
                  for key in required) for row in samples):
        raise VerificationError('native-sample-shape')

    def access(index, **expected):
        row = samples[index]
        return all(row[key] == value for key, value in expected.items())

    reset_rows = [row for row in samples if row['reset'] == 1]
    reset_zero = (bool(reset_rows)
                  and all(row['value'] == 0 for row in reset_rows))
    released = [row for row in samples if row['reset'] == 0]
    reset_probe = (bool(released) and released[0]['value'] == 0
                   and any(row['reset'] == 0 for row in released))

    one_access = next((i for i, row in enumerate(samples)
                       if access(i, paddr=WRITE_ONE, penable=1, psel=1,
                                 pwrite=1, pwdata=TIMER_ONE_VALUE)), None)
    zero_access = next((i for i, row in enumerate(samples)
                        if access(i, paddr=WRITE_ZERO, penable=1, psel=1,
                                  pwrite=1, pwdata=VALUE_ONE)), None)
    read_access = next((i for i, row in enumerate(samples)
                        if access(i, paddr=WRITE_ZERO, penable=1, psel=1,
                                  pwrite=0, prdata=VALUE_ONE, pready=1,
                                  pslverr=0)), None)
    second_access = next((i for i, row in enumerate(samples)
                          if access(i, paddr=WRITE_ZERO, penable=1, psel=1,
                                    pwrite=1, pwdata=VALUE_TWO)), None)
    timer_one_no_move = (
        one_access is not None
        and all(row['value'] == 0 for row in samples[:one_access + 1]))
    timer_zero_commits = (
        zero_access is not None
        and any(row['value'] == VALUE_ONE for row in samples[zero_access + 1:]))
    readback_matches = (
        read_access is not None
        and any(row['value'] == VALUE_ONE for row in samples[read_access + 1:]))
    second_commits = (
        second_access is not None
        and samples[-1]['value'] == VALUE_TWO)
    port_liveness = (
        len({row['value'] for row in samples}) >= 3
        and any(row['psel'] == 1 and row['psel'] != samples[0]['psel']
                for row in samples)
        and any(row['penable'] == 1 for row in samples)
        and any(row['pwrite'] == 1 for row in samples)
        and any(row['pwrite'] == 0 and row['psel'] == 1 for row in samples)
        and len({row['paddr'] for row in samples}) >= 3
        and len({row['pwdata'] for row in samples}) >= 3
        and any(row['prdata'] == VALUE_ONE for row in samples)
        and any(row['pready'] == 1 for row in samples)
        and all(row['pready'] in (0, 1) and row['pslverr'] in (0, 1)
                for row in samples)
        and any(row['reset'] == 1 for row in samples)
        and any(row['reset'] == 0 for row in samples))
    checks = dict(
        reset_value_zero=reset_zero and reset_probe,
        timer1_write_does_not_commit=timer_one_no_move,
        timer0_write_commits=timer_zero_commits,
        readback_matches_storage_prdata=readback_matches and second_commits,
        all_ten_ports_sample_live=port_liveness)
    return checks


def verify(*, cache_dir, proof_out):
    cache = Path(cache_dir).absolute()
    _clean_cache(cache)
    generated = _generate(cache)
    peripheral = generated / 'peripheral'
    artifact = json.loads((peripheral / 'artifact.json').read_text())
    runtime_sv = (peripheral / 'runtime.sv').read_text()
    wrapper_sv = (peripheral / 'wrapper.sv').read_text()
    if hashlib.sha256(runtime_sv.encode()).hexdigest() != artifact['runtime_sv_sha256']:
        raise VerificationError('runtime-sv-digest-mismatch')
    if (hashlib.sha256(wrapper_sv.encode()).hexdigest()
            != artifact['structural_build'].get('wrapper_sha256')):
        raise VerificationError('wrapper-sv-digest-mismatch')
    from myfuzz.local_harness.apb_storage_probe_verification import (
        probe_binding_digest)
    from myfuzz.local_harness.apb_storage_source_contract import (
        _registered_document)
    source_contract = _registered_document()
    probe, rows = _probe_checks(artifact, runtime_sv, source_contract)

    work = cache / 'work'
    work.mkdir()
    runtime_path = work / 'runtime.sv'
    wrapper_path = work / 'wrapper.sv'
    runtime_path.write_text(runtime_sv, encoding='utf-8')
    wrapper_path.write_text(wrapper_sv, encoding='utf-8')
    tb_path = work / TB_SOURCE.name
    shutil.copyfile(TB_SOURCE, tb_path)
    sources = [ROOT / path for path in artifact['structural_build']['source_files']]
    adapters = [ROOT / row['path'] for row in artifact['adapter_sources']]
    for path in (*sources, *adapters):
        if not path.is_file():
            raise VerificationError(f'input-missing: {path.relative_to(ROOT)}')
    module = artifact['module_name']

    version = _run(['verilator', '--version'], cwd=work, timeout=60)
    if version.returncode != 0:
        raise VerificationError('verilator-version-failed')
    verilator_version = (version.stdout or version.stderr).strip().splitlines()[0]

    lint = _run_locked([
        'verilator', '--lint-only', '-Wno-fatal', '--top-module', module,
        str(runtime_path), str(wrapper_path),
        *(str(p) for p in (*sources, *adapters))],
        cwd=work, timeout=300)
    if lint.returncode != 0:
        tail = (lint.stderr or lint.stdout).strip().splitlines()[-6:]
        raise VerificationError(
            'expression-unbound-elaboration-failed: ' + ' | '.join(tail))
    controls = _negative_controls(
        work, runtime_sv, wrapper_path, sources, adapters, module,
        source_contract['storage_expression']['expression'])
    samples = _build_and_sample(
        work, runtime_path, wrapper_path, sources, adapters, module, tb_path)
    sample_checks = _sample_checks(samples)
    checks = dict(
        ten_probe_ports_declared=True,
        expression_resolves_elaboration=True,
        unbound_expression_refused=True,
        **sample_checks)
    if not all(checks.values()):
        raise VerificationError('probe-check-failed: ' + ','.join(
            name for name, ok in checks.items() if not ok))

    claimfiles = {
        'compose': SCENARIO / 'compose.json',
        'peripheral_request': SCENARIO / 'requests/peripheral.json',
        'test_capability': SCENARIO / 'test_capability.json',
        'execution_supplement': SCENARIO / 'execution_supplement.json',
    }
    proof = dict(
        schema_version='apb_storage_probe_hierarchy_proof.v1',
        status='verified',
        probe_binding_digest=probe_binding_digest(probe),
        expression=source_contract['storage_expression']['expression'],
        ports=probe['ports'],
        runtime_sv_sha256=hashlib.sha256(runtime_sv.encode()).hexdigest(),
        wrapper_sha256=artifact['structural_build']['wrapper_sha256'],
        source=source_contract['source'],
        parameters=source_contract['parameters'],
        verilator=dict(version=verilator_version, top_module=module),
        commands=dict(
            lint=['verilator', '--lint-only', '-Wno-fatal',
                  '--top-module', module,
                  'generated/peripheral/runtime.sv',
                  'generated/peripheral/wrapper.sv',
                  *artifact['structural_build']['source_files'],
                  *(row['path'] for row in artifact['adapter_sources'])],
            native=['verilator', '--cc', '--exe', '--build', '-Wno-fatal',
                    '--top-module', module, '--prefix', 'Vtop',
                    'generated/peripheral/runtime.sv',
                    'generated/peripheral/wrapper.sv',
                    *artifact['structural_build']['source_files'],
                    *(row['path'] for row in artifact['adapter_sources']),
                    'tests/native/' + TB_SOURCE.name],
            run=['obj/Vtop']),
        negative_controls=controls,
        samples=samples,
        sample_digest=_digest(samples),
        checks=checks,
        inputs={name: _sha256(path) for name, path in claimfiles.items()},
    )
    proof['proof_digest'] = _digest(proof)

    out = Path(proof_out).absolute()
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
            mode='w', encoding='utf-8', dir=out.parent,
            prefix='.' + out.name + '.', delete=False) as handle:
        temporary = Path(handle.name)
        try:
            handle.write(json.dumps(proof, sort_keys=True, indent=2,
                                    allow_nan=False) + '\n')
        except BaseException:
            temporary.unlink(missing_ok=True)
            raise
    temporary.replace(out)
    return proof, out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache-dir', type=Path,
                        default=ROOT / '.superpowers/cache-verilog-probe-timer',
                        help='fresh bounded build cache under .superpowers/')
    parser.add_argument('--proof-out', type=Path, default=PROOF_DEFAULT,
                        help='digest-bound proof written only on success')
    parser.add_argument('--lock-wait', type=int, default=14400,
                        help='seconds to wait for the heavy-worker lock '
                             '(default 14400)')
    args = parser.parse_args(argv)
    if args.lock_wait < 0:
        parser.error('--lock-wait must be non-negative')
    global LOCK_WAIT
    LOCK_WAIT = args.lock_wait
    try:
        proof, out = verify(cache_dir=args.cache_dir, proof_out=args.proof_out)
    except VerificationError as error:
        print(f'PROBE-VERIFY-FAIL: {error}', file=sys.stderr)
        return 1
    print(f'PROBE-VERIFY-OK proof={out} digest={proof["proof_digest"]} '
          f'expression={proof["commands"]["lint"][0]} '
          f'samples={len(proof["samples"])}')
    print(f'PROBE-BINDING={proof["probe_binding_digest"]}')
    print(f'PROBE-RUNTIME={proof["runtime_sv_sha256"]} '
          f'WRAPPER={proof["wrapper_sha256"]}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
