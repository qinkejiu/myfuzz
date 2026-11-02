"""P2 CPU-only: generated-program fuzz, profile-resolved artifacts, more buses.

Three claims are checked here, each against real RTL and the runner's own
documents:

1. ``--fuzz-mode program`` really executes a **different RV32 program per case**
   (distinct program hashes, distinct reference retirement traces) and compares
   the CPU's own retirement trace and data window with the F1 reference model;
2. the CPU artifact is **resolved from the component profile** on each run, with
   ``cache_hit``/``compiled_this_invocation`` reported, not assumed;
3. the CPU-only route serves a real **Wishbone** and a real **AXI4-Lite** master,
   reporting ``retires=unknown``/``trap=unknown`` for a model that exports no
   RVFI instead of refusing the bus batch.

The data-only P0 shape is kept: the same batch still produces the same case lines
(``test_data_mode_reproduces_the_p0_case_lines``), and a fuzz mapping without a
mode still selects it.
"""
from __future__ import annotations

import json
from pathlib import Path
import random
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT))

from inprocess_cpu_only import (  # noqa: E402
    CpuOnlyError, _fuzz_records, _program_batch, _program_checks, _program_isa,
    build_cpu_only, load_cpu_only_config, run_cpu_only,
)

CACHE = ROOT / 'runs/p2-cpu-only-20261103/host-cache'
IBEX = ROOT / 'configs/scenarios/p2-cpu-only-ibex.json'
CV32E40P = ROOT / 'configs/scenarios/p2-cpu-only-cv32e40p.json'
WB = ROOT / 'configs/scenarios/p2-cpu-only-picorv32-wb.json'
AXI = ROOT / 'configs/scenarios/p2-cpu-only-picorv32-axi.json'
P0_IBEX = ROOT / 'configs/scenarios/p0-cpu-only-ibex.json'

#: The exact case/summary lines the P0 route printed for these inputs before this
#: round (captured from the pre-change route on the pinned Ibex artifact).  Only
#: ``wall_us`` may move; every other byte must be identical.
P0_BASELINE_LINES = [
    'case 0 observations_passed input=0x1 expected=0x2 result=0x2 ticks=13 '
    'retires=5 pc=0x10088 insn=0x130393',
    'case 1 observations_passed input=0x2 expected=0x3 result=0x3 ticks=10 '
    'retires=4 pc=0x10088 insn=0x130393',
    'summary observations_passed cases=2 failed=0 ticks=39 retires=11 '
    'assertions=off model=cpu',
]


def _without_wall_us(line):
    tokens = [token for token in line.split() if not token.startswith('wall_us=')]
    return ' '.join(tokens)


def _pinned(profile, cache_root):
    """Skip when the pinned RTL or a profile this test needs is absent."""
    if not (ROOT / profile).is_file():
        raise unittest.SkipTest('missing profile ' + profile)
    if not cache_root.is_dir():
        raise unittest.SkipTest('missing artifact cache ' + str(cache_root))


class ProgramFuzzTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _pinned('configs/cpus/ibex_rvfi_local/component_profile.json',
                ROOT / 'third_party/rfuzz/upstream/ibex')
        cls.temporary = tempfile.TemporaryDirectory(prefix='p2-cpu-only-test-')
        cls.output = Path(cls.temporary.name)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    # -- 1. a different program per case -------------------------------------
    def test_each_case_is_a_different_real_program(self):
        result = run_cpu_only(IBEX, CACHE, self.output / 'program-ibex',
                              fuzz={'cases': 8, 'seed': 11, 'mode': 'program'})
        self.assertEqual('observations_passed', result['status'], result.get('failure'))
        self.assertEqual(0, result['returncode'])
        self.assertEqual('fuzz', result['input_mode'])
        self.assertEqual('program', result['fuzz_mode'])
        self.assertEqual(8, len(result['programs']))
        self.assertIn('generate_program', result['fuzz']['generator'])
        self.assertIn('validate_f1_program_record', result['fuzz']['gate'])
        self.assertIn('different program per case', result['program_basis'])
        self.assertIn('fresh generation', result['mutation_basis'])
        hashes = [row['program_sha256'] for row in result['programs']]
        self.assertEqual(len(hashes), len(set(hashes)),
                         'two cases executed the same program')
        retirements = [row['expectation']['retired_count'] for row in result['programs']]
        self.assertTrue(all(count >= 1 for count in retirements))
        # The witness is the CPU's own RVFI stream, so the retirement count is a
        # number for this model and matches the reference model's count.
        for case, row in zip(result['cases'], result['programs']):
            self.assertEqual('observations_passed', case['status'])
            self.assertIsInstance(case['retires'], int)
            self.assertEqual(row['expectation']['retired_count'], case['retires'])
            self.assertEqual(row['expectation']['trace_hash_value'], case['trace'])
            self.assertEqual(row['expectation']['rd_mask'], case['rd_mask'])
            self.assertEqual(1, case['insns_match'])
            self.assertEqual(row['data_hash_after'], case['data_hash_after'])
            self.assertEqual(0, case['done'])
            self.assertGreater(case['bus_reads'], 0)
        self.assertTrue(all(check['ok'] for check in result['program_checks']))
        # The programs really reached memory: at least one case stored into its
        # data window (a batch of pure-ALU programs is legal, an all-zero batch is
        # not — the generator was asked for a mixed style over eight programs).
        self.assertTrue(any(case['data_changed'] for case in result['cases']))
        self.assertTrue(any(case['bus_writes'] > 1 for case in result['cases']))
        self.assertEqual('obi', result['bus']['protocol'])
        self.assertTrue(result['signal_status']['retirement'] == 'observed')

    def test_program_generation_is_deterministic_per_seed(self):
        config = load_cpu_only_config(IBEX)
        first = _program_batch(config, {'cases': 4, 'seed': 5})
        second = _program_batch(config, {'cases': 4, 'seed': 5})
        third = _program_batch(config, {'cases': 4, 'seed': 6})
        self.assertEqual([row['program_sha256'] for row in first['rows']],
                         [row['program_sha256'] for row in second['rows']])
        self.assertNotEqual([row['program_sha256'] for row in first['rows']],
                            [row['program_sha256'] for row in third['rows']])
        self.assertEqual(first['firmware'], second['firmware'])
        # Every case's words are the words installed in its own slot.
        for row, meta in zip(first['rows'], first['metadata']):
            self.assertEqual(row['program_start'], meta['start'])
            self.assertEqual(row['program_end'], meta['end'])
            self.assertGreater(meta['trailer'], meta['end'] - 4)

    def test_the_shared_gate_refuses_an_illegal_program(self):
        from unittest import mock
        import myfuzz.fuzz.rv32_program as rv32_program

        class Forged:
            # ``addi x8, x0, 0`` writes a register the F1 gate reserves.
            words = (0x00000413,)

        config = load_cpu_only_config(IBEX)
        with mock.patch.object(rv32_program, 'generate_program',
                               return_value=Forged()):
            with self.assertRaises(CpuOnlyError) as caught:
                _program_batch(config, {'cases': 1, 'seed': 1})
        self.assertIn('cpu-only-program-gate', str(caught.exception))

    def test_correspondence_is_a_live_comparison(self):
        row = dict(index=0, words=['0x00000013'], program_fnva32=1,
                   done_value=0, data_hash_before=2, data_hash_after=3,
                   data_changed=0,
                   expectation=dict(retired_count=1, trace_hash_value=4,
                                    rd_mask=0, trace_hash='fnv1a32:00000004'))
        case = dict(program_hash=1, program_words=1, done=0, data_hash_before=2,
                    data_hash_after=3, data_changed=0, retires=1, trace_count=1,
                    trace=4, rd_mask=0, pc_order=1, insns_match=1)
        self.assertTrue(_program_checks(row, case)['ok'])
        broken = dict(case, trace=5)
        check = _program_checks(row, broken)
        self.assertFalse(check['ok'])
        self.assertEqual(['trace_hash'], [item['name'] for item in check['failures']])
        # A model without RVFI is compared on the data window, and says so.
        unknown = dict(case, retires='unknown', trace='unknown', trace_count='unknown',
                       rd_mask='unknown', pc_order='unknown', insns_match='unknown')
        check = _program_checks(row, unknown)
        self.assertTrue(check['ok'])
        self.assertFalse(check['retirement_known'])
        self.assertIn('no retirement', check['basis'])

    # -- 2. the artifact comes from the profile ------------------------------
    def test_artifact_is_resolved_from_the_profile(self):
        build = build_cpu_only(IBEX, CACHE, self.output / 'build-profile')
        artifact = build['artifact']
        self.assertEqual('profile', artifact['source'])
        self.assertIn('cache_hit', artifact)
        self.assertIn('compiled_this_invocation', artifact)
        self.assertRegex(artifact['artifact_digest'], r'^[0-9a-f]{64}$')
        self.assertEqual(artifact['artifact_digest'], build['artifact_digest'])
        self.assertEqual('profile', build['artifact']['source'])
        self.assertTrue(json.dumps(build['artifact']['rendered']))  # request is recorded
        self.assertEqual('configs/cpus/ibex_rvfi_local/component_profile.json',
                         build['artifact']['rendered']['request']['profile_path'])
        self.assertIn('compiled_this_invocation', build)
        self.assertIn('cache_hit', build)
        # The scenario does not pin a build digest: nothing points at an old path.
        config = load_cpu_only_config(IBEX)
        self.assertIsNone(config.get('cpu_cache_digest'))
        self.assertEqual('profile', config['cpu_artifact_source'])

    # -- 3. Wishbone and AXI4-Lite really run -------------------------------
    def test_wishbone_cpu_runs_a_program_batch_with_real_retirement(self):
        result = run_cpu_only(WB, CACHE, self.output / 'program-wb',
                              fuzz={'cases': 6, 'seed': 11, 'mode': 'program'})
        self.assertEqual('observations_passed', result['status'], result.get('failure'))
        self.assertEqual('wishbone', result['bus']['protocol'])
        self.assertEqual('observed', result['signal_status']['retirement'])
        for case, row in zip(result['cases'], result['programs']):
            self.assertIsInstance(case['retires'], int)
            self.assertGreater(case['retires'], 0)
            self.assertEqual(row['expectation']['trace_hash_value'], case['trace'])
            self.assertEqual(1, case['insns_match'])
            self.assertEqual(0, case['done'])
            self.assertGreater(case['bus_reads'], 0)
        self.assertTrue(any(case['bus_writes'] > 1 for case in result['cases']))

    def test_axi4lite_cpu_runs_a_program_batch_with_unknown_retirement(self):
        result = run_cpu_only(AXI, CACHE, self.output / 'program-axi',
                              fuzz={'cases': 6, 'seed': 11, 'mode': 'program'})
        self.assertEqual('observations_passed', result['status'], result.get('failure'))
        self.assertEqual('axi4-lite', result['bus']['protocol'])
        # No RVFI pair on this core: retirement and trap are unknown, not zero,
        # and the batch still runs on the bus.
        self.assertEqual('unknown', result['signal_status']['retirement'])
        self.assertEqual('unknown', result['signal_status']['trap'])
        for case in result['cases']:
            self.assertEqual('unknown', case['retires'])
            self.assertEqual('unknown', case['trace'])
            self.assertGreater(case['bus_reads'], 0)
            self.assertGreaterEqual(case['bus_writes'], 1)
        self.assertTrue(all(not check['retirement_known']
                            for check in result['program_checks']))
        self.assertTrue(all('completion-store' in check['basis']
                            for check in result['program_checks']))

    def test_second_obi_cpu_runs_the_same_programs_with_unknown_retirement(self):
        result = run_cpu_only(CV32E40P, CACHE, self.output / 'program-cv32e40p',
                              fuzz={'cases': 4, 'seed': 11, 'mode': 'program'})
        self.assertEqual('observations_passed', result['status'], result.get('failure'))
        self.assertEqual('obi', result['bus']['protocol'])
        self.assertEqual('unknown', result['signal_status']['retirement'])
        for case in result['cases']:
            self.assertEqual('unknown', case['retires'])
            self.assertEqual(0, case['done'])

    # -- the P0 data shape is kept ------------------------------------------
    def test_fuzz_without_a_mode_keeps_the_p0_data_shape(self):
        records, document = _fuzz_records({'cases': 3, 'seed': 9})
        self.assertEqual('data', document['mode'])
        generator = random.Random(9)
        expected = ['0x%08x' % generator.getrandbits(32) for _ in range(3)]
        self.assertEqual(expected, ['0x%08x' % word for word in records])
        result = run_cpu_only(IBEX, CACHE, self.output / 'data-default',
                              fuzz={'cases': 3, 'seed': 9})
        self.assertEqual('data', result['fuzz_mode'])
        self.assertEqual(3, result['case_count'])
        self.assertEqual([], result['programs'])
        for case in result['cases']:
            self.assertEqual((case['input'] + 1) & 0xffffffff, case['result'])

    def test_data_mode_reproduces_the_p0_case_lines(self):
        result = run_cpu_only(P0_IBEX, CACHE, self.output / 'data-p0',
                              records=[1, 2], assertions=False)
        self.assertEqual('observations_passed', result['status'])
        lines = [line for line in (Path(result['stdout']).read_text()).splitlines()
                 if line.startswith('case ') or line.startswith('summary ')]
        self.assertEqual(len(lines), len(P0_BASELINE_LINES))
        for line, expected in zip(lines, P0_BASELINE_LINES):
            self.assertEqual(expected, _without_wall_us(line))
        self.assertEqual('pinned', result['artifact']['source'])

    # -- refusals stay named ------------------------------------------------
    def test_the_obi_only_fault_is_refused_on_a_unified_bus(self):
        with self.assertRaises(CpuOnlyError) as caught:
            run_cpu_only(AXI, CACHE, self.output / 'fault-axi',
                         fault={'kind': 'spurious-data-rvalid', 'tick': 30})
        self.assertIn('cpu-only-fault-bus-unsupported:axi4-lite',
                      str(caught.exception))

    def test_an_unknown_fuzz_mode_is_refused(self):
        with self.assertRaises(CpuOnlyError) as caught:
            run_cpu_only(IBEX, CACHE, self.output / 'mode-bogus',
                         fuzz={'cases': 1, 'seed': 1, 'mode': 'bogus'})
        self.assertIn('cpu-only-fuzz-mode:bogus', str(caught.exception))

    def test_a_rv64_profile_is_refused_before_any_build(self):
        document = json.loads(IBEX.read_text(encoding='utf-8'))
        document['cpu_profile'] = 'configs/cpus/boom/component_profile.json'
        document['required_observations'] = []
        path = self.output / 'rv64.json'
        path.write_text(json.dumps(document), encoding='utf-8')
        with self.assertRaises(CpuOnlyError) as caught:
            run_cpu_only(path, CACHE, self.output / 'rv64',
                         fuzz={'cases': 1, 'seed': 1, 'mode': 'program'})
        self.assertIn('cpu-only-program-isa-not-rv32:64', str(caught.exception))

    def test_a_packed_axi4_cpu_is_refused_by_endpoint(self):
        document = json.loads(IBEX.read_text(encoding='utf-8'))
        document['cpu_profile'] = 'configs/cpus/cva6/component_profile.json'
        document['required_observations'] = []
        path = self.output / 'packed.json'
        path.write_text(json.dumps(document), encoding='utf-8')
        with self.assertRaises(CpuOnlyError) as caught:
            build_cpu_only(path, CACHE)
        reason = str(caught.exception)
        self.assertIn('cpu-only-bus-endpoint-unsupported:', reason)
        self.assertIn('processor.memory.unified', reason)
        self.assertNotIn('arvalid', reason)  # names the endpoints, not missing roles

    def test_the_program_isa_keeps_the_declared_extensions(self):
        isa = _program_isa(load_cpu_only_config(IBEX))
        self.assertEqual(32, isa.xlen)
        self.assertTrue(isa.has('I'))
        self.assertTrue(isa.has('M'))
        self.assertEqual(32, isa.register_count)


if __name__ == '__main__':
    unittest.main()
