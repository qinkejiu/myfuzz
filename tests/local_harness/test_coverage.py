import pytest
import os
from pathlib import Path

from myfuzz.local_harness.coverage import (
    coverage_argv, instrument_driver, measure_cached_harness, parse_verilator_coverage,
)


def test_adds_verilator_coverage_dump_only_at_normal_driver_exit():
    source = '#include "verilated.h"\nint main() {\n  dut.final();\n  return 0;\n}\n'
    rendered = instrument_driver(source)
    assert '#include "verilated_cov.h"' in rendered
    assert 'dut.final();\n  VerilatedCov::write("coverage.dat");\n' in rendered


@pytest.mark.parametrize('source', [
    'int main() { return 0; }',
    'dut.final();\ndut.final();',
    'dut.final();\nVerilatedCov::write("coverage.dat");',
])
def test_refuses_unknown_or_preinstrumented_driver(source):
    with pytest.raises(ValueError):
        instrument_driver(source)


def test_coverage_build_preserves_snapshot_and_adds_line_instrumentation():
    argv = ['/tool/verilator', '--cc', '--exe', '--build', '-j', '1',
            '{BUILD}/inputs/generated/driver.cpp']
    result = coverage_argv(argv, '/tmp/build')
    assert '--coverage-line' in result
    assert '/tmp/build/inputs/generated/driver.cpp' in result
    assert argv[-1].startswith('{BUILD}')


def test_refuses_already_instrumented_build():
    with pytest.raises(ValueError):
        coverage_argv(['/tool/verilator', '--coverage', '--build'], '/tmp/build')


def test_original_replies_must_match_the_recorded_live_session():
    from myfuzz.local_harness.coverage import validate_original_replies
    lines = ['READY example', 'RESULT first', 'ACKED retired', 'RESULT second']
    validate_original_replies(lines, ['RESULT first', 'RESULT second'])
    with pytest.raises(ValueError, match='live-session-reply-mismatch'):
        validate_original_replies(lines, ['RESULT first', 'RESULT changed'])


def test_replay_stops_if_driver_output_exceeds_byte_budget(tmp_path):
    from myfuzz.local_harness.coverage import run_replay_bounded
    driver = tmp_path / 'driver.py'
    driver.write_text('#!/usr/bin/env python3\nimport sys\n'
                      'print("READY", flush=True)\n'
                      'for line in sys.stdin:\n'
                      ' if line == "END\\n": break\n'
                      ' print("X" * 1000, flush=True)\n')
    driver.chmod(0o755)
    with pytest.raises(ValueError, match='coverage-output-budget'):
        run_replay_bounded(driver, ['CMD ' + 'a' * 32 + ' 1 STEP'],
                           tmp_path, max_output_bytes=128)


def test_parse_preserves_tool_point_identity_and_raw_file_scope():
    data = ("# SystemC::Coverage-3\n"
            "C '\x01f\x02/tmp/dut.v\x01l\x0215\x01n\x020\x01t\x02branch"
            "\x01page\x02v_line/mod\x01o\x02else\x01h\x02TOP.u_dut' 3\n")
    points = parse_verilator_coverage(data)
    assert points == [{'fields': {'f': '/tmp/dut.v', 'l': '15', 'n': '0',
                                  't': 'branch', 'page': 'v_line/mod', 'o': 'else',
                                  'h': 'TOP.u_dut'}, 'count': 3}]


@pytest.mark.parametrize('data', [
    '# SystemC::Coverage-2\n',
    "# SystemC::Coverage-3\nC '\x01f\x02dut.v\x01f\x02other.v' 1\n",
    "# SystemC::Coverage-3\nC '\x01f\x02dut.v' -1\n",
    "# SystemC::Coverage-3\nC '\x01f\x02dut.v' 1\n",
])
def test_refuses_unsupported_or_ambiguous_coverage_rows(data):
    with pytest.raises(ValueError):
        parse_verilator_coverage(data)


@pytest.mark.skipif(os.environ.get('MYFUZZ_LOCAL_COVERAGE_REAL') != '1',
                    reason='set MYFUZZ_LOCAL_COVERAGE_REAL=1 for saved real harness')
def test_real_wishbone_uart_coverage_matches_uninstrumented_execution(tmp_path):
    root = Path(__file__).resolve().parents[2]
    cache = root / 'runs/generic-runtime/G8/perf-one-64/cache/03622b044e85d2557041f53daa57bd16afddd5c59cb743283edbd9f690de3af8'
    if not cache.is_dir():
        pytest.skip('saved real IP harness unavailable')
    commands = ['CMD 0123456789abcdef0123456789abcdef 1 ACCESS_WB_REG 1 0 55 f',
                'CMD 0123456789abcdef0123456789abcdef 2 ACCESS_WB_REG 0 0 0 f']
    result = measure_cached_harness(cache, tmp_path / 'measure', commands)
    assert result['coverage_kind'] == 'verilator-line-block'
    assert result['replay']['identical_stdout'] is True
    assert result['replay']['result_count'] == 2
    assert (tmp_path / 'measure/coverage.dat').stat().st_size > 0


@pytest.mark.skipif(os.environ.get('MYFUZZ_LOCAL_COVERAGE_REAL') != '1',
                    reason='set MYFUZZ_LOCAL_COVERAGE_REAL=1 for saved real harness')
def test_real_coverage_replays_long_trace_across_driver_ack(tmp_path):
    root = Path(__file__).resolve().parents[2]
    cache = root / 'runs/generic-runtime/G8/perf-one-64/cache/03622b044e85d2557041f53daa57bd16afddd5c59cb743283edbd9f690de3af8'
    if not cache.is_dir():
        pytest.skip('saved real IP harness unavailable')
    commands = [f'CMD 0123456789abcdef0123456789abcdef {index:x} STEP_WB_REG'
                for index in range(1, 18)]
    result = measure_cached_harness(cache, tmp_path / 'measure', commands)
    assert result['replay']['identical_stdout'] is True
    assert result['replay']['result_count'] == 17
    assert result['replay']['local_ticks'] == 17
    assert result['source_selection']['dut_points'] > 0
    assert result['source_selection']['dut_points'] < result['source_selection']['all_points']
    points = (tmp_path / 'measure/coverage-points.json').read_text()
    assert 'third_party/soc-zipcpu-wbuart/rtl/wbuart.v' in points


@pytest.mark.parametrize('budget',[
    {'max_commands':True},{'max_commands':65537},{'max_input_bytes':0},
    {'max_output_bytes':513*1024*1024},{'max_wall_seconds':float('inf')},
    {'max_wall_seconds':3601},
])
def test_invalid_absolute_budget_rejected_before_cache_or_native(tmp_path,budget):
    with pytest.raises(ValueError,match='budget'):
        measure_cached_harness(tmp_path/'missing',tmp_path/'never-created',
            ['CMD '+'a'*32+' 1 STEP'],**budget)
    assert not (tmp_path/'never-created').exists()
