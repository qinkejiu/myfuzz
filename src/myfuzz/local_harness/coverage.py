"""Opt-in Verilator coverage for a copy of a generated local harness.

Coverage is Verilator's line/block instrumentation, not a source-branch
metric and not port semantic feedback. The ordinary harness cache is untouched.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from .build import _compile, _toolchain, _validate_cache
from .renderer import _sha
from .wire import MAX_REPLY_LINE_BYTES, parse_driver_ack, parse_driver_ready, parse_driver_receipt
from myfuzz.scenario.protocol_io import BoundedLineReader, command_deadline, write_local_command


DEFAULT_COVERAGE_BUDGET = dict(max_commands=512, max_input_bytes=64*1024*1024,
    max_output_bytes=64*1024*1024, max_wall_seconds=60.0)


def coverage_budget(**values):
    """Trusted requested bounds; saved metadata cannot raise these limits."""
    result=dict(DEFAULT_COVERAGE_BUDGET,**values)
    if set(result)!=set(DEFAULT_COVERAGE_BUDGET): raise ValueError('invalid-coverage-budget-keys')
    for key,maximum in (('max_commands',65536),('max_input_bytes',512*1024*1024),('max_output_bytes',512*1024*1024)):
        if type(result[key]) is not int or not 1<=result[key]<=maximum:
            raise ValueError('invalid-coverage-budget:'+key)
    wall=result['max_wall_seconds']
    if type(wall) not in (int,float) or not math.isfinite(wall) or not 0<wall<=3600:
        raise ValueError('invalid-coverage-budget:max_wall_seconds')
    return result


def requested_coverage_overrides(budget):
    return {key:value for key,value in budget.items() if value!=DEFAULT_COVERAGE_BUDGET[key]}


def validate_wire_budget(commands, *, max_input_bytes, expected_replies=None, max_output_bytes=64*1024*1024):
    size=len('END\n')
    first=commands[0].split(' ') if commands else []
    nonce=first[1] if len(first)>1 else ''
    for index,line in enumerate(commands,1):
        size+=len(line.encode('ascii'))+1
        if index>1 and (index-1)%16==0:
            size+=len(f'ACK {nonce} {index-1:x}\n')
        if size>max_input_bytes: raise ValueError('coverage-input-byte-budget')
    if expected_replies is not None:
        size=0
        for line in expected_replies:
            size+=len(line.encode('utf8'))+1
            if size>max_output_bytes: raise ValueError('coverage-output-byte-budget')


def instrument_driver(source: str) -> str:
    """Add a coverage dump to the single normal generated driver exit."""
    marker = '  dut.final();\n'
    if (not isinstance(source, str) or source.count(marker) != 1
            or 'VerilatedCov' in source):
        raise ValueError('unsupported-coverage-driver')
    return ('#include "verilated_cov.h"\n' +
            source.replace(marker, marker + '  VerilatedCov::write("coverage.dat");\n'))


def coverage_argv(argv: list[str], build_dir: str, *,
                  build_jobs: int | None = None) -> list[str]:
    """Derive instrumentation flags from a saved local build command.

    ``build_jobs`` is an opt-in throughput cap: when given it replaces the
    saved ``-j`` value and changes only the build schedule, exactly like
    ``MYFUZZ_BUILD_JOBS``.  The pinned inputs, generated sources and
    ``--coverage-line`` instrumentation are untouched.
    """
    if (not isinstance(argv, list) or not argv
            or any(not isinstance(item, str) for item in argv)
            or '--build' not in argv or '--cc' not in argv or '--exe' not in argv
            or any(item.startswith('--coverage') for item in argv)):
        raise ValueError('unsupported-coverage-build')
    result = [argv[0], '--coverage-line',
              *(token.replace('{BUILD}', build_dir) for token in argv[1:])]
    if build_jobs is not None:
        if type(build_jobs) is not int or not 1 <= build_jobs <= 64:
            raise ValueError('invalid-coverage-build-jobs')
        positions = [index for index, token in enumerate(result) if token == '-j']
        if (len(positions) != 1 or positions[0] + 1 >= len(result)
                or not result[positions[0] + 1].isdigit()):
            raise ValueError('unsupported-coverage-build')
        result[positions[0] + 1] = str(build_jobs)
    return result


def dut_source_paths(sources) -> list[str]:
    """Normalize the recorded structural-build source list to snapshot paths.

    A renderer may write a leading ``./`` (the CPU profile does) while the
    cache input path is the normalized relative path.  Both name the same
    pinned file, so the prefix is stripped; anything absolute or containing
    ``.``/``..``/empty components still refuses.  The returned order is the
    artifact order, so the saved point document can be re-derived verbatim.
    """
    if (not isinstance(sources, list) or not sources
            or any(not isinstance(name, str) for name in sources)):
        raise ValueError('coverage-dut-source-list-invalid')
    normalized = []
    for name in sources:
        parts = name.split('/')
        if not name or Path(name).is_absolute() or parts[0] == '':
            raise ValueError('coverage-dut-source-list-invalid')
        if parts[0] == '.':
            parts = parts[1:]
        if not parts or any(part in ('', '.', '..') for part in parts):
            raise ValueError('coverage-dut-source-list-invalid')
        normalized.append('/'.join(parts))
    return normalized


def parse_verilator_coverage(data: str) -> list[dict]:
    """Parse the supported Verilator coverage-3 text, including zero points.

    Keep tool fields intact: a tool's ``branch`` type is not automatically
    equivalent to this project's source-branch instrumentation metric.
    """
    if not isinstance(data, str) or len(data) > 64 * 1024 * 1024:
        raise ValueError('invalid-coverage-data')
    lines = data.splitlines()
    if not lines or lines[0] != '# SystemC::Coverage-3':
        raise ValueError('unsupported-coverage-header')
    result, seen = [], set()
    for line in lines[1:]:
        match = re.fullmatch(r"C '([^'\\]*)' (0|[1-9][0-9]*)", line)
        if match is None:
            raise ValueError('unsupported-coverage-row')
        text, count = match.groups()
        if not text.startswith('\x01'):
            raise ValueError('invalid-coverage-fields')
        fields = {}
        for item in text[1:].split('\x01'):
            key, sep, value = item.partition('\x02')
            if not sep or not key or not value or key in fields or '\x02' in value:
                raise ValueError('invalid-coverage-fields')
            fields[key] = value
        if not {'f', 'l', 'n', 't', 'page', 'o', 'h'} <= fields.keys():
            raise ValueError('missing-coverage-fields')
        if not fields['l'].isdigit() or not fields['n'].isdigit():
            raise ValueError('invalid-coverage-location')
        identity = tuple(sorted(fields.items()))
        if identity in seen:
            raise ValueError('duplicate-coverage-point')
        seen.add(identity)
        result.append({'fields': fields, 'count': int(count)})
    if not result:
        raise ValueError('empty-coverage-points')
    return result


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def replay_wire_input(commands: list[str]) -> str:
    """Retire each 16-receipt window exactly as the live session does."""
    lines = []
    for index, command in enumerate(commands, 1):
        if index > 1 and (index - 1) % 16 == 0:
            lines.append(f"ACK {commands[0].split(' ')[1]} {index - 1:x}")
        lines.append(command)
    return '\n'.join((*lines, 'END')) + '\n'


def run_replay_bounded(binary: Path, commands: list[str], cwd: Path, *,
                       max_output_bytes: int = 64 * 1024 * 1024, max_wall_seconds: float = 60) -> str:
    """Run one command at a time, bounding total replies and process lifetime."""
    if type(max_output_bytes) is not int or max_output_bytes < 1:
        raise ValueError('invalid-coverage-output-budget')
    coverage_budget(max_output_bytes=max_output_bytes,max_wall_seconds=max_wall_seconds)
    deadline = time.monotonic() + max_wall_seconds
    reader = BoundedLineReader(max_line_bytes=MAX_REPLY_LINE_BYTES)
    output, size = [], 0
    with tempfile.TemporaryFile() as errors:
        process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=errors,
                                   text=True, cwd=cwd)
        try:
            def read_reply():
                nonlocal size
                line = reader.readline(process.stdout)
                if not line or not line.endswith('\n'):
                    raise ValueError('coverage-driver-reply-incomplete')
                size += len(line.encode('utf8'))
                if size > max_output_bytes:
                    raise ValueError('coverage-output-budget')
                output.append(line)

            with command_deadline(deadline):
                read_reply()
                for line in replay_wire_input(commands).splitlines():
                    write_local_command(process.stdin, line + '\n')
                    if line != 'END':
                        read_reply()
                process.stdin.close()
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
            if process.returncode != 0:
                errors.seek(0)
                raise ValueError('coverage-driver-exit:' + errors.read(1024).decode('utf-8', 'replace'))
            return ''.join(output)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()


def validate_replay_replies(lines: list[str], commands: list[list[str]], artifact: dict) -> int:
    """Check READY, each result, and each cache-retirement acknowledgement."""
    if len(lines) != 1 + len(commands) + (len(commands) - 1) // 16:
        raise ValueError('coverage-reply-count-mismatch')
    reset = artifact['driver_reset']
    parse_driver_ready(lines[0], digest=artifact['artifact_digest'],
                       assert_ticks=reset['reset_assert_ticks'],
                       release_ticks=reset['reset_release_ticks'])
    tick, cursor = 0, 1
    for index in range(1, len(commands) + 1):
        if index > 1 and (index - 1) % 16 == 0:
            parse_driver_ack(lines[cursor], execution=commands[0][1],
                             sequence=index - 1, current_tick=tick)
            cursor += 1
        receipt = parse_driver_receipt(lines[cursor], execution=commands[0][1],
                                       sequence=index, current_tick=tick,
                                       kind=artifact['kind'],
                                       clock_schedule=artifact.get('clock_schedule'))
        if receipt.status != 'result' or receipt.payload['error'] != 0:
            raise ValueError('coverage-command-failed')
        tick = receipt.tick_after
        cursor += 1
    return tick


def validate_original_replies(lines: list[str], expected: list[str]) -> None:
    actual = [line for line in lines[1:] if line.startswith(('RESULT ', 'ERROR '))]
    if not isinstance(expected, list) or not expected or actual != expected:
        raise ValueError('live-session-reply-mismatch')


def measure_cached_harness(cache: Path, output: Path, commands: list[str],
                           *, expected_replies: list[str] | None = None,
                           max_commands=512, max_input_bytes=64*1024*1024,
                           max_output_bytes=64*1024*1024, max_wall_seconds=60,
                           max_build_jobs: int | None = None) -> dict:
    """Build an instrumented copy and replay explicit commands on both binaries.

    One fresh process per binary ensures startup/reset is repeated. Up to 512
    sequential commands are accepted by default; an explicit budget permits up to 65536; results and every local sample must match
    byte-for-byte, otherwise no evidence document is published. This function
    does not infer or reconstruct a host-side scenario's hidden state.

    ``max_build_jobs`` caps only the compile schedule (never the pinned inputs
    or the instrumentation flags); the executed command is recorded separately
    from the derived instrumentation command.
    """
    budget=coverage_budget(max_commands=max_commands,max_input_bytes=max_input_bytes,
        max_output_bytes=max_output_bytes,max_wall_seconds=max_wall_seconds)
    cache, output = Path(cache).resolve(), Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('coverage-output-must-be-new')
    if (not isinstance(commands, list) or not 1 <= len(commands) <= max_commands
            or any(not isinstance(line, str) or not line.isascii() or '\n' in line
                   or '\r' in line or len(line) > 4096 for line in commands)):
        raise ValueError('invalid-coverage-commands')
    validate_wire_budget(commands,max_input_bytes=max_input_bytes,expected_replies=expected_replies,max_output_bytes=max_output_bytes)
    parsed = [line.split(' ') for line in commands]
    if any(len(row) < 4 or row[0] != 'CMD'
           or not re.fullmatch(r'[0-9a-f]{32}', row[1])
           or row[1] != parsed[0][1] or row[2] != f'{index:x}'
           for index, row in enumerate(parsed, 1)):
        raise ValueError('coverage-commands-must-be-sequential')
    manifest = json.loads((cache / 'manifest.json').read_text())
    identity = manifest['identity']
    unsigned = dict(identity)
    digest = unsigned.pop('build_digest')
    if _sha(unsigned) != digest or cache.name != digest:
        raise ValueError('coverage-build-identity-mismatch')
    for row in identity['inputs']:
        name = row['path']
        if (not isinstance(name, str) or not name or Path(name).is_absolute()
                or any(part in ('', '.', '..') for part in name.split('/'))):
            raise ValueError('invalid-coverage-input-path')
    original = _validate_cache(cache, identity)
    if _toolchain() != identity['toolchain']:
        raise ValueError('coverage-toolchain-mismatch')
    argv = identity['build_argv']
    if argv[0] != identity['toolchain']['verilator']['path']:
        raise ValueError('coverage-verilator-mismatch')
    output.mkdir(parents=True)
    for row in identity['inputs']:
        source = cache / 'inputs' / row['path']
        target = output / 'inputs' / row['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        if _digest(target) != row['sha256']:
            raise ValueError('coverage-input-changed')
    driver = output / 'inputs/generated/driver.cpp'
    driver.write_text(instrument_driver(driver.read_text()), encoding='utf-8')
    build_argv = coverage_argv(argv, str(output))
    executed_argv = (build_argv if max_build_jobs is None
                     else coverage_argv(argv, str(output), build_jobs=max_build_jobs))
    _compile(executed_argv, output)
    binary = output / 'obj/harness'
    if not binary.is_file():
        raise ValueError('coverage-binary-missing')
    command_text = '\n'.join(commands) + '\nEND\n'
    # The instrumented process writes coverage.dat into its private output dir.
    replay_options={key:value for key,value in requested_coverage_overrides(budget).items()
                    if key in ('max_output_bytes','max_wall_seconds')}
    replay_started=time.monotonic()
    plain = run_replay_bounded(original, commands, output,**replay_options)
    plain_finished=time.monotonic()
    measured = run_replay_bounded(binary, commands, output,**replay_options)
    instrumented_finished=time.monotonic()
    if plain != measured:
        raise ValueError('coverage-replay-output-mismatch')
    artifact = json.loads((output / 'inputs/generated/artifact.json').read_text())
    tick = validate_replay_replies(measured.splitlines(), parsed, artifact)
    if expected_replies is not None:
        validate_original_replies(plain.splitlines(), expected_replies)
    coverage = output / 'coverage.dat'
    if not coverage.is_file() or coverage.stat().st_size == 0:
        raise ValueError('coverage-readback-missing')
    points = parse_verilator_coverage(coverage.read_text(encoding='utf-8'))
    sources = dut_source_paths(artifact['structural_build']['source_files'])
    known = {row['path']: row['sha256'] for row in identity['inputs']}
    if any(name not in known for name in sources):
        raise ValueError('coverage-dut-source-list-invalid')
    inputs = (output / 'inputs').resolve()
    for point in points:
        source = Path(point['fields']['f'])
        if not source.is_absolute():
            raise ValueError('coverage-source-not-absolute')
        try:
            relative = source.resolve().relative_to(inputs).as_posix()
        except ValueError:
            raise ValueError('coverage-source-outside-snapshot') from None
        if relative not in known:
            raise ValueError('coverage-source-not-in-snapshot')
        point['normalized_source'] = relative
        point['source_sha256'] = known[relative]
    dut_points = [point for point in points if point['normalized_source'] in sources]
    if not dut_points:
        raise ValueError('coverage-dut-points-missing')
    point_document = {'schema_version': 'local_verilator_points.v1',
                      'all_points': points, 'selected_source_files': sources,
                      'dut_points': dut_points}
    points_path = output / 'coverage-points.json'
    points_path.write_text(json.dumps(point_document, indent=2, sort_keys=True) + '\n')
    (output / 'commands.txt').write_text(command_text)
    (output / 'replies.txt').write_text(measured)
    result = {
        'schema_version': 'local_harness_verilator_coverage.v1',
        'coverage_kind': 'verilator-line-block',
        'replay_budget':budget,
        'replay_seconds':{'plain':plain_finished-replay_started,'instrumented':instrumented_finished-plain_finished},
        'scope': 'whole generated local harness; DUT attribution requires source/hierarchy mapping',
        'limitations': ['includes startup/reset and all executed commands',
                        'not source-branch coverage; no comparison with semantic hits',
                        'recorded commands and replies are not independently authenticated',
                        'explicit command replay is not a reconstructed host scenario'],
        'original_build_digest': digest,
        'original_binary_sha256': _digest(original),
        'coverage_binary_sha256': _digest(binary),
        'coverage_data_sha256': _digest(coverage),
        'coverage_points_sha256': _digest(points_path),
        'instrumented_driver_sha256': _digest(driver),
        'build_argv': build_argv,
        'source_selection': {'basis': 'structural build source files; hierarchy retained',
                             'all_points': len(points), 'dut_points': len(dut_points),
                             'dut_lit_points': sum(p['count'] > 0 for p in dut_points)},
        'replay': {'identical_stdout': True, 'result_count': len(commands), 'local_ticks': tick,
                   'matches_recorded_replies': True if expected_replies is not None else None},
    }
    if executed_argv != build_argv:
        result['build_executed_argv'] = executed_argv
    if max_build_jobs is not None:
        result['build_jobs'] = max_build_jobs
    (output / 'coverage.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
    return result
