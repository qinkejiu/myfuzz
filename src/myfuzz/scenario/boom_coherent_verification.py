"""Exercise accepted A/C/D/E on the built persistent BOOM/RAM driver."""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from myfuzz.local_harness.boom_cpu_session import GeneratedBoomCpuSession
from .coherent_event_stream import CoherentAcceptedEventStream
from .boom_gpio_verification import scoped_prefix


def coherent_ram_program():
    def lui(rd, imm):
        return imm << 12 | rd << 7 | 0x37
    def addi(rd, rs, imm):
        return (imm & 4095) << 20 | rs << 15 | rd << 7 | 0x13
    def store(rs, base, imm, funct=3):
        return ((imm >> 5) & 127) << 25 | rs << 20 | base << 15 | funct << 12 | (imm & 31) << 7 | 0x23
    def load(rd, base, imm):
        return (imm & 4095) << 20 | base << 15 | 3 << 12 | rd << 7 | 3
    def zero_extend_base():
        return [lui(1, 0x80001), 32 << 20 | 1 << 15 | 1 << 12 | 1 << 7 | 0x13,
                32 << 20 | 1 << 15 | 5 << 12 | 1 << 7 | 0x13]
    words = [0x0330000f] + zero_extend_base() + [addi(2, 0, 0x123), store(2, 1, 0), load(3, 1, 0),
                                lui(4, 4), store(3, 4, 0, 2), lui(6, 1)]
    for _ in range(12):
        words.extend([6 << 20 | 1 << 15 | 1 << 7 | 0x33,
                      addi(2, 2, 1), store(2, 1, 0)])
    words += [0x0330000f] + zero_extend_base() + [load(3, 1, 0), store(3, 4, 8, 2), 0x6f]
    return b''.join(word.to_bytes(4, 'little') for word in words)


def run_probe(*, repo, cpu_output, output, one_shot_trace=None, max_edges=3000):
    output.mkdir(parents=True, exist_ok=True)
    traces, identities, summaries, receipts, runtime_prefixes = [], [], [], [], []
    for name in ('fresh1', 'fresh2'):
        stream = CoherentAcceptedEventStream(component_id='boom', instance_id='cpu',
            endpoint_id='coherent', clock_domain='clock', manager_order='per_source',
            address_bits=32, source_bits=3, sink_bits=3)
        rows, counts, measured_edges = [], Counter(), []
        try:
            with GeneratedBoomCpuSession(cpu_output, repo=repo) as session:
                session.begin_case('boom-persistent-coherent-ram')
                process = session._process
                session.load_program(coherent_ram_program())
                identities.append(session.identity_document())
                for _ in range(max_edges):
                    observation = session.step_local({})
                    measured_edges.append(observation)
                    for event in observation['accepted_events']:
                        rows.append(event)
                        counts[event['channel']] += 1
                    stream.consume_step(observation['accepted_events'], execution_id=session.execution_id,
                        reset_epoch=session.reset_epoch, local_tick=session.ticks)
                    if stream.report()['structural_error']:
                        raise RuntimeError('persistent coherent checker rejected actual rows')
                    values = [session.read64(address) for address in (0x4000, 0x4008, 0x80001000)]
                    if (values == [0x123] * 3 and observation['drained']
                            and all(counts[channel] for channel in ('A', 'C', 'D', 'E'))
                            and stream.report()['stream_closed']):
                        break
                else:
                    raise RuntimeError('persistent BOOM coherent probe did not complete')
                summaries.append({'ticks': session.ticks, 'values': values,
                    'channels': dict(counts), 'checker': stream.report()})
            summaries[-1]['native_process'] = {'pid': process.pid, 'exit': process.poll()}
        except Exception as error:
            (output / (name + '.failure.json')).write_text(json.dumps({
                'pass': False, 'type': type(error).__name__, 'error': str(error),
                'checker': stream.report()}, sort_keys=True) + '\n')
            raise
        finally:
            (output / (name + '.jsonl')).write_text(''.join(json.dumps(row, sort_keys=True) + '\n' for row in rows))
            (output / (name + '.runtime.json')).write_text(json.dumps(stream.runtime_events, sort_keys=True) + '\n')
            (output / (name + '.edges.jsonl')).write_text(''.join(json.dumps(edge, sort_keys=True) + '\n' for edge in measured_edges))
        traces.append(rows)
        receipts.append(measured_edges)
        runtime_prefixes.append(scoped_prefix(stream.runtime_events, {
            'cpu_execution': identities[-1]['execution_id'], 'coherent_stream': stream.stream_id}))
    baseline_equal = None
    if one_shot_trace is not None:
        baseline = [json.loads(line) for line in one_shot_trace.read_text().splitlines()]
        baseline = [row for row in baseline if row.get('channel') in ('A', 'C', 'D', 'E')]
        # The one-shot diagnostic adds manager address and fault flag to D.
        # Every actual bus field remains compared without substitution.
        baseline = [{key: value for key, value in row.items()
                     if not (row['channel'] == 'D' and key in ('address', 'fault_read'))}
                    for row in baseline]
        baseline_equal = baseline == traces[0]
    (output / 'program.hex').write_text(coherent_ram_program().hex() + '\n')
    report = {'schema_version': 'boom_persistent_coherent_probe.v1',
        'pass': traces[0] == traces[1] and receipts[0] == receipts[1]
                and runtime_prefixes[0] == runtime_prefixes[1]
                and identities[0]['execution_id'] != identities[1]['execution_id']
                and baseline_equal is not False
                and all(summary['native_process']['exit'] == 0 for summary in summaries),
        'raw_bus_prefix_equal': traces[0] == traces[1],
        'full_measured_edge_prefix_equal': receipts[0] == receipts[1],
        'full_scoped_runtime_prefix_equal': runtime_prefixes[0] == runtime_prefixes[1],
        'one_shot_bus_fields_equal': baseline_equal, 'identities': identities,
        'program_sha256': hashlib.sha256(coherent_ram_program()).hexdigest(),
        'summaries': summaries, 'generic_admission': False, 'full_P6': False}
    (output / 'gate.json').write_text(json.dumps(report, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('repo', 'cpu-output', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--one-shot-trace', type=Path)
    args = parser.parse_args()
    report = run_probe(repo=args.repo, cpu_output=args.cpu_output, output=args.output,
                       one_shot_trace=args.one_shot_trace)
    print(json.dumps({'pass': report['pass'], 'summaries': report['summaries']}))
    raise SystemExit(0 if report['pass'] else 1)


if __name__ == '__main__':
    main()
