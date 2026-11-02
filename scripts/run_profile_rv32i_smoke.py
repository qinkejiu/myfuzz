#!/usr/bin/env python3
"""Execute profile-generated RV32I/RV32M instructions or a flat binary on an OBI CPU."""
import argparse
from dataclasses import asdict, dataclass
from hashlib import sha256
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))


@dataclass(frozen=True)
class BinaryProgram:
    base: int
    code: bytes


def load_binary_program(profile, path, *, base):
    """Load a flat binary at the CPU's source-backed first-fetch address."""
    cpu = profile.cpu
    if cpu is None or cpu.family.lower() != 'riscv' or cpu.xlen != 32 or 'I' not in {x.upper() for x in cpu.extensions}:
        raise ValueError('RV32I CPU profile required')
    data = Path(path).read_bytes()
    if not data or type(base) is not int or base < 0 or base % 4 or base + len(data) > 1 << 32:
        raise ValueError('nonempty flat binary and aligned RV32 load address required')
    return BinaryProgram(base, data)


def observe_binary_retirements(events, *, requested_count=None):
    """Report actual retirement fields; never infer a result or success."""
    fields = ('event_id', 'order', 'pc_rdata', 'insn', 'trap', 'rd_addr', 'rd_wdata', 'pc_wdata')
    rows = [{key: event[key] for key in fields if key in event and event[key] is not None}
            for event in events if event.get('kind') == 'cpu_retire']
    return {'status': 'observed' if rows else 'unobserved', 'retirements': rows,
            'requested_retirements': requested_count,
            'stop_condition_met': None if requested_count is None else len(rows) >= requested_count}


def binary_exit_status(feedback):
    return 0 if feedback['status'] == 'observed' and feedback['stop_condition_met'] is not False else 1


def execute(artifact, program, *, base_dir, cache, output, max_steps,
            stop_after_retirements=None):
    from myfuzz.isa.profile_program import collect_retirements
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.local_harness.session import record_local_commands
    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
    from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
    from myfuzz.scenario.router import DataflowRouter
    from myfuzz.scenario.runner import ScenarioRunner

    output.mkdir()
    region_start = program.base & ~0xfff
    region_size = ((program.base - region_start + len(program.code) + 4095) // 4096) * 4096
    memory = PersistentMemory(regions=(MemoryRegion('ram', region_start, region_size),),
                              initialization_seed=0, max_initialized_bytes=region_size)
    memory.preload(program.base, program.code)
    cpu = GeneratedCve2Session(artifact, base_dir=base_dir, cache_dir=cache,
                               memory=memory, router=DataflowRouter(()), physical_tick_samples=True)
    cpu.configure_built_executable_receipt()
    ownership = compile_ownership((InputField('cpu', 'irq', 1),),
                                  (InputOwner('cpu', 'irq', 0, 1, 'source', 'host-irq'),))
    runner = ScenarioRunner(sessions={'cpu': cpu}, ownership=ownership, bindings=())
    events = []
    with record_local_commands() as recording:
        try:
            runner.begin_test('profile-rv32i-binary' if isinstance(program, BinaryProgram) else 'profile-rv32i-alu')
            runner.inject_source('cpu', 'irq', 0, direction='IP_TO_CPU')
            cursor = 0
            retired = 0
            for _ in range(max_steps):
                runner.step('cpu')
                new_events = runner.events_since(cursor)
                events.extend(new_events)
                cursor = runner.event_count
                if isinstance(program, BinaryProgram):
                    retired += sum(event.get('kind') == 'cpu_retire' for event in new_events)
                    if stop_after_retirements is not None and retired >= stop_after_retirements:
                        break
                else:
                    feedback = collect_retirements(program, events)
                    if feedback['status'] in ('verified', 'mismatch'):
                        break
            feedback = (observe_binary_retirements(events, requested_count=stop_after_retirements) if isinstance(program, BinaryProgram)
                        else collect_retirements(program, events))
        finally:
            runner.finalize()
        identities = recording.export_executions()
        (output / 'local_commands.json').write_text(json.dumps(recording.export_sessions(), indent=2) + '\n')
    (output / 'events.json').write_text(json.dumps(events, indent=2, default=str) + '\n')
    if hasattr(program, 'scratch_address'):
        scratch = memory.read(program.scratch_address, 4, transaction_id='flow-suite-check').value
        feedback['scratch'] = {'address': program.scratch_address, 'observed': scratch,
                               'expected': program.scratch_value}
        if scratch != program.scratch_value:
            feedback['status'] = 'mismatch'
    result = dict(feedback=feedback, processes=identities,
                  scope=('external flat binary; retirement observation only' if isinstance(program, BinaryProgram)
                         else 'profile-generated straight-line instructions; retirement observation only'))
    (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', type=Path, required=True)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--records', help='hexadecimal four-byte records')
    inputs.add_argument('--binary', type=Path, help='flat binary linked at the CPU first-fetch address')
    inputs.add_argument('--m-suite', action='store_true', help='execute the directed RV32M suite when declared')
    inputs.add_argument('--c-suite', action='store_true', help='execute the directed RV32C suite when declared')
    inputs.add_argument('--flow-suite', action='store_true', help='execute RV32I branches, jumps and RAM accesses')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--max-steps', type=int, default=256)
    parser.add_argument('--stop-after-retirements', type=int,
                        help='stop after this many observed retirements (binary mode)')
    args = parser.parse_args()
    if args.max_steps < 1 or (args.stop_after_retirements is not None and args.stop_after_retirements < 1):
        parser.error('step and retirement bounds must be positive')
    if args.stop_after_retirements is not None and args.binary is None:
        parser.error('--stop-after-retirements requires --binary')
    from myfuzz.isa.profile_program import build_alu_program, build_m_suite_program, build_c_suite_program, build_flow_suite_program
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact
    from myfuzz.integration.cpu_boot_contract import source_backed_boot_fetch
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from myfuzz.local_harness.build import host_source_discovery_scope
    if args.output.exists():
        raise ValueError('output already exists')
    args.output.mkdir(parents=True)
    with elaboration_mode_scope('direct'), host_source_discovery_scope(reuse_nested=True), execution_validation_scope():
        artifact = _artifact(str(args.profile), 'cpu')
        if artifact.runtime_document.get('kind') != 'obi_cpu':
            raise ValueError('OBI CPU session required')
        boot = source_backed_boot_fetch(artifact.plan.profile, base_dir=ROOT,
            configured_boot_base=artifact.runtime_document['boot_contract']['configured_boot_base'])
        if args.binary is not None:
            program = load_binary_program(artifact.plan.profile, args.binary, base=boot)
            program_doc = dict(base=boot, code_hex=program.code.hex(), kind='external-flat-binary',
                               source=str(args.binary), sha256=sha256(program.code).hexdigest())
        else:
            program = (build_flow_suite_program(artifact.plan.profile, base=boot) if args.flow_suite
                       else build_m_suite_program(artifact.plan.profile, base=boot) if args.m_suite
                       else build_c_suite_program(artifact.plan.profile, base=boot) if args.c_suite
                       else build_alu_program(artifact.plan.profile, bytes.fromhex(args.records), base=boot))
            program_doc = dict(base=boot, code_hex=program.code.hex(),
                               instructions=[asdict(row) for row in program.instructions])
        (args.output / 'program.json').write_text(json.dumps(program_doc, indent=2) + '\n')
        result = execute(artifact, program, base_dir=ROOT, cache=args.cache,
                         output=args.output / 'original', max_steps=args.max_steps,
                         stop_after_retirements=args.stop_after_retirements)
    print(json.dumps({'status': result['feedback']['status'], 'output': str(args.output)}))
    if args.binary is not None:
        return binary_exit_status(result['feedback'])
    return 0 if result['feedback']['status'] == 'verified' else 1


if __name__ == '__main__':
    raise SystemExit(main())
