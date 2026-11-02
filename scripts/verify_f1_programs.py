#!/usr/bin/env python3
"""Verify real F1 trampoline programs against the RV32 reference model.

The unified entry (``scripts/run_inprocess_f1f6.py``) hands a short straight-line
program to a fixed trampoline slot and reports, per case, how many program words
the CPU really retired, whether they retired in address order as the installed
instructions, the RVFI writeback mask, the last writeback, and the sampled
64-byte data window.  With per-event output the host also prints one
``rvfi <tick> <order> <rd_addr> <rd_wdata>`` and one
``retire <tick> <pc> <insn>`` line per retirement.

This script takes those two facts and checks them against
``myfuzz.fuzz.rv32_program.reference_run``:

* every retirement inside the trampoline slot is paired with its RVFI writeback
  and compared, in program order, with the model's predicted ``(pc, insn, rd,
  rd_wdata)``;
* the case's own program counters (``prog_retires``, ``prog_writebacks``,
  ``prog_rd_mask``, ``prog_last_*``, ``prog_traps``) are compared with the same
  prediction;
* the declared data window is modelled word by word: the host's ``data_hash_*``
  values are compared with an independently computed FNV-1a hash of the
  predicted window, and ``data_changed`` with the predicted number of changed
  words.  Because the window persists across cases in one process, it is carried
  from case to case, starting from the RAM image the entry builds;
* at least one cross-instruction dependency, one store -> load pair and one
  load -> store pair must be observed, and the observed writeback of the
  dependent instruction must equal the model's value.

It runs the entry itself (fixed-record path, events on), so the evidence is a
real CPU/IP/DMA process and its own log, not a replay.  ``--verify-only``
re-checks an existing run directory without running the RTL again.

What the model assumes (and what the script therefore checks)
-------------------------------------------------------------
The firmware establishes ``x8 = mailbox``, ``x9 = slot base`` and (for a program
build) ``x18 = data base`` before it jumps to the slot; it also leaves its own
residue in ``x5``/``x6`` (the F1 command word it just compared and ``1``) and in
whatever the previous case left in other registers.  None of that is observable
from the case line.  The script therefore *only* accepts programs that are
``self_contained`` in ``analyze_program`` terms - every value they read was
written by the program itself, apart from ``x0`` and the ``x18`` base - and
models them with ``x18 = data base`` and every other register zero.  A program
that reads firmware state is refused instead of being compared against a guess.

The data base is not printed either.  The entry's image layout is fixed
(``SLOT_OFFSET``/``DATA_OFFSET`` in the entry), and the case line prints the slot
address as ``fetch``; the script requires ``fetch == image_start + SLOT_OFFSET``
and derives ``data base = image_start + DATA_OFFSET``, so an entry that moved its
layout makes the script fail instead of silently modelling the wrong window.
The window's initial contents are the entry's own ``DATA_WORDS`` image followed
by zeroes; the first case's ``data_hash_before`` is required to equal the hash of
exactly that image.

The run log has to contain only F1 cases for the rolling window model to hold:
another flow (F2/F3) could write the same RAM words, and the script refuses a
non-F1 case by name.  ``--fuzz`` runs are quiet and carry no per-retirement
events, so only the fixed-record path is verifiable here.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT))

from myfuzz.fuzz.rv32_program import (  # noqa: E402
    DEFAULT_RESERVED_REGISTERS, analyze_program, generate_program,
    reference_run,
)
from myfuzz.isa.constraints import f1_isa_from_profile  # noqa: E402
from myfuzz.composition.component_profile import load_component_profile  # noqa: E402
from myfuzz.riscv.encoding import encode  # noqa: E402
from myfuzz.riscv.profile import profile_from_mapping  # noqa: E402
from scripts.run_inprocess_f1f6 import (  # noqa: E402
    DATA_OFFSET, DATA_WORDS, PROGRAM_DATA_WORDS, SLOT_OFFSET, declared_windows,
    parse_case_line, parse_event_line, parse_record, validate_record,
)

SCHEMA = 'f1_program_verification.v1'
FLOWS = ('F1', 'F2', 'F3', 'F4', 'F5', 'F6')
WINDOW_WORDS = PROGRAM_DATA_WORDS
WINDOW_BYTES = WINDOW_WORDS * 4
FNV_OFFSET = 2166136261
FNV_PRIME = 16777619

#: What this verification does not claim, stated once so every report repeats it.
OUTSIDE_CONTRACT = (
    'RV32 only: the generator and the model are 32-bit; RV64 is not claimed.',
    'Straight-line only: no branch, jump, CSR/SYSTEM or FENCE word is admitted '
    'or verified.',
    'Memory words are LW/SW against x18 with a 4-byte aligned offset inside the '
    'declared 16-word (64-byte) window; wider windows or byte/half-word opcodes '
    'would be a host extension.',
    'An effective address is always x18 + immediate, so an ALU result can feed '
    'stored data but never an address; that is a host-contract limit, not a '
    'generator choice.',
    'x8, x9 and x18 are reserved: a verified program never writes them.',
    'AUIPC is admitted by the C++ host and modelled here, but the entry\'s '
    'Python record gate (myfuzz.scenario.rv32i_sources) refuses opcode 0x17, so '
    'no AUIPC record can reach the host through scripts/run_inprocess_f1f6.py '
    'today.  The verified programs omit it.',
    'The case line reports a 32-bit FNV-1a hash of the window, not the words '
    'themselves; the window state is reconstructed from the model and checked '
    'through that hash.',
)


def _hex(value):
    return '0x%08x' % (value & 0xFFFFFFFF)


def window_hash(words):
    """The host's own window hash: 32-bit FNV-1a over the little-endian words."""
    digest = FNV_OFFSET
    for value in words:
        for byte in range(4):
            digest ^= (value >> (8 * byte)) & 0xFF
            digest = (digest * FNV_PRIME) & 0xFFFFFFFF
    return digest


def pristine_window():
    """The declared data window as the entry builds it: its image, then zeroes."""
    window = [0] * WINDOW_WORDS
    for index, value in enumerate(DATA_WORDS[:WINDOW_WORDS]):
        window[index] = value
    return window


def record_text(words):
    return 'F1:' + ':'.join('%08x' % (word & 0xFFFFFFFF) for word in words)


def words_from_record(text):
    fields = text.split(':')
    if not fields or fields[0] != 'F1' or len(fields) < 2:
        raise ValueError('not an F1 record: ' + str(text))
    return tuple(int(field, 16) for field in fields[1:])


def load_context(config_path):
    """The declarations this verification needs, read from the entry itself."""
    path = Path(config_path)
    if not path.is_absolute():
        path = ROOT / path
    config = json.loads(path.read_text())
    dma_window = config.get('dma_window')
    windows = declared_windows(
        config, dma_window['size'] if config.get('dma_profile') is not None
        and isinstance(dma_window, dict) else None)
    f1_words = config.get('f1_program_words', 1)
    if type(f1_words) is not int or not 1 <= f1_words <= 16:
        raise ValueError('f1_program_words must be an integer in 1..16')
    if windows['ram_base'] != config.get('image_start'):
        raise ValueError('the declared data window does not follow image_start')
    data_base = windows['ram_base'] + DATA_OFFSET
    if data_base != windows['data_base']:
        raise ValueError('the entry data window is not image_start + DATA_OFFSET')
    if windows['data_base'] + WINDOW_BYTES > windows['ram_base'] + windows['ram_size']:
        raise ValueError('the declared RAM leaves no room for the data window')
    cpu_profile = load_component_profile(ROOT / config['cpu_profile'])
    isa = f1_isa_from_profile(cpu_profile)
    program_profile = profile_from_mapping(
        json.loads((ROOT / config['cpu_profile']).read_text()))
    if program_profile.xlen != 32:
        raise ValueError('the F1 program model is RV32 only')
    return dict(path=path, config=config, windows=windows, isa=isa,
                program_profile=program_profile, f1_words=f1_words,
                ram_base=windows['ram_base'], slot=windows['ram_base'] + SLOT_OFFSET,
                data_base=data_base, data_words=DATA_WORDS,
                program_data_words=WINDOW_WORDS)


def gate_words(context, words):
    """Ask the entry's own record gate; return the refusal text or None."""
    try:
        record = parse_record(record_text(words), windows=context['windows'],
                              arity={'F1': context['f1_words']},
                              f1_words=context['f1_words'])
        validate_record(record, isa=context['isa'], windows=context['windows'],
                        f1_words=context['f1_words'])
    except ValueError as error:
        return str(error)
    return None


def directed_programs(context):
    """The hand-written programs: one per required data-flow shape.

    Every program is 4..8 words, self-contained, and carries at least one
    cross-instruction register dependency; between them they cover an ALU chain,
    a load feeding an ALU and a store, a store feeding a load, a repeated
    address, M operations and shifts.
    """
    word = lambda name, **operands: encode(name, xlen=32, **operands)  # noqa: E731
    programs = [
        dict(name='alu-chain',
             detail='ADDI writes x5, ADDI reads x5, ADD reads both, SW stores the '
                    'computed value',
             words=(word('ADDI', rd=5, rs1=0, imm=3),
                    word('ADDI', rd=6, rs1=5, imm=4),
                    word('ADD', rd=7, rs1=6, rs2=5),
                    word('SW', rs2=7, rs1=18, imm=0))),
        dict(name='add-writes-x5-add-reads-x5',
             detail='ADD overwrites x5 from x5 (the classic chain example) and a '
                    'later ADD reads the new x5',
             words=(word('LUI', rd=5, imm=1),
                    word('ADD', rd=5, rs1=5, rs2=5),
                    word('ADDI', rd=6, rs1=5, imm=1),
                    word('SW', rs2=5, rs1=18, imm=4),
                    word('ADD', rd=7, rs1=6, rs2=5))),
        dict(name='lw-then-sw-and-store-load',
             detail='LW x10 then SW x10 stores the loaded word back; the ALU '
                    'result is stored at a second offset and reloaded',
             words=(word('LW', rd=10, rs1=18, imm=0),
                    word('ADDI', rd=11, rs1=10, imm=1),
                    word('SW', rs2=11, rs1=18, imm=4),
                    word('LW', rd=12, rs1=18, imm=4),
                    word('SW', rs2=10, rs1=18, imm=0))),
        dict(name='div-rem-chain',
             detail='DIV and REM of one chain, added, stored and reloaded',
             words=(word('ADDI', rd=5, rs1=0, imm=-7),
                    word('ADDI', rd=6, rs1=0, imm=3),
                    word('DIV', rd=7, rs1=5, rs2=6),
                    word('REM', rd=10, rs1=5, rs2=6),
                    word('ADD', rd=11, rs1=7, rs2=10),
                    word('SW', rs2=11, rs1=18, imm=8),
                    word('LW', rd=12, rs1=18, imm=8),
                    word('ADD', rd=13, rs1=12, rs2=11))),
        dict(name='shift-chain',
             detail='LUI then every shift-immediate form, added, stored, reloaded',
             words=(word('LUI', rd=5, imm=0x12345),
                    word('SLLI', rd=6, rs1=5, shamt=4),
                    word('SRLI', rd=7, rs1=6, shamt=2),
                    word('SRAI', rd=10, rs1=7, shamt=1),
                    word('ADD', rd=11, rs1=10, rs2=7),
                    word('SW', rs2=11, rs1=18, imm=12),
                    word('LW', rd=12, rs1=18, imm=12),
                    word('ADD', rd=13, rs1=12, rs2=10))),
        dict(name='two-chains-repeated-address',
             detail='two roots are joined; the same offset is stored twice and '
                    'read back, so the last store is the loaded value',
             words=(word('ADDI', rd=5, rs1=0, imm=5),
                    word('ADDI', rd=6, rs1=0, imm=9),
                    word('ADD', rd=7, rs1=5, rs2=6),
                    word('SW', rs2=7, rs1=18, imm=16),
                    word('SW', rs2=5, rs1=18, imm=16),
                    word('LW', rd=10, rs1=18, imm=16),
                    word('ADD', rd=11, rs1=10, rs2=6))),
        dict(name='slt-sltu-chain',
             detail='signed and unsigned compares of a chain value feeding an ADD '
                    'that is stored and reloaded',
             words=(word('ADDI', rd=5, rs1=0, imm=-1),
                    word('ADDI', rd=6, rs1=0, imm=1),
                    word('SLT', rd=7, rs1=5, rs2=6),
                    word('SLTU', rd=10, rs1=5, rs2=6),
                    word('ADD', rd=11, rs1=7, rs2=6),
                    word('SW', rs2=11, rs1=18, imm=20),
                    word('LW', rd=12, rs1=18, imm=20))),
        dict(name='mul-div-rem-chain',
             detail='MUL, DIV and REM of one root, added and stored then reloaded',
             words=(word('LUI', rd=5, imm=3),
                    word('MUL', rd=6, rs1=5, rs2=5),
                    word('DIV', rd=7, rs1=6, rs2=5),
                    word('REM', rd=10, rs1=6, rs2=5),
                    word('ADD', rd=11, rs1=7, rs2=10),
                    word('SW', rs2=11, rs1=18, imm=24),
                    word('LW', rd=12, rs1=18, imm=24),
                    word('ADD', rd=13, rs1=11, rs2=12))),
    ]
    for program in programs:
        program['style'] = 'directed'
    return programs


def generated_programs(context, count, length, seed_base=0):
    """Generated dependency-skeleton programs of exactly ``length`` words."""
    if count <= 0:
        return []
    if not 4 <= length <= context['f1_words']:
        raise ValueError(
            f'a generated program of {length} words does not fit the declared '
            f'f1_program_words {context["f1_words"]}')
    chosen = []
    for seed in range(seed_base, seed_base + 2000):
        if len(chosen) == count:
            break
        program = generate_program(
            context['program_profile'], seed=seed, max_words=length,
            min_words=length, window_size=WINDOW_BYTES, style='chains',
            allow_auipc=False)
        if len(program.words) != length:
            continue
        if gate_words(context, program.words) is not None:
            continue
        analysis = analyze_program(program.words)
        if not analysis['self_contained'] or analysis['dependency_edges'] < 2:
            continue
        if length >= 8 and not (analysis['store_to_load']
                                and analysis['load_to_store']):
            continue
        chosen.append(dict(name='generated-seed-%d' % seed,
                           detail='generated dependency skeleton (seed %d, '
                                  'style %s)' % (seed, program.style),
                           style=program.style, seed=seed,
                           words=program.words))
    if len(chosen) < count:
        raise ValueError(
            f'only {len(chosen)} of {count} generated programs passed the entry '
            'gate and the data-flow requirements')
    return chosen


def program_set(context, generated, generated_words, seed):
    programs = directed_programs(context) + generated_programs(
        context, generated, generated_words, seed)
    for program in programs:
        words = tuple(program['words'])
        refusal = gate_words(context, words)
        if refusal is not None:
            raise ValueError('program %s is refused by the entry gate: %s'
                             % (program['name'], refusal))
        analysis = analyze_program(words)
        if not analysis['self_contained']:
            raise ValueError('program %s reads firmware state: %s'
                             % (program['name'], analysis['external_reads']))
        if analysis['dependency_edges'] < 1:
            raise ValueError('program %s has no cross-instruction dependency'
                             % program['name'])
        program['words'] = words
        program['text'] = record_text(words)
        program['analysis'] = analysis
    return programs


def describe_programs(programs):
    return [dict(name=program['name'], detail=program['detail'],
                 style=program.get('style'), seed=program.get('seed'),
                 text=program['text'], words=list(program['words']),
                 assembly=[item['assembly'] for item in
                           program['analysis']['instructions']],
                 analysis=program['analysis'])
            for program in programs]


def run_entry(context, programs, *, output, cache, max_ticks, entry_log,
              python=sys.executable):
    """Run the unified entry on exactly these records, events on."""
    if output.exists():
        raise ValueError('the output directory must not exist: ' + str(output))
    records = ','.join(program['text'] for program in programs)
    command = [str(python), str(ROOT / 'scripts/run_inprocess_f1f6.py'),
               '--config', str(context['path']), '--output', str(output),
               '--records', records, '--max-ticks', str(max_ticks)]
    if cache is not None:
        command.extend(['--cache', str(cache)])
    completed = subprocess.run(command, cwd=str(ROOT), text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    entry_log.parent.mkdir(parents=True, exist_ok=True)
    entry_log.write_text(completed.stdout or '')
    if completed.returncode != 0:
        raise RuntimeError('the entry failed with exit %d; see %s'
                           % (completed.returncode, entry_log))
    return command


def _pair_events(lines):
    """Pair every RVFI line with the retire line the host printed with it."""
    rvfi, retires = [], []
    for line in lines:
        if line.startswith('rvfi '):
            rvfi.append(parse_event_line(line))
        elif line.startswith('retire '):
            tokens = line.split()
            if len(tokens) != 4 or not tokens[2].startswith('0x') \
                    or not tokens[3].startswith('0x'):
                raise ValueError('unexpected retire line: ' + line)
            retires.append(dict(kind='retire', tick=int(tokens[1]),
                                pc=int(tokens[2], 16), insn=int(tokens[3], 16)))
    pairs, mismatched = [], []
    if len(rvfi) != len(retires):
        mismatched.append('the case printed %d rvfi lines but %d retire lines'
                          % (len(rvfi), len(retires)))
    for rvfi_event, retire in zip(rvfi, retires):
        if rvfi_event['tick'] != retire['tick']:
            mismatched.append('rvfi tick %d does not pair with retire tick %d'
                              % (rvfi_event['tick'], retire['tick']))
            continue
        pairs.append((rvfi_event, retire))
    return pairs, mismatched


def parse_log(text):
    """Split the run log into cases with the retirement lines each printed.

    The host prints a case line *after* the case completed, so the events between
    the previous case line and this one are exactly this case's events: the
    program retirements and the firmware's return path are included, and the next
    case's polling loop falls into the next bucket, where the program-address
    filter drops it.  The batch path installs every record up front and prints no
    ``CASE_INSTALLED`` line, so the case line - not the install line - is the
    boundary; ``installed`` is kept for the online path where it is printed.
    """
    cases, events, summary, installed = [], [], None, []
    current = []
    for line in text.splitlines():
        if line.startswith('CASE_INSTALLED '):
            installed.append(int(line.split()[1]))
        elif line.startswith('case '):
            cases.append(parse_case_line(line, flows=FLOWS))
            events.append(current)
            current = []
        elif line.startswith('summary '):
            summary = line
        elif line.startswith('rvfi ') or line.startswith('retire '):
            current.append(line)
    if len(events) != len(cases):  # pragma: no cover - parser invariant
        raise ValueError('the run log has %d case lines but %d event groups'
                         % (len(cases), len(events)))
    return dict(cases=cases, events=events, summary=summary, installed=installed)


def _window_state(context, before, model):
    """The window after the model's stores, as the host would sample it."""
    after = list(before)
    for step in model['steps']:
        if step['name'] != 'SW':
            continue
        offset = step['address'] - context['data_base']
        if offset < 0 or offset % 4 or offset >= WINDOW_BYTES:
            raise ValueError('a modelled store left the declared window at %s'
                             % _hex(step['address']))
        after[offset // 4] = step['value']
    return after


def _dependency_examples(context, analysis, model):
    """Concrete dependency statements with the values both sides observed."""
    steps = model['steps']
    examples = []
    for edge in analysis['dependencies']:
        producer = steps[edge['producer']]
        consumer = steps[edge['consumer']]
        produced = producer.get('value')
        if 'rd' in producer and producer['rd']:
            produced = producer['value']
        examples.append(dict(
            producer_index=edge['producer'],
            consumer_index=edge['consumer'],
            register=edge['register'],
            producer=analysis['instructions'][edge['producer']]['assembly'],
            consumer=analysis['instructions'][edge['consumer']]['assembly'],
            produced_value=_hex(produced if produced is not None else 0),
            consumer_value=_hex(consumer.get('value', 0))))
    return examples


def verify_case(context, program, case, event_lines, *, window_before):
    """Check one case; return its report and the window it leaves behind."""
    problems = []
    words = program['words']
    analysis = program.get('analysis') or analyze_program(words)
    count = len(words)
    slot = case.get('fetch')
    if case.get('flow') != 'F1':
        return (dict(index=case.get('index'), record=case.get('record'),
                     status='refused', problems=['the case is not an F1 case']),
                window)
    if slot != context['slot']:
        problems.append('the case fetched from %s, not the declared slot %s'
                        % (slot, _hex(context['slot'])))
        slot = context['slot']
    data_base = context['data_base']
    program_end = slot + 4 * count
    model = reference_run(words, registers={18: data_base},
                          memory={data_base + 4 * index: value
                                  for index, value in enumerate(window_before)
                                  if value},
                          data_base=slot, window_size=WINDOW_BYTES, trace=True)
    predicted_writes = {write['index']: write
                        for write in model['register_writes']}

    # -- retirements ------------------------------------------------------
    pairs, pairing_problems = _pair_events(event_lines)
    problems.extend(pairing_problems)
    program_pairs = [(rvfi_event, retire) for rvfi_event, retire in pairs
                     if slot <= retire['pc'] < program_end]
    retirements = []
    if len(program_pairs) != count:
        problems.append('the program region retired %d words, not %d'
                        % (len(program_pairs), count))
    for position, (rvfi_event, retire) in enumerate(program_pairs):
        expected_pc = slot + 4 * position
        record = dict(index=position, tick=retire['tick'],
                      pc=_hex(retire['pc']), insn=_hex(retire['insn']),
                      rd=rvfi_event['rd_addr'],
                      rd_wdata=_hex(rvfi_event['rd_wdata']))
        if retire['pc'] != expected_pc:
            problems.append('retirement %d is at %s, not %s'
                            % (position, _hex(retire['pc']), _hex(expected_pc)))
        if retire['insn'] != words[position]:
            problems.append('retirement %d retired %s, not the installed %s'
                            % (position, _hex(retire['insn']),
                               _hex(words[position])))
        write = predicted_writes.get(position)
        if write is None:
            record['predicted'] = None
            if rvfi_event['rd_addr'] != 0:
                problems.append('retirement %d wrote x%d but the model writes no '
                                'register there'
                                % (position, rvfi_event['rd_addr']))
        else:
            record['predicted'] = dict(rd=write['rd'], rd_wdata=_hex(write['value']))
            if rvfi_event['rd_addr'] != write['rd']:
                problems.append('retirement %d wrote x%d, the model predicts x%d'
                                % (position, rvfi_event['rd_addr'], write['rd']))
            elif rvfi_event['rd_wdata'] != write['value']:
                problems.append(
                    'retirement %d (x%d) observed %s, the model predicts %s'
                    % (position, write['rd'], _hex(rvfi_event['rd_wdata']),
                       _hex(write['value'])))
        retirements.append(record)
    if len(retirements) == count and retirements:
        # ``prog_last_rd``/``prog_last_wdata`` are the last *writeback*, not the
        # last retirement: a trailing store retires without writing a register,
        # so the last retirement that the model says writes one is the one the
        # case fields have to agree with.
        last_writing = next((row for row in reversed(retirements)
                             if row.get('predicted')), None)
        last_rd = last_writing['predicted']['rd'] if last_writing else 0
        last_wdata = (int(last_writing['predicted']['rd_wdata'], 16)
                      if last_writing else 0)
        if case.get('prog_last_pc') != slot + 4 * (count - 1):
            problems.append('the case last retired pc is %s, not %s'
                            % (case.get('prog_last_pc'),
                               _hex(slot + 4 * (count - 1))))
        if case.get('prog_last_insn') != words[-1]:
            problems.append('the case last retired instruction is %s, not %s'
                            % (_hex(case.get('prog_last_insn') or 0),
                               _hex(words[-1])))
        if case.get('prog_last_rd') != last_rd:
            problems.append('the case last writeback register is x%s, the '
                            'retirements say x%d'
                            % (case.get('prog_last_rd'), last_rd))
        if case.get('prog_last_wdata') != last_wdata:
            problems.append('the case last writeback value is %s, the retirements '
                            'say %s' % (_hex(case.get('prog_last_wdata') or 0),
                                        _hex(last_wdata)))

    # -- the case's own program counters ---------------------------------
    expected_checks = {
        'prog_words': count,
        'prog_retires': count,
        'prog_pc_ordered': 1,
        'prog_insns_match': 1,
        'prog_writebacks': len(predicted_writes),
        'prog_rd_mask': _mask(predicted_writes),
        'prog_last_rd': (model['register_writes'][-1]['rd']
                         if model['register_writes'] else 0),
        'prog_last_wdata': (model['register_writes'][-1]['value']
                            if model['register_writes'] else 0),
        'prog_last_pc': slot + 4 * (count - 1),
        'prog_last_insn': words[-1],
        'prog_traps': 0,
    }
    observed_checks = {}
    for key, expected in expected_checks.items():
        observed = case.get(key)
        observed_checks[key] = observed
        if observed != expected:
            problems.append('the case reports %s %s, the model predicts %s'
                            % (key, observed, expected))
    if case.get('retire_pc') != slot:
        problems.append('the case reports retire_pc %s, not the slot %s'
                        % (case.get('retire_pc'), _hex(slot)))
    if case.get('successor_pc') != program_end:
        problems.append('the case reports successor_pc %s, not %s'
                        % (case.get('successor_pc'), _hex(program_end)))

    # -- the declared data window ----------------------------------------
    window_after = _window_state(context, window_before, model)
    before_hash = window_hash(window_before)
    after_hash = window_hash(window_after)
    changed = sum(1 for before, after in zip(window_before, window_after)
                  if before != after)
    memory_report = dict(
        data_base=_hex(data_base), window_words=WINDOW_WORDS,
        before=[_hex(value) for value in window_before],
        after=[_hex(value) for value in window_after],
        before_hash=_hex(before_hash), after_hash=_hex(after_hash),
        changed=changed,
        observed=dict(before_hash=_hex(case.get('data_hash_before') or 0),
                      after_hash=_hex(case.get('data_hash_after') or 0),
                      changed=case.get('data_changed')),
        stores=[dict(offset=step['address'] - data_base,
                     value=_hex(step['value']))
                for step in model['steps'] if step['name'] == 'SW'])
    if case.get('data_hash_before') != before_hash:
        problems.append('the observed window hash before the case is %s, the '
                        'model predicts %s'
                        % (_hex(case.get('data_hash_before') or 0),
                           _hex(before_hash)))
    if case.get('data_hash_after') != after_hash:
        problems.append('the observed window hash after the case is %s, the '
                        'model predicts %s'
                        % (_hex(case.get('data_hash_after') or 0),
                           _hex(after_hash)))
    if case.get('data_changed') != changed:
        problems.append('the case reports %s changed window words, the model '
                        'predicts %d' % (case.get('data_changed'), changed))

    # -- data-flow evidence ----------------------------------------------
    store_values = {}
    observed_loads = {}
    for pair in analysis['store_to_load']:
        store_step = model['steps'][pair['store']]
        store_values.setdefault(pair['offset'], store_step['value'])
        observed_loads.setdefault(pair['offset'], []).append(pair['load'])
    reload_evidence = []
    for pair in analysis['store_to_load']:
        load = retirements[pair['load']] if pair['load'] < len(retirements) else None
        if load is None:
            continue
        reload_evidence.append(dict(
            offset=pair['offset'],
            store_index=pair['store'],
            load_index=pair['load'],
            stored_value=_hex(store_values[pair['offset']]),
            observed_load_wdata=load['rd_wdata'],
            matches=(int(load['rd_wdata'], 16)
                     == store_values[pair['offset']])))

    return dict(index=case.get('index'), record=case.get('record'),
                status=case.get('status'), program=program['name'],
                words=count, text=program['text'],
                assembly=[item['assembly'] for item in
                          analysis['instructions']],
                retirements=retirements,
                case_checks=dict(expected=expected_checks,
                                 observed=observed_checks),
                memory=memory_report,
                dependencies=_dependency_examples(context, analysis, model),
                dependency_edges=analysis['dependency_edges'],
                load_to_store=analysis['load_to_store'],
                store_to_load=analysis['store_to_load'],
                reload_evidence=reload_evidence,
                self_contained=analysis['self_contained'],
                problems=problems), window_after


def _mask(writes):
    mask = 0
    for write in writes.values():
        mask |= 1 << write['rd']
    return mask


def verify_run(context, run_dir, programs):
    """Verify one saved run directory; return the report document."""
    log_path = Path(run_dir) / 'run.log'
    if not log_path.is_file():
        raise ValueError('the run directory has no run.log: ' + str(run_dir))
    parsed = parse_log(log_path.read_text())
    cases = parsed['cases']
    if not cases:
        raise ValueError('the run log has no case line')
    if len(cases) != len(programs):
        raise ValueError('the run has %d cases but %d programs were submitted'
                         % (len(cases), len(programs)))
    window = pristine_window()
    reports, all_problems = [], []
    for position, case in enumerate(cases):
        program = programs[position]
        events = parsed['events'][position]
        report, window = verify_case(context, program, case, events,
                                     window_before=window)
        reports.append(report)
        all_problems.extend((case.get('index'), problem)
                            for problem in report.get('problems', ()))
    for position, case in enumerate(cases):
        if case.get('status') != 'observations_passed':
            all_problems.append((case.get('index'),
                                 'the entry classified the case as %s'
                                 % case.get('status')))

    dependency_cases = sum(1 for report in reports
                           if report.get('dependency_edges'))
    changed_cases = sum(1 for report in reports
                        if report.get('memory', {}).get('changed'))
    reload_cases = sum(1 for report in reports
                       if any(evidence['matches']
                              for evidence in report.get('reload_evidence', ())))
    load_store_cases = sum(1 for report in reports if report.get('load_to_store'))
    writebacks = sum(1 for report in reports
                     for retirement in report.get('retirements', ())
                     if retirement.get('predicted'))
    retirements = sum(len(report.get('retirements', ())) for report in reports)
    if not dependency_cases:
        all_problems.append((None, 'no case carried a cross-instruction dependency'))
    if not changed_cases:
        all_problems.append((None, 'no case changed the declared data window'))
    if not reload_cases:
        all_problems.append((None, 'no case reloaded a value it had stored'))
    if not load_store_cases:
        all_problems.append((None, 'no case stored a value a load had produced'))

    document = dict(
        schema_version=SCHEMA,
        status='verified' if not all_problems else 'mismatch',
        config=str(context['path']),
        run_dir=str(run_dir),
        run_log=str(log_path),
        host_contract=dict(
            slot=_hex(context['slot']), data_base=_hex(context['data_base']),
            window_bytes=WINDOW_BYTES, window_words=WINDOW_WORDS,
            reserved_registers=list(DEFAULT_RESERVED_REGISTERS),
            flows_offered=list(FLOWS)),
        assumptions=[
            'The firmware sets x8 = mailbox, x9 = slot base and x18 = data base '
            'before the jump; x5 holds the F1 command word it just compared and '
            'x6 holds 1, and other registers keep whatever the previous case '
            'left.  None of that is printed, so every verified program is '
            'self-contained and is modelled with x18 = data base and every other '
            'register zero.',
            'The data base is image_start + DATA_OFFSET (%s); the case line prints '
            'the slot address as fetch, and this script requires fetch == '
            'image_start + SLOT_OFFSET (%s) before it models anything.'
            % (_hex(context['data_base']), _hex(context['slot'])),
            'The data window starts as the entry DATA_WORDS image followed by '
            'zeroes; the first case must reproduce that image\'s FNV-1a hash, and '
            'each later case starts from the window the model left behind.',
            'Only F1 cases may appear in the run: another flow could write the '
            'same RAM words, so a non-F1 case is refused.',
        ],
        data_window=dict(base=_hex(context['data_base']), words=WINDOW_WORDS,
                         pristine=[_hex(value) for value in pristine_window()],
                         hash=_hex(window_hash(pristine_window()))),
        programs=describe_programs(programs),
        cases=reports,
        summary=dict(
            cases=len(cases), cases_matched=sum(1 for report in reports
                                               if not report.get('problems')),
            problems=len(all_problems), retirements_compared=retirements,
            writebacks_compared=writebacks,
            dependency_cases=dependency_cases, changed_window_cases=changed_cases,
            reload_cases=reload_cases, load_to_store_cases=load_store_cases),
        problems=[dict(case=case, problem=problem)
                  for case, problem in all_problems],
        outside_the_host_contract=list(OUTSIDE_CONTRACT),
    )
    return document


def render_markdown(document):
    """One human-readable summary of the same facts."""
    lines = ['# F1 program verification', '',
             'status: **%s**' % document['status'], '',
             'config: `%s`' % document['config'],
             'run: `%s`' % document['run_dir'], '',
             '## Cases', '',
             '| # | program | words | retirements | writebacks | window words '
             'changed | dependencies | problems |',
             '|---|---|---:|---:|---:|---:|---:|---|']
    for report in document['cases']:
        if report.get('status') == 'refused':
            lines.append('| %s | - | - | - | - | - | - | %s |'
                         % (report.get('index'), '; '.join(report['problems'])))
            continue
        memory = report.get('memory', {})
        lines.append('| %s | %s | %s | %s | %s | %s | %s | %s |' % (
            report['index'], report['program'], report['words'],
            len(report['retirements']),
            sum(1 for row in report['retirements'] if row.get('predicted')),
            memory.get('changed'), report.get('dependency_edges'),
            len(report.get('problems', ())) or 'none'))
    lines.extend(['', '## Retirement correspondence', ''])
    lines.append('Every retirement inside the trampoline slot was paired with the '
                 'RVFI writeback the host printed for the same tick and compared '
                 'with `reference_run`; the case counters (`prog_retires`, '
                 '`prog_writebacks`, `prog_rd_mask`, `prog_last_*`, `prog_traps`) '
                 'and the `data_hash_*`/`data_changed` window facts were compared '
                 'with the same prediction.')
    lines.append('')
    for report in document['cases']:
        if report.get('status') == 'refused':
            continue
        rows = [row for row in report['retirements'] if row.get('predicted')]
        if not rows:
            continue
        lines.append('- case %s `%s`: %d retirements, %d predicted writebacks; '
                     'window %s -> %s (%d word(s) changed)'
                     % (report['index'], report['program'],
                        len(report['retirements']), len(rows),
                        report['memory']['before_hash'],
                        report['memory']['after_hash'],
                        report['memory']['changed']))
    lines.extend(['', '## Dependency evidence', ''])
    shown = 0
    for report in document['cases']:
        for example in report.get('dependencies', ()):
            if shown >= 12:
                break
            lines.append('- case %s: word %d `%s` writes x%d, word %d `%s` reads it; '
                         'model value %s'
                         % (report['index'], example['producer_index'],
                            example['producer'], example['register'],
                            example['consumer_index'], example['consumer'],
                            example['produced_value']))
            shown += 1
    for report in document['cases']:
        for evidence in report.get('reload_evidence', ()):
            lines.append('- case %s: offset %d stored `%s` at word %d and word %d '
                         'reloaded `%s` (observed RVFI writeback)'
                         % (report['index'], evidence['offset'],
                            evidence['stored_value'], evidence['store_index'],
                            evidence['load_index'],
                            evidence['observed_load_wdata']))
    lines.extend(['', '## What is outside the host contract', ''])
    for item in document.get('outside_the_host_contract', ()):
        lines.append('- ' + item)
    if document.get('problems'):
        lines.extend(['', '## Problems', ''])
        for row in document['problems']:
            lines.append('- case %s: %s' % (row['case'], row['problem']))
    lines.append('')
    return '\n'.join(lines)


def write_document(document, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / 'verification.json'
    markdown_path = output_dir / 'verification.md'
    json_path.write_text(json.dumps(document, indent=2) + '\n')
    markdown_path.write_text(render_markdown(document))
    return json_path, markdown_path


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--config', required=True,
                        help='the F1 program scenario the run uses')
    parser.add_argument('--output', default=None,
                        help='new directory for the entry run and the report')
    parser.add_argument('--cache', default=None,
                        help='build cache directory handed to the entry')
    parser.add_argument('--run-dir', default=None,
                        help='verify an existing run directory instead of running')
    parser.add_argument('--report-dir', default=None,
                        help='where verification.json/.md go (default: the run '
                             'directory when verifying, else the output parent)')
    parser.add_argument('--generated', type=int, default=4,
                        help='generated dependency-skeleton programs to add')
    parser.add_argument('--generated-words', type=int, default=8,
                        help='length of each generated program (4..16)')
    parser.add_argument('--seed', type=int, default=0,
                        help='first generator seed for the generated programs')
    parser.add_argument('--max-ticks', type=int, default=200000)
    parser.add_argument('--entry-log', default=None,
                        help='file that keeps the entry process output')
    args = parser.parse_args(argv)

    context = load_context(args.config)
    if args.run_dir is not None:
        if args.output is not None:
            parser.error('--run-dir and --output are alternatives')
        run_dir = Path(args.run_dir)
        if args.report_dir is None:
            report_dir = run_dir
        else:
            report_dir = Path(args.report_dir)
        parsed = parse_log((run_dir / 'run.log').read_text())
        programs = []
        for case in parsed['cases']:
            words = words_from_record(case['record'])
            programs.append(dict(name=case['record'], detail='from the run log',
                                 style='from-run-log', words=words,
                                 text=record_text(words),
                                 analysis=analyze_program(words)))
        document = verify_run(context, run_dir, programs)
        document['entry_command'] = None
    else:
        if args.output is None:
            parser.error('--output is required unless --run-dir is given')
        output = Path(args.output)
        programs = program_set(context, args.generated, args.generated_words,
                               args.seed)
        entry_log = Path(args.entry_log) if args.entry_log else \
            output.parent / (output.name + '-entry.log')
        command = run_entry(context, programs, output=output, cache=args.cache,
                            max_ticks=args.max_ticks, entry_log=entry_log)
        report_dir = Path(args.report_dir) if args.report_dir else \
            output.parent / (output.name + '-verify')
        document = verify_run(context, output, programs)
        document['entry_command'] = command
        document['entry_log'] = str(entry_log)
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / 'programs.json').write_text(json.dumps(dict(
            schema_version=SCHEMA,
            config=str(context['path']),
            host_contract=document['host_contract'],
            records=[program['text'] for program in programs],
            programs=describe_programs(programs),
        ), indent=2) + '\n')
    paths = write_document(document, report_dir)
    print('status %s: %d/%d cases verified, %d retirement(s), %d writeback(s) '
          'compared' % (document['status'],
                        document['summary']['cases_matched'],
                        document['summary']['cases'],
                        document['summary']['retirements_compared'],
                        document['summary']['writebacks_compared']))
    for row in document['problems']:
        print('problem case %s: %s' % (row['case'], row['problem']))
    print('report: %s' % paths[1])
    return 0 if document['status'] == 'verified' else 1


if __name__ == '__main__':
    raise SystemExit(main())
