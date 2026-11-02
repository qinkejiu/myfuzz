#!/usr/bin/env python3
"""Every checked-in CPU profile as a capability row for the unified F1-F6 entry.

The matrix is derived from the *generated artifact* of each profile (the same
renderer the entry uses) plus the profile's own CPU declaration, so the exported
retirement/trap fields, the interrupt entry and the declared clock are read from
the model that would really be built.  A profile the renderer refuses is kept in
the matrix as that exact refusal; it is never dropped and never given a zero for
a signal it does not export.

Each flow cell is one of:

* ``runnable`` - the unified entry builds this CPU and the flow's own gate admits
  it (the target/DMA half of the gate is stated separately by the scenario);
* ``refused:<name>`` - a named refusal the entry would produce.  These are the
  same strings the entry and its header raise, imported from the entry module
  rather than re-spelled here;
* ``unknown`` - no artifact could be read, so nothing is claimed.

Command:

    PYTHONPATH=src:. python3 scripts/cpu_capability_matrix.py \
        --markdown docs/cpu-capability-matrix.md --json /tmp/matrix.json
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT))

from scripts.run_inprocess_f1f6 import (  # noqa: E402
    AHB_F1_REFUSAL, AHB_F5_REFUSAL, AXI4_F1_REFUSAL, AXI4_F5_REFUSAL,
    axi4_rvfi_probe_export, cpu_bus, cpu_irq_take_witness, cpu_irq_width,
    cpu_rvfi_trap_port, model_clock_rate)

#: The interrupt facts a profile states for its own entry, or None.
IRQ_FACTS = ('irq_entry_endpoint', 'irq_entry_role', 'irq_entry_polarity',
             'irq_semantics')


def _artifact(root, profile_path, quiet=True):
    """Render the profile's generated CPU artifact, or return its refusal."""
    from myfuzz.composition.component_profile import elaboration_mode_scope
    from myfuzz.local_harness.build import (harness_validation_scope,
                                            host_source_discovery_scope)
    from myfuzz.local_harness.execution_validation import execution_validation_scope
    from scripts.run_inprocess_f1f4 import cpu_request_from_config
    from scripts.run_timer_irq_smoke import timer_artifact
    output = root / 'runs' / 'p1-timing' / '_scratch' / 'matrix' / profile_path.parent.name
    output.mkdir(parents=True, exist_ok=True)
    request = output / 'cpu_request.json'
    request.write_text(json.dumps(cpu_request_from_config({
        'cpu_profile': str(profile_path.relative_to(root)),
        'cpu_timing': {'reset_assert_ticks': 8, 'reset_release_ticks': 8,
                       'max_wait_cycles': 16}}), indent=2) + '\n')
    try:
        with elaboration_mode_scope('direct'), \
                host_source_discovery_scope(reuse_nested=True), \
                harness_validation_scope(), execution_validation_scope():
            return timer_artifact(root, str(request), 'cpu'), None
    except Exception as error:  # the refusal is the capability fact
        return None, str(error)


def _exports(document):
    """The exported physical port names, as a set, plus the RVFI role map."""
    ports = {row.get('physical_port') for row in document.get('physical_exports', [])
             if isinstance(row.get('physical_port'), str)}
    return ports


def _retirement(document, bus):
    """What retirement face the artifact exports, stated by role."""
    if bus == 'ahb':
        return dict(face='none', fields=[], witness='none')
    if bus == 'axi4':
        bundle = axi4_rvfi_probe_export(document)
        if bundle is None:
            return dict(face='none', fields=[], witness='none')
        return dict(face='rvfi_probe_bundle:' + bundle['runtime_name'],
                    fields=['valid', 'order', 'insn', 'pc_rdata', 'trap',
                            'cause', 'intr', 'mode', 'rd_addr', 'rd_wdata'],
                    witness='rvfi_intr')
    ports = _exports(document)
    fields = [role for role in ('valid', 'order', 'insn', 'pc_rdata') if 'rvfi_' + role in ports]
    if 'valid' not in fields:
        return dict(face='none', fields=[], witness='none')
    if 'rvfi_trap' in ports:
        fields.append('trap')
    if 'rvfi_intr' in ports:
        fields.append('intr')
    if {'rvfi_rd_addr', 'rvfi_rd_wdata'} <= ports:
        fields += ['rd_addr', 'rd_wdata']
    if 'rvfi_ext_expanded_insn_valid' in ports:
        fields.append('expanded_valid')
    return dict(face='rvfi_ports', fields=fields,
                witness='rvfi_intr' if 'rvfi_intr' in ports else 'none')


def _trap(document, bus, retirement):
    if bus == 'ahb':
        return 'none'
    if bus == 'axi4':
        spots = [row for row in document.get('physical_exports', [])
                 if row.get('physical_port') == 'rvfi_probes_o']
        return 'adapter_scoreboard:rvfi_trap+cause+intr+mode+csr' if spots else 'none'
    return 'rvfi_trap' if 'trap' in retirement['fields'] else 'none'


def _irq(profile, document, bus):
    cpu = getattr(profile, 'cpu', None)
    facts = {key: getattr(cpu, key, None) for key in IRQ_FACTS} if cpu is not None else {}
    if not any(facts.values()):
        return dict(entry=None, role=None, polarity=None, semantics=None,
                    width=None, stated_as='none_declared')
    width = None
    if bus != 'ahb':
        try:
            width = cpu_irq_width(document)
        except Exception:
            width = None
    role = facts['irq_entry_role']
    semantics = facts['irq_semantics'] or ('custom_eoi_vector' if role == 'custom' else None)
    return dict(entry=facts['irq_entry_endpoint'], role=role,
                polarity=facts['irq_entry_polarity'],
                semantics=semantics, width=width,
                stated_as='profile_cpu_contract')


def _timing(document):
    try:
        hz = model_clock_rate(document, 'cpu')
    except Exception as error:
        return dict(declared_hz=None, mode='unknown', error=str(error))
    contract = document.get('driver_timing')
    half = contract.get('half_period_ps') if isinstance(contract, dict) else None
    return dict(declared_hz=hz,
                mode='timed' if half is not None else 'untimed',
                timed_half_period_ps=half)


def _flows(bus, retirement, witness, artifact_refusal, irq=None):
    """F1-F6 as runnable / refused:<exact contract> / unknown."""
    if artifact_refusal is not None:
        return {flow: 'refused:' + artifact_refusal
                for flow in ('F1', 'F2', 'F3', 'F4', 'F5', 'F6')}
    if isinstance(bus, str) and bus.startswith('refused:'):
        reason = bus[len('refused:'):]
        return {flow: 'refused:' + reason
                for flow in ('F1', 'F2', 'F3', 'F4', 'F5', 'F6')}
    if bus not in ('obi', 'wishbone', 'ahb', 'axi4'):
        return {flow: 'refused:' + str(bus)
                for flow in ('F1', 'F2', 'F3', 'F4', 'F5', 'F6')}
    if bus in ('obi', 'wishbone') and retirement['face'] == 'none':
        # The generated OBI/Wishbone host always compiles the F1 retirement
        # trace against the CPU model's rvfi_* ports, so a model without that
        # face does not build at all.  This is a build-time refusal for every
        # flow, not only F1, and the matrix states it once.
        reason = ('unsupported: F1 needs the CPU rvfi_* retirement probe '
                  '(no rvfi_valid output)')
        return {flow: 'refused:' + reason for flow in ('F1', 'F2', 'F3', 'F4', 'F5', 'F6')}
    flows = {}
    if retirement['face'] == 'none':
        if bus == 'ahb':
            flows['F1'] = 'refused:' + AHB_F1_REFUSAL
        elif bus == 'axi4':
            flows['F1'] = 'refused:' + AXI4_F1_REFUSAL
        else:
            flows['F1'] = ('refused:unsupported: F1 needs the CPU rvfi_* retirement '
                           'probe (no rvfi_valid output)')
    else:
        flows['F1'] = 'runnable'
    flows['F2'] = flows['F3'] = flows['F4'] = 'runnable'
    if bus == 'ahb':
        flows['F5'] = 'refused:' + AHB_F5_REFUSAL
    elif bus == 'axi4':
        flows['F5'] = 'refused:' + AXI4_F5_REFUSAL
    elif bus == 'wishbone':
        width = None if not isinstance(irq, dict) else irq.get('width')
        flows['F5'] = ('refused:unsupported-f5:cpu-irq-unwired:wishbone:'
                       + str(width if width is not None else 'multi')
                       + '-bit-irq-held-at-zero')
    elif witness is None:
        flows['F5'] = ('refused:unsupported-f5:cpu-take-witness-unexported:'
                       + bus + ':needs-one-of:probe_irq_taken_pre,custom_eoi,rvfi_intr')
    else:
        flows['F5'] = 'runnable'
    if bus != 'obi':
        if bus == 'wishbone':
            flows['F6'] = ('refused:unsupported-f6:cpu-dma-port-unexported:wishbone:'
                           'no-custom-irq-bit-declared')
        else:
            flows['F6'] = 'refused:unsupported-f6:cpu-dma-port-unexported:' + bus
    elif witness is None:
        flows['F6'] = ('refused:unsupported-f6:cpu-take-witness-unexported:'
                       + bus + ':needs-one-of:probe_irq_taken_pre,custom_eoi,rvfi_intr')
    else:
        flows['F6'] = 'runnable'
    return flows


def capability_row(root, profile_path, *, artifact=None, refusal=None):
    """One CPU capability row, from the profile plus its generated artifact."""
    from myfuzz.composition.component_profile import load_component_profile
    profile_path = Path(profile_path)
    profile = load_component_profile(root / profile_path)
    if artifact is None and refusal is None:
        artifact, refusal = _artifact(root, profile_path)
    row = dict(profile=str(profile_path.relative_to(root)),
               declared_kind=profile.kind,
               xlen=getattr(getattr(profile, 'cpu', None), 'xlen', None))
    if refusal is not None or artifact is None:
        row.update(bus='refused', retirement=dict(face='unknown', fields=[],
                                                  witness='unknown'),
                   trap='unknown', irq=dict(stated_as='unknown', width=None),
                   timing=dict(declared_hz=None, mode='unknown'),
                   artifact='refused:' + str(refusal),
                   flows=_flows(None, None, None, str(refusal)),
                   row_status='refused')
        return row
    document = artifact.runtime_document
    try:
        bus = cpu_bus(document)
    except Exception as error:
        bus = 'refused:' + str(error)
    row['bus'] = bus
    row['artifact'] = dict(module=document.get('module_name'),
                           clock_schedule=document.get('clock_schedule', {}))
    if bus not in ('obi', 'wishbone', 'ahb', 'axi4'):
        row.update(retirement=dict(face='unknown', fields=[], witness='unknown'),
                   trap='unknown', irq=dict(stated_as='unknown', width=None),
                   timing=_timing(document),
                   flows=_flows(bus, None, None, None),
                   row_status='refused')
        return row
    retirement = _retirement(document, bus)
    witness, _ = cpu_irq_take_witness(document)
    irq = _irq(profile, document, bus)
    row.update(bus=bus, retirement=retirement,
               trap=_trap(document, bus, retirement),
               irq=irq,
               timing=_timing(document),
               flows=_flows(bus, retirement, witness, None, irq),
               row_status='built')
    return row


def matrix(root):
    """Every checked-in CPU profile's capability row, ordered by path."""
    rows = []
    for path in sorted((root / 'configs' / 'cpus').glob('*/component_profile.json')):
        rows.append(capability_row(root, path))
    return rows


def render_markdown(rows):
    def word(value, empty='unknown'):
        if value is None or value == '' or value == []:
            return empty
        if isinstance(value, (list, tuple)):
            return ','.join(str(item) for item in value)
        return str(value)

    lines = [
        '# CPU capability matrix (unified F1-F6 entry)',
        '',
        'Generated by `scripts/cpu_capability_matrix.py` from every checked-in',
        '`configs/cpus/*/component_profile.json` and the generated artifact the',
        'unified entry would link.  A refusal is kept as its exact name; a field a',
        'model does not export is `unknown`/`none`, never a zero.',
        '',
        '## Retirement and trap face',
        '',
        '| profile | bus | xlen | retirement face | RVFI fields | trap face | IRQ entry | IRQ width | IRQ semantics | clock | timing |',
        '|---|---|---|---|---|---|---|---|---|---|---|',
    ]
    for row in rows:
        retirement = row.get('retirement') or {}
        irq = row.get('irq') or {}
        timing = row.get('timing') or {}
        clock = timing.get('declared_hz')
        entry = irq.get('entry')
        lines.append('| `%s` | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |' % (
            row['profile'], word(row.get('bus')),
            word(row.get('xlen')),
            word(retirement.get('face'), 'unknown'),
            word(retirement.get('fields'), '(none)'),
            word(row.get('trap'), 'unknown'),
            word(entry, 'none'),
            word(irq.get('width'), 'unknown' if entry else 'none'),
            word(irq.get('semantics'), 'none'),
            ('%s Hz' % clock) if clock else 'unknown',
            ('timed, %s ps half period' % timing['timed_half_period_ps']
             if timing.get('timed_half_period_ps') else
             word(timing.get('mode'), 'unknown'))))
    lines += [
        '',
        '## Flows the unified entry can actually run',
        '',
        '`runnable` means the entry builds this CPU and the flow gate admits it;',
        'whether a scenario has a compatible target/DMA for that flow is a separate',
        'declaration fact.  `refused:<name>` is the exact refusal the entry raises.',
        '',
        '| profile | F1 | F2 | F3 | F4 | F5 | F6 | row |',
        '|---|---|---|---|---|---|---|---|',
    ]
    for row in rows:
        flows = row.get('flows') or {}
        lines.append('| `%s` | %s | %s | %s | %s | %s | %s | %s |' % (
            row['profile'], flows.get('F1', 'unknown'), flows.get('F2', 'unknown'),
            flows.get('F3', 'unknown'), flows.get('F4', 'unknown'),
            flows.get('F5', 'unknown'), flows.get('F6', 'unknown'),
            row.get('row_status', 'unknown')))
    lines += [
        '',
        '## How to read a refusal',
        '',
        '* `unsupported: F1 needs the CPU rvfi_* retirement probe (...)` - the model',
        '  exports no `rvfi_valid` retirement face, so the host cannot produce the F1',
        '  trace.  The refusal is the build-time contract; no fetch count is used.',
        '* `unsupported-f1:no-retirement-observation:ahb_cvw` - the AHB boundary has no',
        '  RVFI/commit channel at all.',
        '* `unsupported-f5:cpu-irq-unexported:ahb_cvw` - the AHB boundary exports no',
        '  interrupt input.',
        '* `unsupported-f5:cpu-irq-unwired:wishbone:<n>-bit-irq-held-at-zero` - a',
        '  Wishbone build without a declared custom IRQ bit.',
        '* `unsupported-f5:cpu-take-witness-unexported:<bus>:...` /',
        '  `unsupported-f6:cpu-take-witness-unexported:<bus>:...` - the CPU exports',
        '  neither `probe_irq_taken_pre`, nor a custom EOI vector, nor `rvfi_intr`;',
        '  the flows are refused instead of counting a bus access as a take.',
        '* `unsupported-f6:cpu-dma-port-unexported:<bus>` - this CPU bus has no DMA',
        '  port in the unified entry.',
        '* `unsupported-cpu-kind:<kind>` / `full-top-required` / source-lock or',
        '  elaboration refusals - the profile does not produce a model this entry can',
        '  link; F1-F6 are all `refused:<that exact refusal>`.',
    ]
    return '\n'.join(lines) + '\n'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--markdown', type=Path, default=None)
    parser.add_argument('--json', type=Path, default=None)
    parser.add_argument('--check', action='store_true',
                        help='fail when the checked-in markdown differs from this run')
    args = parser.parse_args(argv)
    rows = matrix(ROOT)
    markdown = render_markdown(rows)
    if args.markdown is not None:
        if args.check:
            current = args.markdown.read_text() if args.markdown.is_file() else ''
            if current != markdown:
                print('stale: ' + str(args.markdown))
                return 1
            print('current: ' + str(args.markdown))
            return 0
        args.markdown.write_text(markdown)
        print('wrote ' + str(args.markdown))
    if args.json is not None:
        args.json.write_text(json.dumps(rows, indent=2, sort_keys=True) + '\n')
        print('wrote ' + str(args.json))
    if args.markdown is None and args.json is None:
        print(markdown)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
