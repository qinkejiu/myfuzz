"""Opt-in machine-external IRQ wiring and passive source-proven probe contract.

Paths are required candidates from authenticated RTL instance connections. They
become confirmed generated symbols only after actual native VPI enumeration.
"""
from collections.abc import Mapping
from copy import deepcopy
import json

MEIP = 'auto_int_local_in_2_0'
PROBES = {
    'meip': ('TOP.BoomTile.core.csr_io_interrupts_meip', 1),
    'rob_exception': ('TOP.BoomTile.core.rob_io_com_xcpt_valid', 1),
    'rob_cause': ('TOP.BoomTile.core.rob_io_com_xcpt_bits_cause', 64),
    'csr_exception': ('TOP.BoomTile.core.csr_io_exception', 1),
    'csr_cause': ('TOP.BoomTile.core.csr_io_cause', 64),
    'csr_pc': ('TOP.BoomTile.core.csr_io_pc', 40),
    'csr_evec': ('TOP.BoomTile.core.csr_io_evec', 40),
    'mie': ('TOP.BoomTile.core.csr.reg_mie', 64),
    'global_mie': ('TOP.BoomTile.core.csr.reg_mstatus_mie', 1),
    'privilege': ('TOP.BoomTile.core.csr.reg_mstatus_prv', 2),
    'mtvec': ('TOP.BoomTile.core.csr.reg_mtvec', 32),
    'mcause': ('TOP.BoomTile.core.csr.reg_mcause', 64),
    'mepc': ('TOP.BoomTile.core.csr.reg_mepc', 40),
    'system_return': ('TOP.BoomTile.core.csr.insn_ret', 1),
    'csr_addr': ('TOP.BoomTile.core.csr.io_rw_addr', 12),
    'csr_cmd': ('TOP.BoomTile.core.csr.io_rw_cmd', 3),
}


def irq_profile(baseline):
    result = deepcopy(baseline)
    result['component_id'] = 'boom_irq'
    result['description'] = 'Opt-in derived BOOM machine-external IRQ; runtime verification required.'
    result['port_actions'] = [row for row in result['port_actions'] if row['port'] != MEIP]
    result['endpoints'].append({'endpoint_id':'processor.interrupts', 'function':'interrupt_entry',
        'fields':[{'role':'machine_external','aliases':[MEIP],'direction':'input','width':1}]})
    result['cpu'].update(irq_entry_endpoint='processor.interrupts',
        irq_entry_role='machine_external', irq_entry_polarity='active_high',
        irq_semantics='machine_external')
    result['evidence']['runtime_kind'] = 'tilelink_coherent_cpu_irq'
    return result


def validate_irq_profile(document, baseline):
    if json.dumps(document,sort_keys=True) != json.dumps(irq_profile(baseline),sort_keys=True):
        raise ValueError('BOOM IRQ variant must be exact declared baseline delta')
    actions = {row['port']:row for row in baseline['port_actions']}
    for name in (MEIP,'auto_int_local_in_0_0','auto_int_local_in_1_0',
                 'auto_int_local_in_1_1','auto_int_local_in_3_0'):
        if actions.get(name,{}).get('action') != 'constant' or actions[name].get('value') != 0:
            raise ValueError('BOOM baseline IRQ constant contract changed')
    bus, irq = document['endpoints']
    if bus['endpoint_id'] != 'cpu.coherent_memory' or len(bus['fields']) != 39:
        raise ValueError('BOOM coherent bus mapping incomplete')
    return document


def validate_irq_inputs(inputs):
    if not isinstance(inputs, Mapping) or set(inputs) != {'irq'}:
        raise ValueError('BOOM IRQ step requires exactly one bound irq input')
    if type(inputs['irq']) is not int or inputs['irq'] not in (0,1):
        raise ValueError('BOOM IRQ must be an integer bit')
    return inputs['irq']


def validate_probe_inventory(rows):
    expected = [{'id':key,'path':path,'width':width} for key,(path,width) in PROBES.items()]
    if (not isinstance(rows,list) or rows != expected
            or any(type(row.get('width')) is not int for row in rows)):
        raise ValueError('BOOM actual generated VPI name/width inventory mismatch')


def validate_probe_values(row):
    if not isinstance(row,dict) or set(row) != set(PROBES):
        raise ValueError('BOOM passive probe set mismatch')
    for key,(_,width) in PROBES.items():
        if type(row[key]) is not int or not 0 <= row[key] < 1 << width:
            raise ValueError('BOOM passive probe width mismatch: '+key)


def observed_mret(row):
    return (all(type(row.get(key)) is int for key in ('system_return','csr_cmd','csr_addr'))
            and row.get('system_return') == 1 and row.get('csr_cmd') == 4
            and row.get('csr_addr') == 0x302)
