#!/usr/bin/env python3
"""Prepare the OBI CPU + APB IRQ spike from existing F5 artifacts."""
import argparse
from hashlib import sha256
import json
from pathlib import Path
import re


def identifier(name):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name):
        raise ValueError('unsupported generated C++ identifier')
    return name


def one(rows, **criteria):
    matches = [row for row in rows if all(row.get(k) == v for k, v in criteria.items())]
    if len(matches) != 1:
        raise ValueError('unsupported or ambiguous artifact role: ' + str(criteria))
    return matches[0]


def render_bindings(config, prefix, cpu, ip, profile):
    if cpu['kind'] != 'obi_cpu' or ip['kind'] != 'apb3_register_observe':
        raise ValueError('unsupported: requires OBI CPU and APB3 register target')
    if ip.get('base_protocol_trace', {}).get('protocol') != 'apb3':
        raise ValueError('unsupported target protocol trace')
    if 'driver_timing' in cpu or 'driver_timing' in ip:
        raise ValueError('unsupported: timed models require a timing scheduler')
    def single_clock(artifact):
        schedule=artifact.get('clock_schedule', {})
        clocks=schedule.get('clocks', [])
        if (len(clocks) != 1 or schedule.get('phase_policy') != 'all_low_then_half_period_toggle'
                or clocks[0].get('signal') != 'clk' or clocks[0].get('ratio') != 1
                or clocks[0].get('first_rising_fast_tick') != 1
                or clocks[0].get('half_period_fast_ticks') != 1
                or type(clocks[0].get('frequency_hz')) is not int or clocks[0]['frequency_hz'] <= 0):
            raise ValueError('unsupported: requires one simple clock per model')
        return clocks[0]['frequency_hz']
    if single_clock(cpu) != single_clock(ip):
        raise ValueError('unsupported: CPU and target clock frequencies differ')
    if not any(row.get('name') == 'probe_irq_taken_pre' and row.get('direction') == 'output'
               for row in cpu.get('runtime_ports', [])):
        raise ValueError('unsupported: CPU IRQ take probe is unavailable')
    if profile['cpu']['xlen'] != 32:
        raise ValueError('unsupported: requires RV32 CPU')
    cpu_irq_row=one(cpu['physical_exports'],endpoint_id=profile['cpu']['irq_entry_endpoint'],
                    role=profile['cpu']['irq_entry_role'],direction='input')
    if cpu_irq_row['width'] != 1:
        raise ValueError('unsupported: requires one-bit CPU IRQ input')
    cpu_irq=cpu_irq_row['runtime_name']
    target_irq=one(ip['physical_exports'],physical_port=config['source_port'],direction='output')
    irq_bit=config['source_bit_offset']
    if target_irq['width'] > 64 or not target_irq['bit_lo'] <= irq_bit <= target_irq['bit_hi']:
        raise ValueError('unsupported target IRQ bit')
    fields={'CPU_IRQ':cpu_irq,'CPU_IRQ_TAKE':'probe_irq_taken_pre','TIMER_IRQ':target_irq['runtime_name']}
    for role in ('valid','trap','insn','pc_rdata'):
        fields['CPU_RVFI_'+role.upper()]=one(cpu['physical_exports'],physical_port='rvfi_'+role,
                                            direction='output')['runtime_name']
    roles=('req_valid','req_ready','req_write','req_addr','req_wdata','req_be',
           'rsp_valid','rsp_ready','rsp_rdata','rsp_error')
    for channel in ('i','d'):
        for role in roles:
            fields['CPU_'+channel.upper()+'_'+role.upper()]=one(cpu['backend_ports'],channel=channel,role=role)['name']
    for role in roles:
        fields['IP_'+role.upper()]=one(ip['backend_ports'],channel='reg',role=role)['name']
    for role in ('psel','penable','pready','pwrite','paddr','pwdata','prdata'):
        fields['IP_TRACE_'+role.upper()]=ip['base_protocol_trace']['signals'][role]
    cpu_model='V'+identifier(cpu['module_name']); ip_model='V'+identifier(ip['module_name'])
    f=prefix['firmware']; window=config['target_window']; triggers=config['trigger_writes']
    if not triggers or len(config['status_offsets']) != 1 or config.get('clear_writes'):
        raise ValueError('unsupported: one status register and no clear writes required')
    lines=['#pragma once',f'#include "{cpu_model}.h"',f'#include "{ip_model}.h"',
           f'#define CPU_MODEL {cpu_model}',f'#define IP_MODEL {ip_model}']
    lines += [f'#define {key} {identifier(value)}' for key,value in fields.items()]
    lines += [f'#define IRQ_BIT {irq_bit-target_irq["bit_lo"]}',f'#define IRQ_WIDTH {config["pulse_width_ticks"]}',
              f'#define RAM_BASE {f["image_start"]}u',f'#define RAM_SIZE {f["image_end"]-f["image_start"]}u',
              f'#define IP_BASE 0x{window["base"]:x}u',f'#define IP_SIZE {window["size"]}u',
              f'#define RESULT_ADDRESS {f["result_address"]}u',f'#define MRET_WORD {f["mret_word"]}u',
              f'#define STATUS_OFFSET {config["status_offsets"][0]}u',f'#define TRIGGER_COUNT {len(triggers)}u']
    mailbox=prefix['program'].get('mailbox')
    lines += [f'#define SUPPORT_ONLINE {int(mailbox is not None)}',
              f'#define MAILBOX_ADDRESS {mailbox if mailbox is not None else 0}u']
    for tag,artifact in (('CPU',cpu),('IP',ip)):
        timing=artifact['plan']['timing']
        lines += [f'#define {tag}_RESET_ASSERT {timing["reset_assert_ticks"]}u',
                  f'#define {tag}_RESET_RELEASE {timing["reset_release_ticks"]}u']
    lines += ['struct Trigger { unsigned offset, value; };',
              'static constexpr Trigger triggers[] = {'+', '.join('{%du, %du}' % tuple(row) for row in triggers)+'};']
    firmware=''.join(f'{int(address):x} {code}\n' for address,code in prefix['program']['images'].items())
    return '\n'.join(lines)+'\n',firmware


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config',type=Path,required=True);p.add_argument('--prefix',type=Path,required=True)
    p.add_argument('--cpu-artifact',type=Path,required=True);p.add_argument('--ip-artifact',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--root',type=Path,default=Path.cwd())
    a=p.parse_args();read=lambda path:json.loads(path.read_text())
    config=read(a.config);prefix=read(a.prefix);cpu=read(a.cpu_artifact);ip=read(a.ip_artifact)
    config_digest=sha256(json.dumps(config,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    if prefix.get('config_sha256') != config_digest:
        raise ValueError('unsupported: firmware prefix differs from selected config')
    request=read(a.root/config['source_request'])
    if cpu['plan']['profile_path'] != config['cpu_profile'] or ip['plan']['profile_path'] != request['profile_path']:
        raise ValueError('unsupported: artifacts differ from selected profiles')
    header,firmware=render_bindings(config,prefix,cpu,ip,read(a.root/config['cpu_profile']))
    a.output.mkdir(parents=True,exist_ok=True)
    (a.output/'spike_config.h').write_text(header);(a.output/'firmware.txt').write_text(firmware)


if __name__ == '__main__': main()
