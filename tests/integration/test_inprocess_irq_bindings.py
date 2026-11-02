import copy
import pytest
from scripts.prepare_inprocess_irq_bindings import render_bindings


def artifact(kind, module, ports, exports, trace=None):
    return dict(kind=kind, module_name=module, backend_ports=ports, physical_exports=exports,
                runtime_ports=[dict(name='probe_irq_taken_pre', direction='output', width=1)],
                clock_schedule=dict(phase_policy='all_low_then_half_period_toggle',
                                    clocks=[dict(signal='clk',frequency_hz=50000000,ratio=1,
                                                 first_rising_fast_tick=1,half_period_fast_ticks=1)]),
                plan=dict(timing=dict(reset_assert_ticks=2, reset_release_ticks=3)),
                base_protocol_trace=trace)


def sample():
    roles = ('req_valid','req_ready','req_write','req_addr','req_wdata','req_be',
             'rsp_valid','rsp_ready','rsp_rdata','rsp_error')
    cpuports=[dict(channel=channel,role=role,name=channel+'_'+role) for channel in ('i','d') for role in roles]
    ipports=[dict(channel='reg',role=role,name='reg_'+role) for role in roles]
    exports=[dict(physical_port=n,runtime_name='field_'+n,direction='output',width=1)
             for n in ('rvfi_valid','rvfi_trap','rvfi_insn','rvfi_pc_rdata')]
    exports.append(dict(endpoint_id='processor.interrupts',role='external',runtime_name='cpu_irq',direction='input',width=1))
    signals={role:'apb_'+role for role in ('psel','penable','pready','pwrite','paddr','pwdata','prdata')}
    cpu=artifact('obi_cpu','local_runtime_cpu',cpuports,exports)
    ip=artifact('apb3_register_observe','local_runtime_ip',ipports,
                [dict(physical_port='irq_o',runtime_name='timer_irq',direction='output',width=4,bit_lo=0,bit_hi=3)],
                dict(protocol='apb3',signals=signals))
    config=dict(source_port='irq_o',source_bit_offset=1,pulse_width_ticks=7,
                target_window=dict(base=0x40001000,size=4096),trigger_writes=[[4,9]],status_offsets=[0])
    prefix=dict(firmware=dict(image_start=0x10000,image_end=0x30000,result_address=0x10c40,mret_word=0x30200073),
                program=dict(images={'65664':'13000000'}))
    profile=dict(cpu=dict(xlen=32,irq_entry_endpoint='processor.interrupts',irq_entry_role='external'))
    return config,prefix,cpu,ip,profile


def test_profile_roles_and_scenario_values_generate_bindings():
    config,prefix,cpu,ip,profile=sample()
    header,firmware=render_bindings(config,prefix,cpu,ip,profile)
    assert '#define CPU_IRQ cpu_irq' in header
    assert '#define TIMER_IRQ timer_irq' in header
    assert '#define IRQ_BIT 1' in header and '#define IRQ_WIDTH 7' in header
    assert '0x40001000u' in header and '{4u, 9u}' in header
    assert firmware == '10080 13000000\n'


def test_unsupported_protocol_or_missing_irq_probe_is_explicit():
    config,prefix,cpu,ip,profile=sample()
    broken=copy.deepcopy(ip); broken['kind']='wishbone_register_observe'
    with pytest.raises(ValueError,match='unsupported'):
        render_bindings(config,prefix,cpu,broken,profile)
    cpu['runtime_ports']=[]
    with pytest.raises(ValueError,match='IRQ take'):
        render_bindings(config,prefix,cpu,ip,profile)


def test_rejects_mismatched_or_multiple_clocks_and_timed_models():
    config,prefix,cpu,ip,profile=sample()
    ip['clock_schedule']['clocks'][0]['frequency_hz']=25000000
    with pytest.raises(ValueError,match='clock'):
        render_bindings(config,prefix,cpu,ip,profile)
    config,prefix,cpu,ip,profile=sample()
    ip['clock_schedule']['clocks'].append(dict(ip['clock_schedule']['clocks'][0]))
    with pytest.raises(ValueError,match='clock'):
        render_bindings(config,prefix,cpu,ip,profile)
    config,prefix,cpu,ip,profile=sample()
    cpu['driver_timing']={'mode':'timing'}
    with pytest.raises(ValueError,match='timing'):
        render_bindings(config,prefix,cpu,ip,profile)
