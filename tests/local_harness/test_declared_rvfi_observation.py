from types import SimpleNamespace as NS
import pytest
from myfuzz.local_harness.cpu_session import declared_rvfi_fields


def artifact(widths):
    return NS(plan=NS(profile=NS(port_actions=tuple(NS(port=n,action='observe') for n in widths)),
        facts=NS(ports=tuple(NS(name=n,direction='output',width=w) for n,w in widths.items()))),
        runtime_document={'physical_exports':[dict(physical_port=n,runtime_name='wire_'+n,
            direction='output',width=w,bit_lo=0) for n,w in widths.items()]})


def test_observation_uses_actual_declarations_not_cpu_model():
    widths={'rvfi_valid':1,'rvfi_order':64,'rvfi_insn':32,'rvfi_pc_rdata':32,'rvfi_ext_mip':32}
    assert declared_rvfi_fields(artifact(widths))==widths


def test_partial_rvfi_is_not_retirement_and_bad_export_refuses():
    assert declared_rvfi_fields(artifact({'rvfi_intr':1}))=={}
    actual=artifact({'rvfi_valid':1,'rvfi_order':64,'rvfi_insn':32,'rvfi_pc_rdata':32})
    actual.runtime_document['physical_exports'][1]['width']=32
    with pytest.raises(ValueError):declared_rvfi_fields(actual)


def test_retirement_keeps_only_declared_fields_and_does_not_invent_irq_serial():
    from tests.local_harness.test_cpu_session import GeneratedCpuSessionTests
    fixture=GeneratedCpuSessionTests();fixture.setUp()
    cpu=fixture.cpu
    widths={'rvfi_valid':1,'rvfi_order':64,'rvfi_insn':32,'rvfi_pc_rdata':32,'rvfi_mem_wdata':32}
    cpu._rvfi_contract={'schema_version':'rvfi_observation.v1','sampling_edge':'post_rising','fields':widths}
    cpu._rvfi_enabled=True
    physical=dict(rvfi_valid=1,rvfi_order=0,rvfi_insn=0x13,rvfi_pc_rdata=0x10000,
        rvfi_mem_wdata=42,rvfi_undeclared=99)
    cpu._retire(physical)
    event=cpu.cpu_events[-1]
    assert event['mem_wdata']==42 and 'undeclared' not in event
    assert 'irq_serial_observation' not in event
    assert 'observation_contract' not in event and 'schema_version' not in event
    cpu._retire(physical)
    assert len(cpu.cpu_events)==1
    from myfuzz.scenario.contracts import ProtocolEnvironmentError
    with pytest.raises(ProtocolEnvironmentError):cpu._retire({**physical,'rvfi_order':-1})
