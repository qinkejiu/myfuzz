"""F5 delivery must select a real vector bit, never invent a binding."""
from types import SimpleNamespace as NS
import pytest
from myfuzz.scenario import compiled_paths as cp
from myfuzz.scenario import compiled_ownership as co


def ends(bit, *, width=32, field_low=0):
    field = NS(role='irq', aliases=('irq_i',), bit_range=(field_low, field_low+width-1), width=width)
    endpoint = NS(fields=(field,))
    contract = NS(irq_entry_role='irq')
    cpu = NS(profile=NS(cpu=contract), endpoints_with_function=lambda f:(endpoint,))
    producer_endpoint = object()
    producer = NS(endpoint=lambda name:producer_endpoint)
    delivery = cp.WiringDelivery('d','gpio','src','irq','cpu','dst','pulse','test',consumer_bit_offset=bit)
    return NS(flow_id='F5', delivery=delivery), cpu, producer, producer_endpoint


def test_vector_delivery_selects_declared_physical_bit(monkeypatch):
    assessment,cpu,producer,endpoint=ends(9)
    monkeypatch.setattr(cp,'_selected_interrupt_shape',lambda *args: object())
    monkeypatch.setattr(cp,'_interrupt_source_physical',lambda *args: ('gpio_irq',0))
    result=cp._interrupt_physical_ends(assessment,cpu,producer)
    assert result[1] == ('F5.cpu_irq_entry','irq_i',9)


def test_missing_or_out_of_range_vector_bit_does_not_create_edge(monkeypatch):
    monkeypatch.setattr(cp,'_selected_interrupt_shape',lambda *args: object())
    monkeypatch.setattr(cp,'_interrupt_source_physical',lambda *args: ('gpio_irq',0))
    for bit in (None,32):
        assert cp._interrupt_physical_ends(*ends(bit)[:3]) is None


def test_vector_ownership_maps_declared_dut_bit_to_abi_local_bit():
    field=NS(role='irq', aliases=('irq_i',))
    endpoint=NS(endpoint_id='interrupts', fields=(field,))
    profile=NS(cpu=NS(irq_entry_endpoint='interrupts',irq_entry_role='irq'), endpoints=(endpoint,))
    artifact=NS(plan=NS(profile=profile))
    surface={('cpu','irq_i'):co._Input('cpu','interrupts','irq_i','irq',8,((8,15),))}
    row={'component_id':'cpu','endpoint_id':'interrupts','input_id':'cpu.irq',
         'producer_input_id':'gpio.irq','consumer_bit_offset':9}
    producer, actual_field, local=co._cpu_irq_input(row,surface,{'cpu':artifact})
    assert (producer,actual_field,local)==('gpio.irq',surface[('cpu','irq_i')],1)
    with pytest.raises(co.CompiledOwnershipRefused):
        co._cpu_irq_input({**row,'consumer_bit_offset':7},surface,{'cpu':artifact})
    with pytest.raises(co.CompiledOwnershipRefused):
        co._cpu_irq_input({k:v for k,v in row.items() if k!='consumer_bit_offset'},surface,{'cpu':artifact})


def test_delivery_parser_and_supplement_preserve_explicit_bit():
    row={'delivery_id':'gpio-irq','producer_instance':'gpio','consumer_instance':'cpu',
         'consumer_bit_offset':9}
    delivery=cp._wiring_delivery(row,'/delivery','test')
    assert delivery.consumer_bit_offset == 9
    with pytest.raises(cp.PathCompilationError):
        cp._wiring_delivery({**row,'consumer_bit_offset':-1},'/delivery','test')
    with pytest.raises(cp.PathCompilationError):
        cp._wiring_delivery({**row,'consumer_bit_offset':True},'/delivery','test')


def test_shared_vector_bit_is_not_claimed_as_independent_direct_delivery():
    from dataclasses import replace
    from tests.scenario.test_compiled_paths import probe_device, probe_wiring, real_cpu_component
    device = probe_device('probe_a', irq=True)
    wiring = probe_wiring((device,))
    first = replace(wiring.deliveries[0], consumer_bit_offset=9)
    second = replace(first, delivery_id='other', producer_instance='other')
    wiring = replace(wiring, deliveries=(first,second))
    request=cp.PathCompileRequest(real_cpu_component(),(device,),wiring,{},'processor.data','processor.instruction')
    with pytest.raises(cp.PathCompilationError, match='interrupt-delivery-bit-conflict'):
        cp.compile_paths(request)
