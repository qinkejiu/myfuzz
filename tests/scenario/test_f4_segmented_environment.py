"""An explicit pin slice is meaningful independently of IRQ delivery."""
from dataclasses import replace
import pytest
from tests.scenario.test_compiled_paths import load_request,SOC_RENDER_REQUEST,ROOT,path_of
from myfuzz.scenario.compiled_paths import load_path_compile_request,compile_paths,WiringEnvironmentLink


def request(*,irq=False,segments=((3,1),)):
    original=load_path_compile_request(load_request(SOC_RENDER_REQUEST),base_dir=ROOT)
    # The old fixture derives its physical width from a whole-port link. Give
    # this pure fixture an explicit physical capacity before declaring slices.
    devices=[]
    for device in original.devices:
        endpoints=tuple(replace(e,fields=tuple(replace(f,width=8) if e.endpoint_id=='gpio.pins' and f.role=='in' else f for f in e.fields)) for e in device.profile.endpoints)
        devices.append(replace(device,profile=replace(device.profile,endpoints=endpoints)))
    original=replace(original,devices=tuple(devices))
    link=replace(original.wiring.environment_links[0],endpoint_id='gpio.pins')
    links=tuple(replace(link,link_id='pin'+str(i),bit_offset=offset,width=width) for i,(offset,width) in enumerate(segments))
    return replace(original,wiring=replace(original.wiring,environment_links=links,
        deliveries=original.wiring.deliveries if irq else ()))


@pytest.mark.parametrize('irq',[False,True])
def test_segmented_F4_source_keeps_actual_slice_and_honest_name(irq):
    path=path_of(compile_paths(request(irq=irq)),'F4')
    pin,=[r for r in path['sources'] if r['kind']=='external_pin']
    assert path['status']=='executable'
    assert (pin['bit_offset'],pin['width'],pin['mask'])==(3,1,1)
    assert pin['source_id'].endswith('.irq_event' if irq else '.external')


def test_two_explicit_segments_are_ambiguous_in_current_single_source_F4():
    path=path_of(compile_paths(request(segments=((2,1),(3,1)))),'F4')
    assert path['status']=='unsupported'
    assert path['reason']['code']=='external-pin-source-ambiguous'
