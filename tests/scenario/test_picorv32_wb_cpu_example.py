"""Software contracts for the extracted directed Wishbone custom0 fixture."""
import hashlib
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from myfuzz.scenario.genome import GenomeCodec
from myfuzz.scenario.picorv32_wb_cpu_example import (
    make_picorv32_wb_gpio_irq_genome,
    make_picorv32_wb_gpio_irq_runner,
    picorv32_wb_gpio_irq_ownership,
)


def test_seed_preserves_the_original_directed_genome_bytes():
    seed = make_picorv32_wb_gpio_irq_genome()
    # Recorded before extraction from the existing real test's GenomeCodec.
    assert hashlib.sha256(GenomeCodec.encode(seed)).hexdigest() == (
        '85fdbe6d66a962d4481b7fa1b4238bde6c4cef56a160c2686e236087bc871632')
    program = seed.initial_images[0].data
    assert int.from_bytes(program[0x10:0x14], 'little') == 0x0000c28b  # getq
    assert int.from_bytes(program[0x44:0x48], 'little') == 0x0603600b  # maskirq
    assert int.from_bytes(program[0x48:0x4c], 'little') == 0x0400000b  # retirq
    assert seed.max_steps == 1300
    assert seed.schedule_order == ('gpio', 'cpu')
    assert make_picorv32_wb_gpio_irq_genome() is not seed


def test_only_external_low_gpio_bits_are_mutable():
    ownership = picorv32_wb_gpio_irq_ownership()
    assert ownership.document() == {
        'fields': [
            {'component_id': 'cpu', 'port': 'irq', 'width': 32},
            {'component_id': 'gpio', 'port': 'gpio_in', 'width': 32},
            {'component_id': 'gpio', 'port': 'strap_en', 'width': 1}],
        'owners': [dict(component_id=c, port=p, bit_offset=o, width=w,
                        kind=k, producer_ref=r) for c, p, o, w, k, r in (
            ('cpu', 'irq', 0, 3, 'fixed', 'constant_zero'),
            ('cpu', 'irq', 3, 1, 'bound', 'gpio.irq'),
            ('cpu', 'irq', 4, 28, 'fixed', 'constant_zero'),
            ('gpio', 'gpio_in', 0, 8, 'source', 'external_gpio_pins'),
            ('gpio', 'gpio_in', 8, 24, 'fixed', 'constant_zero'),
            ('gpio', 'strap_en', 0, 1, 'fixed', 'constant_zero'))]}
    assert ownership.mutation_source('gpio', 'gpio_in', 0, 8,
                                      direction='IP_TO_CPU') == 'external_gpio_pins'
    for port, offset in (('irq', 0), ('irq', 3), ('irq', 31)):
        with pytest.raises(ValueError, match='input cannot be mutated'):
            ownership.mutation_source('cpu', port, offset, 1, direction='IP_TO_CPU')
    for port, offset in (('gpio_in', 8), ('gpio_in', 31), ('strap_en', 0)):
        with pytest.raises(ValueError, match='fixed input cannot be mutated'):
            ownership.mutation_source('gpio', port, offset, 1, direction='IP_TO_CPU')


def test_runner_preserves_routing_and_session_construction(tmp_path):
    # The real integration test exercises artifacts/RTL. This contract isolates
    # assembly so it cannot invoke an elaborator, compiler or simulator.
    module = 'myfuzz.scenario.picorv32_wb_cpu_example'
    cpu_art, gpio_art = object(), object()
    def session(artifact, **kwargs):
        return SimpleNamespace(artifact=artifact, **kwargs)
    with patch(module + '._artifact', side_effect=[cpu_art, gpio_art] * 2) as artifacts, \
         patch(module + '.GeneratedWishboneCpuSession', side_effect=session) as cpus, \
         patch(module + '.GeneratedOpentitanGpioSession', side_effect=session) as gpios, \
         patch('subprocess.Popen', side_effect=AssertionError('no processes')):
        first = make_picorv32_wb_gpio_irq_runner(cache_dir=tmp_path / 'cache')
        second = make_picorv32_wb_gpio_irq_runner(cache_dir=tmp_path / 'cache')
    assert [call.args for call in artifacts.call_args_list] == [
        ('configs/cpus/picorv32_wb_irq/component_profile.json', 'cpu'),
        ('configs/peripherals/opentitan_gpio_local/component_profile.json', 'gpio')] * 2
    cpu, gpio = first.sessions['cpu'], first.sessions['gpio']
    assert cpu.artifact is cpu_art
    assert gpio.artifact is gpio_art
    assert cpu.defer_mmio is True
    assert cpu.memory.initialization_seed == 4
    assert cpu.memory.max_initialized_bytes == 4096
    assert cpu.memory.identity_document()['regions'] == [dict(memory_id='ram', base=0, size=4096, aliases=(), readable=True, writable=True)]
    window, = cpu.router.windows
    assert (window.device_id, window.base, window.size) == ('gpio', 0x40000000, 0x1000)
    assert window.target is gpio
    binding, = first.bindings
    assert (binding.source_component, binding.source_port,
            binding.target_component, binding.target_port,
            binding.width, binding.target_bit_offset) == ('gpio', 'irq', 'cpu', 'irq', 1, 3)
    assert first.ownership.document() == picorv32_wb_gpio_irq_ownership().document()
    assert first._irq_pulses == {}
    for component in ('cpu', 'gpio'):
        assert first.sessions[component] is not second.sessions[component]
        assert first.sessions[component].cache_dir == tmp_path / 'cache'
    assert cpu.memory is not second.sessions['cpu'].memory
    assert cpu.router is not second.sessions['cpu'].router
    assert len(cpus.call_args_list) == len(gpios.call_args_list) == 2


def test_artifact_recipe_preserves_original_reset_and_wait_budget():
    from myfuzz.scenario import picorv32_wb_cpu_example as example
    module = example.__name__
    request, plan, harness, lock, runtime, driver = [object() for _ in range(6)]
    with patch(module + '.load_local_harness_request', return_value=request) as load, \
         patch(module + '.plan_local_harness', return_value=SimpleNamespace(profile=plan)) as planning, \
         patch(module + '.render_local_harness', return_value=harness), \
         patch(module + '.verify_local_source_lock', return_value=lock) as verify, \
         patch(module + '.render_local_runtime', return_value=runtime), \
         patch(module + '.render_local_driver', return_value=driver):
        assert example._artifact(example.CPU_PROFILE, 'cpu') is driver
    load.assert_called_once_with(dict(schema_version='local_harness.v1',
        profile_path=example.CPU_PROFILE, instance_id='cpu', reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16))
    planning.assert_called_once_with(request, base_dir=example.ROOT)
    verify.assert_called_once_with(plan, base_dir=example.ROOT)
