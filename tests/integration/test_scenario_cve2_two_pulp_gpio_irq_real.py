"""Persistent bidirectional IRQ acceptance for three generated RTL sessions."""
from pathlib import Path
import os
import unittest

ROOT = Path(__file__).resolve().parents[2]


class IrqFirmwareFixtureTests(unittest.TestCase):
    def test_fixture_declares_real_isr_and_two_rounds(self):
        fixture = ROOT / 'examples/generated_local_irq/bidirectional.S'
        self.assertTrue(fixture.is_file(), 'missing bidirectional IRQ firmware fixture')
        text = fixture.read_text()
        for evidence in ('csrw mtvec', 'csrw mie', 'mret', 'lw t0, 0x24(s1)',
                         'lw t1, 0x08(s1)', 'sw t3, 0x0c(s0)', 'li t0, 0x81',
                         'li t0, 0x82'):
            self.assertIn(evidence, text)

@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned RTL')
class BidirectionalIrqRealTests(unittest.TestCase):
    def test_two_rounds_each_direction_persist_and_replay(self):
        import tempfile
        with tempfile.TemporaryDirectory(prefix='myfuzz-bidirectional-') as directory:
            factory, instances, case = make_case(Path(directory))
            from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
            bundle = Path(directory) / 'evidence'
            from myfuzz.scenario.contracts import ResourceBudget
            budget = ResourceBudget(max_wall_time_ms=180000,
                                    max_materialized_bytes_per_memory=0x20000)
            trace = save_evidence_bundle(case, factory, bundle, budget=budget)
            self.assertEqual('complete', trace.status)
            runner = instances[0]
            memory = runner.sessions['cpu'].memory
            def word(offset):
                return memory.read(0x20000 + offset, 4, transaction_id=f'accept-{offset}').value
            self.assertEqual(4, word(4), f'ISR count; final state {word(0)}')
            self.assertEqual(15, word(0))
            self.assertEqual([0x80, 0x80, 0x8000, 0x8000], [word(32 + 4*i) for i in range(4)])
            self.assertEqual([6, 8, 11, 15], [word(96 + 4*i) for i in range(4)])
            self.assertEqual([1, 2, 3, 4], [(word(64 + 4*i) >> (8 if i >= 2 else 0)) & 0x7f for i in range(4)])
            pulses = [e for e in trace.events if e.get('kind') == 'pulse_start']
            self.assertEqual(4, len(pulses))
            cpu_steps = [e for e in trace.events if 'kind' not in e and e.get('component') == 'cpu']
            for pulse in pulses:
                start, end = pulse['start_cpu_tick'], pulse['end_cpu_tick_exclusive']
                self.assertEqual(4, end - start)
                delivered = [e for e in cpu_steps if start <= e['local_tick'] < end]
                self.assertEqual(list(range(start, end)), [e['local_tick'] for e in delivered])
                self.assertEqual([1] * 4, [e['inputs']['irq'] for e in delivered])
            entered = [e for e in cpu_steps if e['outputs'].get('rvfi_valid') == 1
                       and e['outputs'].get('rvfi_intr') == 1]
            self.assertEqual(4, len(entered))
            self.assertEqual([0x1012c] * 4, [e['outputs']['rvfi_pc_rdata'] for e in entered])
            for source in [e for e in trace.events if e.get('kind') == 'source_start']:
                self.assertTrue(any(e.get('kind') == 'local_tick_sample'
                                    and e.get('component') == 'gpio_b'
                                    and e.get('local_tick') == source['source_tick']
                                    and e['outputs'].get('interrupt') == 1 for e in trace.events))
            statuses = [e['read_value'] for e in trace.events if e.get('kind') == 'mmio_delivery'
                        and e.get('device_id') == 'gpio_b' and not e.get('write')
                        and e.get('offset') == 0x24]
            self.assertEqual([0x80, 0x80, 0x8000, 0x8000], statuses)
            result_writes = [e['write_value'] for e in trace.events if e.get('kind') == 'mmio_delivery'
                             and e.get('device_id') == 'gpio_a' and e.get('write')
                             and e.get('offset') == 0x0c]
            self.assertEqual(0x0f82, result_writes[-1])
            for result in (6, 8, 11, 15):
                self.assertIn(result, [value >> 8 for value in result_writes])
            self.assertEqual(2, sum(e.get('kind') == 'initial_image' for e in trace.events))
            deliveries = [e for e in trace.events if e.get('kind') == 'mmio_delivery']
            keys = [(e['source_transaction']['source_component'],
                     e['source_transaction']['source_epoch'],
                     e['source_transaction']['channel_id'],
                     e['source_transaction']['source_sequence']) for e in deliveries]
            self.assertEqual(len(keys), len(set(keys)))
            self.assertEqual({'cpu_0'}, {key[0] for key in keys})
            self.assertEqual({0}, {key[1] for key in keys})
            self.assertFalse(any(e.get('kind') in ('irq_overrun', 'reset') for e in trace.events))
            import json
            from myfuzz.scenario.contracts import ScenarioManifest
            import jsonschema
            saved_identity = json.loads((bundle / 'manifest.json').read_text())
            timings = {}
            for component, record in saved_identity['sessions'].items():
                artifact = record['identity']['runtime_artifact']
                timings[component] = {
                    'schema_version': 'generated_local_reset.v1',
                    'artifact_digest': artifact['artifact_digest'],
                    'driver_sha256': artifact['cpp_sha256'],
                    'hold_cycles': artifact['driver_reset']['reset_assert_ticks'],
                    'release_cycles': artifact['driver_reset']['reset_release_ticks']}
            manifest = ScenarioManifest.from_runner_identity(
                saved_identity, scenario_id=case.testcase_id, schedule_order=case.schedule_order,
                scheduler_policy_id='stable-local-v1', budget=budget, reset_timings=timings)
            schema = json.loads((ROOT / 'schemas/scenario_runtime_manifest.v1.json').read_text())
            budget_schema = json.loads((ROOT / 'schemas/scenario_manifest.v1.json').read_text())
            schema['properties']['budget'] = budget_schema['properties']['budget']
            schema['$defs'].update(budget_schema.get('$defs', {}))
            jsonschema.Draft202012Validator(schema).validate(manifest.to_document())
            final_state = json.loads((bundle / 'final_state.json').read_text())
            self.assertEqual('scenario_evidence.v1', json.loads((bundle / 'result.json').read_text())['schema_version'])
            self.assertEqual('scenario_manifest_identity.v2', json.loads((bundle / 'manifest.json').read_text())['schema_version'])
            self.assertEqual(0, final_state['memories']['cpu']['generation'])
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay)
            self.assertEqual(runner.local_ticks, instances[1].local_ticks)


def make_case(directory):
    import subprocess
    from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
                                     render_local_harness, render_local_runtime,
                                     verify_local_source_lock)
    from myfuzz.local_harness.driver_renderer import render_local_driver
    from myfuzz.local_harness.cpu_session import GeneratedCve2Session
    from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
    from myfuzz.scenario.genome import Action, Trigger, MemoryImage, ScenarioGenome
    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
    from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
    from myfuzz.scenario.router import DataflowRouter, DeviceWindow
    from myfuzz.scenario.runner import Binding, ScenarioRunner
    source_root = Path(os.environ.get('MYFUZZ_LOCAL_SOURCE_ROOT', ROOT))
    def artifact(profile, instance):
        plan = plan_local_harness(load_local_harness_request({
            'schema_version': 'local_harness.v1', 'profile_path': profile,
            'instance_id': instance, 'reset_assert_ticks': 8,
            'reset_release_ticks': 8, 'max_wait_cycles': 16}), base_dir=source_root)
        return render_local_driver(render_local_runtime(
            plan, render_local_harness(plan), verify_local_source_lock(plan.profile, base_dir=source_root),
            base_dir=source_root), base_dir=source_root)
    cpu_artifact = artifact('configs/cpus/cv32e20/component_profile.json', 'cpu_0')
    gpio_artifacts = {name: artifact('configs/peripherals/pulp_gpio/component_profile.json', name)
                      for name in ('gpio_a', 'gpio_b')}
    binary = directory / 'firmware.bin'
    subprocess.run(['clang', '--target=riscv32', '-march=rv32im_zicsr', '-mabi=ilp32',
                    '-nostdlib', '-fuse-ld=lld', f'-Wl,-T,{ROOT / "examples/generated_local_irq/link.ld"}',
                    '-Wl,--oformat=binary', str(ROOT / 'examples/generated_local_irq/bidirectional.S'),
                    '-o', str(binary)], check=True, capture_output=True)
    irq_binding = Binding('gpio_b', 'irq', 'cpu', 'irq', 1)
    ownership = compile_ownership(
        (InputField('cpu', 'irq', 1), InputField('gpio_a', 'gpio_in', 32), InputField('gpio_b', 'gpio_in', 32)),
        (InputOwner('cpu', 'irq', 0, 1, 'bound', 'gpio_b.irq'),
         InputOwner('gpio_a', 'gpio_in', 0, 32, 'fixed', 'constant_zero'),
         InputOwner('gpio_b', 'gpio_in', 0, 8, 'bound', 'gpio_a.gpio_out'),
         InputOwner('gpio_b', 'gpio_in', 8, 8, 'source', 'external'),
         InputOwner('gpio_b', 'gpio_in', 16, 16, 'fixed', 'constant_zero')))
    instances = []
    def factory():
        memory = PersistentMemory(regions=(MemoryRegion('ram', 0x10000, 0x20000),),
                                  initialization_seed=37, max_initialized_bytes=0x20000)
        gpios = {name: GeneratedPulpGpioSession(a, base_dir=source_root, cache_dir=directory / 'cache')
                 for name, a in gpio_artifacts.items()}
        router = DataflowRouter(tuple(DeviceWindow(name, address, 0x1000, gpios[name])
                                     for name, address in (('gpio_a', 0x40001000), ('gpio_b', 0x40000000))))
        cpu = GeneratedCve2Session(cpu_artifact, base_dir=source_root, cache_dir=directory / 'cache',
                                   memory=memory, router=router, defer_mmio=True)
        runner = ScenarioRunner(sessions={'cpu': cpu, **gpios}, ownership=ownership,
                                bindings=(Binding('gpio_a', 'gpio_out', 'gpio_b', 'gpio_in', 8), irq_binding),
                                irq_pulses={irq_binding: 4})
        instances.append(runner)
        return runner
    direction = 'MULTI_COMPONENT_CHAIN'
    def external(action_id, value, result, delay=0):
        return Action(action_id, 'gpio_b', 'gpio_in', value, direction,
                      Trigger('AFTER_OUTPUT', 'gpio_a', 'gpio_out', 0xff00, result << 8),
                      'cpu', delay, bit_offset=8, width=8)
    case = ScenarioGenome('generated-bidirectional-irq', direction, 'both-directions-two-rounds',
                          ('cpu', 'gpio_a', 'gpio_b'), 1860,
                          (external('external-three-rise', 0x83, 8, 40),
                           external('external-three-fall', 3, 11),
                           external('external-four-rise', 0x84, 11, 80)),
                          (MemoryImage('boot', 'cpu', 0x10000, binary.read_bytes().hex()),
                           MemoryImage('results', 'cpu', 0x20000, '00' * 128)))
    return factory, instances, case
