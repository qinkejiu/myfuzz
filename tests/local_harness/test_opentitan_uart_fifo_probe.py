"""Passive UART FIFO manifest authentication, without RTL compilation."""
import copy
import json
import unittest
from pathlib import Path
from myfuzz.composition.component_profile import load_component_profile

ROOT = Path(__file__).resolve().parents[2]
PROFILE = 'configs/peripherals/opentitan_uart_fifo_local/component_profile.json'

class UartFifoProbeTests(unittest.TestCase):
    def test_explicit_variant_preserves_original_source(self):
        from myfuzz.local_harness.opentitan_uart_fifo_contract import verify_opentitan_uart_fifo_source_contract
        document = json.loads((ROOT / PROFILE).read_bytes())
        original = json.loads((ROOT / 'configs/peripherals/opentitan_uart_local/component_profile.json').read_bytes())
        self.assertEqual(document['source'], original['source'])
        verified = verify_opentitan_uart_fifo_source_contract(load_component_profile(document), base_dir=ROOT)
        self.assertEqual(verified['uart_fifo_observation_contract']['fifo_depth'], 64)
        self.assertTrue(verified['authenticated_inputs'])

    def test_manifest_covers_native_state_and_scalar_widths(self):
        from myfuzz.local_harness.opentitan_uart_fifo_contract import uart_fifo_probe_document
        manifest = uart_fifo_probe_document()
        self.assertEqual(manifest['sampling'], 'pre_post_rising')
        required = {'sync_intq','rx_sync','rx_sync_q1','rx_sync_q2','rx_in','idle','bit_cnt','sreg',
                    'rx_valid','rx_data','fifo_wvalid','fifo_wready','fifo_rvalid','fifo_rdata_re',
                    'fifo_depth','fifo_wptr','fifo_rptr','fifo_clear','fifo_head','fifo_under_rst',
                    'fifo_incr_wptr','fifo_incr_rptr','reg_rdata','captured_rdata','tl_a_valid',
                    'tl_a_ready','tl_d_valid','tl_d_ready','tl_a_source','tl_d_source',
                    'watermark_test','intr_state_rx_watermark','hw_state_de_rx_overflow'}
        self.assertLessEqual(required, set(manifest['probes']))
        for name, probe in manifest['probes'].items():
            self.assertTrue(1 <= probe['width'] <= 64)
            self.assertEqual(probe['runtime_name'], 'probe_uart_' + name)
            self.assertTrue(probe['expression'].startswith('u_component.u_dut.u_uart.'))

    def test_exact_identity_and_probe_mutations_rejected(self):
        from myfuzz.local_harness.opentitan_uart_fifo_contract import (
            uart_fifo_observation_contract, validate_uart_fifo_observation_contract,
            uart_fifo_probe_document, validate_uart_fifo_probe_document)
        for key, value in [('template_version','2'), ('fifo_depth',32), ('fifo_depth',64.0), ('pass',True), ('sampling','post')]:
            document=uart_fifo_observation_contract();document[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError): validate_uart_fifo_observation_contract(document)
        document=uart_fifo_observation_contract();document['unknown']=1
        with self.assertRaises(ValueError):validate_uart_fifo_observation_contract(document)
        for key,value in [('width',8),('expression','u_component.u_dut.u_uart.uart_core.rx_fifo_data')]:
            document=copy.deepcopy(uart_fifo_probe_document());document['probes']['fifo_depth'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):validate_uart_fifo_probe_document(document)

    def test_profile_object_mutation_rejected(self):
        from myfuzz.local_harness.opentitan_uart_fifo_contract import verify_opentitan_uart_fifo_source_contract
        document=json.loads((ROOT/PROFILE).read_bytes());document['capabilities']['uart_fifo_observation_variant']='unknown'
        with self.assertRaises(ValueError):verify_opentitan_uart_fifo_source_contract(load_component_profile(document),base_dir=ROOT)

    def test_passive_runtime_and_driver_preserve_default(self):
        from tests.local_harness.test_renderer import real_plan
        from myfuzz.local_harness import render_local_harness, render_local_runtime, verify_local_source_lock
        from myfuzz.local_harness.driver_renderer import render_local_driver
        from myfuzz.local_harness.opentitan_uart_fifo_contract import uart_fifo_probe_document
        for profile_path, expected in [(PROFILE, True),
                ('configs/peripherals/opentitan_uart_local/component_profile.json', False)]:
            plan=real_plan(profile_path,'uart')
            artifact=render_local_runtime(plan,render_local_harness(plan),
                verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT)
            self.assertEqual('uart_fifo_observation_contract' in artifact.runtime_document, expected)
            if expected:
                driver=render_local_driver(artifact,base_dir=ROOT)
                for name,probe in uart_fifo_probe_document()['probes'].items():
                    self.assertIn(f"assign {probe['runtime_name']} = {probe['expression']};",artifact.runtime_sv)
                    self.assertIn('dut.'+probe['runtime_name'],driver.cpp_text)
            else:
                self.assertNotIn('probe_uart_fifo_', artifact.runtime_sv)
                self.assertEqual(artifact.runtime_document['selected_template']['executor']['contract']['variant_id'],'tlul_uart')

    def test_executor_requires_exact_selection(self):
        from tests.local_harness.test_renderer import real_plan
        from myfuzz.local_harness import render_local_harness, render_local_runtime, verify_local_source_lock
        from myfuzz.local_harness.template_contracts import generated_executor_selection
        plan=real_plan(PROFILE,'uart')
        artifact=render_local_runtime(plan,render_local_harness(plan),
            verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT)
        endpoints=tuple(e for e in plan.binding.endpoints if e.protocol is not None)
        for variant in [None, 'unknown', 'tlul_uart']:
            caps=dict(plan.profile.capabilities)
            if variant is None:caps.pop('uart_fifo_observation_variant')
            else:caps['uart_fifo_observation_variant']=variant
            with self.subTest(variant=variant),self.assertRaises(ValueError):
                generated_executor_selection(artifact.runtime_document,endpoints,caps)
        document=copy.deepcopy(artifact.runtime_document);document.pop('uart_fifo_observation_contract')
        with self.assertRaises(ValueError):generated_executor_selection(document,endpoints,plan.profile.capabilities)

    def test_source_profile_closure_and_lock_tampering_rejected(self):
        from unittest.mock import patch
        from myfuzz.local_harness.opentitan_uart_fifo_contract import verify_opentitan_uart_fifo_source_contract
        profile=load_component_profile(json.loads((ROOT/PROFILE).read_bytes()))
        original=Path.read_bytes
        for relative in [PROFILE,'configs/soc/closures/opentitan_uart_fifo_local.json',
                'third_party/soc-opentitan/hw/ip/uart/rtl/uart_rx.sv']:
            target=ROOT/relative
            def changed(path,target=target):
                raw=original(path)
                return raw+b'\n' if path==target else raw
            with self.subTest(relative=relative),patch.object(Path,'read_bytes',changed),self.assertRaises(ValueError):
                verify_opentitan_uart_fifo_source_contract(profile,base_dir=ROOT)
        lock_path=ROOT/'configs/soc/sources.lock.json'
        for mutation in ['missing','wrong_source']:
            lock=json.loads(original(lock_path));row=next(r for r in lock['components'] if r['id']=='opentitan_uart_fifo_local')
            if mutation=='missing':lock['components'].remove(row)
            else:row['source']['revision']='git:'+'0'*40
            raw=json.dumps(lock).encode()
            def changed(path):return raw if path==lock_path else original(path)
            with self.subTest(mutation=mutation),patch.object(Path,'read_bytes',changed),self.assertRaises(ValueError):
                verify_opentitan_uart_fifo_source_contract(profile,base_dir=ROOT)
