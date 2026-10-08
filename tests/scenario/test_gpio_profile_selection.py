"""Explicit passive GPIO profile selection and authenticated saved replay."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from myfuzz.scenario import ibex_pulp_dual_source as pulp
from myfuzz.integration import ibex_pulp_online as online
from myfuzz.local_harness.pulp_gpio_probe_contract import pulp_gpio_observation_contract

CAUSAL='configs/peripherals/pulp_gpio_causal_local/component_profile.json'


def manifest(observed=True):
    sessions={}
    for component in ('gpio_a','gpio_b'):
        identity={'runtime_artifact':{'kind':'apb_gpio','plan':{
            'component_id':'pulp_gpio_causal_local' if observed else 'pulp_gpio',
            'profile_path':CAUSAL if observed else pulp.GPIO_PROFILE,
            'instance_id':component}}}
        if observed:
            identity.update(gpio_target_context_schema_version='pulp_gpio_routed_access.v1',
                            gpio_observation_contract=pulp_gpio_observation_contract())
        sessions[component]={'identity':identity}
    return {'runner':{'sessions':sessions}}


class GpioProfileSelectionTests(unittest.TestCase):
    def test_gpio_optin_independent_of_cpu_retirement_and_default_preserved(self):
        for gpio in (False,True):
            for cpu in (False,True):
                with self.subTest(gpio=gpio,cpu=cpu),patch.object(pulp,'_artifact') as render:
                    pulp.make_ibex_pulp_dual_source_factory(Path('/tmp/profile-only'),
                        gpio_consumption=gpio,cpu_retirement=cpu)
                    self.assertEqual(render.call_args_list[0].args,
                        (pulp.RVFI_CPU_PROFILE if cpu else pulp.CPU_PROFILE,'cpu'))
                    self.assertEqual([c.args for c in render.call_args_list[1:]],
                        [(CAUSAL if gpio else pulp.GPIO_PROFILE,'gpio_a'),
                         (CAUSAL if gpio else pulp.GPIO_PROFILE,'gpio_b')])

    def test_invalid_gpio_flag_rejected_before_artifact_work(self):
        for value in (1,None,'true'):
            with self.subTest(value=value),patch.object(pulp,'_artifact') as render:
                with self.assertRaises(ValueError):
                    pulp.make_ibex_pulp_dual_source_factory(Path('/tmp/profile-only'),gpio_consumption=value)
                render.assert_not_called()
            with patch.object(online,'make_ibex_pulp_dual_source_factory') as render:
                with self.assertRaises(ValueError):
                    online.make_ibex_pulp_online_runtime(cache_dir=Path('/tmp/profile-only'),
                                                        run_id='test',gpio_consumption=value)
                render.assert_not_called()

    def test_runtime_forwards_explicit_flag_before_any_begin(self):
        session=Mock();session.begin.side_effect=RuntimeError('stop before RTL')
        factory=Mock(return_value=Mock())
        with patch.object(online,'ScenarioSession',return_value=session), \
             patch.object(online,'make_ibex_pulp_dual_source_factory',return_value=factory) as build:
            with self.assertRaisesRegex(RuntimeError,'stop before RTL'):
                online.make_ibex_pulp_online_runtime(cache_dir=Path('/tmp/profile-only'),run_id='test',
                                                    gpio_consumption=True,cpu_retirement=False)
            # The shipped cross-case prerequisite policy switch is forwarded too:
            # the runtime attaches the factory's declared gate by default, and
            # only an explicit source_actions=False selects the legacy path.
            self.assertEqual(build.call_args.kwargs,
                             {'cpu_retirement':False,'gpio_consumption':True,
                              'source_actions':True})
        with patch.object(online,'ScenarioSession',return_value=session), \
             patch.object(online,'make_ibex_pulp_dual_source_factory',return_value=factory) as build:
            with self.assertRaisesRegex(RuntimeError,'stop before RTL'):
                online.make_ibex_pulp_online_runtime(cache_dir=Path('/tmp/profile-only'),run_id='test',
                                                    gpio_consumption=True,cpu_retirement=False,
                                                    source_actions=False)
            self.assertEqual(build.call_args.kwargs,
                             {'cpu_retirement':False,'gpio_consumption':True,
                              'source_actions':False})

    def saved(self, document, changed_raw=None):
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup)
        root=Path(directory.name);raw=json.dumps(document).encode()
        (root/'online_session_manifest.json').write_bytes(changed_raw or raw)
        verified={'artifacts':{'online_session_manifest.json':hashlib.sha256(raw).hexdigest()}}
        return root,verified

    def test_saved_selector_requires_registered_and_coherent_both_gpio_identities(self):
        self.assertTrue(hasattr(online,'_saved_gpio_consumption_mode'),'saved authenticated GPIO selector missing')
        for observed in (False,True):
            root,verified=self.saved(manifest(observed))
            with patch('myfuzz.scenario.contracts._verify_generated_session') as verify:
                self.assertEqual(online._saved_gpio_consumption_mode(root,verified),observed)
                self.assertEqual(verify.call_count,2)
        variants=[]
        mixed=manifest(True);mixed['runner']['sessions']['gpio_b']=manifest(False)['runner']['sessions']['gpio_b'];variants.append(mixed)
        for fault in ('schema','variant','missing_contract','wrong_profile','wrong_instance','missing_component'):
            wrong=manifest(True);identity=wrong['runner']['sessions']['gpio_b']['identity']
            if fault=='schema':identity['gpio_target_context_schema_version']='changed'
            elif fault=='variant':identity['gpio_observation_contract']['variant_id']='changed'
            elif fault=='missing_contract':identity.pop('gpio_observation_contract')
            elif fault=='wrong_profile':identity['runtime_artifact']['plan']['profile_path']=pulp.GPIO_PROFILE
            elif fault=='wrong_instance':identity['runtime_artifact']['plan']['instance_id']='gpio_a'
            else:wrong['runner']['sessions'].pop('gpio_b')
            variants.append(wrong)
        for wrong in variants:
            root,verified=self.saved(wrong)
            with patch('myfuzz.scenario.contracts._verify_generated_session'),self.assertRaises(ValueError):
                online._saved_gpio_consumption_mode(root,verified)

    def test_saved_selector_rechecks_raw_hash_and_never_selects_from_unverified_manifest(self):
        self.assertTrue(hasattr(online,'_saved_gpio_consumption_mode'),'saved authenticated GPIO selector missing')
        root,verified=self.saved(manifest(True),changed_raw=json.dumps(manifest(True),indent=2).encode())
        with patch('myfuzz.scenario.contracts._verify_generated_session') as verify:
            with self.assertRaises(ValueError):online._saved_gpio_consumption_mode(root,verified)
            verify.assert_not_called()
        self.assertFalse(online._saved_gpio_consumption_mode(root,None))


    def test_replay_verifies_saved_bundle_before_profile_selection_and_factory(self):
        root,verified=self.saved(manifest(True))
        plan=root/'online_plan.json';plan.write_bytes(b'{}')
        trace=root/'online_final_trace.json'
        trace.write_text(json.dumps({'genome_sha256':'0'*64,'status':'complete','events':[],
            'local_ticks':{},'semantic_sha256':'0'*64,'manifest_sha256':'0'*64}))
        order=[]
        def verify(*args,**kwargs):order.append('bundle');return verified
        def select(*args,**kwargs):order.append('selector');return True
        def factory(*args,**kwargs):order.append('factory');return Mock()
        with patch.object(online,'_verify_online_run_identity',side_effect=verify), \
             patch.object(online,'_saved_cpu_retirement_mode',return_value=False), \
             patch.object(online,'_saved_pin8_native_irq_mode',return_value=False), \
             patch.object(online,'_saved_gpio_consumption_mode',side_effect=select), \
             patch.object(online,'make_ibex_pulp_dual_source_factory',side_effect=factory) as create, \
             patch.object(online,'replay_online_session',return_value='matched'):
            self.assertEqual(online.replay_ibex_pulp_online_files(cache_dir=root/'cache',plan_path=plan,trace_path=trace),'matched')
            self.assertEqual(order,['bundle','selector','factory'])
            self.assertEqual(create.call_args.kwargs,{'cpu_retirement':False,'gpio_consumption':True})
        with patch.object(online,'_verify_online_run_identity',side_effect=ValueError('tampered')), \
             patch.object(online,'_saved_gpio_consumption_mode') as select, \
             patch.object(online,'make_ibex_pulp_dual_source_factory') as create:
            with self.assertRaisesRegex(ValueError,'tampered'):
                online.replay_ibex_pulp_online_files(cache_dir=root/'cache',plan_path=plan,trace_path=trace)
            select.assert_not_called();create.assert_not_called()

    def test_cli_forwards_gpio_optin_and_preserves_false_default(self):
        import importlib.util
        from contextlib import redirect_stdout
        import io
        path=Path(__file__).resolve().parents[2]/'scripts/run_ibex_pulp_online.py'
        spec=importlib.util.spec_from_file_location('_gpio_profile_cli',path)
        cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
        for enabled in (False,True):
            with tempfile.TemporaryDirectory() as directory:
                args=['run','--client-binary','/tmp/client','--cache-dir','/tmp/cache',
                      '--output',str(Path(directory)/'new-run')]
                if enabled:args.append('--gpio-consumption')
                result=Mock(output_dir=Path(directory)/'new-run',tests=1,statuses={},elapsed_seconds=1,
                            effective_search_seconds=1)
                with patch.object(cli,'make_ibex_pulp_online_runtime',return_value=Mock()) as create, \
                     patch.object(cli,'run_scenario_rfuzz_live',return_value=result),redirect_stdout(io.StringIO()):
                    self.assertEqual(cli.main(args),0)
                    self.assertIn('gpio_consumption',create.call_args.kwargs,'CLI GPIO selector is missing')
                    self.assertIs(create.call_args.kwargs['gpio_consumption'],enabled)


if __name__=='__main__':unittest.main()
