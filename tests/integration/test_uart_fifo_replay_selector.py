"""Saved FIFO selection requires an already verified exact-byte envelope."""
import copy
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from myfuzz.integration.ibex_uart_online import _saved_uart_fifo_mode
from myfuzz.scenario.ibex_uart_online import UART_PROFILE,UART_FIFO_PROFILE
from myfuzz.local_harness.opentitan_uart_fifo_contract import uart_fifo_observation_contract

class UartFifoSavedSelectorTests(unittest.TestCase):
    def identity(self, observed):
        identity={'source_component':'uart','runtime_artifact':{'kind':'tlul_uart','plan':{
            'instance_id':'uart','component_id':'opentitan_uart_fifo_local' if observed else 'opentitan_uart_local',
            'profile_path':UART_FIFO_PROFILE if observed else UART_PROFILE}}}
        if observed:
            identity['uart_fifo_observation_contract']=uart_fifo_observation_contract()
            identity['uart_source_provenance']={'schema_version':'uart_source_frames.v1'}
        return identity

    def save(self, output, identity, newline=b'\n'):
        raw=json.dumps({'runner':{'sessions':{'uart':{'identity':identity}}}},sort_keys=True).encode()+newline
        (output/'online_session_manifest.json').write_bytes(raw)
        return {'artifacts':{'online_session_manifest.json':hashlib.sha256(raw).hexdigest()}}

    def test_saved_default_and_observed_call_strict_identity_admission(self):
        with TemporaryDirectory() as directory:
            output=Path(directory)
            for observed in [False,True]:
                identity=self.identity(observed);envelope=self.save(output,identity)
                with patch('myfuzz.scenario.contracts._verify_generated_session') as verify:
                    self.assertEqual(_saved_uart_fifo_mode(output,envelope),observed)
                verify.assert_called_once_with(identity)
            with patch('myfuzz.scenario.contracts._verify_generated_session') as verify:
                self.assertFalse(_saved_uart_fifo_mode(output,None))
            verify.assert_not_called()

    def test_newline_hash_and_path_tampering_refused_before_admission(self):
        with TemporaryDirectory() as directory:
            output=Path(directory);envelope=self.save(output,self.identity(True))
            path=output/'online_session_manifest.json';raw=path.read_bytes();path.write_bytes(raw[:-1])
            with patch('myfuzz.scenario.contracts._verify_generated_session') as verify,self.assertRaises(ValueError):
                _saved_uart_fifo_mode(output,envelope)
            verify.assert_not_called()
            path.unlink();other=output/'other.json';other.write_bytes(raw);path.symlink_to(other)
            with self.assertRaises(ValueError):_saved_uart_fifo_mode(output,envelope)

    def test_contract_profile_instance_and_provenance_mismatch_refused(self):
        with TemporaryDirectory() as directory:
            output=Path(directory)
            for mutation in ['float_contract','missing_provenance','old_profile','wrong_instance','wrong_component','wrong_kind','wrong_source']:
                identity=self.identity(True)
                if mutation=='float_contract':identity['uart_fifo_observation_contract']['fifo_depth']=64.0
                elif mutation=='missing_provenance':identity.pop('uart_source_provenance')
                elif mutation=='old_profile':identity['runtime_artifact']['plan']['profile_path']=UART_PROFILE
                elif mutation=='wrong_instance':identity['runtime_artifact']['plan']['instance_id']='other'
                elif mutation=='wrong_component':identity['runtime_artifact']['plan']['component_id']='opentitan_uart_local'
                elif mutation=='wrong_kind':identity['runtime_artifact']['kind']='tlul_gpio'
                else:identity['source_component']='other'
                envelope=self.save(output,identity)
                with self.subTest(mutation=mutation),self.assertRaises(ValueError),patch('myfuzz.scenario.contracts._verify_generated_session') as verify:
                    _saved_uart_fifo_mode(output,envelope)
                verify.assert_not_called()

    def test_strict_runtime_failure_prevents_selector(self):
        with TemporaryDirectory() as directory:
            output=Path(directory);envelope=self.save(output,self.identity(True))
            with patch('myfuzz.scenario.contracts._verify_generated_session',side_effect=ValueError('bad build')):
                with self.assertRaisesRegex(ValueError,'bad build'):_saved_uart_fifo_mode(output,envelope)

    def test_replay_profile_selector_runs_after_envelope_and_before_factory(self):
        from myfuzz.integration import ibex_uart_online as module
        with TemporaryDirectory() as directory:
            output=Path(directory);plan=output/'plan.json';plan.write_bytes(b'{}')
            trace=output/'trace.json';trace.write_text(json.dumps({'genome_sha256':'a'*64,'status':'complete',
                'events':[],'local_ticks':{},'semantic_sha256':'b'*64,'manifest_sha256':'c'*64}))
            order=[]
            with patch.object(module,'_verify_online_run_identity',side_effect=lambda *a,**k:order.append('envelope') or {}), \
                 patch.object(module,'_saved_uart_fifo_mode',side_effect=lambda *a:order.append('fifo') or True), \
                 patch.object(module,'_saved_cpu_retirement_mode',return_value=False), \
                 patch.object(module,'_saved_memory_commit_mode',side_effect=lambda *a:order.append('commit') or False), \
                 patch.object(module,'_saved_memory_readback_mode',side_effect=lambda *a:order.append('readback') or False), \
                 patch.object(module,'make_ibex_uart_online_factory',side_effect=lambda *a,**k:order.append('factory') or object()) as factory, \
                 patch.object(module,'replay_online_session',return_value='replayed'):
                self.assertEqual(module.replay_ibex_uart_online_files(cache_dir=output/'cache',plan_path=plan,trace_path=trace),'replayed')
            self.assertEqual(order,['envelope','fifo','commit','readback','factory'])
            self.assertTrue(factory.call_args.kwargs['uart_fifo'])
            self.assertFalse(factory.call_args.kwargs['memory_commit'])
            self.assertFalse(factory.call_args.kwargs['memory_readback'])

    def test_cli_forwards_explicit_flag_and_default(self):
        import importlib.util
        from types import SimpleNamespace
        root=Path(__file__).resolve().parents[2]
        spec=importlib.util.spec_from_file_location('uart_online_cli_test',root/'scripts/run_ibex_uart_online.py')
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        with TemporaryDirectory() as directory:
            output=Path(directory)/'new-output'
            result=SimpleNamespace(output_dir=output,tests=1,statuses={},elapsed_seconds=1,effective_search_seconds=1)
            for enabled in [False,True]:
                arguments=['run','--client-binary','/tmp/client','--cache-dir','/tmp/cache','--output',str(output)]
                if enabled:arguments+=['--uart-fifo']
                with patch.object(module,'make_ibex_uart_online_runtime',return_value=SimpleNamespace(executor=object())) as runtime, \
                     patch.object(module,'run_scenario_rfuzz_live',return_value=result),patch('builtins.print'):
                    self.assertEqual(module.main(arguments),0)
                self.assertIs(runtime.call_args.kwargs['uart_fifo'],enabled)
