"""Independent no-RTL review of saved profile selection and historical replay."""
import json
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from contextlib import nullcontext
from unittest.mock import patch
from myfuzz.integration import ibex_pulp_online as pulp
from myfuzz.integration import ibex_uart_online as uart

class RetirementReplayReviewTests(unittest.TestCase):
    def _files(self, root):
        plan=root/'online_plan.json';plan.write_bytes(b'{}')
        trace=root/'online_final_trace.json';trace.write_text(json.dumps(dict(genome_sha256='a'*64,status='complete',events=[],local_ticks={},semantic_sha256='b'*64,manifest_sha256='c'*64)))
        return plan,trace
    def test_historical_bundle_uses_legacy_profile_after_optional_identity_verification(self):
        for module,func,factory_name in ((pulp,'replay_ibex_pulp_online_files','make_ibex_pulp_dual_source_factory'),(uart,'replay_ibex_uart_online_files','make_ibex_uart_online_factory')):
            with self.subTest(module=module.__name__),TemporaryDirectory() as tmp:
                root=Path(tmp);plan,trace=self._files(root)
                with patch.object(module,'_verify_online_run_identity',return_value=None),patch.object(module,factory_name) as factory,patch.object(module,'replay_online_session',return_value='replayed'):
                    self.assertEqual('replayed',getattr(module,func)(cache_dir=root/'cache',plan_path=plan,trace_path=trace))
                    self.assertFalse(factory.call_args.kwargs['cpu_retirement'])
    def test_saved_verified_manifest_selects_retirement_profile(self):
        for module,func,factory_name in ((pulp,'replay_ibex_pulp_online_files','make_ibex_pulp_dual_source_factory'),(uart,'replay_ibex_uart_online_files','make_ibex_uart_online_factory')):
            for enabled in (False,True):
                with self.subTest(module=module.__name__,enabled=enabled),TemporaryDirectory() as tmp:
                    root=Path(tmp);plan,trace=self._files(root)
                    cpu={'cpu_observation_schema_version':'ibex_rvfi_observation.v1'} if enabled else {}
                    saved={'runner':{'sessions':{'cpu':{'identity':cpu}}}}
                    saved_canonical=json.dumps(saved,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
                    saved_raw=saved_canonical+b'\n'
                    (root/'online_session_manifest.json').write_bytes(saved_raw)
                    order=[]
                    def verified(*args,**kwargs):order.append('verified');return {'session':{'manifest_sha256':hashlib.sha256(saved_canonical).hexdigest()},'artifacts':{'online_session_manifest.json':hashlib.sha256(saved_raw).hexdigest()}}
                    def selected(*args,**kwargs):order.append('selected');return object()
                    # This fixture isolates CPU selection; GPIO selection has
                    # independent complete-manifest and tampering coverage.
                    gpio_selection = (patch.object(module, '_saved_gpio_consumption_mode', return_value=False)
                                      if module is pulp else patch.object(module, '_saved_uart_fifo_mode', return_value=False))
                    with gpio_selection, patch.object(module,'_verify_online_run_identity',side_effect=verified),patch.object(module,factory_name,side_effect=selected) as factory,patch.object(module,'replay_online_session',return_value='replayed'):
                        self.assertEqual('replayed',getattr(module,func)(cache_dir=root/'cache',plan_path=plan,trace_path=trace))
                        self.assertEqual(enabled,factory.call_args.kwargs['cpu_retirement'])
                        self.assertEqual(['verified','selected'],order)
    def test_manifest_changed_after_verification_is_rejected_before_selection(self):
        for module,func,factory_name in ((pulp,'replay_ibex_pulp_online_files','make_ibex_pulp_dual_source_factory'),(uart,'replay_ibex_uart_online_files','make_ibex_uart_online_factory')):
            with self.subTest(module=module.__name__),TemporaryDirectory() as tmp:
                root=Path(tmp);plan,trace=self._files(root)
                saved={'runner':{'sessions':{'cpu':{'identity':{}}}}}
                canonical=json.dumps(saved,sort_keys=True,separators=(',',':')).encode()
                raw=canonical+b'\n'
                manifest=root/'online_session_manifest.json';manifest.write_bytes(raw)
                def verified(*args,**kwargs):
                    saved['runner']['sessions']['cpu']['identity']['cpu_observation_schema_version']='ibex_rvfi_observation.v1'
                    manifest.write_text(json.dumps(saved))
                    return {'session':{'manifest_sha256':hashlib.sha256(canonical).hexdigest()},'artifacts':{'online_session_manifest.json':hashlib.sha256(raw).hexdigest()}}
                with patch.object(module,'_verify_online_run_identity',side_effect=verified),patch.object(module,factory_name) as factory,patch.object(module,'replay_online_session'):
                    with self.assertRaises(ValueError):getattr(module,func)(cache_dir=root/'cache',plan_path=plan,trace_path=trace)
                    factory.assert_not_called()
    def test_failed_saved_identity_does_not_select_or_start_a_factory(self):
        for module,func,factory_name in ((pulp,'replay_ibex_pulp_online_files','make_ibex_pulp_dual_source_factory'),(uart,'replay_ibex_uart_online_files','make_ibex_uart_online_factory')):
            with self.subTest(module=module.__name__),TemporaryDirectory() as tmp:
                root=Path(tmp);plan,trace=self._files(root)
                with patch.object(module,'_verify_online_run_identity',side_effect=ValueError('tampered')),patch.object(module,factory_name) as factory:
                    with self.assertRaisesRegex(ValueError,'tampered'):getattr(module,func)(cache_dir=root/'cache',plan_path=plan,trace_path=trace)
                    factory.assert_not_called()
