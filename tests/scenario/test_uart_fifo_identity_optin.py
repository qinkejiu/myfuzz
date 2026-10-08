"""Strict passive FIFO variant admission and factory opt-in without RTL start."""
import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from myfuzz.scenario.ibex_uart_online import make_ibex_uart_online_factory

class UartFifoFactoryTests(unittest.TestCase):
    def test_boolean_optin_selects_only_explicit_profile(self):
        from myfuzz.scenario.ibex_uart_online import UART_FIFO_PROFILE,UART_PROFILE,CPU_PROFILE
        with patch('myfuzz.scenario.ibex_uart_online._artifact') as artifact:
            make_ibex_uart_online_factory(Path('/tmp/test-uart-fifo-no-start'),uart_fifo=True)
        self.assertEqual(artifact.call_args_list[0].args,(CPU_PROFILE,'cpu'))
        self.assertEqual(artifact.call_args_list[1].args,(UART_FIFO_PROFILE,'uart'))
        with patch('myfuzz.scenario.ibex_uart_online._artifact') as artifact:
            make_ibex_uart_online_factory(Path('/tmp/test-uart-fifo-no-start'))
        self.assertEqual(artifact.call_args_list[1].args,(UART_PROFILE,'uart'))
        from myfuzz.scenario.ibex_uart_online import RVFI_CPU_PROFILE
        with patch('myfuzz.scenario.ibex_uart_online._artifact') as artifact:
            make_ibex_uart_online_factory(Path('/tmp/test-uart-fifo-no-start'),cpu_retirement=True,uart_fifo=True)
        self.assertEqual(artifact.call_args_list[0].args,(RVFI_CPU_PROFILE,'cpu'))
        self.assertEqual(artifact.call_args_list[1].args,(UART_FIFO_PROFILE,'uart'))
        for value in [None,0,1,1.0,'true']:
            with self.subTest(value=value),self.assertRaises(ValueError):
                make_ibex_uart_online_factory(Path('/tmp/test-uart-fifo-no-start'),uart_fifo=value)

class UartFifoIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from myfuzz.scenario.ibex_pulp_dual_source import _artifact,ROOT
        from myfuzz.local_harness.opentitan_uart_session import GeneratedOpentitanUartSession
        cls.artifact=_artifact('configs/peripherals/opentitan_uart_fifo_local/component_profile.json','uart')
        cls.identity=GeneratedOpentitanUartSession(cls.artifact,base_dir=ROOT,
            cache_dir=Path('/tmp/test-uart-fifo-no-start'),source=None,cpu_routed_mode=True).identity_document()

    def test_exact_identity_admitted(self):
        from myfuzz.scenario.contracts import _verify_generated_session
        _verify_generated_session(self.identity)

    def test_contract_artifact_build_types_and_missing_provenance_rejected(self):
        from myfuzz.scenario.contracts import _verify_generated_session
        for mutation in ['float_depth','missing_provenance','missing_contract','float_probe','bool_timing','build_type','build_float_worker','build_bool_waveform','simulation_define']:
            identity=copy.deepcopy(self.identity)
            if mutation=='float_depth':identity['uart_fifo_observation_contract']['fifo_depth']=64.0
            elif mutation=='missing_provenance':identity.pop('uart_source_provenance')
            elif mutation=='missing_contract':identity.pop('uart_fifo_observation_contract')
            elif mutation=='float_probe':
                identity['runtime_artifact']['selected_template']['executor']['binding']['uart_fifo_probe_contract']['probes']['idle']['width']=1.0
            elif mutation=='bool_timing':identity['runtime_artifact']['plan']['timing']['max_wait_cycles']=True
            elif mutation=='build_float_worker':identity['build_identity']['workers']=1.0
            elif mutation=='build_bool_waveform':identity['build_identity']['waveforms']=0
            elif mutation=='simulation_define':identity['build_identity']['build_argv'].append('-DSIMULATION')
            else:identity['build_identity']['schema_version']='wrong'
            with self.subTest(mutation=mutation),self.assertRaises(ValueError):_verify_generated_session(identity)

    def test_authenticated_build_flags_exclude_simulation_cdc_branch(self):
        from myfuzz.local_harness.build import _environment
        from myfuzz.local_harness.opentitan_uart_fifo_contract import uart_fifo_probe_document
        self.assertIs(uart_fifo_probe_document()['cdc']['SIMULATION'],False)
        self.assertEqual(self.artifact.structural.build_document['defines'],[])
        self.assertFalse(any(arg.startswith('-DSIMULATION') for arg in self.identity['build_identity']['build_argv']))
        self.assertEqual(set(_environment()),{'PATH','LC_ALL'})
