"""Independent raw reconstruction of bounded UART seed -> retired SW rs2 use."""
from copy import deepcopy
import json
import os
from pathlib import Path
import unittest

from tests.integration import test_uart_native_irq_taken_real as native_fixture
from tests.integration.test_uart_controlled_entry_read_real import _certificate_matches


@unittest.skipUnless(os.environ.get('MYFUZZ_UART_OPERAND_USE_REAL') == '1',
    'requires a fresh frozen-source UART operand-use online run')
class UartOperandUseRealTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from myfuzz.integration.ibex_uart_online import _read_uart_online_trace
        from myfuzz.integration.scenario_rfuzz_live import _verify_online_run_identity
        output = os.environ.get('MYFUZZ_UART_OPERAND_USE_RUN_DIR')
        if not output:
            raise ValueError('MYFUZZ_UART_OPERAND_USE_RUN_DIR required')
        cls.output = Path(output).resolve()
        plan_path = cls.output / 'online_plan.json'
        trace_path = cls.output / 'online_final_trace.json'
        cls.trace = _read_uart_online_trace(trace_path)
        _verify_online_run_identity(cls.output, plan_path=plan_path,
            trace_path=trace_path, trace=cls.trace)
        cls.plan = json.loads(plan_path.read_bytes())
        cls.manifest = json.loads((cls.output / 'online_session_manifest.json').read_bytes())
        cls.events = list(cls.trace.events)
        cls.index = native_fixture._verified_saved_native_index(cls.plan, cls.manifest)

    def reconstruct(self, mutation=None):
        from myfuzz.scenario.source_provenance import AdmissionRegistry
        from myfuzz.scenario.ownership import compile_ownership, InputField, InputOwner
        from myfuzz.scenario.uart_operand_use import UartOperandUseTracker

        authority = self.manifest['runner']['ownership']
        ownership = compile_ownership(
            tuple(InputField(**field) for field in authority['fields']),
            tuple(InputOwner(**owner) for owner in authority['owners']))
        tracker = UartOperandUseTracker(
            admission_registry=AdmissionRegistry.from_document(
                self.plan['source_admissions']),
            ownership=ownership, edge_index=self.index,
            max_instruction_witnesses=2048)
        reports = []
        for original in self.events:
            event = deepcopy(original)
            if mutation is not None:
                event = mutation(event)
                if event is None:
                    continue
            reports.extend(tracker.consume(event))
        return reports

    def test_four_saved_uses_match_independent_raw_reconstruction(self):
        saved = [event for event in self.events
            if event.get('kind') == 'uart_operand_use']
        generated = self.reconstruct()
        accepted = [report for report in generated
            if report.get('status') == 'accepted']
        self.assertEqual(len(saved), 4)
        self.assertEqual(len(accepted), 4)
        self.assertFalse([report for report in generated
            if report.get('status') == 'incomplete'])
        self.assertEqual([report['source_register_version_key'][2]
            for report in accepted], [81, 151, 226, 300])
        self.assertEqual([report['operand_order'] for report in accepted],
            [83, 153, 228, 302])
        self.assertEqual([report['operand_value'] for report in accepted],
            [90, 126, 127, 128])
        for proof in saved:
            self.assertTrue(any(_certificate_matches(proof, report)
                for report in accepted), proof.get('event_id'))

    def test_required_raw_witness_deletions_revoke_all_uses(self):
        for kind in ('uart_rdata_access', 'cpu_retire'):
            with self.subTest(kind=kind):
                generated = self.reconstruct(
                    lambda event: None if event.get('kind') == kind else event)
                self.assertFalse([report for report in generated
                    if report.get('status') == 'accepted'])

    def test_changed_store_operand_cannot_reuse_saved_seed(self):
        first_store = next(event for event in self.events
            if event.get('kind') == 'cpu_retire' and event.get('insn') == 0x0032a023)

        def mutate(event):
            if event.get('event_id') == first_store['event_id']:
                event['rs2_addr'] = 4
            return event

        generated = self.reconstruct(mutate)
        accepted = [report for report in generated
            if report.get('status') == 'accepted']
        # The raw POST disagreement creates a certainty barrier for the CPU
        # stream, so later uses remain unproven as well.
        self.assertEqual(len(accepted), 0)
        self.assertNotIn(first_store['event_id'],
            [report['operand_retirement_event_id'] for report in accepted])
