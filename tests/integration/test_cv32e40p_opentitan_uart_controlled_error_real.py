"""CV32E40P + OpenTitan UART: one controlled wrong target response is caught by an
independent checker, while the identical scenario without the perturbation stays
silent.

Chain (unchanged, imported from the sibling acceptance test): the real pinned
CV32E40P OBI CPU and the real pinned OpenTitan UART TL-UL RTL run in two
generated harnesses; the genome injects one external 8N1 RX byte ``0x5a``; the
real ``uart_rx_watermark`` output is bound to ``irq_i[11]``; the CV32E40P ISR
reads the real ``INTR_STATE`` (offset 0x00) and the real ``RDATA`` (offset 0x18)
and stores both into persistent RAM.

Controlled perturbation (the only difference between the two runs): exactly one
read of UART ``RDATA`` (offset 0x18) has the response value handed to the fabric
flipped by one bit (``0x5a -> 0x5b``) *after* the real Verilator RTL produced the
true value, and before the CPU consumes the response.  The wrong value really
travels the rest of the chain - the delivery event, the CPU data response, the
ISR store and persistent RAM all carry ``0x5b`` - while the trace keeps the
RTL's own raw TL-UL response sample, which still shows the untouched ``0x5a``.

Boundary of that claim (read before trusting this file):
* ``calibration_only = True``: this is a controlled calibration of the detection
  chain, never a natural RTL defect and never an RTL-internal fault.  The
  perturbation lives in the target session's register-read response
  (``observation_boundary = 'target_register_read_response_copy'``,
  ``rtl_internal_fault = False``); nothing rewrites a decoder, an RTL output, a
  receipt or an owner, and the injected value is computed from the witnessed
  real value (the injection refuses to fire unless the real RTL value is the
  witnessed RX byte).
* The checker is the shipped ``IbexUartOnlineChecker`` - a pure observation
  checker that generates no value of its own and whose invariants only reference
  the declared UART source byte, the UART MMIO read and the CPU data-response
  fields, so it applies unchanged to this non-Ibex CPU.  It is invoked on the
  recorded per-case receipt, exactly the object the online runtime hands to a
  checker.
* Not claimed: coverage-guided search, a multi-case online session, a real
  RTL-internal fault injection, more than one fault variant, or any natural
  defect.  One chain, one injection point, one control.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.scenario.evidence import replay_evidence_bundle, save_evidence_bundle
from myfuzz.scenario.ibex_uart_online_checker import IbexUartOnlineChecker
from myfuzz.scenario.session_runtime import OnlineCaseReceipt, _checker_identity
from tests.integration.test_scenario_cv32e40p_opentitan_uart_irq_real import (
    RESULT, _artifact, _genome, _make_factory)

ROOT = Path(__file__).resolve().parents[2]
CPU_PROFILE = 'configs/cpus/cv32e40p/component_profile.json'
UART_PROFILE = 'configs/peripherals/opentitan_uart_local/component_profile.json'
UART_DEVICE = 'uart'
RDATA_OFFSET = 0x18
INTR_STATE_OFFSET = 0x00
SOURCE_BYTE = 0x5a
INJECTED_BYTE = SOURCE_BYTE ^ 1
FAULT_SCHEMA = 'controlled_target_response_fault.v1'
FAULT_MODE = 'uart_rdata_read_response_xor1.v1'
FAULT_BOUNDARY = 'target_register_read_response_copy'
#: The one violation the independent checker must report for the perturbation.
EXPECTED_VIOLATION = 'uart_rxdata_source_mismatch'


class RdataResponseFault:
    """One-shot perturbation of the UART target's ``RDATA`` read response.

    ``DataflowRouter`` reads a plain target through ``target.read_register``, so
    wrapping that one method on this session instance intercepts exactly the
    value the target hands back for the CPU's RDATA read.  The wrapper calls the
    real method first (the real Verilator RTL executes and returns the true
    value), records that value, and only then flips bit 0 of the returned copy.
    It refuses to fire unless the real value is the witnessed RX byte, disarms
    itself after the single injection, and passes every other call through
    untouched.
    """

    def __init__(self, *, expected_byte: int = SOURCE_BYTE) -> None:
        self.expected_byte = expected_byte
        self.armed = True
        self.read_calls = 0
        self.document: dict | None = None

    @staticmethod
    def _instance_id(session) -> str | None:
        document = getattr(session, '_artifact_document', None) or {}
        plan = document.get('plan') if isinstance(document, dict) else None
        return plan.get('instance_id') if isinstance(plan, dict) else None

    def install(self, session) -> None:
        real = session.read_register

        def read_register(offset: int, *args, **kwargs):
            value = real(offset, *args, **kwargs)
            self.read_calls += 1
            # Fail closed: only perturb the RDATA read whose real RTL value is
            # the witnessed RX byte.
            if (not self.armed or offset != RDATA_OFFSET
                    or not isinstance(value, int)
                    or value & 0xff != self.expected_byte):
                return value
            self.armed = False
            self.document = {
                'schema_version': FAULT_SCHEMA,
                'mode': FAULT_MODE,
                'calibration_only': True,
                'rtl_internal_fault': False,
                'observation_boundary': FAULT_BOUNDARY,
                'injected_once': True,
                'target_instance': self._instance_id(session),
                'offset': offset,
                'write': False,
                'register_read_call_ordinal': self.read_calls,
                'target_local_tick': getattr(session, 'local_ticks', None),
                'target_reset_epoch': getattr(session, 'reset_epoch', None),
                'cpu_routed_mode': bool(getattr(session, 'cpu_routed_mode', False)),
                'real_rtl_rdata': value,
                'delivered_rdata': value ^ 1,
                'expected_source_byte': self.expected_byte,
            }
            return value ^ 1

        session.read_register = read_register


def _make_injecting_factory(cpu_artifact, uart_artifact, cache_dir, faults):
    """The sibling acceptance factory plus the one-shot RDATA response fault."""
    inner, instances = _make_factory(cpu_artifact, uart_artifact, cache_dir)

    def factory():
        runner = inner()
        fault = RdataResponseFault()
        fault.install(runner.sessions[UART_DEVICE])
        faults.append(fault)
        return runner

    return factory, instances


def _receipt(trace, case_id: str) -> OnlineCaseReceipt:
    """The per-case receipt shape the online runtime hands to a checker."""
    events = tuple(trace.events)
    return OnlineCaseReceipt(case_id, 0, len(events), events, {},
                             dict(trace.local_ticks), trace.status)


def _findings(trace, case_id: str) -> tuple[str, ...]:
    return IbexUartOnlineChecker()(_receipt(trace, case_id))


def _rdata_delivery(events) -> dict:
    return next(event for event in events
                if event.get('kind') == 'mmio_delivery'
                and event.get('device_id') == UART_DEVICE
                and event.get('write') is False
                and event.get('offset') == RDATA_OFFSET)


def _source_injection(events) -> dict:
    return next(event for event in events
                if event.get('kind') == 'source_injection'
                and event.get('component') == UART_DEVICE
                and event.get('port') == 'uart_rx_byte'
                and event.get('value') == SOURCE_BYTE)


def _cpu_rdata_consumption(events, transaction: dict) -> dict:
    epoch = transaction['source_epoch']
    sequence = transaction['source_sequence']
    return next(event for event in events
                if event.get('component') == 'cpu'
                and event.get('kind') is None
                and isinstance(event.get('outputs'), dict)
                and event['outputs'].get('data_rsp_consumed') == 1
                and event['outputs'].get('data_rsp_source_epoch') == epoch
                and event['outputs'].get('data_rsp_source_sequence') == sequence)


def _raw_rtl_rdata_response(events) -> dict:
    """The UART RTL's own raw TL-UL response sample for the RDATA read."""
    return next(event for event in events
                if event.get('component') == UART_DEVICE
                and event.get('kind') == 'local_tick_sample'
                and isinstance(event.get('outputs'), dict)
                and isinstance(event['outputs'].get('backend'), dict)
                and event['outputs']['backend'].get('uart_req_addr') == RDATA_OFFSET
                and event['outputs']['backend'].get('uart_rsp_valid') == 1
                and event['outputs']['backend'].get('uart_rsp_ready') == 1)


def _ram_writes(events, address: int) -> list[tuple[int, int]]:
    return [(event['address'], event['value']) for event in events
            if event.get('kind') == 'memory_write'
            and event.get('component') == 'cpu'
            and event.get('address') == address]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, document: dict) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    path.write_text(text, encoding='utf-8')
    return _sha256(path)


def _violation_evidence(trace, findings: tuple[str, ...]) -> dict:
    """The concrete fields the checker decision rests on, read from the trace."""
    events = trace.events
    delivery = _rdata_delivery(events)
    injection = _source_injection(events)
    consumption = _cpu_rdata_consumption(events, delivery['source_transaction'])
    raw = _raw_rtl_rdata_response(events)
    observed = delivery.get('target_uart_access')
    return {
        'findings': list(findings),
        'trace_status': trace.status,
        'source_byte': injection['value'],
        'source_injection_event_id': injection['event_id'],
        'source_action_id': injection['action_id'],
        'rdata_delivery_event_id': delivery['event_id'],
        'rdata_delivery_read_value': delivery['read_value'],
        'rdata_delivery_source_transaction': delivery['source_transaction'],
        'real_rtl_uart_rsp_sample_event_id': raw['event_id'],
        'real_rtl_uart_rsp_local_tick': raw['local_tick'],
        'real_rtl_uart_rsp_rdata': raw['outputs']['backend']['uart_rsp_rdata'],
        'target_uart_access_read_value':
            observed.get('read_value') if isinstance(observed, dict) else None,
        'cpu_rdata_response_event_id': consumption['event_id'],
        'cpu_data_rsp_consumed': consumption['outputs']['data_rsp_consumed'],
        'cpu_data_rsp_rdata': consumption['outputs']['data_rsp_rdata'],
        'cpu_data_rsp_source_epoch':
            consumption['outputs']['data_rsp_source_epoch'],
        'cpu_data_rsp_source_sequence':
            consumption['outputs']['data_rsp_source_sequence'],
        'ram_rdata_write': _ram_writes(events, RESULT),
        'intr_state_read_value': next(
            event['read_value'] for event in events
            if event.get('kind') == 'mmio_delivery'
            and event.get('device_id') == UART_DEVICE
            and event.get('offset') == INTR_STATE_OFFSET),
    }


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned CV32E40P and OpenTitan RTL')
class Cv32e40pOpentitanUartControlledErrorTests(unittest.TestCase):
    """A controlled wrong RDATA response is caught, replayed, and never faked."""

    def test_controlled_rxdata_response_error_is_caught_and_replayed(self):
        override = os.environ.get('MYFUZZ_CONTROLLED_ERROR_OUTPUT')
        cleanup = None
        if override:
            work = Path(override)
            work.mkdir(parents=True, exist_ok=True)
        else:
            cleanup = tempfile.TemporaryDirectory(
                prefix='myfuzz-cv32e40p-uart-controlled-error-')
            work = Path(cleanup.name)
        try:
            self._run_case(work)
        finally:
            if cleanup is not None:
                cleanup.cleanup()

    def _run_case(self, work: Path) -> None:
        cpu_artifact = _artifact(CPU_PROFILE, 'cpu')
        uart_artifact = _artifact(UART_PROFILE, UART_DEVICE)
        genome = _genome()
        checker_identity = _checker_identity(IbexUartOnlineChecker())

        # ------------------------------------------------------------------
        # Control: the identical scenario with no perturbation must be silent.
        # ------------------------------------------------------------------
        control_factory, control_instances = _make_factory(
            cpu_artifact, uart_artifact, work / 'cache')
        control_bundle = work / 'control-bundle'
        control_trace = save_evidence_bundle(genome, control_factory,
                                             control_bundle)
        self.assertEqual('complete', control_trace.status)
        control_findings = _findings(control_trace, 'cv32e40p-uart-control')
        self.assertEqual((), control_findings)
        control_evidence = _violation_evidence(control_trace, control_findings)
        self.assertEqual(SOURCE_BYTE, control_evidence['rdata_delivery_read_value'])
        self.assertEqual(SOURCE_BYTE, control_evidence['real_rtl_uart_rsp_rdata'])
        self.assertEqual(SOURCE_BYTE, control_evidence['cpu_data_rsp_rdata'])
        self.assertEqual([(RESULT, SOURCE_BYTE)], control_evidence['ram_rdata_write'])
        control_memory = control_instances[0].sessions['cpu'].memory
        self.assertEqual(SOURCE_BYTE, control_memory.read(
            RESULT, 4, transaction_id='control-rdata').value)
        control_replay = replay_evidence_bundle(control_bundle, control_factory)
        self.assertTrue(control_replay.matches, control_replay.difference_context)
        self.assertEqual('full', control_replay.verification_scope)
        self.assertEqual((), _findings(control_replay.actual_trace,
                                       'cv32e40p-uart-control-replay'))

        # ------------------------------------------------------------------
        # Perturbed: one controlled wrong RDATA response must be caught.
        # ------------------------------------------------------------------
        faults: list[RdataResponseFault] = []
        fault_factory, fault_instances = _make_injecting_factory(
            cpu_artifact, uart_artifact, work / 'cache', faults)
        fault_bundle = work / 'fault-bundle'
        fault_trace = save_evidence_bundle(genome, fault_factory, fault_bundle)
        self.assertEqual('complete', fault_trace.status)
        self.assertEqual(1, len(faults))
        fault_document = faults[0].document
        self.assertIsNotNone(fault_document, 'the controlled fault never fired')
        self.assertFalse(faults[0].armed)
        self.assertEqual(SOURCE_BYTE, fault_document['real_rtl_rdata'])
        self.assertEqual(INJECTED_BYTE, fault_document['delivered_rdata'])
        self.assertEqual(RDATA_OFFSET, fault_document['offset'])
        self.assertFalse(fault_document['write'])
        self.assertFalse(fault_document['rtl_internal_fault'])

        fault_findings = _findings(fault_trace, 'cv32e40p-uart-controlled-fault')
        self.assertEqual((EXPECTED_VIOLATION,), fault_findings)
        # Both runs declare the very same system identity, so the only
        # difference between them is the one controlled perturbation.
        self.assertEqual(control_trace.manifest_sha256,
                         fault_trace.manifest_sha256)
        fault_evidence = _violation_evidence(fault_trace, fault_findings)
        # The perturbation is visible at every hop of the delivered chain ...
        self.assertEqual(SOURCE_BYTE, fault_evidence['source_byte'])
        self.assertEqual(INJECTED_BYTE,
                         fault_evidence['rdata_delivery_read_value'])
        self.assertEqual(INJECTED_BYTE, fault_evidence['cpu_data_rsp_rdata'])
        self.assertEqual([(RESULT, INJECTED_BYTE)],
                         fault_evidence['ram_rdata_write'])
        # ... while the RTL's own raw TL-UL response sample still shows the
        # untouched byte, so the RTL is provably not the source of the error.
        self.assertEqual(SOURCE_BYTE, fault_evidence['real_rtl_uart_rsp_rdata'])
        self.assertNotEqual(fault_evidence['rdata_delivery_read_value'],
                            fault_evidence['real_rtl_uart_rsp_rdata'])
        # The witness byte really reached the RTL over the RX pin and the ISR
        # really read the asserted watermark status.
        self.assertEqual(SOURCE_BYTE, fault_evidence['source_byte'])
        self.assertEqual(0x2, fault_evidence['intr_state_read_value'] & 0x2)
        fault_memory = fault_instances[0].sessions['cpu'].memory
        self.assertEqual(INJECTED_BYTE, fault_memory.read(
            RESULT, 4, transaction_id='fault-rdata').value)

        # ------------------------------------------------------------------
        # Fresh replay: new harnesses, same events, same violation, same RAM.
        # ------------------------------------------------------------------
        fault_replay = replay_evidence_bundle(fault_bundle, fault_factory)
        self.assertTrue(fault_replay.matches, fault_replay.difference_context)
        self.assertEqual('full', fault_replay.verification_scope)
        self.assertEqual(2, len(faults))
        replayed_findings = _findings(fault_replay.actual_trace,
                                      'cv32e40p-uart-controlled-fault-replay')
        self.assertEqual(fault_findings, replayed_findings)
        replay_evidence = _violation_evidence(fault_replay.actual_trace,
                                              replayed_findings)
        self.assertEqual(fault_evidence, replay_evidence)
        replayed_memory = fault_instances[1].sessions['cpu'].memory
        self.assertIsNot(fault_instances[0].sessions['cpu'].memory,
                         replayed_memory)
        self.assertEqual(INJECTED_BYTE, replayed_memory.read(
            RESULT, 4, transaction_id='fault-replay-rdata').value)

        # ------------------------------------------------------------------
        # Publish the finding document next to (never inside) the bundles, so
        # the immutable evidence tree stays replayable.
        # ------------------------------------------------------------------
        report = {
            'schema_version': 'controlled_error_calibration.v1',
            'chain': {
                'cpu_profile': CPU_PROFILE,
                'cpu_template': cpu_artifact.runtime_document.get('kind'),
                'target_profile': UART_PROFILE,
                'target_device_id': UART_DEVICE,
                'genome_testcase_id': genome.testcase_id,
            },
            'checker': checker_identity,
            'perturbation': fault_document,
            'same_declared_identity': (control_trace.manifest_sha256
                                       == fault_trace.manifest_sha256),
            'declared_identity_sha256': control_trace.manifest_sha256,
            'control': {
                **control_evidence,
                'replay_matches': control_replay.matches,
                'replay_verification_scope': control_replay.verification_scope,
                'replay_first_difference': control_replay.first_difference,
                'trace_json_sha256': _sha256(control_bundle / 'trace.json'),
                'manifest_sha256': _sha256(control_bundle / 'manifest.json'),
            },
            'fault': {
                **fault_evidence,
                'replay_matches': fault_replay.matches,
                'replay_verification_scope': fault_replay.verification_scope,
                'replay_first_difference': fault_replay.first_difference,
                'replay_findings': list(replayed_findings),
                'trace_json_sha256': _sha256(fault_bundle / 'trace.json'),
                'manifest_sha256': _sha256(fault_bundle / 'manifest.json'),
            },
            'expected_violation': EXPECTED_VIOLATION,
        }
        report_sha256 = _write_json(work / 'controlled_error_report.json', report)
        self.assertTrue(report_sha256)
        self.assertEqual([EXPECTED_VIOLATION], report['fault']['findings'])
        self.assertEqual([], report['control']['findings'])


if __name__ == '__main__':
    unittest.main()
