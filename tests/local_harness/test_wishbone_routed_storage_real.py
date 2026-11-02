"""Real Router-delivered CPU MMIO into the native WBUART SETUP storage path.

One real ``GeneratedWishboneRegisterSession`` is prepared with the fixed built
executable receipt, one ``WishboneStorageRegisterVersionAuthority`` is bound to
it before the case starts, and both the routed write and the routed read are
driven through the actual ``ACCESS_WB_REG`` command.  Nothing is simulated and
no evidence is imported: the commit record, the drained pre/post samples and the
single-use token all come from this live process.
"""
from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
import os
from pathlib import Path
import tempfile
import unittest

from myfuzz.local_harness import (
    GeneratedWishboneRegisterSession, load_local_harness_request,
    plan_local_harness, render_local_driver, render_local_harness,
    render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.wishbone_storage_probe_contract import ROLES
from myfuzz.scenario import wishbone_storage_register_version as version_module
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.wishbone_storage_register_version import (
    WISHBONE_STORAGE_CONTEXT_KEYS, WishboneStorageRegisterVersionAuthority,
    wishbone_storage_version_basis)

ROOT = Path(__file__).resolve().parents[2]
TARGET_PROFILE = 'configs/peripherals/zipcpu_uart_storage/component_profile.json'
CONTRACT = 'zipcpu-wbuart.setup.storage.v1'
WINDOW = 0x60000000
WINDOW_SIZE = 16
INSTANCE = 'uart_setup'
COMMIT_KEYS = frozenset({
    'tick', 'raw_address', 'before', 'after', 'sample_index', 'phase',
    'command_sequence', 'context', 'raw_reference'})
RAW_REFERENCE_KEYS = frozenset({
    'execution', 'sequence', 'sample_index', 'phase'})


def target_artifact():
    request = load_local_harness_request(dict(
        schema_version='local_harness.v2', profile_path=TARGET_PROFILE,
        instance_id=INSTANCE, reset_assert_ticks=2, reset_release_ticks=2,
        max_wait_cycles=16,
        tuning={'endpoint_policies': [dict(
            endpoint_id='uart.bus', template_id='target.wishbone',
            template_version='1', variant_id='word-addressed-registered-ack',
            max_outstanding=1)],
            'fixed_inputs': [
                dict(endpoint_id='uart.pins', role='rx', value=1),
                dict(endpoint_id='uart.pins', role='cts_n', value=0)],
            'wishbone_storage_observations': [dict(
                endpoint_id='uart.bus', contract_id=CONTRACT,
                register='SETUP')]}))
    plan = plan_local_harness(request, base_dir=ROOT)
    top = render_local_runtime(
        plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


def delivery_context(source_transaction, *, write, value):
    return dict(source_transaction=asdict(source_transaction),
                device_id=INSTANCE, window_base=WINDOW,
                window_size=WINDOW_SIZE, address=WINDOW, offset=0,
                write=write, value=value, be=15)


@unittest.skipUnless(os.environ.get('MYFUZZ_SCENARIO_REAL') == '1',
                     'set MYFUZZ_SCENARIO_REAL=1 for pinned real RTL')
class WishboneRoutedStorageRealTests(unittest.TestCase):
    def test_routed_write_read_commit_and_single_use_token(self):
        generated = target_artifact()
        document = generated.runtime_document
        self.assertEqual('wishbone_register_observe', document['kind'])
        self.assertEqual(set(ROLES), set(document['base_protocol_trace']['signals']))
        case = 'wishbone-routed-setup'
        with tempfile.TemporaryDirectory(prefix='wishbone-routed-') as directory:
            session = GeneratedWishboneRegisterSession(
                generated, base_dir=ROOT, cache_dir=Path(directory) / 'build')
            session.configure_built_executable_receipt()
            session.prepare_local()
            authority = WishboneStorageRegisterVersionAuthority(
                session, max_writes=16, max_samples=65536, max_tokens=4)
            try:
                # The authority is bound to a prepared but not yet started
                # session, so the routed path stays closed until begin_case.
                self.assertIs(False, session.routed_register_access_enabled)
                session.begin_case(case)
                self.assertIs(True, session.routed_register_access_enabled)

                write_key = TransactionKey('local-execution', case, 'cpu0', 0,
                                           'data', 1)
                write = session.routed_register_access(
                    write_key, address=WINDOW, offset=0, write=True,
                    value=0x55, be=15,
                    delivery_context=delivery_context(
                        write_key, write=True, value=0x55))
                read_key = TransactionKey('local-execution', case, 'cpu0', 0,
                                          'data', 2)
                read = session.routed_register_access(
                    read_key, address=WINDOW, offset=0, write=False,
                    value=0, be=15,
                    delivery_context=delivery_context(
                        read_key, write=False, value=0))

                self.assertEqual(0, write['rdata'])
                self.assertEqual(0x55, read['rdata'])
                self.assertEqual('wishbone_storage_routed_context.v1',
                                 read['target_context_schema_version'])
                self.assertIs(False, read['source_authenticated'])
                self.assertEqual(f'wishbone-storage:{session._execution}:2',
                                 read['target_access_id'])

                # A foreign delivery is refused before any command is issued.
                sequence = session._sequence
                forged = delivery_context(read_key, write=False, value=0)
                forged['offset'] = 4
                forged['address'] = WINDOW + 4
                with self.assertRaisesRegex(
                        ValueError, 'wishbone-storage-routed-delivery-mismatch'):
                    session.routed_register_access(
                        read_key, address=WINDOW, offset=0, write=False,
                        value=0, be=15, delivery_context=forged)
                self.assertEqual(sequence, session._sequence)

                samples = session.drain_tick_samples()
                self.assertEqual(10, len(samples))
                accepted = [
                    index for index, sample in enumerate(samples)
                    if sample['pre']['storage_probes']['storage_cyc'] == 1
                    and sample['pre']['storage_probes']['storage_stb'] == 1
                    and sample['pre']['storage_probes']['storage_we'] == 1]
                self.assertEqual(1, len(accepted))
                write_index = accepted[0]
                write_pre = samples[write_index]
                self.assertEqual(0x19, write_pre['pre']['storage_probes'][
                    'storage_value'])
                self.assertEqual(0x55, write_pre['post']['storage_probes'][
                    'storage_value'])
                self.assertEqual(0, write_pre['pre']['storage_probes'][
                    'storage_adr'])
                self.assertEqual(15, write_pre['pre']['storage_probes'][
                    'storage_sel'])
                read_accepted = [
                    sample for sample in samples
                    if sample['pre']['storage_probes']['storage_cyc'] == 1
                    and sample['pre']['storage_probes']['storage_stb'] == 1
                    and sample['pre']['storage_probes']['storage_we'] == 0]
                self.assertEqual(1, len(read_accepted))
                self.assertEqual(0x55, read_accepted[0]['pre'][
                    'storage_probes']['storage_dat_r'])

                writes = authority.writes()
                self.assertEqual(1, len(writes))
                commit = writes[0]
                self.assertEqual(COMMIT_KEYS, set(commit))
                self.assertEqual(WISHBONE_STORAGE_CONTEXT_KEYS,
                                 set(commit['context']))
                self.assertEqual(RAW_REFERENCE_KEYS,
                                 set(commit['raw_reference']))
                self.assertEqual(0x19, commit['before'])
                self.assertEqual(0x55, commit['after'])
                self.assertEqual(0, commit['raw_address'])
                self.assertEqual('pre', commit['phase'])
                self.assertEqual(1, commit['command_sequence'])
                self.assertEqual(write_index, commit['sample_index'])
                self.assertEqual(write_pre['local_tick'], commit['tick'])
                self.assertEqual(2, commit['tick'])
                self.assertEqual(
                    commit['tick'], commit['context']['tick'])
                self.assertEqual(session._execution,
                                 commit['context']['execution'])
                self.assertEqual(0, commit['context']['reset_epoch'])
                self.assertEqual(1, commit['context']['command_sequence'])
                self.assertEqual('wishbone_storage_routed_context.v1',
                                 commit['context']['schema_version'])
                self.assertIs(False,
                              commit['context']['source_authenticated'])
                self.assertIs(True, commit['context']['write'])
                self.assertEqual(0x55, commit['context']['value'])
                self.assertEqual(15, commit['context']['byte_enable'])
                self.assertEqual(0, commit['context']['word_index'])
                self.assertEqual(0, commit['context']['read_value'])
                self.assertEqual(
                    asdict(write_key),
                    commit['context']['source_transaction'])
                self.assertEqual(dict(
                    execution=session._execution, sequence=1,
                    sample_index=write_index, phase='pre'),
                    commit['raw_reference'])

                token = authority.issue(register='SETUP', reset_epoch=0)
                self.assertIs(type(token), object)
                witness = authority.consume(token)
                self.assertEqual(0x55, witness['value'])
                self.assertEqual('SETUP', witness['register'])
                self.assertEqual(0, witness['reset_epoch'])
                self.assertEqual(1, witness['write_count'])
                self.assertEqual(1, witness['field_version'])
                self.assertEqual(session._sequence, witness['command_sequence'])
                self.assertEqual(2, witness['command_sequence'])
                self.assertEqual(session.local_ticks, witness['local_tick'])
                self.assertEqual(session.process.pid, witness['pid'])
                self.assertEqual(session._execution, witness['execution'])
                self.assertEqual(wishbone_storage_version_basis('SETUP'),
                                 witness['version_basis'])
                self.assertIs(False, witness['reset_waveform_observed'])
                self.assertIs(False, witness['grants_reset_prerequisite'])
                self.assertIs(False, witness['routed_context_authenticated'])
                receipt = session.built_executable_receipt_document()
                self.assertEqual(receipt['build_digest'],
                                 witness['build_identity_sha256'])
                self.assertEqual(document['artifact_digest'],
                                 witness['artifact_digest'])
                self.assertEqual(
                    document['storage_observation']['digest'],
                    witness['probe_digest'])
                self.assertEqual(
                    document['storage_observation']['source_contract'][
                        'digest'], witness['source_contract_digest'])
                self.assertEqual(
                    sha256(Path(version_module.__file__).read_bytes()
                           ).hexdigest(),
                    witness['producer_source_sha256'])
                with self.assertRaises(ValueError):
                    authority.consume(token)
            finally:
                session.end_case()


if __name__ == '__main__':
    unittest.main()
