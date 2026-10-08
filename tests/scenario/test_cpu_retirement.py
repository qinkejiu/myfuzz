"""Independent frozen-response and ordered-beat retirement contract tests."""
import copy
import unittest
from myfuzz.scenario.cpu_retirement import CpuRetirementMatcher

SCOPE = dict(execution_id='run', source_component='cpu', source_epoch=0)
SW = 0x0020a023
LW = 0x0000a183
SB = 0x00208023
NOP = 0x13


def key(seq, channel='data', case='A', epoch=0):
    return dict(SCOPE, source_epoch=epoch, testcase_id=case, channel_id=channel,
                source_sequence=seq)


def fetch(insn=SW, writer='action-A', seq=1, pc=0x100, epoch=0):
    return dict(kind='instr_response', transaction=key(seq, 'instr', epoch=epoch),
                address=pc, error=0, rdata=insn, snapshot=dict(address=pc, value=insn,
                data_hex=insn.to_bytes(4, 'little').hex(), versions=((0, seq),)*4,
                writer_event_ids=(writer,)*4, writer_kinds=('INSTRUCTION_SOURCE',)*4))


def beat(seq=1, address=0x200, write=True, be=15, wdata=0x44332211, case='A'):
    return dict(kind='data_accept', transaction=key(seq, case=case),
                raw_address=address, aligned_address=address & ~3,
                address=address, write=int(write), be=be, wdata=wdata)


def response(seq=1, rdata=0, error=0, case='A'):
    return dict(kind='data_response', transaction=key(seq, case=case), rdata=rdata, error=error)


def retire(insn=SW, order=0, address=0x200, data=0x44332211, epoch=0):
    load = insn == LW
    width = 1 if insn == SB else 4
    return dict(SCOPE, source_epoch=epoch, kind='cpu_retire', order=order,
                pc_rdata=0x100, insn=insn, trap=0, intr=0,
                rs1_addr=1, rs1_rdata=address, rs2_addr=2, rs2_rdata=data,
                rd_addr=3 if load else 0, rd_wdata=data if load else 0,
                mem_addr=address, mem_rmask=(1 << width)-1 if load else 0,
                mem_wmask=0 if load else (1 << width)-1,
                mem_rdata=data if load else 0, mem_wdata=0 if load else data)


class CpuRetirementTests(unittest.TestCase):
    def setUp(self):
        self.matcher = CpuRetirementMatcher(max_pending=16)

    def ready(self, insn=SW, **kwargs):
        self.matcher.consume(fetch(insn))
        self.matcher.consume(beat(**kwargs))
        self.matcher.consume(response())

    def match(self, event=None):
        return self.matcher.consume(event or retire())[0]

    def test_ordered_store_preserves_actual_identity_and_frozen_sources(self):
        f = fetch()
        self.matcher.consume(f)
        f['snapshot']['writer_event_ids'] = ('mutated',)*4
        self.matcher.consume(beat())
        self.matcher.consume(response())
        result = self.match()
        self.assertEqual('accepted', result['status'])
        self.assertEqual([key(1)], result['transaction_keys'])
        self.assertEqual(['action-A'], result['source_refs'])
        self.assertEqual('retired_instruction_origin', result['proof_scope'])

    def test_unresponded_request_is_incomplete(self):
        self.matcher.consume(fetch())
        self.matcher.consume(beat())
        self.assertEqual('incomplete', self.match()['status'])

    def test_identical_later_beat_never_skips_fifo_head(self):
        self.matcher.consume(fetch())
        self.matcher.consume(beat(address=0x204))
        self.matcher.consume(response())
        self.matcher.consume(beat(seq=2))
        self.matcher.consume(response(seq=2))
        self.assertEqual('rejected', self.match()['status'])
        self.assertEqual(2, self.matcher.pending_data_count)

    def test_same_pc_bytes_different_writers_remain_ambiguous(self):
        self.ready()
        self.matcher.consume(fetch(writer='action-B', seq=2))
        self.assertEqual('ambiguous', self.match()['status'])

    def test_cross_case_transaction_survives_case_label(self):
        self.ready(case='A')
        event = retire()
        event['testcase_id'] = 'B'
        self.assertEqual('accepted', self.match(event)['status'])

    def test_reset_cancels_pending_and_epoch_never_reuses_sources(self):
        self.ready()
        reports = self.matcher.consume(dict(SCOPE, kind='cpu_reset', source_epoch=1))
        self.assertTrue(any(row['status'] == 'incomplete' for row in reports))
        self.assertEqual(0, self.matcher.pending_data_count)
        self.assertEqual('incomplete', self.match(retire(epoch=1))['status'])

    def test_non_instruction_byte_kind_cannot_supply_source(self):
        f = fetch()
        f['snapshot']['writer_kinds'] = ('INSTRUCTION_SOURCE',)*3 + ('STORE',)
        self.matcher.consume(f)
        self.matcher.consume(beat())
        self.matcher.consume(response())
        result = self.match()
        self.assertEqual('accepted', result['status'])
        self.assertEqual([], result['source_refs'])
        self.assertEqual('unknown', result['instruction_origin_status'])

    def test_sb_checks_lane_and_ignores_disabled_write_bytes(self):
        self.ready(SB, address=0x203, be=8, wdata=0x11000000)
        self.assertEqual('accepted', self.match(retire(SB, address=0x203))['status'])

    def test_lw_checks_response_bytes(self):
        self.matcher.consume(fetch(LW))
        self.matcher.consume(beat(write=False, wdata=0))
        self.matcher.consume(response(rdata=0x44332211))
        self.assertEqual('accepted', self.match(retire(LW))['status'])

    def test_load_response_mismatch_rejected(self):
        self.matcher.consume(fetch(LW))
        self.matcher.consume(beat(write=False))
        self.matcher.consume(response(rdata=5))
        self.assertEqual('rejected', self.match(retire(LW))['status'])

    def test_unaligned_store_two_beats(self):
        self.matcher.consume(fetch())
        self.matcher.consume(beat(address=0x203, be=8, wdata=0x11000000))
        self.matcher.consume(response())
        self.matcher.consume(beat(seq=2, address=0x204, be=7, wdata=0x00443322))
        self.matcher.consume(response(seq=2))
        result = self.match(retire(address=0x203))
        self.assertEqual('accepted', result['status'])
        self.assertEqual([key(1), key(2)], result['transaction_keys'])

    def test_trap_and_unsupported_do_not_consume_data(self):
        self.ready()
        trapped = retire()
        trapped['trap'] = 1
        self.assertEqual('rejected', self.match(trapped)['status'])
        unsupported = retire(0x0000006f, order=1)
        self.assertEqual('rejected', self.match(unsupported)['status'])
        self.assertEqual(1, self.matcher.pending_data_count)

    def test_duplicate_retire_order_rejected(self):
        self.ready()
        self.match()
        self.assertEqual('rejected', self.match()['status'])

    def test_nop_has_no_memory_effect_and_no_operand_origin(self):
        self.matcher.consume(fetch(NOP))
        r = retire(NOP)
        r.update(rs1_addr=0, rs1_rdata=0, rs2_addr=0, rs2_rdata=0,
                 rd_addr=0, rd_wdata=0, mem_rmask=0, mem_wmask=0)
        result = self.match(r)
        self.assertEqual('accepted', result['status'])
        self.assertEqual([], result['transaction_keys'])

    def test_absent_probe_does_not_fill_retirement_fields(self):
        self.ready()
        r = retire()
        del r['mem_wmask']
        self.assertEqual('incomplete', self.match(r)['status'])

    def test_bounded_pending_explicitly_loses_certainty(self):
        m = CpuRetirementMatcher(max_pending=1)
        m.consume(fetch())
        overflow = m.consume(fetch(writer='B', seq=2))
        self.assertTrue(any(r['status'] == 'incomplete' for r in overflow))
        m.consume(beat())
        m.consume(response())
        self.assertEqual('ambiguous', m.consume(retire())[0]['status'])

    def test_repeated_identical_frozen_fetch_does_not_exhaust_version_capacity(self):
        m = CpuRetirementMatcher(max_pending=2)
        for sequence in range(1, 6):
            event = fetch(NOP, seq=sequence)
            event['snapshot']['versions'] = ((0, 1),) * 4
            self.assertFalse(any(report['status'] == 'incomplete'
                                 for report in m.consume(event)))
        r = retire(NOP)
        r.update(rs1_addr=0, rs1_rdata=0, rd_addr=0)
        self.assertEqual('accepted', m.consume(r)[0]['status'])

    def test_coalesced_latest_fetch_identity_accepts_exact_transport_duplicate(self):
        m = CpuRetirementMatcher(max_pending=2)
        first = fetch(NOP, seq=1)
        second = fetch(NOP, seq=2)
        second['snapshot']['versions'] = first['snapshot']['versions']
        m.consume(first)
        m.consume(second)
        duplicate = m.consume(second)
        self.assertEqual('rejected', duplicate[0]['status'])
        self.assertEqual('nonmonotonic_instruction_response_identity', duplicate[0]['reason'])
        r = retire(NOP)
        r.update(rs1_addr=0, rs1_rdata=0, rd_addr=0)
        self.assertEqual('accepted', m.consume(r)[0]['status'])

    def test_long_stream_of_repeated_real_shape_fetches_preserves_bounded_versions(self):
        m = CpuRetirementMatcher(max_pending=2048)
        for sequence in range(1, 3001):
            address = 0x100 + 4 * ((sequence - 1) % 236)
            event = fetch(NOP, seq=sequence, pc=address)
            event['snapshot']['versions'] = ((0, 1),) * 4
            self.assertFalse(any(report.get('reason') == 'instruction_capacity_exceeded'
                                 for report in m.consume(event)))
        scope = ('run', 'cpu', 0)
        self.assertEqual(236, len(m._states[scope]['fetches']))
        r = retire(NOP)
        r.update(rs1_addr=0, rs1_rdata=0, rd_addr=0)
        self.assertEqual('accepted', m.consume(r)[0]['status'])

    def test_ibex_aligned_bus_address_for_unaligned_sb(self):
        self.ready(SB, address=0x200, be=8, wdata=0x11000000)
        self.assertEqual('accepted', self.match(retire(SB, address=0x203))['status'])

    def test_nonmonotonic_acceptance_identity_rejected(self):
        self.matcher.consume(beat(seq=2))
        self.assertEqual('rejected', self.matcher.consume(beat(seq=1))[0]['status'])

    def test_invalid_frozen_versions_remain_unknown(self):
        f = fetch()
        f['snapshot']['versions'] = (None,)*4
        self.matcher.consume(f)
        self.matcher.consume(beat())
        self.matcher.consume(response())
        self.assertEqual('incomplete', self.match()['status'])

    def test_reset_barrier_rejects_late_old_epoch_events(self):
        self.matcher.consume(dict(SCOPE, source_epoch=1, kind='cpu_reset'))
        self.assertEqual('rejected', self.matcher.consume(fetch())[0]['status'])

    def test_response_error_and_wrong_identity_do_not_match(self):
        self.matcher.consume(fetch())
        self.matcher.consume(beat())
        self.assertEqual('rejected', self.matcher.consume(response(seq=2))[0]['status'])
        self.matcher.consume(response(error=1))
        self.assertEqual('ambiguous', self.match()['status'])

    def test_legal_lui_and_addi_match_frozen_source(self):
        for insn, rs1, rd, value in ((0x123450b7, 0, 1, 0x12345000),
                                     (0x00508113, 1, 2, 0x205)):
            m = CpuRetirementMatcher()
            m.consume(fetch(insn))
            r = retire(insn)
            r.update(rs1_addr=rs1, rd_addr=rd, rd_wdata=value,
                     mem_rmask=0, mem_wmask=0)
            self.assertEqual('accepted', m.consume(r)[0]['status'])

    def test_xori_retirement_certifies_frozen_online_instruction_and_result(self):
        insn = 0xFFF34293  # xori x5, x6, -1
        for result_value, register, status in (
                (0xffffffa5, 6, 'accepted'),
                (0x5a, 6, 'rejected'),
                (0xffffffa5, 7, 'rejected')):
            with self.subTest(result_value=result_value, register=register):
                matcher = CpuRetirementMatcher()
                matcher.consume(fetch(insn, writer='online-xori'))
                observed = retire(insn)
                observed.update(rs1_addr=register, rs1_rdata=0x5a,
                                rd_addr=5, rd_wdata=result_value,
                                mem_rmask=0, mem_wmask=0)
                proof = matcher.consume(observed)[0]
                self.assertEqual(status, proof['status'])
                if status == 'accepted':
                    self.assertEqual(['online-xori'], proof['source_refs'])
                    self.assertEqual([], proof['transaction_keys'])

    def test_snapshot_must_equal_actual_consumed_instruction_response(self):
        f = fetch()
        f['rdata'] = NOP
        self.matcher.consume(f)
        self.matcher.consume(beat())
        self.matcher.consume(response())
        self.assertEqual('incomplete', self.match()['status'])

    def test_missing_acceptance_sequence_cannot_certify_fifo_origin(self):
        self.matcher.consume(fetch())
        self.matcher.consume(beat(seq=2))
        self.matcher.consume(response(seq=2))
        self.assertEqual('ambiguous', self.match()['status'])

    def test_malformed_failed_records_never_raise_or_certify(self):
        records = [None, [], 7, {'kind': 'data_accept', 'transaction': None},
                   {'kind': 'data_accept', 'transaction': []},
                   dict(SCOPE, kind='cpu_retire', execution_id=[])]
        for field, value in (('wdata', 'bad'), ('write', '1'), ('write', 2),
                             ('be', -1), ('be', 32), ('be', True),
                             ('raw_address', []), ('aligned_address', 'bad')):
            event = beat(); event[field] = value; records.append(event)
        for field, value in (('rdata', 'bad'), ('rdata', -1), ('error', True)):
            event = response(); event[field] = value; records.append(event)
        event = beat(); event['transaction']['testcase_id'] = []; records.append(event)
        event = beat(); del event['transaction']['testcase_id']; records.append(event)
        for record in records:
            with self.subTest(record=record):
                matcher = CpuRetirementMatcher()
                for result in matcher.consume(record):
                    self.assertNotEqual('accepted', result['status'])
                matcher.consume(fetch()); matcher.consume(beat()); matcher.consume(response())
                # Malformed observations must never throw while reading later retirement.
                matcher.consume(retire())

    def test_invalid_acceptance_scalar_cannot_equal_a_real_lane(self):
        self.matcher.consume(fetch())
        b = beat(); b['write'] = 2
        self.matcher.consume(b); self.matcher.consume(response())
        self.assertNotEqual('accepted', self.match()['status'])

    def test_out_of_range_rvfi_fields_rejected(self):
        for field, value in (('insn', SW + (1 << 32)), ('pc_rdata', -1),
                             ('mem_wdata', 0x144332211), ('trap', 2)):
            with self.subTest(field=field):
                m = CpuRetirementMatcher(); m.consume(fetch()); m.consume(beat()); m.consume(response())
                r = retire(); r[field] = value
                self.assertNotEqual('accepted', m.consume(r)[0]['status'])

    def test_unknown_repeated_fetch_never_reuses_old_unique_source(self):
        for corrupt in ('missing_snapshot', 'unknown_byte_kind', 'invalid_versions'):
            with self.subTest(corrupt=corrupt):
                m = CpuRetirementMatcher()
                m.consume(fetch()); m.consume(beat()); m.consume(response())
                unknown = fetch(seq=2)
                if corrupt == 'missing_snapshot':
                    del unknown['snapshot']
                elif corrupt == 'unknown_byte_kind':
                    unknown['snapshot']['writer_kinds'] = ('STORE',)*4
                else:
                    unknown['snapshot']['versions'] = (None,)*4
                m.consume(unknown)
                self.assertNotEqual('accepted', m.consume(retire())[0]['status'])

    def test_pinned_ibex_nonmemory_retire_can_keep_stale_rmask(self):
        self.matcher.consume(fetch(0x123450b7)); self.matcher.consume(beat()); self.matcher.consume(response())
        r = retire(0x123450b7)
        r.update(rs1_addr=0, rd_addr=1, rd_wdata=0x12345000, mem_rmask=15, mem_wmask=0)
        self.assertEqual('accepted', self.match(r)['status'])
        self.assertEqual(1, self.matcher.pending_data_count)

    def test_missing_retirement_order_cannot_reassign_pending_beat(self):
        self.ready(); self.match()
        self.matcher.consume(beat(seq=2)); self.matcher.consume(response(seq=2))
        self.assertNotEqual('accepted', self.match(retire(order=2))['status'])

    def test_bootstrap_unknown_origin_at_other_pc_does_not_poison_fuzzer_slot(self):
        boot = fetch(NOP, pc=0x80)
        boot['snapshot']['writer_kinds'] = ('INITIAL_IMAGE',)*4
        self.matcher.consume(boot)
        first = retire(NOP)
        first.update(pc_rdata=0x80, rs1_addr=0, rs1_rdata=0, rd_addr=0)
        unknown = self.match(first)
        self.assertEqual('accepted', unknown['status'])
        self.assertEqual([], unknown['source_refs'])
        self.matcher.consume(fetch(NOP, seq=2, pc=0x100))
        later = retire(NOP, order=1)
        later.update(rs1_addr=0, rs1_rdata=0, rd_addr=0)
        self.assertEqual('accepted', self.match(later)['status'])

    def test_same_pc_unknown_bootstrap_remains_ambiguity_after_later_typed_fetch(self):
        boot = fetch(NOP)
        boot['snapshot']['writer_kinds'] = ('INITIAL_IMAGE',)*4
        self.matcher.consume(boot)
        first = retire(NOP)
        first.update(rs1_addr=0, rs1_rdata=0, rd_addr=0)
        unknown = self.match(first)
        self.assertEqual('accepted', unknown['status'])
        self.assertEqual([], unknown['source_refs'])
        self.matcher.consume(fetch(NOP, seq=2))
        later = dict(first, order=1)
        self.assertEqual('ambiguous', self.match(later)['status'])

    def test_bootstrap_store_witness_consumes_head_without_inventing_source(self):
        boot = fetch(SW, pc=0x80)
        boot['snapshot']['writer_kinds'] = ('INITIAL_IMAGE',)*4
        boot['snapshot']['writer_event_ids'] = ('initial-image',)*4
        self.matcher.consume(boot); self.matcher.consume(beat()); self.matcher.consume(response())
        r = retire(); r['pc_rdata'] = 0x80
        result = self.match(r)
        self.assertEqual('accepted', result['status'])
        self.assertEqual([], result['source_refs'])
        self.assertEqual([key(1)], result['transaction_keys'])
        self.assertEqual(['INITIAL_IMAGE']*4, result['byte_cells'][0]['writer_kinds'])
        self.matcher.consume(fetch(seq=2)); self.matcher.consume(beat(seq=2)); self.matcher.consume(response(seq=2))
        later = self.match(retire(order=1))
        self.assertEqual('accepted', later['status'])
        self.assertEqual([key(2)], later['transaction_keys'])
        self.assertEqual(['action-A'], later['source_refs'])

    def test_bootstrap_load_witness_consumes_real_response_before_known_store(self):
        boot = fetch(LW, pc=0x80)
        boot['snapshot']['writer_kinds'] = ('FIRST_READ',)*4
        self.matcher.consume(boot); self.matcher.consume(beat(write=False)); self.matcher.consume(response(rdata=0x44332211))
        r = retire(LW); r['pc_rdata'] = 0x80
        result = self.match(r)
        self.assertEqual('accepted', result['status'])
        self.assertEqual([], result['source_refs'])
        self.assertEqual(0, self.matcher.pending_data_count)
        self.matcher.consume(fetch(seq=2)); self.matcher.consume(beat(seq=2)); self.matcher.consume(response(seq=2))
        self.assertEqual([key(2)], self.match(retire(order=1))['transaction_keys'])

    def test_instruction_response_sequence_gap_blocks_unique_version_claim(self):
        self.matcher.consume(fetch())
        later = fetch(seq=3)
        later['snapshot']['versions'] = ((0, 1),)*4
        self.matcher.consume(later)
        self.matcher.consume(beat()); self.matcher.consume(response())
        self.assertEqual('ambiguous', self.match()['status'])

    def test_first_instruction_response_sequence_after_one_is_incomplete_stream(self):
        self.matcher.consume(fetch(seq=2)); self.matcher.consume(beat()); self.matcher.consume(response())
        self.assertEqual('ambiguous', self.match()['status'])

    def test_duplicate_instruction_response_identity_never_adds_source_version(self):
        self.matcher.consume(fetch())
        duplicate = self.matcher.consume(fetch(writer='forged-new-writer'))
        self.assertEqual('rejected', duplicate[0]['status'])
        self.matcher.consume(beat()); self.matcher.consume(response())
        result = self.match()
        self.assertEqual(['action-A'], result['source_refs'])
        self.assertEqual(1, len(result['instruction_responses']))

    def test_instruction_sequence_restarts_only_in_new_epoch(self):
        self.matcher.consume(fetch())
        self.matcher.consume(dict(SCOPE, kind='cpu_reset', source_epoch=1))
        self.matcher.consume(fetch(NOP, epoch=1))
        r = retire(NOP, epoch=1)
        r.update(rs1_addr=0, rs1_rdata=0, rd_addr=0)
        self.assertEqual('accepted', self.match(r)['status'])

    def test_unsupported_compressed_store_cannot_reassign_its_beat_to_later_sw(self):
        self.matcher.consume(beat()); self.matcher.consume(response())
        self.assertEqual('rejected', self.match(retire(insn=0xc000))['status'])
        self.assertEqual(1, self.matcher.pending_data_count)
        self.matcher.consume(fetch()); self.matcher.consume(beat(seq=2)); self.matcher.consume(response(seq=2))
        later = self.match(retire(order=1))
        self.assertNotEqual('accepted', later['status'])
        self.assertEqual(2, self.matcher.pending_data_count)

    def test_all_unsupported_memory_classes_preserve_beats_and_block_reassignment(self):
        compressed = [((funct3 << 13) | quadrant)
                      for quadrant in (0, 2) for funct3 in (1, 2, 3, 5, 6, 7)]
        full = [0x00008183, 0x00209023, 0x0000a187, 0x0020a027, 0x0020a1af]
        for insn in compressed + full:
            with self.subTest(insn=hex(insn)):
                m = CpuRetirementMatcher()
                m.consume(beat()); m.consume(response())
                self.assertEqual('rejected', m.consume(retire(insn=insn))[0]['status'])
                m.consume(fetch()); m.consume(beat(seq=2)); m.consume(response(seq=2))
                later = m.consume(retire(order=1))[0]
                self.assertEqual('ambiguous', later['status'])
                self.assertEqual(2, m.pending_data_count)

    def test_trap_barrier_preserves_beats_until_explicit_reset(self):
        self.ready()
        trapped = retire(); trapped['trap'] = 1
        self.assertEqual('rejected', self.match(trapped)['status'])
        self.assertEqual('ambiguous', self.match(retire(order=1))['status'])
        self.assertEqual(1, self.matcher.pending_data_count)
        self.matcher.consume(dict(SCOPE, kind='cpu_reset', source_epoch=1))
        self.matcher.consume(fetch(NOP, epoch=1))
        r = retire(NOP, epoch=1); r.update(rs1_addr=0, rs1_rdata=0, rd_addr=0)
        self.assertEqual('accepted', self.match(r)['status'])

    def test_nonmemory_unsupported_stale_masks_do_not_block_later_real_store(self):
        for insn in (0x0000006f, 0x30011073, 0x1):
            with self.subTest(insn=hex(insn)):
                m = CpuRetirementMatcher()
                m.consume(fetch()); m.consume(beat()); m.consume(response())
                unsupported = retire(insn=insn)
                unsupported.update(mem_rmask=15, mem_wmask=0)
                self.assertEqual('rejected', m.consume(unsupported)[0]['status'])
                self.assertEqual('accepted', m.consume(retire(order=1))[0]['status'])

    def test_incomplete_or_out_of_range_retirement_is_pairing_barrier(self):
        for field, value in (('insn', None), ('mem_wdata', 1 << 32), ('trap', True)):
            with self.subTest(field=field):
                m = CpuRetirementMatcher(); m.consume(fetch()); m.consume(beat()); m.consume(response())
                incomplete = retire(); incomplete[field] = value
                self.assertNotEqual('accepted', m.consume(incomplete)[0]['status'])
                m.consume(beat(seq=2)); m.consume(response(seq=2))
                self.assertNotEqual('accepted', m.consume(retire(order=1))[0]['status'])
                self.assertEqual(2, m.pending_data_count)

    def test_malformed_fullkey_or_unknown_scope_poison_existing_pairing_certainty(self):
        for kind, malformed in (('data_accept', dict(testcase_id=[])),
                                ('data_response', dict(source_sequence=None)),
                                ('instr_response', dict(testcase_id=None))):
            with self.subTest(kind=kind):
                m = CpuRetirementMatcher(); m.consume(fetch()); m.consume(beat()); m.consume(response())
                event = {'data_accept': beat, 'data_response': response, 'instr_response': fetch}[kind]()
                event['transaction'].update(malformed)
                m.consume(event)
                self.assertNotEqual('accepted', m.consume(retire())[0]['status'])
        for event in (None, {'kind': 'data_accept', 'transaction': None}):
            with self.subTest(event=event):
                m = CpuRetirementMatcher(); m.consume(fetch()); m.consume(beat()); m.consume(response())
                m.consume(event)
                self.assertNotEqual('accepted', m.consume(retire())[0]['status'])

    def test_unmatched_supported_memory_retirement_cannot_reassign_old_effect(self):
        for mismatch in ('illegal_effect', 'missing_frozen_response'):
            with self.subTest(mismatch=mismatch):
                m = CpuRetirementMatcher()
                if mismatch == 'illegal_effect':
                    m.consume(fetch())
                m.consume(beat()); m.consume(response())
                first = retire()
                if mismatch == 'illegal_effect':
                    first['rs2_rdata'] = 0
                self.assertNotEqual('accepted', m.consume(first)[0]['status'])
                if mismatch == 'missing_frozen_response':
                    m.consume(fetch())
                m.consume(beat(seq=2)); m.consume(response(seq=2))
                self.assertNotEqual('accepted', m.consume(retire(order=1))[0]['status'])
                self.assertEqual(2, m.pending_data_count)

    def test_required_event_fields_mutation_matrix_barriers(self):
        widths = dict(order=64, pc_rdata=32, insn=32, trap=1, rs1_addr=5,
                      rs2_addr=5, rd_addr=5, rs1_rdata=32, rs2_rdata=32,
                      rd_wdata=32, mem_addr=32, mem_rmask=4, mem_wmask=4,
                      mem_rdata=32, mem_wdata=32)
        specs = [('instr_response', fetch(seq=2), {'address': 32, 'rdata': 32, 'error': 1}),
                 ('data_accept', beat(seq=2), {'raw_address': 32, 'aligned_address': 32,
                  'address': 32, 'be': 4, 'write': 1, 'wdata': 32}),
                 ('data_response', response(seq=2), {'rdata': 32, 'error': 1}),
                 ('cpu_retire', retire(), widths)]
        for kind, template, fields in specs:
            for field, bits in fields.items():
                for corrupt in (None, False, [], -1, 1 << bits, 'missing'):
                    with self.subTest(kind=kind, field=field, corrupt=corrupt):
                        m = CpuRetirementMatcher(); m.consume(fetch()); m.consume(beat()); m.consume(response())
                        malformed = copy.deepcopy(template)
                        if corrupt == 'missing':
                            del malformed[field]
                        else:
                            malformed[field] = corrupt
                        m.consume(malformed)
                        self.assertNotEqual('accepted', m.consume(retire(order=1))[0]['status'])

    def test_instruction_address_missing_cannot_hide_new_frozen_version(self):
        for value in (None, False, [], -1, 1 << 32):
            with self.subTest(value=value):
                m = CpuRetirementMatcher(); m.consume(fetch())
                later = fetch(seq=2, writer='writer-B'); later['address'] = value
                m.consume(later); m.consume(beat()); m.consume(response())
                self.assertNotEqual('accepted', m.consume(retire())[0]['status'])

    def test_full_transaction_identity_matrix_and_extra_fields_barrier(self):
        templates = (fetch(seq=2), beat(seq=2), response(seq=2))
        for template in templates:
            for field in key(1):
                values = (None, False, [], 'missing')
                if field in ('source_epoch', 'source_sequence'):
                    values += (-1, 1 << 64)
                for value in values:
                    with self.subTest(kind=template['kind'], field=field, value=value):
                        m = CpuRetirementMatcher(); m.consume(fetch()); m.consume(beat()); m.consume(response())
                        malformed = copy.deepcopy(template)
                        if value == 'missing': del malformed['transaction'][field]
                        else: malformed['transaction'][field] = value
                        m.consume(malformed)
                        self.assertNotEqual('accepted', m.consume(retire())[0]['status'])
            m = CpuRetirementMatcher(); m.consume(fetch()); m.consume(beat()); m.consume(response())
            malformed = copy.deepcopy(template); malformed['transaction']['extra_identity'] = 'unknown'
            m.consume(malformed)
            self.assertNotEqual('accepted', m.consume(retire())[0]['status'])
            malformed = copy.deepcopy(template)
            malformed['transaction']['channel_id'] = 'data' if template['kind'] == 'instr_response' else 'instr'
            m = CpuRetirementMatcher(); m.consume(fetch()); m.consume(beat()); m.consume(response())
            m.consume(malformed)
            self.assertNotEqual('accepted', m.consume(retire())[0]['status'])

    def test_observed_address_triplet_and_top_scope_mismatch_barrier(self):
        variants = [dict(address=0x204), dict(aligned_address=0x204),
                    dict(source_component='another-cpu'), dict(source_epoch=1),
                    dict(execution_id='another-run'), dict(reset_epoch=1)]
        for values in variants:
            with self.subTest(values=values):
                m = CpuRetirementMatcher(); m.consume(fetch()); m.consume(beat()); m.consume(response())
                malformed = beat(seq=2); malformed.update(values); m.consume(malformed)
                self.assertNotEqual('accepted', m.consume(retire())[0]['status'])

    def test_unknown_scope_before_first_valid_record_is_persistent_barrier(self):
        for unknown in (None, dict(kind='instr_response', transaction=None)):
            with self.subTest(unknown=unknown):
                m = CpuRetirementMatcher(); m.consume(unknown)
                m.consume(fetch()); m.consume(beat()); m.consume(response())
                self.assertNotEqual('accepted', m.consume(retire())[0]['status'])
                m.consume(dict(SCOPE, kind='cpu_reset', source_epoch=1))
                m.consume(fetch(NOP, epoch=1))
                r = retire(NOP, epoch=1); r.update(rs1_addr=0, rs1_rdata=0, rd_addr=0)
                self.assertEqual('accepted', m.consume(r)[0]['status'])
                # Reset restores this known CPU/epoch, not another never-reset CPU.
                f = fetch(); f['transaction']['source_component'] = 'other'; m.consume(f)
                b = beat(); b['transaction']['source_component'] = 'other'; m.consume(b)
                rsp = response(); rsp['transaction']['source_component'] = 'other'; m.consume(rsp)
                r = retire(); r['source_component'] = 'other'
                self.assertNotEqual('accepted', m.consume(r)[0]['status'])

    def test_flush_never_erases_existing_memory_effect_barrier(self):
        self.ready(); trapped = retire(); trapped['trap'] = 1; self.match(trapped)
        self.matcher.consume(dict(SCOPE, kind='cpu_flush'))
        self.matcher.consume(fetch(seq=2)); self.matcher.consume(beat(seq=2)); self.matcher.consume(response(seq=2))
        self.assertNotEqual('accepted', self.match(retire(order=1))['status'])

    def test_invalid_frozen_snapshot_at_other_pc_is_stream_schema_barrier(self):
        for field in ('value', 'data_hex', 'versions', 'writer_event_ids', 'writer_kinds'):
            for value in (None, False, [], 'missing'):
                with self.subTest(field=field, value=value):
                    m = CpuRetirementMatcher(); m.consume(fetch()); m.consume(beat()); m.consume(response())
                    invalid = fetch(seq=2, pc=0x104)
                    if value == 'missing': del invalid['snapshot'][field]
                    else: invalid['snapshot'][field] = value
                    m.consume(invalid)
                    self.assertNotEqual('accepted', m.consume(retire())[0]['status'])

    def test_reset_flush_required_scope_matrix_and_no_transaction_scope_fallback(self):
        for kind in ('cpu_reset', 'cpu_flush'):
            for field in SCOPE:
                for value in (None, False, [], -1, 'missing'):
                    with self.subTest(kind=kind, field=field, value=value):
                        m = CpuRetirementMatcher(); m.consume(fetch()); m.consume(beat()); m.consume(response())
                        invalid = dict(SCOPE, kind=kind)
                        if value == 'missing': del invalid[field]
                        else: invalid[field] = value
                        m.consume(invalid)
                        self.assertNotEqual('accepted', m.consume(retire())[0]['status'])
            m = CpuRetirementMatcher(); m.consume(fetch()); m.consume(beat()); m.consume(response())
            m.consume(dict(kind=kind, transaction=key(1)))
            self.assertNotEqual('accepted', m.consume(retire())[0]['status'])

    def test_invalid_explicit_rvfi_valid_and_request_echo_are_barriers(self):
        for value in (0, False, None, [], 2):
            with self.subTest(valid=value):
                m = CpuRetirementMatcher(); m.consume(fetch()); m.consume(beat()); m.consume(response())
                invalid = retire(); invalid['valid'] = value
                self.assertNotEqual('accepted', m.consume(invalid)[0]['status'])
                self.assertNotEqual('accepted', m.consume(retire(order=1))[0]['status'])
        m = CpuRetirementMatcher(); m.consume(fetch()); m.consume(beat())
        invalid = dict(response(), write=0)
        m.consume(invalid); m.consume(response())
        self.assertNotEqual('accepted', m.consume(retire())[0]['status'])

    def test_unexpected_response_identity_is_missing_stream_barrier(self):
        self.ready()
        self.matcher.consume(response(seq=2))
        self.assertNotEqual('accepted', self.match()['status'])

    def test_global_unknown_gap_does_not_disappear_before_another_scope_reset(self):
        m = CpuRetirementMatcher(); m.consume(None)
        m.consume(dict(SCOPE, kind='cpu_reset', source_epoch=1))
        m.consume(fetch(NOP, epoch=1))
        m.consume(None)
        r = retire(NOP, epoch=1); r.update(rs1_addr=0, rs1_rdata=0, rd_addr=0)
        self.assertNotEqual('accepted', m.consume(r)[0]['status'])

    def test_verified_duplicate_response_has_no_new_effect_or_gap(self):
        self.ready()
        self.assertEqual('rejected', self.matcher.consume(response())[0]['status'])
        self.assertEqual('accepted', self.match()['status'])

    def test_conflicting_stream_component_is_global_identity_barrier(self):
        self.ready()
        invalid = beat(seq=2); invalid['component'] = 'other-owner'
        self.matcher.consume(invalid)
        self.assertNotEqual('accepted', self.match()['status'])

    def test_known_reset_restores_its_scope_after_global_capacity_loss(self):
        m = CpuRetirementMatcher(max_pending=1)
        m.consume(fetch())
        other = fetch(); other['transaction']['source_component'] = 'other'
        m.consume(other)
        m.consume(dict(SCOPE, kind='cpu_reset', source_epoch=1))
        m.consume(fetch(NOP, epoch=1))
        r = retire(NOP, epoch=1); r.update(rs1_addr=0, rs1_rdata=0, rd_addr=0)
        self.assertEqual('accepted', m.consume(r)[0]['status'])

    def test_replayed_reset_marker_cannot_clear_later_global_uncertainty(self):
        self.matcher.consume(dict(SCOPE, kind='cpu_reset', source_epoch=1))
        self.matcher.consume(fetch(NOP, epoch=1))
        self.matcher.consume(None)
        self.matcher.consume(dict(SCOPE, kind='cpu_reset', source_epoch=1))
        self.matcher.consume(fetch(NOP, epoch=1))
        r = retire(NOP, epoch=1); r.update(rs1_addr=0, rs1_rdata=0, rd_addr=0)
        self.assertNotEqual('accepted', self.match(r)['status'])

    def test_reset_epoch_must_advance_an_already_observed_cpu_epoch(self):
        self.ready()
        result = self.matcher.consume(dict(SCOPE, kind='cpu_reset'))
        self.assertEqual('rejected', result[0]['status'])
        self.assertEqual(1, self.matcher.pending_data_count)
        self.assertNotEqual('accepted', self.match()['status'])

    def test_duplicate_fullkey_payload_conflict_is_barrier_but_verified_duplicate_is_not(self):
        for which in ('instruction', 'data'):
            with self.subTest(which=which):
                m = CpuRetirementMatcher(); m.consume(fetch()); m.consume(beat()); m.consume(response())
                conflict = fetch(writer='new-writer') if which == 'instruction' else beat(wdata=7)
                m.consume(conflict)
                self.assertNotEqual('accepted', m.consume(retire())[0]['status'])
        m = CpuRetirementMatcher(); m.consume(fetch()); m.consume(beat()); m.consume(response())
        m.consume(fetch()); m.consume(beat())
        self.assertEqual('accepted', m.consume(retire())[0]['status'])

    def test_failed_duplicate_instruction_response_cannot_throw_on_unusable_snapshot(self):
        self.ready()
        failed = fetch(); failed.update(error=1, snapshot={'versions': [None]})
        self.matcher.consume(failed)
        self.assertNotEqual('accepted', self.match()['status'])

    def test_response_cannot_precede_acceptance(self):
        result = self.matcher.consume(response())[0]
        self.assertEqual('rejected', result['status'])

    def test_arithmetic_accepted_witness_is_field_for_field_unchanged(self):
        """XORI/ADDI/LUI keep their exact accepted witness, key set included."""
        cases = (('xori', 0xFFF34293, 'online-xori', 6, 0x5a, 5, 0xffffffa5),
                 ('addi', 0x00508113, 'online-addi', 1, 0x200, 2, 0x205),
                 ('lui', 0x123450b7, 'online-lui', 0, 0, 1, 0x12345000))
        for label, insn, writer, rs1, rs1_rdata, rd, value in cases:
            with self.subTest(operation=label):
                matcher = CpuRetirementMatcher()
                frozen = fetch(insn, writer=writer)
                matcher.consume(frozen)
                observed = retire(insn)
                observed.update(rs1_addr=rs1, rs1_rdata=rs1_rdata, rd_addr=rd,
                                rd_wdata=value, mem_rmask=0, mem_wmask=0)
                proof = matcher.consume(observed)[0]
                expected = {
                    'schema_version': 'cpu_retirement_match.v1',
                    'status': 'accepted', 'reason': 'matched_instruction',
                    'proof_scope': 'retired_instruction_origin',
                    'cpu_scope': dict(SCOPE), 'order': 0, 'pc': 0x100, 'insn': insn,
                    'source_refs': [writer],
                    'instruction_responses': [frozen],
                    'transaction_keys': [],
                    'instruction_origin_status': 'typed_writer_refs',
                    'byte_cells': [{'writer_event_ids': [writer] * 4,
                                    'writer_kinds': ['INSTRUCTION_SOURCE'] * 4,
                                    'versions': [(0, 1)] * 4}]}
                self.assertEqual(sorted(expected), sorted(proof))
                for name, pinned in expected.items():
                    self.assertEqual(pinned, proof[name], name)

    def test_store_accepted_witness_is_field_for_field_unchanged(self):
        """The ordered SW path, including data_beats, keeps every field."""
        self.ready()
        proof = self.match()
        expected = {
            'schema_version': 'cpu_retirement_match.v1',
            'status': 'accepted',
            'reason': 'matched_ordered_retired_transaction',
            'proof_scope': 'retired_instruction_origin',
            'cpu_scope': dict(SCOPE), 'order': 0, 'pc': 0x100, 'insn': SW,
            'source_refs': ['action-A'],
            'instruction_responses': [fetch()],
            'transaction_keys': [key(1)],
            'instruction_origin_status': 'typed_writer_refs',
            'byte_cells': [{'writer_event_ids': ['action-A'] * 4,
                            'writer_kinds': ['INSTRUCTION_SOURCE'] * 4,
                            'versions': [(0, 1)] * 4}],
            'data_beats': [{**beat(), 'response': response()}]}
        self.assertEqual(sorted(expected), sorted(proof))
        for name, pinned in expected.items():
            self.assertEqual(pinned, proof[name], name)

    def test_ori_andi_and_neighbouring_op_imm_funct3_stay_unsupported(self):
        """Only funct3 1/5 on opcode 0x13 are shifts; 2, 3, 6, 7 stay refused."""
        base = 0x00731293  # slli x5, x6, 7: funct3 1, the new legal neighbour
        for funct3 in (2, 3, 6, 7):
            with self.subTest(funct3=funct3):
                insn = (base & ~(7 << 12)) | (funct3 << 12)
                self.assertEqual(funct3, (insn >> 12) & 7)
                m = CpuRetirementMatcher()
                m.consume(fetch()); m.consume(beat()); m.consume(response())
                unsupported = retire(insn)
                unsupported.update(rs1_addr=6, rs1_rdata=0x80000001, rd_addr=5,
                                   rd_wdata=0x80, mem_rmask=15, mem_wmask=0)
                proof = m.consume(unsupported)[0]
                self.assertEqual('rejected', proof['status'])
                self.assertEqual('unsupported_instruction_observation_only',
                                 proof['reason'])
                self.assertEqual([], proof['transaction_keys'])
                self.assertEqual(1, m.pending_data_count)
                self.assertEqual('accepted', m.consume(retire(order=1))[0]['status'])

    def test_added_serial_sideband_field_never_changes_retirement_matching(self):
        """A retirement carrying the measured serial observation matches the same way."""
        self.ready()
        plain = self.match()
        self.assertEqual('accepted', plain['status'])
        self.matcher = CpuRetirementMatcher(max_pending=16)
        self.ready()
        enriched = retire()
        enriched['irq_serial_observation'] = {
            'schema_version': 'ibex_irq_serial_observation.v1',
            'sampling': 'post_rising', 'width_bits': 64,
            'zero_semantics': 'no_provable_source_lineage',
            'decision': {'physical_port': 'irq_decision_serial', 'phase': 'post',
                         'value': 0, 'status': 'observed'},
            'retirement': {'physical_port': 'irq_retirement_serial', 'phase': 'post',
                           'value': 4, 'status': 'observed'}}
        result = self.match(enriched)
        self.assertEqual(plain['status'], result['status'])
        self.assertEqual(plain['reason'], result['reason'])
        self.assertEqual(plain['order'], result['order'])
        self.assertEqual(plain['source_refs'], result['source_refs'])


if __name__ == '__main__':
    unittest.main()
