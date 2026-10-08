"""Conservative RV32I retirement witnesses from frozen responses and ordered beats.

consume() accepts instr_response (snapshot=asdict(ReadSnapshot)), data_accept,
data_response, cpu_retire and cpu_reset. Transaction identities are full ledger
key dictionaries. CPU scope excludes testcase_id: a running CPU may cross cases.
Returned detached dictionaries explicitly describe evidence limits. Instruction
origin is never operand taint. Unsupported instructions do not consume beats.
"""
from __future__ import annotations

from collections import OrderedDict, deque
from copy import deepcopy


_IDENTITY = ('execution_id', 'source_component', 'source_epoch')
_KEY = ('execution_id', 'testcase_id', 'source_component', 'source_epoch',
        'channel_id', 'source_sequence')
_FIELDS = ('order', 'pc_rdata', 'insn', 'trap', 'rs1_addr', 'rs1_rdata',
           'rs2_addr', 'rs2_rdata', 'rd_addr', 'rd_wdata', 'mem_addr',
           'mem_rmask', 'mem_wmask', 'mem_rdata', 'mem_wdata')


def _scope(event):
    identity = (event.get('transaction') if event.get('kind') in
                ('instr_response', 'data_accept', 'data_response') else event)
    if not isinstance(identity, dict):
        identity = {}
    return tuple(identity.get(field) for field in _IDENTITY)


def _key(event):
    return tuple(event['transaction'].get(field) for field in _KEY)


def _uint(value, bits):
    return type(value) is int and 0 <= value < 1 << bits


def _valid_transaction(event, channel):
    transaction = event.get('transaction')
    return (isinstance(transaction, dict) and set(transaction) == set(_KEY) and
            all(type(transaction.get(field)) is str and transaction[field].strip()
                for field in ('execution_id', 'testcase_id', 'source_component', 'channel_id')) and
            transaction['channel_id'] == channel and
            _uint(transaction.get('source_epoch'), 64) and
            _uint(transaction.get('source_sequence'), 64) and transaction['source_sequence'] > 0)


def _consistent_scope(event):
    identity = event.get('transaction', event)
    if not isinstance(identity, dict):
        return False
    for name in _IDENTITY:
        if name in event and (type(event[name]) is not type(identity.get(name))
                              or event[name] != identity.get(name)):
            return False
    if 'component' in event and (type(event['component']) is not str or
                                 event['component'] != identity.get('source_component')):
        return False
    return ('reset_epoch' not in event or
            _uint(event['reset_epoch'], 64) and event['reset_epoch'] == identity.get('source_epoch'))


def _address_triplet(event):
    return (all(_uint(event.get(name), 32) for name in ('raw_address', 'aligned_address', 'address'))
            and event['address'] == event['raw_address']
            and event['aligned_address'] == event['raw_address'] & ~3)


def _valid_frozen_instruction(event):
    snapshot = event.get('snapshot')
    if not isinstance(snapshot, dict) or not _uint(snapshot.get('value'), 32):
        return False
    raw = snapshot.get('data')
    if 'data' in snapshot and not isinstance(raw, bytes):
        return False
    if 'data_hex' in snapshot:
        value = snapshot['data_hex']
        if type(value) is not str or len(value) != 8:
            return False
        try:
            encoded = bytes.fromhex(value)
        except ValueError:
            return False
        if raw is not None and raw != encoded:
            return False
        raw = encoded
    if not isinstance(raw, bytes) or len(raw) != 4:
        return False
    if int.from_bytes(raw, 'little') != snapshot['value'] or snapshot['value'] != event['rdata']:
        return False
    if 'address' in snapshot and (not _uint(snapshot['address'], 32) or snapshot['address'] != event['address']):
        return False
    for name in ('writer_kinds', 'writer_event_ids', 'versions'):
        if not isinstance(snapshot.get(name), (tuple, list)) or len(snapshot[name]) != 4:
            return False
    if any(type(kind) is not str or kind not in
           ('INSTRUCTION_SOURCE', 'INITIAL_IMAGE', 'FIRST_READ', 'STORE') for kind in snapshot['writer_kinds']):
        return False
    if any(type(ref) is not str or not ref.strip() for ref in snapshot['writer_event_ids']):
        return False
    return all(isinstance(version, (tuple, list)) and len(version) == 2 and
               all(_uint(part, 64) for part in version) for version in snapshot['versions'])


def _instruction_signature(event):
    snapshot = event.get('snapshot')
    if event['error'] != 0 or not isinstance(snapshot, dict):
        return (event['address'], event['rdata'], event['error'], None)
    return (event['address'], event['rdata'], event['error'], snapshot.get('value'),
            tuple(snapshot.get('writer_event_ids', ())), tuple(snapshot.get('writer_kinds', ())),
            tuple(tuple(version) for version in snapshot.get('versions', ())))


def _memory_encoding(insn):
    """Classify potential ISA memory effects without stale RVFI LSU masks.

    Include compressed integer/floating load/store groups and standard scalar,
    floating/vector load/store and atomic major opcodes. Reserved encodings in
    these groups conservatively invalidate pairing; they are never consumed.
    """
    if insn & 3 != 3:
        return (insn & 3) in (0, 2) and ((insn >> 13) & 7) in (1, 2, 3, 5, 6, 7)
    return (insn & 127) in (0x03, 0x23, 0x07, 0x27, 0x2f)


def _signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def _shift_operation(insn, opcode, funct3):
    """Name a legal RV32I OP-IMM shift, or None when its word is reserved.

    SLLI/SRLI/SRAI are opcode 0x13 with funct3 1 (SLLI) or 5 (SRLI/SRAI) and
    take their operation from the reserved funct7 = insn[31:25]: it must be
    exactly zero for SLLI and SRLI and exactly 0b0100000 for SRAI (imm[10]).
    Any other funct7 leaves the word reserved, so it is never re-read as a
    wider shamt. shamt is exactly insn[24:20] and therefore always below 32.
    """
    if opcode != 0x13 or funct3 not in (1, 5):
        return None
    funct7 = insn >> 25
    if funct7 == 0:
        return 'slli' if funct3 == 1 else 'srli'
    return 'srai' if funct3 == 5 and funct7 == 0b0100000 else None


def _shift_result(operation, rs1_rdata, shamt):
    """Apply one RV32I shift-immediate result, truncated to 32 bits."""
    if operation == 'slli':
        return (rs1_rdata << shamt) & 0xffffffff
    if operation == 'srli':
        return rs1_rdata >> shamt
    return (_signed(rs1_rdata, 32) >> shamt) & 0xffffffff


class CpuRetirementMatcher:
    """Incremental bounded matcher; no full event history or nearest-event guess.

    max_pending bounds instruction versions, data beats and CPU scopes. On
    eviction certainty is explicitly degraded until a real reset barrier.
    consume must be called in measured event order, including actual consumed
    instruction/data responses before retirement from the same edge.
    """
    def __init__(self, *, max_pending=256):
        if type(max_pending) is not int or max_pending < 1:
            raise ValueError('max_pending must be positive')
        self.max_pending = max_pending
        self._states = {}
        self._scope_overflow = False
        self._reset_epochs = {}
        self._global_uncertain = False
        self._restored_scopes = {}

    @property
    def pending_data_count(self):
        return sum(len(state['beats']) for state in self._states.values())

    def _degrade(self, scope=None):
        """Keep incomplete observations as certainty barriers, never as gaps.

        An unidentified CPU record can affect every currently pending scope.
        A known scope keeps a bounded tombstone even before its first valid
        event, so later valid fields cannot erase the missing observation.
        """
        if scope is None:
            self._global_uncertain = True
            self._restored_scopes.clear()
            for state in self._states.values():
                state['degraded'] = True
            return
        if scope not in self._states:
            if len(self._states) >= self.max_pending:
                self._states.pop(next(iter(self._states)))
                self._scope_overflow = True
            self._states[scope] = dict(fetches=deque(), fetch_signatures=set(),
                                      recent_fetches=OrderedDict(), beats=deque(), last_order=-1,
                                      last_accept_sequence=-1, last_instr_sequence=0,
                                      degraded=True)
        else:
            self._states[scope]['degraded'] = True

    def _result(self, event, status, reason, **extra):
        return dict(schema_version='cpu_retirement_match.v1', status=status,
                    reason=reason, proof_scope='retired_instruction_origin',
                    cpu_scope=dict(zip(_IDENTITY, _scope(event))),
                    order=event.get('order'), pc=event.get('pc_rdata'),
                    insn=event.get('insn'), source_refs=[],
                    instruction_responses=[], transaction_keys=[], **extra)

    def consume(self, event):
        if not isinstance(event, dict):
            self._degrade()
            return (self._result({}, 'incomplete', 'malformed_cpu_event'),)
        event = deepcopy(event)
        kind = event.get('kind')
        if kind not in ('instr_response', 'data_accept', 'data_response',
                        'cpu_retire', 'cpu_reset', 'cpu_flush'):
            return ()
        scope = _scope(event)
        if (not all(type(value) is str and value.strip() for value in scope[:2]) or
                not _uint(scope[2], 64)):
            self._degrade()
            return (self._result(event, 'incomplete', 'missing_cpu_identity'),)
        if (kind in ('cpu_retire', 'cpu_reset', 'cpu_flush') and 'transaction' in event
                or not _consistent_scope(event)):
            # The record names conflicting CPUs/epochs; neither identity wins.
            self._degrade()
            return (self._result(event, 'incomplete', 'conflicting_cpu_identity'),)
        if kind in ('instr_response', 'data_accept', 'data_response'):
            channel = 'instr' if kind == 'instr_response' else 'data'
            if not _valid_transaction(event, channel):
                self._degrade(scope)
                return (self._result(event, 'incomplete', 'malformed_transaction_identity'),)
        if kind == 'data_accept':
            fields_valid = (_address_triplet(event) and _uint(event.get('wdata'), 32)
                            and _uint(event.get('be'), 4) and _uint(event.get('write'), 1))
            if not fields_valid:
                self._degrade(scope)
                return (self._result(event, 'incomplete', 'malformed_acceptance_fields'),)
        if kind in ('instr_response', 'data_response'):
            if not _uint(event.get('rdata'), 32) or not _uint(event.get('error'), 1):
                self._degrade(scope)
                return (self._result(event, 'incomplete', 'malformed_response_fields'),)
        if kind == 'instr_response':
            if (not _uint(event.get('address'), 32) or
                    any(name in event for name in ('raw_address', 'aligned_address'))
                    and not _address_triplet(event) or
                    any(name in event and not _uint(event[name], bits)
                        for name, bits in (('write', 1), ('be', 4), ('wdata', 32))) or
                    'write' in event and event['write'] != 0):
                self._degrade(scope)
                return (self._result(event, 'incomplete', 'malformed_instruction_response_address'),)
            if event['error'] == 0 and not _valid_frozen_instruction(event):
                self._degrade(scope)
                return (self._result(event, 'incomplete', 'malformed_frozen_instruction_snapshot'),)
        if kind == 'data_response':
            if (any(name in event for name in ('raw_address', 'aligned_address', 'address'))
                    and not _address_triplet(event) or
                    any(name in event and not _uint(event[name], bits)
                        for name, bits in (('write', 1), ('be', 4), ('wdata', 32)))):
                self._degrade(scope)
                return (self._result(event, 'incomplete', 'malformed_response_request_echo'),)
        if kind == 'cpu_reset':
            observed_epochs = [existing[2] for existing in self._states if existing[:2] == scope[:2]]
            if scope[:2] in self._reset_epochs:
                observed_epochs.append(self._reset_epochs[scope[:2]])
            if observed_epochs and scope[2] <= max(observed_epochs):
                self._degrade(scope)
                return (self._result(event, 'rejected', 'reset_epoch_did_not_advance'),)
            if len(self._reset_epochs) >= self.max_pending and scope[:2] not in self._reset_epochs:
                # A forgotten barrier must never enable old-epoch certification.
                self._scope_overflow = True
                self._reset_epochs.pop(next(iter(self._reset_epochs)))
            self._reset_epochs[scope[:2]] = max(scope[2], self._reset_epochs.get(scope[:2], 0))
        if scope[2] < self._reset_epochs.get(scope[:2], 0):
            return (self._result(event, 'rejected', 'event_precedes_reset_epoch'),)
        if kind == 'cpu_flush':
            self._degrade(scope)
            return (self._result(event, 'incomplete', 'cpu_flush_pairing_barrier'),)
        if kind == 'cpu_reset':
            if len(self._restored_scopes) >= self.max_pending and scope not in self._restored_scopes:
                self._restored_scopes.pop(next(iter(self._restored_scopes)))
            self._restored_scopes[scope] = True
            reports = []
            for existing in list(self._states):
                if existing[:2] == scope[:2]:
                    state = self._states.pop(existing)
                    for beat in state['beats']:
                        result = self._result(event, 'incomplete', kind + '_cancelled_pending')
                        result['transaction_keys'] = [beat['transaction']]
                        reports.append(result)
            return tuple(reports)
        reports = []
        if scope not in self._states:
            if len(self._states) >= self.max_pending:
                self._states.pop(next(iter(self._states)))
                self._scope_overflow = True
                reports.append(self._result(event, 'incomplete', 'cpu_scope_capacity_exceeded'))
            self._states[scope] = dict(fetches=deque(), fetch_signatures=set(),
                                      recent_fetches=OrderedDict(), beats=deque(),
                                      last_order=-1, last_accept_sequence=-1, last_instr_sequence=0,
                                      degraded=((self._scope_overflow or self._global_uncertain)
                                                and scope not in self._restored_scopes))
        state = self._states[scope]
        if kind == 'instr_response':
            sequence = event['transaction']['source_sequence']
            if sequence <= state['last_instr_sequence']:
                previous = next((item for item in state['fetches'] if _key(item) == _key(event)), None)
                expected = (_instruction_signature(previous) if previous is not None else
                            state['recent_fetches'].get(_key(event)))
                if expected != _instruction_signature(event):
                    self._degrade(scope)
                return (self._result(event, 'rejected', 'nonmonotonic_instruction_response_identity'),)
            if sequence != state['last_instr_sequence'] + 1:
                state['degraded'] = True
                reports.append(self._result(event, 'incomplete', 'instruction_response_sequence_gap'))
            state['last_instr_sequence'] = sequence
            if event.get('error') != 0 or not isinstance(event.get('snapshot'), dict):
                state['degraded'] = True
                reports.append(self._result(event, 'incomplete', 'missing_frozen_instruction_response'))
            else:
                signature = _instruction_signature(event)
                recent = state['recent_fetches']
                recent[_key(event)] = signature
                if len(recent) > self.max_pending:
                    recent.popitem(last=False)
                if signature not in state['fetch_signatures']:
                    state['fetches'].append(event)
                    state['fetch_signatures'].add(signature)
                    if len(state['fetches']) > self.max_pending:
                        old = state['fetches'].popleft()
                        state['fetch_signatures'].remove(_instruction_signature(old))
                        state['degraded'] = True
                        reports.append(self._result(event, 'incomplete', 'instruction_capacity_exceeded'))
        elif kind == 'data_accept':
            if (event.get('transaction', {}).get('channel_id') != 'data' or
                    any(event.get(name) is None for name in ('raw_address', 'be', 'wdata', 'write'))):
                reports.append(self._result(event, 'incomplete', 'missing_acceptance_fields'))
            elif event['transaction']['source_sequence'] <= state['last_accept_sequence']:
                previous = next((item for item in state['beats'] if _key(item) == _key(event)), None)
                fields = ('raw_address', 'aligned_address', 'address', 'write', 'be', 'wdata')
                if previous is None or any(previous.get(name) != event[name] for name in fields):
                    self._degrade(scope)
                reports.append(self._result(event, 'rejected', 'duplicate_acceptance_identity'))
            else:
                expected_sequence = max(1, state['last_accept_sequence'] + 1)
                if event['transaction']['source_sequence'] != expected_sequence:
                    state['degraded'] = True
                    reports.append(self._result(event, 'incomplete', 'acceptance_sequence_gap'))
                state['last_accept_sequence'] = event['transaction']['source_sequence']
                state['beats'].append(event)
                if len(state['beats']) > self.max_pending:
                    state['beats'].popleft()
                    state['degraded'] = True
                    reports.append(self._result(event, 'incomplete', 'data_capacity_exceeded'))
        elif kind == 'data_response':
            unanswered = next((beat for beat in state['beats'] if 'response' not in beat), None)
            echo_fields = ('raw_address', 'aligned_address', 'address', 'write', 'be', 'wdata')
            if unanswered is None or _key(unanswered) != _key(event):
                previous = next((beat for beat in state['beats'] if _key(beat) == _key(event)), None)
                response = previous.get('response') if previous else None
                duplicate = (response is not None and
                             all(response.get(name) == event.get(name) for name in ('rdata', 'error')) and
                             all(name not in event or event[name] == previous.get(name) for name in echo_fields))
                if not duplicate:
                    self._degrade(scope)
                reports.append(self._result(event, 'rejected', 'response_not_next_accepted_identity'))
            elif any(name in event and event[name] != unanswered.get(name) for name in echo_fields):
                self._degrade(scope)
                reports.append(self._result(event, 'rejected', 'response_request_identity_conflict'))
            else:
                unanswered['response'] = event
        else:
            reports.append(self._retire(event, state))
        return tuple(reports)

    def _sources(self, event, state):
        pc, insn = event['pc_rdata'], event['insn']
        candidates = []
        unknown_matching_version = False
        for response in state['fetches']:
            snapshot = response['snapshot']
            address = response['address']
            if type(address) is not int or address != pc or response.get('rdata') != insn:
                continue
            raw = snapshot.get('data')
            if not isinstance(raw, bytes):
                try:
                    raw = bytes.fromhex(snapshot.get('data_hex', ''))
                except (ValueError, TypeError):
                    unknown_matching_version = True
                    continue
            if (len(raw) < 4 or int.from_bytes(raw[:4], 'little') != insn or
                    response.get('rdata') != insn or snapshot.get('value') != insn):
                unknown_matching_version = True
                continue
            kinds = snapshot.get('writer_kinds', ())
            refs = snapshot.get('writer_event_ids', ())
            versions = snapshot.get('versions', ())
            if (not all(isinstance(values, (list, tuple)) for values in (kinds, refs, versions)) or
                    len(kinds) < 4 or len(refs) < 4 or len(versions) < 4 or
                    any(k not in ('INSTRUCTION_SOURCE', 'INITIAL_IMAGE', 'FIRST_READ', 'STORE')
                        for k in kinds[:4]) or
                    any(type(ref) is not str or not ref for ref in refs[:4]) or
                    any(not isinstance(v, (list, tuple)) or len(v) != 2 or
                        any(type(n) is not int or n < 0 for n in v) for v in versions[:4])):
                unknown_matching_version = True
                continue
            signature = (tuple(refs[:4]), tuple(tuple(v) for v in versions[:4]), tuple(kinds[:4]))
            candidates.append((signature, response))
        return candidates, unknown_matching_version

    def _retire(self, event, state):
        result = self._retire_witness(event, state)
        if (result['status'] != 'accepted' and _uint(event.get('insn'), 32)
                and _memory_encoding(event['insn'])):
            # Any unresolved retired memory effect may own the pending FIFO
            # head, regardless of whether its opcode is otherwise supported.
            state['degraded'] = True
        return result

    def _retire_witness(self, event, state):
        result = self._result(event, 'incomplete', 'missing_retirement_fields')
        if 'valid' in event and (not _uint(event['valid'], 1) or event['valid'] != 1):
            state['degraded'] = True
            result['reason'] = 'invalid_explicit_retirement_valid'
            return result
        if any(type(event.get(field)) is not int for field in _FIELDS):
            state['degraded'] = True
            return result
        widths = dict(order=64, pc_rdata=32, insn=32, trap=1,
                      rs1_addr=5, rs2_addr=5, rd_addr=5, rs1_rdata=32,
                      rs2_rdata=32, rd_wdata=32, mem_addr=32,
                      mem_rmask=4, mem_wmask=4, mem_rdata=32, mem_wdata=32)
        if any(not _uint(event[name], bits) for name, bits in widths.items()):
            state['degraded'] = True
            result.update(status='rejected', reason='out_of_range_retirement_fields')
            return result
        if event['order'] <= state['last_order']:
            result.update(status='rejected', reason='nonmonotonic_retirement_order')
            return result
        if state['last_order'] >= 0 and event['order'] != state['last_order'] + 1:
            state['degraded'] = True
        state['last_order'] = event['order']
        if event['trap']:
            state['degraded'] = True
            result.update(status='rejected', reason='trap_retirement_observation_only')
            return result
        insn = event['insn']
        opcode, funct3 = insn & 127, (insn >> 12) & 7
        operation = ('lui' if opcode == 0x37 else
                     'addi' if opcode == 0x13 and funct3 == 0 else
                     'xori' if opcode == 0x13 and funct3 == 4 else
                     'lw' if opcode == 3 and funct3 == 2 else
                     'sw' if opcode == 0x23 and funct3 == 2 else
                     'sb' if opcode == 0x23 and funct3 == 0 else
                     _shift_operation(insn, opcode, funct3))
        if operation is None or insn & 3 != 3:
            if _memory_encoding(insn):
                # A retired unsupported effect may own the FIFO head. Keep the
                # measured beats and refuse later reassignment until reset.
                state['degraded'] = True
            result.update(status='rejected', reason='unsupported_instruction_observation_only')
            return result
        sources, unknown_matching_version = self._sources(event, state)
        result['instruction_responses'] = [deepcopy(response) for _, response in sources]
        result['source_refs'] = sorted({ref for signature, _ in sources
                                        if all(kind == 'INSTRUCTION_SOURCE' for kind in signature[2])
                                        for ref in signature[0]})
        result['instruction_origin_status'] = 'typed_writer_refs' if result['source_refs'] else 'unknown'
        result['byte_cells'] = [dict(writer_event_ids=list(signature[0]),
                                     writer_kinds=list(signature[2]),
                                     versions=list(signature[1])) for signature, _ in sources]
        if not sources:
            result['reason'] = 'no_valid_frozen_instruction_witness'
            return result
        if (state['degraded'] or unknown_matching_version or
                len({signature for signature, _ in sources}) > 1):
            result.update(status='ambiguous', reason='instruction_versions_or_incomplete_stream')
            return result
        rs1, rs2, rd = (insn >> 15) & 31, (insn >> 20) & 31, (insn >> 7) & 31
        if operation in ('slli', 'srli', 'srai'):
            # The shamt the witness checks is exactly the instruction field; the
            # frame carries no shift amount to compare against. x0 discards its
            # write exactly like the arithmetic path above, but rd and rs1
            # encodings still bind. Stale LSU masks stay unread: only rd_wdata,
            # rs1_rdata and the instruction decide a register-only retirement.
            shamt = (insn >> 20) & 31
            value = _shift_result(operation, event['rs1_rdata'], shamt)
            valid = (event['rd_addr'] == rd and event['rs1_addr'] == rs1 and
                     (rd == 0 or event['rd_wdata'] == value))
            result.update(status='accepted' if valid else 'rejected',
                          reason='matched_instruction' if valid else 'illegal_register_effect')
            return result
        if operation in ('lui', 'addi', 'xori'):
            immediate = _signed(insn >> 20, 12)
            value = (insn & 0xfffff000 if operation == 'lui' else
                     (event['rs1_rdata'] + immediate) & 0xffffffff
                     if operation == 'addi' else
                     (event['rs1_rdata'] ^ immediate) & 0xffffffff)
            valid = (event['rd_addr'] == rd and (rd == 0 or event['rd_wdata'] == value)
                     # Pinned Ibex exposes stale LSU masks for non-memory
                     # retirement. The decoded opcode controls effects.
                     and (operation == 'lui' or event['rs1_addr'] == rs1))
            result.update(status='accepted' if valid else 'rejected',
                          reason='matched_instruction' if valid else 'illegal_register_effect')
            return result
        write, width = operation != 'lw', 1 if operation == 'sb' else 4
        imm = ((insn >> 25) << 5 | (insn >> 7) & 31) if write else insn >> 20
        address = (event['rs1_rdata'] + _signed(imm, 12)) & 0xffffffff
        mask = (1 << width) - 1
        if (event['rs1_addr'] != rs1 or event['mem_addr'] != address or
                event['mem_wmask'] != (mask if write else 0) or
                event['mem_rmask'] != (0 if write else mask) or
                write and (event['rs2_addr'] != rs2 or
                           event['mem_wdata'] & ((1 << (8*width))-1) !=
                           event['rs2_rdata'] & ((1 << (8*width))-1)) or
                not write and (event['rd_addr'] != rd or
                               rd != 0 and event['rd_wdata'] != event['mem_rdata'])):
            result.update(status='rejected', reason='illegal_rv32i_memory_effect')
            return result
        expected = {}
        for offset in range(width):
            byte_address = (address + offset) & 0xffffffff
            aligned, lane = byte_address & ~3, byte_address & 3
            expected.setdefault(aligned, {})[lane] = offset
        beats = list(state['beats'])[:len(expected)]
        result['transaction_keys'] = [deepcopy(beat['transaction']) for beat in beats]
        if len(beats) != len(expected):
            result['reason'] = 'missing_accepted_data_beats'
            return result
        for index, ((aligned, lanes), beat) in enumerate(zip(expected.items(), beats)):
            raw = address if index == 0 else aligned
            if (beat['raw_address'] not in (raw, aligned) or
                    beat.get('aligned_address', beat.get('address')) != aligned or
                    bool(beat['write']) != write or
                    beat['be'] != sum(1 << lane for lane in lanes)):
                result.update(status='rejected', reason='ordered_acceptance_does_not_match')
                return result
            response = beat.get('response')
            if response is None or type(response.get('rdata')) is not int or response.get('error') != 0:
                result['reason'] = 'missing_or_error_data_response'
                return result
            actual = beat['wdata'] if write else response['rdata']
            architectural = event['mem_wdata'] if write else event['mem_rdata']
            if any((actual >> (8*lane)) & 255 != (architectural >> (8*offset)) & 255
                   for lane, offset in lanes.items()):
                result.update(status='rejected', reason='enabled_byte_data_mismatch')
                return result
        result['data_beats'] = deepcopy(beats)
        for _ in beats:
            state['beats'].popleft()
        result.update(status='accepted', reason='matched_ordered_retired_transaction')
        return result
