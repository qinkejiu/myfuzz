#!/usr/bin/env python3
"""Deterministic input rules that consume one real observation per case.

Every rule here is a small pure function of the previous case's observed
record, so the next input cannot be written down before the previous case
actually ran.  The host programs print compact records only; these rules read
those records and never infer behaviour from the component profiles.
"""
import re

MASK32 = 0xFFFFFFFF
F6_MAX_WORD = 2047


def parse_host_line(line):
    """Parse one compact host record used by the feedback rules."""
    parts = line.split()
    if not parts:
        return None
    if parts[0] == 'NEED_RECORD' and len(parts) == 4 and parts[2] == 'tick':
        return dict(event='need_record', case=int(parts[1]), tick=int(parts[3]))
    if parts[0] in ('irq_source', 'irq_take', 'mret') and len(parts) >= 2:
        return dict(event=parts[0], tick=int(parts[1]))
    if parts[0] == 'ip_read' and len(parts) == 3:
        return dict(event='ip_read', tick=int(parts[1]), value=int(parts[2]))
    if parts[0] == 'case' and len(parts) >= 3:
        report = {}
        tail = parts[3:]
        for index in range(0, len(tail) - 1, 2):
            try:
                report[tail[index]] = int(tail[index + 1])
            except ValueError:
                report[tail[index]] = tail[index + 1]
        return dict(event='case', case=int(parts[1]), status=report.pop('status', parts[2]), **report)
    if parts[0] in ('dma_read', 'dma_write') and len(parts) == 4:
        return dict(event=parts[0], tick=int(parts[1]), address=int(parts[2], 16),
                    data=int(parts[3], 16))
    return None


# ---------------------------------------------------------------- F5 timer --
F5_RULE = 'timer_count_echo.v1'
F5_BASIS = ('third_party/soc-pulp-apb-timer/src/timer.sv: '
            'overflow IRQ needs TIMER==0xffff_ffff (lines 58-59); the count resets to 0 on '
            'that IRQ (lines 75-76); it advances only while CTRL[0] is set (lines 81-82)')

_F5_ROLE_SUFFIX = (('count', '_COUNT'), ('ctrl', '_CTRL'), ('cmp', '_CMP'))


def trigger_roles(registers, trigger_offsets):
    """Map the declared trigger addresses to their timer register roles."""
    names = {row.offset: row.name.upper() for row in registers}
    roles = {}
    for offset in trigger_offsets:
        name = names.get(offset)
        if name is None:
            raise ValueError('trigger offset is not a declared register: ' + str(offset))
        for role, suffix in _F5_ROLE_SUFFIX:
            if name.endswith(suffix):
                if role in roles:
                    raise ValueError('trigger registers repeat the ' + role + ' role')
                roles[role] = offset
    if set(roles) != {'count', 'ctrl', 'cmp'}:
        raise ValueError('feedback rule requires declared COUNT, CTRL and CMP trigger registers')
    return roles


def derive_timer_values(observation, trigger_offsets, roles):
    """Derive the next trigger values from the previous real ISR read.

    A stopped timer (CTRL=0) reaches the overflow value only at 0xffff_ffff, so
    the ISR reads 0; a running timer (CTRL=1) is disarmed from 0xffff_ffff by an
    arm delay and leaves a nonzero latency count for the ISR to read.  The next
    case therefore arms the timer exactly when the previous read was zero and
    takes its arm delay from the low bits of that real read.
    """
    result = observation.get('result')
    if type(result) is not int or not 0 <= result <= MASK32:
        raise ValueError('feedback needs one observed result value')
    ctrl = 0 if result else 1
    if ctrl:
        step = (result & 7) + 1
        count = (MASK32 - step) & MASK32
    else:
        step = 0
        count = MASK32
    derived = {'ctrl': ctrl, 'cmp': 0, 'count': count}
    values = []
    for offset in trigger_offsets:
        role = next((name for name, value in roles.items() if value == offset), None)
        if role is None:
            raise ValueError('trigger offset has no feedback role: ' + str(offset))
        values.append(derived[role])
    record = dict(rule=F5_RULE, basis=F5_BASIS, from_case=observation.get('case'),
                  observed={key: observation.get(key) for key in
                            ('result', 'ip_read', 'irq_tick', 'take_tick', 'install_tick')},
                  derived_next=dict(arm_delay=step, ctrl=ctrl, cmp=0, count=count, values=values))
    return values, record


class F5TimerFeedback:
    """Feed one on-demand F5 case at a time and derive the next from the last."""

    def __init__(self, trigger_offsets, roles, seed, *, cases):
        if (not isinstance(seed, (list, tuple)) or len(seed) != len(trigger_offsets)
                or any(type(value) is not int or not 0 <= value <= MASK32 for value in seed)):
            raise ValueError('feedback seed must hold one 32-bit value per trigger')
        if type(cases) is not int or cases < 1:
            raise ValueError('feedback requires a positive case count')
        self.trigger_offsets = list(trigger_offsets)
        self.roles = dict(roles)
        self.seed = list(seed)
        self.cases = cases
        self.records = []
        self.observations = []
        self._current = None

    def note(self, line):
        """Consume one host record; returns True when a case report completed."""
        event = parse_host_line(line)
        if event is None:
            return False
        if event['event'] == 'need_record':
            self._current = dict(case=event['case'], install_tick=event['tick'],
                                 result=None, ip_read=None, irq_tick=None, take_tick=None)
        elif self._current is None:
            return False
        elif event['event'] == 'irq_source':
            if self._current['irq_tick'] is None: self._current['irq_tick'] = event['tick']
        elif event['event'] == 'irq_take':
            if self._current['take_tick'] is None: self._current['take_tick'] = event['tick']
        elif event['event'] == 'ip_read':
            self._current['ip_read'] = event['value']
        elif event['event'] == 'case':
            if event['case'] != self._current['case']:
                raise RuntimeError('case report does not match the installed F5 case')
            self._current['result'] = event.get('result')
            self.observations.append(self._current)
            self._current = None
            return True
        return False

    def values(self, case_index):
        """Values to submit for case_index; may raise when feedback is missing."""
        if case_index == 0:
            return list(self.seed)
        if len(self.observations) != case_index:
            raise RuntimeError('feedback needs exactly one report per finished case')
        previous = self.observations[-1]
        if previous['case'] != case_index - 1:
            raise RuntimeError('feedback case order differs from the host request')
        values, record = derive_timer_values(previous, self.trigger_offsets, self.roles)
        record['derived_next']['case'] = case_index
        self.records.append(record)
        return values


# ------------------------------------------------------------------ F6 input --
F6_RULE = 'dma_word_increment.v1'
F6_BASIS = ('inprocess_obi_wb_dma_spike.cpp: dma_read/dma_write are the real DMA master '
            'transactions (lines 186-187) and each case is checked against the data that '
            'was actually moved (lines 190-199); the next case is derived from that data')


def words_from_raw(raw):
    if type(raw) is not bytes or len(raw) != 8:
        raise ValueError('F6 input must contain eight bytes')
    value = int.from_bytes(raw, 'little')
    if value >> 44:
        raise ValueError('F6 reserved input bits must be zero')
    words = tuple((value >> (11 * index)) & F6_MAX_WORD for index in range(4))
    if len(set(words)) != 4:
        raise ValueError('F6 words must differ')
    return words


def raw_from_words(words):
    if len(words) != 4 or any(type(word) is not int or not 0 <= word <= F6_MAX_WORD for word in words):
        raise ValueError('F6 words must be four 11-bit values')
    if len(set(words)) != 4:
        raise ValueError('F6 words must differ')
    return sum(word << (11 * index) for index, word in enumerate(words)).to_bytes(8, 'little')


def derive_f6_words(observed_words, *, step=0x101):
    """Derive the next four words from the data the DMA actually moved."""
    if len(observed_words) != 4:
        raise ValueError('feedback needs four observed DMA words')
    words, used = [], set()
    for index, word in enumerate(observed_words):
        if type(word) is not int or not 0 <= word <= F6_MAX_WORD:
            raise ValueError('observed DMA word out of range')
        derived = (word + step * (index + 1)) & F6_MAX_WORD
        while derived in used:
            derived = (derived + 1) & F6_MAX_WORD
        used.add(derived)
        words.append(derived)
    return tuple(words)


def derive_f6_record(observation, *, step=0x101):
    """Return (raw8, record) for the next case from the previous real example."""
    observed = observation.get('words')
    if not observed or len(observed) != 4:
        raise ValueError('feedback needs the four observed DMA words')
    words = derive_f6_words(tuple(observed), step=step)
    raw = raw_from_words(words)
    record = dict(rule=F6_RULE, basis=F6_BASIS, from_case=observation.get('case'),
                  observed=dict(words=list(observed), writes=observation.get('writes'),
                                reads=observation.get('reads'), irq_takes=observation.get('irq_takes')),
                  derived_next=dict(words=list(words), record=raw.hex()))
    return raw, record


def _field(value):
    """Render one observation field without breaking the single-line log format."""
    if value is None:
        return 'unknown'
    if isinstance(value, (list, tuple)):
        return ','.join(str(item) for item in value)
    return str(value)


def feedback_line(record):
    """Render one feedback record as a single log line."""
    derived = record['derived_next']
    observed = record['observed']
    fields = [f'feedback case {derived.get("case")} from_case {record.get("from_case")}',
              f'rule {record["rule"]}']
    fields += [f'observed_{key} {_field(value)}' for key, value in observed.items()]
    fields += [f'derived_{key} {_field(value)}' for key, value in derived.items()
               if key not in ('values', 'case', 'words', 'record')]
    if 'values' in derived:
        fields.append('values ' + ','.join(str(value) for value in derived['values']))
    if 'record' in derived:
        fields.append('record ' + derived['record'])
    return ' '.join(fields) + '\n'


class F6DmaFeedback:
    """Feed one on-demand F6 record at a time and derive the next from real DMA data."""

    def __init__(self, seed_raw, *, cases):
        words_from_raw(seed_raw)
        if type(cases) is not int or cases < 1:
            raise ValueError('feedback requires a positive case count')
        self.seed = bytes(seed_raw)
        self.cases = cases
        self.records = []
        self.observations = []
        self._current = None

    def note(self, line):
        """Consume one host record; returns True when a case report completed."""
        event = parse_host_line(line)
        if event is None:
            return False
        if event['event'] == 'need_record':
            self._current = dict(case=event['case'], install_tick=event['tick'],
                                 reads=[], writes=[], report=None)
        elif self._current is None:
            return False
        elif event['event'] == 'dma_read':
            self._current['reads'].append(event['data'])
        elif event['event'] == 'dma_write':
            self._current['writes'].append(event['data'])
        elif event['event'] == 'case':
            if event['case'] != self._current['case']:
                raise RuntimeError('case report does not match the installed F6 case')
            report = {key: value for key, value in event.items() if key not in ('event', 'case')}
            if len(self._current['writes']) != 4:
                raise RuntimeError('feedback needs the four observed DMA writes')
            self.observations.append(dict(case=self._current['case'],
                words=list(self._current['writes']), reads=len(self._current['reads']),
                writes=len(self._current['writes']), irq_takes=report.get('irq_takes'),
                status=report.get('status')))
            self._current = None
            return True
        return False

    def raw(self, case_index):
        """Raw eight bytes to submit for case_index; may raise when feedback is missing."""
        if case_index == 0:
            return self.seed
        if len(self.observations) != case_index:
            raise RuntimeError('feedback needs exactly one report per finished case')
        raw, record = derive_f6_record(self.observations[-1])
        record['derived_next']['case'] = case_index
        self.records.append(record)
        return raw


def hex_bytes(raw):
    if not re.fullmatch(r'[0-9a-fA-F]{16}', raw or ''):
        raise ValueError('F6 record must be eight hexadecimal bytes')
    return bytes.fromhex(raw)
