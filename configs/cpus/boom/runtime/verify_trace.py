#!/usr/bin/env python3
"""Check accepted TileLink events and the real BOOM RAM completion report."""
import argparse
import collections
import json
from pathlib import Path


def verify(path):
    expected = collections.deque()
    sinks = set()
    completed_grants = set()
    pending_c = {}
    counts = collections.Counter()
    result = None
    for line in path.read_text().splitlines():
        event = json.loads(line)
        if 'result' in event:
            result = event
            continue
        channel = event['channel']
        counts[channel] += 1
        opcode = event.get('opcode')
        if channel == 'A':
            assert opcode in (0, 1, 4, 6, 7), event
            # This program sends single-beat puts and block gets/acquires.
            assert opcode not in (0, 1) or event['size'] <= 3, event
            d_opcode = {0: 0, 1: 0, 4: 1, 6: 5, 7: 4}[opcode]
            beats = max(1, 1 << max(0, event['size'] - 3)) if opcode in (4, 6) else 1
            param = (1 if event['param'] == 0 else 0) if opcode in (6, 7) else 0
            expected.append([d_opcode, event['size'], event['source'], beats, 0, param, None])
        elif channel == 'C':
            assert opcode in (6, 7), event
            key = (event['source'], event['address'], event['size'], opcode)
            pending_c[key] = pending_c.get(key, 0) + 1
            beats = max(1, 1 << max(0, event['size'] - 3)) if opcode == 7 else 1
            if pending_c[key] == beats:
                del pending_c[key]
                expected.append([6, event['size'], event['source'], 1, 0, 0, None])
        elif channel == 'D':
            assert expected, event
            current = expected[0]
            assert [opcode, event['size'], event['source']] == current[:3], (event, current)
            assert event['beat'] == current[4] and event['param'] == current[5], (event, current)
            if opcode in (4, 5):
                if current[4] == 0:
                    assert event['sink'] not in sinks, event
                    sinks.add(event['sink'])
                    current[6] = event['sink']
                assert event['sink'] == current[6], event
            current[4] += 1
            if current[4] == current[3]:
                if opcode in (4, 5):
                    completed_grants.add(event['sink'])
                expected.popleft()
        elif channel == 'E':
            assert event['sink'] in completed_grants, event
            completed_grants.remove(event['sink'])
            sinks.remove(event['sink'])
        else:
            raise AssertionError(event)
    assert not expected and not sinks and not pending_c and not completed_grants
    assert result and result['result'] == 'pass', result
    assert result['first_load_result'] == result['reload_result'] == result['cached_ram_value'] == 0x123
    assert result['A_Acquire'] == result['E_GrantAck'] > 0
    assert result['C_ReleaseData'] > 0 and result['A_Put'] == 2 and result['B_valid'] == 0
    assert counts['D'] == result['D_beats'] and counts['E'] == result['E_GrantAck']
    return {'checked_events': sum(counts.values()), 'channel_events': dict(counts), 'result': result}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('trace', type=Path)
    print(json.dumps(verify(parser.parse_args().trace), indent=2))
