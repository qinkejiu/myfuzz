"""Strict host-side receipts for generated local RTL drivers."""
from __future__ import annotations

from dataclasses import dataclass
import json
import re


MAX_PAYLOAD_JSON_BYTES = 1024 * 1024
MAX_REPLY_LINE_BYTES = 2 * MAX_PAYLOAD_JSON_BYTES + 512
_EXECUTION = re.compile(r'[0-9a-f]{32}\Z')
_DIGEST = re.compile(r'[0-9a-f]{64}\Z')
_TOKEN = re.compile(r'[a-z0-9_]+\Z')


def _hex(token: str) -> int:
    if (not isinstance(token, str) or not token or len(token) > 16
            or re.fullmatch(r'(?:0|[1-9a-f][0-9a-f]*)', token) is None):
        raise ValueError('invalid-driver-hex')
    return int(token, 16)


def _tokens(line: str, count: int) -> list[str]:
    if not isinstance(line, str) or not line.isascii() or len(line) > MAX_REPLY_LINE_BYTES:
        raise ValueError('invalid-driver-line')
    tokens = line.split(' ')
    if len(tokens) != count or any(not part for part in tokens):
        raise ValueError('invalid-driver-arity')
    return tokens


@dataclass(frozen=True, slots=True)
class DriverReady:
    artifact_digest: str
    assert_ticks: int
    release_ticks: int


@dataclass(frozen=True, slots=True)
class DriverReceipt:
    status: str
    execution: str
    sequence: int
    tick_before: int
    tick_after: int
    new_ticks: int
    payload: dict[str, object] | None = None
    error_code: str | None = None
    error_detail: str | None = None


def parse_driver_ready(line: str, *, digest: str, assert_ticks: int,
                       release_ticks: int) -> DriverReady:
    parts = _tokens(line, 5)
    if (parts[:2] != ['READY', 'local_driver.v1'] or _DIGEST.fullmatch(parts[2]) is None
            or _DIGEST.fullmatch(digest) is None):
        raise ValueError('invalid-driver-ready')
    asserted, released = _hex(parts[3]), _hex(parts[4])
    if (parts[2], asserted, released) != (digest, assert_ticks, release_ticks):
        raise ValueError('driver-ready-identity-mismatch')
    return DriverReady(digest, asserted, released)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate-driver-json-key')
        result[key] = value
    return result


def _valid_signal_json(value: object) -> bool:
    if type(value) is str:
        return True
    if type(value) is int:
        return value >= 0
    if isinstance(value, list):
        return all(_valid_signal_json(item) for item in value)
    if isinstance(value, dict):
        return all(type(key) is str and _valid_signal_json(item)
                   for key, item in value.items())
    return False


def _payload(encoded: str, *, kind: str, before: int, after: int) -> dict[str, object]:
    if (not encoded or len(encoded) > 2 * MAX_PAYLOAD_JSON_BYTES
            or len(encoded) % 2 or re.fullmatch(r'[0-9a-f]+', encoded) is None):
        raise ValueError('invalid-driver-payload-hex')
    raw = bytes.fromhex(encoded)
    if len(raw) > MAX_PAYLOAD_JSON_BYTES:
        raise ValueError('driver-payload-too-large')
    try:
        document = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('invalid-driver-payload-json') from error
    if not _valid_signal_json(document):
        raise ValueError('invalid-driver-json-value')
    canonical = json.dumps(document, sort_keys=True, separators=(',', ':'),
                           ensure_ascii=False).encode('utf-8')
    if canonical != raw:
        raise ValueError('noncanonical-driver-json')
    if (not isinstance(document, dict) or set(document) != {
            'schema_version', 'kind', 'samples', 'observations',
            'pre_backend', 'rdata', 'error'}
            or document['schema_version'] != 'local_driver_result.v1'
            or document['kind'] != kind or not isinstance(document['samples'], list)
            or not isinstance(document['observations'], dict)
            or not isinstance(document['pre_backend'], dict)
            or type(document['rdata']) is not int or not 0 <= document['rdata'] < 1 << 32
            or type(document['error']) is not int or document['error'] not in (0, 1)):
        raise ValueError('invalid-driver-payload-schema')
    samples = document['samples']
    if len(samples) != after - before:
        raise ValueError('driver-sample-count-mismatch')
    for index, sample in enumerate(samples, start=before + 1):
        if (not isinstance(sample, dict) or set(sample) != {'local_tick', 'pre', 'post'}
                or type(sample['local_tick']) is not int or sample['local_tick'] != index
                or not isinstance(sample['pre'], dict) or not isinstance(sample['post'], dict)):
            raise ValueError('invalid-driver-sample')
    return document


def parse_driver_receipt(line: str, *, execution: str, sequence: int,
                         current_tick: int, kind: str, cached: bool = False) -> DriverReceipt:
    if (_EXECUTION.fullmatch(execution) is None or type(sequence) is not int or sequence < 1
            or type(current_tick) is not int or current_tick < 0 or type(cached) is not bool):
        raise ValueError('invalid-expected-driver-identity')
    if not isinstance(line, str) or not line.startswith(('RESULT ', 'ERROR ')):
        raise ValueError('invalid-driver-reply')
    if line.startswith('RESULT '):
        parts = _tokens(line, 6)
        if parts[1] != execution or _hex(parts[2]) != sequence:
            raise ValueError('driver-reply-identity-mismatch')
        before, after = _hex(parts[3]), _hex(parts[4])
        if after < before or (before != current_tick if not cached else after > current_tick):
            raise ValueError('driver-reply-tick-mismatch')
        payload = _payload(parts[5], kind=kind, before=before, after=after)
        return DriverReceipt('result', execution, sequence, before, after,
                             0 if cached else after - before, payload=payload)
    parts = _tokens(line, 6)
    if parts[1] != execution or _hex(parts[2]) != sequence:
        raise ValueError('driver-reply-identity-mismatch')
    after = _hex(parts[3])
    if ((after < current_tick if not cached else after > current_tick)
            or _TOKEN.fullmatch(parts[4]) is None or _TOKEN.fullmatch(parts[5]) is None):
        raise ValueError('invalid-driver-error')
    return DriverReceipt('error', execution, sequence, current_tick if not cached else after,
                         after, 0 if cached else after - current_tick,
                         error_code=parts[4], error_detail=parts[5])
