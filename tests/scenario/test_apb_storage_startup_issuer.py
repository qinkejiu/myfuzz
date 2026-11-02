"""A2 C issuer controls: pure page/handoff checks and noneligible refusals."""
import copy
import json
from types import SimpleNamespace
import pytest

from tests.local_harness.test_apb_storage_startup_host import (
    a2_generation, a2_session, _generate)


def _contract_and_ports(assert_ticks=2, release_ticks=2):
    from myfuzz.local_harness.apb_storage_startup import startup_contract, PORT_WIDTHS
    contract = startup_contract(assert_ticks=assert_ticks, release_ticks=release_ticks,
        snapshot_max={'backend': {}, 'physical': {}, 'storage_probes': {
            'storage_value': 0xffffffff, 'storage_reset': 1}},
        source_contract_digest='1'*64, probe_digest='2'*64,
        reset_mapping=dict(runtime_port='reset', assertion_high=True,
                           source_port='HRESETn', source_active_low=True))
    ports = [dict(name=name, width=width) for name, width in PORT_WIDTHS.items()]
    return contract, ports


def _page(contract, page_index=0):
    records = []
    start = page_index * contract['page_size']
    for index in range(start+1, min(start+32, contract['total_ticks'])+1):
        reset = int(index <= contract['assert_ticks'])
        group = dict.fromkeys(('storage_value','storage_reset','storage_paddr',
            'storage_psel','storage_penable','storage_pwrite','storage_pwdata',
            'storage_prdata','storage_pready','storage_pslverr'), 0)
        group.update(storage_reset=reset, storage_pready=1)
        records.append(dict(startup_edge_index=index, reset_pre=reset, reset_post=reset,
            sample=dict(local_tick=index,
                        pre={'storage_probes': copy.deepcopy(group)},
                        post={'storage_probes': copy.deepcopy(group)})))
    return dict(schema_version='apb_storage_startup_page.v1', page_index=page_index,
        page_count=contract['page_count'], total_ticks=contract['total_ticks'],
        assert_ticks=contract['assert_ticks'], release_ticks=contract['release_ticks'],
        records=records)


def _wire_receipt(page, *, execution='a'*32, sequence=1, before=0, after=0,
                  kind='apb3_register_observe', rdata=0, error=0, samples=None,
                  observations=None):
    from myfuzz.local_harness.wire import parse_driver_receipt
    payload = dict(schema_version='local_driver_result.v1', kind=kind,
        samples=[] if samples is None else samples,
        observations={'storage_startup': page} if observations is None else observations,
        pre_backend={}, rdata=rdata, error=error)
    raw = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode().hex()
    return parse_driver_receipt(
        f'RESULT {execution} {sequence:x} {before:x} {after:x} {raw}',
        execution=execution, sequence=sequence, current_tick=before, kind=kind)


def test_pure_startup_receipt_accepts_only_exact_zero_tick_page():
    from myfuzz.scenario.apb_storage_register_version import validate_storage_startup_receipt
    contract, ports = _contract_and_ports()
    page = _page(contract)
    receipt = _wire_receipt(page)
    page_out, records = validate_storage_startup_receipt(
        receipt, execution='a'*32, sequence=1, contract=contract, ports=ports,
        expected_page=0)
    assert page_out == page and len(records) == contract['total_ticks']
    from dataclasses import replace
    for mutate in (
        lambda r: replace(r, status='error'),
        lambda r: replace(r, execution='b'*32),
        lambda r: replace(r, sequence=2),
        lambda r: replace(r, tick_before=1, tick_after=1),
        lambda r: replace(r, new_ticks=1),
    ):
        with pytest.raises(ValueError):
            validate_storage_startup_receipt(mutate(receipt), execution='a'*32,
                sequence=1, contract=contract, ports=ports, expected_page=0)
    for kwargs in (dict(samples=[{'fake': 1}]), dict(rdata=1), dict(error=1),
                   dict(observations={}), dict(kind='native_memory_cpu')):
        with pytest.raises(ValueError):
            validate_storage_startup_receipt(
                _wire_receipt(page, **kwargs), execution='a'*32, sequence=1,
                contract=contract, ports=ports, expected_page=0)
    with pytest.raises(ValueError):
        validate_storage_startup_receipt(receipt, execution='a'*32, sequence=2,
            contract=contract, ports=ports, expected_page=0)
    bad = copy.deepcopy(page)
    bad['records'][0]['sample']['pre']['storage_probes']['storage_value'] = True
    with pytest.raises(ValueError):
        validate_storage_startup_receipt(_wire_receipt(bad), execution='a'*32,
            sequence=1, contract=contract, ports=ports, expected_page=0)


def _fresh_authority(a2_session, monkeypatch):
    from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority
    artifact, session = a2_session
    monkeypatch.undo()
    return session, ApbStorageRegisterVersionAuthority(session)


def test_host_and_c_refuse_first_command_before_initial_pages(a2_session, monkeypatch):
    session, authority = _fresh_authority(a2_session, monkeypatch)
    assert authority.target is session
    with pytest.raises(ValueError, match='incomplete'):
        session.command('ACCESS_APB3_REG', (0, 4, 0, 15))
    # Host flags are correlation only: C also refuses a normal command when no
    # initial page has been consumed, even if a tampered host flag claims so.
    session._storage_startup_complete = True
    with pytest.raises(ValueError, match='initial-pages'):
        session.command('ACCESS_APB3_REG', (0, 4, 0, 15))


def test_c_refuses_page_order_before_native_authority(a2_session, monkeypatch):
    session, authority = _fresh_authority(a2_session, monkeypatch)
    session._storage_startup_retrieving = True
    with pytest.raises(ValueError, match='page-order'):
        session.command('READ_APB_STORAGE_STARTUP', (1,))


def test_zero_tick_page_read_revokes_seeded_token(a2_session, monkeypatch):
    from myfuzz.scenario import apb_storage_register_version as module
    session, authority = _fresh_authority(a2_session, monkeypatch)
    session._storage_startup_retrieving = True
    token = object()
    module._TOKENS[authority][token] = {'value': 9}
    with pytest.raises(ValueError):
        session.command('READ_APB_STORAGE_STARTUP', (0,))
    assert token not in module._TOKENS[authority]
    assert module._LIVE[authority]['bad'] is True


def test_standard_storage_issuer_refuses_unknown_startup_read(monkeypatch, tmp_path):
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority
    from tests.local_harness.test_apb_storage_startup_host import ROOT
    artifact = _generate(monkeypatch, startup=False)
    session = GeneratedApb3RegisterSession(artifact, base_dir=ROOT,
                                          cache_dir=tmp_path)
    monkeypatch.undo()
    authority = ApbStorageRegisterVersionAuthority(session)
    with pytest.raises(ValueError, match='retrieval'):
        session.command('READ_APB_STORAGE_STARTUP', (0,))
    # Even a tampered host retrieval flag cannot turn standard APB into A2.
    session._storage_startup_required = True
    session._storage_startup_retrieving = True
    with pytest.raises(ValueError, match='startup-document'):
        session.command('READ_APB_STORAGE_STARTUP', (0,))
    assert authority is not None


def test_tampered_host_contract_refused_before_any_page_authority(
        a2_session, monkeypatch):
    from myfuzz.scenario.apb_storage_register_version import ApbStorageRegisterVersionAuthority
    artifact, session = a2_session
    monkeypatch.undo()
    authority = ApbStorageRegisterVersionAuthority(session)
    # Tampering the host-retained admitted contract cannot be healed by the
    # artifact document; the sealed producer reconstruction refuses before any
    # page is sent or any token can be minted.
    session._storage_startup_contract['page_size'] = 64
    session._storage_startup_retrieving = True
    for _ in range(2):
        with pytest.raises(ValueError):
            session.command('READ_APB_STORAGE_STARTUP', (0,))
    assert session._sequence == 0 and session.local_ticks == 0
    assert authority is not None


def test_page_accumulation_and_handoff_are_documentary_only():
    """Exercise the production page/handoff completion logic without authority.

    No authority object, native eligibility, token journal or registry entry is
    created. Receipts are parsed by the real wire parser; the local live state
    is a plain dictionary owned by the test.
    """
    from myfuzz.scenario.apb_storage_register_version import (
        ApbStorageRegisterVersionAuthority as Authority, _STARTUP_OPERATION,
        _canonical, _source_facts)
    from myfuzz.local_harness.apb_storage_startup import PORT_WIDTHS
    from myfuzz.local_harness.apb_storage_source_contract import _registered_document
    contract, ports = _contract_and_ports(assert_ticks=2, release_ticks=2)
    page = _page(contract)
    target = SimpleNamespace(_execution='a'*32, reset_epoch=0, process=None,
                             _tick_base=0)
    startup = dict(contract=contract, ports=ports, page_count=contract['page_count'],
        next_page=0, pages=[], records=0, bytes=0, complete=False,
        handoff='not_started', handoff_facts=None, last_post=None, last_raw=None,
        reset_observed=False)
    # The production live state also carries the source-bound facts the ordinary
    # command reducer needs (`source_contract` as canonical JSON text, its
    # derived facts and the base the contract was resolved against).  This
    # control takes them from the closed code-owned registry, exactly what
    # `_source_facts()` uses when it is called without a document.
    registered = _registered_document()
    live = dict(startup=startup, state=None, scope=(None, 'a'*32, 0, 0),
                pending=None, limits=(65536, 4096, 16), writes=[], samples=0,
                bad=False, last_wire_sequence=0,
                source_contract=_canonical(registered),
                source_facts=_source_facts(registered),
                source_base='.')
    receipt = _wire_receipt(page)
    Authority._complete_startup_page(None, target, receipt,
        (_STARTUP_OPERATION, (0,), 1, 0, None, 'startup_page'), live)
    assert live['startup']['complete'] is True
    assert live['startup']['handoff'] == 'awaiting_first_command'
    assert live['startup']['records'] == contract['total_ticks']
    assert live['startup']['reset_observed'] is True
    assert live['startup']['last_raw']['namespace'] == 'startup'
    assert live['startup']['last_raw']['sample_phase'] == 'post'
    assert live['startup']['last_raw']['startup_edge_index'] == contract['total_ticks']
    last_post = live['startup']['last_post']
    # A first command that changes persistent storage before the first tick is
    # a measured discontinuity, not a legal handoff.
    group = dict.fromkeys(PORT_WIDTHS, 0)
    group.update(storage_value=1, storage_reset=0, storage_pready=1,
                 storage_psel=1, storage_penable=1, storage_paddr=4,
                 storage_pwrite=1, storage_pwdata=27)
    bad = _wire_receipt(page, sequence=2, samples=[dict(local_tick=1,
        pre={'storage_probes': copy.deepcopy(group)},
        post={'storage_probes': copy.deepcopy(group)})],
        observations={'physical': {}}, before=0, after=1)
    with pytest.raises(ValueError):
        Authority._complete_ordinary_command(None, target, 'ACCESS_APB3_REG',
            (1, 4, 27, 15), bad,
            ('ACCESS_APB3_REG', (1, 4, 27, 15), 2, 0, None, 'command'), live)
    # Persistent storage/reset continuity from the last startup post to the
    # first command pre is accepted; readback remains free.
    group['storage_value'] = last_post['storage_value']
    group['storage_reset'] = last_post['storage_reset']
    group['storage_prdata'] = 0xdead
    post = copy.deepcopy(group)
    post['storage_value'] = 27
    good = _wire_receipt(page, sequence=2, samples=[dict(local_tick=1,
        pre={'storage_probes': copy.deepcopy(group)},
        post={'storage_probes': post})],
        observations={'physical': {}}, before=0, after=1)
    target.process = object()
    live['scope'] = (target.process, 'a'*32, 0, 0)
    live['startup'] = copy.deepcopy(live['startup'])
    Authority._complete_ordinary_command(None, target, 'ACCESS_APB3_REG',
        (1, 4, 27, 15), good,
        ('ACCESS_APB3_REG', (1, 4, 27, 15), 2, 0, None, 'command'), live)
    assert live['state']['value'] == 27
    assert live['state']['sequence'] == 2
    assert live['startup']['handoff'] == 'done'
    facts = live['startup']['handoff_facts']['facts']
    assert facts['grants_reset_prerequisite'] is False
    assert facts['readback_not_storage'] is True
    assert facts['startup_value'] == facts['command_value'] == 0
