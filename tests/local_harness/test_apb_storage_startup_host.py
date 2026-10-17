"""A2 host consumption controls: real renderers/parser, software wire fixture.

Only saved elaborated ports and the existing ``build._toolchain`` seam are
replaced. Source lock, runtime/driver rendering, admission, canonical
reconstruction, the base wire parser and the original command callbacks are
all executed for real. Every fixture here is explicitly noneligible: no
native build receipt, token or reset prerequisite can be issued.
"""
import copy
import json
import os
import subprocess
import threading
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[2]
SELECTOR = dict(endpoint_id='timer.bus',
                contract_id='pulp-apb-timer.ctrl0.source.v1',
                register='TIMER0_CTRL')
A2_SCHEMA = 'local_driver_generation.apb_storage_startup.v2'


def _timer_ports():
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.composition.source_crawler import ElaboratedPortFact
    profile = load_component_profile(ROOT/'configs/peripherals/pulp_timer/component_profile.json')
    rows = [('HCLK', 'input', 1), ('HRESETn', 'input', 1), ('PADDR', 'input', 12),
            ('PWDATA', 'input', 32), ('PWRITE', 'input', 1), ('PSEL', 'input', 1),
            ('PENABLE', 'input', 1), ('PRDATA', 'output', 32), ('PREADY', 'output', 1),
            ('PSLVERR', 'output', 1), ('irq_o', 'output', 4)]
    return profile, tuple(ElaboratedPortFact(
        name=name, direction=direction, width=width, signed=False,
        source_file=profile.source.files[0], line=1, column=1)
        for name, direction, width in rows)


def _generate(monkeypatch, *, startup=True, assert_ticks=32, release_ticks=1):
    """Real profile/binding/source-lock/rendering; saved ports only."""
    from myfuzz.composition.component_profile import PhysicalFacts
    from myfuzz.local_harness import plan as planning, runtime_renderer
    from myfuzz.local_harness import (load_local_harness_request, render_local_harness,
                                      verify_local_source_lock)
    from myfuzz.local_harness.driver_renderer import render_local_driver
    profile, ports = _timer_ports()
    facts = PhysicalFacts(top_module=profile.source.top_module, ports=ports,
                          content_hash='saved_ports_software_fixture_not_elaboration',
                          revision=profile.source.revision, files=profile.source.files,
                          include_roots=profile.source.include_roots)
    monkeypatch.setattr(planning, 'elaborate_profile', lambda *a, **kw: facts)
    monkeypatch.setattr(runtime_renderer, 'elaborate_profile', lambda *a, **kw: facts)
    original = subprocess.Popen
    def guard(argv, *a, **kw):
        if Path(argv[0]).name != 'git':
            raise AssertionError('external model/compiler/elaboration forbidden ' + str(argv))
        return original(argv, *a, **kw)
    monkeypatch.setattr(subprocess, 'Popen', guard)
    tuning = {'endpoint_policies': [dict(endpoint_id='timer.bus', template_id='target.apb3',
                                         template_version='1', variant_id='full-word',
                                         max_outstanding=1)],
              'apb_storage_observations': [dict(SELECTOR, endpoint_id='timer.bus')]}
    if startup:
        tuning['apb_storage_startup'] = [dict(SELECTOR, endpoint_id='timer.bus')]
    request = load_local_harness_request(dict(
        schema_version='local_harness.v2',
        profile_path='configs/peripherals/pulp_timer/component_profile.json',
        instance_id='unrelated_instance', reset_assert_ticks=assert_ticks,
        reset_release_ticks=release_ticks, max_wait_cycles=16, tuning=tuning))
    plan = planning.plan_local_harness(request, base_dir=ROOT)
    structural = render_local_harness(plan)
    verified = verify_local_source_lock(profile, base_dir=ROOT)
    runtime = runtime_renderer.render_local_runtime(plan, structural, verified, base_dir=ROOT)
    return render_local_driver(runtime, base_dir=ROOT)


@pytest.fixture
def a2_generation(monkeypatch):
    artifact = _generate(monkeypatch)
    assert artifact.runtime_document['driver_schema_version'] == A2_SCHEMA
    yield artifact
    monkeypatch.undo()


@pytest.fixture
def a2_session(a2_generation, tmp_path):
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    return a2_generation, GeneratedApb3RegisterSession(
        a2_generation, base_dir=ROOT, cache_dir=tmp_path)


def _rehash(document):
    from myfuzz.local_harness.renderer import _sha
    document['artifact_digest'] = _sha({k: v for k, v in document.items()
                                        if k != 'artifact_digest'})
    return document


def test_real_a2_admission_build_and_host_source_identity(a2_session, monkeypatch):
    from myfuzz.local_harness import build
    artifact, session = a2_session
    document = artifact.runtime_document
    assert session._expected_ready() == (
        document['artifact_digest'], 32, 1, 'apb3_register_observe')
    assert session._storage_startup_required is True
    assert session._storage_startup_contract == document['storage_startup_capture']
    monkeypatch.setattr(build, '_toolchain', lambda: dict(
        verilator=dict(path='software_verilator'), cxx=dict(path='software_cxx'),
        ar=dict(path='software_ar')))
    identity, snapshots = build._prepare(artifact, session.base_dir)
    assert identity['artifact_digest'] == document['artifact_digest']
    assert json.loads(snapshots['generated/artifact.json'])['storage_startup_capture'] == \
        document['storage_startup_capture']
    assert snapshots['generated/driver.cpp'] == artifact.cpp_text.encode()
    host = {row['path'] for row in identity['host_sources']['files']}
    assert 'src/myfuzz/local_harness/apb_storage_startup.py' in host
    inputs = {row['path']: row['sha256'] for row in identity['inputs']}
    header = 'src/myfuzz/local_harness/rtl/local_driver_v1.h'
    assert inputs[header] == __import__('hashlib').sha256(
        (ROOT/header).read_bytes()).hexdigest()
    assert 'CommandSet::ApbStorageStartup' in (ROOT/header).read_text()
    assert identity['toolchain']['verilator']['path'] == 'software_verilator'


@pytest.mark.parametrize('mutation', [
    'missing_capture_keep_schema', 'missing_selection_keep_schema', 'missing_schema',
    'unknown_capture_field', 'tampered_reset_mapping', 'tampered_page_size',
    'capture_on_other_kind', 'selection_foreign_endpoint', 'bool_assert_ticks',
    'unregistered_capture_digest',
])
def test_a2_admission_and_prepare_refuse_partial_or_cross_kind(
        a2_session, monkeypatch, mutation):
    from dataclasses import replace
    from myfuzz.local_harness import build
    artifact, session = a2_session
    document = copy.deepcopy(artifact.runtime_document)
    if mutation == 'missing_capture_keep_schema':
        del document['storage_startup_capture']
    elif mutation == 'missing_selection_keep_schema':
        del document['storage_startup_selection']
    elif mutation == 'missing_schema':
        document['driver_schema_version'] = 'local_driver_generation.v1'
    elif mutation == 'unknown_capture_field':
        document['storage_startup_capture']['caller_expression'] = 'PWDATA'
    elif mutation == 'tampered_reset_mapping':
        document['storage_startup_capture']['reset_mapping']['source_active_low'] = False
    elif mutation == 'tampered_page_size':
        document['storage_startup_capture']['page_size'] = 64
    elif mutation == 'capture_on_other_kind':
        document['kind'] = 'native_memory_cpu'
    elif mutation == 'selection_foreign_endpoint':
        document['storage_startup_selection']['endpoint_id'] = 'foreign.bus'
    elif mutation == 'bool_assert_ticks':
        document['storage_startup_capture']['assert_ticks'] = True
    else:
        del document['storage_observation']
    _rehash(document)
    changed = replace(artifact, runtime_document=document)
    # Real _expected_ready/admission refusal; no tool, renderer or cache seam.
    session._artifact_document = document
    session.artifact = changed
    with pytest.raises(ValueError):
        session._expected_ready()
    # Real build._prepare must refuse before any tool query.
    monkeypatch.setattr(build, '_toolchain', lambda: pytest.fail('tool query forbidden'))
    with pytest.raises(build.LocalHarnessBuildError):
        build._prepare(changed, session.base_dir)


def test_standard_v1_artifact_branch_is_unchanged(monkeypatch, tmp_path):
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    from myfuzz.local_harness.session import registered_operations
    artifact = _generate(monkeypatch, startup=False)
    document = artifact.runtime_document
    assert document['driver_schema_version'] == 'local_driver_generation.v1'
    session = GeneratedApb3RegisterSession(artifact, base_dir=ROOT, cache_dir=tmp_path,
                                           setup_writes=((4, 0x55),), probe_offsets=(4,))
    assert session._expected_ready() == (
        document['artifact_digest'], 32, 1, 'apb3_register_observe')
    assert session._storage_startup_required is False
    assert 'READ_APB_STORAGE_STARTUP' not in registered_operations('apb3_register_observe')
    assert 'READ_APB_STORAGE_STARTUP' not in registered_operations('ahb_lite_cpu')
    monkeypatch.undo()


class SoftwareWireDriver:
    """Deterministic in-process driver using real stdin/stdout pipe descriptors."""

    def __init__(self, artifact, faults=()):
        self.document = artifact.runtime_document
        self.contract = self.document['storage_startup_capture']
        self.digest = self.document['artifact_digest']
        self.assert_ticks = self.contract['assert_ticks']
        self.release_ticks = self.contract['release_ticks']
        self.backend = {row['name']: 0 for row in self.document['backend_ports']}
        self.physical = {row['runtime_name']: 0 for row in self.document['physical_exports']}
        self.probe_ports = copy.deepcopy(self.document['storage_probe_ports'])
        self.execution = ''
        self.sequence = 0
        self.tick = 0
        self.storage = 0
        self.commands = []
        self.acks = []
        self.faults = [dict(row) for row in faults]
        self.closed = False
        self._poll = None
        self._stdin_r, self._stdin_w = os.pipe()
        self._stdout_r, self._stdout_w = os.pipe()
        self.stdin = os.fdopen(self._stdin_w, 'w', buffering=1)
        self.stdout = os.fdopen(self._stdout_r, 'r', buffering=1)
        self._to_driver = os.fdopen(self._stdin_r, 'r', buffering=1)
        self._from_driver = os.fdopen(self._stdout_w, 'w', buffering=1)
        self._stdin_fd = self._stdin_w
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    @property
    def pid(self):
        return 424242

    def poll(self):
        return self._poll

    def kill(self):
        if self._poll is None:
            self._poll = -9
        # Wake the engine's blocking read without taking its buffered-reader
        # lock; closing a TextIOWrapper from another thread can deadlock.
        try:
            os.write(self._stdin_fd, b'END\n')
        except OSError:
            pass
        self._thread.join(0.5)
        self.closed = True

    def wait(self, timeout=None):
        self._thread.join(timeout if timeout is not None else 1)
        if self._poll is None:
            self._poll = 0
        return self._poll

    def _close(self, code):
        if self._poll is None:
            self._poll = code
        self.closed = True

    def _run(self):
        try:
            self._write('READY local_driver.v1 %s %x %x\n'
                        % (self.digest, self.assert_ticks, self.release_ticks))
            while True:
                line = self._to_driver.readline()
                if not line:
                    return
                line = line.rstrip('\n')
                if line == 'END':
                    return
                if line.startswith('ACK '):
                    _, execution, sequence = line.split(' ')
                    self.acks.append((execution, int(sequence, 16), self.tick))
                    fault = self._take_fault(stage='ack')
                    if fault == 'lost_ack':
                        self._close(1)
                        return
                    self._write(f'ACKED {execution} {sequence} {self.tick:x}\n')
                    continue
                tokens = line.split(' ')
                if tokens[0] != 'CMD' or len(tokens) < 4:
                    self._close(2)
                    return
                execution, sequence = tokens[1], int(tokens[2], 16)
                operation = tokens[3]
                fields = tuple(int(token, 16) for token in tokens[4:])
                self.commands.append((operation, fields, sequence, self.tick))
                if not self.execution:
                    self.execution = execution
                if execution != self.execution or sequence != self.sequence + 1:
                    self._close(3)
                    return
                page = fields[0] if operation == 'READ_APB_STORAGE_STARTUP' else None
                fault = self._take_fault(operation=operation, page=page)
                if fault == 'lost_reply':
                    self._close(1)
                    return
                if fault == 'partial':
                    self._write('RESULT ' + execution + ' ')
                    self._close(1)
                    return
                try:
                    before = self.tick
                    if operation == 'READ_APB_STORAGE_STARTUP':
                        payload = self._page_payload(fields[0])
                        after = before
                    else:
                        payload = self._normal_payload(operation, fields)
                        after = before + len(payload['samples'])
                    line_out = self._encode(payload, before, after, sequence,
                                            operation, fields, fault)
                except Exception:
                    self._close(4)
                    return
                self.sequence = sequence
                self.tick = after
                self._write(line_out)
                if fault == 'oserror':
                    closed_fd = os.open(os.devnull, os.O_RDONLY)
                    os.close(closed_fd)
                    class _BadStream:
                        def fileno(self):
                            return closed_fd
                        def close(self):
                            pass
                    self.stdin = _BadStream()
                elif fault == 'epipe':
                    try:
                        self._to_driver.close()
                    except (OSError, ValueError):
                        pass
                elif fault == 'duplicate_line':
                    self._write(line_out)
        except BaseException:
            self._close(5)
        finally:
            if self._poll is None:
                self._poll = 0
            self.closed = True
            for handle in (self._from_driver, self._to_driver):
                try:
                    handle.close()
                except (OSError, ValueError):
                    pass

    def _take_fault(self, *, stage=None, operation=None, page=None):
        for index, fault in enumerate(self.faults):
            if fault.get('stage', 'command') == 'ack':
                if stage != 'ack':
                    continue
            elif stage == 'ack':
                continue
            elif fault.get('operation') != operation:
                continue
            elif 'page' in fault and fault['page'] != page:
                continue
            self.faults.pop(index)
            return fault['action']
        return None

    def _write(self, text):
        self._from_driver.write(text)
        self._from_driver.flush()

    def _encode(self, payload, before, after, sequence, operation, fields, fault):
        execution = self.execution
        raw = json.dumps(payload, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=False).encode('utf-8')
        if fault == 'noncanonical':
            raw = json.dumps(payload, sort_keys=True).encode('utf-8')
        elif fault == 'invalid_utf8':
            raw = b'\xff'
        elif fault == 'unknown_field':
            payload['forged'] = 1
            raw = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
        elif fault == 'bool_width':
            page = payload['observations']['storage_startup']
            page['records'][0]['sample']['pre']['storage_probes']['storage_value'] = True
            raw = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
        elif fault == 'missing_probe':
            page = payload['observations']['storage_startup']
            page['records'][0]['sample']['pre']['storage_probes'].pop('storage_pready')
            raw = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
        elif fault == 'pagecount':
            payload['observations']['storage_startup']['page_count'] += 1
            raw = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
        elif fault == 'reorder':
            page = payload['observations']['storage_startup']
            page['page_index'] = 1 - page['page_index']
            raw = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
        if fault == 'sequence':
            sequence += 1
        if fault == 'execution':
            execution = 'f' * 32
        return f'RESULT {execution} {sequence:x} {before:x} {after:x} {raw.hex()}\n'

    def _page_payload(self, page_index):
        contract = self.contract
        start = page_index * contract['page_size']
        records = []
        for index in range(start + 1, min(start + 32, contract['total_ticks']) + 1):
            reset = int(index <= contract['assert_ticks'])
            group = dict.fromkeys(self.probe_names(), 0)
            group.update(storage_reset=reset, storage_pready=1)
            records.append(dict(
                startup_edge_index=index, reset_pre=reset, reset_post=reset,
                sample=dict(local_tick=index,
                            pre={'storage_probes': copy.deepcopy(group)},
                            post={'storage_probes': copy.deepcopy(group)})))
        return dict(schema_version='local_driver_result.v1',
                    kind='apb3_register_observe', samples=[],
                    observations={'storage_startup': dict(
                        schema_version='apb_storage_startup_page.v1',
                        page_index=page_index, page_count=contract['page_count'],
                        total_ticks=contract['total_ticks'],
                        assert_ticks=contract['assert_ticks'],
                        release_ticks=contract['release_ticks'], records=records)},
                    pre_backend=copy.deepcopy(self.backend), rdata=0, error=0)

    def probe_names(self):
        return {row['name']: row['width'] for row in self.probe_ports}

    def _normal_payload(self, operation, fields):
        group = dict.fromkeys(self.probe_names(), 0)
        group.update(storage_value=self.storage, storage_reset=0,
                     storage_pready=1)
        if operation == 'ACCESS_APB3_REG':
            write, offset, value, be = fields
            if be != 15:
                raise ValueError('bad be')
            group.update(storage_psel=1, storage_penable=1, storage_pwrite=write,
                         storage_paddr=offset,
                         storage_pwdata=value if write else 0,
                         storage_prdata=0 if write else self.storage)
            post = copy.deepcopy(group)
            if write:
                self.storage = value
                post['storage_value'] = value
            payload_rdata = self.storage if not write else 0
        elif operation == 'STEP_APB3_REG':
            payload_rdata = 0
            post = copy.deepcopy(group)
        else:
            raise ValueError('unsupported software command')
        phases = {'pre': {'storage_probes': copy.deepcopy(group),
                          'backend': copy.deepcopy(self.backend),
                          'physical': copy.deepcopy(self.physical)},
                  'post': {'storage_probes': post,
                           'backend': copy.deepcopy(self.backend),
                           'physical': copy.deepcopy(self.physical)}}
        return dict(schema_version='local_driver_result.v1',
                    kind='apb3_register_observe',
                    samples=[dict(local_tick=self.tick + 1, **phases)],
                    observations={'physical': copy.deepcopy(self.physical)},
                    pre_backend=copy.deepcopy(self.backend),
                    rdata=payload_rdata, error=0)


def _wire_session(artifact, session, monkeypatch, faults=()):
    engine = SoftwareWireDriver(artifact, faults)
    session._binary = ROOT/'software-wire-driver-fixture'
    monkeypatch.setattr(subprocess, 'Popen', lambda *a, **kw: engine)
    return engine


def test_pages_precede_first_command_and_keep_zero_command_ticks(
        a2_session, monkeypatch):
    artifact, session = a2_session
    engine = _wire_session(artifact, session, monkeypatch)
    session.begin_case('case')
    assert [row[:2] for row in engine.commands] == [
        ('READ_APB_STORAGE_STARTUP', (0,)),
        ('READ_APB_STORAGE_STARTUP', (1,))]
    assert [row[2] for row in engine.commands] == [1, 2]
    assert session.local_ticks == 0 and session._sequence == 2
    assert session._case_id == 'case' and session.reset_epoch == 0
    assert session._tick_base == 0 and session.process is engine
    assert engine.pid == 424242 and engine.execution == session._execution
    assert session._storage_startup_complete is True
    assert len(session._storage_startup_receipts) == 2
    for index, row in enumerate(session._storage_startup_receipts):
        assert row['page_index'] == index
        assert row['receipt'].tick_before == row['receipt'].tick_after == 0
        assert row['receipt'].new_ticks == 0
        assert row['receipt'].payload['samples'] == []
        assert row['raw'].startswith('RESULT %s %x 0 0 ' % (
            session._execution, index + 1))
    receipt = session.command('ACCESS_APB3_REG', (1, 4, 27, 15))
    assert receipt.sequence == 3 and receipt.tick_before == 0
    assert receipt.tick_after == 1 and receipt.new_ticks == 1
    assert session._take(receipt)['rdata'] == 0
    assert session.local_ticks == 1
    samples = session.drain_tick_samples()
    assert len(samples) == 1 and samples[0]['local_tick'] == 1
    assert not any(row[0] == 'ACCESS_APB3_REG' for row in engine.commands[:2])
    session.end_case()


@pytest.mark.parametrize('fault', [
    dict(stage='command', operation='READ_APB_STORAGE_STARTUP', page=1,
         action='sequence'),
    dict(stage='command', operation='READ_APB_STORAGE_STARTUP', page=1,
         action='execution'),
    dict(stage='command', operation='READ_APB_STORAGE_STARTUP', page=1,
         action='reorder'),
    dict(stage='command', operation='READ_APB_STORAGE_STARTUP', page=0,
         action='duplicate_line'),
    dict(stage='command', operation='READ_APB_STORAGE_STARTUP', page=1,
         action='pagecount'),
    dict(stage='command', operation='READ_APB_STORAGE_STARTUP', page=1,
         action='unknown_field'),
    dict(stage='command', operation='READ_APB_STORAGE_STARTUP', page=1,
         action='bool_width'),
    dict(stage='command', operation='READ_APB_STORAGE_STARTUP', page=1,
         action='missing_probe'),
    dict(stage='command', operation='READ_APB_STORAGE_STARTUP', page=1,
         action='invalid_utf8'),
    dict(stage='command', operation='READ_APB_STORAGE_STARTUP', page=1,
         action='noncanonical'),
    dict(stage='command', operation='READ_APB_STORAGE_STARTUP', page=1,
         action='lost_reply'),
    dict(stage='command', operation='READ_APB_STORAGE_STARTUP', page=1,
         action='partial'),
    dict(stage='command', operation='READ_APB_STORAGE_STARTUP', page=0,
         action='epipe'),
    dict(stage='command', operation='READ_APB_STORAGE_STARTUP', page=0,
         action='oserror'),
])
def test_lost_or_malformed_page_poisons_never_retries(
        a2_session, monkeypatch, fault):
    artifact, session = a2_session
    engine = _wire_session(artifact, session, monkeypatch, [fault])
    with pytest.raises(Exception):
        session.begin_case('case')
    assert session._storage_startup_complete is False
    assert session._storage_startup_failure is not None
    failure = session._storage_startup_failure
    assert failure['possible_effects'] is True
    assert failure['effect_certainty'] == 'unknown'
    assert failure['grants_reset_prerequisite'] is False
    assert session.process is None and engine.closed
    # A parsed-but-invalid page is retained as raw evidence; a transport
    # failure is not counted as a page. Never healed or retried.
    retained = session._storage_startup_receipts
    assert 1 <= len(retained) <= 2
    assert retained[0]['page_index'] == 0
    parsed_invalid = fault['action'] in ('reorder', 'pagecount', 'missing_probe')
    assert len(retained) == (2 if parsed_invalid else 1)
    assert failure['last_page_index'] == (1 if parsed_invalid else 0)
    assert failure['retained_receipts'] is not None
    if parsed_invalid or fault['action'] in ('noncanonical', 'invalid_utf8'):
        assert isinstance(failure['raw_reply'], str)
    with pytest.raises(ValueError):
        session.command('ACCESS_APB3_REG', (0, 4, 0, 15))
    with pytest.raises(ValueError):
        session.begin_case('case')


def test_tampered_contract_or_artifact_poisons_before_reuse(a2_session, monkeypatch):
    artifact, session = a2_session
    session._storage_startup_contract['page_size'] = 64
    engine = _wire_session(artifact, session, monkeypatch)
    with pytest.raises(ValueError):
        session.begin_case('case')
    assert session.process is None and engine.closed
    assert session._storage_startup_failure['possible_effects'] is True
    assert len(session._storage_startup_receipts) == 1


def test_missing_initial_pages_refuse_first_normal_command(a2_session, monkeypatch):
    artifact, session = a2_session
    engine = _wire_session(artifact, session, monkeypatch)
    with pytest.raises(ValueError, match='incomplete'):
        session.command('ACCESS_APB3_REG', (0, 4, 0, 15))
    with pytest.raises(ValueError, match='retrieval'):
        session.command('READ_APB_STORAGE_STARTUP', (0,))
    assert engine.commands == [] and session.local_ticks == 0


@pytest.mark.parametrize('asserted,released', [(512, 1)])
def test_pages_consume_real_wire_sequence_and_ack_capacity(monkeypatch, tmp_path,
                                                           asserted, released):
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    artifact = _generate(monkeypatch, assert_ticks=asserted, release_ticks=released)
    session = GeneratedApb3RegisterSession(artifact, base_dir=ROOT, cache_dir=tmp_path)
    engine = _wire_session(artifact, session, monkeypatch)
    session.begin_case('case')
    contract = artifact.runtime_document['storage_startup_capture']
    assert contract['page_count'] == 17
    assert len(session._storage_startup_receipts) == 17
    assert [ack[1] for ack in engine.acks] == [16]
    assert session._sequence == 17 and session.local_ticks == 0
    assert engine.commands[0][2] == 1 and engine.commands[-1][2] == 17
    session.end_case()
    monkeypatch.undo()


def test_lost_ack_during_retrieval_aborts_without_advancing_pages(monkeypatch, tmp_path):
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    artifact = _generate(monkeypatch, assert_ticks=512, release_ticks=1)
    session = GeneratedApb3RegisterSession(artifact, base_dir=ROOT, cache_dir=tmp_path)
    engine = _wire_session(artifact, session, monkeypatch, [dict(stage='ack',
                                                                 action='lost_ack')])
    with pytest.raises(Exception):
        session.begin_case('case')
    assert session.process is None and engine.closed
    assert session._storage_startup_complete is False
    assert len(session._storage_startup_receipts) == 16
    assert session._sequence == 16
    assert session._storage_startup_failure['possible_effects'] is True
    monkeypatch.undo()


def test_measured_startup_to_first_access_continuity(a2_session, monkeypatch):
    from myfuzz.local_harness.apb_storage_startup import validate_startup_handoff
    artifact, session = a2_session
    engine = _wire_session(artifact, session, monkeypatch)
    session.begin_case('case')
    last_page = session._storage_startup_receipts[-1]['receipt'].payload[
        'observations']['storage_startup']
    last_post = last_page['records'][-1]['sample']['post']['storage_probes']
    reset_observed = any(row['reset_pre'] == 1
        for entry in session._storage_startup_receipts
        for row in entry['receipt'].payload['observations']['storage_startup']['records'])
    assert reset_observed is True
    receipt = session.command('ACCESS_APB3_REG', (1, 4, 27, 15))
    session._take(receipt)
    first_pre = receipt.payload['samples'][0]['pre']['storage_probes']
    facts = validate_startup_handoff(last_post, first_pre,
        operation='ACCESS_APB3_REG', fields=(1, 4, 27, 15),
        reset_observed=reset_observed)
    assert facts['namespace'] == 'startup_to_command'
    assert facts['startup_value'] == facts['command_value'] == 0
    assert facts['startup_reset'] == facts['command_reset'] == 0
    assert facts['readback_not_storage'] is True
    assert facts['grants_reset_prerequisite'] is False
    # Combinational readback/ack is explicitly free across the command drive.
    free = copy.deepcopy(first_pre)
    free.update(storage_prdata=0xdead, storage_pready=1, storage_pslverr=0)
    assert validate_startup_handoff(last_post, free, operation='ACCESS_APB3_REG',
        fields=(1, 4, 27, 15), reset_observed=True)['command_value'] == 0
    # Readback cannot hide a changed persistent storage value.
    bad = copy.deepcopy(first_pre)
    bad.update(storage_value=10, storage_prdata=0)
    with pytest.raises(ValueError):
        validate_startup_handoff(last_post, bad, operation='ACCESS_APB3_REG',
            fields=(1, 4, 27, 15), reset_observed=True)
    session.end_case()


def test_first_step_after_pages_is_idle_and_continuous(a2_session, monkeypatch):
    from myfuzz.local_harness.apb_storage_startup import validate_startup_handoff
    from myfuzz.local_harness.apb3_register_session import GeneratedApb3RegisterSession
    artifact, first = a2_session
    session = GeneratedApb3RegisterSession(artifact, base_dir=ROOT,
                                           cache_dir=first.cache_dir)
    _wire_session(artifact, session, monkeypatch)
    session.begin_case('case')
    last_page = session._storage_startup_receipts[-1]['receipt'].payload[
        'observations']['storage_startup']
    last_post = last_page['records'][-1]['sample']['post']['storage_probes']
    result = session.step_local({})
    assert result['error'] == 0
    sample = session.drain_tick_samples()[0]
    assert sample['local_tick'] == 1
    facts = validate_startup_handoff(
        last_post, sample['pre']['storage_probes'], operation='STEP_APB3_REG',
        fields=(), reset_observed=True)
    assert facts['command_value'] == last_post['storage_value']
    assert facts['command_reset'] == last_post['storage_reset']
    assert facts['grants_reset_prerequisite'] is False
    session.end_case()
