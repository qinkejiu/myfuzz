"""Full AXI4 CPU row: trace mapping, native beat replay and the executor gate.

These are synthetic tests.  They build the same shapes the generated sessions
really export (``backend_ports`` rows and per-tick ``driver_samples``) and
replay the session's own ``ReducedAxiObserver``; they start no RTL, no
Verilator build and no native session.  The wrapper-session section drives the
real session code with only the wire transport replaced, exactly like the AHB
startup fixture does: no process is started and no binary is built.
"""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from myfuzz.integration import cpu_axi4
from myfuzz.integration.mmio_cpu_adapter import MmioCpuAdapter, select_mmio_cpu
from myfuzz.local_harness.vexii_axi_fields import SHAPES, STEP_PORTS
from myfuzz.scenario.ledger import TransactionKey
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.router import DataflowRouter, DeviceWindow

BOOT = 0x8000_0000
MMIO = 0x4000_1000


def reduced_artifact(kind='reduced_dual_axi_cpu', *, override=None):
    """An artifact whose ``backend_ports`` mirror the real reduced AXI rows."""
    ports = []
    for prefix, shape in SHAPES.items():
        for role, (direction, width) in shape.items():
            row = dict(name=prefix + '_' + role, role=role, channel=prefix,
                       direction=direction, width=width)
            if override and override[0] == row['name']:
                row[override[1]] = override[2]
            ports.append(row)
    profile = SimpleNamespace(capabilities={'error_response': True,
                                            'single_beat_reduced_axi': True})
    return SimpleNamespace(runtime_document={'kind': kind, 'backend_ports': ports},
                           plan=SimpleNamespace(profile=profile))


def backend(overrides):
    """One full declared reduced AXI4 sample row with every role present."""
    row = {p + '_' + role: 0 for p, shape in SHAPES.items() for role in shape}
    for prefix in SHAPES:
        row[prefix + '_arready'] = 1
        row[prefix + '_rready'] = 1
        if 'awready' in SHAPES[prefix]:
            row[prefix + '_awready'] = 1
            row[prefix + '_wready'] = 1
            row[prefix + '_bready'] = 1
    row.update(overrides)
    return row


def edge(event_id, tick, overrides, *, outputs=None, component='cpu'):
    """One measured AXI4 edge: pre/post backend rows for the same local tick."""
    sample = dict(local_tick=tick, pre={'backend': backend(overrides)},
                  post={'backend': backend(overrides)})
    return dict(event_id=event_id, component=component, local_tick=tick,
                kind='local_tick',
                outputs=dict(driver_samples=[sample], **(outputs or {})))


def fetch_read_events():
    """Accepted i-AR then its R beat, then a data read and a data write."""
    return [
        edge(1, 1, {'i_arvalid': 1, 'i_araddr': 0x8000_0000, 'i_arsize': 2},
             outputs={'i_ar_accepted': 1}),
        edge(2, 2, {'i_rvalid': 1, 'i_rid': 0, 'i_rdata': 0x0000_0013,
                    'i_rlast': 1, 'i_rresp': 0},
             outputs={'i_r_consumed': 1}),
        edge(3, 3, {'d_arvalid': 1, 'd_araddr': 0x4000_1000, 'd_arsize': 2},
             outputs={'d_ar_accepted': 1}),
        edge(4, 4, {'d_rvalid': 1, 'd_rid': 0, 'd_rdata': 0x5a,
                    'd_rlast': 1, 'd_rresp': 0},
             outputs={'d_r_consumed': 1}),
        edge(5, 5, {'d_awvalid': 1, 'd_awaddr': 0x4000_1004, 'd_awsize': 2,
                    'd_wvalid': 1, 'd_wdata': 0xdead_beef, 'd_wstrb': 0xf,
                    'd_wlast': 1},
             outputs={'d_aw_accepted': 1, 'd_w_accepted': 1}),
        edge(6, 6, {'d_bvalid': 1, 'd_bid': 0},
             outputs={'d_b_consumed': 1}),
    ]


# ---------------------------------------------------------------------------
# selection and refusal
# ---------------------------------------------------------------------------

def test_other_kinds_are_left_to_the_next_seam():
    artifact = SimpleNamespace(runtime_document={'kind': 'obi_cpu'})
    assert cpu_axi4.cpu_adapter(artifact, None, None) is None
    assert cpu_axi4.cpu_adapter(SimpleNamespace(runtime_document=None),
                                None, None) is None


def test_parse_complete_adapter_is_built_for_the_reduced_row():
    adapter = cpu_axi4.axi4_cpu_adapter(reduced_artifact())
    assert isinstance(adapter, MmioCpuAdapter)
    assert adapter.protocol == 'axi4'
    assert adapter.channel_model == 'split'
    assert adapter.instruction_granule == 4
    from myfuzz.local_harness.vexii_axi_session import GeneratedReducedAxiCpuSession
    assert adapter.session_type is GeneratedReducedAxiCpuSession


def test_the_parse_adapter_still_reports_the_shipped_gaps():
    """The generated session is unchanged, so its own gap list stays truthful."""
    adapter = cpu_axi4.axi4_cpu_adapter(reduced_artifact())
    assert 'session-router-keyword-missing' in adapter.executor_gaps
    assert 'session-online-instruction-slots-missing' in adapter.executor_gaps
    assert 'session-parked-fetch-address-missing' in adapter.executor_gaps
    assert cpu_axi4.AXI4_KIND_GAPS.get('reduced_dual_axi_cpu') is None


def test_the_reduced_row_is_admitted_on_the_wrapper():
    """``cpu_adapter`` must bind the class the executor really constructs."""
    from myfuzz.local_harness.vexii_axi_mmio_session import (
        GeneratedVexiiAxiMmioSession)
    adapter = cpu_axi4.cpu_adapter(reduced_artifact(), None, None)
    assert isinstance(adapter, MmioCpuAdapter)
    assert adapter.session_type is GeneratedVexiiAxiMmioSession
    assert adapter.protocol == 'axi4'
    assert adapter.channel_model == 'split'
    assert adapter.executor_gaps == ()
    # The seam names the same class the executor would import.
    assert cpu_axi4.executor_session_class('reduced_dual_axi_cpu') \
        is adapter.session_type
    assert cpu_axi4.SESSION_WRAPPERS['reduced_dual_axi_cpu'].endswith(
        '.GeneratedVexiiAxiMmioSession')


def test_executor_cpu_adapter_binds_the_wrapper_and_keeps_the_parser():
    wrapped = cpu_axi4.executor_cpu_adapter(reduced_artifact())
    parsed = cpu_axi4.axi4_cpu_adapter(reduced_artifact())
    assert wrapped.traces == parsed.traces
    assert wrapped.policy == parsed.policy
    assert wrapped.session_type is not parsed.session_type
    assert wrapped.executor_gaps == () and parsed.executor_gaps


def test_select_mmio_cpu_returns_the_wrapper_row():
    from myfuzz.local_harness.vexii_axi_mmio_session import (
        GeneratedVexiiAxiMmioSession)
    adapter = select_mmio_cpu(reduced_artifact(), None, None)
    assert adapter.session_type is GeneratedVexiiAxiMmioSession
    assert adapter.protocol == 'axi4'


def test_irq_variant_adds_the_missing_step_input_gap():
    adapter = cpu_axi4.axi4_cpu_adapter(reduced_artifact('reduced_dual_axi_irq_cpu'))
    assert 'session-requires-external-step-inputs' in adapter.executor_gaps
    with pytest.raises(ValueError, match='session-requires-external-step-inputs'):
        cpu_axi4.cpu_adapter(reduced_artifact('reduced_dual_axi_irq_cpu'), None, None)


def test_the_irq_kind_is_not_wrapped_so_its_refusal_stays_named():
    """No wrapper can supply the per-step irq bit the generic driver omits."""
    assert 'reduced_dual_axi_irq_cpu' not in cpu_axi4.SESSION_WRAPPERS
    from myfuzz.local_harness.vexii_axi_session import (
        GeneratedReducedAxiIrqCpuSession)
    assert cpu_axi4.executor_session_class('reduced_dual_axi_irq_cpu') \
        is GeneratedReducedAxiIrqCpuSession
    with pytest.raises(ValueError) as refusal:
        cpu_axi4.cpu_adapter(reduced_artifact('reduced_dual_axi_irq_cpu'), None, None)
    message = str(refusal.value)
    assert message.startswith('MMIO-CPU-adapter-unsupported:axi4:'
                              'reduced_dual_axi_irq_cpu:')
    for gap in cpu_axi4.AXI4_KIND_GAPS['reduced_dual_axi_irq_cpu']:
        assert gap.split(':')[0] in message


@pytest.mark.parametrize('kind,missing', [
    ('axi4_cpu', 'native-observer-missing'),
])
def test_the_remaining_kind_refuses_with_its_own_gap_list(kind, missing):
    artifact = SimpleNamespace(runtime_document={'kind': kind})
    with pytest.raises(ValueError) as refusal:
        cpu_axi4.cpu_adapter(artifact, None, None)
    message = str(refusal.value)
    assert message.startswith('MMIO-CPU-adapter-unsupported')
    assert missing in message
    assert all(gap.split(':')[0] in message
               for gap in cpu_axi4.AXI4_KIND_GAPS[kind])


def test_the_legacy_unknown_kind_refusal_is_unchanged():
    """``extension_plugins`` now imports this module for ``axi4_cpu``."""
    with pytest.raises(ValueError, match='MMIO-CPU-adapter-unsupported'):
        select_mmio_cpu(SimpleNamespace(runtime_document={'kind': 'axi4_cpu'}),
                        None, None)


# ---------------------------------------------------------------------------
# trace mapping
# ---------------------------------------------------------------------------

def test_traces_name_every_data_channel_role_from_the_artifact():
    adapter = cpu_axi4.axi4_cpu_adapter(reduced_artifact())
    traces = adapter.traces
    assert traces['schema_version'] == cpu_axi4.TRACE_SCHEMA
    assert traces['protocol'] == 'axi4'
    assert traces['channels'] == {'instr': 'i', 'data': 'd'}
    data = traces['data']
    for role in ('arvalid', 'arready', 'araddr', 'arid', 'arprot', 'arsize',
                 'rvalid', 'rready', 'rid', 'rdata', 'rlast', 'rresp',
                 'awvalid', 'awready', 'awaddr', 'awid',
                 'wvalid', 'wready', 'wdata', 'wstrb', 'wlast',
                 'bvalid', 'bready', 'bid', 'bresp'):
        assert data[role] == 'd_' + role
    # The mapping is exactly the declared reduced shape, no invented role.
    assert set(data) == set(SHAPES['d'])
    assert set(traces['instr']) == set(SHAPES['i'])
    assert traces['instr']['araddr'] == 'i_araddr'
    assert 'awvalid' not in traces['instr']  # the fetch face is AR/R only
    assert traces['observation']['parser'] == \
        'scenario.reduced_axi_events.ReducedAxiObserver'
    assert traces['read_transfer']['sampled_read_strobe'] == 0


def test_a_widened_or_renamed_native_role_is_refused():
    with pytest.raises(ValueError, match='native-role-shape:d_awaddr'):
        cpu_axi4.axi4_cpu_adapter(reduced_artifact(override=('d_awaddr', 'width', 64)))
    with pytest.raises(ValueError, match='native-role-shape:d_awvalid'):
        cpu_axi4.axi4_cpu_adapter(
            reduced_artifact(override=('d_awvalid', 'direction', 'input')))


def test_an_artifact_without_native_ports_is_refused():
    artifact = SimpleNamespace(runtime_document={'kind': 'reduced_dual_axi_cpu'})
    with pytest.raises(ValueError, match='no-native-backend-ports'):
        cpu_axi4.axi4_cpu_adapter(artifact)


# ---------------------------------------------------------------------------
# native beat replay
# ---------------------------------------------------------------------------

def test_beats_and_fetches_come_from_the_real_pre_post_samples():
    adapter = cpu_axi4.axi4_cpu_adapter(reduced_artifact())
    events = fetch_read_events()
    completed = adapter.completed_beats(events, 'cpu')
    assert adapter.first_fetch(events, 'cpu') == [(1, 0x8000_0000)]
    fetch = completed[('instr', 1)]
    assert (fetch['address'], fetch['write'], fetch['rdata']) == \
        (0x8000_0000, 0, 0x13)
    assert (fetch['acceptance_event'], fetch['response_event']) == (1, 2)
    read = completed[('data', 1)]
    assert (read['address'], read['write'], read['rdata']) == \
        (0x4000_1000, 0, 0x5a)
    assert (read['acceptance_event'], read['response_event']) == (3, 4)
    write = completed[('data', 2)]
    assert (write['address'], write['write'], write['value']) == \
        (0x4000_1004, 1, 0xdead_beef)
    assert write['byte_enable'] == 0xf
    assert (write['acceptance_event'], write['response_event']) == (5, 6)


def test_sequences_restart_per_case_so_the_newest_beats_win():
    adapter = cpu_axi4.axi4_cpu_adapter(reduced_artifact())
    events = fetch_read_events() + [
        dict(event_id=7, component='cpu', kind='reset_barrier', local_tick=7,
             outputs={}),
        edge(8, 8, {'d_arvalid': 1, 'd_araddr': 0x4000_2000, 'd_arsize': 2}),
        edge(9, 9, {'d_rvalid': 1, 'd_rid': 0, 'd_rdata': 0x77, 'd_rlast': 1}),
    ]
    completed = adapter.completed_beats(events, 'cpu')
    assert completed[('data', 1)]['address'] == 0x4000_2000
    assert completed[('instr', 1)]['address'] == 0x8000_0000


def test_w_before_aw_is_joined_on_the_later_edge():
    adapter = cpu_axi4.axi4_cpu_adapter(reduced_artifact())
    events = [
        edge(1, 1, {'d_wvalid': 1, 'd_wdata': 0x1122_3344, 'd_wstrb': 0xf,
                    'd_wlast': 1}),
        edge(2, 2, {'d_awvalid': 1, 'd_awaddr': 0x4000_1008, 'd_awsize': 2}),
        edge(3, 3, {'d_bvalid': 1, 'd_bid': 0}),
    ]
    write = adapter.completed_beats(events, 'cpu')[('data', 1)]
    assert (write['address'], write['value']) == (0x4000_1008, 0x1122_3344)
    assert (write['acceptance_event'], write['response_event']) == (2, 3)


def test_empty_or_foreign_evidence_yields_no_beat():
    adapter = cpu_axi4.axi4_cpu_adapter(reduced_artifact())
    assert adapter.completed_beats([], 'cpu') == {}
    foreign = [edge(1, 1, {'d_arvalid': 1, 'd_araddr': 0x4000_1000},
                    component='target')]
    assert adapter.completed_beats(foreign, 'cpu') == {}
    assert adapter.first_fetch(foreign, 'cpu') == []


@pytest.mark.parametrize('overrides,reason', [
    ({'d_rvalid': 1, 'd_rid': 0, 'd_rdata': 1, 'd_rlast': 1}, 'orphan_r'),
    ({'d_arvalid': 1, 'd_araddr': 0x4000_1001, 'd_arsize': 2}, 'size_alignment'),
    ({'d_awvalid': 1, 'd_awaddr': 0x4000_1002, 'd_awsize': 1,
      'd_wvalid': 1, 'd_wdata': 0, 'd_wstrb': 0x3, 'd_wlast': 1},
     'strobe_lanes'),
    ({'d_awvalid': 1, 'd_awaddr': 0x4000_1000, 'd_awsize': 2,
      'd_wvalid': 1, 'd_wdata': 0, 'd_wstrb': 0xf, 'd_wlast': 0}, 'last'),
    ({'d_bvalid': 1, 'd_bid': 0}, 'orphan_b'),
])
def test_impossible_axi4_shapes_are_refused_by_name(overrides, reason):
    adapter = cpu_axi4.axi4_cpu_adapter(reduced_artifact())
    with pytest.raises(ValueError, match='reduced_axi_' + reason):
        adapter.completed_beats([edge(1, 1, overrides)], 'cpu')


def test_a_report_that_disagrees_with_the_sampled_pins_is_refused():
    adapter = cpu_axi4.axi4_cpu_adapter(reduced_artifact())
    events = [edge(1, 1, {'d_arvalid': 1, 'd_araddr': 0x4000_1000},
                   outputs={'d_ar_accepted': 0})]
    with pytest.raises(ValueError, match='native-handshake-report:d_ar_accepted'):
        adapter.completed_beats(events, 'cpu')


def session_outputs(**overrides):
    """Exactly what the generated session reports after one measured edge.

    Both faces report all five channels, so the fetch face really does carry
    ``i_aw_accepted``/``i_w_accepted``/``i_b_consumed`` -- always zero, because
    it has no such pins.  This is the shape that must never be read through a
    reconstructed role name.
    """
    row = {}
    for name in ('i', 'd'):
        for channel, suffix in (('ar', '_accepted'), ('aw', '_accepted'),
                                ('w', '_accepted'), ('r', '_consumed'),
                                ('b', '_consumed')):
            row[name + '_' + channel + suffix] = 0
    row.update(overrides)
    return row


def test_the_full_session_output_row_replays_without_inventing_a_role():
    """Every reported channel resolves through ``traces``; none is guessed."""
    adapter = cpu_axi4.axi4_cpu_adapter(reduced_artifact())
    events = [
        edge(1, 1, {'i_arvalid': 1, 'i_araddr': 0x8000_0000, 'i_arsize': 2},
             outputs=session_outputs(i_ar_accepted=1)),
        edge(2, 2, {'i_rvalid': 1, 'i_rid': 0, 'i_rdata': 0x0000_0013,
                    'i_rlast': 1},
             outputs=session_outputs(i_r_consumed=1)),
        edge(3, 3, {'d_awvalid': 1, 'd_awaddr': 0x4000_1000, 'd_awsize': 2,
                    'd_wvalid': 1, 'd_wdata': 0x55, 'd_wstrb': 0xf, 'd_wlast': 1},
             outputs=session_outputs(d_aw_accepted=1, d_w_accepted=1)),
        edge(4, 4, {'d_bvalid': 1, 'd_bid': 0},
             outputs=session_outputs(d_b_consumed=1)),
    ]
    completed = adapter.completed_beats(events, 'cpu')
    assert adapter.first_fetch(events, 'cpu') == [(1, 0x8000_0000)]
    assert completed[('instr', 1)]['rdata'] == 0x13
    assert completed[('data', 1)]['value'] == 0x55
    # The fetch face has no AW pin, so a zero there is consistent by
    # construction rather than by a fabricated 'awvalid' role.
    assert 'awvalid' not in adapter.traces['instr']


@pytest.mark.parametrize('reported', ['i_aw_accepted', 'i_w_accepted',
                                      'i_b_consumed'])
def test_a_handshake_on_a_face_without_that_channel_is_refused(reported):
    adapter = cpu_axi4.axi4_cpu_adapter(reduced_artifact())
    events = [edge(1, 1, {}, outputs=session_outputs(**{reported: 1}))]
    with pytest.raises(ValueError, match='native-handshake-report:' + reported):
        adapter.completed_beats(events, 'cpu')


def test_a_declared_pin_missing_from_the_row_is_a_named_refusal():
    adapter = cpu_axi4.axi4_cpu_adapter(reduced_artifact())
    row = backend({})
    del row['d_awvalid']
    sample = dict(local_tick=1, pre={'backend': row}, post={'backend': row})
    event = dict(event_id=1, component='cpu', local_tick=1, kind='local_tick',
                 outputs=dict(driver_samples=[sample],
                              **session_outputs(d_aw_accepted=0)))
    with pytest.raises(ValueError, match='native-handshake-signal:d_aw_accepted'):
        adapter.completed_beats([event], 'cpu')


def test_a_bare_role_row_is_never_re_keyed_onto_the_declared_signals():
    """A row without the face prefix is refused; it is not silently re-read."""
    adapter = cpu_axi4.axi4_cpu_adapter(reduced_artifact())
    sample = dict(local_tick=1,
                  pre={'backend': {role: 0 for role in SHAPES['d']}},
                  post={'backend': {role: 0 for role in SHAPES['d']}})
    event = dict(event_id=1, component='cpu', local_tick=1, kind='local_tick',
                 outputs=dict(driver_samples=[sample],
                              **session_outputs(d_ar_accepted=0)))
    with pytest.raises(ValueError,
                       match='native-handshake-signal:i_ar_accepted'):
        adapter.completed_beats([event], 'cpu')


def test_a_missing_sample_edge_is_a_refusal_not_a_skipped_tick():
    adapter = cpu_axi4.axi4_cpu_adapter(reduced_artifact())
    broken = dict(event_id=1, component='cpu', local_tick=1,
                  outputs={'driver_samples': []})
    with pytest.raises(ValueError, match='native-sample-shape'):
        adapter.completed_beats([broken], 'cpu')


# ---------------------------------------------------------------------------
# policy and declaration preparation
# ---------------------------------------------------------------------------

def test_policy_names_the_real_response_status_pins():
    adapter = cpu_axi4.axi4_cpu_adapter(reduced_artifact())
    policy = adapter.policy
    assert policy['protocol'] == 'axi4'
    assert policy['native_error_observation'] is True
    assert policy['error_roles'] == {'read': 'rresp', 'write': 'bresp'}
    assert policy['native_error_pins']['data'] == {'read': 'd_rresp',
                                                  'write': 'd_bresp'}
    assert policy['accepted_status'] == 'okay_only'
    assert policy['declared_error_capability'] is True


def test_a_profile_without_error_response_contradicts_the_row():
    artifact = reduced_artifact()
    artifact.plan.profile.capabilities['error_response'] = False
    with pytest.raises(ValueError, match='declared-error-capability-contradiction'):
        cpu_axi4.axi4_cpu_adapter(artifact)


def test_declaration_preparation_reuses_the_shared_four_byte_granule():
    adapter = cpu_axi4.axi4_cpu_adapter(reduced_artifact())
    declaration = {'code_hex': '93000000', 'code_sha256': 'x'}
    prepared = adapter.prepare_declaration(declaration, address=0x8000_0000)
    assert prepared['code_hex'] == '93000000'
    with pytest.raises(ValueError, match='MMIO-instruction-fetch-alignment'):
        adapter.prepare_declaration(declaration, address=0x8000_0002)


def test_native_protocol_names_the_full_axi4_boundary():
    for kind in cpu_axi4.SESSION_CLASSES:
        assert cpu_axi4.native_cpu_protocol({'kind': kind}) == 'axi4'
    with pytest.raises(ValueError, match='native-protocol-required'):
        cpu_axi4.native_cpu_protocol({'kind': 'obi_cpu'})


def test_every_refused_row_still_names_its_gaps():
    """No row outside the wrapper table is silently advertised as drivable."""
    refused = set(cpu_axi4.SESSION_CLASSES) - set(cpu_axi4.SESSION_WRAPPERS)
    # The packed CVA6 row is admitted by its own wrapper; what it cannot
    # certify is named in its own gap entry and in every certificate, and the
    # data-only F2/F4 campaign is the evidence (runs/cva6-f2f4-20261031).
    assert refused == {'reduced_dual_axi_irq_cpu', 'axi4_cpu'}
    for kind in refused:
        gaps = cpu_axi4.AXI4_KIND_GAPS[kind]
        assert gaps and any('missing' in gap or 'inputs' in gap or 'unsupported' in gap
                            for gap in gaps), kind


# ---------------------------------------------------------------------------
# the shipped wrapper session (real session code, synthetic wire only)
# ---------------------------------------------------------------------------

def wrapper_class():
    from myfuzz.local_harness.vexii_axi_mmio_session import (
        GeneratedVexiiAxiMmioSession)
    return GeneratedVexiiAxiMmioSession


def session_artifact():
    return SimpleNamespace(
        runtime_document=dict(kind='reduced_dual_axi_cpu',
                              artifact_digest='0' * 64,
                              backend_ports=reduced_artifact().runtime_document[
                                  'backend_ports'],
                              physical_exports=[]),
        plan=SimpleNamespace(request=SimpleNamespace(instance_id='cpu',
                                                     max_wait_cycles=16)))


def make_session(tmp_path, *, router=None, **options):
    memory = PersistentMemory(regions=(MemoryRegion('ram', BOOT, 0x10000),),
                              initialization_seed=0,
                              max_initialized_bytes=0x10000)
    session = wrapper_class()(session_artifact(), base_dir=tmp_path,
                              cache_dir=tmp_path, memory=memory,
                              router=router, **options)
    return session, memory


class Wire:
    """The only replaced transport: a synthetic one-tick driver receipt.

    Every session rule -- acceptance, response matching, the observer, the
    ledger, the park -- still runs for real.  ``plan`` holds the roles the
    modelled core drives on the next tick; the commanded role values are
    echoed back unchanged, which is what a real driver reports.
    """

    def __init__(self, session, monkeypatch):
        self.session = session
        self.plan = {}
        self.calls = []
        monkeypatch.setattr(type(session), 'command', self._command)
        monkeypatch.setattr(type(session), 'begin_case', self._begin)

    @staticmethod
    def _begin(session, testcase_id):
        session._execution = 'a' * 32
        session._case_id = testcase_id
        session._sequence = 0
        session.local_ticks = 0
        session._tick_base = 0
        session._clear()

    def _command(self, operation, fields):
        from myfuzz.local_harness.wire import parse_driver_receipt
        session = self.session
        assert operation == 'STEP_REDUCED_AXI'
        assert len(fields) == len(STEP_PORTS)
        self.calls.append((operation, fields))
        sequence = session._sequence + 1
        before = session.local_ticks
        row = backend({**dict(zip(STEP_PORTS, fields)), **self.plan})
        sample = dict(local_tick=before + 1, pre={'backend': row},
                      post={'backend': dict(row)})
        payload = dict(schema_version='local_driver_result.v1',
                       kind='reduced_dual_axi_cpu', samples=[sample],
                       pre_backend=row, observations={'physical': {}},
                       rdata=0, error=0)
        encoded = json.dumps(payload, sort_keys=True,
                             separators=(',', ':')).encode().hex()
        receipt = parse_driver_receipt(
            f'RESULT {session._execution} {sequence:x} '
            f'{before:x} {before + 1:x} {encoded}',
            execution=session._execution, sequence=sequence,
            current_tick=before, kind='reduced_dual_axi_cpu')
        session._sequence = sequence
        session.local_ticks = before + 1
        return receipt


def test_the_wrapper_adds_only_the_executor_surface():
    from myfuzz.local_harness.session import GeneratedLocalSession
    from myfuzz.local_harness.vexii_axi_session import GeneratedReducedAxiCpuSession
    cls = wrapper_class()
    assert issubclass(cls, GeneratedReducedAxiCpuSession)
    for name in ('declare_instruction_slots', 'accept_instructions',
                 '_resume_instruction', 'queue_mmio', 'identity_document'):
        assert callable(getattr(cls, name)), name
    for name in ('waiting_instruction_address', 'parked_instruction_address'):
        assert isinstance(getattr(cls, name), property), name
    # The build-receipt lifecycle is inherited, never re-implemented.
    for name in ('prepare_local', 'configure_built_executable_receipt',
                 'validate_built_executable_receipt'):
        assert getattr(cls, name) is getattr(GeneratedLocalSession, name), name
    # The measured step and its one-tick contract stay the shared session's.
    assert cls.step_local is GeneratedReducedAxiCpuSession.step_local
    assert cls._step_inputs is GeneratedReducedAxiCpuSession._step_inputs
    assert cls.max_local_ticks_per_step == 1
    assert cls.max_mmio_target_accesses_per_step == 0
    assert cpu_axi4.executor_gaps(cls) == ()


def test_the_executor_router_keyword_is_the_shared_mmio_router(tmp_path):
    router = DataflowRouter((DeviceWindow('peripheral', MMIO, 0x1000,
                                          SimpleNamespace()),))
    session, _ = make_session(tmp_path, router=router)
    assert session.router is router
    assert session.mmio_router is router
    # The legacy keyword keeps working for the existing directed rows.
    legacy, _ = make_session(tmp_path, mmio_router=router)
    assert legacy.router is router
    # Two distinct routers are ambiguous, and a non-router is refused.
    other = DataflowRouter(())
    with pytest.raises(ValueError, match='declared twice'):
        make_session(tmp_path, router=router, mmio_router=other)
    with pytest.raises(ValueError, match='must be a DataflowRouter'):
        make_session(tmp_path, router=object())


def test_the_wrapper_identity_names_its_online_slot_service(tmp_path, monkeypatch):
    """Only the added document keys are asserted; the build identity is not
    available without a real artifact, so the inherited part is stubbed."""
    from myfuzz.local_harness.session import GeneratedLocalSession
    from myfuzz.local_harness.vexii_axi_mmio_session import ONLINE_SERVICE_SCHEMA
    monkeypatch.setattr(GeneratedLocalSession, 'identity_document',
                        lambda self: {'stubbed_inherited_identity': True})
    session, _ = make_session(tmp_path)
    session.declare_instruction_slots(BOOT, 2)
    document = session.identity_document()
    assert document['mmio_delivery'] == 'disabled'  # no router on this session
    service = document['online_instruction_service']
    assert service['schema_version'] == ONLINE_SERVICE_SCHEMA
    assert service['executor_router_keyword'] == 'router'
    assert service['declared_slots'] == 2
    assert service['supported_flows'] == ['F2', 'F4']


def test_memory_flow_options_are_implemented_and_unknown_ones_are_named(tmp_path):
    """The three executor options are real switches, not accepted placeholders."""
    from myfuzz.scenario.memory_service import MemoryService
    enabled, _ = make_session(tmp_path, memory_commit_receipts=True,
                              memory_readback_receipts=True,
                              physical_tick_samples=True)
    assert type(enabled.service) is MemoryService
    assert enabled.service.commit_stream_enabled is True
    assert enabled.service.include_writer_kinds is True
    assert enabled.memory_flows_enabled is True
    assert callable(enabled.drain_tick_samples)
    # A boolean-only surface: a truthy non-boolean is refused, never coerced.
    with pytest.raises(ValueError, match='must be boolean'):
        make_session(tmp_path, memory_commit_receipts=1)
    # Any other unknown keyword is still refused by name.
    with pytest.raises(ValueError, match='unsupported reduced AXI MMIO session options'):
        make_session(tmp_path, something_else=True)


def test_instruction_slots_are_declared_before_start(tmp_path):
    session, memory = make_session(tmp_path)
    assert session.waiting_instruction_address is None
    session.declare_instruction_slots(BOOT, 4)
    assert session._declared_slots == 4
    assert len(memory.reserved_instruction_bytes()) == 16
    with pytest.raises(ValueError, match='instruction slots cross memory window'):
        session.declare_instruction_slots(BOOT + 0x10000 - 8, 4)
    session._case_id = 'started'
    with pytest.raises(RuntimeError, match='pre-start declaration'):
        session.declare_instruction_slots(BOOT, 1)


def test_a_fetch_with_no_word_is_parked_after_its_accepted_AR(tmp_path, monkeypatch):
    """The core offers AR, the slot is empty: AR is accepted, R is withheld."""
    session, memory = make_session(tmp_path)
    session.declare_instruction_slots(BOOT, 4)
    wire = Wire(session, monkeypatch)
    session.begin_case('case')
    wire.plan = {'i_arvalid': 1, 'i_araddr': BOOT, 'i_arsize': 2, 'i_arid': 0}
    outputs = session.step_local({})
    assert outputs['i_ar_accepted'] == 1
    assert outputs['i_r_consumed'] == 0
    assert session.waiting_instruction_address == BOOT
    assert session.parked_instruction_address == BOOT
    document = session.online_instruction_document()
    assert document['parked_fetch_address'] == BOOT
    assert document['declared_bytes'] == 16
    # No word was materialized and no response was invented for this edge.
    assert memory.reserved_instruction_bytes()
    assert not [event for event in session._axi_observer.events
                if event['kind'] == 'reduced_axi_complete']
    # The core holds and gets no R until the word exists.
    wire.plan = {}
    outputs = session.step_local({})
    assert outputs['i_r_consumed'] == 0
    assert session.waiting_instruction_address == BOOT
    # Materialize the declared word.  The resume is a *step* event: the read
    # happens on the next measured edge and its R is withheld for one more
    # edge, so the acceptance -> read -> response order stays strict.
    session.accept_instructions(BOOT, (0x13).to_bytes(4, 'little'),
                                source_event_id='doc:0')
    assert session.waiting_instruction_address == BOOT
    wire.plan = {'i_rready': 1}
    outputs = session.step_local({})          # the resumed read happens here
    assert outputs['i_r_consumed'] == 0
    assert session.waiting_instruction_address is None
    assert session.parked_instruction_address is None
    outputs = session.step_local({})          # R is consumed one edge later
    assert outputs['i_r_consumed'] == 1
    reads = [event for event in session.service.events
             if event['kind'] == 'memory_read']
    sources = [event for event in session.service.events
               if event['kind'] == 'instruction_source']
    assert len(reads) == 1 and reads[0]['value'] == 0x13
    assert len(sources) == 1 and sources[0]['source_event_id'] == 'doc:0'
    accepted = [event for event in session._axi_observer.events
                if event['kind'] == 'reduced_axi_accept']
    assert [(event['endpoint_id'], event['channel']) for event in accepted] == \
        [('i', 'ar')]


def test_an_accepted_word_outside_the_parked_slot_does_not_resume_it(tmp_path,
                                                                   monkeypatch):
    session, _ = make_session(tmp_path)
    session.declare_instruction_slots(BOOT, 4)
    wire = Wire(session, monkeypatch)
    session.begin_case('case')
    wire.plan = {'i_arvalid': 1, 'i_araddr': BOOT, 'i_arsize': 2}
    session.step_local({})
    assert session.waiting_instruction_address == BOOT
    session.accept_instructions(BOOT + 4, (0x13).to_bytes(4, 'little'),
                                source_event_id='doc:1')
    assert session.waiting_instruction_address == BOOT
    session.accept_instructions(BOOT, (0x13).to_bytes(4, 'little'),
                                source_event_id='doc:2')
    assert session.waiting_instruction_address == BOOT  # resumed by a step
    session.step_local({})
    assert session.waiting_instruction_address is None


def test_an_instruction_fetch_may_never_reach_declared_mmio(tmp_path):
    from myfuzz.scenario.contracts import ProtocolEnvironmentError
    router = DataflowRouter((DeviceWindow('peripheral', MMIO, 0x1000,
                                          SimpleNamespace()),))
    session, _ = make_session(tmp_path, router=router)
    session._execution, session._case_id = 'a' * 32, 'case'
    key = TransactionKey('a' * 32, 'case', 'cpu', 0, 'instr', 1)
    with pytest.raises(ProtocolEnvironmentError, match='instruction MMIO'):
        session.queue_mmio(key, 'i', MMIO, False, 0, 15, lambda response: None)
    with pytest.raises(ProtocolEnvironmentError, match='cannot write'):
        session.queue_mmio(key, 'i', BOOT, True, 0, 15, lambda response: None)
    assert session.waiting_instruction_address is None


def test_the_lsu_face_keeps_the_shared_router_behavior(tmp_path):
    router = DataflowRouter((DeviceWindow('peripheral', MMIO, 0x1000,
                                          SimpleNamespace()),))
    session, memory = make_session(tmp_path, router=router)
    session._execution, session._case_id = 'a' * 32, 'case'
    materialized = []

    def callback(response):
        materialized.append(response)

    key = TransactionKey('a' * 32, 'case', 'cpu', 0, 'data', 1)
    assert session.queue_mmio(key, 'd', MMIO, False, 0, 15, callback) is True
    assert len(router.acceptances) == 1
    assert session.pending_responses == 0  # queued, answered by the target step
    assert not materialized
    # An address outside every declared window is not the router's.
    outside = TransactionKey('a' * 32, 'case', 'cpu', 0, 'data', 2)
    assert session.queue_mmio(outside, 'd', BOOT + 0x100, False, 0, 15,
                              callback) is False


# ---------------------------------------------------------------------------
# the shipped Vexii descriptor (configuration only, no RTL)
# ---------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / 'configs/scenarios/compiled-f2-f4-axi4-apb-i2c-vexii'


def test_the_vexii_descriptor_is_self_contained_and_declares_f2_f4():
    from myfuzz.runtime.generic_campaign import load_descriptor
    descriptor = load_descriptor(SCENARIO / 'generic_scenario.json', base_dir=ROOT)
    assert descriptor.flow_ids == ('F2', 'F4')
    assert descriptor.executors == {'F2': 'compiled_mmio', 'F4': 'compiled_mmio'}
    for member in (descriptor.compose, descriptor.supplement,
                   descriptor.capability):
        assert member.is_relative_to(descriptor.root) and member.is_file()
    # F1/F3 are deliberately absent: this session refuses the memory-flow
    # options the executor would have to pass for them.
    assert 'F1' not in descriptor.flow_ids and 'F3' not in descriptor.flow_ids


def test_the_vexii_descriptor_names_a_real_reduced_axi_cpu_and_apb_window():
    from myfuzz.local_harness import load_local_harness_request, plan_local_harness
    from myfuzz.local_harness.template_contracts import select_template_contract
    from myfuzz.composition.test_capability import load_ip_test_capability
    compose = json.loads((SCENARIO / 'compose.json').read_text())
    cpu_request = load_local_harness_request(
        json.loads((SCENARIO / compose['cpu']['request']).read_text()))
    cpu = plan_local_harness(cpu_request, base_dir=ROOT)
    # The pinned Vexii profile is the semantic admission the session requires.
    capabilities = dict(cpu.profile.capabilities)
    assert capabilities['single_beat_reduced_axi'] is True
    assert capabilities['bursts'] is False
    assert capabilities['address_width'] == 32
    bound = {endpoint.endpoint_id: endpoint for endpoint in cpu.binding.endpoints}
    assert compose['cpu']['data_endpoint'] in bound
    for endpoint in bound.values():
        assert select_template_contract(endpoint, capabilities) \
            .contract.template_id == 'cpu.axi4-reduced'
    # The instruction image resource must contain the declared reset vector.
    memory, = compose['memory']
    assert memory['component_instance'] == compose['cpu']['instance_id']
    assert memory['read'] is memory['write'] is memory['execute'] is True
    assert memory['base'] <= cpu.profile.cpu.reset_vector \
        < memory['base'] + memory['size']
    # The routed window is exactly the register the F2 record addresses.
    device, = compose['devices']
    request = load_local_harness_request(
        json.loads((SCENARIO / device['request']).read_text()))
    target = plan_local_harness(request, base_dir=ROOT)
    capability = load_ip_test_capability(SCENARIO / 'test_capability.json',
                                         profile=target.profile)
    assert capability.component_id == 'pulp_i2c'
    register, = capability.register_semantics
    # PRESCALER is the first word of apb_i2c.sv (offset 0) and the declared
    # 32-bit word carries only its low half.
    assert register.register == 'PRESCALER'
    assert (register.lsb, register.width) == (0, 32)
    assert register.read_mask == register.write_mask == 0xffff
    assert device['base'] < device['base'] + device['size']


def test_the_descriptor_records_decode_to_the_declared_register_and_values():
    from myfuzz.runtime.generic_campaign import load_descriptor
    from myfuzz.composition.test_capability import load_ip_test_capability
    from myfuzz.local_harness import load_local_harness_request, plan_local_harness
    descriptor = load_descriptor(SCENARIO / 'generic_scenario.json', base_dir=ROOT)
    compose = json.loads((SCENARIO / 'compose.json').read_text())
    device, = compose['devices']
    plan = plan_local_harness(load_local_harness_request(
        json.loads((SCENARIO / device['request']).read_text())), base_dir=ROOT)
    register, = load_ip_test_capability(SCENARIO / 'test_capability.json',
                                        profile=plan.profile).register_semantics
    # The corpus is little-endian 32-bit words, exactly what the candidate
    # layouts decode.
    decode = lambda row: int.from_bytes(bytes.fromhex(row), 'little')
    f2 = [decode(row) for row in descriptor.records('F2')]
    assert f2 and all(value == device['base'] + register.lsb for value in f2)
    for row in descriptor.records('F4'):
        assert 0 <= decode(row) <= register.write_mask, row
    # The ordered smoke uses only declared flows and declared records.
    sequence = json.loads((SCENARIO / 'acceptance_sequence.json').read_text())
    assert sequence and all(row.split(':')[0] in descriptor.flow_ids
                            for row in sequence)
    for row in sequence:
        flow, payload = row.split(':')
        assert payload in descriptor.records(flow), row
    # Every case advances far enough to reach its fragment boundary park.
    assert descriptor.rounds >= 128


# ---------------------------------------------------------------------------
# the shared plan layer: expectation, registry, admission, bound adapter
# ---------------------------------------------------------------------------

def rendered_vexii_artifact():
    """Render the pinned Vexii artifact from its profile; no RTL build."""
    from myfuzz.local_harness import (
        load_local_harness_request, plan_local_harness, render_local_harness,
        render_local_runtime, render_local_driver, verify_local_source_lock)
    request = load_local_harness_request(dict(
        schema_version='local_harness.v1',
        profile_path='configs/cpus/vexiiriscv/component_profile.json',
        instance_id='processor', reset_assert_ticks=12,
        reset_release_ticks=8, max_wait_cycles=16))
    plan = plan_local_harness(request, base_dir=ROOT)
    return render_local_driver(render_local_runtime(
        plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT),
        base_dir=ROOT)


def test_the_plan_compiler_expects_the_full_axi4_cpu_row():
    from myfuzz.runtime import compiler
    expectation = compiler._expectation_for('cpu', ('axi4', '1'))
    assert expectation.role == 'cpu'
    assert expectation.protocol == ('axi4', '1')
    assert expectation.semantic_kind == 'cpu.axi4.v1'
    assert expectation.address_units == 'byte'
    assert expectation.completion_kind == 'independent_channels_response'
    assert expectation.byte_enable is True
    assert expectation.adapter_id == 'axi4.cpu.v1'
    assert compiler._EXPECTATION_BY_ROLE[('cpu', ('axi4', '1'))] is expectation
    # The lite row is untouched and still distinct.
    assert compiler._expectation_for('cpu', ('axi4-lite', '1')).semantic_kind \
        == 'cpu.axi4-lite.v1'


def test_the_registry_admits_exactly_one_axi4_cpu_adapter():
    from myfuzz.runtime import registry
    rows = [row for row in registry.registrations()
            if row.adapter_id == 'axi4.cpu.v1']
    assert len(rows) == 1
    row = rows[0]
    assert row.protocol == ('axi4', '1')
    assert row.semantic_kinds == ('cpu.axi4.v1',)
    assert ('cpu.axi4-reduced', '1', 'fetch-single') in row.templates
    assert ('cpu.axi4-reduced', '1', 'data-single') in row.templates
    assert (row.data_widths, row.address_widths, row.address_units) == \
        ((32,), (32,), ('byte',))
    assert row.completion_kinds == ('independent_channels_response',)
    assert row.max_outstanding == 1 and row.byte_enable is True
    assert 'src/myfuzz/integration/cpu_axi4.py' in row.implementation_files
    assert 'src/myfuzz/local_harness/vexii_axi_mmio_session.py' \
        in row.implementation_files
    # A registry entry pins real files: the digest must be recomputable.
    assert len(row.implementation_sha256()) == 64


def test_only_the_axi4_cpu_registration_matches_the_admitted_endpoint():
    from myfuzz.runtime import admission, registry
    artifact = rendered_vexii_artifact()
    preparation = SimpleNamespace(
        declared_cpu_data_endpoint=lambda instance: 'processor.memory.d',
        declared_endpoint_template=lambda instance, endpoint:
            ('cpu.axi4-reduced', '1', 'data-single'))
    admitted = admission._reduced_axi_cpu_endpoints(
        artifact, preparation=preparation, base_dir=ROOT)
    endpoint = admitted['endpoints'][0]
    assert endpoint['role'] == 'cpu'
    assert endpoint['protocol'] == ['axi4', '1']
    assert endpoint['template'] == ['cpu.axi4-reduced', '1', 'data-single']
    assert endpoint['semantic_kind'] == 'cpu.axi4.v1'
    assert sorted(endpoint['operations']) == ['read', 'write']
    matches = [row.adapter_id for row in registry.registrations()
               if registry._registration_matches(row, endpoint)]
    assert matches == ['axi4.cpu.v1']
    assert admission._BUILTIN_VERIFIERS['reduced_dual_axi_cpu'] \
        is admission._reduced_axi_cpu_endpoints


def test_the_surface_document_is_deterministic_and_names_the_two_faces():
    from hashlib import sha256
    from myfuzz.runtime.adapters import axi4_cpu
    artifact = rendered_vexii_artifact()
    surface = axi4_cpu.reduced_axi_cpu_surface_document(artifact)
    again = axi4_cpu.reduced_axi_cpu_surface_document(artifact)
    assert surface == again
    assert surface['kind'] == 'cpu.axi4.v1'
    assert surface['endpoint_id'] == 'processor.memory.d'
    assert surface['template'] == ['cpu.axi4-reduced', '1', 'data-single']
    assert surface['fetch_endpoint_id'] == 'processor.memory.i'
    assert surface['fetch_template'] == ['cpu.axi4-reduced', '1', 'fetch-single']
    assert len(surface['roles']) == len(axi4_cpu.CPU_DATA_ROLES)
    assert len(surface['fetch_roles']) == len(axi4_cpu.CPU_FETCH_ROLES)
    assert (surface['address_width'], surface['data_width'],
            surface['byte_enable_width']) == (32, 32, 4)
    assert surface['completion_kind'] == 'independent_channels_response'
    assert surface['error_observed'] is True
    assert surface['instruction_identity'] == 'declared_fetch_face_ar_only'
    assert surface['first_fetch_observation'] == 'accepted_i_AR_address'
    # No LEN/BURST/LOCK/QOS pin is invented: the pinned ABI really has none.
    for role in ('arlen', 'awlen', 'arburst', 'awburst', 'arlock', 'awlock',
                 'arqos', 'awqos'):
        assert role not in {row[0] for row in surface['roles']}
    assert sha256(json.dumps(surface, sort_keys=True,
                             separators=(',', ':')).encode()).hexdigest()


def test_the_admission_and_binding_digest_the_same_surface():
    from hashlib import sha256
    from myfuzz.runtime import admission
    from myfuzz.runtime.contracts import canonical_json_bytes
    from myfuzz.runtime.adapters import axi4_cpu
    artifact = rendered_vexii_artifact()
    preparation = SimpleNamespace(
        declared_cpu_data_endpoint=lambda instance: 'processor.memory.d',
        declared_endpoint_template=lambda instance, endpoint:
            ('cpu.axi4-reduced', '1', 'data-single'))
    admitted = admission._reduced_axi_cpu_endpoints(
        artifact, preparation=preparation, base_dir=ROOT)
    expected = sha256(canonical_json_bytes(
        axi4_cpu.reduced_axi_cpu_surface_document(artifact))).hexdigest()
    assert admitted['semantic_contract_sha256'] == expected


def test_the_bound_adapter_binds_the_wrapper_session(tmp_path):
    from myfuzz.runtime import admission, registry
    from myfuzz.runtime.adapters import axi4_cpu
    from myfuzz.runtime.contracts import AdapterSelection, VerifiedComponent
    artifact = rendered_vexii_artifact()
    preparation = SimpleNamespace(
        declared_cpu_data_endpoint=lambda instance: 'processor.memory.d',
        declared_endpoint_template=lambda instance, endpoint:
            ('cpu.axi4-reduced', '1', 'data-single'))
    admitted = admission._reduced_axi_cpu_endpoints(
        artifact, preparation=preparation, base_dir=ROOT)
    component = VerifiedComponent(
        instance_id='processor',
        source_sha256=admission._source_sha256(artifact),
        profile_sha256=admission._profile_sha256(artifact),
        artifact_sha256=artifact.runtime_document['artifact_digest'],
        semantic_contract_sha256=admitted['semantic_contract_sha256'],
        descriptor_bytes=json.dumps(dict(
            schema_version='verified_component_descriptor.v1',
            instance_id='processor',
            source_sha256=admission._source_sha256(artifact),
            profile_sha256=admission._profile_sha256(artifact),
            artifact_sha256=artifact.runtime_document['artifact_digest'],
            semantic_contract_sha256=admitted['semantic_contract_sha256'],
            source_verifier=admitted['source_verifier'],
            endpoints=admitted['endpoints']),
            sort_keys=True, separators=(',', ':')).encode())
    pin = next(row for row in registry.registrations()
               if row.adapter_id == 'axi4.cpu.v1').implementation_sha256()
    selection = AdapterSelection(
        adapter_id='axi4.cpu.v1', adapter_version='1',
        implementation_sha256=pin,
        component_artifact_sha256=component.artifact_sha256,
        semantic_contract_sha256=component.semantic_contract_sha256)
    session, _ = make_session(tmp_path)
    session.artifact = artifact
    bound = axi4_cpu.bind_reduced_axi_cpu_adapter(
        component=component, session=session, selection=selection,
        endpoint_id='processor.memory.d')
    assert bound.adapter_id == 'axi4.cpu.v1'
    assert bound.protocol == ('axi4', '1')
    assert bound.semantic_kind == 'cpu.axi4.v1'
    assert bound.template == ('cpu.axi4-reduced', '1', 'data-single')
    assert bound.endpoint_id == 'processor.memory.d'
    bound.assert_current()
    slots = bound.program_slots['instruction.boot']
    assert slots['kind'] == 'online_instruction_slots'
    assert slots['declare_slots'] == 'declare_instruction_slots'
    assert slots['parked_fetch'] == 'waiting_instruction_address'
    assert bound.local_step_map['completion_kind'] == \
        'independent_channels_response'
    bound.close()

    # A session that is not the wrapper cannot be bound to this row.
    from myfuzz.local_harness.vexii_axi_session import GeneratedReducedAxiCpuSession
    from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
    memory = PersistentMemory(regions=(MemoryRegion('ram', BOOT, 0x10000),),
                              initialization_seed=0, max_initialized_bytes=0x10000)
    base = GeneratedReducedAxiCpuSession(session_artifact(), base_dir=tmp_path,
                                         cache_dir=tmp_path, memory=memory)
    base.artifact = artifact
    with pytest.raises(ValueError) as refused:
        axi4_cpu.bind_reduced_axi_cpu_adapter(
            component=component, session=base, selection=selection)
    assert refused.value.code == 'generic-binding-drift'
    assert 'exact-GeneratedVexiiAxiMmioSession-required' in str(refused.value.detail)


def test_the_binding_registers_the_axi4_cpu_factory():
    from myfuzz.runtime import binding
    factory = binding._FACTORIES['axi4.cpu.v1']
    assert callable(factory)
    # The integrated seam resolves the same adapter id the compiler expects.
    from myfuzz.runtime import compiler
    assert compiler._expectation_for('cpu', ('axi4', '1')).adapter_id \
        in binding._FACTORIES


# ---------------------------------------------------------------------------
# replay normalization of the reduced-AXI observation stream
#
# The runner admits that stream unconditionally for a reduced-AXI session and its
# first operation binds the per-launch execution nonce, so every digest the
# exporter derives from that envelope is process-local.  The F2/F4 prefix
# normalizer must ignore exactly those and nothing else.
# ---------------------------------------------------------------------------

NONCE_A = 'a1b2c3d4e5f60718293a4b5c6d7e8f90'
NONCE_B = '0f1e2d3c4b5a69788796a5b4c3d2e1f0'
REAL_DIGEST_A = '2d78111e8b6fb93523f87b805338706afdbcd6c5c4beb72771fd272b3c271c1d'
REAL_DIGEST_B = 'db1a9b75f6d2f3ee5da4e5cc10e23fbf03cfbe396dc8ba6a9ab2290cb20dbdd2'


def f6_prefix(*, nonce, digest, origin_nonce=None, address=0x40000000,
              data_hex='13', records=1, kind='reduced_axi_source_operation',
              extra=None):
    """One closed prefix whose only process-local content is the nonce."""
    origin = origin_nonce or nonce
    event = {
        'event_id': 3, 'component': 'processor', 'kind': kind,
        'producer_event_id': 1, 'schema_version': 'observation_stream_operation.v1',
        'stream_binding_event_id': 2,
        'operation': {
            'schema_version': 'observation_stream_operation.v1',
            'binding_digest': 'b' * 64,
            'operation_index': 1, 'kind': 'receipt',
            'content_digest': digest,
            'first_record_index': 1, 'record_count': records,
            'payload': {
                'authority': 'observation_only',
                'runtime_accepted': False, 'semantic_accepted': False,
                'scope': {'execution_id': origin, 'testcase_id': 'case',
                          'reset_epoch': 0, 'source_component': 'processor'},
                'wire_command': 'CMD ' + nonce + ' 1 STEP_REDUCED_AXI 1',
                'wire_reply': 'RESULT ' + nonce + ' 1 0 1 ' + data_hex,
                'address': address, 'data_hex': data_hex,
                'cumulative_after': 1, 'tick_base': 0,
            },
            'observations': [{
                'kind': 'reduced_axi_accept', 'endpoint_id': 'd', 'channel': 'aw',
                'local_tick': 1, 'scope': {'execution_id': origin},
                'payload': {'awaddr': address, 'awsize': 2},
                'raw_event_refs': [1],
            }],
        },
    }
    if extra:
        event.update(extra)
    return {
        'schema_version': 'compiled_mmio_prefix.v1',
        'run_id': 'vexii-axi4',
        'records': [],
        'actual_events': [
            {'event_id': 1, 'component': 'scheduler', 'kind': 'scheduler_start'},
            {'event_id': 2, 'component': 'processor', 'kind': 'reduced_axi_stream_binding',
             'binding': {'artifact_digest': 'c' * 64, 'source_component': 'processor'}},
            event,
        ],
        'original_execution_audit': {'identities': {
            'processor': {'component': 'processor', 'role': 'cpu',
                          'execution_nonce': nonce, 'pid': 4242},
            'peripheral': {'component': 'peripheral', 'role': 'bound_target',
                           'execution_nonce': 'f0e1d2c3b4a5968778695a4b3c2d1e0f',
                           'pid': 4343},
        }},
    }


def normalized(prefix):
    from myfuzz.integration.compiled_f6 import _normalized_f6_prefix
    return _normalized_f6_prefix(prefix)


def test_only_the_process_local_nonce_and_its_digests_are_normalized():
    first = f6_prefix(nonce=NONCE_A, digest=REAL_DIGEST_A)
    fresh = f6_prefix(nonce=NONCE_B, digest=REAL_DIGEST_B)
    one, two = normalized(first), normalized(fresh)
    assert one == two
    # The rest of the operation is still there, field by field.
    operation = one['actual_events'][2]['operation']
    assert operation['payload']['address'] == 0x40000000
    assert operation['payload']['data_hex'] == '13'
    assert operation['record_count'] == 1
    assert operation['content_digest'] == '<process-local-derivation>'
    assert operation['payload']['scope']['execution_id'] == '<cpu-execution>'
    assert '<cpu-execution>' in operation['payload']['wire_reply']
    assert operation['observations'][0]['payload'] == {'awaddr': 0x40000000,
                                                       'awsize': 2}


@pytest.mark.parametrize('change', [
    {'address': 0x40001000},
    {'data_hex': '55'},
    {'records': 2},
    {'origin_nonce': NONCE_A},          # scope nonce differs from the identity
])
def test_a_real_stream_difference_is_still_detected(change):
    first = f6_prefix(nonce=NONCE_A, digest=REAL_DIGEST_A)
    fresh = f6_prefix(nonce=NONCE_B, digest=REAL_DIGEST_B, **change)
    assert normalized(first) != normalized(fresh)


def test_a_different_observation_payload_is_still_detected():
    first = f6_prefix(nonce=NONCE_A, digest=REAL_DIGEST_A)
    fresh = f6_prefix(nonce=NONCE_B, digest=REAL_DIGEST_B)
    fresh['actual_events'][2]['operation']['observations'][0]['payload'] = {
        'awaddr': 0x40000004, 'awsize': 2}
    assert normalized(first) != normalized(fresh)


def test_non_reduced_axi_events_keep_their_digests():
    first = f6_prefix(nonce=NONCE_A, digest=REAL_DIGEST_A)
    fresh = f6_prefix(nonce=NONCE_B, digest=REAL_DIGEST_B)
    for prefix, digest in ((first, REAL_DIGEST_A), (fresh, REAL_DIGEST_B)):
        row = prefix['actual_events'][2]
        row['kind'] = 'other_observation_stream_operation'
        row['operation']['content_digest'] = digest
    assert normalized(first) != normalized(fresh)
    # Same digest and same nonce-bearing text -> only the nonce differs, and a
    # non reduced-AXI row is not allowed to hide it.
    first['actual_events'][2]['operation']['content_digest'] = REAL_DIGEST_A
    fresh['actual_events'][2]['operation']['content_digest'] = REAL_DIGEST_A
    assert normalized(first) != normalized(fresh)


def journal_binding(nonce, *, sha, event_id=21, record_index=1, scope_nonce=None):
    return {
        'event_id': event_id, 'component': 'processor',
        'kind': 'reduced_axi_journal_binding',
        'producer_event_id': 20,
        'schema_version': 'reduced_axi_journal_binding.v1',
        'scope': {'execution_id': scope_nonce or nonce, 'testcase_id': 'case',
                  'reset_epoch': 0, 'source_component': 'processor'},
        'stream_binding_event_id': 2, 'operation_event_id': 3,
        'observation_event_id': 19, 'record_index': record_index,
        'observation_sha256': sha,
        'resolved_refs': [{'role': 'raw_event_ref', 'local_refs': [1],
                           'event_ids': [21]}],
        'authority': 'observation_only', 'runtime_accepted': False,
        'semantic_accepted': False,
    }


def test_a_journal_binding_digest_derived_from_the_nonce_is_normalized():
    """``observation_sha256`` hashes a record whose scope holds the nonce."""
    first = f6_prefix(nonce=NONCE_A, digest=REAL_DIGEST_A)
    fresh = f6_prefix(nonce=NONCE_B, digest=REAL_DIGEST_B)
    first['actual_events'].append(
        journal_binding(NONCE_A, sha=REAL_DIGEST_A))
    fresh['actual_events'].append(
        journal_binding(NONCE_B, sha=REAL_DIGEST_B))
    one, two = normalized(first), normalized(fresh)
    assert one == two
    binding = one['actual_events'][-1]
    assert binding['scope']['execution_id'] == '<cpu-execution>'
    assert binding['observation_sha256'] == '<process-local-derivation>'
    # The rest of the journal row still compares field by field.
    assert binding['record_index'] == 1 and binding['observation_event_id'] == 19
    assert binding['resolved_refs'] == [{'role': 'raw_event_ref',
                                         'local_refs': [1], 'event_ids': [21]}]


def test_a_journal_binding_real_difference_is_still_detected():
    first = f6_prefix(nonce=NONCE_A, digest=REAL_DIGEST_A)
    fresh = f6_prefix(nonce=NONCE_B, digest=REAL_DIGEST_B)
    first['actual_events'].append(journal_binding(NONCE_A, sha=REAL_DIGEST_A))
    fresh['actual_events'].append(
        journal_binding(NONCE_B, sha=REAL_DIGEST_A, record_index=2))
    assert normalized(first) != normalized(fresh)


def test_an_artifact_identity_digest_is_never_replaced():
    """Stream digests that identify the artifact keep their value."""
    first = f6_prefix(nonce=NONCE_A, digest=REAL_DIGEST_A)
    fresh = f6_prefix(nonce=NONCE_B, digest=REAL_DIGEST_B)
    first['actual_events'].append(journal_binding(NONCE_A, sha=REAL_DIGEST_A))
    fresh['actual_events'].append(journal_binding(NONCE_B, sha=REAL_DIGEST_B))
    fresh['actual_events'][2]['operation']['payload']['artifact_digest'] = 'd' * 64
    assert normalized(first) != normalized(fresh)
