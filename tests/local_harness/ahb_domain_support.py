"""Explicit measured manager-domain rows for software observer controls.

These helpers never infer the domain from the thirteen external protocol roles:
every edge carries separate one-bit ``manager_ready``/``bus_reset_n`` PRE/POST
values, and a command observation first establishes a measured bus-reset
assertion then release.
"""
from __future__ import annotations

import copy
from pathlib import Path

from myfuzz.local_harness.ahb_manager_domain import software_manager_domain_contract
from myfuzz.local_harness.ahb_startup import startup_contract
from myfuzz.local_harness.wire import MAX_REPLY_LINE_BYTES
from myfuzz.scenario.ahb_cpu_events import SHAPE
from myfuzz.scenario.ledger import TransactionLedger
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.protocol_io import BoundedLineReader


def domain_values(*, manager_ready, bus_reset_n):
    return {'pre': {'manager_ready': int(manager_ready), 'bus_reset_n': int(bus_reset_n)},
            'post': {'manager_ready': int(manager_ready), 'bus_reset_n': int(bus_reset_n)}}


def startup_rows(*, manager_ready=0, bus_reset_n=0, **taps):
    row = dict.fromkeys(SHAPE, 0)
    row.update(taps)
    return {'pre': copy.deepcopy(row), 'post': copy.deepcopy(row),
            'domain': domain_values(manager_ready=manager_ready,
                                    bus_reset_n=bus_reset_n)}


def startup_record(index, *, bus_reset_n, manager_ready=0, asserted=0, **taps):
    row = dict.fromkeys(SHAPE, 0)
    row.update(taps)
    return dict(startup_edge_index=index, reset_pre=int(asserted),
                reset_post=int(asserted),
                sample=dict(local_tick=index,
                            pre=dict(protocol_taps=copy.deepcopy(row),
                                     domain={'manager_ready': int(manager_ready),
                                             'bus_reset_n': int(bus_reset_n)}),
                            post=dict(protocol_taps=copy.deepcopy(row),
                                      domain={'manager_ready': int(manager_ready),
                                              'bus_reset_n': int(bus_reset_n)})))


def start_measured_prefix(observer):
    """Two measured edges: actual bus-reset assertion then release."""
    contract = startup_contract(assert_ticks=1, release_ticks=1, snapshot_max={})
    domain = observer.contract.get('domain_contract')
    if domain is None:
        domain = software_manager_domain_contract(
            protocol_endpoint_id=observer.endpoint_id)
    observer.begin_startup({**contract, 'manager_domain': copy.deepcopy(domain)})
    for index, reset_n in ((1, 0), (2, 1)):
        record = startup_record(index, bus_reset_n=reset_n,
                                asserted=int(index <= 1))
        observer.observe_startup(record, rows={
            'pre': dict(record['sample']['pre']['protocol_taps']),
            'post': dict(record['sample']['post']['protocol_taps']),
            'domain': {'pre': {'manager_ready': 0, 'bus_reset_n': reset_n},
                       'post': {'manager_ready': 0, 'bus_reset_n': reset_n}}})
    observer.finish_startup()


def command_sample(tick, *, manager_ready=0, bus_reset_n=1, **taps):
    row = dict.fromkeys(SHAPE, 0)
    row.update(taps)
    return dict(local_tick=tick, pre=copy.deepcopy(row), post=copy.deepcopy(row),
                domain=domain_values(manager_ready=manager_ready,
                                     bus_reset_n=bus_reset_n))


def install_session_constructor_state(session):
    """Give an ``object.__new__`` session the state its constructor installs.

    Direct controls build ``GeneratedAhbMemorySession`` without running
    ``__init__`` so they can substitute a synthetic transport, but the
    constructor is the *only* producer of the session state the real step/reset
    paths read (pending/queued MMIO, instruction sources, startup receipts, ...).
    Skipping it therefore leaves the control conforming to an older contract.
    This installs that state with inert defaults; the caller must set
    ``session.memory`` first and then override the surface it substitutes.
    Keep this in step with ``GeneratedLocalSession.__init__``,
    ``GeneratedNativeMemorySession.__init__`` and
    ``GeneratedAhbMemorySession.__init__``.
    """
    # GeneratedLocalSession.__init__
    session.base_dir = Path('.')
    session.cache_dir = Path('.')
    session.command_timeout_seconds = 10.0
    session._prepare_attempted = False
    session._start_attempted = False
    session._built_launches = []
    session._built_preparation_failure = None
    session._binary = None
    session._process = None
    session._reader = BoundedLineReader(max_line_bytes=MAX_REPLY_LINE_BYTES)
    session._execution = ''
    session._sequence = 0
    session._acknowledged = 0
    session.local_ticks = 0
    session._tick_base = 0
    session.reset_epoch = 0
    session._case_id = None
    session._native_reset_observation = None
    session._native_reset_build_issuance = None
    session._last_wire_reply = None
    # GeneratedNativeMemorySession.__init__
    session.service = MemoryService(session.memory, TransactionLedger())
    session.router = None
    session.mmio_write_count = 0
    session.mmio_read_count = 0
    session._pending = None
    session._pending_error = 0
    session._queued_mmio = False
    session._sequence_memory = 0
    session._quiescing = False
    session.memory_write_count = 0
    session.native_instruction_fetch_count = 0
    session.accepted_addresses = []
    session.last_samples = ()
    session._online_instruction_slots = False
    session._native_bus_observer = None
    session._native_source_completion_session = None
    session._physical_tick_samples_enabled = False
    # GeneratedAhbMemorySession.__init__
    session.defer_mmio = False
    session.hold_declared_instructions = False
    session._ahb_startup_required = True
    session._ahb_startup_complete = False
    session._ahb_startup_receipts = []
    session._ahb_startup_records = []
    session._last_ahb_receipt = None
    session.instruction_source = None
    session.instruction_hold_ticks = 0
    session.instruction_hold_addresses = []
    return session
