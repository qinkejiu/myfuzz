"""Explicit measured manager-domain rows for software observer controls.

These helpers never infer the domain from the thirteen external protocol roles:
every edge carries separate one-bit ``manager_ready``/``bus_reset_n`` PRE/POST
values, and a command observation first establishes a measured bus-reset
assertion then release.
"""
from __future__ import annotations

import copy

from myfuzz.local_harness.ahb_manager_domain import software_manager_domain_contract
from myfuzz.local_harness.ahb_startup import startup_contract
from myfuzz.scenario.ahb_cpu_events import SHAPE


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
