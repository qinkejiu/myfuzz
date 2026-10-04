"""Deterministic, component-local frequency schedule for generated RTL clocks."""
from __future__ import annotations

import re
from typing import Iterable

from myfuzz.composition.component_profile import ClockBinding, ResetBinding


MAX_CLOCK_RATIO = 1024
_IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z0-9_$]*\Z')


def build_local_clock_schedule(clocks: Iterable[ClockBinding],
                              resets: Iterable[ResetBinding], *,
                              reset_assert_ticks: int,
                              reset_release_ticks: int) -> dict[str, object]:
    """Validate clock/reset declarations and return their artifact identity.

    The fastest declared frequency is one local period per command tick. Every
    other domain toggles at the fixed ``ratio // 2`` boundaries, with all clocks
    starting low. Thus its first rising edge is half a period after schedule
    origin, and coincident transitions are evaluated in the same DUT eval.
    ``reset_assert_ticks`` and ``reset_release_ticks`` are fastest-domain ticks.
    """
    clock_rows = tuple(clocks)
    reset_rows = tuple(resets)
    if not clock_rows or not reset_rows:
        raise ValueError('local-clock-schedule-unsupported:clock-reset-required')
    if (type(reset_assert_ticks) is not int or reset_assert_ticks < 1
            or type(reset_release_ticks) is not int or reset_release_ticks < 0):
        raise ValueError('local-clock-schedule-unsupported:invalid-reset-ticks')

    seen_ports: set[str] = set()
    seen_domains: set[str] = set()
    domain_frequencies: dict[str, int] = {}
    for binding in clock_rows:
        if (not isinstance(binding, ClockBinding)
                or type(binding.frequency_hz) is not int or binding.frequency_hz <= 0):
            raise ValueError('local-clock-schedule-unsupported:frequency_must_be_positive')
        if (not isinstance(binding.port, str) or _IDENTIFIER.fullmatch(binding.port) is None
                or not isinstance(binding.domain, str) or _IDENTIFIER.fullmatch(binding.domain) is None):
            raise ValueError('local-clock-schedule-unsupported:invalid_clock_identity')
        if binding.port in seen_ports:
            raise ValueError('local-clock-schedule-unsupported:duplicate_clock_port')
        seen_ports.add(binding.port)
        if binding.domain in seen_domains:
            raise ValueError('local-clock-schedule-unsupported:duplicate_clock_domain')
        seen_domains.add(binding.domain)
        previous = domain_frequencies.setdefault(binding.domain, binding.frequency_hz)
        if previous != binding.frequency_hz:
            raise ValueError('local-clock-schedule-unsupported:conflicting_domain_frequency')

    fast_frequency_hz = max(domain_frequencies.values())
    fastest_domains = sorted(domain for domain, frequency in domain_frequencies.items()
                             if frequency == fast_frequency_hz)
    primary_clock_domain = fastest_domains[0]
    schedule_clocks = []
    for domain in sorted(domain_frequencies):
        frequency = domain_frequencies[domain]
        if fast_frequency_hz % frequency:
            raise ValueError('local-clock-schedule-unsupported:non_integral_ratio')
        ratio = fast_frequency_hz // frequency
        if ratio != 1 and ratio % 2:
            raise ValueError('local-clock-schedule-unsupported:odd_ratio')
        if ratio > MAX_CLOCK_RATIO:
            raise ValueError('local-clock-schedule-unsupported:ratio_exceeds_limit')
        half_period = 1 if ratio == 1 else ratio // 2
        if reset_assert_ticks < half_period:
            raise ValueError('local-clock-schedule-unsupported:reset_edge_not_sampled')
        signal = 'clk' if domain == primary_clock_domain else 'clk_' + domain
        schedule_clocks.append({
            'domain': domain,
            'signal': signal,
            'frequency_hz': frequency,
            'ratio': ratio,
            'half_period_fast_ticks': half_period,
            'first_rising_fast_tick': half_period,
        })

    seen_reset_ports: set[str] = set()
    reset_domains: set[str] = set()
    for binding in reset_rows:
        if not isinstance(binding, ResetBinding):
            raise ValueError('local-clock-schedule-unsupported:invalid_reset_binding')
        if (not isinstance(binding.port, str) or _IDENTIFIER.fullmatch(binding.port) is None
                or not isinstance(binding.domain, str) or _IDENTIFIER.fullmatch(binding.domain) is None
                or binding.polarity not in ('active_high', 'active_low')
                or type(binding.synchronous) is not bool):
            raise ValueError('local-clock-schedule-unsupported:invalid_reset_identity')
        if binding.port in seen_reset_ports:
            raise ValueError('local-clock-schedule-unsupported:duplicate_reset_port')
        seen_reset_ports.add(binding.port)
        if binding.sequence_after:
            raise ValueError('local-reset-sequence-unsupported')
        reset_domains.add(binding.domain)

    primary_reset_domain = (primary_clock_domain if primary_clock_domain in reset_domains
                            else sorted(reset_domains)[0])
    schedule_resets = [
        {
            'port': binding.port,
            'domain': binding.domain,
            'signal': 'reset' if binding.domain == primary_reset_domain else
                      'reset_' + binding.domain,
            'polarity': binding.polarity,
            'synchronous': binding.synchronous,
        }
        for binding in sorted(reset_rows, key=lambda item: (item.domain, item.port))
    ]
    return {
        'schema_version': 'local_clock_schedule.v1',
        'fast_frequency_hz': fast_frequency_hz,
        'primary_clock_domain': primary_clock_domain,
        'primary_reset_domain': primary_reset_domain,
        'phase_policy': 'all_low_then_half_period_toggle',
        'clock_edges_observed': 'rising_edges_since_ready',
        'startup_fast_ticks': reset_assert_ticks + reset_release_ticks,
        'clocks': schedule_clocks,
        'resets': schedule_resets,
    }


def clock_signal_by_port(clocks: Iterable[ClockBinding],
                         schedule: dict[str, object]) -> dict[str, str]:
    rows = {row['domain']: row for row in schedule['clocks']}
    return {binding.port: rows[binding.domain]['signal'] for binding in clocks}


def reset_signal_by_port(resets: Iterable[ResetBinding],
                         schedule: dict[str, object]) -> dict[str, str]:
    rows = {row['domain']: row for row in schedule['resets']}
    return {binding.port: rows[binding.domain]['signal'] for binding in resets}
