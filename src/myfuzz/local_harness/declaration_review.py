"""P7-A: review one component's declaration before anything is generated.

The plan's rule is *refuse first, then generate*: a profile that does not state
what the harness would need must produce a located, machine-readable review row
rather than a harness that merely looks runnable.  This module therefore never
guesses a semantic fact.  In particular an interrupt's polarity, hold and clear
behaviour are only ever *read* from the profile; an endpoint whose role happens
to be called ``irq`` is not evidence of anything (the plan forbids inferring
them from a port name), so an undeclared interrupt is reported as `missing`
rather than assumed.

Every dimension is judged with the authority the generator itself uses, never
with a second copy of the rule:

``ownership``
    ``composition.soc_port_dispositions.build_port_dispositions`` classifies
    every physical port and bit of the bound component; this module reads that
    ledger.  It does not assemble its own port list, and it does not label a
    port with a disposition the ledger did not assign.
``endpoint`` / ``address``
    The loader's own vocabularies (``FUNCTION_DIRECTIONS``) and the ledger's own
    function-to-target table (``FUNCTION_TARGETS``).
``clock`` / ``reset``
    ``local_harness.clock_schedule.build_local_clock_schedule`` validates the
    declared clock and reset bindings; the tick parameters it also takes are a
    request fact, so the probe below passes the schedule's own ratio ceiling and
    nothing this module reports depends on them.
``interrupt``
    Only the declared interrupt records are read; nothing is inferred from a
    port name, and an interrupt-source endpoint with no declared form is
    refused instead of being driven on an assumption.

Every check reports one of:

``ok``
    the fact this harness needs is declared, and its declaration is coherent.
``missing``
    the fact is absent. Generation must not proceed on a guess.
``conflict``
    the fact is declared twice, or in a way that contradicts another declared
    fact, so the profile is internally inconsistent.
``unsupported``
    the fact is declared but this local harness has no admitted path for it.

Each row carries a ``pointer`` - a JSON pointer into the profile document - so a
caller can locate the declaration instead of searching for it.  The review
document always states ``generated: false``: this module never produces a
harness, only the refusal or the admission that precedes one.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
import json
from pathlib import Path

from myfuzz.composition.component_profile import (
    FUNCTION_DIRECTIONS, POLARITIES, ComponentProfileError, load_component_profile,
)
from myfuzz.composition.soc_port_dispositions import (
    FUNCTION_TARGETS, PortDispositionError, build_port_dispositions,
    disposition_summary, exported_ports, fuzz_ports,
)
from myfuzz.local_harness.clock_schedule import (
    MAX_CLOCK_RATIO, build_local_clock_schedule,
)

#: Version of the review document. Bump when a row's shape changes.
REVIEW_SCHEMA_VERSION = 'declaration_review.v1'

#: The reset polarities this local harness can drive: the loader's own
#: vocabulary, and both of them are rendered.  The generated local top declares
#: its own reset high-active (``local_harness.renderer``) and
#: ``local_harness.port_rendering`` inverts exactly for an active-low
#: declaration, which tests/local_harness/test_multiclock_runtime.py pins for an
#: active-high domain (``= reset_aon;``, no inversion).  Reading the vocabulary
#: from the authority keeps a profile with a correctly declared active-high reset
#: - configs/peripherals/zipcpu_uart does - from being refused as unsupported.
SUPPORTED_RESET_POLARITIES = POLARITIES

#: Interrupt trigger kinds the harness has a declared detection strategy for.
#: The loader admits more than this (``INTERRUPT_TRIGGERS`` also has the edge
#: kinds), so an honestly declared edge trigger is a shape this harness has no
#: admitted path for - ``unsupported`` - rather than something to approximate.
SUPPORTED_INTERRUPT_TRIGGERS = ('level', 'pulse')

#: How each interrupt-form gap classifies. A gap that names something the
#: profile never declared is `missing`; one that contradicts another declaration
#: is `conflict`; one that is declared but has no admitted path is `unsupported`.
_INTERRUPT_GAP_STATUS = {
    'interrupt-endpoint-unknown': 'conflict',
    'interrupt-endpoint-function-mismatch': 'conflict',
    'interrupt-form-field-missing': 'missing',
    'interrupt-role-undeclared': 'missing',
    'interrupt-trigger-unsupported': 'unsupported',
}

#: The one transport the local harness binds as an external serial peer today.
#: A peer endpoint that is neither this nor a plain pin endpoint is not
#: something the current serial-peer policy can drive.
SUPPORTED_SERIAL_PEER_FORMAT = '8N1'

#: The disposition classes that give a physical input a declared owner.  This is
#: the ledger's own rule, not a second one: ``soc_port_dispositions`` publishes
#: it as "input_driver: exactly one of functional/constant/fuzz/external/peer
#: per bit" (``dispositions_document``) and enforces it in ``_validate_coverage``
#: (an input without a driver in that set is refused).  ``unconnected`` is the
#: class that exists precisely to say "nobody drives this"; an input left there
#: is an unowned input, and that is what the ownership row reports.
INPUT_OWNER_DISPOSITIONS = ('functional', 'constant', 'fuzz', 'external', 'peer')

#: The domain labels ``plan_local_harness`` passes to the ledger. They name the
#: local harness's own clock/reset nets (not profile semantics), and they are
#: copied here so the reviewed ledger is the same ledger generation builds.
LOCAL_CLOCK_DOMAIN = 'local_clock'
LOCAL_RESET_DOMAIN = 'local_reset'

_DISPOSITION_CODE_PATH = ('myfuzz.composition.soc_port_dispositions'
                          '.build_port_dispositions')
_ELABORATION_CODE_PATH = ('myfuzz.composition.component_profile'
                          '.elaborate_profile')
_PROFILE_CODE_PATH = ('myfuzz.composition.component_profile'
                      '.load_component_profile')
_CLOCK_CODE_PATH = ('myfuzz.local_harness.clock_schedule'
                    '.build_local_clock_schedule')

#: The disposition ledger's refusal tokens, mapped to the review row a caller
#: sees.  The token is the first field of the ledger's own reason string, so
#: this table transcribes the rejections ``build_port_dispositions`` and
#: ``_validate_coverage`` already raise - the plan's "structured refusal code
#: table over the existing rejection path" - and points at the profile block
#: that has to change.  A token that is not listed is reported as `unsupported`
#: with the raw reason: a new ledger refusal can never be mistaken for clean.
_LEDGER_REFUSALS = (
    ('inout-port-refusal', 'unsupported', 'port-direction-inout-unsupported',
     '/endpoints'),
    ('unsupported-endpoint-function', 'unsupported', 'endpoint-function-unadmitted',
     '/endpoints'),
    ('binding-required', 'conflict', 'profile-binding-required', '/endpoints'),
    ('input-without-driver', 'missing', 'physical-input-unowned', '/port_actions'),
    ('undisposed-port-bits', 'missing', 'port-bits-undisposed', '/port_actions'),
    ('bit-multiple-dispositions', 'conflict', 'port-bit-multiple-dispositions',
     '/port_actions'),
    ('disposition-direction-mismatch', 'conflict',
     'port-disposition-direction-mismatch', '/port_actions'),
    ('port-action-unknown-port', 'conflict', 'port-action-unknown-port',
     '/port_actions'),
    ('duplicate-port-action', 'conflict', 'port-action-duplicate', '/port_actions'),
    ('port-action-member-missing', 'conflict', 'port-action-member-missing',
     '/port_actions'),
    ('port-action-bits-outside-port', 'conflict', 'port-action-bits-outside-port',
     '/port_actions'),
    ('port-action-bits-not-contiguous', 'conflict',
     'port-action-bits-not-contiguous', '/port_actions'),
    ('constant-action-out-of-range', 'conflict', 'port-action-constant-out-of-range',
     '/port_actions'),
    ('fuzz-action-on-non-input', 'conflict', 'port-action-fuzz-on-non-input',
     '/port_actions'),
    ('observe-action-on-non-output', 'conflict', 'port-action-observe-on-non-output',
     '/port_actions'),
    ('fuzz-action-requires-drive-strategy', 'missing',
     'port-action-fuzz-strategy-required', '/port_actions'),
    ('external-action-requires-interface-contract', 'missing',
     'port-action-external-contract-required', '/port_actions'),
)

#: The loader's own refusal tokens, mapped to the profile block a caller has to
#: fix. The token itself is reported as the row's ``code`` - it is the reason the
#: generator would raise. Exact tokens come first; anything else is matched by
#: its leading keyword, so a loader refusal this table has never seen still
#: points at the right block. A token that matches nothing keeps the raw reason
#: and a root pointer rather than an invented location.
_PROFILE_REFUSAL_EXACT = {
    'document-must-be-object-or-path': '',
    'unsupported-profile-schema': '',
    'unsupported-component-kind': '/kind',
    'profile-clock-required': '/clocks',
    'profile-reset-required': '/resets',
    'peripheral-profile-requires-address': '/address',
    'cpu-profile-must-not-declare-mmio-address': '/address',
    'cpu-profile-requires-cpu-contract': '/cpu',
}
_PROFILE_REFUSAL_KEYWORDS = (
    ('interrupt', '/interrupts'),
    ('cpu', '/cpu'),
    ('port-action', '/port_actions'),
    ('drive', '/port_actions'),
    ('constant-port-action', '/port_actions'),
    ('reset', '/resets'),
    ('clock', '/clocks'),
    ('address', '/address'),
    ('register', '/address'),
    ('window', '/address'),
    ('capabilit', '/capabilities'),
    ('endpoint', '/endpoints'),
    ('physical', '/endpoints'),
    ('protocol', '/endpoints'),
    ('alias', '/endpoints'),
    ('port', '/endpoints'),
    ('role', '/endpoints'),
    ('source', '/source'),
    ('elaboration', '/source'),
    ('top-port', '/source'),
    ('filelist', '/source'),
)


def _pointer(*parts: object) -> str:
    """A JSON pointer into the profile document."""
    if not parts:
        return ''
    return '/' + '/'.join(str(part) for part in parts)


def _row(dimension, status, code, pointer, detail=None):
    if status not in ('ok', 'missing', 'conflict', 'unsupported'):
        raise ValueError('declaration-review-status-invalid:' + str(status))
    return {'dimension': dimension, 'status': status, 'code': code,
            'pointer': pointer, 'detail': detail}


def _text(value) -> str | None:
    return value if type(value) is str and value.strip() else None


# ---------------------------------------------------------------------------
# dimensions read straight from the declaration
# ---------------------------------------------------------------------------


def review_source(profile):
    """The source closure is a fact, not an inference from the file name."""
    source = getattr(profile, 'source', None)
    root = getattr(source, 'source_root', None)
    top = getattr(source, 'top_module', None)
    if not _text(root) or not _text(top):
        return _row('source', 'missing', 'source-locator-incomplete',
                    _pointer('source'),
                    {'source_root': root, 'top_module': top})
    return _row('source', 'ok', 'source-locator-declared', _pointer('source'),
                {'source_root': root, 'top_module': top})


def review_clock_schedule(plan):
    """Every endpoint the harness drives needs a clock the schedule knows.

    An endpoint that names no domain uses the schedule's primary domain, which
    is the rule the runtime renderer applies; an endpoint that names a domain
    the declared clocks do not contain is refused instead of being resolved to
    the primary one by accident.
    """
    schedule = plan.clock_schedule if isinstance(plan.clock_schedule, dict) else {}
    primary = schedule.get('primary_clock_domain')
    clocks = schedule.get('clocks') or ()
    if not _text(primary):
        return _row('clock', 'missing', 'clock-primary-domain-required',
                    _pointer('clocks'), {'declared_clocks': len(clocks)})
    if not clocks:
        return _row('clock', 'missing', 'clock-schedule-empty', _pointer('clocks'))
    declared_domains = {row.get('domain') for row in clocks}
    endpoint_domains = {}
    for endpoint in plan.profile.endpoints:
        endpoint_domains[endpoint.endpoint_id] = endpoint.clock or primary
    unknown = sorted({domain for domain in endpoint_domains.values()
                      if domain not in declared_domains})
    if unknown:
        return _row('clock', 'conflict', 'clock-endpoint-domain-unresolved',
                    _pointer('endpoints'), {'domains': unknown,
                                            'declared_domains':
                                            sorted(declared_domains)})
    return _row('clock', 'ok', 'clock-schedule-complete', _pointer('clocks'),
                {'primary_clock_domain': primary,
                 'clock_domains': sorted(declared_domains),
                 'endpoint_domains': endpoint_domains,
                 'code_path': _CLOCK_CODE_PATH})


def review_reset_schedule(plan):
    """The reset bindings, read from the declaration and nothing else.

    Both admitted polarities are drivable (:data:`SUPPORTED_RESET_POLARITIES`),
    so the polarity row is a vocabulary check; the reset the renderer cannot
    express, and the one whose assertion semantics are unstated, are named here
    rather than approximated at run time.
    """
    resets = tuple(getattr(plan.profile, 'resets', ()) or ())
    if not resets:
        return _row('reset', 'missing', 'reset-binding-required',
                    _pointer('resets'))
    unsupported = []
    for index, reset in enumerate(resets):
        polarity = getattr(reset, 'polarity', None)
        if polarity not in SUPPORTED_RESET_POLARITIES:
            unsupported.append({'index': index,
                                'port': getattr(reset, 'port', None),
                                'polarity': polarity})
    if unsupported:
        return _row('reset', 'unsupported', 'reset-polarity-unsupported',
                    _pointer('resets'), {'supported': list(SUPPORTED_RESET_POLARITIES),
                                         'declared': unsupported})
    missing = [index for index, reset in enumerate(resets)
               if getattr(reset, 'synchronous', None) is None]
    if missing:
        return _row('reset', 'missing', 'reset-synchronous-required',
                    _pointer('resets'), {'indices': missing})
    return _row('reset', 'ok', 'reset-bindings-declared', _pointer('resets'),
                {'count': len(resets),
                 'resets': [{'port': reset.port, 'domain': reset.domain,
                             'polarity': reset.polarity,
                             'synchronous': reset.synchronous}
                            for reset in resets]})


def review_endpoints(plan):
    """Functions, protocols and field spans, each read from the declaration.

    The admitted function vocabulary is the loader's own table - the same one
    ``load_component_profile`` validates every endpoint against - so this check
    cannot drift from what a profile is allowed to declare.
    """
    endpoints = tuple(plan.profile.endpoints)
    functions = {endpoint.function for endpoint in endpoints}
    unknown = sorted(functions - set(FUNCTION_DIRECTIONS))
    if unknown:
        return _row('endpoint', 'unsupported', 'endpoint-function-unadmitted',
                    _pointer('endpoints'), {'unadmitted': unknown,
                                            'admitted':
                                            sorted(FUNCTION_DIRECTIONS)})
    protocol_functions = {name for name, direction in FUNCTION_DIRECTIONS.items()
                          if direction in ('protocol', 'protocol-inverted')}
    no_protocol = sorted(endpoint.endpoint_id for endpoint in endpoints
                         if endpoint.function in protocol_functions
                         and endpoint.protocol is None)
    if no_protocol:
        return _row('endpoint', 'missing', 'endpoint-protocol-undeclared',
                    _pointer('endpoints'), {'endpoints': no_protocol})
    empty = sorted(endpoint.endpoint_id for endpoint in endpoints
                   if not endpoint.fields)
    if empty:
        return _row('endpoint', 'missing', 'endpoint-fields-required',
                    _pointer('endpoints'), {'endpoints': empty})
    return _row('endpoint', 'ok', 'endpoint-functions-declared',
                _pointer('endpoints'),
                {'functions': sorted(functions),
                 'protocol_endpoints': sorted(endpoint.endpoint_id
                                              for endpoint in endpoints
                                              if endpoint.protocol is not None)})


def review_interrupts(profile):
    """Interrupt form is declared or absent - never inferred from a role name.

    This is the plan's explicit requirement: polarity, whether the line is held
    or pulsed, and how it is cleared must all be stated, because the harness
    drives a real line and a wrong assumption produces a wrong result rather
    than a refusal.  Every fact below comes from an ``interrupts`` record; a
    port whose name contains ``irq`` produces no claim at all, and an
    interrupt-source endpoint that no record covers is refused.
    """
    sources = tuple(getattr(profile, 'interrupts', ()) or ())
    endpoints = {endpoint.endpoint_id: endpoint
                 for endpoint in profile.endpoints}
    interrupt_endpoints = sorted(
        endpoint.endpoint_id for endpoint in profile.endpoints
        if endpoint.function == 'interrupt_source')
    if not interrupt_endpoints and not sources:
        return _row('interrupt', 'ok', 'no-interrupts-declared', '')
    if interrupt_endpoints and not sources:
        return _row('interrupt', 'missing', 'interrupt-form-undeclared',
                    _pointer('interrupts'),
                    {'endpoints': interrupt_endpoints,
                     'required': ['endpoint_id', 'role', 'polarity',
                                  'clock_domain', 'hold', 'clear', 'trigger']})
    gaps = []
    declared_roles = set()
    for index, source in enumerate(sources):
        endpoint_id = getattr(source, 'endpoint_id', None)
        role = getattr(source, 'role', None)
        row = {'index': index, 'endpoint_id': endpoint_id,
               'role': role,
               'pointer': _pointer('interrupts', index)}
        if endpoint_id not in endpoints:
            gaps.append({**row, 'code': 'interrupt-endpoint-unknown'})
            continue
        if getattr(endpoints[endpoint_id], 'function', None) != 'interrupt_source':
            gaps.append({**row, 'code': 'interrupt-endpoint-function-mismatch',
                         'function': endpoints[endpoint_id].function})
            continue
        # The record claims this endpoint role, whatever else is wrong with the
        # record: a second gap must not report the same role as undeclared.
        declared_roles.add((endpoint_id, role))
        missing = [name for name in ('role', 'polarity', 'clock_domain',
                                     'hold', 'clear', 'trigger')
                   if not _text(getattr(source, name, None))]
        if missing:
            gaps.append({**row, 'code': 'interrupt-form-field-missing',
                         'missing': missing})
            continue
        trigger = getattr(source, 'trigger', None)
        if trigger not in SUPPORTED_INTERRUPT_TRIGGERS:
            gaps.append({**row, 'code': 'interrupt-trigger-unsupported',
                         'trigger': trigger,
                         'supported': list(SUPPORTED_INTERRUPT_TRIGGERS)})
            continue
    undeclared = sorted((endpoint.endpoint_id, field.role)
                        for endpoint in profile.endpoints
                        if endpoint.function == 'interrupt_source'
                        for field in endpoint.fields
                        if (endpoint.endpoint_id, field.role) not in declared_roles)
    if undeclared:
        gaps.append({'code': 'interrupt-role-undeclared',
                     'roles': [{'endpoint_id': item[0], 'role': item[1]}
                               for item in undeclared],
                     'pointer': _pointer('interrupts')})
    if gaps:
        return _row('interrupt', _worst_status(_INTERRUPT_GAP_STATUS[gap['code']]
                                               for gap in gaps),
                    'interrupt-form-incomplete', _pointer('interrupts'),
                    {'rows': gaps})
    return _row('interrupt', 'ok', 'interrupt-form-declared',
                _pointer('interrupts'),
                # The hold/clear prose stays in the profile, where the pointer
                # below locates it; the row echoes the machine-readable fields
                # exactly as declared, so a caller can see what was read.
                {'count': len(sources),
                 'sources': [{'endpoint_id': source.endpoint_id,
                              'role': source.role,
                              'polarity': source.polarity,
                              'trigger': source.trigger,
                              'pointer': _pointer('interrupts', index)}
                             for index, source in enumerate(sources)]})


def review_interrupt_entry(profile, document):
    """A CPU interrupt entry must be named, and its polarity *declared*.

    ``CpuContract.irq_entry_polarity`` defaults to ``active_high`` when the
    document omits it, so the parsed contract alone cannot tell a declared
    polarity from an assumed one; the declaration is read from the profile
    document instead.  The harness drives this line, so an assumed polarity is
    exactly the kind of guess the plan forbids.
    """
    entries = [endpoint for endpoint in profile.endpoints
               if endpoint.function == 'interrupt_entry']
    if not entries:
        return _row('interrupt_entry', 'ok', 'no-interrupt-entry-declared', '')
    entry_ids = sorted(endpoint.endpoint_id for endpoint in entries)
    cpu = getattr(profile, 'cpu', None)
    raw_cpu = document.get('cpu') if isinstance(document, Mapping) else None
    raw_cpu = raw_cpu if isinstance(raw_cpu, Mapping) else {}
    polarity = getattr(cpu, 'irq_entry_polarity', None)
    if not _text(raw_cpu.get('irq_entry_polarity')):
        return _row('interrupt_entry', 'missing',
                    'interrupt-entry-polarity-undeclared',
                    _pointer('cpu', 'irq_entry_polarity'),
                    {'endpoints': entry_ids,
                     'parsed_polarity': polarity,
                     'note': 'the parsed contract defaults an omitted polarity to '
                             'active_high, so the declaration must state it'})
    if cpu is None or not _text(getattr(cpu, 'irq_entry_endpoint', None)):
        return _row('interrupt_entry', 'missing', 'interrupt-entry-undeclared',
                    _pointer('cpu', 'irq_entry_endpoint'),
                    {'endpoints': entry_ids})
    named = [endpoint for endpoint in entries
             if endpoint.endpoint_id == cpu.irq_entry_endpoint]
    if not named:
        return _row('interrupt_entry', 'conflict',
                    'interrupt-entry-endpoint-unknown',
                    _pointer('cpu', 'irq_entry_endpoint'),
                    {'declared': cpu.irq_entry_endpoint, 'endpoints': entry_ids})
    role = getattr(cpu, 'irq_entry_role', None)
    if not _text(role):
        return _row('interrupt_entry', 'missing', 'interrupt-entry-role-undeclared',
                    _pointer('cpu', 'irq_entry_role'),
                    {'endpoints': entry_ids})
    if role not in {field.role for field in named[0].fields}:
        return _row('interrupt_entry', 'conflict', 'interrupt-entry-role-unknown',
                    _pointer('cpu', 'irq_entry_role'),
                    {'declared': role,
                     'roles': sorted(field.role for field in named[0].fields)})
    if polarity not in ('active_high', 'active_low'):
        return _row('interrupt_entry', 'unsupported',
                    'interrupt-entry-polarity-unsupported',
                    _pointer('cpu', 'irq_entry_polarity'), {'declared': polarity})
    return _row('interrupt_entry', 'ok', 'interrupt-entry-declared',
                _pointer('cpu'),
                {'endpoint_id': cpu.irq_entry_endpoint, 'role': role,
                 'polarity': polarity})


def review_address_window(plan):
    """Only a fabric-target endpoint needs an address window.

    ``cpu-profile-must-not-declare-mmio-address`` is the loader's own rule, so a
    CPU that declares only memory masters has no window to state and the
    dimension is not applicable; a profile whose bus slave is not covered by an
    ``address`` block is refused instead.
    """
    slaves = sorted(endpoint.endpoint_id for endpoint in plan.profile.endpoints
                    if FUNCTION_TARGETS.get(endpoint.function) == 'fabric_target')
    if not slaves:
        return _row('address', 'ok', 'address-window-not-applicable',
                    _pointer('endpoints'),
                    {'reason': 'no fabric-target endpoint is declared, and the '
                               'loader forbids an MMIO address block on a cpu '
                               'profile (cpu-profile-must-not-declare-mmio-address)',
                     'endpoints': sorted(endpoint.endpoint_id
                                         for endpoint in plan.profile.endpoints)})
    address = getattr(plan.profile, 'address', None)
    if address is None:
        return _row('address', 'missing', 'address-window-required',
                    _pointer('address'), {'fabric_targets': slaves})
    window = getattr(address, 'window_size', None)
    if type(window) is not int or window <= 0:
        return _row('address', 'conflict', 'address-window-invalid',
                    _pointer('address', 'window_size'), {'window_size': window})
    width = plan.profile.capabilities.get('address_width')
    if type(width) is int and width >= 1 and window > 4 * (1 << width):
        return _row('address', 'conflict', 'address-window-exceeds-width',
                    _pointer('address', 'window_size'),
                    {'window_size': window, 'address_width': width})
    return _row('address', 'ok', 'address-window-declared', _pointer('address'),
                {'window_size': window, 'address_width': width,
                 'fabric_targets': slaves})


def review_serial_peer(profile):
    """A declared serial peer must name the pins and the frame format."""
    pins = [endpoint for endpoint in profile.endpoints
            if endpoint.function == 'external_pins']
    if not pins:
        return _row('serial_peer', 'ok', 'no-external-pins-declared', '')
    roles = {field.role for endpoint in pins for field in endpoint.fields}
    if not roles & {'rx', 'tx'}:
        return _row('serial_peer', 'ok', 'no-serial-roles-declared',
                    _pointer('endpoints'))
    return _row('serial_peer', 'ok', 'serial-pins-declared',
                _pointer('endpoints'),
                {'roles': sorted(roles),
                 'supported_format': SUPPORTED_SERIAL_PEER_FORMAT})


# ---------------------------------------------------------------------------
# ownership, read from the composition's own disposition ledger
# ---------------------------------------------------------------------------


def review_input_ownership(dispositions):
    """Physical inputs are owned by a declared driver, or they are refused.

    The owners are the ledger's classes (:data:`INPUT_OWNER_DISPOSITIONS`), and
    every name in this row comes from the ledger's ``DispositionEntry`` records.
    An input the ledger leaves ``unconnected`` is refused here, with the block
    that has to change; a port the ledger will not classify at all (no
    declaration covers it, two declarations claim one bit) is refused by
    :func:`_ledger_refusal_row` and never reaches this row.  Nothing falls back
    to a default disposition: a port this module cannot place is refused, not
    waved through.
    """
    entries = tuple(dispositions or ())
    if not entries:
        return _row('ownership', 'missing', 'physical-input-ownership-unresolved',
                    _pointer('endpoints'),
                    {'reason': 'no physical disposition ledger was built for this '
                               'profile; see the elaboration or disposition row',
                     'code_path': _DISPOSITION_CODE_PATH})
    inputs = tuple(entry for entry in entries if entry.direction == 'input')
    if not inputs:
        return _row('ownership', 'missing', 'physical-input-ownership-unresolved',
                    _pointer('endpoints'),
                    {'reason': 'the ledger classifies no physical input at all',
                     'code_path': _DISPOSITION_CODE_PATH})
    unowned = sorted({_entry_key(entry) for entry in inputs
                      if entry.disposition not in INPUT_OWNER_DISPOSITIONS})
    if unowned:
        return _row('ownership', 'missing', 'physical-input-unowned',
                    _pointer('port_actions'),
                    {'ports': unowned,
                     'declared_input_dispositions':
                         sorted({entry.disposition for entry in inputs}),
                     'owner_dispositions': list(INPUT_OWNER_DISPOSITIONS),
                     'code_path': _DISPOSITION_CODE_PATH})
    by_class = {}
    for name in INPUT_OWNER_DISPOSITIONS:
        members = sorted({_entry_key(entry) for entry in inputs
                          if entry.disposition == name})
        if members:
            by_class[name] = members
    exported = exported_ports(entries)
    return _row('ownership', 'ok', 'physical-inputs-owned',
                _pointer('endpoints'),
                {'inputs': len(inputs),
                 'input_bits': sum(entry.bit_hi - entry.bit_lo + 1
                                   for entry in inputs),
                 'owner_classes': {name: len(members)
                                   for name, members in by_class.items()},
                 'functional_inputs': by_class.get('functional', []),
                 'constant_inputs': by_class.get('constant', []),
                 'environment_inputs': sorted({_entry_key(entry)
                                               for entry in exported
                                               if entry.direction == 'input'}),
                 'fuzz_inputs': sorted({_entry_key(entry)
                                        for entry in fuzz_ports(entries)}),
                 'peer_inputs': by_class.get('peer', []),
                 'disposition_summary': disposition_summary(entries),
                 'ledger_entries': len(entries),
                 'code_path': _DISPOSITION_CODE_PATH})


def _entry_key(entry) -> str:
    """One ledger segment, named the way the ledger names it."""
    span = ('' if (entry.bit_lo, entry.bit_hi) == (0, entry.width - 1)
            else f'[{entry.bit_hi}:{entry.bit_lo}]')
    return f'{entry.port}{span}'


def _ledger_refusal_row(error: PortDispositionError):
    """One ledger refusal as a located review row."""
    reason = str(error)
    token = reason.split(':', 1)[0]
    for prefix, status, code, pointer in _LEDGER_REFUSALS:
        if token == prefix:
            return _row('ownership', status, code, pointer,
                        {'reason': reason, 'code_path': _DISPOSITION_CODE_PATH,
                         'ledger_token': token})
    return _row('ownership', 'unsupported', 'port-disposition-refused',
                _pointer('port_actions'),
                {'reason': reason, 'code_path': _DISPOSITION_CODE_PATH,
                 'ledger_token': token})


# ---------------------------------------------------------------------------
# one component, then one document
# ---------------------------------------------------------------------------


#: ``build_local_clock_schedule`` rejects a declaration whose fastest reset edge
#: would not be sampled, and how many ticks a reset is held for is a *request*
#: fact this module does not have. The probe therefore passes the schedule's own
#: ratio ceiling, which is the largest admissible half period (ratio <= 1024, so
#: half_period <= 512), and nothing reported below reads the tick-dependent
#: fields of the returned schedule.
_SCHEDULE_PROBE_TICKS = MAX_CLOCK_RATIO


def _clock_schedule(profile):
    """The authority's own validation of the declared clocks and resets."""
    return build_local_clock_schedule(profile.clocks, profile.resets,
                                      reset_assert_ticks=_SCHEDULE_PROBE_TICKS,
                                      reset_release_ticks=0)


def _clock_refusal_row(error: ValueError):
    reason = str(error)
    parts = reason.split(':')
    detail = parts[1] if len(parts) > 1 else reason
    if 'reset' in detail:
        pointer = _pointer('resets')
    else:
        pointer = _pointer('clocks')
    if 'required' in detail:
        status = 'missing'
    elif any(word in detail for word in ('duplicate', 'conflict', 'invalid')):
        status = 'conflict'
    else:
        status = 'unsupported'
    return _row('clock' if pointer == '/clocks' else 'reset', status,
                'clock-schedule-refused', pointer,
                {'reason': reason, 'schedule_reason': detail,
                 'code_path': _CLOCK_CODE_PATH})


def review_component(profile, *, base_dir, profile_path=None, document=None):
    """Review one profile and return its rows plus an overall verdict.

    The ownership dimension is judged from the ledger
    ``build_port_dispositions`` builds for this profile's binding.  When the
    binding cannot be built at all, ownership is reported as ``missing`` with a
    pointer instead of being assumed clean.

    ``document`` is the raw profile mapping the profile was loaded from. It is
    needed because two checks compare a declaration against the parsed contract:
    the loader fills defaults for a few fields, so only the raw document can
    tell a stated fact from an assumed one.  When it is not given, the profile
    file is read back from ``profile_path``.
    """
    from myfuzz.composition.component_profile import (elaborate_profile,
                                                      bind_profile)

    if not isinstance(document, Mapping):
        document = _profile_document(base_dir, profile_path)
    rows = [review_source(profile)]
    binding = None
    dispositions = None
    try:
        facts = elaborate_profile(profile, base_dir=base_dir)
        binding = bind_profile(profile, facts)
    except Exception as error:
        rows.append(_row('elaboration', 'conflict', 'profile-elaboration-failed',
                         '', {'error_type': type(error).__name__,
                              'error': str(error),
                              'code_path': _ELABORATION_CODE_PATH}))
    try:
        schedule = _clock_schedule(profile)
    except ValueError as error:
        schedule = None
        rows.append(_clock_refusal_row(error))
    if schedule is not None:
        rows.append(review_clock_schedule(_Planned(profile, schedule)))
    rows.append(review_reset_schedule(_Planned(profile)))
    rows.append(review_endpoints(_Planned(profile)))
    rows.append(review_interrupts(profile))
    rows.append(review_interrupt_entry(profile, document))
    rows.append(review_serial_peer(profile))
    rows.append(review_address_window(_Planned(profile)))
    ledger_row = None
    if binding is not None:
        try:
            dispositions = build_port_dispositions(
                profile.component_id, binding,
                clock_domain=LOCAL_CLOCK_DOMAIN, reset_domain=LOCAL_RESET_DOMAIN,
                profile_port_actions=profile.port_actions)
        except PortDispositionError as error:
            ledger_row = _ledger_refusal_row(error)
        except Exception as error:
            ledger_row = _row('ownership', 'unsupported', 'port-disposition-refused',
                              _pointer('port_actions'),
                              {'reason': str(error),
                               'error_type': type(error).__name__,
                               'code_path': _DISPOSITION_CODE_PATH})
    if ledger_row is not None:
        rows.append(ledger_row)
    else:
        rows.append(review_input_ownership(dispositions))
    blocking = [row for row in rows if row['status'] != 'ok']
    return {'component_id': profile.component_id,
            'profile_path': (str(profile_path) if profile_path is not None
                             else str(getattr(profile, 'component_id', ''))),
            'status': 'ok' if not blocking else _worst_status(row['status']
                                                              for row in blocking),
            'rows': rows}


class _Planned:
    """The two facts the endpoint/address/clock checks need, without planning.

    Those checks read only declared endpoints, capabilities, the address window
    and the declared clock schedule, so they must not force a full plan (which
    would separate the "declaration is incomplete" report from the "plan was
    refused" one).
    """

    def __init__(self, profile, clock_schedule=None):
        self.profile = profile
        self.clock_schedule = clock_schedule if isinstance(clock_schedule, dict) else {}


def _worst_status(statuses) -> str:
    """The component verdict: unsupported over conflict over missing."""
    values = set(statuses)
    for candidate in ('unsupported', 'conflict', 'missing'):
        if candidate in values:
            return candidate
    return 'ok'


def review_profiles(paths: Iterable[object], *, base_dir) -> dict:
    """Review several profiles and return one ``declaration_review.v1`` document.

    A profile the loader itself refuses still produces a component entry with the
    loader's own reason token as the row's ``code`` and the block that has to
    change as its ``pointer``; nothing is generated either way.
    """
    root = Path(base_dir)
    components = []
    for item in paths:
        path = item if isinstance(item, Path) else Path(item)
        resolved = path if path.is_absolute() else root / path
        profile, document, error = _load_profile(resolved)
        if error is not None:
            components.append(_refused_component(resolved, path, error, document))
            continue
        components.append(review_component(profile, base_dir=root,
                                           profile_path=path, document=document))
    refused = [row['component_id'] for row in components
               if row['status'] != 'ok']
    return {'schema_version': REVIEW_SCHEMA_VERSION,
            'generated': False,
            'components': components,
            'refused': refused,
            'admitted': [row['component_id'] for row in components
                         if row['status'] == 'ok'],
            'status': 'ok' if not refused else 'refused'}


def _load_profile(resolved: Path):
    """Read and load one profile: ``(profile, raw document, error)``."""
    try:
        document = json.loads(Path(resolved).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        return None, {}, error
    if not isinstance(document, Mapping):
        return None, {}, ComponentProfileError('document-must-be-object-or-path')
    try:
        return load_component_profile(document), document, None
    except (ComponentProfileError, ValueError) as error:
        return None, document, error


def _profile_document(base_dir, profile_path) -> Mapping:
    """The raw profile mapping for a path, for callers that did not pass one."""
    if profile_path is None:
        return {}
    path = profile_path if isinstance(profile_path, Path) else Path(str(profile_path))
    resolved = path if path.is_absolute() else Path(base_dir) / path
    return _raw_document(resolved)


def _refused_component(resolved: Path, path: Path, error: Exception,
                       document: Mapping) -> dict:
    """A profile the loader refuses, as a review component entry."""
    component_id = document.get('component_id') if isinstance(document, Mapping) else None
    if not _text(component_id):
        component_id = Path(resolved).stem
    return {'component_id': component_id,
            'profile_path': str(path),
            'status': 'refused',
            'rows': [_profile_refusal_row(document, error)]}


def _raw_document(resolved: Path) -> Mapping:
    try:
        document = json.loads(Path(resolved).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    return document if isinstance(document, Mapping) else {}


def _profile_refusal_row(document: Mapping, error: Exception) -> dict:
    """One loader refusal as a located review row.

    The loader's own reason token is the row's ``code`` - it is what the
    generator would raise - and the token selects the profile block a caller has
    to fix: exactly, by keyword, or - for a token that matches nothing - not at
    all, in which case the raw reason is kept with a root pointer rather than an
    invented location. A file that cannot be read or parsed keeps its own code,
    because there is no declaration to point at.
    """
    if isinstance(error, OSError):
        return _row('declaration', 'conflict', 'profile-unreadable', '',
                    {'reason': str(error), 'code_path': _PROFILE_CODE_PATH})
    if isinstance(error, json.JSONDecodeError):
        return _row('declaration', 'conflict', 'profile-not-json', '',
                    {'reason': str(error), 'code_path': _PROFILE_CODE_PATH})
    reason = str(error) or type(error).__name__
    token, _, parameter = reason.partition(':')
    if token == 'unknown-profile-field' and parameter:
        pointer = _pointer(parameter)
    else:
        pointer = _PROFILE_REFUSAL_EXACT.get(token)
    status = ('missing' if ('required' in token or 'requires' in token)
              else 'unsupported' if token.startswith('unsupported')
              else 'conflict')
    if token == 'invalid-interrupt-polarity':
        pointer, status = _interrupt_polarity_declaration(document)
    if pointer is None:
        pointer = ''
        for keyword, block in _PROFILE_REFUSAL_KEYWORDS:
            if keyword in token:
                pointer = block
                break
    return _row('declaration', status, token, pointer,
                {'reason': reason, 'code_path': _PROFILE_CODE_PATH})


def _interrupt_polarity_declaration(document: Mapping) -> tuple[str, str]:
    """Where a refused interrupt polarity is missing, and whether it is absent."""
    records = document.get('interrupts') if isinstance(document, Mapping) else None
    if not isinstance(records, list):
        return _pointer('interrupts'), 'missing'
    for index, record in enumerate(records):
        if not isinstance(record, Mapping) or not _text(record.get('polarity')):
            return _pointer('interrupts', index, 'polarity'), 'missing'
    return _pointer('interrupts'), 'conflict'


def review_document_json(document: Mapping[str, object]) -> str:
    return json.dumps(document, sort_keys=True, separators=(',', ':')) + '\n'
