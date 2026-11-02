"""P7-C: compile the ``F1..F6`` paths one composition can really walk.

The plan's P7-C deliverable (D3) is a *compiler*, not a hand-written path
declaration: given the declared capabilities of a CPU and of one or more
peripherals plus a declared wiring contract, produce the ``F1..F6`` path set of
that composition -- each path's Fuzzable Source / Bound Input, field
mask/range/alignment/source ownership, prerequisites, initial seed and assertion
set -- and, for every path that cannot be walked, the *named* reason.

Three properties are load-bearing and are enforced here rather than promised.

**Compilation reads capabilities, never names.**
Component ids, endpoint ids and register names are used only as *identity
pointers* (which declaration a caller meant).  Every semantic decision comes
from a declared token: an endpoint's declared ``function`` and its entry in
:data:`myfuzz.composition.component_profile.FUNCTION_DIRECTIONS`, a field's
declared ``direction``/``width``/``bit_range``, a sidecar field's declared
``access``/``read_mask``/``write_mask``/``side_effect``, a CPU profile's
declared ``cpu`` block (ISA, reset vector, IRQ entry role/polarity), a memory
region's declared ``read``/``write``/``execute`` permissions, an
``ip_test_capability`` feature operation, and a source's declared ``origin``.
Nothing is inferred from a component being called ``ibex`` or a register being
called ``PADIN``; this repository has been bitten by exactly that class of
inference (P7 plan section 6, item 6).

**A path is ``executable`` only when every end of every hop is declared.**
``F5`` needs a real IRQ producer *and* a real consumer with a matching declared
polarity; ``F2`` needs a real IP read-response end; ``F6`` needs a real
data-movement provider.  When an end is missing the path is ``unsupported``
with a ``code`` and a JSON ``pointer`` naming the declaration that has to be
added; the Fuzzer is never allowed to manufacture that end.  There is no third
status -- :data:`PATH_STATUSES` has exactly two members and every flow in
:data:`FLOW_IDS` gets a record.

**An illegal declaration refuses the whole compilation.**
Declaring a read-only / reserved field, a DUT-driven output field or the CPU IRQ
input as a fuzzable source is not "unsupported", it is a declaration error:
:class:`PathCompilationError` is raised with ``code`` + ``pointer`` and *no*
``compiled_paths.v1`` document is produced.  Two independent nets catch it: this
module's explicit capability check (which names the pointer) and the shipped
input-layout/constraint compilers (which refuse an unknown input field, a
non-writable field and a double-driven bit).

Reused rather than re-implemented: :mod:`myfuzz.composition.test_capability` for
the ``ip_test_capability.v*`` sidecar, :mod:`myfuzz.composition.input_layout` for
mask/range/alignment/enum compilation, :mod:`myfuzz.composition.input_constraints`
for the bounded rule set and the single-driver / DUT-ownership checks,
:mod:`myfuzz.scenario.assertion_classes` for the three assertion classes and
their expectation ids, :mod:`myfuzz.scenario.source_actions` for the ownership,
prerequisite and termination vocabularies, and
:mod:`myfuzz.scenario.runtime_path_contract` for the emitted
``runtime_path_contract.v1``.

:mod:`myfuzz.composition.constraints` is deliberately *not* used: its declaration
graph is built from elaborated HDL facts (per-port widths out of ``hdl_facts``),
which a capability-only compilation input does not have, and inventing those
widths would be exactly the fabricated evidence this phase refuses to produce.

Nothing here runs RTL, renders or builds a harness, starts a process or writes a
file.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from types import MappingProxyType

from myfuzz.composition.component_profile import (
    FUNCTION_DIRECTIONS, ComponentProfile, ComponentProfileError,
    load_component_profile)
from myfuzz.composition.input_constraints import (
    INPUT_CONSTRAINT_SCHEMA, InputConstraintError, compile_input_constraints)
from myfuzz.composition.input_layout import (
    InputLayoutError, build_input_layout, input_layout_document)
from myfuzz.composition.test_capability import (
    IPTestCapability, IPTestCapabilityError, load_ip_test_capability)
from myfuzz.isa.constraints import IsaContract
from myfuzz.scenario.assertion_classes import (
    ASSERTION_CLASSES, EXPECTATIONS)
from myfuzz.scenario.dependency import (
    DependencyGraph, DependencyRule, FuzzableSource)
from myfuzz.scenario.dma_route_intent import (
    DMA_MASTER_ROUTE_INTENT_SCHEMA, DmaMasterRouteIntent,
    dma_master_route_intents_document, parse_dma_master_route_intents)
from myfuzz.scenario.runtime_path_contract import (
    RuntimeEdgeContract, RuntimeNode, RuntimePathContract)
from myfuzz.scenario.source_actions import (
    DRIVEN_FLOW_IDS, OWNERSHIP_KINDS, PREREQUISITE_KINDS, TERMINATION_KINDS)


# ---------------------------------------------------------------------------
# vocabulary
# ---------------------------------------------------------------------------

COMPILED_PATHS_SCHEMA = 'compiled_paths.v1'
PATH_COMPILE_REQUEST_SCHEMA = 'path_compile_request.v1'
PATH_WIRING_SCHEMA = 'path_wiring.v1'
PATH_WIRING_SCHEMA_V2 = 'path_wiring.v2'
WIRING_CONTRACT_SCHEMA = 'wiring_contract.v1'
WIRING_CONTRACT_SCHEMA_V2 = 'wiring_contract.v2'
SOC_RENDER_CONFIG_SCHEMA = 'soc_render_config.v1'

STATUS_EXECUTABLE = 'executable'
STATUS_UNSUPPORTED = 'unsupported'
#: Exactly two statuses; the plan's first exit criterion forbids a third.
PATH_STATUSES = (STATUS_EXECUTABLE, STATUS_UNSUPPORTED)

#: The driven flow categories, reused from the source-action contract.
FLOW_IDS = tuple(DRIVEN_FLOW_IDS)
#: Source ownership vocabulary, reused from the source-action contract.
ORIGINS = tuple(OWNERSHIP_KINDS)
#: Prerequisite / termination vocabulary, reused from the source-action contract.
PREREQUISITE_KINDS_USED = tuple(PREREQUISITE_KINDS)
TERMINATION_KINDS_USED = tuple(TERMINATION_KINDS)

ORIGIN_FUZZABLE = 'fuzzable'
ORIGIN_BOUND = 'bound'

DIRECTION_CPU_SOURCED = 'CPU_TO_IP'
DIRECTION_IP_SOURCED = 'IP_TO_CPU'

#: Authoritative per-flow definitions.  ``authority`` names file:line of the
#: table this text is copied from, so a reader re-checks the compiler against the
#: requirement instead of against the compiler.
FLOW_DEFINITIONS: dict[str, dict[str, str]] = {
    'F1': {
        'name': 'instruction_stream',
        'summary': '程序存储器 → CPU',
        'propagation': 'Fuzzer 变异程序/初始镜像；CPU 真实 PC 和取指请求决定地址，持久 ROM/RAM 按局部协议返回已保存的指令；CPU 真实译码执行并更新 PC/寄存器。',
        'authority': 'docs/superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md:77',
    },
    'F2': {
        'name': 'data_read_stream',
        'summary': 'RAM 或外设 → CPU',
        'propagation': 'CPU Load 真实发出地址/读请求；RAM 使用提交时冻结的持久字节，MMIO 使用目标 IP RTL 的真实读响应；CPU 真实消费 rdata。已绑定 rdata 不随机覆盖。',
        'authority': 'docs/superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md:78',
    },
    'F3': {
        'name': 'data_write_stream',
        'summary': 'CPU → RAM',
        'propagation': 'CPU Store 真实给出地址、wdata 和 byte-enable；Memory Service 一次提交并逐字节更新；后续 F1/F2 读取同一资源版本，不能重新装载初值。',
        'authority': 'docs/superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md:79',
    },
    'F4': {
        'name': 'mmio_control_stream',
        'summary': 'CPU → 外设',
        'propagation': 'CPU 真实 Load/Store 经声明的地址窗口转换为 IP 原生局部协议事务；寄存器配置、TX、状态读和 W1C 清除均由真实 IP RTL 执行/响应。',
        'authority': 'docs/superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md:80',
    },
    'F5': {
        'name': 'interrupt_event_stream',
        'summary': '外设 → CPU → ISR → MMIO',
        'propagation': 'IP 真实状态/IRQ 经声明的电平或脉冲交付规则送至 CPU 中断输入；CPU 真实 trap/ISR 后再读取 IP 真实状态。IRQ 只通知事件，不代替 F2 的数据返回；不模拟 PLIC 汇聚/优先级。',
        'authority': 'docs/superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md:81',
    },
    'F6': {
        'name': 'dma_transfer_stream',
        'summary': 'CPU 配置 DMA → DMA 主设备 → RAM/IP → 完成 IRQ → CPU',
        'propagation': 'CPU 真实配置 DMA；真实 DMA RTL 在独立 harness 中发出读写主设备请求，Router 将已接受事务交给持久 RAM 或真实 IP FIFO/寄存器；数据和完成 IRQ 均追溯到真实组件输出。',
        'authority': 'docs/superpowers/plans/2026-10-06-current-dataflow-fuzz-implementation-plan.md:82',
    },
}

#: Assertion expectations per flow.  Every id must exist in
#: :data:`myfuzz.scenario.assertion_classes.EXPECTATIONS`; each id's class is read
#: back from that table, never restated here.
_ASSERTIONS_BY_FLOW: dict[str, tuple[str, ...]] = {
    'F1': ('cpu_ip.retirement_observation_supported',
           'cpu_ip.retirement_instruction_origin'),
    'F2': ('protocol_checker.receipt_violations',
           'cross_component.declared_edge_hops'),
    'F3': ('cross_component.chain_certificate_hops',
           'cpu_ip.consumption_record'),
    'F4': ('protocol_checker.receipt_violations',
           'cross_component.declared_edge_hops',
           'cross_component.chain_certificate_hops'),
    'F5': ('cpu_ip.irq_input_expectation',
           'cpu_ip.irq_acceptance',
           'cpu_ip.irq_expiry'),
    'F6': ('cross_component.chain_certificate_hops',
           'cpu_ip.irq_acceptance'),
}
_EXPECTATION_BY_ID = {row['expectation_id']: row for row in EXPECTATIONS}

#: The stable node id a flow's real consumer is compiled to, and the runtime
#: rule kind its hops use.  ``kind`` values are the shipped dependency-rule
#: kinds; see ``myfuzz.scenario.runtime_path_contract._RELATIONS``.
_FLOW_TARGETS: dict[str, str] = {
    'F1': 'instruction_retire',
    'F2': 'data_read_consumed',
    'F3': 'ram_byte_version',
    'F4': 'device_register_response',
    'F5': 'cpu_irq_entry',
    'F6': 'dma_transfer_complete',
}


def _function(token: str) -> str:
    """Return a declared endpoint-function token, proving it is a declaration."""
    if token not in FUNCTION_DIRECTIONS:
        raise AssertionError(f'undeclared endpoint function token: {token}')
    return token


FUNCTION_INSTRUCTION_MASTER = _function('instruction_memory_master')
#: Functions that mean "this single port carries both instruction fetches and
#: data".  CVW's EBU-arbitrated AHB bus and picorv32's ready/valid memory port are
#: both this shape, and a profile that declares one of them is accurate about the
#: hardware; a dedicated instruction master simply does not exist there.
UNIFIED_MASTER_FUNCTIONS = frozenset((_function('memory_master'),
                                      _function('processor_memory_master')))
FUNCTION_DATA_MASTER = _function('data_memory_master')
FUNCTION_MMIO_SLAVE = _function('mmio_slave')
FUNCTION_INTERRUPT_SOURCE = _function('interrupt_source')
FUNCTION_INTERRUPT_ENTRY = _function('interrupt_entry')
FUNCTION_EXTERNAL_PINS = _function('external_pins')

#: Every endpoint function whose declared direction is ``protocol-inverted`` is a
#: bus master; the set is derived from the profile schema's own table.
MASTER_FUNCTIONS = frozenset(name for name, direction in FUNCTION_DIRECTIONS.items()
                             if direction == 'protocol-inverted')
#: A component declares bulk data movement with this feature operation
#: (``ip_test_capability.v2`` feature contract); F6 requires one.
FEATURE_TRANSFER = 'transfer'

for _flow_id, _rows in _ASSERTIONS_BY_FLOW.items():
    if _flow_id not in FLOW_IDS or _flow_id not in _FLOW_TARGETS:
        raise AssertionError(f'assertion mapping names an unknown flow: {_flow_id}')
    for _expectation_id in _rows:
        if _expectation_id not in _EXPECTATION_BY_ID:
            raise AssertionError(f'unknown assertion expectation: {_expectation_id}')
        if _EXPECTATION_BY_ID[_expectation_id]['assertion_class'] not in ASSERTION_CLASSES:
            raise AssertionError('assertion class is not a declared class')


# ---------------------------------------------------------------------------
# errors and small readers
# ---------------------------------------------------------------------------

class PathCompilationError(ValueError):
    """A declaration is illegal, contradictory or unusable.

    ``code`` is a stable machine-readable reason; ``pointer`` is a JSON pointer
    into the offending request / wiring / profile document.
    """

    def __init__(self, code: str, pointer: str = '', detail=None):
        self.code = code
        self.pointer = pointer
        self.detail = detail
        super().__init__(f'{code} at {pointer or "/"}')


def _refuse(code: str, pointer: str = '', detail=None):
    raise PathCompilationError(code, pointer, detail)


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def _digest(value: object) -> str:
    return 'sha256:' + hashlib.sha256(_canonical(value)).hexdigest()


def compiled_document_sha256(compiled: object) -> str:
    """The one canonical digest of a ``compiled_paths.v1`` document.

    ``CompiledF4Runtime`` binds the exact document with this digest and every
    compiled-RFuzz consumer must compute the same bytes before comparing.  The
    canonical form is sorted-key, compact JSON with the default ASCII escaping
    (the runtime's historical form); it is deliberately separate from
    ``_canonical`` above, whose non-ASCII form is already part of issued path
    records.  A caller must not re-derive its own JSON form.
    """
    if not isinstance(compiled, dict):
        raise ValueError('compiled-document-required')
    try:
        encoded = json.dumps(compiled, sort_keys=True, separators=(',', ':'),
                             allow_nan=False)
    except (TypeError, ValueError, RecursionError) as error:
        raise ValueError('compiled-document-not-json') from error
    return hashlib.sha256(encoded.encode('utf-8')).hexdigest()


def _text(value: object, pointer: str, code: str) -> str:
    if not isinstance(value, str) or not value:
        _refuse(code, pointer, {'value': value})
    return value


def _integer(value: object, pointer: str, code: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        _refuse(code, pointer, {'value': value})
    return value


def _boolean(value: object, pointer: str, code: str) -> bool:
    if type(value) is not bool:
        _refuse(code, pointer, {'value': value})
    return value


def _object(value: object, pointer: str, code: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        _refuse(code, pointer)
    return value


def _array(value: object, pointer: str, code: str) -> list:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        _refuse(code, pointer)
    return list(value)


def _closed(row: Mapping[str, object], required: set, optional: set,
            pointer: str, code: str) -> dict:
    """A declaration is a closed record, never an open bag."""
    missing = sorted(required - set(row))
    unknown = sorted(set(row) - required - optional)
    if missing:
        _refuse(f'{code}-field-missing', pointer, {'missing': missing})
    if unknown:
        _refuse(f'{code}-field-unknown', pointer, {'unknown': unknown})
    return dict(row)


def _read_json(document_or_path: object, code: str) -> dict:
    if isinstance(document_or_path, Mapping):
        return dict(document_or_path)
    if isinstance(document_or_path, (str, Path)):
        path = Path(document_or_path)
        try:
            document = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, UnicodeError, json.JSONDecodeError):
            _refuse(code, str(path))
        if not isinstance(document, dict):
            _refuse(code, str(path))
        return document
    _refuse(code, '')


def _missing(code: str, pointer: str, detail) -> dict[str, object]:
    return {'code': code, 'pointer': pointer, 'detail': detail}


# ---------------------------------------------------------------------------
# wiring
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class WiringWindow:
    """A declared MMIO aperture: who is addressed, where, through which end."""

    device_id: str
    target_instance: str
    base: int
    size: int
    endpoint_id: str | None
    source: str
    #: P7-B carries the admitted template identity of each end; kept as evidence.
    template: str | None = None
    variant_id: str | None = None


@dataclass(frozen=True, slots=True)
class WiringResource:
    """A declared memory resource with its declared permissions."""

    resource_id: str
    component_instance: str | None
    base: int | None
    size: int | None
    read: bool | None
    write: bool | None
    execute: bool | None
    initialization_policy: str | None
    source: str


@dataclass(frozen=True, slots=True)
class WiringDelivery:
    """A declared event delivery: producer end -> consumer end."""

    delivery_id: str
    producer_instance: str
    producer_endpoint_id: str | None
    producer_signal: str | None
    consumer_instance: str
    consumer_endpoint_id: str | None
    trigger: str | None
    source: str
    # Absolute DUT bit within the declared consumer field; required for vectors.
    consumer_bit_offset: int | None = None


@dataclass(frozen=True, slots=True)
class WiringEnvironmentLink:
    """A declared external environment link with its declared width."""

    link_id: str
    component_instance: str
    endpoint_id: str | None
    width: int | None
    event_kind: str | None
    source: str
    bit_offset: int | None = None


@dataclass(frozen=True, slots=True)
class WiringFixedInput:
    """A declared constant on one physical input bit range of one instance.

    The declaration says *this range is not a fuzzable source and not a bound
    delivery target*: the environment holds it at ``constant``.  It is the only
    wiring section that can own an input the compiled paths do not mention, so it
    is closed and typed here and cross-checked against the real ABI by
    :mod:`myfuzz.scenario.compiled_ownership`.
    """

    component_instance: str
    port: str
    bit_offset: int
    width: int
    constant: int
    source: str


@dataclass(frozen=True, slots=True)
class PathWiring:
    """One composition's declared wiring, normalised to a single shape."""

    schema_version: str
    cpu_instance_id: str | None
    cpu_data_endpoint_id: str | None
    windows: tuple[WiringWindow, ...] = ()
    resources: tuple[WiringResource, ...] = ()
    deliveries: tuple[WiringDelivery, ...] = ()
    environment_links: tuple[WiringEnvironmentLink, ...] = ()
    fixed_inputs: tuple[WiringFixedInput, ...] = ()
    dma_master_routes: tuple[DmaMasterRouteIntent, ...] = ()
    dma_master_route_bindings: tuple[Mapping[str, object], ...] = ()
    dma_master_routes_sha256: str | None = None
    declared_sections: tuple[str, ...] = ()
    absent_sections: tuple[str, ...] = ()
    document: Mapping[str, object] = field(default_factory=dict)


_WIRING_SECTIONS = ('cpu', 'windows', 'resources', 'deliveries',
                    'environment_links', 'fixed_inputs')
_WIRING_SECTIONS_V2 = (*_WIRING_SECTIONS, 'dma_master_routes',
                        'dma_master_route_bindings')


def _wiring_window(row: Mapping[str, object], pointer: str, source: str) -> WiringWindow:
    row = _closed(row, {'device_id', 'target_instance', 'base', 'size'},
                  {'endpoint_id', 'template', 'variant_id'}, pointer, 'wiring-window')
    optional = {name: (None if row.get(name) is None else
                       _text(row[name], f'{pointer}/{name}', f'wiring-window-{name}'))
                for name in ('endpoint_id', 'template', 'variant_id')}
    return WiringWindow(
        _text(row['device_id'], pointer + '/device_id', 'wiring-window-device-id'),
        _text(row['target_instance'], pointer + '/target_instance', 'wiring-window-target'),
        _integer(row['base'], pointer + '/base', 'wiring-window-base'),
        _integer(row['size'], pointer + '/size', 'wiring-window-size', minimum=1),
        optional['endpoint_id'],
        source, optional['template'], optional['variant_id'])


def _wiring_resource(row: Mapping[str, object], pointer: str, source: str) -> WiringResource:
    row = _closed(row, {'resource_id'},
                  {'component_instance', 'base', 'size', 'read', 'write', 'execute',
                   'initialization_policy'}, pointer, 'wiring-resource')
    numbers = {name: (None if row.get(name) is None else
                      _integer(row[name], f'{pointer}/{name}', f'wiring-resource-{name}'))
               for name in ('base', 'size')}
    flags = {name: (None if row.get(name) is None else
                    _boolean(row[name], f'{pointer}/{name}', f'wiring-resource-{name}'))
             for name in ('read', 'write', 'execute')}
    instance = row.get('component_instance')
    policy = row.get('initialization_policy')
    return WiringResource(
        _text(row['resource_id'], pointer + '/resource_id', 'wiring-resource-id'),
        (None if instance is None else
         _text(instance, pointer + '/component_instance', 'wiring-resource-owner')),
        numbers['base'], numbers['size'],
        flags['read'], flags['write'], flags['execute'],
        (None if policy is None else
         _text(policy, pointer + '/initialization_policy', 'wiring-resource-policy')),
        source)


def _wiring_delivery(row: Mapping[str, object], pointer: str, source: str) -> WiringDelivery:
    row = _closed(row, {'delivery_id', 'producer_instance', 'consumer_instance'},
                  {'producer_endpoint_id', 'producer_signal', 'consumer_endpoint_id',
                   'trigger', 'consumer_bit_offset'}, pointer, 'wiring-delivery')
    optional = {name: (None if row.get(name) is None else
                       _text(row[name], f'{pointer}/{name}', f'wiring-delivery-{name}'))
                for name in ('producer_endpoint_id', 'producer_signal',
                             'consumer_endpoint_id', 'trigger')}
    return WiringDelivery(
        _text(row['delivery_id'], pointer + '/delivery_id', 'wiring-delivery-id'),
        _text(row['producer_instance'], pointer + '/producer_instance',
              'wiring-delivery-producer'),
        optional['producer_endpoint_id'], optional['producer_signal'],
        _text(row['consumer_instance'], pointer + '/consumer_instance',
              'wiring-delivery-consumer'),
        optional['consumer_endpoint_id'], optional['trigger'], source,
        None if row.get('consumer_bit_offset') is None else _integer(
            row['consumer_bit_offset'], pointer + '/consumer_bit_offset', 'wiring-delivery-consumer-bit'))


def _wiring_link(row: Mapping[str, object], pointer: str, source: str) -> WiringEnvironmentLink:
    row = _closed(row, {'link_id', 'component_instance'},
                  {'endpoint_id', 'width', 'event_kind', 'bit_offset'}, pointer, 'wiring-link')
    width = row.get('width')
    event_kind = row.get('event_kind')
    endpoint_id = row.get('endpoint_id')
    bit_offset = row.get('bit_offset')
    if bit_offset is not None and (width is None or endpoint_id is None):
        _refuse('wiring-link-segment-incomplete', pointer)
    return WiringEnvironmentLink(
        _text(row['link_id'], pointer + '/link_id', 'wiring-link-id'),
        _text(row['component_instance'], pointer + '/component_instance',
              'wiring-link-component'),
        (None if endpoint_id is None else
         _text(endpoint_id, pointer + '/endpoint_id', 'wiring-link-endpoint')),
        (None if width is None else
         _integer(width, pointer + '/width', 'wiring-link-width', minimum=1)),
        (None if event_kind is None else
         _text(event_kind, pointer + '/event_kind', 'wiring-link-event-kind')),
        source,
        (None if bit_offset is None else
         _integer(bit_offset, pointer + '/bit_offset', 'wiring-link-offset', minimum=0)))


def _wiring_fixed_input(row: Mapping[str, object], pointer: str,
                        source: str) -> WiringFixedInput:
    """Read one declared constant input range of a wiring contract.

    The record is closed: an unknown key, a missing width/constant or a constant
    that does not fit the declared width is a named refusal.  Whether the range
    really names an input is cross-checked against the loaded ABI by the
    ownership compiler, which is the module that knows the physical ports.
    """
    row = _closed(row, {'component_instance', 'port', 'width', 'constant'},
                  {'bit_offset'}, pointer, 'wiring-fixed-input')
    offset = row.get('bit_offset', 0)
    width = _integer(row['width'], pointer + '/width', 'wiring-fixed-input-width',
                     minimum=1)
    constant = _integer(row['constant'], pointer + '/constant',
                        'wiring-fixed-input-constant')
    if constant >= 1 << width:
        _refuse('wiring-fixed-input-constant-exceeds-width', pointer + '/constant',
                {'constant': constant, 'width': width})
    return WiringFixedInput(
        _text(row['component_instance'], pointer + '/component_instance',
              'wiring-fixed-input-component'),
        _text(row['port'], pointer + '/port', 'wiring-fixed-input-port'),
        _integer(offset, pointer + '/bit_offset', 'wiring-fixed-input-offset'),
        width, constant, source)


def _static_sha256(value: object, pointer: str, *, profile: bool = False) -> str:
    text = _text(value, pointer, 'dma-route-binding-fingerprint-invalid')
    digest = text.removeprefix('sha256:') if profile else text
    if len(digest) != 64 or any(char not in '0123456789abcdef' for char in digest):
        _refuse('dma-route-binding-fingerprint-invalid', pointer,
                {'value': text, 'kind': 'profile' if profile else 'sha256'})
    if profile and not text.startswith('sha256:'):
        _refuse('dma-route-binding-fingerprint-invalid', pointer,
                {'value': text, 'requires_prefix': 'sha256:'})
    if not profile and text.startswith('sha256:'):
        _refuse('dma-route-binding-fingerprint-invalid', pointer,
                {'value': text, 'requires_prefix': False})
    return text


def _dma_template_binding(row: object, pointer: str) -> dict[str, object]:
    row = _closed(_object(row, pointer, 'dma-route-binding-endpoint-object'),
                  {'profile_endpoint_sha256', 'template_id', 'template_version',
                   'variant_id', 'contract_sha256', 'selection_sha256'}, set(),
                  pointer, 'dma-route-binding-endpoint')
    return {
        'profile_endpoint_sha256': _static_sha256(
            row['profile_endpoint_sha256'], pointer + '/profile_endpoint_sha256'),
        'template_id': _text(row['template_id'], pointer + '/template_id',
                             'dma-route-binding-template-id'),
        'template_version': _text(row['template_version'],
                                  pointer + '/template_version',
                                  'dma-route-binding-template-version'),
        'variant_id': _text(row['variant_id'], pointer + '/variant_id',
                            'dma-route-binding-variant'),
        'contract_sha256': _static_sha256(row['contract_sha256'],
                                          pointer + '/contract_sha256'),
        'selection_sha256': _static_sha256(row['selection_sha256'],
                                           pointer + '/selection_sha256'),
    }


def _dma_memory_target_binding(row: object, pointer: str) -> dict[str, object]:
    row = _closed(_object(row, pointer, 'dma-route-binding-memory-object'),
                  {'kind', 'owner_profile_fingerprint', 'resource_sha256'}, set(),
                  pointer, 'dma-route-binding-memory')
    if row['kind'] != 'persistent_memory':
        _refuse('dma-route-binding-target-kind-mismatch', pointer + '/kind',
                {'observed': row['kind'], 'expected': 'persistent_memory'})
    return {
        'kind': 'persistent_memory',
        'owner_profile_fingerprint': _static_sha256(
            row['owner_profile_fingerprint'],
            pointer + '/owner_profile_fingerprint', profile=True),
        'resource_sha256': _static_sha256(row['resource_sha256'],
                                          pointer + '/resource_sha256'),
    }


def _dma_route_binding_rows(document: object,
                            routes: tuple[DmaMasterRouteIntent, ...],
                            pointer: str) -> tuple[Mapping[str, object], ...]:
    rows = _array(document, pointer, 'dma-route-bindings-array-required')
    expected_ids = [route.route_id for route in routes]
    seen: set[str] = set()
    bindings = []
    for index, raw in enumerate(rows):
        item_pointer = f'{pointer}/{index}'
        row = _closed(_object(raw, item_pointer, 'dma-route-binding-object'),
                      {'route_id', 'initiator', 'target'}, set(), item_pointer,
                      'dma-route-binding')
        route_id = _text(row['route_id'], item_pointer + '/route_id',
                         'dma-route-binding-route-id')
        if route_id in seen:
            _refuse('dma-route-binding-id-duplicate', item_pointer + '/route_id',
                    {'route_id': route_id})
        seen.add(route_id)
        route = next((value for value in routes if value.route_id == route_id), None)
        if route is None:
            _refuse('dma-route-binding-route-undeclared', item_pointer + '/route_id',
                    {'route_id': route_id, 'declared_route_ids': expected_ids})
        initiator = _dma_template_binding(row['initiator'],
                                         item_pointer + '/initiator')
        if route.target['kind'] == 'peripheral':
            target = _dma_template_binding(row['target'], item_pointer + '/target')
        else:
            target = _dma_memory_target_binding(row['target'],
                                                item_pointer + '/target')
        bindings.append(MappingProxyType({
            'route_id': route_id, 'initiator': MappingProxyType(initiator),
            'target': MappingProxyType(target)}))
    if [row['route_id'] for row in bindings] != expected_ids:
        _refuse('dma-route-binding-order-or-set-mismatch', pointer,
                {'route_ids': [row['route_id'] for row in bindings],
                 'expected_route_ids': expected_ids})
    return tuple(bindings)


def _parse_dma_route_sections(row: Mapping[str, object], pointer: str):
    try:
        routes = parse_dma_master_route_intents(
            row['dma_master_routes'], pointer=pointer + '/dma_master_routes')
        canonical = dma_master_route_intents_document(routes)
    except (KeyError, ValueError) as error:
        _refuse('dma-route-intent-invalid', pointer + '/dma_master_routes',
                {'error': str(error)})
    if canonical != row['dma_master_routes']:
        _refuse('dma-route-intent-not-canonical', pointer + '/dma_master_routes',
                {'requires': 'route rows sorted by route_id and canonical row shape'})
    digest = _static_sha256(row['dma_master_routes_sha256'],
                            pointer + '/dma_master_routes_sha256')
    expected_digest = hashlib.sha256(_canonical(canonical)).hexdigest()
    if digest != expected_digest:
        _refuse('dma-route-intent-digest-mismatch',
                pointer + '/dma_master_routes_sha256',
                {'declared': digest, 'computed': expected_digest})
    bindings = _dma_route_binding_rows(row['dma_master_route_bindings'], routes,
                                       pointer + '/dma_master_route_bindings')
    return routes, bindings, digest


def _from_wiring_contract(document: Mapping[str, object]) -> PathWiring:
    """Normalise the P7-B ``wiring_contract.v1`` document.

    The contract's base sections are the CPU's data endpoint and the device
    windows.  A composition may additionally declare ``resources`` (the memory
    regions, including the CPU's program image), and those are read here.

    It still carries no event deliveries and no environment links, so those two
    sections are reported as *absent* and every path that needs them is
    ``unsupported`` by construction rather than by guesswork.
    """
    row = _closed(document, {'schema_version', 'delivery', 'global_interconnect',
                             'cycle_accurate', 'cpu', 'windows'},
                  {'resources', 'fixed_inputs'}, '', 'wiring-contract')
    if row['global_interconnect'] is not False or row['cycle_accurate'] is not False:
        _refuse('wiring-contract-claims-interconnect', '/global_interconnect')
    cpu = _closed(_object(row['cpu'], '/cpu', 'wiring-contract-cpu'),
                  {'instance_id', 'endpoint_id'}, {'template', 'variant_id'},
                  '/cpu', 'wiring-contract-cpu')
    windows = tuple(_wiring_window(item, f'/windows/{index}', WIRING_CONTRACT_SCHEMA)
                    for index, item in enumerate(
                        _array(row['windows'], '/windows', 'wiring-contract-windows')))
    resources = tuple(_wiring_resource(item, f'/resources/{index}', WIRING_CONTRACT_SCHEMA)
                      for index, item in enumerate(
                          _array(row.get('resources', []), '/resources',
                                 'wiring-contract-resources')))
    fixed_inputs = tuple(
        _wiring_fixed_input(item, f'/fixed_inputs/{index}', WIRING_CONTRACT_SCHEMA)
        for index, item in enumerate(
            _array(row.get('fixed_inputs', []), '/fixed_inputs',
                   'wiring-contract-fixed-inputs')))
    declared = tuple(name for name in _WIRING_SECTIONS if name in row)
    return PathWiring(
        WIRING_CONTRACT_SCHEMA,
        _text(cpu['instance_id'], '/cpu/instance_id', 'wiring-contract-cpu-instance'),
        _text(cpu['endpoint_id'], '/cpu/endpoint_id', 'wiring-contract-cpu-endpoint'),
        windows=windows,
        resources=resources,
        fixed_inputs=fixed_inputs,
        declared_sections=declared,
        absent_sections=tuple(name for name in _WIRING_SECTIONS
                              if name not in declared),
        document=dict(document))


def _from_wiring_contract_v2(document: Mapping[str, object]) -> PathWiring:
    """Read strict P7-B wiring v2 with static DMA intent and binding rows."""
    row = _closed(document, {'schema_version', 'delivery', 'global_interconnect',
                             'cycle_accurate', 'cpu', 'windows',
                             'dma_master_routes', 'dma_master_route_bindings',
                             'dma_master_routes_sha256'},
                  {'resources', 'fixed_inputs'}, '', 'wiring-contract')
    if row['global_interconnect'] is not False or row['cycle_accurate'] is not False:
        _refuse('wiring-contract-claims-interconnect', '/global_interconnect')
    cpu = _closed(_object(row['cpu'], '/cpu', 'wiring-contract-cpu'),
                  {'instance_id', 'endpoint_id'}, {'template', 'variant_id'},
                  '/cpu', 'wiring-contract-cpu')
    windows = tuple(_wiring_window(item, f'/windows/{index}', WIRING_CONTRACT_SCHEMA_V2)
                    for index, item in enumerate(
                        _array(row['windows'], '/windows', 'wiring-contract-windows')))
    resources = tuple(_wiring_resource(item, f'/resources/{index}',
                                       WIRING_CONTRACT_SCHEMA_V2)
                      for index, item in enumerate(
                          _array(row.get('resources', []), '/resources',
                                 'wiring-contract-resources')))
    fixed_inputs = tuple(
        _wiring_fixed_input(item, f'/fixed_inputs/{index}', WIRING_CONTRACT_SCHEMA_V2)
        for index, item in enumerate(
            _array(row.get('fixed_inputs', []), '/fixed_inputs',
                   'wiring-contract-fixed-inputs')))
    routes, bindings, digest = _parse_dma_route_sections(row, '')
    declared = tuple(name for name in _WIRING_SECTIONS_V2 if name in row)
    return PathWiring(
        WIRING_CONTRACT_SCHEMA_V2,
        _text(cpu['instance_id'], '/cpu/instance_id', 'wiring-contract-cpu-instance'),
        _text(cpu['endpoint_id'], '/cpu/endpoint_id', 'wiring-contract-cpu-endpoint'),
        windows=windows, resources=resources, fixed_inputs=fixed_inputs,
        dma_master_routes=routes, dma_master_route_bindings=bindings,
        dma_master_routes_sha256=digest,
        declared_sections=declared,
        absent_sections=tuple(name for name in _WIRING_SECTIONS_V2
                              if name not in declared),
        document=dict(document))


def _from_path_wiring(document: Mapping[str, object]) -> PathWiring:
    """Read this module's own ``path_wiring.v1`` wiring contract."""
    row = _closed(document, {'schema_version', 'cpu'}, set(_WIRING_SECTIONS) - {'cpu'},
                  '', 'path-wiring')
    cpu = _closed(_object(row['cpu'], '/cpu', 'path-wiring-cpu'),
                  {'instance_id'}, {'data_endpoint'}, '/cpu', 'path-wiring-cpu')
    windows = tuple(_wiring_window(item, f'/windows/{index}', PATH_WIRING_SCHEMA)
                    for index, item in enumerate(
                        _array(row.get('windows', []), '/windows', 'path-wiring-windows')))
    resources = tuple(_wiring_resource(item, f'/resources/{index}', PATH_WIRING_SCHEMA)
                      for index, item in enumerate(
                          _array(row.get('resources', []), '/resources',
                                 'path-wiring-resources')))
    deliveries = tuple(_wiring_delivery(item, f'/deliveries/{index}', PATH_WIRING_SCHEMA)
                       for index, item in enumerate(
                           _array(row.get('deliveries', []), '/deliveries',
                                  'path-wiring-deliveries')))
    links = tuple(_wiring_link(item, f'/environment_links/{index}', PATH_WIRING_SCHEMA)
                  for index, item in enumerate(
                      _array(row.get('environment_links', []), '/environment_links',
                             'path-wiring-links')))
    fixed_inputs = tuple(
        _wiring_fixed_input(item, f'/fixed_inputs/{index}', PATH_WIRING_SCHEMA)
        for index, item in enumerate(
            _array(row.get('fixed_inputs', []), '/fixed_inputs',
                   'path-wiring-fixed-inputs')))
    data_endpoint = cpu.get('data_endpoint')
    return PathWiring(
        PATH_WIRING_SCHEMA,
        _text(cpu['instance_id'], '/cpu/instance_id', 'path-wiring-cpu-instance'),
        (None if data_endpoint is None else
         _text(data_endpoint, '/cpu/data_endpoint', 'path-wiring-cpu-data-endpoint')),
        windows=windows, resources=resources, deliveries=deliveries,
        environment_links=links, fixed_inputs=fixed_inputs,
        declared_sections=tuple(name for name in _WIRING_SECTIONS if name in row),
        absent_sections=tuple(name for name in _WIRING_SECTIONS if name not in row),
        document=dict(document))


def _from_path_wiring_v2(document: Mapping[str, object]) -> PathWiring:
    """Read strict internal v2 wiring without treating it as a live route."""
    row = _closed(document, {'schema_version', 'cpu', 'dma_master_routes',
                             'dma_master_route_bindings',
                             'dma_master_routes_sha256'},
                  set(_WIRING_SECTIONS) - {'cpu'}, '', 'path-wiring')
    cpu = _closed(_object(row['cpu'], '/cpu', 'path-wiring-cpu'),
                  {'instance_id'}, {'data_endpoint'}, '/cpu', 'path-wiring-cpu')
    windows = tuple(_wiring_window(item, f'/windows/{index}', PATH_WIRING_SCHEMA_V2)
                    for index, item in enumerate(
                        _array(row.get('windows', []), '/windows', 'path-wiring-windows')))
    resources = tuple(_wiring_resource(item, f'/resources/{index}', PATH_WIRING_SCHEMA_V2)
                      for index, item in enumerate(
                          _array(row.get('resources', []), '/resources',
                                 'path-wiring-resources')))
    deliveries = tuple(_wiring_delivery(item, f'/deliveries/{index}', PATH_WIRING_SCHEMA_V2)
                       for index, item in enumerate(
                           _array(row.get('deliveries', []), '/deliveries',
                                  'path-wiring-deliveries')))
    links = tuple(_wiring_link(item, f'/environment_links/{index}', PATH_WIRING_SCHEMA_V2)
                  for index, item in enumerate(
                      _array(row.get('environment_links', []), '/environment_links',
                             'path-wiring-links')))
    fixed_inputs = tuple(
        _wiring_fixed_input(item, f'/fixed_inputs/{index}', PATH_WIRING_SCHEMA_V2)
        for index, item in enumerate(
            _array(row.get('fixed_inputs', []), '/fixed_inputs',
                   'path-wiring-fixed-inputs')))
    routes, bindings, digest = _parse_dma_route_sections(row, '')
    data_endpoint = cpu.get('data_endpoint')
    return PathWiring(
        PATH_WIRING_SCHEMA_V2,
        _text(cpu['instance_id'], '/cpu/instance_id', 'path-wiring-cpu-instance'),
        (None if data_endpoint is None else
         _text(data_endpoint, '/cpu/data_endpoint', 'path-wiring-cpu-data-endpoint')),
        windows=windows, resources=resources, deliveries=deliveries,
        environment_links=links, fixed_inputs=fixed_inputs,
        dma_master_routes=routes, dma_master_route_bindings=bindings,
        dma_master_routes_sha256=digest,
        declared_sections=tuple(name for name in _WIRING_SECTIONS_V2 if name in row),
        absent_sections=tuple(name for name in _WIRING_SECTIONS_V2 if name not in row),
        document=dict(document))


def _from_soc_render_config(document: Mapping[str, object],
                            profiles: Mapping[str, ComponentProfile]) -> PathWiring:
    """Read a ``soc_render_config.v1`` document as a wiring contract.

    The SoC render profile already declares the CPU's ISA and reset vector, each
    peripheral's MMIO window, the memory regions with their permissions, the
    external environment links and the interrupt routes.  Component ids are used
    only to match a declaration to the profile carrying the same declared
    ``component_id`` -- the identity match
    :func:`myfuzz.composition.test_capability.load_ip_test_capability` performs.

    Two things it does *not* declare are left absent instead of being filled in by
    guesswork: which instance serves a memory region, and which endpoint a
    declared interrupt signal belongs to.  A caller supplies the first through
    the request's ``memory`` supplement; the second is resolved only from a
    declared ``interrupt_source`` endpoint function, and when a component has
    none the delivery keeps ``producer_endpoint_id: None`` so the path is
    reported unsupported instead of the signal name being turned into an
    endpoint.
    """
    row = _closed(document, {'schema_version', 'cpu', 'peripherals'},
                  {'config_id', 'cell_id', 'families', 'distinct_ip_count',
                   'source_locks', 'status', 'memory_regions', 'environment_links',
                   'interrupt_routes', 'modes', 'harness', 'acceptance',
                   'provenance'}, '', 'soc-render-config')
    by_component_id: dict[str, ComponentProfile] = {}
    for profile in profiles.values():
        if profile.component_id in by_component_id:
            _refuse('soc-render-config-component-id-ambiguous', '',
                    {'component_id': profile.component_id})
        by_component_id[profile.component_id] = profile
    cpu_row = _object(row['cpu'], '/cpu', 'soc-render-config-cpu')
    cpu_id = _text(cpu_row.get('id'), '/cpu/id', 'soc-render-config-cpu-id')
    if cpu_id not in by_component_id:
        _refuse('soc-render-config-component-unmatched', '/cpu/id',
                {'component_id': cpu_id})

    windows = []
    for index, item in enumerate(_array(row['peripherals'], '/peripherals',
                                        'soc-render-config-peripherals')):
        pointer = f'/peripherals/{index}'
        item = _object(item, pointer, 'soc-render-config-peripheral')
        peripheral_id = _text(item.get('id'), pointer + '/id',
                              'soc-render-config-peripheral-id')
        if peripheral_id not in by_component_id:
            _refuse('soc-render-config-component-unmatched', pointer + '/id',
                    {'component_id': peripheral_id})
        window = _object(item.get('window'), pointer + '/window',
                         'soc-render-config-window')
        windows.append(WiringWindow(
            peripheral_id, peripheral_id,
            _integer(window.get('base'), pointer + '/window/base',
                     'soc-render-config-window-base'),
            _integer(window.get('size'), pointer + '/window/size',
                     'soc-render-config-window-size', minimum=1),
            None, SOC_RENDER_CONFIG_SCHEMA))

    resources = []
    for index, item in enumerate(_array(row.get('memory_regions', []),
                                        '/memory_regions',
                                        'soc-render-config-memory-regions')):
        pointer = f'/memory_regions/{index}'
        item = _object(item, pointer, 'soc-render-config-memory-region')
        permissions = _object(item.get('permissions', {}), pointer + '/permissions',
                              'soc-render-config-permissions')
        policy = item.get('initialization_policy')
        resources.append(WiringResource(
            _text(item.get('region_id'), pointer + '/region_id',
                  'soc-render-config-region-id'),
            None,  # not declared by the render profile; a request may declare it
            _integer(item.get('base'), pointer + '/base', 'soc-render-config-region-base'),
            _integer(item.get('size'), pointer + '/size',
                     'soc-render-config-region-size', minimum=1),
            (None if 'read' not in permissions else
             _boolean(permissions['read'], pointer + '/permissions/read',
                      'soc-render-config-permission')),
            (None if 'write' not in permissions else
             _boolean(permissions['write'], pointer + '/permissions/write',
                      'soc-render-config-permission')),
            (None if 'execute' not in permissions else
             _boolean(permissions['execute'], pointer + '/permissions/execute',
                      'soc-render-config-permission')),
            (None if policy is None else
             _text(policy, pointer + '/initialization_policy',
                   'soc-render-config-policy')),
            SOC_RENDER_CONFIG_SCHEMA))

    links = []
    for index, item in enumerate(_array(row.get('environment_links', []),
                                        '/environment_links',
                                        'soc-render-config-links')):
        pointer = f'/environment_links/{index}'
        item = _object(item, pointer, 'soc-render-config-link')
        component_id = _text(item.get('component_id'), pointer + '/component_id',
                             'soc-render-config-link-component')
        if component_id not in by_component_id:
            _refuse('soc-render-config-component-unmatched', pointer + '/component_id',
                    {'component_id': component_id})
        parameters = _object(item.get('parameters', {}), pointer + '/parameters',
                             'soc-render-config-link-parameters')
        # Both spellings occur in this tree: ``width`` on a pin bundle and
        # ``bits`` on a serial link.  Both are declared bit-width facts.
        width = parameters.get('width', parameters.get('bits'))
        event_kind = parameters.get('event_kind')
        links.append(WiringEnvironmentLink(
            _text(item.get('link_id'), pointer + '/link_id',
                  'soc-render-config-link-id'),
            component_id, None,
            (None if width is None else
             _integer(width, pointer + '/parameters/width',
                      'soc-render-config-link-width', minimum=1)),
            (None if event_kind is None else
             _text(event_kind, pointer + '/parameters/event_kind',
                   'soc-render-config-link-event-kind')),
            SOC_RENDER_CONFIG_SCHEMA))

    deliveries = []
    for index, item in enumerate(_array(row.get('interrupt_routes', []),
                                        '/interrupt_routes',
                                        'soc-render-config-routes')):
        pointer = f'/interrupt_routes/{index}'
        item = _object(item, pointer, 'soc-render-config-route')
        source_row = _object(item.get('source', {}), pointer + '/source',
                             'soc-render-config-route-source')
        component_id = _text(source_row.get('component_id'),
                             pointer + '/source/component_id',
                             'soc-render-config-route-component')
        if component_id not in by_component_id:
            _refuse('soc-render-config-component-unmatched',
                    pointer + '/source/component_id', {'component_id': component_id})
        signal = source_row.get('signal')
        trigger = source_row.get('trigger')
        deliveries.append(WiringDelivery(
            _text(item.get('route_id'), pointer + '/route_id',
                  'soc-render-config-route-id'),
            component_id,
            None,  # resolved from a declared interrupt_source endpoint, never a name
            (None if signal is None else
             _text(signal, pointer + '/source/signal', 'soc-render-config-route-signal')),
            cpu_id, None,
            (None if trigger is None else
             _text(trigger, pointer + '/source/trigger', 'soc-render-config-trigger')),
            SOC_RENDER_CONFIG_SCHEMA))

    return PathWiring(
        SOC_RENDER_CONFIG_SCHEMA, cpu_id, None, windows=tuple(windows),
        resources=tuple(resources), deliveries=tuple(deliveries),
        environment_links=tuple(links),
        declared_sections=_WIRING_SECTIONS, absent_sections=(),
        document=dict(document))


def _load_wiring_into(document: Mapping[str, object],
                      profiles: Sequence[ComponentProfile]) -> PathWiring:
    schema = document.get('schema_version')
    if schema == PATH_WIRING_SCHEMA:
        return _from_path_wiring(document)
    if schema == PATH_WIRING_SCHEMA_V2:
        return _from_path_wiring_v2(document)
    if schema == WIRING_CONTRACT_SCHEMA:
        return _from_wiring_contract(document)
    if schema == WIRING_CONTRACT_SCHEMA_V2:
        return _from_wiring_contract_v2(document)
    if schema == SOC_RENDER_CONFIG_SCHEMA:
        return _from_soc_render_config(document, {row.component_id: row
                                                  for row in profiles})
    _refuse('unsupported-wiring-schema', '/schema_version',
            {'schema_version': schema})


def load_path_wiring(document_or_path: object, *,
                     profiles: Sequence[ComponentProfile] = ()) -> PathWiring:
    """Load one declared wiring contract in any shape this module understands."""
    return _load_wiring_into(
        _read_json(document_or_path, 'wiring-document-unreadable'), profiles)


def _merge_rows(declared: tuple, supplement: tuple, *, key: str, kind: str,
                pointer: str, fields: tuple[str, ...]) -> tuple:
    """Fill undeclared fields from a supplement; a contradiction is refused."""
    merged = list(declared)
    by_key = {getattr(row, key): index for index, row in enumerate(declared)}
    for index, extra in enumerate(supplement):
        extra_key = getattr(extra, key)
        where = f'{pointer}/{index}'
        if extra_key not in by_key:
            by_key[extra_key] = len(merged)
            merged.append(extra)
            continue
        position = by_key[extra_key]
        current = merged[position]
        values = {}
        for name in fields:
            left, right = getattr(current, name), getattr(extra, name)
            if left is None and right is None:
                continue
            if left is None:
                values[name] = right
            elif right is None or right == left:
                values[name] = left
            else:
                _refuse(f'wiring-{kind}-conflict', where + '/' + name,
                        {'declared': left, 'supplement': right})
        merged[position] = type(current)(**{
            name: values.get(name, getattr(current, name)) for name in current.__slots__})
    return tuple(merged)


_SUPPLEMENTS = {
    'memory': (WiringResource, _wiring_resource, 'resource_id', 'resource',
               ('component_instance', 'base', 'size', 'read', 'write', 'execute',
                'initialization_policy'), 'resources'),
    'deliveries': (WiringDelivery, _wiring_delivery, 'delivery_id', 'delivery',
                   ('producer_instance', 'producer_endpoint_id', 'producer_signal',
                    'consumer_instance', 'consumer_endpoint_id', 'trigger', 'consumer_bit_offset'), 'deliveries'),
    'environment_links': (WiringEnvironmentLink, _wiring_link, 'link_id', 'link',
                          ('component_instance', 'endpoint_id', 'width', 'event_kind', 'bit_offset'),
                          'environment_links'),
}


# ---------------------------------------------------------------------------
# request
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class DeclaredSource:
    """One declared source claim with the pointer it was read from."""

    pointer: str
    row: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class PathComponent:
    """One declared component of the composition under compilation."""

    instance_id: str
    profile: ComponentProfile
    capability: IPTestCapability | None = None
    declared_sources: tuple[DeclaredSource, ...] = ()

    @property
    def component_id(self) -> str:
        return self.profile.component_id

    @property
    def is_cpu(self) -> bool:
        return self.profile.cpu is not None

    def endpoints(self):
        return self.profile.endpoints

    def endpoint(self, endpoint_id: str):
        return next((row for row in self.profile.endpoints
                     if row.endpoint_id == endpoint_id), None)

    def endpoints_with_function(self, function: str):
        return tuple(row for row in self.profile.endpoints if row.function == function)

    def input_fields(self):
        return tuple((endpoint, item) for endpoint in self.profile.endpoints
                     for item in endpoint.fields
                     if _effective_direction(endpoint, item) in ('input', 'inout'))


@dataclass(frozen=True, slots=True)
class PathCompileRequest:
    """A loaded ``path_compile_request.v1`` document."""

    cpu: PathComponent
    devices: tuple[PathComponent, ...]
    wiring: PathWiring
    document: Mapping[str, object] = field(default_factory=dict)
    #: Declared role pointers, cross-checked against function-based resolution.
    cpu_data_endpoint_id: str | None = None
    cpu_instruction_endpoint_id: str | None = None
    base_dir: str = '.'

    def components(self) -> tuple[PathComponent, ...]:
        return (self.cpu, *self.devices)

    def component(self, instance_id: str) -> PathComponent | None:
        return next((row for row in self.components()
                     if row.instance_id == instance_id), None)

    def device(self, instance_id: str) -> PathComponent | None:
        return next((row for row in self.devices if row.instance_id == instance_id),
                    None)

    def role_pointer(self, function: str) -> str | None:
        if function == FUNCTION_DATA_MASTER:
            return self.cpu_data_endpoint_id or self.wiring.cpu_data_endpoint_id
        if function == FUNCTION_INSTRUCTION_MASTER:
            return self.cpu_instruction_endpoint_id
        return None


def _component_row(row: Mapping[str, object], pointer: str, *,
                   base_dir: Path, extra: set | None = None, device: bool = False):
    row = _closed(row, {'instance_id', 'profile'},
                  {'test_capability', 'device_id'} | (extra or set()) if device
                  else {'test_capability'} | (extra or set()),
                  pointer, 'component')
    instance_id = _text(row['instance_id'], pointer + '/instance_id', 'component-instance')
    profile_path = _text(row['profile'], pointer + '/profile', 'component-profile-path')
    resolved = Path(profile_path)
    if not resolved.is_absolute():
        resolved = base_dir / profile_path
    if not resolved.is_file():
        _refuse('component-profile-missing', pointer + '/profile',
                {'profile': profile_path})
    try:
        profile = load_component_profile(
            json.loads(resolved.read_text(encoding='utf-8')))
    except (ComponentProfileError, OSError, UnicodeError, json.JSONDecodeError) as error:
        _refuse('component-profile-invalid', pointer + '/profile',
                {'profile': profile_path, 'error': str(error)})
    capability = None
    sidecar = row.get('test_capability')
    if sidecar is not None:
        sidecar_path = Path(_text(sidecar, pointer + '/test_capability',
                                  'component-test-capability-path'))
        if not sidecar_path.is_absolute():
            sidecar_path = base_dir / sidecar_path
        if not sidecar_path.is_file():
            _refuse('component-test-capability-missing', pointer + '/test_capability',
                    {'path': str(sidecar)})
        try:
            capability = load_ip_test_capability(sidecar_path, profile=profile)
        except (IPTestCapabilityError, OSError, UnicodeError) as error:
            _refuse('component-test-capability-invalid', pointer + '/test_capability',
                    {'path': str(sidecar), 'error': str(error)})
    return instance_id, profile, capability


def _sole_unified_master(profile) -> str | None:
    """The profile's unified memory port, when it is its *sole* master.

    A core may expose one master that carries both instruction fetches and data
    (CVW's EBU-arbitrated AHB bus, picorv32's ready/valid port).  Only endpoints
    whose declared direction is ``protocol-inverted`` can be a bus master, so a
    passive declaration next to the bus (CVW's ``cpu.manager_domain``
    observation endpoint, a configuration endpoint, an interrupt entry) never
    makes the port ambiguous.  A profile with zero or several master-capable
    endpoints has no unified role to accept, and ``None`` is returned.

    This is the **single** predicate for that rule: both
    :func:`load_path_compile_request` (the declared role pointers) and
    :func:`_cpu_master` (the per-flow resolver) call it, so the two can no longer
    disagree about which declarations are accepted.
    """
    masters = [item for item in profile.endpoints
               if item.function in MASTER_FUNCTIONS]
    unified = [item for item in masters
               if item.function in UNIFIED_MASTER_FUNCTIONS]
    if len(masters) == 1 and len(unified) == 1:
        return unified[0].endpoint_id
    return None


def load_path_compile_request(document_or_path: object, *,
                              base_dir: object = '.') -> PathCompileRequest:
    """Load a closed ``path_compile_request.v1`` composition declaration.

    The request names *which* declarations the caller means (profile paths,
    instance ids, the CPU's data endpoint role pointer) and the wiring contract.
    It never restates a capability fact that a profile or sidecar already
    carries; the ``memory`` / ``deliveries`` / ``environment_links`` supplements
    exist only to fill in wiring facts the referenced wiring document does not
    declare, and a supplement contradicting it is refused.
    """
    base = Path(base_dir)
    document = _read_json(document_or_path, 'request-unreadable')
    row = _closed(document, {'schema_version', 'cpu', 'devices', 'wiring'},
                  {'memory', 'deliveries', 'environment_links', 'fixed_inputs', 'sources', 'f6_execution'},
                  '', 'request')
    if row['schema_version'] != PATH_COMPILE_REQUEST_SCHEMA:
        _refuse('unsupported-request-schema', '/schema_version',
                {'expected': PATH_COMPILE_REQUEST_SCHEMA,
                 'observed': row['schema_version']})
    cpu_row = _object(row['cpu'], '/cpu', 'request-cpu')
    cpu_instance, cpu_profile, cpu_capability = _component_row(
        cpu_row, '/cpu', base_dir=base,
        extra={'data_endpoint', 'instruction_endpoint'})
    if cpu_profile.cpu is None:
        _refuse('component-declares-no-cpu-contract', '/cpu/profile',
                {'component_id': cpu_profile.component_id})
    role_pointers = {}
    for name, function in (('data_endpoint', FUNCTION_DATA_MASTER),
                           ('instruction_endpoint', FUNCTION_INSTRUCTION_MASTER)):
        value = cpu_row.get(name)
        if value is None:
            role_pointers[name] = None
            continue
        declared = _text(value, f'/cpu/{name}', 'request-cpu-role-pointer')
        endpoint = next((item for item in cpu_profile.endpoints
                         if item.endpoint_id == declared), None)
        # A unified-memory CPU (CVW's AHB external bus, picorv32's ready/valid
        # port) exposes one master that carries both fetches and data, so the same
        # endpoint legitimately fills both role pointers.  Accepting it only when
        # it is the profile's sole *master-capable* endpoint keeps the pointer
        # unambiguous while allowing passive declarations (observation,
        # configuration) beside the bus; refusing it would reject every accurate
        # unified-memory declaration.  The predicate is shared with
        # :func:`_cpu_master` so the two decisions cannot drift apart.
        accept_unified = (endpoint is not None
                          and endpoint.function in UNIFIED_MASTER_FUNCTIONS
                          and _sole_unified_master(cpu_profile)
                          == endpoint.endpoint_id)
        if endpoint is None or (endpoint.function != function and not accept_unified):
            _refuse('cpu-master-role-pointer-mismatch', f'/cpu/{name}',
                    {'endpoint_id': declared,
                     'requires': f'a declared endpoint with function {function!r}',
                     'or_sole_unified_master': sorted(UNIFIED_MASTER_FUNCTIONS),
                     'declared_endpoints': sorted(item.endpoint_id
                                                  for item in cpu_profile.endpoints)})
        role_pointers[name] = declared
    parsed_devices = []
    for index, item in enumerate(_array(row['devices'], '/devices', 'request-devices')):
        device_row = _object(item, f'/devices/{index}', 'request-device')
        instance_id, profile, capability = _component_row(
            device_row, f'/devices/{index}', base_dir=base, device=True)
        if profile.cpu is not None:
            _refuse('device-declares-cpu-contract', f'/devices/{index}/profile',
                    {'component_id': profile.component_id})
        declared_device_id = device_row.get('device_id')
        if declared_device_id is not None:
            declared_device_id = _text(declared_device_id,
                                       f'/devices/{index}/device_id',
                                       'request-device-id')
        parsed_devices.append((instance_id, profile, capability, declared_device_id))
    if not parsed_devices:
        _refuse('request-devices-empty', '/devices')
    instances = [cpu_instance, *(row[0] for row in parsed_devices)]
    if len(set(instances)) != len(instances):
        _refuse('duplicate-instance-id', '/devices')

    wiring_row = _object(row['wiring'], '/wiring', 'request-wiring')
    all_profiles = [cpu_profile, *(row[1] for row in parsed_devices)]
    if 'source' in wiring_row:
        wiring_row = _closed(wiring_row, {'source'}, set(), '/wiring', 'request-wiring')
        source = Path(_text(wiring_row['source'], '/wiring/source', 'wiring-source'))
        if not source.is_absolute():
            source = base / source
        if not source.is_file():
            _refuse('wiring-document-missing', '/wiring/source', {'path': str(source)})
        wiring = load_path_wiring(source, profiles=all_profiles)
    else:
        wiring = load_path_wiring(wiring_row, profiles=all_profiles)

    for index, (instance_id, _, _, declared_device_id) in enumerate(parsed_devices):
        if declared_device_id is None:
            continue
        for window in wiring.windows:
            if window.target_instance != instance_id:
                continue
            if window.device_id != declared_device_id:
                _refuse('device-id-conflict', f'/devices/{index}/device_id',
                        {'request': declared_device_id, 'wiring': window.device_id,
                         'target_instance': instance_id})

    for name, (_, reader, key, kind, fields, attribute) in _SUPPLEMENTS.items():
        raw = row.get(name)
        if raw is None:
            continue
        parsed = tuple(reader(item, f'/{name}/{index}', f'{name}-supplement')
                       for index, item in enumerate(
                           _array(raw, f'/{name}', f'request-{name}')))
        if len({getattr(item, key) for item in parsed}) != len(parsed):
            _refuse(f'duplicate-{kind}-id', f'/{name}')
        merged = _merge_rows(getattr(wiring, attribute), parsed, key=key, kind=kind,
                             pointer=f'/{name}', fields=fields)
        fields_now = {
            'schema_version': wiring.schema_version,
            'cpu_instance_id': wiring.cpu_instance_id,
            'cpu_data_endpoint_id': wiring.cpu_data_endpoint_id,
            'windows': wiring.windows,
            'resources': wiring.resources,
            'deliveries': wiring.deliveries,
            'environment_links': wiring.environment_links,
            'fixed_inputs': wiring.fixed_inputs,
            'dma_master_routes': wiring.dma_master_routes,
            'dma_master_route_bindings': wiring.dma_master_route_bindings,
            'dma_master_routes_sha256': wiring.dma_master_routes_sha256,
            'declared_sections': wiring.declared_sections,
            'absent_sections': wiring.absent_sections,
            'document': wiring.document,
        }
        fields_now[attribute] = merged
        wiring = PathWiring(**fields_now)

    if 'fixed_inputs' in row:
        additions = tuple(_wiring_fixed_input(item, f'/fixed_inputs/{index}', 'fixed-inputs-supplement')
                          for index, item in enumerate(
                              _array(row['fixed_inputs'], '/fixed_inputs', 'request-fixed-inputs')))
        fixed = list(wiring.fixed_inputs)
        for index, addition in enumerate(additions):
            if any(old.component_instance == addition.component_instance and old.port == addition.port
                   and old.bit_offset < addition.bit_offset + addition.width
                   and addition.bit_offset < old.bit_offset + old.width for old in fixed):
                _refuse('fixed-input-overlap', f'/fixed_inputs/{index}',
                        {'component_instance': addition.component_instance, 'port': addition.port})
            fixed.append(addition)
        wiring = replace(wiring, fixed_inputs=tuple(fixed))

    if 'f6_execution' in row and wiring.dma_master_routes:
        # F6's bound DMA declaration replays the complete wiring document.
        # Keep the caller's original request bytes/supplements as its identity;
        # only the explicitly marked typed wiring gets this complete view.
        wiring=load_path_wiring(_f6_complete_wiring_document(wiring))

    claims = tuple(DeclaredSource(f'/sources/{index}', item)
                   for index, item in enumerate(
                       _array(row.get('sources', []), '/sources', 'request-sources')))
    by_instance: dict[str, list[DeclaredSource]] = {name: [] for name in instances}
    for claim in claims:
        declared = claim.row.get('component')
        if not isinstance(declared, str) or declared not in by_instance:
            _refuse('source-component-undeclared', claim.pointer + '/component',
                    {'declared': declared, 'declared_instances': sorted(instances)})
        by_instance[declared].append(claim)

    if wiring.cpu_instance_id is not None and wiring.cpu_instance_id != cpu_instance:
        _refuse('wiring-cpu-instance-mismatch', '/wiring/cpu/instance_id',
                {'declared': wiring.cpu_instance_id, 'request': cpu_instance})
    data_pointer = role_pointers['data_endpoint']
    if (data_pointer is not None and wiring.cpu_data_endpoint_id is not None
            and data_pointer != wiring.cpu_data_endpoint_id):
        _refuse('cpu-data-endpoint-conflict', '/cpu/data_endpoint',
                {'request': data_pointer, 'wiring': wiring.cpu_data_endpoint_id})
    cpu = PathComponent(cpu_instance, cpu_profile, cpu_capability,
                        tuple(by_instance[cpu_instance]))
    devices = tuple(PathComponent(instance_id, profile, capability,
                                  tuple(by_instance[instance_id]))
                    for instance_id, profile, capability, _ in parsed_devices)
    return PathCompileRequest(cpu, devices, wiring, dict(document),
                              data_pointer or wiring.cpu_data_endpoint_id,
                              role_pointers['instruction_endpoint'], str(base.resolve()))


# ---------------------------------------------------------------------------
# declared facts, read only through declared roles
# ---------------------------------------------------------------------------

def _effective_direction(endpoint, profile_field) -> str | None:
    """A field's direction: its own declaration, else its function's declaration."""
    if profile_field.direction is not None:
        return profile_field.direction
    declared = FUNCTION_DIRECTIONS.get(endpoint.function)
    if declared in ('input', 'output'):
        return declared
    return None


def _isa_extensions(cpu: ComponentProfile) -> tuple[str, ...]:
    """Canonicalise declared ISA tokens; both spellings exist in this tree."""
    contract = cpu.cpu
    extensions = tuple(sorted({item.upper() for item in contract.extensions}))
    if not extensions:
        _refuse('cpu-isa-extensions-undeclared', '/cpu/profile/cpu/extensions')
    return extensions


def isa_contract(cpu: ComponentProfile) -> IsaContract:
    """The CPU's declared ISA as an :class:`IsaContract`.

    Instruction alignment is derived from the declared ISA itself: the ``C``
    extension defines 16-bit instruction parcels, so a declared ``C`` means
    2-byte alignment and its absence means 4.
    """
    contract = cpu.cpu
    extensions = _isa_extensions(cpu)
    alignment = 2 if 'C' in extensions else 4
    try:
        return IsaContract(contract.xlen, extensions, instruction_alignment=alignment)
    except ValueError as error:
        _refuse('cpu-isa-contract-invalid', '/cpu/profile/cpu', {'error': str(error)})


def _capabilities(profile: ComponentProfile) -> Mapping[str, object]:
    return profile.capabilities if isinstance(profile.capabilities, Mapping) else {}


#: Roles whose width a profile's declared capacity block really fixes.
_ADDRESS_ROLES = frozenset(('address', 'addr', 'paddr'))
_DATA_ROLES = frozenset(('data', 'wdata', 'rdata', 'pwdata', 'prdata', 'instruction'))


def _declared_width(profile: ComponentProfile, role: str) -> int | None:
    """A declared capacity for a protocol role, from the profile's own block.

    ``address_width``/``data_width`` are declared capacities of the endpoint, not
    inferences from a port name.  A role this block does not fix has *no*
    declared width and is reported as a gap rather than guessed.
    """
    capabilities = _capabilities(profile)
    if role in _ADDRESS_ROLES:
        width = capabilities.get('address_width')
        return width if type(width) is int and width > 0 else None
    if role in _DATA_ROLES:
        width = capabilities.get('data_width')
        return width if type(width) is int and width > 0 else None
    if role == 'byte_enable':
        width = capabilities.get('data_width')
        return width // 8 if type(width) is int and width > 0 and width % 8 == 0 else None
    return None


def _effective_field_width(component: PathComponent, endpoint, profile_field,
                           wiring: PathWiring) -> int | None:
    """A field's width from its own declaration, its capacity block or a link."""
    if profile_field.width:
        return profile_field.width
    width = _declared_width(component.profile, profile_field.role)
    if width:
        return width
    links = [row for row in wiring.environment_links
             if row.component_instance == component.instance_id and row.width
             and row.bit_offset is None]
    named = [row for row in links if row.endpoint_id == endpoint.endpoint_id]
    if len(named) == 1:
        return named[0].width
    unnamed = [row for row in links if row.endpoint_id is None]
    input_endpoints = component.input_fields()
    owners = {row[0].endpoint_id for row in input_endpoints}
    if len(unnamed) == 1 and owners == {endpoint.endpoint_id}:
        return unnamed[0].width
    return None


def _register_access(profile: ComponentProfile, register: str) -> str | None:
    if profile.address is None:
        return None
    row = next((item for item in profile.address.registers if item.name == register), None)
    return None if row is None else row.access


def _sidecar_rows(capability: IPTestCapability | None):
    return () if capability is None else capability.register_semantics


def _readable_rows(capability: IPTestCapability | None):
    return tuple(row for row in _sidecar_rows(capability)
                 if row.read_mask != 0 and row.access in ('ro', 'rw'))


def _writable_rows(capability: IPTestCapability | None):
    return tuple(row for row in _sidecar_rows(capability)
                 if row.write_mask != 0 and row.access in ('wo', 'rw'))


def _preferred(rows, access_order: tuple[str, ...]):
    """Pick one row deterministically, preferring a side-effect-free field."""
    clean = [row for row in rows if row.side_effect == 'none']
    pool = clean or list(rows)
    return sorted(pool, key=lambda row: (access_order.index(row.access)
                                         if row.access in access_order else 99,
                                         row.register, row.field))[0]


def _endpoint_operations(component: PathComponent, endpoint_id: str) -> tuple[str, ...]:
    if component.capability is None:
        return ()
    row = next((item for item in component.capability.endpoint_capabilities
                if item.endpoint_id == endpoint_id), None)
    return () if row is None else tuple(row.operations)


# ---------------------------------------------------------------------------
# per-flow assessment
# ---------------------------------------------------------------------------

class _Assessment:
    """Everything one flow's evaluation produced, missing facts included."""

    def __init__(self, flow_id: str):
        self.flow_id = flow_id
        self.target = f'{flow_id}.{_FLOW_TARGETS[flow_id]}'
        self.missing: list[dict[str, object]] = []
        self.endpoints: list[dict[str, object]] = []
        self.sources: list[dict[str, object]] = []
        self.bound: list[dict[str, object]] = []
        self.prerequisites: list[dict[str, object]] = []
        self.seed: dict[str, object] | None = None
        self.termination: dict[str, object] = {
            'kind': 'incomplete',
            'basis': 'no declared end for this flow; an incomplete observation is '
                     'recorded rather than a manufactured result',
        }
        self.windows: list[WiringWindow] = []
        self.resource: WiringResource | None = None
        self.delivery: WiringDelivery | None = None
        self.direction: str = DIRECTION_CPU_SOURCED

    def need(self, code: str, pointer: str, detail) -> None:
        if code not in {row['code'] for row in self.missing}:
            self.missing.append(_missing(code, pointer, detail))

    def endpoint(self, component: PathComponent, endpoint, declared_role: str) -> None:
        record = {
            'instance_id': component.instance_id,
            'component_id': component.component_id,
            'endpoint_id': endpoint.endpoint_id,
            'function': endpoint.function,
            'protocol': list(endpoint.protocol) if endpoint.protocol else None,
            'declared_role': declared_role,
        }
        if record not in self.endpoints:
            self.endpoints.append(record)

    @property
    def status(self) -> str:
        return STATUS_UNSUPPORTED if self.missing else STATUS_EXECUTABLE


def _cpu_master(assessment: _Assessment, cpu: PathComponent, function: str, code: str,
                declared_pointer: str | None = None):
    matches = cpu.endpoints_with_function(function)
    if not matches:
        # A core with one unified memory port (CVW's EBU-arbitrated AHB bus,
        # picorv32's ready/valid port) has no separate instruction or data master,
        # and its profile is accurate to say so.  The single unified master fills
        # both roles; accepting it here is what keeps an accurate unified-memory
        # declaration from being reported as an unsupported flow.  It is accepted
        # only when it is the profile's sole *master-capable* endpoint (passive
        # observation/configuration declarations beside the bus are irrelevant), so
        # the role stays unambiguous and a profile with several masters must still
        # name the right one.  :func:`_sole_unified_master` is the one predicate
        # for this rule, shared with :func:`load_path_compile_request`.
        if function in (FUNCTION_INSTRUCTION_MASTER, FUNCTION_DATA_MASTER):
            sole = _sole_unified_master(cpu.profile)
            if sole is not None:
                matches = [row for row in cpu.endpoints()
                           if row.endpoint_id == sole]
    if not matches:
        assessment.need(code, '/cpu/profile/endpoints',
                        {'requires': f'an endpoint with function {function!r}',
                         'or_sole_unified_master': sorted(UNIFIED_MASTER_FUNCTIONS),
                         'component_id': cpu.component_id,
                         'declared_endpoints': sorted(row.endpoint_id
                                                      for row in cpu.endpoints())})
        return None
    if len(matches) > 1:
        _refuse('ambiguous-cpu-master-endpoint', '/cpu/profile/endpoints',
                {'function': function,
                 'endpoints': sorted(row.endpoint_id for row in matches)})
    if declared_pointer is not None and declared_pointer != matches[0].endpoint_id:
        _refuse('cpu-master-role-pointer-mismatch', '/cpu/role-pointer',
                {'declared': declared_pointer,
                 'resolved_by_declared_function': matches[0].endpoint_id,
                 'function': function})
    assessment.endpoint(cpu, matches[0], function)
    return matches[0]


def _instruction_source(assessment: _Assessment, cpu: PathComponent,
                        wiring: PathWiring,
                        pointers: Mapping[str, str | None] | None = None):
    """``(resource, source)`` for the declared CPU program image, or ``None``.

    F1 needs it by definition.  F2..F5 need it too, because a Load, a Store, an
    MMIO transaction or a trap is only produced by a CPU that is really running a
    declared image; without one the CPU-side end of those hops does not exist.
    Every missing fact is recorded before returning, so the report names them all.
    """
    pointers = pointers or {}
    instruction = _cpu_master(assessment, cpu, FUNCTION_INSTRUCTION_MASTER,
                              'cpu-instruction-master-missing',
                              pointers.get(FUNCTION_INSTRUCTION_MASTER))
    reset_vector = cpu.profile.cpu.reset_vector
    candidates = [row for row in wiring.resources
                  if row.execute is True and row.read is True
                  and row.base is not None and row.size is not None
                  and row.base <= reset_vector < row.base + row.size]
    if not candidates:
        assessment.need('instruction-image-resource-undeclared', '/wiring/resources',
                        {'requires': 'a declared resource with read and execute '
                                     'permissions containing the declared reset vector',
                         'reset_vector': reset_vector,
                         'declared_resources': [row.resource_id
                                                for row in wiring.resources]})
        return None
    if len(candidates) > 1:
        _refuse('ambiguous-instruction-image-resource', '/wiring/resources',
                {'resources': sorted(row.resource_id for row in candidates)})
    resource = candidates[0]
    if resource.component_instance is None:
        assessment.need('memory-serving-component-undeclared', '/wiring/resources',
                        {'resource_id': resource.resource_id,
                         'requires': 'the component_instance that really serves this '
                                     'region; an address range alone does not say who '
                                     'returns the stored instructions'})
        return None
    if instruction is None:
        return None
    width = _declared_width(cpu.profile, 'instruction')
    return resource, {
        'source_id': f'{resource.resource_id}.image',
        'origin': ORIGIN_FUZZABLE,
        'kind': 'instruction_image',
        'component': resource.component_instance,
        'endpoint_id': instruction.endpoint_id,
        'port': resource.resource_id,
        'bit_offset': 0,
        'width': resource.size * 8,
        'register': None,
        'field': None,
        'mask': (1 << width) - 1 if width else None,
        'alignment': isa_contract(cpu.profile).instruction_alignment,
        'range': [resource.base, resource.base + resource.size - 1],
        'origin_ref': f'wiring:{wiring.schema_version}',
        'constraint_basis': 'declared read+execute region containing the declared '
                            'reset vector',
    }


def _adopt_instruction_source(assessment: _Assessment, cpu: PathComponent,
                              wiring: PathWiring, pointers) -> dict | None:
    """Evaluate the program image, and adopt it as a source when it is declared."""
    result = _instruction_source(assessment, cpu, wiring, pointers)
    if result is None:
        return None
    resource, source = result
    assessment.resource = resource
    assessment.sources.append(source)
    return source


def _mmio_candidates(wiring: PathWiring, devices: tuple[PathComponent, ...]):
    """Resolve every declared window to a device, by declared function only.

    A window whose device endpoint *function* turns out not to be ``mmio_slave``,
    or whose aperture contradicts the device's declared alignment/window size, is
    a contradiction between two declarations and refuses the compilation.  A
    device that declares no address map at all is a *missing fact*: the window is
    reported as unresolved so the affected flows can name it, and the report
    carries it as a composition gap.
    """
    resolved, unresolved = [], []
    for window in wiring.windows:
        device = next((row for row in devices
                       if row.instance_id == window.target_instance), None)
        if device is None:
            _refuse('wiring-window-target-undeclared', '/windows',
                    {'target_instance': window.target_instance,
                     'declared_instances': sorted(row.instance_id for row in devices)})
        if window.endpoint_id is not None:
            endpoint = device.endpoint(window.endpoint_id)
            if endpoint is None:
                _refuse('wiring-window-endpoint-undeclared', '/windows',
                        {'endpoint_id': window.endpoint_id,
                         'instance_id': device.instance_id})
        else:
            matches = device.endpoints_with_function(FUNCTION_MMIO_SLAVE)
            if len(matches) != 1:
                _refuse('ambiguous-mmio-slave-endpoint',
                        f'/devices/{device.instance_id}/profile/endpoints',
                        {'instance_id': device.instance_id,
                         'endpoints': sorted(row.endpoint_id for row in matches)})
            endpoint = matches[0]
        if endpoint.function != FUNCTION_MMIO_SLAVE:
            _refuse('wiring-window-endpoint-not-mmio-slave', '/windows',
                    {'endpoint_id': endpoint.endpoint_id,
                     'declared_function': endpoint.function})
        address = device.profile.address
        if address is None:
            unresolved.append((window, device, endpoint, _missing(
                'mmio-device-address-map-undeclared',
                f'/devices/{device.instance_id}/profile/address',
                {'instance_id': device.instance_id,
                 'requires': 'a declared address map, so the window aperture can be '
                             'checked against the declared alignment and window size'})))
            continue
        if window.base % address.alignment:
            _refuse('wiring-window-misaligned', '/windows',
                    {'base': window.base, 'alignment': address.alignment})
        if window.size > address.window_size:
            _refuse('wiring-window-exceeds-declared-aperture', '/windows',
                    {'size': window.size, 'window_size': address.window_size})
        resolved.append((window, device, endpoint))
    return tuple(resolved), tuple(unresolved)


def _read_candidates(assessment: _Assessment, mmio: tuple, unresolved: tuple) -> list:
    """Devices whose declared capability really carries a read response."""
    readable = []
    for window, device, endpoint in mmio:
        if 'read' not in _endpoint_operations(device, endpoint.endpoint_id):
            continue
        rows = _readable_rows(device.capability)
        if rows:
            readable.append((window, device, endpoint, rows))
    if readable:
        return readable
    if not mmio and unresolved:
        _, _, _, need = unresolved[0]
        assessment.need(need['code'], need['pointer'], need['detail'])
        return []
    if not mmio:
        assessment.need('ip-read-response-missing', '/wiring/windows',
                        {'requires': 'a declared MMIO window to a device whose '
                                     'declared bus endpoint and capability sidecar '
                                     'really carry a read response',
                         'declared_windows': 0})
        return []
    assessment.need(
        'ip-read-response-missing',
        f'/devices/{mmio[0][1].instance_id}/test_capability',
        {'requires': "the endpoint's declared operations to contain 'read' and the "
                     'ip_test_capability sidecar to declare at least one readable '
                     'register field; the real IP read-response end of F2 is missing, '
                     'so the Fuzzer may not stand in for it',
         'devices': [row[1].instance_id for row in mmio],
         'declared_operations': {
             row[1].instance_id: list(_endpoint_operations(row[1], row[2].endpoint_id))
             for row in mmio},
         'declared_readable_fields': {
             row[1].instance_id: len(_readable_rows(row[1].capability))
             for row in mmio},
         'sidecar_absent': {row[1].instance_id: row[1].capability is None
                            for row in mmio}})
    return []


def _write_candidates(assessment: _Assessment, mmio: tuple, unresolved: tuple) -> list:
    """Devices whose declared capability really carries a writable field."""
    writable = []
    for window, device, endpoint in mmio:
        rows = _writable_rows(device.capability)
        if rows:
            writable.append((window, device, endpoint, rows))
    if writable:
        return writable
    if not mmio and unresolved:
        _, _, _, need = unresolved[0]
        assessment.need(need['code'], need['pointer'], need['detail'])
        return []
    if not mmio:
        assessment.need('mmio-window-missing', '/wiring/windows',
                        {'requires': 'a declared MMIO window from the CPU data master '
                                     'to a device bus endpoint'})
        return []
    assessment.need(
        'writable-field-undeclared',
        f'/devices/{mmio[0][1].instance_id}/test_capability/register_semantics',
        {'requires': 'the ip_test_capability sidecar to declare at least one field '
                     'with a nonzero write mask',
         'devices': [row[1].instance_id for row in mmio],
         'declared_writable_fields': {
             row[1].instance_id: len(_writable_rows(row[1].capability))
             for row in mmio}})
    return []


def _evaluate_f1(assessment: _Assessment, cpu: PathComponent, wiring: PathWiring,
                 pointers: Mapping[str, str | None] | None = None) -> None:
    source = _adopt_instruction_source(assessment, cpu, wiring, pointers)
    if source is None or assessment.missing:
        return
    assessment.direction = DIRECTION_CPU_SOURCED
    assessment.seed = {
        'kind': 'instruction_image',
        'detail': {
            'resource_id': source['port'],
            'base': source['range'][0],
            'size': source['range'][1] - source['range'][0] + 1,
            'isa': {'xlen': cpu.profile.cpu.xlen,
                    'extensions': list(_isa_extensions(cpu.profile)),
                    'instruction_alignment': source['alignment']},
        },
    }
    assessment.prerequisites.append({
        'kind': 'instruction_slot_unmaterialized',
        'basis': 'F1 mutates the program image itself, so the slot has to be still '
                 'unmaterialized when the case is admitted '
                 '(myfuzz.scenario.source_actions:PREREQUISITE_KINDS)',
        'subject': {'component': source['component']},
    })
    assessment.termination = {
        'kind': 'retirement',
        'basis': 'CPU 真实译码执行并更新 PC/寄存器 (plan line 77)',
    }


def _compile_register_source_access(assessment,cpu,master,device,endpoint,window,field,*,write):
    from .register_source_access import register_source_access
    try:
        return register_source_access(cpu=cpu,master=master,device=device,
            endpoint=endpoint,window=window,field=field,write=write)
    except ValueError as error:
        assessment.need(str(error),f'/devices/{device.instance_id}/profile/address/registers',
            {'register':field.register,'requires':'declared aligned 32-bit target-word access'})
        return None


def _evaluate_f2(assessment: _Assessment, cpu: PathComponent, wiring: PathWiring,
                 mmio: tuple, unresolved: tuple = (),
                 pointers: Mapping[str, str | None] | None = None,
                 selected_register: tuple[str, str] | None = None) -> None:
    pointers = pointers or {}
    master = _cpu_master(assessment, cpu, FUNCTION_DATA_MASTER,
                         'cpu-data-master-missing',
                         pointers.get(FUNCTION_DATA_MASTER))
    image = _instruction_source(assessment, cpu, wiring, pointers)
    readable = _read_candidates(assessment, mmio, unresolved)
    if selected_register is not None:
        readable = [(window, device, endpoint, [r for r in rows if r.register == selected_register[1]])
                    for window, device, endpoint, rows in readable if device.instance_id == selected_register[0]]
        readable = [row for row in readable if row[3]]
        if not readable:
            assessment.need('selected-mmio-read-register-unavailable', '/f6_execution/shared_slots/read_register',
                            {'component': selected_register[0], 'register': selected_register[1]})
    if assessment.missing or master is None or image is None or not readable:
        return
    resource, image_source = image
    assessment.resource = resource
    assessment.sources.append(image_source)
    window, device, endpoint, rows = readable[0]
    field = _preferred(rows, ('ro', 'rw'))
    access=_compile_register_source_access(assessment,cpu,master,device,endpoint,window,field,write=False)
    if access is None:return
    assessment.windows.append(window)
    assessment.endpoint(device, endpoint, 'read_response_producer')
    assessment.direction = DIRECTION_CPU_SOURCED
    assessment.bound.append({
        'input_id': f'{device.instance_id}.{endpoint.endpoint_id}.read_response',
        'origin': ORIGIN_BOUND,
        'kind': 'ip_read_response',
        'component': device.instance_id,
        'endpoint_id': endpoint.endpoint_id,
        'basis': 'F2 uses the target IP RTL real read response; bound rdata is never '
                 'randomly overwritten (plan line 78)',
    })
    assessment.sources.append({
        'source_id': f'{device.instance_id}.{field.register}.{field.field}.address',
        'origin': ORIGIN_FUZZABLE,
        'kind': 'cpu_load_stream',
        'component': cpu.instance_id,
        'endpoint_id': master.endpoint_id,
        'port': None,
        'bit_offset': 0,
        'width': 32,
        'register': field.register,
        'field': field.field,
        'mask': 0xffffffff,
        'alignment': access['access_alignment'],
        'range': [access['address'],access['address']],
        'register_access': access,
        'origin_ref': f'wiring:{wiring.schema_version}',
        'constraint_basis': 'the CPU-side load stream is the fuzzable source; the IP '
                            'read response stays bound',
    })
    assessment.prerequisites.append({
        'kind': 'ip_register_version',
        'basis': 'F2 requires the current live IP register version before reading',
        'subject': {'component': device.instance_id, 'register': field.register},
    })
    assessment.termination = {
        'kind': 'consumption',
        'basis': 'CPU 真实消费 rdata (plan line 78)',
    }


def _evaluate_f3(assessment: _Assessment, cpu: PathComponent, wiring: PathWiring,
                 pointers: Mapping[str, str | None] | None = None) -> None:
    pointers = pointers or {}
    master = _cpu_master(assessment, cpu, FUNCTION_DATA_MASTER,
                         'cpu-data-master-missing',
                         pointers.get(FUNCTION_DATA_MASTER))
    image = _instruction_source(assessment, cpu, wiring, pointers)
    candidates = [row for row in wiring.resources
                  if row.read is True and row.write is True]
    resource = None
    if not candidates:
        assessment.need('persistent-memory-resource-missing', '/wiring/resources',
                        {'requires': 'a declared resource the CPU can write and read '
                                     'back, so a later F1/F2 observes the same version',
                         'declared_resources': [{'resource_id': row.resource_id,
                                                 'read': row.read, 'write': row.write}
                                                for row in wiring.resources],
                         'wiring_schema': wiring.schema_version,
                         'absent_sections': list(wiring.absent_sections)})
    elif candidates[0].component_instance is None:
        assessment.need('memory-serving-component-undeclared', '/wiring/resources',
                        {'resource_id': candidates[0].resource_id,
                         'requires': 'the component_instance that really serves the '
                                     'persistent memory; a permission flag alone does '
                                     'not say who commits the byte version'})
    else:
        resource = candidates[0]
    if assessment.missing or master is None or image is None or resource is None:
        return
    _, image_source = image
    assessment.resource = image[0]
    assessment.sources.append(image_source)
    width = _declared_width(cpu.profile, 'data')
    assessment.direction = DIRECTION_CPU_SOURCED
    assessment.sources.append({
        'source_id': f'{resource.resource_id}.store_stream',
        'origin': ORIGIN_FUZZABLE,
        'kind': 'cpu_store_stream',
        'component': cpu.instance_id,
        'endpoint_id': master.endpoint_id,
        'port': None,
        'bit_offset': 0,
        'width': width,
        'register': None,
        'field': None,
        'mask': (1 << width) - 1 if width else None,
        'alignment': 4,
        'range': [resource.base, resource.base + resource.size - 1],
        'origin_ref': f'wiring:{wiring.schema_version}',
        'constraint_basis': 'CPU Store really supplies address, wdata and byte-enable '
                            '(plan line 79)',
    })
    assessment.prerequisites.append({
        'kind': 'ram_byte_version',
        'basis': 'a committed byte version must exist before a later read observes it',
        'subject': {'memory_id': resource.resource_id},
    })
    assessment.termination = {
        'kind': 'consumption',
        'basis': 'Memory Service 一次提交并逐字节更新 (plan line 79)',
    }


def _evaluate_f4(assessment: _Assessment, cpu: PathComponent, wiring: PathWiring,
                 mmio: tuple, unresolved: tuple = (),
                 pointers: Mapping[str, str | None] | None = None,
                 selected_register: tuple[str, str] | None = None) -> None:
    pointers = pointers or {}
    master = _cpu_master(assessment, cpu, FUNCTION_DATA_MASTER,
                         'cpu-data-master-missing',
                         pointers.get(FUNCTION_DATA_MASTER))
    image = _instruction_source(assessment, cpu, wiring, pointers)
    writable = _write_candidates(assessment, mmio, unresolved)
    if selected_register is not None:
        writable = [(window, device, endpoint, [r for r in rows if r.register == selected_register[1]])
                    for window, device, endpoint, rows in writable if device.instance_id == selected_register[0]]
        writable = [row for row in writable if row[3]]
        if not writable:
            assessment.need('selected-mmio-write-register-unavailable', '/f6_execution/shared_slots/register',
                            {'component': selected_register[0], 'register': selected_register[1]})
    if assessment.missing or master is None or image is None or not writable:
        return
    resource, image_source = image
    assessment.resource = resource
    assessment.sources.append(image_source)
    window, device, endpoint, rows = writable[0]
    field = _preferred(rows, ('rw', 'wo'))
    access=_compile_register_source_access(assessment,cpu,master,device,endpoint,window,field,write=True)
    if access is None:return
    assessment.windows.append(window)
    assessment.endpoint(device, endpoint, 'mmio_control_target')
    assessment.direction = DIRECTION_CPU_SOURCED
    assessment.sources.append({
        'source_id': f'{device.instance_id}.{field.register}.{field.field}.mmio',
        'origin': ORIGIN_FUZZABLE,
        'kind': 'cpu_mmio_stream',
        'component': cpu.instance_id,
        'endpoint_id': master.endpoint_id,
        'port': None,
        'bit_offset': field.lsb,
        'width': field.width,
        'register': field.register,
        'field': field.field,
        'mask': field.write_mask << field.lsb,
        'alignment': access['access_alignment'],
        'range': [access['address'],access['address']],
        'register_access': access,
        'origin_ref': f'wiring:{wiring.schema_version}',
        'constraint_basis': 'the register is reachable only through the CPU MMIO '
                            'path, so it is never randomised independently '
                            '(docs/CURRENT_DESIGN.md:34)',
    })
    assessment.bound.append({
        'input_id': f'{device.instance_id}.{endpoint.endpoint_id}.register.'
                    f'{field.register}.{field.field}',
        'origin': ORIGIN_BOUND,
        'kind': 'ip_register_commit',
        'component': device.instance_id,
        'endpoint_id': endpoint.endpoint_id,
        'basis': 'the register value is owned by the real IP RTL and the CPU MMIO '
                 'transaction; the environment may not write it '
                 '(docs/CURRENT_DESIGN.md:34)',
    })
    for endpoint_row in device.profile.endpoints:
        for profile_field in endpoint_row.fields:
            if _effective_direction(endpoint_row, profile_field) != 'input':
                continue
            width = _effective_field_width(device, endpoint_row, profile_field, wiring)
            if width is None:
                continue
            # A fully zero-fixed field is not a fuzz source. This agrees with
            # the Runner's zero initialization; nonzero fixed inputs need a
            # separate runtime value authority before they can be excluded.
            if len(profile_field.aliases) == 1:
                fixed_bits = set()
                for fixed in wiring.fixed_inputs:
                    if (fixed.component_instance == device.instance_id
                            and fixed.port == profile_field.aliases[0] and fixed.constant == 0):
                        fixed_bits.update(range(fixed.bit_offset, fixed.bit_offset + fixed.width))
                if all(bit in fixed_bits for bit in range(width)):
                    continue
            # Explicit external slices retain their physical mutation domain
            # independently of whether this composition declares an IRQ route.
            pin_links = [link for link in wiring.environment_links
                if link.component_instance == device.instance_id
                and link.endpoint_id == endpoint_row.endpoint_id
                and link.bit_offset is not None]
            if len(pin_links)>1:
                assessment.need('external-pin-source-ambiguous','/wiring/environment_links',
                    {'component':device.instance_id,'endpoint_id':endpoint_row.endpoint_id,
                     'requires':'one explicit external pin segment'})
                return
            offset = pin_links[0].bit_offset if pin_links else 0
            source_width = pin_links[0].width if pin_links else width
            if (type(source_width) is not int or source_width<1 or offset<0 or offset+source_width>width):
                assessment.need('external-pin-segment-out-of-range','/wiring/environment_links',
                    {'component':device.instance_id,'endpoint_id':endpoint_row.endpoint_id,'field_width':width})
                return
            shared_irq = (bool(pin_links) and any(
                delivery.producer_instance == device.instance_id
                and delivery.consumer_instance == cpu.instance_id
                for delivery in wiring.deliveries))
            assessment.sources.append({
                'source_id': (f'{device.instance_id}.{profile_field.role}.irq_event' if shared_irq
                              else f'{device.instance_id}.{profile_field.role}.external'),
                'origin': ORIGIN_FUZZABLE,
                'kind': 'external_pin',
                'component': device.instance_id,
                'endpoint_id': endpoint_row.endpoint_id,
                'port': profile_field.aliases[0] if profile_field.aliases else None,
                'bit_offset': offset,
                'width': source_width,
                'register': None,
                'field': None,
                'mask': (1 << source_width) - 1,
                'alignment': 1,
                'range': None,
                'origin_ref': f'wiring:{wiring.schema_version}',
                'constraint_basis': 'a declared input field on a declared external '
                                    'environment endpoint',
            })
    assessment.prerequisites.append({
        'kind': 'ip_register_version',
        'basis': 'the pre-state of the configured register is a declared version, not '
                 'a freshly loaded initial value',
        'subject': {'component': device.instance_id, 'register': field.register,
                    'reset_epoch': 0},
    })
    assessment.termination = {
        'kind': 'consumption',
        'basis': 'CPU 真实 Load/Store 经声明的地址窗口转换为 IP 原生局部协议事务 '
                 '(plan line 80)',
    }


def _selected_interrupt_shape(device, endpoint, delivery):
    """Resolve a delivery to one declared interrupt, without guessing a role."""
    shapes = [row for row in device.profile.interrupts
              if row.endpoint_id == endpoint.endpoint_id]
    signal = delivery.producer_signal
    if signal is not None:
        fields = {field.role: field for field in endpoint.fields}
        shapes = [shape for shape in shapes if signal in
                  (shape.role, shape.source_id, *getattr(fields.get(shape.role), 'aliases', ()))]
    return shapes[0] if len(shapes) == 1 else None


def _interrupt_source_physical(endpoint, shape):
    """Resolve one selected IRQ role to a bounded declared output alias."""
    fields = [field for field in endpoint.fields if field.role == shape.role]
    if len(fields) != 1:
        return None
    field = fields[0]
    if (_effective_direction(endpoint, field) != 'output' or len(field.aliases) != 1
            or shape.source_id and shape.source_id != field.aliases[0]
            or type(shape.bit) is not int or shape.bit < 0):
        return None
    span = field.bit_range
    if span is not None:
        low, high = span
    elif type(field.width) is int and field.width > 0:
        low, high = 0, field.width - 1
    else:
        return None
    if not low <= shape.bit <= high:
        return None
    return field.aliases[0], shape.bit


def _evaluate_f5(assessment: _Assessment, cpu: PathComponent, wiring: PathWiring,
                 devices: tuple[PathComponent, ...],
                 pointers: Mapping[str, str | None] | None = None, *, selected_producer=None) -> None:
    entry = None
    entry_matches = cpu.endpoints_with_function(FUNCTION_INTERRUPT_ENTRY)
    if not entry_matches:
        assessment.need('interrupt-consumer-missing', '/cpu/profile/endpoints',
                        {'requires': f'an endpoint with function '
                                     f'{FUNCTION_INTERRUPT_ENTRY!r}',
                         'component_id': cpu.component_id})
    elif len(entry_matches) > 1:
        _refuse('ambiguous-interrupt-entry-endpoint', '/cpu/profile/endpoints',
                {'endpoints': sorted(row.endpoint_id for row in entry_matches)})
    else:
        entry = entry_matches[0]
        assessment.endpoint(cpu, entry, 'interrupt_consumer')
    contract = cpu.profile.cpu
    if entry is not None:
        if contract.irq_entry_role is None or contract.irq_entry_polarity is None:
            assessment.need('interrupt-consumer-shape-undeclared', '/cpu/profile/cpu',
                            {'requires': 'irq_entry_role and irq_entry_polarity, '
                                         'because the IRQ shape must be declared and '
                                         'is never inferred from a port name'})
        elif not [row for row in entry.fields
                  if row.role == contract.irq_entry_role]:
            assessment.need('interrupt-consumer-shape-undeclared',
                            '/cpu/profile/endpoints',
                            {'requires': f'a field with role '
                                         f'{contract.irq_entry_role!r}',
                             'declared_roles': sorted(row.role for row in entry.fields)})
    # A generic delivery to another CPU endpoint is not an IRQ.  The legacy
    # SoC format's interrupt_routes section is itself IRQ-specific and its
    # parser intentionally leaves the consumer endpoint implicit.
    irq_deliveries = tuple(delivery for delivery in wiring.deliveries
        if entry is not None and delivery.consumer_instance == cpu.instance_id
        and (delivery.consumer_endpoint_id == entry.endpoint_id
             or delivery.consumer_endpoint_id is None
             and delivery.source == SOC_RENDER_CONFIG_SCHEMA))
    # Explicit vector routes must name distinct lines.  A shared physical
    # line is an IRQ group, not multiple independent direct bindings.
    explicit_bits = [d.consumer_bit_offset for d in irq_deliveries
                     if d.consumer_bit_offset is not None]
    if len(explicit_bits) != len(set(explicit_bits)):
        _refuse('interrupt-delivery-bit-conflict', '/wiring/deliveries',
                {'requires': 'distinct vector bits for independent direct bindings'})
    if selected_producer is None and len(irq_deliveries) > 1 and explicit_bits:
        _refuse('interrupt-delivery-ambiguous', '/wiring/deliveries',
                {'requires': 'explicit producer selection for multiple vector routes'})
    # Shared dispatch explicitly selects the pin-source member. Other group
    # members (e.g. DMA completion) must not contribute missing GPIO/status
    # requirements or silently become this F5 path's producer. Runtime group
    # admission separately binds the physical path to actual OR membership.
    if selected_producer is not None:
        irq_deliveries=tuple(d for d in irq_deliveries if d.producer_instance==selected_producer)
    if not irq_deliveries:
        assessment.need('interrupt-delivery-missing', '/wiring/deliveries',
                        {'requires': 'a declared delivery from a real IP interrupt '
                                     'producer to the CPU interrupt entry; IRQ 的生产者'
                                     '与消费者都必须是真实存在的端',
                         'declared_sections': list(wiring.declared_sections),
                         'absent_sections': list(wiring.absent_sections),
                         'wiring_schema': wiring.schema_version})
    producers = []
    for delivery in irq_deliveries:
        device = next((row for row in devices
                       if row.instance_id == delivery.producer_instance), None)
        if device is None:
            assessment.need('interrupt-producer-missing', '/wiring/deliveries',
                            {'delivery_id': delivery.delivery_id,
                             'producer_instance': delivery.producer_instance,
                             'requires': 'the producer to be one of the declared '
                                         'composition devices'})
            continue
        if delivery.producer_endpoint_id is None:
            matches = device.endpoints_with_function(FUNCTION_INTERRUPT_SOURCE)
            if not matches:
                assessment.need(
                    'interrupt-producer-missing',
                    f'/devices/{device.instance_id}/profile/endpoints',
                    {'delivery_id': delivery.delivery_id,
                     'declared_signal': delivery.producer_signal,
                     'requires': f'an endpoint with function '
                                 f'{FUNCTION_INTERRUPT_SOURCE!r}; the declared signal '
                                 'name is evidence, not an endpoint, so the Fuzzer may '
                                 'not turn it into one',
                     'declared_endpoints': sorted(row.endpoint_id
                                                  for row in device.endpoints())})
                continue
            if len(matches) > 1:
                _refuse('ambiguous-interrupt-source-endpoint',
                        f'/devices/{device.instance_id}/profile/endpoints',
                        {'endpoints': sorted(row.endpoint_id for row in matches)})
            producer = matches[0]
        else:
            producer = device.endpoint(delivery.producer_endpoint_id)
            if producer is None or producer.function != FUNCTION_INTERRUPT_SOURCE:
                assessment.need('interrupt-producer-missing', '/wiring/deliveries',
                                {'delivery_id': delivery.delivery_id,
                                 'producer_endpoint_id': delivery.producer_endpoint_id,
                                 'requires': f'an endpoint with function '
                                             f'{FUNCTION_INTERRUPT_SOURCE!r}'})
                continue
        shape = _selected_interrupt_shape(device, producer, delivery)
        if shape is None:
            assessment.need('interrupt-producer-shape-undeclared',
                            f'/devices/{device.instance_id}/profile/interrupts',
                            {'endpoint_id': producer.endpoint_id,
                             'requires': 'a declared polarity and trigger for the '
                                         'producer; the IRQ shape is never inferred'})
            continue
        if _interrupt_source_physical(producer, shape) is None:
            assessment.need('interrupt-producer-physical-port-invalid',
                            f'/devices/{device.instance_id}/profile/interrupts',
                            {'endpoint_id': producer.endpoint_id, 'role': shape.role,
                             'requires': 'one declared output alias and an in-range physical bit'})
            continue
        if contract.irq_entry_polarity is not None and (
                shape.polarity != contract.irq_entry_polarity):
            _refuse('interrupt-shape-mismatch', '/wiring/deliveries',
                    {'delivery_id': delivery.delivery_id,
                     'producer_polarity': shape.polarity,
                     'consumer_polarity': contract.irq_entry_polarity})
        if shape.trigger not in ('level', 'pulse'):
            _refuse('interrupt-trigger-undeclared', '/wiring/deliveries',
                    {'delivery_id': delivery.delivery_id, 'trigger': shape.trigger})
        if delivery.trigger is not None and delivery.trigger != shape.trigger:
            _refuse('interrupt-trigger-mismatch', '/wiring/deliveries',
                    {'delivery_id': delivery.delivery_id,
                     'producer_trigger': shape.trigger, 'delivery_trigger': delivery.trigger})
        readable = _readable_rows(device.capability)
        if not readable:
            assessment.need(
                'post-irq-status-read-missing',
                f'/devices/{device.instance_id}/test_capability/register_semantics',
                {'delivery_id': delivery.delivery_id,
                 'requires': 'the producer to declare a readable status field, because '
                             'F5 ends with the CPU ISR reading the real IP state'})
            continue
        producers.append((delivery, device, producer, shape, readable))

    image = _instruction_source(assessment, cpu, wiring, pointers) if producers else None
    if not producers or image is None or assessment.missing:
        return
    delivery, device, producer, shape, _readable = producers[0]
    resource, image_source = image
    assessment.resource = resource
    assessment.sources.append(image_source)
    assessment.direction = DIRECTION_IP_SOURCED
    assessment.delivery = delivery
    assessment.endpoint(device, producer, 'interrupt_producer')
    # Only an explicit environment link to an external-pins endpoint can
    # nominate the source. A bus input is owned by its routed initiator even
    # if it appears first in the profile or carries an input direction.
    candidates = []
    segments = {}
    unresolved_candidates = 0
    for link in wiring.environment_links:
        if link.component_instance != device.instance_id or link.endpoint_id is None:
            continue
        owner = device.endpoint(link.endpoint_id)
        if owner is None or (link.bit_offset is not None and owner.function != FUNCTION_EXTERNAL_PINS):
            _refuse('wiring-link-segment-endpoint-invalid' if link.bit_offset is not None
                    else 'wiring-link-endpoint-invalid', '/wiring/environment_links',
                    {'link_id': link.link_id, 'endpoint_id': link.endpoint_id})
        if owner is None or owner.function != FUNCTION_EXTERNAL_PINS:
            continue
        if link.bit_offset is not None and (
                type(link.bit_offset) is not int or link.bit_offset < 0
                or type(link.width) is not int or link.width < 1):
            _refuse('wiring-link-segment-out-of-range', '/wiring/environment_links',
                    {'link_id': link.link_id})
        if link.bit_offset is not None and not any(
                _effective_direction(owner, item) == 'input' and len(item.aliases) == 1
                for item in owner.fields):
            _refuse('wiring-link-segment-endpoint-invalid', '/wiring/environment_links',
                    {'link_id': link.link_id, 'endpoint_id': link.endpoint_id})
        for pin_field in owner.fields:
            width = _effective_field_width(device, owner, pin_field, wiring)
            if (width is None and link.width is not None and link.bit_offset is None
                    and _effective_direction(owner, pin_field) == 'input'
                    and len(pin_field.aliases) == 1):
                unresolved_candidates += 1
            if (link.bit_offset is not None and _effective_direction(owner, pin_field) == 'input'
                    and len(pin_field.aliases) == 1):
                if width is None or link.bit_offset + link.width > width:
                    _refuse('wiring-link-segment-out-of-range', '/wiring/environment_links',
                            {'link_id': link.link_id, 'field_width': width})
            if (_effective_direction(owner, pin_field) == 'input'
                    and len(pin_field.aliases) == 1 and width is not None
                    and (link.bit_offset is not None or link.width is None or link.width == width)):
                key = (device.instance_id, owner.endpoint_id, pin_field.aliases[0])
                start = link.bit_offset if link.bit_offset is not None else 0
                end = start + (link.width if link.bit_offset is not None else width)
                if any(fixed.component_instance == device.instance_id
                       and fixed.port == pin_field.aliases[0]
                       and start < fixed.bit_offset + fixed.width
                       and fixed.bit_offset < end for fixed in wiring.fixed_inputs):
                    _refuse('wiring-link-fixed-overlap', '/wiring/environment_links',
                            {'link_id': link.link_id, 'port': pin_field.aliases[0]})
                if any(start < old_end and old_start < end and (explicit or link.bit_offset is not None)
                       for old_start, old_end, explicit in segments.get(key, ())):
                    _refuse('wiring-link-segment-overlap', '/wiring/environment_links',
                            {'link_id': link.link_id})
                segments.setdefault(key, []).append((start, end, link.bit_offset is not None))
                candidates.append((link, owner, pin_field,
                                   link.width if link.bit_offset is not None else width))
    if len(candidates) != 1 or unresolved_candidates:
        assessment.need('interrupt-source-ambiguous'
                        if len(candidates) + unresolved_candidates > 1 else 'interrupt-source-missing',
                        '/wiring/environment_links',
                        {'producer_instance': device.instance_id,
                         'candidate_count': len(candidates),
                         'requires': 'exactly one declared, usable external input source'})
        return
    if len(candidates) == 1:
        link, owner, pin_field, width = candidates[0]
        if width is not None:
            assessment.sources.append({
                'source_id': f'{device.instance_id}.{pin_field.role}.irq_event',
                'origin': ORIGIN_FUZZABLE,
                'kind': 'external_pin',
                'component': device.instance_id,
                'endpoint_id': owner.endpoint_id,
                'port': pin_field.aliases[0] if pin_field.aliases else None,
                'bit_offset': link.bit_offset if link.bit_offset is not None else 0,
                'width': width,
                'register': None,
                'field': None,
                'mask': (1 << width) - 1,
                'alignment': 1,
                'range': None,
                'origin_ref': f'wiring:{link.link_id}',
                'constraint_basis': 'the environment really drives this declared input; '
                                    'the IRQ itself stays bound',
            })
    assessment.bound.append({
        'input_id': f'{device.instance_id}.{producer.endpoint_id}.irq',
        'origin': ORIGIN_BOUND,
        'kind': 'ip_irq',
        'component': device.instance_id,
        'endpoint_id': producer.endpoint_id,
        'basis': 'the IRQ producer end is a real IP output; the Fuzzer may not '
                 'manufacture it (plan P7-C step 2)',
    })
    assessment.bound.append({
        'input_id': f'{cpu.instance_id}.{entry.endpoint_id}.{contract.irq_entry_role}',
        'origin': ORIGIN_BOUND,
        'kind': 'cpu_irq_input',
        'component': cpu.instance_id,
        'endpoint_id': entry.endpoint_id,
        **({'consumer_bit_offset': delivery.consumer_bit_offset} if delivery.consumer_bit_offset is not None else {}),
        'basis': 'the CPU IRQ input is a bound real output: the source-action '
                 'contract refuses a mutable payload whose endpoint_class is in '
                 'CPU_IRQ_ENDPOINT_CLASSES (source_actions.py:68,448)',
    })
    assessment.prerequisites.append({
        'kind': 'irq_input_delivered',
        'basis': 'the declared delivery has to be observed delivered before the CPU '
                 'can trap',
        'subject': {'cpu_component': cpu.instance_id,
                    'source_event_id': delivery.delivery_id},
    })
    assessment.termination = {
        'kind': 'delivery',
        'basis': 'IP 真实状态/IRQ 经声明的交付规则送至 CPU 中断输入 (plan line 81)',
    }


def _evaluate_declared_irq_f5(assessment, request, marker, *, base_dir, pointers):
    """F5 initiated by a CPU MMIO program, with the IRQ still DUT-owned."""
    from myfuzz.integration.shared_declared_irq import compile_declared_irq
    plan = compile_declared_irq(request, marker, request.document['f6_execution']['program'], base_dir=base_dir)
    cpu, wiring = request.cpu, request.wiring
    target = request.device(plan['component'])
    windows = [w for w in wiring.windows if w.target_instance == target.instance_id]
    deliveries = [d for d in wiring.deliveries if d.producer_instance == target.instance_id
                  and d.consumer_instance == cpu.instance_id]
    entry = cpu.endpoint(cpu.profile.cpu.irq_entry_endpoint)
    irq = target.endpoint(deliveries[0].producer_endpoint_id)
    if entry is None or irq is None:
        raise ValueError('shared-declared-IRQ-endpoint-required')
    image = _instruction_source(assessment, cpu, wiring, pointers)
    if image is None:
        return
    assessment.resource, source = image
    assessment.sources.append(source)
    assessment.windows.append(windows[0])
    assessment.delivery = deliveries[0]
    assessment.direction = DIRECTION_CPU_SOURCED
    assessment.endpoint(target, irq, 'interrupt_producer')
    assessment.endpoint(cpu, entry, 'interrupt_consumer')
    assessment.declared_irq = plan
    assessment.bound.extend([{'input_id': target.instance_id + '.irq', 'origin': ORIGIN_BOUND,
        'kind': 'ip_irq', 'component': target.instance_id, 'endpoint_id': irq.endpoint_id,
        'basis': 'the declared-output interrupt is observed from the actual target'},
        {'input_id': cpu.instance_id + '.irq', 'origin': ORIGIN_BOUND, 'kind': 'cpu_irq_input',
         'component': cpu.instance_id, 'endpoint_id': entry.endpoint_id,
         **({'consumer_bit_offset': deliveries[0].consumer_bit_offset} if deliveries[0].consumer_bit_offset is not None else {}),
         'basis': 'the CPU IRQ is delivered from the real shared group'}])
    assessment.termination = {'kind': 'delivery', 'basis': 'actual declared target IRQ delivered to CPU'}


def _profile_endpoint_sha256(component: PathComponent, endpoint_id: str) -> str:
    return hashlib.sha256(_canonical({
        'profile_fingerprint': component.profile.profile_fingerprint,
        'endpoint_id': endpoint_id,
    })).hexdigest()


def _f6_complete_wiring_document(wiring):
    from dataclasses import asdict
    from myfuzz.scenario.dma_route_intent import dma_master_route_intents_document
    def plain(value):
        if isinstance(value,Mapping):return {key:plain(item) for key,item in value.items()}
        if isinstance(value,(tuple,list)):return [plain(item) for item in value]
        return value
    def rows(values):
        return [{key:plain(item) for key,item in asdict(value).items()
                 if key!='source' and item is not None} for value in values]
    return dict(schema_version=PATH_WIRING_SCHEMA_V2,
        cpu=dict(instance_id=wiring.cpu_instance_id,data_endpoint=wiring.cpu_data_endpoint_id),
        windows=rows(wiring.windows),resources=rows(wiring.resources),deliveries=rows(wiring.deliveries),
        environment_links=rows(wiring.environment_links),fixed_inputs=rows(wiring.fixed_inputs),
        dma_master_routes=dma_master_route_intents_document(wiring.dma_master_routes),
        dma_master_routes_sha256=wiring.dma_master_routes_sha256,
        dma_master_route_bindings=plain(wiring.dma_master_route_bindings))


def _wiring_resource_document(resource: WiringResource) -> dict[str, object]:
    row = {
        'resource_id': resource.resource_id,
        'component_instance': resource.component_instance,
        'base': resource.base, 'size': resource.size,
        'read': resource.read, 'write': resource.write,
        'execute': resource.execute,
    }
    if resource.initialization_policy is not None:
        row['initialization_policy'] = resource.initialization_policy
    return row


def _validate_static_dma_routes(cpu: PathComponent, devices: tuple[PathComponent, ...],
                                wiring: PathWiring) -> None:
    """Bind v2 static intents to declared profiles without creating live routes."""
    if not wiring.dma_master_routes:
        if wiring.dma_master_route_bindings:
            _refuse('dma-route-bindings-without-routes', '/wiring/dma_master_route_bindings')
        return
    components = {row.instance_id: row for row in (cpu, *devices)}
    bindings = {row['route_id']: row for row in wiring.dma_master_route_bindings}
    for index, route in enumerate(wiring.dma_master_routes):
        pointer = f'/wiring/dma_master_routes/routes/{index}'
        mover = components.get(route.initiator_instance)
        if mover is None or mover.is_cpu:
            _refuse('dma-route-initiator-instance-undeclared',
                    pointer + '/initiator_instance',
                    {'instance_id': route.initiator_instance,
                     'declared_devices': sorted(row.instance_id for row in devices)})
        endpoint = mover.endpoint(route.initiator_endpoint_id)
        if endpoint is None:
            _refuse('dma-route-initiator-endpoint-undeclared',
                    pointer + '/initiator_endpoint_id',
                    {'endpoint_id': route.initiator_endpoint_id,
                     'declared_endpoints': sorted(row.endpoint_id
                                                  for row in mover.endpoints())})
        if endpoint.function not in MASTER_FUNCTIONS:
            _refuse('dma-route-initiator-not-master',
                    pointer + '/initiator_endpoint_id',
                    {'endpoint_id': endpoint.endpoint_id,
                     'declared_function': endpoint.function,
                     'requires_one_of': sorted(MASTER_FUNCTIONS)})
        feature = mover.capability.feature_contract if mover.capability else None
        matching_transfer = tuple(
            row for row in feature.operations
            if row.operation == FEATURE_TRANSFER
            and row.endpoint_id == route.initiator_endpoint_id) if feature else ()
        if not matching_transfer:
            _refuse('dma-route-transfer-endpoint-mismatch',
                    pointer + '/initiator_endpoint_id',
                    {'endpoint_id': route.initiator_endpoint_id,
                     'transfer_endpoints': ([row.endpoint_id for row in feature.operations
                                             if row.operation == FEATURE_TRANSFER]
                                            if feature else []),
                     'requires': 'the exact declared endpoint of a transfer feature '
                                 'operation'})
        binding = bindings[route.route_id]
        initiator_binding = binding['initiator']
        initiator_fingerprint = _profile_endpoint_sha256(mover,
                                                          route.initiator_endpoint_id)
        if initiator_binding['profile_endpoint_sha256'] != initiator_fingerprint:
            _refuse('dma-route-profile-endpoint-fingerprint-mismatch',
                    f'/wiring/dma_master_route_bindings/{index}/initiator'
                    '/profile_endpoint_sha256',
                    {'route_id': route.route_id,
                     'declared': initiator_binding['profile_endpoint_sha256'],
                     'computed': initiator_fingerprint})

        target = route.target
        if target['kind'] == 'persistent_memory':
            owner_instance = target['component_instance']
            owner = components.get(owner_instance)
            if owner is None:
                _refuse('dma-route-target-instance-undeclared',
                        pointer + '/target/component_instance',
                        {'instance_id': owner_instance,
                         'declared_instances': sorted(components)})
            resources = [row for row in wiring.resources
                         if row.resource_id == target['resource_id']]
            if len(resources) != 1:
                _refuse('dma-route-target-resource-ambiguous-or-missing',
                        pointer + '/target/resource_id',
                        {'resource_id': target['resource_id'],
                         'matches': len(resources)})
            resource = resources[0]
            if resource.component_instance != owner_instance:
                _refuse('dma-route-target-resource-owner-mismatch',
                        pointer + '/target/component_instance',
                        {'declared': owner_instance,
                         'resource_owner': resource.component_instance})
            if (resource.base is None or resource.size is None
                    or route.base < resource.base
                    or route.base + route.size > resource.base + resource.size):
                _refuse('dma-route-target-aperture-outside-resource',
                        pointer + '/base',
                        {'route': [route.base, route.base + route.size],
                         'resource': [resource.base,
                                      (resource.base + resource.size
                                       if resource.base is not None
                                       and resource.size is not None else None)]})
            for permission in route.permissions:
                if getattr(resource, permission) is not True:
                    _refuse('dma-route-target-resource-permission-mismatch',
                            pointer + '/permissions',
                            {'resource_id': resource.resource_id,
                             'permission': permission,
                             'declared': getattr(resource, permission)})
            target_binding = binding['target']
            resource_sha256 = hashlib.sha256(
                _canonical(_wiring_resource_document(resource))).hexdigest()
            if target_binding['owner_profile_fingerprint'] != \
                    owner.profile.profile_fingerprint:
                _refuse('dma-route-target-profile-fingerprint-mismatch',
                        f'/wiring/dma_master_route_bindings/{index}/target'
                        '/owner_profile_fingerprint',
                        {'route_id': route.route_id,
                         'declared': target_binding['owner_profile_fingerprint'],
                         'computed': owner.profile.profile_fingerprint})
            if target_binding['resource_sha256'] != resource_sha256:
                _refuse('dma-route-target-resource-fingerprint-mismatch',
                        f'/wiring/dma_master_route_bindings/{index}/target'
                        '/resource_sha256',
                        {'route_id': route.route_id,
                         'declared': target_binding['resource_sha256'],
                         'computed': resource_sha256})
        else:
            target_instance = target['component_instance']
            target_component = components.get(target_instance)
            if target_component is None or target_component.is_cpu:
                _refuse('dma-route-target-instance-undeclared',
                        pointer + '/target/component_instance',
                        {'instance_id': target_instance,
                         'declared_devices': sorted(row.instance_id
                                                    for row in devices)})
            target_endpoint_id = target['endpoint_id']
            target_endpoint = target_component.endpoint(target_endpoint_id)
            if target_endpoint is None:
                _refuse('dma-route-target-endpoint-undeclared',
                        pointer + '/target/endpoint_id',
                        {'endpoint_id': target_endpoint_id,
                         'declared_endpoints': sorted(row.endpoint_id
                                                      for row in target_component.endpoints())})
            if (target_endpoint.protocol is None
                    or FUNCTION_DIRECTIONS.get(target_endpoint.function) != 'protocol'):
                _refuse('dma-route-target-not-protocol-slave',
                        pointer + '/target/endpoint_id',
                        {'endpoint_id': target_endpoint_id,
                         'declared_function': target_endpoint.function})
            windows = [row for row in wiring.windows
                       if row.device_id == target['device_id']
                       and row.target_instance == target_instance
                       and row.endpoint_id == target_endpoint_id]
            if len(windows) != 1:
                _refuse('dma-route-target-window-ambiguous-or-missing',
                        pointer + '/target',
                        {'device_id': target['device_id'],
                         'target_instance': target_instance,
                         'endpoint_id': target_endpoint_id,
                         'matches': len(windows)})
            window = windows[0]
            address = target_component.profile.address
            if (route.base < window.base or route.base + route.size > window.base + window.size
                    or address is None
                    or route.base - window.base + route.size > address.window_size):
                _refuse('dma-route-target-aperture-outside-window', pointer + '/base',
                        {'route': [route.base, route.base + route.size],
                         'window': [window.base, window.base + window.size],
                         'profile_window_size': (address.window_size
                                                 if address is not None else None)})
            declared_operations = next((row.operations for row in
                                        target_component.capability.endpoint_capabilities
                                        if row.endpoint_id == target_endpoint_id), ()) \
                if target_component.capability else ()
            for permission in route.permissions:
                if (target_component.profile.capabilities.get(permission) is not True
                        or permission not in declared_operations):
                    _refuse('dma-route-target-operation-undeclared',
                            pointer + '/permissions',
                            {'endpoint_id': target_endpoint_id,
                             'operation': permission,
                             'profile_capability': target_component.profile.capabilities.get(
                                 permission),
                             'endpoint_operations': list(declared_operations)})
                offsets = (route.readable_offsets if permission == 'read'
                           else route.writable_offsets)
                for offset_index, offset in enumerate(offsets):
                    absolute_offset = route.base - window.base + offset
                    registers = [row for row in address.registers
                                 if row.offset == absolute_offset]
                    if len(registers) != 1:
                        _refuse('dma-route-target-register-offset-undeclared',
                                f'{pointer}/{"readable_offsets" if permission == "read" else "writable_offsets"}/{offset_index}',
                                {'offset': offset,
                                 'profile_offset': absolute_offset,
                                 'matches': len(registers)})
                    access = registers[0].access
                    if ((permission == 'read' and access == 'wo')
                            or (permission == 'write' and access == 'ro')):
                        _refuse('dma-route-target-register-permission-mismatch',
                                f'{pointer}/{"readable_offsets" if permission == "read" else "writable_offsets"}/{offset_index}',
                                {'offset': absolute_offset, 'access': access,
                                 'permission': permission})
            target_binding = binding['target']
            target_fingerprint = _profile_endpoint_sha256(target_component,
                                                           target_endpoint_id)
            if target_binding['profile_endpoint_sha256'] != target_fingerprint:
                _refuse('dma-route-profile-endpoint-fingerprint-mismatch',
                        f'/wiring/dma_master_route_bindings/{index}/target'
                        '/profile_endpoint_sha256',
                        {'route_id': route.route_id,
                         'declared': target_binding['profile_endpoint_sha256'],
                         'computed': target_fingerprint})


def _evaluate_f6(assessment: _Assessment, cpu: PathComponent, wiring: PathWiring,
                 devices: tuple[PathComponent, ...],
                 pointers: Mapping[str, str | None] | None = None,
                 *, request: PathCompileRequest | None = None) -> None:
    if request is not None and 'f6_execution' in request.document:
        from .f6_execution_contract import compile_f6_execution_contract, SCHEMA_VERSION
        contract = compile_f6_execution_contract(request, base_dir=request.base_dir)
        assessment.execution_contract = contract
        assessment.direction = DIRECTION_CPU_SOURCED
        resource, image = _instruction_source(assessment, cpu, wiring, pointers)
        assessment.resource = resource
        assessment.bound.append(dict(image, origin=ORIGIN_BOUND))
        for operand in contract['candidate_layout']['sources']:
            assessment.sources.append(dict(operand, origin=ORIGIN_FUZZABLE,
                kind='cpu_instruction_operand', component=cpu.instance_id,
                endpoint_id=image['endpoint_id'], port=resource.resource_id,
                field='imm11', alignment=1, range=[0, 2047],
                origin_ref=image['source_id'], constraint_basis=SCHEMA_VERSION,
                instruction_source_id=image['source_id']))
        words = contract['candidate_layout']['seed']
        raw = sum(word << (11*i) for i, word in enumerate(words))
        assessment.seed = dict(kind='cpu_instruction_operands', words=list(words),
            raw8_hex=raw.to_bytes(8, 'little').hex(),
            source_ids=[source['source_id'] for source in assessment.sources])
        assessment.prerequisites.extend([
            dict(kind='instruction_slot_unmaterialized', subject=dict(component=cpu.instance_id),
                 basis='online prefix requires unmaterialized instruction slots'),
            dict(kind='dma_live_topology_binding', subject=dict(route_ids=[r.route_id for r in wiring.dma_master_routes]),
                 basis='static support never substitutes for the live topology binder')])
        assessment.termination = dict(kind=contract['termination'],
            basis='native DMA IRQ, native CPU take, ISR readback and authenticated MRET')
        return
    feature_providers = [row for row in devices
                         if row.capability is not None
                         and row.capability.feature_contract is not None
                         and any(operation.operation == FEATURE_TRANSFER
                                 for operation in row.capability.feature_contract.operations)]
    if not feature_providers:
        assessment.need(
            'dma-master-not-declared',
            '/devices/*/test_capability/feature_contract',
            {'requires': f'an ip_test_capability v2+ feature contract declaring the '
                         f'{FEATURE_TRANSFER!r} operation, i.e. a real data-movement '
                         'provider; no declared component offers one',
             'declared_feature_providers': {
                 row.instance_id: (row.capability.feature_contract.provider_id
                                   if row.capability and row.capability.feature_contract
                                   else None)
                 for row in devices}})
        return
    routes = wiring.dma_master_routes
    if not routes:
        assessment.need(
            'dma-master-route-undeclared', '/wiring/dma_master_routes',
            {'requires': 'an explicit route from the transfer feature endpoint to '
                         'its declared persistent-memory or peripheral target'})
        return
    movers = {route.initiator_instance for route in routes}
    if len(movers) != 1:
        assessment.need('dma-route-mover-ambiguous', '/wiring/dma_master_routes',
                        {'initiator_instances': sorted(movers),
                         'requires': 'one explicitly selected transfer mover for F6'})
        return
    mover = next((row for row in feature_providers
                  if row.instance_id in movers), None)
    if mover is None:
        # Global validation rejects this condition; retain the guard so a direct
        # caller cannot turn a malformed PathWiring into a guessed F6 source.
        assessment.need('dma-route-transfer-provider-missing',
                        '/wiring/dma_master_routes',
                        {'initiator_instance': next(iter(movers))})
        return
    endpoint_ids = {route.initiator_endpoint_id for route in routes}
    if len(endpoint_ids) != 1:
        assessment.need('dma-route-master-endpoint-ambiguous',
                        '/wiring/dma_master_routes',
                        {'initiator_endpoint_ids': sorted(endpoint_ids),
                         'requires': 'all routes in one F6 path share one explicitly '
                                     'declared transfer master endpoint'})
        return
    endpoint = mover.endpoint(next(iter(endpoint_ids)))
    image = _instruction_source(assessment, cpu, wiring, pointers)
    if image is None or assessment.missing or endpoint is None:
        return
    resource, image_source = image
    assessment.resource = resource
    assessment.sources.append(image_source)
    width = _declared_width(mover.profile, 'data')
    assessment.endpoint(mover, endpoint, 'dma_master')
    assessment.direction = DIRECTION_CPU_SOURCED
    assessment.sources.append({
        'source_id': f'{mover.instance_id}.{endpoint.endpoint_id}.transfer',
        'origin': ORIGIN_FUZZABLE,
        'kind': 'dma_transfer_descriptor',
        'component': mover.instance_id,
        'endpoint_id': endpoint.endpoint_id,
        'port': None,
        'bit_offset': 0,
        'width': width,
        'register': None,
        'field': None,
        'mask': (1 << width) - 1 if width else None,
        'alignment': 4,
        'range': None,
        'origin_ref': f'feature:{mover.capability.feature_contract.provider_id}',
        'constraint_basis': 'the declared transfer feature operation and exact '
                            'static master route intent',
    })
    assessment.need(
        'dma-route-live-topology-binding-required', '/wiring/dma_master_routes',
        {'requires': 'bind every static intent to the live Runner master endpoint '
                     'and target window before runtime DMA edges or execution are '
                     'admitted',
         'route_ids': [route.route_id for route in routes],
         'intent_sha256': wiring.dma_master_routes_sha256})
    assessment.termination = {
        'kind': 'incomplete',
        'basis': 'static route intent does not prove a completion interrupt or CPU '
                 'consumption (plan line 82)',
    }


# ---------------------------------------------------------------------------
# declared source claims and the compiled input constraints
# ---------------------------------------------------------------------------

def _claim_is_randomizable(claim: Mapping[str, object]) -> bool:
    return claim.get('origin', ORIGIN_FUZZABLE) == ORIGIN_FUZZABLE


def _register_claim(component: PathComponent, claim: Mapping[str, object],
                    pointer: str) -> dict:
    """Validate one register-field source claim against the declared capability."""
    row = _closed(claim, {'source_id', 'flow_id', 'component', 'endpoint_id',
                          'register', 'field'},
                  {'origin', 'mask', 'range', 'alignment'}, pointer, 'source')
    if row['flow_id'] not in FLOW_IDS:
        _refuse('unknown-source-flow', pointer + '/flow_id',
                {'declared': row['flow_id'], 'allowed': list(FLOW_IDS)})
    if not _claim_is_randomizable(row):
        return row
    capability = component.capability
    if capability is None:
        _refuse('test-capability-required', pointer,
                {'component_id': component.component_id,
                 'requires': 'an ip_test_capability sidecar to prove the declared '
                             'field is really writable'})
    semantics = next((item for item in _sidecar_rows(capability)
                      if item.register == row['register'] and item.field == row['field']),
                     None)
    if semantics is None:
        _refuse('undeclared-register-field', pointer + '/field',
                {'register': row['register'], 'field': row['field'],
                 'declared_fields': sorted(f'{item.register}.{item.field}'
                                           for item in _sidecar_rows(capability))})
    access = _register_access(component.profile, row['register'])
    if access == 'ro' or semantics.access == 'ro':
        _refuse('read-only-register-declared-fuzzable', pointer + '/field',
                {'register': row['register'], 'field': row['field'],
                 'declared_register_access': access,
                 'declared_field_access': semantics.access,
                 'sidecar_fingerprint': capability.sidecar_fingerprint})
    if semantics.write_mask == 0:
        _refuse('reserved-field-declared-fuzzable', pointer + '/field',
                {'register': row['register'], 'field': row['field'],
                 'declared_write_mask': semantics.write_mask,
                 'declared_read_mask': semantics.read_mask,
                 'evidence_ref': semantics.evidence_ref})
    return {**row, 'lsb': semantics.lsb, 'width': semantics.width,
            'write_mask': semantics.write_mask, 'read_mask': semantics.read_mask,
            'side_effect': semantics.side_effect}


def _endpoint_claim(component: PathComponent, claim: Mapping[str, object],
                    pointer: str):
    row = _closed(claim, {'source_id', 'flow_id', 'component', 'endpoint_id', 'role'},
                  {'origin', 'mask', 'range', 'alignment'}, pointer, 'source')
    if row['flow_id'] not in FLOW_IDS:
        _refuse('unknown-source-flow', pointer + '/flow_id',
                {'declared': row['flow_id'], 'allowed': list(FLOW_IDS)})
    endpoint = component.endpoint(row['endpoint_id'])
    if endpoint is None:
        _refuse('unknown-endpoint', pointer + '/endpoint_id',
                {'endpoint_id': row['endpoint_id'],
                 'declared_endpoints': sorted(item.endpoint_id
                                              for item in component.endpoints())})
    profile_field = next((item for item in endpoint.fields if item.role == row['role']),
                         None)
    if profile_field is None:
        _refuse('unknown-endpoint-field-role', pointer + '/role',
                {'endpoint_id': endpoint.endpoint_id, 'role': row['role'],
                 'declared_roles': sorted(item.role for item in endpoint.fields)})
    if not _claim_is_randomizable(row):
        return row, endpoint, profile_field, None
    contract = component.profile.cpu
    if endpoint.function == FUNCTION_INTERRUPT_ENTRY or (
            contract is not None and contract.irq_entry_endpoint == endpoint.endpoint_id):
        _refuse('cpu-irq-cannot-be-a-fuzzable-source', pointer,
                {'endpoint_id': endpoint.endpoint_id,
                 'declared_function': endpoint.function,
                 'rule': 'source_actions.py:68 CPU_IRQ_ENDPOINT_CLASSES and '
                         'source_actions.py:448 refuse a mutable source with that '
                         'endpoint class; the IRQ is a bound real output'})
    direction = _effective_direction(endpoint, profile_field)
    if direction not in ('input', 'inout'):
        _refuse('output-field-declared-fuzzable', pointer + '/role',
                {'endpoint_id': endpoint.endpoint_id, 'role': profile_field.role,
                 'declared_direction': direction,
                 'endpoint_function': endpoint.function})
    return row, endpoint, profile_field, direction


def _declared_claims(components: tuple[PathComponent, ...],
                     wiring: PathWiring) -> tuple[list[dict], list[dict], list[dict]]:
    """Validate every fuzzable-source declaration; refuse the illegal ones.

    Two sources of claims are checked: a profile field that declares
    ``randomizable`` (the profile schema's own "the environment drives this"
    flag) and a request ``sources`` row.  This is the compile-time gate for the
    "reserved-bit random source" negative: a claim that a read-only register
    field, a reserved field, a DUT-driven output or the CPU IRQ input is a
    fuzzable source is refused with the pointer to the exact claim and to the
    capability that forbids it.
    """
    constraints, claims, register_claims = [], [], []
    for component in components:
        for endpoint in component.profile.endpoints:
            for profile_field in endpoint.fields:
                if not profile_field.randomizable:
                    continue
                # The pointer names the instance as well as the profile: two
                # instances of one profile (two PULP GPIOs) declare the same
                # component id, endpoint and role, so a pointer without the
                # instance cannot say which one a gap or refusal is about.
                pointer = (f'profile:{component.component_id}:instance:'
                           f'{component.instance_id}:endpoints:'
                           f'{endpoint.endpoint_id}:fields:{profile_field.role}')
                if endpoint.function == FUNCTION_INTERRUPT_ENTRY:
                    _refuse('cpu-irq-cannot-be-a-fuzzable-source', pointer,
                            {'endpoint_id': endpoint.endpoint_id,
                             'declared_function': endpoint.function,
                             'rule': 'source_actions.py:448 refuses a mutable source '
                                     'with a CPU_IRQ endpoint class'})
                direction = _effective_direction(endpoint, profile_field)
                if direction not in ('input', 'inout'):
                    _refuse('output-field-declared-fuzzable', pointer,
                            {'endpoint_id': endpoint.endpoint_id,
                             'role': profile_field.role,
                             'declared_direction': direction})
        for claim in component.declared_sources:
            if 'register' in claim.row or 'field' in claim.row:
                row = _register_claim(component, claim.row, claim.pointer)
                if _claim_is_randomizable(row):
                    # A register field is never an environment-driven layout
                    # field: docs/CURRENT_DESIGN.md:34 fixes that the CPU MMIO
                    # transaction owns it, so the claim constrains the value the
                    # CPU writes instead of adding a second writer.
                    register_claims.append({**row, 'pointer': claim.pointer,
                                            'component_instance': component.instance_id,
                                            'constraint_basis':
                                                'reachable only through the CPU MMIO '
                                                'path (docs/CURRENT_DESIGN.md:34)'})
                claims.append({'pointer': claim.pointer, 'claim': dict(claim.row),
                               'resolved': row})
                continue
            row, endpoint, profile_field, direction = _endpoint_claim(
                component, claim.row, claim.pointer)
            width = _effective_field_width(component, endpoint, profile_field, wiring)
            if width is None and _claim_is_randomizable(row):
                _refuse('source-width-undeclared', claim.pointer,
                        {'role': profile_field.role,
                         'requires': 'a declared field width or a declared external '
                                     'environment link width'})
            if _claim_is_randomizable(row):
                constraints.append({
                    'owner': endpoint.endpoint_id,
                    '_component_instance': component.instance_id,
                    'role': profile_field.role,
                    'randomizable': True,
                    **{name: row[name] for name in ('mask', 'range', 'alignment')
                       if name in row},
                })
            claims.append({'pointer': claim.pointer, 'claim': dict(claim.row),
                           'resolved': {**row, 'width': width,
                                        'direction': direction}})
    return constraints, claims, register_claims


def _layout_annotations(components: tuple[PathComponent, ...],
                        wiring: PathWiring) -> tuple[list[dict], list[dict]]:
    """Declared input fields as an ``input_layout`` annotation document.

    Only fields whose declared (or function-declared) direction is an input are
    laid out, because a layout describes what the environment may drive.  A field
    whose width no declaration fixes is *not* silently given one: it is reported
    as a gap and left out.
    """
    endpoints, gaps = [], []
    # Raw layout names are global, whereas physical ports are local to each
    # independent artifact. Namespace only collisions across instances; keep
    # existing single-instance layouts byte-identical.
    seen: set[tuple[str, str, str]] = set()
    ports: dict[tuple[str, str], str] = {}
    endpoint_instances: dict[str, set[str]] = {}
    port_instances: dict[str, set[str]] = {}
    for component in components:
        for endpoint in component.profile.endpoints:
            if endpoint.function == FUNCTION_INTERRUPT_ENTRY:
                continue
            for profile_field in endpoint.fields:
                if (_effective_direction(endpoint, profile_field) in ('input', 'inout')
                        and profile_field.aliases
                        and _effective_field_width(component, endpoint, profile_field, wiring) is not None):
                    endpoint_instances.setdefault(endpoint.endpoint_id, set()).add(component.instance_id)
                    port_instances.setdefault(profile_field.aliases[0], set()).add(component.instance_id)
    for component in components:
        for endpoint in component.profile.endpoints:
            # A CPU interrupt entry is a *bound real output* of a peripheral, not
            # something the environment drives: source_actions.py:68/448 refuse a
            # mutable source with that endpoint class.  A layout describes only
            # what the environment may drive, so an interrupt entry is not part of
            # it.  Laying it out also cannot work in general - the CPU may bind one
            # bit inside a wider packed interrupt port (cv32e40p binds irq_i[11],
            # CSR_MEIX_BIT), and the shipped layout compiler requires a packed
            # port's fields to tile it from bit 0, which those constant-zero bits
            # are declared for in ``port_actions`` rather than as layout fields.
            if endpoint.function == FUNCTION_INTERRUPT_ENTRY:
                continue
            fields = []
            for profile_field in endpoint.fields:
                direction = _effective_direction(endpoint, profile_field)
                if direction not in ('input', 'inout'):
                    continue
                # The pointer names the instance as well as the profile: two
                # instances of one profile (two PULP GPIOs) declare the same
                # component id, endpoint and role, so a pointer without the
                # instance cannot say which one a gap or refusal is about.
                pointer = (f'profile:{component.component_id}:instance:'
                           f'{component.instance_id}:endpoints:'
                           f'{endpoint.endpoint_id}:fields:{profile_field.role}')
                key = (component.instance_id, endpoint.endpoint_id,
                       profile_field.role)
                if key in seen:
                    _refuse('duplicate-layout-field', pointer,
                            {'instance_id': component.instance_id,
                             'owner': endpoint.endpoint_id,
                             'role': profile_field.role})
                seen.add(key)
                width = _effective_field_width(component, endpoint, profile_field, wiring)
                if width is None:
                    gaps.append(_missing(
                        'source-width-undeclared', pointer,
                        {'requires': 'a declared field width, a declared capacity for '
                                     'the role, or a declared external environment '
                                     'link width',
                         'role': profile_field.role,
                         'endpoint_function': endpoint.function}))
                    continue
                if not profile_field.aliases:
                    gaps.append(_missing(
                        'source-port-undeclared', pointer,
                        {'requires': 'at least one declared alias naming the port'}))
                    continue
                port = profile_field.aliases[0]
                owner = f'{component.instance_id}::{endpoint.endpoint_id}'
                port_key = (component.instance_id, port)
                if port_key in ports and ports[port_key] != owner:
                    _refuse('duplicate-input-port', pointer,
                            {'port': port, 'declared_by': ports[port_key],
                             'also_declared_by': owner})
                ports[port_key] = owner
                bit_range = profile_field.bit_range
                record = {
                    'role': profile_field.role,
                    'direction': 'input',
                    'width': (bit_range[1] - bit_range[0] + 1) if bit_range else width,
                    'port': (f'{component.instance_id}::{port}'
                             if len(port_instances[port]) > 1 else port),
                    'randomizable': (endpoint.function == FUNCTION_EXTERNAL_PINS
                                     and endpoint.function != FUNCTION_INTERRUPT_ENTRY),
                    'evidence': [f'profile:endpoints:{endpoint.endpoint_id}:'
                                 f'{profile_field.role}'],
                }
                if bit_range is not None:
                    record['member_path'] = [profile_field.role]
                    record['raw_lo'] = bit_range[0]
                    record['raw_hi'] = bit_range[1]
                    record['container_width'] = width
                fields.append(record)
            if fields:
                endpoints.append({'endpoint_id': (f'{component.instance_id}::{endpoint.endpoint_id}'
                                  if len(endpoint_instances[endpoint.endpoint_id]) > 1
                                  else endpoint.endpoint_id),
                                  '_component_instance': component.instance_id,
                                  '_original_endpoint_id': endpoint.endpoint_id,
                                  'fields': fields})
    owners = [endpoint['endpoint_id'] for endpoint in endpoints]
    # Different endpoint identities may not collide after namespacing either.
    if len(owners) != len(set(owners)):
        _refuse('duplicate-layout-owner', '/inputs')
    layout_ports = [(endpoint['_component_instance'], row['port'])
                    for endpoint in endpoints for row in endpoint['fields']]
    for index, (instance, port) in enumerate(layout_ports):
        if any(other_port == port and other_instance != instance
               for other_instance, other_port in layout_ports[:index]):
            _refuse('duplicate-input-port', '/inputs', {'port': port})
    return endpoints, gaps


def _compile_constraints(components: tuple[PathComponent, ...], wiring: PathWiring,
                         annotations: list[dict], constraints: list[dict]):
    """Compile the declared inputs through the shipped constraint compiler."""
    cpu = next((row for row in components if row.is_cpu), None)
    layout = None
    if annotations:
        try:
            owner_map = {(row['_component_instance'], row['_original_endpoint_id']): row['endpoint_id']
                         for row in annotations}
            layout_constraints = []
            for row in constraints:
                record = dict(row)
                instance = record.pop('_component_instance')
                record['owner'] = owner_map.get((instance, record['owner']), record['owner'])
                layout_constraints.append(record)
            layout = build_input_layout(
                {'endpoints': annotations},
                component_constraints=tuple(layout_constraints),
                isa=isa_contract(cpu.profile) if cpu is not None else None)
        except InputLayoutError as error:
            # Second net: an unknown/contradictory/illegal input field is refused
            # by the shipped layout compiler as well as by the explicit gate.
            _refuse('input-layout-refused', '/sources', {'error': str(error)})
    windows = [{'target_id': window.device_id, 'base': window.base, 'size': window.size,
                'request_sources': [window.target_instance]}
               for window in wiring.windows]
    plan = SimpleNamespace(
        raw_layout=input_layout_document(layout) if layout is not None else {},
        instances=(), plan={'address_map': {'windows': windows}}, plan_hash='')
    try:
        policy = compile_input_constraints(plan, drive_profile='cpu_execute')
    except InputConstraintError as error:
        # Second net: a double-driven bit or an environment write over a
        # DUT-owned value is refused by the shipped constraint compiler.
        pointer = '/wiring/windows' if 'window' in str(error) else '/sources'
        _refuse('input-constraint-refused', pointer, {'error': str(error)})
    return layout, policy


# ---------------------------------------------------------------------------
# runtime contract
# ---------------------------------------------------------------------------

def _runtime_declaration(assessments: list[_Assessment], cpu: PathComponent,
                         wiring: PathWiring, devices: tuple[PathComponent, ...]):
    """Compile the executable paths' declared hops into a real runtime contract.

    Only declared facts become nodes and edges.  A hop whose ends are not both
    declared is omitted with a named reason instead of being approximated, and
    when nothing can be declared the contract is ``None``.
    """
    sources: list[FuzzableSource] = []
    rules: list[DependencyRule] = []
    nodes: dict[str, RuntimeNode] = {}
    edges: list[RuntimeEdgeContract] = []
    omitted: list[dict] = []
    index = 0

    def add_rule(target: str, prerequisite: str, kind: str, relation: str | None,
                 **kwargs):
        nonlocal index
        rules.append(DependencyRule(target, (prerequisite,), kind))
        if relation is not None:
            edges.append(RuntimeEdgeContract(index, 0, relation, **kwargs))
        index += 1

    for assessment in assessments:
        flow = assessment.flow_id
        if flow == 'F6' and hasattr(assessment, 'execution_contract'):
            c = assessment.execution_contract
            for source in assessment.sources:
                source_id = source['source_id']
                sources.append(FuzzableSource(source_id, cpu.instance_id, source['port'],
                    source['bit_offset'], source['width'], (DIRECTION_CPU_SOURCED,)))
                nodes[source_id] = RuntimeNode(source_id, cpu.instance_id, 'state')
            stages = [('cpu_source_configuration', cpu.instance_id),
                      ('dma_control_acceptance', c['dma']['instance_id']),
                      ('native_dma_read_snapshot', c['dma']['instance_id']),
                      ('native_dma_write_commit', c['dma']['instance_id']),
                      ('native_dma_irq', c['dma']['instance_id']),
                      ('native_cpu_irq_take', cpu.instance_id),
                      ('isr_status_data_readback', cpu.instance_id),
                      ('dma_transfer_complete', cpu.instance_id)]
            previous = [s['source_id'] for s in assessment.sources]
            for stage_index, (stage, component) in enumerate(stages):
                node = 'F6.' + stage
                nodes[node] = RuntimeNode(node, component, 'logical')
                for prerequisite in previous:
                    if stage_index == 1:
                        add_rule(node, prerequisite, 'EVENT_ORDER', 'mmio_route',
                            initiator_component=cpu.instance_id, device_id=c['control']['device_id'],
                            base=c['control']['base'], size=c['control']['size'])
                    elif stage_index in (0, 3):
                        add_rule(node, prerequisite, 'PERSISTENT_STATE_RULE', 'persistent_state',
                            resource_component=cpu.instance_id, resource_id=assessment.resource.resource_id)
                    else:
                        add_rule(node, prerequisite, 'EVENT_ORDER', 'causal_order')
                previous = [node]
            continue
        if flow == 'F6':
            if wiring.dma_master_routes:
                omitted.append(_missing(
                    'dma-route-live-topology-binding-required', '/wiring/dma_master_routes',
                    {'flow_id': flow,
                     'requires': 'static route intent must be bound to the live Runner '
                                 'master endpoint and target window before a runtime '
                                 'DMA_MASTER_TRANSFER edge can be emitted'}))
            else:
                omitted.append(_missing(
                    'dma-master-route-undeclared', '/wiring',
                    {'flow_id': flow,
                     'requires': 'a declared DMA master route; a master declaration '
                                 'without an explicit target hop is not a runtime edge'}))
            continue
        if assessment.status != STATUS_EXECUTABLE:
            continue
        if flow == 'F5' and hasattr(assessment, 'declared_irq'):
            plan = assessment.declared_irq
            image = next(s for s in assessment.sources if s['kind'] == 'instruction_image')
            image_node, trigger_node, source_node = 'F5.program_image', 'F5.mmio_trigger', 'F5.ip_irq'
            sources.append(FuzzableSource(image_node, image['component'], image['port'], 0,
                image['width'], (DIRECTION_CPU_SOURCED,), kind='memory_image'))
            nodes[image_node] = RuntimeNode(image_node, image['component'], 'state')
            nodes[trigger_node] = RuntimeNode(trigger_node, cpu.instance_id, 'logical')
            nodes[source_node] = RuntimeNode(source_node, plan['component'], 'physical',
                plan['source']['port'], plan['source']['bit_offset'], 1)
            entry = cpu.endpoint(cpu.profile.cpu.irq_entry_endpoint)
            field = next(f for f in entry.fields if f.role == cpu.profile.cpu.irq_entry_role)
            bit = field.bit_range[0] if field.bit_range else 0
            nodes[assessment.target] = RuntimeNode(assessment.target, cpu.instance_id, 'physical',
                field.aliases[0], bit, 1)
            add_rule(trigger_node, image_node, 'PERSISTENT_STATE_RULE', 'persistent_state',
                resource_component=assessment.resource.component_instance,
                resource_id=assessment.resource.resource_id)
            window = assessment.windows[0]
            add_rule(source_node, trigger_node, 'EVENT_ORDER', 'mmio_route',
                initiator_component=cpu.instance_id, device_id=window.device_id,
                base=window.base, size=window.size)
            add_rule(assessment.target, source_node, 'EVENT_ORDER', 'direct_binding')
            continue
        if flow == 'F5' and assessment.delivery is not None:
            delivery = assessment.delivery
            producer = next((row for row in devices
                             if row.instance_id == delivery.producer_instance), None)
            if producer is None:
                omitted.append(_missing('interrupt-producer-undeclared',
                                        '/wiring/deliveries', {'flow_id': flow}))
                continue
            ends = _interrupt_physical_ends(assessment, cpu, producer)
            if ends is None:
                omitted.append(_missing(
                    'interrupt-physical-ends-undeclared', '/wiring/deliveries',
                    {'flow_id': flow,
                     'requires': 'declared port aliases and bit ranges on both the '
                                 'producer and the consumer interrupt fields, because '
                                 'a direct_binding relation names physical endpoints'}))
                continue
            (producer_node, producer_port, producer_bit), \
                (entry_node, entry_port, entry_bit) = ends
            nodes[producer_node] = RuntimeNode(producer_node, producer.instance_id,
                                               'physical', producer_port, producer_bit, 1)
            nodes[entry_node] = RuntimeNode(entry_node, cpu.instance_id, 'physical',
                                            entry_port, entry_bit, 1)
            pin = next((row for row in assessment.sources
                        if row['kind'] == 'external_pin'), None)
            if pin is None:
                omitted.append(_missing('interrupt-source-node-undeclared',
                                        '/paths', {'flow_id': flow}))
                continue
            pin_node = f'{flow}.pin_event'
            sources.append(FuzzableSource(pin_node, pin['component'], pin['port'], pin['bit_offset'],
                                          pin['width'], (DIRECTION_IP_SOURCED,)))
            nodes[pin_node] = RuntimeNode(pin_node, pin['component'], 'physical',
                                          pin['port'], pin['bit_offset'], pin['width'])
            add_rule(producer_node, pin_node, 'EVENT_ORDER', None)
            add_rule(entry_node, producer_node, 'EVENT_ORDER', 'direct_binding')
            continue
        target = assessment.target
        image = next((row for row in assessment.sources
                      if row['kind'] == 'instruction_image'), None)
        if image is None:
            omitted.append(_missing('instruction-image-node-undeclared', '/paths',
                                    {'flow_id': flow}))
            continue
        # A declared non-IRQ F4 auxiliary drive is an independent source
        # domain, not an AND prerequisite or cause of the CPU register write.
        if flow=='F4':
            pins=[s for s in assessment.sources if s['kind']=='external_pin']
            for pin in pins:
                links=[link for link in wiring.environment_links
                    if link.component_instance==pin['component'] and link.endpoint_id==pin['endpoint_id']
                    and (link.bit_offset,link.width)==(pin['bit_offset'],pin['width'])]
                irq_route=any(d.producer_instance==pin['component'] and d.consumer_instance==cpu.instance_id
                    for d in wiring.deliveries)
                if len(links)==1 and not irq_route:
                    name=pin['source_id']
                    sources.append(FuzzableSource(name,pin['component'],pin['port'],pin['bit_offset'],pin['width'],
                        (DIRECTION_CPU_SOURCED,)))
                    nodes[name]=RuntimeNode(name,pin['component'],'physical',pin['port'],pin['bit_offset'],pin['width'])
        image_node = f'{flow}.program_image'
        if image_node not in nodes:
            sources.append(FuzzableSource(image_node, image['component'],
                                          image['port'], 0, image['width'],
                                          (DIRECTION_CPU_SOURCED,),
                                          kind='memory_image'))
            nodes[image_node] = RuntimeNode(image_node, image['component'], 'state')
        resource = assessment.resource
        if resource is None or resource.component_instance is None:
            omitted.append(_missing('persistent-state-resource-undeclared',
                                    '/wiring/resources',
                                    {'flow_id': flow,
                                     'requires': 'a declared serving instance for the '
                                                 'instruction image'}))
            continue
        nodes[target] = RuntimeNode(target, cpu.instance_id, 'logical')
        if flow == 'F1':
            add_rule(target, image_node, 'PERSISTENT_STATE_RULE', 'persistent_state',
                     resource_component=resource.component_instance,
                     resource_id=resource.resource_id)
            continue
        if flow in ('F2', 'F4'):
            window = assessment.windows[0]
            device = next((row for row in devices
                           if row.instance_id == window.target_instance), None)
            if device is None:
                omitted.append(_missing('mmio-route-device-undeclared', '/wiring/windows',
                                        {'flow_id': flow,
                                         'target_instance': window.target_instance}))
                continue
            if flow == 'F4':
                # F4 ends at the actual peripheral register response. Keeping
                # both ends on the CPU contradicts the declared MMIO route
                # and prevents the generic runtime topology binder admitting it.
                nodes[target] = RuntimeNode(target, device.instance_id, 'logical')
            hop = f'{flow}.{"read_request" if flow == "F2" else "mmio_access"}'
            nodes[hop] = RuntimeNode(hop, cpu.instance_id, 'logical')
            add_rule(hop, image_node, 'PERSISTENT_STATE_RULE', 'persistent_state',
                     resource_component=resource.component_instance,
                     resource_id=resource.resource_id)
            response = f'{flow}.read_response' if flow == 'F2' else target
            if flow == 'F2':
                nodes[response] = RuntimeNode(response, device.instance_id, 'logical')
            add_rule(response, hop, 'DATA_BINDING', 'mmio_route',
                     initiator_component=cpu.instance_id, device_id=window.device_id,
                     base=window.base, size=window.size)
            if flow == 'F2':
                add_rule(target, response, 'DATA_BINDING', 'mmio_route',
                         initiator_component=cpu.instance_id, device_id=window.device_id,
                         base=window.base, size=window.size)
            continue
        if flow == 'F3':
            ram = next((row for row in wiring.resources
                        if row.read is True and row.write is True
                        and row.component_instance), None)
            if ram is None:
                omitted.append(_missing('persistent-memory-resource-undeclared',
                                        '/wiring/resources', {'flow_id': flow}))
                continue
            store = f'{flow}.cpu_store'
            nodes[store] = RuntimeNode(store, cpu.instance_id, 'logical')
            add_rule(store, image_node, 'PERSISTENT_STATE_RULE', 'persistent_state',
                     resource_component=resource.component_instance,
                     resource_id=resource.resource_id)
            add_rule(target, store, 'PERSISTENT_STATE_RULE', 'persistent_state',
                     resource_component=ram.component_instance,
                     resource_id=ram.resource_id)
            continue
        omitted.append(_missing('runtime-hop-undeclared', '/paths',
                                {'flow_id': flow,
                                 'requires': 'a declared hop shape for this flow'}))

    if not edges:
        return None, (omitted or [_missing('runtime-declaration-empty', '/paths',
                                          {'reason': 'no executable path declared a '
                                                     'runtime hop'})])
    graph = DependencyGraph(sources=tuple(sources), rules=tuple(rules))
    graph_sha256 = hashlib.sha256(_canonical(graph.edge_document())).hexdigest()
    contract = RuntimePathContract(graph_sha256, tuple(nodes.values()), tuple(edges))
    return (graph, contract), omitted


def _interrupt_physical_ends(assessment: _Assessment, cpu: PathComponent,
                             producer: PathComponent):
    """Physical (node, port, bit) for both IRQ ends, or None when undeclared."""
    contract = cpu.profile.cpu
    delivery = assessment.delivery
    producer_end = producer.endpoint(delivery.producer_endpoint_id)
    if producer_end is None:
        candidates = producer.endpoints_with_function(FUNCTION_INTERRUPT_SOURCE)
        producer_end = candidates[0] if len(candidates) == 1 else None
    consumer_matches = cpu.endpoints_with_function(FUNCTION_INTERRUPT_ENTRY)
    consumer_end = consumer_matches[0] if len(consumer_matches) == 1 else None
    if producer_end is None or consumer_end is None:
        return None
    shape = _selected_interrupt_shape(producer, producer_end, delivery)
    consumer_field = next((row for row in consumer_end.fields
                           if row.role == contract.irq_entry_role), None)
    if shape is None or consumer_field is None or not consumer_field.aliases:
        return None
    producer_physical = _interrupt_source_physical(producer_end, shape)
    if producer_physical is None:
        return None
    span = consumer_field.bit_range
    entry_width = (span[1] - span[0] + 1) if span else consumer_field.width
    low = span[0] if span else 0
    selected_bit = delivery.consumer_bit_offset
    if selected_bit is None:
        if entry_width != 1:
            return None
        entry_bit = low
    else:
        if type(selected_bit) is not int or entry_width is None or not low <= selected_bit < low + entry_width:
            return None
        entry_bit = selected_bit
    return ((f'{assessment.flow_id}.ip_irq', *producer_physical),
            (f'{assessment.flow_id}.cpu_irq_entry', consumer_field.aliases[0],
             entry_bit))


def _runtime_identities(graph, assessments: list[_Assessment]) -> dict:
    """Stable ``dependency_edge_path_identity.v1`` per executable path."""
    identities = {}
    if graph is None:
        return identities
    targets = {rule.target for rule in graph.ordered_rules}
    for assessment in assessments:
        if assessment.status != STATUS_EXECUTABLE or assessment.target not in targets:
            continue
        try:
            paths = graph.edge_paths_to(assessment.target,
                                        direction=assessment.direction)
        except ValueError:
            continue
        if not paths:
            continue
        path = paths[0]
        identities[assessment.flow_id] = {
            'direction': assessment.direction,
            'path_id': graph.path_identity(path, direction=assessment.direction),
            'source_ids': list(path.source_ids),
            'edges': [edge.document() for edge in path.edges],
        }
    return identities


# ---------------------------------------------------------------------------
# compilation
# ---------------------------------------------------------------------------

def _assertion_set(flow_id: str) -> list[dict]:
    rows = []
    for expectation_id in _ASSERTIONS_BY_FLOW[flow_id]:
        expectation = _EXPECTATION_BY_ID[expectation_id]
        rows.append({
            'expectation_id': expectation_id,
            'assertion_class': expectation['assertion_class'],
            'declared_by': expectation['declared_by'],
            'asserts': expectation['asserts'],
        })
    return rows


def _rule_applies(rule, assessment: _Assessment) -> bool:
    """Which compiled rules one path's declared inputs are subject to."""
    if rule.rule_id.startswith('window:'):
        return any(rule.rule_id == f'window:{window.device_id}'
                   for window in assessment.windows)
    if rule.rule_id.startswith(('value:', 'drive:')):
        owner = rule.rule_id.split(':', 1)[1].split(':', 1)[0]
        return (any(endpoint['endpoint_id'] == owner
                    for endpoint in assessment.endpoints)
                or any(row.get('component') == owner for row in assessment.sources))
    return False


def compile_paths(request: PathCompileRequest) -> dict:
    """Compile every ``F1..F6`` path of one composition into one document.

    The returned mapping is a complete ``compiled_paths.v1`` document: one record
    per flow, each carrying ``status`` and ``reason``, plus the compiled input
    constraints and the runtime path contract of the executable paths.  An illegal
    declaration raises :class:`PathCompilationError` instead, and no document is
    produced.
    """
    if not isinstance(request, PathCompileRequest):
        _refuse('path-compile-request-required', '')
    cpu, devices, wiring = request.cpu, request.devices, request.wiring
    components = (cpu, *devices)

    _validate_static_dma_routes(cpu, devices, wiring)
    source_constraints, claims, register_claims = _declared_claims(components, wiring)
    annotations, layout_gaps = _layout_annotations(components, wiring)
    layout, policy = _compile_constraints(components, wiring, annotations,
                                          source_constraints)
    mmio, unresolved_windows = _mmio_candidates(wiring, devices)
    marker = request.document.get('f6_execution', {})
    slots = marker.get('shared_slots', {}) if isinstance(marker, Mapping) else {}
    # An explicit read register selects an ordinary APB target separately from
    # any GPIO companion used to produce F5; legacy GPIO selections retain
    # their distinct PADIN read and GPIOEN write behavior.
    selected = (slots.get('component'), slots.get('read_register')) if isinstance(slots, Mapping) and 'read_register' in slots else None
    selected_write = (slots.get('component'), slots.get('register')) if selected is not None else None
    pointers = {function: request.role_pointer(function)
                for function in (FUNCTION_DATA_MASTER, FUNCTION_INSTRUCTION_MASTER)}

    assessments: list[_Assessment] = []
    for flow_id in FLOW_IDS:
        assessment = _Assessment(flow_id)
        if flow_id == 'F1':
            _evaluate_f1(assessment, cpu, wiring, pointers)
        elif flow_id == 'F2':
            _evaluate_f2(assessment, cpu, wiring, mmio, unresolved_windows, pointers, selected)
        elif flow_id == 'F3':
            _evaluate_f3(assessment, cpu, wiring, pointers)
        elif flow_id == 'F4':
            _evaluate_f4(assessment, cpu, wiring, mmio, unresolved_windows, pointers, selected_write)
        elif flow_id == 'F5':
            marker=request.document.get('f6_execution',{})
            declared=marker.get('declared_irq') if isinstance(marker,Mapping) else None
            if declared is not None:
                _evaluate_declared_irq_f5(assessment, request, declared, base_dir=request.base_dir, pointers=pointers)
            else:
                gpio=marker.get('gpio_irq',{}) if isinstance(marker,Mapping) else {}
                selected=gpio.get('component') if isinstance(gpio,Mapping) else None
                _evaluate_f5(assessment, cpu, wiring, devices, pointers,selected_producer=selected)
        else:
            from .f6_execution_contract import F6ContractRefused
            try:
                _evaluate_f6(assessment, cpu, wiring, devices, pointers,
                             request=request)
            except F6ContractRefused as error:
                raise PathCompilationError(error.code, error.pointer,
                                           error.detail) from error
        assessments.append(assessment)

    runtime, omitted = _runtime_declaration(assessments, cpu, wiring, devices)
    graph, contract = runtime if runtime is not None else (None, None)
    identities = _runtime_identities(graph, assessments)

    paths = []
    for assessment in assessments:
        primary = assessment.sources[0]['source_id'] if assessment.sources else None
        path_id = (f'{assessment.flow_id}:{primary}' if primary
                   else f'{assessment.flow_id}:{cpu.instance_id}')
        applicable = [rule for rule in policy.rules if _rule_applies(rule, assessment)]
        paths.append({
            'path_id': path_id,
            'flow_id': assessment.flow_id,
            'flow_name': FLOW_DEFINITIONS[assessment.flow_id]['name'],
            'definition': dict(FLOW_DEFINITIONS[assessment.flow_id]),
            'status': assessment.status,
            'reason': {
                'code': assessment.missing[0]['code'] if assessment.missing else None,
                'pointer': (assessment.missing[0]['pointer']
                            if assessment.missing else None),
                'detail': assessment.missing[0]['detail'] if assessment.missing else None,
                'missing': list(assessment.missing),
            },
            'target': {'component': (
                assessment.windows[0].target_instance
                if assessment.flow_id == 'F4' and assessment.windows else cpu.instance_id),
                'node': assessment.target},
            'direction': assessment.direction,
            'endpoints': list(assessment.endpoints),
            'sources': list(assessment.sources),
            'bound_inputs': list(assessment.bound),
            'constraints': {
                'schema_version': INPUT_CONSTRAINT_SCHEMA,
                'policy_hash': policy.policy_hash,
                'layout_hash': layout.layout_hash if layout is not None else None,
                'rule_ids': [rule.rule_id for rule in applicable],
                'rules': [rule.document() for rule in applicable],
                'register_field_constraints': [
                    row for row in register_claims
                    if row['flow_id'] == assessment.flow_id],
                'source_constraints': [{
                    'source_id': row['source_id'],
                    'origin': row['origin'],
                    'kind': row['kind'],
                    'width': row['width'],
                    'bit_offset': row['bit_offset'],
                    'mask': row['mask'],
                    'alignment': row['alignment'],
                    'range': row['range'],
                    'constraint_basis': row['constraint_basis'],
                    **({'register_access':row['register_access']} if 'register_access' in row else {}),
                } for row in assessment.sources],
            },
            'prerequisites': list(assessment.prerequisites),
            'termination_observation': dict(assessment.termination),
            'seed': assessment.seed,
            'assertions': ([dict(expectation_id=e,
                assertion_class=('protocol_checker' if e.startswith('protocol_checker.') else
                    'cross_component_provenance_and_order' if e.startswith('cross_component.') else 'cpu_ip_behaviour'),
                declared_by='compiled_F6_cpu_dma_contract.v1', asserts=e)
                for e in assessment.execution_contract['expectation_ids']]
                if hasattr(assessment, 'execution_contract') else _assertion_set(assessment.flow_id)),
            'runtime_path_identity': identities.get(assessment.flow_id),
            'not_claimed': ['rtl_operational', 'cross_component_accepted',
                            'coverage_guided_searched', 'bug_confirmed'],
        })

    from .f2_read_contract import build_f2_read_contract
    for row in paths:
        if row['flow_id'] == 'F2' and row['status'] == STATUS_EXECUTABLE:
            row['execution_contract'] = build_f2_read_contract(row)
        if row['flow_id'] == 'F6' and 'f6_execution' in request.document:
            row['execution_contract'] = next(a.execution_contract for a in assessments if a.flow_id == 'F6')

    return {
        'schema_version': COMPILED_PATHS_SCHEMA,
        'identity': {
            'cpu': _component_identity(cpu),
            'devices': [_component_identity(row) for row in devices],
            'wiring': {
                'schema_version': wiring.schema_version,
                'declared_sections': list(wiring.declared_sections),
                'absent_sections': list(wiring.absent_sections),
                **({'dma_master_routes_sha256': wiring.dma_master_routes_sha256,
                    'dma_master_route_bindings_sha256': hashlib.sha256(
                        _canonical(wiring.document['dma_master_route_bindings']))
                        .hexdigest()}
                   if wiring.dma_master_routes else {}),
            },
            'request_sha256': _digest(request.document) if request.document else None,
        },
        'flow_definitions': {flow: dict(FLOW_DEFINITIONS[flow]) for flow in FLOW_IDS},
        'paths': paths,
        'counts': {
            'executable': sum(1 for row in paths
                              if row['status'] == STATUS_EXECUTABLE),
            'unsupported': sum(1 for row in paths
                               if row['status'] == STATUS_UNSUPPORTED),
            'total': len(paths),
        },
        'declared_source_claims': claims,
        'declared_register_field_constraints': register_claims,
        'input_constraints': {
            'schema_version': INPUT_CONSTRAINT_SCHEMA,
            'policy_hash': policy.policy_hash,
            'drive_profile': policy.drive_profile,
            'bus_owner': policy.bus_owner,
            'layout_hash': layout.layout_hash if layout is not None else None,
            'layout': input_layout_document(layout) if layout is not None else None,
            'rules': [rule.document() for rule in policy.rules],
            'closure': [list(row) for row in policy.closure],
            'cycles': [list(row) for row in policy.cycles],
            'dut_owned_inputs': sorted({name for rule in policy.rules
                                        if rule.owner == 'dut'
                                        for name in rule.read_set}),
            'gaps': list(policy.gaps),
        },
        'runtime_dependency_graph': (graph.edge_document() if graph is not None
                                     else None),
        'runtime_path_contract': contract.document() if contract is not None else None,
        'runtime_path_contract_omissions': list(omitted),
        'gaps': [*layout_gaps, *(row[3] for row in unresolved_windows)],
        'not_claimed': [
            'no RTL was compiled, elaborated or run',
            'no harness was generated or built (that is P7-B)',
            'executable means every declared end of every hop exists; it is not '
            'runtime evidence that the hop was observed',
            'P7-D session wiring, graded capability report and fresh replay are out '
            'of scope here',
        ],
    }


def _component_identity(component: PathComponent) -> dict:
    return {
        'instance_id': component.instance_id,
        'component_id': component.component_id,
        'kind': component.profile.kind,
        'profile_fingerprint': component.profile.profile_fingerprint,
        'sidecar_fingerprint': (component.capability.sidecar_fingerprint
                                if component.capability else None),
        'sidecar_schema_version': (component.capability.schema_version
                                   if component.capability else None),
    }


__all__ = [
    'COMPILED_PATHS_SCHEMA', 'FLOW_DEFINITIONS', 'FLOW_IDS', 'ORIGINS',
    'PATH_COMPILE_REQUEST_SCHEMA', 'PATH_STATUSES', 'PATH_WIRING_SCHEMA',
    'PATH_WIRING_SCHEMA_V2',
    'PREREQUISITE_KINDS_USED', 'SOC_RENDER_CONFIG_SCHEMA', 'STATUS_EXECUTABLE',
    'STATUS_UNSUPPORTED', 'TERMINATION_KINDS_USED', 'WIRING_CONTRACT_SCHEMA',
    'WIRING_CONTRACT_SCHEMA_V2',
    'DeclaredSource', 'PathCompilationError', 'PathComponent', 'PathCompileRequest',
    'PathWiring', 'WiringDelivery', 'WiringEnvironmentLink', 'WiringResource',
    'WiringWindow', 'compile_paths', 'isa_contract', 'load_path_compile_request',
    'load_path_wiring',
]
