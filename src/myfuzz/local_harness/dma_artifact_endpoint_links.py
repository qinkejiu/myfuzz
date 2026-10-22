"""Detached generation evidence for one registered physical DMA master.

These documents certify generated assignments only. They grant no live Runner,
request, target, or replay status. Parsing validates a detached declaration;
validation against an actual artifact is a separate, mandatory admission step.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from .renderer import _sha
from .runtime_artifact import LocalRuntimeArtifact
from .template_contracts import select_template_contract, generated_executor_selection, list_template_contracts
from .wishbone_dma_fields import DMA_MASTER_SHAPE, dma_edge_contract
from .wishbone_dma_template import dma_edge_policy

PROVIDER_ID = 'wishbone-dma-single-master.v1'
_PROVIDER_CONTRACT = {
    'provider_id': PROVIDER_ID, 'provider_version': '1',
    'kind': 'wishbone_dma', 'function': 'memory_master', 'protocol_side': 'master',
    'backend_channel': 'mwb', 'template_id': 'master.wishbone-pipelined',
    'template_version': '1', 'variant_id': 'dma-full-word-no-select',
    'roles': {role: list(shape) for role, shape in sorted(DMA_MASTER_SHAPE.items())},
    'dma_edge_contract': dma_edge_contract(),
}
_ROLE_KEYS = {'role', 'direction', 'width', 'physical_port', 'member_path',
              'raw_lo', 'raw_hi', 'port_width', 'backend_port'}
_BINDING_KEYS = {'profile_endpoint_sha256', 'template_id', 'template_version',
                 'variant_id', 'contract_sha256', 'selection_sha256'}
_LINK_KEYS = {'link_id', 'endpoint_id', 'function', 'protocol_side',
              'backend_channel', 'template_binding', 'roles'}
_DOCUMENT_KEYS = {'schema_version', 'provider_id', 'provider_version',
                  'provider_contract_sha256', 'runtime_artifact_sha256',
                  'runtime_sv_sha256', 'cpp_sha256', 'links', 'identity_sha256'}


class DmaArtifactEndpointLinkError(ValueError):
    def __init__(self, code, pointer, detail):
        self.code, self.pointer = code, pointer
        super().__init__(f'{code} at {pointer}: {detail}')


def _refuse(pointer, detail, code='dma-binding-endpoint-link-mismatch'):
    raise DmaArtifactEndpointLinkError(code, pointer, detail)


def _closed(value, keys, pointer):
    if type(value) is not dict or set(value) != keys:
        _refuse(pointer, 'closed object keys required')


def _text(value, pointer):
    if type(value) is not str or not value or value != value.strip():
        _refuse(pointer, 'nonempty canonical text required')


def _digest(value, pointer):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        _refuse(pointer, 'lowercase SHA256 required')


def _canonical(document):
    return json.dumps(document, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


@dataclass(frozen=True)
class DmaArtifactEndpointLinks:
    _canonical_document: bytes

    def document(self):
        return json.loads(self._canonical_document)

    @property
    def identity_sha256(self):
        return self.document()['identity_sha256']


def _master_selection(plan, master):
    capabilities = dict(plan.profile.capabilities)
    capabilities.update(address_width=capabilities['master_address_width'],
                        has_error=capabilities['master_has_error'],
                        address_units=capabilities['master_address_units'])
    return select_template_contract(master, capabilities,
        template_id='master.wishbone-pipelined', template_version='1',
        variant_id='dma-full-word-no-select')


def parse_dma_artifact_endpoint_links(document, *, pointer='/endpoint_links'):
    """Strict detached parsing; hashes are declarations until artifact admission."""
    _closed(document, _DOCUMENT_KEYS, pointer)
    if (document['provider_id'] != PROVIDER_ID or document['provider_version'] != '1'
            or document['provider_contract_sha256'] != _sha(_PROVIDER_CONTRACT)):
        _refuse(pointer + '/provider_id', 'unregistered issuer contract',
                'dma-binding-provider-unsupported')
    if document['schema_version'] != 'dma_artifact_endpoint_links.v1':
        _refuse(pointer + '/schema_version', 'unsupported schema')
    for key in ('provider_contract_sha256', 'runtime_artifact_sha256',
                'runtime_sv_sha256', 'cpp_sha256', 'identity_sha256'):
        _digest(document[key], pointer + '/' + key)
    links = document['links']
    # This issuer admits exactly one actual master channel.
    if type(links) is not list or len(links) != 1:
        _refuse(pointer + '/links', 'single master link required')
    for index, link in enumerate(links):
        at = pointer + '/links/' + str(index)
        _closed(link, _LINK_KEYS, at)
        _text(link['endpoint_id'], at + '/endpoint_id')
        if (link['link_id'] != 'mwb' or link['function'] != 'memory_master'
                or link['protocol_side'] != 'master' or link['backend_channel'] != 'mwb'):
            _refuse(at, 'registered master/channel required')
        binding = link['template_binding']
        _closed(binding, _BINDING_KEYS, at + '/template_binding')
        for key in _BINDING_KEYS:
            if key.endswith('sha256'):
                _digest(binding[key], at + '/template_binding/' + key)
            elif binding[key] != _PROVIDER_CONTRACT[key]:
                _refuse(at + '/template_binding/' + key, 'registered template required',
                        'dma-binding-template-mismatch')
        # Resolve the registered contract itself, rather than trusting a label/hash.
        contract, = [c for c in list_template_contracts() if (c.template_id, c.template_version, c.variant_id) ==
                     (binding['template_id'], binding['template_version'], binding['variant_id'])]
        if binding['contract_sha256'] != contract.identity_sha256:
            _refuse(at + '/template_binding/contract_sha256', 'contract digest mismatch',
                    'dma-binding-template-mismatch')
        roles = link['roles']
        if type(roles) is not list or len(roles) != len(DMA_MASTER_SHAPE):
            _refuse(at + '/roles', 'complete role map required')
        for position, (row, role) in enumerate(zip(roles, sorted(DMA_MASTER_SHAPE))):
            rp = at + '/roles/' + str(position)
            _closed(row, _ROLE_KEYS, rp)
            direction, width = DMA_MASTER_SHAPE[role]
            if (row['role'] != role or row['direction'] != direction
                    or type(row['width']) is not int or row['width'] != width
                    or row['backend_port'] != 'mwb_' + role):
                _refuse(rp, 'sorted complete registered backend roles required')
            _text(row['physical_port'], rp + '/physical_port')
            if type(row['member_path']) is not list:
                _refuse(rp + '/member_path', 'array required')
            for member in row['member_path']:
                _text(member, rp + '/member_path')
            for key in ('raw_lo', 'raw_hi', 'port_width'):
                if type(row[key]) is not int or row[key] < 0:
                    _refuse(rp + '/' + key, 'nonnegative integer required')
            if (row['raw_hi'] - row['raw_lo'] + 1 != width
                    or row['raw_hi'] >= (row['port_width'] or width)):
                _refuse(rp, 'invalid physical span')
    if document['identity_sha256'] != _sha({k:v for k,v in document.items() if k != 'identity_sha256'}):
        _refuse(pointer + '/identity_sha256', 'digest mismatch')
    return DmaArtifactEndpointLinks(_canonical(document))


def _artifact_link(artifact, *, pointer='/endpoint_links'):
    """Recompute all admitted facts from the artifact's real plan and ABI."""
    from .runtime_renderer import _shape
    document = artifact.runtime_document
    at = pointer
    if (document.get('kind') != 'wishbone_dma' or document.get('status') != 'driver_generated'
            or document.get('driver_status') != 'generated' or not artifact.cpp_text):
        _refuse(at, 'final generated DMA artifact required', 'dma-binding-artifact-mismatch')
    if (document.get('structural_abi') != artifact.structural.abi_document
            or document.get('structural_build') != artifact.structural.build_document
            or document.get('plan') != artifact.plan.document()
            or document.get('source_verification') != artifact.source_verification
            or document.get('dma_edge_contract') != dma_edge_contract()
            or document.get('artifact_digest') != _sha({k:v for k,v in document.items() if k != 'artifact_digest'})):
        _refuse(at, 'artifact metadata mismatch', 'dma-binding-artifact-mismatch')
    for key, text in (('runtime_sv_sha256', artifact.runtime_sv), ('cpp_sha256', artifact.cpp_text)):
        if document.get(key) != hashlib.sha256(text.encode()).hexdigest():
            _refuse(at + '/' + key, 'generated text hash mismatch', 'dma-binding-artifact-mismatch')
    plan = artifact.plan
    abi = artifact.structural.abi_document['ports']
    try:
        _, master, _, contracts = dma_edge_policy(plan, abi)
        wires = _shape(master, DMA_MASTER_SHAPE, abi)
        selection = _master_selection(plan, master)
    except ValueError as error:
        _refuse(at, str(error), 'dma-binding-template-mismatch')
    executor = document.get('selected_template', {}).get('executor', {})
    sources = executor.get('binding', {}).get('implementation_sources', [])
    expected_executor = generated_executor_selection(document,
        [e for e in plan.binding.endpoints if e.protocol is not None], plan.profile.capabilities,
        protocol_templates=contracts, implementation_sources=sources)
    if executor != expected_executor:
        _refuse(at, 'generated executor selection mismatch', 'dma-binding-template-mismatch')
    roles = []
    backend = document.get('backend_ports', [])
    if len([p for p in backend if p.get('channel') == 'mwb']) != len(DMA_MASTER_SHAPE):
        _refuse(at, 'unexpected backend master map')
    for field in sorted(master.fields, key=lambda field: field.role):
        name = 'mwb_' + field.role
        expected = dict(name=name, direction=field.direction, width=field.width,
                        role=field.role, channel='mwb')
        if [p for p in backend if p.get('name') == name] != [expected]:
            _refuse(at, 'backend assignment mismatch')
        assignment = (f'assign {name} = {wires[field.role]};' if field.direction == 'output'
                      else f'assign {wires[field.role]} = {name};')
        if artifact.runtime_sv.count(assignment) != 1:
            _refuse(at, 'generated master assignment mismatch')
        roles.append(dict(role=field.role, direction=field.direction, width=field.width,
            physical_port=field.port, member_path=list(field.member_path), raw_lo=field.raw_lo,
            raw_hi=field.raw_hi, port_width=field.port_width, backend_port=name))
    binding = dict(profile_endpoint_sha256=_sha({
        'profile_fingerprint': plan.profile.profile_fingerprint, 'endpoint_id': master.endpoint_id}),
        template_id=selection.contract.template_id, template_version=selection.contract.template_version,
        variant_id=selection.contract.variant_id, contract_sha256=selection.contract.identity_sha256,
        selection_sha256=selection.identity_sha256)
    return dict(link_id='mwb', endpoint_id=master.endpoint_id, function=master.function,
                protocol_side='master', backend_channel='mwb', template_binding=binding, roles=roles)


def validate_dma_artifact_endpoint_links(document, artifact, *, pointer='/endpoint_links'):
    """Revalidate detached evidence against the supplied actual generated artifact."""
    parsed = parse_dma_artifact_endpoint_links(document, pointer=pointer)
    if not isinstance(artifact, LocalRuntimeArtifact):
        _refuse(pointer, 'runtime artifact required', 'dma-binding-artifact-mismatch')
    try:
        expected_link = _artifact_link(artifact, pointer=pointer)
    except (AttributeError, KeyError, TypeError) as error:
        _refuse(pointer, 'unsupported artifact shape: ' + str(error),
                'dma-binding-artifact-mismatch')
    actual = parsed.document()
    if (actual['runtime_artifact_sha256'] != _sha(artifact.runtime_document)
            or any(actual[key] != artifact.runtime_document[key]
                   for key in ('runtime_sv_sha256', 'cpp_sha256'))
            or actual['links'] != [expected_link]):
        _refuse(pointer, 'artifact/link mismatch', 'dma-binding-artifact-mismatch')
    return parsed


@dataclass(frozen=True, slots=True)
class DmaLinkedRuntimeArtifact:
    artifact: LocalRuntimeArtifact
    _endpoint_links: DmaArtifactEndpointLinks

    def endpoint_links_document(self):
        return self._endpoint_links.document()

    def document(self):
        # Revalidate mutable inner artifact state before exporting detached bytes.
        links = self.endpoint_links_document()
        validate_dma_artifact_endpoint_links(links, self.artifact)
        document = dict(schema_version='dma_linked_runtime_artifact.v1',
                        runtime_artifact=json.loads(_canonical(self.artifact.runtime_document)),
                        endpoint_links=links)
        return {**document, 'identity_sha256': _sha(document)}


def render_dma_linked_runtime(plan, structural, source_verification, *, base_dir, provider_id):
    """Opt in during generation; finalize only after ordinary driver rendering."""
    from .runtime_renderer import render_local_runtime
    from .driver_renderer import render_local_driver
    if provider_id != PROVIDER_ID:
        _refuse('/endpoint_links/provider_id', 'unregistered issuer', 'dma-binding-provider-unsupported')
    facts = []
    top = render_local_runtime(plan, structural, source_verification, base_dir=base_dir,
                               _endpoint_link_collector=facts)
    artifact = render_local_driver(top, base_dir=base_dir)
    link = _artifact_link(artifact)
    expected = [dict(endpoint_id=link['endpoint_id'], function=link['function'],
                     backend_channel=link['backend_channel'], **row) for row in link['roles']]
    if sorted(facts, key=lambda row: row['role']) != expected:
        _refuse('/endpoint_links/links', 'generation assignment facts required')
    document = dict(schema_version='dma_artifact_endpoint_links.v1',
        provider_id=PROVIDER_ID, provider_version='1', provider_contract_sha256=_sha(_PROVIDER_CONTRACT),
        runtime_artifact_sha256=_sha(artifact.runtime_document),
        runtime_sv_sha256=hashlib.sha256(artifact.runtime_sv.encode()).hexdigest(),
        cpp_sha256=hashlib.sha256(artifact.cpp_text.encode()).hexdigest(), links=[link])
    document['identity_sha256'] = _sha(document)
    parsed = validate_dma_artifact_endpoint_links(document, artifact)
    return DmaLinkedRuntimeArtifact(artifact, parsed)
