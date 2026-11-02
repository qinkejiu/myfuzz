"""Source-backed registration of ZipDMA's selected Wishbone smoke session.

This is an independent process backend, not a generated runtime artifact or an
F6 admission. CPU sessions connect through the normal router and shared RAM.
"""
import json
import hashlib
from copy import deepcopy
from pathlib import Path

from myfuzz.composition.component_profile import ComponentProfile
from myfuzz.scenario.memory_service import MemoryService
from .zipdma_smoke import ZipDmaScenarioSession, zipdma_behavior

_CONTROL = {'cyc': ('i_swb_cyc', 'input', 1), 'stb': ('i_swb_stb', 'input', 1),
            'we': ('i_swb_we', 'input', 1), 'adr': ('i_swb_addr', 'input', 2),
            'dat_w': ('i_swb_data', 'input', 32), 'sel': ('i_swb_sel', 'input', 4),
            'stall': ('o_swb_stall', 'output', 1), 'ack': ('o_swb_ack', 'output', 1),
            'dat_r': ('o_swb_data', 'output', 32)}
_MASTER = {'cyc': ('o_mwb_cyc', 'output', 1), 'stb': ('o_mwb_stb', 'output', 1),
           'we': ('o_mwb_we', 'output', 1), 'adr': ('o_mwb_addr', 'output', 30),
           'dat_w': ('o_mwb_data', 'output', 32), 'sel': ('o_mwb_sel', 'output', 4),
           'stall': ('i_mwb_stall', 'input', 1), 'ack': ('i_mwb_ack', 'input', 1),
           'dat_r': ('i_mwb_data', 'input', 32), 'err': ('i_mwb_err', 'input', 1)}


class SelectedWishboneDmaScenarioSession(ZipDmaScenarioSession):
    """Runner-facing selected Wishbone backend with real bridge observations.

    Its source contract identifies this concrete backend; it does not issue a
    generated runtime artifact or grant F6 authority.
    """
    def __init__(self, binary, memory_service, *, component_profile, source_contract,
                 source_component='dma'):
        super().__init__(binary, memory_service, source_component=source_component)
        self.component_profile = component_profile
        self.source_contract = deepcopy(source_contract)
        self.runtime_events = []

    def _step(self, **kwargs):
        start = len(self._bridge.events)
        sample = super()._step(**kwargs)
        for event in self._bridge.events[start:]:
            self.runtime_events.append({'kind': 'wishbone_dma_master_accepted',
                'local_tick': self.local_ticks, 'source_component': self.source_component,
                'reset_epoch': self.reset_epoch, **event})
        return sample

    def identity_document(self):
        return {**super().identity_document(), 'source_contract': deepcopy(self.source_contract)}

    def lifecycle_receipt(self):
        if self.driver is None:
            return {'status': 'not_started', 'returncode': None, 'reaped': False}
        process = self.driver.process
        code = process.poll()
        return {**self.execution_identity(), 'status': 'exited' if code is not None else 'running',
                'returncode': code, 'reaped': code is not None}


def verify_zipdma_profile(profile, *, base_dir):
    if not isinstance(profile, ComponentProfile) or profile.component_id != 'zipdma_selected_wishbone' or profile.kind != 'peripheral':
        raise ValueError('ZipDMA component profile required')
    root = Path(base_dir)
    manifest = json.loads((root / 'configs/peripherals/zipdma_smoke/profile.json').read_text())
    behavior = zipdma_behavior(manifest, root / 'third_party/soc-zipcpu')
    source = profile.source_document
    parameters = {p['name']: p['value'] for p in source.get('elaboration', {}).get('parameters', [])}
    expected_parameters = {name: str(value) for name, value in manifest['parameters'].items()}
    if (source.get('root') != 'third_party/soc-zipcpu' or source.get('top_module') != manifest['top']
            or source.get('revision') != 'git:' + manifest['source_revision']
            or source.get('files') != list(manifest['sources']) or source.get('include_roots') != []
            or parameters != expected_parameters or source.get('elaboration', {}).get('defines')):
        raise ValueError('ZipDMA profile source or parameters mismatch')
    endpoints = {ep.endpoint_id: ep for ep in profile.endpoints}
    if set(endpoints) != {'dma.control', 'dma.memory', 'dma.interrupt'}:
        raise ValueError('ZipDMA endpoint set mismatch')
    for name, function, shape in (('dma.control', 'mmio_slave', _CONTROL),
                                  ('dma.memory', 'memory_master', _MASTER)):
        endpoint = endpoints[name]
        fields = {f.role: (f.aliases[0] if len(f.aliases) == 1 else None, f.direction, f.width)
                  for f in endpoint.fields}
        if endpoint.function != function or endpoint.protocol != ('wishbone', 'pipelined') or fields != shape:
            raise ValueError('ZipDMA endpoint mapping mismatch')
    irq = endpoints['dma.interrupt']
    irq_fields = [(f.role, f.aliases, f.direction, f.width) for f in irq.fields]
    if irq.function != 'interrupt_source' or irq_fields != [('irq', ('o_interrupt',), 'output', 1)]:
        raise ValueError('ZipDMA IRQ endpoint mismatch')
    expected_caps = {'address_width': 2, 'data_width': 32, 'address_units': 'word',
                     'master_address_width': 30, 'master_address_units': 'word',
                     'byte_enable': True, 'master_byte_enable': True,
                     'local_runtime_variant': 'wishbone_dma_selected_edge_v1'}
    if any(profile.capabilities.get(k) != v for k, v in expected_caps.items()):
        raise ValueError('ZipDMA capability mismatch')
    expected_registers = [(0, 32, 'rw', 'start_or_clear_irq'), (4, 32, 'rw', 'byte_address'),
                          (8, 32, 'rw', 'byte_address'), (12, 32, 'rw', 'byte_count')]
    address = profile.address
    if (address is None or address.window_size != 16 or address.alignment != 16
            or [(r.offset, r.width, r.access, r.side_effect) for r in address.registers] != expected_registers):
        raise ValueError('ZipDMA register map mismatch')
    triggers = [p for p in profile.port_actions if p.port == 'i_dev_ints']
    if len(triggers) != 1 or triggers[0].action != 'constant' or triggers[0].value != 0:
        raise ValueError('ZipDMA trigger input mismatch')
    return {'schema_version': 'zipdma_selected_profile_contract.v1',
            'profile_fingerprint': profile.profile_fingerprint,
            'lock_sha256': hashlib.sha256((root / 'configs/soc/sources.lock.json').read_bytes()).hexdigest(),
            'source_revision': manifest['source_revision'], 'sources': dict(manifest['sources']),
            'behavior': behavior, 'control_select': 'i_swb_sel', 'master_select': 'o_mwb_sel',
            'irq_clear': 'idle and SEL[3] and (data[29] or not data[30])',
            'scope': 'source-backed independent session; no generated runtime or F6 admission'}


def create_zipdma_session(profile, *, binary, memory_service, base_dir, source_component='dma'):
    if not isinstance(memory_service, MemoryService):
        raise ValueError('shared MemoryService required')
    contract = verify_zipdma_profile(profile, base_dir=base_dir)
    return SelectedWishboneDmaScenarioSession(binary, memory_service, component_profile=profile,
        source_contract=contract, source_component=source_component)
