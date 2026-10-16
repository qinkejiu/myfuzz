"""Code-owned prospective storage wiring; never a live evidence issuer."""
import hashlib
import json
from .apb_storage_source_contract import select_apb_storage_source_contract


def storage_probe_selection(plan):
    rows = [r.document() for r in plan.request.tuning.records
            if r.kind == 'apb_storage_observations']
    if not rows:
        return None
    endpoints = [e for e in plan.binding.endpoints if e.protocol is not None]
    if (len(rows) != 1 or len(endpoints) != 1
            or endpoints[0].protocol != ('apb', '3')
            or endpoints[0].function != 'mmio_slave'
            or rows[0]['endpoint_id'] != endpoints[0].endpoint_id):
        raise ValueError('storage-probe-endpoint-unsupported')
    return rows[0]


def generate_storage_probe(plan, wires, *, base_dir):
    selection = storage_probe_selection(plan)
    if selection is None:
        return None
    source = select_apb_storage_source_contract(plan.profile, base_dir=base_dir,
        selection={k: selection[k] for k in ('contract_id', 'register')})
    expressions = [('value', 32, source['storage_expression']['expression']),
                   ('reset', 1, 'reset')]
    widths = dict(paddr=12, psel=1, penable=1, pwrite=1, pwdata=32,
                  prdata=32, pready=1, pslverr=1)
    if set(wires) != set(widths):
        raise ValueError('storage-probe-APB-shape')
    expressions += [(role, width, wires[role]) for role, width in widths.items()]
    ports = [dict(name='storage_'+role, direction='output', width=width,
                  role=role, expression=expression) for role, width, expression in expressions]
    doc = dict(schema_version='apb_storage_probe.v1', scope='generated_expression_source_mapped',
        selection=selection, source_contract=source, sample_group='storage_probes',
        ports=ports, hierarchy_verified=False, native_verified=False,
        reset_authority=False, version_authority=False, source_authority=False)
    doc['digest'] = hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()).hexdigest()
    return doc


def validate_storage_probe_sample(sample, ports):
    """Validate shape only: a dict cannot establish measured hardware origin."""
    group = sample.get('storage_probes')
    if not isinstance(group, dict) or set(group) != {r['name'] for r in ports}:
        raise ValueError('storage-probe-sample-shape')
    for row in ports:
        value = group[row['name']]
        if type(value) is not int or not 0 <= value < 1 << row['width']:
            raise ValueError('storage-probe-sample-width')
    return dict(group)
