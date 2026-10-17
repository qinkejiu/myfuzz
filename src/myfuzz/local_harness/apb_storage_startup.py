"""APB storage startup capture shape and conservative transport bounds.

These are documentary measurements, never a CPU/source authority contract.
"""
from __future__ import annotations
import copy
import json
import re

PAGE_SIZE=32
MAX_BUFFER_BYTES=8*1024*1024
MAX_PAGE_JSON_BYTES=1024*1024
PORT_WIDTHS=dict(storage_value=32,storage_reset=1,storage_paddr=12,storage_psel=1,storage_penable=1,storage_pwrite=1,storage_pwdata=32,storage_prdata=32,storage_pready=1,storage_pslverr=1)


def startup_contract(*,assert_ticks,release_ticks,snapshot_max,source_contract_digest,probe_digest,reset_mapping):
    size=len(json.dumps(snapshot_max,sort_keys=True,separators=(',',':'),allow_nan=False).encode())
    return _bound_identity(_bounded_contract(assert_ticks,release_ticks,size),source_contract_digest,probe_digest,reset_mapping)


def _bound_identity(contract,source_contract_digest,probe_digest,reset_mapping):
    if any(type(v) is not str or re.fullmatch('[0-9a-f]{64}',v) is None for v in (source_contract_digest,probe_digest)):
        raise ValueError('storage_startup_digest')
    expected=dict(runtime_port='reset',assertion_high=True,source_port='HRESETn',source_active_low=True)
    if json.dumps(reset_mapping,sort_keys=True)!=json.dumps(expected,sort_keys=True):raise ValueError('storage_startup_reset_mapping')
    return dict(contract,source_contract_digest=source_contract_digest,probe_digest=probe_digest,reset_mapping=copy.deepcopy(expected))


def _bounded_contract(assert_ticks,release_ticks,size):
    if (type(assert_ticks) is not int or not 1<=assert_ticks<=1024
        or type(release_ticks) is not int or not 0<=release_ticks<=1024):
        raise ValueError('storage_startup_timing')
    if type(size) is not int or size<2:raise ValueError('storage_startup_serialized_bound')
    total=assert_ticks+release_ticks
    # Full native pre/post snapshots plus sample tick and reset/index envelope.
    record_bound=2*size+256
    buffer_bound=total*(record_bound+1)+2
    page_bound=PAGE_SIZE*(record_bound+1)+2*size+4096
    receipt_storage_bound=((total+PAGE_SIZE-1)//PAGE_SIZE)*(page_bound+512)
    if buffer_bound>MAX_BUFFER_BYTES or page_bound>MAX_PAGE_JSON_BYTES or receipt_storage_bound>MAX_BUFFER_BYTES:
        raise ValueError('storage_startup_serialized_bound')
    return dict(schema_version='apb_storage_startup_capture.v1',assert_ticks=assert_ticks,
        release_ticks=release_ticks,total_ticks=total,page_size=PAGE_SIZE,
        page_count=(total+PAGE_SIZE-1)//PAGE_SIZE,max_pages=64,
        max_buffer_bytes=MAX_BUFFER_BYTES,buffer_bound_bytes=buffer_bound,
        max_page_json_bytes=MAX_PAGE_JSON_BYTES,page_json_bound_bytes=page_bound,
        record_bound_bytes=record_bound,snapshot_bound_bytes=size,
        receipt_storage_bound_bytes=receipt_storage_bound,
        sampling='actual_reset_release_pre_post',reset_polarity='assertion_high',
        startup_tick_namespace='startup',command_tick_namespace='command',
        retrieval='zero_clock_READ_APB_STORAGE_STARTUP',
        authority='observation_only',prefix_claim='captured_reset_levels_only_no_command_continuity',
        hierarchy_verified=False,native_verified=False,reset_authority=False,version_authority=False,source_authority=False)


def validate_startup_contract(contract):
    if not isinstance(contract,dict):raise ValueError('storage_startup_contract')
    expected=_bound_identity(_bounded_contract(contract.get('assert_ticks'),contract.get('release_ticks'),
        contract.get('snapshot_bound_bytes')),contract.get('source_contract_digest'),contract.get('probe_digest'),contract.get('reset_mapping'))
    if json.dumps(contract,sort_keys=True,separators=(',',':'),allow_nan=False)!=json.dumps(expected,sort_keys=True,separators=(',',':'),allow_nan=False):
        raise ValueError('storage_startup_contract')
    return copy.deepcopy(expected)


def validate_startup_page(page,contract,*,expected_page,ports):
    contract=validate_startup_contract(contract)
    if (type(expected_page) is not int or not isinstance(ports,list)
        or len(ports)!=len(PORT_WIDTHS) or any(type(r.get('width')) is not int for r in ports)
        or {r['name']:r['width'] for r in ports}!=PORT_WIDTHS):raise ValueError('storage_startup_port_shape')
    names={'schema_version','page_index','page_count','total_ticks','assert_ticks','release_ticks','records'}
    if not isinstance(page,dict) or set(page)!=names or page.get('schema_version')!='apb_storage_startup_page.v1':
        raise ValueError('storage_startup_page_shape')
    for key,expected in [('page_index',expected_page),*[(k,contract[k]) for k in ('page_count','total_ticks','assert_ticks','release_ticks')]]:
        if type(page[key]) is not int or page[key]!=expected:raise ValueError('storage_startup_page_identity')
    if not 0<=expected_page<contract['page_count']:raise ValueError('storage_startup_page_range')
    records=page['records'];start=expected_page*PAGE_SIZE
    if not isinstance(records,list) or len(records)!=min(PAGE_SIZE,contract['total_ticks']-start):
        raise ValueError('storage_startup_page_count')
    for index,record in enumerate(records,start=start+1):
        if not isinstance(record,dict) or set(record)!={'startup_edge_index','reset_pre','reset_post','sample'}:
            raise ValueError('storage_startup_record_shape')
        reset=int(index<=contract['assert_ticks'])
        for key,value in [('startup_edge_index',index),('reset_pre',reset),('reset_post',reset)]:
            if type(record[key]) is not int or record[key]!=value:raise ValueError('storage_startup_record_identity')
        sample=record['sample']
        if (not isinstance(sample,dict) or set(sample)!={'local_tick','pre','post'}
            or type(sample['local_tick']) is not int or sample['local_tick']!=index
            or not all(isinstance(sample[p],dict) for p in ('pre','post'))):
            raise ValueError('storage_startup_record_sample')
        from .apb_storage_probe_contract import validate_storage_probe_sample
        for phase in ('pre','post'):
            values=validate_storage_probe_sample(sample[phase],ports)
            if values.get('storage_reset')!=reset:raise ValueError('storage_startup_actual_reset_mismatch')
    if len(json.dumps(page,sort_keys=True,separators=(',',':'),allow_nan=False).encode())>contract['page_json_bound_bytes']:
        raise ValueError('storage_startup_page_bound')
    return copy.deepcopy(records)


def validate_startup_handoff(last_startup,first_command,*,operation,fields,reset_observed):
    """Pure startup-post to first-command-pre continuity namespace join.

    Persistent source-mapped storage and reset levels must be unchanged. APB
    request roles that a command actually drives must match that command;
    combinational readback/acknowledge roles are deliberately free to change
    and readback is never used as a storage substitute. This function issues
    no token, authority or reset prerequisite.
    """
    if reset_observed is not True:raise ValueError('storage_startup_reset_not_observed')
    names=tuple(PORT_WIDTHS)
    for group in (last_startup,first_command):
        if not isinstance(group,dict) or set(group)!=set(names):raise ValueError('storage_startup_handoff_shape')
        for name in names:
            value=group[name]
            if type(value) is not int or not 0<=value<1<<PORT_WIDTHS[name]:
                raise ValueError('storage_startup_handoff_width')
    if last_startup['storage_reset'] not in (0,1):raise ValueError('storage_startup_handoff_reset')
    if first_command['storage_value']!=last_startup['storage_value']:
        raise ValueError('storage_startup_value_discontinuity')
    if first_command['storage_reset']!=last_startup['storage_reset']:
        raise ValueError('storage_startup_reset_discontinuity')
    if operation=='ACCESS_APB3_REG':
        if (type(fields) is not tuple or len(fields)!=4
            or any(type(value) is not int for value in fields)):
            raise ValueError('storage_startup_handoff_command')
        write,offset,value,be=fields
        if write not in (0,1) or be!=15 or not 0<=offset<1<<12 or offset%4:
            raise ValueError('storage_startup_handoff_command')
        if first_command['storage_psel']!=1:raise ValueError('storage_startup_handoff_drive')
        if first_command['storage_paddr']!=offset:raise ValueError('storage_startup_handoff_address')
        if first_command['storage_pwrite']!=write:raise ValueError('storage_startup_handoff_write')
        if write and first_command['storage_pwdata']!=value:
            raise ValueError('storage_startup_handoff_wdata')
    elif operation=='STEP_APB3_REG':
        if type(fields) is not tuple or fields:raise ValueError('storage_startup_handoff_command')
        if first_command['storage_psel']!=0 or first_command['storage_penable']!=0:
            raise ValueError('storage_startup_handoff_drive')
    else:raise ValueError('storage_startup_handoff_command')
    return dict(namespace='startup_to_command',startup_phase='last_startup_post',
        command_phase='first_command_pre',startup_value=last_startup['storage_value'],
        startup_reset=last_startup['storage_reset'],
        command_value=first_command['storage_value'],
        command_reset=first_command['storage_reset'],operation=operation,
        fields=list(fields),readback_not_storage=True,
        combinational_readback_free=True,storage_reset_persistent=True,
        source_equation_reset_checked=True,grants_reset_prerequisite=False)


def render_startup_helpers(contract):
    """Emit only passive capture and zero-clock serialization helpers."""
    contract=validate_startup_contract(contract)
    text=r'''static std::vector<std::string> storage_startup_records;
static std::size_t storage_startup_bytes = 0;
static unsigned storage_startup_next_page = 0;
static void capture_storage_startup(Model &dut) {
  const auto reset_pre = static_cast<unsigned>(dut.reset);
  std::vector<std::string> measured;
  tick(dut, &measured);
  const auto reset_post = static_cast<unsigned>(dut.reset);
  const auto index = storage_startup_records.size() + 1;
  const unsigned expected_reset = index <= @ASSERT@ ? 1 : 0;
  if (measured.size() != 1 || index > @TOTAL@ ||
      reset_pre != expected_reset || reset_post != expected_reset)
    throw std::runtime_error("storage_startup_capture_shape");
  const auto record = object({{"startup_edge_index", std::to_string(index)},
      {"reset_pre", std::to_string(reset_pre)}, {"reset_post", std::to_string(reset_post)},
      {"sample", measured[0]}});
  if (record.size() > @RECORD_BOUND@ ||
      storage_startup_bytes + record.size() + 1 > @BUFFER_BOUND@)
    throw std::length_error("storage_startup_buffer_bound");
  storage_startup_bytes += record.size() + 1;
  storage_startup_records.push_back(record);
}
static std::string storage_startup_page(unsigned page) {
  if (page >= @PAGES@ || storage_startup_records.size() != @TOTAL@)
    throw std::runtime_error("storage_startup_page_shape");
  const auto start = page * @PAGE_SIZE@;
  std::vector<std::string> records;
  for (unsigned i = start; i < start + @PAGE_SIZE@ && i < @TOTAL@; ++i)
    records.push_back(storage_startup_records[i]);
  const auto result = object({{"schema_version", quote("apb_storage_startup_page.v1")},
      {"page_index", std::to_string(page)}, {"page_count", "@PAGES@"},
      {"total_ticks", "@TOTAL@"}, {"assert_ticks", "@ASSERT@"},
      {"release_ticks", "@RELEASE@"}, {"records", array(records)}});
  if (result.size() > @PAGE_BOUND@) throw std::length_error("storage_startup_page_bound");
  return result;
}
'''
    replacements={'ASSERT':contract['assert_ticks'],'RELEASE':contract['release_ticks'],
        'TOTAL':contract['total_ticks'],'PAGES':contract['page_count'],
        'PAGE_SIZE':contract['page_size'],'RECORD_BOUND':contract['record_bound_bytes'],
        'BUFFER_BOUND':contract['buffer_bound_bytes'],'PAGE_BOUND':contract['page_json_bound_bytes']}
    for key,value in replacements.items():text=text.replace('@'+key+'@',str(value))
    return text



def startup_selection(plan,storage_probe):
    if not hasattr(plan.request,'tuning'):return None
    rows=[r.document() for r in plan.request.tuning.records if r.kind=='apb_storage_startup']
    if not rows:return None
    endpoints=[e for e in plan.binding.endpoints if e.protocol is not None]
    if (len(rows)!=1 or len(endpoints)!=1 or endpoints[0].protocol!=('apb','3')
        or endpoints[0].function!='mmio_slave' or storage_probe is None
        or rows[0]!=storage_probe['selection'] or rows[0]['endpoint_id']!=endpoints[0].endpoint_id
        or any(r.kind in ('startup_writes','environment_bindings','bound_bindings') for r in plan.request.tuning.records)):
        raise ValueError('storage_startup_selection')
    return copy.deepcopy(rows[0])


def contract_for_snapshot(document,snapshot,assert_ticks,release_ticks):
    probe=document['storage_observation']
    if (document.get('kind')!='apb3_register_observe'
        or document.get('storage_startup_selection')!=probe['selection']
        or document.get('dynamic_physical_inputs') or document.get('bound_physical_inputs')):
        raise ValueError('storage_startup_runtime')
    return startup_contract(assert_ticks=assert_ticks,release_ticks=release_ticks,snapshot_max=snapshot,
        source_contract_digest=probe['source_contract']['digest'],probe_digest=probe['digest'],
        reset_mapping=dict(runtime_port='reset',assertion_high=True,source_port='HRESETn',source_active_low=True))


def contract_from_document(document):
    if (document.get('kind')!='apb3_register_observe'
        or document.get('driver_schema_version')!='local_driver_generation.apb_storage_startup.v2'):
        raise ValueError('storage_startup_driver_version')
    snapshot=dict(backend={r['name']:(1<<r['width'])-1 for r in document['backend_ports']},
        physical={r['runtime_name']:('f'*r['hex_digits'] if r['width']>64 else (1<<r['width'])-1) for r in document['physical_exports']},
        storage_probes={r['name']:(1<<r['width'])-1 for r in document['storage_probe_ports']})
    if document.get('protocol_tap_ports'):
        snapshot['protocol_taps']={r['name']:(1<<r['width'])-1 for r in document['protocol_tap_ports']}
    reset=document['driver_reset']
    expected=contract_for_snapshot(document,snapshot,reset['reset_assert_ticks'],reset['reset_release_ticks'])
    if json.dumps(document.get('storage_startup_capture'),sort_keys=True,allow_nan=False)!=json.dumps(expected,sort_keys=True,allow_nan=False):
        raise ValueError('storage_startup_contract_mismatch')
    return expected
