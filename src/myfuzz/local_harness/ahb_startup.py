"""AHB-only startup capture shape and conservative transport bounds.

These are documentary measurements, never a CPU/source authority contract.
"""
from __future__ import annotations
import copy
import json

PAGE_SIZE=32
MAX_BUFFER_BYTES=8*1024*1024
MAX_PAGE_JSON_BYTES=1024*1024


def startup_contract(*,assert_ticks,release_ticks,snapshot_max):
    size=len(json.dumps(snapshot_max,sort_keys=True,separators=(',',':'),allow_nan=False).encode())
    return _bounded_contract(assert_ticks,release_ticks,size)


def _bounded_contract(assert_ticks,release_ticks,size):
    if (type(assert_ticks) is not int or not 1<=assert_ticks<=1024
        or type(release_ticks) is not int or not 0<=release_ticks<=1024):
        raise ValueError('ahb_startup_timing')
    if type(size) is not int or size<2:raise ValueError('ahb_startup_serialized_bound')
    total=assert_ticks+release_ticks
    # Full native pre/post snapshots plus sample tick and reset/index envelope.
    record_bound=2*size+256
    buffer_bound=total*(record_bound+1)+2
    page_bound=PAGE_SIZE*(record_bound+1)+2*size+4096
    receipt_storage_bound=((total+PAGE_SIZE-1)//PAGE_SIZE)*(page_bound+512)
    if buffer_bound>MAX_BUFFER_BYTES or page_bound>MAX_PAGE_JSON_BYTES or receipt_storage_bound>MAX_BUFFER_BYTES:
        raise ValueError('ahb_startup_serialized_bound')
    return dict(schema_version='cpu_ahb_startup_capture.v1',assert_ticks=assert_ticks,
        release_ticks=release_ticks,total_ticks=total,page_size=PAGE_SIZE,
        page_count=(total+PAGE_SIZE-1)//PAGE_SIZE,max_pages=64,
        max_buffer_bytes=MAX_BUFFER_BYTES,buffer_bound_bytes=buffer_bound,
        max_page_json_bytes=MAX_PAGE_JSON_BYTES,page_json_bound_bytes=page_bound,
        record_bound_bytes=record_bound,snapshot_bound_bytes=size,
        receipt_storage_bound_bytes=receipt_storage_bound,
        sampling='actual_reset_release_pre_post',reset_polarity='assertion_high',
        startup_tick_namespace='startup',command_tick_namespace='command',
        retrieval='zero_clock_READ_AHB_STARTUP',
        authority='observation_only',prefix_claim='measured_reset_to_command_prefix')


def validate_startup_contract(contract):
    if not isinstance(contract,dict):raise ValueError('ahb_startup_contract')
    core={key:value for key,value in contract.items() if key!='manager_domain'}
    expected=_bounded_contract(core.get('assert_ticks'),core.get('release_ticks'),
        core.get('snapshot_bound_bytes'))
    if json.dumps(core,sort_keys=True,separators=(',',':'),allow_nan=False)!=json.dumps(expected,sort_keys=True,separators=(',',':'),allow_nan=False):
        raise ValueError('ahb_startup_contract')
    if 'manager_domain' in contract:
        from .ahb_manager_domain import validate_manager_domain_contract
        validate_manager_domain_contract(contract['manager_domain'])
    return copy.deepcopy(expected)


def validate_startup_page(page,contract,*,expected_page):
    names={'schema_version','page_index','page_count','total_ticks','assert_ticks','release_ticks','records'}
    if not isinstance(page,dict) or set(page)!=names or page.get('schema_version')!='cpu_ahb_startup_page.v1':
        raise ValueError('ahb_startup_page_shape')
    for key,expected in [('page_index',expected_page),*[(k,contract[k]) for k in ('page_count','total_ticks','assert_ticks','release_ticks')]]:
        if type(page[key]) is not int or page[key]!=expected:raise ValueError('ahb_startup_page_identity')
    if not 0<=expected_page<contract['page_count']:raise ValueError('ahb_startup_page_range')
    records=page['records'];start=expected_page*PAGE_SIZE
    if not isinstance(records,list) or len(records)!=min(PAGE_SIZE,contract['total_ticks']-start):
        raise ValueError('ahb_startup_page_count')
    for index,record in enumerate(records,start=start+1):
        if not isinstance(record,dict) or set(record)!={'startup_edge_index','reset_pre','reset_post','sample'}:
            raise ValueError('ahb_startup_record_shape')
        reset=int(index<=contract['assert_ticks'])
        for key,value in [('startup_edge_index',index),('reset_pre',reset),('reset_post',reset)]:
            if type(record[key]) is not int or record[key]!=value:raise ValueError('ahb_startup_record_identity')
        sample=record['sample']
        if (not isinstance(sample,dict) or set(sample)!={'local_tick','pre','post'}
            or type(sample['local_tick']) is not int or sample['local_tick']!=index
            or not all(isinstance(sample[p],dict) for p in ('pre','post'))):
            raise ValueError('ahb_startup_record_sample')
    if len(json.dumps(page,sort_keys=True,separators=(',',':'),allow_nan=False).encode())>contract['page_json_bound_bytes']:
        raise ValueError('ahb_startup_page_bound')
    return copy.deepcopy(records)


def render_startup_helpers(contract):
    """Emit only passive capture and zero-clock serialization helpers."""
    text=r'''static std::vector<std::string> ahb_startup_records;
static std::size_t ahb_startup_bytes = 0;
static unsigned ahb_startup_next_page = 0;
static void capture_ahb_startup(Model &dut) {
  const auto reset_pre = static_cast<unsigned>(dut.reset);
  std::vector<std::string> measured;
  tick(dut, &measured);
  const auto reset_post = static_cast<unsigned>(dut.reset);
  const auto index = ahb_startup_records.size() + 1;
  const unsigned expected_reset = index <= @ASSERT@ ? 1 : 0;
  if (measured.size() != 1 || index > @TOTAL@ ||
      reset_pre != expected_reset || reset_post != expected_reset)
    throw std::runtime_error("ahb_startup_capture_shape");
  const auto record = object({{"startup_edge_index", std::to_string(index)},
      {"reset_pre", std::to_string(reset_pre)}, {"reset_post", std::to_string(reset_post)},
      {"sample", measured[0]}});
  if (record.size() > @RECORD_BOUND@ ||
      ahb_startup_bytes + record.size() + 1 > @BUFFER_BOUND@)
    throw std::length_error("ahb_startup_buffer_bound");
  ahb_startup_bytes += record.size() + 1;
  ahb_startup_records.push_back(record);
}
static std::string ahb_startup_page(unsigned page) {
  if (page >= @PAGES@ || ahb_startup_records.size() != @TOTAL@)
    throw std::runtime_error("ahb_startup_page_shape");
  const auto start = page * @PAGE_SIZE@;
  std::vector<std::string> records;
  for (unsigned i = start; i < start + @PAGE_SIZE@ && i < @TOTAL@; ++i)
    records.push_back(ahb_startup_records[i]);
  const auto result = object({{"schema_version", quote("cpu_ahb_startup_page.v1")},
      {"page_index", std::to_string(page)}, {"page_count", "@PAGES@"},
      {"total_ticks", "@TOTAL@"}, {"assert_ticks", "@ASSERT@"},
      {"release_ticks", "@RELEASE@"}, {"records", array(records)}});
  if (result.size() > @PAGE_BOUND@) throw std::length_error("ahb_startup_page_bound");
  return result;
}
'''
    replacements={'ASSERT':contract['assert_ticks'],'RELEASE':contract['release_ticks'],
        'TOTAL':contract['total_ticks'],'PAGES':contract['page_count'],
        'PAGE_SIZE':contract['page_size'],'RECORD_BOUND':contract['record_bound_bytes'],
        'BUFFER_BOUND':contract['buffer_bound_bytes'],'PAGE_BOUND':contract['page_json_bound_bytes']}
    for key,value in replacements.items():text=text.replace('@'+key+'@',str(value))
    return text


def transport_contract_from_document(document):
    """Recompute only the unchanged bounded capture/page transport contract."""
    if document.get('kind')!='ahb_lite_cpu' or document.get('driver_schema_version')!='local_driver_generation.ahb_startup.v2':
        raise ValueError('ahb_startup_driver_version')
    snapshot={'backend':{r['name']:(1<<r['width'])-1 for r in document['backend_ports']},
        'physical':{r['runtime_name']:('f'*r['hex_digits'] if r['width']>64 else (1<<r['width'])-1) for r in document['physical_exports']},
        'protocol_taps':{r['name']:(1<<r['width'])-1 for r in document['protocol_tap_ports']}}
    reset=document['driver_reset']
    expected=startup_contract(assert_ticks=reset['reset_assert_ticks'],
        release_ticks=reset['reset_release_ticks'],snapshot_max=snapshot)
    if json.dumps(document.get('ahb_startup_contract'),sort_keys=True,separators=(',',':'),allow_nan=False)!=json.dumps(expected,sort_keys=True,separators=(',',':'),allow_nan=False):
        raise ValueError('ahb_startup_contract_mismatch')
    return expected


def contract_from_document(document):
    """Transport contract plus the authenticated measured-domain interpretation."""
    from .ahb_manager_domain import authenticate_manager_domain
    transport=transport_contract_from_document(document)
    domain=authenticate_manager_domain(document)
    return {**transport,'manager_domain':domain}


def configure_observer_startup(observer,document):
    from .ahb_manager_domain import OBSERVER_VERSION,SAMPLING_DOMAIN
    combined=contract_from_document(document)
    transport={key:value for key,value in combined.items() if key!='manager_domain'}
    observer.contract.update(observer_version=OBSERVER_VERSION,startup_capture=transport,
        startup_prefix='observer_version_3_measured_manager_ready_and_bus_reset_pre_only',
        sampling_domain=SAMPLING_DOMAIN,
        domain_contract=copy.deepcopy(combined['manager_domain']),
        tick_namespaces={'startup':'original_native_startup_tick','command':'original_native_command_tick',
            'measurement_tick':'startup_total_plus_command_tick'})
    return combined
