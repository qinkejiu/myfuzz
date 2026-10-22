"""Pure source-reviewed descriptor controls, never live storage authority."""
import copy
from dataclasses import replace
import importlib
import json
from pathlib import Path
import subprocess
import pytest
import myfuzz.local_harness  # Initialize import-time producer pins before the no-tool guard.
from myfuzz.composition.component_profile import load_component_profile

ROOT=Path(__file__).resolve().parents[2]
CONTRACT='pulp-apb-timer.ctrl0.source.v1'


def api():
 try:return importlib.import_module('myfuzz.local_harness.apb_storage_source_contract')
 except ModuleNotFoundError:pytest.fail('closed APB storage source contract missing')


@pytest.fixture(autouse=True)
def no_tools(monkeypatch):
 def forbidden(*a,**kw):pytest.fail('source-contract must not invoke tools/frontend/model')
 monkeypatch.setattr(subprocess,'Popen',forbidden)
 monkeypatch.setattr(subprocess,'run',forbidden)


@pytest.fixture
def timer():return load_component_profile(ROOT/'configs/peripherals/pulp_timer/component_profile.json')


def choose(profile,base_dir=ROOT,**selection):
 return api().select_apb_storage_source_contract(profile,base_dir=base_dir,
  selection={'contract_id':CONTRACT,'register':'TIMER0_CTRL',**selection})


def test_actual_pinned_source_has_closed_reviewed_scope(timer):
 m=api();d=choose(timer)
 assert m.registered_apb_storage_source_contracts()==(CONTRACT,SPI_CONTRACT)
 assert d['digest']=='75bf4ddf1bacc6879235cabf980ec7c252dbd9251243895f25f72ebddd1f131f'
 assert d['scope']=='source_reviewed_contract' and d['authority'] is False
 assert all(d[k] is False for k in ('native_verified','hierarchy_verified','reset_authority','version_authority','source_authority'))
 assert d['parameters']=={'APB_ADDR_WIDTH':12,'TIMER_CNT':2}
 assert d['register']=={'name':'TIMER0_CTRL','canonical_offset':4,'width':32,'reset_value':0,'write_mask':0xffffffff,'read_mask':0xffffffff}
 assert d['storage_expression']['status']=='prospective_not_codegen_or_native_verified'
 assert d['storage_expression']['expression']=='u_component.u_dut.TIMER_GEN[0].timer_i.regs_q[1]'
 assert len(d['source']['files'])==2 and d['source']['top_module']=='apb_timer'
 assert d['writers']['complete_for_registered_source'] is True
 assert d['writers']['autonomous_ctrl_writers']==[]
 assert m.validate_apb_storage_source_contract(d,timer,base_dir=ROOT)==d
 assert m.validate_apb_storage_source_contract(json.loads(json.dumps(d)),timer,base_dir=ROOT)==d


def test_alias_decode_counts_every_physical_address_not_only_host_word(timer):
 m=api();d=choose(timer)
 assert d['decode']['mask']==0x1c and d['decode']['value']==4
 assert d['decode']['alias_period_bytes']==32 and d['decode']['host_alignment_bytes']==4
 assert d['decode']['ignored_address_bits']==[0,1,5,6,7,8,9,10,11]
 actual=[a for a in range(4096) if m.apb_storage_address_matches(d,a)]
 assert actual==[a for a in range(4096) if (a>>2)&7==1]
 assert len(actual)==512
 assert all(m.apb_storage_address_matches(d,a) for a in (4,5,6,7,0x24,0xfe7))
 assert not any(m.apb_storage_address_matches(d,a) for a in (0,8,0x14,0xfff))
 for bad in (True,-1,4096,'4'):
  with pytest.raises(ValueError):m.apb_storage_address_matches(d,bad)


def test_source_identity_not_component_name(timer):
 assert choose(replace(timer,component_id='renamed_real_source'))==choose(timer)
 gpio=load_component_profile(ROOT/'configs/peripherals/pulp_gpio/component_profile.json')
 with pytest.raises(ValueError):choose(gpio)
 with pytest.raises(ValueError):choose(replace(gpio,component_id='pulp_timer'))


@pytest.mark.parametrize('selection',[
 {'contract_id':'unregistered'}, {'register':'TIMER0_COUNT'}, {'register':'TIMER1_CTRL'},
 {'expression':'PWDATA'}, {'source_hashes':{}}, {'evidence_ref':'trust me'}, {'width':32},
])
def test_caller_can_only_select_registered_contract_and_register(timer,selection):
 with pytest.raises(ValueError):choose(timer,**selection)


@pytest.mark.parametrize('change',[
 {'revision':'git:'+'0'*40},{'top_module':'timer'},{'files':('src/timer.sv',)},
 {'include_roots':('unreviewed',)},{'filelist':'extra.f'},
])
def test_unknown_source_closure_or_identity_rejected(timer,change):
 with pytest.raises(ValueError):choose(replace(timer,source=replace(timer.source,**change)))


@pytest.mark.parametrize('params',[(('APB_ADDR_WIDTH','13'),('TIMER_CNT','2')),
 (('APB_ADDR_WIDTH','12'),('TIMER_CNT','1')),(('APB_ADDR_WIDTH','12'),('TIMER_CNT','2'),('EXTRA','0'))])
def test_other_elaboration_parameters_rejected(timer,params):
 settings=replace(timer.source.elaboration,parameters=params)
 with pytest.raises(ValueError):choose(replace(timer,source=replace(timer.source,elaboration=settings)))


@pytest.mark.parametrize('mutate',[
 lambda d:d.update(authority=True),lambda d:d['register'].update(reset_value=False),
 lambda d:d['register'].update(width=16),lambda d:d['decode'].update(value=True),
 lambda d:d['decode'].update(mask=0xfff),lambda d:d['storage_expression'].update(expression='PWDATA'),
 lambda d:d['writers'].update(autonomous_ctrl_writers=['new clock writer']),
 lambda d:d.update(hierarchy_verified=True),lambda d:d.update(extra='caller evidence'),
])
def test_serialized_or_mutated_documents_cannot_redefine_contract(timer,mutate):
 m=api();d=choose(timer);mutate(d)
 with pytest.raises(ValueError):m.validate_apb_storage_source_contract(d,timer,base_dir=ROOT)
 with pytest.raises(ValueError):m.apb_storage_address_matches(d,4)


@pytest.mark.parametrize('relative,old,new',[
 ('src/timer.sv','regs_n[`REG_TIMER_CTRL] = PWDATA;','regs_n[`REG_TIMER_CTRL] = PWDATA ^ 1;'),
 ('src/timer.sv',"regs_q          <= '{default: 32'b0};","regs_q          <= '{default: 32'b1};"),
 ('src/timer.sv','PRDATA = regs_q[`REG_TIMER_CTRL];','PRDATA = PWDATA;'),
 ('src/timer.sv','register_adr = PADDR[`REGS_MAX_IDX + 2:2]','register_adr = PADDR[3:1]'),
 ('src/apb_timer.sv','.PADDR      ( PADDR        )','.PADDR      ( PWDATA[11:0] )'),
])
def test_actual_byte_changes_to_any_writer_reset_decode_or_read_rejected(timer,tmp_path,relative,old,new):
 for name in timer.source.files:
  p=tmp_path/timer.source.source_root/name;p.parent.mkdir(parents=True,exist_ok=True)
  p.write_bytes((ROOT/timer.source.source_root/name).read_bytes())
 p=tmp_path/timer.source.source_root/relative;text=p.read_text();assert old in text;p.write_text(text.replace(old,new))
 with pytest.raises(ValueError):choose(timer,base_dir=tmp_path)


def test_symlink_source_and_missing_source_refused(timer,tmp_path):
 target=tmp_path/timer.source.source_root;target.parent.mkdir(parents=True)
 target.symlink_to(ROOT/timer.source.source_root,target_is_directory=True)
 with pytest.raises(ValueError):choose(timer,base_dir=tmp_path)
 with pytest.raises(ValueError):choose(timer,base_dir=tmp_path/'missing')


def test_descriptor_does_not_reuse_caller_mutable_metadata(timer):
 d=choose(timer);d['writers']['autonomous_ctrl_writers'].append('fake')
 assert choose(timer)['writers']['autonomous_ctrl_writers']==[]


@pytest.mark.parametrize('change',[
 {'offset':8},{'width':16},{'access':'ro'},{'reset_value':1},{'reset_value':False},
 {'writable_bits':1},{'side_effect':'read_clears'},
])
def test_same_source_with_false_register_declaration_refused(timer,change):
 rows=tuple(replace(r,**change) if r.name=='TIMER0_CTRL' else r for r in timer.address.registers)
 with pytest.raises(ValueError):choose(replace(timer,address=replace(timer.address,registers=rows)))


@pytest.mark.parametrize('which,change',[
 ('clock',{'port':'fake_clk'}),('reset',{'port':'fake_reset'}),
 ('reset',{'polarity':'active_high'}),('reset',{'synchronous':True}),
 ('reset',{'synchronous':0}),
])
def test_same_source_with_false_clock_reset_binding_refused(timer,which,change):
 if which=='clock':profile=replace(timer,clocks=(replace(timer.clocks[0],**change),))
 else:profile=replace(timer,resets=(replace(timer.resets[0],**change),))
 with pytest.raises(ValueError):choose(profile)


def test_nonsemantic_domain_names_do_not_select_contract(timer):
 assert choose(replace(timer,clocks=(replace(timer.clocks[0],domain='renamed',frequency_hz=25000000),),resets=(replace(timer.resets[0],domain='renamed_reset'),)))==choose(timer)


@pytest.mark.parametrize('key,value',[('address_width',16),('data_width',16),('address_width',True)])
def test_same_source_with_false_declared_bus_width_refused(timer,key,value):
 with pytest.raises(ValueError):choose(replace(timer,capabilities={**timer.capabilities,key:value}))


def test_validation_rereads_actual_bytes_after_selection(timer,tmp_path):
 for name in timer.source.files:
  p=tmp_path/timer.source.source_root/name;p.parent.mkdir(parents=True,exist_ok=True)
  p.write_bytes((ROOT/timer.source.source_root/name).read_bytes())
 d=choose(timer,base_dir=tmp_path)
 p=tmp_path/timer.source.source_root/'src/timer.sv';p.write_bytes(p.read_bytes()+b'\n// new source identity\n')
 with pytest.raises(ValueError):api().validate_apb_storage_source_contract(d,timer,base_dir=tmp_path)


SPI_CONTRACT='pulp-apb-spi.spicmd.source.v1'
SPI_SOURCES={
 'soc-pulp-apb-spi/apb_spi_master.sv':'dfc82b0f3c91ba44d986288e1884b1eede0aad6ed8c5b09179a629344d547d0e',
 'soc-pulp-apb-spi/spi_master_apb_if.sv':'a9a32da6cc07768cab293c48989599e36b2000bb572191667960aa1423fc790a',
 'soc-pulp-axi-spi/spi_master_clkgen.sv':'dbfc81a8afe1c05a4372cf7e46f1217f6b57d56c8927bf25ee5f427761b15332',
 'soc-pulp-axi-spi/spi_master_controller.sv':'0ba0d90e99949939b3815ed2e69a9f95b980114ec554baca14083ab54496db76',
 'soc-pulp-axi-spi/spi_master_fifo.sv':'226f53f2e78a82eb9859149a505c287daa8cfd54f55c51b6c1cfa2cd90a38555',
 'soc-pulp-axi-spi/spi_master_rx.sv':'1290e4beaa7d4b588da9cf84da47b39923010bcfdb355641509ee90295d8ca5f',
 'soc-pulp-axi-spi/spi_master_tx.sv':'ee9a7d305bc7bb574ece02dbd6dc8a3f0403729d336bd7431689da47a08558f6',
}


@pytest.fixture
def spi():return load_component_profile(ROOT/'configs/peripherals/pulp_spi/component_profile.json')


def choose_spi(profile,base_dir=ROOT,**selection):
 return choose(profile,base_dir,contract_id=SPI_CONTRACT,register='SPICMD',**selection)


def copy_spi_sources(spi,tmp_path):
 for name in spi.source.files:
  p=tmp_path/spi.source.source_root/name;p.parent.mkdir(parents=True,exist_ok=True)
  p.write_bytes((ROOT/spi.source.source_root/name).read_bytes())


def test_spi_exact_source_contract_is_documentary_and_roundtrips(spi):
 import hashlib
 m=api();d=choose_spi(spi)
 assert d['contract_id']==SPI_CONTRACT and d['scope']=='source_reviewed_contract'
 assert all(d[k] is False for k in ('authority','source_authority','native_verified','hierarchy_verified','reset_authority','version_authority'))
 assert d['source']['root']=='third_party'
 assert d['source']['revision']=='sha256:c653811843b453f0689a8f6942934ff9d551734aa4bc4e197d8b9acbfb020230'
 assert d['source']['top_module']=='apb_spi_master' and d['source']['files']==SPI_SOURCES
 assert {n:hashlib.sha256((ROOT/'third_party'/n).read_bytes()).hexdigest() for n in SPI_SOURCES}==SPI_SOURCES
 assert d['parameters']=={'APB_ADDR_WIDTH':12,'BUFFER_DEPTH':10}
 assert d['register']==dict(name='SPICMD',canonical_offset=8,width=32,reset_value=0,write_mask=0xffffffff,read_mask=0xffffffff)
 assert d['clock']==dict(port='HCLK',edge='posedge')
 assert d['reset']==dict(port='HRESETn',polarity='active_low',synchronous=False,event='negedge HRESETn or asserted at posedge HCLK')
 assert d['storage_expression']['expression']=='u_component.u_dut.u_axiregs.spi_cmd'
 assert d['storage_expression']['status']=='prospective_not_codegen_or_native_verified'
 assert d['writers']['complete_for_registered_source'] is True
 assert d['writers']['autonomous_ctrl_writers']==[]
 assert m.validate_apb_storage_source_contract(json.loads(json.dumps(d)),spi,base_dir=ROOT)==d
 assert choose_spi(replace(spi,component_id='unrelated_source_name'))==d
 d['writers']['autonomous_ctrl_writers'].append('caller writer')
 assert choose_spi(spi)['writers']['autonomous_ctrl_writers']==[]


def test_spi_raw_and_aligned_alias_geometry(spi):
 m=api();d=choose_spi(spi)
 assert d['decode']['mask']==0x3c and d['decode']['value']==8
 assert d['decode']['address_width']==12 and d['decode']['alias_period_bytes']==64
 assert d['decode']['raw_address_alias_count']==256 and d['decode']['aligned_word_alias_count']==64
 assert d['decode']['ignored_address_bits']==[0,1,6,7,8,9,10,11]
 actual=[a for a in range(4096) if m.apb_storage_address_matches(d,a)]
 assert actual==[a for a in range(4096) if (a>>2)&15==2]
 assert len(actual)==256 and len([a for a in actual if a%4==0])==64
 assert all(m.apb_storage_address_matches(d,a) for a in (8,9,10,11,0x48,0xfcb))
 assert not any(m.apb_storage_address_matches(d,a) for a in (0,4,12,0x28,0xfff))
 for bad in (True,-1,4096,'8'):
  with pytest.raises(ValueError):m.apb_storage_address_matches(d,bad)


def test_contracts_refuse_cross_pairing_in_selection_and_validation(timer,spi):
 with pytest.raises(ValueError):choose(spi)
 with pytest.raises(ValueError):choose_spi(timer)
 with pytest.raises(ValueError):api().validate_apb_storage_source_contract(choose(timer),spi,base_dir=ROOT)
 with pytest.raises(ValueError):api().validate_apb_storage_source_contract(choose_spi(spi),timer,base_dir=ROOT)


@pytest.mark.parametrize('selection',[
 {'contract_id':'unknown','register':'SPICMD'},
 {'contract_id':SPI_CONTRACT,'register':'SPIADR'},
 {'contract_id':SPI_CONTRACT,'register':'TIMER0_CTRL'},
 {'contract_id':CONTRACT,'register':'SPICMD'},
 {'contract_id':SPI_CONTRACT,'register':'SPICMD','evidence_ref':'caller authority'},
])
def test_spi_unknown_selection_refused(spi,selection):
 with pytest.raises(ValueError):api().select_apb_storage_source_contract(spi,base_dir=ROOT,selection=selection)


@pytest.mark.parametrize('change',[
 {'source_root':'third_party/soc-pulp-apb-spi'},{'revision':'sha256:'+'0'*64},
 {'top_module':'spi_master_apb_if'},{'files':tuple(SPI_SOURCES)[:-1]},
 {'files':tuple(reversed(SPI_SOURCES))},{'include_roots':('extra',)},
 {'filelist':'extra.f'},{'filelist_variables':(('ROOT','extra'),)},
])
def test_spi_source_identity_drift_refused(spi,change):
 choose_spi(spi)
 with pytest.raises(ValueError):choose_spi(replace(spi,source=replace(spi.source,**change)))


@pytest.mark.parametrize('change',[
 {'parameters':(('APB_ADDR_WIDTH','13'),('BUFFER_DEPTH','10'))},
 {'parameters':(('APB_ADDR_WIDTH','12'),('BUFFER_DEPTH','11'))},
 {'parameters':(('APB_ADDR_WIDTH','12'),('BUFFER_DEPTH','10'),('EXTRA','0'))},
 {'frontend':'other'},{'defines':(('EXTRA','1'),)},{'warning_policy':'fatal'},
])
def test_spi_elaboration_drift_refused(spi,change):
 choose_spi(spi)
 with pytest.raises(ValueError):
  settings=replace(spi.source.elaboration,**change)
  choose_spi(replace(spi,source=replace(spi.source,elaboration=settings)))


@pytest.mark.parametrize('which,change',[
 ('clock',{'port':'fake_clk'}),('reset',{'port':'fake_reset'}),
 ('reset',{'polarity':'active_high'}),('reset',{'synchronous':True}),
 ('reset',{'synchronous':0}),('reset',{'sequence_after':('other',)}),
])
def test_spi_clock_reset_drift_refused(spi,which,change):
 choose_spi(spi)
 if which=='clock':profile=replace(spi,clocks=(replace(spi.clocks[0],**change),))
 else:profile=replace(spi,resets=(replace(spi.resets[0],**change),))
 with pytest.raises(ValueError):choose_spi(profile)


@pytest.mark.parametrize('change',[
 {'function':'mmio_master'},{'protocol':('apb','4')},{'fields':()},
 {'clock':'wrong_clk'},{'reset':'wrong_reset'},
])
def test_spi_apb_endpoint_drift_refused(spi,change):
 choose_spi(spi)
 endpoints=tuple(replace(e,**change) if e.protocol is not None else e for e in spi.endpoints)
 with pytest.raises(ValueError):choose_spi(replace(spi,endpoints=endpoints))


def test_spi_apb_field_binding_drift_refused(spi):
 choose_spi(spi)
 bus=spi.endpoints[0]
 fields=tuple(replace(f,aliases=('PWDATA',)) if f.role=='paddr' else f for f in bus.fields)
 with pytest.raises(ValueError):choose_spi(replace(spi,endpoints=(replace(bus,fields=fields),*spi.endpoints[1:])))


@pytest.mark.parametrize('change',[{'window_size':8192},{'alignment':2048},{'window_size':True}])
def test_spi_address_window_drift_refused(spi,change):
 choose_spi(spi)
 with pytest.raises(ValueError):choose_spi(replace(spi,address=replace(spi.address,**change)))


@pytest.mark.parametrize('change',[
 {'offset':4},{'offset':False},{'width':16},{'access':'ro'},{'side_effect':'write_starts_transfer'},
 {'reset_value':1},{'reset_value':False},{'writable_bits':1},{'clears_register':'STATUS'},
])
def test_spi_register_fact_drift_refused(spi,change):
 choose_spi(spi)
 rows=tuple(replace(r,**change) if r.name=='SPICMD' else r for r in spi.address.registers)
 with pytest.raises(ValueError):choose_spi(replace(spi,address=replace(spi.address,registers=rows)))


@pytest.mark.parametrize('mutate',[
 lambda d:d.update(authority=True),lambda d:d['register'].update(reset_value=False),
 lambda d:d['decode'].update(mask=0x1c),lambda d:d['decode'].update(value=4),
 lambda d:d['storage_expression'].update(expression='u_component.u_dut.spi_cmd'),
 lambda d:d['source']['files'].update({'extra.sv':'0'*64}),lambda d:d.update(digest='0'*64),
])
def test_spi_document_tampering_refused(spi,mutate):
 d=choose_spi(spi);mutate(d)
 with pytest.raises(ValueError):api().validate_apb_storage_source_contract(d,spi,base_dir=ROOT)
 with pytest.raises(ValueError):api().apb_storage_address_matches(d,8)


@pytest.mark.parametrize('relative',tuple(SPI_SOURCES))
def test_spi_every_closure_byte_is_rechecked(spi,tmp_path,relative):
 copy_spi_sources(spi,tmp_path);d=choose_spi(spi,base_dir=tmp_path)
 path=tmp_path/spi.source.source_root/relative;path.write_bytes(path.read_bytes()+b'\n// byte drift\n')
 with pytest.raises(ValueError,match='reviewed-source-bytes-changed'):choose_spi(spi,base_dir=tmp_path)
 with pytest.raises(ValueError,match='reviewed-source-bytes-changed'):api().validate_apb_storage_source_contract(d,spi,base_dir=tmp_path)


@pytest.mark.parametrize('relative',tuple(SPI_SOURCES))
def test_spi_each_source_symlink_refused(spi,tmp_path,relative):
 copy_spi_sources(spi,tmp_path);choose_spi(spi,base_dir=tmp_path)
 path=tmp_path/spi.source.source_root/relative;path.unlink();path.symlink_to(ROOT/spi.source.source_root/relative)
 with pytest.raises(ValueError,match='source-symlink'):choose_spi(spi,base_dir=tmp_path)


def test_spi_source_directory_symlink_and_missing_files_refused(spi,tmp_path):
 choose_spi(spi)
 target=tmp_path/'third_party';target.symlink_to(ROOT/'third_party',target_is_directory=True)
 with pytest.raises(ValueError,match='source-symlink'):choose_spi(spi,base_dir=tmp_path)
 with pytest.raises(ValueError,match='source-unavailable'):choose_spi(spi,base_dir=tmp_path/'missing')
