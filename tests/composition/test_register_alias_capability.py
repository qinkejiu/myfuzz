"""Next-package v3 alias declaration TDD; data-only, no renderer or RTL."""
import copy
import json
import pytest
from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.test_capability import load_ip_test_capability,plan_register_operation,_canonical_value,_document_fingerprint
from myfuzz.composition.ip_test_levels import assess_ip_test_level
from tests.composition.test_pulp_gpio_test_capability import PROFILE,SIDECAR


def documents(*,renamed=False):
    raw_profile=json.loads(PROFILE.read_text())
    document=json.loads(SIDECAR.read_text())
    names={'PADOUT':'DATA','PADOUTSET':'DATA_SET','PADOUTCLR':'DATA_CLEAR'} if renamed else {}
    endpoint='register.bus' if renamed else 'gpio.bus'
    if renamed:
        raw_profile['component_id']='generic_register_device'
        for item in raw_profile['address']['registers']:item['name']=names.get(item['name'],item['name'])
        for item in raw_profile['endpoints']:
            if item['endpoint_id']=='gpio.bus':item['endpoint_id']=endpoint
        for item in document['register_semantics']:item['register']=names.get(item['register'],item['register'])
        for item in document['endpoint_capabilities']:
            if item['endpoint_id']=='gpio.bus':item['endpoint_id']=endpoint
    profile=load_component_profile(raw_profile)
    document.update(schema_version='ip_test_capability.v3',component_id=profile.component_id,
        profile_fingerprint=profile.profile_fingerprint)
    fields={(item['register'],item['field']):item for item in document['register_semantics']}
    destination=names.get('PADOUT','PADOUT')
    document['register_aliases']=[dict(source_register=names.get(register,register),source_field='bits',
        destination_register=destination,destination_field='value',endpoint_id=endpoint,
        operation=operation,bus_width=32,evidence_ref=fields[(names.get(register,register),'bits')]['evidence_ref'])
        for register,operation in [('PADOUTSET','set_bits'),('PADOUTCLR','clear_bits')]]
    return raw_profile,profile,document


def feature_contract(document):
    mapping=document['observation_mappings'][0]
    return dict(provider_id='example.declaration',provider_version='1.0',operations=[dict(
        endpoint_id=mapping['endpoint_id'],operation='state_transition',
        required_observation_mappings=[mapping['mapping_id']],evidence_ref=mapping['evidence_ref'])])


@pytest.mark.parametrize('renamed',[False,True])
def test_v3_loads_source_bound_set_clear_and_complete_actual_field_matrix(renamed):
    _,profile,document=documents(renamed=renamed)
    capability=load_ip_test_capability(document,profile=profile)
    assert len(capability.register_semantics)==72
    assert capability.feature_contract is None
    assert len(capability.register_aliases)==2
    for actual,declared in zip(capability.register_aliases,document['register_aliases']):
        assert {key:getattr(actual,key) for key in declared}==declared
        plan=plan_register_operation(profile,capability,register=actual.source_register,
            field=actual.source_field,operation='register_write',value=0x80000001,allow_side_effect=True)
        assert plan.bus_mask==0xffffffff and plan.bus_value==0x80000001
    assessment=assess_ip_test_level(profile,sidecar=capability)
    assert assessment.effective_level is None and assessment.verified_level is None


@pytest.mark.parametrize('version',['ip_test_capability.v1','ip_test_capability.v2'])
def test_legacy_schema_empty_alias_tuple_preserves_raw_document_and_fingerprint(version):
    profile=load_component_profile(PROFILE);document=json.loads(SIDECAR.read_text())
    document['schema_version']=version
    document.pop('register_aliases',None)
    if version.endswith('.v2'):document['feature_contract']=feature_contract(document)
    first=load_ip_test_capability(document,profile=profile)
    assert first.register_aliases==()
    assert _canonical_value(first.source_document)==document
    assert first.sidecar_fingerprint==_document_fingerprint(document)
    assert first.sidecar_fingerprint==load_ip_test_capability(copy.deepcopy(document),profile=profile).sidecar_fingerprint
    if version.endswith('.v2'):assert first.feature_contract.provider_id=='example.declaration'


def test_v3_can_preserve_strict_existing_feature_contract_without_alias_grants():
    _,profile,document=documents()
    document['feature_contract']=feature_contract(document)
    capability=load_ip_test_capability(document,profile=profile)
    assert capability.feature_contract.provider_id=='example.declaration'
    assert len(capability.register_aliases)==2
    assert assess_ip_test_level(profile,sidecar=capability).verified_level is None


@pytest.mark.parametrize('mutation',['unknown_source','unknown_source_field','unknown_destination',
    'unknown_destination_field','foreign_endpoint','unknown_operation','bool_width','wrong_width',
    'extra_field','empty_evidence','duplicate','conflicting','self_alias','effect_mismatch',
    'partial_source_mask','partial_destination_mask','narrow_source','narrow_destination',
    'unreadable_destination','destination_effect','same_offset','stale_evidence_revision','stale_evidence_sha'])
def test_alias_invalidity_has_alias_specific_error_not_unsupported_schema(mutation):
    raw_profile,profile,document=documents()
    row=document['register_aliases'][0]
    semantics={(field['register'],field['field']):field for field in document['register_semantics']}
    if mutation=='unknown_source':row['source_register']='MISSING'
    elif mutation=='unknown_source_field':row['source_field']='missing'
    elif mutation=='unknown_destination':row['destination_register']='MISSING'
    elif mutation=='unknown_destination_field':row['destination_field']='missing'
    elif mutation=='foreign_endpoint':row['endpoint_id']='gpio.pins'
    elif mutation=='unknown_operation':row['operation']='copy'
    elif mutation=='bool_width':row['bus_width']=True
    elif mutation=='wrong_width':row['bus_width']=16
    elif mutation=='extra_field':row['extra']=True
    elif mutation=='empty_evidence':row['evidence_ref']=''
    elif mutation in ('duplicate','conflicting'):
        other=copy.deepcopy(row)
        if mutation=='conflicting':other['operation']='clear_bits'
        document['register_aliases'].append(other)
    elif mutation=='self_alias':row.update(destination_register='PADOUTSET',destination_field='bits')
    elif mutation=='effect_mismatch':row['operation']='clear_bits'
    elif mutation=='partial_source_mask':semantics[('PADOUTSET','bits')]['write_mask']=255
    elif mutation=='partial_destination_mask':semantics[('PADOUT','value')]['read_mask']=255
    elif mutation=='narrow_source':semantics[('PADOUTSET','bits')].update(width=16,write_mask=65535)
    elif mutation=='narrow_destination':semantics[('PADOUT','value')].update(width=16,read_mask=65535,write_mask=65535)
    elif mutation=='unreadable_destination':
        next(item for item in raw_profile['address']['registers'] if item['name']=='PADOUT')['access']='wo'
        semantics[('PADOUT','value')].update(access='wo',read_mask=0)
    elif mutation=='destination_effect':
        semantics[('PADOUT','value')]['side_effect']='read_clears'
        next(item for item in raw_profile['address']['registers'] if item['name']=='PADOUT')['side_effect']='read_clears'
    elif mutation=='same_offset':
        next(item for item in raw_profile['address']['registers'] if item['name']=='PADOUTSET')['offset']=12
    elif mutation=='stale_evidence_revision':
        row['evidence_ref']=row['evidence_ref'].replace(profile.source.revision.removeprefix('git:'),'0'*40)
    elif mutation=='stale_evidence_sha':row['evidence_ref']=row['evidence_ref'].split(';sha256=')[0]+';sha256='+'0'*64
    profile=load_component_profile(raw_profile)
    document['profile_fingerprint']=profile.profile_fingerprint
    with pytest.raises(ValueError,match='register[-_]alias'):
        load_ip_test_capability(document,profile=profile)


@pytest.mark.parametrize('version',['ip_test_capability.v1','ip_test_capability.v2'])
def test_existing_versions_do_not_admit_new_alias_root_field(version):
    _,profile,document=documents();document['schema_version']=version
    if version.endswith('.v2'):document['feature_contract']=feature_contract(document)
    with pytest.raises(ValueError,match='unknown-test-capability-field:register_aliases'):
        load_ip_test_capability(document,profile=profile)


def test_v3_empty_alias_matrix_is_a_declaration_without_verified_grants():
    _,profile,document=documents();document['register_aliases']=[]
    capability=load_ip_test_capability(document,profile=profile)
    assert capability.register_aliases==() and capability.feature_contract is None
    assert len(capability.register_semantics)==72
    assert assess_ip_test_level(profile,sidecar=capability).verified_level is None


@pytest.mark.parametrize('mutation',['missing_aliases','nonarray_aliases','nonobject_row','missing_row_key'])
def test_alias_collection_and_rows_are_closed(mutation):
    _,profile,document=documents()
    if mutation=='missing_aliases':del document['register_aliases']
    elif mutation=='nonarray_aliases':document['register_aliases']={}
    elif mutation=='nonobject_row':document['register_aliases'][0]=[]
    else:del document['register_aliases'][0]['destination_field']
    with pytest.raises(ValueError,match='register[-_]alias'):
        load_ip_test_capability(document,profile=profile)
