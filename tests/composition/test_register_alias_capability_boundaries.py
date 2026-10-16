"""Independent source-bound v3 declaration checks; no runtime authority/RTL."""
from dataclasses import replace
import pytest
from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.test_capability import load_ip_test_capability, plan_register_operation
from myfuzz.composition.ip_test_levels import assess_ip_test_level
from tests.composition.test_register_alias_capability import documents, feature_contract


@pytest.mark.parametrize('mutation',['wishbone','data16','data64','no_read','no_write'])
def test_alias_declared_bus_requires_actual_supported_profile_bus(mutation):
    raw, _, document = documents()
    endpoint=next(row for row in raw['endpoints'] if row['endpoint_id']=='gpio.bus')
    if mutation=='wishbone':endpoint['protocol']=['wishbone','classic']
    elif mutation.startswith('data'):raw['capabilities']['data_width']=int(mutation[4:])
    elif mutation=='no_read':raw['capabilities']['read']=False
    else:raw['capabilities']['write']=False
    profile=load_component_profile(raw)
    document['profile_fingerprint']=profile.profile_fingerprint
    with pytest.raises(ValueError,match='register[-_]alias'):
        load_ip_test_capability(document,profile=profile)


@pytest.mark.parametrize('entrypoint',['plan','assessment'])
@pytest.mark.parametrize('mutation',['drop_aliases','destination','evidence'])
def test_replaced_typed_aliases_never_keep_original_source_contract(entrypoint,mutation):
    _,profile,document=documents()
    capability=load_ip_test_capability(document,profile=profile)
    aliases=capability.register_aliases
    if mutation=='drop_aliases':aliases=()
    elif mutation=='destination':aliases=(replace(aliases[0],destination_register='PADDIR'),)+aliases[1:]
    else:aliases=(replace(aliases[0],evidence_ref='caller-fabricated'),)+aliases[1:]
    changed=replace(capability,register_aliases=aliases)
    with pytest.raises(ValueError,match='typed-contract-mismatch'):
        if entrypoint=='plan':
            plan_register_operation(profile,changed,register='PADOUTSET',field='bits',
                operation='register_write',value=1,allow_side_effect=True)
        else:assess_ip_test_level(profile,sidecar=changed)


@pytest.mark.parametrize('mutation',['extra','null','invalid_operation'])
def test_v3_optional_feature_contract_keeps_existing_closed_validation(mutation):
    _,profile,document=documents()
    document['feature_contract']=feature_contract(document)
    if mutation=='extra':document['feature_contract']['saved_authority']=True
    elif mutation=='null':document['feature_contract']=None
    else:document['feature_contract']['operations'][0]['operation']='forged_completion'
    with pytest.raises(ValueError):load_ip_test_capability(document,profile=profile)


def test_alias_evidence_cannot_reuse_other_declared_field_evidence():
    _,profile,document=documents()
    other=next(row for row in document['register_semantics'] if row['register']=='PADDIR')
    # Existing source refs may be identical; select an observation ref which
    # still belongs to the same source profile but is a different declaration.
    document['register_aliases'][0]['evidence_ref']=document['observation_mappings'][0]['evidence_ref']
    source=next(row for row in document['register_semantics'] if row['register']=='PADOUTSET')
    if document['register_aliases'][0]['evidence_ref']==source['evidence_ref']:
        pytest.skip('fixture uses a shared evidence reference')
    with pytest.raises(ValueError,match='register-alias-evidence-mismatch'):
        load_ip_test_capability(document,profile=profile)


@pytest.mark.parametrize('entrypoint',['plan','assessment'])
def test_typed_alias_bus_width_float_cannot_compare_equal_to_canonical_int(entrypoint):
    _,profile,document=documents()
    capability=load_ip_test_capability(document,profile=profile)
    aliases=(replace(capability.register_aliases[0],bus_width=32.0),)+capability.register_aliases[1:]
    changed=replace(capability,register_aliases=aliases)
    with pytest.raises(ValueError,match='typed-contract-mismatch'):
        if entrypoint=='plan':
            plan_register_operation(profile,changed,register='PADOUTSET',field='bits',
                operation='register_write',value=1,allow_side_effect=True)
        else:assess_ip_test_level(profile,sidecar=changed)
