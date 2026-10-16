"""Actual profile/sidecar declaration geometry; never live authority."""
import pytest
from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.test_capability import load_ip_test_capability
from tests.composition.test_register_alias_capability import documents


@pytest.mark.parametrize('mutation',['source_unaligned','destination_unaligned','source_cross_window',
    'destination_cross_window','source_ro','source_partial_writable','field_spills',
    'field_overlap','alias_cycle','alias_sources_same_address'])
def test_alias_declaration_geometry_and_access_are_closed(mutation):
    raw,_,document=documents()
    registers={r['name']:r for r in raw['address']['registers']}
    fields={(r['register'],r['field']):r for r in document['register_semantics']}
    if mutation=='source_unaligned':registers['PADOUTSET']['offset']=17
    elif mutation=='destination_unaligned':registers['PADOUT']['offset']=13
    elif mutation=='source_cross_window':registers['PADOUTSET']['offset']=raw['address']['window_size']
    elif mutation=='destination_cross_window':registers['PADOUT']['offset']=raw['address']['window_size']
    elif mutation=='source_ro':registers['PADOUTSET']['access']='ro'
    elif mutation=='source_partial_writable':registers['PADOUTSET']['writable_bits']=255
    elif mutation=='field_spills':fields[('PADOUTSET','bits')]['lsb']=1
    elif mutation=='field_overlap':
        document['register_semantics'].append(dict(fields[('PADOUTSET','bits')],field='overlap'))
    elif mutation=='alias_cycle':
        document['register_aliases'][0].update(destination_register='PADOUTCLR',destination_field='bits')
        document['register_aliases'][1].update(destination_register='PADOUTSET',destination_field='bits')
    else:registers['PADOUTCLR']['offset']=registers['PADOUTSET']['offset']
    with pytest.raises(ValueError):
        profile=load_component_profile(raw)
        document['profile_fingerprint']=profile.profile_fingerprint
        load_ip_test_capability(document,profile=profile)
