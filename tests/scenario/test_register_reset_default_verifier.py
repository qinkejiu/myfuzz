"""Pure current-source rules and actual-object refusal; no native positive proof."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from myfuzz.scenario.genome import ScenarioGenome
from myfuzz.scenario.session_runtime import ScenarioSession
from tests.composition.test_pulp_gpio_test_capability import loaded,ROOT
from tests.local_harness.test_ordinary_apb_access_receipts import native_factory
from tests.scenario.test_native_reset_evidence import configured_runner
from tests.scenario.test_register_program_replay import adapter

READBACK_SCOPE='observed_source_bound_reset_default_readback'
REFUSAL_SCOPE='source_bound_reset_default_refusal_only'
GRANTS=('grants_storage','grants_version_dependency','grants_prerequisites','grants_functional')
RESULT_ADDRESS=0x10004


def test_current_source_inten_rule_is_exact_and_detached():
    from myfuzz.scenario.register_reset_default_verifier import derive_inten_reset_rule
    profile,capability=loaded()
    rule=derive_inten_reset_rule(profile,capability,base_dir=ROOT)
    assert rule['offset']==24 and rule['reset_value']==0 and rule['width']==32
    assert rule['address_decode_mask']==124 and rule['alias_period']==128
    assert rule['grants_functional'] is False
    assert rule['source_sha256']=='1e271914da4d25c87acd12121dde60a6ed955033870fd7a6730b2c9bafcbcaef'
    rule['known_unrelated_offsets'].clear()
    assert derive_inten_reset_rule(profile,capability,base_dir=ROOT)['known_unrelated_offsets']


# Task3c expectation change (explicit, not a weakening): offset 12 (PADOUT) is
# now the reviewed `readback_independent_write` class instead of the generic
# `unrelated_write`; it is still a non-read write classification, and offset 28
# (INTTYPE_LOW) keeps the `unrelated_write` outcome pinned.  The refused alias
# (152 -> INTEN), equal-value write to INTEN (24) and reserved offset (124) rows
# are unchanged.
@pytest.mark.parametrize('offset,classification',[(24,'affecting_write'),(152,'affecting_write'),
    (12,'readback_independent_write'),(28,'unrelated_write'),(124,'unknown_offset')])
def test_total_command_rule_does_not_ignore_equal_zero_or_address_alias(offset,classification):
    from myfuzz.scenario.register_reset_default_verifier import derive_inten_reset_rule,classify_inten_command
    p,c=loaded();rule=derive_inten_reset_rule(p,c,base_dir=ROOT)
    assert classify_inten_command(dict(status='parsed_complete',operation='ACCESS_GPIO',fields=[0,1,offset,0,15]),rule=rule)==classification
    assert classify_inten_command(dict(status='pending',operation='ACCESS_GPIO',fields=[0,1,offset,0,15]),rule=rule)=='incomplete'


def test_wrong_sidecar_reset_cannot_supply_a_rule():
    from myfuzz.scenario.register_reset_default_verifier import derive_inten_reset_rule
    p,c=loaded();rows=tuple(replace(r,reset_value=1) if r.register=='INTEN' else r for r in c.register_semantics)
    with pytest.raises(ValueError):derive_inten_reset_rule(p,replace(c,register_semantics=rows),base_dir=ROOT)


def test_actual_runtime_without_task2_is_refused_before_consumer_registration(native_factory,tmp_path):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    from myfuzz.scenario.genome import ScenarioGenome
    from myfuzz.scenario.session_runtime import ScenarioSession
    from tests.scenario.test_register_program_replay import adapter
    runner=configured_runner(native_factory,tmp_path)
    session=ScenarioSession(ScenarioGenome('directed','CPU_TO_IP','register_program',('cpu','gpio_a','gpio_b'),144,()),runner)
    session.declare_instruction_slots('cpu',0x11000,32)
    runtime=adapter(session);authority=runner._memory_commit_authority;before=set(authority._consumers)
    with pytest.raises(ValueError):RegisterResetDefaultVerifier(runtime)
    assert authority._consumers==before and runner._register_reset_default_verifier is None


def installed(native_factory,tmp_path,*,ordinary=False):
    from myfuzz.scenario.genome import ScenarioGenome
    from myfuzz.scenario.session_runtime import ScenarioSession
    from tests.scenario.test_register_program_replay import adapter
    runner=configured_runner(native_factory,tmp_path)
    session=ScenarioSession(ScenarioGenome('directed','CPU_TO_IP','register_program',('cpu','gpio_a','gpio_b'),144,()),runner)
    session.declare_instruction_slots('cpu',0x11000,32)
    if ordinary:session.configure_ordinary_apb_access_evidence(max_records=4)
    runner.install_native_reset_evidence(max_commands=32)
    return adapter(session)


def test_mechanical_provider_has_no_reset_default_certificate(native_factory,tmp_path):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier,validate_register_reset_default_session_document
    runtime=installed(native_factory,tmp_path);verifier=RegisterResetDefaultVerifier(runtime,max_records=4)
    assert 'register_reset_default_verifier' in runtime.runner._memory_commit_authority._consumers
    target=runtime.runner.sessions['gpio_a']
    target.begin_case('mechanical')
    try:
        state=verifier.report()
        assert state['current_certificates']==state['historical_certificates']==[]
        assert state['gaps'][0]['reason']=='missing_native_reset_default_readback'
        document=verifier.session_document()
        detached=validate_register_reset_default_session_document(document,configuration=runtime.configuration())
        detached['state']['gaps'].clear()
        assert verifier.report()['gaps']
    finally:target.end_case()


def test_standalone_reset_is_permanent_gap_not_a_default_certificate(native_factory,tmp_path):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path);verifier=RegisterResetDefaultVerifier(runtime)
    target=runtime.runner.sessions['gpio_a'];target.begin_case('mechanical')
    try:
        verifier.report();target.reset_local()
        state=verifier.report()
        assert state['current_certificates']==state['historical_certificates']==[]
        assert state['gaps'][0]['reason']=='incomplete_reset_evidence'
        assert runtime.runner._native_reset_evidence._status=='incomplete'
        with pytest.raises(ValueError):verifier._preflight_command()
    finally:target.end_case()


def test_rule_rejects_changed_actual_rtl_bytes(tmp_path):
    from myfuzz.scenario.register_reset_default_verifier import derive_inten_reset_rule
    from tests.composition.test_pulp_gpio_test_capability import SOURCE
    p,c=loaded();path=tmp_path/SOURCE.relative_to(ROOT);path.parent.mkdir(parents=True);path.write_bytes(SOURCE.read_bytes()+b'\n')
    with pytest.raises(ValueError,match='source-drift'):derive_inten_reset_rule(p,c,base_dir=tmp_path)


@pytest.mark.parametrize('operation,fields,classification',[
    ('STEP_GPIO',[0],'stable_field_no_internal_writer'),('RESET_GPIO',[],'unknown_command'),
    ('ACCESS_GPIO',[0,False,24,0,15],'unknown_command'),('ACCESS_GPIO',[0,0,24,0,15],'read')])
def test_command_classification_is_total_and_strict(operation,fields,classification):
    from myfuzz.scenario.register_reset_default_verifier import derive_inten_reset_rule,classify_inten_command
    p,c=loaded();rule=derive_inten_reset_rule(p,c,base_dir=ROOT)
    assert classify_inten_command(dict(status='parsed_complete',operation=operation,fields=fields),rule=rule)==classification


@pytest.mark.parametrize('fields',[[],[True],[0,1],[1<<32]])
def test_unparsed_step_arguments_are_not_stable_field_permission(fields):
    from myfuzz.scenario.register_reset_default_verifier import derive_inten_reset_rule,classify_inten_command
    p,c=loaded();rule=derive_inten_reset_rule(p,c,base_dir=ROOT)
    assert classify_inten_command(dict(status='parsed_complete',operation='STEP_GPIO',fields=fields),rule=rule)=='unknown_command'


def test_report_document_is_closed_and_cannot_restore_certificates(native_factory,tmp_path):
    from copy import deepcopy
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier,validate_register_reset_default_session_document
    runtime=installed(native_factory,tmp_path);verifier=RegisterResetDefaultVerifier(runtime)
    document=verifier.session_document()
    for mutate in (lambda d:d['configuration'].update(authority=True),lambda d:d['state']['gaps'][0].update(authority=True),lambda d:d['state']['current_certificates'].append({'status':'verified'})):
        changed=deepcopy(document);mutate(changed)
        with pytest.raises(ValueError):validate_register_reset_default_session_document(changed,configuration=runtime.configuration())


def test_foreign_authority_is_rejected_without_registration(native_factory,tmp_path,monkeypatch):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    from myfuzz.scenario.memory_commit_authority import MemoryCommitAuthority
    runtime=installed(native_factory,tmp_path);runner=runtime.runner
    foreign=MemoryCommitAuthority(services={'cpu':runner.sessions['cpu'].service})
    monkeypatch.setattr(runner,'_memory_commit_authority',foreign)
    with pytest.raises(ValueError):RegisterResetDefaultVerifier(runtime)
    assert foreign._consumers=={'default'} and runner._register_reset_default_verifier is None


def test_duplicate_consumer_installation_does_not_change_shared_authority(native_factory,tmp_path):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path);verifier=RegisterResetDefaultVerifier(runtime)
    consumers=set(runtime.runner._memory_commit_authority._consumers)
    with pytest.raises(ValueError):RegisterResetDefaultVerifier(runtime)
    assert runtime.runner._register_reset_default_verifier is verifier
    assert runtime.runner._memory_commit_authority._consumers==consumers


@pytest.mark.parametrize('reference',[
    'rtl:foreign/path.sv@f82caeb7f7d89427f05e9af5ed31e0675efe0d83:217,325-328,590-598,138;sha256=1e271914da4d25c87acd12121dde60a6ed955033870fd7a6730b2c9bafcbcaef',
    'rtl:third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv@f82caeb7f7d89427f05e9af5ed31e0675efe0d83:1;sha256=1e271914da4d25c87acd12121dde60a6ed955033870fd7a6730b2c9bafcbcaef'])
def test_rehashed_sidecar_wrong_evidence_path_or_lines_is_not_source_rule(reference):
    import json
    from myfuzz.composition.test_capability import load_ip_test_capability
    from myfuzz.scenario.register_reset_default_verifier import derive_inten_reset_rule
    from tests.composition.test_pulp_gpio_test_capability import SIDECAR
    p,_=loaded();document=json.loads(SIDECAR.read_text())
    row=next(r for r in document['register_semantics'] if r['register']=='INTEN');row['evidence_ref']=reference
    capability=load_ip_test_capability(document,profile=p)
    with pytest.raises(ValueError):derive_inten_reset_rule(p,capability,base_dir=ROOT)


def test_access_gpio_input_must_fit_actual_producer_uint32():
    from myfuzz.scenario.register_reset_default_verifier import derive_inten_reset_rule,classify_inten_command
    p,c=loaded();rule=derive_inten_reset_rule(p,c,base_dir=ROOT)
    assert classify_inten_command(dict(status='parsed_complete',operation='ACCESS_GPIO',fields=[1<<32,0,24,0,15]),rule=rule)=='unknown_command'


@pytest.mark.parametrize('method_name',['report','_validate','__init__'])
def test_preinstall_task3_methods_are_not_learned_as_startup_authority(native_factory,tmp_path,monkeypatch,method_name):
    from types import MappingProxyType
    from myfuzz.scenario import register_reset_default_verifier as module
    runtime=installed(native_factory,tmp_path);authority=runtime.runner._memory_commit_authority
    before=set(authority._consumers);original=getattr(module.RegisterResetDefaultVerifier,method_name)
    def replacement(*args,**kwargs):return original(*args,**kwargs)
    with pytest.raises(ValueError):monkeypatch.setattr(module.RegisterResetDefaultVerifier,method_name,replacement)
    assert getattr(module.RegisterResetDefaultVerifier,method_name) is original
    assert authority._consumers==before and runtime.runner._register_reset_default_verifier is None


def test_preinstall_commit_hook_drift_cannot_register_a_recipient(native_factory,tmp_path,monkeypatch):
    from myfuzz.scenario import register_reset_default_verifier as module
    runtime=installed(native_factory,tmp_path);authority=runtime.runner._memory_commit_authority;before=set(authority._consumers)
    original=module.RegisterResetDefaultVerifier._consume_actual_commit
    with pytest.raises(ValueError):monkeypatch.setattr(module.RegisterResetDefaultVerifier,'_consume_actual_commit',lambda *args:None)
    assert module.RegisterResetDefaultVerifier._consume_actual_commit is original
    assert authority._consumers==before and runtime.runner._register_reset_default_verifier is None


def test_missing_actual_authority_is_not_created_by_task3(native_factory,tmp_path,monkeypatch):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path);before=set(runtime.runner._memory_commit_authority._consumers)
    authority=runtime.runner._memory_commit_authority
    monkeypatch.setattr(runtime.runner,'_memory_commit_authority',None)
    with pytest.raises(ValueError):RegisterResetDefaultVerifier(runtime)
    assert runtime.runner._memory_commit_authority is None
    assert authority._consumers==before and runtime.runner._register_reset_default_verifier is None


def test_task3_must_precede_existing_register_verifier(native_factory,tmp_path):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    runtime=installed(native_factory,tmp_path)
    runtime.session.configure_ordinary_apb_access_evidence(max_records=4)
    previous=RegisterProgramVerifier(runtime);authority=runtime.runner._memory_commit_authority;before=set(authority._consumers)
    with pytest.raises(ValueError):RegisterResetDefaultVerifier(runtime)
    assert runtime.runner._register_program_verifier is previous
    assert authority._consumers==before and runtime.runner._register_reset_default_verifier is None


@pytest.mark.parametrize('changes',[{'reset_value':1},{'read_mask':0xfffffffe},{'write_mask':0xfffffffe},{'side_effect':'write_one_sets'}])
def test_rehashed_field_metadata_cannot_replace_current_source_rule(changes):
    import json
    from myfuzz.composition.test_capability import load_ip_test_capability
    from myfuzz.scenario.register_reset_default_verifier import derive_inten_reset_rule
    from tests.composition.test_pulp_gpio_test_capability import SIDECAR
    p,_=loaded();document=json.loads(SIDECAR.read_text());row=next(r for r in document['register_semantics'] if r['register']=='INTEN');row.update(changes)
    with pytest.raises(ValueError):derive_inten_reset_rule(p,load_ip_test_capability(document,profile=p),base_dir=ROOT)


def test_source_constants_cannot_authorize_changed_rtl(tmp_path,monkeypatch):
    import hashlib
    from myfuzz.scenario import register_reset_default_verifier as module
    from tests.composition.test_pulp_gpio_test_capability import SOURCE
    p,c=loaded();path=tmp_path/SOURCE.relative_to(ROOT);path.parent.mkdir(parents=True);path.write_bytes(SOURCE.read_bytes()+b'\n')
    changed=hashlib.sha256(path.read_bytes()).hexdigest()
    monkeypatch.setattr(module,'_SOURCE_SHA',changed)
    monkeypatch.setattr(module,'_EVIDENCE_REF',next(r.evidence_ref for r in c.register_semantics if r.register=='INTEN'))
    with pytest.raises(ValueError):module.derive_inten_reset_rule(p,c,base_dir=tmp_path)


def test_replaced_pure_document_validator_cannot_return_certificates(native_factory,tmp_path,monkeypatch):
    from myfuzz.scenario import register_reset_default_verifier as module
    runtime=installed(native_factory,tmp_path);verifier=module.RegisterResetDefaultVerifier(runtime)
    monkeypatch.setattr(module,'validate_register_reset_default_session_document',lambda *args,**kwargs:{'certificates':[{'verified':True}]})
    with pytest.raises(ValueError):verifier.session_document()


@pytest.mark.parametrize('change',['rule','sources','no_gaps'])
def test_rehashed_comparison_document_requires_actual_rules_sources_and_refusal(native_factory,tmp_path,change):
    from copy import deepcopy
    from myfuzz.scenario import register_reset_default_verifier as module
    runtime=installed(native_factory,tmp_path);verifier=module.RegisterResetDefaultVerifier(runtime)
    document=verifier.session_document();configuration=deepcopy(document['configuration'])
    if change=='rule':configuration['rules']['gpio_a']['reset_value']=1
    elif change=='sources':configuration['source_files']={'foreign.py':'0'*64}
    else:document['state']['gaps']=[]
    document['configuration']=configuration;document['state']['configuration']=deepcopy(configuration)
    with pytest.raises(ValueError):module.validate_register_reset_default_session_document(document,configuration=runtime.configuration())


@pytest.mark.parametrize('helper',['load_ip_test_capability','_revalidate_ip_test_capability'])
def test_preinstall_rule_loaders_cannot_be_replaced(native_factory,tmp_path,monkeypatch,helper):
    from myfuzz.scenario import register_reset_default_verifier as module
    runtime=installed(native_factory,tmp_path);authority=runtime.runner._memory_commit_authority;before=set(authority._consumers)
    original=getattr(module,helper)
    monkeypatch.setattr(module,helper,lambda *args,**kwargs:original(*args,**kwargs))
    with pytest.raises(ValueError):module.RegisterResetDefaultVerifier(runtime)
    assert authority._consumers==before and runtime.runner._register_reset_default_verifier is None


@pytest.mark.parametrize('already_installed',[False,True])
def test_memory_resolver_drift_is_refused_without_issuance(native_factory,tmp_path,monkeypatch,already_installed):
    from myfuzz.scenario import register_reset_default_verifier as module
    from myfuzz.scenario.memory_authority_distribution import MemoryAuthorityDistribution
    runtime=installed(native_factory,tmp_path);authority=runtime.runner._memory_commit_authority
    verifier=module.RegisterResetDefaultVerifier(runtime) if already_installed else None
    before=set(authority._consumers);calls=[]
    def replacement(*args,**kwargs):calls.append((args,kwargs));return None
    monkeypatch.setattr(MemoryAuthorityDistribution,'resolve',replacement)
    with pytest.raises(ValueError):
        if already_installed:verifier._preflight_command()
        else:module.RegisterResetDefaultVerifier(runtime)
    assert authority._consumers==before and authority.pending_count==0 and calls==[]


def test_recipient_removal_is_precommand_refusal(native_factory,tmp_path):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path);verifier=RegisterResetDefaultVerifier(runtime)
    authority=runtime.runner._memory_commit_authority
    authority._consumers.remove('register_reset_default_verifier')
    with pytest.raises(ValueError):verifier._preflight_command()
    assert authority.pending_count==0


def test_mutable_rule_projection_is_not_a_new_source_baseline(native_factory,tmp_path):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path);verifier=RegisterResetDefaultVerifier(runtime)
    verifier._rules.clear()
    with pytest.raises(ValueError):verifier.report()


@pytest.mark.parametrize('change',['component','register','window','kind'])
def test_reidentified_profile_shape_cannot_reuse_inten_source_rule(change):
    import json
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.composition.test_capability import load_ip_test_capability
    from myfuzz.scenario.register_reset_default_verifier import derive_inten_reset_rule
    from tests.composition.test_pulp_gpio_test_capability import PROFILE,SIDECAR
    profile_document=json.loads(PROFILE.read_text());capability_document=json.loads(SIDECAR.read_text())
    if change=='component':
        profile_document['component_id']='foreign_gpio';capability_document['component_id']='foreign_gpio'
    elif change=='register':
        next(r for r in profile_document['address']['registers'] if r['name']=='INTEN')['name']='FOREIGN'
        next(r for r in capability_document['register_semantics'] if r['register']=='INTEN')['register']='FOREIGN'
    elif change=='kind':profile_document['kind']='memory'
    else:profile_document['address']['window_size']=8192
    profile=load_component_profile(profile_document);capability_document['profile_fingerprint']=profile.profile_fingerprint
    capability=load_ip_test_capability(capability_document,profile=profile)
    with pytest.raises(ValueError):derive_inten_reset_rule(profile,capability,base_dir=ROOT)


def test_current_probe_decode_drift_is_not_saved_alias_authority(monkeypatch):
    from myfuzz.local_harness import pulp_gpio_probe_contract as probe
    from myfuzz.scenario.register_reset_default_verifier import derive_inten_reset_rule
    p,c=loaded();original=probe.pulp_gpio_register_map
    def changed():
        document=original();document['alias_period_bytes']=256;return document
    monkeypatch.setattr(probe,'pulp_gpio_register_map',changed)
    with pytest.raises(ValueError):derive_inten_reset_rule(p,c,base_dir=ROOT)


def test_unknown_extra_memory_recipient_is_not_a_permitted_startup_change(native_factory,tmp_path):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path);verifier=RegisterResetDefaultVerifier(runtime)
    runtime.runner._memory_commit_authority.register_consumer('foreign_consumer')
    with pytest.raises(ValueError):verifier._preflight_command()


@pytest.mark.parametrize('field,value',[('address_decode_mask',0),('known_unrelated_offsets',[24,124])])
def test_caller_rule_cannot_change_source_bound_effect_classification(field,value):
    from myfuzz.scenario.register_reset_default_verifier import derive_inten_reset_rule,classify_inten_command
    p,c=loaded();rule=derive_inten_reset_rule(p,c,base_dir=ROOT);rule[field]=value
    with pytest.raises(ValueError):classify_inten_command(dict(status='parsed_complete',operation='ACCESS_GPIO',fields=[0,1,24,0,15]),rule=rule)


def test_external_source_files_and_actual_instance_are_explicit_pins(native_factory,tmp_path):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path);verifier=RegisterResetDefaultVerifier(runtime)
    configuration=verifier.configuration();sources=configuration['source_files']
    assert str(ROOT/'third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv') in sources
    assert str(ROOT/'src/myfuzz/local_harness/pulp_gpio_probe_contract.py') in sources
    assert configuration['rules']['gpio_a']['target_instance']=='gpio_a'


def test_resetting_consumer_floor_cannot_authorize_foreign_recipient(native_factory,tmp_path):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path);verifier=RegisterResetDefaultVerifier(runtime)
    authority=runtime.runner._memory_commit_authority;authority.register_consumer('foreign_consumer')
    verifier._consumer_floor=frozenset(authority._consumers)
    with pytest.raises(ValueError):verifier._preflight_command()


def test_empty_instance_method_projection_does_not_hide_override(native_factory,tmp_path,monkeypatch):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path);verifier=RegisterResetDefaultVerifier(runtime)
    verifier._methods={}
    monkeypatch.setattr(verifier,'report',lambda:{'current_certificates':[{'verified':True}]})
    with pytest.raises(ValueError):RegisterResetDefaultVerifier._validate(verifier)


@pytest.mark.parametrize('relative_path',['third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv','src/myfuzz/local_harness/pulp_gpio_probe_contract.py'])
def test_actual_external_file_bytes_drift_is_permanent_refusal(native_factory,tmp_path,relative_path):
    import hashlib
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path);verifier=RegisterResetDefaultVerifier(runtime)
    path=ROOT/relative_path;original=path.read_bytes();before=hashlib.sha256(original).hexdigest()
    try:
        path.write_bytes(original+b'\n')
        with pytest.raises(ValueError,match='binding-or-source-drift'):verifier.report()
        with pytest.raises(ValueError):verifier._preflight_command()
    finally:path.write_bytes(original)
    assert hashlib.sha256(path.read_bytes()).hexdigest()==before
    assert path.read_bytes()==original
    with pytest.raises(ValueError,match='permanently-incomplete'):verifier._preflight_command()
    assert verifier.report()['current_certificates']==verifier.report()['historical_certificates']==[]
    assert verifier.report()['gaps'][0]['reason']=='incomplete_reset_evidence'


def test_only_actual_later_register_program_verifier_is_permitted(native_factory,tmp_path):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    from myfuzz.scenario.register_program_verifier import RegisterProgramVerifier
    runtime=installed(native_factory,tmp_path,ordinary=True)
    verifier=RegisterResetDefaultVerifier(runtime)
    subsequent=RegisterProgramVerifier(runtime)
    verifier._preflight_command()
    assert runtime.runner._register_program_verifier is subsequent
    assert verifier.report()['current_certificates']==[]


def test_equal_content_authority_recipient_registry_is_not_same_object(native_factory,tmp_path):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path);verifier=RegisterResetDefaultVerifier(runtime)
    authority=runtime.runner._memory_commit_authority
    replacement=set(authority._consumers)
    authority._consumers=replacement;verifier._consumer_set=replacement
    with pytest.raises(ValueError):verifier._preflight_command()


@pytest.mark.parametrize('fault',['authority_resolve','paired_verifier_methods'])
def test_real_issued_commit_method_shadows_cannot_ack_with_pending_views(native_factory,tmp_path,monkeypatch,fault):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path);verifier=RegisterResetDefaultVerifier(runtime)
    runner=runtime.runner;authority=runner._memory_commit_authority;cpu=runner.sessions['cpu']
    if fault=='authority_resolve':monkeypatch.setattr(authority,'resolve',lambda *args,**kwargs:None)
    else:
        monkeypatch.setattr(verifier,'_preflight_command',lambda *args,**kwargs:None)
        monkeypatch.setattr(verifier,'_consume_actual_commit',lambda *args,**kwargs:None)
    cpu.begin_case('mechanical')
    try:
        cpu._serve('data',1,0x10004,0x12345678,15)
        issued=cpu.service.drain_commit_events()[0];commit_id=issued['commit_id']
        with pytest.raises(ValueError):runner._append_external_events('cpu',0)
        assert cpu.service.lookup_pending_commit(commit_id)[1]==issued
        assert runner._status=='failed' and runner.failure_status=='uncertain_effect'
        assert runner.native_reset_evidence_snapshot()['status']=='incomplete'
        if fault=='authority_resolve':assert authority.pending_count>0  # Broken external resolver leaves terminal views; never ack.
        else:assert authority.pending_count==0
    finally:
        from myfuzz.scenario.memory_authority_distribution import MemoryAuthorityDistribution
        for token in tuple(authority._pending):
            for recipient in tuple(authority._consumers):MemoryAuthorityDistribution.resolve(authority,token,consumer=recipient)
        cpu.end_case()


def test_instance_register_noop_cannot_publish_a_half_installed_verifier(native_factory,tmp_path,monkeypatch):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path);authority=runtime.runner._memory_commit_authority
    authority.register_consumer('rogue');before=set(authority._consumers)
    monkeypatch.setattr(authority,'register_consumer',lambda name:None)
    with pytest.raises(ValueError):RegisterResetDefaultVerifier(runtime)
    assert authority._consumers==before and runtime.runner._register_reset_default_verifier is None


def test_instance_registration_validation_cannot_ignore_real_staged_token(native_factory,tmp_path,monkeypatch):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    from myfuzz.scenario.memory_authority_distribution import MemoryAuthorityDistribution
    runtime=installed(native_factory,tmp_path);runner=runtime.runner;authority=runner._memory_commit_authority
    cpu=runner.sessions['cpu'];cpu.begin_case('mechanical');token=None
    try:
        cpu._serve('data',1,0x10004,0x12345678,15)
        issued=cpu.service.drain_commit_events()[0]
        receipt,_=cpu.service.lookup_pending_commit(issued['commit_id'])
        token=authority.stage('cpu',cpu.service,cpu.service.ledger,receipt.transaction_id,receipt)
        assert type(token) is int and authority._next_token==2
        before=set(authority._consumers)
        monkeypatch.setattr(authority,'validate_consumer_registration',lambda name:None)
        with pytest.raises(ValueError):RegisterResetDefaultVerifier(runtime)
        assert authority._consumers==before and runner._register_reset_default_verifier is None
    finally:
        if token is not None:
            for recipient in tuple(authority._consumers):MemoryAuthorityDistribution.resolve(authority,token,consumer=recipient)
        cpu.end_case()


@pytest.mark.parametrize('installed_verifier',[False,True])
def test_runtime_validator_instance_shadow_is_not_a_trusted_boundary(native_factory,tmp_path,monkeypatch,installed_verifier):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path);authority=runtime.runner._memory_commit_authority
    verifier=RegisterResetDefaultVerifier(runtime) if installed_verifier else None;before=set(authority._consumers)
    monkeypatch.setattr(runtime,'validate_static_configuration' if installed_verifier else 'validate',lambda:None)
    with pytest.raises(ValueError):
        if installed_verifier:verifier._preflight_command()
        else:RegisterResetDefaultVerifier(runtime)
    assert authority._consumers==before
    if not installed_verifier:assert runtime.runner._register_reset_default_verifier is None


@pytest.mark.parametrize('already_installed',[False,True])
@pytest.mark.parametrize('method_name',['validate','configuration','snapshot'])
def test_task2_validator_shadow_cannot_become_task3_evidence(native_factory,tmp_path,monkeypatch,already_installed,method_name):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path);authority=runtime.runner._memory_commit_authority
    verifier=RegisterResetDefaultVerifier(runtime) if already_installed else None
    before=set(authority._consumers)
    monkeypatch.setattr(runtime.runner._native_reset_evidence,method_name,lambda **kwargs:None)
    with pytest.raises(ValueError):
        if already_installed:verifier._preflight_command()
        else:RegisterResetDefaultVerifier(runtime)
    assert authority._consumers==before
    if not already_installed:assert runtime.runner._register_reset_default_verifier is None


def test_unbound_dispatch_dependencies_are_explicit_source_pins(native_factory,tmp_path):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path);verifier=RegisterResetDefaultVerifier(runtime)
    sources=verifier.configuration()['source_files']
    for name in ('native_reset_evidence.py','register_program_runtime.py','memory_commit_authority.py','memory_authority_distribution.py','register_program_verifier.py'):
        assert str(ROOT/'src/myfuzz/scenario'/name) in sources


def test_standard_class_special_entry_reassignment_is_rejected(native_factory,tmp_path,monkeypatch):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path);verifier=RegisterResetDefaultVerifier(runtime)
    original=RegisterResetDefaultVerifier.__getattribute__
    def replacement(self,name):
        if name in ('_preflight_command','_consume_actual_commit'):return lambda *args,**kwargs:None
        return object.__getattribute__(self,name)
    with pytest.raises(ValueError):monkeypatch.setattr(RegisterResetDefaultVerifier,'__getattribute__',replacement)
    assert RegisterResetDefaultVerifier.__getattribute__ is original
    assert verifier.report()['current_certificates']==[]


def test_path_alias_cannot_hide_actual_own_source_bytes_drift(native_factory,tmp_path,monkeypatch):
    import io
    from myfuzz.scenario import register_reset_default_verifier as module
    runtime=installed(native_factory,tmp_path);verifier=module.RegisterResetDefaultVerifier(runtime)
    actual_path=Path(module.__file__).resolve();original=actual_path.read_bytes()
    class CachedPath(type(actual_path)):
        def open(self,*args,**kwargs):
            if str(self.resolve())==str(actual_path):return io.BytesIO(original)
            return super().open(*args,**kwargs)
    assert CachedPath.read_bytes is module.Path.read_bytes
    monkeypatch.setattr(module,'Path',CachedPath)
    try:
        actual_path.write_bytes(original+b'\n')
        with pytest.raises(ValueError):verifier.report()
    finally:actual_path.write_bytes(original)
    assert actual_path.read_bytes()==original


def test_noncanonical_actual_target_source_root_cannot_enroll(native_factory,tmp_path):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    from myfuzz.scenario.genome import ScenarioGenome
    from myfuzz.scenario.session_runtime import ScenarioSession
    from tests.scenario.test_register_program_replay import adapter
    runner=configured_runner(native_factory,tmp_path);target=runner.sessions['gpio_a']
    alternate=tmp_path/'alternate-root'
    for relative in (target.artifact.plan.request.profile_path,'third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv'):
        destination=alternate/relative;destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes((ROOT/relative).read_bytes())
    target.base_dir=alternate
    session=ScenarioSession(ScenarioGenome('directed','CPU_TO_IP','register_program',('cpu','gpio_a','gpio_b'),144,()),runner)
    session.declare_instruction_slots('cpu',0x11000,32)
    runner.install_native_reset_evidence(max_commands=32)
    runtime=adapter(session);authority=runner._memory_commit_authority;before=set(authority._consumers)
    with pytest.raises(ValueError,match='canonical'):RegisterResetDefaultVerifier(runtime)
    assert authority._consumers==before and runner._register_reset_default_verifier is None


def test_path_open_cannot_hide_actual_own_source_bytes_drift(native_factory,tmp_path,monkeypatch):
    import io
    import pathlib
    from myfuzz.scenario import register_reset_default_verifier as module
    runtime=installed(native_factory,tmp_path);verifier=module.RegisterResetDefaultVerifier(runtime)
    actual_path=Path(module.__file__).resolve();original=actual_path.read_bytes()
    original_open=pathlib.Path.open
    def cached_open(self,*args,**kwargs):
        if str(self.resolve())==str(actual_path) and args==() and kwargs.get('mode')=='rb':return io.BytesIO(original)
        return original_open(self,*args,**kwargs)
    # Use the original open for our real mutation/restoration, not the patched reader.
    try:
        with original_open(actual_path,'wb') as stream:stream.write(original+b'\n')
        monkeypatch.setattr(pathlib.Path,'open',cached_open)
        with pytest.raises(ValueError):verifier.report()
    finally:
        monkeypatch.undo()
        with original_open(actual_path,'wb') as stream:stream.write(original)
    assert actual_path.read_bytes()==original


@pytest.mark.parametrize('installed_verifier',[False,True])
@pytest.mark.parametrize('entry',['open','read_text','resolve','with_name','__truediv__','parents'])
def test_path_dispatch_replacement_is_refused_before_trust(native_factory,tmp_path,monkeypatch,installed_verifier,entry):
    import pathlib
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path);authority=runtime.runner._memory_commit_authority
    verifier=RegisterResetDefaultVerifier(runtime) if installed_verifier else None;before=set(authority._consumers)
    original=getattr(pathlib.Path,entry)
    if isinstance(original,property):replacement=property(lambda self:original.fget(self))
    else:
        def replacement(*args,**kwargs):return original(*args,**kwargs)
    monkeypatch.setattr(pathlib.Path,entry,replacement)
    with pytest.raises(ValueError):
        if installed_verifier:verifier.report()
        else:RegisterResetDefaultVerifier(runtime)
    assert authority._consumers==before
    if not installed_verifier:assert runtime.runner._register_reset_default_verifier is None


@pytest.mark.parametrize('installed_verifier',[False,True])
@pytest.mark.parametrize('entry',['__fspath__','__new__','__getattribute__','__str__','__eq__'])
def test_path_special_dispatch_replacement_is_refused(native_factory,tmp_path,monkeypatch,installed_verifier,entry):
    import pathlib
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path);authority=runtime.runner._memory_commit_authority
    verifier=RegisterResetDefaultVerifier(runtime) if installed_verifier else None;before=set(authority._consumers)
    original=getattr(pathlib.Path,entry)
    def replacement(*args,**kwargs):return original(*args,**kwargs)
    monkeypatch.setattr(pathlib.Path,entry,replacement)
    with pytest.raises(ValueError):
        if installed_verifier:verifier.report()
        else:RegisterResetDefaultVerifier(runtime)
    assert authority._consumers==before
    if not installed_verifier:assert runtime.runner._register_reset_default_verifier is None


def build_reset_default_chain(native_factory,tmp_path,*,read_value=0,max_records=8):
    """Real software lifecycle/APB/RAM chain; mechanical, never native eligibility."""
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runner=configured_runner(native_factory,tmp_path)
    session=ScenarioSession(ScenarioGenome('directed','CPU_TO_IP','register_program',('cpu','gpio_a','gpio_b'),144,()),runner)
    session.declare_instruction_slots('cpu',0x11000,32)
    session.configure_ordinary_apb_access_evidence(max_records=8)
    runner.enable_event_journal()
    runner.install_native_reset_evidence(max_commands=32)
    runtime=adapter(session)
    verifier=RegisterResetDefaultVerifier(runtime,max_records=max_records)
    target=runner.sessions['gpio_a']
    target.begin_case('semantic-conformance')
    cpu=runner.sessions['cpu'];runner._status='running';cpu._case_id='semantic-conformance-case'
    runner._events.append(dict(event_id=len(runner._events)+1,kind='software_fixture_start',component='cpu'))
    window=next(w for w in cpu.router.windows if w.device_id=='gpio_a')
    cpu._pending_data=None
    cpu._serve('data',0,window.base+24,0,15)
    runner._append_external_events('cpu',len(runner._events))
    runner._step_once('gpio_a')
    cpu._pending_data=None
    cpu._serve('data',1,RESULT_ADDRESS,read_value,15)
    runner._append_external_events('cpu',len(runner._events))
    return SimpleNamespace(runner=runner,runtime=runtime,verifier=verifier,target=target,cpu=cpu)


@pytest.fixture(scope='module')
def conformance_chain(native_factory,tmp_path_factory):
    chain=build_reset_default_chain(native_factory,tmp_path_factory.mktemp('reset-default-chain'))
    yield chain
    chain.target.end_case()


@pytest.fixture
def nonzero_chain(native_factory,tmp_path,monkeypatch):
    """Real chain whose bounded worker returns 7; the observer pins the patched bytes."""
    from tests.scenario import test_native_reset_evidence as evidence_tests
    original=evidence_tests.wire_local
    def nonzero(factory,directory,**kwargs):
        local=original(factory,directory,**kwargs)
        worker=local._binary;text=worker.read_text()
        # Patches trace_prdata and the payload rdata together, as the worker emits both.
        assert 'rdata=0' in text
        worker.write_text(text.replace('rdata=0','rdata=7'))
        return local
    monkeypatch.setattr(evidence_tests,'wire_local',nonzero)
    chain=build_reset_default_chain(native_factory,tmp_path,read_value=7)
    yield chain
    chain.target.end_case()


def chain_inputs(chain,*,barrier=1):
    """Detached seal/command projection plus the live access and commit references."""
    facts=chain.runner.native_reset_evidence_snapshot()['facts']
    lifecycle=next(fact['document'] for fact in facts if fact['kind']=='lifecycle')
    seal=dict(schema_version='native_reset_interval.v1',target_instance='gpio_a',
        target_epoch=lifecycle['target_epoch'],logical_process=lifecycle['logical_process'],
        reset_barrier_event_id=barrier,cpu_component='cpu',cpu_source_epoch=chain.cpu.reset_epoch,
        cpu_logical_process=1,runner_command_epoch=chain.runner.command_epoch,
        memory_generation=chain.cpu.memory.generation,memory_ids=list(chain.cpu.memory.memory_ids))
    commands=[fact['document'] for fact in facts if fact['kind']=='command_parsed']
    accesses=chain.runner._ordinary_apb_access_evidence.completed_accesses()
    commits=tuple(json.loads(encoded) for encoded in chain.verifier._commits.values())
    return seal,commands,accesses,commits


def rehash(certificate):
    certificate['evidence_id']=hashlib.sha256(json.dumps(
        {name:value for name,value in certificate.items() if name!='evidence_id'},
        sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return certificate


def conformance_document(verifier,certificate):
    """Detached semantic-conformance comparison wrapper; never a live verifier output."""
    configuration=verifier.configuration()
    state=dict(schema_version='register_reset_default_state.v1',configuration=configuration,
        proof_scope=READBACK_SCOPE,current_certificates=[certificate],historical_certificates=[certificate],
        gaps=[],interval_refusals=[],
        grants_storage=False,grants_version_dependency=False,grants_prerequisites=False,grants_functional=False)
    return dict(schema_version='register_reset_default_session.v1',configuration=configuration,state=state)


def issued_certificate(chain):
    seal,commands,accesses,commits=chain_inputs(chain)
    certificate,reason=chain.verifier._certificate_for_interval(seal,commands=commands,accesses=accesses,commits=commits)
    assert reason is None
    return certificate


def test_semantic_conformance_complete_chain_issues_positive_scope_certificate(conformance_chain):
    """Semantic-conformance software evidence only; never native acceptance.

    The completed READ row and the issued RAM commit are live sealed objects.
    The seal projection is detached because under the frozen Task1 software
    boundary no software fixture can produce native-eligible lifecycle evidence,
    so the barrier reference is a placeholder that the live report() re-resolves
    against the real journal and would refuse. This test cannot and does not
    claim native eligibility, a joined Runner reset, or any granted capability.
    """
    from myfuzz.scenario.register_reset_default_verifier import validate_register_reset_default_session_document
    chain=conformance_chain
    state=chain.verifier.report()
    assert state['current_certificates']==[] and state['historical_certificates']==[]
    assert chain.runner._native_reset_evidence.completed_intervals()==()
    certificate=issued_certificate(chain)
    assert certificate['schema_version']=='ordinary_register_reset_default_certificate.v1'
    assert certificate['proof_scope']==READBACK_SCOPE
    assert all(certificate[name] is False for name in GRANTS)
    assert (certificate['register'],certificate['field'],certificate['operation'])==('INTEN','value','register_read')
    assert certificate['offset']==24 and certificate['width']==32
    assert certificate['reset_value']==0 and certificate['observed_reset_value']==0
    assert certificate['target_instance']=='gpio_a'
    assert certificate['source_sha256']=='1e271914da4d25c87acd12121dde60a6ed955033870fd7a6730b2c9bafcbcaef'
    assert certificate['reset_seal']['reset_barrier_event_id']==1
    assert certificate['coverage_cursor']['command_count']==2
    assert certificate['read_access_ref']['access_id']=='ordinary-apb:gpio_a:1'
    assert certificate['read_access_ref']['observed_readback']==0
    assert certificate['read_access_ref']['cpu_response']==[0,0,1]
    assert certificate['ram_commit_ref']['commit_id'] in chain.verifier._commits
    assert certificate['ram_commit_ref']['fullkey']['source_sequence']>1
    assert certificate['ram_commit_ref']['generation']==certificate['reset_seal']['memory_generation']
    assert certificate['evidence_id']==hashlib.sha256(json.dumps(
        {name:value for name,value in certificate.items() if name!='evidence_id'},
        sort_keys=True,separators=(',',':')).encode()).hexdigest()
    detached=validate_register_reset_default_session_document(
        conformance_document(chain.verifier,deepcopy(certificate)),configuration=chain.runtime.configuration())
    detached['state']['current_certificates'].clear()
    assert chain.verifier.report()['current_certificates']==[]
    assert chain.verifier._history=={}


def test_live_report_stays_refusal_scope_for_non_native_software_evidence(conformance_chain):
    from myfuzz.scenario.register_reset_default_verifier import validate_register_reset_default_session_document
    chain=conformance_chain
    state=chain.verifier.report()
    assert state['proof_scope']==REFUSAL_SCOPE
    assert state['current_certificates']==state['historical_certificates']==[]
    assert [gap['reason'] for gap in state['gaps']]==['missing_native_reset_default_readback']
    assert chain.verifier.configuration()['proof_scope']==READBACK_SCOPE
    assert chain.runner._native_reset_evidence.completed_intervals()==()
    assert chain.verifier._commits and chain.runner._ordinary_apb_access_evidence.completed_accesses()
    detached=validate_register_reset_default_session_document(chain.verifier.session_document(),
        configuration=chain.runtime.configuration())
    assert detached['state']['proof_scope']==REFUSAL_SCOPE
    assert chain.verifier.session_document()['state']['proof_scope']==REFUSAL_SCOPE


@pytest.mark.parametrize('mutation,reason',[
    ('affecting_write','affecting_write_in_reset_interval'),
    ('unknown_command','unknown_command_in_reset_interval'),
    ('unknown_offset','unknown_offset_in_reset_interval'),
    ('incomplete_cursor','incomplete_command_coverage'),
    ('no_access_evidence','missing_ordinary_access_evidence'),
    ('missing_read_access','missing_actual_selected_read'),
    ('missing_ram_commit','missing_issued_ram_commit'),
    ('foreign_ram_commit','foreign_issued_ram_commit'),
    ('prior_ram_commit','foreign_issued_ram_commit'),
    ('no_barrier','missing_actual_reset_barrier_binding'),
    ('foreign_seal_domain','interval_seal_domain_mismatch')])
def test_incomplete_or_foreign_links_never_issue_a_certificate(conformance_chain,mutation,reason):
    chain=conformance_chain
    seal,commands,accesses,commits=chain_inputs(chain)
    commands=[deepcopy(command) for command in commands];seal=deepcopy(seal)
    if mutation=='affecting_write':
        commands.append({**deepcopy(commands[-1]),'command_ordinal':3,'coverage_cursor':3,
            'command_sequence':3,'fields':[0,1,24,0,15]})
    elif mutation=='unknown_command':
        commands.append({**deepcopy(commands[-1]),'command_ordinal':3,'coverage_cursor':3,
            'command_sequence':3,'operation':'RESET_GPIO'})
    elif mutation=='unknown_offset':
        commands.append({**deepcopy(commands[-1]),'command_ordinal':3,'coverage_cursor':3,
            'command_sequence':3,'fields':[0,1,124,0,15]})
    elif mutation=='incomplete_cursor':
        commands=[commands[0],{**commands[-1],'command_ordinal':3,'coverage_cursor':3,'command_sequence':3}]
    elif mutation=='no_access_evidence':accesses=None
    elif mutation=='missing_read_access':accesses=()
    elif mutation=='missing_ram_commit':commits=()
    elif mutation=='foreign_ram_commit':
        commits=tuple(json.loads(json.dumps(entry)) for entry in commits)
        commits[0]['certificate']['fullkey']['testcase_id']='foreign-case'
    elif mutation=='prior_ram_commit':
        commits=tuple(json.loads(json.dumps(entry)) for entry in commits)
        commits[0]['certificate']['fullkey']['source_sequence']=1
    elif mutation=='no_barrier':seal['reset_barrier_event_id']=None
    else:seal['target_instance']='gpio_b'
    certificate,observed=chain.verifier._certificate_for_interval(seal,commands=commands,
        accesses=accesses,commits=commits)
    assert certificate is None and observed==reason
    assert chain.verifier.report()['current_certificates']==[]


def test_nonzero_readback_is_not_a_source_reset_default(nonzero_chain):
    chain=nonzero_chain
    seal,commands,accesses,commits=chain_inputs(chain)
    assert accesses[0]['receipt']['rdata']==7 and accesses[0]['cpu_response'][0]==7
    certificate,reason=chain.verifier._certificate_for_interval(seal,commands=commands,
        accesses=accesses,commits=commits)
    assert certificate is None and reason=='observed_readback_is_not_source_reset_default'
    assert chain.verifier.report()['current_certificates']==[]


@pytest.mark.parametrize('register,offset',[('PADIN',8),('INTSTATUS',36)])
def test_unreviewed_register_classes_cannot_reuse_the_inten_rule(register,offset):
    from myfuzz.scenario.register_reset_default_verifier import _validate_inten_rule,derive_inten_reset_rule
    p,c=loaded();rule=derive_inten_reset_rule(p,c,base_dir=ROOT)
    assert (rule['register'],rule['offset'])==('INTEN',24)
    with pytest.raises(ValueError):_validate_inten_rule({**rule,'register':register,'offset':offset})
    profile=next(row for row in p.address.registers if row.name==register)
    assert (profile.offset,profile.reset_value)==(offset,None)   # sidecar zero is not a rule


def test_strictly_valid_conformance_document_is_comparison_data_only(conformance_chain):
    from myfuzz.scenario.register_reset_default_verifier import validate_register_reset_default_session_document
    chain=conformance_chain
    document=conformance_document(chain.verifier,issued_certificate(chain))
    before=deepcopy(chain.verifier.report())
    detached=validate_register_reset_default_session_document(deepcopy(document),
        configuration=chain.runtime.configuration())
    assert detached['state']['current_certificates'][0]['proof_scope']==READBACK_SCOPE
    detached['state']['historical_certificates'].clear()
    assert chain.verifier.report()==before
    assert chain.verifier._history=={} and chain.verifier._commits


@pytest.mark.parametrize('mutation',['grant','proof_scope','config_scope','missing_read_access_ref',
    'missing_ram_commit_ref','extra_field','wrong_type','source_fingerprint','foreign_memory',
    'swapped_target','reset_value','stale_rehash','state_scope','gap_partition'])
def test_tampered_or_rehashed_certificate_document_is_rejected(conformance_chain,mutation):
    from myfuzz.scenario.register_reset_default_verifier import validate_register_reset_default_session_document
    chain=conformance_chain
    document=conformance_document(chain.verifier,deepcopy(issued_certificate(chain)))
    certificate=document['state']['current_certificates'][0]
    if mutation=='grant':certificate['grants_storage']=True
    elif mutation=='proof_scope':certificate['proof_scope']=REFUSAL_SCOPE
    elif mutation=='config_scope':document['configuration']['proof_scope']=REFUSAL_SCOPE;document['state']['configuration']=document['configuration']
    elif mutation=='missing_read_access_ref':certificate.pop('read_access_ref')
    elif mutation=='missing_ram_commit_ref':certificate.pop('ram_commit_ref')
    elif mutation=='extra_field':certificate['authority']=True
    elif mutation=='wrong_type':certificate['reset_value']=False
    elif mutation=='source_fingerprint':certificate['source_sha256']='0'*64
    elif mutation=='foreign_memory':certificate['ram_commit_ref']['memory_id']='foreign'
    elif mutation=='swapped_target':certificate['target_instance']='gpio_b'
    elif mutation=='reset_value':certificate['reset_value']=1
    elif mutation=='stale_rehash':certificate['observed_reset_value']=1;certificate['read_access_ref']['observed_readback']=1
    elif mutation=='state_scope':document['state']['proof_scope']=REFUSAL_SCOPE
    else:document['state']['gaps']=[dict(target_instance='gpio_a',reason='missing_native_reset_default_readback')]
    if mutation!='stale_rehash':rehash(certificate)
    with pytest.raises(ValueError):
        validate_register_reset_default_session_document(deepcopy(document),configuration=chain.runtime.configuration())


def test_live_ordinary_collector_instance_shadow_is_refused(native_factory,tmp_path,monkeypatch):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path,ordinary=True)
    verifier=RegisterResetDefaultVerifier(runtime,max_records=4)
    collector=runtime.runner._ordinary_apb_access_evidence
    monkeypatch.setattr(collector,'completed_accesses',lambda:())
    with pytest.raises(ValueError):verifier.report()


def test_replaced_live_ordinary_collector_is_refused(native_factory,tmp_path,monkeypatch):
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    runtime=installed(native_factory,tmp_path,ordinary=True)
    verifier=RegisterResetDefaultVerifier(runtime,max_records=4)
    monkeypatch.setattr(runtime.runner,'_ordinary_apb_access_evidence',None)
    with pytest.raises(ValueError):verifier.report()


# ---------------------------------------------------------------------------
# Task3c scoped re-open: the source-reviewed readback-independence allow-list
# (FIX 1) and the per-interval refusal projection (FIX 2).
#
# The allow-list is INTEN-referenced, never profile-wide: apb_gpio.sv assigns
# r_gpio_inten only at :217 (asynchronous active-low reset) and :234 (its own
# APB write), so a write decoded to r_gpio_dir / r_gpio_out / r_gpio_en shares
# no stored state with the observed INTEN readback.  r_gpio_en does gate the
# IRQ output at :138, so the permission is scoped to the observed readback and
# is not a statement about interrupt behaviour.
# ---------------------------------------------------------------------------

ALLOWLISTED_BOOTSTRAP_WRITES=((0,255),(4,255),(12,0))      # PADDIR, GPIOEN, PADOUT


def appended_commands(commands,rows):
    """Detached command projection with contiguous ordinals and sequences appended."""
    result=[deepcopy(command) for command in commands]
    base=deepcopy(result[-1]);ordinal=base['command_ordinal'];sequence=base['command_sequence']
    for fields in rows:
        ordinal+=1;sequence+=1
        result.append({**deepcopy(base),'command_ordinal':ordinal,'coverage_cursor':ordinal,
            'command_sequence':sequence,'operation':'ACCESS_GPIO','fields':list(fields)})
    return result


def allowlisted_writes():
    return [[0,1,offset,value,15] for offset,value in ALLOWLISTED_BOOTSTRAP_WRITES]


def test_reviewed_allowlist_is_the_inten_referenced_bootstrap_class():
    """The permission is a closed, source-cited class for the INTEN readback only."""
    from myfuzz.scenario.register_reset_default_verifier import derive_inten_reset_rule
    p,c=loaded();rule=derive_inten_reset_rule(p,c,base_dir=ROOT)
    assert rule['schema_version']=='source_bound_inten_reset_rule.v2'
    assert [(row['register'],row['offset']) for row in rule['readback_independent_writes']]==[
        ('PADDIR',0),('GPIOEN',4),('PADOUT',12)]
    assert rule['readback_independent_offsets']==[0,4,12]
    assert rule['readback_allowance_class']=='source_reviewed_disjoint_state_write'
    assert rule['readback_scope_only'] is True and rule['irq_semantics_granted'] is False
    assert rule['inten_writer_source_lines']==[217,234]
    assert rule['irq_output_gate_source_line']==138
    assert rule['known_unrelated_offsets']==[0,4,8,12,16,20,28,32,36]
    assert rule['profile_offsets_outside_reviewed_map']==[40,44,48,52]
    for row in rule['readback_independent_writes']:
        assert row['state'] not in ('r_gpio_inten',) and row['write_enable']!='s_write_inten'


@pytest.mark.parametrize('mutation',['inten_reset_writer_reworded','inten_second_writer_in_paddir',
    'inten_enable_set_from_paddir_decode','dir_state_assigned_in_inten_decode','irq_gate_reworded'])
def test_readback_independence_is_revalidated_against_live_rtl_bytes(mutation):
    """A saved allow-list is never trusted: the claim is re-derived from the bytes."""
    from myfuzz.scenario import register_reset_default_verifier as module
    from tests.composition.test_pulp_gpio_test_capability import SOURCE
    text=SOURCE.read_text()
    if mutation=='inten_reset_writer_reworded':
        text=text.replace("                r_gpio_inten[i]   <= 1'b0;","                r_gpio_inten[i]   <= 1'b1;")
    elif mutation=='inten_second_writer_in_paddir':
        text=text.replace("                    s_gpio_dir[31:0]   = PWDATA;",
            "                    s_gpio_dir[31:0]   = PWDATA;\n                    r_gpio_inten[31:0] <= PWDATA;")
    elif mutation=='inten_enable_set_from_paddir_decode':
        text=text.replace("                    s_write_dir[31:0]  = 32'hFFFFFFFF;",
            "                    s_write_dir[31:0]  = 32'hFFFFFFFF;\n                    s_write_inten[31:0] = 32'hFFFFFFFF;")
    elif mutation=='dir_state_assigned_in_inten_decode':
        text=text.replace("                    s_write_inten[31:0] = 32'hFFFFFFFF;",
            "                    s_write_inten[31:0] = 32'hFFFFFFFF;\n                    r_gpio_dir[i] <= s_gpio_dir[i];")
    else:
        text=text.replace("assign s_is_int_all  = r_gpio_inten & r_gpio_en &",
            "assign s_is_int_all  = r_gpio_inten &")
    assert text!=SOURCE.read_text()
    with pytest.raises(ValueError):module._reviewed_readback_independence(text)
    module._reviewed_readback_independence(SOURCE.read_text())


def test_caller_rule_cannot_widen_the_readback_independence_allowlist():
    """A caller-supplied or saved rule can never grant the permission itself."""
    from myfuzz.scenario.register_reset_default_verifier import derive_inten_reset_rule,classify_inten_command
    p,c=loaded();rule=derive_inten_reset_rule(p,c,base_dir=ROOT)
    for widened in ({**rule,'readback_independent_offsets':[0,4,12,28]},
                    {**rule,'readback_independent_writes':[*rule['readback_independent_writes'],
                        dict(rule['readback_independent_writes'][0],register='INTTYPE_LOW',offset=28)]},
                    {**rule,'irq_semantics_granted':True},
                    {**rule,'readback_scope_only':False}):
        with pytest.raises(ValueError):
            classify_inten_command(dict(status='parsed_complete',operation='ACCESS_GPIO',
                fields=[0,1,28,0,15]),rule=widened)


def test_bootstrap_readback_independent_writes_still_issue_reset_default_certificate(conformance_chain):
    """The positive: DIR/OUT/GPIOEN writes cannot invalidate the observed INTEN readback.

    RTL justification re-derived from the pinned bytes: r_gpio_inten is assigned
    only at apb_gpio.sv:217 (reset) and :234 (its own APB write), so the writes
    decoded to r_gpio_dir / r_gpio_out / r_gpio_en at :229-232,:235-236 share no
    state with the readback.  Every grant stays False.
    """
    chain=conformance_chain
    seal,commands,accesses,commits=chain_inputs(chain)
    commands=appended_commands(commands,allowlisted_writes())
    certificate,reason=chain.verifier._certificate_for_interval(deepcopy(seal),commands=commands,
        accesses=accesses,commits=commits)
    assert reason is None,reason
    assert certificate['schema_version']=='ordinary_register_reset_default_certificate.v1'
    assert certificate['proof_scope']==READBACK_SCOPE
    assert certificate['reset_value']==0 and certificate['observed_reset_value']==0
    assert all(certificate[name] is False for name in GRANTS)
    allowance=certificate['readback_allowance']
    assert allowance['scope']=='observed_readback_only' and allowance['irq_semantics_granted'] is False
    assert allowance['observed_register']=='INTEN' and allowance['observed_offset']==24
    assert allowance['permitted_offsets']==[0,4,12]
    assert allowance['permitted_registers']==['PADDIR','GPIOEN','PADOUT']
    assert allowance['permitted_command_ordinals']==[3,4,5]
    assert allowance['permitted_command_count']==3
    assert allowance['inten_writer_source_lines']==[217,234]
    assert allowance['irq_output_gate_source_line']==138


@pytest.mark.parametrize('offset,value,be',[(24,0,15),(24,0x80000000,15),(24,0xffffffff,15),
    (152,0,15),(280,0,15),(24,0,1),(24,0,3),(24,0x80000000,7)])
def test_any_write_to_the_observed_inten_word_or_alias_still_invalidates(conformance_chain,offset,value,be):
    """INTEN itself, its 128-byte alias, equal-value writes, byte enables and fullword RMW."""
    chain=conformance_chain
    seal,commands,accesses,commits=chain_inputs(chain)
    commands=appended_commands(commands,[[0,1,offset,value,be]])
    certificate,reason=chain.verifier._certificate_for_interval(deepcopy(seal),commands=commands,
        accesses=accesses,commits=commits)
    assert certificate is None and reason=='affecting_write_in_reset_interval'


@pytest.mark.parametrize('rows',[
    allowlisted_writes()+[[0,1,24,257,15]],
    [allowlisted_writes()[0],[0,1,24,257,15]]+allowlisted_writes()[1:],
    [[0,1,0,255,15],[0,1,0,0,15],[0,1,4,257,15],[0,1,12,0,15],[0,1,152,0,15]]])
def test_allowlisted_writes_never_forgive_an_affecting_write_to_the_observed_register(conformance_chain,rows):
    """The relaxation is scoped: it must not become a general amnesty."""
    chain=conformance_chain
    seal,commands,accesses,commits=chain_inputs(chain)
    commands=appended_commands(commands,rows)
    certificate,reason=chain.verifier._certificate_for_interval(deepcopy(seal),commands=commands,
        accesses=accesses,commits=commits)
    assert certificate is None and reason=='affecting_write_in_reset_interval'
    assert chain.verifier.report()['current_certificates']==[]


@pytest.mark.parametrize('offset,reason',[(16,'incomplete_command_in_reset_interval'),
    (20,'incomplete_command_in_reset_interval'),(28,'incomplete_command_in_reset_interval'),
    (32,'incomplete_command_in_reset_interval'),(36,'incomplete_command_in_reset_interval'),
    (40,'unknown_offset_in_reset_interval'),(48,'unknown_offset_in_reset_interval'),
    (56,'unknown_offset_in_reset_interval'),(124,'unknown_offset_in_reset_interval')])
def test_writes_outside_the_source_reviewed_allowlist_still_refuse(conformance_chain,offset,reason):
    """PADOUTSET/PADOUTCLR/INTTYPE/INTSTATUS/PADCFG/reserved are never allow-listed."""
    chain=conformance_chain
    seal,commands,accesses,commits=chain_inputs(chain)
    commands=appended_commands(commands,[[0,1,offset,255,15]])
    certificate,observed=chain.verifier._certificate_for_interval(deepcopy(seal),commands=commands,
        accesses=accesses,commits=commits)
    assert certificate is None and observed==reason


@pytest.mark.parametrize('mutation,reason',[('pending','incomplete_command_coverage'),
    ('failed_applied','incomplete_command_coverage'),('unparsed_reason','incomplete_command_coverage'),
    ('cursor_gap','incomplete_command_coverage'),('foreign_logical_process','incomplete_command_coverage')])
def test_pending_failed_or_incomplete_commands_still_refuse(conformance_chain,mutation,reason):
    chain=conformance_chain
    seal,commands,accesses,commits=chain_inputs(chain)
    commands=appended_commands(commands,allowlisted_writes())
    if mutation=='pending':commands[-1]={**commands[-1],'status':'pending','reason':'reserved'}
    elif mutation=='failed_applied':commands[-1]={**commands[-1],'status':'failed','reason':'applied_then_failed'}
    elif mutation=='unparsed_reason':commands[-1]={**commands[-1],'reason':'late_reason'}
    elif mutation=='cursor_gap':commands[-2]={**commands[-2],'command_ordinal':9,'coverage_cursor':9}
    else:commands[-1]={**commands[-1],'logical_process':commands[-1]['logical_process']+1}
    certificate,observed=chain.verifier._certificate_for_interval(deepcopy(seal),commands=commands,
        accesses=accesses,commits=commits)
    assert certificate is None and observed==reason


def reset_bound_chain(native_factory,tmp_path,monkeypatch):
    """Real software Task1/Task2/Task3 chain able to drive a real Runner global reset.

    ``native_qualification_stand_in`` is the accepted Task2b test double for the frozen
    Task1 qualification callable; it marks the mechanical software lifecycles
    ``native_eligible`` so that the interval projection is exercised.  It makes no
    native claim, grants nothing, and every assertion below reads only refusal
    reasons: the pre-reset (barrier-None) interval can never yield a certificate.
    """
    from tests.scenario import test_native_reset_evidence as evidence_tests
    from myfuzz.scenario.register_reset_default_verifier import RegisterResetDefaultVerifier
    evidence_tests.native_qualification_stand_in(monkeypatch)
    runner=configured_runner(native_factory,tmp_path)
    session=ScenarioSession(ScenarioGenome('directed','CPU_TO_IP','register_program',('cpu','gpio_a','gpio_b'),144,()),runner)
    session.declare_instruction_slots('cpu',0x11000,32)
    session.configure_ordinary_apb_access_evidence(max_records=8)
    runner.install_native_reset_evidence(max_commands=32)
    runtime=adapter(session)
    for name in ('cpu','gpio_a','gpio_b'):runner.sessions[name].begin_case('mechanical')
    verifier=RegisterResetDefaultVerifier(runtime,max_records=8)
    runner._status='running'
    return SimpleNamespace(runner=runner,runtime=runtime,verifier=verifier,evidence=runner._native_reset_evidence)


def close_reset_bound_chain(chain):
    for name in ('cpu','gpio_a','gpio_b'):
        if chain.runner.sessions[name].process is not None:chain.runner.sessions[name].end_case()


def record_target_write(chain,*,device='gpio_a',offset=24,value=0):
    """One real APB ACCESS_GPIO write through the actual CPU router and target wire."""
    runner=chain.runner;cpu=runner.sessions['cpu']
    window=next(w for w in cpu.router.windows if w.device_id==device)
    cpu._pending_data=None
    cpu._serve('data',1,window.base+offset,value,15)
    runner._append_external_events('cpu',len(runner._events))
    runner._step_once(device)


def gap_rows(state,device):
    return [gap for gap in state['gaps'] if gap['target_instance']==device]


def interval_rows(state,device):
    return [row for row in state['interval_refusals'] if row['target_instance']==device]


def test_report_publishes_each_reset_interval_reason_separately(native_factory,tmp_path,monkeypatch):
    """RED (masking): the barrier-None pre-reset interval must not hide the barriered reason.

    The epoch-0 interval a real begin() seals carries ``reset_barrier_event_id=None``.
    No software fixture may reach the frozen ``begin_test`` hook (it would prepare and
    compile local RTL), so that row is produced by the frozen private interval builder
    from the live committed lifecycle and the live domains projection.  A barrier-None
    row can only ever refuse, so it cannot manufacture a certificate; the barriered
    epoch-1 interval below is sealed by a real Runner global reset.
    """
    chain=reset_bound_chain(native_factory,tmp_path,monkeypatch)
    try:
        evidence=chain.evidence
        evidence.snapshot()
        evidence._add_interval('gpio_a',None,evidence._domains('gpio_a'))
        chain.runner.reset_all('warm_all')
        state=chain.verifier.report()
        assert state['current_certificates']==state['historical_certificates']==[]
        assert gap_rows(state,'gpio_a')==[dict(target_instance='gpio_a',
            reason='incomplete_command_coverage')]
        assert [(row['target_epoch'],row['reason']) for row in interval_rows(state,'gpio_a')]==[
            (0,'missing_actual_reset_barrier_binding'),(1,'incomplete_command_coverage')]
        # This runtime pins gpio_a as its only rule target (adapter sidecars).
        assert sorted(chain.verifier._rules)==['gpio_a']
    finally:close_reset_bound_chain(chain)


def test_each_barriered_interval_reports_its_own_reason(native_factory,tmp_path,monkeypatch):
    """A later interval's real reason is published, never discarded by an earlier one.

    Both intervals here are sealed by real Runner global resets.  The first carries a
    real recorded INTEN write (offset 24 -> affecting); the second records no command.
    """
    chain=reset_bound_chain(native_factory,tmp_path,monkeypatch)
    try:
        chain.runner.reset_all('warm_all')
        record_target_write(chain,offset=24,value=0x80000000)
        chain.runner.reset_all('warm_all')
        state=chain.verifier.report()
        assert state['current_certificates']==state['historical_certificates']==[]
        assert [(row['target_epoch'],row['reason']) for row in interval_rows(state,'gpio_a')]==[
            (1,'affecting_write_in_reset_interval'),(2,'incomplete_command_coverage')]
        assert gap_rows(state,'gpio_a')==[dict(target_instance='gpio_a',
            reason='affecting_write_in_reset_interval')]
    finally:close_reset_bound_chain(chain)


def test_post_reset_interval_with_unrelated_and_affecting_writes_still_refuses(native_factory,tmp_path,monkeypatch):
    """The gpio_b shape: allow-listed writes never forgive a write to the observed INTEN."""
    chain=reset_bound_chain(native_factory,tmp_path,monkeypatch)
    try:
        chain.runner.reset_all('warm_all')
        record_target_write(chain,offset=0,value=255)
        record_target_write(chain,offset=4,value=255)
        record_target_write(chain,offset=12,value=0)
        record_target_write(chain,offset=24,value=0x101)
        state=chain.verifier.report()
        assert state['current_certificates']==state['historical_certificates']==[]
        assert gap_rows(state,'gpio_a')==[dict(target_instance='gpio_a',
            reason='affecting_write_in_reset_interval')]
        assert [(row['target_epoch'],row['reason']) for row in interval_rows(state,'gpio_a')]==[
            (1,'affecting_write_in_reset_interval')]
    finally:close_reset_bound_chain(chain)


def test_refusal_projection_document_is_closed_and_tamper_proof(conformance_chain):
    """The extended closed validator accepts the live shape and rejects every mutation."""
    from myfuzz.scenario.register_reset_default_verifier import validate_register_reset_default_session_document
    chain=conformance_chain
    configuration=chain.runtime.configuration()
    live=chain.verifier.session_document()
    assert validate_register_reset_default_session_document(deepcopy(live),configuration=configuration)==live
    assert len(live['state']['interval_refusals'])==1
    for gap in live['state']['gaps']:
        assert gap['reason'] in {row['reason'] for row in live['state']['interval_refusals']
                                 if row['target_instance']==gap['target_instance']}
    reference=live['state']['interval_refusals'][0]
    def rejects(document):
        with pytest.raises(ValueError):
            validate_register_reset_default_session_document(deepcopy(document),configuration=configuration)
    def intervals(document,row):
        document['state']['interval_refusals']=[row]
    for mutation,row in (('dropped',None),('foreign_target',{'target_instance':'gpio_c'}),
                         ('unknown_reason',{'reason':'looks-fine'}),('bool_epoch',{'target_epoch':True}),
                         ('extra_field',{'authority':True}),('missing_epoch',{'target_epoch':'remove'})):
        document=deepcopy(live);row=dict(reference,**(row or {}))
        if row.get('target_epoch')=='remove':row.pop('target_epoch')
        document['state']['interval_refusals']=[] if mutation=='dropped' else [row]
        rejects(document)
    # The headline gap reason must be one of the published per-interval reasons.
    document=deepcopy(live)
    document['state']['gaps']=[dict(document['state']['gaps'][0],
        reason='observed_readback_is_not_source_reset_default')]
    rejects(document)
    certificate=deepcopy(issued_certificate(chain))
    document=conformance_document(chain.verifier,certificate)
    assert validate_register_reset_default_session_document(deepcopy(document),configuration=configuration)
    for mutation in ('allowance_missing','allowance_extra','allowance_irq','allowance_widened',
                     'allowance_ordinal','allowance_register'):
        tampered=deepcopy(document);row=tampered['state']['current_certificates'][0]
        if mutation=='allowance_missing':row.pop('readback_allowance')
        elif mutation=='allowance_extra':row['readback_allowance']['authority']=True
        elif mutation=='allowance_irq':row['readback_allowance']['irq_semantics_granted']=True
        elif mutation=='allowance_widened':row['readback_allowance']['permitted_offsets']=[0,4,12,28]
        elif mutation=='allowance_ordinal':row['readback_allowance']['permitted_command_ordinals']=[99]
        else:row['readback_allowance']['observed_register']='INTSTATUS'
        rehash(row)
        with pytest.raises(ValueError):
            validate_register_reset_default_session_document(tampered,configuration=configuration)
