"""Live ordinary register proofs; saved reports never install authority."""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path

from myfuzz.composition.ip_test_levels import VerifiedCapabilitySnapshot
from myfuzz.composition.test_capability import load_ip_test_capability
from .ordinary_apb_access_evidence import OrdinaryApbAccessEvidence
from .register_program_runtime import RegisterProgramRuntime
from .ledger import TransactionKey
from .memory_commit_authority import MemoryCommitAuthority
from .memory_authority_distribution import MemoryAuthorityDistribution


def _json(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)


class RegisterProgramVerifier:
    def __init__(self,runtime,*,max_records=256):
        if (type(runtime) is not RegisterProgramRuntime or type(max_records) is not int
                or not 1<=max_records<=65536 or runtime.session._begun):
            raise ValueError('register-verifier-beforebegin-actual-runtime-required')
        runtime.validate()
        collector=runtime.runner._ordinary_apb_access_evidence
        if type(collector) is not OrdinaryApbAccessEvidence:
            raise ValueError('register-verifier-actual-collector-required')
        collector.validate()
        self.runtime=runtime;self._collector=collector;self.max_records=max_records
        self._runtime_configuration_method=RegisterProgramRuntime.configuration
        self._runtime_validation_methods={name:getattr(RegisterProgramRuntime,name)
            for name in ('validate','validate_static_configuration')}
        self._runtime_static_json=runtime._static_json
        self._runtime_configuration_sha256=hashlib.sha256(runtime._static_json.encode()).hexdigest()
        self._limit=max_records;self._completed_method=OrdinaryApbAccessEvidence.completed_accesses
        self._successful=runtime._successful;self._cases=runtime.session._cases;self._runtime_records=runtime._records
        self._configuration=dict(schema_version='register_program_verifier_configuration.v1',
            max_records=max_records,runtime_configuration_sha256=self._runtime_configuration_sha256,
            ordinary_configuration_sha256=collector.configuration_sha256,
            proof_scope='observed_cpu_register_readback_consistency',grants_storage=False,grants_version_dependency=False,grants_prerequisites=False,grants_functional=False)
        self._sources={str(path.resolve()):hashlib.sha256(path.read_bytes()).hexdigest() for path in (
            Path(__file__),Path(__file__).with_name('memory_commit_authority.py'),
            Path(__file__).with_name('memory_authority_distribution.py'),
            Path(__file__).parents[1]/'composition'/'ip_test_levels.py')}
        self._method_pins={name:getattr(type(self),name) for name in ('_validate','_preflight_command','_consume_actual_commit','_issued_result','_alias_result','report','snapshot','session_document','_report_and_snapshots')}
        self._configuration['source_files']=dict(self._sources)
        self._preflight=runtime.capability_preflight()
        self._configuration['target_identities']={alias:{name:target['runtime_support'][name]
            for name in ('component_id','profile_fingerprint','sidecar_fingerprint')}
            for alias,target in self._preflight['targets'].items()}
        self._history={};self._commits={};self._bad=False
        authority=runtime.runner._memory_commit_authority
        if type(authority) is not MemoryCommitAuthority or getattr(runtime.runner,'_register_program_verifier',None) is not None:
            raise ValueError('register-verifier-actual-memory-authority-required')
        authority.validate_consumer_registration('register_program_verifier')
        self._authority=authority;self._authority_resolve=MemoryAuthorityDistribution.resolve
        authority.register_consumer('register_program_verifier')
        self._consumers=authority._consumers;self._consumer_configuration=frozenset(authority._consumers)
        runtime.runner._register_program_verifier=self

    def configuration(self):return deepcopy(self._configuration)

    def _validate(self):
        runtime=self.runtime
        if any(name in vars(runtime) or getattr(RegisterProgramRuntime,name) is not method
                for name,method in self._runtime_validation_methods.items()):
            raise ValueError('register-verifier-runtime-method-drift')
        if any(name in vars(self) or getattr(type(self),name) is not method for name,method in self._method_pins.items()):
            raise ValueError('register-verifier-method-drift')
        if any(hashlib.sha256(Path(path).read_bytes()).hexdigest()!=digest for path,digest in self._sources.items()):
            raise ValueError('register-verifier-source-drift')
        if (runtime.runner._register_program_verifier is not self
                or runtime.runner._memory_commit_authority is not self._authority
                or self._authority._consumers is not self._consumers
                or frozenset(self._consumers)!=self._consumer_configuration
                or MemoryAuthorityDistribution.resolve is not self._authority_resolve
                or 'resolve' in vars(self._authority)):
            raise ValueError('register-verifier-memory-authority-drift')
        if (type(self.max_records) is not int or self.max_records!=self._limit
                or RegisterProgramRuntime.configuration is not self._runtime_configuration_method
                or 'configuration' in vars(runtime)
                or runtime._static_json is not self._runtime_static_json
                or runtime.runner._ordinary_apb_access_evidence is not self._collector
                or OrdinaryApbAccessEvidence.completed_accesses is not self._completed_method
                or 'completed_accesses' in vars(self._collector)
                or runtime._successful is not self._successful or runtime.session._cases is not self._cases
                or runtime._records is not self._runtime_records):
            raise ValueError('register-verifier-binding-drift')
        # Uncertain runtime prefixes can be exported, never accepted as successes.
        if runtime._uncertain:
            runtime.validate_static_configuration()
        else:runtime.validate()
        self._collector.validate(allow_incomplete=True)
        if (self._runtime_configuration_sha256!=self._configuration['runtime_configuration_sha256']
                or self._collector.configuration_sha256!=self._configuration['ordinary_configuration_sha256']):
            raise ValueError('register-verifier-configuration-drift')

    def _preflight_command(self, *, new_operation=False):
        if type(new_operation) is not bool:raise ValueError('register-verifier-new-operation-boolean-required')
        self._validate()
        if self._bad or self.runtime._uncertain or self._collector._status=='incomplete':
            raise ValueError('register-verifier-permanently-incomplete')
        if new_operation and (len(self._commits)>=self._limit or len(self._history)>=self._limit
                or len(self._successful)>=self._limit):
            raise ValueError('register-verifier-command-capacity')

    def _consume_actual_commit(self,logged,token):
        """Only Runner's actual pre-ack issuance hook can call this path."""
        certificate=self._authority_resolve(self._authority,token,consumer='register_program_verifier')
        try:
            self._validate()
            if self._bad:raise ValueError('register-verifier-permanently-incomplete')
            if type(logged) is not dict or type(logged.get('event_id')) is not int:
                raise ValueError('register-verifier-actual-commit-required')
            actual=self.runtime.runner._event_ref_by_id(logged['event_id'])
            if _json(actual)!=_json(logged):raise ValueError('register-verifier-commit-journal-mismatch')
            if certificate is None or certificate.get('component')!=self.runtime.cpu_component:
                raise ValueError('register-verifier-issued-commit-required')
            if (_json(certificate['commit_document'])!=_json(logged.get('commit_document'))
                    or _json(certificate['fullkey'])!=_json(logged.get('transaction'))
                    or certificate['commit_id']!=logged.get('commit_id')):
                raise ValueError('register-verifier-issued-commit-mismatch')
            active=self.runtime._active_submission
            if active is None:return
            if (type(active) is not tuple or len(active)!=2 or not self._cases or active[0] is not self._cases[-1]
                    or not self._runtime_records or self._runtime_records[-1]['phase']!='session_submission'
                    or self._runtime_records[-1]['status']!='attempted'
                    or _json(active[1])!=_json(self._runtime_records[-1]['manifest'])):
                raise ValueError('register-verifier-active-submission-mismatch')
            manifest=active[1];request=manifest['request'];context=manifest['context']
            if request['operation']!='register_read':return
            document=certificate['commit_document'];key=certificate['fullkey'];waiting=context['waiting_transaction']
            span=self.runtime._objects[1].resolve_span(request['result_address'],4,write=True)
            if (key['channel_id']!='data'
                    or any(key[name]!=waiting[name] for name in ('execution_id','testcase_id','source_component','source_epoch'))
                    or document['generation']!=context['generation']
                    or (document['memory_id'],document['generation'],document['byte_offset'])!=span
                    or document['width_bytes']!=4 or document['byte_enable']!=15):return
            if len(self._commits)>=self._limit:raise ValueError('register-verifier-commit-capacity')
            self._commits[logged['event_id']]=_json(dict(logged=logged,certificate=certificate))
        except BaseException:
            self._bad=True;raise

    def _issued_result(self,receipt,request,expected,association):
        generation=association['memory_generation'];source=association['source_transaction']
        for event in receipt.events:
            encoded=self._commits.get(event.get('event_id'))
            if encoded is None:continue
            sealed=json.loads(encoded);actual=sealed['logged'];document=sealed['certificate']['commit_document']
            if _json(actual)!=_json(event):raise ValueError('register-verifier-result-event-drift')
            fullkey=sealed['certificate']['fullkey']
            if (actual['event_id']<=association['delivery_event_id']
                    or any(fullkey.get(name)!=source[name] for name in ('execution_id','testcase_id','source_component','source_epoch','channel_id'))
                    or type(fullkey.get('source_sequence')) is not int
                    or fullkey['source_sequence']<=source['source_sequence']):continue
            cells=document.get('enabled_byte_cells',[])
            if (document.get('generation')==generation and document.get('commit_status')=='complete'
                    and document.get('byte_enable')==15 and len(cells)==4
                    and [cell['value'] for cell in cells]==list(expected.to_bytes(4,'little'))
                    and (document.get('memory_id'),document.get('byte_offset'))==tuple(
                        self.runtime._objects[1].resolve_span(request['result_address'],4,write=True)[::2])):
                return dict(event_id=event['event_id'],commit_id=actual['commit_id'])
        return None

    def _alias_result(self, request, plan, write, capability, successful, accesses):
        relations=[row for row in capability.register_aliases
            if (row.source_register,row.source_field,row.endpoint_id)==(
                request['register'],request['field'],request['endpoint_id'])]
        if len(relations)!=1:
            reason=('unsupported_effect_rule' if capability.schema_version in (
                'ip_test_capability.v1','ip_test_capability.v2') else 'missing_source_bound_alias_relation')
            return None,reason
        relation=relations[0]
        if request['read_modify_write'] or plan['side_effect'] not in ('write_one_sets','write_one_clears'):
            return None,'unsupported_effect_rule'
        destination=next(row for row in capability.register_semantics
            if (row.register,row.field)==(relation.destination_register,relation.destination_field))
        profile=self.runtime.runner.sessions[request['target_instance']].artifact.plan.profile
        offset=next(row.offset for row in profile.address.registers if row.name==relation.destination_register)
        origin=write['association']
        if origin['endpoint_id']!=request['endpoint_id']:
            return None,'alias_scope_mismatch'
        def same_scope(row):
            actual=row['association']
            return (actual['endpoint_id']==origin['endpoint_id']==request['endpoint_id']
                and actual['target_reset_epoch']==origin['target_reset_epoch']
                and actual['memory_generation']==origin['memory_generation']
                and all(actual['source_transaction'][name]==origin['source_transaction'][name]
                    for name in ('execution_id','testcase_id','source_component','source_epoch','channel_id')))
        def selected_read(row):
            matches=[]
            for read,manifest,receipt in successful:
                if (read['operation']=='register_read' and read['target_instance']==request['target_instance']
                        and read['endpoint_id']==request['endpoint_id']
                        and (read['register'],read['field'])==(relation.destination_register,relation.destination_field)
                        and row['association']['delivery_event_id'] in {event['event_id'] for event in receipt.events}):
                    expected=(row['cpu_response'][0] & manifest['program']['operation_plan']['bus_mask'])>>destination.lsb
                    commit=self._issued_result(receipt,read,expected,row['association'])
                    if commit:matches.append(commit)
            return matches[0] if len(matches)==1 else None
        before=None;before_commit=None
        for row in reversed(accesses):
            if row['ordinal']>=write['ordinal'] or row['association']['target_instance']!=request['target_instance']:continue
            if not same_scope(row):return None,'alias_scope_mismatch'
            if row['association']['source_transaction']['source_sequence']>=origin['source_transaction']['source_sequence']:
                return None,'alias_scope_mismatch'
            context=row['receipt']['delivery_context']
            if context['write']:return None,'intervening_target_write'
            if context['offset']!=offset:continue
            commit=selected_read(row)
            if commit:before=row;before_commit=commit;break
        if before is None:return None,'missing_alias_before_readback'
        old=before['cpu_response'][0];written=write['receipt']['delivery_context']['value']
        expected=((old|written) if relation.operation=='set_bits' else old&(~written&0xffffffff))&0xffffffff
        for row in accesses:
            if row['ordinal']<=write['ordinal'] or row['association']['target_instance']!=request['target_instance']:continue
            if not same_scope(row):return None,'alias_scope_mismatch'
            if row['association']['source_transaction']['source_sequence']<=origin['source_transaction']['source_sequence']:
                return None,'alias_scope_mismatch'
            context=row['receipt']['delivery_context']
            if context['write']:return None,'intervening_target_write'
            if context['offset']!=offset:continue
            commit=selected_read(row)
            if commit is None:continue
            if row['cpu_response'][0]!=expected:return None,'actual_alias_readback_mismatch'
            return dict(alias_relation=asdict(relation),before_readback_access=before,
                after_readback_access=row,before_result_commit=before_commit,
                after_result_commit=commit,expected_value=expected),None
        return None,'missing_alias_after_readback'

    def report(self):
        self._validate();runtime=self.runtime
        accesses=self._completed_method(self._collector)
        successful=[];gaps=[]
        for case_id,(encoded,receipt) in self._successful.items():
            manifest=json.loads(encoded);request=manifest['request'];context=manifest['context']
            matches=[case for case in self._cases if case.case_id==case_id]
            submitted=[record for record in self._runtime_records if record['status']=='submitted' and record['manifest']['request']['case_id']==case_id]
            if (len(matches)!=1 or len(submitted)!=1 or _json(submitted[0]['manifest'])!=encoded
                    or submitted[0]['case_index'] is None or self._cases[submitted[0]['case_index']] is not matches[0]
                    or matches[0].source.action_id!=request['action_id']
                    or asdict(matches[0].source)!=manifest['program']['source']):
                raise ValueError('register-verifier-successful-case-binding')
            successful.append((request,manifest,receipt))
        if len(successful)>self._limit:raise ValueError('register-verifier-capacity')
        for request,manifest,case_receipt in successful:
            plan=manifest['program']['operation_plan'];context=manifest['context']
            target=runtime.runner.sessions[request['target_instance']]
            cap=load_ip_test_capability(runtime.sidecars[request['target_instance']],profile=target.artifact.plan.profile)
            field=next(row for row in cap.register_semantics if row.register==request['register'] and row.field==request['field'])
            ids={event['event_id'] for event in case_receipt.events}
            waiting=context['waiting_transaction']
            own=[row for row in accesses if row['association']['target_instance']==request['target_instance']
                and row['association']['source_transaction']['channel_id']=='data'
                and all(row['association']['source_transaction'][name]==waiting[name] for name in ('execution_id','testcase_id','source_component','source_epoch'))
                and row['association']['delivery_event_id'] in ids
                and row['receipt']['delivery_context']['offset']==plan['offset']]
            own.sort(key=lambda row:row['ordinal'])
            if request['operation']=='register_write':
                writes=[row for row in own if row['receipt']['delivery_context']['write']]
                if len(writes)==1:
                    prior=[row for row in own if row['ordinal']<writes[0]['ordinal'] and not row['receipt']['delivery_context']['write']]
                    own=([prior[-1],writes[0]] if request['read_modify_write'] and prior else writes)
            else:own=[row for row in own if not row['receipt']['delivery_context']['write']]
            required=2 if request['read_modify_write'] else 1
            reason='missing_actual_requested_access';selected=None;result=None;rule=None
            if len(own)==required:
                own.sort(key=lambda row:row['ordinal'])
                if request['operation']=='register_read' and not own[0]['receipt']['delivery_context']['write']:
                    selected=own[0];raw=selected['cpu_response'][0]
                    expected=(raw & plan['bus_mask'])>>field.lsb
                    result=self._issued_result(case_receipt,request,expected,selected['association'])
                    reason='missing_actual_cpu_result_commit'
                    if result:rule='ordinary_register_read_result.v1'
                elif request['operation']=='register_write' and own[-1]['receipt']['delivery_context']['write']:
                    write=own[-1];written=write['receipt']['delivery_context']['value'];wanted=plan['bus_value']
                    arithmetic=True
                    if request['read_modify_write']:
                        arithmetic=not own[0]['receipt']['delivery_context']['write']
                        wanted=(own[0]['cpu_response'][0]&(~plan['bus_mask']&0xffffffff))|plan['bus_value']
                    arithmetic=arithmetic and written==wanted
                    reason='missing_later_actual_readback'
                    # Aliases need a separately audited source relationship; never overwrite-rule promotion.
                    if plan['side_effect']!='none':
                        reason='actual_write_arithmetic_mismatch' if not arithmetic else 'unsupported_effect_rule'
                        if arithmetic and plan['side_effect'] in ('write_one_sets','write_one_clears'):
                            result,reason=self._alias_result(request,plan,write,cap,successful,accesses)
                            if result is not None:
                                selected=write;rule='ordinary_register_alias_readback.v1'
                    elif arithmetic:
                        for later in accesses:
                            if later['ordinal']<=write['ordinal'] or later['association']['target_instance']!=request['target_instance']:continue
                            a=later['association'];w=write['association']
                            if (any(a['source_transaction'][name]!=w['source_transaction'][name] for name in ('execution_id','testcase_id','source_component','channel_id'))
                                    or a['source_transaction']['source_sequence']<=w['source_transaction']['source_sequence']
                                    or a['target_reset_epoch']!=w['target_reset_epoch'] or a['memory_generation']!=w['memory_generation']
                                    or a['source_transaction']['source_epoch']!=w['source_transaction']['source_epoch']):break
                            if later['receipt']['delivery_context']['write']:
                                # Conservatively all writes on the target invalidate, including aliases.
                                reason='intervening_target_write';break
                            if later['receipt']['delivery_context']['offset']!=plan['offset']:continue
                            if later['cpu_response'][0]!=written:reason='actual_readback_mismatch';break
                            selected=write;result=dict(readback_ordinal=later['ordinal'],readback_association=later['association'],readback_access=later)
                            rule='ordinary_register_rmw_readback.v1' if request['read_modify_write'] else 'ordinary_register_write_readback.v1';break
                    else:reason='actual_write_arithmetic_mismatch'
            if rule:
                body=dict(schema_version='ordinary_register_semantic_certificate.v1',rule=rule,
                    configuration_sha256=hashlib.sha256(_json(self._configuration).encode()).hexdigest(),
                    case_id=request['case_id'],target_instance=request['target_instance'],endpoint_id=request['endpoint_id'],
                    register=request['register'],field=request['field'],operation=request['operation'],
                    profile_fingerprint=target.artifact.plan.profile.profile_fingerprint,sidecar_fingerprint=cap.sidecar_fingerprint,
                    operation_plan=plan,association=selected['association'],observed_accesses=own,result=result,
                    proof_scope='observed_cpu_register_readback_consistency',grants_storage=False,grants_version_dependency=False,grants_prerequisites=False,grants_functional=False)
                digest=hashlib.sha256(_json(body).encode()).hexdigest();body['evidence_id']=digest
                if digest not in self._history and len(self._history)>=self._limit:raise ValueError('register-verifier-capacity')
                self._history[digest]=body
            else:gaps.append(dict(case_id=request['case_id'],reason=reason))
        current=[]
        for cert in self._history.values():
            a=cert['association'];target=runtime.runner.sessions[cert['target_instance']]
            if (a['target_reset_epoch']==target.reset_epoch and a['memory_generation']==runtime._objects[1].generation
                    and a['source_transaction']['source_epoch']==runtime._objects[0].reset_epoch):current.append(cert)
        reason=('verifier_incomplete' if self._bad else 'runtime_uncertain' if runtime._uncertain
            else 'ordinary_observation_incomplete' if self._collector._status=='incomplete' else None)
        if reason is not None:
            current=[];gaps.append(dict(case_id=None,reason=reason))
        return deepcopy(dict(schema_version='register_program_verifier_state.v1',configuration=self._configuration,
            status='complete' if reason is None else 'incomplete',reason=reason,
            historical_certificates=list(self._history.values()),current_certificates=current,gaps=gaps,
            grants_storage=False,grants_version_dependency=False,grants_prerequisites=False,grants_functional=False))

    def _report_and_snapshots(self):
        # Only this live report supplies capability projections; no saved input.
        report=self.report();snapshots={}
        for target_instance in sorted(self.runtime.sidecars):
            target=self.runtime.runner.sessions[target_instance]
            cap=load_ip_test_capability(self.runtime.sidecars[target_instance],profile=target.artifact.plan.profile)
            effective={(row['endpoint_id'],row['operation'],row['scope']) for row in self._preflight['targets'][target_instance]['assessment']['support_matrix'] if row['effective']}
            operations={}
            for cert in report['current_certificates']:
                key=(cert['endpoint_id'],cert['operation'],cert['register']+'.'+cert['field'])
                if cert['target_instance']==target_instance and key in effective:
                    operations.setdefault(key,[]).append('ordinary_register_semantic:'+cert['evidence_id'])
            snapshots[target_instance]=VerifiedCapabilitySnapshot.from_mapping(target.artifact.plan.profile,sidecar=cap,operations=operations)
        return report,snapshots

    def session_document(self):
        report,snapshots=self._report_and_snapshots()
        return dict(schema_version='register_program_verifier_session.v1',configuration=self.configuration(),
            state=report,verified_capabilities={alias:asdict(snapshot) for alias,snapshot in snapshots.items()})

    def snapshot(self,target_instance):
        if type(target_instance) is not str or target_instance not in self.runtime.sidecars:
            raise ValueError('register-verifier-target-required')
        return self._report_and_snapshots()[1][target_instance]



def validate_register_program_verifier_session_document(document, *, configuration=None):
    """Validate closed comparison data without reading files or installing authority.

    A self-consistent saved proof is still only comparison material. The trusted
    replay must reconstruct its entire contents from fresh live objects/evidence.
    """
    import re
    from myfuzz.local_harness.ordinary_apb_access_receipts import validate_ordinary_apb_target_receipt

    grants={'grants_storage','grants_version_dependency','grants_prerequisites','grants_functional'}
    bus_grants={'grants_verified','grants_storage','grants_functional'}
    scope='observed_cpu_register_readback_consistency'
    def fail(reason):raise ValueError('invalid-register-verifier-session-document:'+reason)
    def keys(row,names):
        if type(row) is not dict or any(type(k) is not str for k in row) or set(row)!=set(names):fail('closed-fields')
    def text(value,limit=256):
        if type(value) is not str or not 0<len(value)<=limit or value.strip()!=value:fail('text')
    def uint(value,maximum=(1<<64)-1,minimum=0):
        if type(value) is not int or not minimum<=value<=maximum:fail('unsigned-integer')
    def digest(value):
        if type(value) is not str or re.fullmatch('[0-9a-f]{64}',value) is None:fail('sha256')
    def fingerprint(value):
        if type(value) is not str or not value.startswith('sha256:'):fail('fingerprint')
        digest(value[7:])
    def false(row,names):
        if any(row[k] is not False for k in names):fail('saved-grants')
    def same(left,right):
        if _json(left)!=_json(right):fail('comparison-mismatch')
    def items(value,maximum,minimum=0):
        if type(value) is not list or not minimum<=len(value)<=maximum:fail('bounded-list')
    def transaction(row):
        keys(row,('execution_id','testcase_id','source_component','source_epoch','channel_id','source_sequence'))
        for name in ('execution_id','testcase_id','source_component','channel_id'):text(row[name])
        for name in ('source_epoch','source_sequence'):uint(row[name])
        if row['channel_id']!='data':fail('data-transaction-required')
    def references(value,maximum,minimum):
        items(value,maximum,minimum)
        for n in value:uint(n,minimum=1)
        if value!=sorted(set(value)):fail('event-reference-order')
    keys(document,('schema_version','configuration','state','verified_capabilities'))
    if document['schema_version']!='register_program_verifier_session.v1':fail('version')
    cfg=document['configuration']
    keys(cfg,{'schema_version','max_records','runtime_configuration_sha256','ordinary_configuration_sha256',
        'proof_scope','source_files','target_identities'}|grants)
    if cfg['schema_version']!='register_program_verifier_configuration.v1' or cfg['proof_scope']!=scope:fail('configuration-scope')
    false(cfg,grants);uint(cfg['max_records'],65536,1);limit=cfg['max_records']
    for name in ('runtime_configuration_sha256','ordinary_configuration_sha256'):digest(cfg[name])
    sources=cfg['source_files']
    expected_sources={'register_program_verifier.py','memory_commit_authority.py','memory_authority_distribution.py','ip_test_levels.py'}
    if type(sources) is not dict or len(sources)!=len(expected_sources):fail('source-files')
    for path,sha in sources.items():
        text(path,4096);digest(sha)
        if not Path(path).is_absolute():fail('source-path')
    if {Path(p).name for p in sources}!=expected_sources:fail('source-closure')
    identities=cfg['target_identities']
    if type(identities) is not dict or not 1<=len(identities)<=256:fail('target-identities')
    for alias,identity in identities.items():
        text(alias);keys(identity,('component_id','profile_fingerprint','sidecar_fingerprint'))
        text(identity['component_id']);fingerprint(identity['profile_fingerprint']);fingerprint(identity['sidecar_fingerprint'])
    if configuration is not None:
        if (type(configuration) is not dict or configuration.get('schema_version')!='register_program_runtime_configuration.v1'
                or type(configuration.get('sidecars')) is not dict or type(configuration.get('artifacts')) is not dict):fail('runtime-configuration')
        same(hashlib.sha256(_json(configuration).encode()).hexdigest(),cfg['runtime_configuration_sha256'])
        if set(identities)!=set(configuration['sidecars']):fail('runtime-targets')
        for alias,identity in identities.items():
            artifact=configuration['artifacts'].get(alias)
            if type(artifact) is not dict or type(artifact.get('plan')) is not dict:fail('runtime-target-artifact')
            same(identity['profile_fingerprint'],artifact['current_profile_fingerprint'])
            same(identity['component_id'],artifact['plan']['component_id'])
    cfg_sha=hashlib.sha256(_json(cfg).encode()).hexdigest()
    state=document['state']
    keys(state,{'schema_version','configuration','status','reason','historical_certificates','current_certificates','gaps'}|grants)
    if state['schema_version']!='register_program_verifier_state.v1':fail('state-version')
    false(state,grants);same(state['configuration'],cfg)
    reasons={'verifier_incomplete','runtime_uncertain','ordinary_observation_incomplete'}
    if state['status']=='complete':
        if state['reason'] is not None:fail('complete-reason')
    elif state['status']=='incomplete':
        if type(state['reason']) is not str or state['reason'] not in reasons:fail('incomplete-reason')
    else:fail('state-status')
    items(state['gaps'],limit+1)
    for gap in state['gaps']:
        keys(gap,('case_id','reason'));text(gap['reason'])
        if gap['case_id'] is not None:text(gap['case_id'])
    if state['status']=='incomplete' and {'case_id':None,'reason':state['reason']} not in state['gaps']:fail('incomplete-gap')
    rows_by_ordinal={};rows_by_transaction={};rows_by_access_id={};event_owners={};commit_events={};commit_ids={}
    def association(row):
        keys(row,{'schema_version','access_id','target_instance','endpoint_id','source_transaction','target_reset_epoch',
            'memory_generation','target_receipt_event_id','acceptance_event_id','delivery_event_id','raw_event_refs',
            'base_event_refs','status','reason','proof_scope'}|bus_grants)
        if (row['schema_version']!='ordinary_apb_access_association.v1' or row['status']!='cpu_delivery_confirmed'
                or row['reason'] is not None or row['proof_scope']!='actual_command_protocol_boundary_association_only'):fail('association-state')
        false(row,bus_grants)
        for name in ('access_id','target_instance','endpoint_id'):text(row[name])
        if row['target_instance'] not in identities:fail('association-target')
        transaction(row['source_transaction'])
        for name in ('target_reset_epoch','memory_generation'):uint(row[name])
        for name in ('target_receipt_event_id','acceptance_event_id','delivery_event_id'):uint(row[name],minimum=1)
        references(row['raw_event_refs'],131072,2);references(row['base_event_refs'],3,3)
        if len(row['raw_event_refs'])%2:fail('raw-phases')
        refs=[row[n] for n in ('target_receipt_event_id','acceptance_event_id','delivery_event_id')]+row['raw_event_refs']+row['base_event_refs']
        if len(refs)!=len(set(refs)) or row['acceptance_event_id']>=row['delivery_event_id']:fail('association-references')
        return refs
    def access(row):
        keys(row,{'schema_version','ordinal','association','receipt','acceptance','delivery','cpu_response',
            'request_evidence','command_samples_sha256'}|bus_grants)
        if row['schema_version']!='ordinary_apb_completed_access.v1':fail('access-version')
        false(row,bus_grants);uint(row['ordinal'],65536,1);digest(row['command_samples_sha256'])
        a=row['association'];refs=association(a);receipt=row['receipt']
        validate_ordinary_apb_target_receipt(receipt,source_transaction=a['source_transaction'])
        for name in ('access_id','target_instance','endpoint_id','target_reset_epoch'):same(receipt[name],a[name])
        context=receipt['delivery_context'];key=a['source_transaction'];writing=context['write']
        if len(a['raw_event_refs'])!=2*len(receipt['sample_ticks']):fail('command-span')
        acceptance=row['acceptance'];delivery=row['delivery']
        common={'source_transaction','device_id','address','offset','write','write_value','byte_enable','beat_bytes','source_sequence'}
        keys(acceptance,common|{'acceptance_order'})
        keys(delivery,common|{'read_value','delivery_order','target_delivery_order','target_access_id','target_access_receipt','source_delivery_confirmed'})
        for event,orders in ((acceptance,('acceptance_order',)),(delivery,('delivery_order','target_delivery_order'))):
            same(event['source_transaction'],key)
            for name in ('device_id','address','offset','write'):same(event[name],context[name])
            same(event['source_sequence'],key['source_sequence'])
            if event['byte_enable']!=15 or type(event['byte_enable']) is not int or event['beat_bytes']!=4 or type(event['beat_bytes']) is not int:fail('full-word-event')
            same(event['write_value'],context['value'] if writing else None)
            for order in orders:uint(event[order],minimum=1)
        if delivery['source_delivery_confirmed'] is not True:fail('delivery-confirmation')
        same(delivery['target_access_id'],a['access_id']);same(delivery['target_access_receipt'],receipt)
        expected_read=None if writing else receipt['rdata']
        same(delivery['read_value'],expected_read)
        response=row['cpu_response'];items(response,3,3)
        for n in response:uint(n,(1<<64)-1)
        same(response,[0 if writing else receipt['rdata'],0,key['source_sequence']])
        evidence=row['request_evidence']
        keys(evidence,('transaction','raw_address','aligned_address','address','write','be','wdata','acceptance_tick'))
        same(evidence['transaction'],key)
        for name in ('raw_address','aligned_address','address'):
            uint(evidence[name],(1<<32)-1);same(evidence[name],context['address'])
        uint(evidence['write'],1);same(evidence['write'],int(writing))
        uint(evidence['be'],15);same(evidence['be'],15)
        uint(evidence['wdata'],(1<<32)-1);same(evidence['wdata'],context['value']);uint(evidence['acceptance_tick'])
        canonical=_json(row);token=_json(key)
        # The same read can prove an earlier write and its own requested READ.
        # Reuse is legal only when every sealed fact is identical.
        for registry,index in ((rows_by_ordinal,row['ordinal']),(rows_by_transaction,token),(rows_by_access_id,a['access_id'])):
            if index in registry and registry[index]!=canonical:fail('conflicting-access-reuse')
            registry[index]=canonical
        for ref in refs:
            if ref in commit_events:fail('conflicting-event-role')
            if ref in event_owners and event_owners[ref]!=canonical:fail('conflicting-event-reference')
            event_owners[ref]=canonical
    alias_comparisons=[]
    def result_commit(result,selected):
        keys(result,('event_id','commit_id'));digest(result['commit_id']);uint(result['event_id'],minimum=1)
        if result['event_id']<=selected['association']['delivery_event_id']:fail('result-order')
        event_id=result['event_id'];commit_id=result['commit_id']
        if event_id in event_owners:fail('conflicting-event-role')
        if event_id in commit_events and commit_events[event_id]!=commit_id:fail('conflicting-commit-reference')
        if commit_id in commit_ids and commit_ids[commit_id]!=event_id:fail('conflicting-commit-reference')
        commit_events[event_id]=commit_id;commit_ids[commit_id]=event_id
    def certificate(cert):
        keys(cert,{'schema_version','rule','configuration_sha256','case_id','target_instance','endpoint_id','register','field',
            'operation','profile_fingerprint','sidecar_fingerprint','operation_plan','association','observed_accesses','result',
            'proof_scope','evidence_id'}|grants)
        false(cert,grants)
        if cert['schema_version']!='ordinary_register_semantic_certificate.v1' or cert['proof_scope']!=scope:fail('certificate-scope')
        digest(cert['evidence_id']);same(cert['configuration_sha256'],cfg_sha)
        digest(cert['configuration_sha256'])
        same(cert['evidence_id'],hashlib.sha256(_json({k:v for k,v in cert.items() if k!='evidence_id'}).encode()).hexdigest())
        for name in ('case_id','target_instance','endpoint_id','register','field'):text(cert[name])
        for name in ('register','field'):
            if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',cert[name]) is None:fail('field-scope-identifier')
        identity=identities.get(cert['target_instance'])
        if identity is None:fail('certificate-target')
        for name in ('profile_fingerprint','sidecar_fingerprint'):same(cert[name],identity[name])
        rules={'ordinary_register_read_result.v1':('register_read',1),
               'ordinary_register_write_readback.v1':('register_write',1),
               'ordinary_register_rmw_readback.v1':('register_write',2),
               'ordinary_register_alias_readback.v1':('register_write',1)}
        if type(cert['rule']) is not str or cert['rule'] not in rules:fail('certificate-rule')
        operation,count=rules[cert['rule']]
        if cert['operation']!=operation:fail('rule-operation')
        plan=cert['operation_plan']
        keys(plan,('register','field','operation','offset','field_width','bus_mask','bus_value','side_effect','evidence_ref'))
        for name in ('register','field','operation'):same(plan[name],cert[name])
        uint(plan['offset'],(1<<32)-1);uint(plan['field_width'],32,1);uint(plan['bus_mask'],(1<<32)-1,1)
        mask=plan['bus_mask'];shift=(mask & -mask).bit_length()-1
        if mask>>shift!=(1<<plan['field_width'])-1:fail('field-mask-geometry')
        text(plan['evidence_ref'],4096)
        alias_rule=cert['rule']=='ordinary_register_alias_readback.v1'
        if plan['offset']%4 or (not alias_rule and plan['side_effect']!='none'):fail('ordinary-rule-plan')
        if operation=='register_read':
            if plan['bus_value'] is not None:fail('read-value')
        else:
            uint(plan['bus_value'],(1<<32)-1)
            if plan['bus_value']&~plan['bus_mask']:fail('write-mask')
        observed=cert['observed_accesses'];items(observed,count,count)
        for row in observed:
            access(row);a=row['association'];context=row['receipt']['delivery_context']
            for name in ('target_instance','endpoint_id'):same(a[name],cert[name])
            same(context['offset'],plan['offset'])
        if [r['ordinal'] for r in observed]!=sorted(set(r['ordinal'] for r in observed)):fail('observed-order')
        selected=observed[-1];same(cert['association'],selected['association'])
        selected_context=selected['receipt']['delivery_context'];selected_key=selected['association']['source_transaction']
        result=cert['result']
        if alias_rule:
            if not selected_context['write']:fail('alias-write-access')
            if plan['field_width']!=32 or plan['bus_mask']!=0xffffffff:fail('alias-full-word-plan')
            same(selected_context['value'],plan['bus_value'])
            keys(result,('alias_relation','before_readback_access','after_readback_access',
                         'before_result_commit','after_result_commit','expected_value'))
            relation=result['alias_relation']
            keys(relation,('endpoint_id','source_register','source_field','destination_register',
                           'destination_field','operation','bus_width','evidence_ref'))
            for name in ('endpoint_id','source_register','source_field','destination_register','destination_field'):
                text(relation[name])
            for name in ('source_register','source_field','destination_register','destination_field'):
                if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*',relation[name]) is None:fail('alias-field-identifier')
            same(relation['endpoint_id'],cert['endpoint_id'])
            same(relation['source_register'],cert['register']);same(relation['source_field'],cert['field'])
            text(relation['evidence_ref'],4096);same(relation['evidence_ref'],plan['evidence_ref'])
            uint(relation['bus_width'],32,32)
            effects={'set_bits':'write_one_sets','clear_bits':'write_one_clears'}
            if type(relation['operation']) is not str or relation['operation'] not in effects:fail('alias-operation')
            same(plan['side_effect'],effects[relation['operation']])
            if relation['source_register']==relation['destination_register']:fail('alias-self-reference')
            before=result['before_readback_access'];after=result['after_readback_access']
            for row in (before,after):
                access(row);a=row['association'];context=row['receipt']['delivery_context']
                if context['write'] or context['offset']==plan['offset']:fail('alias-readback-offset')
                for name in ('target_instance','endpoint_id','target_reset_epoch','memory_generation'):
                    same(a[name],selected['association'][name])
                for name in ('execution_id','testcase_id','source_component','source_epoch','channel_id'):
                    same(a['source_transaction'][name],selected_key[name])
            same(before['receipt']['delivery_context']['offset'],after['receipt']['delivery_context']['offset'])
            if not before['ordinal']<selected['ordinal']<after['ordinal']:fail('alias-access-order')
            if not (before['association']['source_transaction']['source_sequence']<selected_key['source_sequence']
                    <after['association']['source_transaction']['source_sequence']):fail('alias-source-order')
            old=before['cpu_response'][0];written=selected_context['value']
            expected=(old|written) if relation['operation']=='set_bits' else old&(~written&0xffffffff)
            uint(result['expected_value'],(1<<32)-1)
            same(result['expected_value'],expected);same(after['cpu_response'][0],expected)
            result_commit(result['before_result_commit'],before)
            result_commit(result['after_result_commit'],after)
            if result['before_result_commit']['event_id']>=selected['association']['target_receipt_event_id']:
                fail('alias-before-result-order')
            alias_comparisons.append(cert)
        elif operation=='register_read':
            if selected_context['write']:fail('read-access')
            result_commit(result,selected)
        else:
            if not selected_context['write']:fail('write-access')
            wanted=plan['bus_value']
            if count==2:
                initial=observed[0]
                if initial['receipt']['delivery_context']['write']:fail('rmw-initial-read')
                if (initial['association']['memory_generation']!=selected['association']['memory_generation']
                        or initial['association']['target_reset_epoch']!=selected['association']['target_reset_epoch']):fail('rmw-epoch')
                for name in ('execution_id','testcase_id','source_component','source_epoch','channel_id'):
                    same(initial['association']['source_transaction'][name],selected_key[name])
                if initial['association']['source_transaction']['source_sequence']>=selected_key['source_sequence']:fail('rmw-order')
                wanted=(initial['cpu_response'][0]&(~plan['bus_mask']&0xffffffff))|wanted
            same(selected_context['value'],wanted)
            keys(result,('readback_ordinal','readback_association','readback_access'))
            access(result['readback_access']);later=result['readback_access'];a=later['association'];w=selected['association']
            same(result['readback_ordinal'],later['ordinal']);same(result['readback_association'],a)
            if later['ordinal']<=selected['ordinal'] or later['receipt']['delivery_context']['write']:fail('readback-order')
            same(later['receipt']['delivery_context']['offset'],plan['offset']);same(later['cpu_response'][0],wanted)
            for name in ('target_instance','endpoint_id','target_reset_epoch','memory_generation'):same(a[name],w[name])
            for name in ('execution_id','testcase_id','source_component','source_epoch','channel_id'):same(a['source_transaction'][name],selected_key[name])
            if a['source_transaction']['source_sequence']<=selected_key['source_sequence']:fail('readback-source-order')
    history=state['historical_certificates'];current=state['current_certificates']
    items(history,limit);items(current,limit)
    history_by_id={}
    for cert in history:
        certificate(cert)
        if cert['evidence_id'] in history_by_id:fail('duplicate-certificate')
        history_by_id[cert['evidence_id']]=cert
    # Link both readbacks to the closed READ certificates in this same saved
    # wrapper. This checks comparison consistency; it installs no authority.
    read_certificates={}
    for cert in history:
        if cert['rule']=='ordinary_register_read_result.v1':
            access_id=cert['association']['access_id']
            if access_id in read_certificates:fail('duplicate-read-certificate')
            read_certificates[access_id]=cert
    for cert in alias_comparisons:
        result=cert['result'];relation=result['alias_relation']
        for prefix in ('before','after'):
            row=result[prefix+'_readback_access']
            read=read_certificates.get(row['association']['access_id'])
            if read is None:fail('alias-read-certificate-required')
            same(read['observed_accesses'],[row])
            same(read['register'],relation['destination_register'])
            same(read['field'],relation['destination_field'])
            if read['operation_plan']['field_width']!=32 or read['operation_plan']['bus_mask']!=0xffffffff:
                fail('alias-read-full-word-plan')
            same(read['result'],result[prefix+'_result_commit'])
    current_ids=set()
    for cert in current:
        if type(cert) is not dict or type(cert.get('evidence_id')) is not str or cert['evidence_id'] not in history_by_id:fail('current-certificate')
        same(cert,history_by_id[cert['evidence_id']])
        if cert['evidence_id'] in current_ids:fail('duplicate-current')
        current_ids.add(cert['evidence_id'])
    if state['status']=='incomplete' and current:fail('incomplete-current')
    snapshots=document['verified_capabilities']
    if type(snapshots) is not dict or set(snapshots)!=set(identities):fail('snapshot-targets')
    for alias,snapshot in snapshots.items():
        keys(snapshot,('component_id','profile_fingerprint','sidecar_fingerprint','operations'))
        for name in identities[alias]:same(snapshot[name],identities[alias][name])
        expected={}
        for cert in current:
            if cert['target_instance']==alias:
                key=(cert['endpoint_id'],cert['operation'],cert['register']+'.'+cert['field'])
                expected.setdefault(key,[]).append('ordinary_register_semantic:'+cert['evidence_id'])
        items(snapshot['operations'],limit);actual={}
        for op in snapshot['operations']:
            keys(op,('endpoint_id','operation','scope','evidence_refs'))
            for name in ('endpoint_id','operation','scope'):text(op[name])
            key=(op['endpoint_id'],op['operation'],op['scope'])
            if key in actual or key not in expected:fail('snapshot-operation')
            items(op['evidence_refs'],limit,1)
            for ref in op['evidence_refs']:text(ref)
            if op['evidence_refs']!=sorted(set(op['evidence_refs'])):fail('snapshot-refs')
            same(op['evidence_refs'],sorted(set(expected[key])));actual[key]=op['evidence_refs']
        if set(actual)!=set(expected):fail('snapshot-projection')
    return json.loads(_json(document))
