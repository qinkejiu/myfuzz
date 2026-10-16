"""Software-only closed register selector admission."""
from copy import deepcopy
import importlib
import unittest
from unittest.mock import patch


def module():
    return importlib.import_module('myfuzz.integration.ibex_pulp_register_replay')


class RegisterAssemblyTests(unittest.TestCase):
    def test_closed_assembly_available(self):
        try:
            api = module()
        except ModuleNotFoundError:
            self.fail('closed register replay API missing')
        doc = api.make_register_assembly(advance_rounds=48, max_program_bytes=64, max_records=10)
        self.assertEqual(api.validate_register_assembly(doc), doc)
        self.assertEqual(doc['selector'], 'ibex_pulp_ordinary_gpio')

    def test_exact_types_and_unsupported_modes(self):
        api = module()
        baseline = api.make_register_assembly()
        changes = {'native_physical_observations': False, 'memory_commit_receipts': 1,
                   'persistent_memory_prerequisites': False, 'checker': 'pilot',
                   'selector': 'arbitrary.module', 'sidecar_selector': '/tmp/sidecar',
                   'max_records': True, 'max_program_bytes': 0,
                   'runtime_contract_sha256': '0'*64, 'gpio_consumption': True}
        for key, value in changes.items():
            with self.subTest(key=key):
                doc = deepcopy(baseline); doc[key] = value
                with self.assertRaises(ValueError): api.validate_register_assembly(doc)
        doc=deepcopy(baseline);doc['provider_path']='evil.py'
        with self.assertRaises(ValueError): api.validate_register_assembly(doc)

    def test_detached_data_and_bounded_limits(self):
        api=module();doc=api.make_register_assembly()
        actual=api.validate_register_assembly(doc);actual['max_records']=2
        self.assertNotEqual(actual,doc)
        for name,value in [('advance_rounds',0),('max_records',65537),('max_program_bytes',3)]:
            with self.subTest(name=name), self.assertRaises(ValueError):
                api.make_register_assembly(**{name:value})

    def test_file_rejects_missing_identity_before_factory(self):
        api=module()
        with patch.object(api,'_candidate_reference',return_value=('trace',object())), \
             patch.object(api,'_verify_online_run_identity',return_value=None), \
             patch.object(api,'make_register_factory') as factory:
            with self.assertRaisesRegex(ValueError,'verified'):
                api.replay_ibex_pulp_register_files(cache_dir='cache',output_dir='saved')
            factory.assert_not_called()

    def test_invalid_assembly_rejects_before_factory(self):
        api=module()
        with patch.object(api,'_candidate_reference',return_value=('trace',object())), \
             patch.object(api,'_verify_online_run_identity',return_value={'execution_mode':'register_programs', 'run_config': {'register_program_assembly':{}}}), \
             patch.object(api,'make_register_factory') as factory:
            with self.assertRaises(ValueError):
                api.replay_ibex_pulp_register_files(cache_dir='cache',output_dir='saved')
            factory.assert_not_called()

    def test_assembly_configuration_must_match_current_modes(self):
        api=module();d=api.make_register_assembly()
        config=dict(cpu_component='cpu',advance_rounds=d['advance_rounds'],
            max_program_bytes=d['max_program_bytes'],max_records=d['max_records'],
            sidecars={name:dict(path=str((api._ROOT/api.SIDECAR).resolve()),
                sha256=__import__('hashlib').sha256((api._ROOT/api.SIDECAR).read_bytes()).hexdigest())
                for name in ('gpio_a','gpio_b')},
            provider={'runtime_contract_sha256':d['runtime_contract_sha256']})
        self.assertIsNone(api._verify_assembly_configuration(d,config))
        for key,value in [('advance_rounds',True),('sidecars',{}),('provider',{})]:
            bad=deepcopy(config);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                api._verify_assembly_configuration(d,bad)

    def test_cli_selects_register_replay_and_returns_mismatch(self):
        import importlib.util
        from pathlib import Path
        spec=importlib.util.spec_from_file_location('register_cli',Path('scripts/run_ibex_pulp_online.py'))
        cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
        from types import SimpleNamespace
        fake=SimpleNamespace(matches=False,verification_scope=('register_program_reconstruction',),
            comparison=SimpleNamespace(first_difference=1,difference_context='changed',
                actual_trace=SimpleNamespace(events=[{}],semantic_sha256='a'*64)))
        with patch.object(cli,'replay_ibex_pulp_register_files',return_value=fake) as replay:
            import io,json
            from contextlib import redirect_stdout
            output=io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(cli.main(['replay-register-programs','--cache-dir','cache','--run-dir','saved']),2)
            result=json.loads(output.getvalue())
            self.assertEqual(result['event_count'],1)
            self.assertEqual(result['semantic_sha256'],'a'*64)
            replay.assert_called_once()

    def test_small_runtime_budgets_are_rejected(self):
        api=module()
        for size in (4,8,12):
            with self.subTest(size=size),self.assertRaises(ValueError):
                api.make_register_assembly(max_program_bytes=size)

    def test_writer_authenticates_assembly_and_state_without_rfuzz(self):
        api=module()
        import tempfile,json,hashlib
        from pathlib import Path
        from dataclasses import replace
        from myfuzz.scenario.replay import ScenarioTrace
        from myfuzz.scenario.session_runtime import ScenarioSession,_online_manifest
        from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_stream_bootstrap
        with tempfile.TemporaryDirectory() as temp:
            assembly=api.make_register_assembly()
            bootstrap=make_ibex_pulp_dual_source_stream_bootstrap()
            session=ScenarioSession(bootstrap.template,
                api.make_register_factory(cache_dir=Path(temp)/'render',assembly=assembly)())
            session.declare_instruction_slots('cpu',bootstrap.instruction_start,bootstrap.instruction_count)
            adapter=api.make_register_runtime_factory(assembly)(session)
            state=adapter.snapshot()
            manifest=_online_manifest(session.runner,None,register_program_configuration=adapter.configuration())
            plan=session.encode_plan()
            trace=ScenarioTrace(genome_sha256=hashlib.sha256(plan).hexdigest(),status='complete',events=(),local_ticks={},
                semantic_sha256=hashlib.sha256(b'{"events":[],"local_ticks":{},"status":"complete"}').hexdigest(),
                manifest_sha256=hashlib.sha256(api._json(manifest).encode()).hexdigest())
            output=Path(temp)/'new'
            with self.assertRaisesRegex(ValueError,'semantic'):
                api.save_ibex_pulp_register_bundle(output_dir=output,assembly=assembly,session_manifest=manifest,
                    plan_bytes=plan,trace=replace(trace,events=({'kind':'forged'},)),runtime_state=state)
            self.assertFalse(output.exists())
            api.save_ibex_pulp_register_bundle(output_dir=output,assembly=assembly,session_manifest=manifest,
                plan_bytes=plan,trace=trace,runtime_state=state)
            identity=json.loads((output/'online_run_identity.json').read_bytes())['identity']
            badstate=deepcopy(state);badstate['records']=[{'status':'submitted'}]
            with self.assertRaises(ValueError):api._validate_saved_register_documents(json.loads(plan),badstate)
            badstate=deepcopy(state);badstate['arbitrary']=True
            with self.assertRaises(ValueError):api._validate_saved_register_documents(json.loads(plan),badstate)
            self.assertEqual(identity['execution_mode'],'register_programs')
            self.assertIsNone(identity['toolchain']['client'])
            self.assertFalse(identity['run_config']['rfuzz_client_executed'])
            self.assertIn('corpus/register_program_state.json',identity['artifacts'])
            self.assertIn('corpus/register_program_assembly.json',identity['artifacts'])
            actual=api._verify_online_run_identity(output,plan_path=output/'online_plan.json',trace_path=output/'online_final_trace.json',trace=trace)
            self.assertEqual(actual['execution_mode'],'register_programs')
            (output/'corpus/register_program_state.json').write_text('{}')
            with self.assertRaisesRegex(ValueError,'artifact mismatch'):
                api._verify_online_run_identity(output,plan_path=output/'online_plan.json',trace_path=output/'online_final_trace.json',trace=trace)

    def test_authenticated_artifact_is_rechecked_at_use(self):
        api=module()
        self.assertTrue(hasattr(api,'_authenticated_bytes'),'authenticated reread missing')
        import tempfile,hashlib
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);p=root/'plan.json';p.write_bytes(b'first')
            identity={'artifacts':{'plan.json':hashlib.sha256(b'first').hexdigest()}}
            self.assertEqual(api._authenticated_bytes(root,'plan.json',identity),b'first')
            p.write_bytes(b'second')
            with self.assertRaises(ValueError):api._authenticated_bytes(root,'plan.json',identity)
            p.unlink();p.symlink_to(root/'absent')
            with self.assertRaises(ValueError):api._authenticated_bytes(root,'plan.json',identity)

    def test_fixed_factory_has_exact_native_and_gate_modes(self):
        api=module();assembly=api.make_register_assembly()
        with patch('myfuzz.scenario.ibex_pulp_dual_source.make_ibex_pulp_dual_source_factory') as factory:
            api.make_register_factory(cache_dir='cache',assembly=assembly)
            kwargs=factory.call_args.kwargs
            self.assertEqual(kwargs,dict(source_actions=True,gpio_consumption=False,
                physical_observations=True,memory_commit_receipts=True,
                persistent_memory_runtime_contract_sha256=assembly['runtime_contract_sha256']))

    def test_directed_persistent_policy_does_not_need_causal_paths(self):
        api=module()
        import tempfile
        from pathlib import Path
        from myfuzz.scenario.session_runtime import ScenarioSession,_online_manifest
        from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_stream_bootstrap
        with tempfile.TemporaryDirectory() as temp:
            assembly=api.make_register_assembly(max_records=10)
            factory=api.make_register_factory(cache_dir=Path(temp)/'render',assembly=assembly)
            bootstrap=make_ibex_pulp_dual_source_stream_bootstrap()
            session=ScenarioSession(bootstrap.template,factory())
            session.declare_instruction_slots('cpu',bootstrap.instruction_start,bootstrap.instruction_count)
            adapter=api.make_register_runtime_factory(assembly)(session)
            manifest=_online_manifest(session.runner,None,register_program_configuration=adapter.configuration())
            self.assertNotIn('runtime_paths',manifest)
            api._verify_assembly_configuration(assembly,adapter.configuration())
            api._verify_persistent_mode(manifest,assembly['runtime_contract_sha256'])
            saved=deepcopy(manifest)
            manifest['runner']['memory_dependency_evidence']['runtime_contract_sha256']='0'*64
            with self.assertRaises(ValueError):api._verify_persistent_mode(manifest,assembly['runtime_contract_sha256'])

            import json,hashlib
            from myfuzz.scenario.replay import ScenarioTrace
            plan=session.encode_plan()
            trace=ScenarioTrace(genome_sha256=hashlib.sha256(plan).hexdigest(),status='complete',events=(),local_ticks={},
                semantic_sha256=hashlib.sha256(b'{"events":[],"local_ticks":{},"status":"complete"}').hexdigest(),
                manifest_sha256=hashlib.sha256(api._json(saved).encode()).hexdigest())
            output=Path(temp)/'bundle'
            api.save_ibex_pulp_register_bundle(output_dir=output,assembly=assembly,session_manifest=saved,
                plan_bytes=plan,trace=trace,runtime_state=adapter.snapshot())
            identity=api._verify_online_run_identity(output,plan_path=output/'online_plan.json',
                trace_path=output/'online_final_trace.json',trace=trace)
            selected,state=api._verified_register_bundle(output,identity,plan)
            self.assertEqual(selected,assembly)
            self.assertEqual(state,adapter.snapshot())
            badplan=json.loads(plan);badplan['register_programs']['terminal_attempt']={'status':'uncertain'}
            with self.assertRaises(ValueError):api._validate_saved_register_documents(badplan,state)
            # Rehash artifact, envelope and report consistently: event semantics still refuse.
            trace_document=json.loads((output/'online_final_trace.json').read_bytes())
            trace_document['events']=[{'kind':'forged'}]
            raw=(api._json(trace_document)+'\n').encode()
            (output/'online_final_trace.json').write_bytes(raw)
            envelope=json.loads((output/'online_run_identity.json').read_bytes())
            envelope['identity']['artifacts']['online_final_trace.json']=hashlib.sha256(raw).hexdigest()
            envelope['sha256']=hashlib.sha256(api._json(envelope['identity']).encode()).hexdigest()
            (output/'online_run_identity.json').write_text(api._json(envelope)+'\n')
            report=json.loads((output/'report.json').read_bytes())
            report['online_run_identity_sha256']=envelope['sha256']
            (output/'report.json').write_text(api._json(report)+'\n')
            with patch.object(api,'make_register_factory') as fresh_factory:
                with self.assertRaisesRegex(ValueError,'semantic'):
                    api.replay_ibex_pulp_register_files(cache_dir=Path(temp)/'fresh',output_dir=output)
                fresh_factory.assert_not_called()

    def test_closed_bootstrap_refuses_rehashed_initial_program_or_slots(self):
        api=module()
        self.assertTrue(hasattr(api,'_verify_bootstrap_plan'),'closed bootstrap selector missing')
        import json
        from myfuzz.scenario.ibex_pulp_dual_source import make_ibex_pulp_dual_source_stream_bootstrap
        from myfuzz.scenario.genome import GenomeCodec
        bootstrap=make_ibex_pulp_dual_source_stream_bootstrap()
        plan=dict(template=json.loads(GenomeCodec.encode(bootstrap.template)),
            instruction_slots=[['cpu',bootstrap.instruction_start,bootstrap.instruction_count]])
        api._verify_bootstrap_plan(plan)
        for key,value in [('instruction_slots',[['cpu',0x11000,1]]),('template',{})]:
            bad=deepcopy(plan);bad[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):api._verify_bootstrap_plan(bad)

    def test_authority_distribution_is_pinned_and_drift_rejects_before_factory(self):
        api=module()
        path='src/myfuzz/scenario/memory_authority_distribution.py'
        sources=api._sources()
        self.assertIn(path,[row['path'] for row in sources])
        next(row for row in sources if row['path']==path)['sha256']='0'*64
        identity=dict(execution_mode='register_programs',run_config=dict(
            register_program_assembly=api.make_register_assembly(),register_program_source_files=sources,
            register_program_state_sha256='0'*64,rfuzz_client_executed=False))
        with patch.object(api,'_candidate_reference',return_value=('trace',object())), \
             patch.object(api,'_verify_online_run_identity',return_value=identity), \
             patch.object(api,'_authenticated_bytes',return_value=b'{}'), \
             patch.object(api,'make_register_factory') as factory:
            with self.assertRaisesRegex(ValueError,'source identity mismatch'):
                api.replay_ibex_pulp_register_files(cache_dir='cache',output_dir='saved')
            factory.assert_not_called()

    def test_native_projection_checker_sources_are_pinned_before_factory(self):
        api=module();sources=api._sources()
        for name in ('ip_base_events.py','ip_protocol_events.py','ip_protocol_checker.py'):
            path='src/myfuzz/scenario/'+name
            with self.subTest(path=path):
                self.assertIn(path,[row['path'] for row in sources])
                changed=deepcopy(sources)
                next(row for row in changed if row['path']==path)['sha256']='0'*64
                identity=dict(execution_mode='register_programs',run_config=dict(
                    register_program_assembly=api.make_register_assembly(),register_program_source_files=changed,
                    register_program_state_sha256='0'*64,rfuzz_client_executed=False))
                with patch.object(api,'_candidate_reference',return_value=('trace',object())), \
                     patch.object(api,'_verify_online_run_identity',return_value=identity), \
                     patch.object(api,'_authenticated_bytes',return_value=b'{}'), \
                     patch.object(api,'make_register_factory') as factory:
                    with self.assertRaisesRegex(ValueError,'source identity mismatch'):
                        api.replay_ibex_pulp_register_files(cache_dir='cache',output_dir='saved')
                    factory.assert_not_called()

    def test_reference_semantics_are_checked_before_factory(self):
        api=module()
        self.assertTrue(hasattr(api,'_validate_reference'),'reference semantic preflight missing')
        from myfuzz.scenario.replay import ScenarioTrace
        from myfuzz.scenario.session_runtime import _trace_semantic_sha256
        trace=ScenarioTrace(genome_sha256='a'*64,status='complete',events=(),local_ticks={},
            manifest_sha256='b'*64,semantic_sha256=_trace_semantic_sha256('complete',(),{}))
        api._validate_reference(trace)
        from dataclasses import replace
        bad=replace(trace,events=({'kind':'forged'},))
        with self.assertRaisesRegex(ValueError,'semantic'):
            api._validate_reference(bad)
        with patch.object(api,'_candidate_reference',return_value=('trace',bad)), \
             patch.object(api,'_verify_online_run_identity',return_value=dict(run_config={'register_program_assembly':api.make_register_assembly()})), \
             patch.object(api,'_authenticated_bytes',return_value=b'{}'), \
             patch.object(api,'_verified_register_bundle',return_value=(api.make_register_assembly(),{})), \
             patch.object(api,'make_register_factory') as factory:
            with self.assertRaisesRegex(ValueError,'semantic'):
                api.replay_ibex_pulp_register_files(cache_dir='cache',output_dir='saved')
            factory.assert_not_called()

    def test_optional_minimum_is_explicit_and_default_layout_unchanged(self):
        api=module();default=api.make_register_assembly()
        self.assertNotIn('requested_minimum_level',default)
        for level in (None,'L1','L2','L3'):
            declared=api.make_register_assembly(requested_minimum_level=level)
            self.assertIn('requested_minimum_level',declared)
            self.assertEqual(declared['requested_minimum_level'],level)
            self.assertEqual(api.validate_register_assembly(declared),declared)
        for value in (True,1,'L0','L4','none',{},[]):
            with self.subTest(value=value),self.assertRaises(ValueError):
                api.make_register_assembly(requested_minimum_level=value)
        self.assertEqual(set(default),set(api._FIXED)|set(api._LIMITS)|{'runtime_contract_sha256'})

class RegisterCapabilityChannelTests(unittest.TestCase):
    def test_conditional_source_closure_preserves_default(self):
        api=module();default=api.make_register_assembly()
        self.assertEqual(api._sources(),api._sources(default))
        for minimum in (None,'L1','L2','L3'):
            enabled=api.make_register_assembly(requested_minimum_level=minimum)
            paths=[row['path'] for row in api._sources(enabled)]
            self.assertEqual(len(paths),len(api._sources())+2)
            self.assertIn('src/myfuzz/scenario/register_program_capabilities.py',paths)

    def test_channel_presence_rejected_before_saved_report_is_used(self):
        api=module()
        default=api.make_register_assembly()
        enabled=api.make_register_assembly(requested_minimum_level='L1')
        for assembly,registers,manifest in ((default,{'capability_preflight':{}},{}),
            (enabled,{},{}),(enabled,{'capability_preflight':{}},{})):
            with self.subTest(assembly=assembly),self.assertRaisesRegex(ValueError,'presence'):
                api._verify_capability_channel(assembly,{'register_programs':registers},manifest)

    def test_installer_configures_only_explicit_minimum(self):
        api=module()
        from types import SimpleNamespace
        for sentinel in ('omitted',None,'L1'):
            assembly=api.make_register_assembly() if sentinel=='omitted' else api.make_register_assembly(requested_minimum_level=sentinel)
            with patch('myfuzz.scenario.register_program_runtime.RegisterProgramRuntime') as ctor:
                from unittest.mock import Mock
                session=Mock()
                self.assertIs(api.make_register_runtime_factory(assembly)(session),ctor.return_value)
                if sentinel=='omitted':session.configure_register_capability_preflight.assert_not_called()
                else:session.configure_register_capability_preflight.assert_called_once_with(sentinel)
