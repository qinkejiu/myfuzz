"""Online provenance attempts are explicit, replayable and fail closed."""
from dataclasses import asdict, replace
import hashlib
import json
import unittest
from unittest.mock import Mock

from myfuzz.scenario.session_runtime import (replay_online_session, ScenarioSession,
                                           OnlineCase, OnlineInstruction)
from tests.scenario.test_session_runtime_paths import configured, case, factory


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


class OnlineSourceProvenanceTests(unittest.TestCase):
    def test_ambiguous_declared_sources_cannot_become_one_admission(self):
        from myfuzz.scenario.batch import BatchSourceEvent, BatchAdvance
        from myfuzz.scenario.dependency import DependencyGraph, DependencyRule, FuzzableSource
        from myfuzz.scenario.runtime_path_contract import (RuntimeNode, RuntimePathContract,
                                                         PreparedRuntimePathContract)
        from myfuzz.scenario.session_runtime import _resolve_case_source
        graph = DependencyGraph(sources=tuple(FuzzableSource(name, 'a', 'pin', 0, 1, ('IP_TO_IP',))
                for name in ('declared.first', 'declared.second')),
            rules=(DependencyRule('target', ('declared.first', 'declared.second'), 'EVENT_ORDER'),))
        contract = RuntimePathContract(hashlib.sha256(canonical(graph.edge_document())).hexdigest(),
            tuple(RuntimeNode(name, 'a', 'physical', 'pin', 0, 1)
                  for name in ('declared.first', 'declared.second')) +
            (RuntimeNode('target', 'a', 'logical'),), ())
        paths = tuple(('IP_TO_IP', path) for path in graph.edge_paths_to('target', direction='IP_TO_IP'))
        prepared = PreparedRuntimePathContract(graph, contract, paths)
        candidate = OnlineCase('case', 'IP_TO_IP', prepared.path_ids[0],
            BatchSourceEvent('arbitrary-action', 'a', 'pin', 1, 0, 1), (BatchAdvance(('a',)),))
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            _resolve_case_source(prepared, candidate)

    def test_instruction_and_fixed_support_have_separate_material_and_identity(self):
        from myfuzz.scenario.batch import BatchSourceEvent, BatchAdvance
        from myfuzz.scenario.online_case_decoder import OnlineDependencyGraph, OnlineDependencySource
        from myfuzz.scenario.dependency import DependencyRule
        from myfuzz.scenario.runtime_path_contract import RuntimeNode, RuntimePathContract
        def instruction_factory():
            runner = factory()
            runner.sessions['a'].accept_instructions = lambda *args, **kwargs: None
            return runner
        graph = OnlineDependencyGraph(sources=(
            OnlineDependencySource('declared.external', 'source', 'a', ('IP_TO_IP',), port='pin'),
            OnlineDependencySource('declared.program', 'instruction', 'a', ('IP_TO_IP',))),
            rules=(DependencyRule('external.target', ('declared.external',), 'EVENT_ORDER'),
                   DependencyRule('program.target', ('declared.program',), 'EVENT_ORDER')))
        contract = RuntimePathContract(hashlib.sha256(canonical(graph.edge_document())).hexdigest(),
            (RuntimeNode('declared.external', 'a', 'physical', 'pin', 0, 1),
             RuntimeNode('declared.program', 'a', 'logical'),
             RuntimeNode('external.target', 'a', 'logical'),
             RuntimeNode('program.target', 'a', 'logical')), ())
        paths = tuple(('IP_TO_IP', path) for target in ('external.target', 'program.target')
                      for path in graph.edge_paths_to(target, direction='IP_TO_IP'))
        session = ScenarioSession(configured().template, instruction_factory())
        session.configure_runtime_paths(graph, contract, paths, source_ownership=factory().ownership)
        session.begin()
        external = OnlineCase('external-case', 'IP_TO_IP', session.runtime_path_ids[0],
            BatchSourceEvent('arbitrary-action-without-source-name', 'a', 'pin', 1, 0, 1),
            (BatchAdvance(('a',)),), (OnlineInstruction('nop-support', 'a', 0, '13000000'),))
        session.submit_case(external)
        program = OnlineCase('program-case', 'IP_TO_IP', session.runtime_path_ids[1],
            OnlineInstruction('another-arbitrary-action', 'a', 4, '93001000'),
            (BatchAdvance(('a',)),))
        session.submit_case(program)
        rows = session.runner.source_admissions['admissions']
        self.assertEqual(['a.fixed_support', 'declared.external', 'declared.program'],
                         [row['source_id'] for row in rows])
        self.assertEqual(['fixed_support', 'fuzz_source', 'fuzz_source'], [row['role'] for row in rows])
        self.assertEqual(['instruction', 'source_event', 'instruction'], [row['input_kind'] for row in rows])
        reference = session.finish()
        self.assertTrue(replay_online_session(session.encode_plan(), instruction_factory, reference).matches)

    def test_configured_session_binds_registry_and_bootstrap_role(self):
        session = configured()
        session.begin()
        candidate = case(session)
        receipt = session.submit_case(candidate, source_role='bootstrap')
        admission_events = [event for event in receipt.events if event.get('kind') == 'source_admission']
        self.assertEqual(1, len(admission_events))
        self.assertEqual({'case_id': candidate.case_id, 'case_index': 0},
                         admission_events[0]['provenance']['observed_case'])
        document = json.loads(session.encode_plan())
        self.assertEqual(10, document['schema_version'])
        self.assertEqual('bootstrap', document['cases'][0]['source_role'])
        self.assertEqual(document['provenance_configuration'],
                         session.manifest_document['provenance_configuration'])
        rows = document['source_admissions']['admissions']
        self.assertEqual(1, len(rows))
        self.assertEqual('s', rows[0]['source_id'])
        self.assertEqual('bootstrap', rows[0]['role'])
        self.assertEqual(candidate.case_id, rows[0]['case_id'])
        self.assertEqual(0, rows[0]['case_index'])
        self.assertEqual(hashlib.sha256(canonical(asdict(candidate.source) |
                          {'kind': 'source_event'})).hexdigest(), rows[0]['input_sha256'])
        self.assertEqual(receipt, session.submit_case(candidate, source_role='bootstrap'))
        with self.assertRaises(ValueError):
            session.submit_case(candidate, source_role='fuzz_source')
        reference = session.finish()
        self.assertTrue(replay_online_session(session.encode_plan(), factory, reference).matches)

    def test_invalid_role_and_schedule_leave_no_admissions(self):
        session = configured()
        session.begin()
        for role in ('fixed_support', 'invalid', None):
            with self.assertRaises(ValueError):
                session.submit_case(case(session), source_role=role)
        from myfuzz.scenario.batch import BatchAdvance
        with self.assertRaises(ValueError):
            session.submit_case(replace(case(session), advances=(BatchAdvance(('unknown',)),)))
        self.assertEqual([], session.runner.source_admissions['admissions'])
        self.assertEqual((), session.cases)

    def test_partial_failure_preserves_authorization_and_clears_observation(self):
        def fail_factory():
            runner = factory()
            runner.step_batch = Mock(side_effect=RuntimeError('lost response'))
            return runner
        session = configured(fail_factory())
        session.begin()
        session.runner.clear_observation_case = Mock(wraps=session.runner.clear_observation_case)
        with self.assertRaisesRegex(RuntimeError, 'lost response'):
            session.submit_case(case(session))
        session.runner.clear_observation_case.assert_called_once()
        document = json.loads(session.encode_plan())
        self.assertEqual(11, document['schema_version'])
        self.assertEqual(1, len(document['source_admissions']['admissions']))
        reference = session.finish()
        self.assertTrue(replay_online_session(session.encode_plan(), fail_factory, reference).matches)

    def test_registration_failure_preserves_attempted_case_and_registered_prefix(self):
        def fail_factory():
            runner = factory()
            runner.register_source_admission = Mock(side_effect=RuntimeError('metadata capacity'))
            return runner
        session = configured(fail_factory())
        session.begin()
        session.runner.clear_observation_case = Mock(wraps=session.runner.clear_observation_case)
        with self.assertRaisesRegex(RuntimeError, 'metadata capacity'):
            session.submit_case(case(session))
        session.runner.clear_observation_case.assert_called_once()
        self.assertEqual(1, len(session.cases))
        document = json.loads(session.encode_plan())
        self.assertEqual('provenance_admission', document['terminal_failure']['phase'])
        self.assertEqual(0, document['terminal_failure']['command_index'])
        self.assertEqual([], document['source_admissions']['admissions'])
        reference = session.finish()
        self.assertTrue(replay_online_session(session.encode_plan(), fail_factory, reference).matches)

    def test_registration_failure_keeps_prior_cases_and_rejects_deleted_prior_record(self):
        def fail_factory():
            runner = factory()
            register = runner.register_source_admission
            def fail_second(admission):
                if admission.case_index == 1:
                    raise RuntimeError('metadata capacity')
                return register(admission)
            runner.register_source_admission = fail_second
            return runner
        session = configured(fail_factory())
        session.begin()
        first = case(session)
        session.submit_case(first)
        second = replace(first, case_id='two', source=replace(first.source, action_id='two:s'))
        with self.assertRaises(RuntimeError):
            session.submit_case(second)
        reference = session.finish()
        self.assertTrue(replay_online_session(session.encode_plan(), fail_factory, reference).matches)
        doc = json.loads(session.encode_plan())
        doc['source_admissions']['admissions'].clear()
        plan = canonical(doc)
        forged = replace(reference, genome_sha256=hashlib.sha256(plan).hexdigest())
        no_factory = Mock(side_effect=AssertionError('factory must not run'))
        with self.assertRaises(ValueError):
            replay_online_session(plan, no_factory, forged)
        no_factory.assert_not_called()

    def test_registration_failure_after_record_insertion_replays_full_current_prefix(self):
        def fail_factory():
            runner = factory()
            register = runner.register_source_admission
            def fail_after_register(admission):
                register(admission)
                raise RuntimeError('metadata append failed')
            runner.register_source_admission = fail_after_register
            return runner
        session = configured(fail_factory())
        session.begin()
        with self.assertRaises(RuntimeError):
            session.submit_case(case(session))
        self.assertEqual(1, len(session.runner.source_admissions['admissions']))
        reference = session.finish()
        self.assertTrue(replay_online_session(session.encode_plan(), fail_factory, reference).matches)

    def test_checker_failure_clears_observation_and_keeps_environment_error(self):
        session = configured()
        session.begin()
        session.checker = Mock(side_effect=ValueError('bad checker'))
        session.runner.clear_observation_case = Mock(wraps=session.runner.clear_observation_case)
        with self.assertRaisesRegex(ValueError, 'bad checker'):
            session.submit_case(case(session))
        session.runner.clear_observation_case.assert_called_once()
        self.assertEqual('environment_error', session.trace().status)

    def test_tampering_registry_or_role_or_config_rejects_before_factory(self):
        session = configured()
        session.begin()
        session.submit_case(case(session))
        reference = session.finish()
        original = json.loads(session.encode_plan())
        for change in ('registry', 'role', 'config', 'input', 'missing'):
            doc = json.loads(canonical(original))
            if change == 'registry': doc['source_admissions']['admissions'] = []
            elif change == 'role': doc['cases'][0]['source_role'] = 'bootstrap'
            elif change == 'config': doc['provenance_configuration']['edge_index_sha256'] = '0' * 64
            elif change == 'input': doc['cases'][0]['source']['value'] = 0
            else: doc['cases'][0].pop('source_role')
            plan = canonical(doc)
            forged = replace(reference, genome_sha256=hashlib.sha256(plan).hexdigest())
            no_factory = Mock(side_effect=AssertionError('factory must not run'))
            with self.subTest(change=change), self.assertRaises(ValueError):
                replay_online_session(plan, no_factory, forged)
            no_factory.assert_not_called()

    def test_legacy_runtime_plan_retains_schema_eight_without_provenance(self):
        from myfuzz.scenario.session_runtime import ScenarioSession
        from tests.scenario.test_session_runtime_paths import declaration
        base = configured()
        session = ScenarioSession(base.template, factory())
        graph, contract, paths = declaration()
        session.configure_runtime_paths(graph, contract, paths,
            source_ownership=factory().ownership, provenance=False)
        session.begin()
        session.submit_case(case(session))
        reference = session.finish()
        doc = json.loads(session.encode_plan())
        self.assertEqual(8, doc['schema_version'])
        self.assertNotIn('source_role', doc['cases'][0])
        self.assertNotIn('provenance_configuration', session.manifest_document)
        self.assertTrue(replay_online_session(session.encode_plan(), factory, reference).matches)

    def test_malformed_action_documents_reject_with_valueerror_before_factory(self):
        from myfuzz.scenario.genome import ScenarioGenome, GenomeCodec
        from myfuzz.scenario.replay import ScenarioTrace
        template = ScenarioGenome('legacy', 'IP_TO_IP', 'template', ('a', 'b'), 8, ())
        original = {'schema_version': 4, 'template': json.loads(GenomeCodec.encode(template)),
            'instruction_slots': [], 'warmup_advances': [], 'cases': [
                {'case_id': 'one', 'direction': 'IP_TO_IP', 'path_id': 'path',
                 'source': {'kind': 'source_event', 'action_id': 'one:s', 'component': 'a',
                            'port': 'pin', 'value': 1, 'bit_offset': 0, 'width': 1},
                 'support_instructions': [], 'advances': [['a', 'b']]}]}
        reference = ScenarioTrace('', 'complete', (), {}, '', '')
        for change in ('kind_missing', 'source_extra', 'support_extra', 'advances_type'):
            doc = json.loads(canonical(original))
            row = doc['cases'][0]
            if change == 'kind_missing': row['source'].pop('kind')
            elif change == 'source_extra': row['source']['unknown'] = 1
            elif change == 'support_extra': row['support_instructions'] = [{'unknown': 1}]
            else: row['advances'] = None
            plan = canonical(doc)
            forged = replace(reference, genome_sha256=hashlib.sha256(plan).hexdigest())
            no_factory = Mock(side_effect=AssertionError('factory must not run'))
            with self.subTest(change=change), self.assertRaises(ValueError):
                replay_online_session(plan, no_factory, forged)
            no_factory.assert_not_called()

    def test_terminal_command_indices_outside_final_case_reject_before_factory(self):
        runner = factory()
        runner.step_batch = Mock(side_effect=RuntimeError('lost response'))
        session = configured(runner)
        session.begin()
        with self.assertRaises(RuntimeError):
            session.submit_case(case(session))
        reference = session.finish()
        original = json.loads(session.encode_plan())
        for schema in (5, 7, 9, 11):
            for phase, index, support_count in (('step', 1, 0), ('step', 999, 0),
                    ('support_admission', 0, 0), ('support_admission', 999, 0),
                    ('support_admission', 1, 1), ('support_admission', 999, 1)):
                doc = json.loads(canonical(original))
                if support_count:
                    from myfuzz.scenario.source_provenance import SourceAdmission
                    support = asdict(OnlineInstruction('fixed-nop', 'a', 0, '13000000'))
                    doc['cases'][0]['support_instructions'] = [support]
                    fields = {key: value for key, value in doc['source_admissions']['admissions'][0].items()
                              if key not in ('schema_version', 'admission_id')}
                    fields.update(action_id='fixed-nop', source_id='a.fixed_support', role='fixed_support',
                                  input_kind='instruction', input_sha256=hashlib.sha256(
                                      canonical(support | {'kind': 'instruction'})).hexdigest())
                    doc['source_admissions']['admissions'].insert(0, SourceAdmission.create(**fields).document())
                doc['schema_version'] = schema
                if schema != 11:
                    doc.pop('source_admissions')
                    doc.pop('provenance_configuration')
                    for row in doc['cases']:
                        row.pop('source_role')
                if schema in (5, 7):
                    doc.pop('runtime_paths')
                    if schema == 7:
                        doc['cases'][0]['source']['scheduled_local_tick'] = 0
                    else:
                        doc['cases'][0]['source'].pop('scheduled_local_tick', None)
                doc['terminal_failure']['phase'] = phase
                doc['terminal_failure']['command_index'] = index
                plan = canonical(doc)
                forged = replace(reference, genome_sha256=hashlib.sha256(plan).hexdigest())
                no_factory = Mock(side_effect=AssertionError('factory must not run'))
                with self.subTest(schema=schema, phase=phase, index=index,
                                  support_count=support_count), self.assertRaises(ValueError):
                    replay_online_session(plan, no_factory, forged)
                no_factory.assert_not_called()
