"""P7-C: the compiled ``F1..F6`` path set, its refusals and its naming rule.

Three plan exit criteria are covered here, plus the property the P7 gate cares
about most:

* every ``F1..F6`` path appears with ``executable`` or ``unsupported`` and a
  reason -- there is no third, vague status;
* a deliberately declared "reserved-bit random source" is *refused* at compile
  time with ``code`` + ``pointer``;
* a deliberately missing source is ``unsupported`` and *names what is missing*;
* a real composition (the repository's own pinned Ibex + PULP GPIO profiles, and
  the repository's own ``configs/soc/ibex-pulp.json`` render profile) compiles to
  executable paths that the existing runtime-path pipeline can consume;
* the compiler branches on declared capabilities, never on a component id, an
  endpoint id or a register name.
"""
from ast import (AsyncFunctionDef, Attribute, ClassDef, Compare, Constant, Expr,
                 FunctionDef, Module, parse, walk)
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from myfuzz.scenario.compiled_paths import (
    COMPILED_PATHS_SCHEMA, DIRECTION_IP_SOURCED, FLOW_IDS, PATH_STATUSES,
    PathCompilationError, PathComponent, PathCompileRequest, STATUS_EXECUTABLE,
    STATUS_UNSUPPORTED, compile_paths, load_path_compile_request, load_path_wiring)
from myfuzz.scenario.dependency import DependencyGraph
from myfuzz.scenario.runtime_path_contract import (
    PreparedRuntimePathContract, RuntimePathContract)

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / 'src' / 'myfuzz' / 'scenario' / 'compiled_paths.py'
FIXTURES = ROOT / 'tests' / 'scenario' / 'fixtures'
P7B_REQUEST = FIXTURES / 'path_compile_ibex_obi_pulp_gpio_wiring_contract.json'
SOC_RENDER_REQUEST = FIXTURES / 'path_compile_ibex_pulp_soc_render.json'
PULP_GPIO_PROFILE = 'configs/peripherals/pulp_gpio/component_profile.json'
PULP_I2C_PROFILE = 'configs/peripherals/pulp_i2c/component_profile.json'

EXECUTABLE_FLOWS = ('F1', 'F2', 'F3', 'F4')


def load_request(path, **overrides):
    """Load one fixture request, with optional in-memory declaration edits."""
    document = json.loads(Path(path).read_text(encoding='utf-8'))
    return {**document, **overrides}


def compile_document(path, **overrides):
    return compile_paths(
        load_path_compile_request(load_request(path, **overrides), base_dir=ROOT))


def path_of(document, flow_id):
    rows = [row for row in document['paths'] if row['flow_id'] == flow_id]
    if len(rows) != 1:
        raise AssertionError(f'flow {flow_id} has {len(rows)} records')
    return rows[0]


def missing_codes(path):
    return {row['code'] for row in path['reason']['missing']}


class FlowStatusTests(unittest.TestCase):
    """Exit criterion 1: every F1..F6 has a status and a reason, and no third."""

    def test_every_flow_gets_exactly_one_of_two_statuses(self):
        document = compile_document(SOC_RENDER_REQUEST)
        self.assertEqual(COMPILED_PATHS_SCHEMA, document['schema_version'])
        self.assertEqual(list(FLOW_IDS), [row['flow_id'] for row in document['paths']])
        self.assertEqual(2, len(PATH_STATUSES))
        for path in document['paths']:
            self.assertIn(path['status'], PATH_STATUSES)
            self.assertIn('reason', path)
            self.assertIsInstance(path['reason']['missing'], list)
            if path['status'] == STATUS_EXECUTABLE:
                self.assertEqual([], path['reason']['missing'])
                self.assertIsNone(path['reason']['code'])
                self.assertTrue(path['sources'])
            else:
                self.assertTrue(path['reason']['missing'])
                self.assertTrue(path['reason']['code'])
                self.assertTrue(path['reason']['pointer'])
                self.assertEqual(path['reason']['code'],
                                 path['reason']['missing'][0]['code'])
            for row in path['reason']['missing']:
                self.assertTrue(row['code'])
                self.assertTrue(row['pointer'])
                self.assertIsNotNone(row['detail'])
        self.assertEqual({'executable', 'unsupported'}, set(
            key for key in document['counts'] if key != 'total'))
        self.assertEqual(6, document['counts']['total'])

    def test_definition_of_every_flow_is_carried_with_its_authority(self):
        document = compile_document(SOC_RENDER_REQUEST)
        for path in document['paths']:
            self.assertEqual(path['definition'],
                             document['flow_definitions'][path['flow_id']])
            self.assertIn('docs/superpowers/plans/2026-10-06-current-dataflow-fuzz-'
                          'implementation-plan.md:', path['definition']['authority'])
            self.assertTrue(path['definition']['propagation'])

    def test_every_path_declares_assertions_from_the_shipped_classes(self):
        document = compile_document(SOC_RENDER_REQUEST)
        seen_classes = set()
        for path in document['paths']:
            self.assertTrue(path['assertions'])
            for row in path['assertions']:
                self.assertTrue(row['expectation_id'])
                self.assertTrue(row['asserts'])
                seen_classes.add(row['assertion_class'])
        self.assertEqual({'protocol_checker', 'cross_component_provenance_and_order',
                          'cpu_ip_behaviour'}, seen_classes)

    def test_prerequisites_and_termination_use_the_shipped_vocabulary(self):
        from myfuzz.scenario.source_actions import PREREQUISITE_KINDS, TERMINATION_KINDS
        document = compile_document(SOC_RENDER_REQUEST)
        for path in document['paths']:
            self.assertIn(path['termination_observation']['kind'], TERMINATION_KINDS)
            for row in path['prerequisites']:
                self.assertIn(row['kind'], PREREQUISITE_KINDS)


class RealCompositionTests(unittest.TestCase):
    """A real composition: executable paths, and the ones that are refused."""

    def test_soc_render_profile_compiles_four_executable_paths(self):
        document = compile_document(SOC_RENDER_REQUEST)
        statuses = {row['flow_id']: row['status'] for row in document['paths']}
        self.assertEqual({flow: STATUS_EXECUTABLE for flow in EXECUTABLE_FLOWS},
                         {flow: statuses[flow] for flow in EXECUTABLE_FLOWS})
        self.assertEqual(STATUS_UNSUPPORTED, statuses['F5'])
        self.assertEqual(STATUS_UNSUPPORTED, statuses['F6'])
        self.assertEqual({'executable': 4, 'unsupported': 2, 'total': 6},
                         document['counts'])

    def test_f1_compiles_the_declared_boot_region_as_a_fuzzable_image(self):
        path = path_of(compile_document(SOC_RENDER_REQUEST), 'F1')
        image = [row for row in path['sources'] if row['kind'] == 'instruction_image']
        self.assertEqual(1, len(image))
        self.assertEqual('fuzzable', image[0]['origin'])
        self.assertEqual('rom0', image[0]['port'])
        self.assertEqual([0x10000, 0x18000 - 1], image[0]['range'])
        self.assertEqual('instruction_memory_master',
                         [row['function'] for row in path['endpoints']
                          if row['endpoint_id'] == image[0]['endpoint_id']][0])
        self.assertEqual(2, path['seed']['detail']['isa']['instruction_alignment'])
        self.assertEqual('instruction_slot_unmaterialized',
                         path['prerequisites'][0]['kind'])

    def test_f2_keeps_the_real_ip_read_response_bound(self):
        path = path_of(compile_document(SOC_RENDER_REQUEST), 'F2')
        bound = [row for row in path['bound_inputs']
                 if row['kind'] == 'ip_read_response']
        self.assertEqual(1, len(bound))
        self.assertEqual('bound', bound[0]['origin'])
        self.assertEqual('pulp_gpio', bound[0]['component'])
        self.assertNotIn(bound[0]['input_id'],
                         {row['source_id'] for row in path['sources']})
        load = next(row for row in path['sources']
                    if row['kind'] == 'cpu_load_stream')
        self.assertEqual('fuzzable', load['origin'])
        self.assertEqual(0x40000000, load['range'][0])
        producer = next(row['endpoint_id'] for row in path['endpoints']
                        if row['declared_role'] == 'read_response_producer')
        self.assertEqual('gpio.bus', producer)
        self.assertEqual('data_memory_master',
                         next(row['function'] for row in path['endpoints']
                              if row['endpoint_id'] == load['endpoint_id']))

    def test_f4_keeps_the_configured_register_bound_and_the_pins_fuzzable(self):
        path = path_of(compile_document(SOC_RENDER_REQUEST), 'F4')
        kinds = {row['kind']: row for row in path['sources']}
        self.assertIn('cpu_mmio_stream', kinds)
        self.assertIn('external_pin', kinds)
        self.assertEqual('fuzzable', kinds['external_pin']['origin'])
        self.assertEqual(8, kinds['external_pin']['width'])
        register = next(row for row in path['bound_inputs']
                        if row['kind'] == 'ip_register_commit')
        self.assertEqual('bound', register['origin'])
        self.assertIn('CURRENT_DESIGN.md:34', kinds['cpu_mmio_stream']
                      ['constraint_basis'])

    def test_variant_a_the_p7b_wiring_contract_alone_declares_no_executable_path(self):
        document = compile_document(P7B_REQUEST)
        self.assertEqual({'executable': 0, 'unsupported': 6, 'total': 6},
                         document['counts'])
        self.assertEqual(['cpu', 'windows'], document['identity']['wiring']
                         ['declared_sections'])
        self.assertEqual(['resources', 'deliveries', 'environment_links'],
                         document['identity']['wiring']['absent_sections'])
        for flow in EXECUTABLE_FLOWS:
            path = path_of(document, flow)
            self.assertIn('instruction-image-resource-undeclared', missing_codes(path))
            self.assertEqual('/wiring/resources', path['reason']['pointer'])
        self.assertEqual({'interrupt-delivery-missing'},
                         missing_codes(path_of(document, 'F5')))
        self.assertEqual('/wiring/deliveries', path_of(document, 'F5')
                         ['reason']['pointer'])
        self.assertEqual({'dma-master-not-declared'},
                         missing_codes(path_of(document, 'F6')))
        self.assertIsNone(document['runtime_path_contract'])
        self.assertTrue(document['runtime_path_contract_omissions'])

    def test_missing_ip_read_response_is_named_with_a_pointer(self):
        device = load_request(SOC_RENDER_REQUEST)['devices'][0]
        without_sidecar = {key: value for key, value in device.items()
                           if key != 'test_capability'}
        document = compile_document(
            SOC_RENDER_REQUEST,
            devices=[without_sidecar, load_request(SOC_RENDER_REQUEST)['devices'][1]])
        f2 = path_of(document, 'F2')
        self.assertEqual(STATUS_UNSUPPORTED, f2['status'])
        self.assertIn('ip-read-response-missing', missing_codes(f2))
        named = next(row for row in f2['reason']['missing']
                     if row['code'] == 'ip-read-response-missing')
        self.assertEqual('/devices/pulp_gpio/test_capability', named['pointer'])
        self.assertTrue(named['detail']['sidecar_absent']['pulp_gpio'])
        self.assertIn('read-response end of F2 is missing', named['detail']['requires'])
        f4 = path_of(document, 'F4')
        self.assertEqual(STATUS_UNSUPPORTED, f4['status'])
        self.assertIn('writable-field-undeclared', missing_codes(f4))

    def test_declared_irq_route_without_a_declared_producer_is_named(self):
        document = compile_document(SOC_RENDER_REQUEST)
        f5 = path_of(document, 'F5')
        self.assertEqual(STATUS_UNSUPPORTED, f5['status'])
        self.assertIn('interrupt-producer-missing', missing_codes(f5))
        named = next(row for row in f5['reason']['missing']
                     if row['code'] == 'interrupt-producer-missing')
        self.assertEqual('/devices/pulp_gpio/profile/endpoints', named['pointer'])
        self.assertEqual('interrupt', named['detail']['declared_signal'])
        self.assertIn('interrupt_source', named['detail']['requires'])
        self.assertEqual([], f5['sources'])
        self.assertEqual('incomplete', f5['termination_observation']['kind'])

    def test_compile_time_gaps_are_reported_not_silently_dropped(self):
        document = compile_document(P7B_REQUEST)
        codes = {row['code'] for row in document['gaps']}
        self.assertIn('source-width-undeclared', codes)
        for row in document['gaps']:
            self.assertTrue(row['pointer'])
            self.assertIsNotNone(row['detail'])

    def test_compiled_constraints_are_the_shipped_policy_shape(self):
        document = compile_document(SOC_RENDER_REQUEST)
        constraints = document['input_constraints']
        self.assertEqual('soc_input_constraints.v1', constraints['schema_version'])
        self.assertEqual('cpu_execute', constraints['drive_profile'])
        self.assertTrue(constraints['policy_hash'].startswith('sha256:'))
        rules = {row['rule_id']: row for row in constraints['rules']}
        self.assertIn('window:pulp_gpio', rules)
        self.assertEqual('reachable_window', rules['window:pulp_gpio']['primitive'])
        self.assertIn('drive:gpio_in', rules)
        self.assertEqual('environment', rules['drive:gpio_in']['owner'])
        self.assertEqual('runtime', rules['drive:gpio_in']['phase'])
        f4 = path_of(document, 'F4')
        self.assertIn('window:pulp_gpio', f4['constraints']['rule_ids'])
        self.assertEqual(constraints['policy_hash'], f4['constraints']['policy_hash'])

    def test_every_path_carries_its_compiled_mask_range_and_alignment(self):
        document = compile_document(SOC_RENDER_REQUEST)
        for path in document['paths']:
            constraints = path['constraints']
            self.assertEqual(document['input_constraints']['policy_hash'],
                             constraints['policy_hash'])
            basis = {row['source_id']: row
                     for row in constraints['source_constraints']}
            self.assertEqual({row['source_id'] for row in path['sources']},
                             set(basis))
            for row in constraints['source_constraints']:
                self.assertTrue(row['constraint_basis'])
                if row['origin'] == 'fuzzable' and row['kind'] != 'instruction_image':
                    self.assertIsNotNone(row['mask'])
                    self.assertIsNotNone(row['alignment'])
        f1 = path_of(document, 'F1')['constraints']['source_constraints'][0]
        self.assertEqual(0xffffffff, f1['mask'])
        self.assertEqual(2, f1['alignment'])
        self.assertEqual([0x10000, 0x18000 - 1], f1['range'])
        f4 = path_of(document, 'F4')['constraints']['source_constraints']
        mmio = next(row for row in f4 if row['kind'] == 'cpu_mmio_stream')
        self.assertEqual(0xffffffff, mmio['mask'])
        self.assertEqual(4096, mmio['alignment'])
        self.assertEqual([0x40000000, 0x40000fff], mmio['range'])

    def test_compiled_contract_is_consumable_by_the_shipped_runtime_pipeline(self):
        document = compile_document(SOC_RENDER_REQUEST)
        graph = DependencyGraph.from_edge_document(document['runtime_dependency_graph'])
        graph_sha256 = hashlib.sha256(json.dumps(
            graph.edge_document(), sort_keys=True, separators=(',', ':'),
            ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        contract_document = document['runtime_path_contract']
        self.assertEqual(graph_sha256, contract_document['graph_sha256'])
        contract = RuntimePathContract.from_document(contract_document)
        self.assertEqual('runtime_path_contract.v1', contract_document['schema_version'])
        selections = []
        for path in document['paths']:
            identity = path['runtime_path_identity']
            if identity is None:
                continue
            paths = graph.edge_paths_to(path['target']['node'],
                                        direction=identity['direction'])
            self.assertEqual(1, len(paths))
            self.assertEqual(identity['path_id'],
                             graph.path_identity(paths[0],
                                                 direction=identity['direction']))
            selections.append((identity['direction'], paths[0]))
        self.assertEqual(4, len(selections))
        prepared = PreparedRuntimePathContract(graph, contract, tuple(selections))
        self.assertEqual(tuple(row['runtime_path_identity']['path_id']
                               for row in document['paths']
                               if row['runtime_path_identity']), prepared.path_ids)
        relations = [row['relation'] for row in contract_document['edges']]
        self.assertIn('persistent_state', relations)
        self.assertIn('mmio_route', relations)

    def test_document_claims_no_runtime_evidence(self):
        document = compile_document(SOC_RENDER_REQUEST)
        self.assertTrue(document['not_claimed'])
        for path in document['paths']:
            self.assertEqual(['rtl_operational', 'cross_component_accepted',
                              'coverage_guided_searched', 'bug_confirmed'],
                             path['not_claimed'])


class ReservedSourceRefusalTests(unittest.TestCase):
    """Exit criterion 2: an illegal fuzzable claim refuses the compilation."""

    def refuse(self, **overrides):
        with self.assertRaises(PathCompilationError) as caught:
            compile_document(SOC_RENDER_REQUEST, **overrides)
        return caught.exception

    def test_read_only_register_field_declared_fuzzable_is_refused(self):
        error = self.refuse(sources=[{
            'source_id': 'gpio.padin', 'flow_id': 'F2', 'origin': 'fuzzable',
            'component': 'pulp_gpio', 'endpoint_id': 'gpio.bus',
            'register': 'PADIN', 'field': 'value'}])
        self.assertEqual('read-only-register-declared-fuzzable', error.code)
        self.assertEqual('/sources/0/field', error.pointer)
        self.assertEqual('ro', error.detail['declared_register_access'])
        self.assertEqual('ro', error.detail['declared_field_access'])
        self.assertTrue(error.detail['sidecar_fingerprint'].startswith('sha256:'))

    def test_reserved_undeclared_bits_declared_fuzzable_are_refused(self):
        error = self.refuse(sources=[{
            'source_id': 'gpio.reserved', 'flow_id': 'F2', 'origin': 'fuzzable',
            'component': 'pulp_gpio', 'endpoint_id': 'gpio.bus',
            'register': 'PADDIR', 'field': 'reserved'}])
        self.assertEqual('undeclared-register-field', error.code)
        self.assertEqual('/sources/0/field', error.pointer)
        self.assertIn('PADDIR', error.detail['register'])

    def test_dut_driven_output_pin_declared_fuzzable_is_refused(self):
        error = self.refuse(sources=[{
            'source_id': 'gpio.out', 'flow_id': 'F4', 'origin': 'fuzzable',
            'component': 'pulp_gpio', 'endpoint_id': 'gpio.pins', 'role': 'out'}])
        self.assertEqual('output-field-declared-fuzzable', error.code)
        self.assertEqual('/sources/0/role', error.pointer)
        self.assertEqual('output', error.detail['declared_direction'])

    def test_declared_protocol_role_declared_fuzzable_is_refused(self):
        error = self.refuse(sources=[{
            'source_id': 'gpio.paddr', 'flow_id': 'F4', 'origin': 'fuzzable',
            'component': 'pulp_gpio', 'endpoint_id': 'gpio.bus', 'role': 'paddr'}])
        self.assertEqual('output-field-declared-fuzzable', error.code)
        self.assertIsNone(error.detail['declared_direction'])

    def test_cpu_irq_entry_declared_fuzzable_is_refused(self):
        error = self.refuse(sources=[{
            'source_id': 'cpu.irq', 'flow_id': 'F5', 'origin': 'fuzzable',
            'component': 'ibex', 'endpoint_id': 'processor.interrupts',
            'role': 'external'}])
        self.assertEqual('cpu-irq-cannot-be-a-fuzzable-source', error.code)
        self.assertEqual('/sources/0', error.pointer)
        self.assertIn('source_actions.py:448', error.detail['rule'])

    def test_unknown_field_role_is_refused_with_the_declared_roles(self):
        error = self.refuse(sources=[{
            'source_id': 'gpio.nope', 'flow_id': 'F4', 'origin': 'fuzzable',
            'component': 'pulp_gpio', 'endpoint_id': 'gpio.pins', 'role': 'nope'}])
        self.assertEqual('unknown-endpoint-field-role', error.code)
        self.assertIn('out', error.detail['declared_roles'])

    def test_bound_claim_on_a_read_only_field_is_accepted_and_stays_bound(self):
        document = compile_document(SOC_RENDER_REQUEST, sources=[{
            'source_id': 'gpio.padin.bound', 'flow_id': 'F2', 'origin': 'bound',
            'component': 'pulp_gpio', 'endpoint_id': 'gpio.bus',
            'register': 'PADIN', 'field': 'value'}])
        claim = document['declared_source_claims'][0]
        self.assertEqual('bound', claim['claim']['origin'])
        self.assertEqual('PADIN', claim['resolved']['register'])
        self.assertEqual([], document['declared_register_field_constraints'])
        self.assertNotIn('drive:gpio.bus:PADIN.value',
                         [row['rule_id'] for row in document['input_constraints']
                          ['rules']])

    def test_legal_writable_register_claim_compiles_as_an_mmio_constraint(self):
        document = compile_document(SOC_RENDER_REQUEST, sources=[{
            'source_id': 'gpio.paddir', 'flow_id': 'F4', 'origin': 'fuzzable',
            'component': 'pulp_gpio', 'endpoint_id': 'gpio.bus',
            'register': 'PADDIR', 'field': 'value', 'mask': 0xffff}])
        f4 = path_of(document, 'F4')
        self.assertEqual(STATUS_EXECUTABLE, f4['status'])
        claim, = f4['constraints']['register_field_constraints']
        self.assertEqual('PADDIR', claim['register'])
        self.assertEqual(0, claim['lsb'])
        self.assertEqual(32, claim['width'])
        self.assertEqual(0xffffffff, claim['write_mask'])
        self.assertIn('CURRENT_DESIGN.md:34', claim['constraint_basis'])
        self.assertEqual([], [row['rule_id'] for row in document['input_constraints']
                              ['rules'] if 'PADDIR' in row['rule_id']])


class NoNameBranchingTests(unittest.TestCase):
    """The P7 gate: compilation must read capabilities, never names."""

    def declared_names(self):
        profiles = sorted((ROOT / 'configs').glob('*/*/component_profile.json'))
        self.assertGreater(len(profiles), 10)
        component_ids, endpoint_ids, register_names = set(), set(), set()
        for path in profiles:
            document = json.loads(path.read_text(encoding='utf-8'))
            component_ids.add(document['component_id'])
            for endpoint in document.get('endpoints', ()):
                endpoint_ids.add(endpoint['endpoint_id'])
            address = document.get('address') or {}
            for register in address.get('registers', ()):
                register_names.add(register['name'])
        self.assertGreater(len(component_ids), 5)
        self.assertGreater(len(register_names), 10)
        return component_ids, endpoint_ids, register_names

    def module_constants(self):
        """Every non-docstring string constant of the compiler module."""
        tree = parse(MODULE_PATH.read_text(encoding='utf-8'))
        docstrings = set()
        for node in walk(tree):
            if isinstance(node, (Module, ClassDef, FunctionDef, AsyncFunctionDef)):
                body = getattr(node, 'body', ())
                if body and isinstance(body[0], Expr) and isinstance(body[0].value,
                                                                    Constant):
                    docstrings.add(id(body[0].value))
        return tree, [node.value for node in walk(tree)
                      if isinstance(node, Constant) and isinstance(node.value, str)
                      and id(node) not in docstrings]

    def test_no_declared_component_endpoint_or_register_name_is_hardcoded(self):
        component_ids, endpoint_ids, register_names = self.declared_names()
        _, constants = self.module_constants()
        literal = set(constants)
        self.assertEqual(set(), literal & component_ids,
                         'a component id is hardcoded in the compiler')
        self.assertEqual(set(), literal & endpoint_ids,
                         'an endpoint id is hardcoded in the compiler')
        self.assertEqual(set(), literal & register_names,
                         'a register name is hardcoded in the compiler')
        for value in constants:
            for fragment in value.replace('\n', ' ').split():
                self.assertNotIn(fragment.strip('.,;:()'), component_ids)
                self.assertNotIn(fragment.strip('.,;:()'), register_names)

    def test_a_declared_identity_is_never_compared_against_a_literal(self):
        """Identity lookups are fine; literal dispatch on an identity is not.

        ``profile.component_id in by_component_id`` matches a declaration to the
        profile carrying the same declared id, which is the sanctioned identity
        match.  ``component_id == 'ibex'`` would be name-based branching.  This
        test separates the two by requiring a literal on the other side.
        """
        tree, _ = self.module_constants()
        del tree  # only the constants are needed here
        tree, _ = self.module_constants()
        offenders = []
        for node in walk(tree):
            if not isinstance(node, Compare):
                continue
            sides = (node.left, *node.comparators)
            for side in sides:
                if not isinstance(side, Attribute):
                    continue
                if side.attr not in ('component_id', 'component', 'endpoint_id',
                                     'field', 'register', 'role', 'port', 'name'):
                    continue
                for other in sides:
                    if other is side or isinstance(other, Attribute):
                        continue
                    if isinstance(other, Constant) and isinstance(other.value, str):
                        offenders.append((node.lineno, side.attr, other.value))
        self.assertEqual([], offenders)

    def test_the_module_never_infers_semantics_from_a_port_or_signal_name(self):
        """No `.endpoint_id ==`/`.port ==`/`.name ==` literal dispatch either."""
        tree, _ = self.module_constants()
        allowed = {'endpoint_id', 'role', 'register', 'field', 'function',
                   'component', 'flow_id', 'origin', 'source_id', 'declared'}
        offenders = []
        for node in walk(tree):
            if not isinstance(node, Compare):
                continue
            for side in (node.left, *node.comparators):
                if isinstance(side, Attribute) and side.attr in (
                        'endpoint_id', 'field', 'register', 'role', 'function'):
                    for other in (node.left, *node.comparators):
                        if other is side:
                            continue
                        if isinstance(other, Constant) and other.value not in (
                                None, True, False) and other.value not in allowed:
                            if isinstance(other.value, str) and other.value not in (
                                    'ro', 'wo', 'rw', 'none', 'input', 'output',
                                    'level', 'pulse'):
                                offenders.append((node.lineno, side.attr, other.value))
        self.assertEqual([], offenders)

    def test_role_tokens_come_from_the_profile_schema(self):
        from myfuzz.composition.component_profile import FUNCTION_DIRECTIONS
        from myfuzz.scenario import compiled_paths
        for token in (compiled_paths.FUNCTION_INSTRUCTION_MASTER,
                      compiled_paths.FUNCTION_DATA_MASTER,
                      compiled_paths.FUNCTION_MMIO_SLAVE,
                      compiled_paths.FUNCTION_INTERRUPT_SOURCE,
                      compiled_paths.FUNCTION_INTERRUPT_ENTRY,
                      compiled_paths.FUNCTION_EXTERNAL_PINS):
            self.assertIn(token, FUNCTION_DIRECTIONS)
        self.assertEqual({'instruction_memory_master', 'data_memory_master',
                          'processor_memory_master', 'memory_master'},
                         set(compiled_paths.MASTER_FUNCTIONS))


# ---------------------------------------------------------------------------
# test-only declared facts
#
# No component in the repository declares an ``interrupt_source`` endpoint
# together with a capability sidecar carrying a readable status field, and none
# declares a ``transfer`` feature operation, so no real composition can make F5
# or F6 executable today.  The declarations below are *test-only* documents that
# are internally consistent (the sidecar is bound to the profile fingerprint the
# shipped loader computes) and are used to prove the compiler really handles the
# declared facts instead of hardcoding a refusal.  They are not shipped configs.
# ---------------------------------------------------------------------------


def probe_profile(component_id, *, irq=False, transfer=False):
    endpoints = [
        {'endpoint_id': f'{component_id}.bus', 'function': 'mmio_slave',
         'protocol': ['apb', '3'],
         'fields': [{'role': role} for role in
                    ('paddr', 'psel', 'penable', 'pwrite', 'pwdata', 'pready',
                     'prdata', 'pslverr')]},
        {'endpoint_id': f'{component_id}.pins', 'function': 'external_pins',
         'fields': [{'role': 'in', 'direction': 'input',
                     'aliases': [f'{component_id}_pin_i']}]},
    ]
    if irq:
        endpoints.append({'endpoint_id': f'{component_id}.irq',
                          'function': 'interrupt_source',
                          'fields': [{'role': 'irq',
                                      'aliases': [f'{component_id}_irq_o']}]})
    if transfer:
        endpoints.append({'endpoint_id': f'{component_id}.master',
                          'function': 'memory_master', 'protocol': ['obi', '1'],
                          'fields': [{'role': 'req', 'aliases': [f'{component_id}_req_o']},
                                     {'role': 'addr', 'aliases': [f'{component_id}_addr_o']}]})
    document = {
        'schema_version': 'component_profile.v1', 'component_id': component_id,
        'kind': 'peripheral', 'description': 'test-only declared probe device',
        'source': {'root': 'tests/fixtures/probe',
                   'revision': 'sha256:' + 'a' * 64, 'top_module': 'probe_top',
                   'files': ['probe_top.sv']},
        'endpoints': endpoints,
        'address': {'window_size': 4096, 'alignment': 4096,
                    'registers': [{'name': 'STATUS', 'offset': 0, 'width': 32,
                                   'access': 'rw', 'side_effect': 'none'}]},
        'capabilities': {'address_width': 12, 'data_width': 32, 'read': True,
                         'write': True},
        'clocks': [{'port': 'clk_i', 'domain': 'core', 'frequency_hz': 50000000}],
        'resets': [{'port': 'rst_ni', 'domain': 'sys_rst', 'polarity': 'active_low',
                    'synchronous': False}],
    }
    if irq:
        document['interrupts'] = [{
            'endpoint_id': f'{component_id}.irq', 'role': 'irq', 'bit': 0,
            'polarity': 'active_high', 'trigger': 'level', 'clock_domain': 'core',
            'hold': 'held until STATUS is read', 'clear': 'read of STATUS',
            'source_id': f'{component_id}_irq_o'}]
    return document


def probe_sidecar(profile, component_id, *, transfer=False):
    document = {
        'schema_version': ('ip_test_capability.v2' if transfer
                           else 'ip_test_capability.v1'),
        'component_id': component_id,
        'profile_fingerprint': profile.profile_fingerprint,
        'endpoint_capabilities': [{
            'endpoint_id': f'{component_id}.bus',
            'operations': ['request', 'accept', 'response', 'read', 'write', 'wait']}],
        'register_semantics': [{
            'register': 'STATUS', 'field': 'value', 'lsb': 0, 'width': 32,
            'access': 'rw', 'read_mask': 0xffffffff, 'write_mask': 0xffffffff,
            'side_effect': 'none', 'evidence_ref': 'test:probe', 'reset_value': 0}],
        'observation_mappings': [{
            'mapping_id': 'probe-pin-sample',
            'endpoint_id': f'{component_id}.pins', 'role': 'in',
            'observation_kind': 'input_sample', 'evidence_ref': 'test:probe'}],
    }
    if transfer:
        document['endpoint_capabilities'].append({
            'endpoint_id': f'{component_id}.master',
            'operations': ['request', 'accept', 'response', 'read', 'write']})
        document['observation_mappings'].append({
            'mapping_id': 'probe-master-sample',
            'endpoint_id': f'{component_id}.master', 'role': 'addr',
            'observation_kind': 'port_sample', 'evidence_ref': 'test:probe'})
        document['feature_contract'] = {
            'provider_id': 'probe-mover', 'provider_version': '1',
            'operations': [{
                'endpoint_id': f'{component_id}.master', 'operation': 'transfer',
                'required_observation_mappings': ['probe-master-sample'],
                'evidence_ref': 'test:probe'}]}
    return document


def probe_device(component_id, **kwargs):
    from myfuzz.composition.component_profile import load_component_profile
    from myfuzz.composition.test_capability import load_ip_test_capability
    profile = load_component_profile(probe_profile(component_id, **kwargs))
    capability = load_ip_test_capability(
        probe_sidecar(profile, component_id, transfer=kwargs.get('transfer', False)),
        profile=profile)
    return PathComponent(component_id, profile, capability, ())


def probe_wiring(devices):
    return load_path_wiring({
        'schema_version': 'path_wiring.v1',
        'cpu': {'instance_id': 'ibex', 'data_endpoint': 'processor.data'},
        'windows': [{'device_id': row.instance_id,
                     'target_instance': row.instance_id,
                     'base': 0x40000000 + 0x1000 * index, 'size': 0x1000,
                     'endpoint_id': f'{row.instance_id}.bus'}
                    for index, row in enumerate(devices)],
        'resources': [
            {'resource_id': 'rom0', 'component_instance': 'ibex', 'base': 0x10000,
             'size': 0x8000, 'read': True, 'write': False, 'execute': True,
             'initialization_policy': 'preload'},
            {'resource_id': 'ram0', 'component_instance': 'ibex', 'base': 0x80000000,
             'size': 0x10000, 'read': True, 'write': True, 'execute': True,
             'initialization_policy': 'on_demand'}],
        'deliveries': [{'delivery_id': 'probe_a_irq', 'producer_instance': 'probe_a',
                        'producer_endpoint_id': 'probe_a.irq',
                        'consumer_instance': 'ibex',
                        'consumer_endpoint_id': 'processor.interrupts',
                        'trigger': 'level'}],
        'environment_links': [{'link_id': f'{row.instance_id}_pins',
                              'component_instance': row.instance_id,
                              'endpoint_id': f'{row.instance_id}.pins',
                              'width': 8, 'event_kind': 'edge'}
                              for row in devices]})


def real_cpu_component():
    from myfuzz.composition.component_profile import load_component_profile
    document = json.loads((ROOT / 'configs/cpus/ibex/component_profile.json')
                          .read_text(encoding='utf-8'))
    return PathComponent('ibex', load_component_profile(document), None, ())


class DeclaredFactTests(unittest.TestCase):
    """The compiler follows the declarations in both directions."""

    def compile_probe(self):
        devices = (probe_device('probe_a', irq=True),
                   probe_device('probe_mover', transfer=True))
        request = PathCompileRequest(real_cpu_component(), devices,
                                     probe_wiring(devices), {},
                                     'processor.data', 'processor.instruction')
        return compile_paths(request)

    def test_all_six_flows_are_executable_when_every_fact_is_declared(self):
        document = self.compile_probe()
        self.assertEqual({'executable': 6, 'unsupported': 0, 'total': 6},
                         document['counts'])
        for path in document['paths']:
            self.assertEqual(STATUS_EXECUTABLE, path['status'])
            self.assertEqual([], path['reason']['missing'])
            self.assertIsNone(path['reason']['code'])

    def test_f5_keeps_the_irq_bound_on_both_ends(self):
        path = path_of(self.compile_probe(), 'F5')
        kinds = {row['kind']: row for row in path['bound_inputs']}
        self.assertEqual({'ip_irq', 'cpu_irq_input'}, set(kinds))
        self.assertEqual({'bound'}, {row['origin'] for row in path['bound_inputs']})
        self.assertIn('source_actions.py:68,448', kinds['cpu_irq_input']['basis'])
        self.assertEqual('delivery', path['termination_observation']['kind'])
        self.assertEqual('irq_input_delivered', path['prerequisites'][0]['kind'])
        self.assertEqual(DIRECTION_IP_SOURCED, path['direction'])

    def test_f6_needs_a_declared_transfer_provider_and_names_the_route_gap(self):
        document = self.compile_probe()
        path = path_of(document, 'F6')
        self.assertEqual(STATUS_UNSUPPORTED,
                         path_of(compile_document(SOC_RENDER_REQUEST), 'F6')['status'])
        descriptor, = [row for row in path['sources']
                       if row['kind'] == 'dma_transfer_descriptor']
        self.assertEqual('feature:probe-mover', descriptor['origin_ref'])
        omissions = {row['code']: row
                     for row in document['runtime_path_contract_omissions']}
        self.assertIn('dma-master-route-undeclared', omissions)
        self.assertEqual('F6', omissions['dma-master-route-undeclared']['detail']
                         ['flow_id'])
        self.assertIn('interrupt-physical-ends-undeclared', omissions)

    def test_a_path_wider_wiring_never_upgrades_an_undeclared_flow(self):
        without = probe_device('probe_plain')
        request = PathCompileRequest(real_cpu_component(), (without,),
                                     probe_wiring((without,)), {},
                                     'processor.data', 'processor.instruction')
        document = compile_paths(request)
        statuses = {row['flow_id']: row['status'] for row in document['paths']}
        self.assertEqual(STATUS_UNSUPPORTED, statuses['F5'])
        self.assertEqual(STATUS_UNSUPPORTED, statuses['F6'])
        self.assertEqual({'interrupt-producer-missing'},
                         missing_codes(path_of(document, 'F5')))


class RequestLoadingTests(unittest.TestCase):
    """The request is a closed declaration; conflicts are refused, not merged."""

    def test_a_supplement_contradicting_the_wiring_is_refused(self):
        with self.assertRaises(PathCompilationError) as caught:
            compile_document(SOC_RENDER_REQUEST,
                             memory=[{'resource_id': 'rom0', 'base': 0}])
        self.assertEqual('wiring-resource-conflict', caught.exception.code)
        self.assertEqual('/memory/0/base', caught.exception.pointer)

    def test_the_memory_supplement_is_what_names_the_serving_instance(self):
        document = compile_document(SOC_RENDER_REQUEST)
        path = path_of(document, 'F1')
        self.assertEqual('ibex', path['sources'][0]['component'])
        self.assertEqual(0x10000, path['sources'][0]['range'][0])
        # The render profile declares the region but not who serves it, so
        # without the supplement the same region cannot become an image source.
        without = path_of(compile_document(SOC_RENDER_REQUEST, memory=[]), 'F1')
        self.assertEqual(STATUS_UNSUPPORTED, without['status'])
        self.assertEqual({'memory-serving-component-undeclared'},
                         missing_codes(without))
        self.assertEqual('/wiring/resources', without['reason']['pointer'])

    def test_an_unknown_wiring_schema_is_refused(self):
        with self.assertRaises(PathCompilationError) as caught:
            compile_document(SOC_RENDER_REQUEST,
                             wiring={'schema_version': 'made-up.v9'})
        self.assertEqual('unsupported-wiring-schema', caught.exception.code)

    def test_a_cpu_profile_without_a_cpu_contract_is_refused(self):
        with self.assertRaises(PathCompilationError) as caught:
            compile_document(P7B_REQUEST, cpu={
                'instance_id': 'cpu',
                'profile': 'configs/peripherals/pulp_gpio/component_profile.json'})
        self.assertEqual('component-declares-no-cpu-contract', caught.exception.code)

    def test_a_source_claim_for_an_undeclared_instance_is_refused(self):
        with self.assertRaises(PathCompilationError) as caught:
            compile_document(P7B_REQUEST, sources=[{
                'source_id': 'x', 'flow_id': 'F1', 'origin': 'fuzzable',
                'component': 'nope', 'endpoint_id': 'gpio.pins', 'role': 'in'}])
        self.assertEqual('source-component-undeclared', caught.exception.code)

    def test_compilation_does_not_mutate_the_request_document(self):
        request = load_request(SOC_RENDER_REQUEST)
        snapshot = copy.deepcopy(request)
        compile_paths(load_path_compile_request(request, base_dir=ROOT))
        self.assertEqual(snapshot, request)


class TwoInstancesOfOneProfileTests(unittest.TestCase):
    """Two instances of the same profile must both be laid out.

    Both shipped dual-source runtime families wire exactly ``cpu`` plus two PULP
    GPIO instances, so this is the composition shape the end-to-end driver has to
    compile.  The layout annotation used to key its duplicate check by
    ``(endpoint_id, role)`` alone, which made the *second instance of one profile*
    look like a duplicate declaration and refused the whole compilation with
    ``duplicate-layout-field``.

    These use the real composition and the real generator, because that is the
    path the end-to-end driver takes.
    """

    def request_from_generated_set(self, output):
        from myfuzz.local_harness.harness_set import (generate_harness_set,
                                                      load_compose)
        base = ROOT / 'configs' / 'scenarios' / 'ibex-pulp-dual-gpio'
        compose = load_compose(base / 'compose.json', base_dir=ROOT)
        document = generate_harness_set(compose, base_dir=ROOT, compose_base=base,
                                        output_root=output)
        self.assertEqual('generated', document['tier'])
        wiring = output / 'wiring_contract.json'
        self.assertTrue(wiring.is_file())
        return {
            'schema_version': 'path_compile_request.v1',
            'cpu': {'instance_id': 'cpu',
                    'profile': 'configs/cpus/ibex_obi_local/component_profile.json',
                    'data_endpoint': 'processor.data',
                    'instruction_endpoint': 'processor.instruction'},
            'devices': [
                {'device_id': name, 'instance_id': name,
                 'profile': 'configs/peripherals/pulp_gpio/component_profile.json',
                 'test_capability':
                     'configs/peripherals/pulp_gpio/test_capability.json'}
                for name in ('gpio_a', 'gpio_b')],
            'wiring': {'source': str(wiring)},
        }

    def test_two_instances_of_one_profile_compile(self):
        with tempfile.TemporaryDirectory(prefix='two-instances-',
                                         dir=ROOT / 'runs') as tmp:
            request = self.request_from_generated_set(Path(tmp) / 'generated')
            document = compile_paths(
                load_path_compile_request(request, base_dir=ROOT))
        self.assertEqual({'executable': 4, 'unsupported': 2, 'total': 6},
                         document['counts'])
        f4 = path_of(document, 'F4')
        self.assertEqual(STATUS_EXECUTABLE, f4['status'])
        self.assertNotIn('duplicate-layout-field', missing_codes(f4))
        # Both device instances really contribute their declared input fields.
        self.assertEqual(2, len(f4['sources']),
                         'each device instance must be its own source')

    def test_gap_pointers_name_the_instance_not_only_the_profile(self):
        """Two instances of one profile must be distinguishable in the report.

        ``pulp_gpio``'s declared input pin width is not fixed by anything, so both
        instances produce a ``source-width-undeclared`` gap.  Before the pointer
        carried the instance, both gaps pointed at the identical string
        ``profile:pulp_gpio:endpoints:gpio.pins:fields:in``, which cannot say which
        of the two a reader must fix.
        """
        with tempfile.TemporaryDirectory(prefix='instance-pointer-',
                                         dir=ROOT / 'runs') as tmp:
            request = self.request_from_generated_set(Path(tmp) / 'generated')
            document = compile_paths(
                load_path_compile_request(request, base_dir=ROOT))
        pointers = [gap['pointer'] for gap in document['gaps']
                    if gap['code'] == 'source-width-undeclared']
        self.assertEqual(2, len(pointers), document['gaps'])
        self.assertEqual(len(set(pointers)), len(pointers),
                         'gap pointers must not collide across instances')
        self.assertIn('profile:pulp_gpio:instance:gpio_a:endpoints:gpio.pins:fields:in',
                      pointers)
        self.assertIn('profile:pulp_gpio:instance:gpio_b:endpoints:gpio.pins:fields:in',
                      pointers)

    def test_two_different_profiles_with_distinct_ports_both_lay_out(self):
        """The scope of the fix: distinct input ports are laid out side by side.

        This records where the port-identity check does *not* fire.  ``pulp_gpio``
        and ``pulp_i2c`` are different components, but their only declared input
        fields are their own pin ports (``gpio_in`` versus ``scl_pad_i`` /
        ``sda_pad_i``); their shared APB names (PADDR/PSEL/...) are not input
        fields, so nothing here collides.  A real collision needs two profiles
        whose *input* port names coincide, which the shipped peripheral library
        does not currently contain - so this test pins the negative space rather
        than pretending to exercise ``duplicate-input-port``.
        """
        from myfuzz.composition.component_profile import load_component_profile
        from myfuzz.scenario.compiled_paths import (PathWiring,
                                                    WiringEnvironmentLink,
                                                    _layout_annotations)

        def component(instance_id, path):
            profile = load_component_profile(
                json.loads((ROOT / path).read_text(encoding='utf-8')))
            return PathComponent(instance_id, profile)

        wiring = PathWiring(
            'path_wiring.v1', 'cpu', None,
            environment_links=(
                WiringEnvironmentLink('pins_gpio', 'gpio', 'gpio.pins', 8,
                                      'external_pin', 'path_wiring.v1'),
                WiringEnvironmentLink('pins_i2c', 'i2c', 'i2c.pins', 1,
                                      'external_pin', 'path_wiring.v1')))
        endpoints, gaps = _layout_annotations(
            (component('gpio', PULP_GPIO_PROFILE),
             component('i2c', PULP_I2C_PROFILE)), wiring)
        self.assertEqual([], gaps)
        ports = sorted(row['port'] for endpoint in endpoints
                       for row in endpoint['fields'])
        self.assertEqual(['gpio_in', 'scl_pad_i', 'sda_pad_i'], ports)

    def test_the_same_profile_twice_is_not_a_collision(self):
        """The discriminator: one profile twice compiles, two profiles collides."""
        with tempfile.TemporaryDirectory(prefix='same-profile-',
                                         dir=ROOT / 'runs') as tmp:
            request = self.request_from_generated_set(Path(tmp) / 'generated')
            document = compile_paths(
                load_path_compile_request(request, base_dir=ROOT))
        # Both instances of the one profile are laid out, so F4 names both.
        f4 = path_of(document, 'F4')
        self.assertEqual(STATUS_EXECUTABLE, f4['status'])
        self.assertEqual(2, len(f4['sources']))


if __name__ == '__main__':  # pragma: no cover
    unittest.main()
