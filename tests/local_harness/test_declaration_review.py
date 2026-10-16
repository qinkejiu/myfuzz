"""P7-A: the declaration reviewer admits correct profiles and refuses the rest.

The positive half is a regression guard: the reviewer once synthesised its own
ABI, labelled every field ``functional`` and therefore reported the functional
bus ports of a bound endpoint (PADDR/PSEL/PWDATA ...) as unowned physical inputs.
Every assertion about ownership below reads names the composition's own
disposition ledger produced, never a name this test guessed.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))

from myfuzz.local_harness.declaration_review import review_profiles


#: Repository profiles the plan requires to be admitted as they stand. The
#: fifth one is included because its declared reset is active-high: the reviewer
#: used to refuse that as unsupported even though
#: tests/local_harness/test_multiclock_runtime.py pins the rendered active-high
#: reset domain (`= reset_aon;`, no inversion).
REPOSITORY_PROFILES = (
    'configs/peripherals/pulp_gpio/component_profile.json',
    'configs/peripherals/zipcpu_axiluart/component_profile.json',
    'configs/peripherals/zipcpu_uart/component_profile.json',
    'configs/cpus/ibex_obi_local/component_profile.json',
    'configs/cpus/cva6/component_profile.json',
)

#: Small profile the negative fixtures are derived from.
FIXTURE_SOURCE = 'configs/peripherals/zipcpu_axiluart/component_profile.json'
#: Profile with declared port actions, used for the unclassified-port fixture.
ACTION_SOURCE = 'configs/cpus/ibex_obi_local/component_profile.json'


def _document(path: str) -> dict:
    return json.loads((ROOT / path).read_text(encoding='utf-8'))


def _resolve_pointer(document, pointer: str):
    """Walk a JSON pointer, failing the test when it does not locate a node."""
    node = document
    if pointer == '':
        return node
    assert pointer.startswith('/'), f'pointer is not absolute: {pointer!r}'
    for token in pointer.split('/')[1:]:
        token = token.replace('~1', '/').replace('~0', '~')
        if isinstance(node, list):
            assert token.isdigit() and int(token) < len(node), \
                f'{pointer!r} does not locate a list element in the profile'
            node = node[int(token)]
        elif isinstance(node, dict):
            assert token in node, f'{pointer!r} does not locate a key in the profile'
            node = node[token]
        else:
            raise AssertionError(f'{pointer!r} walks into a scalar')
    return node


def _rows(component, code: str):
    return [row for row in component['rows'] if row['code'] == code]


class RepositoryProfileReviewTests(unittest.TestCase):
    """Every correct repository profile is admitted, and nothing is invented."""

    @classmethod
    def setUpClass(cls):
        cls.review = review_profiles(REPOSITORY_PROFILES, base_dir=ROOT)
        cls.components = {component['component_id']: component
                          for component in cls.review['components']}

    def test_every_repository_profile_reports_ok(self):
        self.assertEqual(
            'ok', self.review['status'],
            [(component['component_id'],
              [(row['status'], row['code'], row['pointer'])
               for row in component['rows'] if row['status'] != 'ok'])
             for component in self.review['components']])
        self.assertEqual([], self.review['refused'])
        self.assertEqual(['cva6', 'ibex_obi_local', 'pulp_gpio', 'zipcpu_axiluart',
                          'zipcpu_uart'],
                         sorted(self.review['admitted']))
        for component in self.review['components']:
            for row in component['rows']:
                self.assertEqual('ok', row['status'],
                                 f"{component['component_id']}: {row['code']}")

    def test_the_review_never_generates_a_harness(self):
        self.assertEqual('declaration_review.v1', self.review['schema_version'])
        self.assertIs(False, self.review['generated'])

    def test_every_pointer_locates_a_path_in_the_profile_document(self):
        for component in self.review['components']:
            document = _document(component['profile_path'])
            pointers = {row['pointer'] for row in component['rows']}
            self.assertIn('/source', pointers)
            self.assertIn('/clocks', pointers)
            self.assertIn('/resets', pointers)
            self.assertIn('/endpoints', pointers)
            for pointer in pointers:
                _resolve_pointer(document, pointer)

    def test_functional_bus_ports_are_not_reported_as_unowned_inputs(self):
        """The confirmed defect: a bound bus endpoint's inputs are owned."""
        ownership = _rows(self.components['pulp_gpio'], 'physical-inputs-owned')[0]
        self.assertEqual('ok', ownership['status'])
        self.assertEqual('/endpoints', ownership['pointer'])
        detail = ownership['detail']
        # The ledger classified the APB roles as functional - the reviewer read
        # the ledger instead of calling every field functional itself.
        self.assertIn('PADDR', ' '.join(detail['functional_inputs']))
        self.assertIn('PSEL', ' '.join(detail['functional_inputs']))
        self.assertIn('PWRITE', ' '.join(detail['functional_inputs']))
        # gpio_in is the one real external input of that profile.
        self.assertIn('gpio_in', ' '.join(detail['environment_inputs']))
        self.assertNotIn('gpio_in', ' '.join(detail['functional_inputs']))
        for code in ('physical-input-unowned', 'physical-abi-required'):
            self.assertEqual([], _rows(self.components['pulp_gpio'], code))
        self.assertEqual([], _rows(self.components['zipcpu_axiluart'],
                                   'physical-input-unowned'))
        self.assertEqual([], _rows(self.components['ibex_obi_local'],
                                   'physical-input-unowned'))
        self.assertEqual([], _rows(self.components['cva6'],
                                   'physical-input-unowned'))
        # The ledger's own classes are the only owner names reported.
        self.assertEqual({'constant', 'external', 'functional'},
                         set(detail['owner_classes']))

    def test_external_and_constant_inputs_keep_their_ledger_class(self):
        detail = _rows(self.components['zipcpu_axiluart'],
                       'physical-inputs-owned')[0]['detail']
        self.assertIn('i_uart_rx', ' '.join(detail['environment_inputs']))
        self.assertIn('i_cts_n', ' '.join(detail['environment_inputs']))
        self.assertIn('functional', detail['owner_classes'])
        cva6 = _rows(self.components['cva6'], 'physical-inputs-owned')[0]['detail']
        self.assertIn('time_irq_i', ' '.join(cva6['fuzz_inputs']))
        self.assertIn('boot_addr_i', ' '.join(cva6['constant_inputs']))

    def test_an_active_high_reset_is_admitted(self):
        """Both declared polarities are drivable; only the declaration is read.

        The local top declares its own reset high-active and the port renderer
        inverts for an active-low declaration, which
        tests/local_harness/test_multiclock_runtime.py already pins. The
        reviewer used to call every active-high reset unsupported.
        """
        reset = _rows(self.components['zipcpu_uart'], 'reset-bindings-declared')[0]
        self.assertEqual('ok', reset['status'])
        self.assertEqual('/resets', reset['pointer'])
        self.assertEqual('active_high', reset['detail']['resets'][0]['polarity'])
        self.assertEqual('i_reset', reset['detail']['resets'][0]['port'])

    def test_interrupt_form_is_never_inferred_from_a_port_name(self):
        """pulp_gpio has a port named ``interrupt`` and declares no IRQ form."""
        component = self.components['pulp_gpio']
        document = _document('configs/peripherals/pulp_gpio/component_profile.json')
        ports = {action['port'] for action in document['port_actions']}
        self.assertIn('interrupt', ports)
        self.assertEqual([], document['interrupts'])
        interrupt = _rows(component, 'no-interrupts-declared')[0]
        self.assertEqual('ok', interrupt['status'])
        self.assertEqual('', interrupt['pointer'])
        self.assertEqual([], _rows(component, 'interrupt-form-declared'))


class RefusalTests(unittest.TestCase):
    """A missing declaration is located and refuses generation."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)

    def _mutated(self, source: str, name: str, mutate) -> Path:
        document = _document(source)
        mutate(document)
        path = Path(self.temporary.name) / name
        path.write_text(json.dumps(document, indent=2), encoding='utf-8')
        return path

    def _review(self, path: Path) -> dict:
        return review_profiles([path], base_dir=ROOT)

    def test_a_port_with_no_declaration_is_located_and_refuses_generation(self):
        def drop_test_en(document):
            document['port_actions'] = [action for action in document['port_actions']
                                        if action['port'] != 'test_en_i']
        path = self._mutated(ACTION_SOURCE, 'ibex-no-test-en.json', drop_test_en)
        review = self._review(path)
        self.assertIs(False, review['generated'])
        self.assertEqual('refused', review['status'])
        self.assertEqual(['ibex_obi_local'], review['refused'])
        component = review['components'][0]
        self.assertNotEqual('ok', component['status'])
        rows = _rows(component, 'port-bits-undisposed')
        self.assertEqual(1, len(rows))
        self.assertEqual('missing', rows[0]['status'])
        self.assertEqual('/port_actions', rows[0]['pointer'])
        self.assertIn('test_en_i', rows[0]['detail']['reason'])
        self.assertEqual(
            'myfuzz.composition.soc_port_dispositions.build_port_dispositions',
            rows[0]['detail']['code_path'])
        document = _document(ACTION_SOURCE)
        _resolve_pointer(document, rows[0]['pointer'])

    def test_an_interrupt_endpoint_without_a_declared_form_is_refused(self):
        def drop_interrupts(document):
            document['interrupts'] = []
        path = self._mutated(FIXTURE_SOURCE, 'uart-no-interrupt-form.json',
                             drop_interrupts)
        review = self._review(path)
        self.assertIs(False, review['generated'])
        self.assertEqual(['zipcpu_axiluart'], review['refused'])
        rows = _rows(review['components'][0], 'interrupt-form-undeclared')
        self.assertEqual(1, len(rows))
        self.assertEqual('missing', rows[0]['status'])
        self.assertEqual('/interrupts', rows[0]['pointer'])
        self.assertEqual(['uart.interrupts'], rows[0]['detail']['endpoints'])
        _resolve_pointer(_document(FIXTURE_SOURCE), rows[0]['pointer'])

    def test_an_edge_triggered_interrupt_is_unsupported_not_driven(self):
        """An admitted-by-the-loader shape this harness has no path for.

        ``INTERRUPT_TRIGGERS`` also has the edge kinds, so this profile loads;
        the reviewer still refuses to drive it instead of treating the line as a
        level (pulp_gpio's own evidence records that same refusal).
        """
        def edge_trigger(document):
            document['interrupts'][0]['trigger'] = 'rising_edge'
        path = self._mutated(FIXTURE_SOURCE, 'uart-edge-trigger.json', edge_trigger)
        review = self._review(path)
        self.assertIs(False, review['generated'])
        self.assertEqual(['zipcpu_axiluart'], review['refused'])
        rows = _rows(review['components'][0], 'interrupt-form-incomplete')
        self.assertEqual(1, len(rows))
        self.assertEqual('unsupported', rows[0]['status'])
        self.assertEqual('/interrupts', rows[0]['pointer'])
        gaps = rows[0]['detail']['rows']
        self.assertEqual(['interrupt-trigger-unsupported'],
                         [gap['code'] for gap in gaps])
        self.assertEqual('/interrupts/0', gaps[0]['pointer'])
        self.assertEqual('rising_edge', gaps[0]['trigger'])

    def test_a_partly_declared_interrupt_endpoint_is_refused(self):
        """Every declared interrupt line needs its own form, not just one."""
        def keep_one(document):
            document['interrupts'] = document['interrupts'][:1]
        path = self._mutated(FIXTURE_SOURCE, 'uart-partial-interrupt-form.json',
                             keep_one)
        review = self._review(path)
        self.assertIs(False, review['generated'])
        self.assertEqual(['zipcpu_axiluart'], review['refused'])
        rows = _rows(review['components'][0], 'interrupt-form-incomplete')
        self.assertEqual(1, len(rows))
        self.assertEqual('missing', rows[0]['status'])
        self.assertEqual('/interrupts', rows[0]['pointer'])
        gaps = rows[0]['detail']['rows']
        self.assertEqual(['interrupt-role-undeclared'], [gap['code'] for gap in gaps])
        self.assertEqual(['rxfifo', 'tx', 'txfifo'],
                         [item['role'] for item in gaps[0]['roles']])
        _resolve_pointer(_document(FIXTURE_SOURCE), gaps[0]['pointer'])

    def test_an_input_left_open_is_reported_as_unowned(self):
        """An input the ledger leaves unconnected is refused, not waved through."""
        def open_the_input(document):
            for action in document['port_actions']:
                if action['port'] == 'dft_cg_enable_i':
                    action.pop('value', None)
                    action['action'] = 'unconnected'
                    action['protocol'] = ['dft-contract', '1']
                    action['reason'] = 'fixture: an input deliberately left open'
        path = self._mutated('configs/peripherals/pulp_gpio/component_profile.json',
                             'gpio-open-input.json', open_the_input)
        review = self._review(path)
        self.assertIs(False, review['generated'])
        self.assertEqual(['pulp_gpio'], review['refused'])
        rows = _rows(review['components'][0], 'physical-input-unowned')
        self.assertEqual(1, len(rows))
        self.assertEqual('missing', rows[0]['status'])
        self.assertEqual('/port_actions', rows[0]['pointer'])
        self.assertIn('dft_cg_enable_i', rows[0]['detail']['reason'])
        self.assertEqual('input-without-driver', rows[0]['detail']['ledger_token'])
        _resolve_pointer(_document(
            'configs/peripherals/pulp_gpio/component_profile.json'),
            rows[0]['pointer'])

    def test_an_interrupt_without_a_declared_polarity_is_refused(self):
        """A form the reviewer cannot read is refused, never defaulted."""
        def drop_polarity(document):
            document['interrupts'][0].pop('polarity')
        path = self._mutated(FIXTURE_SOURCE, 'uart-no-polarity.json', drop_polarity)
        review = self._review(path)
        self.assertIs(False, review['generated'])
        self.assertEqual(['zipcpu_axiluart'], review['refused'])
        component = review['components'][0]
        rows = _rows(component, 'invalid-interrupt-polarity')
        self.assertEqual(1, len(rows))
        self.assertEqual('missing', rows[0]['status'])
        self.assertEqual('/interrupts/0/polarity', rows[0]['pointer'])
        self.assertIn('polarity', rows[0]['detail']['reason'])
        _resolve_pointer(_document(FIXTURE_SOURCE), '/interrupts/0/polarity')

    def test_a_reversed_but_declared_polarity_is_read_verbatim(self):
        """The reviewer reports the declared form; it never normalises it.

        Whether ``active_low`` matches the RTL cannot be decided from the
        declaration alone (pulp_gpio's own evidence records that), so what this
        test pins down is the weaker, honest guarantee: the row echoes the
        declaration instead of substituting a polarity of its own.
        """
        def flip_polarity(document):
            document['interrupts'][0]['polarity'] = 'active_low'
        path = self._mutated(FIXTURE_SOURCE, 'uart-flipped-polarity.json',
                             flip_polarity)
        review = self._review(path)
        self.assertEqual('ok', review['status'], review['refused'])
        rows = _rows(review['components'][0], 'interrupt-form-declared')
        self.assertEqual(1, len(rows))
        self.assertEqual('active_low', rows[0]['detail']['sources'][0]['polarity'])
        self.assertEqual('level', rows[0]['detail']['sources'][0]['trigger'])

    def test_a_profile_the_loader_refuses_becomes_a_located_row(self):
        def break_it(document):
            document['resets'] = []
        path = self._mutated(FIXTURE_SOURCE, 'uart-no-resets.json', break_it)
        review = self._review(path)
        self.assertIs(False, review['generated'])
        self.assertEqual(['zipcpu_axiluart'], review['refused'])
        rows = review['components'][0]['rows']
        self.assertEqual(1, len(rows))
        self.assertEqual('profile-reset-required', rows[0]['code'])
        self.assertEqual('/resets', rows[0]['pointer'])
        self.assertEqual('missing', rows[0]['status'])


class DeclarationReviewCliTests(unittest.TestCase):
    """The executable entry point gates generation on the review."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)

    def _run(self, *arguments):
        return subprocess.run(
            [sys.executable, str(ROOT / 'scripts/review_component_declarations.py'),
             '--base-dir', str(ROOT), *arguments],
            cwd=str(ROOT), capture_output=True, text=True,
            env={**os.environ, 'PYTHONPATH': str(ROOT / 'src')})

    def test_exit_zero_and_machine_readable_document_for_reviewed_profiles(self):
        output = Path(self.temporary.name) / 'review.json'
        result = self._run('--profile', 'configs/peripherals/zipcpu_axiluart/component_profile.json',
                           '--profile', 'configs/peripherals/pulp_gpio/component_profile.json',
                           '--output', str(output))
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        document = json.loads(output.read_text(encoding='utf-8'))
        self.assertEqual('declaration_review.v1', document['schema_version'])
        self.assertIs(False, document['generated'])
        self.assertEqual('ok', document['status'])
        self.assertEqual([], document['refused'])
        self.assertIn('zipcpu_axiluart', result.stdout)
        self.assertIn('pulp_gpio', result.stdout)
        self.assertIn('declaration-review: ok', result.stdout)

    def test_exit_nonzero_and_code_plus_pointer_for_a_refused_profile(self):
        document = _document(FIXTURE_SOURCE)
        document['interrupts'] = []
        path = Path(self.temporary.name) / 'uart-no-interrupt-form.json'
        path.write_text(json.dumps(document, indent=2), encoding='utf-8')
        output = Path(self.temporary.name) / 'refused.json'
        result = self._run('--profile', str(path), '--output', str(output))
        self.assertNotEqual(0, result.returncode)
        self.assertIn('interrupt-form-undeclared', result.stdout)
        self.assertIn('/interrupts', result.stdout)
        self.assertIn('zipcpu_axiluart', result.stdout)
        written = json.loads(output.read_text(encoding='utf-8'))
        self.assertIs(False, written['generated'])
        self.assertEqual('refused', written['status'])
        self.assertEqual(['zipcpu_axiluart'], written['refused'])


if __name__ == '__main__':
    unittest.main()
