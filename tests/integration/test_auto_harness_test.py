"""P7-E: the one-command driver must refuse honestly and never fake a stage.

``scripts/auto_harness_test.py`` chains the four accepted P7 stages (D1
declaration review, D2 harness-set generation, D3 path compilation, D4 the
graded capability report) plus an *optional* live session and fresh replay.
These are the software-only guards: no test here starts RTL.

The three rules this file pins:

* **the runtime family is never guessed** - an unknown family, or a composition
  that does not satisfy the family's own declared requirements, is refused with
  a ``code`` and a JSON ``pointer`` (and the refusal is the whole set, not a
  partial one);
* **a refusal is not a partial run** - the output directory always carries a
  ``run-summary.json`` and, unless every requested stage completed, an
  ``.incomplete`` marker, so a stopped run cannot be mistaken for a finished one;
* **a missing stage is a named absence** - without a runtime family or a client
  binary the run still emits D1..D3 plus ``capability-report.json``, the session
  appears as an absence with a reason, ``fresh-verification.json`` is not written
  at all, and no zero is invented for throughput.

One test records a real limitation rather than a success: the CV32E40P
composition of the mandated ``cv32e40p-pulp-dual-source`` family is refused by
D2, because that CPU's declared OBI endpoints carry no error role and the
admitted ``cpu.obi`` templates require one.  The driver must pass that refusal
through by name instead of adapting the composition.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / 'scripts' / 'auto_harness_test.py'

IBEX_COMPOSE = 'configs/scenarios/ibex-pulp-dual-gpio/compose.json'
IBEX_CPU = 'configs/cpus/ibex_obi_local/component_profile.json'
#: The one composition whose paths the admitted compiler can really compile:
#: a single PULP GPIO instance.  The dual-GPIO composition of both shipped
#: runtime families is refused by D3 (see ``test_two_instances_...``).
SOLO_COMPOSE = 'configs/scenarios/ibex-pulp-gpio/compose.json'
CV32E40P_COMPOSE = 'configs/scenarios/cv32e40p-pulp-dual-gpio/compose.json'
CV32E40P_CPU = 'configs/cpus/cv32e40p/component_profile.json'
GPIO = 'configs/peripherals/pulp_gpio/component_profile.json'


def run_cli(*arguments: object, timeout: float = 600.0):
    """Run the shipped entry point and decode its final machine-readable line."""
    environment = {**os.environ, 'PYTHONPATH': str(ROOT / 'src')}
    result = subprocess.run(
        [sys.executable, str(CLI), *(str(item) for item in arguments)],
        cwd=ROOT, capture_output=True, text=True, env=environment,
        timeout=timeout)
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    payload = json.loads(lines[-1]) if lines else None
    return result, payload


def driver_arguments(output: Path, compose: str, cpu: str, *extra: object):
    return ['--cpu', cpu, '--ip', GPIO, '--compose', compose,
            '--output', output, *extra]


def read(path: Path):
    return json.loads(path.read_text(encoding='utf-8'))


@pytest.fixture(scope='module')
def software_run(tmp_path_factory):
    """One real D1..D3 + report run, reused by the tests that need it.

    ``--skip-session`` is the explicit software-only request, so completing it
    is a *success* (exit 0) rather than a run that quietly dropped a stage.
    """
    output = tmp_path_factory.mktemp('runs') / 'software-only'
    result, payload = run_cli(
        *driver_arguments(output, SOLO_COMPOSE, IBEX_CPU, '--skip-session'))
    assert result.returncode == 0, result.stderr[-4000:]
    return output, payload


# ---------------------------------------------------------------------------
# rule 3: a missing stage is a named absence, never a zero and never a fake
# ---------------------------------------------------------------------------

def test_without_a_runtime_family_the_chain_still_emits_d1_to_d3_and_a_report(tmp_path):
    output = tmp_path / 'no-runtime'
    result, payload = run_cli(*driver_arguments(output, SOLO_COMPOSE, IBEX_CPU))

    # The session stage did not complete, so the run cannot report success.
    assert result.returncode != 0, result.stdout
    assert payload['status'] == 'refused'
    assert payload['exit_code'] == result.returncode
    assert payload['stages']['session']['status'] == 'absent'
    assert payload['stages']['session']['code'] == 'runtime-family-required'
    assert payload['stages']['session']['reason']

    # D1..D3 and the report are all still the real documents.
    review = read(output / 'declaration-review.json')
    assert review['schema_version'] == 'declaration_review.v1'
    assert review['status'] == 'ok'
    assert [len(row['rows']) for row in review['components']] == [9, 9]
    assert read(output / 'generated' / 'harness_set.json')['tier'] == 'generated'
    compiled = read(output / 'compiled_paths.v1.json')
    assert compiled['schema_version'] == 'compiled_paths.v1'
    assert compiled['counts']['executable'] == 4
    report = read(output / 'capability-report.json')
    assert report['schema_version'] == 'capability_report.v1'

    # No session ran, so no session document, no bundle and no replay document.
    assert not (output / 'session').exists()
    assert not (output / 'bundle').exists()
    assert not (output / 'fresh-verification.json').exists()
    assert payload['stages']['fresh_verification']['status'] == 'absent'

    # The absence is named, and nothing is zeroed to stand in for a measurement.
    assert report['session']['supplied'] is False
    assert report['session']['reason']
    assert report['throughput']['status'] == 'not_measured'
    assert report['build_cost']['status'] != 'measured'
    assert payload['absences'], 'the missing session must be listed as an absence'

    # The report was built from the documents this run wrote, by path.
    compiled_input = report['inputs']['compiled_paths']
    assert compiled_input['source'] == 'file'
    assert compiled_input['path'] == str(output / 'compiled_paths.v1.json')
    assert report['inputs']['harness_set']['path'] == str(
        output / 'generated' / 'harness_set.json')
    assert report['counts']['compiled_paths'] == compiled['counts']

    # A stopped run cannot be mistaken for a finished one.
    assert (output / '.incomplete').exists()
    assert read(output / 'run-summary.json')['status'] == 'refused'


def test_a_finished_run_removes_the_incomplete_marker(software_run):
    output, payload = software_run

    assert payload['status'] == 'complete'
    assert payload['stages']['session']['status'] == 'not_requested'
    assert payload['stages']['fresh_verification']['status'] == 'not_requested'
    assert not (output / '.incomplete').exists()
    assert read(output / 'run-summary.json')['status'] == 'complete'
    assert not (output / 'fresh-verification.json').exists()


def test_the_software_run_documents_are_the_real_module_outputs(software_run):
    output, payload = software_run

    harness = read(output / 'generated' / 'harness_set.json')
    assert harness['schema_version'] == 'harness_set.v1'
    assert harness['tier'] == 'generated'
    assert [row['instance_id'] for row in harness['components']] == [
        'cpu', 'gpio']
    assert [row['role'] for row in harness['components']] == [
        'cpu', 'device']
    assert harness['not_claimed'], 'the generated tier must list what it does not claim'

    # D3 read the contract D2 wrote, and reached executable paths with the
    # declaration the composition carries - not by inventing an image.
    wiring = read(output / 'generated' / 'wiring_contract.json')
    assert harness['wiring'] == wiring
    assert [row['resource_id'] for row in wiring['resources']] == ['ram']
    request = read(output / 'path_compile_request.json')
    assert request['wiring']['source'] == str(
        output / 'generated' / 'wiring_contract.json')
    # The instruction endpoint is the profile's declared instruction master.
    assert request['cpu']['instruction_endpoint'] == 'processor.instruction'
    assert request['cpu']['data_endpoint'] == 'processor.data'
    # The IP capability sidecar declared next to the profile is carried through.
    assert [row['test_capability'] for row in request['devices']] == [
        'configs/peripherals/pulp_gpio/test_capability.json']

    compiled = read(output / 'compiled_paths.v1.json')
    flows = {row['flow_id']: row for row in compiled['paths']}
    for flow in ('F1', 'F2', 'F3', 'F4'):
        assert flows[flow]['status'] == 'executable', (flow, flows[flow]['reason'])
    for flow in ('F5', 'F6'):
        assert flows[flow]['status'] == 'unsupported'
        assert flows[flow]['reason']['code']

    report = read(output / 'capability-report.json')
    assert report['schema_version'] == 'capability_report.v1'
    assert report['generated'] is False
    assert report['counts']['executable'] == compiled['counts']['executable']
    assert report['counts']['unsupported'] == compiled['counts']['unsupported']
    assert payload['stages']['capability_report']['status'] == 'ok'
    # Rule 5: the report was built from the documents this run wrote, by path -
    # not from this driver's summary of them.
    assert report['inputs']['compiled_paths']['path'] == str(
        output / 'compiled_paths.v1.json')
    assert report['inputs']['compiled_paths']['source'] == 'file'
    assert report['inputs']['harness_set']['supplied'] is True
    assert report['inputs']['harness_set']['path'] == str(
        output / 'generated' / 'harness_set.json')
    assert report['inputs']['harness_set']['tier'] == 'generated'
    assert report['inputs']['session']['supplied'] is False
    assert report['inputs']['session']['reason']


# ---------------------------------------------------------------------------
# rule 1: the runtime family is named, never guessed, and always validated
# ---------------------------------------------------------------------------

def test_an_unknown_runtime_family_is_refused_and_names_the_known_ones(tmp_path):
    output = tmp_path / 'unknown-family'
    result, payload = run_cli(*driver_arguments(
        output, IBEX_COMPOSE, IBEX_CPU, '--runtime', 'pulp-dual-source-guess',
        '--client-binary', tmp_path / 'no-client'))

    assert result.returncode != 0
    assert payload['status'] == 'refused'
    assert payload['runtime_family']['status'] == 'refused'
    assert payload['runtime_family']['code'] == 'runtime-family-unknown'
    assert 'cv32e40p-pulp-dual-source' in payload['runtime_family']['known']

    check = read(output / 'runtime-family.json')
    refusal, = check['refusals']
    assert refusal['code'] == 'runtime-family-unknown'
    assert refusal['pointer'] == '/runtime'
    assert 'pulp-dual-source-guess' in json.dumps(refusal['detail'])

    # Nothing was generated from an unvalidated family.
    assert not (output / 'generated').exists()
    assert not (output / 'capability-report.json').exists()
    assert (output / '.incomplete').exists()
    assert read(output / 'run-summary.json')['status'] == 'refused'


@pytest.mark.parametrize('mutation,code,pointer', [
    ('cpu', 'runtime-family-cpu-component-mismatch', '/cpu/request'),
    ('instances', 'runtime-family-instances-mismatch', '/devices'),
    ('protocol', 'runtime-family-device-endpoint-mismatch', '/devices/0/bus_endpoint'),
    ('window', 'runtime-family-window-mismatch', '/devices/0/base'),
    ('memory', 'runtime-family-memory-mismatch', '/memory'),
    ('device_id', 'runtime-family-window-device-id-mismatch', '/devices/0/device_id'),
])
def test_a_composition_that_does_not_satisfy_the_family_is_refused(
        tmp_path, mutation, code, pointer):
    """Every family requirement is checked, and each failure names its pointer."""
    compose_dir = tmp_path / mutation
    _copy_tree(ROOT / 'configs/scenarios/ibex-pulp-dual-gpio', compose_dir)
    document = read(compose_dir / 'compose.json')
    if mutation == 'cpu':
        request = read(compose_dir / 'requests' / 'cpu.json')
        request['profile_path'] = CV32E40P_CPU
        (compose_dir / 'requests' / 'cpu.json').write_text(
            json.dumps(request), encoding='utf-8')
    elif mutation == 'instances':
        document['devices'][1]['instance_id'] = 'gpio_c'
        document['devices'][1]['device_id'] = 'gpio_c'
    elif mutation == 'protocol':
        document['devices'][0]['bus_endpoint'] = 'gpio.pins'
    elif mutation == 'window':
        document['devices'][0]['base'] = 0x40002000
    elif mutation == 'memory':
        document['memory'][0]['size'] = 0x2000
    elif mutation == 'device_id':
        document['devices'][0]['device_id'] = 'gpio_renamed'
    (compose_dir / 'compose.json').write_text(
        json.dumps(document, indent=2), encoding='utf-8')

    output = tmp_path / f'out-{mutation}'
    # --skip-session still validates a family that was explicitly named.
    result, payload = run_cli(*driver_arguments(
        output, str(compose_dir / 'compose.json'),
        IBEX_CPU if mutation != 'cpu' else CV32E40P_CPU,
        '--runtime', 'ibex-pulp-dual-source', '--skip-session'))

    assert result.returncode != 0, result.stdout
    assert payload['status'] == 'refused'
    refusals = read(output / 'runtime-family.json')['refusals']
    assert [(row['code'], row['pointer']) for row in refusals] == [(code, pointer)], (
        mutation, refusals)
    # A refused composition produces no harness set at all.
    assert not (output / 'generated').exists()
    assert not (output / 'capability-report.json').exists()
    assert read(output / 'run-summary.json')['status'] == 'refused'
    assert (output / '.incomplete').exists()


def test_the_cv32e40p_composition_is_admitted_by_the_protocol_subset(tmp_path):
    """The mandated family's CPU shape now matches an admitted template shape.

    This test used to record the opposite: CV32E40P's declared OBI
    instruction/data endpoints carry no ``error`` role, and both admitted
    ``cpu.obi`` variants required one, so D2 refused the composition with
    ``protocol-shape-not-admitted``.

    That was a gap in the *contract set*, not a boundary of the CPU: OBI does not
    require an error channel, and the pinned core really has no
    ``instr_err_i``/``data_err_i`` (its profile says so in ``capabilities.
    evidence``).  Two no-error variants were added, and because a limit-only
    variant would have matched the error-capable endpoints too - making selection
    ambiguous, which the selector refuses - they bind the declared
    ``error_response`` profile fact.  Ibex still selects the error-capable
    variants, which the sibling test pins.
    """
    output = tmp_path / 'cv32e40p'
    result, payload = run_cli(*driver_arguments(
        output, CV32E40P_COMPOSE, CV32E40P_CPU,
        '--runtime', 'cv32e40p-pulp-dual-source', '--skip-session'))

    assert result.returncode == 0, payload
    assert payload['status'] == 'complete'
    assert payload['stages']['harness_set']['status'] == 'ok'
    assert payload['stages']['path_compilation']['status'] == 'ok'
    assert payload['stages']['path_compilation']['counts'] == {
        'executable': 4, 'unsupported': 2, 'total': 6}
    templates = {
        row['instance_id']: row['template']
        for row in read(output / 'generated' / 'harness_set.json')['components']}
    assert templates['cpu']['variant_id'] == 'read-write-no-error-pins'


def test_an_existing_output_directory_is_never_reused(tmp_path):
    output = tmp_path / 'existing'
    output.mkdir()
    (output / 'run-summary.json').write_text('{"status": "complete"}\n',
                                             encoding='utf-8')
    result, payload = run_cli(*driver_arguments(
        output, IBEX_COMPOSE, IBEX_CPU, '--skip-session'))

    assert result.returncode != 0
    assert payload['status'] == 'refused'
    assert payload['refusals'][0]['code'] == 'output-directory-exists'
    assert read(output / 'run-summary.json') == {'status': 'complete'}


def _copy_tree(source: Path, target: Path) -> None:
    target.mkdir(parents=True)
    for path in source.rglob('*'):
        relative = path.relative_to(source)
        if path.is_dir():
            (target / relative).mkdir(parents=True, exist_ok=True)
        else:
            (target / relative).parent.mkdir(parents=True, exist_ok=True)
            (target / relative).write_bytes(path.read_bytes())


def test_two_instances_of_one_profile_compile_at_d3(tmp_path):
    """Two instances of one profile must both be laid out.

    This test used to record the opposite.  Both shipped runtime families wire
    exactly ``cpu``, ``gpio_a`` and ``gpio_b``, and the compiler keyed its input
    layout by ``(endpoint_id, role)``, so it read the *second instance of one
    profile* as a duplicate declaration and refused the whole compilation with
    ``duplicate-layout-field``.  That made every family-satisfying composition
    uncompilable, and this test asserted the refusal as if it were the boundary.

    It was not a boundary, it was a defect: a layout belongs to an instance, and
    a real collision - two components claiming one physical input port name - is
    already refused separately by ``duplicate-input-port``.  The key now carries
    the instance id, so this composition compiles and the driver can reach D4.
    """
    output = tmp_path / 'dual-gpio'
    result, payload = run_cli(*driver_arguments(
        output, IBEX_COMPOSE, IBEX_CPU, '--skip-session'))

    assert result.returncode == 0, payload
    assert payload['status'] == 'complete'
    assert payload['stages']['harness_set']['status'] == 'ok'
    assert payload['stages']['path_compilation']['status'] == 'ok'
    assert payload['stages']['path_compilation']['counts'] == {
        'executable': 4, 'unsupported': 2, 'total': 6}
    assert payload['refusals'] == []
    assert (output / 'compiled_paths.v1.json').exists()
    assert (output / 'capability-report.json').exists()
    assert not (output / '.incomplete').exists()


def test_a_name_similar_sibling_component_is_refused_by_name(tmp_path):
    """The old-component negative: no fallback to a similarly named sibling.

    CVW's own P7-E entry requires keeping one old component negative, to show the
    generator does not apply a template because a name looks close.  ``cv32e20``
    and ``cv32e40p`` are siblings with near-identical names, the same declared OBI
    protocol and the same endpoint ids - so a name-driven or protocol-only match
    would happily accept the wrong CPU.  The runtime family declares which
    component it is for, and the driver cross-checks that declared fact against
    the profile the composition actually names.
    """
    source = ROOT / CV32E40P_COMPOSE
    compose = tmp_path / 'compose'
    (compose / 'requests').mkdir(parents=True)
    (compose / 'compose.json').write_text(
        source.read_text(encoding='utf-8'), encoding='utf-8')
    for name in ('gpio_a', 'gpio_b', 'cpu'):
        document = json.loads(
            (source.parent / 'requests' / f'{name}.json').read_text(encoding='utf-8'))
        if name == 'cpu':
            # The only change: the CPU request names the name-similar sibling.
            document['profile_path'] = 'configs/cpus/cv32e20/component_profile.json'
        (compose / 'requests' / f'{name}.json').write_text(
            json.dumps(document), encoding='utf-8')

    output = tmp_path / 'out'
    result, payload = run_cli(*driver_arguments(
        output, str(compose / 'compose.json'),
        'configs/cpus/cv32e20/component_profile.json',
        '--runtime', 'cv32e40p-pulp-dual-source', '--skip-session'))

    assert result.returncode != 0
    assert payload['status'] == 'refused'
    refusal, = payload['refusals']
    assert refusal['code'] == 'runtime-family-cpu-component-mismatch'
    assert refusal['stage'] == 'runtime_family'
    assert refusal['detail']['expected'] == 'cv32e40p'
    assert refusal['detail']['observed'] == 'cv32e20'
    # The whole set stops: nothing was generated for the wrong component.
    assert payload['stages']['harness_set']['status'] == 'not_requested'
    assert not (output / 'generated').exists()
    assert not (output / 'compiled_paths.v1.json').exists()


def test_the_family_requirements_come_from_the_family_declaration():
    """The registry is small, explicit and reads the wiring it validates against."""
    from myfuzz.local_harness.auto_harness_test import (known_family_ids,
                                                        runtime_family, wiring_facts)
    families = known_family_ids()
    assert 'cv32e40p-pulp-dual-source' in families
    family = runtime_family('cv32e40p-pulp-dual-source')
    assert family.cpu_component_id == 'cv32e40p'
    facts = wiring_facts(family)
    assert facts['instances'] == ['cpu', 'gpio_a', 'gpio_b']
    assert [(row['instance_id'], row['base'], row['size'])
            for row in facts['windows']] == [
        ('gpio_a', 0x40001000, 0x1000), ('gpio_b', 0x40000000, 0x1000)]
    assert [(row['component_instance'], row['base'], row['size'])
            for row in facts['memory_regions']] == [('cpu', 0x10000, 0x30000)]


def test_the_session_preflight_refuses_by_name_without_starting_rtl(tmp_path):
    """Every D4 precondition has its own code; none of these starts a session."""
    from myfuzz.local_harness.auto_harness_test import (AutoHarnessRefused,
                                                        run_live_session,
                                                        runtime_family)
    family = runtime_family('ibex-pulp-dual-source')
    client = tmp_path / 'client'
    client.write_bytes(b'not a binary; only its existence is preflighted')
    cache = tmp_path / 'cache-file'
    cache.write_bytes(b'not a directory')

    def call(**overrides):
        arguments = dict(family=family, session_dir=tmp_path / 'session',
                         client_binary=client, cache_dir=cache, run_id='probe',
                         budget_seconds=1.0, max_tests=1, search_seed=None,
                         max_runs_per_batch=1, base_dir=tmp_path)
        arguments.update(overrides)
        return arguments

    for overrides, code, pointer in (
            ({'client_binary': None}, 'client-binary-required', '/client-binary'),
            ({'client_binary': tmp_path / 'absent'}, 'client-binary-missing',
             '/client-binary'),
            ({'budget_seconds': 0}, 'budget-seconds-invalid', '/budget-seconds'),
            ({'max_tests': 0}, 'max-tests-invalid', '/max-tests'),
            ({'max_runs_per_batch': 99}, 'max-runs-per-batch-invalid',
             '/max-runs-per-batch'),
            ({'cache_dir': tmp_path / 'absent-cache'}, 'build-cache-missing',
             '/cache-dir'),
            ({'cache_dir': cache}, 'build-cache-invalid', '/cache-dir')):
        with pytest.raises(AutoHarnessRefused) as raised:
            run_live_session(**call(**overrides))
        assert raised.value.code == code, overrides
        assert raised.value.pointer == pointer, overrides
    assert not (tmp_path / 'session').exists()


def test_an_explicit_capability_sidecar_is_matched_by_component_id(tmp_path):
    """The sidecar is a declaration matched by ``component_id``, not by filename."""
    from myfuzz.local_harness.auto_harness_test import (load_composition,
                                                        test_capability_sidecar)
    composition = load_composition(SOLO_COMPOSE, base_dir=ROOT)

    sibling, source = test_capability_sidecar(composition, 'gpio', ())
    assert source == 'profile-sibling'
    assert sibling == 'configs/peripherals/pulp_gpio/test_capability.json'

    declared, source = test_capability_sidecar(composition, 'gpio', (sibling,))
    assert source == 'declared-option'
    assert declared == sibling

    # A sidecar for another component is not silently used.
    other = tmp_path / 'other.json'
    other.write_text(json.dumps({'component_id': 'pulp_spi'}), encoding='utf-8')
    absent, source = test_capability_sidecar(composition, 'gpio', (other,))
    assert absent == sibling and source == 'profile-sibling'

    both = tmp_path / 'both.json'
    both.write_text(json.dumps({'component_id': 'pulp_gpio'}), encoding='utf-8')
    with pytest.raises(Exception) as raised:
        test_capability_sidecar(composition, 'gpio', (sibling, both))
    assert 'ip-capability-ambiguous' in str(raised.value)


#: Refusals the CLI's help text used to advertise for the composition shape both
#: shipped runtime families wire (one CPU plus two instances of one IP profile).
#: ``duplicate-layout-field`` was a real defect, not a boundary: the layout key
#: now carries the instance id (``compiled_paths._layout_annotations``), and
#: ``test_two_instances_of_one_profile_compile_at_d3`` proves that shape compiles
#: and reaches D4.  The stale paragraph said "the chain stops before the session"
#: for *every* family-satisfying composition, i.e. it denied the one command that
#: works.
STALE_BOUNDARY_TOKENS = ('duplicate-layout-field',)

#: Every artifact one requested run writes.  The help text is the only place a
#: caller learns what to look for afterwards, so it has to name all of them.
DOCUMENTED_ARTIFACTS = (
    'declaration-review.json', 'generated/', 'compiled_paths.v1.json',
    'capability-report.json', 'session/', 'bundle/', 'fresh-verification.json',
)


def stale_boundary_claims(documented_help: str) -> list[str]:
    """The not-actually-shipped refusals a help text still advertises."""
    return [token for token in STALE_BOUNDARY_TOKENS
            if token in unwrapped_help(documented_help)]


def missing_documented_artifacts(documented_help: str) -> list[str]:
    """The run artifacts a help text fails to name."""
    return [name for name in DOCUMENTED_ARTIFACTS
            if name not in unwrapped_help(documented_help)]


def unwrapped_help(documented_help: str) -> str:
    """Undo the help formatter's soft wrapping, so a token can be read whole.

    ``argparse`` re-wraps the docstring to the terminal width and breaks on
    hyphens, so a rendered ``--help`` legitimately contains ``declaration-`` at
    the end of one line and ``review.json`` at the start of the next (observed:
    ``--help`` at the default 80 columns).  The token is still documented; only
    the line break landed inside it.  Normalizing here keeps this guard about
    what the help text *says* instead of about where the breaks fell.
    """
    rejoined = re.sub(r'-\n\s*', '-', documented_help)
    return re.sub(r'\s+', ' ', rejoined)


def test_the_help_text_matches_the_shipped_stages():
    """The entry point must not document a boundary this tree does not have.

    ``auto_harness_test.py --help`` is rendered from the script's docstring and
    is how a caller learns both what a run writes and where it stops.  It once
    announced that D3 refused the dual-instance composition with
    ``duplicate-layout-field``, so "the chain stops before the session and no
    report is written for that composition".  That refusal was a fixed defect,
    and a real run of exactly that composition writes all seven artifacts and
    exits 0.  A help text that denies the working command is worse than no help
    text, so both directions are pinned here: it must not repeat the dead
    refusal, and it must still name every artifact the driver really writes.
    """
    result = subprocess.run(
        [sys.executable, str(CLI), '--help'], cwd=ROOT, capture_output=True,
        text=True, env={**os.environ, 'PYTHONPATH': str(ROOT / 'src')},
        timeout=120)
    assert result.returncode == 0, result.stderr
    assert stale_boundary_claims(result.stdout) == [], (
        'the help text still advertises a refusal the shipped compiler no '
        'longer performs')
    assert missing_documented_artifacts(result.stdout) == [], (
        'the help text no longer names every artifact a run writes')
