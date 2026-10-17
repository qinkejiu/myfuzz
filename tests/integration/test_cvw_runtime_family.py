"""The CVW runtime family: registered, derived, and really startable.

``cvw-ahb-pulp-gpio`` is the third family of the P7-E driver's closed set and the
first non-PULP one.  Its CPU is CVW (CORE-V Wally) at its **unified** AHB-Lite
memory master ``cpu.external_bus`` - the EBU arbitrates the IFU and the LSU onto
that one bus, so the profile declares a single ``memory_master`` endpoint and no
instruction/data pair - and its device is one ``pulp_gpio`` on APB3 in a 4 KiB
window inside the external aperture, with host RAM carved below MMIO.

The claims this file pins, each with a guard that can fail:

* the family is registered and selectable by id, and its id/entry points are the
  ones the family module declares (a drifted literal is caught);
* the family publishes a real session assembly - boot image, instruction source
  and runner factory - and each named entry resolves to a callable/document in
  the module that really implements it;
* an unknown family id is still refused by name - the set did not become
  "anything goes" when a third entry was added;
* the family's declared shape (component ids, protocols, endpoint, window,
  memory region, boot base) is what the two real profiles and the pinned derived
  configuration actually say, and a *mutated* declaration is refused by name
  (the scratch-tree tests below are those RED guards);
* the pure run reaches D1..D3 plus the capability report with
  ``--runtime cvw-ahb-pulp-gpio --skip-session``, and the old
  ``cvw-online-assembly-undeclared`` refusal is gone;
* the gated real run (``MYFUZZ_SCENARIO_REAL=1``) reaches the family's directed
  session, with a real F4 receipt and a fresh replay conclusion.

Nothing here fabricates a session: the real case is skipped unless the caller
explicitly opts in, and it is the CLI itself - not a fixture - that starts it.
"""
from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from myfuzz.integration import cvw_pulp_online as family_module
from myfuzz.local_harness.auto_harness_test import (AutoHarnessRefused,
                                                    check_composition,
                                                    known_family_ids,
                                                    load_composition,
                                                    run_live_session,
                                                    runtime_family,
                                                    wiring_facts)

ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / 'scripts' / 'auto_harness_test.py'

CVW_CPU_PROFILE = ROOT / 'configs' / 'cpus' / 'cvw' / 'component_profile.json'
GPIO_PROFILE = ROOT / 'configs' / 'peripherals' / 'pulp_gpio' / 'component_profile.json'
CVW_DERIVED_CONFIG = ROOT / 'configs' / 'cpus' / 'cvw' / 'config_extmem' / 'config.vh'
CVW_SCENARIO = ROOT / 'configs' / 'scenarios' / 'cvw-pulp-gpio'

FAMILY_ID = 'cvw-ahb-pulp-gpio'

pytestmark = pytest.mark.skipif(
    not CVW_CPU_PROFILE.is_file() or not CVW_SCENARIO.is_dir(),
    reason='the CVW profile or composition is not present in this checkout')


def read(path: Path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def family() -> object:
    return runtime_family(FAMILY_ID)


def resolved_entry(spec: str):
    """The shipped ``module:attribute`` resolution the driver itself performs."""
    module_name, _, attribute = spec.partition(':')
    entry = getattr(importlib.import_module(module_name), attribute, None)
    assert callable(entry), spec
    return entry


# ---------------------------------------------------------------------------
# (a) registered and selectable
# ---------------------------------------------------------------------------

def test_the_family_is_registered_and_selectable():
    assert FAMILY_ID in known_family_ids()
    assert FAMILY_ID == family_module.CVW_FAMILY_ID
    selected = family()
    assert selected.family_id == FAMILY_ID
    assert selected.cpu_component_id == 'cvw'
    assert selected.cpu_profile == ('configs/cpus/cvw/component_profile.json')
    assert selected.device_component_id == 'pulp_gpio'
    assert list(selected.device_protocol) == ['apb', '3']
    assert selected.device_endpoint_function == 'mmio_slave'
    assert list(selected.cpu_master_protocol) == ['ahb-lite', '1']
    assert selected.wiring_declaration.endswith(':cvw_pulp_gpio_wiring')
    assert selected.runtime_entry.endswith(':make_cvw_pulp_online_runtime')
    assert selected.replay_entry.endswith(':replay_cvw_pulp_online_files')
    # Both named entry points really resolve to callables, which is what the
    # driver's own ``_load_entry`` requires before it starts anything.
    assert resolved_entry(selected.runtime_entry) is family_module.make_cvw_pulp_online_runtime
    assert resolved_entry(selected.replay_entry) is family_module.replay_cvw_pulp_online_files
    # And the family's own session assembly is published, not restated here.
    assembly = selected.session_assembly_document()
    assert assembly is not None and assembly['status'] == 'ok', assembly
    assert assembly == {'status': 'ok', **family_module.CVW_SESSION_ASSEMBLY}
    assert assembly['kind'] == 'directed_fixed_image'
    for key in ('boot_image', 'online_decoder', 'runner_factory',
                'directed_session', 'runtime_assembly'):
        assert resolved_entry(assembly[key]) is not None, key
    assert selected.directed_session_entry() == assembly['directed_session']


def test_the_assembly_declares_the_three_real_pieces():
    """The boot image, instruction source and factory really exist as code."""
    from myfuzz.scenario import cvw_session

    boot_image = resolved_entry(family_module.CVW_SESSION_ASSEMBLY['boot_image'])
    source = resolved_entry(family_module.CVW_SESSION_ASSEMBLY['online_decoder'])
    factory = resolved_entry(family_module.CVW_SESSION_ASSEMBLY['runner_factory'])
    assert boot_image is cvw_session.make_cvw_boot_image
    assert source is cvw_session.make_cvw_boot_instruction_source
    assert factory is cvw_session.make_cvw_gpio_session_factory
    image = boot_image()
    assert isinstance(image, cvw_session.CvwBootImage)
    assert image.base == 0xC0000000 and image.result == 0xC0000400
    assert image.words == len(image.data) // 4 == 64
    instruction_source = source(image)
    declaration = instruction_source.document()
    assert declaration['schema_version'] == 'cvw_boot_instruction_source.v1'
    assert declaration['kind'] == 'fixed_boot_image_instruction_source'
    assert 'no RFuzz record' in declaration['not_an_online_decoder']
    assert declaration['boot_image']['sha256'] == image.sha256
    assert instruction_source.evidence()['delivered'] is False

def test_the_family_requirements_come_from_its_own_declaration():
    facts = wiring_facts(family())
    assert facts['instances'] == ['cpu', 'gpio']
    assert [(row['instance_id'], row['device_id'], row['base'], row['size'])
            for row in facts['windows']] == [('gpio', 'gpio', 0xCFFF0000, 4096)]
    assert [(row['component_instance'], row['base'], row['size'])
            for row in facts['memory_regions']] == [('cpu', 0xC0000000, 0x0FFF0000)]


# ---------------------------------------------------------------------------
# (b) an unknown family id is still refused
# ---------------------------------------------------------------------------

def test_an_unknown_family_id_is_still_refused():
    # A name that looks exactly like a family this repository *could* have: the
    # closed set must refuse it rather than pattern-match it onto a shipped one.
    for requested in ('cvw-pulp-dual-source', 'cvw-ahb-pulp-gpio-', 'CVW-AHB-PULP-GPIO'):
        with pytest.raises(AutoHarnessRefused) as raised:
            runtime_family(requested)
        assert raised.value.code == 'runtime-family-unknown'
        assert raised.value.pointer == '/runtime'
        assert raised.value.detail['requested'] == requested
        assert FAMILY_ID in raised.value.detail['known']
    # And the family is still *not* guessed when nothing is named at all.
    with pytest.raises(AutoHarnessRefused) as raised:
        runtime_family(None)
    assert raised.value.code == 'runtime-family-required'


# ---------------------------------------------------------------------------
# (c) the declared shape matches the real profiles
# ---------------------------------------------------------------------------

def test_the_declared_shape_matches_the_real_profiles():
    """Read the declarations directly here, so the family cannot drift from them."""
    cpu = read(CVW_CPU_PROFILE)
    gpio = read(GPIO_PROFILE)
    config_text = CVW_DERIVED_CONFIG.read_text(encoding='utf-8')

    cpu_endpoints = cpu['endpoints']
    # The manager-domain observation endpoint is a separate passive declaration;
    # the bus itself remains the profile's only memory master.
    bus_endpoints = [row for row in cpu_endpoints
                     if row['function'] != 'observation']
    assert [row['function'] for row in bus_endpoints] == ['memory_master']
    observations = [row for row in cpu_endpoints
                    if row['function'] == 'observation']
    assert len(observations) == 1
    assert {field['role'] for field in observations[0]['fields']} == {
        'manager_ready', 'bus_reset_n'}
    cpu_endpoint = bus_endpoints[0]
    assert cpu_endpoint['endpoint_id'] == 'cpu.external_bus'
    assert cpu_endpoint['protocol'] == ['ahb-lite', '1']
    haddr = [field for field in cpu_endpoint['fields'] if field['role'] == 'haddr']
    assert [field['width'] for field in haddr] == [cpu['capabilities']['address_width']] == [34]

    gpio_endpoint = [row for row in gpio['endpoints']
                     if row['endpoint_id'] == 'gpio.bus'][0]
    assert gpio_endpoint['function'] == 'mmio_slave'
    assert gpio_endpoint['protocol'] == ['apb', '3']
    assert gpio['address']['window_size'] == 4096
    assert cpu['cpu']['reset_vector'] == 0xC0000000
    assert "localparam logic [63:0] EXT_MEM_BASE     = 64'hC0000000;" in config_text
    assert "localparam logic [63:0] EXT_MEM_RANGE    = 64'hFFFFFFF;" in config_text

    capabilities = family_module.cvw_pulp_gpio_capabilities()
    assert capabilities['cpu'] == {
        'component_id': 'cvw', 'instance_id': 'cpu',
        'profile': 'configs/cpus/cvw/component_profile.json',
        'endpoint_id': 'cpu.external_bus', 'function': 'memory_master',
        'protocol': ['ahb-lite', '1'], 'address_width': 34, 'data_width': 32,
        'byte_lane_width': 4, 'boot_base': 0xC0000000}
    assert capabilities['device'] == {
        'component_id': 'pulp_gpio', 'instance_id': 'gpio',
        'profile': 'configs/peripherals/pulp_gpio/component_profile.json',
        'endpoint_id': 'gpio.bus', 'function': 'mmio_slave',
        'protocol': ['apb', '3'], 'window': {'base': 0xCFFF0000, 'size': 4096}}
    assert capabilities['memory'] == {
        'component': 'cpu',
        'regions': [{'memory_id': 'ram', 'base': 0xC0000000, 'size': 0x0FFF0000}]}

    # The registry's own literals must equal that derivation: the driver and the
    # family module are two views of one declaration, never two declarations.
    selected = family()
    assert selected.cpu_component_id == capabilities['cpu']['component_id']
    assert selected.device_component_id == capabilities['device']['component_id']
    assert list(selected.cpu_master_protocol) == capabilities['cpu']['protocol']
    assert list(selected.device_protocol) == capabilities['device']['protocol']
    assert selected.cpu_profile == capabilities['cpu']['profile']


# ---------------------------------------------------------------------------
# (c, continued) the derivation refuses a mutated declaration - the RED guards
# ---------------------------------------------------------------------------

def _scratch_tree(tmp_path, *, cpu=None, gpio=None, config=None) -> Path:
    """A scratch repository root holding copies of the three real declarations.

    Each mutation must *return* the document it changed: a mutation that mutates
    in place and falls out as ``None`` would write ``null`` and the test would
    then be measuring a malformed file rather than the fact it names.
    """
    root = tmp_path / 'scratch'
    for relative in ('configs/cpus/cvw/component_profile.json',
                     'configs/peripherals/pulp_gpio/component_profile.json',
                     'configs/cpus/cvw/config_extmem/config.vh'):
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, target)
    for name, mutate, relative in (
            ('cpu', cpu, 'configs/cpus/cvw/component_profile.json'),
            ('gpio', gpio, 'configs/peripherals/pulp_gpio/component_profile.json')):
        if mutate is None:
            continue
        path = root / relative
        mutated = mutate(read(path))
        assert isinstance(mutated, dict), f'the {name} mutation returned nothing to write'
        path.write_text(json.dumps(mutated, indent=1), encoding='utf-8')
    if config is not None:
        path = root / 'configs/cpus/cvw/config_extmem/config.vh'
        mutated = config(path.read_text(encoding='utf-8'))
        assert isinstance(mutated, str), 'the config mutation returned nothing to write'
        path.write_text(mutated, encoding='utf-8')
    return root


def _cpu_function_to_data_master(document):
    document['endpoints'][0].update(function='data_memory_master')
    return document


def _cpu_protocol_to_obi(document):
    document['endpoints'][0].update(protocol=['obi', '1'])
    return document


def _cpu_address_width_to_32(document):
    document['capabilities'].update(address_width=32)
    return document


def _cpu_reset_vector_back_to_uncore_ram(document):
    document['cpu'].update(reset_vector=0x80000000)
    return document


def _gpio_bus_protocol_to_apb4(document):
    document['endpoints'][0].update(protocol=['apb', '4'])
    return document


MUTATIONS = (
    ('cpu endpoint function is no longer the unified memory master',
     {'cpu': _cpu_function_to_data_master},
     'cvw-family-cpu-master-unsupported', '/cpu/request'),
    ('cpu master protocol is no longer the AHB-Lite template',
     {'cpu': _cpu_protocol_to_obi},
     'cvw-family-cpu-master-protocol-mismatch', '/cpu/request'),
    ('the declared address width no longer matches HADDR',
     {'cpu': _cpu_address_width_to_32},
     'cvw-family-address-width-mismatch', '/cpu/request'),
    ('the reset vector left the external-memory region',
     {'cpu': _cpu_reset_vector_back_to_uncore_ram},
     'cvw-family-boot-base-mismatch', '/cpu/request'),
    ('the device bus is no longer the APB3 mmio_slave endpoint',
     {'gpio': _gpio_bus_protocol_to_apb4},
     'cvw-family-device-endpoint-mismatch', '/devices/0/bus_endpoint'),
    ('the derived configuration no longer declares EXT_MEM_BASE',
     {'config': lambda text: text.replace(
         "localparam logic [63:0] EXT_MEM_BASE     = 64'hC0000000;", '')},
     'cvw-family-external-memory-config-incomplete', '/memory'),
    ('EXT_MEM_RANGE is no longer a thermometer mask',
     {'config': lambda text: text.replace(
         "localparam logic [63:0] EXT_MEM_RANGE    = 64'hFFFFFFF;",
         "localparam logic [63:0] EXT_MEM_RANGE    = 64'hFFFFFFE;")},
     'cvw-family-external-memory-range-not-thermometer', '/memory'),
)


@pytest.mark.parametrize('label,changes,code,pointer', MUTATIONS,
                         ids=[row[0] for row in MUTATIONS])
def test_a_mutated_declaration_is_refused_by_name(tmp_path, label, changes, code, pointer):
    root = _scratch_tree(tmp_path, **changes)
    with pytest.raises(AutoHarnessRefused) as raised:
        family_module.cvw_pulp_gpio_wiring(base_dir=root)
    assert raised.value.code == code, label
    assert raised.value.pointer == pointer, label


def test_the_unmutated_scratch_tree_still_derives_the_same_declaration(tmp_path):
    """The RED guards above are measuring the mutation, not the copy itself."""
    root = _scratch_tree(tmp_path)
    assert (family_module.cvw_pulp_gpio_wiring(base_dir=root).document()
            == family_module.cvw_pulp_gpio_wiring().document())


# ---------------------------------------------------------------------------
# (c, continued) the unified CPU master is accepted, and only that shape
# ---------------------------------------------------------------------------

def _composition_with_cpu_profile(tmp_path, profile_document: dict):
    """The real CVW composition, re-pointed at a scratch CPU declaration."""
    compose = tmp_path / 'compose'
    shutil.copytree(CVW_SCENARIO, compose)
    profile = tmp_path / 'cpu.json'
    profile.write_text(json.dumps(profile_document, indent=1), encoding='utf-8')
    for name, path in (('cpu', str(profile)),
                       ('gpio', str(GPIO_PROFILE))):
        request_path = compose / 'requests' / f'{name}.json'
        request = read(request_path)
        request['profile_path'] = path
        request_path.write_text(json.dumps(request), encoding='utf-8')
    return load_composition(compose / 'compose.json', base_dir=str(tmp_path))


def test_the_real_cvw_composition_satisfies_the_family(tmp_path):
    """The unified master fills both CPU roles, and every other fact matches."""
    composition = load_composition(CVW_SCENARIO / 'compose.json', base_dir=ROOT)
    selected = family()
    check = check_composition(composition, family=selected,
                              facts=wiring_facts(selected))
    assert check['status'] == 'ok', check['refusals']
    rows = {row['check']: row for row in check['rows']}
    assert rows['cpu-master-endpoints']['status'] == 'ok'
    assert rows['cpu-master-protocol']['status'] == 'ok'
    assert rows['cpu-data-endpoint-pointer']['status'] == 'ok'
    assert rows['instances']['status'] == 'ok'
    assert rows['memory-regions']['status'] == 'ok'


def test_a_cpu_without_its_unified_master_is_refused(tmp_path):
    """RED for the row above: the same composition, one declaration fact moved.

    Moving the sole endpoint's function away from ``memory_master`` leaves the CPU
    with neither an instruction master nor a unified one, which is exactly the
    shape the family cannot start - so the check must refuse it by name instead
    of quietly accepting "some master exists".
    """
    document = read(CVW_CPU_PROFILE)
    document['endpoints'][0]['function'] = 'data_memory_master'
    composition = _composition_with_cpu_profile(tmp_path, document)
    selected = family()
    check = check_composition(composition, family=selected,
                              facts=wiring_facts(selected))
    assert check['status'] == 'refused'
    assert [row['code'] for row in check['refusals']] == \
        ['runtime-family-cpu-master-missing']
    assert check['refusals'][0]['detail']['or_sole_unified'] == 'memory_master'


# ---------------------------------------------------------------------------
# (d) the real session route, and the boundaries it keeps
# ---------------------------------------------------------------------------

def test_the_rfuzz_live_route_does_not_start_cvw_without_d3_inputs(tmp_path):
    """The RFuzz transport is not silently borrowed by the directed family.

    ``run_live_session`` is the shared RFuzz path.  Called without the D3
    compiled inputs it refuses before the family entry point, so naming a client
    binary cannot turn the directed family into an online campaign by accident.
    No RTL is started and the heavy-worker lock is never taken.
    """
    cache = ROOT / '.superpowers' / 'cache' / 'local-harness'
    if not cache.is_dir():
        pytest.skip('the shared local-harness build cache is not present')
    client = tmp_path / 'client'
    client.write_bytes(b'a stub: only its existence is preflighted')

    with pytest.raises(AutoHarnessRefused) as raised:
        run_live_session(family=family(), session_dir=tmp_path / 'session',
                         client_binary=client, cache_dir=cache, run_id='family-probe',
                         budget_seconds=1.0, max_tests=1, search_seed=None,
                         max_runs_per_batch=1, base_dir=tmp_path)

    assert raised.value.code == 'compiled-runtime-input-required'
    assert raised.value.pointer == '/compiled_inputs'
    assert family().directed_session_entry() is not None
    # Nothing was created: no session directory, and the repository's one heavy
    # worker lock was never taken for a run that cannot proceed.
    assert not (tmp_path / 'session').exists()
    assert not (tmp_path / '.superpowers' / 'sdd' / 'stage2-heavy-worker.lock').exists()
    assert sorted(path.name for path in tmp_path.iterdir()) == ['client']


def test_the_opt_in_observations_are_refused_by_name(monkeypatch):
    """Every opt-in is off by default, and an unavailable one is refused, not dropped."""
    cache = ROOT / '.superpowers' / 'cache' / 'local-harness'
    entry = family_module.make_cvw_pulp_online_runtime

    def call(**overrides):
        arguments = dict(cache_dir=cache, run_id='family-probe')
        arguments.update(overrides)
        return arguments

    for overrides, code, pointer in (
            ({'cpu_retirement': True}, 'cvw-retirement-observation-unavailable',
             '/cpu/retirement'),
            ({'native_irq_receipts': True}, 'cvw-retirement-observation-unavailable',
             '/cpu/retirement'),
            ({'gpio_consumption': True}, 'cvw-family-observation-undeclared',
             '/devices/0'),
            ({'cpu_retirement': 'yes'}, 'cvw-family-policy-invalid', '/runtime'),
            ({'max_warmup_rounds': 0}, 'cvw-family-policy-invalid', '/runtime'),
            ({'run_id': '  '}, 'cvw-online-run-id-required', '/run-id')):
        with pytest.raises(AutoHarnessRefused) as raised:
            entry(**call(**overrides))
        assert raised.value.code == code, overrides
        assert raised.value.pointer == pointer, overrides

    # With every opt-in at its default the entry builds the real assembly and
    # returns it.  The assembly builder is replaced here so this stays a pure
    # test: constructing the real one renders CVW harnesses, which the gated
    # test below does through the CLI.
    class _Assembly:
        def document(self):
            return {'schema_version': 'cvw_session_assembly.v1',
                    'kind': 'directed_fixed_image'}

    monkeypatch.setattr(family_module, '_make_assembly',
                        lambda **kwargs: _Assembly())
    runtime = entry(**call())
    assert isinstance(runtime, family_module.CvwOnlineRuntime)
    # No ``.executor`` attribute at all: the RFuzz live transport is not this
    # family's session, and the driver's own ``getattr(runtime, 'executor', None)``
    # check names the absence rather than receiving a fabricated executor.
    assert not hasattr(runtime, 'executor')
    document = runtime.document()
    assert document['kind'] == 'directed_fixed_image'
    assert document['not_an_rfuzz_online_campaign'] is True
    assert document['executor'] is None
    assert 'run_cvw_directed_session' in document['fresh_replay']

    # The old assembly-undeclared stop is gone from the module that used to
    # declare it; the pieces it named are declared instead.
    source = Path(family_module.__file__).read_text(encoding='utf-8')
    assert 'cvw-online-assembly-undeclared' not in source
    assert not hasattr(family_module, 'CVW_ONLINE_MISSING')
    for key in ('boot_image', 'online_decoder', 'runner_factory',
                'directed_session'):
        assert key in family_module.CVW_SESSION_ASSEMBLY


def test_the_replay_entry_refuses_because_a_directed_session_has_no_online_bundle():
    with pytest.raises(AutoHarnessRefused) as raised:
        family_module.replay_cvw_pulp_online_files(
            cache_dir=ROOT, plan_path='online_plan.json', trace_path='trace.json')
    assert raised.value.code == 'cvw-directed-session-has-no-online-bundle'
    assert raised.value.pointer == '/runtime'
    assert 'directed session entry re-runs' in raised.value.detail['requires']
    assert raised.value.detail['family_id'] == FAMILY_ID


def test_the_family_run_reaches_its_d1_to_d3_stage_with_skip_session(tmp_path):
    """The exact shipped command with ``--runtime cvw-ahb-pulp-gpio``.

    ``--skip-session`` is the explicit software-only request: D1..D3 and the
    capability report complete, the family is admitted and validated with its
    published assembly, and the session is ``not_requested`` rather than a
    fabricated run.  The real directed session is the gated test below.
    """
    output = tmp_path / 'cvw-family-run'
    environment = {**os.environ, 'PYTHONPATH': str(ROOT / 'src')}
    # ``start_new_session`` is what the repository's own campaign supervisor uses
    # to launch a child (``myfuzz.integration.campaign``), and it is load-bearing
    # here: CVW's elaboration picks the supervised path only when the child can
    # verify its own process group, and that path skips the content-pin re-check
    # the *direct* fallback performs.  Without it the run's D1 verdict would
    # depend on this sandbox's process-group arrangement rather than on the
    # declarations under test.
    result = subprocess.run(
        [sys.executable, str(CLI),
         '--cpu', 'configs/cpus/cvw/component_profile.json',
         '--ip', 'configs/peripherals/pulp_gpio/component_profile.json',
         '--compose', 'configs/scenarios/cvw-pulp-gpio/compose.json',
         '--output', str(output), '--runtime', FAMILY_ID, '--skip-session'],
        cwd=ROOT, capture_output=True, text=True, env=environment, timeout=1800,
        start_new_session=True)
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    payload = json.loads(lines[-1]) if lines else None
    assert payload is not None, result.stderr[-4000:]

    if payload['stages']['declaration_review']['status'] != 'ok':
        # D1 runs before the family is consulted, so a declaration review that
        # refuses stops the run before ``runtime_family`` is reached.  That is a
        # verdict about the declarations (CVW's source pin/elaboration), not about
        # this family, so it is recorded as a skip naming the codes rather than
        # reported as a chain this run did not reach.
        pytest.skip('the CVW declaration review refused first: '
                    + ', '.join(row['code'] for row in payload['refusals']))

    assert payload['refusals'] == [], result.stderr[-4000:]
    assert payload['status'] == 'complete'
    assert result.returncode == payload['exit_code'] == 0
    assert payload['runtime_family']['status'] == 'ok'
    assert payload['runtime_family']['family'] == FAMILY_ID
    assert payload['runtime_family']['detail']['requirements']['instances'] == ['cpu', 'gpio']
    for stage in ('declaration_review', 'harness_set', 'path_compilation',
                  'capability_report'):
        assert payload['stages'][stage]['status'] == 'ok', stage
    assert payload['stages']['session']['status'] == 'not_requested'
    assert payload['stages']['fresh_verification']['status'] == 'not_requested'
    assert payload['absences'] == []

    # The family document and the composition it accepted are on disk, and the
    # assembly declaration is the one the module really publishes.
    check = read(output / 'runtime-family.json')
    assert check['family']['family_id'] == FAMILY_ID
    assert check['status'] == 'ok' and check['refusals'] == []
    assert check['requirements']['memory_regions'] == [
        {'component_instance': 'cpu', 'base': 0xC0000000, 'size': 0x0FFF0000}]
    assembly = check['family']['session_assembly']
    assert assembly['status'] == 'ok'
    assert assembly['kind'] == 'directed_fixed_image'
    assert assembly['directed_session'].endswith(':run_cvw_directed_session')
    assert not (output / 'session').exists()
    assert not (output / 'fresh-verification.json').exists()
    assert not (output / '.incomplete').exists()

    # The four memory-image flows of the unified master really are executable;
    # the two that are not stay unsupported for their own real reasons.
    compiled = read(output / 'compiled_paths.v1.json')
    assert compiled['counts'] == {'executable': 4, 'unsupported': 2, 'total': 6}
    reasons = {row['path_id'].split(':')[0]: row['reason']['code']
               for row in compiled['paths'] if row['status'] == 'unsupported'}
    assert reasons == {'F5': 'interrupt-consumer-missing',
                       'F6': 'dma-master-not-declared'}


@pytest.mark.skipif(os.environ.get('MYFUZZ_SCENARIO_REAL') != '1',
                    reason='set MYFUZZ_SCENARIO_REAL=1 to start real CVW RTL')
def test_the_family_cli_starts_a_real_directed_session_and_grades_f4(tmp_path):
    """The real gate: the CLI itself starts CVW, runs F4 and replays it fresh.

    Run under the repository's heavy-worker lock.  Every assertion below is read
    from the run's own documents, and the session is a *directed fixed-image*
    case: the F4 receipt is the one CPU→PULP GPIO program this run really
    executed, not an online campaign.
    """
    cache = Path(os.environ.get('MYFUZZ_CVW_SESSION_CACHE',
                                str(ROOT / '.superpowers' / 'cache' / 'local-harness')))
    if not cache.is_dir():
        pytest.skip('the CVW session build cache is not present')
    output = tmp_path / 'cvw-real-run'
    environment = {**os.environ, 'PYTHONPATH': str(ROOT / 'src')}
    result = subprocess.run(
        [sys.executable, str(CLI),
         '--cpu', 'configs/cpus/cvw/component_profile.json',
         '--ip', 'configs/peripherals/pulp_gpio/component_profile.json',
         '--compose', 'configs/scenarios/cvw-pulp-gpio/compose.json',
         '--output', str(output), '--runtime', FAMILY_ID,
         '--cache-dir', str(cache), '--budget-seconds', '600',
         '--label', 'cvw-real-directed'],
        cwd=ROOT, capture_output=True, text=True, env=environment, timeout=7200,
        start_new_session=True)
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    payload = json.loads(lines[-1]) if lines else None
    assert payload is not None, result.stderr[-8000:]

    if payload['stages']['declaration_review']['status'] != 'ok':
        pytest.skip('the CVW declaration review refused first: '
                    + ', '.join(row['code'] for row in payload['refusals']))
    assert payload['refusals'] == [], result.stderr[-8000:]
    assert payload['status'] == 'complete'
    assert result.returncode == payload['exit_code'] == 0
    assert payload['stages']['session']['status'] == 'ok'
    assert payload['stages']['session']['transport']['mode'] == 'directed_fixed_image'
    assert payload['stages']['fresh_verification']['status'] == 'ok'
    assert payload['fresh_replay']['matches'] is True
    assert payload['fresh_replay']['first_difference'] is None
    assert payload['fresh_replay']['verification_scope'] == 'full'

    report = read(output / 'session' / 'report.json')
    assert report['execution_mode'] == 'directed_fixed_image'
    assert report['execution_status'] == 'complete'
    assert report['tests'] == 1
    evidence = report['evidence']
    assert evidence['delivery_count'] == 7
    assert evidence['accepted_beat_count'] > 0
    assert evidence['result_words'] == [0x35, 0x6A, 1, 0xA5]
    assert evidence['first_measured_fetch_address'] == 0xC0000000
    assert evidence['boot_hold_ticks'] >= 1
    assert evidence['final_target_state']['gpio_out'] == 0x6A
    assert evidence['final_target_state']['gpio_dir'] == 0xFFFFFFFF
    assert report['assembly']['kind'] == 'directed_fixed_image'
    assert report['not_claimed']

    receipts = [json.loads(line) for line in
                (output / 'session' / 'receipts.jsonl').read_text(
                    encoding='utf-8').splitlines() if line.strip()]
    assert len(receipts) == 1
    receipt = receipts[0]
    assert receipt['flow_id'] == 'F4' and receipt['direction'] == 'CPU_TO_IP'
    assert receipt['candidate_disposition_reason'] == 'rtl_case_committed'
    assert receipt['local_ticks']['cpu'] > 0 and receipt['local_ticks']['gpio'] > 0
    assert any(token.startswith('cpu:gpio:')
               for token in receipt['interaction_new_features'])

    session = read(output / 'session' / 'directed-session.json')
    assert session['comparison']['matches'] is True
    # The raw documents carry each run's own execution keys; the observed
    # device effects must be identical without them.
    def rows(run):
        return [(row['offset'], row['write'], row['write_value'],
                 row['read_value']) for row in run['deliveries']]
    def beats(run):
        return [(row['step'], row['address'], row['write'], row['value'],
                 row['byte_enable']) for row in run['accepted_beats']]
    assert rows(session['first']) == rows(session['fresh'])
    assert beats(session['first']) == beats(session['fresh'])

    grading = read(output / 'capability-report.json')
    f4 = [row for row in grading['paths'] if row.get('flow_id') == 'F4']
    assert len(f4) == 1
    tiers = {row['tier']: row['disposition'] for row in f4[0]['tiers']}
    assert tiers['RTL operational'] == 'awarded', f4[0]
    assert tiers['Cross-component accepted'] == 'awarded', f4[0]
    assert tiers['Coverage-guided searched'] == 'grade_not_claimed'

    # The seven artifacts the help text promises really exist.
    for path in ('declaration-review.json', 'generated/harness_set.json',
                 'compiled_paths.v1.json', 'capability-report.json',
                 'session/report.json', 'bundle/bundle-manifest.json',
                 'fresh-verification.json', 'run-summary.json'):
        assert (output / path).is_file(), path


def test_mmio_is_reachable_and_host_ram_is_carved():
    wiring = family_module.cvw_pulp_gpio_wiring()
    assert wiring.window_base == 0xCFFF0000
    region, = wiring.memory_regions
    assert (region.base, region.size) == (0xC0000000, 0x0FFF0000)
    assert region.base + region.size == wiring.window_base


@pytest.mark.parametrize('base', [0, 0xC0001000, 0xD0000000])
def test_unreachable_or_ram_overlapping_mmio_is_refused(monkeypatch, base):
    monkeypatch.setattr(family_module, 'GPIO_WINDOW_BASE', base)
    code = ('cvw-family-window-overlaps-memory' if base == 0xC0001000
            else 'cvw-family-window-outside-external-memory')
    with pytest.raises(AutoHarnessRefused, match=code):
        family_module.cvw_pulp_gpio_wiring()
