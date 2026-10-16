"""The CVW runtime family: registered, derived from the real profiles, honest stop.

``cvw-ahb-pulp-gpio`` is the third family of the P7-E driver's closed set and the
first non-PULP one.  Its CPU is CVW (CORE-V Wally) at its **unified** AHB-Lite
memory master ``cpu.external_bus`` - the EBU arbitrates the IFU and the LSU onto
that one bus, so the profile declares a single ``memory_master`` endpoint and no
instruction/data pair - and its device is one ``pulp_gpio`` on APB3 in a 4 KiB
window, with the CPU's own external-memory region as the only RAM resource.

The four claims this file pins, each with a guard that can fail:

* the family is registered and selectable by id, and its id/entry points are the
  ones the family module declares (a drifted literal is caught);
* an unknown family id is still refused by name - the set did not become
  "anything goes" when a third entry was added;
* the family's declared shape (component ids, protocols, endpoint, window,
  memory region, boot base) is what the two real profiles and the pinned derived
  configuration actually say, and a *mutated* declaration is refused by name
  (the scratch-tree tests below are those RED guards);
* the run reaches its honest stage: D1..D3 plus the capability report complete
  with ``--runtime cvw-ahb-pulp-gpio``, the session appears as the named absence
  ``client-binary-required``, and the runtime entry point itself refuses with
  ``cvw-online-assembly-undeclared`` before any RTL, session directory or
  heavy-worker lock exists.

Nothing here fabricates a session: no test asserts that a CVW RFuzz campaign
ran, because it cannot run yet (see the family module's ``CVW_ONLINE_MISSING``).
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


def test_the_family_requirements_come_from_its_own_declaration():
    facts = wiring_facts(family())
    assert facts['instances'] == ['cpu', 'gpio']
    assert [(row['instance_id'], row['device_id'], row['base'], row['size'])
            for row in facts['windows']] == [('gpio', 'gpio', 0, 4096)]
    assert [(row['component_instance'], row['base'], row['size'])
            for row in facts['memory_regions']] == [('cpu', 0xC0000000, 0x10000000)]


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
    assert [row['function'] for row in cpu_endpoints] == ['memory_master']
    cpu_endpoint = cpu_endpoints[0]
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
        'protocol': ['apb', '3'], 'window': {'base': 0, 'size': 4096}}
    assert capabilities['memory'] == {
        'component': 'cpu',
        'regions': [{'memory_id': 'ram', 'base': 0xC0000000, 'size': 0x10000000}]}

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
# (d) the run's honest stage, and the entry point's honest stop
# ---------------------------------------------------------------------------

def test_the_runtime_entry_refuses_by_name_without_starting_rtl(tmp_path):
    """The live path stops at the real gap, before RTL, a session dir or a lock."""
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

    assert raised.value.code == 'cvw-online-assembly-undeclared'
    assert raised.value.pointer == '/runtime'
    detail = raised.value.detail
    assert detail['family_id'] == FAMILY_ID
    assert [row['requirement'] for row in detail['missing']] == \
        ['boot_image', 'online_decoder', 'runner_factory']
    assert detail['declared']['cpu']['endpoint_id'] == 'cpu.external_bus'
    assert detail['not_started']['rtl_processes'] == 0

    # Nothing was created: no session directory, and the repository's one heavy
    # worker lock was never taken for a run that cannot proceed.
    assert not (tmp_path / 'session').exists()
    assert not (tmp_path / '.superpowers' / 'sdd' / 'stage2-heavy-worker.lock').exists()
    assert sorted(path.name for path in tmp_path.iterdir()) == ['client']


def test_the_opt_in_observations_are_refused_by_name():
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

    # With every opt-in at its default the refusal is the assembly gap, not a
    # policy: the defaults themselves are what the family ships.
    with pytest.raises(AutoHarnessRefused) as raised:
        entry(**call())
    assert raised.value.code == 'cvw-online-assembly-undeclared'


def test_the_replay_entry_refuses_because_no_session_can_have_produced_a_bundle():
    with pytest.raises(AutoHarnessRefused) as raised:
        family_module.replay_cvw_pulp_online_files(
            cache_dir=ROOT, plan_path='online_plan.json', trace_path='trace.json')
    assert raised.value.code == 'cvw-online-assembly-undeclared'
    assert 'nothing to replay' in raised.value.detail['requires']


def test_the_family_run_reaches_its_d1_to_d3_stage_and_names_the_missing_session(tmp_path):
    """The exact shipped command with ``--runtime cvw-ahb-pulp-gpio``.

    No client binary is named, so D1..D3 and the capability report all complete
    and the session is the *named absence* ``client-binary-required`` - the family
    is admitted and validated, and nothing pretends a session ran.  The driver
    reports ``refused``/exit 1 for a named absence (``--skip-session`` is the
    explicit way to ask for a software-only run), with an empty ``refusals``
    list: nothing was refused, one stage is absent and its reason is written.
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
         '--output', str(output), '--runtime', FAMILY_ID],
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
    assert payload['status'] == 'refused'
    assert result.returncode == payload['exit_code'] == 1
    assert payload['runtime_family']['status'] == 'ok'
    assert payload['runtime_family']['family'] == FAMILY_ID
    assert payload['runtime_family']['detail']['requirements']['instances'] == ['cpu', 'gpio']
    for stage in ('declaration_review', 'harness_set', 'path_compilation',
                  'capability_report'):
        assert payload['stages'][stage]['status'] == 'ok', stage
    assert payload['stages']['session']['status'] == 'absent'
    assert payload['stages']['session']['code'] == 'client-binary-required'
    assert payload['stages']['fresh_verification']['status'] == 'absent'
    assert [row['code'] for row in payload['absences']] == \
        ['client-binary-required', 'fresh-replay-requires-a-session']

    # The family document and the composition it accepted are on disk.
    check = read(output / 'runtime-family.json')
    assert check['family']['family_id'] == FAMILY_ID
    assert check['status'] == 'ok' and check['refusals'] == []
    assert check['requirements']['memory_regions'] == [
        {'component_instance': 'cpu', 'base': 0xC0000000, 'size': 0x10000000}]
    assert not (output / 'session').exists()
    assert not (output / 'fresh-verification.json').exists()
    # A named absence still marks the run incomplete: it is not a finished run.
    assert (output / '.incomplete').is_file()

    # The four memory-image flows of the unified master really are executable;
    # the two that are not stay unsupported for their own real reasons.
    compiled = read(output / 'compiled_paths.v1.json')
    assert compiled['counts'] == {'executable': 4, 'unsupported': 2, 'total': 6}
    reasons = {row['path_id'].split(':')[0]: row['reason']['code']
               for row in compiled['paths'] if row['status'] == 'unsupported'}
    assert reasons == {'F5': 'interrupt-consumer-missing',
                       'F6': 'dma-master-not-declared'}
