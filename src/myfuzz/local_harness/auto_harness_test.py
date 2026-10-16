"""P7-E: one command from trusted declarations to a graded capability report.

The plan's target is a single invocation that chains the already-accepted P7
stages and then, *only if the caller opts in*, runs a real session against a
named runtime family:

    D1 ``declaration_review`` -> ``declaration-review.json``
    D2 ``harness_set``        -> ``generated/`` (one harness per component)
    D3 ``compiled_paths``     -> ``compiled_paths.v1.json``
    D4 ``capability_report``  -> ``capability-report.json``
       plus, when a family and a client binary are named: ``session/``,
       ``bundle/`` and ``fresh-verification.json``

Three rules shape this module, and each has its own refusal code.

**The runtime family is named, never guessed.**  No module in this repository
composes an arbitrary composition into a runnable executor: each family owns
its boot image, its pin wiring and its ownership map.  ``--runtime`` therefore
selects one explicitly-registered family and the composition is then *validated
against that family's own declared requirements* - its declared component ids,
instances, MMIO windows and memory regions, read from the family's wiring
declaration rather than restated here.  A mismatch is refused with a ``code``
and a JSON ``pointer``; it is never silently adapted.

**Refuse, then generate, and never leave a half-run.**  Every refusal names a
``code`` (or a list of them) and a JSON ``pointer``, the refusing stage's own
document is written first, and the output directory always ends with a
``run-summary.json``.  Until every requested stage has completed the directory
also carries an ``.incomplete`` marker, so a stopped run cannot be mistaken for
a finished one.

**Never fake a stage.**  A stage that could not run is reported as a named
absence with a reason - not as zeros, not as an omitted key.  Without a runtime
family (or without a client binary, or with an unusable build cache) the run
still emits D1..D3 plus ``capability-report.json``; ``fresh-verification.json``
is written only when a fresh replay really happened.

Every document written here is the real product of the real module: the
declaration review is rendered by
:func:`myfuzz.local_harness.declaration_review.review_document_json`, the
harness set and wiring contract are the bytes of
:func:`myfuzz.local_harness.harness_set.generate_harness_set`, the compiled
paths come from :func:`myfuzz.scenario.compiled_paths.compile_paths` and the
report from :func:`myfuzz.scenario.capability_report.build_capability_report`.
The summary reads each stage's verdict back from that stage's document.

Superseded boundary (kept as a record, no longer true)
------------------------------------------------------

This block used to state that both shipped runtime families were unreachable
through the CLI: they wire two instances of one PULP GPIO profile, and D3 keyed
its input-layout annotation by ``(endpoint_id, role)``, so the second instance
was refused with ``duplicate-layout-field`` and no compiled paths existed.

That is no longer the case.  ``compiled_paths._layout_annotations`` now keys the
annotation by ``(component.instance_id, endpoint.endpoint_id, role)``, so a
composition with two instances of one profile compiles; the full chain runs from
this CLI for exactly that shape.  Verified end to end on 2026-10-14 with two
real sessions (``runs/p7-e2e-run2-20261014-185652`` on ``ibex-pulp-dual-source``
and ``runs/p7-e2e-cv32-20261014-185910`` on ``cv32e40p-pulp-dual-source``):
D1..D4, 200 real case receipts each, and ``fresh-verification.json`` with
``matches:true`` over the whole trace.

The record is kept rather than deleted because the failure mode is instructive:
a stale docstring outlived the defect it described and was still telling readers
that a working path was unreachable.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
import contextlib
import fcntl
import hashlib
import importlib
import json
import os
from pathlib import Path
import shutil
import traceback

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.local_harness.declaration_review import (review_document_json,
                                                     review_profiles)
from myfuzz.local_harness.harness_set import (HarnessSetRefused,
                                              generate_harness_set,
                                              load_compose)
from myfuzz.scenario.capability_report import (CapabilityReportRefused,
                                               build_capability_report)
from myfuzz.scenario.compiled_paths import (PathCompilationError,
                                            compile_paths,
                                            load_path_compile_request)

#: Version of the driver's own summary document.
AUTO_HARNESS_SCHEMA = 'auto_harness_test_run.v1'
#: Version of the runtime-family check document written before generation.
RUNTIME_CHECK_SCHEMA = 'runtime_family_check.v1'
#: Version of the fresh-replay conclusion document.
FRESH_VERIFICATION_SCHEMA = 'fresh_verification.v1'
#: Version of the authenticated-prefix bundle manifest.
BUNDLE_SCHEMA = 'authenticated_prefix_bundle.v1'
#: Version of the per-stage refusal record.
REFUSAL_SCHEMA = 'auto_harness_stage_refusal.v1'

#: Shared identity-keyed local harness cache of this repository.
DEFAULT_CACHE_DIR = '.superpowers/cache/local-harness'
#: The single heavy-worker lock every real-RTL run in this repository takes.
HEAVY_WORKER_LOCK = '.superpowers/sdd/stage2-heavy-worker.lock'

#: Stage verdicts.
OK = 'ok'
REFUSED = 'refused'
ABSENT = 'absent'
NOT_REQUESTED = 'not_requested'

#: Run verdicts.
RUN_COMPLETE = 'complete'
RUN_REFUSED = 'refused'
RUN_DIFFERENCE = 'difference'

EXIT_COMPLETE = 0
EXIT_REFUSED = 1
EXIT_DIFFERENCE = 2

#: Files the fresh replay authenticates inside ``bundle/``.  The bundle is a
#: byte-identical second view of these, so the replay reads the bundle itself.
BUNDLE_SIDECARS = ('online_run_identity.json', 'report.json')


class AutoHarnessRefused(ValueError):
    """The driver refuses to continue. ``code`` names the fact, ``pointer`` locates it."""

    def __init__(self, code: str, pointer: str = '', detail=None):
        self.code = code
        self.pointer = pointer
        self.detail = detail
        super().__init__(f'{code} at {pointer or "/"}')


def _refuse(code, pointer='', detail=None):
    raise AutoHarnessRefused(code, pointer, detail)


# ---------------------------------------------------------------------------
# the runtime families this repository can really start
# ---------------------------------------------------------------------------

class RuntimeFamily:
    """One explicitly-named way to turn a validated composition into real RTL.

    The record names *what the family requires of a composition* and *which
    shipped entry points build and replay it*.  The topology facts (instances,
    MMIO windows, memory regions) are deliberately **not** restated here: they
    are read from the family's own wiring declaration by :func:`wiring_facts`,
    so a family cannot be declared more generously than the wiring it builds.
    """

    def __init__(self, *, family_id, cpu_component_id, cpu_profile,
                 device_component_id, device_protocol, device_endpoint_function,
                 cpu_master_protocol, wiring_declaration, runtime_entry,
                 replay_entry, note=''):
        self.family_id = family_id
        self.cpu_component_id = cpu_component_id
        self.cpu_profile = cpu_profile
        self.device_component_id = device_component_id
        self.device_protocol = tuple(device_protocol)
        self.device_endpoint_function = device_endpoint_function
        self.cpu_master_protocol = tuple(cpu_master_protocol)
        self.wiring_declaration = wiring_declaration
        self.runtime_entry = runtime_entry
        self.replay_entry = replay_entry
        self.note = note

    def document(self) -> dict:
        return {'family_id': self.family_id,
                'cpu_component_id': self.cpu_component_id,
                'cpu_profile': self.cpu_profile,
                'device_component_id': self.device_component_id,
                'device_protocol': list(self.device_protocol),
                'device_endpoint_function': self.device_endpoint_function,
                'cpu_master_protocol': list(self.cpu_master_protocol),
                'wiring_declaration': self.wiring_declaration,
                'runtime_entry': self.runtime_entry,
                'replay_entry': self.replay_entry,
                'note': self.note}


_SHARED_DUAL_SOURCE = {
    'device_component_id': 'pulp_gpio',
    'device_protocol': ('apb', '3'),
    'device_endpoint_function': 'mmio_slave',
    'cpu_master_protocol': ('obi', '1'),
    'wiring_declaration':
        'myfuzz.scenario.ibex_pulp_dual_source:dual_source_wiring',
}

#: The closed set of runtime families this driver may start.  Selecting a
#: family by id is the honest model - building a composition into an executor
#: generically does not exist in this repository yet - and every family below
#: is validated against the composition before anything is generated.
RUNTIME_FAMILIES = {
    family.family_id: family for family in (
        RuntimeFamily(
            family_id='cv32e40p-pulp-dual-source',
            cpu_component_id='cv32e40p',
            cpu_profile='configs/cpus/cv32e40p/component_profile.json',
            runtime_entry=('myfuzz.integration.cv32e40p_pulp_online'
                           ':make_cv32e40p_pulp_online_runtime'),
            replay_entry=('myfuzz.integration.cv32e40p_pulp_online'
                          ':replay_cv32e40p_pulp_online_files'),
            note=('reset-free CV32E40P and two PULP GPIO cores; the CPU has no '
                  'authenticated RVFI retirement profile, so retirement and '
                  'native IRQ receipts are refused by its factory'),
            **_SHARED_DUAL_SOURCE),
        RuntimeFamily(
            family_id='ibex-pulp-dual-source',
            cpu_component_id='ibex_obi_local',
            cpu_profile='configs/cpus/ibex_obi_local/component_profile.json',
            runtime_entry=('myfuzz.integration.ibex_pulp_online'
                           ':make_ibex_pulp_online_runtime'),
            replay_entry=('myfuzz.integration.ibex_pulp_online'
                          ':replay_ibex_pulp_online_files'),
            note=('Ibex and two PULP GPIO cores on the same shared dual-source '
                  'wiring and the same declared ownership map'),
            **_SHARED_DUAL_SOURCE),
        # CVW is the unified-memory shape: cpu ``cvw`` (CORE-V Wally) on its ONE
        # AHB-Lite memory master ``cpu.external_bus`` - the EBU arbitrates the
        # IFU and the LSU onto that single bus, so the profile declares no
        # instruction/data pair - wired to ONE ``pulp_gpio`` device (APB3,
        # ``gpio.bus``, full-word MMIO) in a 4 KiB window, with the CPU's own
        # external-memory region as the only RAM resource.  Its device protocol
        # is therefore APB3 rather than the PULP families' shared OBI, and its
        # requirements are read from the family's own declaration rather than
        # from ``_SHARED_DUAL_SOURCE``.
        RuntimeFamily(
            family_id='cvw-ahb-pulp-gpio',
            cpu_component_id='cvw',
            cpu_profile='configs/cpus/cvw/component_profile.json',
            device_component_id='pulp_gpio',
            device_protocol=('apb', '3'),
            device_endpoint_function='mmio_slave',
            cpu_master_protocol=('ahb-lite', '1'),
            wiring_declaration=('myfuzz.integration.cvw_pulp_online'
                                ':cvw_pulp_gpio_wiring'),
            runtime_entry=('myfuzz.integration.cvw_pulp_online'
                           ':make_cvw_pulp_online_runtime'),
            replay_entry=('myfuzz.integration.cvw_pulp_online'
                          ':replay_cvw_pulp_online_files'),
            note=('unified AHB-Lite CVW external bus and one PULP GPIO core on '
                  'APB3; the family is admitted and validated, and its runtime '
                  'entry point refuses by name (cvw-online-assembly-undeclared) '
                  'until a CVW boot program, online decoder and runner factory '
                  'are declared')),
    )
}


def known_family_ids() -> list:
    """The families this driver knows, sorted so a refusal can name them."""
    return sorted(RUNTIME_FAMILIES)


def runtime_family(family_id) -> RuntimeFamily:
    """Resolve an explicitly-named family, or refuse naming the known ones."""
    if family_id is None or (isinstance(family_id, str)
                             and not family_id.strip()):
        _refuse('runtime-family-required', '/runtime',
                {'known': known_family_ids(),
                 'requires': 'an explicit --runtime <family-id>; this driver '
                             'never guesses which wiring a composition belongs to'})
    if type(family_id) is not str:
        _refuse('runtime-family-required', '/runtime',
                {'observed': type(family_id).__name__, 'known': known_family_ids()})
    family = RUNTIME_FAMILIES.get(family_id)
    if family is None:
        _refuse('runtime-family-unknown', '/runtime',
                {'requested': family_id, 'known': known_family_ids()})
    return family


def _load_entry(spec: str, *, code: str, pointer: str, detail=None):
    """Resolve one ``module:attribute`` entry point, or refuse by name."""
    module_name, separator, attribute = spec.partition(':')
    if not separator or not module_name or not attribute:
        _refuse(code, pointer, {'entry': spec, 'requires': 'module:attribute',
                                **(detail or {})})
    try:
        module = importlib.import_module(module_name)
    except ImportError as error:
        _refuse(code, pointer, {'entry': spec, 'error': str(error),
                                **(detail or {})})
    entry = getattr(module, attribute, None)
    if not callable(entry):
        _refuse(code, pointer, {'entry': spec,
                                'requires': 'a callable attribute',
                                **(detail or {})})
    return entry


def wiring_facts(family: RuntimeFamily) -> dict:
    """The topology the family's own wiring declaration requires.

    These are read from the shipped ``pulp_dual_source_wiring.v1`` declaration
    the factory builds from, never restated in this driver, so the validation
    below cannot drift from the RTL the family really starts.
    """
    declaration = _load_entry(
        family.wiring_declaration, code='runtime-wiring-declaration-unavailable',
        pointer='/runtime', detail={'family_id': family.family_id})
    wiring = declaration()
    return {
        'instances': list(wiring.sessions),
        'windows': [{'instance_id': component, 'device_id': device_id,
                     'base': base, 'size': size}
                    for device_id, base, size, component in wiring.windows],
        'memory_regions': [{'component_instance': wiring.memory_component,
                            'base': region.base, 'size': region.size}
                           for region in wiring.memory_regions],
    }


# ---------------------------------------------------------------------------
# small document helpers
# ---------------------------------------------------------------------------

def _json_bytes(value) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                       allow_nan=False) + '\n').encode('utf-8')


def _write(path: Path, value) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(_json_bytes(value))
    return path


def _sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(Path(path).read_bytes())


def _utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _resolve(base: Path, value) -> Path:
    path = Path(value)
    return path if path.is_absolute() else base / path


def _display(base: Path, path: Path) -> str:
    """A path as a repository-relative string when it lives under the root."""
    try:
        return path.resolve().relative_to(base.resolve()).as_posix()
    except ValueError:
        return str(path)


def _empty_stage(status=NOT_REQUESTED, **extra) -> dict:
    return {'status': status, 'code': None, 'pointer': None, 'detail': None,
            **extra}


# ---------------------------------------------------------------------------
# composition loading and family validation
# ---------------------------------------------------------------------------

class _Composition:
    """The declarations one composition names, loaded once."""

    def __init__(self, *, document, path, base_dir):
        # ``load_compose`` returns the *CPU row* of the closed declaration with
        # ``devices`` and ``memory`` folded into it - that is exactly the shape
        # ``generate_harness_set`` consumes, so it is kept and never rebuilt.
        self.document = document
        self.cpu = document
        self.path = Path(path)
        self.base_dir = Path(base_dir)
        self.compose_base = self.path.parent
        self.requests = {}
        self.profile_paths = {}
        self.profile_documents = {}
        self.profiles = {}
        self._load()

    def _load(self):
        rows = [self.cpu] + list(self.cpu['devices'])
        for row in rows:
            instance_id = row['instance_id']
            pointer = ('/cpu' if instance_id == self.cpu['instance_id']
                       else f'/devices/{self._device_index(instance_id)}')
            request_path = _resolve(self.compose_base, row['request'])
            try:
                request = json.loads(request_path.read_text(encoding='utf-8'))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                _refuse('component-request-unreadable', pointer,
                        {'instance_id': instance_id, 'request': row['request'],
                         'error': str(error)})
            profile_path = request.get('profile_path')
            if type(profile_path) is not str or not profile_path.strip():
                _refuse('component-request-profile-missing',
                        pointer + '/request' if pointer else '/request',
                        {'instance_id': instance_id, 'request': row['request']})
            resolved_profile = _resolve(self.base_dir, profile_path)
            try:
                profile_document = json.loads(
                    resolved_profile.read_text(encoding='utf-8'))
            except (OSError, UnicodeError, json.JSONDecodeError) as error:
                _refuse('component-profile-unreadable', pointer,
                        {'instance_id': instance_id, 'profile': profile_path,
                         'error': str(error)})
            try:
                profile = load_component_profile(profile_document)
            except (ValueError, KeyError, TypeError) as error:
                _refuse('component-profile-invalid', pointer,
                        {'instance_id': instance_id, 'profile': profile_path,
                         'error': str(error)})
            self.requests[instance_id] = request
            self.profile_paths[instance_id] = profile_path
            self.profile_documents[instance_id] = profile_document
            self.profiles[instance_id] = profile

    def _device_index(self, instance_id) -> int:
        for index, row in enumerate(self.cpu['devices']):
            if row['instance_id'] == instance_id:
                return index
        return 0

    def pointers(self) -> dict:
        pointers = {self.cpu['instance_id']: '/cpu'}
        for index, row in enumerate(self.cpu['devices']):
            pointers[row['instance_id']] = f'/devices/{index}'
        return pointers

    def masters(self, instance_id, function):
        return [endpoint for endpoint in self.profiles[instance_id].endpoints
                if endpoint.function == function]

    def instruction_master(self, instance_id):
        """The endpoint instruction fetches leave through.

        A core may expose either a dedicated instruction master (Ibex, CV32E40P)
        or one *unified* memory master that carries both fetches and data (CVW's
        AHB external bus, picorv32's ready/valid port).  Both are real shapes, so
        the unified form is accepted here rather than refused: requiring a
        dedicated instruction_memory_master would reject every unified-memory CPU
        even though its profile is accurate.  The unified case is only accepted
        when it is the *only* master, so there is no ambiguity about which port
        fetches leave through.
        """
        matches = self.masters(instance_id, 'instruction_memory_master')
        if len(matches) == 1:
            return matches[0]
        unified = self.masters(instance_id, 'memory_master')
        if not matches and len(unified) == 1:
            return unified[0]
        _refuse('cpu-instruction-master-ambiguous', '/cpu/request',
                {'instance_id': instance_id,
                 'profile': self.profile_paths[instance_id],
                 'declared': [endpoint.endpoint_id
                              for endpoint in self.profiles[instance_id].endpoints
                              if endpoint.function in ('instruction_memory_master',
                                                       'memory_master')],
                 'requires': 'exactly one endpoint with function '
                             'instruction_memory_master, or exactly one unified '
                             'memory_master when no instruction master is declared'})


def load_composition(path, *, base_dir) -> _Composition:
    """Load the ``harness_compose.v1`` document and every declaration it names.

    The loader's own refusals (``compose-field-missing`` and friends) travel
    unchanged; the extra refusals here are about the *request and profile files*
    the composition points at, which the loader does not open.
    """
    try:
        document = load_compose(path, base_dir=base_dir)
    except HarnessSetRefused:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        _refuse('compose-unreadable', '/compose',
                {'path': str(path), 'error': str(error)})
    return _Composition(document=document, path=path, base_dir=base_dir)


def _reviewed_profiles(paths, *, base_dir) -> set:
    return {_resolve(Path(base_dir), path).resolve() for path in paths}


def check_review_coverage(composition: _Composition, *, reviewed) -> list:
    """Every component the composition generates must be one D1 reviewed."""
    refusals = []
    rows = [('cpu', composition.cpu['instance_id'], '/cpu/request')]
    rows += [('device', row['instance_id'], f'/devices/{index}/request')
             for index, row in enumerate(composition.cpu['devices'])]
    for kind, instance_id, pointer in rows:
        profile = _resolve(composition.base_dir,
                           composition.profile_paths[instance_id]).resolve()
        if profile not in reviewed:
            refusals.append({
                'check': f'{kind}-profile-reviewed', 'code': 'composition-profile-not-reviewed',
                'pointer': pointer,
                'detail': {'instance_id': instance_id,
                           'profile': composition.profile_paths[instance_id],
                           'requires': 'a profile named by --cpu/--ip; the '
                                       'declaration review must cover every '
                                       'component this run generates'}})
    return refusals


def check_composition(composition: _Composition, *, family: RuntimeFamily,
                      facts: Mapping) -> dict:
    """Validate the composition against the family's declared requirements.

    Every requirement is evaluated independently so one run reports *all* the
    mismatches, each with its own ``code`` and JSON ``pointer``.  Nothing is
    defaulted and nothing is adapted: a composition that does not match the
    family is refused before any harness is generated.
    """
    rows = []
    refusals = []

    def note(check, *, code=None, pointer='', detail=None):
        status = OK if code is None else REFUSED
        row = {'check': check, 'status': status, 'code': code,
               'pointer': pointer, 'detail': detail}
        rows.append(row)
        if code is not None:
            refusals.append({'check': check, 'code': code, 'pointer': pointer,
                             'detail': detail})
        return code is None

    pointers = composition.pointers()
    cpu_instance = composition.cpu['instance_id']
    cpu_profile = composition.profiles[cpu_instance]

    note('cpu-component-id',
         code=(None if cpu_profile.component_id == family.cpu_component_id
               else 'runtime-family-cpu-component-mismatch'),
         pointer='/cpu/request',
         detail={'expected': family.cpu_component_id,
                 'observed': cpu_profile.component_id,
                 'profile': composition.profile_paths[cpu_instance],
                 'profile_pointer': '/component_id'})

    instruction = composition.masters(cpu_instance, 'instruction_memory_master')
    data = composition.masters(cpu_instance, 'data_memory_master')
    if not instruction and not data:
        # A core may carry fetches and data on ONE unified memory master instead
        # of a dedicated instruction/data pair: CVW's AHB-Lite external bus, and
        # picorv32's ready/valid port, are that shape.  This is exactly the rule
        # ``_Composition.instruction_master`` and ``compiled_paths._cpu_master``
        # already apply, so the family checks read the same declaration the same
        # way: the sole unified master fills both roles, and with several masters
        # the roles stay ambiguous and the composition is still refused below.
        unified = composition.masters(cpu_instance, 'memory_master')
        if len(unified) == 1:
            instruction = data = unified
    masters_ok = note(
        'cpu-master-endpoints',
        code=(None if instruction and data else 'runtime-family-cpu-master-missing'),
        pointer='/cpu/request',
        detail={'expected_functions': ['instruction_memory_master',
                                       'data_memory_master'],
                'or_sole_unified': 'memory_master',
                'declared': [endpoint.endpoint_id
                             for endpoint in cpu_profile.endpoints],
                'profile': composition.profile_paths[cpu_instance]})
    if masters_ok:
        mismatched = [endpoint.endpoint_id
                      for endpoint in {endpoint.endpoint_id: endpoint
                                       for endpoint in [*instruction, *data]}.values()
                      if list(endpoint.protocol or ()) != list(family.cpu_master_protocol)]
        note('cpu-master-protocol',
             code=(None if not mismatched
                   else 'runtime-family-cpu-master-protocol-mismatch'),
             pointer='/cpu/request',
             detail={'expected': list(family.cpu_master_protocol),
                     'endpoints': mismatched,
                     'profile': composition.profile_paths[cpu_instance]})
        declared_data = composition.cpu['data_endpoint']
        note('cpu-data-endpoint-pointer',
             code=(None if declared_data == data[0].endpoint_id
                   else 'runtime-family-cpu-data-endpoint-mismatch'),
             pointer='/cpu/data_endpoint',
             detail={'declared': declared_data,
                     'requires': data[0].endpoint_id,
                     'function': 'data_memory_master'})

    required_instances = list(facts['instances'])
    observed_instances = [cpu_instance, *[row['instance_id'] for row
                                          in composition.cpu['devices']]]
    missing = sorted(set(required_instances) - set(observed_instances))
    unexpected = sorted(set(observed_instances) - set(required_instances))
    note('instances',
         code=(None if not missing and not unexpected
               else 'runtime-family-instances-mismatch'),
         pointer='/devices',
         detail={'required': required_instances,
                 'observed': observed_instances,
                 'missing': missing, 'unexpected': unexpected,
                 'requires': 'the instance ids this family wires, exactly'})

    windows = {row['instance_id']: row for row in facts['windows']}
    for index, row in enumerate(composition.cpu['devices']):
        instance_id = row['instance_id']
        pointer = f'/devices/{index}'
        if instance_id not in required_instances:
            rows.append({'check': f'device[{instance_id}]', 'status': 'not_checked',
                         'code': None, 'pointer': pointer,
                         'detail': {'reason': 'the instance-set check already '
                                              'refused this instance'}})
            continue
        device_profile = composition.profiles[instance_id]
        device_pointer = pointers[instance_id]
        note(f'device[{instance_id}].component-id',
             code=(None if device_profile.component_id == family.device_component_id
                   else 'runtime-family-device-component-mismatch'),
             pointer=device_pointer + '/request',
             detail={'expected': family.device_component_id,
                     'observed': device_profile.component_id,
                     'profile': composition.profile_paths[instance_id],
                     'profile_pointer': '/component_id'})
        declared = row['bus_endpoint']
        matches = [endpoint for endpoint in device_profile.endpoints
                   if endpoint.endpoint_id == declared]
        endpoint = matches[0] if len(matches) == 1 else None
        problems = []
        if endpoint is None:
            problems.append({'fact': 'endpoint', 'declared': declared,
                             'requires': 'a declared endpoint of this profile'})
        else:
            if endpoint.function != family.device_endpoint_function:
                problems.append({'fact': 'function',
                                 'declared': endpoint.function,
                                 'requires': family.device_endpoint_function})
            if list(endpoint.protocol or ()) != list(family.device_protocol):
                problems.append({'fact': 'protocol',
                                 'declared': list(endpoint.protocol or ()),
                                 'requires': list(family.device_protocol)})
        note(f'device[{instance_id}].bus-endpoint',
             code=(None if not problems
                   else 'runtime-family-device-endpoint-mismatch'),
             pointer=device_pointer + '/bus_endpoint',
             detail={'declared': declared, 'problems': problems,
                     'endpoint_id': declared,
                     'declared_endpoints': [item.endpoint_id
                                            for item in device_profile.endpoints]})
        window = windows[instance_id]
        note(f'device[{instance_id}].device-id',
             code=(None if row['device_id'] == window['device_id']
                   else 'runtime-family-window-device-id-mismatch'),
             pointer=device_pointer + '/device_id',
             detail={'declared': row['device_id'],
                     'requires': window['device_id'],
                     'requires_pointer': 'the wiring declaration of this family'})
        for field in ('base', 'size'):
            note(f'device[{instance_id}].window-{field}',
                 code=(None if row[field] == window[field]
                       else 'runtime-family-window-mismatch'),
                 pointer=f'{device_pointer}/{field}',
                 detail={'declared': row[field], 'requires': window[field],
                         'instance_id': instance_id})

    declared_resources = composition.cpu['memory']
    missing_regions = []
    for region in facts['memory_regions']:
        match = next((resource for resource in declared_resources
                      if resource['component_instance'] == region['component_instance']
                      and resource['base'] == region['base']
                      and resource['size'] == region['size']
                      and resource['read'] is True
                      and resource['execute'] is True), None)
        if match is None:
            missing_regions.append(dict(region))
    note('memory-regions',
         code=(None if not missing_regions else 'runtime-family-memory-mismatch'),
         pointer='/memory',
         detail={'required': [dict(region) for region in facts['memory_regions']],
                 'missing': missing_regions,
                 'declared': [{'resource_id': resource['resource_id'],
                               'component_instance': resource['component_instance'],
                               'base': resource['base'], 'size': resource['size'],
                               'read': resource['read'], 'write': resource['write'],
                               'execute': resource['execute']}
                              for resource in declared_resources],
                 'requires': 'every region this family serves must be declared '
                             'readable and executable by the composition'})

    return {'schema_version': RUNTIME_CHECK_SCHEMA,
            'family': family.document(),
            'requirements': {'instances': list(facts['instances']),
                             'windows': [dict(row) for row in facts['windows']],
                             'memory_regions': [dict(row) for row in
                                                facts['memory_regions']]},
            'composition': {'path': str(composition.path),
                            'compose_base': str(composition.compose_base),
                            'requests': {instance: composition.profile_paths[instance]
                                         for instance in composition.profile_paths},
                            'instance_ids': observed_instances,
                            'windows': [{'instance_id': row['instance_id'],
                                         'device_id': row['device_id'],
                                         'base': row['base'], 'size': row['size']}
                                        for row in composition.cpu['devices']],
                            'memory': [{'resource_id': resource['resource_id'],
                                        'component_instance': resource['component_instance'],
                                        'base': resource['base'],
                                        'size': resource['size'],
                                        'read': resource['read'],
                                        'write': resource['write'],
                                        'execute': resource['execute']}
                                       for resource in declared_resources]},
            'rows': rows,
            'refusals': refusals,
            'status': OK if not refusals else REFUSED}


# ---------------------------------------------------------------------------
# D3 input: the real path_compile_request.v1 document
# ---------------------------------------------------------------------------

def test_capability_sidecar(composition: _Composition, instance_id,
                             declared: Sequence) -> tuple:
    """``(repository-relative path or None, source)`` for one IP capability sidecar.

    The sidecar is a *declaration* like any other, so it is never guessed from
    a component name: an explicitly supplied ``--ip-capability`` document is
    matched by the ``component_id`` it declares, and otherwise the shipped
    ``test_capability.json`` sitting next to the profile is used, because that
    is the layout every admitted IP profile in this repository uses.  When
    neither exists the device simply carries no sidecar, and that absence is
    reported in the run summary.
    """
    profile_path = composition.profile_paths[instance_id]
    profile = composition.profiles[instance_id]
    resolved_profile = _resolve(composition.base_dir, profile_path)
    matches = []
    for candidate in declared:
        path = _resolve(composition.base_dir, candidate)
        try:
            document = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            _refuse('ip-capability-unreadable', '/ip-capability',
                    {'path': str(candidate), 'error': str(error)})
        if document.get('component_id') == profile.component_id:
            matches.append(path)
    if len(matches) > 1:
        _refuse('ip-capability-ambiguous', '/ip-capability',
                {'component_id': profile.component_id,
                 'candidates': [str(path) for path in matches]})
    if matches:
        return _display(composition.base_dir, matches[0]), 'declared-option'
    sibling = resolved_profile.with_name('test_capability.json')
    if sibling.is_file():
        return _display(composition.base_dir, sibling), 'profile-sibling'
    return None, ABSENT


def build_path_compile_request(composition: _Composition, *,
                               wiring_path, ip_capabilities=()) -> tuple:
    """The real ``path_compile_request.v1`` document, plus its sidecar notes.

    The CPU's two master roles are read from the CPU profile's *declared*
    ``function`` values, never from an endpoint name: ``data_endpoint`` is the
    composition's own declaration and ``instruction_endpoint`` is the single
    declared ``instruction_memory_master``.  The wiring points at the contract
    D2 just wrote, so D3 compiles the harness set this run really generated.
    """
    cpu_instance = composition.cpu['instance_id']
    instruction = composition.instruction_master(cpu_instance)
    devices = []
    sidecars = []
    for row in composition.cpu['devices']:
        instance_id = row['instance_id']
        device = {'device_id': row['device_id'], 'instance_id': instance_id,
                  'profile': composition.profile_paths[instance_id]}
        sidecar, source = test_capability_sidecar(composition, instance_id,
                                                   ip_capabilities)
        if sidecar is not None:
            device['test_capability'] = sidecar
        sidecars.append({'instance_id': instance_id,
                         'profile': composition.profile_paths[instance_id],
                         'test_capability': sidecar, 'source': source})
        devices.append(device)
    document = {
        'schema_version': 'path_compile_request.v1',
        'cpu': {'instance_id': cpu_instance,
                'profile': composition.profile_paths[cpu_instance],
                'data_endpoint': composition.cpu['data_endpoint'],
                'instruction_endpoint': instruction.endpoint_id},
        'devices': devices,
        'wiring': {'source': str(wiring_path)},
    }
    return document, sidecars


# ---------------------------------------------------------------------------
# D4: the live session, its authenticated prefix and the fresh replay
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def _heavy_worker_lock(base_dir: Path):
    """Take the repository's single heavy-worker lock, or refuse by name."""
    path = Path(base_dir) / HEAVY_WORKER_LOCK
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a') as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            _refuse('heavy-worker-lock-held', '/session',
                    {'lock': str(path), 'error': str(error),
                     'requires': 'the single heavy-worker lock; another real-RTL '
                                 'run in this repository holds it'})
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _link_or_copy(source: Path, target: Path) -> None:
    """Second view of an authenticated artifact: hard link, else a byte copy."""
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(source, target)
    except OSError:
        shutil.copyfile(source, target)


def run_live_session(*, family: RuntimeFamily, session_dir, client_binary,
                     cache_dir, run_id, budget_seconds, max_tests, search_seed,
                     max_runs_per_batch, base_dir) -> dict:
    """Start one real family runtime and run the shared online transport.

    Preflight refusals (no client binary, unusable cache, invalid budget) are
    named here, before any RTL is started; the session itself is the shipped
    :func:`myfuzz.integration.scenario_rfuzz_live.run_scenario_rfuzz_live`.
    """
    if client_binary is None:
        _refuse('client-binary-required', '/client-binary',
                {'requires': 'the RFuzz client binary; no session can be '
                             'started without it'})
    client = _resolve(Path.cwd(), client_binary)
    if not client.is_file():
        _refuse('client-binary-missing', '/client-binary', {'path': str(client)})
    if type(budget_seconds) not in (int, float) or not 0 < budget_seconds <= 3600:
        _refuse('budget-seconds-invalid', '/budget-seconds',
                {'observed': budget_seconds, 'allowed': '0 < seconds <= 3600'})
    if type(max_tests) is not int or not 1 <= max_tests <= 100000:
        _refuse('max-tests-invalid', '/max-tests',
                {'observed': max_tests, 'allowed': '1 <= tests <= 100000'})
    if type(max_runs_per_batch) is not int or not 1 <= max_runs_per_batch <= 8:
        _refuse('max-runs-per-batch-invalid', '/max-runs-per-batch',
                {'observed': max_runs_per_batch, 'allowed': '1..8'})
    if search_seed is not None and (type(search_seed) is not int
                                    or not 0 <= search_seed < 2 ** 64):
        _refuse('search-seed-invalid', '/search-seed', {'observed': search_seed})
    cache = (_resolve(Path.cwd(), cache_dir) if cache_dir is not None
             else Path(base_dir) / DEFAULT_CACHE_DIR)
    if not cache.exists():
        _refuse('build-cache-missing', '/cache-dir',
                {'path': str(cache), 'requires': 'an existing shared build '
                 'cache; a session is not started when its harnesses would have '
                 'to be built from cold inside the run budget'})
    if not cache.is_dir():
        _refuse('build-cache-invalid', '/cache-dir', {'path': str(cache)})
    builder = _load_entry(family.runtime_entry, code='runtime-entry-unavailable',
                          pointer='/runtime', detail={'family_id': family.family_id})
    run_live = _load_entry(
        'myfuzz.integration.scenario_rfuzz_live:run_scenario_rfuzz_live',
        code='session-transport-unavailable', pointer='/session')
    runtime = builder(cache_dir=cache, run_id=run_id)
    executor = getattr(runtime, 'executor', None)
    if executor is None:
        _refuse('runtime-entry-has-no-executor', '/runtime',
                {'entry': family.runtime_entry,
                 'requires': 'an object exposing `.executor`'})
    with _heavy_worker_lock(Path(base_dir)):
        result = run_live(executor=executor, client_binary=client,
                          output_dir=Path(session_dir),
                          duration_seconds=budget_seconds, max_tests=max_tests,
                          search_seed=search_seed,
                          max_runs_per_batch=max_runs_per_batch)
    return {'output_dir': str(result.output_dir), 'tests': result.tests,
            'statuses': dict(result.statuses),
            'completed_feedback_exchanges': result.completed_feedback_exchanges,
            'client_returncode': result.client_returncode,
            'elapsed_seconds': result.elapsed_seconds,
            'effective_search_seconds': result.effective_search_seconds}


def write_authenticated_bundle(*, session_dir, bundle_dir) -> dict:
    """Second, byte-identical view of the session's authenticated artifacts.

    The fresh replay entry verifies the whole saved-bundle identity inside the
    directory it is pointed at, so the bundle carries every artifact that
    identity authenticates - including the identity envelope itself - and the
    replay below reads the bundle rather than the session directory.
    """
    session_dir = Path(session_dir)
    bundle_dir = Path(bundle_dir)
    if bundle_dir.exists() or bundle_dir.is_symlink():
        _refuse('bundle-directory-exists', '/session', {'path': str(bundle_dir)})
    envelope_path = session_dir / 'online_run_identity.json'
    if not envelope_path.is_file():
        _refuse('authenticated-prefix-missing', '/session',
                {'path': str(session_dir),
                 'requires': 'a saved online_run_identity.json envelope'})
    envelope = json.loads(envelope_path.read_text(encoding='utf-8'))
    identity = envelope.get('identity')
    if not isinstance(identity, Mapping) or not isinstance(
            identity.get('artifacts'), Mapping):
        _refuse('authenticated-prefix-invalid', '/session',
                {'path': str(envelope_path)})
    trace_name = identity.get('trace_file')
    if type(trace_name) is not str or trace_name not in identity['artifacts']:
        _refuse('authenticated-prefix-invalid', '/session',
                {'path': str(envelope_path), 'trace_file': trace_name})
    bundle_dir.mkdir(parents=True)
    names = sorted(set(identity['artifacts']) | set(BUNDLE_SIDECARS))
    files = []
    for name in names:
        source = session_dir / name
        if not source.is_file():
            continue
        target = bundle_dir / name
        _link_or_copy(source, target)
        files.append({'name': name, 'sha256': _sha256_file(target),
                      'matches_session': _sha256_file(target) == _sha256_file(source)})
    manifest = {'schema_version': BUNDLE_SCHEMA,
                'session_dir': str(session_dir),
                'identity_envelope': envelope_path.name,
                'identity_sha256': envelope.get('sha256'),
                'trace_file': trace_name,
                'plan_file': 'online_plan.json',
                'files': files,
                'not_copied': {'failures': 'saved inside the session directory, '
                                           'not authenticated by the run identity'},
                'status': OK}
    _write(bundle_dir / 'bundle-manifest.json', manifest)
    return manifest


def run_fresh_replay(*, family: RuntimeFamily, bundle_dir, cache_dir, base_dir) -> dict:
    """Replay the bundled authenticated prefix on fresh RTL processes.

    The conclusion document is written from the replay entry's own
    ``ReplayComparison``: ``matches``, ``first_difference``, the difference
    context and the verification scope are that object's values, not this
    driver's summary of them.
    """
    bundle_dir = Path(bundle_dir)
    manifest = json.loads((bundle_dir / 'bundle-manifest.json').read_text(
        encoding='utf-8'))
    replay = _load_entry(family.replay_entry, code='replay-entry-unavailable',
                         pointer='/runtime', detail={'family_id': family.family_id})
    cache = (_resolve(Path.cwd(), cache_dir) if cache_dir is not None
             else Path(base_dir) / DEFAULT_CACHE_DIR)
    comparison = replay(cache_dir=cache,
                        plan_path=bundle_dir / manifest['plan_file'],
                        trace_path=bundle_dir / manifest['trace_file'])
    document = {
        'schema_version': FRESH_VERIFICATION_SCHEMA,
        'matches': bool(comparison.matches),
        'first_difference': comparison.first_difference,
        'difference_context': comparison.difference_context,
        'verification_scope': comparison.verification_scope,
        'event_count': len(comparison.actual_trace.events),
        'semantic_sha256': comparison.actual_trace.semantic_sha256,
        'manifest_sha256': comparison.actual_trace.manifest_sha256,
        'replay_entry': family.replay_entry,
        'replayed_from': {'bundle': str(bundle_dir),
                          'plan': manifest['plan_file'],
                          'trace': manifest['trace_file']},
        'not_a_substitute_for': ('a fresh replay of the saved prefix is not a '
                                 'new search and confirms nothing the session '
                                 'did not already record'),
    }
    return document


# ---------------------------------------------------------------------------
# the driver
# ---------------------------------------------------------------------------

def run_auto_harness_test(*, cpu, ips, compose, output, base_dir='.',
                          runtime=None, client_binary=None, cache_dir=None,
                          build_cache=None, budget_seconds=60.0, max_tests=200,
                          search_seed=None, max_runs_per_batch=1,
                          skip_session=False, label=None,
                          ip_capabilities=()) -> dict:
    """Run every requested P7 stage and return the machine-readable summary.

    The returned summary is also written to ``<output>/run-summary.json`` and
    is the one JSON line the shipped CLI prints last.  ``exit_code`` inside it
    is the process exit code: ``0`` only when every requested stage completed,
    ``1`` when any stage refused or is absent, ``2`` when a fresh replay really
    ran and reported a difference.
    """
    base = Path(base_dir).resolve()
    output = Path(output)
    if not output.is_absolute():
        output = Path.cwd() / output
    # The runtime-family stage is one record, published under its own key and
    # inside ``stages`` (the same object), so a reader can see the family
    # verdict without walking the stage map and cannot read two different ones.
    family_stage = {'requested': runtime, 'family': None, 'status':
                    NOT_REQUESTED, 'code': None, 'pointer': None,
                    'detail': None, 'known': known_family_ids()}
    summary = {
        'schema_version': AUTO_HARNESS_SCHEMA,
        'status': RUN_REFUSED,
        'exit_code': EXIT_REFUSED,
        'label': label or output.name,
        'base_dir': str(base),
        'output': str(output),
        'started_utc': _utc_now(),
        'runtime_family': family_stage,
        'stages': {
            'declaration_review': _empty_stage(),
            'runtime_family': family_stage,
            'harness_set': _empty_stage(),
            'path_compilation': _empty_stage(),
            'session': _empty_stage(),
            'fresh_verification': _empty_stage(),
            'capability_report': _empty_stage(),
        },
        'refusals': [],
        'absences': [],
        'documents': {},
        'fresh_replay': None,
        'run_summary': {'path': None, 'reason': None},
    }

    def refuse(stage, code, pointer='', detail=None):
        entry = {'stage': stage, 'code': code, 'pointer': pointer,
                 'detail': detail}
        summary['refusals'].append(entry)
        if stage in summary['stages']:
            summary['stages'][stage].update(status=REFUSED, code=code,
                                            pointer=pointer, detail=detail)
        return entry

    def absent(stage, code, pointer='', reason=None, detail=None):
        entry = {'quantity': stage, 'code': code, 'pointer': pointer,
                 'reason': reason or code}
        summary['absences'].append(entry)
        summary['stages'][stage].update(status=ABSENT, code=code,
                                        pointer=pointer, reason=entry['reason'],
                                        detail=detail)
        return entry

    def record(key, path: Path, document=None):
        summary['documents'][key] = {
            'path': _display(base, path), 'sha256': _sha256_file(path),
            'schema_version': (document or {}).get('schema_version')
            if isinstance(document, Mapping) else None}

    # The output directory is owned by this run or not written at all.
    if output.exists() or output.is_symlink():
        summary['run_summary'] = {
            'path': None,
            'reason': ('the output directory already exists, so this run wrote '
                       'nothing: an existing run is never overwritten')}
        summary['refusals'].append({'stage': 'output', 'code':
                                    'output-directory-exists',
                                    'pointer': '/output',
                                    'detail': {'output': str(output),
                                               'requires': 'a new directory'}})
        return summary
    output.mkdir(parents=True)
    marker = output / '.incomplete'
    marker.write_bytes(_json_bytes({'schema_version': AUTO_HARNESS_SCHEMA,
                                    'status': 'started',
                                    'started_utc': summary['started_utc'],
                                    'output': str(output)}))

    def finish():
        complete = summary['status'] == RUN_COMPLETE
        summary['finished_utc'] = _utc_now()
        summary['exit_code'] = (EXIT_DIFFERENCE if summary['status'] == RUN_DIFFERENCE
                                else EXIT_COMPLETE if complete else EXIT_REFUSED)
        summary_path = output / 'run-summary.json'
        summary['run_summary'] = {'path': _display(base, summary_path),
                                  'reason': None}
        _write(summary_path, summary)
        if complete:
            # The marker is what makes a stopped run unmistakable, so it is
            # removed only after a run whose every requested stage completed.
            marker.unlink(missing_ok=True)
        return summary

    try:
        # -- D1: the declaration review is the first refusal point ----------
        review_paths = [cpu, *ips]
        try:
            review = review_profiles(review_paths, base_dir=base)
        except Exception as error:  # pragma: no cover - defensive
            traceback.print_exc()
            refuse('declaration_review', 'declaration-review-failed', '',
                   {'error': f'{type(error).__name__}: {error}'})
            return finish()
        review_path = output / 'declaration-review.json'
        review_path.write_text(review_document_json(review), encoding='utf-8')
        record('declaration_review', review_path, review)
        summary['stages']['declaration_review'].update(
            status=OK if review['status'] == OK else REFUSED,
            document=_display(base, review_path),
            refused=[{'component_id': component['component_id'],
                      'status': component['status'],
                      'rows': [{'code': row['code'], 'pointer': row['pointer'],
                                'status': row['status']}
                               for row in component['rows']
                               if row['status'] != OK]}
                     for component in review['components']
                     if component['status'] != OK])
        if review['status'] != OK:
            for component in review['components']:
                for row in component['rows']:
                    if row['status'] != OK:
                        summary['refusals'].append({
                            'stage': 'declaration_review',
                            'code': row['code'], 'pointer': row['pointer'],
                            'detail': {'component_id': component['component_id'],
                                       'status': row['status']}})
            return finish()

        # -- the composition and every declaration it names -----------------
        reviewed = _reviewed_profiles(review_paths, base_dir=base)
        try:
            composition = load_composition(compose, base_dir=base)
        except HarnessSetRefused as error:
            _write(output / 'harness-set-refusal.json',
                   {'schema_version': REFUSAL_SCHEMA, 'stage': 'harness_set',
                    'code': error.code, 'pointer': error.pointer,
                    'detail': error.detail})
            refuse('harness_set', error.code, error.pointer, error.detail)
            return finish()
        except AutoHarnessRefused as error:
            _write(output / 'harness-set-refusal.json',
                   {'schema_version': REFUSAL_SCHEMA, 'stage': 'harness_set',
                    'code': error.code, 'pointer': error.pointer,
                    'detail': error.detail})
            refuse('harness_set', error.code, error.pointer, error.detail)
            return finish()

        coverage = check_review_coverage(composition, reviewed=reviewed)
        family = None
        facts = None
        if runtime is not None:
            try:
                family = runtime_family(runtime)
                facts = wiring_facts(family)
            except AutoHarnessRefused as error:
                summary['runtime_family'].update(status=REFUSED, code=error.code,
                                                 pointer=error.pointer,
                                                 detail=error.detail,
                                                 family=None)
                check = {'schema_version': RUNTIME_CHECK_SCHEMA,
                         'family': {'requested': runtime},
                         'rows': [], 'refusals': [{'code': error.code,
                                                   'pointer': error.pointer,
                                                   'detail': error.detail}],
                         'status': REFUSED}
                check_path = _write(output / 'runtime-family.json', check)
                record('runtime_family', check_path, check)
                refuse('runtime_family', error.code, error.pointer, error.detail)
                return finish()
            summary['runtime_family'].update(status=OK, family=family.family_id,
                                             detail={'requirements': facts,
                                                     'note': family.note})
        if coverage:
            check = {'schema_version': RUNTIME_CHECK_SCHEMA,
                     'family': (family.document() if family else None),
                     'requirements': facts,
                     'rows': [], 'refusals': coverage, 'status': REFUSED}
            check_path = _write(output / 'runtime-family.json', check)
            record('runtime_family', check_path, check)
            for refusal in coverage:
                refuse('runtime_family', refusal['code'], refusal['pointer'],
                       refusal['detail'])
            return finish()
        if family is not None:
            check = check_composition(composition, family=family, facts=facts)
            check_path = _write(output / 'runtime-family.json', check)
            record('runtime_family', check_path, check)
            if check['status'] != OK:
                for refusal in check['refusals']:
                    refuse('runtime_family', refusal['code'], refusal['pointer'],
                           refusal['detail'])
                return finish()
            summary['runtime_family'].update(status=OK, code=None, pointer=None)

        # -- D2: generate one harness per component, or refuse the set ------
        build_cache_path = (None if build_cache is None
                            else _resolve(Path.cwd(), build_cache))
        try:
            harness_document = generate_harness_set(
                composition.document, base_dir=base,
                output_root=output / 'generated',
                compose_base=composition.compose_base,
                build_cache=build_cache_path, review=review)
        except HarnessSetRefused as error:
            refusal_path = _write(output / 'harness-set-refusal.json',
                                  {'schema_version': REFUSAL_SCHEMA,
                                   'stage': 'harness_set', 'code': error.code,
                                   'pointer': error.pointer, 'detail': error.detail})
            record('harness_set_refusal', refusal_path)
            refuse('harness_set', error.code, error.pointer, error.detail)
            return finish()
        harness_path = output / 'generated' / 'harness_set.json'
        record('harness_set', harness_path, harness_document)
        summary['stages']['harness_set'].update(
            status=OK, document=_display(base, harness_path),
            tier=harness_document['tier'],
            components=[row['instance_id'] for row in harness_document['components']],
            binaries={row['instance_id']: row['binary']
                      for row in harness_document['components']})

        # -- D3: compile the paths of the contract D2 wrote -----------------
        try:
            request_document, sidecars = build_path_compile_request(
                composition,
                wiring_path=output / 'generated' / 'wiring_contract.json',
                ip_capabilities=ip_capabilities)
        except AutoHarnessRefused as error:
            refusal_path = _write(output / 'path-compilation-refusal.json',
                                  {'schema_version': REFUSAL_SCHEMA,
                                   'stage': 'path_compilation',
                                   'code': error.code, 'pointer': error.pointer,
                                   'detail': error.detail})
            record('path_compilation_refusal', refusal_path)
            refuse('path_compilation', error.code, error.pointer, error.detail)
            return finish()
        request_path = _write(output / 'path_compile_request.json', request_document)
        record('path_compile_request', request_path, request_document)
        try:
            compiled_document = compile_paths(
                load_path_compile_request(request_document, base_dir=base))
        except PathCompilationError as error:
            refusal_path = _write(output / 'path-compilation-refusal.json',
                                  {'schema_version': REFUSAL_SCHEMA,
                                   'stage': 'path_compilation',
                                   'code': error.code, 'pointer': error.pointer,
                                   'detail': error.detail})
            record('path_compilation_refusal', refusal_path)
            refuse('path_compilation', error.code, error.pointer, error.detail)
            return finish()
        compiled_path = _write(output / 'compiled_paths.v1.json', compiled_document)
        record('compiled_paths', compiled_path, compiled_document)
        summary['stages']['path_compilation'].update(
            status=OK, document=_display(base, compiled_path),
            counts=dict(compiled_document['counts']),
            sidecars=sidecars)

        # -- D4a: the live session, only when the caller opted in -----------
        session_dir = None
        fresh_path = None
        if skip_session:
            summary['stages']['session'].update(status=NOT_REQUESTED)
            summary['stages']['fresh_verification'].update(status=NOT_REQUESTED)
        elif family is None:
            absent('session', 'runtime-family-required', '/runtime',
                   'no runtime family was named, so no session was started; '
                   'the family is never guessed')
            absent('fresh_verification', 'fresh-replay-requires-a-session',
                   '/session', 'no session ran, so there was no authenticated '
                               'prefix to replay')
        elif client_binary is None:
            absent('session', 'client-binary-required', '/client-binary',
                   'no RFuzz client binary was named, so no session was started')
            absent('fresh_verification', 'fresh-replay-requires-a-session',
                   '/session', 'no session ran, so there was no authenticated '
                               'prefix to replay')
        else:
            run_id = summary['label']
            try:
                live = run_live_session(
                    family=family, session_dir=output / 'session',
                    client_binary=client_binary,
                    cache_dir=cache_dir, run_id=run_id,
                    budget_seconds=budget_seconds, max_tests=max_tests,
                    search_seed=search_seed,
                    max_runs_per_batch=max_runs_per_batch, base_dir=base)
            except AutoHarnessRefused as error:
                refusal_path = _write(output / 'session-refusal.json',
                                      {'schema_version': REFUSAL_SCHEMA,
                                       'stage': 'session', 'code': error.code,
                                       'pointer': error.pointer,
                                       'detail': error.detail})
                record('session_refusal', refusal_path)
                refuse('session', error.code, error.pointer, error.detail)
                absent('fresh_verification', 'fresh-replay-requires-a-session',
                       '/session', 'the session did not run, so nothing was replayed')
            except Exception as error:
                traceback.print_exc()
                detail = {'error': f'{type(error).__name__}: {error}',
                          'session_dir': _display(base, output / 'session'),
                          'partial_evidence': (output / 'session').exists()}
                refusal_path = _write(output / 'session-refusal.json',
                                      {'schema_version': REFUSAL_SCHEMA,
                                       'stage': 'session',
                                       'code': 'session-run-failed',
                                       'pointer': '/session', 'detail': detail})
                record('session_refusal', refusal_path)
                refuse('session', 'session-run-failed', '/session', detail)
                absent('fresh_verification', 'fresh-replay-requires-a-session',
                       '/session', 'the session did not complete, so nothing was replayed')
            else:
                session_dir = output / 'session'
                report = json.loads((session_dir / 'report.json').read_text(
                    encoding='utf-8'))
                summary['stages']['session'].update(
                    status=OK, directory=_display(base, session_dir),
                    tests=report.get('tests'),
                    execution_status=report.get('execution_status'),
                    statuses=report.get('statuses'),
                    elapsed_seconds=report.get('elapsed_seconds'),
                    effective_search_seconds=report.get('effective_search_seconds'),
                    transport=live)
                record('session_report', session_dir / 'report.json', report)

                # -- D4b: the authenticated prefix and its fresh replay -----
                try:
                    bundle_dir = output / 'bundle'
                    bundle = write_authenticated_bundle(session_dir=session_dir,
                                                        bundle_dir=bundle_dir)
                    record('bundle', bundle_dir / 'bundle-manifest.json', bundle)
                    verification = run_fresh_replay(
                        family=family, bundle_dir=bundle_dir,
                        cache_dir=cache_dir, base_dir=base)
                except AutoHarnessRefused as error:
                    refusal_path = _write(
                        output / 'fresh-verification-refusal.json',
                        {'schema_version': REFUSAL_SCHEMA,
                         'stage': 'fresh_verification', 'code': error.code,
                         'pointer': error.pointer, 'detail': error.detail})
                    record('fresh_verification_refusal', refusal_path)
                    refuse('fresh_verification', error.code, error.pointer,
                           error.detail)
                except Exception as error:
                    traceback.print_exc()
                    detail = {'error': f'{type(error).__name__}: {error}'}
                    refusal_path = _write(
                        output / 'fresh-verification-refusal.json',
                        {'schema_version': REFUSAL_SCHEMA,
                         'stage': 'fresh_verification',
                         'code': 'fresh-replay-failed', 'pointer': '/session',
                         'detail': detail})
                    record('fresh_verification_refusal', refusal_path)
                    refuse('fresh_verification', 'fresh-replay-failed',
                           '/session', detail)
                else:
                    fresh_path = _write(output / 'fresh-verification.json',
                                        verification)
                    record('fresh_verification', fresh_path, verification)
                    summary['stages']['fresh_verification'].update(
                        status=OK, document=_display(base, fresh_path),
                        matches=verification['matches'],
                        first_difference=verification['first_difference'],
                        verification_scope=verification['verification_scope'])
                    summary['fresh_replay'] = {
                        'matches': verification['matches'],
                        'first_difference': verification['first_difference'],
                        'verification_scope': verification['verification_scope']}

        # -- D4: the graded capability report, from the documents on disk ---
        try:
            report_document = build_capability_report(
                compiled_path, harness_set=harness_path,
                session=session_dir, fresh_verification=fresh_path,
                checker_findings=None, unavailable=None,
                label=summary['label'], base_dir=base)
        except CapabilityReportRefused as error:
            refusal_path = _write(output / 'capability-report-refusal.json',
                                  {'schema_version': REFUSAL_SCHEMA,
                                   'stage': 'capability_report',
                                   'code': error.code, 'pointer': error.pointer,
                                   'detail': error.detail})
            record('capability_report_refusal', refusal_path)
            refuse('capability_report', error.code, error.pointer, error.detail)
            return finish()
        report_path = _write(output / 'capability-report.json', report_document)
        record('capability_report', report_path, report_document)
        summary['stages']['capability_report'].update(
            status=OK, document=_display(base, report_path),
            counts=dict(report_document['counts']),
            throughput_status=report_document['throughput']['status'])
    except AutoHarnessRefused as error:
        # A refusal is ordinary control flow, not a crash: it is recorded by
        # name and the run still finishes with its summary and its marker.
        refuse('driver', error.code, error.pointer, error.detail)
    except Exception as error:  # pragma: no cover - defensive
        traceback.print_exc()
        refuse('driver', 'auto-harness-failed', '',
               {'error': f'{type(error).__name__}: {error}',
                'requires': 'an unexpected driver failure; see stderr'})

    requested = [name for name, stage in summary['stages'].items()
                 if stage['status'] != NOT_REQUESTED]
    if all(summary['stages'][name]['status'] == OK for name in requested):
        if summary['fresh_replay'] is not None and not summary['fresh_replay']['matches']:
            summary['status'] = RUN_DIFFERENCE
        else:
            summary['status'] = RUN_COMPLETE
    return finish()
