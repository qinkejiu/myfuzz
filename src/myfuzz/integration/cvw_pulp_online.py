"""The CVW AHB-Lite runtime family of the P7-E entry point (``cvw-ahb-pulp-gpio``).

CPU + device + protocol shape of this family
--------------------------------------------

* **CPU** ``cvw`` (CORE-V Wally) at its one *unified* AHB-Lite memory master
  ``cpu.external_bus``.  The EBU arbitrates the IFU and the LSU onto that single
  bus, so the profile declares one endpoint with function ``memory_master`` and
  no dedicated instruction/data pair; its protocol is ``ahb-lite 1``, ``HADDR``
  is 34 bits while ``HWDATA``/``HRDATAEXT`` are 32 and ``HWSTRB`` is 4.
* **Device** one ``pulp_gpio`` (APB3, 32 pads, full-word MMIO) at the
  composition's ``gpio`` window.  Its bus endpoint is ``gpio.bus`` with function
  ``mmio_slave`` and protocol ``apb 3``, and its declared aperture is the
  profile's own ``address.window_size`` (4 KiB).
* **Wiring** the two sessions ``cpu``/``gpio``, one 4 KiB MMIO window, and one
  RAM resource carved from the CPU's declared external-memory region - the
  region the derived configuration also points the reset vector at, so the boot
  fetch is a real AHB-Lite transfer the harness's memory service answers.

What is derived, never restated
-------------------------------

Every fact above is read from the two real declarations
(``configs/cpus/cvw/component_profile.json`` and
``configs/peripherals/pulp_gpio/component_profile.json``) and from the pinned
derived configuration ``configs/cpus/cvw/config_extmem/config.vh``:
:func:`cvw_pulp_gpio_wiring` is the declaration
:func:`myfuzz.local_harness.auto_harness_test.wiring_facts` reads, so the family
cannot be declared more generously than the profiles it builds, and a profile
that stops declaring this shape is refused *by name* (``cvw-family-*``) instead
of being adapted. The window, RAM carveout and instance ids are integration
choices shared with the shipped composition.

The identity discipline of the frozen template is kept verbatim: every opt-in is
off by default, an unavailable observation is refused by name rather than
downgraded, and no default is guessed for anything the caller did not declare.

What this module declares now
-----------------------------

The three pieces the family's session stage used to name as missing are real
code in :mod:`myfuzz.scenario.cvw_session` and are published here as the
family's ``session_assembly``:

* ``boot_image`` - :func:`myfuzz.scenario.cvw_session.make_cvw_boot_image`, the
  RV32 program supplied through the AHB-Lite memory service;
* ``online_decoder`` - :func:`myfuzz.scenario.cvw_session.make_cvw_boot_instruction_source`,
  a declared instruction source that holds the reset word until the core
  presents the measured reset vector and then supplies the image;
* ``runner_factory`` - :func:`myfuzz.scenario.cvw_session.make_cvw_gpio_session_factory`,
  which constructs the real ``GeneratedAhbMemorySession`` + real
  ``GeneratedPulpGpioSession`` + ``DataflowRouter`` chain as a
  :class:`myfuzz.scenario.runner.ScenarioRunner`.

:func:`make_cvw_pulp_online_runtime` builds that assembly and returns it
(unstarted).  :func:`run_cvw_directed_session` is the family's *directed*
session entry: it starts the real RTL, boots the core, performs the declared
CPU→PULP GPIO transactions and re-runs the case fresh.  It is deliberately not
the RFuzz live transport: it declares no ``OnlineCaseDecoder``, no per-case
instruction window, no client binary and no coverage search, and its documents
say so.

The saved-bundle replay entry remains separate.  A directed session has no
RFuzz authenticated prefix, so :func:`replay_cvw_pulp_online_files` refuses
with ``cvw-directed-session-has-no-online-bundle`` instead of pretending to
verify one; the directed entry's own fresh re-run is its replay.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.scenario.memory import MemoryRegion

#: The family id ``--runtime`` selects.  The driver's closed set registers this
#: exact string; the family test pins that the two cannot drift apart.
CVW_FAMILY_ID = 'cvw-ahb-pulp-gpio'

#: The two real component declarations this family's shape is read from.
CPU_PROFILE = 'configs/cpus/cvw/component_profile.json'
GPIO_PROFILE = 'configs/peripherals/pulp_gpio/component_profile.json'

#: The derived CVW configuration the profile elaborates.  It is where the
#: external-memory region and the reset vector inside it are really declared
#: (``myfuzz.local_harness.cvw_contract`` pins its bytes).
CVW_EXTERNAL_MEMORY_CONFIG = 'configs/cpus/cvw/config_extmem/config.vh'

#: The component ids this family is for.
CPU_COMPONENT_ID = 'cvw'
DEVICE_COMPONENT_ID = 'pulp_gpio'

#: Instance ids of the shipped composition ``configs/scenarios/cvw-pulp-gpio``.
#: The family wires these two sessions; the second half of a device window's
#: record is the instance that owns it.
CPU_INSTANCE_ID = 'cpu'
DEVICE_INSTANCE_ID = 'gpio'

#: The endpoint ids the composition points at, cross-checked against the
#: profiles rather than assumed from a name.
CPU_MASTER_ENDPOINT = 'cpu.external_bus'
DEVICE_BUS_ENDPOINT = 'gpio.bus'

#: The one protocol pair this family's generated harness is built from: the
#: ``cpu.ahb-lite`` CPU template and the ``target.apb3`` device template.  They
#: are the family's identity, so a profile that stops declaring them is refused
#: instead of being silently re-aimed at another template.
CPU_MASTER_PROTOCOL = ('ahb-lite', '1')
DEVICE_PROTOCOL = ('apb', '3')
DEVICE_ENDPOINT_FUNCTION = 'mmio_slave'

#: Integration choice, not a profile fact: the CPU's external-memory region is
#: ``0xC0000000..0xCFFFFFFF`` (its own derived configuration), and the device
#: window is inside that reachable aperture; host RAM ends immediately before it.
#: D-cache is disabled in this profile; code/I-cache fills must remain in RAM.
GPIO_WINDOW_BASE = 0xCFFF0000
RAM_END = 0xCFFF0000

#: The RAM resource id the composition declares for the CPU's own region.
MEMORY_RESOURCE_ID = 'ram'

#: Version of the capability document this module derives.
CVW_CAPABILITIES_SCHEMA = 'cvw_pulp_gpio_capabilities.v1'

#: The family's real session assembly.  Each entry is a ``module:attribute`` the
#: driver resolves with its own ``_load_entry``; every piece lives in
#: :mod:`myfuzz.scenario.cvw_session` and is exercised by the directed entry.
#: The kind is part of the declaration so no caller can read the directed
#: session as an RFuzz online campaign.
CVW_SESSION_ASSEMBLY = {
    'schema_version': 'cvw_session_assembly_declaration.v1',
    'kind': 'directed_fixed_image',
    'boot_image': ('myfuzz.scenario.cvw_session:make_cvw_boot_image'),
    'online_decoder': ('myfuzz.scenario.cvw_session:'
                       'make_cvw_boot_instruction_source'),
    'runner_factory': ('myfuzz.scenario.cvw_session:'
                       'make_cvw_gpio_session_factory'),
    'directed_session': ('myfuzz.integration.cvw_pulp_online:'
                         'run_cvw_directed_session'),
    'runtime_assembly': ('myfuzz.integration.cvw_pulp_online:'
                         'make_cvw_pulp_online_runtime'),
    'note': ('a fixed boot image, a declared instruction source and a real '
             'CVW+PULP GPIO runner factory.  The directed session starts the '
             'real chain and re-runs it fresh; it declares no RFuzz '
             'OnlineCaseDecoder, no per-case instruction window, no client '
             'binary and no coverage-guided search.'),
}


def _repository_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _refuse(code: str, pointer: str = '', detail=None):
    """Refuse in the driver's own vocabulary: ``code`` + JSON ``pointer`` + detail.

    The P7-E driver already owns the vocabulary every stage refusal is written in
    (:class:`myfuzz.local_harness.auto_harness_test.AutoHarnessRefused`).  A family
    that cannot build the session it is named for refuses in that vocabulary
    rather than inventing a second one, so the CLI writes the real ``code`` into
    ``runtime-family.json`` / ``session-refusal.json`` and ``run-summary.json``
    instead of a generic failure.  The import is local because the driver resolves
    this module lazily itself, and a module-level import would couple the two
    import orders for no benefit.
    """
    from myfuzz.local_harness.auto_harness_test import AutoHarnessRefused
    raise AutoHarnessRefused(code, pointer, detail)


def _load_profile(root: Path, relative: str, *, code: str):
    path = root / relative
    try:
        document = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        _refuse(code + '-unreadable', '/profile',
                {'profile': relative, 'error': str(error)})
    try:
        return load_component_profile(document)
    except (ValueError, KeyError, TypeError) as error:
        _refuse(code + '-invalid', '/profile',
                {'profile': relative, 'error': str(error)})


def _sole_memory_master(profile):
    """The one unified CPU memory master, or a refusal naming what was declared."""
    masters = [endpoint for endpoint in profile.endpoints
               if endpoint.function in ('memory_master', 'instruction_memory_master',
                                        'data_memory_master')]
    unified = [endpoint for endpoint in masters if endpoint.function == 'memory_master']
    if len(masters) != 1 or len(unified) != 1:
        _refuse('cvw-family-cpu-master-unsupported', '/cpu/request',
                {'declared_masters': [{'endpoint_id': endpoint.endpoint_id,
                                       'function': endpoint.function,
                                       'protocol': list(endpoint.protocol or ())}
                                      for endpoint in masters],
                 'requires': 'exactly one memory master with function memory_master; '
                             'this family builds the CPU\'s single unified AHB-Lite '
                             'external bus'})
    return masters[0]


def _declared_haddr_width(endpoint):
    rows = [item for item in endpoint.fields if item.role == 'haddr']
    return rows[0].width if len(rows) == 1 else None


def _rvfi_observation_ports(profile) -> tuple:
    """Elaborated boundary ports that could carry a retirement observation."""
    boundary = profile.source_document.get('elaboration_boundary') or {}
    outputs = boundary.get('native_outputs') or []
    return tuple(str(name) for name in outputs if 'rvfi' in str(name).lower())


_EXT_MEM_REGION_RE = re.compile(
    r"^localparam logic \[63:0\] (EXT_MEM_BASE|EXT_MEM_RANGE)\s*=\s*64'h([0-9A-Fa-f]+);$",
    re.MULTILINE)


def _external_memory_region(root: Path) -> tuple:
    """``(base, size)`` of the derived configuration's external-memory region."""
    path = root / CVW_EXTERNAL_MEMORY_CONFIG
    try:
        text = path.read_text(encoding='utf-8')
    except (OSError, UnicodeError) as error:
        _refuse('cvw-family-external-memory-config-unreadable', '/memory',
                {'config': CVW_EXTERNAL_MEMORY_CONFIG, 'error': str(error)})
    declared = {name: int(value, 16) for name, value in _EXT_MEM_REGION_RE.findall(text)}
    if set(declared) != {'EXT_MEM_BASE', 'EXT_MEM_RANGE'}:
        _refuse('cvw-family-external-memory-config-incomplete', '/memory',
                {'config': CVW_EXTERNAL_MEMORY_CONFIG,
                 'declared': sorted(declared),
                 'requires': 'the derived configuration to declare EXT_MEM_BASE and '
                             'EXT_MEM_RANGE exactly once each'})
    base, mask = declared['EXT_MEM_BASE'], declared['EXT_MEM_RANGE']
    # adrdec matches with (Address ~^ Base) | Range, so Range is a thermometer
    # bitmask rather than a length - the same reading scripts/derive_cvw_config.py
    # asserts at generation time.
    if mask & (mask + 1) or mask < 3:
        _refuse('cvw-family-external-memory-range-not-thermometer', '/memory',
                {'config': CVW_EXTERNAL_MEMORY_CONFIG, 'EXT_MEM_RANGE': hex(mask)})
    return base, mask + 1


def cvw_pulp_gpio_wiring(*, base_dir=None) -> 'CvwPulpGpioWiring':
    """The topology this family really wires, read from the real declarations.

    With no ``base_dir`` the repository this module lives in is read, which is how
    the driver's ``wiring_facts`` resolves this family's ``wiring_declaration``.
    ``base_dir`` exists so a caller can point the same derivation at a scratch
    tree and show that a mutated profile is refused (that is the derivation's RED
    evidence).
    """
    root = _repository_root() if base_dir is None else Path(base_dir)
    cpu = _load_profile(root, CPU_PROFILE, code='cvw-family-cpu-profile')
    if cpu.component_id != CPU_COMPONENT_ID:
        _refuse('cvw-family-cpu-component-mismatch', '/cpu/request',
                {'profile': CPU_PROFILE, 'expected': CPU_COMPONENT_ID,
                 'observed': cpu.component_id, 'profile_pointer': '/component_id'})
    master = _sole_memory_master(cpu)
    protocol = tuple(master.protocol or ())
    if protocol != CPU_MASTER_PROTOCOL:
        _refuse('cvw-family-cpu-master-protocol-mismatch', '/cpu/request',
                {'profile': CPU_PROFILE, 'endpoint_id': master.endpoint_id,
                 'expected': list(CPU_MASTER_PROTOCOL), 'observed': list(protocol),
                 'requires': 'the one protocol this family\'s cpu.ahb-lite harness '
                             'template builds'})
    if master.endpoint_id != CPU_MASTER_ENDPOINT:
        _refuse('cvw-family-cpu-master-endpoint-mismatch', '/cpu/data_endpoint',
                {'expected': CPU_MASTER_ENDPOINT, 'observed': master.endpoint_id})

    address_width = cpu.capability('address_width')
    haddr_width = _declared_haddr_width(master)
    if type(address_width) is not int or haddr_width != address_width:
        _refuse('cvw-family-address-width-mismatch', '/cpu/request',
                {'profile': CPU_PROFILE, 'capabilities_address_width': address_width,
                 'haddr_field_width': haddr_width,
                 'requires': 'the declared address width and the extracted HADDR width '
                             'to agree; this bus is 34 bits wide while its data path is 32'})

    region_base, region_size = _external_memory_region(root)
    if cpu.cpu is None or cpu.cpu.reset_vector != region_base:
        _refuse('cvw-family-boot-base-mismatch', '/cpu/request',
                {'profile': CPU_PROFILE,
                 'declared_reset_vector': (cpu.cpu.reset_vector if cpu.cpu else None),
                 'external_memory_base': region_base,
                 'requires': 'the profile\'s reset vector to be the external-memory base '
                             'the derived configuration declares, so the boot fetch is '
                             'an AHB-Lite transfer the harness serves'})

    device = _load_profile(root, GPIO_PROFILE, code='cvw-family-device-profile')
    if device.component_id != DEVICE_COMPONENT_ID:
        _refuse('cvw-family-device-component-mismatch', '/devices/0/request',
                {'profile': GPIO_PROFILE, 'expected': DEVICE_COMPONENT_ID,
                 'observed': device.component_id, 'profile_pointer': '/component_id'})
    matches = [endpoint for endpoint in device.endpoints
               if endpoint.endpoint_id == DEVICE_BUS_ENDPOINT]
    endpoint = matches[0] if len(matches) == 1 else None
    if (endpoint is None or endpoint.function != DEVICE_ENDPOINT_FUNCTION
            or tuple(endpoint.protocol or ()) != DEVICE_PROTOCOL):
        _refuse('cvw-family-device-endpoint-mismatch', '/devices/0/bus_endpoint',
                {'profile': GPIO_PROFILE, 'endpoint_id': DEVICE_BUS_ENDPOINT,
                 'expected_function': DEVICE_ENDPOINT_FUNCTION,
                 'expected_protocol': list(DEVICE_PROTOCOL),
                 'observed': (None if endpoint is None else
                              {'function': endpoint.function,
                               'protocol': list(endpoint.protocol or ())}),
                 'declared_endpoints': [item.endpoint_id for item in device.endpoints]})
    window_size = device.address.window_size if device.address is not None else None
    if (type(window_size) is not int or window_size < 4 or window_size & (window_size - 1)):
        _refuse('cvw-family-device-window-invalid', '/devices/0/size',
                {'profile': GPIO_PROFILE, 'window_size': window_size,
                 'requires': 'a power-of-two aperture of at least 4 bytes'})
    if GPIO_WINDOW_BASE + window_size > 1 << address_width:
        _refuse('cvw-family-window-outside-address-space', '/devices/0/base',
                {'base': GPIO_WINDOW_BASE, 'size': window_size,
                 'address_width': address_width})
    if not (region_base <= GPIO_WINDOW_BASE
            and GPIO_WINDOW_BASE + window_size <= region_base + region_size):
        _refuse('cvw-family-window-outside-external-memory', '/devices/0/base',
                {'base': GPIO_WINDOW_BASE, 'size': window_size,
                 'external_base': region_base, 'external_size': region_size})
    ram_size = RAM_END - region_base
    if ram_size <= 0 or RAM_END > region_base + region_size:
        _refuse('cvw-family-memory-outside-external-memory', '/memory',
                {'base': region_base, 'end': RAM_END})
    if GPIO_WINDOW_BASE < RAM_END and region_base < GPIO_WINDOW_BASE + window_size:
        _refuse('cvw-family-window-overlaps-memory', '/devices/0/base',
                {'window': {'base': GPIO_WINDOW_BASE, 'size': window_size},
                 'memory_region': {'base': region_base, 'size': ram_size},
                 'requires': 'a reachable device window disjoint from host RAM'})

    return CvwPulpGpioWiring(
        cpu_profile=CPU_PROFILE, gpio_profile=GPIO_PROFILE,
        sessions=(CPU_INSTANCE_ID, DEVICE_INSTANCE_ID),
        windows=((DEVICE_INSTANCE_ID, GPIO_WINDOW_BASE, window_size,
                  DEVICE_INSTANCE_ID),),
        window_size=window_size,
        memory_component=CPU_INSTANCE_ID,
        memory_regions=(MemoryRegion(MEMORY_RESOURCE_ID, region_base, ram_size),),
        cpu_component_id=CPU_COMPONENT_ID, device_component_id=DEVICE_COMPONENT_ID,
        cpu_master_endpoint=master.endpoint_id,
        cpu_master_protocol=protocol, device_protocol=tuple(endpoint.protocol),
        cpu_master_address_width=address_width,
        cpu_data_width=cpu.capability('data_width'),
        cpu_byte_lane_width=cpu.capability('byte_lane_width'),
        boot_base=region_base)


@dataclass(frozen=True)
class CvwPulpGpioWiring:
    """The derived declaration of this family's CPU, device, window and memory.

    The first four fields keep the exact attribute names and shapes
    ``wiring_facts`` reads from the PULP families' wiring record (``sessions``,
    ``windows``, ``memory_component``, ``memory_regions``), so the driver's
    validation reads one shape for every family.  The remaining fields are this
    family's derived protocol/boot facts, published in :meth:`document` so the
    capability document and the driver's requirement record cannot disagree.
    """

    cpu_profile: str
    gpio_profile: str
    sessions: tuple
    windows: tuple
    memory_component: str
    memory_regions: tuple
    cpu_component_id: str
    device_component_id: str
    cpu_master_endpoint: str
    cpu_master_protocol: tuple
    device_protocol: tuple
    cpu_master_address_width: int
    cpu_data_width: object
    cpu_byte_lane_width: object
    boot_base: int
    device_endpoint_id: str = DEVICE_BUS_ENDPOINT
    window_base: int = GPIO_WINDOW_BASE
    window_size: int = 0

    def document(self) -> dict:
        return {
            'schema_version': 'cvw_pulp_gpio_wiring.v1',
            'family_id': CVW_FAMILY_ID,
            'cpu': {'component_id': self.cpu_component_id,
                    'instance_id': CPU_INSTANCE_ID,
                    'profile': self.cpu_profile,
                    'endpoint_id': self.cpu_master_endpoint,
                    'function': 'memory_master',
                    'protocol': list(self.cpu_master_protocol),
                    'address_width': self.cpu_master_address_width,
                    'data_width': self.cpu_data_width,
                    'byte_lane_width': self.cpu_byte_lane_width,
                    'boot_base': self.boot_base},
            'device': {'component_id': self.device_component_id,
                       'instance_id': DEVICE_INSTANCE_ID,
                       'profile': self.gpio_profile,
                       'endpoint_id': self.device_endpoint_id,
                       'function': DEVICE_ENDPOINT_FUNCTION,
                       'protocol': list(self.device_protocol),
                       'window': {'base': self.window_base, 'size': self.window_size}},
            'sessions': list(self.sessions),
            'windows': [{'device_id': device_id, 'base': base, 'size': size,
                         'component': component}
                        for device_id, base, size, component in self.windows],
            'memory': {'component': self.memory_component,
                       'regions': [{'memory_id': region.memory_id,
                                    'base': region.base, 'size': region.size}
                                   for region in self.memory_regions]},
        }


def cvw_pulp_gpio_capabilities(*, base_dir=None) -> dict:
    """The capability document of this family, from the same single derivation."""
    wiring = cvw_pulp_gpio_wiring(base_dir=base_dir)
    return {'schema_version': CVW_CAPABILITIES_SCHEMA,
            'family_id': CVW_FAMILY_ID,
            **{key: value for key, value in wiring.document().items()
               if key not in ('schema_version', 'family_id')}}


def _validate_cvw_policies(*, cpu_retirement, native_irq_receipts, gpio_consumption,
                           max_warmup_rounds) -> None:
    """Refuse every policy this CPU cannot satisfy, before any work is done.

    Off is the shipped default of each flag, so a caller that declares nothing
    gets no observation it did not ask for and no identity changes silently.  The
    retirement refusal is *derived*: it fires because the elaborated boundary the
    profile declares exports no RVFI port, not because a CPU name is hard-coded
    into a rule.
    """
    for name, value in (('cpu_retirement', cpu_retirement),
                        ('native_irq_receipts', native_irq_receipts),
                        ('gpio_consumption', gpio_consumption)):
        if type(value) is not bool:
            _refuse('cvw-family-policy-invalid', '/runtime',
                    {'policy': name, 'observed': type(value).__name__,
                     'requires': 'boolean or unset; every policy here is off by default'})
    if type(max_warmup_rounds) is not int or max_warmup_rounds < 1:
        _refuse('cvw-family-policy-invalid', '/runtime',
                {'policy': 'max_warmup_rounds', 'observed': max_warmup_rounds,
                 'requires': 'a positive integer'})
    if cpu_retirement or native_irq_receipts:
        root = _repository_root()
        profile = _load_profile(root, CPU_PROFILE, code='cvw-family-cpu-profile')
        declared = _rvfi_observation_ports(profile)
        if not declared:
            _refuse('cvw-retirement-observation-unavailable', '/cpu/retirement',
                    {'profile': CPU_PROFILE, 'cpu_component_id': CPU_COMPONENT_ID,
                     'declared_rvfi_boundary_ports': list(declared),
                     'requires': 'an authenticated retirement observation; the AHB-Lite '
                                 'boundary this profile elaborates exports no RVFI port, '
                                 'so retirement and native IRQ receipts are unavailable '
                                 'here (they are Ibex RVFI observations in this '
                                 'repository)'})
    if gpio_consumption:
        _refuse('cvw-family-observation-undeclared', '/devices/0',
                {'observation': 'gpio_consumption',
                 'declared_device_profile': GPIO_PROFILE,
                 'requires': 'the causal GPIO profile of this family\'s declaration; this '
                             'family declares the functional pulp_gpio profile only, so '
                             'the observation is refused rather than downgraded'})


def _make_assembly(*, cache_dir, generated_artifacts=None):
    """The assembly seam, so a test can exercise the runtime without RTL planning."""
    from myfuzz.scenario.cvw_session import make_cvw_session_assembly
    return make_cvw_session_assembly(cache_dir=cache_dir,
                                     generated_artifacts=generated_artifacts)


@dataclass(frozen=True)
class CvwOnlineRuntime:
    """The built (unstarted) CVW session assembly of one run.

    It deliberately exposes **no** ``.executor``: this family's real session is
    the directed fixed-image session of :func:`run_cvw_directed_session`, not
    the RFuzz live transport.  A caller that tries to drive it as an RFuzz
    executor gets the driver's own ``runtime-entry-has-no-executor`` refusal
    instead of a silently invented online campaign.
    """

    assembly: object
    run_id: str
    cache_dir: Path
    evidence_dir: object = None

    def document(self) -> dict:
        return {'schema_version': 'cvw_online_runtime.v1',
                'family_id': CVW_FAMILY_ID,
                'run_id': self.run_id,
                'kind': 'directed_fixed_image',
                'executor': None,
                'not_an_rfuzz_online_campaign': True,
                'assembly': self.assembly.document(),
                'fresh_replay': (
                    'run_cvw_directed_session re-runs the directed case on fresh '
                    'RTL; there is no RFuzz authenticated prefix bundle')}


def make_cvw_pulp_online_runtime(*, cache_dir, run_id, evidence_dir=None,
                                 checker=None, feedback_interval: int = 16,
                                 max_warmup_rounds: int = 1024,
                                 cpu_retirement: bool = False,
                                 native_irq_receipts: bool = False,
                                 gpio_consumption: bool = False,
                                 generated_artifacts=None,
                                 compiled_inputs=None):
    """Build the family's real session assembly; start nothing.

    The signature mirrors the two shipped families so the driver can resolve
    the same entry point.  Every opt-in observation this CPU cannot supply is
    refused by name *before* any harness is rendered or any process is started,
    and the returned object publishes the assembly's own declaration.  It is
    not an RFuzz runtime: ``executor`` is absent by declaration, and the
    directed session is entered through :func:`run_cvw_directed_session`.

    No RTL is started and no build cache entry is written here.  The returned
    object exposes no ``.executor``: the shared RFuzz live path's own checks
    (its compiled-input admission, then its executor-shape check) refuse such a
    use instead of inventing an online campaign.
    """
    if type(run_id) is not str or not run_id.strip():
        _refuse('cvw-online-run-id-required', '/run-id',
                {'observed': repr(run_id),
                 'requires': 'a nonempty run id; it is the identity every saved '
                             'artifact of the run is keyed by'})
    _validate_cvw_policies(cpu_retirement=cpu_retirement,
                           native_irq_receipts=native_irq_receipts,
                           gpio_consumption=gpio_consumption,
                           max_warmup_rounds=max_warmup_rounds)
    assembly = _make_assembly(cache_dir=Path(cache_dir),
                              generated_artifacts=generated_artifacts)
    return CvwOnlineRuntime(assembly=assembly, run_id=run_id,
                            cache_dir=Path(cache_dir), evidence_dir=evidence_dir)


def run_cvw_directed_session(*, cache_dir, run_id, session_dir,
                             generated_artifacts=None, compiled_document=None,
                             budget_seconds=300.0, max_steps=20000):
    """The family's directed session entry: real CVW → real PULP GPIO.

    This is the entry the P7-E driver calls for this family.  It starts real
    RTL, boots the core from the declared boot image over the AHB-Lite memory
    service, performs the declared CPU→IP program, re-runs it on fresh
    processes, and writes the session's report, receipt and replay comparison.
    It must be called inside the repository's heavy-worker lock; the driver
    takes that lock around it.
    """
    from myfuzz.integration.cvw_directed_session import (
        run_cvw_directed_session as _run)
    return _run(cache_dir=cache_dir, run_id=run_id, session_dir=session_dir,
                generated_artifacts=generated_artifacts,
                compiled_document=compiled_document,
                budget_seconds=budget_seconds, max_steps=max_steps)


def replay_cvw_pulp_online_files(*, cache_dir, plan_path, trace_path):
    """The saved-bundle replay entry: a directed session has no RFuzz prefix.

    A fresh replay authenticates a *saved RFuzz online prefix*; this family's
    real session is directed and its fresh replay is the second isolated run
    inside :func:`run_cvw_directed_session`.  The refusal names that boundary
    instead of pretending to verify a bundle, and keeps the family's declared
    replay entry point resolving for the driver's registry.
    """
    _refuse('cvw-directed-session-has-no-online-bundle', '/runtime',
            {'family_id': CVW_FAMILY_ID,
             'saved_bundle': {'plan': str(plan_path), 'trace': str(trace_path),
                              'cache_dir': str(cache_dir)},
             'directed_session': ('myfuzz.integration.cvw_pulp_online:'
                                  'run_cvw_directed_session'),
             'requires': ('the directed session entry re-runs the case on fresh '
                          'RTL and compares the full projection; it writes no '
                          'RFuzz authenticated prefix bundle for this entry to '
                          'authenticate')})


__all__ = ['CVW_FAMILY_ID', 'CVW_SESSION_ASSEMBLY', 'CPU_PROFILE', 'GPIO_PROFILE',
           'CPU_MASTER_PROTOCOL', 'DEVICE_PROTOCOL', 'CvwOnlineRuntime',
           'CvwPulpGpioWiring', 'cvw_pulp_gpio_wiring',
           'cvw_pulp_gpio_capabilities', 'make_cvw_pulp_online_runtime',
           'replay_cvw_pulp_online_files', 'run_cvw_directed_session']
