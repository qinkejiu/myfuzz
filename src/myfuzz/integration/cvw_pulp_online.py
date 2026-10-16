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
  RAM resource that is exactly the CPU's declared external-memory region - the
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
of being adapted.  Only two facts are integration choices and are marked as
such: the window's base address and the instance ids the shipped composition
uses.

The identity discipline of the frozen template is kept verbatim: every opt-in is
off by default, an unavailable observation is refused by name rather than
downgraded, and no default is guessed for anything the caller did not declare.

What this module does *not* claim
---------------------------------

The family is registered, admitted and validated, and both entry points have the
shape the P7-E driver calls - but no CVW *online campaign* can be assembled from
this repository's shipped declarations yet, so
:func:`make_cvw_pulp_online_runtime` refuses with
``cvw-online-assembly-undeclared`` and lists every missing requirement instead of
returning an object that would pretend a session exists.
:func:`replay_cvw_pulp_online_files` refuses for the matching reason: no session
can have produced a bundle to replay.  This boundary is deliberately independent
of the separate work on whether the generated CVW harness drives AHB traffic:
the declarations here are correct whether or not that harness drives AHB, and
the refusal names the campaign assembly pieces, not that harness behaviour.
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
#: window is placed at 0 - aligned to its own aperture, disjoint from the boot
#: region, and the base the shipped composition declares.
GPIO_WINDOW_BASE = 0x0

#: The RAM resource id the composition declares for the CPU's own region.
MEMORY_RESOURCE_ID = 'ram'

#: Version of the capability document this module derives.
CVW_CAPABILITIES_SCHEMA = 'cvw_pulp_gpio_capabilities.v1'

#: What a CVW online campaign needs and what no shipped module declares yet.
#: Each row is a *named* absence with the reason it is needed, so the refusal
#: below can be read as work rather than as a shrug.  Nothing here is a guess:
#: the boot base is the profile's own reset vector, and the session class that
#: would serve it already exists and is named.
CVW_ONLINE_MISSING = (
    {'requirement': 'boot_image',
     'pointer': '/boot-image',
     'requires': "a declared RV32 program for the boot base the profile names "
                 "(reset_vector, which the derived configuration also uses as "
                 "EXT_MEM_BASE).  The AHB session declares that word from the "
                 "artifact's own boot_contract.configured_boot_base and HOLDS the "
                 "fetch until the program is supplied, so a campaign must declare "
                 "the program AND a phase that supplies it before the core's first "
                 "fetch: the generated driver releases reset and only then reads its "
                 "first command, while CVW fetches from the reset vector the moment "
                 "reset is released.  No shipped module declares either half for CVW."},
    {'requirement': 'online_decoder',
     'pointer': '/online-decoder',
     'requires': "an OnlineCaseDecoder for this CPU.  The shipped decoders are the "
                 "PULP dual-source ones (and the Ibex UART one), and they decode "
                 "RFuzz records into the PULP wiring's own instruction window; CVW "
                 "boots into its own external-memory region, so its window, its "
                 "instruction source and its record-to-slot mapping are undeclared."},
    {'requirement': 'runner_factory',
     'pointer': '/factory',
     'requires': "a factory returning a ScenarioRunner over the generated "
                 "'ahb_lite_cpu' harness with this family's gpio window routed to the "
                 "real pulp_gpio target.  GeneratedAhbMemorySession admits the "
                 "artifact and the generated harness builds, but nothing assembles "
                 "the runner, its router, its bindings and its ownership map."},
)


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
    if (GPIO_WINDOW_BASE < region_base + region_size
            and region_base < GPIO_WINDOW_BASE + window_size):
        _refuse('cvw-family-window-overlaps-memory', '/devices/0/base',
                {'window': {'base': GPIO_WINDOW_BASE, 'size': window_size},
                 'memory_region': {'base': region_base, 'size': region_size},
                 'requires': 'the device window to stay outside the CPU\'s own '
                             'external-memory region'})

    return CvwPulpGpioWiring(
        cpu_profile=CPU_PROFILE, gpio_profile=GPIO_PROFILE,
        sessions=(CPU_INSTANCE_ID, DEVICE_INSTANCE_ID),
        windows=((DEVICE_INSTANCE_ID, GPIO_WINDOW_BASE, window_size,
                  DEVICE_INSTANCE_ID),),
        window_size=window_size,
        memory_component=CPU_INSTANCE_ID,
        memory_regions=(MemoryRegion(MEMORY_RESOURCE_ID, region_base, region_size),),
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


def make_cvw_pulp_online_runtime(*, cache_dir, run_id, evidence_dir=None,
                                 checker=None, feedback_interval: int = 16,
                                 max_warmup_rounds: int = 1024,
                                 cpu_retirement: bool = False,
                                 native_irq_receipts: bool = False,
                                 gpio_consumption: bool = False):
    """The CVW entry point of the shared online-runtime shape - and its honest stop.

    The signature mirrors the two shipped families': the caller names a build
    cache and a run id, every opt-in observation defaults off, and an observation
    this CPU cannot supply is refused by name before any harness is rendered or
    any process started.  What it does *not* do is return a runtime object,
    because this repository cannot assemble a CVW online campaign yet:
    :data:`CVW_ONLINE_MISSING` lists each undeclared requirement (boot program,
    RFuzz online decoder, runner factory) and the refusal below publishes that
    list with the family's own derived declaration.  Returning an object with an
    ``.executor`` would claim a session that cannot run, and the driver would
    then report a failure somewhere further from the cause.

    No RTL is started and no build cache entry is written: the refusal happens
    before ``ScenarioSession.begin()`` would be reached, so the driver never takes
    the heavy-worker lock for a run that cannot proceed.
    """
    if type(run_id) is not str or not run_id.strip():
        _refuse('cvw-online-run-id-required', '/run-id',
                {'observed': repr(run_id),
                 'requires': 'a nonempty run id; it is the identity every saved '
                             'artifact of the run is keyed by'})
    wiring = cvw_pulp_gpio_wiring()
    _validate_cvw_policies(cpu_retirement=cpu_retirement,
                           native_irq_receipts=native_irq_receipts,
                           gpio_consumption=gpio_consumption,
                           max_warmup_rounds=max_warmup_rounds)
    _refuse('cvw-online-assembly-undeclared', '/runtime',
            {'family_id': CVW_FAMILY_ID,
             'declared': wiring.document(),
             'missing': [dict(row) for row in CVW_ONLINE_MISSING],
             'not_started': {'rtl_processes': 0,
                             'build_cache': str(cache_dir),
                             'run_id': run_id},
             'requires': 'every requirement in `missing` to be declared by a shipped '
                         'module before a session is started; until then this entry '
                         'point refuses instead of returning an object that claims one'})


def replay_cvw_pulp_online_files(*, cache_dir, plan_path, trace_path):
    """The CVW replay entry point: there is no CVW session whose prefix could replay.

    A fresh replay authenticates a *saved* session's prefix, and no CVW session
    can run yet (see :func:`make_cvw_pulp_online_runtime`), so this refuses by
    name instead of pretending to verify a bundle.  It keeps the family's declared
    replay entry point resolving, which is what the driver's registry requires.
    """
    _refuse('cvw-online-assembly-undeclared', '/runtime',
            {'family_id': CVW_FAMILY_ID,
             'saved_bundle': {'plan': str(plan_path), 'trace': str(trace_path),
                              'cache_dir': str(cache_dir)},
             'missing': [dict(row) for row in CVW_ONLINE_MISSING],
             'requires': 'a CVW session that produced an authenticated prefix; no such '
                         'session can run yet, so there is nothing to replay'})


__all__ = ['CVW_FAMILY_ID', 'CVW_ONLINE_MISSING', 'CPU_PROFILE', 'GPIO_PROFILE',
           'CPU_MASTER_PROTOCOL', 'DEVICE_PROTOCOL', 'CvwPulpGpioWiring',
           'cvw_pulp_gpio_wiring', 'cvw_pulp_gpio_capabilities',
           'make_cvw_pulp_online_runtime', 'replay_cvw_pulp_online_files']
