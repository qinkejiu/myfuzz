"""The real CVW session assembly: boot image, instruction source, factory.

What this module is
    The CVW runtime family (``cvw-ahb-pulp-gpio``) was registered and validated
    while its session stage refused with ``cvw-online-assembly-undeclared``
    because three *named* pieces did not exist as code: a boot image the real
    core fetches, an instruction source that can drive real CPU fetches, and a
    runner factory that constructs the real CVW + target chain.  This module is
    those three pieces, with the same derivation discipline as the rest of the
    family: the boot base and the device window come from
    :func:`myfuzz.integration.cvw_pulp_online.cvw_pulp_gpio_wiring`, never from
    a literal that could drift from the two profiles.

The three declared pieces
    ``boot_image``
        :class:`CvwBootImage` - the RV32 program the real core executes, the
        declared result window, its provenance and content hash.  It is supplied
        through the AHB-Lite memory service, not poked into the core: the core's
        first fetch is a real AHB-Lite transfer whose address is the profile's
        own reset vector.
    ``online_decoder`` / instruction source
        :class:`CvwBootInstructionSource` - a declared, stateful instruction
        source.  It observes the *measured* AHB request address (the generated
        driver's pre-phase ``m_req_addr``), supplies the reset word through the
        memory layer's online-slot interface (``accept_instructions``, which
        validates the instruction bytes) and materializes the rest of the fixed
        boot image from the declared bytes.  It **is not** an RFuzz
        ``OnlineCaseDecoder``: it decodes no fuzzer record and admits no random
        instruction.  That boundary is stated in :meth:`document` and is why the
        family's report claims a directed F4 transaction, not an online campaign.
    ``runner_factory``
        :func:`make_cvw_gpio_session_factory` - renders (or admits the D2
        generated) CPU and PULP GPIO harnesses once, then builds a real
        :class:`myfuzz.scenario.runner.ScenarioRunner` whose CPU session is a
        :class:`myfuzz.local_harness.ahb_lite_session.GeneratedAhbMemorySession`
        with the declared ``router`` to the real ``GeneratedPulpGpioSession``.
        Constructing a runner starts no RTL process; ``begin_test`` does.

Reused rather than reimplemented
    The chain is the one already verified by
    ``tests/integration/test_cvw_cpu_pulp_gpio_chain_real.py`` (the EBU's AHB
    external bus drives the subordinate, the subordinate's beat face drives the
    ``DataflowRouter``, and the router's declared window reaches the real PULP
    GPIO APB3 target).  This module only changes *how the program reaches the
    core*: instead of preloading all 256 bytes, the reset word is held until the
    core really asks for it and then supplied by the declared source.  The
    static-image fixture in :mod:`myfuzz.scenario.cvw_gpio_example` stays the
    initial-image reference; nothing here weakens it.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path

from myfuzz.integration.cvw_pulp_online import cvw_pulp_gpio_wiring
from myfuzz.local_harness.ahb_lite_session import GeneratedAhbMemorySession
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession

from .cvw_gpio_example import (BOOT_BASE, RESULT, _artifact, cvw_gpio_program)
from .memory import PersistentMemory
from .ownership import InputField, InputOwner, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import ScenarioRunner

ROOT = Path(__file__).resolve().parents[3]

#: Version of the assembly declaration this module publishes.
ASSEMBLY_SCHEMA = 'cvw_session_assembly.v1'
#: Version of the boot-image declaration.
BOOT_IMAGE_SCHEMA = 'cvw_boot_image.v1'
#: Version of the instruction source's declaration and of its run evidence.
INSTRUCTION_SOURCE_SCHEMA = 'cvw_boot_instruction_source.v1'
INSTRUCTION_EVIDENCE_SCHEMA = 'cvw_boot_instruction_source_evidence.v1'

#: The result window the boot program writes and the caller reads back.  The
#: program addresses RESULT + 0/4/8/12; the extra bytes keep one preload span.
RESULT_BYTES = 64

#: The declaration that this source is *not* an RFuzz online decoder.  It is a
#: field of the published document, not a comment, so a saved run states it.
NOT_AN_ONLINE_DECODER = (
    'this is a fixed boot-image instruction source: it decodes no RFuzz record '
    'and admits no random instruction.  The AHB session holds the reset word '
    'until the core really presents that address, the source supplies it and '
    'the declared image through the memory service, and the core then executes '
    'the fixed program.  An online RFuzz campaign needs an OnlineCaseDecoder, '
    'a reserved per-case instruction window and a checker; this assembly '
    'declares and runs none of them.')


@dataclass(frozen=True)
class CvwBootImage:
    """The declared RV32 program the real core fetches from its reset vector.

    ``data`` is the complete program; ``base`` is the profile's reset vector and
    the derived configuration's external-memory base; ``result`` is the result
    window the program writes.  ``source`` names the function that produced the
    bytes, and :attr:`sha256` pins them, so a saved run never depends on a
    mutable fixture.
    """

    base: int
    result: int
    data: bytes
    source: str
    gpio_base: int

    def __post_init__(self) -> None:
        for name, value in (('base', self.base), ('result', self.result),
                            ('gpio_base', self.gpio_base)):
            if type(value) is not int or value < 0 or value % 4:
                raise ValueError(f'CVW boot image {name} must be an aligned address')
        if not isinstance(self.data, bytes) or not self.data or len(self.data) % 4:
            raise ValueError('CVW boot image must be nonempty 4-byte words')
        if self.result < self.base + len(self.data):
            raise ValueError('CVW result window overlaps the boot program')
        if self.result + RESULT_BYTES > 1 << 32:
            raise ValueError('CVW result window exceeds the 32-bit data path')
        if type(self.source) is not str or not self.source:
            raise ValueError('CVW boot image needs a provenance source')

    @property
    def words(self) -> int:
        return len(self.data) // 4

    @property
    def window(self) -> tuple[int, int]:
        return self.base, len(self.data)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    def document(self) -> dict:
        return {'schema_version': BOOT_IMAGE_SCHEMA,
                'base': self.base, 'size_bytes': len(self.data),
                'words': self.words, 'sha256': self.sha256,
                'result': self.result, 'result_bytes': RESULT_BYTES,
                'gpio_base': self.gpio_base, 'source': self.source,
                'supply': ('the AHB-Lite CPU memory service: the reset word is '
                           'held until the core presents the measured reset '
                           'vector, then supplied through accept_instructions '
                           'with the rest of the declared image')}

    def install_program(self, memory: PersistentMemory) -> None:
        """Install the whole image as an initial image (the static-image path)."""
        memory.preload(self.base, self.data)

    def install_result_window(self, memory: PersistentMemory) -> None:
        memory.preload(self.result, bytes(RESULT_BYTES))


def make_cvw_boot_image(*, gpio_base=None) -> CvwBootImage:
    """Derive the boot image from the family declaration, never from a literal.

    The reset vector (hence ``base``), the device window base and the derived
    external-memory region all come from
    :func:`myfuzz.integration.cvw_pulp_online.cvw_pulp_gpio_wiring`, which reads
    the real profiles and the pinned derived configuration.  A profile whose
    reset vector left the external region is already refused there.
    """
    wiring = cvw_pulp_gpio_wiring()
    base = wiring.boot_base
    device = wiring.window_base if gpio_base is None else gpio_base
    if type(device) is not int or device < 0 or device % 0x1000:
        raise ValueError('GPIO program base must be an aligned RV32 page')
    return CvwBootImage(
        base=base, result=base + (RESULT - BOOT_BASE),
        data=cvw_gpio_program(gpio_base=device),
        source=('myfuzz.scenario.cvw_gpio_example:cvw_gpio_program'),
        gpio_base=device)


class CvwBootInstructionSource:
    """A declared instruction source driven by the measured AHB request address.

    The source has exactly the shape
    :class:`myfuzz.local_harness.ahb_lite_session.GeneratedAhbMemorySession`
    accepts (``before_step`` / ``after_step``) and records every decision it
    makes.  It supplies *only* the declared boot image: the reset word through
    the memory layer's validated online-slot interface and the rest of the image
    through the declared initial-image interface.  A measured request for any
    other address is a declaration error, not something to paper over.
    """

    def __init__(self, image: CvwBootImage):
        if not isinstance(image, CvwBootImage):
            raise ValueError('instruction source needs a declared CVW boot image')
        self.image = image
        self.source_event_prefix = f'cvw-boot:{image.sha256[:16]}'
        self.reset()

    def reset(self) -> None:
        self._step = 0
        self._delivered = False
        self._delivered_step = None
        self._hold_ticks_before_delivery = None
        self._first_presented_address = None
        self._first_presented_step = None
        self._first_measured_fetch_address = None
        self._accepted = []

    # -- the session's declared hooks --------------------------------------

    def before_step(self, session) -> None:
        self._step += 1
        if self._delivered:
            return
        address = session.measured_request_address()
        if address is None:
            # The core has not presented the fetch yet.  The session holds the
            # reset word; no bytes are supplied for a request nobody made.
            return
        if address != self.image.base:
            raise ValueError(
                'CVW boot fetch left the declared reset vector: '
                f'measured={address:#x} declared={self.image.base:#x}')
        self._first_measured_fetch_address = address
        self._hold_ticks_before_delivery = session.instruction_hold_ticks
        memory = session.memory
        # The reset word is admitted through the validated online-slot
        # interface; the rest of the fixed image is the declared initial image.
        memory.accept_instructions(
            self.image.base, self.image.data[:4],
            source_event_id=self.source_event_prefix + ':reset-word')
        if len(self.image.data) > 4:
            memory.preload(self.image.base + 4, self.image.data[4:])
        self._delivered = True
        self._delivered_step = self._step

    def after_step(self, session, outputs) -> None:
        if (self._first_presented_address is None
                and outputs.get('data_req_valid')):
            address = outputs.get('data_addr')
            if type(address) is int:
                self._first_presented_address = address
                self._first_presented_step = self._step
        if outputs.get('data_req_accepted'):
            address = outputs.get('data_addr')
            if type(address) is int and len(self._accepted) < 4096:
                self._accepted.append({
                    'step': self._step, 'address': address,
                    'write': bool(outputs.get('data_write')),
                    'value': outputs.get('data_wdata'),
                    'byte_enable': outputs.get('data_be')})

    # -- publication --------------------------------------------------------

    def document(self) -> dict:
        return {'schema_version': INSTRUCTION_SOURCE_SCHEMA,
                'kind': 'fixed_boot_image_instruction_source',
                'not_an_online_decoder': NOT_AN_ONLINE_DECODER,
                'boot_image': self.image.document(),
                'source_event_prefix': self.source_event_prefix,
                'holds': ('the reset word is declared as an instruction slot and '
                          'held until the measured request address is the '
                          'declared reset vector; the source then supplies the '
                          'word through accept_instructions and the rest of the '
                          'declared image as the initial image'),
                'refuses': ('a first measured fetch outside the declared reset '
                            'vector, and any attempt to supply bytes for a '
                            'request the core did not present')}

    def evidence(self) -> dict:
        image_base, image_size = self.image.window
        fetch_addresses = sorted({row['address'] for row in self._accepted
                                  if image_base <= row['address'] < image_base + image_size})
        return {'schema_version': INSTRUCTION_EVIDENCE_SCHEMA,
                'boot_image_sha256': self.image.sha256,
                'delivered': self._delivered,
                'delivered_step': self._delivered_step,
                'hold_ticks_before_delivery': self._hold_ticks_before_delivery,
                'first_presented_address': self._first_presented_address,
                'first_presented_step': self._first_presented_step,
                'first_measured_fetch_address': self._first_measured_fetch_address,
                'instruction_steps': self._step,
                'accepted_beats': list(self._accepted),
                'accepted_count': len(self._accepted),
                'fetch_addresses_from_image': fetch_addresses,
                'fetch_count_from_image': len(fetch_addresses)}


def make_cvw_boot_instruction_source(image: CvwBootImage | None = None
                                     ) -> CvwBootInstructionSource:
    return CvwBootInstructionSource(
        make_cvw_boot_image() if image is None else image)


def _session_artifacts(*, generated_artifacts, wiring):
    """The two admitted artifacts: the D2 set when supplied, else rendered here.

    A supplied D2 set is admitted through the shipped
    :func:`myfuzz.local_harness.generated_execution_admission.select_factory_artifacts`,
    so a profile/instance/kind/observation-mode mismatch is refused by name
    instead of being adapted.
    """
    if generated_artifacts is None:
        return (_artifact(wiring.cpu_profile, 'cpu'),
                _artifact(wiring.gpio_profile, 'gpio'))
    from myfuzz.local_harness.generated_execution_admission import (
        select_factory_artifacts)
    admitted = select_factory_artifacts(
        generated_artifacts,
        expected={'cpu': (wiring.cpu_profile, 'ahb_lite_cpu'),
                  'gpio': (wiring.gpio_profile, 'apb_gpio')},
        base_dir=ROOT)
    return admitted['cpu'], admitted['gpio']


def make_cvw_gpio_session_factory(*, cache_dir, boot_image: CvwBootImage | None = None,
                                  gpio_base=None, generated_artifacts=None,
                                  ) -> Callable[[], ScenarioRunner]:
    """Build the real CVW + PULP GPIO runner factory.

    Every call returns a **fresh** :class:`ScenarioRunner` over new CPU and GPIO
    session objects (and therefore new RTL processes when it is begun), with a
    fresh instruction source.  The host RAM is one declared persistent memory
    over the family's own external-memory region; the GPIO window is routed from
    the CPU's accepted AHB beats through one :class:`DataflowRouter`.
    """
    wiring = cvw_pulp_gpio_wiring()
    image = make_cvw_boot_image(gpio_base=gpio_base) if boot_image is None else boot_image
    if not isinstance(image, CvwBootImage):
        raise ValueError('CVW factory needs a declared boot image')
    cache_dir = Path(cache_dir)
    cpu_artifact, gpio_artifact = _session_artifacts(
        generated_artifacts=generated_artifacts, wiring=wiring)

    def factory() -> ScenarioRunner:
        memory = PersistentMemory(
            regions=wiring.memory_regions, initialization_seed=17,
            max_initialized_bytes=0x10000)
        image.install_result_window(memory)
        gpio = GeneratedPulpGpioSession(gpio_artifact, base_dir=ROOT,
                                        cache_dir=cache_dir)
        router = DataflowRouter((DeviceWindow(
            'gpio', wiring.window_base, wiring.window_size, gpio),))
        source = CvwBootInstructionSource(image)
        cpu = GeneratedAhbMemorySession(
            cpu_artifact, base_dir=ROOT, cache_dir=cache_dir, memory=memory,
            router=router, instruction_source=source)
        ownership = compile_ownership(
            (InputField('gpio', 'gpio_in', wiring.cpu_data_width),),
            (InputOwner('gpio', 'gpio_in', 0, wiring.cpu_data_width, 'source',
                        'cvw-directed-session:external-pins'),))
        runner = ScenarioRunner(
            sessions={'cpu': cpu, 'gpio': gpio}, ownership=ownership,
            bindings=())
        # The assembly facts travel with the factory so a caller never has to
        # reconstruct which image or window the returned runner really uses.
        runner.cvw_boot_image = image
        runner.cvw_instruction_source = source
        runner.cvw_session_wiring = wiring
        return runner

    factory.cvw_boot_image = image
    factory.cvw_session_wiring = wiring
    factory.cvw_generated_artifacts = generated_artifacts

    def document() -> dict:
        return {'schema_version': ASSEMBLY_SCHEMA,
                'kind': 'directed_fixed_image',
                'factory': ('myfuzz.scenario.cvw_session:'
                            'make_cvw_gpio_session_factory'),
                'boot_image': image.document(),
                'online_decoder': 'myfuzz.scenario.cvw_session:'
                                  'make_cvw_boot_instruction_source',
                'instruction_source': CvwBootInstructionSource(image).document(),
                'target_boundary': {
                    'cpu_endpoint': wiring.cpu_master_endpoint,
                    'cpu_protocol': list(wiring.cpu_master_protocol),
                    'adapter': ('src/myfuzz/protocols/rtl/'
                                'ahb_lite_memory_target.sv'),
                    'router': 'myfuzz.scenario.router:DataflowRouter',
                    'device_instance': 'gpio',
                    'device_endpoint': wiring.device_endpoint_id,
                    'device_protocol': list(wiring.device_protocol),
                    'window_base': wiring.window_base,
                    'window_size': wiring.window_size},
                'not_an_rfuzz_online_campaign': (
                    'a directed fixed-image session: no OnlineCaseDecoder, no '
                    'per-case reserved instruction window, no RFuzz client and '
                    'no coverage-guided search')}

    factory.document = document
    return factory


@dataclass(frozen=True)
class CvwSessionAssembly:
    """The three declared pieces, built once and published as one document."""

    boot_image: CvwBootImage
    instruction_source: CvwBootInstructionSource
    factory: Callable[[], ScenarioRunner]
    wiring: object

    def new_runner(self) -> ScenarioRunner:
        return self.factory()

    def document(self) -> dict:
        return self.factory.document()


def make_cvw_session_assembly(*, cache_dir, generated_artifacts=None,
                              gpio_base=None) -> CvwSessionAssembly:
    """Build the family's complete session assembly; no RTL is started."""
    image = make_cvw_boot_image(gpio_base=gpio_base)
    wiring = cvw_pulp_gpio_wiring()
    factory = make_cvw_gpio_session_factory(
        cache_dir=cache_dir, boot_image=image, gpio_base=gpio_base,
        generated_artifacts=generated_artifacts)
    return CvwSessionAssembly(
        boot_image=image, instruction_source=CvwBootInstructionSource(image),
        factory=factory, wiring=wiring)


__all__ = [
    'ASSEMBLY_SCHEMA', 'BOOT_IMAGE_SCHEMA', 'INSTRUCTION_EVIDENCE_SCHEMA',
    'INSTRUCTION_SOURCE_SCHEMA', 'NOT_AN_ONLINE_DECODER', 'RESULT_BYTES',
    'CvwBootImage', 'CvwBootInstructionSource', 'CvwSessionAssembly',
    'make_cvw_boot_image', 'make_cvw_boot_instruction_source',
    'make_cvw_gpio_session_factory', 'make_cvw_session_assembly']
