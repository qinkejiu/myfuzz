"""BOOM/PULP GPIO through the standard ScenarioRunner scheduler.

Source integration only: compilation, native execution and acceptance controls
remain separate verification work. There is no IRQ or online ISA mutation path.
"""
from pathlib import Path

from myfuzz.local_harness.boom_scenario_session import GeneratedBoomScenarioSession
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from .boom_gpio_example import GPIO_BASE, RESULT, _gpio_artifact, boom_gpio_program
from .genome import ScenarioGenome
from .ownership import InputField, InputOwner, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import ScenarioRunner


def make_boom_gpio_runner(*, repo: Path, cpu_output: Path,
                          cache_dir: Path) -> ScenarioRunner:
    """Assemble an unstarted CPU/real GPIO pair for ordinary scheduled steps.

    CPU RTL must have been built explicitly using build_boom_session and its
    shared heavy lock. Static code is part of the session identity and is loaded
    before its first edge, including after reset; no result RAM is preloaded.
    Generic router discovery schedules GPIO access after CPU request acceptance.
    """
    repo = repo.resolve()
    gpio = GeneratedPulpGpioSession(_gpio_artifact(repo), base_dir=repo,
                                    cache_dir=cache_dir)
    cpu = None
    try:
        router = DataflowRouter((DeviceWindow('gpio', GPIO_BASE, 0x1000, gpio),))
        cpu = GeneratedBoomScenarioSession(cpu_output, repo=repo, router=router,
            program=boom_gpio_program(), source_component='cpu',
            observed_ram_addresses=(RESULT,))
        ownership = compile_ownership((InputField('gpio', 'gpio_in', 32),),
            (InputOwner('gpio', 'gpio_in', 0, 32, 'fixed', 'constant_zero'),))
        return ScenarioRunner(sessions={'cpu': cpu, 'gpio': gpio},
                              ownership=ownership, bindings=())
    except BaseException:
        try:
            if cpu is not None:
                cpu.end_case()
        finally:
            gpio.end_case()
        raise


def make_boom_gpio_genome(*, max_steps: int = 20000) -> ScenarioGenome:
    """Directed static image: write/read PADOUT then CPU result/success stores.

    A run must separately inspect actual CPU result observations and physical
    GPIO access evidence. A completed schedule alone does not establish pass.
    """
    if type(max_steps) is not int or not 1 <= max_steps <= 250000:
        raise ValueError('invalid BOOM directed scheduler bound')
    return ScenarioGenome(testcase_id='boom-pulp-gpio-directed',
        direction='CPU_TO_IP_TO_CPU',
        path_id='boom-coherent-uncached-pulp-gpio-readback-native-ram',
        schedule_order=('cpu', 'gpio'), max_steps=max_steps, actions=(),
        encoding_version=3, quiesce_steps=512)
