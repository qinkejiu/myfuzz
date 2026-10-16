"""Opt-in BOOM MEIP experiment. Source-only until its separate native gate passes."""
from pathlib import Path

from myfuzz.local_harness.boom_irq_scenario_session import GeneratedBoomIrqScenarioSession
from myfuzz.local_harness.gpio_session import GeneratedPulpGpioSession
from .boom_gpio_example import GPIO_BASE, _gpio_artifact, _addi, _sw, _bne
from .genome import Action, Trigger, ScenarioGenome
from .ownership import InputField, InputOwner, compile_ownership
from .router import DataflowRouter, DeviceWindow
from .runner import Binding, ScenarioRunner

IRQ_WIDTH_CPU_TICKS = 64
ISR_ADDRESS = 0x80000400
RAM_ADDRESSES = (0x3000, 0x3010, 0x3018, 0x3020, 0x3028)


def _csr(address, funct, rd=0, rs=0):
    return address << 20 | rs << 15 | funct << 12 | rd << 7 | 0x73


def _load(rd, base, offset, width=2):
    return offset << 20 | base << 15 | width << 12 | rd << 7 | 3


def _sd(rs, base, offset):
    return (_sw(rs, base, offset) & ~(7 << 12)) | 3 << 12


def boom_gpio_irq_program() -> bytes:
    """Real CSR setup, one ISR and foreground recovery; no result preload.

    x1 and x4 are immutable GPIO/RAM bases. ISR uses x10..x13 only. MEIE is
    disabled inside the ISR so the declared fixed pulse cannot retrap on MRET.
    Every RAM result below comes from a CPU instruction after boot.
    """
    words = [
        _csr(0x300, 7, rs=8),      # csrci mstatus,8
        _csr(0x304, 1), _csr(0x303, 1),  # mie=0, mideleg=0
        0x800002b7,               # lui x5,0x80000 (RV64 sign extends)
        0x02029293, 0x0202d293,   # slli/srli x5,32: zero extend
        _addi(5,5,0x400), _csr(0x305,1,rs=5),
        0x000040b7, 0x00003237, _addi(2,0,1),
        _sw(2,1,4), _sw(2,1,0x18), _sw(2,1,0x1c),
        0x0ff0000f, _load(3,1,0x24),  # clear old GPIO status
        _addi(5,0,1), 11 << 20 | 5 << 15 | 1 << 12 | 5 << 7 | 0x13,
        _csr(0x304,1,rs=5), _csr(0x300,6,rs=8),
        _sw(2,4,0),               # actual boot-ready RAM store
        _load(6,4,0x28),          # wait for ISR, never poll GPIO status
        _bne(6,0,8), 0xff9ff06f,  # nonzero -> resume, else jal -8
        _addi(6,0,1), _sw(6,4,0x2c), 0x0000006f,
    ]
    words += [0x00000013] * (256-len(words))
    words += [
        _csr(0x342,2,rd=10), _csr(0x341,2,rd=11),
        _sd(10,4,0x10), _sd(11,4,0x18),
        _addi(12,0,1), 11 << 20 | 12 << 15 | 1 << 12 | 12 << 7 | 0x13,
        _csr(0x304,3,rs=12),       # csrc mie,MEIE; no pulse extension
        _load(12,1,0x24), 0x0ff0000f, _load(13,1,0x24),
        _sw(12,4,0x20), _sw(13,4,0x24),
        _addi(12,0,1), _sw(12,4,0x28), 0x0ff0000f,
        0x30200073,               # exact MRET, not aggregate system-return
    ]
    words += [0x00000013] * (320-len(words))
    return b''.join(word.to_bytes(4,'little') for word in words)


def make_boom_gpio_irq_runner(*, repo: Path, cpu_output: Path,
                             cache_dir: Path) -> ScenarioRunner:
    repo = repo.resolve()
    gpio = GeneratedPulpGpioSession(_gpio_artifact(repo),base_dir=repo,cache_dir=cache_dir)
    cpu = None
    try:
        router = DataflowRouter((DeviceWindow('gpio',GPIO_BASE,0x1000,gpio),))
        cpu = GeneratedBoomIrqScenarioSession(cpu_output,repo=repo,router=router,
            program=boom_gpio_irq_program(),observed_ram_addresses=RAM_ADDRESSES)
        ownership = compile_ownership((InputField('gpio','gpio_in',32),InputField('cpu','irq',1)),
            (InputOwner('gpio','gpio_in',0,1,'source','external_pin'),
             InputOwner('gpio','gpio_in',1,31,'fixed','constant_zero'),
             InputOwner('cpu','irq',0,1,'bound','gpio.irq')))
        binding = Binding('gpio','irq','cpu','irq',1)
        return ScenarioRunner(sessions={'cpu':cpu,'gpio':gpio},ownership=ownership,
            bindings=(binding,),irq_pulses={binding:IRQ_WIDTH_CPU_TICKS})
    except BaseException:
        try:
            if cpu is not None: cpu.end_case()
        finally:
            gpio.end_case()
        raise


def make_boom_gpio_irq_genome(*, max_steps=20000):
    if type(max_steps) is not int or not 1 <= max_steps <= 250000:
        raise ValueError('invalid IRQ scheduler bound')
    return ScenarioGenome(testcase_id='boom-pulp-gpio-meip',direction='IP_TO_CPU',
        path_id='real-gpio-edge-fixed64-meip-machine-isr-mret-ram',
        schedule_order=('gpio','cpu'),max_steps=max_steps,encoding_version=3,quiesce_steps=512,
        actions=(Action('pin-rise','gpio','gpio_in',1,'IP_TO_CPU',
            Trigger('AFTER_OUTPUT','cpu','boot_ready',1,1),width=1),))
