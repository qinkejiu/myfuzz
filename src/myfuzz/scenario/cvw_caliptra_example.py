"""Static CVW CPU image executing two hashes on the real Caliptra AHB target."""
from pathlib import Path
from functools import lru_cache

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, render_local_driver, verify_local_source_lock)
from myfuzz.local_harness.ahb_lite_register_session import GeneratedAhbLiteRegisterSession
from myfuzz.local_harness.ahb_lite_session import GeneratedAhbMemorySession
from myfuzz.integration.cvw_pulp_online import cvw_pulp_gpio_wiring
from .cvw_gpio_example import _artifact, _addi, _sw, _lw, _bne
from .memory import PersistentMemory
from .router import DataflowRouter, DeviceWindow

ROOT = Path(__file__).resolve().parents[3]
BOOT_BASE = 0xC0000000
RESULT = BOOT_BASE + 0x1000
BASE = 0xCFFF0000
BOOT_BYTES = 1024
SHA_PROFILE = 'configs/peripherals/caliptra_sha256/component_profile.json'


def _li(rd, value):
    value &= 0xffffffff
    low = value & 0xfff
    high = ((value + 0x800) & 0xfffff000)
    return [high | rd << 7 | 0x37, _addi(rd, rd, low)]


def cvw_caliptra_program(*, sha_base=BASE, partial_store=False):
    """Only message padding and code are supplied; the CPU loads actual digests."""
    if type(sha_base) is not int or not 0 <= sha_base <= 0xfffff000 or sha_base % 4096:
        raise ValueError('SHA base must be an aligned RV32 page')
    words = _li(1, sha_base) + _li(8, RESULT)
    for message_index, payload in enumerate((b'abc', b'abd')):
        block = [int.from_bytes(payload+b'\x80', 'big')] + [0]*14 + [24]
        for index, value in enumerate(block):
            words += _li(2, value) + [_sw(2, 1, 0x80+index*4)]
        words += [_addi(2, 0, 5), _sw(2, 1, 0x10)]
        # Real STATUS.valid gates all digest loads. Target advances on each poll.
        words += [_lw(3, 1, 0x18), (2 << 20) | (3 << 15) | (7 << 12) | (3 << 7) | 0x13,
                  _bne(3, 0, 8), 0xff5ff06f]  # j back 12 bytes
        for index in range(8):
            words += [_lw(3, 1, 0x100+index*4), _sw(3, 8, message_index*32+index*4)]
    if partial_store:
        # First BLOCK write becomes an actual CPU SB, unsupported by the target.
        words[6] &= ~(7 << 12)
    words += [_addi(4, 0, 1), _sw(4, 8, 64), 0x0000006f]
    assert len(words)*4 <= BOOT_BYTES
    words += [0x00000013]*(BOOT_BYTES//4-len(words))
    return b''.join(word.to_bytes(4, 'little') for word in words)


@lru_cache(maxsize=1)
def _artifacts():
    """Verify frozen source profiles once; native sessions remain independent."""
    wiring = cvw_pulp_gpio_wiring()
    cpu_art = _artifact(wiring.cpu_profile, 'cpu')
    request = load_local_harness_request(dict(schema_version='local_harness.v2',
        profile_path=SHA_PROFILE, instance_id='sha', reset_assert_ticks=8,
        reset_release_ticks=8, max_wait_cycles=16,
        tuning={'endpoint_policies': [dict(endpoint_id='sha256.bus',
            template_id='target.ahb-lite', template_version='1',
            variant_id='full-word-single', max_outstanding=1)]}))
    plan = plan_local_harness(request, base_dir=ROOT)
    sha_art = render_local_driver(render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT), base_dir=ROOT)
    return wiring, cpu_art, sha_art


def make_cvw_caliptra_chain(*, cache_dir: Path, sha_base=BASE, partial_store=False):
    wiring, cpu_art, sha_art = _artifacts()
    memory = PersistentMemory(regions=wiring.memory_regions,
        initialization_seed=17, max_initialized_bytes=0x10000)
    memory.preload(BOOT_BASE, cvw_caliptra_program(sha_base=sha_base, partial_store=partial_store))
    memory.preload(RESULT, bytes(68))
    sha = GeneratedAhbLiteRegisterSession(sha_art, base_dir=ROOT, cache_dir=cache_dir)
    router = DataflowRouter((DeviceWindow('sha', sha_base, 4096, sha),))
    cpu = GeneratedAhbMemorySession(cpu_art, base_dir=ROOT, cache_dir=cache_dir,
                                    memory=memory, router=router)
    return cpu, sha, router, memory
