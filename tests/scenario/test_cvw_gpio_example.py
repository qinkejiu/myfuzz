"""Software contracts for the static CVW GPIO directed fixture."""
from unittest.mock import patch
from types import SimpleNamespace

from myfuzz.scenario.cvw_gpio_example import (
    BOOT_BASE, BOOT_BYTES, RESULT, cvw_gpio_program, make_cvw_gpio_chain,
)


def test_boot_image_is_complete_cache_lines_with_real_branches_and_two_outputs():
    image = cvw_gpio_program()
    assert BOOT_BASE % 64 == 0
    assert len(image) == BOOT_BYTES == 256
    words = [int.from_bytes(image[n:n+4], 'little') for n in range(0, len(image), 4)]
    assert words[0] == 0xCFFF00B7
    assert sum(w & 0x7f == 0x63 for w in words) == 2
    assert sum(w & 0x7f == 0x03 for w in words) == 2
    assert words[6] == 0x03500113
    assert words[11] == 0x06A00113
    assert words[18] == words[21] == 0x0000006F
    assert set(words[22:]) == {0x00000013}
    assert cvw_gpio_program(gpio_base=0)[:4] == bytes.fromhex('b7000000')


def test_entire_image_is_preloaded_before_cpu_construction(tmp_path):
    module = 'myfuzz.scenario.cvw_gpio_example'
    artifacts = [object(), object()]
    def cpu(artifact, **kwargs):
        memory = kwargs['memory']
        assert b''.join(memory.read(BOOT_BASE+n, 4, transaction_id=f'fixture-{n}').data for n in range(0, BOOT_BYTES, 4)) == cvw_gpio_program()
        assert b''.join(memory.read(RESULT+n, 4, transaction_id=f'result-{n}').data for n in range(0, 12, 4)) == bytes(12)
        return SimpleNamespace(artifact=artifact, **kwargs)
    with patch(module + '._artifact', side_effect=artifacts), \
         patch(module + '.GeneratedAhbMemorySession', side_effect=cpu), \
         patch(module + '.GeneratedPulpGpioSession', side_effect=lambda a, **kw: SimpleNamespace(artifact=a, **kw)):
        core, gpio, router, memory = make_cvw_gpio_chain(cache_dir=tmp_path)
    assert core.router is router
    assert router.windows[0].target is gpio
    assert router.windows[0].base == 0xCFFF0000
    assert memory.identity_document()['regions'][0]['size'] == 0x0FFF0000
