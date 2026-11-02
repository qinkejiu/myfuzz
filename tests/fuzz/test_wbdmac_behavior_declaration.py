"""Pure-Python check of the wbdmac F6 behavior declaration and its cross-check.

No RTL is simulated and no Verilator is started.  Two independent readings are
compared:

* ``configs/behaviors/wbdmac_f6.json`` through the entry's own
  ``dma_behavior()`` loader, which reports whether the control-status bits were
  declared by the device or fell back to the built-in ZipDMA default;
* the pinned wbdmac source contract (``verify_wbdmac_source_contract``), whose
  0x80000000 / 0x40000000 masks and ``native_pulse`` IRQ are the code-owned
  reading of ``third_party/soc-zipcpu/rtl/peripherals/wbdmac.v``.

The entry's ``dma_declaration`` is then exercised with the shape-only fake DMA
artifact already used by ``tests/integration/test_inprocess_f1f6_entry.py``, so
the test proves the existing wbdmac capability still passes that gate without
building anything.  The wbdmac artifact is the *no-master-SEL* shape
(``dma_artifact(master_sel=False)``): the pinned device has no ``o_mwb_sel`` and
its edge contract fixes the master enable at a full word, so an artifact that
declared a SEL would be refused by the planning module as a device contradiction.
"""
import json
from pathlib import Path

from myfuzz.composition.component_profile import load_component_profile
from myfuzz.composition.inprocess_behavior import (BUILTIN_STATUS_SOURCE,
                                                  dma_behavior)
from myfuzz.local_harness.wbdmac_source_contract import (
    verify_wbdmac_source_contract)
from scripts.run_inprocess_f1f6 import dma_declaration
from tests.integration.test_inprocess_f1f6_entry import dma_artifact

ROOT = Path(__file__).resolve().parents[2]
CONFIG = json.loads(
    (ROOT / 'configs/scenarios/inprocess-generality-wbdmac-f1f6-dma-decl.json')
    .read_text())
BEHAVIOR_PATH = 'configs/behaviors/wbdmac_f6.json'


def wbdmac_profile():
    return load_component_profile(ROOT / CONFIG['dma_profile'])


def facts():
    return dma_behavior(CONFIG, base_dir=ROOT)


def test_the_scenario_points_at_the_device_behavior_file():
    assert CONFIG['dma_behavior'] == BEHAVIOR_PATH
    assert (ROOT / CONFIG['dma_behavior']).is_file()


def test_the_file_declares_the_control_status_bits_not_the_builtin_default():
    declared = facts()
    # The declaration, not the fallback, is what the entry reads.
    assert declared['declared_by'] == 'file'
    assert declared['declaration_path'] == BEHAVIOR_PATH
    assert declared['status_bits_declared'] is True
    assert declared['status_bits_source'] == BEHAVIOR_PATH
    assert declared['status_bits_source'] != BUILTIN_STATUS_SOURCE
    # Values the file states, and the block this scenario transfers.
    assert declared['busy_bit'] == 31
    assert declared['err_bit'] == 30
    assert declared['block_words'] == 4
    assert declared['status_kind'] == 'status'
    # The file does not invent a delivery width: the native pulse width is a
    # profile interrupt fact, and the host delivery width stays the inline
    # default, so irq_pulse_ticks is absent rather than guessed.
    assert declared['irq_pulse_ticks'] is None


def test_the_declared_bits_match_the_pinned_wbdmac_readback():
    contract = verify_wbdmac_source_contract(wbdmac_profile(), base_dir=ROOT)
    declared = facts()
    # The masks the pinned source contract reads out of wbdmac.v: bit 31 is the
    # non-idle/readback busy bit and bit 30 is the latched cfg_err bit.
    assert contract['readback']['status_busy_mask'] == 1 << declared['busy_bit']
    assert contract['csr']['status_error_mask'] == 1 << declared['err_bit']
    assert contract['readback']['completion_irq'] == \
        'last_write_ack_or_nonidle_native_error_pulse'
    assert contract['irq']['trigger'] == 'native_pulse'
    assert contract['irq']['physical_port'] == 'o_interrupt'
    # The unit facts the behavior file deliberately does not restate.
    assert contract['readback']['length_encoding'] == '30_bit_word_count'
    assert contract['csr']['source_destination_units'] == 'byte_address'
    assert contract['csr']['master_address_units'] == 'word'
    assert contract['declared']['irq_clear'] == 'none'


def test_the_existing_wbdmac_capability_still_validates_dma_declaration():
    declaration = dma_declaration(CONFIG, wbdmac_profile(), dma_artifact(master_sel=False))
    assert declaration['busy_bit'] == 31
    assert declaration['err_bit'] == 30
    assert declaration['status_bits_declared'] is True
    assert declaration['status_bits_source'] == BEHAVIOR_PATH
    assert declaration['declared_behavior']['declaration_path'] == BEHAVIOR_PATH
    # The blocking and length facts still come from the profile contract: a
    # four-word transfer, word length, pulse completion IRQ with no clear write.
    assert declaration['block_words'] == 4
    assert declaration['length_value'] == 4
    assert declaration['clear'] is None
    assert declaration['irq']['trigger'] == 'pulse'
    assert declaration['irq']['port'] == 'o_interrupt'
    # The register kind is the profile's CONTROL_STATUS name, not a behavior
    # claim; the behavior file's status_kind is reported separately.
    assert declaration['status_kind'] == 'status'
    assert declaration['declared_behavior']['status_kind'] == 'status'


def test_without_the_file_the_entry_reports_the_builtin_default():
    plain = {key: value for key, value in CONFIG.items()
             if key != 'dma_behavior'}
    declaration = dma_declaration(plain, wbdmac_profile(), dma_artifact(master_sel=False))
    assert declaration['status_bits_declared'] is False
    assert declaration['status_bits_source'] == BUILTIN_STATUS_SOURCE
    # The fallback still produces the historical ZipDMA positions; the report
    # says where they came from instead of presenting them as wbdmac facts.
    assert (declaration['busy_bit'], declaration['err_bit']) == (31, 30)
    assert declaration['declared_behavior']['declaration_path'] is None


def test_behavior_pulse_width_is_consumed_before_the_inline_key():
    from scripts.run_inprocess_f1f6 import dma_irq_pulse_ticks
    assert dma_irq_pulse_ticks({'dma_irq_pulse_ticks': 3},
                               {'irq_pulse_ticks': 1}) == 1
    assert dma_irq_pulse_ticks({'dma_irq_pulse_ticks': 3},
                               {'irq_pulse_ticks': None}) == 3
    assert dma_irq_pulse_ticks({}, None) == 16
