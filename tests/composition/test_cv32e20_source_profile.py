from pathlib import Path
import unittest
from myfuzz.composition.component_profile import bind_profile, elaborate_profile, load_component_profile
from myfuzz.composition.soc_port_dispositions import build_port_dispositions

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / 'configs/cpus/cv32e20/component_profile.json'

class CV32E20SourceProfileTests(unittest.TestCase):
    def test_complete_top_and_obi_roles(self):
        profile = load_component_profile(PROFILE)
        facts = elaborate_profile(profile, base_dir=ROOT)
        self.assertEqual(facts.selection, 'all')
        self.assertEqual(facts.top_module, 'cve2_top')
        binding = bind_profile(profile, facts)
        ledger = build_port_dispositions('cv32e20_0', binding, clock_domain='core', reset_domain='sys_rst', profile_port_actions=profile.port_actions)
        self.assertEqual(binding.endpoint('processor.instruction').function, 'instruction_memory_master')
        self.assertEqual(binding.endpoint('processor.data').function, 'data_memory_master')
        self.assertEqual(binding.field('processor.interrupts', 'external').port, 'irq_external_i')
        self.assertTrue(ledger)
        self.assertEqual(profile.source.revision, 'git:d079e8c8e6a08b330940ae123876ba0612bec18d')
