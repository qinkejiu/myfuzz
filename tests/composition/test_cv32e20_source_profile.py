import json
from copy import deepcopy
from pathlib import Path
import unittest
from myfuzz.composition.component_profile import ComponentProfileError, bind_profile, elaborate_profile, load_component_profile
from myfuzz.composition.soc_port_dispositions import PortDispositionError, build_port_dispositions

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / 'configs/cpus/cv32e20/component_profile.json'

class CV32E20SourceProfileTests(unittest.TestCase):
    def test_complete_top_and_obi_roles(self):
        profile = load_component_profile(PROFILE)
        facts = elaborate_profile(profile, base_dir=ROOT)
        self.assertEqual(facts.selection, 'all')
        self.assertEqual(facts.top_module, 'cve2_top')
        self.assertEqual((len(facts.ports), sum(p.width for p in facts.ports)),
                         (70, 1308))
        binding = bind_profile(profile, facts)
        ledger = build_port_dispositions('cv32e20_0', binding, clock_domain='core', reset_domain='sys_rst', profile_port_actions=profile.port_actions)
        self.assertEqual(binding.endpoint('processor.instruction').function, 'instruction_memory_master')
        self.assertEqual(binding.endpoint('processor.data').function, 'data_memory_master')
        self.assertEqual(binding.field('processor.interrupts', 'external').port, 'irq_external_i')
        self.assertTrue(ledger)
        self.assertEqual(sum(entry.bit_hi - entry.bit_lo + 1 for entry in ledger),
                         sum(port.width for port in facts.ports))
        self.assertEqual(profile.source.revision, 'git:d079e8c8e6a08b330940ae123876ba0612bec18d')

    def test_wrong_source_revision_is_rejected(self):
        document = json.loads(PROFILE.read_text())
        document["source"]["revision"] = "git:" + "0" * 40
        with self.assertRaisesRegex(ComponentProfileError, "git-revision-mismatch"):
            elaborate_profile(load_component_profile(document), base_dir=ROOT)

    def test_missing_input_action_is_rejected(self):
        document = json.loads(PROFILE.read_text())
        document["port_actions"] = [action for action in document["port_actions"]
                                    if action["port"] != "fetch_enable_i"]
        profile = load_component_profile(document)
        binding = bind_profile(profile, elaborate_profile(profile, base_dir=ROOT))
        with self.assertRaisesRegex(PortDispositionError,
                                    "undisposed-port-bits:cv32e20_0:fetch_enable_i:0:0"):
            build_port_dispositions(
                "cv32e20_0", binding, clock_domain="core", reset_domain="sys_rst",
                profile_port_actions=profile.port_actions)

    def test_duplicate_physical_obi_output_is_rejected(self):
        document = json.loads(PROFILE.read_text())
        data = next(item for item in document["endpoints"]
                    if item["endpoint_id"] == "processor.data")
        req = next(item for item in data["fields"] if item["role"] == "req")
        # Equal direction and width isolate duplicate ownership from width errors.
        we = next(item for item in data["fields"] if item["role"] == "we")
        we["aliases"] = deepcopy(req["aliases"])
        with self.assertRaisesRegex(ComponentProfileError,
                                    "duplicate-port-binding:data_req_o:"):
            profile = load_component_profile(document)
            bind_profile(profile, elaborate_profile(profile, base_dir=ROOT))
