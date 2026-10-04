"""Pinned ZipCPU full AXI4 generated runtime and formal fresh replay."""
from pathlib import Path
import json
import tempfile
import unittest

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.axi4_cpu_session import GeneratedAxi4CpuSession
from myfuzz.scenario.evidence import save_evidence_bundle, replay_evidence_bundle
from myfuzz.scenario.genome import MemoryImage, ScenarioGenome
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.ownership import compile_ownership
from myfuzz.scenario.runner import ScenarioRunner
from myfuzz.scenario.contracts import ResourceBudget

ROOT = Path(__file__).resolve().parents[2]


def artifact():
    request = load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path='configs/cpus/zipaxi/component_profile.json', instance_id='zipcpu',
        reset_assert_ticks=16, reset_release_ticks=20, max_wait_cycles=32))
    plan = plan_local_harness(request, base_dir=ROOT)
    top = render_local_runtime(plan, render_local_harness(plan),
        verify_local_source_lock(plan.profile, base_dir=ROOT), base_dir=ROOT)
    return render_local_driver(top, base_dir=ROOT)


def program_bytes():
    # Existing encoder is derived from pinned ZipCPU RTL and disassembler.
    from importlib.util import module_from_spec, spec_from_file_location
    spec = spec_from_file_location('zipcpu_boot_image', ROOT/'tests/integration/zipcpu_boot_image.py')
    module = module_from_spec(spec)
    import sys
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return b''.join(item.word.to_bytes(4, 'little') for item in module.build_program())


class Axi4CpuAcceptance(unittest.TestCase):
    def test_published_manifest_schema_accepts_exact_axi4_session(self):
        from myfuzz.scenario.contracts import ResourceBudget, ScenarioManifest
        from jsonschema import Draft202012Validator
        cpu_artifact=artifact()
        memory=PersistentMemory(regions=(MemoryRegion('ram',0,4096),),
            initialization_seed=0,max_initialized_bytes=4096)
        cpu=GeneratedAxi4CpuSession(cpu_artifact,base_dir=ROOT,
            cache_dir=ROOT/'unused',memory=memory)
        identity=ScenarioRunner(sessions={'cpu':cpu},
            ownership=compile_ownership((),()),bindings=()).identity_document()
        doc=cpu_artifact.runtime_document
        reset=doc['driver_reset']
        timing=dict(schema_version='generated_local_reset.v1',
            artifact_digest=doc['artifact_digest'],driver_sha256=doc['cpp_sha256'],
            hold_cycles=reset['reset_assert_ticks'],
            release_cycles=reset['reset_release_ticks'])
        manifest=ScenarioManifest.from_runner_identity(identity,
            scenario_id='axi4-schema',schedule_order=('cpu',),
            scheduler_policy_id='stable-local-v1',budget=ResourceBudget(),
            reset_timings={'cpu':timing})
        schema=json.loads((ROOT/'schemas/scenario_runtime_manifest.v1.json').read_text())
        budget_schema=json.loads((ROOT/'schemas/scenario_manifest.v1.json').read_text())
        schema['properties']['budget']=budget_schema['properties']['budget']
        schema['$defs'].update(budget_schema.get('$defs',{}))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(manifest.to_document())

    def test_full_axi4_burst_program_and_fresh_formal_replay(self):
        cpu_artifact = artifact()
        self.assertEqual('axi4_cpu', cpu_artifact.runtime_document['kind'])
        self.assertEqual(74, len(cpu_artifact.runtime_document['backend_ports']))
        self.assertEqual([], cpu_artifact.runtime_document['adapter_sources'])
        with tempfile.TemporaryDirectory(prefix='myfuzz-axi4-evidence-') as directory:
            path = Path(directory)
            instances = []
            def factory():
                memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 4096),),
                    initialization_seed=0, max_initialized_bytes=4096)
                cpu = GeneratedAxi4CpuSession(cpu_artifact, base_dir=ROOT,
                    cache_dir=path/'cache', memory=memory)
                runner = ScenarioRunner(sessions={'cpu': cpu},
                    ownership=compile_ownership((), ()), bindings=())
                instances.append((cpu, memory))
                return runner
            case = ScenarioGenome(testcase_id='axi4-zipcpu-burst-program',
                direction='CPU_TO_IP', path_id='zipaxi-ram', schedule_order=('cpu',),
                max_steps=80, actions=(),
                initial_images=(MemoryImage('program', 'cpu', 0x100, program_bytes().hex()),))
            bundle = path/'evidence'
            trace = save_evidence_bundle(case, factory, bundle,
                budget=ResourceBudget(max_wall_time_ms=180000,
                                      max_materialized_bytes_per_memory=4096))
            self.assertEqual('complete', trace.status)
            cpu, memory = instances[0]
            self.assertGreaterEqual(cpu.read_bursts, 1)
            self.assertGreaterEqual(cpu.read_beats, 8)
            self.assertGreaterEqual(cpu.max_read_burst_length, 8)
            self.assertEqual(2, cpu.write_beats)
            self.assertEqual(0xbeef, memory.read(0x200, 4, transaction_id='verify').value)
            self.assertEqual(0xbef0, memory.read(0x204, 4, transaction_id='verify').value)
            self.assertEqual('axi4_cpu', json.loads((bundle/'manifest.json').read_text())
                             ['sessions']['cpu']['identity']['runtime_artifact']['kind'])
            replay = replay_evidence_bundle(bundle, factory)
            self.assertTrue(replay.matches, replay)
            self.assertEqual(0xbef0,
                instances[1][1].read(0x204, 4, transaction_id='replay').value)
            self.assertNotEqual(instances[0][0]._execution, instances[1][0]._execution)


if __name__ == '__main__':
    unittest.main()
