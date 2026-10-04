"""Build admission and an actual source-backed GPIO fixture executable."""
from dataclasses import replace
import copy
import hashlib
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from myfuzz.local_harness import render_local_harness, render_local_runtime, verify_local_source_lock
from myfuzz.local_harness.build import build_local_harness, local_build_identity, LocalHarnessBuildError
from myfuzz.local_harness.build import _verify_generated_driver as verify_generated_driver
from myfuzz.local_harness.renderer import _sha
from tests.local_harness.test_renderer import real_plan, ROOT


class BuildIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        plan=real_plan('configs/peripherals/pulp_gpio/component_profile.json','build_gpio')
        generator=ROOT/'src/myfuzz/local_harness/driver_renderer.py'
        if not generator.exists():
            generator.write_text('# Build-test generator identity fixture; no operational driver.\n')
            cls.addClassCleanup(generator.unlink)
        cls.top=render_local_runtime(plan,render_local_harness(plan),verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT)

    def setUp(self):
        # Only the driver-generation boundary is simulated. DUT source lock,
        # elaboration, snapshots, hashes, toolchain and actual compilation run.
        boundary=patch('myfuzz.local_harness.build._verify_generated_driver')
        boundary.start();self.boundary=boundary;self.addCleanup(boundary.stop)

    def fixture(self, cpp_suffix=''):
        module=self.top.runtime_document['module_name']
        cpp='''#include "V%s.h"
#include "verilated.h"
#include "local_driver_v1.h"
#include <iostream>
#define FIXTURE_STR_INNER(x) #x
#define FIXTURE_STR(x) FIXTURE_STR_INNER(x)
int main() {
  V%s dut; dut.clk=0; dut.reset=0; dut.eval();
  dut.reset=1; dut.eval(); dut.clk=1; dut.eval();
  dut.clk=0; dut.reset=0; dut.eval(); dut.final();
  std::cout << "FIXTURE " << FIXTURE_STR(MYFUZZ_ARTIFACT_DIGEST) << "\\n";
  return 0;
}
''' % (module,module)
        cpp += cpp_suffix
        doc=copy.deepcopy(self.top.runtime_document)
        doc.update(status='driver_generated',driver_status='generated',driver_schema_version='local_driver_generation.v1',
                   cpp_sha256=hashlib.sha256(cpp.encode()).hexdigest(),driver_header_sources=[
                       dict(path=p,sha256=hashlib.sha256((ROOT/p).read_bytes()).hexdigest()) for p in (
                           'src/myfuzz/local_harness/rtl/local_driver_v1.h','src/myfuzz/scenario/rtl/local_command_replay.h')])
        doc.update(driver_field_map={},driver_reset=dict(schema_version='generated_local_reset.v1',
                   reset_assert_ticks=self.top.plan.request.reset_assert_ticks,
                   reset_release_ticks=self.top.plan.request.reset_release_ticks),
                   driver_limits=dict(max_command_bytes=1024,max_payload_json_bytes=1048576,
                   max_reply_line_bytes=2097664,max_cached_bytes=67108864,reply_reservation_bytes=1024,
                   max_samples_per_command=2*self.top.runtime_document['effective_max_wait_cycles']+5))
        doc.pop('artifact_digest');doc['artifact_digest']=_sha(doc)
        return replace(self.top,cpp_text=cpp,runtime_document=doc)

    def test_top_only_and_mutated_artifacts_refused(self):
        with TemporaryDirectory() as cache:
            with self.assertRaisesRegex(LocalHarnessBuildError,'driver'):
                build_local_harness(self.top,base_dir=ROOT,cache_dir=Path(cache))
        a=self.fixture()
        bad_doc=copy.deepcopy(a.runtime_document);bad_doc['structural_abi']['ports'][0]['width']+=1
        for bad in (replace(a,cpp_text=a.cpp_text+'//changed'), replace(a,runtime_sv=a.runtime_sv+'//changed'),
                    replace(a,runtime_document=bad_doc)):
            with self.assertRaises(LocalHarnessBuildError):
                local_build_identity(bad,base_dir=ROOT)

    def test_identity_covers_driver_headers_flags_toolchain_and_generator(self):
        a=self.fixture();first=local_build_identity(a,base_dir=ROOT)
        self.assertEqual(first,local_build_identity(a,base_dir=ROOT))
        self.assertNotEqual(first['build_digest'],local_build_identity(self.fixture('//variant\n'),base_dir=ROOT)['build_digest'])
        with patch('myfuzz.local_harness.build.CXX_STANDARD','c++20'):
            self.assertNotEqual(first['build_digest'],local_build_identity(a,base_dir=ROOT)['build_digest'])
        paths={row['path'] for row in first['host_sources']['files']}
        self.assertIn('src/myfuzz/local_harness/build.py',paths)
        self.assertIn('src/myfuzz/local_harness/runtime_renderer.py',paths)
        self.assertIn('src/myfuzz/local_harness/rtl/local_driver_v1.h',{r['path'] for r in first['inputs']})
        self.assertIn(a.runtime_document['artifact_digest'],' '.join(first['build_argv']))
        self.assertEqual(first['schema_version'],'local_harness_build_identity.v1')
        self.assertEqual(first['workers'],1)

    def test_repeated_identity_reuses_verified_preparation_and_rechecks_bytes(self):
        artifact = self.fixture()
        with patch('myfuzz.local_harness.build.render_local_runtime',
                   wraps=render_local_runtime) as renderer:
            first = local_build_identity(artifact, base_dir=ROOT)
            second = local_build_identity(artifact, base_dir=ROOT)
            self.assertEqual(first, second)
            self.assertEqual(1, renderer.call_count)
        header = (ROOT / 'src/myfuzz/local_harness/rtl/local_driver_v1.h').resolve()
        original_read = Path.read_bytes

        def changed_header(path):
            raw = original_read(path)
            return raw + b'\n// changed after admission\n' if path.resolve() == header else raw

        with patch.object(Path, 'read_bytes', changed_header):
            with self.assertRaises(LocalHarnessBuildError):
                local_build_identity(artifact, base_dir=ROOT)

        source = (ROOT / 'third_party/soc-pulp-apb-gpio/rtl/apb_gpio.sv').resolve()

        def changed_rtl(path):
            raw = original_read(path)
            return raw + b'\n// changed RTL\n' if path.resolve() == source else raw

        with patch.object(Path, 'read_bytes', changed_rtl):
            with self.assertRaises(LocalHarnessBuildError):
                local_build_identity(artifact, base_dir=ROOT)

        changed_toolchain = copy.deepcopy(first['toolchain'])
        changed_toolchain['cxx']['version'] += '-mutated'
        with patch('myfuzz.local_harness.build._toolchain',
                   return_value=changed_toolchain):
            changed = local_build_identity(artifact, base_dir=ROOT)
            self.assertNotEqual(first['build_digest'], changed['build_digest'])

        artifact.runtime_document['driver_reset']['reset_assert_ticks'] += 1
        with self.assertRaisesRegex(LocalHarnessBuildError, 'artifact-digest'):
            local_build_identity(artifact, base_dir=ROOT)

    def test_header_change_and_undeclared_extension_refused(self):
        a=self.fixture()
        for mutate in ('header','extra','missing','escape'):
            doc=copy.deepcopy(a.runtime_document)
            if mutate=='header': doc['driver_header_sources'][0]['sha256']='0'*64
            if mutate=='extra': doc['unexpected']=True
            if mutate=='missing': doc['driver_header_sources'].pop()
            if mutate=='escape': doc['driver_header_sources'][0]['path']='../outside.h'
            doc.pop('artifact_digest');doc['artifact_digest']=_sha(doc)
            with self.assertRaises(LocalHarnessBuildError):
                local_build_identity(replace(a,runtime_document=doc),base_dir=ROOT)

    def test_actual_verilator_build_cache_and_corrupt_binary_refusal(self):
        a=self.fixture()
        with TemporaryDirectory() as cache:
            cache=Path(cache)
            executable=build_local_harness(a,base_dir=ROOT,cache_dir=cache)
            result=subprocess.run([str(executable)],text=True,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('FIXTURE '+a.runtime_document['artifact_digest'],result.stdout)
            before=executable.stat().st_mtime_ns
            self.assertEqual(executable,build_local_harness(a,base_dir=ROOT,cache_dir=cache))
            self.assertEqual(before,executable.stat().st_mtime_ns)
            source=executable.parent/'inputs/generated/runtime.sv'
            original=source.read_bytes();source.write_bytes(original+b'// cache mutation')
            with self.assertRaisesRegex(LocalHarnessBuildError,'cache'):
                build_local_harness(a,base_dir=ROOT,cache_dir=cache)
            source.write_bytes(original)
            executable.write_bytes(b'broken')
            with self.assertRaisesRegex(LocalHarnessBuildError,'cache'):
                build_local_harness(a,base_dir=ROOT,cache_dir=cache)

    def test_failed_build_is_not_published(self):
        a=self.fixture('\nthis is invalid C++\n')
        with TemporaryDirectory() as cache:
            cache=Path(cache)
            with self.assertRaises(LocalHarnessBuildError):
                build_local_harness(a,base_dir=ROOT,cache_dir=cache)
            self.assertEqual(list(cache.iterdir()),[])

    def test_timeout_cleans_staging_and_never_publishes(self):
        with TemporaryDirectory() as cache:
            with patch('myfuzz.local_harness.build.BUILD_TIMEOUT_SECONDS',0.001):
                with self.assertRaisesRegex(LocalHarnessBuildError,'timeout'):
                    build_local_harness(self.fixture(),base_dir=ROOT,cache_dir=Path(cache))
            self.assertEqual(list(Path(cache).iterdir()),[])

    def test_extra_declared_header_changes_identity(self):
        a=self.fixture();first=local_build_identity(a,base_dir=ROOT)
        with TemporaryDirectory(prefix='.build-extra-header-',dir=ROOT) as directory:
            header=Path(directory)/'extra.h';header.write_text('#pragma once\n')
            name=header.relative_to(ROOT).as_posix()
            doc=copy.deepcopy(a.runtime_document)
            doc['driver_header_sources'].append(dict(path=name,sha256=hashlib.sha256(header.read_bytes()).hexdigest()))
            doc.pop('artifact_digest');doc['artifact_digest']=_sha(doc)
            second=local_build_identity(replace(a,runtime_document=doc),base_dir=ROOT)
            self.assertNotEqual(first['build_digest'],second['build_digest'])

    def test_formal_driver_boundary_requires_generator_and_exact_regeneration(self):
        a=self.fixture()
        with TemporaryDirectory() as root:
            with patch('myfuzz.local_harness.build._IMPLEMENTATION_ROOT',Path(root)):
                with self.assertRaisesRegex(LocalHarnessBuildError,'generator-unavailable'):
                    verify_generated_driver(a,self.top,ROOT)
        generator=SimpleNamespace(render_local_driver=lambda baseline,base_dir:a)
        with patch('myfuzz.local_harness.build.importlib.import_module',return_value=generator):
            verify_generated_driver(a,self.top,ROOT)
            with self.assertRaisesRegex(LocalHarnessBuildError,'driver-identity'):
                verify_generated_driver(replace(a,cpp_text=a.cpp_text+'//other'),self.top,ROOT)

    def test_real_generated_driver_build_and_ready(self):
        self.boundary.stop()
        from myfuzz.local_harness.driver_renderer import render_local_driver
        artifact=render_local_driver(self.top,base_dir=ROOT)
        with TemporaryDirectory() as cache:
            executable=build_local_harness(artifact,base_dir=ROOT,cache_dir=Path(cache))
            result=subprocess.run([str(executable)],input='END\n',text=True,capture_output=True,timeout=10)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('READY local_driver.v1 '+artifact.runtime_document['artifact_digest'],result.stdout)
            self.assertEqual(executable,build_local_harness(artifact,base_dir=ROOT,cache_dir=Path(cache)))
