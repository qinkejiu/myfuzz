"""Receipts bind real source-backed artifact inputs to selected executable bytes."""
import copy
from dataclasses import replace
import errno
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from myfuzz.local_harness import build
from tests.local_harness import test_build_identity as fixture_module
ROOT = fixture_module.ROOT


class BuiltExecutableReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_module.BuildIdentityTests.setUpClass.__func__(cls)

    def setUp(self):
        self.boundary = patch.object(build, '_verify_generated_driver')
        self.boundary.start()
        self.addCleanup(self.boundary.stop)
        self.artifact = fixture_module.BuildIdentityTests.fixture(self)
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.cache = Path(self.temporary.name)

    def fake_compile(self, argv, stage):
        (stage / 'obj').mkdir()
        binary = stage / 'obj/harness'
        binary.write_bytes(b'branch fixture executable')
        binary.chmod(0o700)

    def issue(self):
        return build.build_local_harness_with_receipt(self.artifact, base_dir=ROOT, cache_dir=self.cache)

    def test_real_build_receipt_and_detached_cache_hit(self):
        first = self.issue()
        receipt = first.receipt_document()
        self.assertEqual(receipt['schema_version'], 'local_harness_built_receipt.v1')
        self.assertEqual(receipt['artifact_digest'], self.artifact.runtime_document['artifact_digest'])
        self.assertEqual(receipt['binary_sha256'], build._digest(first.binary_path.read_bytes()))
        self.assertEqual(first.receipt_sha256, build._digest(build._canonical(receipt)))
        self.assertEqual(first.observation_document()['outcome'], 'compiled_published')
        second = self.issue()
        self.assertEqual(receipt, second.receipt_document())
        observation = second.observation_document()
        self.assertEqual(observation['outcome'], 'cache_hit')
        self.assertIsNone(observation['compile_seconds'])
        self.assertEqual(observation['compile_seconds_reason'], 'not_compiled_this_invocation')
        receipt['build_identity']['workers'] = False
        observation['outcome'] = 'fake'
        self.assertEqual(second.receipt_document()['build_identity']['workers'], 1)
        self.assertEqual(second.observation_document()['outcome'], 'cache_hit')
        self.assertEqual(second.validate_current(self.artifact, base_dir=ROOT, cache_dir=self.cache), first.binary_path)

    def test_race_reports_actual_compile_and_winning_binary(self):
        original = Path.rename
        def race(stage, final):
            if stage.parent == self.cache and stage.name.startswith('.'):
                import shutil
                shutil.copytree(stage, final)
                winner = final / 'harness'
                winner.write_bytes(b'independent winner')
                manifest = json.loads((final / 'manifest.json').read_bytes())
                manifest['binary_sha256'] = build._digest(winner.read_bytes())
                (final / 'manifest.json').write_bytes(build._canonical(manifest))
                raise OSError(errno.EEXIST, 'publication race')
            return original(stage, final)
        with patch.object(build, '_compile', self.fake_compile), patch.object(Path, 'rename', race):
            result = self.issue()
        self.assertEqual(result.observation_document()['outcome'], 'compiled_race_reused')
        self.assertTrue(result.observation_document()['compiled_this_invocation'])
        self.assertIsNotNone(result.observation_document()['compile_seconds'])
        self.assertEqual(result.receipt_document()['binary_sha256'], build._digest(b'independent winner'))

    def test_pinned_manifest_binary_inputs_identity_and_path_refuse(self):
        with patch.object(build, '_compile', self.fake_compile):
            result = self.issue()
        manifest = result.binary_path.parent / 'manifest.json'
        raw = manifest.read_bytes()
        manifest.write_bytes(raw + b'\n')
        with self.assertRaises(build.LocalHarnessBuildError):
            result.validate_current(self.artifact, base_dir=ROOT, cache_dir=self.cache)
        manifest.write_bytes(raw)
        for path in (result.binary_path, result.binary_path.parent / 'inputs/generated/runtime.sv'):
            saved = path.read_bytes()
            path.write_bytes(saved + b'changed')
            with self.assertRaises(build.LocalHarnessBuildError):
                result.validate_current(self.artifact, base_dir=ROOT, cache_dir=self.cache)
            path.write_bytes(saved)
        with self.assertRaises(build.LocalHarnessBuildError):
            replace(result, binary_path=result.binary_path.parent / 'obj/harness').validate_current(
                self.artifact, base_dir=ROOT, cache_dir=self.cache)
        with patch.object(build, 'CXX_STANDARD', 'c++20'):
            with self.assertRaises(build.LocalHarnessBuildError):
                result.validate_current(self.artifact, base_dir=ROOT, cache_dir=self.cache)
        changed = replace(self.artifact, cpp_text=self.artifact.cpp_text + '// drift')
        with self.assertRaises(build.LocalHarnessBuildError):
            result.validate_current(changed, base_dir=ROOT, cache_dir=self.cache)

    def test_malformed_cache_schema_and_document_refuse_without_repair(self):
        with patch.object(build, '_compile', self.fake_compile):
            result = self.issue()
        manifest = result.binary_path.parent / 'manifest.json'
        saved = json.loads(manifest.read_bytes())
        for bad in ({**saved, 'schema_version': 'future'}, {**saved, 'binary_sha256': True},
                    {**saved, 'identity': []}, [], {**saved, 'actual_build_argv': [False]}):
            manifest.write_text(json.dumps(bad))
            with patch.object(build, '_compile') as compile_mock:
                with self.assertRaises(build.LocalHarnessBuildError) as raised:
                    self.issue()
                compile_mock.assert_not_called()
                self.assertIsNotNone(raised.exception.preparation_observation)

    def test_failure_observation_is_detached_and_has_compile_phase(self):
        with patch.object(build, '_compile', side_effect=build.LocalHarnessBuildError('build-timeout')):
            with self.assertRaises(build.LocalHarnessBuildError) as raised:
                self.issue()
        observation = raised.exception.preparation_observation
        self.assertEqual(observation['failure_stage'], 'compile')
        self.assertTrue(observation['compiled_this_invocation'])
        self.assertIsNotNone(observation['compile_seconds'])
        self.assertTrue(observation['actual_build_argv'])
        observation['failure_stage'] = 'changed'
        self.assertEqual(raised.exception.preparation_observation['failure_stage'], 'compile')
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_receipt_shape_scalar_coercion_and_symlinks_refuse(self):
        with patch.object(build, '_compile', self.fake_compile):
            result = self.issue()
        receipt = result.receipt_document()
        for bad in ({**receipt, 'schema_version': 'future'},
                    {**receipt, 'binary_sha256': True},
                    {**receipt, 'build_identity': {**receipt['build_identity'], 'workers': True}}):
            with self.assertRaises(build.LocalHarnessBuildError):
                replace(result, _receipt_bytes=build._canonical(bad)).validate_current(
                    self.artifact, base_dir=ROOT, cache_dir=self.cache)
        binary = result.binary_path
        saved = binary.read_bytes()
        alternate = binary.parent / 'alternate'
        alternate.write_bytes(saved)
        alternate.chmod(0o700)
        binary.unlink()
        binary.symlink_to(alternate)
        with self.assertRaises(build.LocalHarnessBuildError):
            result.validate_current(self.artifact, base_dir=ROOT, cache_dir=self.cache)
        binary.unlink()
        alternate.rename(binary)
        inputs = binary.parent / 'inputs/generated'
        actual = binary.parent / 'generated-alternate'
        inputs.rename(actual)
        inputs.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(build.LocalHarnessBuildError):
            result.validate_current(self.artifact, base_dir=ROOT, cache_dir=self.cache)

    def test_postcompile_identity_failure_reports_identity_revalidation(self):
        with patch.object(build, '_compile', self.fake_compile), patch.object(
                build, 'local_build_identity', side_effect=build.LocalHarnessBuildError('changed-input')):
            with self.assertRaises(build.LocalHarnessBuildError) as raised:
                self.issue()
        observation = raised.exception.preparation_observation
        self.assertEqual(observation['failure_stage'], 'identity_revalidation')
        self.assertTrue(observation['compiled_this_invocation'])
        self.assertIsNotNone(observation['compile_seconds'])
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_publication_failure_reports_publication(self):
        with patch.object(build, '_compile', self.fake_compile), patch.object(
                Path, 'rename', side_effect=PermissionError(errno.EACCES, 'publication denied')):
            with self.assertRaises(build.LocalHarnessBuildError) as raised:
                self.issue()
        observation = raised.exception.preparation_observation
        self.assertEqual(observation['failure_stage'], 'publication')
        self.assertTrue(observation['compiled_this_invocation'])
        self.assertIsNotNone(observation['compile_seconds'])
        self.assertEqual(list(self.cache.iterdir()), [])

    def test_materialization_failure_reports_materialization_without_compile(self):
        original = Path.write_bytes
        def refuse_materialized(path, raw):
            if path.is_relative_to(self.cache) and 'inputs' in path.parts:
                raise PermissionError(errno.EACCES, 'materialization denied')
            return original(path, raw)
        with patch.object(build, '_compile') as compile_mock, patch.object(Path, 'write_bytes', refuse_materialized):
            with self.assertRaises(build.LocalHarnessBuildError) as raised:
                self.issue()
            compile_mock.assert_not_called()
        observation = raised.exception.preparation_observation
        self.assertEqual(observation['failure_stage'], 'materialization')
        self.assertFalse(observation['compiled_this_invocation'])
        self.assertIsNone(observation['compile_seconds'])
        self.assertEqual(list(self.cache.iterdir()), [])
