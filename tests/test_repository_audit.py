from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import py_compile
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/audit_repository.py'


class RepositoryAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'repo'
        self.root.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'user.name', 'test')
        self.write('.gitignore', '__pycache__/\n/runs/\n')
        self.write('src/model.py', 'VALUE = 1\n')
        self.write('sources.f', 'third_party/ip.sv\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')
        self.write('third_party/ip.sv', 'module ip; endmodule\n')
        self.write('notes.md', 'user notes\n')
        py_compile.compile(str(self.root / 'src/model.py'), doraise=True)
        self.cache = next((self.root / 'src/__pycache__').glob('*.pyc'))
        self.relative = self.cache.relative_to(self.root).as_posix()

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args], check=True,
                              capture_output=True, text=True).stdout

    def write(self, path, content):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

    def module(self):
        self.assertTrue(SCRIPT.exists(), 'repository audit tool is not implemented')
        spec = importlib.util.spec_from_file_location('repository_audit', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def selection(self):
        return [{'path': self.relative,
                 'sha256': hashlib.sha256(self.cache.read_bytes()).hexdigest(),
                 'reason': 'rebuild using python3 -m compileall src/model.py'}]

    def test_audit_is_read_only_and_protects_sources(self):
        api = self.module()
        before = self.cache.read_bytes()
        report = api.audit(self.root)
        self.assertEqual(report['entries']['third_party/ip.sv']['action'], 'keep')
        self.assertEqual(report['entries']['notes.md']['action'], 'keep')
        self.assertEqual(report['entries'][self.relative]['action'], 'eligible')
        self.assertEqual(before, self.cache.read_bytes())
        self.assertFalse((self.root / 'runs').exists())

    def test_dirty_source_and_tracked_cache_are_kept(self):
        api = self.module()
        self.write('src/model.py', 'VALUE = 2\n')
        self.assertEqual(api.audit(self.root)['entries'][self.relative]['action'], 'keep')
        self.git('add', 'src/model.py')
        self.assertEqual(api.audit(self.root)['entries'][self.relative]['action'], 'keep')
        self.git('commit', '-qm', 'change')
        self.git('add', '-f', self.relative)
        self.assertEqual(api.audit(self.root)['entries'][self.relative]['action'], 'keep')

    def test_referenced_cache_is_kept(self):
        api = self.module()
        self.write('config.json', json.dumps({'source': self.relative}))
        self.assertEqual(api.audit(self.root)['entries'][self.relative]['action'], 'keep')

    def test_quarantine_and_restore_preserve_bytes(self):
        api = self.module()
        before = self.cache.read_bytes()
        manifest = api.quarantine(self.root, self.selection(), 'test-batch')
        self.assertFalse(self.cache.exists())
        record = json.loads(manifest.read_text())
        self.assertEqual(record['entries'][0]['path'], self.relative)
        self.assertEqual(record['entries'][0]['status'], 'moved')
        self.assertEqual((self.root / record['entries'][0]['stored_path']).read_bytes(), before)
        api.restore(self.root, manifest)
        self.assertEqual(self.cache.read_bytes(), before)
        self.assertEqual(json.loads(manifest.read_text())['entries'][0]['status'], 'restored')

    def test_invalid_selection_never_moves(self):
        api = self.module()
        for patch in [{'path': '../outside.pyc'}, {'path': str(self.cache)},
                      {'sha256': '0' * 64}, {'reason': ''},
                      {'path': 'third_party/ip.sv'}]:
            with self.subTest(patch=patch):
                item = self.selection()[0] | patch
                with self.assertRaises(ValueError):
                    api.quarantine(self.root, [item], 'invalid')
                self.assertTrue(self.cache.exists())

    def test_batch_validation_is_all_or_nothing(self):
        api = self.module()
        selection = self.selection() + [self.selection()[0] | {'path': 'notes.md'}]
        with self.assertRaises(ValueError):
            api.quarantine(self.root, selection, 'invalid')
        self.assertTrue(self.cache.exists())

    def test_symlink_and_nested_git_repositories_are_kept(self):
        api = self.module()
        outside = Path(self.temp.name) / 'outside'
        outside.mkdir()
        (outside / 'payload.pyc').write_bytes(b'not ours')
        (self.root / 'linked').symlink_to(outside, target_is_directory=True)
        self.write('src/nested/.git/HEAD', 'nested')
        self.write('src/nested/__pycache__/item.cpython-312.pyc', 'opaque')
        report = api.audit(self.root)
        self.assertEqual(report['entries']['linked']['action'], 'keep')
        self.assertNotIn('linked/payload.pyc', report['entries'])
        self.assertEqual(report['entries']['src/nested']['action'], 'keep')

    def test_restore_rejects_collision_and_tampering(self):
        api = self.module()
        manifest = api.quarantine(self.root, self.selection(), 'test-batch')
        self.cache.write_bytes(b'new cache')
        with self.assertRaises(ValueError):
            api.restore(self.root, manifest)
        self.assertEqual(self.cache.read_bytes(), b'new cache')
        self.cache.unlink()
        record = json.loads(manifest.read_text())
        record['entries'][0]['path'] = '../outside.pyc'
        manifest.write_text(json.dumps(record))
        with self.assertRaises(ValueError):
            api.restore(self.root, manifest)

    def test_cli_default_audit_never_overwrites_output(self):
        self.module()
        output = self.root / 'inventory.json'
        args = ['python3', str(SCRIPT), '--root', str(self.root), '--output', str(output)]
        subprocess.run(args, check=True, capture_output=True)
        before = output.read_bytes()
        result = subprocess.run(args, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(output.read_bytes(), before)
        self.assertTrue(self.cache.exists())

    def test_cache_shaped_symlink_to_outside_file_is_kept(self):
        api = self.module()
        outside = Path(self.temp.name) / 'outside.pyc'
        outside.write_bytes(b'\x42\x0d\x0d\x0a' + b'\x00' * 12 + b'external payload')
        link = self.root / 'src/__pycache__/orphan.cpython-312.pyc'
        link.symlink_to(outside)
        report = api.audit(self.root)
        self.assertEqual(report['entries']['src/__pycache__/orphan.cpython-312.pyc']['action'], 'keep')
        self.assertNotIn('src/__pycache__/orphan.cpython-312.pyc',
                         [c['path'] for c in report['quarantine_candidates']])
        self.assertTrue(outside.exists())
        self.assertEqual(link.resolve(), outside.resolve())

    def test_symlinked_parent_escape_never_moves_outside_file(self):
        api = self.module()
        outside = Path(self.temp.name) / 'outside'
        outside.mkdir()
        payload = outside / 'payload.pyc'
        payload.write_bytes(b'outside bytes')
        shutil.rmtree(self.root / 'src/__pycache__')
        (self.root / 'src/__pycache__').symlink_to(outside, target_is_directory=True)
        selection = [{'path': 'src/__pycache__/payload.pyc',
                      'sha256': hashlib.sha256(payload.read_bytes()).hexdigest(),
                      'reason': 'rebuildable'}]
        with self.assertRaises(ValueError):
            api.quarantine(self.root, selection, 'escape')
        self.assertEqual(payload.read_bytes(), b'outside bytes')

    def test_apply_rechecks_the_audit_verdict(self):
        api = self.module()
        selection = self.selection()
        self.write('src/model.py', 'VALUE = 3\n')
        with self.assertRaises(ValueError):
            api.quarantine(self.root, selection, 'stale-verdict')
        self.assertTrue(self.cache.exists())

    def test_failed_move_rolls_the_whole_batch_back(self):
        api = self.module()
        self.write('src/other.py', 'OTHER = 1\n')
        self.git('add', 'src/other.py')
        self.git('commit', '-qm', 'other')
        py_compile.compile(str(self.root / 'src/other.py'), doraise=True)
        other = next((self.root / 'src/__pycache__').glob('other*.pyc'))
        report = api.audit(self.root)
        self.assertEqual(report['entries'][self.relative]['action'], 'eligible')
        self.assertEqual(report['entries'][other.relative_to(self.root).as_posix()]['action'], 'eligible')

        real_move = shutil.move
        calls = []

        def flaky(source, destination):
            calls.append(str(destination))
            if len(calls) == 2:
                raise OSError('simulated move failure')
            return real_move(source, destination)

        with patch.object(api.shutil, 'move', side_effect=flaky):
            with self.assertRaises(ValueError):
                api.quarantine(self.root, report['quarantine_candidates'], 'flaky')
        self.assertTrue(self.cache.exists())
        self.assertTrue(other.exists())
        manifest = self.root / 'runs/quarantine/flaky/manifest.json'
        statuses = {entry['status'] for entry in json.loads(manifest.read_text())['entries']}
        self.assertIn('rolled-back', statuses)
        self.assertNotIn('moved', statuses)

    def test_restore_never_clobbers_tracked_or_foreign_targets(self):
        api = self.module()
        manifest = api.quarantine(self.root, self.selection(), 'guarded')
        document = json.loads(manifest.read_text())
        original = document['entries'][0]['stored_path']
        document['entries'][0]['stored_path'] = 'src/model.py'
        manifest.write_text(json.dumps(document))
        with self.assertRaises(ValueError):
            api.restore(self.root, manifest)
        self.assertTrue((self.root / 'src/model.py').exists())
        document['entries'][0]['stored_path'] = original
        document['root'] = '/tmp/not-this-worktree'
        manifest.write_text(json.dumps(document))
        with self.assertRaises(ValueError):
            api.restore(self.root, manifest)
        document['root'] = str(self.root.resolve())
        manifest.write_text(json.dumps(document))
        self.write(self.relative, 'cached again')
        self.git('add', '-f', self.relative)
        with self.assertRaises(ValueError):
            api.restore(self.root, manifest)
        self.assertEqual((self.root / self.relative).read_text(), 'cached again')

    def test_cache_without_pinned_source_is_kept(self):
        api = self.module()
        self.write('src/gone.py', 'GONE = 1\n')
        self.git('add', 'src/gone.py')
        self.git('commit', '-qm', 'gone')
        py_compile.compile(str(self.root / 'src/gone.py'), doraise=True)
        cache = self.root / 'src/__pycache__/gone.cpython-312.pyc'
        self.assertTrue(cache.exists())
        self.git('rm', '-q', 'src/gone.py')
        report = api.audit(self.root)
        self.assertEqual(report['entries']['src/__pycache__/gone.cpython-312.pyc']['action'], 'keep')
        self.assertTrue(cache.exists())

    def test_hash_invalidated_cache_is_kept(self):
        api = self.module()
        self.write('src/hashed.py', 'HASHED = 1\n')
        self.git('add', 'src/hashed.py')
        self.git('commit', '-qm', 'hashed')
        py_compile.compile(str(self.root / 'src/hashed.py'), doraise=True,
                           invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH)
        report = api.audit(self.root)
        self.assertEqual(report['entries']['src/__pycache__/hashed.cpython-312.pyc']['action'], 'keep')

    def test_staged_rename_reports_both_paths_as_dirty(self):
        api = self.module()
        self.write('src/extra.py', 'EXTRA = 1\n')
        self.git('add', 'src/extra.py')
        self.git('commit', '-qm', 'extra')
        self.git('mv', 'src/extra.py', 'src/extra_renamed.py')
        dirty = api._dirty_paths(self.root)
        self.assertIn('src/extra_renamed.py', dirty)
        self.assertIn('src/extra.py', dirty)

    def test_inventory_written_into_the_tree_does_not_hide_candidates(self):
        self.module()
        output = self.root / 'inventory.json'
        subprocess.run(['python3', str(SCRIPT), '--root', str(self.root), '--output', str(output)],
                       check=True, capture_output=True)
        api = self.module()
        self.assertEqual(api.audit(self.root)['entries'][self.relative]['action'], 'eligible')

    def test_cli_rejects_ambiguous_or_unused_options(self):
        self.module()
        target = self.root / 'shared.json'
        result = subprocess.run(['python3', str(SCRIPT), '--root', str(self.root),
                                 '--output', str(target), '--quarantine-list', str(target)],
                                capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(target.exists())
        result = subprocess.run(['python3', str(SCRIPT), '--root', str(self.root),
                                 '--batch', 'orphan'], capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_cli_apply_records_batch_audit_and_manifest(self):
        self.module()
        selection = self.root / 'selection.json'
        subprocess.run(['python3', str(SCRIPT), '--root', str(self.root),
                        '--quarantine-list', str(selection)], check=True, capture_output=True)
        result = subprocess.run(['python3', str(SCRIPT), '--root', str(self.root),
                                 '--apply', str(selection), '--batch', 'batch-one'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        inventory = self.root / 'runs/repository-audit/batch-one/inventory.json'
        self.assertTrue(inventory.exists())
        self.assertTrue((self.root / 'runs/quarantine/batch-one/manifest.json').exists())
        document = json.loads(inventory.read_text())
        self.assertEqual(document['entries'][self.relative]['action'], 'eligible')

    def test_batch_directory_symlink_is_rejected(self):
        api = self.module()
        outside = Path(self.temp.name) / 'store-one'
        outside.mkdir()
        (self.root / 'runs/quarantine').mkdir(parents=True)
        (self.root / 'runs/quarantine/batch-a').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            api.quarantine(self.root, self.selection(), 'batch-a')
        self.assertTrue(self.cache.exists())
        self.assertEqual(list(outside.iterdir()), [])

    def test_symlinked_package_directory_inside_store_is_rejected(self):
        api = self.module()
        outside = Path(self.temp.name) / 'store-two'
        outside.mkdir()
        (self.root / 'runs/quarantine/batch-b/files').mkdir(parents=True)
        (self.root / 'runs/quarantine/batch-b/files/src').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            api.quarantine(self.root, self.selection(), 'batch-b')
        self.assertTrue(self.cache.exists())
        self.assertEqual(list(outside.iterdir()), [])

    def test_partial_restore_failure_stays_recoverable(self):
        api = self.module()
        self.write('src/other.py', 'OTHER = 1\n')
        self.git('add', 'src/other.py')
        self.git('commit', '-qm', 'other')
        py_compile.compile(str(self.root / 'src/other.py'), doraise=True)
        other = next((self.root / 'src/__pycache__').glob('other*.pyc'))
        manifest = api.quarantine(self.root, api.audit(self.root)['quarantine_candidates'], 'partial')

        real_move = shutil.move
        calls = []

        def flaky(source, destination):
            calls.append(str(destination))
            if len(calls) == 2:
                raise OSError('simulated restore failure')
            return real_move(source, destination)

        with patch.object(api.shutil, 'move', side_effect=flaky):
            with self.assertRaises(ValueError):
                api.restore(self.root, manifest)
        statuses = {entry['status'] for entry in json.loads(manifest.read_text())['entries']}
        self.assertIn('restored', statuses)
        self.assertIn('moved', statuses)
        api.restore(self.root, manifest)
        self.assertTrue(self.cache.exists())
        self.assertTrue(other.exists())

    def test_cache_inside_pruned_ignored_directory_is_discovered(self):
        api = self.module()
        self.write('.gitignore', '__pycache__/\n/runs/\n.venv/\n')
        self.git('add', '.gitignore')
        self.git('commit', '-qm', 'ignore venv')
        self.write('.venv/lib/dep.py', 'DEP = 1\n')
        py_compile.compile(str(self.root / '.venv/lib/dep.py'), doraise=True)
        report = api.audit(self.root)
        self.assertEqual(report['entries']['.venv/lib/__pycache__/dep.cpython-312.pyc']['action'],
                         'keep')
        self.assertEqual(report['entries']['.venv/lib/__pycache__/dep.cpython-312.pyc']['reason'],
                         'untracked-source')

    def test_own_manifest_does_not_reference_the_rebuilt_cache(self):
        api = self.module()
        self.write('.gitignore', '__pycache__/\n')
        self.git('add', '.gitignore')
        self.git('commit', '-qm', 'runs is visible here')
        api.quarantine(self.root, self.selection(), 'round-one')
        py_compile.compile(str(self.root / 'src/model.py'), doraise=True)
        self.assertEqual(api.audit(self.root)['entries'][self.relative]['action'], 'eligible')

    def test_marker_text_in_a_non_json_file_does_not_hide_a_reference(self):
        api = self.module()
        self.write('notes.txt', 'see repository_audit.v1 docs, path ' + self.relative + '\n')
        self.assertEqual(api.audit(self.root)['entries'][self.relative]['action'], 'keep')

    def test_bare_filename_reference_is_detected(self):
        api = self.module()
        self.write('notes.txt', 'cached as ' + self.relative.rsplit('/', 1)[-1] + '\n')
        self.assertEqual(api.audit(self.root)['entries'][self.relative]['action'], 'keep')

    def test_hand_written_in_tree_selection_is_excluded_from_the_scan(self):
        api = self.module()
        selection_path = self.root / 'selection.json'
        selection_path.write_text(json.dumps({'entries': self.selection()}))
        self.assertEqual(api.audit(self.root)['entries'][self.relative]['action'], 'keep')
        manifest = api.quarantine(self.root, self.selection(), 'manual',
                                  selection_source=selection_path)
        self.assertFalse(self.cache.exists())
        self.assertEqual(json.loads(Path(manifest).read_text())['batch'], 'manual')

    def test_cli_restore_rejects_other_actions(self):
        self.module()
        result = subprocess.run(['python3', str(SCRIPT), '--root', str(self.root),
                                 '--restore', 'missing.json', '--batch', 'y'],
                                capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_rolled_back_batch_can_be_reopened_by_restore(self):
        api = self.module()
        self.write('src/other.py', 'OTHER = 1\n')
        self.git('add', 'src/other.py')
        self.git('commit', '-qm', 'other')
        py_compile.compile(str(self.root / 'src/other.py'), doraise=True)
        other = next((self.root / 'src/__pycache__').glob('other*.pyc'))
        real_move = shutil.move
        calls = []

        def flaky(source, destination):
            calls.append(str(destination))
            if len(calls) == 2:
                raise OSError('simulated move failure')
            return real_move(source, destination)

        with patch.object(api.shutil, 'move', side_effect=flaky):
            with self.assertRaises(ValueError):
                api.quarantine(self.root, api.audit(self.root)['quarantine_candidates'], 'reopen')
        manifest = self.root / 'runs/quarantine/reopen/manifest.json'
        api.restore(self.root, manifest)
        self.assertTrue(self.cache.exists())
        self.assertTrue(other.exists())

    def test_dangling_manifest_symlink_is_rejected(self):
        api = self.module()
        outside = Path(self.temp.name) / 'pwned.json'
        batch = self.root / 'runs/quarantine/batch-sym'
        batch.mkdir(parents=True)
        (batch / 'manifest.json').symlink_to(outside)
        with self.assertRaises(ValueError):
            api.quarantine(self.root, self.selection(), 'batch-sym')
        self.assertFalse(outside.exists())
        self.assertTrue(self.cache.exists())

    def test_audit_directory_symlink_is_rejected_before_any_move(self):
        self.module()
        outside = Path(self.temp.name) / 'audit-outside'
        outside.mkdir()
        (self.root / 'runs').mkdir()
        (self.root / 'runs/repository-audit').symlink_to(outside, target_is_directory=True)
        selection = self.root / 'sel-audit.json'
        subprocess.run(['python3', str(SCRIPT), '--root', str(self.root),
                        '--quarantine-list', str(selection)], check=True, capture_output=True)
        result = subprocess.run(['python3', str(SCRIPT), '--root', str(self.root),
                                 '--apply', str(selection), '--batch', 'nope'],
                                capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertTrue(self.cache.exists())

    def test_restore_reconciles_a_crash_between_move_and_manifest(self):
        api = self.module()
        manifest = api.quarantine(self.root, self.selection(), 'crash-window')
        document = json.loads(manifest.read_text())
        shutil.move(str(self.root / document['entries'][0]['stored_path']), str(self.cache))
        api.restore(self.root, manifest)
        self.assertTrue(self.cache.exists())
        self.assertEqual(json.loads(manifest.read_text())['entries'][0]['status'], 'restored')

    def test_rollback_failed_entries_remain_recoverable(self):
        api = self.module()
        manifest = api.quarantine(self.root, self.selection(), 'stuck')
        document = json.loads(manifest.read_text())
        document['entries'][0]['status'] = 'rollback-failed'
        manifest.write_text(json.dumps(document))
        api.restore(self.root, manifest)
        self.assertTrue(self.cache.exists())
        self.assertEqual(json.loads(manifest.read_text())['entries'][0]['status'], 'restored')

    def test_manifest_write_is_atomic(self):
        api = self.module()
        manifest = api.quarantine(self.root, self.selection(), 'atomic')
        before = manifest.read_text()
        with patch.object(api.os, 'replace', side_effect=OSError('simulated rename failure')):
            with self.assertRaises(ValueError):
                api.restore(self.root, manifest)
        self.assertEqual(manifest.read_text(), before)
        self.assertFalse((manifest.parent / (manifest.name + '.tmp')).exists())
        api.restore(self.root, manifest)
        self.assertTrue(self.cache.exists())

    def test_legal_json_cannot_crash_the_audit(self):
        api = self.module()
        self.write('weird.json', json.dumps({'schema_version': ['repository_audit.v1'],
                                             'note': self.relative}))
        self.write('nested.json', '[' * 4000 + self.relative + ']' * 4000)
        report = api.audit(self.root)
        self.assertEqual(report['entries'][self.relative]['action'], 'keep')

    def test_references_without_a_known_extension_are_detected(self):
        api = self.module()
        self.write('Makefile', 'PYC := ' + self.relative + '\n')
        self.write('types.pyi', '# see ' + self.relative + '\n')
        self.write('.gitignore', '__pycache__/\n/runs/\n# ' + self.relative + '\n')
        self.assertEqual(api.audit(self.root)['entries'][self.relative]['action'], 'keep')

    def test_large_text_references_are_detected(self):
        api = self.module()
        self.write('big.txt', 'x' * (5 * 1024 * 1024) + '\n' + self.relative + '\n')
        self.assertEqual(api.audit(self.root)['entries'][self.relative]['action'], 'keep')

    def test_bare_cache_directory_mention_does_not_pin_candidates(self):
        api = self.module()
        self.write('cleanup.sh', 'rm -rf __pycache__\n')
        self.assertEqual(api.audit(self.root)['entries'][self.relative]['action'], 'eligible')

    def test_failed_apply_does_not_burn_the_batch_name(self):
        self.module()
        selection = self.root / 'sel-batch.json'
        subprocess.run(['python3', str(SCRIPT), '--root', str(self.root),
                        '--quarantine-list', str(selection)], check=True, capture_output=True)
        document = json.loads(selection.read_text())
        document['entries'][0]['sha256'] = '0' * 64
        selection.write_text(json.dumps(document))
        failed = subprocess.run(['python3', str(SCRIPT), '--root', str(self.root),
                                 '--apply', str(selection), '--batch', 'reused'],
                                capture_output=True)
        self.assertNotEqual(failed.returncode, 0)
        self.assertFalse((self.root / 'runs/repository-audit/reused/inventory.json').exists())
        document['entries'][0]['sha256'] = hashlib.sha256(self.cache.read_bytes()).hexdigest()
        selection.write_text(json.dumps(document))
        retried = subprocess.run(['python3', str(SCRIPT), '--root', str(self.root),
                                  '--apply', str(selection), '--batch', 'reused'],
                                 capture_output=True, text=True)
        self.assertEqual(retried.returncode, 0, retried.stdout + retried.stderr)
        self.assertTrue((self.root / 'runs/repository-audit/reused/inventory.json').exists())

    def test_output_is_written_alongside_apply(self):
        self.module()
        selection = self.root / 'sel-output.json'
        subprocess.run(['python3', str(SCRIPT), '--root', str(self.root),
                        '--quarantine-list', str(selection)], check=True, capture_output=True)
        output = self.root / 'audit-out.json'
        result = subprocess.run(['python3', str(SCRIPT), '--root', str(self.root),
                                 '--apply', str(selection), '--batch', 'with-output',
                                 '--output', str(output)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(output.exists())
        self.assertEqual(json.loads(output.read_text())['schema_version'],
                         'repository_audit.v1')

    def test_batch_name_is_validated_before_any_path_is_built(self):
        self.module()
        selection = self.root / 'sel-escape.json'
        subprocess.run(['python3', str(SCRIPT), '--root', str(self.root),
                        '--quarantine-list', str(selection)], check=True, capture_output=True)
        result = subprocess.run(['python3', str(SCRIPT), '--root', str(self.root),
                                 '--apply', str(selection), '--batch', '../../../evil'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('invalid-batch-name', result.stdout)
        self.assertFalse((Path(self.temp.name) / 'evil').exists())
        self.assertFalse((Path(self.temp.name) / 'evil' / 'inventory.json').exists())
        self.assertTrue(self.cache.exists())

    def test_restore_refuses_to_call_foreign_destination_bytes_restored(self):
        api = self.module()
        manifest = api.quarantine(self.root, self.selection(), 'foreign')
        document = json.loads(manifest.read_text())
        (self.root / document['entries'][0]['stored_path']).unlink()
        self.cache.write_bytes(b'foreign bytes')
        with self.assertRaises(ValueError):
            api.restore(self.root, manifest)
        self.assertEqual(self.cache.read_bytes(), b'foreign bytes')
        self.assertEqual(json.loads(manifest.read_text())['entries'][0]['status'], 'moved')

    def test_directory_references_with_trailing_slash_or_dot_slash_are_detected(self):
        for content in ('rm -rf src/__pycache__/\n', 'rm -rf ./src/__pycache__\n'):
            with self.subTest(content=content):
                api = self.module()
                self.write('cleanup.sh', content)
                self.assertEqual(api.audit(self.root)['entries'][self.relative]['action'],
                                 'keep')
                (self.root / 'cleanup.sh').unlink()

    def test_quarantine_wraps_a_failing_manifest_write(self):
        api = self.module()
        with patch.object(api.os, 'replace', side_effect=OSError('simulated rename failure')):
            with self.assertRaises(ValueError) as caught:
                api.quarantine(self.root, self.selection(), 'writefail')
        self.assertIn('quarantine-failed', str(caught.exception))
        self.assertTrue(self.cache.exists())

    def test_user_output_paths_reject_symlinks_and_tool_state(self):
        self.module()
        manifest = self.root / 'runs/quarantine/protect/manifest.json'
        manifest.parent.mkdir(parents=True)
        manifest.write_text('{"schema_version": "repository_quarantine.v1", "entries": []}')
        protected = subprocess.run(['python3', str(SCRIPT), '--root', str(self.root),
                                    '--output', str(manifest)], capture_output=True, text=True)
        self.assertNotEqual(protected.returncode, 0)
        self.assertIn('output-path-inside-tool-state', protected.stdout)
        self.assertEqual(json.loads(manifest.read_text())['schema_version'],
                         'repository_quarantine.v1')
        outside = Path(self.temp.name) / 'linked.json'
        link = self.root / 'link-out.json'
        link.symlink_to(outside)
        linked = subprocess.run(['python3', str(SCRIPT), '--root', str(self.root),
                                 '--quarantine-list', str(link)], capture_output=True, text=True)
        self.assertNotEqual(linked.returncode, 0)
        self.assertFalse(outside.exists())

    def test_restore_rejects_malformed_manifests_without_a_traceback(self):
        self.module()
        for payload in ('[]', 'null', '123', '"hello"', 'not json at all'):
            with self.subTest(payload=payload):
                manifest = self.root / 'broken.json'
                manifest.write_text(payload)
                result = subprocess.run(['python3', str(SCRIPT), '--root', str(self.root),
                                         '--restore', str(manifest)],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('Traceback', result.stderr)
                self.assertTrue(result.stdout.strip().startswith('{'))

    def test_unreadable_selection_is_reported_not_traced(self):
        self.module()
        selection = self.root / 'binary-selection.json'
        selection.write_bytes(b'\xff\xfe\x00\x01 not utf-8')
        result = subprocess.run(['python3', str(SCRIPT), '--root', str(self.root),
                                 '--apply', str(selection), '--batch', 'binary'],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('Traceback', result.stderr)
        self.assertIn('unreadable-selection', result.stdout)

    def test_giant_integer_json_cannot_crash_the_audit(self):
        api = self.module()
        self.write('huge.json', '{"n": ' + '9' * 5000 + ', "note": "' + self.relative + '"}')
        self.assertEqual(api.audit(self.root)['entries'][self.relative]['action'], 'keep')

    def test_own_artifact_is_recognised_from_its_head_alone(self):
        api = self.module()
        self.write('runs/repository-audit/big/inventory.json',
                   '{"schema_version": "repository_audit.v1", "entries": ['
                   + '0' * 20000 + ' this is not valid json')
        self.assertEqual(api.audit(self.root)['entries'][self.relative]['action'], 'eligible')

    def test_bookkeeping_failure_after_a_completed_move_is_a_warning(self):
        api = self.module()
        selection = self.root / 'sel-warning.json'
        selection.write_text(json.dumps({'entries': self.selection()}))
        with patch.object(api, '_write_new', side_effect=api.AuditError('disk full')):
            code = api.main(['--root', str(self.root), '--apply', str(selection),
                             '--batch', 'warned'])
        self.assertEqual(code, 0)
        self.assertTrue((self.root / 'runs/quarantine/warned/manifest.json').exists())

