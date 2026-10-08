"""Contract tests for the documentation cross-reference checker.

The checker is a zero-dependency stdlib tool (``scripts/check_doc_links.py``)
that validates relative Markdown links and heading anchors across the
repository documents, so that reports, plans and progress entry points never
silently lose a cross reference.

These tests build tiny throwaway repositories under ``tmp_path`` and pin the
exact JSON report shape, the broken-entry shape, the skip rules and the CLI
exit codes.  One smoke test runs the checker over the real repository root to
prove it terminates quickly and still emits a structured report; it does not
assert that the real repository has zero broken links.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / 'scripts/check_doc_links.py'
SCHEMA_VERSION = 'doc_link_check.v1'
REPORT_FIELDS = {
    'schema_version',
    'files_scanned',
    'links_checked',
    'broken',
    'skipped_schemes',
    'rules_version',
}
BROKEN_FIELDS = {'file', 'line', 'target', 'reason'}


def load_module():
    if not SCRIPT.exists():
        raise AssertionError(f'documentation link checker is not implemented: {SCRIPT}')
    spec = importlib.util.spec_from_file_location('check_doc_links', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DocLinkCheckTests(unittest.TestCase):
    """Behaviour of the checker on synthetic repositories."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'repo'
        self.root.mkdir()

    # -- fixture helpers ---------------------------------------------------
    def write(self, relative, content):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding='utf-8')
        return target

    def check(self, **kwargs):
        return load_module().check_repository(self.root, **kwargs)

    def cli(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), '--root', str(self.root), *args],
            capture_output=True, text=True, timeout=120,
        )

    def broken(self, report):
        return report['broken']

    # -- report shape ------------------------------------------------------
    def test_report_shape_and_valid_links(self):
        self.write('docs/index.md', (
            '# Index\n'
            '\n'
            '[Peer](peer.md)\n'
            '[Subdirectory](sub)\n'
            '[External](https://example.com/spec)\n'
            '[Mail](mailto:someone@example.com)\n'
            '[Self](#index)\n'
            '[Spaced](<with space.md>)\n'
        ))
        self.write('docs/peer.md', '# Peer\n')
        self.write('docs/with space.md', '# Spaced\n')
        (self.root / 'docs/sub').mkdir()

        report = self.check()

        self.assertEqual(set(report), REPORT_FIELDS)
        self.assertEqual(report['schema_version'], SCHEMA_VERSION)
        self.assertIsInstance(report['rules_version'], str)
        self.assertTrue(report['rules_version'])
        self.assertEqual(report['files_scanned'], 3)
        # three relative targets are checked; external URLs and the pure
        # anchor are skipped
        self.assertEqual(report['links_checked'], 3)
        self.assertEqual(report['broken'], [])
        self.assertEqual(report['skipped_schemes'], {'https': 1, 'mailto': 1})
        self.assertIsInstance(report['broken'], list)
        self.assertIsInstance(report['skipped_schemes'], dict)

    def test_broken_relative_link_reports_file_line_target_reason(self):
        self.write('docs/index.md', '# Index\n\nSee [gone](missing.md).\n')

        report = self.check()

        self.assertEqual(report['links_checked'], 1)
        self.assertEqual(report['broken'], [
            {'file': 'docs/index.md', 'line': 3, 'target': 'missing.md', 'reason': 'missing_file'},
        ])
        self.assertEqual(set(report['broken'][0]), BROKEN_FIELDS)

    def test_broken_entries_are_sorted_and_complete(self):
        self.write('docs/a.md', (
            '# A\n'
            '[one](../nowhere.md)\n'
            '[two](also-missing.md)\n'
        ))
        self.write('README.md', '[three](docs/gone.md)\n')

        report = self.check()

        self.assertEqual(report['broken'], [
            {'file': 'README.md', 'line': 1, 'target': 'docs/gone.md', 'reason': 'missing_file'},
            {'file': 'docs/a.md', 'line': 2, 'target': '../nowhere.md', 'reason': 'missing_file'},
            {'file': 'docs/a.md', 'line': 3, 'target': 'also-missing.md', 'reason': 'missing_file'},
        ])

    def test_directory_link_exists_and_missing_directory_is_broken(self):
        (self.root / 'docs/sub').mkdir(parents=True)
        self.write('docs/index.md', '[ok](sub)\n[ok-slash](sub/)\n[bad](absent-dir/)\n')

        report = self.check()

        self.assertEqual(report['broken'], [
            {'file': 'docs/index.md', 'line': 3, 'target': 'absent-dir/', 'reason': 'missing_file'},
        ])

    # -- skipping rules ----------------------------------------------------
    def test_external_schemes_and_data_uri_are_skipped(self):
        self.write('docs/index.md', (
            '[a](http://example.com/a)\n'
            '[b](https://example.com/b)\n'
            '[c](mailto:dev@example.com)\n'
            '[d](data:text/plain;base64,QUJD)\n'
        ))

        report = self.check()

        self.assertEqual(report['links_checked'], 0)
        self.assertEqual(report['broken'], [])
        self.assertEqual(
            report['skipped_schemes'],
            {'data': 1, 'http': 1, 'https': 1, 'mailto': 1},
        )

    def test_pure_anchor_is_skipped_even_when_heading_is_absent(self):
        # Pure anchors are in the skip list; an explicit self reference to the
        # same anchor is still validated.
        self.write('docs/index.md', (
            '# Index\n'
            '\n'
            '[nowhere](#no-such-heading)\n'
            '[still-nowhere](index.md#no-such-heading)\n'
        ))

        report = self.check()

        self.assertEqual(report['links_checked'], 1)
        self.assertEqual(report['broken'], [
            {'file': 'docs/index.md', 'line': 4, 'target': 'index.md#no-such-heading',
             'reason': 'missing_anchor'},
        ])

    # -- anchors -----------------------------------------------------------
    def test_same_file_anchor_is_checked(self):
        self.write('docs/index.md', (
            '# Index\n'
            '\n'
            '## Section One\n'
            '\n'
            '[good](index.md#section-one)\n'
            '[bad](index.md#section-two)\n'
        ))

        report = self.check()

        self.assertEqual(report['links_checked'], 2)
        self.assertEqual(report['broken'], [
            {'file': 'docs/index.md', 'line': 6, 'target': 'index.md#section-two',
             'reason': 'missing_anchor'},
        ])

    def test_cross_file_anchor_is_checked(self):
        self.write('docs/index.md', (
            '[good](peer.md#peer-section)\n'
            '[bad](peer.md#peer-sections)\n'
            '[missing](absent.md#peer-section)\n'
        ))
        self.write('docs/peer.md', '# Peer\n\n## Peer Section\n')

        report = self.check()

        self.assertEqual(report['broken'], [
            {'file': 'docs/index.md', 'line': 2, 'target': 'peer.md#peer-sections', 'reason': 'missing_anchor'},
            {'file': 'docs/index.md', 'line': 3, 'target': 'absent.md#peer-section', 'reason': 'missing_file'},
        ])

    def test_anchor_on_non_markdown_target_is_not_slug_checked(self):
        self.write('docs/index.md', '[code](../scripts/tool.py#L10)\n')
        self.write('scripts/tool.py', 'print(1)\n')

        report = self.check()

        self.assertEqual(report['broken'], [])
        self.assertEqual(report['links_checked'], 1)

    def test_chinese_heading_anchor(self):
        heading = 'UART 生产者列表释放：独立快照与内存实测'
        self.write('docs/index.md',
                   f'## {heading}\n\n[go](index.md#uart-生产者列表释放独立快照与内存实测)\n')
        self.write('docs/peer.md', f'# P\n\n## {heading}\n')
        self.write('README.md', '[x](docs/peer.md#uart-生产者列表释放独立快照与内存实测)\n')

        report = self.check()

        self.assertEqual(report['broken'], [])
        self.assertEqual(report['links_checked'], 2)

    def test_slugify_rules(self):
        slugify = load_module().slugify

        self.assertEqual(slugify('Hello, World!'), 'hello-world')
        self.assertEqual(slugify('1.2 系统时序接口'), '12-系统时序接口')
        self.assertEqual(slugify('A_B-c'), 'a_b-c')
        self.assertEqual(slugify('  Spaced Out  '), 'spaced-out')
        # GitHub replaces every space with one hyphen, runs included
        self.assertEqual(slugify('A  B'), 'a--b')
        self.assertEqual(slugify('RISC-V “quoted” (draft)'), 'risc-v-quoted-draft')
        self.assertEqual(slugify('中文标题：测试'), '中文标题测试')

    def test_duplicate_headings_get_numeric_suffixes(self):
        self.write('docs/index.md', (
            '# Dup\n'
            '\n'
            '## Dup\n'
            '## Dup\n'
            '\n'
            '[first](#dup)\n'
            '[second](#dup-1)\n'
            '[third](#dup-2)\n'
        ))

        module = load_module()
        self.assertEqual(module.heading_slugs('# Dup\n\n## Dup\n## Dup\n'), ['dup', 'dup-1', 'dup-2'])

        report = self.check()
        self.assertEqual(report['broken'], [])

    def test_heading_inline_markup_is_slugified_as_rendered_text(self):
        self.write('docs/index.md', '## The `foo` *bar* [baz](peer.md)\n\n[go](#the-foo-bar-baz)\n')
        self.write('docs/peer.md', '# Peer\n')

        report = self.check()

        self.assertEqual(report['broken'], [])

    def test_headings_inside_fenced_code_do_not_create_anchors(self):
        self.write('docs/index.md', (
            '# Index\n'
            '\n'
            '```text\n'
            '## Not A Heading\n'
            '```\n'
            '\n'
            '[go](index.md#not-a-heading)\n'
        ))

        report = self.check()

        self.assertEqual(report['broken'], [
            {'file': 'docs/index.md', 'line': 7, 'target': 'index.md#not-a-heading',
             'reason': 'missing_anchor'},
        ])

    # -- code spans and fenced blocks --------------------------------------
    def test_link_inside_inline_code_span_is_not_a_link(self):
        self.write('docs/index.md', '# Index\n\nRun `[fake](missing.md)` here.\n')

        default = self.check()
        self.assertEqual(default['links_checked'], 0)
        self.assertEqual(default['broken'], [])

        allowed = self.check(allow_code_spans=True)
        self.assertEqual(allowed['links_checked'], 1)
        self.assertEqual(allowed['broken'], [
            {'file': 'docs/index.md', 'line': 3, 'target': 'missing.md', 'reason': 'missing_file'},
        ])

    def test_link_inside_fenced_code_block_is_not_a_link(self):
        self.write('docs/index.md', (
            '# Index\n'
            '\n'
            '```markdown\n'
            '[fake](missing.md)\n'
            '```\n'
            '\n'
            '~~~\n'
            '[other](also-missing.md)\n'
            '~~~\n'
        ))

        default = self.check()
        self.assertEqual(default['links_checked'], 0)
        self.assertEqual(default['broken'], [])

        allowed = self.check(allow_code_spans=True)
        self.assertEqual(allowed['links_checked'], 2)
        self.assertEqual([item['target'] for item in allowed['broken']],
                         ['missing.md', 'also-missing.md'])

    def test_lone_backtick_does_not_swallow_following_links(self):
        self.write('docs/index.md', '# Index\n\na ` tick and [real](peer.md)\n')
        self.write('docs/peer.md', '# Peer\n')

        report = self.check()

        self.assertEqual(report['links_checked'], 1)
        self.assertEqual(report['broken'], [])

    def test_image_targets_are_checked_as_file_references(self):
        self.write('docs/index.md', '![diagram](assets/diagram.png)\n![gone](assets/missing.png)\n')
        (self.root / 'docs/assets').mkdir(parents=True)
        self.write('docs/assets/diagram.png', 'png\n')

        report = self.check()

        self.assertEqual(report['links_checked'], 2)
        self.assertEqual(report['broken'], [
            {'file': 'docs/index.md', 'line': 2, 'target': 'assets/missing.png',
             'reason': 'missing_file'},
        ])

    # -- reference style ---------------------------------------------------
    def test_reference_style_definitions_are_checked(self):
        self.write('docs/index.md', (
            '# Index\n'
            '\n'
            '[good][peer] and [bad][gone]\n'
            '\n'
            '[peer]: peer.md\n'
            '[gone]: missing.md "title"\n'
        ))
        self.write('docs/peer.md', '# Peer\n')

        report = self.check()

        self.assertEqual(report['links_checked'], 2)
        self.assertEqual(report['broken'], [
            {'file': 'docs/index.md', 'line': 6, 'target': 'missing.md', 'reason': 'missing_file'},
        ])

    def test_reference_definition_inside_fenced_block_is_ignored(self):
        self.write('docs/index.md', (
            '# Index\n'
            '\n'
            '```\n'
            '[gone]: missing.md\n'
            '```\n'
        ))

        report = self.check()

        self.assertEqual(report['links_checked'], 0)
        self.assertEqual(report['broken'], [])

    # -- target spellings --------------------------------------------------
    def test_percent_encoded_target_and_anchor(self):
        self.write('docs/with space.md', '# Spaced Target\n\n## 中文 标题\n')
        self.write('docs/index.md', (
            '[file](with%20space.md)\n'
            '[anchor](with%20space.md#%E4%B8%AD%E6%96%87-%E6%A0%87%E9%A2%98)\n'
            '[broken-anchor](with%20space.md#nope)\n'
        ))

        report = self.check()

        self.assertEqual(report['links_checked'], 3)
        self.assertEqual(report['broken'], [
            {'file': 'docs/index.md', 'line': 3, 'target': 'with%20space.md#nope',
             'reason': 'missing_anchor'},
        ])

    def test_angle_bracket_target_with_title_is_parsed(self):
        self.write('docs/with space.md', '# Spaced Target\n')
        self.write('docs/index.md', '[ok](<with space.md> "the title")\n[bad](<gone file.md> "x")\n')

        report = self.check()

        self.assertEqual(report['links_checked'], 2)
        self.assertEqual(report['broken'], [
            {'file': 'docs/index.md', 'line': 2, 'target': '<gone file.md>', 'reason': 'missing_file'},
        ])

    def test_setext_heading_anchor(self):
        self.write('docs/index.md', 'Setext Title\n============\n\n[go](index.md#setext-title)\n')

        self.assertEqual(load_module().heading_slugs('Setext Title\n============\n'),
                         ['setext-title'])
        report = self.check()
        self.assertEqual(report['broken'], [])
        self.assertEqual(report['links_checked'], 1)

    # -- scope and pruning -------------------------------------------------
    def test_only_scoped_documents_are_scanned(self):
        self.write('README.md', '[ok](docs/peer.md)\n')
        self.write('QUICKSTART.md', '# Quick\n')
        self.write('agent.md', '# Agent\n')
        self.write('docs/peer.md', '# Peer\n')
        self.write('docs/superpowers/plans/plan.md', '# Plan\n')
        self.write('.superpowers/sdd/report.md', '# Report\n')
        # out of scope
        self.write('notes.md', '[bad](missing.md)\n')
        self.write('third_party/vendor.md', '[bad](missing.md)\n')
        self.write('archive/old.md', '[bad](missing.md)\n')
        self.write('runs/session/run.md', '[bad](missing.md)\n')
        self.write('.git/objects.md', '[bad](missing.md)\n')

        report = self.check()

        self.assertEqual(report['files_scanned'], 6)
        self.assertEqual(report['broken'], [])

    def test_include_runs_scans_run_reports(self):
        self.write('runs/session/run.md', '[bad](missing.md)\n')

        default = self.check()
        self.assertEqual(default['files_scanned'], 0)

        included = self.check(include_runs=True)
        self.assertEqual(included['files_scanned'], 1)
        self.assertEqual(included['broken'], [
            {'file': 'runs/session/run.md', 'line': 1, 'target': 'missing.md', 'reason': 'missing_file'},
        ])

    # -- CLI ---------------------------------------------------------------
    def test_cli_exit_zero_when_clean_and_one_when_broken(self):
        self.write('README.md', '[ok](QUICKSTART.md)\n')
        self.write('QUICKSTART.md', '# Quick\n')

        clean = self.cli()
        self.assertEqual(clean.returncode, 0, clean.stderr)
        self.assertIn('broken', clean.stdout.lower())

        self.write('README.md', '[bad](missing.md)\n')
        broken = self.cli()
        self.assertEqual(broken.returncode, 1, broken.stderr)
        self.assertIn('missing.md', broken.stdout)

    def test_cli_json_out_writes_the_report(self):
        self.write('README.md', '[bad](missing.md)\n')
        out = Path(self.temp.name) / 'report.json'

        result = self.cli('--json-out', str(out))

        self.assertEqual(result.returncode, 1)
        document = json.loads(out.read_text(encoding='utf-8'))
        self.assertEqual(set(document), REPORT_FIELDS)
        self.assertEqual(document['schema_version'], SCHEMA_VERSION)
        self.assertEqual(document['broken'], [
            {'file': 'README.md', 'line': 1, 'target': 'missing.md', 'reason': 'missing_file'},
        ])

    def test_cli_include_runs_and_allow_code_spans_flags(self):
        self.write('runs/session/run.md', '# Run\n\n`![x](missing.md)`\n')

        default = self.cli()
        self.assertEqual(default.returncode, 0)

        included = self.cli('--include-runs')
        self.assertEqual(included.returncode, 0)

        flagged = self.cli('--include-runs', '--allow-code-spans')
        self.assertEqual(flagged.returncode, 1, flagged.stderr)
        self.assertIn('missing.md', flagged.stdout)


class RealRepositorySmokeTests(unittest.TestCase):
    """The checker must survive the real repository within a few seconds."""

    def test_real_repository_smoke(self):
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / 'doc_link_report.json'
            started = time.monotonic()
            result = subprocess.run(
                [sys.executable, str(SCRIPT), '--root', str(REPO_ROOT), '--json-out', str(out)],
                capture_output=True, text=True, timeout=180,
            )
            elapsed = time.monotonic() - started
            document = json.loads(out.read_text(encoding='utf-8'))

        self.assertIn(result.returncode, (0, 1), result.stderr)
        self.assertLess(elapsed, 60.0, f'repository scan took {elapsed:.1f}s')
        self.assertIn('doc_link_check.v1', result.stdout)
        self.assertEqual(set(document), REPORT_FIELDS)
        self.assertEqual(document['schema_version'], SCHEMA_VERSION)
        self.assertGreater(document['files_scanned'], 300)
        self.assertGreater(document['links_checked'], 50)
        for item in document['broken']:
            self.assertEqual(set(item), BROKEN_FIELDS)
            self.assertTrue(item['reason'])

        print(json.dumps({
            'elapsed_seconds': round(elapsed, 2),
            'files_scanned': document['files_scanned'],
            'links_checked': document['links_checked'],
            'skipped_schemes': document['skipped_schemes'],
            'broken': document['broken'],
        }, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    unittest.main()
