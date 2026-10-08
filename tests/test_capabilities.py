"""Capabilities expose documented evidence without promoting source availability."""
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]


class CapabilityTests(unittest.TestCase):
    def test_authoritative_table_keeps_every_row_and_original_cells(self):
        from myfuzz.capabilities import query_capabilities
        result = query_capabilities()
        content = (ROOT / 'docs/LOCAL_HARNESS_RUNTIME.md').read_bytes()
        lines = content.decode('utf-8').splitlines()
        table = lines[lines.index('| 组件/协议 | 当前证据 | 等级 |') + 2:]
        expected = []
        for line in table:
            if not line.startswith('|'):
                break
            expected.append([field.strip() for field in line[1:-1].split('|')])
        self.assertEqual(expected, [[row['component'], row['evidence'], row['level']]
                                    for row in result['capabilities']])
        self.assertEqual(hashlib.sha256(content).hexdigest(), result['source']['sha256'])
        self.assertEqual('documented_evidence', result['basis'])
        self.assertFalse(result['runtime_revalidated'])
        for row in result['capabilities']:
            self.assertEqual(lines[row['source_line'] - 1], row['source_text'])
        self.assertTrue(result['limitations'])
        self.assertTrue(any('尚未满足的验收' == section['title']
                            for section in result['limitations']))
        linked = next(row for row in result['capabilities']
                      if row['component'] == 'CVA6 ↔ OpenTitan GPIO M_EXT')
        self.assertIn('docs/reports/generated-cva6-opentitan-gpio-mext-irq-20261005.md',
                      linked['evidence_paths'])

    def test_filter_retains_unverified_source_lock_and_fixed_limits(self):
        from myfuzz.capabilities import query_capabilities
        result = query_capabilities(match='RVX')
        self.assertEqual(1, len(result['capabilities']))
        self.assertIn('runtime_status=runtime_unverified', result['capabilities'][0]['level'])
        self.assertIn('未接 IP、IRQ 或 RVX bus', result['capabilities'][0]['level'])
        self.assertEqual([], query_capabilities(match='unsupported-dma-automatic')['capabilities'])
        self.assertEqual(query_capabilities(match='uart'), query_capabilities(match='UART'))
        self.assertEqual(query_capabilities()['limitations'], result['limitations'])

    def test_malformed_table_is_rejected(self):
        from myfuzz.capabilities import parse_capabilities_document
        valid = '## 当前可运行路径\n\n| 组件/协议 | 当前证据 | 等级 |\n|---|---|---|\n| A | fixed | unverified |\n'
        for malformed in (valid.replace('| A | fixed | unverified |', '| A | fixed |'),
                          valid.replace('|---|---|---|', '|---|---|'),
                          valid.replace('组件/协议', 'Capability'),
                          valid.replace('| A | fixed | unverified |', ''),
                          valid.replace('| A | fixed | unverified |', 'A | fixed | unverified |')):
            with self.subTest(malformed=malformed), self.assertRaises(ValueError):
                parse_capabilities_document(malformed)

    def test_script_and_module_parity_without_runtime_imports(self):
        from myfuzz.__main__ import main
        from scripts.query_capabilities import main as script_main
        for args in ([], ['--match', 'RvX'], ['--match', 'nonexistent']):
            outputs = []
            for entry, argv in ((main, ['capabilities', *args]), (script_main, args)):
                captured = io.StringIO()
                with redirect_stdout(captured):
                    self.assertEqual(0, entry(argv))
                outputs.append(json.loads(captured.getvalue()))
            self.assertEqual(outputs[0], outputs[1])
        code = "from myfuzz.__main__ import main; main(['capabilities', '--match', 'RVX']); import sys; assert not any(k.startswith(('myfuzz.integration', 'myfuzz.local_harness', 'myfuzz.scenario')) for k in sys.modules)"
        run = subprocess.run([sys.executable, '-c', code], cwd=ROOT, capture_output=True,
                             text=True)
        self.assertEqual(0, run.returncode, run.stderr)


if __name__ == '__main__':
    unittest.main()
