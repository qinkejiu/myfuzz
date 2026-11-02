"""Exercise generated timing code with a tiny fake model, not an RTL build."""
import ast
import json
import os
from pathlib import Path
import subprocess


def test_opt_in_eval_timing_keeps_model_calls_and_separate_phases(tmp_path):
    source = Path('src/myfuzz/local_harness/driver_renderer.py').read_text()
    module = ast.parse(source)
    template = next(n.value for n in ast.walk(module) if isinstance(n, ast.Constant)
                    and isinstance(n.value, str) and 'MYFUZZ_DUT_TIMING_DIR' in n.value)
    generated = template.replace('dut.eval();', 'eval_dut(dut);')
    generated = generated.replace('{ eval_dut(dut); return; }', '{ dut.eval(); return; }')
    generated = generated.replace('const auto started = std::chrono::steady_clock::now();\n  eval_dut(dut);',
                                  'const auto started = std::chrono::steady_clock::now();\n  dut.eval();')
    helper = generated[generated.index('static const char *dut_timing_dir'):generated.index('static std::uint64_t local_ticks')]
    helper = helper.replace('@KIND@', 'test_kind').replace('@MODULE@', 'test_module')
    code = '''#include <chrono>\n#include <cstdlib>\n#include <fstream>\n#include <string>\n#include <cstdint>\n#include <unistd.h>\nstruct Model { int calls=0; void eval() { ++calls; } };\n'''+helper+'''
int main() { Model dut; eval_dut(dut); dut_timing_startup=false; eval_dut(dut); eval_dut(dut); write_dut_timing(); return dut.calls == 3 ? 0 : 1; }
'''
    cpp = tmp_path/'test.cpp'; cpp.write_text(code)
    binary = tmp_path/'test'
    subprocess.run(['c++', '-std=c++17', str(cpp), '-o', str(binary)], check=True)
    subprocess.run([str(binary)], check=True, env={k:v for k,v in os.environ.items() if k != 'MYFUZZ_DUT_TIMING_DIR'})
    assert not list(tmp_path.glob('dut-timing-*.json'))
    subprocess.run([str(binary)], check=True, env={**os.environ, 'MYFUZZ_DUT_TIMING_DIR':str(tmp_path)})
    row = json.loads(next(tmp_path.glob('dut-timing-*.json')).read_text())
    assert (row['kind'], row['module']) == ('test_kind', 'test_module')
    assert (row['startup_eval_count'], row['runtime_eval_count']) == (1, 2)
    assert row['startup_eval_ns'] >= 0 and row['runtime_eval_ns'] >= 0
