"""Optional Verilator scheduling contracts; no DUT executable is built/run."""
from types import SimpleNamespace
import pytest


def profile(mode=None):
    return SimpleNamespace(capabilities={} if mode is None else {'verilator_timing_mode': mode})


def test_build_flags_require_explicit_timing_and_preserve_old_modes():
    from myfuzz.local_harness.build import _verilator_timing_flags, LocalHarnessBuildError
    assert _verilator_timing_flags(profile()) == ()
    assert _verilator_timing_flags(profile('no_timing')) == ('--no-timing',)
    assert _verilator_timing_flags(profile('timing')) == ('--timing', '--timescale', '1ns/1ps')
    with pytest.raises(LocalHarnessBuildError): _verilator_timing_flags(profile(True))


@pytest.mark.parametrize('hz,half_ps', [(50_000_000, 10_000), (25_000_000, 20_000)])
def test_timed_half_period_is_derived_from_actual_declared_clock(hz, half_ps):
    from myfuzz.local_harness.driver_renderer import _timed_clock_contract
    contract = _timed_clock_contract(profile('timing'), {'fast_frequency_hz': hz})
    assert contract['half_period_ps'] == half_ps
    assert contract['fast_frequency_hz'] == hz
    assert contract['timeprecision'] == '1ps'


def test_nonintegral_ps_clock_and_unknown_mode_refuse_instead_of_rounding():
    from myfuzz.local_harness.driver_renderer import _timed_clock_contract
    assert _timed_clock_contract(profile(), {}) is None
    assert _timed_clock_contract(profile('no_timing'), {}) is None
    with pytest.raises(ValueError): _timed_clock_contract(profile('timing'), {'fast_frequency_hz': 333_333_333})
    with pytest.raises(ValueError): _timed_clock_contract(profile('automatic'), {'fast_frequency_hz': 50_000_000})


def test_generated_scheduler_drains_same_time_and_boundary_events_without_future_jump(tmp_path):
    import shutil
    import subprocess
    from myfuzz.local_harness.driver_renderer import _timed_driver_cpp, _timed_clock_contract
    compiler = shutil.which('c++')
    if compiler is None: pytest.skip('C++ compiler unavailable for software-only mock')
    contract = _timed_clock_contract(profile('timing'), {'fast_frequency_hz': 50_000_000})
    mock = r'''
#include <cstdint>
#include <vector>
#include <cassert>
struct Context {
  std::uint64_t now = 0;
  int precision = -12;
  std::uint64_t time() const { return now; }
  void timeInc(std::uint64_t delta) { now += delta; }
  int timeprecision() const { return precision; }
};
struct Model {
  Context context;
  std::vector<std::uint64_t> slots{0, 0, 10, 1000, 10000, 10000, 20000};
  std::vector<std::uint64_t> calls;
  unsigned cursor = 0;
  bool stuck = false;
  Context *contextp() { return &context; }
  bool eventsPending() { return cursor < slots.size(); }
  std::uint64_t nextTimeSlot() { return slots[cursor]; }
  void eval() {
    calls.push_back(context.now);
    if (eventsPending() && slots[cursor] == context.now && !stuck) ++cursor;
  }
};
static void eval_dut(Model &dut) { dut.eval(); }
'''
    main = r'''
int main() {
  Model model;
  timed_advance_to(model, 10000);
  assert(model.context.now == 10000 && model.nextTimeSlot() == 20000);
  assert((model.calls == std::vector<std::uint64_t>{0, 0, 10, 1000, 10000, 10000}));
  timed_advance_to(model, 15000);
  assert(model.context.now == 15000 && model.nextTimeSlot() == 20000 && model.calls.back() == 15000);
  timed_advance_to(model, 20000);
  assert(model.context.now == 20000 && !model.eventsPending());
  timed_advance_to(model, 25000);
  assert(model.context.now == 25000 && model.calls.back() == 25000);
  bool refused = false;
  try { timed_advance_to(model, 19999); } catch (const std::runtime_error &) { refused = true; }
  assert(refused);
  Model wrong_precision; wrong_precision.context.precision = -9; refused = false;
  try { timed_advance_to(wrong_precision, 10000); } catch (const std::runtime_error &) { refused = true; }
  assert(refused);
  Model stuck; stuck.stuck = true; refused = false;
  try { timed_advance_to(stuck, 10000); } catch (const std::runtime_error &) { refused = true; }
  assert(refused && stuck.calls.size() <= 65536 && stuck.context.now == 0);
}
'''
    source = tmp_path/'scheduler_mock.cpp'
    source.write_text(mock + _timed_driver_cpp(contract) + main)
    binary = tmp_path/'scheduler_mock'
    subprocess.run([compiler, '-std=c++17', str(source), '-o', str(binary)], check=True,
                   capture_output=True, text=True)
    subprocess.run([str(binary)], check=True, capture_output=True, text=True)


def test_actual_optin_profile_build_identity_and_driver_phase_order():
    from pathlib import Path
    from myfuzz.scenario.ibex_pulp_dual_source import _artifact
    from myfuzz.local_harness.build import local_build_identity, LocalHarnessBuildError
    from myfuzz.local_harness.renderer import _sha
    from dataclasses import replace
    from copy import deepcopy
    root = Path(__file__).resolve().parents[2]
    artifact = _artifact('configs/cpus/cv32e40p_rvfi_local/component_profile.json', 'timed_cpu')
    contract = artifact.runtime_document['driver_timing']
    assert contract['half_period_ps'] == 10000
    assert contract['startup_diagnostics'] == 'stderr_before_READY'
    assert artifact.cpp_text.index('TimedStartupDiagnostics startup_diagnostics;') < artifact.cpp_text.index('  Model dut;')
    assert artifact.cpp_text.index('startup_diagnostics.restore();') < artifact.cpp_text.index('std::cout << "READY local_driver.v1')
    identity = local_build_identity(artifact, base_dir=root)
    argv = identity['build_argv']
    assert '--timing' in argv and '--no-timing' not in argv
    assert argv[argv.index('--timescale')+1] == '1ns/1ps'
    tick = artifact.cpp_text.split('static void tick(Model &dut,', 1)[1].split('@AHB', 1)[0]
    pre = tick.index('const auto pre =')
    post = tick.index('const auto post =')
    assert tick.index('timed_advance_to(dut, timed_tick_begin + timed_half_period_ps);') < pre
    assert pre < tick.index('dut.clk = 1;') < tick.index('timed_advance_to(dut, timed_tick_begin + 2 * timed_half_period_ps);') < post
    assert post < tick.index('dut.clk = 0;', post)
    document = deepcopy(artifact.runtime_document)
    document['driver_timing']['half_period_ps'] += 1
    document['artifact_digest'] = _sha({k:v for k,v in document.items() if k != 'artifact_digest'})
    with pytest.raises(LocalHarnessBuildError, match='driver-timing-contract-mismatch'):
        local_build_identity(replace(artifact, runtime_document=document), base_dir=root)


def test_timed_startup_diagnostics_are_visible_on_stderr_before_wire_ready(tmp_path):
    import shutil
    import subprocess
    from myfuzz.local_harness.driver_renderer import _timed_driver_cpp, _timed_clock_contract
    compiler = shutil.which('c++')
    if compiler is None: pytest.skip('C++ compiler unavailable for software-only mock')
    mock = r'''
#include <cstdint>
struct Context { std::uint64_t time() { return 0; } void timeInc(std::uint64_t) {} int timeprecision() { return -12; } };
struct Model { Context ctx; Context *contextp() { return &ctx; } bool eventsPending() { return false; } std::uint64_t nextTimeSlot() { return 0; } };
static void eval_dut(Model &) {}
'''
    main = r'''
int main() {
  TimedStartupDiagnostics startup;
  std::printf("official monitor startup banner\n");
  std::cout << "monitor buffered diagnostic\n";
  startup.restore();
  std::cout << "READY local_driver.v1\n";
  std::cout << "RESULT wire remains stdout\n";
}
'''
    source = tmp_path/'startup_mock.cpp'
    source.write_text(mock + _timed_driver_cpp(_timed_clock_contract(profile('timing'), {'fast_frequency_hz': 50_000_000})) + main)
    binary = tmp_path/'startup_mock'
    subprocess.run([compiler, '-std=c++17', str(source), '-o', str(binary)], check=True, capture_output=True, text=True)
    result = subprocess.run([str(binary)], check=True, capture_output=True, text=True)
    assert result.stdout == 'READY local_driver.v1\nRESULT wire remains stdout\n'
    assert 'official monitor startup banner' in result.stderr
    assert 'monitor buffered diagnostic' in result.stderr
