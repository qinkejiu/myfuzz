"""Exercise real subprocess trees; resource termination is not a DUT finding."""
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from myfuzz.experiments import resource_policy as policy

GIB = 1024 ** 3


def test_budget_reserves_two_gib_and_caps_at_four():
    resolve = getattr(policy, 'heavy_process_budget', None)
    assert callable(resolve), 'heavy process budget admission is missing'
    assert resolve(10 * GIB) == 4 * GIB
    assert resolve(5 * GIB) == 3 * GIB
    assert resolve(3 * GIB) == GIB
    with pytest.raises(policy.ResourceProfileError, match='insufficient'):
        resolve(3 * GIB - 1)
    for value in [True, -1, 1.5]:
        with pytest.raises(policy.ResourceProfileError):
            resolve(value)


def guarded():
    run = getattr(policy, 'run_budgeted_process', None)
    assert callable(run), 'process tree resource supervisor is missing'
    return run


def test_normal_execution_records_measured_tree_rss(tmp_path):
    result = guarded()([sys.executable, '-c', 'print("receipt")'],
                       lock_path=tmp_path/'worker.lock', available_bytes=5*GIB)
    assert result.returncode == 0
    assert result.stdout.strip() == 'receipt'
    receipt = result.resource_receipt
    assert receipt['status'] == 'complete'
    assert receipt['rss_limit_bytes'] == 3*GIB
    assert receipt['peak_tree_rss_bytes'] > 0
    assert receipt['elapsed_seconds'] > 0
    assert receipt['workers'] == 1


def test_low_budget_refuses_before_start(tmp_path):
    marker = tmp_path/'started'
    with pytest.raises(policy.ResourceProfileError, match='insufficient'):
        guarded()([sys.executable, '-c', f'open({str(marker)!r}, "w").close()'],
                  lock_path=tmp_path/'worker.lock', available_bytes=2*GIB)
    assert not marker.exists()


def test_serial_worker_lock_refuses_second_heavy_command(tmp_path):
    import fcntl
    lock = tmp_path/'worker.lock'
    with lock.open('w') as stream:
        fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(policy.ResourceProfileError, match='worker busy'):
            guarded()([sys.executable, '-c', 'pass'], lock_path=lock,
                      available_bytes=5*GIB)


def running(pid):
    try:
        # A reparented zombie has no executable process or RSS.
        return Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1][0] != 'Z'
    except FileNotFoundError:
        return False


@pytest.mark.parametrize('mode', ['rss', 'failed_parent', 'timeout'])
def test_cleanup_covers_descendants_and_classifies_budget(tmp_path, mode):
    marker = tmp_path/'child.pid'
    child = 'import time; payload=bytearray(160*1024*1024); time.sleep(20)'
    # The parent exits without waiting in failed_parent; its child retains the
    # process group and pipes, so root PID liveness alone cannot end supervision.
    parent = (f'import subprocess,sys,time; p=subprocess.Popen([sys.executable,"-c",{child!r}]); '
              f'open({str(marker)!r},"w").write(str(p.pid)); '
              + ('time.sleep(.2);sys.exit(7)' if mode == 'failed_parent' else 'time.sleep(20)'))
    result = guarded()([sys.executable, '-c', parent],
                       lock_path=tmp_path/'worker.lock', available_bytes=5*GIB,
                       rss_limit_bytes=80*1024*1024 if mode=='rss' else GIB,
                       timeout_seconds=.8 if mode=='timeout' else 4)
    pid = int(marker.read_text())
    until = time.monotonic()+2
    while running(pid) and time.monotonic()<until:
        time.sleep(.02)
    assert not running(pid), 'supervisor leaked a descendant'
    if mode == 'rss':
        assert result.returncode == 124
        assert result.resource_receipt['status'] == 'budget_terminated'
        assert result.resource_receipt['peak_tree_rss_bytes'] > 80*1024*1024
        assert result.resource_receipt['dut_finding'] is False
    elif mode == 'timeout':
        assert result.returncode == 124
        assert result.resource_receipt['status'] == 'wall_timeout'
    else:
        assert result.returncode == 7
        assert result.resource_receipt['status'] == 'command_failed'


def test_short_lived_parent_cannot_leak_detached_child(tmp_path):
    marker = tmp_path/'detached.pid'
    child = 'import time;time.sleep(20)'
    parent = (f'import subprocess,sys; p=subprocess.Popen([sys.executable,"-c",{child!r}], '
              'start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); '
              f'open({str(marker)!r},"w").write(str(p.pid))')
    result = guarded()([sys.executable, '-c', parent],
                       lock_path=tmp_path/'worker.lock', available_bytes=5*GIB)
    pid = int(marker.read_text())
    try:
        assert result.returncode == 0
        assert not running(pid), 'detached child survived short-lived parent'
    finally:
        if running(pid):
            os.kill(pid, 9)


@pytest.mark.parametrize('signum', [15, 1])
def test_supervisor_signal_cleans_worker_and_restores_handlers(tmp_path, signum):
    marker = tmp_path/'worker.pid'
    supervisor = ('from myfuzz.experiments.resource_policy import run_budgeted_process; '
                  'from pathlib import Path;import sys;'
                  f'run_budgeted_process([sys.executable,"-c",'
                  f'{("import os,time;open("+repr(str(marker))+",\"w\").write(str(os.getpid()));time.sleep(20)")!r}], '
                  f'lock_path=Path({str(tmp_path/"worker.lock")!r}),available_bytes=5*1024**3)')
    process = subprocess.Popen([sys.executable, '-c', supervisor])
    pid = None
    try:
        until = time.monotonic()+4
        while not marker.exists() and time.monotonic()<until:
            time.sleep(.01)
        assert marker.exists()
        pid = int(marker.read_text())
        os.kill(process.pid, signum)
        process.wait(timeout=4)
        assert not running(pid), 'worker survived supervisor termination signal'
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        if pid is not None and running(pid):
            os.kill(pid, 9)


def test_supervisor_refuses_existing_children_without_killing_them(tmp_path):
    unrelated = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(20)'],
                                 start_new_session=True)
    try:
        with pytest.raises(policy.ResourceProfileError, match='existing child'):
            guarded()([sys.executable, '-c', 'pass'],
                      lock_path=tmp_path/'worker.lock', available_bytes=5*GIB)
        assert unrelated.poll() is None
    finally:
        unrelated.kill()
        unrelated.wait()


@pytest.mark.parametrize('command', [
    ['java', '-jar', 'generator.jar'],
    ['sbt', 'runMain', 'Generator'],
    ['mill', 'generator.run'],
])
def test_jvm_heavy_command_requires_explicit_heap_before_start(tmp_path, command):
    with pytest.raises(policy.ResourceProfileError, match='explicit JVM heap'):
        guarded()(command, lock_path=tmp_path/'worker.lock', available_bytes=5*GIB)


@pytest.mark.parametrize(('launcher_name', 'option', 'task', 'expected'), [
    ('java', '-Xmx1g', '-version', 1024**3),
    ('java', '-Xmx512m', '-version', 512*1024**2),
    ('java', '-XX:MaxHeapSize=1g', '-version', 1024**3),
    ('java', '-Xmx1073741824', '-version', 1024**3),
    ('java', '-Xmx04m', '-version', 4*1024**2),
    ('java', '-Xmx0x10000000', '-version', 256*1024**2),
    ('sbt', '-J-Xmx768m', 'compile', 768*1024**2),
    ('sbt', '-J-XX:MaxHeapSize=1g', 'compile', 1024**3),
])
def test_jvm_heavy_command_accepts_explicit_heap_below_rss_limit(
        tmp_path, launcher_name, option, task, expected):
    launcher = tmp_path/launcher_name
    launcher.write_text('#!/bin/sh\nprintf "ok\\n"\n')
    launcher.chmod(0o755)
    result = guarded()([str(launcher), option, task],
                       lock_path=tmp_path/'worker.lock', available_bytes=5*GIB)
    assert result.returncode == 0
    assert result.stdout.strip() == 'ok'
    assert result.resource_receipt['jvm_heap_limit_bytes'] == expected


def test_jvm_heap_cannot_exceed_process_tree_rss_budget(tmp_path):
    with pytest.raises(policy.ResourceProfileError, match='exceeds process RSS'):
        guarded()(['java', '-Xmx4g', '-version'], lock_path=tmp_path/'worker.lock',
                  available_bytes=5*GIB)


def test_jvm_heap_after_java_target_does_not_count_as_launcher_limit(tmp_path):
    with pytest.raises(policy.ResourceProfileError, match='explicit JVM heap'):
        guarded()(['java', '-jar', 'generator.jar', '-Xmx1g'],
                  lock_path=tmp_path/'worker.lock', available_bytes=5*GIB)


def test_jvm_heap_after_value_taking_launcher_option_is_recognized(tmp_path):
    launcher = tmp_path/'java'
    launcher.write_text('#!/bin/sh\nprintf "ok\\n"\n')
    launcher.chmod(0o755)
    result = guarded()([str(launcher), '--add-modules', 'java.sql', '-Xmx1g', '-version'],
                       lock_path=tmp_path/'worker.lock', available_bytes=5*GIB)
    assert result.returncode == 0
    assert result.resource_receipt['jvm_heap_limit_bytes'] == GIB


@pytest.mark.parametrize(('command', 'environment'), [
    (['java', '-Xmx1g', '-XX:MaxHeapSize=4g', '-version'], None),
    (['java', '--module=generator/com.Main', '-Xmx1g'], None),
    (['java', '-Xmx1g', '-Xmx4294967296', '-version'], None),
    (['java', '-Xmx1g', '@heap.args'], None),
    (['java', '-Xmx1g', '-XX:VMOptionsFile=heap.options', '-version'], None),
    (['java', '-Xmx1g', '-Xmx04g', '-version'], None),
    (['java', '-Xmx1g', '-Xmx0x100000000', '-version'], None),
    (['java', '-Xmx1g', '-Xmx1t', '-version'], None),
    (['java', '-Xmx1g', '-version'], ('JDK_JAVA_OPTIONS', '-XX:MaxHeapSize=4g')),
    (['java', '-Xmx1g', '-version'], ('JDK_JAVA_OPTIONS', '@heap.args')),
    (['java', '-Xmx1g', '-version'], ('JAVA_TOOL_OPTIONS', '-XX:MaxHeapSize=4g')),
    (['java', '-Xmx1g', '-version'], ('_JAVA_OPTIONS', '-XX:MaxHeapSize=4g')),
    (['java', '-Xmx1g', '-version'], ('_JAVA_OPTIONS', '-Xmx04g')),
    (['java', '-Xmx1g', '-version'], ('_JAVA_OPTIONS', '-Xmx0x100000000')),
    (['java', '-Xmx1g', '-version'], ('_JAVA_OPTIONS', '-Xmx1t')),
    (['sbt', '-J-Xmx1g', 'compile'], ('SBT_OPTS', '-J-XX:MaxHeapSize=4g')),
    (['sbt', '-J-Xmx1g', 'compile', '-J-Xmx4g'], None),
    (['sbt', '-J-Xmx1g', '-mem', '4096', 'compile'], None),
    (['sbt', '-J-Xmx1g', 'compile', '--mem', '4096'], None),
    (['sbt', '-Xmx1g', 'compile'], None),
    (['sbt', '-J-Xmx1g', 'compile'], ('SBT_OPTS', '-mem 4096')),
    (['sbt', '-J-Xmx1g', 'compile'], ('SBT_OPTS', '-J-Xmx4g')),
    (['mill', '-J-Xmx1g', 'generator.run'], ('MILL_JVM_OPTS', '-J-XX:MaxHeapSize=4g')),
])
def test_jvm_heap_overrides_from_aliases_argfiles_and_environment_are_refused(
        tmp_path, monkeypatch, command, environment):
    if environment is not None:
        monkeypatch.setenv(*environment)
    with pytest.raises(policy.ResourceProfileError,
                       match='heap|argument files|environment|memory'):
        guarded()(command, lock_path=tmp_path/'worker.lock', available_bytes=5*GIB)


@pytest.mark.parametrize(('filename', 'contents'), [
    ('.jvmopts', '-Xmx4g\n'),
    ('.sbtopts', '-J-Xmx4g\n'),
    ('.sbtopts', '-mem 4096\n'),
])
def test_sbt_project_option_files_cannot_override_bounded_heap(
        tmp_path, monkeypatch, filename, contents):
    monkeypatch.chdir(tmp_path)
    (tmp_path/filename).write_text(contents)
    with pytest.raises(policy.ResourceProfileError, match='heap|memory|option'):
        guarded()(['sbt', '-J-Xmx1g', 'compile'],
                  lock_path=tmp_path/'worker.lock', available_bytes=5*GIB)


def test_sbt_global_option_file_cannot_override_bounded_heap(tmp_path, monkeypatch):
    global_options = tmp_path/'sbtopts'
    global_options.write_text('-mem 4096\n')
    monkeypatch.setattr(policy, '_SBT_GLOBAL_OPTIONS_PATH', global_options, raising=False)
    with pytest.raises(policy.ResourceProfileError, match='memory|option'):
        guarded()(['sbt', '-J-Xmx1g', 'compile'],
                  lock_path=tmp_path/'worker.lock', available_bytes=5*GIB)


@pytest.mark.parametrize(('filename', 'path_env'), [
    ('.mill-jvm-opts', None),
    ('external-mill-jvm-opts', 'MILL_JVM_OPTS_PATH'),
])
def test_mill_launcher_is_refused_when_jvm_options_are_not_version_locked(
        tmp_path, monkeypatch, filename, path_env):
    monkeypatch.chdir(tmp_path)
    for name in ('JDK_JAVA_OPTIONS', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS',
                 'JAVA_OPTS', 'MILL_JVM_OPTS'):
        monkeypatch.delenv(name, raising=False)
    options = tmp_path/filename
    options.write_text('-Xmx4g\n')
    if path_env:
        monkeypatch.setenv(path_env, str(options))
    marker = tmp_path/'mill-was-launched'
    launcher = tmp_path/'mill'
    launcher.write_text(f'#!/bin/sh\ntouch {str(marker)!r}\n')
    launcher.chmod(0o755)
    with pytest.raises(policy.ResourceProfileError, match='Mill.*heap|explicit JVM heap'):
        guarded()([str(launcher), '-J-Xmx1g', 'generator.run'],
                  lock_path=tmp_path/'worker.lock', available_bytes=5*GIB)
    assert not marker.exists()


@pytest.mark.parametrize('option', ['-Xmx1p', '-Xmxgarbage', '-XX:MaxHeapSize=wat'])
def test_malformed_heap_prefixed_option_is_not_ignored(tmp_path, option):
    with pytest.raises(policy.ResourceProfileError, match='heap'):
        guarded()(['java', '-Xmx1g', option, '-version'],
                  lock_path=tmp_path/'worker.lock', available_bytes=5*GIB)


@pytest.mark.parametrize('option', ['-Xmx04g', '-Xmx0x100000000', '-Xmx1t'])
def test_valid_large_heap_formats_are_compared_to_rss_budget(tmp_path, option):
    with pytest.raises(policy.ResourceProfileError, match='exceeds process RSS'):
        guarded()(['java', option, '-version'],
                  lock_path=tmp_path/'worker.lock', available_bytes=5*GIB)
