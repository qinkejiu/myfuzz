"""Exercise process group observation with disposable real child processes."""

from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = ROOT / "scripts/task5_native_completion_r11/r11-one-shot-controller.v1.py"

WORKER = r'''
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time

libc = ctypes.CDLL(None, use_errno=True)
prctl = getattr(libc, "prctl", None)
if prctl is None or prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
    print("SKIP: PR_SET_CHILD_SUBREAPER unavailable, errno=%s" % ctypes.get_errno())
    sys.exit(77)

spec = importlib.util.spec_from_file_location("r11_group_controller", sys.argv[1])
controller = importlib.util.module_from_spec(spec)
spec.loader.exec_module(controller)
root = Path(sys.argv[2])
marker = root / "release"
pidfile = root / "descendant.pid"
dummy = r"""
import os
from pathlib import Path
import sys
import time
child = os.fork()
if child:
    Path(sys.argv[2]).write_text(str(child))
    os._exit(0)
deadline = time.monotonic() + 5
while not Path(sys.argv[1]).exists() and time.monotonic() < deadline:
    time.sleep(0.01)
os._exit(0)
"""
parent = subprocess.Popen([sys.executable, "-B", "-c", dummy,
                           str(marker), str(pidfile)], start_new_session=True)
descendant = None
reaped = False
try:
    assert parent.wait(timeout=3) == 0
    descendant = int(pidfile.read_text())
    assert os.getpgid(descendant) == parent.pid
    assert controller.group_gone(parent.pid) is False
    assert controller.observe_group(parent.pid, time.monotonic() + 0.05) is False
    marker.touch()
    waited, status = os.waitpid(descendant, 0)
    reaped = True
    assert waited == descendant and os.waitstatus_to_exitcode(status) == 0
    assert controller.group_gone(parent.pid) is True
    assert controller.observe_group(parent.pid, time.monotonic() + 0.1) is True
    print(json.dumps({"parent_reaped": True, "descendant_same_pgid": True,
                      "live_after_parent_wait": True, "descendant_reaped": True,
                      "group_gone_after_descendant_wait": True}))
finally:
    marker.touch()
    if parent.poll() is None:
        parent.wait(timeout=6)
    if descendant is None and pidfile.exists():
        descendant = int(pidfile.read_text())
    if descendant is not None and not reaped:
        os.waitpid(descendant, 0)
'''


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux child subreaper")
def test_group_stays_live_until_orphaned_descendant_is_reaped(tmp_path):
    result = subprocess.run(
        [sys.executable, "-B", "-c", WORKER, str(CONTROLLER), str(tmp_path)],
        text=True, capture_output=True, timeout=15)
    if result.returncode == 77:
        pytest.skip(result.stdout.strip())
    assert result.returncode == 0, result.stdout + result.stderr
    assert '"group_gone_after_descendant_wait": true' in result.stdout
