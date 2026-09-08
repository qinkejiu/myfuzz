from __future__ import annotations
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
import tests.integration.test_riscv_execution as task13_tests

EVIDENCE = Path(__file__).resolve().parent
RUN = EVIDENCE / "run"
RUN.mkdir(parents=True, exist_ok=False)

class PersistentDirectory:
    def __init__(self, *args, **kwargs):
        self.name = str(RUN)
    def __enter__(self):
        return self.name
    def __exit__(self, exc_type, exc, tb):
        return False

original_temporary_directory = tempfile.TemporaryDirectory
temporary_directory_calls = 0
def evidence_directory(*args, **kwargs):
    global temporary_directory_calls
    temporary_directory_calls += 1
    if temporary_directory_calls == 1:
        return PersistentDirectory(*args, **kwargs)
    return original_temporary_directory(*args, **kwargs)

original_run = subprocess.run
sequence = 0
def recorded_run(*args, **kwargs):
    global sequence
    result = original_run(*args, **kwargs)
    sequence += 1
    command = args[0] if args else kwargs.get("args")
    if isinstance(command, (str, bytes)):
        normalized = str(command)
    else:
        normalized = [str(item) for item in command]
    record = {
        "command": normalized,
        "cwd": str(kwargs.get("cwd", Path.cwd())),
        "returncode": result.returncode,
        "stdout": result.stdout if isinstance(result.stdout, str) else None,
        "stderr": result.stderr if isinstance(result.stderr, str) else None,
    }
    (EVIDENCE / f"subprocess-{sequence:02d}.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result

task13_tests.tempfile.TemporaryDirectory = evidence_directory
subprocess.run = recorded_run
suite = unittest.TestSuite((
    task13_tests.RiscvExecutionTests("test_ibex_executes_boot_through_generated_split_obi_path"),
))
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
