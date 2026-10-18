"""Unexecuted read-only observation helper for the one existing OpenTitan job."""
import subprocess

REMOTE = r'''
import json, os, time
from pathlib import Path
base = Path('/root/fanzehui/myfuzz/operations/p8-source-opentitan-metadata-20261018-attempt2')
if any(p.is_symlink() for p in (base, *base.parents)):
    raise ValueError('operation-symlink')
control = base / 'control'
if control.is_symlink():
    raise ValueError('control-symlink')

def read_json(path):
    if path.is_symlink():
        raise ValueError('receipt-symlink')
    if not path.exists():
        return None
    if path.stat().st_size > 1024 * 1024:
        return {'observation_error': 'receipt-exceeds-1MiB', 'path': str(path)}
    try:
        return json.loads(path.read_bytes())
    except (ValueError, OSError) as error:
        return {'observation_error': repr(error), 'path': str(path)}

def file_info(name):
    path = control / name
    if path.is_symlink():
        raise ValueError('map-symlink')
    if not path.exists():
        return {'exists': False}
    info = path.stat()
    return {'exists': True, 'bytes': info.st_size, 'modified_unix': info.st_mtime}

start = read_json(control / 'parent-start.json')
terminal = read_json(control / 'parent-terminal.json')
result = dict(schema_version='p8_opentitan_readonly_observation.v1', observed_unix=time.time(),
    operation=str(base), parent_start=start, parent_terminal=terminal,
    maps={name: file_info(name) for name in ('source-before-files.json',
          'source-before-directories.json', 'source-after-files.json', 'source-after-directories.json',
          'snapshot-objects.json', 'snapshot-paths.json', 'stage-files.json', 'stage-directories.json',
          'missing-pinned-files-plan.json', 'missing-pinned-files-reconstruction.json')},
    no_git_or_model_invocation=True)
# Only enumerate this small control directory and read tiny child receipts;
# never recurse source/object trees or open large batch stdout/map payloads.
names = [path.name for path in control.iterdir()] if control.exists() else []
starts = sorted(name for name in names if name.startswith('child-') and name.endswith('.start.json'))
ends = sorted(name for name in names if name.startswith('child-') and name.endswith('.terminal.json'))
counts, malformed = {}, []
for name in ends:
    row = read_json(control / name)
    if not isinstance(row, dict) or 'returncode' not in row:
        malformed.append(name)
        continue
    key = str(row['returncode'])
    counts[key] = counts.get(key, 0) + 1
result.update(children_started=len(starts), children_terminal=len(ends),
    completed_child_returncodes=counts, unreadable_terminal_receipts=malformed,
    last_child_start=read_json(control / starts[-1]) if starts else None,
    last_child_terminal=read_json(control / ends[-1]) if ends else None)
pid = start.get('pid') if isinstance(start, dict) else None
if type(pid) is int and pid > 0:
    proc = Path('/proc') / str(pid)
    try:
        # Explicit proc observation: no signals, process commands, or state changes.
        result['actual_parent_proc'] = {'pid': pid,
            'stat': (proc / 'stat').read_text(),
            'cmdline': (proc / 'cmdline').read_bytes().replace(b'\0', b' ').decode(errors='replace')}
    except OSError as error:
        result['actual_parent_proc'] = {'pid': pid, 'observation_error': repr(error)}
print(json.dumps(result, indent=2, sort_keys=True))
'''


def main():
    # The script is intentionally not run during source preparation. Invoking it
    # later reads the existing operation only; it cannot launch/restart the job.
    command = ['ssh', 'jumpserver', 'ssh root@192.168.5.70 python3 -']
    result = subprocess.run(command, input=REMOTE.encode(), capture_output=True)
    import sys
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
