from hashlib import sha256
from myfuzz.integration.compiled_f4 import _closure


def test_closure_tracks_changed_added_and_removed_python_sources(tmp_path):
    source = tmp_path / 'src' / 'myfuzz'
    nested = source / 'nested'
    nested.mkdir(parents=True)
    first = source / 'first.py'
    second = nested / 'second.py'
    first.write_bytes(b'initial')
    (source / 'ignored.txt').write_bytes(b'ignored')

    assert _closure(tmp_path) == {
        'src/myfuzz/first.py': sha256(b'initial').hexdigest(),
    }
    first.write_bytes(b'changed')
    second.write_bytes(b'added')
    assert _closure(tmp_path) == {
        'src/myfuzz/first.py': sha256(b'changed').hexdigest(),
        'src/myfuzz/nested/second.py': sha256(b'added').hexdigest(),
    }
    first.unlink()
    assert _closure(tmp_path) == {
        'src/myfuzz/nested/second.py': sha256(b'added').hexdigest(),
    }
