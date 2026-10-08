"""Cached build identity must distinguish JSON booleans, integers and floats."""
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from myfuzz.local_harness.build import _validate_cache,LocalHarnessBuildError

class CachedScalarIdentityTests(unittest.TestCase):
    def cache(self,directory,saved):
        binary=directory/'harness';binary.write_bytes(b'authenticated cache fixture');binary.chmod(0o700)
        (directory/'manifest.json').write_text(json.dumps({'identity':saved,
            'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest()}))
        return binary

    def test_correct_old_cached_identity_remains_admitted(self):
        identity={'workers':1,'waveforms':False,'inputs':[]}
        with TemporaryDirectory() as temporary:
            directory=Path(temporary);binary=self.cache(directory,identity)
            self.assertEqual(_validate_cache(directory,identity),binary)

    def test_boolean_integer_and_float_substitutions_are_rejected(self):
        identity={'workers':1,'waveforms':False,'inputs':[]}
        for key,value in [('waveforms',0),('workers',1.0),('workers',True)]:
            with self.subTest(key=key,value=value),TemporaryDirectory() as temporary:
                directory=Path(temporary);saved=dict(identity);saved[key]=value
                self.cache(directory,saved)
                with self.assertRaisesRegex(LocalHarnessBuildError,'identity differs'):
                    _validate_cache(directory,identity)
