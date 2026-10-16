"""Prepared launcher regression; never invokes its commands."""
from pathlib import Path


def test_build_uses_real_prescribed_environment_interpreter():
    script=Path(__file__).with_name('build.sh').read_text().splitlines()
    commands=[line.split()[0] for line in script if line.startswith('python')]
    assert commands == ['python3','python3']
