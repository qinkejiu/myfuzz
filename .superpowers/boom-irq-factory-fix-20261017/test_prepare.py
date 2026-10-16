import importlib.util
from pathlib import Path
import pytest


def module():
    path=Path(__file__).with_name('prepare.py')
    if not path.exists():pytest.fail('factory metadata preparation source missing')
    spec=importlib.util.spec_from_file_location('pure_factory_prep',path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m


def test_snapshot_delta_is_exact_existing_factory_plus_new_test():
    m=module();old={m.control.FACTORY:m.control.OLD_FACTORY,'unchanged':'abc'}
    overlay={m.control.FACTORY:m.control.NEW_FACTORY,m.NEW_TEST:'testsha'}
    new=old|overlay
    m.validate_delta(old,new,overlay)
    for bad in (new|{'unchanged':'other'},new|{'extra':'new'},{k:v for k,v in new.items() if k!='unchanged'}):
        with pytest.raises(ValueError):m.validate_delta(old,bad,overlay)
