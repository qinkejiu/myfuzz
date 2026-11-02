"""Production search ownership and legacy module compatibility (software only)."""
import importlib
from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def legacy_import_path(monkeypatch):
    root = Path(__file__).resolve().parents[2]
    monkeypatch.syspath_prepend(str(root / 'research/input-strategy-audit-20261027/prototype'))


MODULES = ('actions', 'frontier', 'gpio', 'gpio_actions', 'gpio_fields',
           'gpio_relations', 'gpio_search', 'journal', 'model', 'native',
           'policy', 'r1_probe', 'r1_session', 'storage')


@pytest.mark.parametrize('name', MODULES)
def test_legacy_module_is_production_module(name):
    old = importlib.import_module('dependency_search.' + name)
    new = importlib.import_module('myfuzz.search.' + name)
    assert old is new
    assert Path(new.__file__).parent.name == 'search'


def test_legacy_monkeypatch_reaches_production(monkeypatch):
    old = importlib.import_module('dependency_search.native')
    new = importlib.import_module('myfuzz.search.native')
    sentinel = object()
    monkeypatch.setattr(old, '_prepare', sentinel)
    assert new._prepare is sentinel
    old_gpio = importlib.import_module('dependency_search.gpio_search')
    new_gpio = importlib.import_module('myfuzz.search.gpio_search')
    monkeypatch.setattr(old_gpio, 'create_r1_session', sentinel)
    assert new_gpio.create_r1_session is sentinel


def test_production_root_and_sources_ignore_research_artifacts(monkeypatch, tmp_path):
    native = importlib.import_module('myfuzz.search.native')
    root = Path(__file__).resolve().parents[2]
    assert native.ROOT == root
    monkeypatch.setattr(native, 'AUDIT', tmp_path / 'absent-research')
    sources = native.source_files()
    assert any(row['path'] == 'src/myfuzz/search/native.py' for row in sources)
    assert all(row['base'] == 'project' for row in sources)
    assert all('run_r0.py' not in row['path'] for row in sources)
    assert all('prototype/dependency_search' not in row['path'] for row in sources)
    gpio = importlib.import_module('myfuzz.search.gpio_search')
    assert any(row['path'] == 'src/myfuzz/search/gpio_search.py'
               for row in gpio.source_files())


def test_legacy_output_scope_is_preserved(tmp_path, monkeypatch):
    native = importlib.import_module('myfuzz.search.native')
    monkeypatch.setattr(native, 'AUDIT', tmp_path / 'audit')
    with pytest.raises(ValueError, match='research directory'):
        native.require_new_output(tmp_path / 'elsewhere', 'original')
    assert native.require_new_output(tmp_path / 'audit' / 'case', 'original') == tmp_path / 'audit' / 'case' / 'original'
