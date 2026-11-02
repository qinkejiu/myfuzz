"""Software-only lifecycle helpers for native F6 control tests."""
import pytest


def helpers_module():
    from tests.integration.test_verify_compiled_f6 import auditor_module
    return auditor_module()


def test_property_capture_reads_the_public_property_descriptors():
    class Runtime:
        def __init__(self):
            self.reads = []

        @property
        def trace(self):
            self.reads.append('trace')
            return {'events': []}

        @property
        def finish_diagnostic(self):
            self.reads.append('finish_diagnostic')
            return {'finished': True}

    runtime = Runtime()
    result = helpers_module().read_properties(runtime, ('trace', 'finish_diagnostic'))
    assert result == {'trace': {'events': []},
                      'finish_diagnostic': {'finished': True}}
    assert runtime.reads == ['trace', 'finish_diagnostic']


def test_attempt_all_runs_cleanup_and_every_export_after_failures():
    helper = helpers_module().attempt_all
    calls = []
    first = RuntimeError('finish failed')
    second = RuntimeError('trace export failed')

    def finish():
        calls.append('finish')
        raise first

    def trace():
        calls.append('trace')
        raise second

    def audit():
        calls.append('audit')
        return {'closed': True}

    with pytest.raises(RuntimeError) as caught:
        helper((('finish', finish), ('trace', trace), ('audit', audit)))
    assert caught.value is first
    assert calls == ['finish', 'trace', 'audit']
    assert any('trace' in note and 'trace export failed' in note
               for note in getattr(first, '__notes__', ()))


def test_supplied_primary_and_its_nested_notes_survive_secondary_cleanup_errors():
    helper = helpers_module().attempt_all
    primary = RuntimeError('original execution failure')
    primary.add_note('original nested source note')
    secondary = RuntimeError('finish failure')
    secondary.add_note('finish nested cleanup note')
    calls = []

    def finish():
        calls.append('finish')
        raise secondary

    def export():
        calls.append('export')
        return 'captured'

    with pytest.raises(RuntimeError) as caught:
        helper((('finish', finish), ('export', export)), primary=primary)
    assert caught.value is primary
    assert calls == ['finish', 'export']
    notes = getattr(primary, '__notes__', ())
    assert notes[0] == 'original nested source note'
    assert any('finish failure' in note for note in notes)
    assert any('finish nested cleanup note' in note for note in notes)

