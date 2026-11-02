"""Document only a real F4 version that the subsequent F2 actually reads."""

from myfuzz.integration.shared_slot_consumers import _shared_apb_version_consumption


def version(value=85, field_version=1, epoch=0, digest='source-a'):
    return dict(register='TIMER0_CTRL', reset_epoch=epoch, value=value,
        field_version=field_version, write_count=field_version,
        artifact_digest='artifact-a', source_contract_digest=digest)


def writer(case_id='write-1', post=None):
    return dict(flow='F4', status='passed', case_id=case_id,
        certificate=dict(status='certified', case_id=case_id, value=85,
            postcondition=post or version(),
            commit=dict(after=85, field_version=1,
                context=dict(device_id='timer', source_authenticated=False))))


def test_observed_current_version_has_no_inferred_source_or_reward():
    result = _shared_apb_version_consumption([writer()], before=version(),
        reader_case_id='read-2', device_id='timer', read_event=47)
    assert result['status'] == 'observed'
    assert (result['writer_case_id'], result['reader_case_id'], result['read_event_id']) == ('write-1', 'read-2', 47)
    assert result['source_origin'] == 'unknown'
    assert result['reward_eligible'] is False and result['native_authority'] is False


def test_stale_reset_foreign_or_unsealed_writers_are_not_attributed():
    for row in (writer(post=version(field_version=2)), writer(post=version(epoch=1)),
                writer(post=version(digest='other')), dict(writer(), status='reserved')):
        result = _shared_apb_version_consumption([row], before=version(),
            reader_case_id='read-2', device_id='timer', read_event=47)
        assert result['status'] == 'unknown'
        assert result['writer_case_id'] is None and result['reward_eligible'] is False


def test_later_matching_writer_wins_and_other_device_does_not():
    old = writer('old')
    other = writer('other')
    other['certificate']['commit']['context']['device_id'] = 'different'
    new = writer('new')
    result = _shared_apb_version_consumption([old, other, new], before=version(),
        reader_case_id='read-4', device_id='timer', read_event=71)
    assert result['writer_case_id'] == 'new'
