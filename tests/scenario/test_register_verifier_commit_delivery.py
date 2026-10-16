"""Runner delivers a private issuance token before acknowledging actual RAM."""
from tests.local_harness.test_ordinary_apb_access_receipts import native_factory


def test_installed_verifier_observes_its_one_shot_actual_commit_before_ack(native_factory):
    runner=native_factory();cpu=runner.sessions['cpu'];cpu._case_id='commit-delivery'
    authority=runner._memory_commit_authority
    authority.register_consumer('register_program_verifier')
    seen=[]
    class Observer:
        def _consume_actual_commit(self,event,token):
            actual=authority.resolve(token,consumer='register_program_verifier')
            assert actual is not None
            assert cpu.service.pending_commit_count==1
            assert actual['fullkey']==event['transaction']
            assert actual['commit_document']==event['commit_document']
            seen.append((event['event_id'],actual))
    runner._register_program_verifier=Observer()
    cpu._serve('data',1,0x10004,0x89abcdef,15)
    runner._append_external_events('cpu',1)
    assert len(seen)==1
    assert cpu.service.pending_commit_count==0
    assert authority.pending_count==0
    runner._append_external_events('cpu',1)
    assert len(seen)==1
