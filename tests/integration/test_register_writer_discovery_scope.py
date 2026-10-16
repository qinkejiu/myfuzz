"""Public writer/selector invocation scope; actual discovery code call counts."""
import sys
from unittest.mock import patch
from myfuzz.integration import ibex_pulp_register_replay as api
from myfuzz.local_harness import build


def test_writer_and_selector_each_discover_once_and_do_not_leak(tmp_path):
    code=build._discover_host_sources.__code__;calls=[]
    def profile(frame,event,arg):
        if event=='call' and frame.f_code is code:calls.append(frame)
    def pipeline(**kwargs):
        first=build._host_sources()
        for _ in range(5):assert build._host_sources()==first
        return 'actual-discovery-dispatch-fixture'
    prior=sys.getprofile();sys.setprofile(profile)
    try:
        with patch.object(api,'_save_ibex_pulp_register_bundle',side_effect=pipeline,create=True):
            assert api.save_ibex_pulp_register_bundle(output_dir=tmp_path/'never-created',assembly={},session_manifest={},plan_bytes=b'',trace=None,runtime_state={})=='actual-discovery-dispatch-fixture'
        assert len(calls)==1 and not (tmp_path/'never-created').exists()
        with patch.object(api,'_register_file_preflight_unscoped',side_effect=pipeline,create=True):
            assert api._register_file_preflight(output=tmp_path/'none')=='actual-discovery-dispatch-fixture'
        assert len(calls)==2
        build._host_sources();assert len(calls)==3
    finally:sys.setprofile(prior)
