"""The CLI must validate the saved documents whose byte digests it publishes."""
from copy import deepcopy
from hashlib import sha256
import json
from unittest.mock import patch

import pytest


@pytest.mark.parametrize('changed',['none','join','prefix','replay'])
def test_saved_outputs_match_same_call_before_material_verification(tmp_path,changed):
    from myfuzz.integration.compiled_rfuzz import verify_saved_compiled_f4_build_outputs
    outcome={'build_join':{'status':'complete'},'plan':{'path':'selected'},
        'replay':{'matches':True,'actual_prefix':{},'actual_events':[1]}}
    docs={'compiled_f4_build_join.v1.json':deepcopy(outcome['build_join']),
        'compiled_f4_prefix.json':deepcopy(outcome['plan']),
        'compiled_f4_replay.json':{'matches':True,'actual_event_count':1}}
    if changed!='none':
        name={'join':'compiled_f4_build_join.v1.json','prefix':'compiled_f4_prefix.json',
            'replay':'compiled_f4_replay.json'}[changed]
        docs[name]['substituted']=True
    for name,doc in docs.items():(tmp_path/name).write_text(json.dumps(doc)+'\n')
    with patch('myfuzz.integration.compiled_f4_build_join.verify_compiled_f4_build_material') as check:
        if changed=='none':
            hashes=verify_saved_compiled_f4_build_outputs(tmp_path,outcome=outcome,harness_set={},manifest={})
            assert hashes['compiled_f4_build_join.v1.json']==sha256((tmp_path/'compiled_f4_build_join.v1.json').read_bytes()).hexdigest()
            check.assert_called_once()
        else:
            with pytest.raises(ValueError,match='saved.*build|saved.*output'):
                verify_saved_compiled_f4_build_outputs(tmp_path,outcome=outcome,harness_set={},manifest={})
            check.assert_not_called()
