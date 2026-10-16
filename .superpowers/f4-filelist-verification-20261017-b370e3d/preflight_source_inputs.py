from pathlib import Path
from unittest.mock import patch
import json,sys
base=Path('/root/fanzehui/f4-filelist-verification-20261017-b370e3d');project=base/'project'
sys.path.insert(0,str(project/'src'))
from myfuzz.integration.compiled_execution_files import _source_paths,_hashes
summary=[]
with patch('subprocess.Popen',side_effect=AssertionError('source-only preflight cannot start processes')):
    for fixture in ('compiled-f4-obi-apb','compiled-f4-obi-apb-ibex'):
        config=project/'configs/scenarios'/fixture
        paths=_source_paths(project,config/'compose.json',(config/'test_capability.json',),
            config/'execution_supplement.json',config/'example_records.json')
        record=dict(fixture=fixture,source_count=len(paths),hashes=_hashes(paths),native_executed=False)
        (base/'logs'/f'{fixture}.input-preflight.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
        summary.append({k:v for k,v in record.items() if k!='hashes'})
print(json.dumps(summary,sort_keys=True))
