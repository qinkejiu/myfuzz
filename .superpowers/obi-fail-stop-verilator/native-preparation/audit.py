import json,re
from pathlib import Path
base=Path('/root/fanzehui/obi-fail-stop-verilator-20261017-434a4e8')
log=(base/'native.log').read_text()
assert re.search(r'\b1 passed\b',log) and 'SKIPPED' not in log and '1 skipped' not in log
build=[json.loads(s.split('OBI_FAIL_STOP_BUILD ',1)[1]) for s in log.splitlines() if 'OBI_FAIL_STOP_BUILD ' in s]
result=[json.loads(s.split('OBI_FAIL_STOP_RESULT ',1)[1]) for s in log.splitlines() if 'OBI_FAIL_STOP_RESULT ' in s]
assert len(build)==len(result)==1
assert build[0]['returncode']==0 and result[0]['returncode']!=0
assert 'OBI backend error cannot be represented' in result[0]['stdout']+result[0]['stderr']
pins=json.loads((base/'source-manifest.json').read_text())
assert build[0]['adapter_sha256']==pins['src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv']
assert build[0]['testbench_sha256']=='83b46a7a6fb8dacc15dfe19a8b04926215877ce867003944670648d11153dc39'
assert int((base/'native.exit').read_text())==0 and int((base/'source-after.exit').read_text())==0
print(json.dumps({'gate':'same_testbench_verilator_no_error_fail_stop','build':build[0],'native_result':result[0],'pytest_exit':0,'source_after_exit':0,'scope':'adapter RTL only; not generated CPU boundary or F4 semantic acceptance'},indent=2))
