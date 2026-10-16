import gzip,json
from pathlib import Path
base=Path('/root/fanzehui/cva6-full-axi-observer-20261017-attempt1')
root=base/'run'
s=json.loads((root/'summary.json').read_text())
assert s['status']=='pass' and s['native_run'] is True
assert all(s[k] is True for k in ('raw_prefix_equal','whole_observer_prefix_equal','whole_runner_prefix_equal','whole_driver_prefix_equal'))
assert not (root/'incomplete.json').exists()
first=json.loads(gzip.decompress((root/'first.json.gz').read_bytes()))
fresh=json.loads(gzip.decompress((root/'fresh.json.gz').read_bytes()))
assert first['native_execution']!=fresh['native_execution']
for run in (first,fresh):
 assert run['status']=='complete' and len(run['samples'])==len(run['driver_receipts'])==650
 assert run['write_beats']==2 and run['ram_values']==[0x600dcafe]*2
 assert len(run['lifecycle'])==1 and run['lifecycle'][0]['returncode']==run['lifecycle'][0]['poll_after_close']==0
 assert run['lifecycle'][0]['closed'] is True
assert first['lifecycle'][0]['pid']!=fresh['lifecycle'][0]['pid']
assert first['samples']==fresh['samples'] and first['pending']==fresh['pending'] and first['accepted']==fresh['accepted']
assert (base/'control/root-operation/controller.exit').read_text().strip()=='0'
print(json.dumps({'audit':'terminal_native_gate_pass','controller_exit':0,'first_pid':first['lifecycle'][0]['pid'],
 'fresh_pid':fresh['lifecycle'][0]['pid'],'raw_samples_each':650,'pending':s['pending'],
 'prefix_state':s['prefix_state'],'source_authority':False,'retirement_verified':False,'scope':'bounded CPU RAM AXI observation only'}))
