from pathlib import Path
import subprocess,shlex,json,os
base='/root/fanzehui/cvw-ahb-observer-20261017-attempt1'
bootstrap="""
import os,json,sys
from pathlib import Path
base=Path('/root/fanzehui/cvw-ahb-observer-20261017-attempt1')
receipt={'schema_version':'cvw_ahb_pure_preparation_started.v1','pid':os.getpid(),'phase':'pure_copy_hash_import_validate','native_run':False}
with (base/'preparation.started.json').open('x') as stream:json.dump(receipt,stream);stream.write('\\n')
print(json.dumps(receipt),flush=True)
os.execv(sys.executable,[sys.executable,str(base/'control/validate-preparation.py')])
"""
exports={'PYTHONPATH':base+'/project/src:'+base+'/project:/root/fanzehui/system-20261016/pythonlib','PYTHONDONTWRITEBYTECODE':'1','PYTHONOPTIMIZE':'0','TMPDIR':base+'/tmp','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':base+'/control/empty.gitconfig','GIT_OPTIONAL_LOCKS':'0'}
command='cd '+shlex.quote(base+'/project')+' && '+shlex.join(['env',*[k+'='+v for k,v in exports.items()],'python3','-c',bootstrap])
outer='ssh root@192.168.5.70 '+shlex.quote(command)
process=subprocess.Popen(['ssh','jumpserver',outer],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
state={'local_wrapper_pid':os.getpid(),'actual_ssh_pid':process.pid,'phase':'pure_remote_validate','native_run':False}
print(json.dumps(state),flush=True)
path=Path('/home/qinkejiu/myfuzz/docs/reports/evidence/cvw-ahb-control-20261017/remote-validation.log')
with path.open('x') as output:
 output.write(json.dumps(state)+'\n');output.flush()
 for line in process.stdout:
  print(line,end='',flush=True);output.write(line);output.flush()
 status=process.wait();output.write('actual_ssh_exit='+str(status)+'\n')
raise SystemExit(status)
