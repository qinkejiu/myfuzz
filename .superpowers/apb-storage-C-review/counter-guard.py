"""Evaluate only frozen issue/consume rejection expressions; no live issuer."""
import ast,json,subprocess
from types import SimpleNamespace
source=subprocess.check_output(['git','show','cadaa75:src/myfuzz/scenario/apb_storage_register_version.py']).decode()
cls=next(n for n in ast.parse(source).body if isinstance(n,ast.ClassDef));rows=[]
for name in ('issue','consume'):
 fn=next(n for n in cls.body if isinstance(n,ast.FunctionDef) and n.name==name)
 guard=next(n for n in ast.walk(fn) if isinstance(n,ast.If) and "state['sequence']" in ast.unparse(n.test))
 process=SimpleNamespace(poll=lambda:None)
 target=SimpleNamespace(process=process,_execution='scope-placeholder',reset_epoch=0,_sequence=1,local_ticks=6,_tick_base=1)
 env=dict(register='TIMER0_CTRL',reset_epoch=0,t=target,live=dict(pending=None,scope=(process,target._execution,0)),state=dict(tick=5,sequence=1,value=9))
 refused=eval(compile(ast.Expression(guard.test),'frozen-cadaa75-guard','eval'),env)
 rows.append(dict(method=name,rejection_guard_value=refused,stored_state_tick=5,target_local_ticks=6,target_tick_base=1,scope_matches=True,sequence_matches=True))
print(json.dumps(dict(scope='isolated_actual_AST_guard_only_not_live_issuer',native_eligible_checked=False,token_issued=False,rows=rows),indent=2))
