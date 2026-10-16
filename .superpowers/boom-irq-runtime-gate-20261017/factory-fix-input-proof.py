"""Pure historical archive/byte proof. No generation, constructor or tools."""
import hashlib,json
from pathlib import Path
from myfuzz.local_harness.boom_irq_recovery import load_origin,INPUTS
from myfuzz.local_harness.boom_irq_contract import PROBES
from myfuzz.scenario.boom_gpio_irq_runner import boom_gpio_irq_program
ROOT=Path(__file__).resolve().parents[2]
files,origin=load_origin(ROOT/'.superpowers/boom-irq-verification-20261017')
hash_bytes=lambda data:hashlib.sha256(data).hexdigest()
host=ROOT/'src/myfuzz/local_harness'
paths={'driver.cpp':host/'boom_irq_cpu_driver.cpp','tl_ram.h':ROOT/'configs/cpus/boom/runtime/tl_ram.h',
       'boom_irq_probes.h':host/'boom_irq_probes.h',
       **{name:ROOT/'configs/cpus/boom/generated'/name for name in ('EICG_wrapper.v','chipyard.TestHarness.SmallBoomConfig.top.mems.v','chipyard.TestHarness.SmallBoomConfig.top.v','plusarg_reader.v')},
       **{output:ROOT/'configs/cpus/boom_irq'/source for output,source in (('passive_probes.vlt','passive_probes.vlt'),('irq-profile.json','component_profile.json'),('probe_contract.json','probe_contract.json'),('irq-interface.json','interface_description.json'))}}
values={name:path.read_bytes() for name,path in paths.items()}
spec='inline std::vector<BoomProbe> boom_probe_specs() {return {\n'
spec+=',\n'.join('{'+json.dumps(key)+','+json.dumps(path)+','+str(width)+'}' for key,(path,width) in PROBES.items())
values['boom_irq_probe_specs.h']=(spec+'\n};}\n').encode()
assert set(values)==set(INPUTS)
assert {name:hash_bytes(data) for name,data in values.items()}==origin['effective_inputs']
assert all(values[name]==files['artifact/'+name] for name in INPUTS)
baseline=json.loads((ROOT/'.superpowers/boom-irq-runtime-gate-20261017/baseline-source-files.json').read_text())['files']
implementation_names=('boom_irq_generation.py','boom_irq_contract.py','boom_irq_cpu_session.py','boom_irq_cpu_driver.cpp','boom_irq_probes.h','boom_irq_scenario_session.py','boom_irq_recovery.py','tilelink_coherent_cpu_session.py')
implementation={name:hash_bytes((host/name).read_bytes()) for name in implementation_names}
assert all(value==baseline['src/myfuzz/local_harness/'+name] for name,value in implementation.items())
factory=ROOT/'src/myfuzz/scenario/boom_gpio_irq_runner.py';new=factory.read_bytes()
old=new.replace(b"'bound','gpio.irq'",b"'bound','gpio_irq'")
assert old!=new and hash_bytes(old)==baseline['src/myfuzz/scenario/boom_gpio_irq_runner.py']
program=boom_gpio_irq_program()
assert hash_bytes(program)=='acecf7cb717ea5fee1791e14313a8b66d94b96ac2c4b63a6c53645892f28ae39'
print(json.dumps(dict(proof_kind='pure_byte_comparison_not_native',effective_input_count=len(values),
    effective_inputs={name:hash_bytes(data) for name,data in values.items()},
    effective_inputs_byte_equal=True,implementation_hashes_unchanged=implementation,
    factory_old_sha256=hash_bytes(old),factory_new_sha256=hash_bytes(new),factory_exact_owner_string_delta=True,
    program_sha256=hash_bytes(program),historical_binary_sha256=hash_bytes(files['artifact/obj/VBoomTile']),
    historical_build_exit=origin['build_exit'],historical_probe_exit=origin['probe_exit'],historical_failed_stage_exit=origin['failed_stage_exit'],
    constructor_executed=False,generator_executed=False,tool_executed=False,model_executed=False),indent=2))
