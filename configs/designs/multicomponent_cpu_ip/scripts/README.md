# Scripts

Planned helpers:

```text
check_dependency_manifest.py
run_local_smoke.py
run_remote_smoke_commands.sh
```

Local scripts should only do schema/config/filelist/harness checks. Do not run
RFuzz server or fuzz locally for this target because local memory is not enough.
Formal runs and even heavier smoke runs belong on `inner70:/root/fanzehui/myfuzz`
and must be recorded in the global results document.

Current check:

```bash
python3 configs/designs/multicomponent_cpu_ip/scripts/check_dependency_manifest.py \
  configs/designs/multicomponent_cpu_ip/manifests/rvx_initial_dependency_manifest.json
```
