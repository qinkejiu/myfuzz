"""Profile-driven Wishbone CPU/IRQ-vector assembly for shared flow runtimes.

This installs real component bindings only. It creates neither IRQ source
lineage nor handler retirement evidence, and grants no F5/F6 certificate.
"""
from dataclasses import dataclass
from pathlib import Path

from myfuzz.local_harness.profile_custom_irq import verify_custom_irq_artifact
from myfuzz.local_harness.wishbone_cpu_session import GeneratedWishboneCpuSession
from myfuzz.scenario.ownership import InputField, InputOwner, compile_ownership
from myfuzz.scenario.runner import Binding


@dataclass(frozen=True)
class SharedCustomIrqCpu:
    cpu: GeneratedWishboneCpuSession
    bindings: tuple
    ownership: object
    contract: dict


def build_shared_custom_irq_cpu(*, artifact, base_dir, cache_dir, memory, router,
                                irq_sources):
    """Allocate a pre-start CPU and deterministic IRQ-vector bindings.

    Each source is (component, session output port, IRQ bit). The actual
    ScenarioRunner must own matching real source sessions. Inactive CPU bits
    remain fixed zero; distinct sources cannot claim the same IRQ line.
    """
    irq = verify_custom_irq_artifact(artifact,base_dir=Path(base_dir))
    if (irq['input_port'] != 'irq' or type(irq_sources) is not tuple or not irq_sources
            or any(type(row) is not tuple or len(row)!=3 or
                   any(type(value) is not str or not value for value in row[:2]) or
                   type(row[2]) is not int or not 3 <= row[2] < 32 for row in irq_sources)
            or len({row[2] for row in irq_sources}) != len(irq_sources)
            or len({row[:2] for row in irq_sources}) != len(irq_sources)):
        raise ValueError('shared-custom-IRQ-source-declaration')
    cpu_id=artifact.plan.request.instance_id
    if any(component==cpu_id for component,_,_ in irq_sources):
        raise ValueError('shared-custom-IRQ-source-self-loop')
    cpu=GeneratedWishboneCpuSession(artifact,base_dir=base_dir,cache_dir=cache_dir,
        memory=memory,router=router,defer_mmio=True,memory_commit_receipts=True,
        memory_readback_receipts=True,physical_tick_samples=True,custom_irq_observations=True)
    bindings=tuple(Binding(component,port,cpu_id,'irq',1,target_bit_offset=bit)
                   for component,port,bit in irq_sources)
    by_bit={bit:(component,port) for component,port,bit in irq_sources}
    owners=tuple(InputOwner(cpu_id,'irq',bit,1,
        'bound' if bit in by_bit else 'fixed',
        '.'.join(by_bit[bit]) if bit in by_bit else 'inactive') for bit in range(32))
    ownership=compile_ownership((InputField(cpu_id,'irq',32),),owners)
    document=dict(schema_version='shared_custom_irq_cpu.v1',cpu_instance=cpu_id,
        component_id=artifact.plan.profile.component_id,
        profile_fingerprint=artifact.plan.profile.profile_fingerprint,
        artifact_digest=artifact.runtime_document['artifact_digest'],abi=irq['abi'],
        routes=[dict(source_component=c,source_port=p,irq_bit=b) for c,p,b in irq_sources],
        observation='physical_input_eoi_trap_pre_post',source_attribution='unknown',
        retirement='unknown',f5_f6_certificate='not_granted')
    return SharedCustomIrqCpu(cpu,bindings,ownership,document)
