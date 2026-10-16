"""Bounded real Ibex -> wbdmac -> shared RAM -> native IRQ/ISR fixture.

Independent RTL processes are advanced in an explicit deterministic host order.
This fixture does not admit DMA to ScenarioRunner or claim a hardware bus bridge.
"""
from pathlib import Path

from myfuzz.local_harness import (load_local_harness_request, plan_local_harness,
    render_local_harness, render_local_runtime, verify_local_source_lock)
from myfuzz.local_harness.driver_renderer import render_local_driver
from myfuzz.local_harness.cpu_session import GeneratedCve2Session
from myfuzz.local_harness.wishbone_dma_session import GeneratedWishboneDmaSession
from .memory import PersistentMemory, MemoryRegion
from .router import DataflowRouter, DeviceWindow

ROOT = Path(__file__).resolve().parents[3]
DMA_BASE = 0x40000000
SOURCE = 0x22000
DESTINATION = 0x23000
RESULT = 0x24000
MAIN = 0x10080
ISR = 0x1022c
WORDS = (0x135,0x246,0x357,0x468)


def _addi(rd,rs,imm):
    return (imm&0xfff)<<20 | rs<<15 | rd<<7 | 0x13


def _lui(rd,address):
    return (address & 0xfffff000) | rd<<7 | 0x37


def _sw(rs,base,offset):
    return ((offset>>5)&127)<<25 | rs<<20 | base<<15 | 2<<12 | (offset&31)<<7 | 0x23


def _lw(rd,base,offset):
    return (offset&0xfff)<<20 | base<<15 | 2<<12 | rd<<7 | 0x03


def _csr(csr,rs,rd=0):
    return csr<<20 | rs<<15 | 2<<12 | rd<<7 | 0x73


def _bne(a,b,offset):
    v=offset&0x1fff
    return ((v>>12)&1)<<31 | ((v>>5)&63)<<25 | b<<20 | a<<15 | 1<<12 | ((v>>1)&15)<<8 | ((v>>11)&1)<<7 | 0x63


def ibex_dma_images(*, start_key=0xfed):
    if type(start_key) is not int or not 0 <= start_key <= 0xfff:
        raise ValueError('DMA start key must be 12 bits')
    main=[_lui(1,DMA_BASE),_lui(2,SOURCE),_lui(4,DESTINATION),_lui(5,RESULT)]
    for i,word in enumerate(WORDS):
        main += [_addi(3,0,word),_sw(3,2,i*4)]
    main += [_lui(7,0x10000),_addi(7,7,0x200),_csr(0x305,7),
             _lui(7,0x1000),_addi(7,7,-0x800),_csr(0x304,7),
             _addi(7,0,8),_csr(0x300,7),
             _sw(2,1,8),_sw(4,1,12),_addi(3,0,4),_sw(3,1,4),
             _lui(3,start_key<<16),_addi(3,3,4),_sw(3,1,0),0x0000006f]
    # Ibex's vectored machine external entry is mtvec base + 11*4.
    isr=[_csr(0x342,0,6),_sw(6,5,0),_lw(7,1,0),_sw(7,5,4)]
    branches=[]
    for i,word in enumerate(WORDS):
        isr += [_lw(8,4,i*4),_sw(8,5,8+i*4),_addi(9,0,word)]
        branches.append(len(isr));isr += [0]
    isr += [_addi(3,0,1),_sw(3,5,24),0x30200073]
    failure=len(isr)
    isr += [_addi(3,0,-1),_sw(3,5,24),0x0000006f]
    for index in branches:
        isr[index]=_bne(8,9,(failure-index)*4)
    encode=lambda words:b''.join(w.to_bytes(4,'little') for w in words)
    return {MAIN:encode(main),ISR:encode(isr),DESTINATION:bytes(16),RESULT:bytes(28)}


def _artifact(profile,instance):
    request=load_local_harness_request(dict(schema_version='local_harness.v1',
        profile_path=profile,instance_id=instance,reset_assert_ticks=8,
        reset_release_ticks=8,max_wait_cycles=16))
    plan=plan_local_harness(request,base_dir=ROOT)
    return render_local_driver(render_local_runtime(plan,render_local_harness(plan),
        verify_local_source_lock(plan.profile,base_dir=ROOT),base_dir=ROOT),base_dir=ROOT)


def make_ibex_dma_chain(*,cache_dir,start_key=0xfed):
    memory=PersistentMemory(regions=(MemoryRegion('ram',0x10000,0x20000),),
        initialization_seed=17,max_initialized_bytes=0x20000)
    for address,image in ibex_dma_images(start_key=start_key).items():
        memory.preload(address,image)
    dma=GeneratedWishboneDmaSession(_artifact(
        'configs/peripherals/zipcpu_wbdmac/component_profile.json','dma'),
        base_dir=ROOT,cache_dir=cache_dir,memory=memory,command_timeout_seconds=30)
    router=DataflowRouter((DeviceWindow('dma',DMA_BASE,16,dma),))
    cpu=GeneratedCve2Session(_artifact('configs/cpus/ibex_rvfi_local/component_profile.json','cpu'),
        base_dir=ROOT,cache_dir=cache_dir,memory=memory,router=router,
        defer_mmio=True,native_irq_receipts=True,command_timeout_seconds=30)
    return cpu,dma,router,memory


def advance_ibex_dma(cpu,dma,router,*,step,irq_latch):
    """One declared scheduler iteration; retain extra control-access DMA edges.

    All actual DMA native pulses observed in this iteration drive exactly the
    CPU input latch. It clears only after actual irq_taken_pre; source pulses
    and latch transitions are separate facts. No expected data creates an IRQ.
    """
    start=len(dma.events)
    dma.step_local()
    router.drain_one('dma')
    pulses=[e['tick'] for e in dma.events[start:]
            if any(e['payload']['observations']['physical'].values())]
    before=list(irq_latch.get('pending_native_edges',()))
    pending=before+pulses
    irq=int(bool(pending))
    output=cpu.step_local({'irq':irq})
    taken=bool(output['irq_taken_pre'])
    irq_latch['pending_native_edges']=[] if taken else pending
    return dict(irq_latch_before=before,irq_latch_sources=pending,
        irq_latch_after=list(irq_latch['pending_native_edges']),
        irq_latch_cleared_by_actual_take=taken,step=step,dma_edge_ticks=[e['tick'] for e in dma.events[start:]],
        dma_native_irq_ticks=pulses,cpu_irq_input=irq,cpu_tick=cpu.local_ticks,
        cpu_output=output)
