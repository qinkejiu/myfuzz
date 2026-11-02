#!/usr/bin/env python3
"""Run a real ZipDMA RTL copy using the shared host memory service.

This is a standalone DMA smoke, not a CPU/F6 execution or a generic profile
admission. The pinned upstream RTL is never edited; one Verilator worker builds
an isolated driver, and the temporary build tree is removed after compilation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from myfuzz.local_harness.zipdma_smoke import (ZipDmaMemoryBridge, ZipDmaTargetSession, ZipDmaDriver as Driver,
                                              verify_sources, zipdma_behavior)
from myfuzz.scenario.ledger import TransactionKey, TransactionLedger
from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
from myfuzz.scenario.memory_service import MemoryService
from myfuzz.scenario.router import DataflowRouter, DeviceWindow

PROFILE = ROOT / 'configs/peripherals/zipdma_smoke/profile.json'
DRIVER = ROOT / 'src/myfuzz/local_harness/rtl/zipdma_smoke_driver.cpp'
SOURCE_ROOT = ROOT / 'third_party/soc-zipcpu'


def build(profile, output):
    sources = verify_sources(profile, SOURCE_ROOT)
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='myfuzz-zipdma-build-') as tmp:
        command = ['verilator', '--cc', '--exe', '--build', '-j', '1', '-Wno-fatal',
                   '--top-module', profile['top'], '--Mdir', tmp, '-o', 'harness']
        command.extend('-G' + name + '=' + str(value)
                       for name, value in profile['parameters'].items())
        command.extend(str(path) for path in sources)
        command.append(str(DRIVER))
        with (output / 'build.log').open('w') as log:
            subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True, cwd=ROOT)
        shutil.copy2(Path(tmp) / 'harness', output / 'harness')
    return time.monotonic() - start


def run(binary, profile):
    memory = PersistentMemory(regions=(MemoryRegion('ram', 0, 0x1000),),
                              initialization_seed=0, max_initialized_bytes=0x1000)
    words = (1, 2, 3, 4)
    memory.preload(0x100, b''.join(word.to_bytes(4, 'little') for word in words))
    bridge = ZipDmaMemoryBridge(MemoryService(memory, TransactionLedger()))
    driver = Driver(binary, bridge)
    target = ZipDmaTargetSession(driver)
    router = DataflowRouter((DeviceWindow('dma', 0x40001000, 16, target),))
    ledger = TransactionLedger()
    sequence = 0
    def control(offset, value=0, *, write=True):
        nonlocal sequence
        sequence += 1
        key = TransactionKey('zipdma-smoke', 'copy', 'host', 0, 'control', sequence)
        result, error = router.transact(ledger, key, address=0x40001000 + offset,
                                        write=write, wdata=value, be=15, beat_bytes=4)
        if error:
            raise RuntimeError('DMA control router returned an error')
        return result
    try:
        driver.step(reset=1)
        driver.step(reset=1)
        driver.step()
        csr = profile['control_registers']
        control(csr['source'], 0x100)
        control(csr['destination'], 0x200)
        control(csr['length_bytes'], 16)
        control(csr['control'], profile['control']['start'])
        for _ in range(2000):
            if target.step_local()['irq']:
                break
        else:
            raise RuntimeError('DMA completion interrupt not observed')
        copied = [memory.read(0x200 + 4*i, 4, transaction_id='verify').value for i in range(4)]
        reads = [e for e in bridge.events if not e['write']]
        writes = [e for e in bridge.events if e['write']]
        if (copied != list(words) or len(reads) != 4 or len(writes) != 4
                or any(e['sel'] != 15 for e in bridge.events)
                or [e['address'] for e in reads] != list(range(0x100, 0x110, 4))
                or [e['address'] for e in writes] != list(range(0x200, 0x210, 4))):
            raise RuntimeError('actual DMA transfer did not match four aligned words')
        status = control(csr['control'], write=False)
        if status & profile['control']['error_mask']:
            raise RuntimeError('DMA control read failed or reports error')
        control(csr['control'], profile['control']['clear_interrupt'])
        if target.irq or target.step_local()['irq']:
            raise RuntimeError('DMA interrupt did not clear')
        return {'status': 'verified', 'words': copied, 'ticks': driver.ticks,
                'irq_observed': True, 'irq_cleared': True, 'master_events': bridge.events,
                'control_events': target.control_events}
    finally:
        driver.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new result directory')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    profile = json.loads(PROFILE.read_text())
    behavior = zipdma_behavior(profile, SOURCE_ROOT)
    build_seconds = build(profile, args.output)
    result = run(args.output.resolve() / 'harness', profile)
    result.update(profile=str(PROFILE.relative_to(ROOT)), source_revision=profile['source_revision'],
                  source_sha256=profile['sources'], build_seconds=build_seconds,
                  behavior=behavior,
                  driver_sha256=hashlib.sha256(DRIVER.read_bytes()).hexdigest(),
                  binary_sha256=hashlib.sha256((args.output / 'harness').read_bytes()).hexdigest(),
                  scope='standalone ZipDMA RTL and host RAM; no CPU or F6 admission')
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'ticks': result['ticks']}))


if __name__ == '__main__':
    main()
