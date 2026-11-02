"""One-outstanding Wishbone DMA bridge using the shared host MemoryService."""
import hashlib
import json
import select
import subprocess
import uuid
from copy import deepcopy
from dataclasses import asdict
from pathlib import Path
from myfuzz.scenario.ledger import TransactionKey


class ZipDmaDriver:
    """One real Verilated ZipDMA process with one-step request/reply transport."""
    def __init__(self, binary, bridge):
        self.bridge = bridge
        self.process = subprocess.Popen([str(binary)], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, text=True, bufsize=1)
        self.ticks = 0
        if self._line() != 'READY':
            raise RuntimeError('ZipDMA driver did not become ready')

    def _line(self):
        if not select.select([self.process.stdout], [], [], 30)[0]:
            raise RuntimeError('ZipDMA driver response timeout')
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError('ZipDMA driver exited')
        return line.strip()

    def step(self, *, reset=0, cyc=0, stb=0, we=0, addr=0, data=0, sel=15):
        stall, ack, rdata, err = self.bridge.response()
        fields = (reset, cyc, stb, we, addr, data, sel, stall, ack, rdata, err)
        self.process.stdin.write('STEP ' + ' '.join(map(str, fields)) + '\n')
        self.process.stdin.flush()
        sample = json.loads(self._line())
        self.ticks += 1
        if ack:
            self.bridge.complete()
        if not reset and sample['cyc'] and sample['stb'] and not stall:
            self.bridge.accept(sample)
        return sample

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.write('EXIT\n')
            self.process.stdin.flush()
        self.process.stdin.close()
        rc = self.process.wait(timeout=10)
        self.process.stdout.close()
        if rc:
            raise RuntimeError('ZipDMA driver exit: ' + str(rc))
        return rc


def verify_sources(profile, root):
    files = tuple(Path(root) / name for name in profile['sources'])
    for path, digest in zip(files, profile['sources'].values()):
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('source mismatch: ' + str(path))
    return files


def zipdma_behavior(profile, root):
    """Return semantics for the pinned ZipDMA RTL, not arbitrary DMA profiles."""
    source_identity = hashlib.sha256(json.dumps(profile['sources'], sort_keys=True,
                                      separators=(',', ':')).encode()).hexdigest()
    if (source_identity != '19f767e6ca1dc2f00e70368d43ae4f83b8909e8aa6b4c5c9c6819896c2854e73'
            or profile.get('top') != 'zipdma'
            or profile.get('parameters') != {'ADDRESS_WIDTH': 32, 'SLV_WIDTH': 32,
                'BUS_WIDTH': 32, 'LGMEMLEN': 6, 'OPT_LITTLE_ENDIAN': 1}
            or profile.get('control_registers') != {'control': 0, 'source': 4,
                                                     'destination': 8, 'length_bytes': 12}
            or profile.get('control') != {'start': 0, 'clear_interrupt': 0x80000000,
                                           'error_mask': 0x40000000}):
        raise ValueError('ZipDMA behavior does not match pinned RTL')
    verify_sources(profile, root)
    return {'registers': dict(profile['control_registers']),
            'start': profile['control']['start'],
            'clear_interrupt': profile['control']['clear_interrupt'],
            'error_mask': profile['control']['error_mask'],
            'source_address_unit': 'bytes', 'destination_address_unit': 'bytes',
            'length_unit': 'bytes', 'irq': 'level_until_control_write',
            'source_manifest_sha256': source_identity}


class ZipDmaMemoryBridge:
    def __init__(self, service, *, execution_id='zipdma-smoke', testcase_id='copy',
                 source_component='dma', source_epoch=0):
        self.service = service
        self.execution_id = execution_id
        self.testcase_id = testcase_id
        self.source_component = source_component
        self.source_epoch = source_epoch
        self.pending = None
        self.events = []
        self.sequence = 0

    def response(self):
        return (0, 0, 0, 0) if self.pending is None else (1, 1, self.pending, 0)

    def complete(self):
        self.pending = None

    def accept(self, observed):
        if not observed['cyc'] or not observed['stb']:
            return
        if self.pending is not None:
            raise ValueError('one outstanding DMA request already exists')
        self.sequence += 1
        key = TransactionKey(self.execution_id, self.testcase_id, self.source_component,
                             self.source_epoch, 'dma-memory', self.sequence)
        address = observed['addr'] << 2
        if observed['we']:
            self.service.write(key, address, observed['data'], width_bytes=4,
                               byte_enable=observed['sel'])
            value = 0
        else:
            value = self.service.read(key, address, width_bytes=4).value
        self.events.append(dict(address=address, write=bool(observed['we']),
                                data=observed['data'] if observed['we'] else value,
                                sel=observed['sel']))
        self.pending = value


class ZipDmaTargetSession:
    """Expose real Wishbone control edges through the shared MMIO router API.

    The driver owns the actual RTL process and its DMA-master MemoryService
    bridge. This session is a composable register target, not an F6 admission.
    """
    routed_register_access_enabled = True

    def __init__(self, driver):
        self.driver = driver
        self.irq = 0
        self.control_events = []

    def _step(self, **kwargs):
        return self.driver.step(**kwargs)

    def step_local(self, inputs=None):
        if inputs not in (None, {}):
            raise ValueError('ZipDMA has no scheduler inputs')
        sample = self._step()
        self.irq = sample['irq']
        return {'irq': self.irq}

    def _register_access(self, offset, value, write, be):
        if type(offset) is not int or offset not in (0, 4, 8, 12):
            raise ValueError('ZipDMA control offset must be a 32-bit register')
        if type(be) is not int or not 1 <= be <= 15:
            raise ValueError('ZipDMA control byte enable must be nonzero')
        sample = self._step(cyc=1, stb=1, we=int(write), addr=offset // 4,
                            data=value, sel=be)
        if sample['control_stall'] or not sample['control_ack']:
            raise RuntimeError('ZipDMA control transaction not acknowledged')
        self.irq = sample['irq']
        self.control_events.append(dict(offset=offset, write=write, value=value,
                                        be=be, read_value=sample['control_data'],
                                        irq=self.irq))
        return sample['control_data']

    def write_register(self, offset, value, *, be=15):
        self._register_access(offset, value, True, be)

    def read_register(self, offset):
        return self._register_access(offset, 0, False, 15)

    def routed_register_access(self, key, *, address, offset, write, value, be,
                               delivery_context):
        """Expose the actual control edge for the router's source transaction."""
        rdata = self._register_access(offset, value, write, be)
        receipt = dict(source_transaction=asdict(key), address=address,
                       offset=offset, write=write, value=value, byte_enable=be,
                       delivery_context=deepcopy(delivery_context),
                       edge_ticks=[getattr(self, 'local_ticks', self.driver.ticks)])
        return dict(rdata=rdata, dma_control_receipt=receipt)


class ZipDmaScenarioSession(ZipDmaTargetSession):
    """ZipDMA process lifecycle and sampled edges for ScenarioRunner.

    The binary is the real standalone Verilator build; no component artifact or
    F6 authorization is invented. A caller supplies the shared MemoryService.
    """
    max_local_ticks_per_step = 1
    max_local_ticks_per_register_access = 1
    max_mmio_target_accesses_per_step = 0

    def __init__(self, binary, memory_service, *, source_component='dma'):
        super().__init__(None)
        self.binary = Path(binary)
        self.memory_service = memory_service
        self.memory = memory_service.memory
        self.service = memory_service
        self.source_component = source_component
        self.local_ticks = 0
        self.reset_epoch = 0
        self._samples = []
        self.startup_samples = []
        self.reset_samples = []
        self._execution = ''
        self._case_id = None
        self._bridge = None

    @property
    def pending_responses(self):
        return int(self._bridge is not None and self._bridge.pending is not None)

    def begin_case(self, testcase_id):
        if self.driver is not None or not testcase_id:
            raise ValueError('ZipDMA case must begin once')
        self._execution = uuid.uuid4().hex
        self._case_id = testcase_id
        self._bridge = ZipDmaMemoryBridge(self.memory_service, execution_id=self._execution,
            testcase_id=testcase_id, source_component=self.source_component)
        self.driver = ZipDmaDriver(self.binary, self._bridge)
        # Startup reset edges precede the local execution tick timeline.
        self.startup_samples = [self.driver.step(reset=1), self.driver.step(reset=1),
                                self.driver.step()]

    def _step(self, **kwargs):
        sample = self.driver.step(**kwargs)
        self.local_ticks += 1
        self._samples.append({'local_tick': self.local_ticks,
            'pre': {'irq': sample['irq_pre']}, 'post': {'irq': sample['irq']}})
        return sample

    def drain_tick_samples(self):
        samples, self._samples = tuple(self._samples), []
        return samples

    def reset_local(self):
        cancelled = self.pending_responses
        self._bridge.complete()
        reset_samples = [self._step(reset=1), self._step(reset=1), self._step()]
        self.reset_samples.extend(reset_samples)
        self.reset_epoch += 1
        self._bridge.source_epoch = self.reset_epoch
        self._bridge.sequence = 0
        # The runner records the reset barrier; don't route reset edges as a
        # post-barrier IRQ transition under the new epoch.
        self._samples.clear()
        self.irq = reset_samples[-1]['irq']
        return {'cancelled_responses': cancelled}

    def execution_identity(self):
        return {'pid': self.driver.process.pid, 'execution_nonce': self._execution,
                'reset_epoch': self.reset_epoch,
                'binary_sha256': hashlib.sha256(self.binary.read_bytes()).hexdigest()}

    def identity_document(self):
        return {'kind': 'zipdma_scenario_session.v1',
                'binary_sha256': hashlib.sha256(self.binary.read_bytes()).hexdigest(),
                'scope': 'real independent RTL driver; no F6 authority'}

    def end_case(self):
        if self.driver is not None:
            self.driver.close()
