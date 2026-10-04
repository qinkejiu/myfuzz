"""Persistent generated OpenTitan SPI Device local RTL session."""
from __future__ import annotations

from collections import deque
from collections.abc import Mapping

from .session import GeneratedLocalSession

_HALF_PERIOD = 8


class GeneratedOpentitanSpiDeviceSession(GeneratedLocalSession):
    artifact_kind = 'tlul_spi_device'
    max_local_ticks_per_step = 1

    def __init__(self, artifact, *, base_dir, cache_dir,
                 cpu_routed_mode: bool = False, **kwargs):
        super().__init__(artifact, base_dir=base_dir, cache_dir=cache_dir, **kwargs)
        if type(cpu_routed_mode) is not bool:
            raise ValueError('CPU-routed SPI Device mode must be boolean')
        if self._expected_ready()[3] != self.artifact_kind:
            raise ValueError('generated OpenTitan SPI Device requires tlul_spi_device artifact')
        wait = artifact.runtime_document['effective_max_wait_cycles']
        if type(wait) is not int or wait < 1:
            raise ValueError('invalid TL-UL SPI Device wait bound')
        self.max_local_ticks_per_register_access = 2 * wait + 5
        self.cpu_routed_mode = cpu_routed_mode
        self._samples: deque[dict[str, object]] = deque()
        self._pins = {'sck_i': 0, 'csb_i': 1, 'tpm_csb_i': 1, 'sd_i': 0}
        self._master_frame: int | None = None
        self._frame_done = False
        if cpu_routed_mode:
            # One upload frame is clocked with native mode-0 local SPI timing.
            self.max_local_ticks_per_step = 800

    def identity_document(self):
        identity = super().identity_document()
        identity.update(tlul_spi_device_service_schema_version=(
                            'generated_tlul_spi_device_service.v2'
                            if self.cpu_routed_mode else 'generated_tlul_spi_device_service.v1'),
                        source_component=self.artifact.plan.request.instance_id,
                        external_spi_mode='mode_0_single_bit_local_sck',
                        **({'cpu_routed_mode': True,
                            'source_mode': 'genome_one_upload_frame'}
                           if self.cpu_routed_mode else {}))
        return identity

    def validate_scenario_ownership(self, component, ownership) -> None:
        if not self.cpu_routed_mode:
            return
        if component != self.artifact.plan.request.instance_id:
            raise ValueError('CPU-routed SPI Device component identity mismatch')
        source = ownership.mutation_source(component, 'master_frame', 0, 32,
                                           direction='CPU_TO_IP_TO_CPU')
        if source != 'external_spi_master_frame':
            raise ValueError('CPU-routed SPI Device master frame source identity mismatch')

    def begin_case(self, testcase_id: str) -> None:
        super().begin_case(testcase_id)
        self._samples.clear()
        self._pins = {'sck_i': 0, 'csb_i': 1, 'tpm_csb_i': 1, 'sd_i': 0}
        self._master_frame = None
        self._frame_done = False

    @property
    def pending_events(self) -> int:
        return 0

    def begin_quiesce(self) -> None:
        if self.process is None or self.process.poll() is not None:
            raise RuntimeError('generated OpenTitan SPI Device process is not running')

    def _take(self, reply):
        if reply.status != 'result' or reply.payload is None:
            raise RuntimeError('generated OpenTitan SPI Device protocol error: ' + str(reply.error_code))
        payload = reply.payload
        samples = payload['samples']
        if len(self._samples) + len(samples) > 65536:
            raise RuntimeError('generated OpenTitan SPI Device tick evidence capacity exceeded')
        for sample in samples:
            for phase in ('pre', 'post'):
                row = sample[phase]
                for name, limit in (('sd_o', 16), ('sd_en_o', 16), ('irq_o', 256)):
                    value = row.get(name)
                    if type(value) is not int or not 0 <= value < limit:
                        raise ValueError('invalid native OpenTitan SPI Device output: ' + name)
            self._samples.append({**sample,
                                  'local_tick': self._tick_base + sample['local_tick']})
        return payload

    def drain_tick_samples(self):
        rows = list(self._samples)
        self._samples.clear()
        return rows

    def _fields(self):
        return tuple(self._pins[name] for name in ('sck_i', 'csb_i', 'tpm_csb_i', 'sd_i'))

    def step_local(self, inputs: Mapping[str, int]):
        if self.cpu_routed_mode:
            if not isinstance(inputs, Mapping) or set(inputs) - {'master_frame'}:
                raise ValueError('CPU-routed SPI Device accepts only genome master_frame')
            if 'master_frame' in inputs:
                frame = inputs['master_frame']
                if type(frame) is not int or not 0 <= frame <= 0xffffffff:
                    raise ValueError('SPI Device master frame must be a 32-bit value')
                if self._master_frame is not None and frame != self._master_frame:
                    raise ValueError('SPI Device master frame cannot change after transfer')
                if self._master_frame is None:
                    # Upload opcode 0x02 is configured through CPU-origin MMIO.
                    # No expected DUT response is injected here.
                    self._master_frame = frame
                    self.transfer_bytes(bytes((0x02,)) + frame.to_bytes(4, 'big'))
                    self._frame_done = True
            observed = self._take(self.command('STEP_TLUL_SPI_DEVICE', self._fields()))['observations']
            return {name: observed[name] for name in
                    ('sck_i', 'csb_i', 'tpm_csb_i', 'sd_i', 'sd_o', 'sd_en_o', 'irq_o')} | {
                        'master_frame_done': int(self._frame_done)}
        return self._step_pins(inputs)

    def _step_pins(self, inputs: Mapping[str, int]):
        if not isinstance(inputs, Mapping) or set(inputs) - set(self._pins):
            raise ValueError('undeclared OpenTitan SPI Device external input')
        limits = {'sck_i': 2, 'csb_i': 2, 'tpm_csb_i': 2, 'sd_i': 16}
        for name, value in inputs.items():
            if type(value) is not int or not 0 <= value < limits[name]:
                raise ValueError('invalid OpenTitan SPI Device external pin')
        self._pins.update(inputs)
        observed = self._take(self.command('STEP_TLUL_SPI_DEVICE', self._fields()))['observations']
        return {name: observed[name] for name in
                ('sck_i', 'csb_i', 'tpm_csb_i', 'sd_i', 'sd_o', 'sd_en_o', 'irq_o')}

    def drive_pins(self, sck: int, csb: int, mosi: int, cycles: int = 1):
        if type(cycles) is not int or not 1 <= cycles <= 32:
            raise ValueError('invalid local SPI phase length')
        observed = None
        for _ in range(cycles):
            observed = self._step_pins({'sck_i': sck, 'csb_i': csb,
                                        'tpm_csb_i': 1, 'sd_i': mosi})
        return observed

    def transfer_bytes(self, data: bytes, read_count: int = 0) -> bytes:
        if not isinstance(data, bytes) or not data:
            raise ValueError('SPI Device transfer requires command bytes')
        if type(read_count) is not int or not 0 <= read_count <= 4096:
            raise ValueError('SPI Device read count is out of range')
        if self._pins['csb_i'] == 0:
            raise RuntimeError('SPI Device transfer already has CS asserted')
        received = bytearray()
        self.drive_pins(0, 0, 0, _HALF_PERIOD)
        try:
            for sent in data + bytes(read_count):
                value = 0
                for shift in range(7, -1, -1):
                    bit = (sent >> shift) & 1
                    self.drive_pins(0, 0, bit, _HALF_PERIOD)
                    observed = self.drive_pins(1, 0, bit, _HALF_PERIOD)
                    miso = ((observed['sd_o'] >> 1) & 1) if observed['sd_en_o'] & 2 else 0
                    value = (value << 1) | miso
                received.append(value)
            self.drive_pins(0, 0, 0, _HALF_PERIOD)
        finally:
            self.drive_pins(0, 1, 0, _HALF_PERIOD)
        return bytes(received[len(data):])

    @staticmethod
    def _offset(offset: int) -> None:
        if type(offset) is not int or offset < 0 or offset > 8188 or offset % 4:
            raise ValueError('invalid OpenTitan SPI Device register offset')

    def write_register(self, offset: int, value: int, *, be: int = 15) -> None:
        self._offset(offset)
        if type(value) is not int or not 0 <= value <= 0xffffffff:
            raise ValueError('invalid OpenTitan SPI Device write value')
        if type(be) is not int or not 0 <= be <= 15:
            raise ValueError('invalid OpenTitan SPI Device byte enable')
        payload = self._take(self.command('ACCESS_TLUL_SPI_DEVICE',
                                          (*self._fields(), 1, offset, value, be)))
        if payload['error']:
            raise RuntimeError(f'OpenTitan SPI Device TL-UL write error at {offset:#x}')

    def read_register(self, offset: int) -> int:
        self._offset(offset)
        payload = self._take(self.command('ACCESS_TLUL_SPI_DEVICE',
                                          (*self._fields(), 0, offset, 0, 15)))
        if payload['error']:
            raise RuntimeError(f'OpenTitan SPI Device TL-UL read error at {offset:#x}')
        return payload['rdata']

    def reset_local(self):
        result = super().reset_local()
        self._samples.clear()
        self._pins = {'sck_i': 0, 'csb_i': 1, 'tpm_csb_i': 1, 'sd_i': 0}
        self._master_frame = None
        self._frame_done = False
        return result
