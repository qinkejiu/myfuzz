"""Pin level contract for the OpenTitan I2C external target peer."""

from myfuzz.scenario.i2c_peer import I2cPeer


class Host:
    def __init__(self, peer: I2cPeer):
        self.peer = peer
        self.tick(0, 0)

    def tick(self, scl_low: int, sda_low: int) -> tuple[int, int]:
        self.peer.observe(scl_en=scl_low, sda_en=sda_low)
        return self.peer.scl_i, self.peer.sda_i

    def start(self) -> None:
        self.tick(0, 0)
        self.tick(0, 1)
        self.tick(1, 1)

    def stop(self) -> None:
        self.tick(1, 1)
        self.tick(0, 1)
        self.tick(0, 0)

    def write_byte(self, value: int) -> int:
        for shift in range(7, -1, -1):
            low = 1 - ((value >> shift) & 1)
            self.tick(1, low)
            self.tick(0, low)
        self.tick(1, 0)
        _, ack = self.tick(0, 0)
        self.tick(1, 0)
        return ack

    def read_byte(self, *, ack: bool) -> int:
        value = 0
        for _ in range(8):
            self.tick(1, 0)
            _, bit = self.tick(0, 0)
            value = (value << 1) | bit
        self.tick(1, int(ack))
        self.tick(0, int(ack))
        self.tick(1, int(ack))
        return value


def test_address_ack_and_two_reads_survive_transaction_boundary():
    peer = I2cPeer(b"\xa5\x3c", address=0x50)
    host = Host(peer)

    host.start()
    assert host.write_byte(0xA1) == 0
    assert host.read_byte(ack=False) == 0xA5
    host.stop()

    host.start()
    assert host.write_byte(0xA1) == 0
    assert host.read_byte(ack=False) == 0x3C
    host.stop()

    assert peer.payload_index == 2
    assert peer.start_count == 2
    assert peer.stop_count == 2
    assert peer.ack_count == 2


def test_write_address_and_data_are_acked_and_recorded():
    peer = I2cPeer(address=0x42)
    host = Host(peer)
    host.start()
    assert host.write_byte(0x84) == 0
    assert host.write_byte(0x19) == 0
    assert host.write_byte(0xE7) == 0
    host.stop()
    assert peer.completed_writes == (b"\x19\xe7",)
    assert peer.ack_count == 3


def test_wrong_address_is_nacked_and_does_not_consume_payload():
    peer = I2cPeer(b"\x66", address=0x50)
    host = Host(peer)
    host.start()
    assert host.write_byte(0xA3) == 1
    host.stop()
    assert peer.payload_index == 0
    assert peer.ack_count == 0


def test_reset_case_rewinds_protocol_and_replaces_payload():
    peer = I2cPeer(b"\x12", address=0x50)
    host = Host(peer)
    host.start()
    assert host.write_byte(0xA1) == 0
    assert host.read_byte(ack=False) == 0x12
    host.stop()
    peer.reset_case(b"\x34")
    assert peer.payload_index == 0
    assert peer.start_count == 0
    assert peer.stop_count == 0
    host = Host(peer)
    host.start()
    assert host.write_byte(0xA1) == 0
    assert host.read_byte(ack=False) == 0x34


def test_target_only_changes_sda_during_scl_low_except_host_start_stop():
    peer = I2cPeer(b"\x80", address=0x50)
    host = Host(peer)
    host.start()
    assert host.write_byte(0xA1) == 0
    assert peer.scl_i == 0
    assert peer.sda_i == 1  # first read bit is already prepared
    assert host.read_byte(ack=False) == 0x80
    assert peer.start_count == 1
    assert peer.stop_count == 0


def test_repeated_start_closes_write_and_switches_to_read():
    peer = I2cPeer(b"\xd2", address=0x50)
    host = Host(peer)
    host.start()
    assert host.write_byte(0xA0) == 0
    assert host.write_byte(0x07) == 0
    host.tick(0, 0)
    host.start()
    assert host.write_byte(0xA1) == 0
    assert host.read_byte(ack=False) == 0xD2
    host.stop()
    assert peer.completed_writes == (b"\x07",)
    assert peer.sampled_bytes == (0xA0, 0x07, 0xA1)
    assert peer.start_count == 2
    assert peer.stop_count == 1


def test_empty_read_queue_nacks_address_until_payload_is_queued():
    peer = I2cPeer(address=0x50)
    host = Host(peer)
    host.start()
    assert host.write_byte(0xA1) == 1
    host.stop()
    peer.queue_payload(b"\x55")
    host.start()
    assert host.write_byte(0xA1) == 0
    assert host.read_byte(ack=False) == 0x55
    host.stop()
    assert peer.payload_index == 1


def test_wired_and_and_bounded_clock_stretch():
    peer = I2cPeer(b"\x80", address=0x50, stretch_cycles=2)
    host = Host(peer)
    host.start()
    # Host pulls both lines low for the address MSB.
    assert host.tick(1, 1) == (0, 0)
    assert not peer.peer_scl_low
    assert not peer.peer_sda_low
    # Releasing SCL starts a finite peer low interval, then the bit rises.
    assert host.tick(0, 1) == (0, 0)
    assert peer.peer_scl_low
    assert host.tick(0, 1) == (0, 0)
    assert host.tick(0, 1) == (1, 0)
    assert not peer.peer_scl_low
    # A host low always wins regardless of what the peer is doing.
    assert host.tick(1, 1) == (0, 0)
