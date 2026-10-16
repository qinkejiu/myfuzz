# Direct generated BoomTile runtime probe

The direct tile probe uses the captured 47-port generated `BoomTile`, including
its coherent A/B/C/D/E memory boundary. Its fixed reset address is 0x10040.
A sparse byte-addressed RAM supplies a reset trampoline and a program at
0x80000000. The program stores/loads cached RAM, reports the loaded value via
an uncached RAM address, and creates conflicting dirty lines to exercise
release writeback. No synthetic CPU master is substituted.

The RAM manager serializes responses, handles Get, PutFullData/PutPartialData,
AcquireBlock/AcquirePerm, Release/ReleaseData and GrantAck, and preserves source,
size and sink identities. No external coherent client exists, so B.valid is
held zero; the other B inputs are driven zero. The probe is an isolated RAM
manager calibration, not a claim of a general coherent interconnect adapter.

Run `g++ -std=c++17 tl_ram_test.cpp -o tl_ram_test && ./tl_ram_test` for the
host manager checks. They cover Get, masked and block Put, AcquireBlock,
AcquirePerm, ReleaseData, Release, GrantAck, bad sink rejection and D data
stability while a response is backpressured. Read responses snapshot their
data when accepted, so later RAM writes cannot change a stalled D payload.

`build_and_run.sh` records the exact build/run command for the build host.
It builds the generated tile and SRAM RTL using Verilator, then executes the
CPU probe under the shared heavy worker lock. The program uses explicit RV64
zero extension for its 32-bit physical RAM addresses. Two result stores target
0x4000 and 0x4008, uncached legal addresses in the generated tile's address
map. In this isolated probe they are RAM locations; the full Chipyard SoC maps
that range to its boot address register. The probe does not instantiate that
SoC register or claim an SoC boot.

`verify_trace.py <runtime.jsonl>` independently checks every accepted A/C/D/E
beat, source/size/opcode matching, response order, multibeat counts, grant sink
identity and GrantAck after the complete grant. The final pass additionally
requires both CPU result words and dirty RAM writeback to equal 0x123, and
all response, partial transfer and sink state to be drained. B stays inactive
because there are no other coherent clients. Probe handling is not exercised.

The recorded run in `../evidence/runtime-20261017/` passes after 555 cycles:
5 Get, 13 AcquireBlock, 2 Put, 10 ReleaseData, 156 D beats and 13 GrantAck.
