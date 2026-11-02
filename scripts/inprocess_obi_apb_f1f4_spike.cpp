// One initialized CPU, one register target, the host RAM and - when the selected
// component profiles provide them - a Wishbone DMA, the real interrupt outputs of
// the wired devices and the pins of a pin target.  Two axes come from the
// generated binding header, never from a component name:
//
//   * the CPU-side bus: an OBI CPU's two request channels (i and d) or a
//     Wishbone CPU's single cyc/stb/adr/we/sel master whose fetch/data identity
//     is the CPU's own mem_instr output (CPU_BUS_WISHBONE);
//   * the target side: the APB3 or AXI4-Lite bridge at its beat side, plus the
//     pin endpoint of a pin target, which the host drives and samples every tick
//     (HAVE_PINS).
//
// The CPU fetches and executes real instructions from host RAM; the target sees
// real transfers; the DMA master issues real Wishbone cycles against the same
// RAM, or - when the header declares `dma_route` - against the routed target's
// APB3 request port, where the master beat is held until the target answers and
// the routed address is never written to RAM; every interrupt line that is wired
// is sampled from the device's own output and delivered to the CPU input the CPU
// profile declares.  All of them
// are separate generated Verilator models: the address route, the RAM, the
// response timing and the IRQ delivery live in this host.
//
// What is wired is decided by the macros the binding header declares (which
// models were generated, and the I/O names of those models).  There is no
// CPU x IP identity branch here: the same loop drives every flow, and a flow the
// selected components cannot serve is refused by name instead of being guessed.
//
// When the header carries no DMA, no IRQ links and no pins (a bare F1-F4
// binding), every guarded block below compiles out and the loop is exactly the
// F1-F4 one.
#include "spike_config.h"
#include "verilated.h"
#include "inprocess_memory.h"
#include "inprocess_phase_clock.h"
#if CPU_BUS_AXI4
// The packed AXI4 CPU is driven through the repository's processor-side adapter
// by this reusable link.  The target/IP/DMA models remain separate Verilator
// instances in the same host tick.
#include "inprocess_axi4_host.h"
#endif
// Which object carries the RVFI retirement face.  An OBI or Wishbone CPU model
// exports the rvfi_* ports itself, so the object is the CPU model.  A packed
// AXI4 build (CVA6) exports a 6974-bit RVFI *probe bundle* instead, and the
// pinned scoreboard that turns it into records is a second Verilated model
// (`rvfi`); HAVE_RVFI_ADAPTER is 1 only when that model was built and linked.
#if CPU_BUS_AXI4
#define cpu_retirement rvfi
#else
#define cpu_retirement cpu
#endif
// Whether the retirement face exports the trap bit at all.  A header rendered
// before this declaration existed belongs to a build whose CPU did export it,
// so the historical 1 is the right default; the entry states 0 explicitly for a
// model that assigns only valid/order/insn/pc.
#ifndef HAVE_RVFI_TRAP_PORT
#define HAVE_RVFI_TRAP_PORT 1
#endif
#if CPU_BUS_AHB
#include "inprocess_ahb_identity.h"
#endif
#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <functional>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <vector>

#ifndef HAVE_DMA
#define HAVE_DMA 0
#endif
// Which CPU-side bus this build drives.  A header that declares neither keeps
// the OBI i/d host every saved binding before the Wishbone CPU expected.
#ifndef CPU_BUS_WISHBONE
#define CPU_BUS_WISHBONE 0
#endif
// A third CPU-side bus: an AHB-Lite CPU is the manager of one unified external
// bus.  The generated model already instantiates the subordinate adapter, so
// this host drives only the beat face (m_req_*/m_rsp_*) and reads the manager
// domain and the protocol taps; the fetch/data identity comes from the sampled
// address phase (HTRANS/HSEL/HPROT at manager HREADY), never from the address.
#ifndef CPU_BUS_AHB
#define CPU_BUS_AHB 0
#endif
#if CPU_BUS_WISHBONE && CPU_BUS_AHB
#error "one generated header cannot select two CPU buses"
#endif
#ifndef CPU_CUSTOM_IRQ
#define CPU_CUSTOM_IRQ 0
#endif
// The pin endpoint of a pin target, and the width the host resolves.  A register
// target without the endpoint keeps HAVE_PINS 0: no pad is driven or sampled and
// no case line gains a pad field.
#ifndef HAVE_PINS
#define HAVE_PINS 0
#endif
#ifndef PAD_WIDTH
#define PAD_WIDTH 32
#endif
#ifndef IP_PAD_EXT_DEFAULT
#define IP_PAD_EXT_DEFAULT 0u
#endif
#ifndef IP_PADIN_OFFSET
#define IP_PADIN_OFFSET 0u
#endif
#ifndef IP_PADOUT_OFFSET
#define IP_PADOUT_OFFSET 0xffffffffu
#endif
#ifndef IP_PADOUTSET_OFFSET
#define IP_PADOUTSET_OFFSET 0xffffffffu
#endif
#ifndef IP_PADOUTCLR_OFFSET
#define IP_PADOUTCLR_OFFSET 0xffffffffu
#endif
// A declared pad-group list, and a declared serial peer.  A behavior document may
// state its pads as an ordered list of named groups instead of the single ``pins``
// block; each group is either the dir-resolved pad word this host resolves or a
// framed serial peer.  The header states one row per pad group (name, declared
// direction, hold window and external driver word) and the peer's own timing and
// port bindings.  A declaration with no group list leaves all of it at zero and
// the historical single-pad path runs unchanged.
#ifndef HAVE_PIN_GROUPS
#define HAVE_PIN_GROUPS 0
#endif
#ifndef PIN_GROUP_COUNT
#define PIN_GROUP_COUNT 0
#endif
#define PIN_GROUP_ROW(name, direction, hold, ext) {name, direction, hold, ext},
// The one pad word this host resolves.  A group is either that word or a framed
// serial peer; the dir-resolved groups are the ones the table below states.
#define PIN_GROUP_KIND_WORD "dir_resolved_pad_word"
#ifndef PIN_GROUP_TABLE
#define PIN_GROUP_TABLE(X)
#endif
#ifndef HAVE_SERIAL_PEER
#define HAVE_SERIAL_PEER 0
#endif
// The peer's own frame code: 0 = 8n1, 1 = 8e1, 2 = 8o1.  The bit count follows
// from it (start + 8 data + parity + stop), so the driver's schedule and the
// sampler's frame check read one declaration.
#ifndef SERIAL_PEER_FRAME_CODE
#define SERIAL_PEER_FRAME_CODE 0
#endif
#ifndef SERIAL_PEER_FRAME_BITS
#define SERIAL_PEER_FRAME_BITS 10
#endif
#ifndef SERIAL_PEER_BIT_TICKS
#define SERIAL_PEER_BIT_TICKS 1
#endif
#ifndef SERIAL_PEER_IDLE_LEVEL
#define SERIAL_PEER_IDLE_LEVEL 1
#endif
#ifndef SERIAL_PEER_FRAME
#define SERIAL_PEER_FRAME "8n1"
#endif
#ifndef SERIAL_PEER_NAME
#define SERIAL_PEER_NAME "serial"
#endif
#ifndef HAVE_SERIAL_TX_EN
#define HAVE_SERIAL_TX_EN 0
#endif
#ifndef SERIAL_PEER_RX_PORT
#define SERIAL_PEER_RX_PORT __serial_peer_has_no_rx_port__
#endif
#ifndef SERIAL_PEER_TX_PORT
#define SERIAL_PEER_TX_PORT __serial_peer_has_no_tx_port__
#endif
#ifndef SERIAL_PEER_TX_EN_PORT
#define SERIAL_PEER_TX_EN_PORT __serial_peer_has_no_tx_en_port__
#endif
#ifndef CPU_IRQ_WIDTH
#define CPU_IRQ_WIDTH 1
#endif
#ifndef HAVE_IRQ_LINKS
#define HAVE_IRQ_LINKS 0
#endif
#ifndef HAVE_CPU_TAKE
#define HAVE_CPU_TAKE 0
#endif
#ifndef TRIGGER_COUNT
#define TRIGGER_COUNT 0
#endif
#ifndef DMA_BLOCK_WORDS
#define DMA_BLOCK_WORDS 0
#endif
// The declared shape of one F6 transfer, all of it rendered from the transfer
// plan (src/myfuzz/composition/dma_transfer.py).  A header that does not declare
// them keeps the historical full-word, zero-delay, one-beat-per-word host:
// DMA_MASTER_PARTIAL 0 makes a non-full master byte enable a refusal, and
// DMA_RESPONSE_DELAY 0 keeps mwb_stall/mwb_ack exactly as they were.
#ifndef DMA_MASTER_PARTIAL
#define DMA_MASTER_PARTIAL 0
#endif
#ifndef DMA_MASTER_BEATS_PER_WORD
#define DMA_MASTER_BEATS_PER_WORD 1
#endif
#ifndef DMA_MASTER_LANE_COUNT
#define DMA_MASTER_LANE_COUNT 1
#endif
#ifndef DMA_MASTER_LANES_PER_BEAT
#define DMA_MASTER_LANES_PER_BEAT 4
#endif
#ifndef DMA_RESPONSE_DELAY
#define DMA_RESPONSE_DELAY 0
#endif

// How many master responses this host holds at once (the plan's declared
// ``max_outstanding``).  The historical host served exactly one: from the accepted
// beat until its ack it held mwb_stall, so a device that presented a second
// request before the first was answered was stalled.  A *pipelined* master
// declares a deeper environment - the pinned wbdmac counts the requests it has
// presented (nracks/nwritten) separately from the acks it received (nread/nwacks),
// rtl/peripherals/wbdmac.v:410-456 - and this host then serves a ring of that many
// pending responses, holds mwb_stall only while the ring is full, and reports the
// peak it really reached.  1 is the default, and at 1 every historical case line is
// byte-for-byte what it always was.
#ifndef DMA_MASTER_OUTSTANDING
#define DMA_MASTER_OUTSTANDING 1
#endif
#if DMA_MASTER_OUTSTANDING < 1
#error "DMA_MASTER_OUTSTANDING must hold at least one response"
#endif
// The declared observation expectation, printed beside what was measured.  It is
// never used to manufacture an observation: a zero here means "not declared".
#ifndef DMA_STALL_EXPECT_MIN
#define DMA_STALL_EXPECT_MIN 0
#endif
#ifndef DMA_STALL_EXPECT_MAX
#define DMA_STALL_EXPECT_MAX 0
#endif
#ifndef DMA_EXPECTED_READS
#define DMA_EXPECTED_READS DMA_BLOCK_WORDS
#endif
#ifndef DMA_EXPECTED_WRITES
#define DMA_EXPECTED_WRITES DMA_BLOCK_WORDS
#endif
#ifndef DMA_DEST_SENTINEL
#define DMA_DEST_SENTINEL 0xa5a5a5a5u
#endif
// The declared DMA-to-target route (rendered by the entry from the transfer
// plan).  DMA_ROUTE_ENABLED 0 is the RAM-only master the previous increment ran:
// every routed block below compiles out and no case line gains a route field.
// An enabled route states one fixed destination, the taget that owns it, and the
// readable evidence word the F6 firmware samples before and after the transfer.
#ifndef DMA_ROUTE_ENABLED
#define DMA_ROUTE_ENABLED 0
#endif
#if DMA_ROUTE_ENABLED
#ifndef DMA_ROUTE_TARGET_INDEX
#error "a routed binding must declare DMA_ROUTE_TARGET_INDEX"
#endif
#ifndef DMA_ROUTE_TARGET_BASE
#error "a routed binding must declare DMA_ROUTE_TARGET_BASE"
#endif
#ifndef DMA_ROUTE_TARGET_SIZE
#define DMA_ROUTE_TARGET_SIZE 4096u
#endif
#ifndef DMA_ROUTE_ADDRESS
#error "a routed binding must declare DMA_ROUTE_ADDRESS"
#endif
#ifndef DMA_ROUTE_OFFSET
#error "a routed binding must declare DMA_ROUTE_OFFSET"
#endif
#ifndef DMA_ROUTE_FIXED
#define DMA_ROUTE_FIXED 1
#endif
#ifndef DMA_ROUTE_READ
#define DMA_ROUTE_READ 0
#endif
#ifndef DMA_ROUTE_EVIDENCE_OFFSET
#define DMA_ROUTE_EVIDENCE_OFFSET 0
#endif
#ifndef DMA_ROUTE_EVIDENCE_LOW
#define DMA_ROUTE_EVIDENCE_LOW 0
#endif
#ifndef DMA_ROUTE_EVIDENCE_HIGH
#define DMA_ROUTE_EVIDENCE_HIGH 0
#endif
#ifndef DMA_ROUTE_EVIDENCE_MASK
#define DMA_ROUTE_EVIDENCE_MASK 0u
#endif
#ifndef DMA_ROUTE_EVIDENCE_DEPTH
#define DMA_ROUTE_EVIDENCE_DEPTH 0
#endif
#ifndef DMA_ROUTE_BEFORE_ADDRESS
#define DMA_ROUTE_BEFORE_ADDRESS 0u
#endif
#ifndef DMA_ROUTE_AFTER_ADDRESS
#define DMA_ROUTE_AFTER_ADDRESS 0u
#endif
#ifndef DMA_ROUTE_RESET_BEFORE_CASE
#define DMA_ROUTE_RESET_BEFORE_CASE 1
#endif
#ifndef DMA_ROUTE_SENTINEL
#define DMA_ROUTE_SENTINEL 0xffffffffu
#endif
#ifndef DMA_ROUTE_PUSHES
#define DMA_ROUTE_PUSHES DMA_EXPECTED_WRITES
#endif
#ifndef DMA_ROUTE_READS
#define DMA_ROUTE_READS 0u
#endif
#ifndef DMA_ROUTE_DST_ADDRESS
#define DMA_ROUTE_DST_ADDRESS 0u
#endif
// The declared read shape.  DMA_ROUTE_FIFO marks a read route whose port pops
// on the read access itself: the level before the transfer is the declared beat
// count, the level after it is the declared zero, and each popped word is the
// declared expected word when the declaration states one.  DMA_ROUTE_APERTURE
// marks an incrementing read over a declared list of consecutive target
// addresses, each of which the master must present in order.
#ifndef DMA_ROUTE_FIFO
#define DMA_ROUTE_FIFO 0
#endif
#ifndef DMA_ROUTE_APERTURE
#define DMA_ROUTE_APERTURE 0
#endif
#ifndef DMA_ROUTE_LEVEL_BEFORE
#define DMA_ROUTE_LEVEL_BEFORE 0u
#endif
#ifndef DMA_ROUTE_LEVEL_AFTER
#define DMA_ROUTE_LEVEL_AFTER 0u
#endif
#ifndef DMA_ROUTE_EXPECT_WORD
#define DMA_ROUTE_EXPECT_WORD 0
#endif
#ifndef DMA_ROUTE_EXPECT_VALUE
#define DMA_ROUTE_EXPECT_VALUE 0u
#endif
#ifndef DMA_ROUTE_ERROR_BEAT
#define DMA_ROUTE_ERROR_BEAT -1
#endif
#ifndef DMA_ROUTE_APERTURE_COUNT
#define DMA_ROUTE_APERTURE_COUNT 0u
#endif
#ifndef DMA_ROUTE_APERTURE_ADDRESSES
#define DMA_ROUTE_APERTURE_ADDRESSES(X)
#endif
#ifndef DMA_ROUTE_APERTURE_ADDRESS
#define DMA_ROUTE_APERTURE_ADDRESS 0u
#endif
// The routed target's own adapter protocol, and whether this route prints the
// route-only protocol trace group.  A route on APB3 states TRACE 0 and keeps the
// case line it always printed; a TL-UL, Wishbone or AXI4-Lite route states its
// own wire and prints that wire's counters (it is the only sampler of a routed
// beat on that protocol, because the CPU MMIO trace group only counts the CPU's
// own transfers).
#ifndef DMA_ROUTE_PROTOCOL
#define DMA_ROUTE_PROTOCOL "none"
#endif
#ifndef DMA_ROUTE_TRACE
#define DMA_ROUTE_TRACE 0
#endif
#endif  // DMA_ROUTE_ENABLED
// Event-layer switches.  A header that does not declare them keeps the F1-F4
// entry byte-for-byte on its old behavior: no extra event lines and the old
// trap refusal.  The F1-F6 entry turns the layer on together with the model
// pins it needs, so an event is printed only when the model carries it.
#ifndef HAVE_EVENT_LAYER
#define HAVE_EVENT_LAYER 0
#endif
#ifndef HAVE_RVFI_WRITEBACK
#define HAVE_RVFI_WRITEBACK 0
#endif
#ifndef HAVE_RVFI_EXPANDED
#define HAVE_RVFI_EXPANDED 0
#endif
#ifndef HAVE_APB_PSLVERR
#define HAVE_APB_PSLVERR 0
#endif
// Which target bridge the header selected.  The target model is the same shape
// in both cases: a 'reg' beat channel this host serves, plus the passive taps of
// the slave port the declared bridge drives.  What differs is the protocol those
// taps show, and therefore what counts as one completed transfer:
//
//   APB3       psel, penable and pready in one pre-edge sample, pwrite selecting
//              the data direction, paddr/pwdata/prdata carrying the payload.
//   AXI4-Lite  AW and W each handshaking plus B completing the write, or AR plus
//              R completing the read; wstrb carrying the strobes and bresp/rresp
//              the response code.
//
// A header that declares neither keeps the APB3 section, which is what every
// binding rendered before the AXI4-Lite target existed expects.
#ifndef TARGET_PROTOCOL_APB3
#define TARGET_PROTOCOL_APB3 1
#endif
#ifndef TARGET_PROTOCOL_AXI4LITE
#define TARGET_PROTOCOL_AXI4LITE 0
#endif
// The two protocols this increment added to the one unified target engine.  A
// header rendered before them defines neither, so both default to 0 and every
// APB3/AXI4-Lite build compiles exactly as it did.
#ifndef TARGET_PROTOCOL_WISHBONE
#define TARGET_PROTOCOL_WISHBONE 0
#endif
#ifndef TARGET_PROTOCOL_TLUL
#define TARGET_PROTOCOL_TLUL 0
#endif
// The fifth target protocol the one unified target engine drives: an AHB-Lite
// subordinate port.  Its address phase and its data phase are separate edges and
// its completion is the target's own HREADYOUT, so the host samples two phases
// per transfer instead of one handshake sample.  A header rendered before this
// protocol existed defines nothing here, so every APB3/AXI4-Lite/Wishbone/TL-UL
// build compiles exactly as it did.
#ifndef TARGET_PROTOCOL_AHB
#define TARGET_PROTOCOL_AHB 0
#endif
// A mixed build states one protocol per target (TARGET_PROTOCOL_*_<n>, carried
// by the generated `IpTarget<n>` traits) and leaves all four build-wide macros
// neutral.  Nothing below may then read them as "the" protocol: every
// protocol-specific step is selected from the routed target's own trait, and
// these macros only spell the fallback a one-protocol header keeps using.
#ifndef TARGET_PROTOCOLS_MIXED
#define TARGET_PROTOCOLS_MIXED 0
#endif
// Whether a case line states the routed target's protocol word.  A mixed build
// always does; a Wishbone/TL-UL build does too because those protocols have no
// historical spelling to preserve.  A header rendered before this macro existed
// keeps the mixed-build meaning.
#ifndef TARGET_PROTOCOL_VERBOSE
#define TARGET_PROTOCOL_VERBOSE TARGET_PROTOCOLS_MIXED
#endif
#if !TARGET_PROTOCOLS_MIXED
#if (TARGET_PROTOCOL_APB3 + TARGET_PROTOCOL_AXI4LITE + TARGET_PROTOCOL_WISHBONE \
     + TARGET_PROTOCOL_TLUL + TARGET_PROTOCOL_AHB) != 1
#error "a generated one-protocol header must select exactly one target protocol"
#endif
#endif  // !TARGET_PROTOCOLS_MIXED
// Which protocols this build really contains, homogeneous or mixed.  A header
// rendered before these macros existed defines none of them, so a one-protocol
// build answers from its own TARGET_PROTOCOL_* macro exactly as it always did;
// a mixed build states its members here because all four of those macros are
// neutral for it.  Every protocol-specific sample, completion and print step
// below is guarded by one of the derived words, so a mixed build compiles and
// prints exactly the groups it has: an APB3 + Wishbone build prints no zero
// axi_* group, and the historical APB3 + AXI4-Lite pair keeps the exact case and
// summary lines it always printed.
#ifndef TARGET_MIXED_HAS_APB3
#define TARGET_MIXED_HAS_APB3 0
#endif
#ifndef TARGET_MIXED_HAS_AXI4LITE
#define TARGET_MIXED_HAS_AXI4LITE 0
#endif
#ifndef TARGET_MIXED_HAS_WISHBONE
#define TARGET_MIXED_HAS_WISHBONE 0
#endif
#ifndef TARGET_MIXED_HAS_TLUL
#define TARGET_MIXED_HAS_TLUL 0
#endif
#ifndef TARGET_MIXED_HAS_AHB
#define TARGET_MIXED_HAS_AHB 0
#endif
#define TARGET_HAS_APB3 (TARGET_PROTOCOL_APB3 != 0 || TARGET_MIXED_HAS_APB3 != 0)
#define TARGET_HAS_AXI4LITE \
  (TARGET_PROTOCOL_AXI4LITE != 0 || TARGET_MIXED_HAS_AXI4LITE != 0)
#define TARGET_HAS_WISHBONE \
  (TARGET_PROTOCOL_WISHBONE != 0 || TARGET_MIXED_HAS_WISHBONE != 0)
#define TARGET_HAS_TLUL (TARGET_PROTOCOL_TLUL != 0 || TARGET_MIXED_HAS_TLUL != 0)
#define TARGET_HAS_AHB (TARGET_PROTOCOL_AHB != 0 || TARGET_MIXED_HAS_AHB != 0)
// Exactly one sampled protocol group prints the shared neutral counter words
// (target_transfers and target_error) at the head of the protocol groups, so a
// build that samples several protocols never prints the same key twice.  A
// one-protocol build is its own group and is unchanged; the historical pair is
// the AXI4-Lite group, exactly as before.
#if TARGET_HAS_AXI4LITE
#define TARGET_NEUTRAL_COUNTERS_AXI 1
#define TARGET_NEUTRAL_COUNTERS_WB 0
#define TARGET_NEUTRAL_COUNTERS_TLUL 0
#define TARGET_NEUTRAL_COUNTERS_AHB 0
#elif TARGET_HAS_WISHBONE
#define TARGET_NEUTRAL_COUNTERS_AXI 0
#define TARGET_NEUTRAL_COUNTERS_WB 1
#define TARGET_NEUTRAL_COUNTERS_TLUL 0
#define TARGET_NEUTRAL_COUNTERS_AHB 0
#elif TARGET_HAS_TLUL
#define TARGET_NEUTRAL_COUNTERS_AXI 0
#define TARGET_NEUTRAL_COUNTERS_WB 0
#define TARGET_NEUTRAL_COUNTERS_TLUL 1
#define TARGET_NEUTRAL_COUNTERS_AHB 0
#elif TARGET_HAS_AHB
#define TARGET_NEUTRAL_COUNTERS_AXI 0
#define TARGET_NEUTRAL_COUNTERS_WB 0
#define TARGET_NEUTRAL_COUNTERS_TLUL 0
#define TARGET_NEUTRAL_COUNTERS_AHB 1
#else
#define TARGET_NEUTRAL_COUNTERS_AXI 0
#define TARGET_NEUTRAL_COUNTERS_WB 0
#define TARGET_NEUTRAL_COUNTERS_TLUL 0
#define TARGET_NEUTRAL_COUNTERS_AHB 0
#endif
// The protocol's name in a host message, and the channel name a sampled target
// error response belongs to.  Both are stated by the header, not guessed here.
#ifndef TARGET_NAME
#define TARGET_NAME "APB"
#endif
#ifndef TARGET_BUS_CHANNEL
#define TARGET_BUS_CHANNEL "apb"
#endif
// The bridge module the generated model instantiates.  A header rendered before
// the AXI4-Lite target existed states none, and its one target is the APB3 one.
#ifndef TARGET_BRIDGE
#define TARGET_BRIDGE "apb3_mmio_bridge"
#endif
// The spelling of each neutral target counter in the run log.  An APB3 build
// keeps the names its saved evidence already uses; an AXI4-Lite build prints the
// protocol-neutral name (and its per-channel axi_* counters beside it).
#ifndef KEY_TARGET_READS
#define KEY_TARGET_READS "apb_reads"
#endif
#ifndef KEY_TARGET_WRITES
#define KEY_TARGET_WRITES "apb_writes"
#endif
#ifndef KEY_TARGET_TRANSFERS
#define KEY_TARGET_TRANSFERS "apb_transfers"
#endif
#ifndef KEY_TARGET_ERRORS
#define KEY_TARGET_ERRORS "apb_errors"
#endif
#ifndef KEY_TARGET_READY
#define KEY_TARGET_READY "apb_pready"
#endif
#ifndef KEY_TARGET_OFFSET
#define KEY_TARGET_OFFSET "apb_offset"
#endif
#ifndef KEY_TARGET_WDATA
#define KEY_TARGET_WDATA "apb_pwdata"
#endif
#ifndef KEY_TARGET_RDATA
#define KEY_TARGET_RDATA "apb_rdata"
#endif
#ifndef KEY_TARGET_READ_OFFSET
#define KEY_TARGET_READ_OFFSET "apb_read_offset"
#endif
#ifndef KEY_TARGET_READ_DATA
#define KEY_TARGET_READ_DATA "apb_read_data"
#endif
#ifndef KEY_TARGET_LAST_WRITE_OFFSET
#define KEY_TARGET_LAST_WRITE_OFFSET "apb_last_write_offset"
#endif
#ifndef KEY_TARGET_LAST_WRITE_DATA
#define KEY_TARGET_LAST_WRITE_DATA "apb_last_write_data"
#endif
#ifndef KEY_READ_FROM_TARGET
#define KEY_READ_FROM_TARGET "apb"
#endif
// The constant inputs the target profile pins at a value (serial pins of a UART,
// for example).  They are applied once, before reset, from the header's own rows;
// a header without such rows compiles this to nothing.
#ifndef IP_FIXED_INPUT_COUNT
#define IP_FIXED_INPUT_COUNT 0
#endif
#ifndef IP_FIXED_INPUTS
#define IP_FIXED_INPUTS(X)
#endif
// Kind of the declared status word, taken from the profile's register name.
// It is printed verbatim as one token of the case line.
#ifndef IP_STATUS_KIND
#define IP_STATUS_KIND "undeclared"
#endif
#ifndef DMA_STATUS_KIND
#define DMA_STATUS_KIND "undeclared"
#endif
// Whether the declaration carries cause bits.  The timer does not, so the ISR
// read value is never a cause and the summary says so.
#ifndef IP_CAUSE_DECLARED
#define IP_CAUSE_DECLARED 0
#endif
#ifndef IP_CAUSE_MASK
#define IP_CAUSE_MASK 0u
#endif
// A declared ISR clear write is counted apart from the trigger sequence: the
// pass criterion checks both counts, so a clear can no longer make every
// triggered F5 case fail as an extra target write.
#ifndef IP_CLEAR_DECLARED
#define IP_CLEAR_DECLARED 0
#endif
#ifndef IP_CLEAR_OFFSET
#define IP_CLEAR_OFFSET 0u
#endif
#ifndef IP_CLEAR_VALUE
#define IP_CLEAR_VALUE 0u
#endif
#if IP_CLEAR_DECLARED
#define IP_CLEAR_COUNT 1u
#else
#define IP_CLEAR_COUNT 0u
#endif
// A declared DMA IRQ clear: the host expects a clear write only when the target
// declaration says one exists, and recognises it by the bit mask it declares.
#ifndef DMA_CLEAR_DECLARED
#define DMA_CLEAR_DECLARED 0
#endif
#ifndef DMA_CLEAR_MASK
#define DMA_CLEAR_MASK 0u
#endif
// Bit positions of the DMA control register's busy and error fields.  The
// selected profiles declare the register's side effect only, not its bit
// meanings; these defaults are the ZipDMA RTL ones (zipdma_ctrl.v:116-117) and
// the summary states that the bits are not declared by the profile.
#ifndef DMA_BUSY_BIT
#define DMA_BUSY_BIT 31
#endif
#ifndef DMA_ERR_BIT
#define DMA_ERR_BIT 30
#endif
// The per-case tick guard.  A case whose bounded F5/F6 wait is longer than
// this is reported as a host error rather than a device timeout; the value is
// declared per scenario because a slow CPU can spend tens of ticks per wait
// iteration.
#ifndef CASE_TICK_BUDGET
#define CASE_TICK_BUDGET 4000
#endif
// The boot address the CPU artifact declares for itself.  Only the AXI4 CVA6
// path uses it (to state its boot fetch as an observation); a header rendered by
// an entry that predates the macro keeps 0, which never equals a served address.
#ifndef CPU_BOOT_ADDRESS
#define CPU_BOOT_ADDRESS 0u
#endif
// The firmware entry point the image declares (the boot stub jumps here).  The
// AXI4 host reports the first fetch at or above this address as the observed
// hand-over from the boot stub to the firmware.
#ifndef CPU_MAIN_ADDRESS
#define CPU_MAIN_ADDRESS 0u
#endif
// The RAM cell the F6 body stores the pre-start control word in.
#ifndef DMA_CTL_BEFORE_ADDRESS
#define DMA_CTL_BEFORE_ADDRESS 0u
#endif
// How many 32-bit instruction words one F1 record may hand over.  The firmware
// reserves this many words plus the fixed return jump in the trampoline slot.
// The host writes the record's own words and then one return jump immediately
// after them, so a shorter program never runs the previous case's leftovers and
// a longer one overwrites the old return jump before it is fetched.
#ifndef F1_MAX_WORDS
#define F1_MAX_WORDS 1
#endif
// Whether an F1 program may use byte/halfword loads and stores.  The generated
// spike_config.h sets this from the scenario's f1_subword flag; a hand-built
// host keeps the legacy LW/SW-only gate.
#ifndef F1_ALLOW_SUBWORD
#define F1_ALLOW_SUBWORD 0
#endif
// Whether an F1 program may name a register other than x18 as a memory base.
// The generated spike_config.h sets this from the scenario's
// f1_allow_address_forms flag; a hand-built host keeps the legacy x18-only gate.
#ifndef F1_ALLOW_ADDRESS_FORMS
#define F1_ALLOW_ADDRESS_FORMS 0
#endif
// Whether an F1 program may carry strictly-forward B-type branches.  The
// generated spike_config.h sets this from the scenario's f1_allow_branches flag;
// a hand-built host keeps the historical straight-line-only gate.  With this
// set, the case's retirement evidence is the in-slot RVFI trace (count, order
// and the FNV-1a trace hash) rather than "every installed word retired".
#ifndef F1_ALLOW_BRANCHES
#define F1_ALLOW_BRANCHES 0
#endif
// Whether an F1 record word whose bits [1:0] are not ``11`` is *two 16-bit
// parcels* instead of one 32-bit instruction.  The generated spike_config.h sets
// this from the scenario's f1_allow_compressed flag; a hand-built host keeps the
// historical "one 32-bit word" gate.  With this set the low half executes at pc
// and the high half at pc + 2, a 32-bit instruction still occupies a whole record
// word (it may not straddle one), and the retirement evidence is the parcel/word
// trace: prog_retires counts instructions, a parcel steps 2 bytes and a 32-bit
// word steps 4, and the case prints the same prog_trace_hash/prog_trace_count/
// prog_pc_order the branch build prints, compared with the Python reference.
#ifndef F1_ALLOW_COMPRESSED
#define F1_ALLOW_COMPRESSED 0
#endif
// Whether an F1 program may carry JAL/JALR with a statically proven target.  The
// generated spike_config.h sets this from the scenario's f1_allow_jumps flag.  The
// link destination is x0 or x1, the target must be a strictly forward instruction
// start of the installed image (the appended return jump is the legal exit), and a
// JALR is admitted only when its base register is x0 or a register the program
// provably loads one exact constant into.
#ifndef F1_ALLOW_JUMPS
#define F1_ALLOW_JUMPS 0
#endif
// Whether an F1 program may carry the canonical bounded loop: `addi xN, x0, K`
// with K in 2..6, a body that never writes xN, `addi xN, xN, -1` and
// `bne xN, x0, head`.  The trip count is static, so the loop terminates; repeated
// PCs are legal in this mode and the host's retirement evidence is the exact
// reference trace (count and FNV-1a hash) rather than a strictly increasing PC
// order.
#ifndef F1_ALLOW_LOOPS
#define F1_ALLOW_LOOPS 0
#endif
// Whether the compressed parcel subset is widened with the six compressed control
// transfers (C.J/C.JAL/C.JR/C.JALR/C.BEQZ/C.BNEZ).  Every target must be a strictly
// forward instruction start of the image; C.JR/C.JALR need a proven constant base.
#ifndef F1_ALLOW_COMPRESSED_CONTROL
#define F1_ALLOW_COMPRESSED_CONTROL 0
#endif
// Whether the compressed parcel subset is widened with the four compressed word
// loads/stores (C.LW/C.SW/C.LWSP/C.SWSP).  The base register must be statically
// proven to hold an in-window data address.
#ifndef F1_ALLOW_COMPRESSED_MEMORY
#define F1_ALLOW_COMPRESSED_MEMORY 0
#endif
// Whether the case's retirement evidence is the reference trace rather than
// "every installed word retired".  Every opt-in control shape (branches, jumps,
// the bounded loop, compressed parcels) retires a sequence the Python reference
// trace decides, so the host prints and compares the same trace hash.  The two
// declared whole-record modes need it too: a trap program's ECALL retires with
// trap=1 (never "every installed word retired untrapped"), and an RV64 program's
// writebacks are 64-bit values the reference trace decides.
#ifndef F1_RV64
#define F1_RV64 0
#endif
#ifndef F1_TRAP_PROGRAM
#define F1_TRAP_PROGRAM 0
#endif
#define F1_TRACED (F1_ALLOW_BRANCHES || F1_ALLOW_JUMPS || F1_ALLOW_LOOPS \
                   || F1_ALLOW_COMPRESSED || F1_ALLOW_COMPRESSED_CONTROL \
                   || F1_ALLOW_COMPRESSED_MEMORY || F1_RV64 || F1_TRAP_PROGRAM)
// The address the trampoline return jump targets (the firmware's f1_back label).
#ifndef SLOT_RETURN
#define SLOT_RETURN 0u
#endif
// The declared program data window, in 32-bit words, starting at DATA_BASE.  The
// firmware points x18 at DATA_BASE before the jump; every program LW/SW uses it,
// and the host samples exactly this window before and after a case so a store is
// a sampled change rather than an inference.
#ifndef PROGRAM_DATA_WORDS
#define PROGRAM_DATA_WORDS 16
#endif
// Which sampled IRQ link is the DMA completion source.
#ifndef IRQ_DMA_LINK_INDEX
#define IRQ_DMA_LINK_INDEX 0xffffffffu
#endif
// A target may declare several IRQ links (v2 behavior); the F5 record names the
// link it triggers.  The flat IP_* facts above stay the first link for old
// headers and for the fields that are genuinely single-valued.
#ifndef IRQ_SOURCE_COUNT
#define IRQ_SOURCE_COUNT 0
#endif
#ifndef IRQ_TARGET_LINK_COUNT
#define IRQ_TARGET_LINK_COUNT 0
#endif
// A level source whose declared clear does not deassert the line makes the CPU
// re-enter the handler on every MRET, so the per-case tick budget would abort
// the whole batch with zero cases.  After this many accepted interrupts in one
// case, a declared level link that is still high is a reported storm: the case
// fails, only the devices are reset, and the line is never masked while the CPU
// runs.  A pulse source and a build with no declared target link never abort.
#ifndef IRQ_TAKE_LIMIT
#define IRQ_TAKE_LIMIT 4
#endif
#ifndef IRQ_LINK_STATUS_OFFSETS
#define IRQ_LINK_STATUS_OFFSETS 0u
#define IRQ_LINK_CAUSE_MASKS 0u
#define IRQ_LINK_CLEAR_DECLARED 0u
#define IRQ_LINK_CLEAR_OFFSETS 0u
#define IRQ_LINK_CLEAR_VALUES 0u
#define IRQ_LINK_CAUSE_DECLARED 0u
#define IRQ_LINK_TRIGGER_LAST 0u
#define IRQ_LINK_TRIGGER_COUNTS 0u
#define IRQ_LINK_STATUS_KINDS "undeclared"
#define IRQ_LINK_LEVEL 0u
#define IRQ_LINK_READ_CLEARS 0u
#define IRQ_LINK_CLEAR_COUNTS 0u
#define IRQ_LINK_CLEAR2_OFFSETS 0u
#define IRQ_LINK_CLEAR2_VALUES 0u
#endif
// How many ordered clear writes one link's acknowledge protocol declares, and
// the second step's own address/value.  A header rendered before the multi-step
// clear increment states one step per declared clear (0 = no clear) and zeros
// here, so the historical single-clear classification is exactly what it was.
#ifndef IRQ_CLEAR_STEPS
#define IRQ_CLEAR_STEPS 0u
#endif
// Whether this image's ISR clears the core's own mcause after the entry, which
// is what makes an interrupt take observable on a CPU with no probe port.  A
// header without it keeps the historical ISR byte for byte.
#ifndef IRQ_TAKE_CLEAR
#define IRQ_TAKE_CLEAR 0
#endif
// Which declared target each global link belongs to, and the window base that
// link's firmware body addresses.  The entry's one global link numbering covers
// every declaring target, so a legacy header without these tables keeps the
// historical single-target fallback (the first declaring target).
#ifndef IRQ_LINK_TARGETS
#define IRQ_LINK_TARGETS 0u
#endif
#ifndef IRQ_LINK_BASES
#define IRQ_LINK_BASES 0u
#endif
// The synthetic two-source F5 selection over the physical link table.  The
// generated header states it only when exactly two targets declare F5 with one
// link each; a header without one keeps IRQ_BOTH_ENABLED 0 and none of the
// arrays below are referenced.  The member rows are *physical* link indices, so
// every status/trigger/clear fact is still read from the one link table above.
#ifndef IRQ_BOTH_ENABLED
#define IRQ_BOTH_ENABLED 0
#endif
#if IRQ_BOTH_ENABLED
#ifndef IRQ_BOTH_LINK_INDEX
#define IRQ_BOTH_LINK_INDEX 0u
#endif
#ifndef IRQ_BOTH_MEMBER_COUNT
#define IRQ_BOTH_MEMBER_COUNT 0u
#endif
#ifndef IRQ_BOTH_LINKS
#define IRQ_BOTH_LINKS 0u
#endif
#ifndef IRQ_BOTH_WORDS
#define IRQ_BOTH_WORDS 0u
#endif
#ifndef IRQ_BOTH_TRIGGER_WORDS
#define IRQ_BOTH_TRIGGER_WORDS 0u
#endif
#ifndef IRQ_BOTH_TRIGGER_POSITIONS
#define IRQ_BOTH_TRIGGER_POSITIONS 0u
#endif
#ifndef IRQ_BOTH_TRIGGER_COUNTS
#define IRQ_BOTH_TRIGGER_COUNTS 0u
#endif
#ifndef IRQ_BOTH_TARGETS
#define IRQ_BOTH_TARGETS 0u
#endif
#ifndef IRQ_BOTH_CAUSE_MASKS
#define IRQ_BOTH_CAUSE_MASKS 0u
#endif
#ifndef IRQ_BOTH_CAUSE_DECLARED
#define IRQ_BOTH_CAUSE_DECLARED 0u
#endif
#ifndef IRQ_BOTH_CLEAR_DECLARED
#define IRQ_BOTH_CLEAR_DECLARED 0u
#endif
#ifndef IRQ_BOTH_CLEAR_OFFSETS
#define IRQ_BOTH_CLEAR_OFFSETS 0u
#endif
#ifndef IRQ_BOTH_CLEAR_VALUES
#define IRQ_BOTH_CLEAR_VALUES 0u
#endif
#ifndef IRQ_BOTH_LEVEL
#define IRQ_BOTH_LEVEL 0u
#endif
static constexpr unsigned kIrqBothMemberCount = IRQ_BOTH_MEMBER_COUNT;
static constexpr uint32_t kIrqBothLink[IRQ_BOTH_MEMBER_COUNT > 0 ? IRQ_BOTH_MEMBER_COUNT : 1] =
    { IRQ_BOTH_LINKS };
static constexpr uint32_t kIrqBothTriggerPosition[
    IRQ_BOTH_MEMBER_COUNT > 0 ? IRQ_BOTH_MEMBER_COUNT : 1] = { IRQ_BOTH_TRIGGER_POSITIONS };
static constexpr uint32_t kIrqBothTriggerCount[
    IRQ_BOTH_MEMBER_COUNT > 0 ? IRQ_BOTH_MEMBER_COUNT : 1] = { IRQ_BOTH_TRIGGER_COUNTS };
static constexpr uint32_t kIrqBothTarget[
    IRQ_BOTH_MEMBER_COUNT > 0 ? IRQ_BOTH_MEMBER_COUNT : 1] = { IRQ_BOTH_TARGETS };
static constexpr uint32_t kIrqBothCauseMask[
    IRQ_BOTH_MEMBER_COUNT > 0 ? IRQ_BOTH_MEMBER_COUNT : 1] = { IRQ_BOTH_CAUSE_MASKS };
static constexpr uint32_t kIrqBothCauseDeclared[
    IRQ_BOTH_MEMBER_COUNT > 0 ? IRQ_BOTH_MEMBER_COUNT : 1] = { IRQ_BOTH_CAUSE_DECLARED };
static constexpr uint32_t kIrqBothClearDeclared[
    IRQ_BOTH_MEMBER_COUNT > 0 ? IRQ_BOTH_MEMBER_COUNT : 1] = { IRQ_BOTH_CLEAR_DECLARED };
static constexpr uint32_t kIrqBothClearOffset[
    IRQ_BOTH_MEMBER_COUNT > 0 ? IRQ_BOTH_MEMBER_COUNT : 1] = { IRQ_BOTH_CLEAR_OFFSETS };
static constexpr uint32_t kIrqBothClearValue[
    IRQ_BOTH_MEMBER_COUNT > 0 ? IRQ_BOTH_MEMBER_COUNT : 1] = { IRQ_BOTH_CLEAR_VALUES };
static constexpr uint32_t kIrqBothLevel[
    IRQ_BOTH_MEMBER_COUNT > 0 ? IRQ_BOTH_MEMBER_COUNT : 1] = { IRQ_BOTH_LEVEL };
#endif
#ifndef IP_F5_TARGET_COUNT
#define IP_F5_TARGET_COUNT 1
#endif
#ifndef IP_F5_TARGET_MULTI
#define IP_F5_TARGET_MULTI 0
#endif
#ifndef DMA_IRQ_LEVEL
#define DMA_IRQ_LEVEL 0
#endif
#if IRQ_TARGET_LINK_COUNT > 0
static constexpr uint32_t kIrqLinkStatus[IRQ_TARGET_LINK_COUNT] = { IRQ_LINK_STATUS_OFFSETS };
static constexpr uint32_t kIrqLinkCauseMask[IRQ_TARGET_LINK_COUNT] = { IRQ_LINK_CAUSE_MASKS };
static constexpr uint32_t kIrqLinkClearDeclared[IRQ_TARGET_LINK_COUNT] = { IRQ_LINK_CLEAR_DECLARED };
static constexpr uint32_t kIrqLinkClearOffset[IRQ_TARGET_LINK_COUNT] = { IRQ_LINK_CLEAR_OFFSETS };
static constexpr uint32_t kIrqLinkClearValue[IRQ_TARGET_LINK_COUNT] = { IRQ_LINK_CLEAR_VALUES };
static constexpr uint32_t kIrqLinkClearCount[IRQ_TARGET_LINK_COUNT] = { IRQ_LINK_CLEAR_COUNTS };
static constexpr uint32_t kIrqLinkClear2Offset[IRQ_TARGET_LINK_COUNT] = { IRQ_LINK_CLEAR2_OFFSETS };
static constexpr uint32_t kIrqLinkClear2Value[IRQ_TARGET_LINK_COUNT] = { IRQ_LINK_CLEAR2_VALUES };
static constexpr uint32_t kIrqLinkCauseDeclared[IRQ_TARGET_LINK_COUNT] = { IRQ_LINK_CAUSE_DECLARED };
static constexpr uint32_t kIrqLinkTriggerLast[IRQ_TARGET_LINK_COUNT] = { IRQ_LINK_TRIGGER_LAST };
static constexpr uint32_t kIrqLinkTriggerCount[IRQ_TARGET_LINK_COUNT] = { IRQ_LINK_TRIGGER_COUNTS };
static constexpr uint32_t kIrqLinkLevel[IRQ_TARGET_LINK_COUNT] = { IRQ_LINK_LEVEL };
static constexpr uint32_t kIrqLinkReadClears[IRQ_TARGET_LINK_COUNT] = { IRQ_LINK_READ_CLEARS };
static constexpr uint32_t kIrqLinkTarget[IRQ_TARGET_LINK_COUNT] = { IRQ_LINK_TARGETS };
static constexpr uint32_t kIrqLinkBase[IRQ_TARGET_LINK_COUNT] = { IRQ_LINK_BASES };
static const char *const kIrqLinkStatusKind[IRQ_TARGET_LINK_COUNT] = { IRQ_LINK_STATUS_KINDS };
#endif
// How many independent MMIO target models this build instantiates, and which one
// owns the CPU's one interrupt line.  A header rendered before the multi-target
// integration states neither and keeps the historical one-target build.
#ifndef IP_COUNT
#define IP_COUNT 1
#endif
#ifndef IP_F5_TARGET_INDEX
#define IP_F5_TARGET_INDEX 0u
#endif
#ifndef IP_TARGETS_GENERATED
#define IP_TARGETS_GENERATED 0
#endif
#ifndef HAVE_IP_IRQ
#define HAVE_IP_IRQ 0
#endif
// The declared per-model clock plan.  One grid step is the reference CPU's half
// period and a model's half period is a whole number of those steps (the entry
// refuses any other ratio by name).  A header rendered before the phase
// scheduler describes one tick for every model, which is the ratio-1 plan, so a
// build with an older generated header still compiles and still runs.
#ifndef CLOCK_PLAN_MODE
#define CLOCK_PLAN_MODE "one_tick"
#endif
#ifndef CLOCK_REFERENCE_HZ
#define CLOCK_REFERENCE_HZ 0u
#endif
#ifndef CLOCK_GRID_PERIOD_PS
#define CLOCK_GRID_PERIOD_PS 0u
#endif
#ifndef CLOCK_REFERENCE_HALF_PERIOD_PS
#define CLOCK_REFERENCE_HALF_PERIOD_PS 0u
#endif
#ifndef TIMED_GRID_PS
#define TIMED_GRID_PS 0u
#endif
#ifndef CLOCK_CPU_HALF_TICKS
#define CLOCK_CPU_HALF_TICKS 1u
#endif
#ifndef CLOCK_IP_HALF_TICKS
#define CLOCK_IP_HALF_TICKS 1u
#endif
#ifndef CLOCK_DMA_HALF_TICKS
#define CLOCK_DMA_HALF_TICKS 1u
#endif
#ifndef HAVE_RVFI_INTR_PORT
#define HAVE_RVFI_INTR_PORT 0
#endif
#ifndef CPU_TAKE_WITNESS
#define CPU_TAKE_WITNESS "unexported"
#endif
#ifndef HAVE_CPU_TAKE_WITNESS
#define HAVE_CPU_TAKE_WITNESS 0
#endif
// The declared low-first per-model phase contract and the three per-tick sample
// gates live in one small header so the schedule arithmetic can be unit-tested
// without a model.  See scripts/inprocess_phase_clock.h.

// ---------------------------------------------------------------------------
// The per-target port traits
// ---------------------------------------------------------------------------
// One `IpTarget<I>` names the model class and every port the host touches for
// target I.  A multi-target header generates one specialization per declared
// target from that target's own generated binding, so the host loop below has no
// CPU x IP branch and no device name: swapping a target's profile changes only
// the generated header.  A one-target header rendered before the integration
// keeps the flat IP_* macros, and the fallback specialization below expresses
// exactly the same interface with them, so both builds run the same loop.
namespace myfuzz_ip {
template <unsigned I> struct IpTarget;
}

#if !IP_TARGETS_GENERATED
namespace myfuzz_ip {
template <> struct IpTarget<0> {
  using Model = IP_MODEL;
  // This target's own protocol, as the header states it.  A one-protocol build
  // reads the build-wide macros here; a mixed build never uses this fallback
  // specialization (IP_TARGETS_GENERATED is 1 and one specialization per target
  // is generated instead), so the two protocols are never conflated.
  static constexpr bool apb = TARGET_PROTOCOL_APB3 != 0;
  static constexpr bool axi4lite = TARGET_PROTOCOL_AXI4LITE != 0;
  static constexpr bool wishbone = TARGET_PROTOCOL_WISHBONE != 0;
  static constexpr bool tlul = TARGET_PROTOCOL_TLUL != 0;
  static constexpr bool ahb = TARGET_PROTOCOL_AHB != 0;
  static constexpr bool apb_error_sampled = HAVE_APB_PSLVERR != 0;
  static constexpr const char *protocol =
      TARGET_PROTOCOL_AXI4LITE != 0 ? "axi4-lite" :
      TARGET_PROTOCOL_WISHBONE != 0 ? "wishbone" :
      TARGET_PROTOCOL_TLUL != 0 ? "tl-ul" :
      TARGET_PROTOCOL_AHB != 0 ? "ahb-lite" : "apb3";
  static constexpr const char *name = TARGET_NAME;
  static constexpr const char *bridge = TARGET_BRIDGE;
  static constexpr const char *bus_channel = TARGET_BUS_CHANNEL;
  static constexpr unsigned fixed_input_count = IP_FIXED_INPUT_COUNT;
  static constexpr uint32_t base = IP_BASE;
  static constexpr uint32_t size = IP_SIZE;
  static constexpr unsigned reset_assert = IP_RESET_ASSERT;
  static constexpr unsigned reset_release = IP_RESET_RELEASE;
  static constexpr bool has_f5 = IRQ_TARGET_LINK_COUNT > 0;
  static constexpr bool has_irq = HAVE_IP_IRQ != 0;
  static void clock(Model &m, int level) { m.clk = level; }
  static void set_reset(Model &m, int level) { m.reset = level; }
  static void eval(Model &m) { m.eval(); }
  static void finalize(Model &m) { m.final(); }
  static bool events_pending(Model &m) { return m.eventsPending(); }
  // The time of this model's earliest scheduled event, read only when
  // events_pending() is true; an untimed model never schedules one.
  static uint64_t next_time_slot(Model &m) { return m.nextTimeSlot(); }
  static void fixed_inputs(Model &m) {
#define MYFUZZ_FIXED_INPUT(name, value) m.name = (value);
    IP_FIXED_INPUTS(MYFUZZ_FIXED_INPUT)
#undef MYFUZZ_FIXED_INPUT
  }
  static void drive_request(Model &m, bool valid, bool write, uint32_t address,
                            uint32_t value, unsigned be) {
    m.IP_REQ_VALID = valid;
    m.IP_REQ_WRITE = write;
    m.IP_REQ_ADDR = address;
    m.IP_REQ_WDATA = value;
    m.IP_REQ_BE = be;
    m.IP_RSP_READY = 1;
  }
  static bool request_ready(const Model &m) { return m.IP_REQ_READY; }
  static bool response_valid(const Model &m) { return m.IP_RSP_VALID; }
  static uint32_t response_rdata(const Model &m) { return m.IP_RSP_RDATA; }
  static bool response_error(const Model &m) { return m.IP_RSP_ERROR; }
#if HAVE_IP_IRQ
  static uint64_t irq_value(const Model &m) { return uint64_t(m.IP_IRQ); }
#endif
#if HAVE_PINS
  static uint32_t pin_in(const Model &m) { return uint32_t(m.IP_PIN_IN); }
  static uint32_t pin_out(const Model &m) { return uint32_t(m.IP_PIN_OUT); }
  static uint32_t pin_dir(const Model &m) { return uint32_t(m.IP_PIN_DIR); }
  static uint32_t pin_in_sync(const Model &m) { return uint32_t(m.IP_PIN_IN_SYNC); }
  static void set_pin_in(Model &m, uint32_t value) { m.IP_PIN_IN = value; }
  static uint32_t probe_padin_latch(const Model &m) {
    return uint32_t(m.IP_PROBE_PADIN_LATCH);
  }
  static uint32_t probe_rise(const Model &m) { return uint32_t(m.IP_PROBE_RISE); }
  static uint32_t probe_fall(const Model &m) { return uint32_t(m.IP_PROBE_FALL); }
  static uint32_t probe_inten(const Model &m) { return uint32_t(m.IP_PROBE_INTEN); }
  static uint32_t probe_status(const Model &m) { return uint32_t(m.IP_PROBE_STATUS); }
#endif
#if HAVE_SERIAL_PEER
  // The peer's two wires: a driven input and a sampled output, plus the device's
  // own transmit-enable indication when the profile declares it.  A build without
  // a declared peer names none of them and the host never touches these ports.
  static void set_serial_rx(Model &m, unsigned level) {
    m.SERIAL_PEER_RX_PORT = level & 1u;
  }
  static unsigned serial_tx(const Model &m) {
    return unsigned(m.SERIAL_PEER_TX_PORT) & 1u;
  }
#if HAVE_SERIAL_TX_EN
  static unsigned serial_tx_en(const Model &m) {
    return unsigned(m.SERIAL_PEER_TX_EN_PORT) & 1u;
  }
#endif
#endif
#if TARGET_PROTOCOL_AXI4LITE
  static bool axi_awvalid(const Model &m) { return m.IP_TRACE_AWVALID; }
  static bool axi_awready(const Model &m) { return m.IP_TRACE_AWREADY; }
  static uint32_t axi_awaddr(const Model &m) { return m.IP_TRACE_AWADDR; }
  static unsigned axi_awprot(const Model &m) { return m.IP_TRACE_AWPROT; }
  static bool axi_wvalid(const Model &m) { return m.IP_TRACE_WVALID; }
  static bool axi_wready(const Model &m) { return m.IP_TRACE_WREADY; }
  static uint32_t axi_wdata(const Model &m) { return m.IP_TRACE_WDATA; }
  static unsigned axi_wstrb(const Model &m) { return m.IP_TRACE_WSTRB; }
  static bool axi_bvalid(const Model &m) { return m.IP_TRACE_BVALID; }
  static bool axi_bready(const Model &m) { return m.IP_TRACE_BREADY; }
  static unsigned axi_bresp(const Model &m) { return m.IP_TRACE_BRESP; }
  static bool axi_arvalid(const Model &m) { return m.IP_TRACE_ARVALID; }
  static bool axi_arready(const Model &m) { return m.IP_TRACE_ARREADY; }
  static uint32_t axi_araddr(const Model &m) { return m.IP_TRACE_ARADDR; }
  static unsigned axi_arprot(const Model &m) { return m.IP_TRACE_ARPROT; }
  static bool axi_rvalid(const Model &m) { return m.IP_TRACE_RVALID; }
  static bool axi_rready(const Model &m) { return m.IP_TRACE_RREADY; }
  static uint32_t axi_rdata(const Model &m) { return m.IP_TRACE_RDATA; }
  static unsigned axi_rresp(const Model &m) { return m.IP_TRACE_RRESP; }
#elif TARGET_PROTOCOL_WISHBONE
  // A Wishbone classic target: the slave's own handshake pins.  The offset the
  // host reports is the slave's word address times four (the admitted template
  // variant is word-addressed), so the printed value is the byte offset of the
  // declared window the slave really decoded.
  static bool wb_cyc(const Model &m) { return bool(m.IP_TRACE_CYC); }
  static bool wb_stb(const Model &m) { return bool(m.IP_TRACE_STB); }
  static bool wb_ack(const Model &m) { return bool(m.IP_TRACE_ACK); }
  static bool wb_we(const Model &m) { return bool(m.IP_TRACE_WE); }
  static uint32_t wb_adr(const Model &m) { return uint32_t(m.IP_TRACE_ADR); }
  static uint32_t wb_dat_w(const Model &m) { return uint32_t(m.IP_TRACE_DAT_W); }
  static uint32_t wb_dat_r(const Model &m) { return uint32_t(m.IP_TRACE_DAT_R); }
  static unsigned wb_sel(const Model &m) { return unsigned(m.IP_TRACE_SEL); }
#ifdef IP_TRACE_STALL
  static constexpr bool wb_stall_sampled = true;
  static bool wb_stall(const Model &m) { return bool(m.IP_TRACE_STALL); }
#else
  static constexpr bool wb_stall_sampled = false;
#endif
#elif TARGET_PROTOCOL_AHB
  // An AHB-Lite target: the slave port's own address phase (hsel/htrans/haddr/
  // hwrite/hsize, completed by hreadyin) and its data phase (hwdata for a write,
  // hrdata/hresp for a read, completed by hreadyout).
  static bool ahb_hsel(const Model &m) { return bool(m.IP_TRACE_HSEL); }
  static unsigned ahb_htrans(const Model &m) { return unsigned(m.IP_TRACE_HTRANS); }
  static uint32_t ahb_haddr(const Model &m) { return uint32_t(m.IP_TRACE_HADDR); }
  static bool ahb_hwrite(const Model &m) { return bool(m.IP_TRACE_HWRITE); }
  static unsigned ahb_hsize(const Model &m) { return unsigned(m.IP_TRACE_HSIZE); }
  static uint32_t ahb_hwdata(const Model &m) { return uint32_t(m.IP_TRACE_HWDATA); }
  static bool ahb_hreadyin(const Model &m) { return bool(m.IP_TRACE_HREADYIN); }
  static bool ahb_hreadyout(const Model &m) { return bool(m.IP_TRACE_HREADYOUT); }
  static uint32_t ahb_hrdata(const Model &m) { return uint32_t(m.IP_TRACE_HRDATA); }
  static bool ahb_hresp(const Model &m) { return bool(m.IP_TRACE_HRESP); }
#elif TARGET_PROTOCOL_TLUL
  // A TL-UL target: the A channel the request was accepted on and the D channel
  // the response completed on.
  static bool tlul_a_valid(const Model &m) { return bool(m.IP_TRACE_A_VALID); }
  static bool tlul_a_ready(const Model &m) { return bool(m.IP_TRACE_A_READY); }
  static unsigned tlul_a_opcode(const Model &m) { return unsigned(m.IP_TRACE_A_OPCODE); }
  static uint32_t tlul_a_address(const Model &m) { return uint32_t(m.IP_TRACE_A_ADDRESS); }
  static unsigned tlul_a_mask(const Model &m) { return unsigned(m.IP_TRACE_A_MASK); }
  static uint32_t tlul_a_data(const Model &m) { return uint32_t(m.IP_TRACE_A_DATA); }
  static bool tlul_d_valid(const Model &m) { return bool(m.IP_TRACE_D_VALID); }
  static bool tlul_d_ready(const Model &m) { return bool(m.IP_TRACE_D_READY); }
  static uint32_t tlul_d_data(const Model &m) { return uint32_t(m.IP_TRACE_D_DATA); }
  static bool tlul_d_error(const Model &m) { return bool(m.IP_TRACE_D_ERROR); }
#else
  static bool apb_sel(const Model &m) { return m.IP_TRACE_PSEL; }
  static bool apb_enable(const Model &m) { return m.IP_TRACE_PENABLE; }
  static bool apb_ready(const Model &m) { return m.IP_TRACE_PREADY; }
  static bool apb_write(const Model &m) { return m.IP_TRACE_PWRITE; }
  static uint32_t apb_addr(const Model &m) { return m.IP_TRACE_PADDR; }
  static uint32_t apb_wdata(const Model &m) { return m.IP_TRACE_PWDATA; }
  static uint32_t apb_rdata(const Model &m) { return m.IP_TRACE_PRDATA; }
#if HAVE_APB_PSLVERR
  static bool apb_error(const Model &m) { return m.IP_TRACE_PSLVERR; }
#endif
#endif
};
}  // namespace myfuzz_ip
// The generated header states these two for every build; the fallback states
// them only for a header rendered before it did, so the two never collide.
#ifndef IP_MODEL_TYPES
#define IP_MODEL_TYPES std::unique_ptr<IP_MODEL>
#endif
#ifndef IP_MODEL_INSTANCES
#define IP_MODEL_INSTANCES(context) std::make_unique<IP_MODEL>((&context), "target")
#endif
#endif  // !IP_TARGETS_GENERATED


// Every target model of this build.  The generated header names the model types
// and constructs them; the host owns the tuple so one tick, one reset sequence
// and one finalize call reach all of them.
using IpModels = std::tuple<IP_MODEL_TYPES>;
// The first target keeps the historical alias name for the pads and for the flat
// macros an older header still expands inside IRQ_SOURCES.
static constexpr uint32_t kRamBase = RAM_BASE, kRamSize = RAM_SIZE;
static constexpr uint32_t kIpBase = myfuzz_ip::IpTarget<0>::base;
static constexpr uint32_t kIpSize = myfuzz_ip::IpTarget<0>::size;
// The level of every sampled target interrupt output, refreshed once per tick.
static uint64_t g_ip_irq[IP_COUNT > 0 ? IP_COUNT : 1] = {};
// The routing table is derived from the generated traits, not from a CPU x IP
// branch: target I owns [base, base+size), and an address outside every window
// belongs to RAM, the DMA control port or nobody.
template <unsigned I>
int ip_index_of_from(uint64_t address) {
  if constexpr (I >= IP_COUNT) {
    return -1;
  } else {
    const bool inside = address >= myfuzz_ip::IpTarget<I>::base
        && address - myfuzz_ip::IpTarget<I>::base
            <= uint64_t(myfuzz_ip::IpTarget<I>::size) - 4;
    if (inside) return int(I);
    return ip_index_of_from<I + 1>(address);
  }
}

inline int ip_index_of(uint64_t address) {
  return ip_index_of_from<0>(address);
}

template <unsigned I>
uint32_t ip_base_from(int index) {
  if constexpr (I >= IP_COUNT) {
    return 0;
  } else {
    if (index == int(I)) return myfuzz_ip::IpTarget<I>::base;
    return ip_base_from<I + 1>(index);
  }
}

inline uint32_t ip_base_of(int index) {
  return ip_base_from<0>(index);
}

template <unsigned I>
uint32_t ip_size_from(int index) {
  if constexpr (I >= IP_COUNT) {
    return 0;
  } else {
    if (index == int(I)) return myfuzz_ip::IpTarget<I>::size;
    return ip_size_from<I + 1>(index);
  }
}

inline uint32_t ip_size_of(int index) {
  return ip_size_from<0>(index);
}

template <unsigned I>
bool ip_has_irq_from(int index) {
  if constexpr (I >= IP_COUNT) {
    return false;
  } else {
    if (index == int(I)) return myfuzz_ip::IpTarget<I>::has_irq;
    return ip_has_irq_from<I + 1>(index);
  }
}

inline bool ip_has_irq(int index) {
  return ip_has_irq_from<0>(index);
}

template <unsigned I>
bool ip_has_f5_from(int index) {
  if constexpr (I >= IP_COUNT) {
    return false;
  } else {
    if (index == int(I)) return myfuzz_ip::IpTarget<I>::has_f5;
    return ip_has_f5_from<I + 1>(index);
  }
}

// Whether this target declares at least one F5 link, and whether any of its
// links is wired into the CPU's one external IRQ input.  A target that exposes a
// real interrupt output but declares no link is observed and stated as
// observe-only; the two facts are separate on purpose.
inline bool ip_has_f5(int index) {
  return ip_has_f5_from<0>(index);
}

inline bool ip_irq_delivered(int index) {
#if IRQ_TARGET_LINK_COUNT > 0
  for (unsigned link = 0; link < unsigned(IRQ_TARGET_LINK_COUNT); ++link)
    if (int(kIrqLinkTarget[link]) == index) return true;
#else
  (void)index;
#endif
  return false;
}

// Which protocol the routed target speaks.  A one-protocol build folds this to a
// constant; a mixed build answers per target from the traits, which is what makes
// the trace sample, the completion criterion and the case-line words per-target
// instead of per-build.  ``-1`` (a RAM-only case) speaks neither.
template <unsigned I>
bool ip_axi4lite_from(int index) {
  if constexpr (I >= IP_COUNT) {
    (void)index;
    return false;
  } else {
    if (index == int(I)) return myfuzz_ip::IpTarget<I>::axi4lite;
    return ip_axi4lite_from<I + 1>(index);
  }
}

inline bool ip_is_axi4lite(int index) {
  return index >= 0 && ip_axi4lite_from<0>(index);
}

template <unsigned I>
bool ip_wishbone_from(int index) {
  if constexpr (I >= IP_COUNT) {
    (void)index;
    return false;
  } else {
    if (index == int(I)) return myfuzz_ip::IpTarget<I>::wishbone;
    return ip_wishbone_from<I + 1>(index);
  }
}

inline bool ip_is_wishbone(int index) {
  return index >= 0 && ip_wishbone_from<0>(index);
}

template <unsigned I>
bool ip_tlul_from(int index) {
  if constexpr (I >= IP_COUNT) {
    (void)index;
    return false;
  } else {
    if (index == int(I)) return myfuzz_ip::IpTarget<I>::tlul;
    return ip_tlul_from<I + 1>(index);
  }
}

inline bool ip_is_tlul(int index) {
  return index >= 0 && ip_tlul_from<0>(index);
}

template <unsigned I>
bool ip_ahb_from(int index) {
  if constexpr (I >= IP_COUNT) {
    (void)index;
    return false;
  } else {
    if (index == int(I)) return myfuzz_ip::IpTarget<I>::ahb;
    return ip_ahb_from<I + 1>(index);
  }
}

inline bool ip_is_ahb(int index) {
  return index >= 0 && ip_ahb_from<0>(index);
}

template <unsigned I>
const char *ip_protocol_from(int index) {
  if constexpr (I >= IP_COUNT) {
    (void)index;
    return "unknown";
  } else {
    if (index == int(I)) return myfuzz_ip::IpTarget<I>::protocol;
    return ip_protocol_from<I + 1>(index);
  }
}

template <unsigned I>
const char *ip_channel_from(int index) {
  if constexpr (I >= IP_COUNT) {
    (void)index;
    return "unknown";
  } else {
    if (index == int(I)) return myfuzz_ip::IpTarget<I>::bus_channel;
    return ip_channel_from<I + 1>(index);
  }
}

// The channel a sampled error of this target belongs to, and its operator-facing
// protocol/bridge words.  They are the traits' own declarations, so a mixed
// build prints "apb"/"axi" per transfer instead of one build-wide word and a
// Wishbone/TL-UL build prints its own name.
inline const char *ip_bus_channel(int index) {
  return index < 0 ? "unknown" : ip_channel_from<0>(index);
}

inline const char *ip_protocol_word(int index) {
  return index < 0 ? "none" : ip_protocol_from<0>(index);
}

template <unsigned I>
const char *ip_bridge_from(int index) {
  if constexpr (I >= IP_COUNT) {
    (void)index;
    return "unknown";
  } else {
    if (index == int(I)) return myfuzz_ip::IpTarget<I>::bridge;
    return ip_bridge_from<I + 1>(index);
  }
}

inline const char *ip_bridge_of(int index) {
  return index < 0 ? "unknown" : ip_bridge_from<0>(index);
}

// How many pin constants this target's own generated request pinned.  A
// one-target build answers with the historical flat count.
template <unsigned I>
unsigned ip_fixed_inputs_from(int index) {
  if constexpr (I >= IP_COUNT) {
    (void)index;
    return 0u;
  } else {
    if (index == int(I)) return myfuzz_ip::IpTarget<I>::fixed_input_count;
    return ip_fixed_inputs_from<I + 1>(index);
  }
}

inline unsigned ip_fixed_input_count(int index) {
  return index < 0 ? 0u : ip_fixed_inputs_from<0>(index);
}

// The F5 handler addresses its own target's window; a build without an F5 target
// keeps the first window under the historical name (F5 is refused there).
static const uint32_t kIrqTargetBase =
    IP_F5_TARGET_INDEX == 0xffffffffu ? kIpBase
                                      : ip_base_of(int(IP_F5_TARGET_INDEX));

// Visit every target model with both its runtime index and its compile-time
// index, so a per-target trait can name ports without a CPU x IP branch.
template <typename Tuple, typename Fn, std::size_t... I>
void for_each_ip_impl(Tuple &models, Fn &fn, std::index_sequence<I...>) {
  (fn(std::integral_constant<unsigned, unsigned(I)>{}, *std::get<I>(models)), ...);
}

template <typename Tuple, typename Fn>
void for_each_ip(Tuple &models, Fn &&fn) {
  for_each_ip_impl(models, fn,
                   std::make_index_sequence<std::tuple_size<Tuple>::value>{});
}

#if HAVE_DMA
static constexpr uint32_t kDmaBase = DMA_BASE, kDmaSize = DMA_SIZE;
static constexpr uint32_t kDmaControlOffset = DMA_CONTROL_OFFSET;
static constexpr uint32_t kDmaStartWord = DMA_START_WORD;
static constexpr uint32_t kDmaSourceBase = DMA_SOURCE, kDmaDestinationBase = DMA_DESTINATION;
static constexpr unsigned kDmaBlockWords = DMA_BLOCK_WORDS;
static constexpr uint32_t kDmaResult = DMA_RESULT_ADDRESS;
static constexpr uint32_t kDmaCtlBefore = DMA_CTL_BEFORE_ADDRESS;
// The master-response ring depth this build serves, and the channel/beat facts
// the case line states so a reader can tell which DMA device and which channel a
// transfer belongs to (a device with one channel reports channel 0).
static constexpr unsigned kDmaOutstanding = DMA_MASTER_OUTSTANDING;
#ifndef DMA_DEVICE_CHANNELS
#define DMA_DEVICE_CHANNELS 1
#endif
#ifndef DMA_DEVICE_BEAT_BYTES
#define DMA_DEVICE_BEAT_BYTES 4
#endif
#ifndef DMA_DEVICE_FAMILY
#define DMA_DEVICE_FAMILY "zipdma"
#endif
// Whether this build's F6 case line states the device/channel/beat group.  The
// historical ZipDMA shape (one channel, a four-byte beat, one response in flight)
// prints none of it, because every saved ZipDMA F6 case line has to stay
// byte-for-byte what it was; any other device or any deeper shape prints the
// group, so a line can never be read as if the ZipDMA had produced it.
#ifndef DMA_DEVICE_REPORTED
#define DMA_DEVICE_REPORTED 0
#endif
#if DMA_ROUTE_ENABLED
// The one declared route this build executes.  The address, the target offset
// and the evidence field are the plan's values; nothing here is derived.
static constexpr unsigned kDmaRouteTargetIndex = DMA_ROUTE_TARGET_INDEX;
static constexpr uint32_t kDmaRouteTargetBase = DMA_ROUTE_TARGET_BASE;
static constexpr uint32_t kDmaRouteAddress = DMA_ROUTE_ADDRESS;
static constexpr uint32_t kDmaRouteOffset = DMA_ROUTE_OFFSET;
static constexpr bool kDmaRouteFixed = DMA_ROUTE_FIXED != 0;
static constexpr uint32_t kDmaRouteEvidenceOffset = DMA_ROUTE_EVIDENCE_OFFSET;
static constexpr unsigned kDmaRouteEvidenceLow = DMA_ROUTE_EVIDENCE_LOW;
static constexpr unsigned kDmaRouteEvidenceHigh = DMA_ROUTE_EVIDENCE_HIGH;
static constexpr uint32_t kDmaRouteEvidenceMask = DMA_ROUTE_EVIDENCE_MASK;
static constexpr unsigned kDmaRouteEvidenceDepth = DMA_ROUTE_EVIDENCE_DEPTH;
static constexpr uint32_t kDmaRouteBefore = DMA_ROUTE_BEFORE_ADDRESS;
static constexpr uint32_t kDmaRouteAfter = DMA_ROUTE_AFTER_ADDRESS;
static constexpr bool kDmaRouteResetBeforeCase = DMA_ROUTE_RESET_BEFORE_CASE != 0;
static constexpr uint32_t kDmaRouteSentinel = DMA_ROUTE_SENTINEL;
// The prefill every per-case route evidence cell starts from.  It has to differ
// from every word the route may legitimately leave there, otherwise "the cell
// still holds the prefill" cannot mean "the firmware never wrote it".  When the
// declared expected word *is* the route sentinel (a FIFO whose port returns
// 0xffffffff) the prefill moves to the destination-block sentinel instead.
static constexpr uint32_t kDmaRouteCellPrefill =
    (DMA_ROUTE_EXPECT_WORD != 0 && DMA_ROUTE_EXPECT_VALUE == DMA_ROUTE_SENTINEL)
        ? 0xa5a5a5a5u : kDmaRouteSentinel;
static constexpr unsigned kDmaRoutePushes = DMA_ROUTE_PUSHES;
#if DMA_ROUTE_READ
static constexpr unsigned kDmaRouteReads = DMA_ROUTE_READS;
static constexpr uint32_t kDmaRouteDst = DMA_ROUTE_DST_ADDRESS;
#endif
// The declared read shape: a FIFO read states its level bounds and the word the
// popped entries must carry, an aperture read states the target address of every
// routed beat, and either may declare one beat whose master response is an error.
// These are declared for every routed build (a write route declares none of them)
// because the routed-beat detection reads the aperture table, not only the read
// path.
static constexpr bool kDmaRouteFifo = DMA_ROUTE_FIFO != 0;
static constexpr bool kDmaRouteAperture = DMA_ROUTE_APERTURE != 0;
static constexpr unsigned kDmaRouteLevelBefore = DMA_ROUTE_LEVEL_BEFORE;
static constexpr unsigned kDmaRouteLevelAfter = DMA_ROUTE_LEVEL_AFTER;
static constexpr bool kDmaRouteExpectWord = DMA_ROUTE_EXPECT_WORD != 0;
static constexpr uint32_t kDmaRouteExpectValue = DMA_ROUTE_EXPECT_VALUE;
static constexpr int kDmaRouteErrorBeat = DMA_ROUTE_ERROR_BEAT;
static constexpr unsigned kDmaRouteApertureCount = DMA_ROUTE_APERTURE_COUNT;
static constexpr uint32_t kDmaRouteApertureCells = DMA_ROUTE_APERTURE_ADDRESS;
static constexpr uint32_t kDmaRouteApertureAddress[
    kDmaRouteApertureCount > 0 ? kDmaRouteApertureCount : 1] = {
#define MYFUZZ_APERTURE_ADDRESS(index, address) address,
  DMA_ROUTE_APERTURE_ADDRESSES(MYFUZZ_APERTURE_ADDRESS)
#undef MYFUZZ_APERTURE_ADDRESS
};
// The routed target's own wire protocol and whether the route prints its own
// protocol trace.  Both are the declaration's facts (the entry renders them from
// the routed target artifact), never a build-wide assumption.
static constexpr const char *kDmaRouteProtocol = DMA_ROUTE_PROTOCOL;
static constexpr bool kDmaRouteTrace = DMA_ROUTE_TRACE != 0;
#endif
#endif
static constexpr uint32_t kSlot = SLOT_ADDRESS;
static constexpr uint32_t kCommand = MAILBOX_ADDRESS;
static constexpr uint32_t kArgument = MAILBOX_ADDRESS + 4;
static constexpr uint32_t kEcho = MAILBOX_ADDRESS + 8;
static constexpr uint32_t kValue = MAILBOX_ADDRESS + 12;
static constexpr uint32_t kInput = MAILBOX_ADDRESS + 16;
static constexpr uint32_t kDataBase = DATA_BASE;
#if HAVE_IRQ_LINKS
static constexpr uint32_t kIpStatusOffset = IP_STATUS_OFFSET;
static constexpr uint32_t kIpResult = IP_RESULT_ADDRESS;
// The second result cell of a two-source F5 ISR.  A header rendered by an entry
// that does not build that image states no address; the fallback is the layout's
// fixed +28 cell and is only ever read inside the IRQ_BOTH_ENABLED branch.
#ifndef IP_RESULT2_ADDRESS
#define IP_RESULT2_ADDRESS (IP_RESULT_ADDRESS + 28u)
#endif
static constexpr uint32_t kIpResult2 = IP_RESULT2_ADDRESS;
static constexpr uint32_t kFlagAddress = FLAG_ADDRESS;
#endif

using myfuzz::inprocess_spike::Memory;
using myfuzz::inprocess_spike::Response;

namespace {

// Quiet mode (``--quiet``): the per-tick and per-transaction event lines are the
// detailed evidence layer; a long fuzz batch wants one case line each, so they
// are suppressed at runtime instead of being written and then thrown away.  The
// case and summary lines are never suppressed, so a quiet run is still parseable
// by the same reader.
bool g_events = true;

// Every event print goes through this token so one flag controls them all.  It
// expands to ``if (g_events) std::cout`` and is only ever used as a statement
// head, never inside a comma or a condition.
#define EVENT_STREAM if (g_events) std::cout

// One APB3 request started by a real CPU data beat.  The address is the CPU's
// own byte address; the target offset is derived from the declared window.
struct Mmio {
  bool busy = false, sent = false, write = false;
  uint32_t address = 0, value = 0;
  unsigned be = 0;
  // The declared target window this request was routed to.  Only that model is
  // driven with the request; every other target stays at req_valid 0 for it.
  unsigned target = 0;
};

// The AXI4-Lite channel handshake counters as they stood when one CPU MMIO
// request was accepted by its target.  A completion criterion is "this request
// completed one AW+W+B (or AR+R)", so it is a delta from this mark, not the
// case-wide total: a DMA route case legitimately reads the same target twice in
// one case (the declared evidence word before and after the routed transfer),
// and a case-wide "exactly one" would reject its second read as a defect even
// though both transactions completed on the target's own channels.
struct AxiMark {
  unsigned aw = 0, w = 0, b = 0, ar = 0, r = 0;
};

inline AxiMark axi_mark_of(unsigned aw, unsigned w, unsigned b, unsigned ar,
                           unsigned r) {
  AxiMark mark;
  mark.aw = aw; mark.w = w; mark.b = b; mark.ar = ar; mark.r = r;
  return mark;
}

// The per-target transfer counters this case saw.  The global observation fields
// keep their historical meaning (the one target the case was routed to), and
// these arrays make "the other IP did not move" a printed fact.
struct TargetCounters {
  unsigned reads = 0, writes = 0;
  uint32_t last_offset = 0, last_data = 0;
  bool ready = false;
  // The two-source F5 evidence, per target: the last completed read's offset and
  // data (the ISR's status read), and the writes split into the declared
  // trigger sequence and the declared clear.  A single-link build never reads
  // these; keeping them per target is what lets a both case prove that each
  // target's own status word was read and each declared clear really happened.
  uint32_t last_read_offset = 0, last_read_data = 0;
  unsigned trigger_writes = 0, clear_writes = 0;
  // How many ordered clear steps of the declared sequence this target has
  // already performed.  A one-step declaration reaches 1 and is the historical
  // single-clear case; a two-step declaration reaches 2 only when the second
  // declared write really completed after the first.
  unsigned clear_step = 0;
  uint32_t last_trigger_offset = 0, last_trigger_data = 0;
  uint32_t last_clear_offset = 0, last_clear_data = 0;
};

#if CPU_BUS_AHB
// One accepted AHB beat: the adapter raised its backend request, this host
// accepted it, and the answer is outstanding until the adapter samples
// rsp_valid in its COMPLETE state.  `have_value` separates "accepted" from
// "the answer is known", which is what a target access needs: the AHB
// subordinate may hold HREADYEXT low for as long as the target takes.
struct AhbBeat {
  bool active = false, have_value = false, write = false;
  uint32_t address = 0, value = 0;
  unsigned be = 0;
  bool command_store = false;
};
#endif

#if HAVE_DMA
// One Wishbone control-port request started by a real CPU data beat.  The DMA
// profile declares a word-indexed control port, so the byte offset is shifted.
struct Control {
  bool busy = false, accepted = false, write = false;
  uint32_t offset = 0, value = 0;
  unsigned be = 0;
};

// The single outstanding Wishbone master response this host serves from RAM.
// ``delay`` is the number of host ticks still owed before the ack: a declared
// DMA_RESPONSE_DELAY plus the one-cycle write-data-late case, which is a bus
// fact and not the declared knob.  ``accept_tick`` is when the beat was taken,
// so the measured wait of each response is a counted difference, never a claim.
// ``routed`` marks a beat whose destination is the declared target route: it is
// neither written to nor read from RAM, and it is acked only after the target's
// own APB3 bridge returned a response.
struct Master {
  bool pending = false;
  unsigned delay = 0;
  uint32_t data = 0;
  uint64_t accept_tick = 0;
#if DMA_ROUTE_ENABLED
  bool routed = false;
  // A declared error injection: this beat's response is ACK+ERR on the device's
  // own mwb_err input, and the host counts it as the declared injection.
  bool error = false;
#endif
};

#if DMA_ROUTE_ENABLED
// One routed master beat in flight.  ``waiting`` starts when the master accepts
// the beat and ends when the response is delivered back to the DMA; the target
// request port is driven while ``presented``, accepted when ``sent``, and the
// route is a real completion only when ``done`` was set from the target's own
// rsp_valid.  ``wdata`` is the whole word the device presented, which the APB3
// bridge forwards as PWDATA; a write route returns no read data.  A read route
// drives PWRITE=0 instead, captures the target's PRDATA in ``rdata`` and returns
// it to the DMA on mwb_dat_r when the beat is acked.
struct MasterRoute {
  bool waiting = false, presented = false, sent = false, done = false;
  bool read = false;
  // ``offset`` is the target offset this beat carries: the declared fixed route
  // offset, or the aperture offset the master itself addressed.
  uint32_t offset = 0;
  uint32_t wdata = 0, rdata = 0;
};
#endif
#endif

#if HAVE_IRQ_LINKS
// One real interrupt output of one selected model.  A declared pulse source is
// stretched to the declared delivery width; a declared level source passes
// straight through.  Sampling is per tick, from the device's own port.
struct IrqLink {
  std::function<unsigned()> sample;
  unsigned pulse_ticks = 0, remaining = 0, edges = 0;
  bool last = false;
};
#endif

// The host's own two helpers are defined below the model structs, and the serial
// peer's event prints and pad-group rows use them from here, so the declarations
// are visible before them.  They are the same functions the case line uses.
std::string hex32(uint32_t value);

#if HAVE_PINS
// The host pad model.  ``ext`` is the declared external driver (or this case's
// stimulus word), ``out`` and ``dir`` are sampled from the device's own ports and
// ``value`` is the wire the host drives into the device's pin input port.  A pad
// bit is the device's registered output while its direction bit is high and the
// host driver value otherwise; there is no third driver.
struct Pads {
  uint32_t ext = IP_PAD_EXT_DEFAULT, value = 0, out = 0, dir = 0, sync = 0;
};

static constexpr uint32_t kPadMask =
    PAD_WIDTH >= 32 ? 0xffffffffu : ((uint32_t(1) << PAD_WIDTH) - 1u);

uint32_t resolve_pads(uint32_t out, uint32_t dir, uint32_t ext) {
  return ((out & dir) | (ext & ~dir)) & kPadMask;
}
#endif

#if HAVE_PINS && HAVE_PIN_GROUPS
// One declared pad group, as the generated header states it.  ``direction`` is
// the declared ownership of the group's pads: 0 = the host drives them, 1 = the
// device does, 2 = both (the per-bit dir resolution).  It selects the wire the
// host presents and the witness the case line reports, and it is never inferred
// from a component name.
struct PinGroupRow {
  const char *name;
  unsigned direction, hold_ticks;
  uint32_t ext;
};

static const PinGroupRow kPinGroups[] = { PIN_GROUP_TABLE(PIN_GROUP_ROW) };
static constexpr unsigned kPinGroupCount =
    sizeof(kPinGroups) / sizeof(kPinGroups[0]);
static_assert(PIN_GROUP_COUNT == kPinGroupCount,
              "the generated pad-group table and its count disagree");

const char *pin_group_direction_name(unsigned direction) {
  return direction == 0 ? "in" : direction == 1 ? "out" : "inout";
}

// What one group really did in one case.  Every field is measured on the ticks
// the group held the wire: the external word it presented, the window it got, the
// changes the resolution made while it held it, and the witness its declared
// direction produced on the device's own dir port.
struct PinGroupCase {
  unsigned ticks = 0, changes = 0, rise = 0, fall = 0, conflicts = 0;
  uint32_t ext = 0, dir_observed = 0, pad_before = 0, pad_after = 0;
  bool applied = false;
};

// The ordered schedule.  Groups take the wire one after another in declaration
// order, each for the window it declares (``hold_ticks`` host ticks, at least
// one), and the last group keeps the wire for the rest of the case.  The host
// does not reorder, drop or merge them: a case line states every group's own
// window and effect.
struct PinGroupSchedule {
  unsigned active = 0, held = 0;
  bool stimulus_override = false;
  uint32_t stimulus_ext = 0;
  PinGroupCase groups[PIN_GROUP_COUNT ? PIN_GROUP_COUNT : 1];

  void begin_case(bool stimulus, uint32_t stimulus_word) {
    active = 0;
    held = 0;
    stimulus_override = stimulus;
    stimulus_ext = stimulus_word;
    for (unsigned index = 0; index < kPinGroupCount; ++index)
      groups[index] = PinGroupCase();
  }
  unsigned window(unsigned index) const {
    return kPinGroups[index].hold_ticks ? kPinGroups[index].hold_ticks : 1u;
  }
  uint32_t ext(unsigned index) const {
    return (index == 0 && stimulus_override) ? stimulus_ext : kPinGroups[index].ext;
  }
  unsigned direction() const { return kPinGroups[active].direction; }
  // One host tick of the schedule: the wire value this tick, then the window
  // bookkeeping.  A group is presented for at least one tick, so every declared
  // group is really applied and observable instead of being skipped.
  uint32_t step() {
    PinGroupCase &row = groups[active];
    row.applied = true;
    row.ext = ext(active);
    ++row.ticks;
    ++held;
    if (active + 1 < kPinGroupCount && held >= window(active)) {
      active += 1;
      held = 0;
    }
    return row.ext;
  }
  void note_dir(uint32_t dir) {
    PinGroupCase &row = groups[active];
    row.dir_observed |= dir & kPadMask;
    // The declared direction is a falsifiable statement about the device's own
    // dir port: ``in`` means the host owns every bit of the group's word, ``out``
    // means the device does.  A bit that contradicts it is counted here, per
    // group, instead of being silently resolved in the declaration's favour.
    if (kPinGroups[active].direction == 0) {
      row.conflicts += __builtin_popcount(dir & kPadMask);
    } else if (kPinGroups[active].direction == 1) {
      row.conflicts += __builtin_popcount(~dir & kPadMask);
    }
  }
  void note_change(uint32_t before, uint32_t after, uint32_t rise, uint32_t fall) {
    PinGroupCase &row = groups[active];
    if (row.ticks == 1) row.pad_before = before;
    row.pad_after = after;
    if (after != before) ++row.changes;
    if (rise) ++row.rise;
    if (fall) ++row.fall;
  }
  uint32_t resolve(const PinGroupRow &row, uint32_t out, uint32_t dir,
                   uint32_t ext_word) const {
    // The declared direction selects the wire.  ``in`` presents the host driver
    // on every bit, ``out`` presents the device's own output, and ``inout``
    // resolves bit by bit from the device's dir port - the one pad resolution a
    // declaration may state.
    if (row.direction == 0) return ext_word & kPadMask;
    if (row.direction == 1) return out & kPadMask;
    return resolve_pads(out, dir, ext_word);
  }
};
#endif

#if HAVE_SERIAL_PEER
// One declared framed serial peer: the host drives ``rx_role`` with a complete
// frame and samples ``tx_role`` at the declared bit period.  The frame is the
// declared 8n1 / 8e1 / 8o1 shape, and the peer's own idle level is what the wire
// rests at between frames.  The device's ``tx_en_role`` output, when the profile
// declares one, is sampled and reported; it is the device's own indication and
// the peer never drives it.
template <typename Model>
struct SerialPeer {
  static constexpr unsigned kBitTicks = SERIAL_PEER_BIT_TICKS;
  static constexpr unsigned kIdle = SERIAL_PEER_IDLE_LEVEL;
  static constexpr unsigned kFrameBits = SERIAL_PEER_FRAME_BITS;
  static constexpr unsigned kDataBits = 8;
  static constexpr bool kParity = SERIAL_PEER_FRAME_CODE != 0;
  static constexpr bool kParityOdd = SERIAL_PEER_FRAME_CODE == 2;
  static constexpr unsigned kParityBit = 9;  // when kParity
  static_assert(kFrameBits == (kParity ? 11u : 10u),
                "the declared frame code and bit count disagree");

  // The rx driver: ``frame_word`` holds the levels the host presents, bit 0 the
  // first bit time (the start bit).  ``holding`` parks the CPU clock while the
  // host is the one driving the wire.
  bool holding = false;
  // The byte this case asked the peer to clock out, and whether one was asked for
  // at all: a case with no stimulus word drives no frame.
  bool pending = false;
  uint32_t pending_byte = 0;
  unsigned rx_remaining = 0, rx_bit = 0, rx_frames = 0, rx_held = 0;
  unsigned rx_bits = 0;
  uint64_t rx_first_tick = 0, rx_last_tick = 0;
  uint32_t rx_frame_word = 0, rx_byte = 0, rx_levels = 0;
  unsigned rx_parity_level = 0;

  // The tx sampler: one bit-center sample per bit time after a start edge, with
  // the levels recorded in the same order as the driver's frame word.
  bool tx_active = false;
  int tx_last_level = -1;
  unsigned tx_bit = 0, tx_frames = 0, tx_bits = 0;
  unsigned tx_framing_ok = 0, tx_stop_ok = 0;
  uint64_t tx_first_tick = 0, tx_last_tick = 0, tx_next_sample = 0;
  uint32_t tx_levels = 0, tx_byte = 0;
  unsigned tx_parity_level = 0;
  unsigned tx_en_ticks = 0, tx_en_level = 0;

  static bool parity_of(uint32_t byte) {
    return (__builtin_popcount(byte & 0xffu) & 1u) != 0u;
  }
  // The frame the host presents for one byte: start (0), 8 data bits LSB first,
  // the parity bit when the declared frame has one, then one stop bit (idle).
  static uint32_t frame_word(uint32_t byte) {
    uint32_t word = 0;  // bit 0 = start bit = 0
    for (unsigned bit = 0; bit < 8; ++bit)
      word |= ((byte >> bit) & 1u) << (1 + bit);
    if (kParity) {
      // Even parity: the parity bit makes the number of ones even.  Odd parity
      // is its complement.
      const bool odd = parity_of(byte);
      const unsigned level = kParityOdd ? (odd ? 0u : 1u) : (odd ? 1u : 0u);
      word |= level << kParityBit;
    }
    word |= 1u << (kFrameBits - 1);  // one stop bit at the idle level
    return word;
  }
  void begin_rx(uint32_t byte, uint64_t tick) {
    rx_frame_word = frame_word(byte);
    rx_remaining = kBitTicks;
    rx_bit = 0;
    rx_bits = 0;
    rx_levels = 0;
    rx_parity_level = kParity ? ((rx_frame_word >> kParityBit) & 1u) : 0u;
    rx_first_tick = tick;
    rx_last_tick = tick;
    rx_byte = byte & 0xffu;
    holding = true;
    ++rx_frames;
  }
  // One host tick of the driver: the level of this bit time, and the bookkeeping
  // that makes the frame exactly ``kFrameBits * kBitTicks`` ticks long.
  void step_rx(Model &model, uint64_t tick) {
    if (!holding) return;
    const unsigned level = (rx_frame_word >> rx_bit) & 1u;
    myfuzz_ip::IpTarget<0>::set_serial_rx(model, level);
    rx_levels |= uint32_t(level) << rx_bit;
    rx_last_tick = tick;
    ++rx_held;
    if (--rx_remaining == 0) {
      ++rx_bit;
      ++rx_bits;  // one completed bit time of the declared frame
      if (rx_bit == kFrameBits) {
        myfuzz_ip::IpTarget<0>::set_serial_rx(model, kIdle);
        holding = false;
        EVENT_STREAM << "serial rx " << tick << " frame end byte "
                     << hex32(rx_byte) << " levels " << hex32(rx_levels)
                     << " first " << rx_first_tick << " last " << tick << '\n';
        return;
      }
      rx_remaining = kBitTicks;
      EVENT_STREAM << "serial rx " << tick << " bit " << rx_bit << " level "
                   << level << '\n';
    }
  }
  void sample_tx(Model &model, uint64_t tick) {
    const unsigned level = myfuzz_ip::IpTarget<0>::serial_tx(model) & 1u;
    tx_last_level = int(level);
    if (!tx_active) {
      if (level == 0) {
        // A start edge: the frame begins at this tick and the first sample is
        // the middle of the start bit.
        tx_active = true;
        tx_first_tick = tick;
        tx_next_sample = tick + kBitTicks / 2;
        tx_bit = 0;
        tx_levels = 0;
        tx_bits = 0;
        EVENT_STREAM << "serial tx " << tick << " frame start\n";
      }
      return;
    }
    if (tick != tx_next_sample) return;
    tx_levels |= uint32_t(level) << tx_bit;
    ++tx_bits;
    EVENT_STREAM << "serial tx " << tick << " bit " << tx_bit << " level "
                 << level << '\n';
    ++tx_bit;
    if (tx_bit == kFrameBits) {
      tx_active = false;
      tx_last_tick = tick;
      ++tx_frames;
      tx_byte = (tx_levels >> 1) & 0xffu;
      tx_parity_level = kParity ? ((tx_levels >> kParityBit) & 1u) : 0u;
      const unsigned start_ok = ((tx_levels & 1u) == 0u) ? 1u : 0u;
      const unsigned stop_ok =
          ((tx_levels >> (kFrameBits - 1)) & 1u) == kIdle ? 1u : 0u;
      unsigned parity_ok = 1;
      if (kParity) {
        const bool odd = parity_of(tx_byte);
        const unsigned expected = kParityOdd ? (odd ? 0u : 1u) : (odd ? 1u : 0u);
        parity_ok = tx_parity_level == expected ? 1u : 0u;
      }
      tx_framing_ok += (start_ok && stop_ok && parity_ok) ? 1u : 0u;
      tx_stop_ok += stop_ok && start_ok ? 1u : 0u;
      EVENT_STREAM << "serial tx " << tick << " frame end byte "
                   << hex32(tx_byte) << " levels " << hex32(tx_levels)
                   << " framing_ok " << int(start_ok && stop_ok && parity_ok)
                   << '\n';
      return;
    }
    tx_next_sample = tick + kBitTicks;
  }
#if HAVE_SERIAL_TX_EN
  void sample_tx_en(Model &model) {
    tx_en_level = myfuzz_ip::IpTarget<0>::serial_tx_en(model) & 1u;
    if (tx_en_level) ++tx_en_ticks;
  }
#endif
  void reset_case() {
    rx_frames = rx_held = rx_bits = 0;
    rx_first_tick = rx_last_tick = 0;
    rx_byte = rx_levels = 0;
    tx_frames = tx_bits = 0;
    tx_framing_ok = tx_stop_ok = 0;
    tx_first_tick = tx_last_tick = 0;
    tx_byte = tx_levels = 0;
    tx_en_ticks = 0;
  }
};
#endif

enum Flow { kNone = 0, kF1 = 1, kF2 = 2, kF3 = 3, kF4 = 4, kF5 = 5, kF6 = 6 };

struct Record {
  Flow flow = kNone;
  // How many words the operator handed over: F2 carries the external pin word as
  // an optional second operand on a pin target, F5 carries the link index followed
  // by that link's trigger values when N links are declared, F6 one word per
  // declared DMA block word, and F1 one to F1_MAX_WORDS instruction words.
  unsigned words = 0;
  uint32_t values[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  // The F1 control-flow facts make_record proved: the exact retirement count of
  // a bounded-loop image (0 when the range check applies), whether that count is
  // exact, whether the image contains a bounded loop, and how many repeated PCs
  // the reference trace will show.  They are filled only by the whole-image
  // control-flow pass; every other flow leaves them at zero.
  unsigned expected_retires = 0;
  bool exact_retires = false;
  bool loop_mode = false;
  unsigned expected_repeats = 0;
};

// Which target link this F5 case selected.  A single-link declaration keeps the
// historical input shape (no index word); a multi-link one puts the index first.
inline unsigned selected_f5_link(const Record &record) {
#if IRQ_TARGET_LINK_COUNT > 1
  return record.values[0] < IRQ_TARGET_LINK_COUNT ? record.values[0] : 0u;
#else
  (void)record;
  return 0u;
#endif
}

// Whether this F5 record selected the synthetic two-source row.  The row is not
// a physical link: its index is one past the link table, and its case names the
// member links that share it.  A header without a both row states
// IRQ_BOTH_ENABLED 0, so this is a compile-time false and the single-link path
// is the only one built.
inline bool is_both_f5(const Record &record) {
#if IRQ_BOTH_ENABLED && IRQ_TARGET_LINK_COUNT > 0
  return record.flow == kF5 && record.words > 0
      && record.values[0] == IRQ_BOTH_LINK_INDEX;
#else
  (void)record;
  return false;
#endif
}

// The declared clear write of the selected F5 link, if any.  A write is counted
// as the handler's clear only after the CPU accepted the interrupt, so a
// trigger write to the same address/value is still a trigger.  ``target`` is the
// target that completed the write: the link's clear only applies to the target
// that declared that link, so a write into another target is never labelled the
// selected link's clear.  ``step`` is the position in the declared clear
// sequence: a one-step declaration keeps the historical reading exactly, and a
// two-step declaration (a real acknowledge-then-release protocol) names its own
// second address/value, which the handler must perform in order.
inline void selected_clear(const Record &record, unsigned target, unsigned step,
                          bool &declared, uint32_t &offset, uint32_t &value) {
  declared = false;
  offset = 0;
  value = 0;
#if IRQ_TARGET_LINK_COUNT > 0
  if (record.flow == kF5) {
#if IRQ_BOTH_ENABLED
    if (is_both_f5(record)) {
      // A both case declares one clear per member, and the member rows are the
      // physical links.  The write is attributed only to the target that owns
      // the member link; a write into another target is never labelled a clear.
      // A member with an ordered multi-step protocol is refused at header build
      // time, so only step 0 exists here.
      if (step == 0) {
        for (unsigned member = 0; member < kIrqBothMemberCount; ++member) {
          const unsigned link = kIrqBothLink[member];
          if (kIrqLinkTarget[link] == target) {
            declared = kIrqLinkClearDeclared[link] != 0;
            offset = kIrqLinkClearOffset[link];
            value = kIrqLinkClearValue[link];
          }
        }
      }
    } else
#endif
    {
      const unsigned link = selected_f5_link(record);
      // How many ordered steps this link declares.  A header rendered before the
      // multi-step clear increment has no count table; its declared flag is the
      // one-step statement and is used instead.
      const unsigned count = kIrqLinkClearCount[link] != 0
          ? kIrqLinkClearCount[link] : kIrqLinkClearDeclared[link];
      if (kIrqLinkTarget[link] == target && step < count) {
        declared = true;
        offset = step == 0 ? kIrqLinkClearOffset[link] : kIrqLinkClear2Offset[link];
        value = step == 0 ? kIrqLinkClearValue[link] : kIrqLinkClear2Value[link];
      }
    }
  }
#else
  (void)record;
  (void)target;
  (void)step;
#endif
}

struct Observation {
  unsigned i_fetches = 0, d_reads = 0, d_writes = 0;
  // AXI4 CPU only: the firmware's poll loop re-reads the command word every
  // iteration, so a non-zero count is a real bus observation that the CPU
  // reached the poll loop (and not a conclusion drawn from having booted).
  unsigned poll_reads = 0;
  // Target transfers under neutral names: one member counts one completed
  // transfer of whichever target bridge the header selected.  The run log prints
  // them under the protocol's own spelling (apb_reads for an APB3 target;
  // target_reads plus axi_* for an AXI4-Lite one), so the counters keep the same
  // meaning and only the words differ.
  unsigned target_reads = 0, target_writes = 0, ip_irq_high = 0;
  // Retirement events.  retires counts the RVFI-valid retirements this case
  // saw, rvfi_writebacks the ones that changed a register, traps the ones the
  // CPU flagged as traps (recorded, never a reason to stop the loop).
  unsigned retires = 0, rvfi_writebacks = 0, traps = 0, target_errors = 0;
  // AXI4-Lite only: the five channel handshake counts of the same transaction,
  // the response code of its B/R channel and the strobes of its W beat.  An
  // APB3 target has no channels and no response code, so these stay zero and an
  // APB3 build never prints them.
  unsigned axi_aw = 0, axi_w = 0, axi_b = 0, axi_ar = 0, axi_r = 0;
  unsigned axi_resp_non_okay = 0, target_wstrb = 0;
  uint32_t target_resp = 0;
  // Wishbone target only: the slave's own handshake as it was sampled at the
  // completed cycle (cyc/stb/ack/we/adr/dat_w/dat_r/sel, plus stall when the
  // trace carries it), and the counters of the cycles the case really put on
  // that port.  ``wb_stb_pulses`` is the request phase (cyc and stb in one
  // sample) and ``wb_acks`` the completion (cyc held with ack): the admitted
  // registered-ack variants pulse STB for one cycle and answer one or two cycles
  // later, so the two are counted where each really is.  ``wb_adr`` is the
  // slave's word address; ``target_offset`` is the byte offset it means.
  unsigned wb_acks = 0, wb_stalls = 0, wb_stb_pulses = 0;
  bool wb_cyc = false, wb_stb = false, wb_ack = false, wb_we = false;
  unsigned wb_sel = 0;
  uint32_t wb_adr = 0, wb_dat_w = 0, wb_dat_r = 0;
  // TL-UL target only: the A channel handshake that accepted the request, the D
  // channel handshake that completed it, and the response's own error bit.
  unsigned tlul_a_handshakes = 0, tlul_d_handshakes = 0, tlul_errors = 0;
  bool tlul_a_valid = false, tlul_a_ready = false;
  bool tlul_d_valid = false, tlul_d_ready = false, tlul_d_error = false;
  unsigned tlul_a_opcode = 0, tlul_a_mask = 0;
  uint32_t tlul_a_address = 0, tlul_a_data = 0, tlul_d_data = 0;
  // AHB-Lite target only: the address phase the slave's own port accepted and the
  // data phase it completed, plus the pins each phase presented.  ``ahb_hreadyin``
  // completes the address phase and ``ahb_hreadyout`` the data phase; the pinned
  // wrapper ties both to its single-target fabric, but the host samples the two
  // declared pins rather than assuming it.  ``ahb_hresp`` is the target's own
  // response pin: the pinned wrapper drives it from a tied-low ``err`` input, so
  // the case prints the pin as sampled and states ``ahb_error unknown`` - a zero
  // here is never read as a clean bus.
  unsigned ahb_address_phases = 0, ahb_data_phases = 0;
  bool ahb_hsel = false, ahb_hwrite = false, ahb_hreadyin = false;
  bool ahb_hreadyout = false, ahb_hresp = false;
  unsigned ahb_htrans = 0, ahb_hsize = 0;
  uint32_t ahb_haddr = 0, ahb_hwdata = 0, ahb_hrdata = 0;
  // The address phase this case's target beat presented, kept between the
  // address sample and the data sample of that same transfer.  It starts false
  // for every case, so idle pins are never read as a transaction.
  bool ahb_address_seen = false;
  uint64_t rvfi_order = 0, rvfi_expanded = 0;
  bool rvfi_order_monotonic = true;
  bool slot_fetch = false, slot_retire = false, slot_successor = false;
  uint32_t slot_fetch_address = 0, slot_retire_pc = 0, slot_retire_insn = 0;
  uint32_t slot_successor_pc = 0;
  // The short program that ran in the trampoline slot: how many of its own
  // instructions really retired, whether they retired in strictly increasing
  // address order with the instruction the host installed, the registers the CPU
  // wrote back, the last writeback, and the declared program data window sampled
  // before and after the case.  An instruction that never retires is a count
  // difference, not an assumption; a branch program legally skips words, and a
  // compressed record retires two 16-bit parcels per installed record word.
  // ``prog_trace_hash`` is the FNV-1a 32 of the in-slot retirement trace (pc,
  // insn, rd, wdata), printed in a branch or compressed build and compared with
  // the Python reference model.
  unsigned prog_retires = 0, prog_writebacks = 0, prog_traps = 0;
  // How many in-slot retirements did not advance the PC (a bounded loop's back
  // edge).  It is printed beside the strict-rise flag so a loop case states the
  // repeat count the reference trace has, and every other traced shape states 0.
  unsigned prog_pc_repeat = 0;
  bool prog_pc_ordered = true, prog_insns_match = true;
  uint32_t prog_rd_mask = 0, prog_last_rd = 0, prog_last_wdata = 0;
  uint32_t prog_last_pc = 0, prog_last_insn = 0;
  uint32_t prog_trace_hash = 2166136261u;
  unsigned prog_trace_count = 0;
  // The same in-slot retirement trace at the RV64 record's natural width.  A
  // 64-bit declaration hashes (pc, insn, rd, wdata) as 64-bit fields, so the
  // 32-bit digest above is never used to state an RV64 result; this one is
  // FNV-1a 64 over the same four fields, and the Python reference computes it.
  uint64_t prog_trace_hash64 = 14695981039346656037ull;
  uint64_t prog_last_wdata64 = 0, prog_last_pc64 = 0;
  // Trap / interrupt witness of this case, taken from the RVFI record itself
  // (cause/intr/mode are the record's own fields) and from the scoreboard's CSR
  // readback.  ``trap_count`` counts trap-flagged retirements; the first one is
  // the one the trap-program case states.  The stored cells are what the
  // firmware's own handler wrote to RAM (TRAP_* macros), read at case end.
  unsigned trap_count = 0;
  uint32_t trap_pc = 0, trap_insn = 0;
  uint64_t trap_cause = 0, trap_intr = 0;
  unsigned trap_mode = 0;
  unsigned rvfi_csr_samples = 0;
  // The first readback snapshot whose mcause is non-zero: the trap entry, with
  // mcause and mepc as the core wrote them at the trapping edge.  ``*_final`` is
  // the last snapshot the case sampled, so the handler's own mepc write (it
  // advances past the ECALL) is visible beside the entry value.
  bool rvfi_csr_trap_seen = false;
  uint64_t rvfi_mcause = 0, rvfi_mepc = 0, rvfi_mtval = 0, rvfi_mtvec = 0;
  uint64_t rvfi_mstatus = 0;
  uint64_t rvfi_mcause_final = 0, rvfi_mepc_final = 0;
  // The last mepc the readback stated, so a change is printed once and not on
  // every tick after it.
  uint64_t rvfi_mepc_last = 0;
  // The last interrupt cause the readback stated and that was counted as a take.
  // The F5 ISR clears mcause, so a new entry is a new value and a repeated sample
  // of the same entry is not counted twice.
  uint64_t rvfi_take_mcause_last = 0;
  uint32_t trap_stored_cause = 0, trap_stored_epc = 0;
  uint32_t trap_flag = 0;
  uint32_t data_hash_before = 0, data_hash_after = 0;
  unsigned data_changed = 0;
  bool read_accepted = false, read_from_ip = false, echo_stored = false;
  uint32_t read_address = 0, read_value = 0, echo_value = 0;
  bool write_accepted = false, target_ready = false;
  uint32_t write_address = 0, write_value = 0, ram_before = 0;
  unsigned write_be = 0;
  // The offset inside the declared target window, the write data, the read data
  // and the last write/read pair - the same four facts for both protocols.
  uint32_t target_offset = 0, target_wdata = 0, target_rdata = 0;
  // F5/F6: only completed bus transfers and real device outputs land here.
  uint32_t target_read_offset = 0, target_read_data = 0;
  uint32_t target_last_write_offset = 0, target_last_write_data = 0;
  // F5 trigger writes and the ISR's declared clear write are different facts.
  unsigned trigger_writes = 0, clear_writes = 0;
  uint32_t target_last_trigger_offset = 0, target_last_trigger_data = 0;
  uint32_t target_last_clear_offset = 0, target_last_clear_data = 0;
  // The cause field a declared status word carries (zero when none is declared).
  uint32_t isr_cause = 0;
  // Which target the case was routed to (-1: no target access, e.g. an F2 RAM
  // read, an F3 store or an F6 DMA transfer).  It is printed only when the
  // declaration has more than one target, so a legacy case line is unchanged.
  int target_index = -1;
  TargetCounters ip_targets[IP_COUNT > 0 ? IP_COUNT : 1];
  // Each target's own interrupt output, counted once per tick.  Every target
  // that declares an IRQ link has its output delivered through the one CPU IRQ
  // input (the host ORs all links); a target whose output exists but declares no
  // link is observed and stated as observe-only in the summary.  The delivered
  // count is per target too: it counts the ticks that target's own link held the
  // delivered line, which is a stricter fact than the shared input's level.
  unsigned target_irq_high[IP_COUNT > 0 ? IP_COUNT : 1] = {};
  unsigned target_irq_delivered[IP_COUNT > 0 ? IP_COUNT : 1] = {};
  // The device output level and the delivered CPU input level are counted
  // apart: a pulse source is stretched by the host, so the two counts differ.
  unsigned irq_edges = 0, irq_takes = 0, irq_high = 0, irq_delivered_high = 0;
  // Per sampled link: the edges this case saw, and the raw level each link held
  // at the last tick.  `level_stuck` is set when a declared link is still
  // asserted after the handler ran; it fails the case and resets the devices
  // instead of masking the line.
  unsigned irq_link_edges[IRQ_SOURCE_COUNT ? IRQ_SOURCE_COUNT : 1] = {};
  uint32_t irq_level_final = 0;
  bool level_stuck = false;
  bool isr_flag = false;
  // A bounded firmware wait wrote the timeout marker instead of the handler's
  // flag: the case is a real timed-out observation, not a lost batch.
  bool wait_timeout = false;
  uint32_t isr_result = 0;
  // What the ISR really addressed and stored, plus the kind of the declared
  // status word (count/status/...) taken from the profile's register name.
  uint32_t isr_read_address = 0, isr_read_value = 0;
#if IRQ_BOTH_ENABLED && IRQ_TARGET_LINK_COUNT > 0
  // A two-source case stores a second result and reads a second status word at
  // its own address.  A single-link case leaves these zero, so its case line and
  // its document are unchanged.
  uint32_t isr_result2 = 0, isr_read_address2 = 0, isr_read_value2 = 0;
#endif
  // The raw level every sampled target link held on the last tick of the case,
  // as a bitmask over the physical link indices.  ``irq_level_final`` above is
  // the same sample restricted to declared level links; this one also covers a
  // pulse link, so "both final levels are low" is stated for every member.
  uint32_t irq_link_last = 0;
  unsigned ctl_reads = 0, ctl_writes = 0, ctl_config_writes = 0;
  unsigned ctl_start_writes = 0, ctl_clear_writes = 0;
  unsigned ctl_reads_before_start = 0;
  uint32_t ctl_status = 0, ctl_before = 0;
  unsigned busy_before = 0, busy_after = 0, err_before = 0, err_after = 0;
  unsigned busy_high_reads = 0;
  unsigned dma_reads = 0, dma_writes = 0;
  uint32_t dma_first_read_address = 0, dma_first_read_value = 0;
  uint32_t dma_last_write_address = 0, dma_last_write_value = 0;
  // The declared route as it executed: accepted master write beats presented on
  // the routed target's APB port, the subset the target really answered, and the
  // target's own completed APB writes.  ``dma_ram_writes`` is the other half of
  // ``dma_writes``, so "the routed block never landed in RAM" is a counted fact.
  unsigned dma_route_writes = 0, dma_route_acks = 0, dma_route_target_writes = 0;
  unsigned dma_route_target_ready = 0, dma_ram_writes = 0;
  uint32_t dma_route_last_offset = 0, dma_route_last_wdata = 0;
  // The evidence word the F6 firmware read before and after the transfer, and
  // the declared field it carries.  Both cells start at the sentinel and are
  // reported as "unknown" when the firmware never wrote them.
  bool dma_route_before_written = false, dma_route_after_written = false;
  uint32_t fifo_status_before = 0, fifo_status_after = 0;
  unsigned tx_fifo_level_before = 0, tx_fifo_level_after = 0;
  unsigned dma_route_expected_level = 0;
  // How many of the declared pushes the readback shows as accepted, and whether
  // that is fewer than the declared pushes (a full FIFO drops the rest).  Both
  // are derived from the two readbacks, never from the ack count.
  unsigned dma_route_accepted = 0;
  bool dma_route_partial = false;
#if DMA_ROUTE_ENABLED && DMA_ROUTE_TRACE
  // The routed beat's own protocol trace.  Only a transfer the route really made
  // is counted here (the CPU's MMIO evidence read is a different owner of the
  // port), and the completion is that protocol's own handshake - a Wishbone
  // ack with cyc, a TL-UL D response after the A request, an AXI4-Lite B or R
  // after AW/W or AR.  The routed offset/direction are the payload that handshake
  // carried, kept from the request channel, because the response channel of a
  // pipelined protocol no longer holds the address.  These fields are shared by
  // both route directions, so they are declared outside the read-only group.
  unsigned dma_route_protocol_transfers = 0;
  unsigned dma_route_wb_acks = 0, dma_route_wb_stb_pulses = 0;
  unsigned dma_route_tlul_a_handshakes = 0, dma_route_tlul_d_handshakes = 0;
  unsigned dma_route_axi_aw = 0, dma_route_axi_w = 0, dma_route_axi_b = 0;
  unsigned dma_route_axi_ar = 0, dma_route_axi_r = 0;
  uint32_t dma_route_trace_offset = 0;
  bool dma_route_trace_write = false;
#endif
  // The routed target's completed reads and the last word it returned.  They are
  // declared for a write route too, because the route's own protocol trace
  // samples the read handshake of every protocol the target might use; a write
  // route simply never completes one.
  unsigned dma_route_target_reads = 0;
  uint32_t dma_route_last_rodata = 0;
#if DMA_ROUTE_READ
  // A read route's own facts: accepted master read beats presented on the routed
  // target's APB port, the subset the target answered, the target's completed APB
  // reads, and the word the target returned on each read.  ``dma_ram_reads`` is
  // the number of master reads served from RAM (it must stay zero on a read
  // route), so "the routed read was not served from RAM" is a counted fact.
  unsigned dma_route_reads = 0, dma_ram_reads = 0;
  unsigned dma_route_read_stable = 0, dma_route_read_matched = 0;
  unsigned dma_route_cpu_matched = 0;
  uint32_t dma_route_read_first = 0, dma_route_read_value = 0;
  uint32_t dma_route_read_capture[DMA_BLOCK_WORDS > 0 ? DMA_BLOCK_WORDS : 1] = {};
  uint32_t dma_route_cpu_dst[DMA_BLOCK_WORDS > 0 ? DMA_BLOCK_WORDS : 1] = {};
  bool dma_route_cpu_written = false;
  // The declared read shape as it executed: the target offset of every routed
  // read beat (so a wrong sequence is a printed fact), the number of beats that
  // presented the declared aperture address in order, and the number of captured
  // words that equal the declared expected word.
  uint32_t dma_route_beat_offset[DMA_BLOCK_WORDS > 0 ? DMA_BLOCK_WORDS : 1] = {};
  unsigned dma_route_sequence = 0, dma_route_fifo_matched = 0;
  // The CPU's own readback of the declared aperture words, one cell per beat.
  uint32_t dma_route_cpu_aper[DMA_BLOCK_WORDS > 0 ? DMA_BLOCK_WORDS : 1] = {};
  unsigned dma_route_cpu_aper_matched = 0;
  // The declared error injection: how many master responses carried ERR, and on
  // which routed beat.  -1 keeps "no injection was declared" distinct from
  // "beat 0 was injected".
  unsigned dma_error_injections = 0;
  int dma_error_beat = -1;
#endif
  // Backpressure, measured per accepted master beat: how many host ticks the
  // host held mwb_stall with a response owed, the longest such run, and the
  // measured wait of every completed response (ticks from accept to ack).
  unsigned dma_stall_ticks = 0, dma_stall_run = 0, dma_stall_max_run = 0;
  // The deepest master-response pipeline this case really reached, counted when a
  // response is taken while another is still owed.  It is the measurement the
  // declared depth is checked against: a build that declares two and never exceeds
  // one reports peak 1, and that is the honest answer, not the declaration.
  unsigned dma_outstanding_peak = 0;
  unsigned dma_acks = 0, dma_delayed_acks = 0;
  unsigned dma_wait_min = 0, dma_wait_max = 0;
  uint64_t dma_wait_total = 0;
  // Byte enables as the device presented them.  ``sel_full``/``sel_partial``
  // count accepted master writes by their lane mask, and the per-byte hit
  // counters below show, lane by lane, which bytes of the declared destination
  // block the device really strobed (once, more than once, or never).
  unsigned dma_sel_full = 0, dma_sel_partial = 0;
  unsigned dma_sel_undeclared = 0;
  unsigned dma_read_lane_partial = 0;
  unsigned dma_bytes_outside_block = 0, dma_lane_extra = 0;
  unsigned dma_dst_lane_hits[4 * 16] = {};
  // The one guard word on either side of the declared destination block, read
  // after the case: a transfer that wrote outside its block shows up here.
  uint32_t dma_guard_lo = 0, dma_guard_hi = 0;
  // The control write the host counted as the start, so the plan's start word is
  // compared with what the device really received instead of assumed.
  bool dma_start_seen = false;
  uint32_t dma_start_write = 0;
  // Derived, not sampled: the DMA model exposes o_interrupt only.  The event
  // fires on the completion IRQ edge that follows the last accepted master
  // write, and the summary states that derivation.
  bool dma_done = false;
  uint64_t dma_done_tick = 0;
  // AHB-Lite only: what the sampled address phase said about the beats this
  // case really put on the backend face.  `ahb_unknown` counts the beats whose
  // identity could not be established (the classifier saw no accepted address
  // phase for them), and `ahb_unknown_reset` the subset taken while the CPU's
  // own synchronized bus reset HRESETn had not been observed released yet.
  // An unknown beat is served and counted, never guessed into a fetch.
  unsigned ahb_beats = 0, ahb_unknown = 0, ahb_unknown_reset = 0;
#if HAVE_PINS
  // The pin model: snapshots of the resolved wire and of the device ports, and
  // whether this case's F2 carried an external stimulus word.
  bool pin_stimulus = false;
  uint32_t pad_before = 0, pad_after = 0, pad_at_read = 0;
  // Both transition directions are sampled: the device's declared interrupt
  // type decides whether a rise or a fall is the cause, so the host records
  // both and accepts either when the enable mask covers the pin.
  unsigned pad_fall_events = 0;
  uint64_t first_fall_tick = 0, first_transition_tick = 0;
  uint32_t transition_mask = 0;
  uint32_t out_before = 0, out_after = 0, dir_before = 0, dir_after = 0;
  uint32_t sync_at_read = 0, padin_latch_at_read = 0, padin_latch = 0;
  uint32_t ext_value = IP_PAD_EXT_DEFAULT;
  // Whether the instant the CPU read the pad, the wire and the device's
  // synchronizer latch happened to agree.  It is reported, not required: the
  // synchronizer has its own latency, so a read may legitimately observe the
  // previous latch while the wire has already moved.
  bool pad_settled = false;
  unsigned pad_changes = 0, pad_rise_events = 0;
  uint32_t rise_mask = 0, fall_mask = 0;
  uint64_t first_rise_tick = 0, first_irq_tick = 0;
  uint32_t irq_cause_pins = 0, inten_at_irq = 0, status_after_read = 0;
#endif
#if HAVE_PINS && HAVE_PIN_GROUPS
  // The declared pad groups this case really executed, group by group, plus the
  // totals the case line and the summary read.  A group is executed when it held
  // the wire for at least one tick; every declared group is applied, none is
  // skipped to make the totals look whole.
  unsigned pin_group_declared = 0, pin_group_executed = 0;
  unsigned pin_group_ticks = 0, pin_group_changes = 0, pin_group_conflicts = 0;
  bool pin_stimulus_group = false;
  PinGroupCase pin_groups[PIN_GROUP_COUNT ? PIN_GROUP_COUNT : 1];
#endif
#if HAVE_SERIAL_PEER
  // The declared serial peer's own facts for this case: what the host really
  // clocked onto rx (the frame it built from the declared shape) and what it
  // really sampled from tx, tick by tick.
  unsigned serial_rx_frames = 0, serial_rx_bits = 0, serial_rx_held_ticks = 0;
  uint32_t serial_rx_byte = 0, serial_rx_levels = 0;
  unsigned serial_rx_parity = 0;
  uint64_t serial_rx_first_tick = 0, serial_rx_last_tick = 0;
  unsigned serial_tx_frames = 0, serial_tx_bits = 0, serial_tx_framing_ok = 0;
  unsigned serial_tx_stop_ok = 0;
  uint32_t serial_tx_byte = 0, serial_tx_levels = 0;
  unsigned serial_tx_parity = 0;
  uint64_t serial_tx_first_tick = 0, serial_tx_last_tick = 0;
  unsigned serial_tx_en_ticks = 0, serial_tx_en_level = 0;
#endif
};

// Classify one completed target write.  A write that matches the *next*
// declared clear step address/value after the CPU has taken the interrupt is the
// handler's clear; every other write belongs to the trigger sequence.  Counting
// the same transfer as both was the conflict that made clear_writes impossible.
// The step advances only on a match, so an ordered two-write acknowledge
// protocol is checked in the order it was declared and a missing or reordered
// step is reported as a missing clear rather than accepted.
inline void note_target_write(Observation &observation, const Record &record,
                              unsigned target, uint32_t offset, uint32_t value) {
  ++observation.target_writes;
  ++observation.ip_targets[target].writes;
  observation.ip_targets[target].last_offset = offset;
  observation.ip_targets[target].last_data = value;
  observation.ip_targets[target].ready = true;
  observation.target_last_write_offset = offset;
  observation.target_last_write_data = value;
  bool clear_declared = false;
  uint32_t clear_offset = 0, clear_value = 0;
  selected_clear(record, target, observation.ip_targets[target].clear_step,
                 clear_declared, clear_offset, clear_value);
  const bool clear = clear_declared && observation.irq_takes > 0
      && offset == clear_offset && value == clear_value;
  if (clear) {
    ++observation.clear_writes;
    ++observation.ip_targets[target].clear_writes;
    ++observation.ip_targets[target].clear_step;
    observation.ip_targets[target].last_clear_offset = offset;
    observation.ip_targets[target].last_clear_data = value;
    observation.target_last_clear_offset = offset;
    observation.target_last_clear_data = value;
  } else {
    ++observation.trigger_writes;
    ++observation.ip_targets[target].trigger_writes;
    observation.ip_targets[target].last_trigger_offset = offset;
    observation.ip_targets[target].last_trigger_data = value;
    observation.target_last_trigger_offset = offset;
    observation.target_last_trigger_data = value;
  }
}


std::string hex32(uint32_t value) {
  std::ostringstream text;
  text << "0x" << std::hex << std::setw(8) << std::setfill('0') << value;
  return text.str();
}

// A 64-bit channel word (the AXI4 CPU side carries 64-bit addresses, data and
// user fields; the low 32 bits alone would hide a real high word).
std::string hex64(uint64_t value) {
  std::ostringstream text;
  text << "0x" << std::hex << std::setw(16) << std::setfill('0') << value;
  return text.str();
}

#if HAVE_DMA
// The declared master lane patterns packed four bits each, so one hex word
// states every mask the device is allowed to present: 0xf for a full-word
// transfer, 0x8421 for ZipDMA's four one-byte beats, 0xc3 for two half-words.
unsigned dma_lane_mask_word() {
  unsigned packed = 0;
  for (unsigned lane = 0; lane < DMA_MASTER_LANE_COUNT && lane < 4; ++lane) {
    const unsigned mask = ((1u << DMA_MASTER_LANES_PER_BEAT) - 1u)
        << (lane * DMA_MASTER_LANES_PER_BEAT);
    packed |= (mask & 0xfu) << (4 * lane);
  }
  return packed;
}

// Whether the declared response delay was *observed*: every accepted master beat
// waited at least the declared ticks plus the host's one pending tick.  A run
// that declared no delay says so; a declared delay that was not measured stays
// unknown, so it is never reported as a pass.
const char *dma_delay_evidence(const Observation &observation) {
#if DMA_RESPONSE_DELAY > 0
  const unsigned beats = observation.dma_reads + observation.dma_writes;
  if (beats && observation.dma_acks == beats
      && observation.dma_delayed_acks == beats
      && observation.dma_wait_min >= DMA_RESPONSE_DELAY + 1)
    return "observed";
  return "unknown";
#else
  (void)observation;
  return "not_declared";
#endif
}
#if DMA_ROUTE_ENABLED
// The declared evidence field of one status word, under its own bit span.  The
// host only extracts the field the plan declared; it never invents a level.
inline unsigned dma_route_level(uint32_t status) {
  return (status & kDmaRouteEvidenceMask) >> kDmaRouteEvidenceLow;
}

// The FIFO occupancy the declared pushes should leave behind: min(pushes, depth).
// The pinned FIFO drops a write while full (spi_master_fifo.sv:83-88 keeps
// `elements` at BUFFER_DEPTH), so a block that overflows is a partial acceptance
// and is reported as the depth, never as a level above it.
inline unsigned dma_route_expected_level(unsigned before) {
  const unsigned pushed = before + kDmaRoutePushes;
  return pushed < kDmaRouteEvidenceDepth ? pushed : kDmaRouteEvidenceDepth;
}
#endif
#endif

// Canonical record text, the same shape the Python entry accepts and sends.
std::string hex8(uint32_t value) {
  std::ostringstream text;
  text << std::hex << std::setw(8) << std::setfill('0') << value;
  return text.str();
}

std::string seconds_text(double value) {
  std::ostringstream text;
  text << std::setprecision(9) << value;
  return text.str();
}

// A tick that was never observed is written as the word "unknown"; a sampled
// one as its number.  The two are never the same token.
std::string tick_text(bool observed, uint64_t value) {
  return observed ? std::to_string(value) : std::string("unknown");
}

const char *flow_name(Flow flow) {
  switch (flow) {
    case kF1: return "F1";
    case kF2: return "F2";
    case kF3: return "F3";
    case kF4: return "F4";
    case kF5: return "F5";
    case kF6: return "F6";
    default: return "none";
  }
}

// How many input words one record carries.  F5 takes one value per declared
// trigger write and F6 one word per declared DMA block word; zero means the
// selected components cannot serve that flow at all.
unsigned word_count(Flow flow) {
  switch (flow) {
    case kF1: case kF2: return 1;
    case kF3: case kF4: return 2;
    case kF5: return TRIGGER_COUNT + (IRQ_TARGET_LINK_COUNT > 1 ? 1u : 0u);
    case kF6: return DMA_BLOCK_WORDS;
    default: return 0;
  }
}

uint32_t word_at(const Record &record, unsigned index) {
  if (index >= record.words || index >= 16)
    throw std::runtime_error("record word index out of range");
  return record.values[index];
}

uint32_t parse_hex(const std::string &text, const char *what) {
  if (text.empty() || text.size() > 8) throw std::runtime_error(std::string("invalid ") + what);
  uint32_t value = 0;
  for (const char raw : text) {
    const auto character = static_cast<unsigned char>(raw);
    if (!std::isxdigit(character)) throw std::runtime_error(std::string("invalid ") + what);
    value = value * 16u + uint32_t(std::isdigit(character) ? character - '0'
                                                          : std::tolower(character) - 'a' + 10);
  }
  return value;
}

bool in_ram(uint64_t address) {
  return address >= kRamBase && address - kRamBase <= uint64_t(kRamSize) - 4;
}

bool in_ip(uint64_t address) {
  return ip_index_of(address) >= 0;
}

#if HAVE_DMA
bool in_dma(uint64_t address) {
  return address >= kDmaBase && address - kDmaBase <= uint64_t(kDmaSize) - 4;
}
#endif

std::vector<std::string> split(const std::string &text, char separator) {
  std::vector<std::string> parts;
  std::string current;
  for (const char character : text) {
    if (character == separator) { parts.push_back(current); current.clear(); }
    else current.push_back(character);
  }
  parts.push_back(current);
  return parts;
}

// JAL rd=0 with a PC-relative offset: the fixed trampoline return jump the host
// writes right after a record's program words.  A program never carries control
// flow of its own, so this is the only jump inside the slot.
uint32_t encode_trampoline_return(uint32_t pc, uint32_t target) {
  const int32_t delta = int32_t(target) - int32_t(pc);
  if (delta % 2 || delta < -(1 << 20) || delta >= (1 << 20))
    throw std::runtime_error("trampoline return jump is out of JAL range");
  const uint32_t imm = uint32_t(delta);
  return (((imm >> 20) & 1u) << 31) | (((imm >> 1) & 0x3ffu) << 21)
         | (((imm >> 11) & 1u) << 20) | (((imm >> 12) & 0xffu) << 12) | 0x6fu;
}

// BEGIN F1_ADDRESS_PROVENANCE
// Mirror of myfuzz.fuzz.rv32_program._provenance_states and
// validate_address_program, the Python authority for the opt-in computed-base
// address forms.  Every tracked register holds one of three may-values:
//
//   unknown    firmware state, a loaded word, or an untracked operation;
//   constant   an exactly known 32-bit constant;
//   window     data_base + d for some d in [low, high].
//
// Only the window interval is needed to decide whether a computed memory base
// is statically inside the declared data window.  A program with strictly
// forward branches is a DAG, so one pass in index order with a union merge at
// every branch target is exact: the merge takes the union of the two proven
// ranges, and a constant that two paths disagree on becomes unknown.  ANDI folds
// only a proven constant: a mask on an address clears the base's high bits, so
// that result is a bare offset and is reported as unknown instead of being
// trusted.  Control-flow legality is not decided here (make_record owns it):
// this pass only proves memory addresses.
namespace f1_provenance {

enum class Kind { kUnknown, kConstant, kWindow };

struct Value {
  Kind kind = Kind::kUnknown;
  uint32_t constant = 0;
  int64_t low = 0;
  int64_t high = 0;
};

inline Value unknown() { return Value(); }

inline Value constant(uint32_t value) {
  Value out;
  out.kind = Kind::kConstant;
  out.constant = value;
  return out;
}

inline Value window(int64_t low, int64_t high) {
  Value out;
  out.kind = Kind::kWindow;
  out.low = low;
  out.high = high;
  return out;
}

// The 12-bit I-type immediate, sign-extended.
inline int64_t immediate_i(uint32_t word) {
  const uint32_t raw = (word >> 20) & 0xfffu;
  return (raw & 0x800u) ? int64_t(raw) - 4096 : int64_t(raw);
}

// The 12-bit S-type immediate, sign-extended (a store splits it in two fields).
inline int64_t immediate_s(uint32_t word) {
  const uint32_t raw = (((word >> 25) & 0x7fu) << 5) | ((word >> 7) & 0x1fu);
  return (raw & 0x800u) ? int64_t(raw) - 4096 : int64_t(raw);
}

inline Value addi(const Value &source, int64_t immediate) {
  if (source.kind == Kind::kConstant)
    return constant(uint32_t((uint64_t(source.constant) + uint64_t(immediate))
                             & 0xffffffffu));
  if (source.kind == Kind::kWindow)
    return window(source.low + immediate, source.high + immediate);
  return unknown();
}

inline Value add(const Value &left, const Value &right) {
  if (left.kind == Kind::kConstant && right.kind == Kind::kConstant)
    return constant(uint32_t((uint64_t(left.constant) + uint64_t(right.constant))
                             & 0xffffffffu));
  if (left.kind == Kind::kWindow && right.kind == Kind::kConstant)
    return window(left.low + int64_t(right.constant),
                  left.high + int64_t(right.constant));
  if (left.kind == Kind::kConstant && right.kind == Kind::kWindow)
    return window(right.low + int64_t(left.constant),
                  right.high + int64_t(left.constant));
  return unknown();
}

inline Value andi(const Value &source, uint32_t mask) {
  if (source.kind == Kind::kConstant) return constant(source.constant & mask);
  return unknown();
}

// The 13-bit B-type immediate, sign-extended: imm[12|10:5] at 31|30:25 and
// imm[4:1|11] at 11:8|7.
inline int64_t immediate_b(uint32_t word) {
  const uint32_t raw = (((word >> 31) & 0x1u) << 12)
                       | (((word >> 7) & 0x1u) << 11)
                       | (((word >> 25) & 0x3fu) << 5)
                       | (((word >> 8) & 0xfu) << 1);
  return (raw & 0x1000u) ? int64_t(raw) - 8192 : int64_t(raw);
}

inline bool same(const Value &left, const Value &right) {
  if (left.kind != right.kind) return false;
  if (left.kind == Kind::kConstant) return left.constant == right.constant;
  if (left.kind == Kind::kWindow)
    return left.low == right.low && left.high == right.high;
  return true;
}

// The join at a control-flow merge: the union of two proven window ranges is a
// sound over-approximation, and anything else is unknown.
inline Value merge(const Value &left, const Value &right) {
  if (same(left, right)) return left;
  if (left.kind == Kind::kWindow && right.kind == Kind::kWindow)
    return window(left.low < right.low ? left.low : right.low,
                  left.high > right.high ? left.high : right.high);
  return unknown();
}

struct Result {
  bool ok = true;
  unsigned index = 0;
  std::string message;
};

inline Result fail(unsigned index, const std::string &message) {
  Result result;
  result.ok = false;
  result.index = index;
  result.message = message;
  return result;
}

// Check every LW/SW against the declared window: x18 keeps the legacy "any
// in-window immediate" form, every other base must be proven window[d, d] (so
// the immediate is 0) and its whole proven range plus the immediate must stay
// 4-byte aligned inside [0, window_words * 4 - 4].  The state before each word
// is the merge of every path that reaches it, so a branch target sees the union
// of its fall-through and taken predecessors.
inline Result check(const uint32_t *words, unsigned count,
                    unsigned window_words) {
  // F1_MAX_WORDS never exceeds 16; the table is one slot above that so a
  // hand-built caller is still bounded instead of writing out of range.
  static constexpr unsigned kCapacity = 32;
  Value states[kCapacity][32];
  bool live[kCapacity];
  for (unsigned index = 0; index < kCapacity; ++index) {
    live[index] = false;
    for (unsigned reg = 0; reg < 32; ++reg) states[index][reg] = unknown();
  }
  if (count == 0 || count > kCapacity)
    return fail(0, "F1 program has no instruction");
  states[0][0] = constant(0);
  states[0][18] = window(0, 0);
  live[0] = true;
  const int64_t window_end = int64_t(window_words) * 4;
  for (unsigned index = 0; index < count; ++index) {
    const uint32_t word = words[index];
    const unsigned opcode = word & 0x7fu;
    const unsigned rd = (word >> 7) & 31u;
    const unsigned funct3 = (word >> 12) & 7u;
    const unsigned rs1 = (word >> 15) & 31u;
    const unsigned rs2 = (word >> 20) & 31u;
    // The state before this word: all-unknown when no path reaches it, which is
    // the same reading the Python authority uses for an unreachable word.
    // ``outgoing`` is the state after it, which is what its successors merge.
    Value outgoing[32];
    for (unsigned reg = 0; reg < 32; ++reg) outgoing[reg] = states[index][reg];
    if (opcode == 0x03u || opcode == 0x23u) {
      const bool store = opcode == 0x23u;
      const int64_t offset = store ? immediate_s(word) : immediate_i(word);
      if (rs1 != 18u && offset != 0)
        return fail(index, "F1 program memory word " + std::to_string(index) +
                               " with a computed base must use immediate 0");
      const Value base = states[index][rs1];
      if (base.kind != Kind::kWindow)
        return fail(index, "F1 program memory word " + std::to_string(index) +
                               " base x" + std::to_string(rs1) +
                               " is not a statically proven data-window address");
      const int64_t low = base.low + offset;
      const int64_t high = base.high + offset;
      if (low % 4 || high % 4)
        return fail(index, "F1 program memory word " + std::to_string(index) +
                               " address is not 4-byte aligned (offset range " +
                               std::to_string(low) + ".." + std::to_string(high) +
                               ")");
      if (low < 0 || high > window_end - 4)
        return fail(index, "F1 program memory word " + std::to_string(index) +
                               " leaves the declared data window (offset range " +
                               std::to_string(low) + ".." + std::to_string(high) +
                               ")");
      // A load writes its destination (a word read from the window is not a
      // proven address); a store writes no register.
      if (opcode == 0x03u && rd != 0) outgoing[rd] = unknown();
    } else if (opcode != 0x63u && rd != 0) {
      // A branch writes no register: its bits 11:7 are immediate bits, not a
      // destination.  Every other word with a destination applies the checked
      // transfer below.
      Value next = unknown();
      if (opcode == 0x37u) {
        next = constant(uint32_t((word >> 12) << 12));
      } else if (opcode == 0x13u && funct3 == 0u) {
        next = addi(states[index][rs1], immediate_i(word));
      } else if (opcode == 0x13u && funct3 == 7u) {
        next = andi(states[index][rs1], uint32_t(immediate_i(word)));
      } else if (opcode == 0x33u && funct3 == 0u && (word >> 25) == 0u) {
        next = add(states[index][rs1], states[index][rs2]);
      }
      // Every other write (AUIPC, shifts, other M/R operations) is unknown; the
      // word itself is still admitted by the ordinary ALU rule.
      outgoing[rd] = next;
    }
    // Successors of the DAG: the fall-through word and, for a branch, its
    // strictly-forward target.  A target at the appended return jump (index
    // count) has no state to merge into.
    unsigned successors[2] = {index + 1, index + 1};
    unsigned successor_count = 1;
    if (opcode == 0x63u) {
      const int64_t displacement = immediate_b(word);
      if (displacement % 4 == 0) {
        const int64_t target = int64_t(index) + displacement / 4;
        if (target > int64_t(index) && target < int64_t(count)
            && target != int64_t(index) + 1) {
          successors[1] = unsigned(target);
          successor_count = 2;
        }
      }
    }
    for (unsigned slot = 0; slot < successor_count; ++slot) {
      const unsigned successor = successors[slot];
      if (successor >= count) continue;
      if (!live[successor]) {
        for (unsigned reg = 0; reg < 32; ++reg)
          states[successor][reg] = outgoing[reg];
        live[successor] = true;
      } else {
        for (unsigned reg = 0; reg < 32; ++reg)
          states[successor][reg] = merge(states[successor][reg], outgoing[reg]);
      }
    }
  }
  return Result();
}

}  // namespace f1_provenance
// END F1_ADDRESS_PROVENANCE

// BEGIN F1_BRANCH_TARGET
// The host mirror of the opt-in forward-branch rule, and the one place a
// branch target is decoded.  The Python authority is
// myfuzz.fuzz.rv32_program.validate_program_words(..., allow_branches=True):
// only the six B-type branches are admitted, the target is
// ``kSlot + 4 * index + sext(bimm)``, it must be 4-byte aligned and strictly
// forward, and it must stay inside the installed image.  ``count`` is the
// record-word count, so the target ``count`` is the appended return jump the
// firmware/host writes right after the last installed word: reaching it is the
// legal way out of the slot, not an escape.  Everything else is refused by
// name, never repaired.
namespace f1_branch {

struct Result {
  bool ok = true;
  uint32_t target = 0;
  std::string message;
};

// The 13-bit B-type immediate, sign-extended.
inline int64_t immediate_b(uint32_t word) {
  const uint32_t raw = (((word >> 31) & 0x1u) << 12)
                       | (((word >> 7) & 0x1u) << 11)
                       | (((word >> 25) & 0x3fu) << 5)
                       | (((word >> 8) & 0xfu) << 1);
  return (raw & 0x1000u) ? int64_t(raw) - 8192 : int64_t(raw);
}

inline Result fail(const std::string &message) {
  Result result;
  result.ok = false;
  result.message = message;
  return result;
}

// The legal target of the branch at ``index``, or a named refusal.
inline Result check(uint32_t word, unsigned index, unsigned count,
                    uint32_t slot) {
  const unsigned opcode = word & 0x7fu;
  if (opcode != 0x63u)
    return fail("F1 instruction " + std::to_string(index) + " is not a branch");
  const unsigned funct3 = (word >> 12) & 7u;
  if (funct3 != 0u && funct3 != 1u && funct3 != 4u && funct3 != 5u
      && funct3 != 6u && funct3 != 7u)
    return fail("F1 instruction " + std::to_string(index) + " is branch funct3 " +
                std::to_string(funct3) +
                "; only BEQ/BNE/BLT/BGE/BLTU/BGEU are admitted");
  const int64_t displacement = immediate_b(word);
  if (displacement % 4 != 0)
    return fail("F1 branch " + std::to_string(index) +
                " target is not 4-byte aligned (displacement " +
                std::to_string(displacement) + ")");
  if (displacement <= 0)
    return fail("F1 branch " + std::to_string(index) +
                " branches backward (displacement " +
                std::to_string(displacement) +
                "); only strictly forward branches are admitted");
  const uint32_t pc = slot + 4u * index;
  const uint32_t program_end = slot + 4u * count;
  const uint32_t target = uint32_t(int64_t(pc) + displacement);
  if (target <= pc || target > program_end)
    return fail("F1 branch " + std::to_string(index) + " target " +
                std::to_string(target) +
                " is outside the installed image; the target must be in (" +
                std::to_string(pc) + ", " + std::to_string(program_end) + "]");
  Result result;
  result.target = target;
  return result;
}

}  // namespace f1_branch
// END F1_BRANCH_TARGET

// BEGIN F1_COMPRESSED_PARCEL
// The host mirror of the opt-in compressed (two-parcel) record word.  The Python
// authority is myfuzz.fuzz.rv32_compressed.validate_compressed_program /
// decode_compressed_parcel: a record word whose bits [1:0] are not ``11`` is two
// 16-bit parcels, the low half executing at pc and the high half at pc + 2, and
// each parcel must be one of the safe straight-line ALU forms with a destination
// in x12..x15.  A 32-bit instruction still occupies a whole record word and may
// not straddle one (a high half that starts a 32-bit-length encoding is refused).
// Compressed control transfers and compressed loads/stores are refused by name;
// so are the stack-pointer, system, floating-point and RV64-only forms.  HINT
// encodings (a zero immediate or a zero shift amount) are refused even though
// their effect would be a no-op, because the entry's record gate treats them as
// implementation-defined.
namespace f1_parcels {

// The opt-in parcel groups.  The generated spike_config.h states them; a
// hand-built or mirrored copy of this block keeps the historical ALU-only gate.
#ifndef F1_ALLOW_COMPRESSED_CONTROL
#define F1_ALLOW_COMPRESSED_CONTROL 0
#endif
#ifndef F1_ALLOW_COMPRESSED_MEMORY
#define F1_ALLOW_COMPRESSED_MEMORY 0
#endif
// Whether the case's retirement evidence is the reference trace rather than
// "every installed word retired".  Every opt-in control shape (branches, jumps,
// the bounded loop, compressed parcels) retires a sequence the Python reference
// trace decides, so the host prints and compares the same trace hash.  The two
// declared whole-record modes need it too: a trap program's ECALL retires with
// trap=1 (never "every installed word retired untrapped"), and an RV64 program's
// writebacks are 64-bit values the reference trace decides.
#ifndef F1_RV64
#define F1_RV64 0
#endif
#ifndef F1_TRAP_PROGRAM
#define F1_TRAP_PROGRAM 0
#endif
#define F1_TRACED (F1_ALLOW_BRANCHES || F1_ALLOW_JUMPS || F1_ALLOW_LOOPS \
                   || F1_ALLOW_COMPRESSED || F1_ALLOW_COMPRESSED_CONTROL \
                   || F1_ALLOW_COMPRESSED_MEMORY || F1_RV64 || F1_TRAP_PROGRAM)

struct Result {
  bool ok = true;
  unsigned index = 0;     // the record word this parcel belongs to
  unsigned half = 0;      // 0 = the low parcel at pc, 1 = the high parcel at pc+2
  uint32_t rd = 0;        // destination register of an admitted parcel
  const char *name = "";  // the encoding this result names
  std::string message;
};

inline std::string hex4(uint32_t value) {
  static const char digits[] = "0123456789abcdef";
  std::string text("0x");
  for (int shift = 12; shift >= 0; shift -= 4)
    text += digits[(value >> shift) & 0xfu];
  return text;
}

inline Result fail(unsigned index, unsigned half, const char *name,
                   const std::string &message) {
  Result result;
  result.ok = false;
  result.index = index;
  result.half = half;
  result.name = name;
  result.message = message;
  return result;
}

// A recognised-but-refused form, by the name the entry's refusals use.
inline Result refused(unsigned index, unsigned half, const char *name) {
  const std::string label(name);
  if (label == "C.J" || label == "C.JAL" || label == "C.JR"
      || label == "C.JALR" || label == "C.BEQZ" || label == "C.BNEZ")
    return fail(index, half, name,
                "compressed control transfer " + label + " is refused; only "
                "forward 32-bit branches are admitted");
  if (label == "C.LW" || label == "C.SW" || label == "C.LWSP"
      || label == "C.SWSP" || label == "C.LD" || label == "C.SD"
      || label == "C.LDSP" || label == "C.SDSP" || label == "C.FLDSP"
      || label == "C.FSDSP" || label == "C.FLWSP" || label == "C.FSWSP")
    return fail(index, half, name,
                "compressed memory instruction " + label + " is refused; use a "
                "32-bit LW/SW against x18");
  return fail(index, half, name,
              "compressed form " + label + " is refused; only safe ALU parcels "
              "with a destination in x12..x15 are admitted");
}

// The 6-bit immediate of a CI/CANDI parcel, sign-extended (the same 5-bit field
// as a shift amount, plus its high bit at bit 12).
inline int64_t immediate6(uint32_t parcel) {
  const uint32_t raw = ((parcel >> 2) & 0x1fu) | (((parcel >> 12) & 1u) << 5);
  return (raw & 0x20u) ? int64_t(raw) - 64 : int64_t(raw);
}

inline uint32_t shamt5(uint32_t parcel) {
  return ((parcel >> 2) & 0x1fu) | (((parcel >> 12) & 1u) << 5);
}

inline uint32_t rd_field(uint32_t parcel) { return (parcel >> 7) & 0x1fu; }
inline uint32_t rs2_field(uint32_t parcel) { return (parcel >> 2) & 0x1fu; }
inline uint32_t prime_rd(uint32_t parcel) { return 8u + ((parcel >> 7) & 7u); }
inline uint32_t prime_rs2(uint32_t parcel)
{ return 8u + ((parcel >> 2) & 7u); }
// The admitted destination range: x12..x15.  x8/x9/x18 are excluded by the same
// range, so the host's reserved-register rule needs no second check here.
inline bool prime(uint32_t reg) { return reg >= 12u && reg <= 15u; }

inline Result outside(unsigned index, unsigned half, const char *name,
                      const std::string &what) {
  return fail(index, half, name,
              what + " is outside the admitted x12..x15 range");
}

// One 16-bit parcel against the admitted subset.
inline Result check_parcel(uint32_t parcel, unsigned index, unsigned half) {
  const std::string position = "F1 program record word " +
      std::to_string(index) + (half == 0u ? " low" : " high") + " parcel at pc+" +
      std::to_string(half * 2u) + ": ";
  const auto reject = [&](const Result &inner) {
    return fail(index, half, inner.name, position + inner.message);
  };
  const unsigned quadrant = parcel & 3u;
  const unsigned funct3 = (parcel >> 13) & 7u;
  if (quadrant == 0u) {
#if F1_ALLOW_COMPRESSED_MEMORY
    if (funct3 == 2u) {
      // The CL format: rd' is bits 4:2 and rs1' is bits 9:7.
      const uint32_t rd = 8u + ((parcel >> 2) & 7u);
      if (rd == 8u || rd == 9u)
        return fail(index, half, "C.LW",
                    position + "C.LW dest x" + std::to_string(rd) +
                    " is a reserved register");
      Result ok;
      ok.index = index;
      ok.half = half;
      ok.rd = rd;
      ok.name = "C.LW";
      return ok;
    }
    if (funct3 == 6u) {
      Result ok;
      ok.index = index;
      ok.half = half;
      ok.name = "C.SW";
      return ok;
    }
#endif
    const char *name = nullptr;
    switch (funct3) {
      case 0u: name = "C.ADDI4SPN"; break;
      case 2u: name = "C.LW"; break;
      case 3u: name = "C.LD"; break;
      case 6u: name = "C.SW"; break;
      case 7u: name = "C.SD"; break;
      default: break;
    }
    if (name == nullptr)
      return fail(index, half, "",
                  position + "compressed parcel " + hex4(parcel) +
                  " has reserved quadrant 0 funct3 " + std::to_string(funct3));
    return reject(refused(index, half, name));
  }
  if (quadrant == 1u) {
    if (funct3 == 0u) {
      const uint32_t rd = rd_field(parcel);
      if (rd == 0u) {
        if (immediate6(parcel) == 0)
          return reject(refused(index, half, "C.NOP"));
        return reject(refused(index, half, "C.RESERVED"));
      }
      if (!prime(rd)) return reject(outside(index, half, "C.ADDI",
                                           "C.ADDI dest x" + std::to_string(rd)));
      if (immediate6(parcel) == 0)
        return reject(fail(index, half, "C.ADDI",
                           "C.ADDI with a zero immediate is a HINT and is "
                           "refused"));
      Result ok;
      ok.index = index;
      ok.half = half;
      ok.rd = rd;
      ok.name = "C.ADDI";
      return ok;
    }
#if F1_ALLOW_COMPRESSED_CONTROL
    if (funct3 == 1u) {
      Result ok;
      ok.index = index;
      ok.half = half;
      ok.rd = 1u;
      ok.name = "C.JAL";
      return ok;
    }
#else
    if (funct3 == 1u) return reject(refused(index, half, "C.JAL"));
#endif
    if (funct3 == 2u) {
      const uint32_t rd = rd_field(parcel);
      if (!prime(rd)) return reject(outside(index, half, "C.LI",
                                           "C.LI dest x" + std::to_string(rd)));
      if (immediate6(parcel) == 0)
        return reject(fail(index, half, "C.LI",
                           "C.LI with a zero immediate is a HINT and is "
                           "refused"));
      Result ok;
      ok.index = index;
      ok.half = half;
      ok.rd = rd;
      ok.name = "C.LI";
      return ok;
    }
    if (funct3 == 3u) {
      const uint32_t rd = rd_field(parcel);
      if (rd == 2u) return reject(refused(index, half, "C.ADDI16SP"));
      if (!prime(rd)) return reject(outside(index, half, "C.LUI",
                                           "C.LUI dest x" + std::to_string(rd)));
      if (immediate6(parcel) == 0)
        return reject(fail(index, half, "C.LUI",
                           "C.LUI with a zero immediate is reserved"));
      Result ok;
      ok.index = index;
      ok.half = half;
      ok.rd = rd;
      ok.name = "C.LUI";
      return ok;
    }
#if F1_ALLOW_COMPRESSED_CONTROL
    if (funct3 == 5u || funct3 == 6u || funct3 == 7u) {
      const char *name = funct3 == 5u ? "C.J"
                       : funct3 == 6u ? "C.BEQZ" : "C.BNEZ";
      Result ok;
      ok.index = index;
      ok.half = half;
      ok.name = name;
      return ok;
    }
#else
    if (funct3 == 5u) return reject(refused(index, half, "C.J"));
    if (funct3 == 6u) return reject(refused(index, half, "C.BEQZ"));
    if (funct3 == 7u) return reject(refused(index, half, "C.BNEZ"));
#endif
    // funct3 == 4: the shift / AND-immediate / register-op group.
    const unsigned operation = (parcel >> 10) & 3u;
    if (operation != 3u) {
      const char *name = operation == 0u ? "C.SRLI"
                       : operation == 1u ? "C.SRAI" : "C.ANDI";
      const uint32_t rd = prime_rd(parcel);
      if (!prime(rd))
        return reject(outside(index, half, name,
                              std::string(name) + " dest x" +
                              std::to_string(rd)));
      if (std::string(name) != "C.ANDI" && shamt5(parcel) == 0u)
        return reject(fail(index, half, name,
                           std::string(name) + " with a zero shift amount is a "
                           "HINT and is refused"));
      Result ok;
      ok.index = index;
      ok.half = half;
      ok.rd = rd;
      ok.name = name;
      return ok;
    }
    if ((parcel >> 12) & 1u)
      return reject(fail(index, half, "C.SUBW",
                         "compressed word forms C.SUBW/C.ADDW require RV64 and "
                         "are refused on RV32"));
    const unsigned alu_operation = (parcel >> 5) & 3u;
    const char *name = alu_operation == 0u ? "C.SUB"
                     : alu_operation == 1u ? "C.XOR"
                     : alu_operation == 2u ? "C.OR" : "C.AND";
    const uint32_t rd = prime_rd(parcel), rs2 = prime_rs2(parcel);
    if (!prime(rd) || !prime(rs2))
      return reject(outside(index, half, name,
                            std::string(name) + " registers x" +
                            std::to_string(rd) + "/x" + std::to_string(rs2)));
    Result ok;
    ok.index = index;
    ok.half = half;
    ok.rd = rd;
    ok.name = name;
    return ok;
  }
  if (quadrant == 2u) {
    if (funct3 == 0u) {
      const uint32_t rd = rd_field(parcel);
      if (!prime(rd))
        return reject(outside(index, half, "C.SLLI",
                              "C.SLLI dest x" + std::to_string(rd)));
      if (shamt5(parcel) == 0u)
        return reject(fail(index, half, "C.SLLI",
                           "C.SLLI with a zero shift amount is a HINT and is "
                           "refused"));
      Result ok;
      ok.index = index;
      ok.half = half;
      ok.rd = rd;
      ok.name = "C.SLLI";
      return ok;
    }
    if (funct3 == 1u) return reject(refused(index, half, "C.FLDSP"));
    if (funct3 == 3u) return reject(refused(index, half, "C.FLWSP"));
    if (funct3 == 5u) return reject(refused(index, half, "C.FSDSP"));
    if (funct3 == 7u) return reject(refused(index, half, "C.FSWSP"));
#if F1_ALLOW_COMPRESSED_MEMORY
    if (funct3 == 2u) {
      const uint32_t rd = rd_field(parcel);
      if (rd == 0u)
        return reject(fail(index, half, "C.LWSP",
                           "C.LWSP with rd=x0 is a HINT and is refused"));
      if (rd == 8u || rd == 9u || rd == 18u)
        return reject(fail(index, half, "C.LWSP",
                           "C.LWSP dest x" + std::to_string(rd) +
                           " is a reserved register"));
      Result ok;
      ok.index = index;
      ok.half = half;
      ok.rd = rd;
      ok.name = "C.LWSP";
      return ok;
    }
    if (funct3 == 6u) {
      Result ok;
      ok.index = index;
      ok.half = half;
      ok.name = "C.SWSP";
      return ok;
    }
#else
    if (funct3 == 2u) return reject(refused(index, half, "C.LWSP"));
    if (funct3 == 6u) return reject(refused(index, half, "C.SWSP"));
#endif
    // funct3 == 4: C.MV / C.ADD, and the C.JR / C.JALR / C.EBREAK aliases.
    const uint32_t rd = rd_field(parcel), rs2 = rs2_field(parcel);
    if (((parcel >> 12) & 1u) == 0u) {
      if (rd == 0u)
        return reject(fail(index, half, "C.JR",
                           "C.JR with rs1 = x0 is a reserved encoding and is "
                           "refused"));
      if (rs2 == 0u) {
#if F1_ALLOW_COMPRESSED_CONTROL
        Result ok;
        ok.index = index;
        ok.half = half;
        ok.name = "C.JR";
        return ok;
#else
        return reject(refused(index, half, "C.JR"));
#endif
      }
      if (!prime(rd) || !prime(rs2))
        return reject(outside(index, half, "C.MV",
                              "C.MV registers x" + std::to_string(rd) + "/x" +
                              std::to_string(rs2)));
      Result ok;
      ok.index = index;
      ok.half = half;
      ok.rd = rd;
      ok.name = "C.MV";
      return ok;
    }
    if (rd == 0u) return reject(refused(index, half, "C.EBREAK"));
    if (rs2 == 0u) {
#if F1_ALLOW_COMPRESSED_CONTROL
      Result ok;
      ok.index = index;
      ok.half = half;
      ok.rd = 1u;
      ok.name = "C.JALR";
      return ok;
#else
      return reject(refused(index, half, "C.JALR"));
#endif
    }
    if (!prime(rd) || !prime(rs2))
      return reject(outside(index, half, "C.ADD",
                            "C.ADD registers x" + std::to_string(rd) + "/x" +
                            std::to_string(rs2)));
    Result ok;
    ok.index = index;
    ok.half = half;
    ok.rd = rd;
    ok.name = "C.ADD";
    return ok;
  }
  // quadrant == 3: a 32-bit-length encoding is not a parcel.
  return fail(index, half, "",
              position + "compressed parcel " + hex4(parcel) +
              " is a 32-bit-length encoding, not a 16-bit parcel");
}

// One record word: a whole 32-bit instruction (the caller's own 32-bit rules
// decide it) or two parcels.
inline Result check_word(uint32_t word, unsigned index) {
  Result result;
  result.index = index;
  if ((word & 3u) == 3u) return result;
  if (((word >> 16) & 3u) == 3u) {
    return fail(index, 1, "",
                "F1 program record word " + std::to_string(index) +
                " high parcel starts a 32-bit instruction at pc+2; a 32-bit "
                "instruction may not straddle a record word");
  }
  for (unsigned half = 0; half < 2; ++half) {
    const uint32_t parcel = half == 0u ? (word & 0xffffu) : (word >> 16);
    const Result one = check_parcel(parcel, index, half);
    if (!one.ok) return one;
  }
  return result;
}

// The instruction byte at ``offset`` (0 or 2) of one installed record word: the
// 16-bit parcel for a compressed word.  It is also the value RVFI reports as
// ``insn`` for a compressed retirement ({16'b0, parcel}), so the retirement
// comparison and the trace hash use the same number.
inline uint32_t parcel_at(uint32_t word, uint32_t offset) {
  return offset == 0u ? (word & 0xffffu) : (word >> 16);
}

// The first instruction of one installed record word: its low parcel for a pair
// word, the whole 32-bit instruction otherwise.
inline uint32_t first_instruction(uint32_t word) {
  return (word & 3u) == 3u ? word : (word & 0xffffu);
}

// How many instructions one installed image retires: two per pair word, one per
// whole 32-bit word.
inline unsigned instruction_count(const uint32_t *words, unsigned count) {
  unsigned total = 0;
  for (unsigned index = 0; index < count; ++index)
    total += (words[index] & 3u) == 3u ? 1u : 2u;
  return total;
}

}  // namespace f1_parcels
// END F1_COMPRESSED_PARCEL

// BEGIN F1_TRACE_HASH
// The in-slot retirement trace hash: FNV-1a 32 over the four little-endian
// 32-bit fields (pc, insn, rd, wdata) of every RVFI retirement, in retirement
// order.  It is the same FNV-1a pair the data-window hash uses and the exact
// value myfuzz.fuzz.f1_program_gate.trace_hash computes from a reference trace,
// projected onto what RVFI exposes (a retirement that writes no register has
// rd_addr 0 and rd_wdata 0).  Python correspondence compares the two.
namespace f1_trace {

inline uint32_t offset_basis() { return 2166136261u; }

inline uint32_t step(uint32_t hash, uint32_t value) {
  for (unsigned byte = 0; byte < 4; ++byte) {
    hash ^= (value >> (8 * byte)) & 0xffu;
    hash *= 16777619u;
  }
  return hash;
}

inline uint32_t entry(uint32_t hash, uint32_t pc, uint32_t insn, uint32_t rd,
                      uint32_t wdata) {
  return step(step(step(step(hash, pc), insn), rd), wdata);
}

}  // namespace f1_trace
// END F1_TRACE_HASH

// BEGIN F1_TRACE_HASH_64
// The 64-bit twin of the trace hash, for a declaration whose CPU really is RV64
// (`F1_RV64`).  It is FNV-1a 64 over the same four fields, each as an
// little-endian 8-byte value: the record's own 64-bit ``pc_rdata`` and
// ``rd_wdata``, the 32-bit instruction word and the 5-bit register index widened
// to 64 bits.  The Python authority is ``myfuzz.fuzz.f1_rv64.trace_hash64``; the
// 32-bit digest above is never used to state an RV64 result.
namespace f1_trace64 {

inline uint64_t offset_basis() { return 14695981039346656037ull; }

inline uint64_t step(uint64_t hash, uint64_t value) {
  for (unsigned byte = 0; byte < 8; ++byte) {
    hash ^= (value >> (8 * byte)) & 0xffull;
    hash *= 1099511628211ull;
  }
  return hash;
}

inline uint64_t entry(uint64_t hash, uint64_t pc, uint64_t insn, uint64_t rd,
                      uint64_t wdata) {
  return step(step(step(step(hash, pc), insn), rd), wdata);
}

}  // namespace f1_trace64
// END F1_TRACE_HASH_64

// BEGIN F1_CONTROL_FLOW
// The host mirror of the opt-in control-flow shapes: statically proven JAL/JALR,
// the canonical bounded loop, and the compressed control/memory parcel groups.
// The Python authority is myfuzz.fuzz.rv32_program.control_flow_analysis /
// validate_program_words and myfuzz.fuzz.rv32_compressed.
// validate_compressed_program; this pass decides exactly the same facts:
//
//   * a JAL target is ``pc + sext(jimm)``; a JALR target is
//     ``x[rs1] + sext(imm)`` and is admitted only when ``rs1`` is x0 or a
//     register the program provably loads one exact constant into (the same
//     LUI/ADDI/ADD/ANDI provenance the address forms use).  Both link x0/x1 only.
//   * a compressed C.J/C.JAL/C.BEQZ/C.BNEZ target is ``pc + sext(imm)``; a
//     C.JR/C.JALR target is the proven constant in its base register.  Every
//     compressed target is strictly forward.
//   * a backward branch is legal only as the canonical bounded loop's back edge:
//     ``addi xN, x0, K`` (K in 2..6), a body that never writes xN,
//     ``addi xN, xN, -1`` and ``bne xN, x0, head``.  The trip count is static, so
//     the loop terminates and the host knows the exact retirement count.
//   * a C.LW/C.SW/C.LWSP/C.SWSP base must be a proven in-window data address and
//     the parcel's own 4-byte aligned offset must stay inside the window.
//
// Everything is refused by name, never guessed, and no target is derived from a
// register the program did not prove.
namespace f1_control {

enum class Kind {
  kAlu, kLui, kAddi, kAndi, kAdd, kLw, kSw, kBranch, kJal, kJalr,
  kCAddi, kCli, kClui, kCAndi, kCMv, kCAdd, kCOther,
  kCJ, kCJal, kCJr, kCJalr, kCBeqz, kCBnez, kCLw, kCSw, kCLwsp, kCSwsp,
};

struct Entry {
  uint32_t pc = 0;       // byte offset inside the image
  uint32_t word = 0;     // the installed record word
  uint32_t parcel = 0;   // the 16-bit parcel (0 for a 32-bit word)
  unsigned width = 4;    // 2 or 4
  unsigned index = 0;    // record word index
  unsigned half = 0;     // 0/1 for a parcel, 0 for a 32-bit word
  Kind kind = Kind::kAlu;
  int64_t imm = 0;
  uint32_t rd = 0, rs1 = 0, rs2 = 0;
};

// F1_MAX_WORDS never exceeds 16, so an image has at most 32 instruction starts
// (two parcels per record word); the table is one slot above that.
static constexpr unsigned kCapacity = 40;

struct Image {
  Entry entries[kCapacity];
  unsigned count = 0;
  uint32_t program_end = 0;
};

struct Result {
  bool ok = true;
  std::string message;
  // What the host expects to observe: the exact retirement count of a bounded
  // loop image, or 0 when the existing range check applies.
  unsigned expected_retires = 0;
  bool exact_retires = false;
  bool loop_mode = false;
  unsigned loop_repeats = 0;
};

inline Result fail(const std::string &message) {
  Result result;
  result.ok = false;
  result.message = message;
  return result;
}

inline bool is_control(Kind kind) {
  switch (kind) {
    case Kind::kBranch: case Kind::kJal: case Kind::kJalr: case Kind::kCJ:
    case Kind::kCJal: case Kind::kCJr: case Kind::kCJalr: case Kind::kCBeqz:
    case Kind::kCBnez:
      return true;
    default:
      return false;
  }
}

inline bool is_unconditional(Kind kind) {
  switch (kind) {
    case Kind::kJal: case Kind::kJalr: case Kind::kCJ: case Kind::kCJal:
    case Kind::kCJr: case Kind::kCJalr:
      return true;
    default:
      return false;
  }
}

inline bool writes_rd(Kind kind) {
  switch (kind) {
    case Kind::kLui: case Kind::kAddi: case Kind::kAndi: case Kind::kAdd:
    case Kind::kLw: case Kind::kCAddi: case Kind::kCli: case Kind::kClui:
    case Kind::kCAndi: case Kind::kCMv: case Kind::kCAdd: case Kind::kCOther:
    case Kind::kCJal: case Kind::kCJalr: case Kind::kCLw: case Kind::kCLwsp:
      return true;
    default:
      return false;
  }
}

inline bool is_memory(Kind kind) {
  switch (kind) {
    case Kind::kLw: case Kind::kSw: case Kind::kCLw: case Kind::kCSw:
    case Kind::kCLwsp: case Kind::kCSwsp:
      return true;
    default:
      return false;
  }
}

// --- the compressed immediates ----------------------------------------------

inline int64_t cj_imm(uint32_t parcel) {
  const uint32_t raw = (((parcel >> 12) & 1u) << 11)
                       | (((parcel >> 11) & 1u) << 4)
                       | (((parcel >> 9) & 3u) << 8)
                       | (((parcel >> 8) & 1u) << 10)
                       | (((parcel >> 7) & 1u) << 6)
                       | (((parcel >> 6) & 1u) << 7)
                       | (((parcel >> 3) & 7u) << 1)
                       | (((parcel >> 2) & 1u) << 5);
  return (raw & 0x800u) ? int64_t(raw) - 4096 : int64_t(raw);
}

inline int64_t cb_imm(uint32_t parcel) {
  const uint32_t raw = (((parcel >> 12) & 1u) << 8)
                       | (((parcel >> 10) & 3u) << 3)
                       | (((parcel >> 5) & 3u) << 6)
                       | (((parcel >> 3) & 3u) << 1)
                       | (((parcel >> 2) & 1u) << 5);
  return (raw & 0x100u) ? int64_t(raw) - 512 : int64_t(raw);
}

inline int64_t cl_off(uint32_t parcel) {
  return int64_t((((parcel >> 10) & 7u) << 3) | (((parcel >> 6) & 1u) << 2)
                 | (((parcel >> 5) & 1u) << 6));
}

inline int64_t clsp_off(uint32_t parcel) {
  return int64_t((((parcel >> 12) & 1u) << 5) | (((parcel >> 4) & 7u) << 2)
                 | (((parcel >> 2) & 3u) << 6));
}

inline int64_t cssp_off(uint32_t parcel) {
  return int64_t((((parcel >> 9) & 0xfu) << 2) | (((parcel >> 7) & 3u) << 6));
}

// The 21-bit J-type immediate, sign-extended.
inline int64_t jal_imm(uint32_t word) {
  const uint32_t raw = (((word >> 31) & 1u) << 20)
                       | (((word >> 12) & 0xffu) << 12)
                       | (((word >> 20) & 1u) << 11)
                       | (((word >> 21) & 0x3ffu) << 1);
  return (raw & 0x100000u) ? int64_t(raw) - 2097152 : int64_t(raw);
}

// --- decoding ----------------------------------------------------------------

inline bool decode_word(uint32_t word, unsigned index, Entry &out) {
  out = Entry();
  out.word = word;
  out.width = 4;
  out.index = index;
  out.pc = 4u * index;
  const unsigned opcode = word & 0x7fu;
  const unsigned funct3 = (word >> 12) & 7u;
  out.rd = (word >> 7) & 31u;
  out.rs1 = (word >> 15) & 31u;
  out.rs2 = (word >> 20) & 31u;
  switch (opcode) {
    case 0x37u:
      out.kind = Kind::kLui;
      out.imm = int64_t((word >> 12) & 0xfffffu);
      return true;
    case 0x17u:
      out.kind = Kind::kAlu;  // AUIPC: no proven value
      return true;
    case 0x13u:
      if (funct3 == 0u) {
        out.kind = Kind::kAddi;
        out.imm = f1_provenance::immediate_i(word);
        return true;
      }
      if (funct3 == 7u) {
        out.kind = Kind::kAndi;
        out.imm = f1_provenance::immediate_i(word);
        return true;
      }
      out.kind = Kind::kAlu;
      return true;
    case 0x33u:
      if (funct3 == 0u && (word >> 25) == 0u) {
        out.kind = Kind::kAdd;
        return true;
      }
      out.kind = Kind::kAlu;
      return true;
    case 0x03u:
      out.kind = Kind::kLw;
      out.imm = f1_provenance::immediate_i(word);
      return true;
    case 0x23u:
      out.kind = Kind::kSw;
      out.imm = f1_provenance::immediate_s(word);
      return true;
    case 0x63u:
      out.kind = Kind::kBranch;
      out.imm = f1_provenance::immediate_b(word);
      return true;
    case 0x6fu:
      out.kind = Kind::kJal;
      out.imm = jal_imm(word);
      return true;
    case 0x67u:
      out.kind = Kind::kJalr;
      out.imm = f1_provenance::immediate_i(word);
      return true;
    default:
      return false;
  }
}

inline bool decode_parcel(uint32_t parcel, unsigned index, unsigned half,
                          Entry &out) {
  out = Entry();
  out.parcel = parcel;
  out.width = 2;
  out.index = index;
  out.half = half;
  out.pc = 4u * index + 2u * half;
  const unsigned quadrant = parcel & 3u;
  const unsigned funct3 = (parcel >> 13) & 7u;
  const uint32_t rd = f1_parcels::rd_field(parcel);
  const uint32_t rs2 = f1_parcels::rs2_field(parcel);
  const uint32_t prime_rd = f1_parcels::prime_rd(parcel);
  const uint32_t prime_rs2 = f1_parcels::prime_rs2(parcel);
  const uint32_t prime_rs1 = 8u + ((parcel >> 7) & 7u);
  if (quadrant == 0u) {
    if (funct3 == 2u) {
      out.kind = Kind::kCLw;
      out.rd = 8u + ((parcel >> 2) & 7u);
      out.rs1 = prime_rs1;
      out.imm = cl_off(parcel);
      return true;
    }
    if (funct3 == 6u) {
      out.kind = Kind::kCSw;
      out.rs2 = prime_rs2;
      out.rs1 = prime_rs1;
      out.imm = cl_off(parcel);
      return true;
    }
    return false;
  }
  if (quadrant == 1u) {
    switch (funct3) {
      case 0u:
        out.kind = Kind::kCAddi;
        out.rd = rd;
        out.imm = f1_parcels::immediate6(parcel);
        return true;
      case 1u:
        out.kind = Kind::kCJal;
        out.rd = 1u;
        out.imm = cj_imm(parcel);
        return true;
      case 2u:
        out.kind = Kind::kCli;
        out.rd = rd;
        out.imm = f1_parcels::immediate6(parcel);
        return true;
      case 3u:
        out.kind = Kind::kClui;
        out.rd = rd;
        out.imm = f1_parcels::immediate6(parcel);
        return true;
      case 4u: {
        const unsigned operation = (parcel >> 10) & 3u;
        if (operation == 2u) {
          out.kind = Kind::kCAndi;
          out.rd = prime_rd;
          out.imm = f1_parcels::immediate6(parcel);
          return true;
        }
        if (operation == 0u || operation == 1u) {
          out.kind = Kind::kCOther;
          out.rd = prime_rd;
          return true;
        }
        out.kind = Kind::kCOther;  // CA alu (and the RV64-only forms)
        out.rd = prime_rd;
        out.rs2 = prime_rs2;
        return true;
      }
      case 5u:
        out.kind = Kind::kCJ;
        out.imm = cj_imm(parcel);
        return true;
      case 6u:
        out.kind = Kind::kCBeqz;
        out.rs1 = prime_rd;
        out.imm = cb_imm(parcel);
        return true;
      case 7u:
        out.kind = Kind::kCBnez;
        out.rs1 = prime_rd;
        out.imm = cb_imm(parcel);
        return true;
      default:
        return false;
    }
  }
  if (quadrant == 2u) {
    switch (funct3) {
      case 0u:
        out.kind = Kind::kCOther;
        out.rd = rd;
        return true;
      case 2u:
        out.kind = Kind::kCLwsp;
        out.rd = rd;
        out.rs1 = 2u;
        out.imm = clsp_off(parcel);
        return true;
      case 6u:
        out.kind = Kind::kCSwsp;
        out.rs2 = rs2;
        out.rs1 = 2u;
        out.imm = cssp_off(parcel);
        return true;
      case 4u:
        if (((parcel >> 12) & 1u) == 0u) {
          if (rs2 == 0u) {
            if (rd == 0u) return false;  // C.JR x0 is reserved
            out.kind = Kind::kCJr;
            out.rs1 = rd;
            return true;
          }
          out.kind = Kind::kCMv;
          out.rd = rd;
          out.rs2 = rs2;
          return true;
        }
        if (rs2 == 0u) {
          out.kind = Kind::kCJalr;
          out.rd = 1u;
          out.rs1 = rd;
          return true;
        }
        out.kind = Kind::kCAdd;
        out.rd = rd;
        out.rs2 = rs2;
        return true;
      default:
        return false;
    }
  }
  return false;
}

inline bool build(const uint32_t *words, unsigned count, Image &image) {
  image = Image();
  image.program_end = 4u * count;
  for (unsigned index = 0; index < count; ++index) {
    const uint32_t word = words[index];
    if ((word & 3u) == 3u) {
      Entry entry;
      if (!decode_word(word, index, entry)) return false;
      if (image.count >= kCapacity) return false;
      image.entries[image.count++] = entry;
      continue;
    }
    for (unsigned half = 0; half < 2; ++half) {
      const uint32_t parcel = half == 0u ? (word & 0xffffu) : (word >> 16);
      Entry entry;
      if (!decode_parcel(parcel, index, half, entry)) return false;
      if (image.count >= kCapacity) return false;
      image.entries[image.count++] = entry;
    }
  }
  return true;
}

inline int find_pc(const Image &image, int64_t pc) {
  for (unsigned index = 0; index < image.count; ++index)
    if (int64_t(image.entries[index].pc) == pc) return int(index);
  return -1;
}

// --- the provenance transfer -------------------------------------------------

inline f1_provenance::Value transfer(const Entry &entry,
                                     const f1_provenance::Value *state) {
  using f1_provenance::add;
  using f1_provenance::addi;
  using f1_provenance::andi;
  using f1_provenance::constant;
  using f1_provenance::unknown;
  switch (entry.kind) {
    case Kind::kLui:
      return constant(uint32_t((uint64_t(entry.imm) << 12) & 0xffffffffu));
    case Kind::kAddi:
      return addi(state[entry.rs1], entry.imm);
    case Kind::kAndi:
      return andi(state[entry.rs1], uint32_t(entry.imm));
    case Kind::kAdd:
      return add(state[entry.rs1], state[entry.rs2]);
    case Kind::kCli:
      return constant(uint32_t(uint64_t(entry.imm) & 0xffffffffu));
    case Kind::kClui:
      return constant(uint32_t((uint64_t(entry.imm) << 12) & 0xffffffffu));
    case Kind::kCAddi:
      return addi(state[entry.rd], entry.imm);
    case Kind::kCAndi:
      return andi(state[entry.rd], uint32_t(entry.imm));
    case Kind::kCMv:
      return state[entry.rs2];
    case Kind::kCAdd:
      return add(state[entry.rd], state[entry.rs2]);
    default:
      return unknown();
  }
}

// The statically known target byte offset of one control transfer, or false
// when the transfer is indirect and its base is not a proven constant.
inline bool control_target(const Entry &entry,
                           const f1_provenance::Value *state, uint32_t slot,
                           int64_t &target) {
  switch (entry.kind) {
    case Kind::kBranch:
    case Kind::kJal:
    case Kind::kCJ:
    case Kind::kCJal:
    case Kind::kCBeqz:
    case Kind::kCBnez:
      target = int64_t(entry.pc) + entry.imm;
      return true;
    case Kind::kJalr:
    case Kind::kCJr:
    case Kind::kCJalr: {
      const f1_provenance::Value &base = state[entry.rs1];
      if (base.kind != f1_provenance::Kind::kConstant) return false;
      target = int64_t(base.constant) + entry.imm - int64_t(slot);
      return true;
    }
    default:
      return false;
  }
}

inline unsigned entry_index_of(const Image &image, const Entry &entry) {
  for (unsigned index = 0; index < image.count; ++index)
    if (image.entries[index].pc == entry.pc) return index;
  return image.count;
}

inline unsigned successor_list(const Entry &entry,
                               const f1_provenance::Value *state, uint32_t slot,
                               const Image &image, unsigned *out) {
  unsigned count = 0;
  const unsigned self = entry_index_of(image, entry);
  const auto add_pc = [&](int64_t pc) {
    if (pc < 0 || pc >= int64_t(image.program_end)) return;
    const int index = find_pc(image, pc);
    if (index < 0 || unsigned(index) == self) return;
    for (unsigned seen = 0; seen < count; ++seen)
      if (out[seen] == unsigned(index)) return;
    out[count++] = unsigned(index);
  };
  const auto add_index = [&](unsigned index) {
    if (index >= image.count || index == self) return;
    for (unsigned seen = 0; seen < count; ++seen)
      if (out[seen] == index) return;
    out[count++] = index;
  };
  if (is_control(entry.kind)) {
    int64_t target = 0;
    const bool resolved = control_target(entry, state, slot, target);
    if (resolved) add_pc(target);
    if (!is_unconditional(entry.kind)) add_index(self + 1);
    return count;
  }
  add_index(self + 1);
  return count;
}

// --- the whole-image check ---------------------------------------------------

inline Result check(const uint32_t *words, unsigned count, uint32_t slot,
                    unsigned window_words) {
  Image image;
  if (!build(words, count, image))
    return fail("F1 program image is not decodable by the control-flow pass");
  if (image.count == 0) return fail("F1 program has no instruction");
  // The least-fixpoint may-provenance of every register, over a graph that may
  // contain a bounded loop's back edge.  A worklist keeps it linear in practice;
  // every state is a 32-entry vector of a finite domain, so it converges.
  static constexpr unsigned kQueue = 2048;
  f1_provenance::Value states[kCapacity][32];
  bool live[kCapacity];
  for (unsigned index = 0; index < kCapacity; ++index) {
    live[index] = false;
    for (unsigned reg = 0; reg < 32; ++reg) states[index][reg] = f1_provenance::unknown();
  }
  states[0][0] = f1_provenance::constant(0u);
  states[0][18] = f1_provenance::window(0, 0);
  live[0] = true;
  unsigned queue[kQueue];
  unsigned head = 0, tail = 0;
  queue[tail++] = 0;
  while (head < tail) {
    const unsigned index = queue[head++];
    if (index >= image.count) continue;
    const Entry &entry = image.entries[index];
    f1_provenance::Value outgoing[32];
    for (unsigned reg = 0; reg < 32; ++reg) outgoing[reg] = states[index][reg];
    if (writes_rd(entry.kind) && entry.rd != 0u && entry.rd < 32u)
      outgoing[entry.rd] = transfer(entry, states[index]);
    unsigned next[2] = {0u, 0u};
    const unsigned next_count =
        successor_list(entry, states[index], slot, image, next);
    for (unsigned edge = 0; edge < next_count; ++edge) {
      const unsigned successor = next[edge];
      if (successor >= image.count) continue;
      bool changed = false;
      if (!live[successor]) {
        for (unsigned reg = 0; reg < 32; ++reg) states[successor][reg] = outgoing[reg];
        live[successor] = true;
        changed = true;
      } else {
        for (unsigned reg = 0; reg < 32; ++reg) {
          const f1_provenance::Value merged =
              f1_provenance::merge(states[successor][reg], outgoing[reg]);
          if (!f1_provenance::same(merged, states[successor][reg])) {
            states[successor][reg] = merged;
            changed = true;
          }
        }
      }
      if (changed && tail < kQueue) queue[tail++] = successor;
    }
  }

  // 1. Every control transfer must have a proven, in-image target.  A jump and
  //    every compressed transfer must be strictly forward; a 32-bit branch may
  //    be backward only as the canonical loop's back edge, which is checked
  //    below (with the macro off, a backward branch is refused here).
  for (unsigned index = 0; index < image.count; ++index) {
    const Entry &entry = image.entries[index];
    if (!is_control(entry.kind)) continue;
    int64_t target = 0;
    if (!control_target(entry, states[index], slot, target))
      return fail("F1 instruction at pc+" + std::to_string(entry.pc) +
                  " is an indirect jump whose base register is not a "
                  "statically proven constant address");
    if (target < 0 || target > int64_t(image.program_end))
      return fail("F1 instruction at pc+" + std::to_string(entry.pc) +
                  " target pc+" + std::to_string(target) +
                  " is outside the installed image");
    if (target == int64_t(image.program_end)) continue;  // the legal exit
    if (find_pc(image, target) < 0)
      return fail("F1 instruction at pc+" + std::to_string(entry.pc) +
                  " target pc+" + std::to_string(target) +
                  " is not an instruction start of this image");
    if (entry.kind != Kind::kBranch && target <= int64_t(entry.pc))
      return fail("F1 instruction at pc+" + std::to_string(entry.pc) +
                  " target pc+" + std::to_string(target) +
                  " is not strictly forward; a backward jump is refused");
  }

#if F1_ALLOW_COMPRESSED_MEMORY
  // 2. Every compressed load/store must name a proven in-window address: the
  //    base register holds ``data_base + d`` and the parcel's own 4-byte aligned
  //    offset keeps the whole proven interval inside the declared window.  A
  //    32-bit LW/SW keeps the per-word x18 rule make_record already applied.
  {
    const int64_t window_end = int64_t(window_words) * 4;
    for (unsigned index = 0; index < image.count; ++index) {
      const Entry &entry = image.entries[index];
      if (entry.kind != Kind::kCLw && entry.kind != Kind::kCSw
          && entry.kind != Kind::kCLwsp && entry.kind != Kind::kCSwsp)
        continue;
      const f1_provenance::Value &base = states[index][entry.rs1];
      if (base.kind != f1_provenance::Kind::kWindow)
        return fail("F1 compressed memory instruction at pc+" +
                    std::to_string(entry.pc) + " base x" +
                    std::to_string(entry.rs1) +
                    " is not a statically proven data-window address");
      const int64_t low = base.low + entry.imm;
      const int64_t high = base.high + entry.imm;
      if (low % 4 || high % 4)
        return fail("F1 compressed memory instruction at pc+" +
                    std::to_string(entry.pc) +
                    " address is not 4-byte aligned (offset range " +
                    std::to_string(low) + ".." + std::to_string(high) + ")");
      if (low < 0 || high > window_end - 4)
        return fail("F1 compressed memory instruction at pc+" +
                    std::to_string(entry.pc) +
                    " leaves the declared data window (offset range " +
                    std::to_string(low) + ".." + std::to_string(high) + ")");
    }
  }
#endif

#if F1_ALLOW_LOOPS
  // 3. The canonical bounded loop: identify every backward branch, prove the
  //    shape, and compute the exact retirement count.
  struct Loop {
    int64_t init_pc;
    int64_t head_pc;
    int64_t back_pc;
    unsigned trip;
    unsigned length;
  };
  Loop loops[8];
  unsigned loop_count = 0;
  unsigned expected = image.count;
  unsigned repeats = 0;
  bool exact = true;
  for (unsigned index = 0; index < image.count; ++index) {
    const Entry &entry = image.entries[index];
    if (entry.kind != Kind::kBranch) continue;
    const int64_t target = int64_t(entry.pc) + entry.imm;
    if (target > int64_t(entry.pc)) continue;
    const unsigned funct3 = (entry.word >> 12) & 7u;
    if (funct3 != 1u)
      return fail("F1 instruction at pc+" + std::to_string(entry.pc) +
                  " branches backward; only the canonical bne loop back edge "
                  "is admitted");
    const uint32_t rs1 = (entry.word >> 15) & 31u;
    const uint32_t rs2 = (entry.word >> 20) & 31u;
    uint32_t induction = 0;
    if (rs2 == 0u && rs1 != 0u) induction = rs1;
    else if (rs1 == 0u && rs2 != 0u) induction = rs2;
    else
      return fail("F1 loop back edge at pc+" + std::to_string(entry.pc) +
                  " does not compare an induction register with x0");
    if (induction == 8u || induction == 9u || induction == 18u)
      return fail("F1 loop induction register is a reserved register");
    const int step_index = find_pc(image, target);  // head
    const int init_index = find_pc(image, target - 4);
    const int dec_index = find_pc(image, int64_t(entry.pc) - 4);
    if (step_index < 0 || init_index < 0 || dec_index < 0)
      return fail("F1 loop at pc+" + std::to_string(entry.pc) +
                  " has no canonical init/step/back-edge shape");
    const Entry &init = image.entries[unsigned(init_index)];
    const Entry &step = image.entries[unsigned(dec_index)];
    if (init.kind != Kind::kAddi || init.rd != induction || init.rs1 != 0u
        || init.imm < 2 || init.imm > 6)
      return fail("F1 loop at pc+" + std::to_string(entry.pc) +
                  " has no `addi xN, x0, K` init with K in 2..6");
    if (step.kind != Kind::kAddi || step.rd != induction
        || step.rs1 != induction || step.imm != -1)
      return fail("F1 loop at pc+" + std::to_string(entry.pc) +
                  " has no `addi xN, xN, -1` induction step");
    for (unsigned body = unsigned(step_index); body < unsigned(dec_index); ++body) {
      const Entry &word = image.entries[body];
      if (is_control(word.kind))
        return fail("F1 loop body at pc+" + std::to_string(word.pc) +
                    " contains a control transfer");
      if (writes_rd(word.kind) && word.rd == induction)
        return fail("F1 loop body at pc+" + std::to_string(word.pc) +
                    " writes the induction register");
    }
    if (loop_count >= 8)
      return fail("F1 program has more than the admitted eight bounded loops");
    loops[loop_count].init_pc = target - 4;
    loops[loop_count].head_pc = target;
    loops[loop_count].back_pc = int64_t(entry.pc);
    loops[loop_count].trip = unsigned(init.imm);
    loops[loop_count].length =
        unsigned((int64_t(entry.pc) - target) / 4 + 1);
    ++loop_count;
    expected += (unsigned(init.imm) - 1u) * loops[loop_count - 1u].length;
    repeats += unsigned(init.imm) - 1u;
  }
  // Two loops must be disjoint, and no other transfer may enter a loop: the
  // only legal way in is the init that immediately precedes the head.
  for (unsigned left = 0; left < loop_count; ++left) {
    for (unsigned right = left + 1u; right < loop_count; ++right) {
      if (loops[left].init_pc <= loops[right].back_pc
          && loops[right].init_pc <= loops[left].back_pc)
        return fail("F1 bounded loops overlap; nested or interleaved loops are "
                    "not admitted");
    }
  }
  for (unsigned index = 0; index < image.count; ++index) {
    const Entry &entry = image.entries[index];
    if (!is_control(entry.kind)) continue;
    int64_t target = 0;
    if (!control_target(entry, states[index], slot, target)) continue;
    for (unsigned loop = 0; loop < loop_count; ++loop) {
      const bool own_edge = entry.kind == Kind::kBranch
                            && int64_t(entry.pc) == loops[loop].back_pc
                            && target == loops[loop].head_pc;
      if (own_edge) continue;
      if (target >= loops[loop].init_pc && target <= loops[loop].back_pc)
        return fail("F1 instruction at pc+" + std::to_string(entry.pc) +
                    " targets the interior of the bounded loop at pc+" +
                    std::to_string(loops[loop].back_pc));
    }
  }
  // A forward branch or jump may skip words, so the exact count only holds for
  // an image whose only control transfers are the loop back edges.
  for (unsigned index = 0; index < image.count; ++index) {
    const Entry &entry = image.entries[index];
    if (!is_control(entry.kind)) continue;
    bool back_edge = false;
    for (unsigned loop = 0; loop < loop_count; ++loop)
      if (entry.kind == Kind::kBranch
          && int64_t(entry.pc) == loops[loop].back_pc)
        back_edge = true;
    if (!back_edge) exact = false;
  }
  Result result;
  result.loop_mode = loop_count > 0;
  result.loop_repeats = repeats;
  if (loop_count > 0) {
    result.expected_retires = expected;
    result.exact_retires = exact;
  }
  return result;
#else
  // Without the loop declaration a backward branch is refused by name.
  for (unsigned index = 0; index < image.count; ++index) {
    const Entry &entry = image.entries[index];
    if (entry.kind != Kind::kBranch) continue;
    if (int64_t(entry.pc) + entry.imm <= int64_t(entry.pc))
      return fail("F1 instruction at pc+" + std::to_string(entry.pc) +
                  " branches backward; loops are not declared");
  }
  return Result();
#endif
}

}  // namespace f1_control
// END F1_CONTROL_FLOW

// FNV-1a over the declared program data window.  The window is a handful of
// words, so sampling it once per case is cheap, and the changed-word count and
// final hash are what a program's own stores really did to the declared RAM.
uint32_t window_hash(const Memory &memory, uint32_t base, unsigned words) {
  uint32_t hash = 2166136261u;
  for (unsigned index = 0; index < words; ++index) {
    const uint32_t value = memory.read(base + 4 * index);
    for (unsigned byte = 0; byte < 4; ++byte) {
      hash ^= (value >> (8 * byte)) & 0xffu;
      hash *= 16777619u;
    }
  }
  return hash;
}

// BEGIN F1_TRAP_PROGRAM_GATE
// The declared trap program's host-side shape gate.  The slot's first word is
// the ECALL the core must trap on; every following word is one RV32I ALU form
// whose sources this same program already wrote (or x0/x18), so the reference
// trace the entry compares is decided by the declared state.  No memory,
// control transfer, CSR or second system word is admitted, and the firmware's
// own registers (x8 mailbox, x9 reserved, x18 data base) may not be written.
namespace f1_trap_gate {

struct Result {
  bool ok = true;
  std::string message;
};

inline Result check(const uint32_t *words, unsigned count) {
  Result result;
  const auto fail = [&result](const std::string &message) {
    result.ok = false;
    result.message = message;
    return result;
  };
#ifndef F1_TRAP_WORDS
#define F1_TRAP_WORDS F1_MAX_WORDS
#endif
  if (count < 1 || count > F1_MAX_WORDS || count > F1_TRAP_WORDS)
    return fail("F1 trap program takes one to " +
                std::to_string(std::min<int>(F1_MAX_WORDS, F1_TRAP_WORDS)) +
                " word(s)");
  if (words[0] != 0x00000073u)
    return fail("F1 trap program word 0 is not an ECALL (0x00000073)");
  bool written[32] = {};
  written[0] = true;   // x0 is constant zero, x18 is the firmware's data base
  written[18] = true;
  for (unsigned index = 1; index < count; ++index) {
    const uint32_t word = words[index];
    if ((word & 3u) != 3u)
      return fail("F1 trap program word " + std::to_string(index) +
                  " is not one 32-bit instruction");
    const unsigned opcode = word & 0x7fu, rd = (word >> 7) & 31u;
    const unsigned funct3 = (word >> 12) & 7u, rs1 = (word >> 15) & 31u;
    const unsigned rs2 = (word >> 20) & 31u, funct7 = (word >> 25) & 0x7fu;
    if (opcode != 0x37u && opcode != 0x13u && opcode != 0x33u)
      return fail("F1 trap program word " + std::to_string(index) +
                  " is outside the declared straight-line ALU subset after the "
                  "ECALL");
    if (opcode == 0x17u)
      return fail("F1 trap program word " + std::to_string(index) +
                  " is AUIPC; its value would depend on the slot address");
    if (opcode == 0x13u) {
      if (funct3 == 2u || funct3 == 3u)
        return fail("F1 trap program word " + std::to_string(index) +
                    " is SLTI/SLTIU, which this declared subset omits");
      if (funct3 == 1u && funct7 != 0u)
        return fail("F1 trap program word " + std::to_string(index) +
                    " is not an SLLI");
      if (funct3 == 5u && funct7 != 0u && funct7 != 0x20u)
        return fail("F1 trap program word " + std::to_string(index) +
                    " is not SRLI/SRAI");
    }
    if (opcode == 0x33u) {
      if (funct7 != 0u && funct7 != 0x20u)
        return fail("F1 trap program word " + std::to_string(index) +
                    " is not an RV32I OP word");
      if (funct7 == 0x20u && funct3 != 0u)
        return fail("F1 trap program word " + std::to_string(index) +
                    " is not SUB");
    }
    if (rd == 8u || rd == 9u || rd == 18u)
      return fail("F1 trap program word " + std::to_string(index) +
                  " writes a register the firmware owns");
    const bool reads_rs2 = opcode == 0x33u;
    if (opcode != 0x37u && !written[rs1])
      return fail("F1 trap program word " + std::to_string(index) +
                  " reads x" + std::to_string(rs1) + " before this program wrote it");
    if (reads_rs2 && !written[rs2])
      return fail("F1 trap program word " + std::to_string(index) +
                  " reads x" + std::to_string(rs2) + " before this program wrote it");
    written[rd] = true;
  }
  return result;
}

}  // namespace f1_trap_gate
// END F1_TRAP_PROGRAM_GATE

// BEGIN F1_RV64_GATE
// The declared RV64I program's host-side shape gate.  The subset is the one
// myfuzz.fuzz.f1_rv64 admits: LUI/ADDI/ADD/SUB/AND/OR/XOR, the RV64 word ALU
// forms ADDIW/ADDW/SLLIW/SRLIW/SRAIW, and LD/SD against x18 inside the declared
// data window.  Every read register must be one this program wrote (or x0/x18),
// no firmware-owned register may be written, and LD/SD must be 8-byte aligned
// and inside the window, so no instruction can escape the slot or read state the
// reference trace cannot state.
namespace f1_rv64_gate {

struct Result {
  bool ok = true;
  std::string message;
};

inline Result check(const uint32_t *words, unsigned count) {
  Result result;
  const auto fail = [&result](const std::string &message) {
    result.ok = false;
    result.message = message;
    return result;
  };
  if (count < 1 || count > F1_MAX_WORDS)
    return fail("F1 RV64 program takes one to " + std::to_string(F1_MAX_WORDS) +
                " word(s)");
  bool written[32] = {};
  written[0] = true;
  written[18] = true;
  for (unsigned index = 0; index < count; ++index) {
    const uint32_t word = words[index];
    if ((word & 3u) != 3u)
      return fail("F1 RV64 word " + std::to_string(index) +
                  " is not one 32-bit instruction");
    const unsigned opcode = word & 0x7fu, rd = (word >> 7) & 31u;
    const unsigned funct3 = (word >> 12) & 7u, rs1 = (word >> 15) & 31u;
    const unsigned rs2 = (word >> 20) & 31u, funct7 = (word >> 25) & 0x7fu;
    const int imm_i = int((word >> 20) & 0xfffu);
    const int offset = (imm_i & 0x800) ? imm_i - 4096 : imm_i;
    bool memory = false;
    bool store = false;
    if (opcode == 0x37u) {                       // LUI
    } else if (opcode == 0x13u && funct3 == 0u) {  // ADDI
    } else if (opcode == 0x1bu && funct3 == 0u) {  // ADDIW
    } else if (opcode == 0x33u
               && ((funct7 == 0u && (funct3 == 0u || funct3 == 7u
                                     || funct3 == 6u || funct3 == 4u))
                   || (funct7 == 0x20u && funct3 == 0u))) {
    } else if (opcode == 0x3bu && funct3 == 0u && funct7 == 0u) {  // ADDW
    } else if (opcode == 0x1bu && funct3 == 1u && funct7 == 0u) {  // SLLIW
    } else if (opcode == 0x1bu && funct3 == 5u
               && (funct7 == 0u || funct7 == 0x20u)) {             // SRLIW/SRAIW
    } else if (opcode == 0x03u && funct3 == 3u) {  // LD
      memory = true;
    } else if (opcode == 0x23u && funct3 == 3u) {  // SD
      memory = true;
      store = true;
    } else {
      return fail("F1 RV64 word " + std::to_string(index) +
                  " is outside the declared RV64I subset");
    }
    if (store) {
      const int store_offset = int((((word >> 25) & 0x7fu) << 5)
                                  | ((word >> 7) & 0x1fu));
      const int signed_offset = (store_offset & 0x800)
                                    ? store_offset - 4096 : store_offset;
      if (rs1 != 18u)
        return fail("F1 RV64 store " + std::to_string(index) +
                    " must use x18, the declared data-window base");
      if (signed_offset % 8 != 0 || signed_offset < 0
          || signed_offset > int(PROGRAM_DATA_WORDS * 4) - 8)
        return fail("F1 RV64 store " + std::to_string(index) +
                    " leaves the declared data window");
      if (!written[rs2])
        return fail("F1 RV64 store " + std::to_string(index) +
                    " reads x" + std::to_string(rs2) +
                    " before this program wrote it");
    } else if (memory) {
      if (rs1 != 18u)
        return fail("F1 RV64 load " + std::to_string(index) +
                    " must use x18, the declared data-window base");
      if (offset % 8 != 0 || offset < 0
          || offset > int(PROGRAM_DATA_WORDS * 4) - 8)
        return fail("F1 RV64 load " + std::to_string(index) +
                    " leaves the declared data window");
      if (rd == 8u || rd == 9u || rd == 18u)
        return fail("F1 RV64 load " + std::to_string(index) +
                    " writes a register the firmware owns");
      if (rd) written[rd] = true;
    } else {
      if (opcode != 0x37u && !written[rs1])
        return fail("F1 RV64 word " + std::to_string(index) +
                    " reads x" + std::to_string(rs1) +
                    " before this program wrote it");
      if (opcode == 0x33u || opcode == 0x3bu) {
        if (!written[rs2])
          return fail("F1 RV64 word " + std::to_string(index) +
                      " reads x" + std::to_string(rs2) +
                      " before this program wrote it");
      }
      if (rd == 8u || rd == 9u || rd == 18u)
        return fail("F1 RV64 word " + std::to_string(index) +
                    " writes a register the firmware owns");
      written[rd] = true;
    }
  }
  return result;
}

}  // namespace f1_rv64_gate
// END F1_RV64_GATE

// The host re-checks shape and window; Python already rejected anything that is
// not a record the selected components can serve before either model was
// initialized.
Record make_record(Flow flow, const uint32_t *words, unsigned count) {
  // The F1 control-flow facts the whole-image pass proves; they are copied into
  // the returned record (which is constructed after the per-flow gate).
  unsigned f1_expected_retires = 0;
  bool f1_exact_retires = false, f1_loop_mode = false;
  unsigned f1_expected_repeats = 0;
  if (flow == kF1) {
#if CPU_BUS_AHB
    throw std::runtime_error("unsupported-f1:no-retirement-observation:ahb_cvw");
#endif
    // One to F1_MAX_WORDS 32-bit instructions execute in the fixed trampoline
    // slot.  A jump or CSR would escape the slot or change the CPU state the
    // trampoline returns into; a write to the mailbox pointer x8 would break the
    // polling loop; and with a program the data-window base x18 is the only
    // address a memory word may use unless F1_ALLOW_ADDRESS_FORMS admits the
    // statically proven computed-base forms (proved by the whole-program pass
    // below).  A branch is admitted only when F1_ALLOW_BRANCHES is set, and only
    // as a strictly-forward B-type branch inside the installed image.  All of
    // that is refused here by name, not guessed.
    if (count < 1 || count > F1_MAX_WORDS)
      throw std::runtime_error("F1 takes one to " + std::to_string(F1_MAX_WORDS) +
                               " instruction word(s)");
#if F1_ALLOW_BRANCHES && (!HAVE_RVFI_WRITEBACK || !HAVE_EVENT_LAYER)
    // A branch program's retirement sequence is not "every installed word", so
    // the case's evidence is the RVFI retirement trace itself.  A CPU that
    // exports no register writeback through RVFI cannot state that trace, and
    // the entry would have nothing to compare the reference trace with.
    throw std::runtime_error(
        "unsupported-f1:no-rvfi-writeback:branch-trace-unobservable");
#endif
#if F1_ALLOW_ADDRESS_FORMS && F1_ALLOW_SUBWORD
    // The two opt-ins have different memory rules (a 4-byte proven address vs a
    // width-carrying access), and the scenario gate refuses the combination.  A
    // hand-built header that states both is refused by name, not resolved in
    // favour of one.
    throw std::runtime_error("F1 address forms and subword widths are not combined");
#endif
#if F1_ALLOW_COMPRESSED && (F1_ALLOW_ADDRESS_FORMS || F1_ALLOW_SUBWORD)
    // A compressed record word carries two parcels, so there is no single 32-bit
    // instruction for the address-form provenance pass or the subword width rule
    // to read.  The scenario gate refuses both combinations before any record is
    // validated; a hand-built header that states one is refused by name here.
    throw std::runtime_error(
        "F1 compressed parcels and address forms or subword widths are not "
        "combined");
#endif
#if F1_ALLOW_COMPRESSED && (!HAVE_RVFI_WRITEBACK || !HAVE_EVENT_LAYER)
    // A compressed record's evidence is the parcel/word retirement trace (the
    // count, the PC sequence and the trace hash), so a CPU that exports no
    // retirement writeback cannot state it.
    throw std::runtime_error(
        "unsupported-f1:no-rvfi-writeback:compressed-trace-unobservable");
#endif
#if F1_ALLOW_JUMPS && (!HAVE_RVFI_WRITEBACK || !HAVE_EVENT_LAYER)
    // A jump program's retirement sequence is not "every installed word" either;
    // its evidence is the in-slot RVFI trace.
    throw std::runtime_error(
        "unsupported-f1:no-rvfi-writeback:jump-trace-unobservable");
#endif
#if F1_ALLOW_LOOPS && (!HAVE_RVFI_WRITEBACK || !HAVE_EVENT_LAYER)
    // A bounded loop repeats PCs, so the strict-rise evidence is unavailable and
    // the case's evidence is the exact RVFI retirement trace.
    throw std::runtime_error(
        "unsupported-f1:no-rvfi-writeback:loop-trace-unobservable");
#endif
#if F1_ALLOW_LOOPS && !F1_ALLOW_BRANCHES
    // The loop back edge is a B-type branch; a header that declares loops
    // without branches is inconsistent and is refused by name.
    throw std::runtime_error("F1 loops require the branch declaration");
#endif
#if F1_ALLOW_COMPRESSED && (F1_ALLOW_JUMPS || F1_ALLOW_LOOPS)
    // A jump or a loop is a 32-bit control-flow shape; a compressed record's
    // instruction starts are 2-byte granular and its control transfers have
    // their own forward-only rule.  The scenario gate refuses the combination.
    throw std::runtime_error(
        "F1 compressed parcels and 32-bit jumps or loops are not combined");
#endif
#if F1_ALLOW_COMPRESSED_CONTROL && !F1_ALLOW_COMPRESSED
    throw std::runtime_error(
        "F1 compressed control requires the compressed declaration");
#endif
#if F1_ALLOW_COMPRESSED_MEMORY && !F1_ALLOW_COMPRESSED
    throw std::runtime_error(
        "F1 compressed memory requires the compressed declaration");
#endif
#if F1_TRAP_PROGRAM
    // A declared M-mode ECALL program: the ECALL first, then straight-line ALU
    // words whose sources this program wrote.  No control or address pass
    // applies, because the record has neither a branch nor a memory word.
    {
      const f1_trap_gate::Result trap = f1_trap_gate::check(words, count);
      if (!trap.ok) throw std::runtime_error(trap.message);
    }
#elif F1_RV64
    // A declared RV64I program: the myfuzz.fuzz.f1_rv64 subset at the record's
    // own width.  The per-instruction rules (reserved registers, read-after-
    // write, x18-bounded 8-byte memory) are re-checked here so a hand-built
    // record cannot execute a word the entry would refuse.
    {
      const f1_rv64_gate::Result rv64 = f1_rv64_gate::check(words, count);
      if (!rv64.ok) throw std::runtime_error(rv64.message);
    }
#else
    for (unsigned index = 0; index < count; ++index) {
      const uint32_t word = words[index];
#if F1_ALLOW_COMPRESSED
      // A record word whose bits [1:0] are not ``11`` is two 16-bit parcels: the
      // low half executes at pc and the high half at pc + 2.  Each half is
      // checked against the admitted safe ALU subset (x12..x15 destinations) and
      // a 32-bit instruction may not straddle the word.  Compressed control and
      // memory forms are refused by name, never executed.
      if ((word & 3u) != 3u) {
        const f1_parcels::Result parcels = f1_parcels::check_word(word, index);
        if (!parcels.ok) throw std::runtime_error(parcels.message);
        continue;
      }
#else
      if ((word & 3u) != 3u)
        throw std::runtime_error("F1 instruction " + std::to_string(index) +
                                 " is not one 32-bit word");
#endif
      const unsigned opcode = word & 0x7fu, rd = (word >> 7) & 31u;
      const unsigned funct3 = (word >> 12) & 7u, rs1 = (word >> 15) & 31u;
      // The I-type immediate is bits 31:20; an S-type store splits it into
      // 31:25 and 11:7, so a store's offset is not the I-type field.
      const bool store = opcode == 0x23u;
      const unsigned raw_imm = store
          ? ((((word >> 25) & 0x7fu) << 5) | ((word >> 7) & 0x1fu))
          : ((word >> 20) & 0xfffu);
      const int offset = (raw_imm & 0x800u) ? int(raw_imm) - 4096 : int(raw_imm);
      const bool alu = opcode == 0x37u || opcode == 0x17u || opcode == 0x13u
                       || opcode == 0x33u;
      const bool memory = opcode == 0x03u || opcode == 0x23u;
      // A jump or a system word stays out of scope in every F1 shape: a jump
      // would escape the slot's retirement accounting and a CSR write would
      // change the CPU state the trampoline returns into.  A branch is the one
      // opt-in control transfer (F1_ALLOW_BRANCHES), and its target is checked
      // above; both are refused by name rather than folded into the generic ALU
      // refusal.
      if (opcode == 0x63u) {
#if F1_ALLOW_BRANCHES
        // The opt-in shape: a B-type branch inside the image.  Its bits 11:7 are
        // immediate bits, not a destination register, so no rd rule applies.
        // With the loop declaration a backward branch may be the canonical loop
        // back edge, which the whole-image control-flow pass proves; without it
        // the per-word gate keeps the strictly-forward rule.
#if F1_ALLOW_LOOPS
        const unsigned branch_funct3 = (word >> 12) & 7u;
        if (branch_funct3 != 0u && branch_funct3 != 1u && branch_funct3 != 4u
            && branch_funct3 != 5u && branch_funct3 != 6u && branch_funct3 != 7u)
          throw std::runtime_error(
              "F1 instruction " + std::to_string(index) + " is branch funct3 " +
              std::to_string(branch_funct3) +
              "; only BEQ/BNE/BLT/BGE/BLTU/BGEU are admitted");
        if (f1_provenance::immediate_b(word) % 4 != 0)
          throw std::runtime_error("F1 branch " + std::to_string(index) +
                                   " target is not 4-byte aligned");
#else
        const f1_branch::Result branch =
            f1_branch::check(word, index, count, kSlot);
        if (!branch.ok) throw std::runtime_error(branch.message);
#endif
        continue;
#else
        throw std::runtime_error("F1 instruction " + std::to_string(index) +
                                 " is a branch; the trampoline program is "
                                 "straight-line");
#endif
      }
      if (opcode == 0x6fu || opcode == 0x67u) {
#if F1_ALLOW_JUMPS
        // The opt-in jump shape: link x0/x1 only, and the whole-image pass
        // resolves the target (a JALR base must be a proven constant).  JAL has
        // no funct3 field (bits 14:12 are immediate bits), so only JALR's funct3
        // is checked.
        if (opcode == 0x67u && funct3 != 0u)
          throw std::runtime_error("F1 instruction " + std::to_string(index) +
                                   " is not JALR funct3 0");
        if (rd != 0u && rd != 1u)
          throw std::runtime_error("F1 instruction " + std::to_string(index) +
                                   " jump link destination x" +
                                   std::to_string(rd) +
                                   " is not x0 or x1");
        if (opcode == 0x6fu && f1_control::jal_imm(word) % 4 != 0)
          throw std::runtime_error("F1 instruction " + std::to_string(index) +
                                   " JAL target is not 4-byte aligned");
        continue;
#else
        throw std::runtime_error("F1 instruction " + std::to_string(index) +
                                 " is a jump; the trampoline program is "
                                 "straight-line");
#endif
      }
      if (opcode == 0x73u)
        throw std::runtime_error("F1 instruction " + std::to_string(index) +
                                 " is a CSR or system word; the trampoline "
                                 "program executes no system instruction");
      // Program mode (F1_MAX_WORDS > 1) also admits a one-word program whose
      // word is a memory instruction: the firmware still points x18 at the
      // declared data window, so the word has a bounded base.
      if (!alu && !(memory && F1_MAX_WORDS > 1))
        throw std::runtime_error("F1 instruction " + std::to_string(index) +
                                 " is outside the executed ALU subset");
      if (memory) {
        // F1_ALLOW_SUBWORD is a compile-time fact from spike_config.h: a host
        // built for a scenario without the opt-in keeps the legacy LW/SW gate.
        // The width table is the same one the Python gate and the program
        // reference model use (loads 0/1/2/4/5, stores 0/1/2), and the window
        // bound follows the access width rather than a fixed four bytes.
#if F1_ALLOW_SUBWORD
        const bool is_load = opcode == 0x03u;
        const bool width_ok =
            is_load ? (funct3 == 0u || funct3 == 1u || funct3 == 2u
                       || funct3 == 4u || funct3 == 5u)
                    : (funct3 == 0u || funct3 == 1u || funct3 == 2u);
        if (!width_ok)
          throw std::runtime_error(
              "F1 program memory word " + std::to_string(index) +
              (is_load ? " is not LB/LH/LW/LBU/LHU" : " is not SB/SH/SW"));
        const unsigned size = (funct3 == 0u || funct3 == 4u) ? 1u
                            : (funct3 == 1u || funct3 == 5u) ? 2u : 4u;
#else
        if (funct3 != 2u)
          throw std::runtime_error("F1 program memory word " + std::to_string(index) +
                                   " is not LW or SW");
        const unsigned size = 4u;
#endif
        if (rs1 != 18u) {
#if F1_ALLOW_ADDRESS_FORMS
          // The displacement lives in the base register: a computed base must
          // carry immediate 0, and the proof that the register holds an
          // in-window address is the whole-program pass below.  The legacy
          // immediate check still runs (0 is aligned and inside every window).
          if (offset != 0)
            throw std::runtime_error("F1 program memory word " +
                                     std::to_string(index) +
                                     " with a computed base must use immediate 0");
#else
          throw std::runtime_error("F1 program memory word " + std::to_string(index) +
                                   " must use x18, the declared data-window base");
#endif
        }
        if (offset % int(size) || offset < 0
            || offset > int(PROGRAM_DATA_WORDS * 4) - int(size))
          throw std::runtime_error("F1 program memory word " + std::to_string(index) +
                                   " leaves the declared data window");
        if (opcode == 0x03u && (rd == 8u || rd == 9u || rd == 18u))
          throw std::runtime_error("F1 program load " + std::to_string(index) +
                                   " may not overwrite x8, x9 or x18");
      } else if (rd == 8u) {
        throw std::runtime_error("F1 input may not overwrite the mailbox pointer");
      } else if (F1_MAX_WORDS > 1 && (rd == 9u || rd == 18u)) {
        throw std::runtime_error("F1 program instruction " + std::to_string(index) +
                                 " may not overwrite the reserved x9/x18");
      }
    }
#if F1_ALLOW_ADDRESS_FORMS && !F1_ALLOW_COMPRESSED
    // The static may-provenance pass: every memory word whose base is not x18
    // must be proven in-window.  x18 memory words are re-checked by the same
    // pass with x18's window[0,0] value, so the rule has one definition.  A
    // forward branch is a merge point; the pass joins the two path states.  A
    // compressed record is never combined with address forms (refused above), so
    // this pass only ever reads whole 32-bit instruction words.
    const f1_provenance::Result proof =
        f1_provenance::check(words, count, PROGRAM_DATA_WORDS);
    if (!proof.ok) throw std::runtime_error(proof.message);
#endif
#if F1_ALLOW_JUMPS || F1_ALLOW_LOOPS || F1_ALLOW_COMPRESSED_CONTROL || F1_ALLOW_COMPRESSED_MEMORY
    // The whole-image control-flow pass: statically proven jump and compressed
    // control targets, the canonical bounded loop (with its exact retirement
    // count) and the proven compressed memory addresses.  Python is the
    // authority; this repeats the same rules so a hand-built record is refused
    // here rather than executing an unproven target.
    {
      const f1_control::Result control =
          f1_control::check(words, count, kSlot, PROGRAM_DATA_WORDS);
      if (!control.ok) throw std::runtime_error(control.message);
      f1_expected_retires = control.expected_retires;
      f1_exact_retires = control.exact_retires;
      f1_loop_mode = control.loop_mode;
      f1_expected_repeats = control.loop_repeats;
    }
#endif
#endif  // !F1_TRAP_PROGRAM && !F1_RV64
  } else if (flow == kF2) {
    if ((words[0] & 3u) || !(in_ip(words[0]) || (in_ram(words[0]) && words[0] >= kDataBase)))
      throw std::runtime_error("F2 address must be an aligned APB or data-window RAM word");
#if HAVE_PINS
    // A stimulus word is only meaningful on the device's declared pin input
    // register: the host rewrites its own driver value, then the CPU reads it.
    if (count == 2
        && (words[0] != kIpBase + IP_PADIN_OFFSET || (words[1] & ~kPadMask)))
      throw std::runtime_error("an F2 stimulus word applies only to the declared "
                               "PADIN address and the declared pad width");
#elif HAVE_SERIAL_PEER
    // A serial peer's stimulus word is the one byte it clocks onto rx; the case
    // may read any word of the same target while that frame is on the wire.
    if (count == 2 && (words[1] > 0xffu))
      throw std::runtime_error("an F2 serial stimulus is one byte");
#else
    if (count != 1)
      throw std::runtime_error("F2 takes one word on a target without a pin model");
#endif
  } else if (flow == kF3) {
    if ((words[0] & 3u) || words[0] < kDataBase || !in_ram(words[0]))
      throw std::runtime_error("F3 address must be an aligned data-window RAM word");
  } else if (flow == kF4) {
    if ((words[0] & 3u) || !in_ip(words[0]))
      throw std::runtime_error("F4 address must be an aligned word in the APB window");
  } else if (flow == kF5) {
    // The declared trigger order fixes which register each value reaches; the
    // values themselves are the operator's and are not second-guessed here.
    if (!TRIGGER_COUNT) throw std::runtime_error("F5 needs a declared IRQ trigger sequence");
    bool both = false;
#if IRQ_BOTH_ENABLED
    both = count > 0 && words[0] == IRQ_BOTH_LINK_INDEX;
    if (both && count != IRQ_BOTH_WORDS)
      throw std::runtime_error("F5 both link needs " + std::to_string(IRQ_BOTH_WORDS) +
                               " word(s)");
#endif
#if IRQ_TARGET_LINK_COUNT > 1
    if (!both && (!count || words[0] >= IRQ_TARGET_LINK_COUNT))
      throw std::runtime_error("F5 link index is not one of the declared links");
#endif
  } else if (flow == kF6) {
    if (!DMA_BLOCK_WORDS) throw std::runtime_error("F6 needs a declared DMA block");
  } else {
    throw std::runtime_error("unsupported flow tag");
  }
  Record record;
  record.flow = flow;
  record.words = count;
  for (unsigned index = 0; index < count; ++index) record.values[index] = words[index];
  record.expected_retires = f1_expected_retires;
  record.exact_retires = f1_exact_retires;
  record.loop_mode = f1_loop_mode;
  record.expected_repeats = f1_expected_repeats;
  return record;
}

Flow parse_flow(const std::string &text) {
#if CPU_BUS_AHB
  // F1 is a *retirement* input: its witness is the CPU's RVFI/commit stream.
  // This CPU exposes no retirement observation at all, and a fetch beat is not
  // a retirement, so F1 is refused by name instead of being inferred.
  if (text == "F1")
    throw std::runtime_error("unsupported-f1:no-retirement-observation:ahb_cvw");
#endif
  if (text == "F1") return kF1;
  if (text == "F2") return kF2;
  if (text == "F3") return kF3;
  if (text == "F4") return kF4;
  // A flow whose components are not part of this build is refused by name.
  if (text == "F5" && TRIGGER_COUNT > 0) return kF5;
  if (text == "F6" && DMA_BLOCK_WORDS > 0) return kF6;
  throw std::runtime_error("unsupported flow tag: " + text);
}

Record parse_fields(const std::vector<std::string> &fields) {
  if (fields.size() < 2 || fields.size() > 1 + 16)
    throw std::runtime_error("one record needs a flow tag and one to sixteen words");
  const Flow flow = parse_flow(fields[0]);
  unsigned count = word_count(flow);
  if (flow == kF1) {
    // An F1 record carries one to F1_MAX_WORDS instruction words; the count is
    // the message's own, and the program's length is the number of words.
    count = unsigned(fields.size() - 1);
    if (count < 1 || count > F1_MAX_WORDS)
      throw std::runtime_error("F1 takes one to " + std::to_string(F1_MAX_WORDS) +
                               " instruction word(s)");
  }
#if HAVE_PINS || HAVE_SERIAL_PEER
  // F2 may carry one stimulus operand: the external pin word on a pad target, or
  // the byte a declared serial peer clocks onto the wire.  Nothing else is
  // variable, so a third word is still refused.
  else if (flow == kF2 && fields.size() == 3) {
    count = 2;
  }
#endif
#if IRQ_BOTH_ENABLED
  // An F5 record whose first word is the synthetic both index carries the two
  // member trigger sequences, so its operand count is the declared better one
  // rather than the single-link count.  The index word is decoded before the
  // value loop; the link itself was declared by the generated header.
  else if (flow == kF5 && fields.size() >= 2
           && parse_hex(fields[1], "record address or value") == IRQ_BOTH_LINK_INDEX) {
    count = IRQ_BOTH_WORDS;
  }
#endif
  if (fields.size() != 1 + count)
    throw std::runtime_error(std::string("wrong operand count for ") + flow_name(flow));
  uint32_t words[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  for (unsigned index = 0; index < count; ++index)
    words[index] = parse_hex(fields[1 + index], "record address or value");
  return make_record(flow, words, count);
}

}  // namespace

int main(int argc, char **argv) {
  if (argc < 3 || argc > 5) {
    std::cerr << "usage: spike firmware.txt records|--online [max_ticks] [--quiet|--events]\n";
    return 2;
  }
  try {
    const std::string input = argv[2];
    const bool online = input == "--online";
    std::vector<Record> records;
    if (!online) {
      for (const std::string &text : split(input, ','))
        records.push_back(parse_fields(split(text, ':')));
    }
    const uint64_t kMaxTicks = argc >= 4 ? std::stoull(argv[3]) : 20000;
    if (!kMaxTicks) throw std::runtime_error("max_ticks must be positive");
    for (int index = 4; index < argc; ++index) {
      const std::string flag = argv[index];
      if (flag == "--quiet") g_events = false;
      else if (flag == "--events") g_events = true;
      else throw std::runtime_error("unsupported host flag: " + flag);
    }
    if (online) std::cout << std::unitbuf;
    const auto started = std::chrono::steady_clock::now();
    Memory memory(kRamBase, kRamSize);
    memory.load(argv[1]);
    VerilatedContext context;
    CPU_MODEL cpu(&context, "cpu");
    // One model per declared target.  The header names the types and constructs
    // them; the host owns the tuple so one tick, one reset sequence and one
    // finalize call reach all of them.
    IpModels ip_models{IP_MODEL_INSTANCES(context)};
    auto &ip = *std::get<0>(ip_models);
#if HAVE_DMA
    DMA_MODEL dma(&context, "dma");
#endif
#if CPU_BUS_AXI4
    AXI4_ADAPTER adapter(&context, "adapter");
    myfuzz::axi4::CpuLink link(cpu, adapter);
#if HAVE_RVFI_ADAPTER
    // The pinned CVA6 RVFI scoreboard (core/cva6_rvfi.sv), Verilated beside this
    // run and driven from the CPU model's exported 6974-bit probe bundle.  It is
    // not part of the generated model: cva6_rvfi.sv is not in the core filelist,
    // so the harness compiles it as its own model (scripts/inprocess_cva6_rvfi_build.py)
    // and this bridge carries the bundle across on the link's own low phase and
    // clocks it on the link's one rising edge per tick.
    RVFI_ADAPTER rvfi(&context, "rvfi");
    struct RvfiBridge {
      RVFI_ADAPTER *model;
      static void drive(void *context, const std::uint32_t *words, unsigned count) {
        auto *self = static_cast<RvfiBridge *>(context);
        for (unsigned index = 0; index < count; ++index)
          self->model->rvfi_probes_i[index] = words[index];
        self->model->eval();
      }
      static void reset(void *context, bool level) {
        static_cast<RvfiBridge *>(context)->model->rst_ni = level ? 0 : 1;
      }
      static void clock(void *context, bool level) {
        auto *self = static_cast<RvfiBridge *>(context);
        self->model->clk_i = level ? 1 : 0;
        self->model->eval();
      }
    } rvfi_bridge{&rvfi};
    link.attach_probe_adapter(myfuzz::axi4::CpuLink::ProbeAdapter{
        &rvfi_bridge, cpu.CPU_RVFI_PROBES.data(), CPU_RVFI_PROBES_WORDS,
        &RvfiBridge::drive, &RvfiBridge::reset, &RvfiBridge::clock});
#endif
#endif
    // --- the declared per-model clock phase grid ------------------------------
    // One grid step is the greatest common half period of the declared models
    // (1 / (2 * CLOCK_GRID_LCM_HZ) seconds).  The entry normalizes every model's
    // declared rate into a whole number of those steps (CLOCK_*_HALF_TICKS) and
    // refuses a pair whose exact grid does not fit its bound, so nothing here
    // rounds a declared frequency: a model with half period R steps keeps its
    // declared low-first phase, toggles at phase_level(step, R), and its first
    // rising edge is exactly at its own half period.  The reference CPU's half
    // period is CLOCK_CPU_HALF_TICKS steps, so one host tick advances
    // CLOCK_GRID_STEPS_PER_TICK steps - exactly one CPU cycle - and a model
    // declared faster than the CPU takes several of its own edges inside one
    // tick: the sub-stepping is this same schedule, not a second one.  A timed
    // model's own half period in picoseconds is R times TIMED_GRID_PS, the one
    // simulation-time step the shared context advances.
    constexpr unsigned kCpuHalfTicks = CLOCK_CPU_HALF_TICKS;
    constexpr unsigned kGridStepsPerTick = CLOCK_GRID_STEPS_PER_TICK;
    static_assert(kGridStepsPerTick == 2u * kCpuHalfTicks,
                  "one host tick is exactly one reference CPU cycle");
    static_assert(kCpuHalfTicks >= 1u, "the reference CPU half period is at least one step");
#if IP_COUNT > 0
    static constexpr unsigned kIpHalfTicks[IP_COUNT] = { CLOCK_IP_HALF_TICKS };
#endif
    constexpr unsigned kDmaHalfTicks = CLOCK_DMA_HALF_TICKS;
    unsigned phase_step = 0;
    unsigned cpu_clock_level = 0, cpu_rises = 0;
    unsigned ip_clock_level[IP_COUNT > 0 ? IP_COUNT : 1] = {};
    unsigned ip_rises[IP_COUNT > 0 ? IP_COUNT : 1] = {};
    // Set when a model's rising edge was applied at a boundary; consumed by the
    // next tick's low-phase sample, which is where this host has always read a
    // model's registered protocol outputs.
    bool ip_rise_pending[IP_COUNT > 0 ? IP_COUNT : 1] = {};
    unsigned dma_clock_level = 0, dma_rises = 0;
    bool dma_rise_pending = false;
    // Per-case evidence baselines, captured when a case is installed.
    unsigned case_cpu_rises = 0, case_dma_rises = 0;
    unsigned case_ip_rises[IP_COUNT > 0 ? IP_COUNT : 1] = {};
    auto ip_half_ticks = [](unsigned index) -> unsigned {
#if IP_COUNT > 0
      return kIpHalfTicks[index];
#else
      (void)index;
      return 1u;
#endif
    };
    auto eval_ip = [&] {
      for_each_ip(ip_models, [&](auto constant, auto &model) {
        myfuzz_ip::IpTarget<constant()>::eval(model);
      });
    };
    // Apply one grid boundary: every model whose declared half period divides
    // this step takes its level for the step that begins here, in the declared
    // low-first order.  ``drive_cpu`` is false on the packed AXI4 path, where
    // CpuLink owns the CPU/adapter clock edge; targets and DMA are still stepped.
    auto apply_phase_boundary = [&](bool drive_cpu) {
      ++phase_step;
      if (drive_cpu) {
        const unsigned level = phase_level(phase_step, kCpuHalfTicks);
        if (level != cpu_clock_level) {
          cpu_clock_level = level;
          cpu.clk = level;
          if (level) ++cpu_rises;
        }
      }
      for_each_ip(ip_models, [&](auto constant, auto &model) {
        const unsigned index = constant();
        const unsigned level = phase_level(phase_step, ip_half_ticks(index));
        if (level == ip_clock_level[index]) return;
        ip_clock_level[index] = level;
        myfuzz_ip::IpTarget<index>::clock(model, level);
        if (level) {
          ++ip_rises[index];
          ip_rise_pending[index] = true;
        }
      });
#if HAVE_DMA
      {
        const unsigned level = phase_level(phase_step, kDmaHalfTicks);
        if (level != dma_clock_level) {
          dma_clock_level = level;
          dma.clk = level;
          if (level) {
            ++dma_rises;
            dma_rise_pending = true;
          }
        }
      }
#endif
    };
    auto eval_all = [&] {
#if CPU_BUS_AXI4
      link.settle();
#endif
#if !CPU_BUS_AXI4
      cpu.eval();
#endif
      eval_ip();
#if HAVE_DMA
      dma.eval();
#endif
    };
    auto set_reset = [&](unsigned step) {
#if CPU_BUS_AXI4
      link.set_reset(step < CPU_RESET_ASSERT);
#else
      cpu.reset = step < CPU_RESET_ASSERT;
#endif
      for_each_ip(ip_models, [&](auto constant, auto &model) {
        myfuzz_ip::IpTarget<constant()>::set_reset(
            model, step < myfuzz_ip::IpTarget<constant()>::reset_assert);
      });
#if HAVE_DMA
      dma.reset = step < DMA_RESET_ASSERT;
#endif
    };
    auto clear_reset = [&] {
#if CPU_BUS_AXI4
      link.set_reset(false);
#else
      cpu.reset = 0;
#endif
      for_each_ip(ip_models, [&](auto constant, auto &model) {
        myfuzz_ip::IpTarget<constant()>::set_reset(model, 0);
      });
#if HAVE_DMA
      dma.reset = 0;
#endif
    };
    unsigned ip_assert_ticks = 0, ip_release_ticks = 0;
    for_each_ip(ip_models, [&](auto constant, auto &) {
      ip_assert_ticks = std::max(ip_assert_ticks,
                                 myfuzz_ip::IpTarget<constant()>::reset_assert);
      ip_release_ticks = std::max(ip_release_ticks,
                                  myfuzz_ip::IpTarget<constant()>::reset_release);
    });
    const unsigned kAssertTicks = std::max({CPU_RESET_ASSERT, ip_assert_ticks,
#if HAVE_DMA
                                            DMA_RESET_ASSERT
#endif
    });
    const unsigned kReleaseTicks = std::max({CPU_RESET_RELEASE, ip_release_ticks,
#if HAVE_DMA
                                             DMA_RESET_RELEASE
#endif
    });
    auto timed_events = [&] {
#if CPU_BUS_AXI4
      bool pending = false;
#else
      bool pending = cpu.eventsPending();
#endif
      for_each_ip(ip_models, [&](auto constant, auto &model) {
        pending = pending || myfuzz_ip::IpTarget<constant()>::events_pending(model);
      });
#if HAVE_DMA
      pending = pending || dma.eventsPending();
#endif
      return pending;
    };
    // A model built with Verilator --timing schedules its own simulation events
    // (the pinned passive CV32E40P RVFI monitor is one: `assign #0.01 clk_i_d =
    // clk_i` plus `#1` inside its observation tasks), so evaluating it is not
    // enough - the host has to move the shared context through real time.  The
    // contract is the one the model's own generated driver states, and it is
    // generic: each host clock phase lasts one declared half period, the clock
    // rises/falls on the phase boundary, and every event the models scheduled on
    // the way is evaluated at its own time before the boundary is reached.  An
    // untimed build never enters this path (CPU_TIMED_MODEL is 0) and keeps the
    // pure evaluate-only loop it always had.
    constexpr bool kTimedModel = CPU_TIMED_MODEL != 0;
    constexpr unsigned kMaxTimedEvaluationsPerPhase = 65536;
    auto timed_next_slot = [&] {
      std::uint64_t next = UINT64_MAX;
#if !CPU_BUS_AXI4
      if (cpu.eventsPending()) next = std::min(next, cpu.nextTimeSlot());
#endif
      for_each_ip(ip_models, [&](auto constant, auto &model) {
        if (myfuzz_ip::IpTarget<constant()>::events_pending(model))
          next = std::min<std::uint64_t>(
              next, myfuzz_ip::IpTarget<constant()>::next_time_slot(model));
      });
#if HAVE_DMA
      if (dma.eventsPending()) next = std::min(next, dma.nextTimeSlot());
#endif
      return next;
    };
    auto timed_advance_to = [&](std::uint64_t boundary) {
      if (!kTimedModel) return;
      if (context.timeprecision() != -12)
        throw std::runtime_error("timed model context precision is not 1 ps");
      unsigned evaluations = 0;
      for (;;) {
        const bool pending = timed_events();
        const std::uint64_t next = pending ? timed_next_slot() : boundary;
        if (pending && next == UINT64_MAX)
          throw std::runtime_error("timed model event without a time slot");
        if (pending && next < context.time())
          throw std::runtime_error("timed model event in the past");
        if (context.time() == boundary && (!pending || next > boundary)) break;
        if (++evaluations > kMaxTimedEvaluationsPerPhase)
          throw std::runtime_error("timed phase event bound");
        const std::uint64_t target = pending && next <= boundary ? next : boundary;
        context.timeInc(target - context.time());
        eval_all();
      }
    };
    auto finalize = [&] {
#if CPU_BUS_AXI4
      adapter.final();
#else
      cpu.final();
#endif
      for_each_ip(ip_models, [&](auto constant, auto &model) {
        myfuzz_ip::IpTarget<constant()>::finalize(model);
      });
#if HAVE_DMA
      dma.final();
#endif
    };
    auto edge = [&] {
#if CPU_BUS_AXI4
      // One CPU/adapter clock edge, plus the target/DMA boundary that belongs to
      // this phase.  CpuLink resolves the combinational CPU<->adapter loop.
      apply_phase_boundary(false);
      link.settle();
      eval_ip();
#if HAVE_DMA
      dma.eval();
#endif
      link.clock_edge();
      ++cpu_rises;  // the link's one CPU rising edge
      apply_phase_boundary(false);
      eval_ip();
#else
      // The low half of the reference cycle, its rising boundary, the high half
      // and the falling boundary.  A model whose declared half period is R grid
      // steps only toggles at its own boundary, so the declared reset window is
      // R times shorter in that model's own cycles - which is what its declared
      // rate means.  A timed model's own scheduled events run at their real time
      // inside each step; an untimed build advances nothing.  One reference half
      // period is kCpuHalfTicks grid steps, so each half above is that many
      // steps: for a ratio-1 reference clock (kCpuHalfTicks == 1) this is the
      // historical two-boundary tick exactly.
      for (unsigned s = 0; s < kGridStepsPerTick; ++s) {
        timed_advance_to(context.time() + TIMED_GRID_PS);
        apply_phase_boundary(true);
        eval_all();
      }
#endif
    };
    // The profile pins some target inputs at a constant, and the constant is the
    // declaration's, not this host's: each target's generated trait applies its
    // own rows.  A target with no such pin needs no edit here.
    for_each_ip(ip_models, [&](auto constant, auto &model) {
      myfuzz_ip::IpTarget<constant()>::fixed_inputs(model);
    });
#if HAVE_PINS
    // A pin target's input port is driven by the host pad model from the first
    // tick: the declared driver value, resolved against the device's own ports
    // once the model has evaluated.
    Pads pads;
    pads.value = pads.ext & kPadMask;
    myfuzz_ip::IpTarget<0>::set_pin_in(ip, pads.value);
#if HAVE_PIN_GROUPS
    // The declared group schedule.  It is a per-case fact set, so it is reset by
    // every ``install``; the declaration itself (the generated table) is constant.
    PinGroupSchedule pin_schedule;
#endif
#endif
#if HAVE_SERIAL_PEER
    // The declared peer.  It is one instance for the whole run: a frame that
    // starts in one case may still be on the wire when the next one is installed,
    // and the sampler keeps its own state across that boundary so no byte is
    // dropped or counted twice.
    SerialPeer<IP_MODEL> serial_peer;
    // RX starts in the first non-reset tick of the case it was declared in; the
    // CPU clock stays parked until the frame's last stop bit.
    myfuzz_ip::IpTarget<0>::set_serial_rx(ip, SERIAL_PEER_IDLE_LEVEL & 1u);
#endif
    // Whether this tick's clock boundaries may clock the CPU.  A declared serial
    // peer parks it while the host itself drives the wire, so a case that carries
    // a received byte starts from a device state that already contains it.  Every
    // other build drives the CPU on every boundary exactly as before.
    auto cpu_clock_drive = [&]() -> bool {
#if HAVE_SERIAL_PEER
      return !serial_peer.holding;
#else
      return true;
#endif
    };
    // Every clock starts low (the step-0 level); no boundary is due yet.
    clear_reset(); eval_all();
    set_reset(0); eval_all();
#if HAVE_RVFI_ADAPTER
    // The adapter states the probe-bundle width it was elaborated with.  The
    // exported port's width is the binding's own declaration; a disagreement
    // means the vector is not the bundle the scoreboard expects, so the run stops
    // instead of reinterpreting bits.
    if (unsigned(rvfi.rvfi_probes_width_o) != CPU_RVFI_PROBES_WIDTH)
      throw std::runtime_error(
          "CVA6 RVFI adapter probe bundle is " +
          std::to_string(unsigned(rvfi.rvfi_probes_width_o)) + " bits but the CPU "
          "model's rvfi_probes_o export is " + std::to_string(CPU_RVFI_PROBES_WIDTH));
#endif
    for (unsigned n = 0; n < kAssertTicks; ++n) { set_reset(n); edge(); }
    clear_reset(); eval_all();
    for (unsigned n = 0; n < kReleaseTicks; ++n) edge();
    // A timed model always has an event pending past the phase boundary the host
    // just reached: that is its next scheduled task, not a leak.  The scheduler
    // owns that time, so the gate states the untimed case only.
    if (!kTimedModel && timed_events())
      throw std::runtime_error("unsupported timed model events");

    Response ins, dat;
    Mmio mmio;
    // The channel counters as they stood when the request in ``mmio`` was
    // accepted.  Every completion criterion compares against this mark, so one
    // case may complete several target transactions (a routed F6 case reads the
    // evidence word before and after the transfer) without any of them being
    // mistaken for a duplicate handshake.
    AxiMark axi_mark;
#if CPU_BUS_AXI4
    // The adapter beat currently being answered by the target model.  RAM beats
    // are answered inside the same tick; a target beat waits for the APB
    // transaction the common target path already performs.
    struct Axi4TargetBeat {
      bool active = false, write = false;
      uint32_t address = 0;
    };
    Axi4TargetBeat axi4_target;
#endif
#if CPU_BUS_AHB
    // The one outstanding backend beat and the address-phase classifier the
    // manager-domain taps feed.  Both live for the whole session: no case
    // resets them.
    AhbBeat beat;
    AhbIdentity identity;
#endif
#if HAVE_DMA
    Control control;
    // The outstanding master responses, oldest first.  At the historical depth of
    // one this is one slot and the code below behaves exactly as it always did;
    // at a declared depth of N the host serves N responses before it stalls the
    // master, which is what a pipelined master's request/ack counters expect.
    // A slot is only ever read when ``master_count`` says it is in use, so the
    // accessors below are the only way the rest of the host touches it.
    Master master_ring[kDmaOutstanding];
    unsigned master_head = 0, master_count = 0;
    auto master_head_entry = [&]() -> Master & { return master_ring[master_head]; };
    auto master_pending = [&] { return master_count > 0; };
    auto master_full = [&] { return master_count >= kDmaOutstanding; };
    auto master_head_delay = [&]() -> unsigned {
      return master_pending() ? master_head_entry().delay : 0u;
    };
    // Take the accepted beat as the newest outstanding response.  The ring can only
    // be full when mwb_stall was low, so this never drops a record.
    auto master_push = [&]() -> Master & {
      const unsigned slot = (master_head + master_count) % kDmaOutstanding;
      master_ring[slot] = Master();
      ++master_count;
      return master_ring[slot];
    };
    // Retire the oldest response, the one the ack just completed.
    auto master_pop = [&] {
      master_head_entry() = Master();
      master_head = (master_head + 1u) % kDmaOutstanding;
      --master_count;
    };
#if DMA_ROUTE_ENABLED
    MasterRoute route;
#endif
#endif
    Observation observation;
    Record record;
    // The declared program data window as it stood when the current case was
    // installed; the case-end comparison is against these words, not against a
    // re-derivation from the program's instructions.
    uint32_t data_before[PROGRAM_DATA_WORDS] = {0};
#if HAVE_IRQ_LINKS
    std::vector<IrqLink> irq_links;
#define IRQ_LINK(expression, bit, pulse, invert) \
    irq_links.push_back(IrqLink{[&] { \
      return unsigned(((uint64_t(expression) >> (bit)) & 1ull) ^ (uint64_t(invert))); \
    }, (pulse)});
    IRQ_SOURCES(IRQ_LINK)
#undef IRQ_LINK
#endif
    bool ack_pending = false, frame_done = false, normal_finish = false;
    bool irq_delivered = false;
    // A level-storm abort already reset the devices (the reported recovery), so
    // the ordinary end-of-case recovery must not count a second reset for the
    // same case.  The case still ends on the handler's own mailbox store: the
    // CPU has to leave the handler and reach its poll loop before the next
    // input is installed, otherwise that handler's completion store would
    // overwrite the next case's command word.
    bool level_stuck_recovered = false, storm_waiting_mailbox = false;
#if CPU_CUSTOM_IRQ
    bool custom_eoi_previous = false;
    bool custom_irq_previous = false;
#endif
    uint64_t tick = 0, case_tick = 0;
#if CPU_BUS_AHB
    // The CPU's declared boot base is a configuration constant; the first real
    // instruction beat is the runtime observation the artifact asks for.
    bool first_fetch_seen = false;
    uint32_t first_fetch_address = 0;
    uint64_t first_fetch_tick = 0;
#endif
#if CPU_BUS_AXI4
    // CVA6 bakes its reset vector into its own configuration (0x10000 for the
    // pinned cv64a6 build), so the boot fetch is an observation, not a host
    // choice: the first instruction word this run served, the AXI ID it rode and
    // the tick it happened on.  A configured-base fetch is tracked apart from
    // "some fetch" so a CPU that starts elsewhere cannot be reported as a boot.
    bool first_fetch_seen = false;
    uint32_t first_fetch_address = 0;
    uint64_t first_fetch_tick = 0;
    unsigned first_fetch_arid = 0;
    bool boot_fetch_seen = false;
    uint64_t boot_fetch_tick = 0;
    bool firmware_fetch_seen = false;
    uint64_t firmware_fetch_tick = 0;
    uint32_t firmware_fetch_address = 0;
#endif
    unsigned cases = 0, failed_cases = 0, total_target_reads = 0, total_target_writes = 0;
    unsigned total_ip_reads[IP_COUNT > 0 ? IP_COUNT : 1] = {};
    unsigned total_ip_writes[IP_COUNT > 0 ? IP_COUNT : 1] = {};
    unsigned total_ip_irq_high[IP_COUNT > 0 ? IP_COUNT : 1] = {};
    unsigned total_ip_irq_delivered[IP_COUNT > 0 ? IP_COUNT : 1] = {};
    unsigned total_d_reads = 0, total_d_writes = 0, total_fetches = 0, total_irq_high = 0;
#if CPU_BUS_AXI4
    unsigned total_poll_reads = 0;
#endif
    unsigned total_irq_edges = 0, total_irq_takes = 0;
#if IRQ_BOTH_ENABLED && IRQ_TARGET_LINK_COUNT > 0
    // How many cases selected the synthetic two-source row.  A build without
    // one never prints the count, so its summary line is unchanged.
    unsigned total_both_cases = 0;
#endif
    unsigned total_retires = 0, total_rvfi_writebacks = 0, total_traps = 0;
    unsigned total_target_errors = 0, total_irq_delivered_high = 0;
    // A case whose bounded firmware wait expired is counted, and its device
    // state is reset before the next case so a pending interrupt cannot leak.
    unsigned total_wait_timeouts = 0, recovery_resets = 0;
    unsigned total_level_stuck = 0;
#if IRQ_SOURCE_COUNT > 0
    unsigned total_irq_link_edges[IRQ_SOURCE_COUNT] = {};
#endif
    uint64_t total_rvfi_expanded = 0;
    bool total_rvfi_order_monotonic = true;
#if CPU_BUS_AHB
    unsigned total_ahb_beats = 0, total_ahb_unknown = 0, total_ahb_unknown_reset = 0;
#endif
#if TARGET_HAS_AXI4LITE
    // The five-channel handshake totals of every AXI4-Lite target in this build.
    // A mixed build accumulates them beside the APB3 target's neutral counters
    // and states which target each count came from in the per-target block.
    unsigned total_axi_aw = 0, total_axi_w = 0, total_axi_b = 0;
    unsigned total_axi_ar = 0, total_axi_r = 0;
    unsigned total_wstrb_full = 0, total_resp_non_okay = 0;
#endif
#if TARGET_HAS_WISHBONE
    // The classic handshake this build really sampled: completed cycles and the
    // stall ticks the slave's own stall pin held.
    unsigned total_wb_acks = 0, total_wb_stalls = 0, total_wb_stb_pulses = 0;
#endif
#if TARGET_HAS_TLUL
    // The A/D channel handshake totals and the responses that carried d_error.
    unsigned total_tlul_a = 0, total_tlul_d = 0, total_tlul_errors = 0;
#endif
#if TARGET_HAS_AHB
    // The two AHB-Lite phases this build completed, totalled over the batch.
    unsigned total_ahb_address_phases = 0, total_ahb_data_phases = 0;
#endif
#if HAVE_DMA
    unsigned total_dma_reads = 0, total_dma_writes = 0, total_ctl_writes = 0;
    unsigned total_dma_done = 0, total_busy_high_reads = 0;
    // F6 backpressure and byte enables, accumulated over the cases that ran the
    // DMA.  A run that executed no F6 case reports them as zero beats and the
    // delay evidence as unknown, never as a passing observation.
    unsigned total_dma_acks = 0, total_dma_delayed = 0, total_dma_stall = 0;
    unsigned total_dma_max_stall = 0, total_dma_sel_full = 0, total_dma_sel_partial = 0;
    unsigned total_dma_lane_written = 0, total_dma_lane_missing = 0;
    unsigned total_dma_lane_extra = 0, total_dma_outside = 0;
    unsigned total_dma_f6_cases = 0;
#if DMA_ROUTE_ENABLED
    // The routed transfer totals, so a batch summary states how many accepted
    // master writes went to the target, how many it answered, and how many of
    // its own APB writes completed them.
    unsigned total_dma_route_writes = 0, total_dma_route_acks = 0;
    unsigned total_dma_route_target_writes = 0, total_dma_ram_writes = 0;
    unsigned total_dma_route_f6_cases = 0;
#if DMA_ROUTE_ENABLED && DMA_ROUTE_TRACE
    // The routed beats the target's own protocol trace completed, totalled over
    // the batch.  Only a non-APB3 route prints it; an APB3 route keeps the
    // summary line it always had.
    unsigned total_dma_route_protocol_transfers = 0;
#endif
#if DMA_ROUTE_READ
    // The read route's totals: routed master reads, the target's completed APB
    // reads, and the master reads that were served from RAM (must stay zero).
    unsigned total_dma_route_reads = 0, total_dma_route_target_reads = 0;
    unsigned total_dma_ram_reads = 0;
#endif
#endif
#endif
#if HAVE_PINS
    unsigned total_pad_changes = 0, total_pad_rise_events = 0, total_pin_stimulus = 0;
    unsigned total_pad_unsettled_reads = 0;
#endif
#if HAVE_PINS && HAVE_PIN_GROUPS
    unsigned total_pin_group_ticks = 0, total_pin_group_changes = 0;
    unsigned total_pin_group_conflicts = 0;
#endif
#if HAVE_SERIAL_PEER
    unsigned total_serial_rx_frames = 0, total_serial_rx_bits = 0;
    unsigned total_serial_tx_frames = 0, total_serial_tx_framing_ok = 0;
#endif
    auto case_started = std::chrono::steady_clock::now();

    // A timed-out case may leave a device still counting toward its own
    // interrupt.  Resetting only the devices (never the CPU) clears that pending
    // condition between two cases; the CPU is held with its clock low and stays
    // in the fixed polling loop.
    auto device_tick = [&] {
      // Only the devices are reset (recover_devices holds the CPU clock low).
      // One host tick of device-domain boundaries advances every target and DMA
      // model at its own declared rate; a slow device sees its own cycles, never
      // the reference CPU's tick count, and the host does not over-clock it.  The
      // CPU is not stepped here, so its own half period only sets how many grid
      // steps one tick of device time is (2 per reference half period).
      for (unsigned s = 0; s < kGridStepsPerTick; ++s) {
        apply_phase_boundary(false);
        eval_all();
      }
    };
    // ``drop_cpu_channels`` also clears the two CPU response channels, which is
    // right on a timeout (the CPU is parked in its wait loop) but wrong at an
    // ordinary case boundary: the CPU may already have an instruction response in
    // flight, and dropping it would park the CPU waiting forever for a response
    // that never comes.
    auto recover_devices = [&](bool drop_cpu_channels = true) {
      cpu.clk = 0;
#if HAVE_DMA
      const unsigned assert_ticks = std::max(ip_assert_ticks, DMA_RESET_ASSERT);
      const unsigned release_ticks = std::max(ip_release_ticks, DMA_RESET_RELEASE);
#else
      const unsigned assert_ticks = ip_assert_ticks;
      const unsigned release_ticks = ip_release_ticks;
#endif
      for (unsigned n = 0; n < assert_ticks; ++n) {
        for_each_ip(ip_models, [&](auto constant, auto &model) {
          myfuzz_ip::IpTarget<constant()>::set_reset(
              model, n < myfuzz_ip::IpTarget<constant()>::reset_assert);
        });
#if HAVE_DMA
        dma.reset = n < DMA_RESET_ASSERT;
#endif
        device_tick();
      }
      for_each_ip(ip_models, [&](auto constant, auto &model) {
        myfuzz_ip::IpTarget<constant()>::set_reset(model, 0);
      });
#if HAVE_DMA
      dma.reset = 0;
#endif
      for (unsigned n = 0; n < release_ticks; ++n) device_tick();
#if HAVE_PINS
      // The reset changed the device's own pad ports; resample them before the
      // next case so its ``pad_before``/``out_before`` baseline is the real
      // post-reset state rather than the last pre-reset sample.
      {
        const uint32_t sampled_out = myfuzz_ip::IpTarget<0>::pin_out(ip) & kPadMask;
        const uint32_t sampled_dir = myfuzz_ip::IpTarget<0>::pin_dir(ip) & kPadMask;
        pads.out = sampled_out;
        pads.dir = sampled_dir;
        pads.sync = myfuzz_ip::IpTarget<0>::pin_in_sync(ip) & kPadMask;
        pads.value = resolve_pads(sampled_out, sampled_dir, pads.ext);
        myfuzz_ip::IpTarget<0>::set_pin_in(ip, pads.value);
      }
      eval_all();
#endif
      if (drop_cpu_channels) {
        ins = Response(); dat = Response();
      }
      mmio = Mmio();
#if HAVE_DMA
      control = Control();
      for (unsigned slot = 0; slot < kDmaOutstanding; ++slot)
        master_ring[slot] = Master();
      master_head = 0; master_count = 0;
#if DMA_ROUTE_ENABLED
      route = MasterRoute();
#endif
#endif
      irq_delivered = false;
#if HAVE_IRQ_LINKS
      for (IrqLink &link : irq_links) {
        link.last = false; link.remaining = 0; link.edges = 0;
      }
#endif
      ++recovery_resets;
    };

    // Handing over one input never resets any model: the fragment lands in the
    // immutable trampoline slot, in a mailbox cell, or in the input block the
    // CPU itself reads; the CPU observes the command word on its next poll.  On a
    // pin target an F2 carrying a second word also rewrites the host's own
    // external driver, which is the stimulus side of the pad model.
    auto install = [&](const Record &next) {
#if HAVE_DMA && DMA_ROUTE_ENABLED
      // A routed F6 case starts from the devices' own reset state: the routed
      // FIFO has to be empty for the before/after level readback to describe
      // this transfer, and the DMA control word has to be idle.  This is the
      // same devices-only recovery the timeout path uses (the CPU and the RAM
      // image are retained), and it is reported under device_resets.
      if (next.flow == kF6 && kDmaRouteResetBeforeCase) recover_devices(false);
#endif
      record = next;
      observation = Observation();
      ack_pending = frame_done = false;
      level_stuck_recovered = storm_waiting_mailbox = false;
      case_tick = tick;
      case_started = std::chrono::steady_clock::now();
      // Per-model clock baselines: the per-case evidence line below states the
      // rising edges each model's own clock really received inside this case.
      case_cpu_rises = cpu_rises;
      for_each_ip(ip_models, [&](auto constant, auto &) {
        case_ip_rises[constant()] = ip_rises[constant()];
      });
#if HAVE_DMA
      case_dma_rises = dma_rises;
#endif
#if HAVE_PINS
      observation.pad_before = pads.value;
      observation.out_before = pads.out;
      observation.dir_before = pads.dir;
      observation.padin_latch = pads.sync;
      observation.pin_stimulus = record.flow == kF2 && record.words == 2;
      pads.ext = observation.pin_stimulus ? word_at(record, 1)
                                          : uint32_t(IP_PAD_EXT_DEFAULT);
      observation.ext_value = pads.ext;
#if HAVE_PIN_GROUPS
      // The declared groups take the wire in declaration order from this case's
      // first tick.  A case's own stimulus word overrides the first group's
      // declared driver value and nothing else: the rest of the schedule is the
      // declaration's, not the operator's.
      pin_schedule.begin_case(observation.pin_stimulus, pads.ext);
#endif
#endif
#if HAVE_SERIAL_PEER
      // A case's own stimulus word is the byte the peer clocks onto rx.  The
      // frame starts at this case's first tick and the CPU stays parked until its
      // last stop bit, so the byte is on the device before the CPU reads it.
      serial_peer.reset_case();
      serial_peer.pending = record.flow == kF2 && record.words == 2;
      serial_peer.pending_byte = serial_peer.pending
          ? (word_at(record, 1) & 0xffu) : 0u;
#endif
      if (record.flow == kF1) {
        // The program's words land in the trampoline slot and one return jump is
        // written immediately after them.  Bytes left over from an earlier case
        // sit behind that jump and are never executed; a longer program
        // overwrites the old jump before it is fetched.  The declared data
        // window is sampled here so a later store is a measured change.
        for (unsigned index = 0; index < record.words; ++index)
          memory.write(kSlot + 4 * index, word_at(record, index), 15);
        const uint32_t return_pc = kSlot + 4 * record.words;
        // A header that states no return address (an older entry) keeps the
        // firmware image's own return jump.  Writing the default 0 there would
        // send the CPU to address zero, which is outside the declared RAM.
        if (SLOT_RETURN != 0u)
          memory.write(return_pc, encode_trampoline_return(return_pc, SLOT_RETURN), 15);
        observation.data_hash_before = window_hash(memory, kDataBase, PROGRAM_DATA_WORDS);
        for (unsigned index = 0; index < PROGRAM_DATA_WORDS; ++index)
          data_before[index] = memory.read(kDataBase + 4 * index);
#if F1_TRAP_PROGRAM
        // The three cells the firmware's trap handler stores to start from a
        // sentinel, so a word that survives is reported as "the handler never
        // ran for this case" instead of as the previous case's value.
        memory.write(TRAP_CAUSE_CELL, TRAP_SENTINEL, 15);
        memory.write(TRAP_EPC_CELL, TRAP_SENTINEL, 15);
        memory.write(TRAP_FLAG_CELL, TRAP_SENTINEL, 15);
#endif
      }
      if (record.flow == kF2) memory.write(kArgument, word_at(record, 0), 15);
      if (record.flow == kF3 || record.flow == kF4) {
        memory.write(kArgument, word_at(record, 0), 15);
        memory.write(kValue, word_at(record, 1), 15);
        if (record.flow == kF3) observation.ram_before = memory.read(word_at(record, 0));
      }
      if (record.flow == kF5 || record.flow == kF6) {
        for (unsigned index = 0; index < record.words; ++index)
          memory.write(kInput + 4 * index, word_at(record, index), 15);
      }
#if HAVE_DMA
      if (record.flow == kF6) {
        // The declared destination block starts from a known sentinel, and one
        // guard word on either side of it is part of the same image: a word the
        // transfer never reaches keeps the sentinel, and a strobe outside the
        // block shows up in the guard word it touched.
        for (unsigned index = 0; index < kDmaBlockWords; ++index)
          memory.write(kDmaDestinationBase + 4 * index, DMA_DEST_SENTINEL, 15);
        memory.write(kDmaDestinationBase - 4, DMA_DEST_SENTINEL, 15);
        memory.write(kDmaDestinationBase + 4 * kDmaBlockWords, DMA_DEST_SENTINEL, 15);
#if DMA_ROUTE_ENABLED
        // The evidence cells belong to this case: a sentinel that survives means
        // the firmware never read the routed status word, which is reported as
        // unknown instead of as the previous case's value.
        memory.write(kDmaRouteBefore, kDmaRouteCellPrefill, 15);
        memory.write(kDmaRouteAfter, kDmaRouteCellPrefill, 15);
#if DMA_ROUTE_READ
        // The read route's CPU destination-readback cells are per-case too: a
        // cell still holding the prefill was never written by this case's CPU.
        for (unsigned index = 0; index < kDmaBlockWords; ++index)
          memory.write(kDmaRouteDst + 4 * index, kDmaRouteCellPrefill, 15);
#endif
#endif
      }
#endif
      memory.write(kCommand, unsigned(record.flow), 15);
    };

    auto receive = [&](size_t index) {
      std::cout << "NEED_RECORD " << index << " tick " << tick << '\n';
      std::string line;
      if (!std::getline(std::cin, line) || line == "END") return false;
      std::istringstream message(line);
      std::vector<std::string> tokens;
      for (std::string token; message >> token;) tokens.push_back(token);
      if (tokens.size() < 2 || tokens.front() != "CASE")
        throw std::runtime_error("invalid online record");
      tokens.erase(tokens.begin());
      install(parse_fields(tokens));
      std::cout << "CASE_INSTALLED " << index << '\n';
      return true;
    };

    if (online) {
      if (!receive(0)) throw std::runtime_error("no online record");
    } else if (!records.empty()) {
      install(records.front());
    } else {
      throw std::runtime_error("no record");
    }

#if HAVE_EVENT_LAYER
    // An error response is an event only when a model produces it.  The OBI
    // response error wires are CPU inputs this host drives, and the DMA model
    // exposes no error output, so those channels are stated as unknown instead
    // of being wired to zero and then reported as a clean bus.  The target's own
    // error response is a real trace output and is sampled per transfer; an
    // AXI4-Lite slave that only ever drives OKAY is stated as unknown, never as a
    // clean bus that was covered.  A Wishbone CPU build declares the one channel
    // it actually has, so the OBI words are not printed for it.
#if CPU_BUS_WISHBONE
    std::cout << "bus_error unknown wb\n";
#elif CPU_BUS_AHB
    // The AHB manager's own response-error input is a host input with no model
    // output behind it (the adapter propagates the service's flag), so the
    // channel is stated as unknown and never as a covered error path.
    std::cout << "bus_error unknown ahb\n";
#elif CPU_BUS_AXI4
    // The AXI4 CPU side's rsp_error_i is a host input this path always drives
    // low; only the adapter's DECERR fallback exists behind it, so the CPU-side
    // channel is stated as unknown rather than as a clean bus that was covered.
    std::cout << "bus_error unknown axi\n";
#else
    std::cout << "bus_error unknown obi_i\n";
    std::cout << "bus_error unknown obi_d\n";
#endif
#if HAVE_DMA
    std::cout << "bus_error unknown mwb\n";
#endif
#if TARGET_PROTOCOLS_MIXED
    // A mixed build declares every channel it really samples, one word per
    // channel: the AXI4-Lite slave's BRESP/RRESP, a Wishbone target's own ack
    // cycle, a TL-UL target's d_error, and the APB3 trace's pslverr (only when
    // the target's profile exposes it).  A channel that was never produced is
    // unknown, never a clean bus, and a channel this build does not have is not
    // named at all.
#if TARGET_HAS_AXI4LITE
    std::cout << "bus_error unknown axi\n";
#endif
#if TARGET_HAS_WISHBONE
    std::cout << "bus_error unknown wb\n";
#endif
#if TARGET_HAS_TLUL
    std::cout << "bus_error unknown tlul\n";
#endif
#if TARGET_HAS_AHB
    std::cout << "bus_error unknown ahb\n";
#endif
#if TARGET_HAS_APB3 && !HAVE_APB_PSLVERR
    std::cout << "bus_error unknown apb\n";
#endif
#elif TARGET_PROTOCOL_AXI4LITE
    std::cout << "bus_error unknown " TARGET_BUS_CHANNEL "\n";
#elif !HAVE_APB_PSLVERR
    std::cout << "bus_error unknown " TARGET_BUS_CHANNEL "\n";
#endif
#endif

#if CPU_BUS_AXI4
    // The CPU-side AXI4 channel traffic this host really handshook, printed on
    // the same pre-edge sample the link took.  The `axi4` prefix names the CPU
    // port (the AXI4-Lite target's own taps keep their `axi` name), so a saved
    // log shows which address, ID, kind, data and strobe crossed the bus instead
    // of only a per-case count.  A beat line is the adapter's one-outstanding
    // beat face: the request the host was handed and the answer it drove back.
    auto trace_axi4 = [&] {
#if HAVE_EVENT_LAYER
      const myfuzz::axi4::Observation &ob = link.observation();
      if (ob.ar.valid)
        EVENT_STREAM << "axi4 ar " << tick << " id " << ob.ar.id
                     << " addr " << hex64(ob.ar.address)
                     << " len " << ob.ar.len << " size " << ob.ar.size
                     << " burst " << ob.ar.burst << " kind "
                     << myfuzz::axi4::CpuLink::kind_name(ob.ar.kind) << '\n';
      if (ob.r.valid)
        EVENT_STREAM << "axi4 r " << tick << " id " << ob.r.id
                     << " data " << hex64(ob.r.data) << " resp " << ob.r.resp
                     << " last " << ob.r.last << " kind "
                     << myfuzz::axi4::CpuLink::kind_name(ob.r.kind) << '\n';
      if (ob.aw.valid)
        EVENT_STREAM << "axi4 aw " << tick << " id " << ob.aw.id
                     << " addr " << hex64(ob.aw.address)
                     << " len " << ob.aw.len << " size " << ob.aw.size
                     << " burst " << ob.aw.burst << " kind data\n";
      if (ob.w.valid)
        EVENT_STREAM << "axi4 w " << tick << " data " << hex64(ob.w.data)
                     << " strb " << hex32(ob.w.strobe) << " last "
                     << int(ob.w.last) << " kind data\n";
      if (ob.b.valid)
        EVENT_STREAM << "axi4 b " << tick << " id " << ob.b.id
                     << " resp " << ob.b.resp << " kind data\n";
      if (ob.beat_request)
        EVENT_STREAM << "axi4 beat req " << tick << ' '
                     << (ob.beat.write ? "write" : "read")
                     << " addr " << hex64(ob.beat.address)
                     << " data " << hex64(ob.beat.wdata)
                     << " be " << hex32(ob.beat.be) << '\n';
      if (ob.beat_response)
        EVENT_STREAM << "axi4 beat rsp " << tick << ' '
                     << (link.last_beat_was_write() ? "write" : "read")
                     << " data " << hex64(link.response_rdata())
                     << " error " << int(link.response_error()) << '\n';
#endif
    };
#endif

    for (; tick < kMaxTicks; ++tick) {
#if HAVE_SERIAL_PEER
      // The declared peer drives its frame one bit time at a time.  The frame
      // starts at the first tick of the case that asked for one, the rx level is
      // set before this tick's rising boundary so the device samples exactly this
      // level, and ``holding`` parks the CPU clock for the frame's whole span
      // (``cpu_clock_drive`` below).  The tx line is sampled after the models
      // evaluated, in the same phase the pad and interrupt samples are read.
      if (serial_peer.pending) {
        serial_peer.pending = false;
        serial_peer.begin_rx(serial_peer.pending_byte, tick);
        EVENT_STREAM << "serial rx " << tick << " frame start byte "
                     << hex32(serial_peer.rx_byte) << " frame "
                     << SERIAL_PEER_FRAME << " bit_ticks "
                     << SerialPeer<IP_MODEL>::kBitTicks << '\n';
      }
      serial_peer.step_rx(ip, tick);
#endif
      // Which model observations are readable in this tick's low phase.  The host
      // has always read a model's registered protocol outputs there, one tick
      // after the rising edge that produced them, so a model whose declared half
      // period is R grid steps presents a new sample on one tick in R:
      //   * trace_now   - a rising edge happens in this tick (mid or end), so the
      //                   level the low phase reads is the one that edge will
      //                   latch (request/trace handshakes are pre-edge facts);
      //   * response_now- the previous tick applied the rising edge that
      //                   registered a response, read here;
      //   * probe_now   - the post-edge probe sample (pins) can see a rise at the
      //                   end of the previous tick or at this tick's mid.
      // A ratio-1 model gets all three on every tick, which is the historical
      // loop exactly.
      bool ip_trace_now[IP_COUNT > 0 ? IP_COUNT : 1] = {};
      bool ip_response_now[IP_COUNT > 0 ? IP_COUNT : 1] = {};
      bool ip_probe_now[IP_COUNT > 0 ? IP_COUNT : 1] = {};
      for_each_ip(ip_models, [&](auto constant, auto &) {
        const unsigned index = constant();
        const PhaseSampleGates gates = phase_sample_gates(
            phase_step, ip_half_ticks(index), ip_rise_pending[index],
            kGridStepsPerTick);
        ip_trace_now[index] = gates.trace;
        ip_response_now[index] = gates.response;
        ip_probe_now[index] = gates.probe;
        ip_rise_pending[index] = false;
      });
#if HAVE_DMA
      const PhaseSampleGates dma_gates = phase_sample_gates(
          phase_step, kDmaHalfTicks, dma_rise_pending, kGridStepsPerTick);
      const bool dma_trace_now = dma_gates.trace;
      const bool dma_response_now = dma_gates.response;
      dma_rise_pending = false;
#endif
#if !CPU_BUS_AXI4
      // The previous tick ended on the falling edge, so this tick begins in the
      // low phase.  A timed model spends exactly one grid step (the reference
      // CPU's declared half period) there before the rising boundary; an untimed
      // build (TIMED_GRID_PS is 0 and the model schedules nothing) advances
      // nothing.
      timed_advance_to(context.time() + TIMED_GRID_PS);
#endif
#if CPU_BUS_AXI4
      // Begin the tick on the CPU/adapter pair: settle the combinational loop,
      // sample the AXI channels, and capture at most one adapter beat.  The
      // captured beat's request handshake stays asserted through this tick's
      // rising edge; its answer is driven only after that edge.
      link.begin_tick();
      trace_axi4();
      myfuzz::axi4::BeatRequest axi4_beat;
      // Only a beat handshaked on this low phase is a new beat to service.  A
      // beat already captured and handed to the target stays readable through
      // beat_request() until its answer is driven, so request_handshaked() (not
      // beat_request()) is what tells the two apart.
      if (link.request_handshaked() && link.beat_request(axi4_beat)) {
        if (axi4_target.active)
          throw std::runtime_error(
              "AXI4 adapter issued a beat while the target beat is still in flight");
        myfuzz::axi4::WordAccess words[2];
        const unsigned word_count = myfuzz::axi4::CpuLink::split_beat(axi4_beat, words);
        if (word_count == 0)
          throw std::runtime_error("AXI4 beat selected no byte lane");
        if (axi4_beat.write) {
          bool target_taken = false;
          for (unsigned index = 0; index < word_count; ++index) {
            const auto &word = words[index];
            if (in_ip(word.address)) {
              if (word_count != 1 || word.be != 15 || target_taken)
                throw std::runtime_error(
                    "AXI4 target write is not one full 32-bit word: the CPU merged "
                    "an IP store across the beat (64-bit write, address " +
                    hex64(axi4_beat.address) + ", be " +
                    std::to_string(axi4_beat.be) + ")");
              mmio.busy = true; mmio.sent = false; mmio.write = true;
              mmio.address = uint32_t(word.address); mmio.value = word.value; mmio.be = 15;
              mmio.target = unsigned(ip_index_of(word.address));
              observation.target_index = int(mmio.target);
              axi4_target.active = true; axi4_target.write = true;
              axi4_target.address = uint32_t(word.address);
              target_taken = true;
              EVENT_STREAM << "cpu_mmio " << tick << " write " << hex32(word.address)
                           << ' ' << hex32(word.value) << '\n';
            } else if (in_ram(word.address)) {
              if (word.be > 15) throw std::runtime_error("invalid AXI4 RAM byte enable");
              memory.write(uint32_t(word.address), word.value, word.be);
              ++observation.d_writes;
              // The firmware's own store of zero into the command word is the
              // only case delimiter.  This write is already committed to RAM in
              // this tick; the case still waits for the adapter's response (see
              // the idle test) so the CPU really received its write response.
              if (uint32_t(word.address) == kCommand && word.be == 15 && word.value == 0)
                frame_done = true;
              if (uint32_t(word.address) == kEcho && word.be == 15) {
                observation.echo_stored = true;
                observation.echo_value = word.value;
              }
              if (uint32_t(word.address) >= kDataBase) {
                observation.write_accepted = true;
                observation.write_address = uint32_t(word.address);
                observation.write_value = word.value;
                observation.write_be = word.be;
              }
#if HAVE_EVENT_LAYER
              EVENT_STREAM << "cpu_data " << tick << " write " << hex32(word.address)
                           << ' ' << hex32(word.value) << std::dec << " be " << word.be << '\n';
#endif
            } else {
              throw std::runtime_error("AXI4 write outside RAM and the declared target windows");
            }
          }
          if (!target_taken) {
            myfuzz::axi4::BeatResponse response;
            response.rdata = 0; response.error = false;
            link.beat_response(response);
          }
        } else {
          const auto kind = link.request_kind(link.last_ar_id());
          const bool instruction = kind == Axi4CpuIdentity::Instruction;
          bool target_taken = false;
          uint32_t low = 0, high = 0;
          for (unsigned index = 0; index < word_count; ++index) {
            const auto &word = words[index];
            if (in_ip(word.address)) {
              // An instruction fetch belongs in RAM: the target window is a
              // register file, not code.  Refuse it by name instead of serving
              // the fetch with a device register value.
              if (instruction)
                throw std::runtime_error("AXI4 instruction fetch inside the target window");
              if (word_count != 1 || word.be != 15 || target_taken)
                throw std::runtime_error("AXI4 target read is not one full 32-bit word");
              mmio.busy = true; mmio.sent = false; mmio.write = false;
              mmio.address = uint32_t(word.address); mmio.value = 0; mmio.be = 15;
              mmio.target = unsigned(ip_index_of(word.address));
              observation.target_index = int(mmio.target);
              axi4_target.active = true; axi4_target.write = false;
              axi4_target.address = uint32_t(word.address);
              target_taken = true;
              EVENT_STREAM << "cpu_mmio " << tick << " read " << hex32(word.address) << '\n';
            } else if (in_ram(word.address)) {
              const uint32_t value = memory.read(uint32_t(word.address));
              if ((word.address & 4) != 0) high = value; else low = value;
              if (instruction) {
                ++observation.i_fetches;
                if (!first_fetch_seen) {
                  first_fetch_seen = true;
                  first_fetch_address = uint32_t(word.address);
                  first_fetch_tick = tick;
                  first_fetch_arid = link.last_ar_id();
                }
                if (!boot_fetch_seen && uint32_t(word.address) == CPU_BOOT_ADDRESS) {
                  boot_fetch_seen = true;
                  boot_fetch_tick = tick;
                  EVENT_STREAM << "boot_fetch " << tick << ' '
                               << hex32(uint32_t(word.address)) << " arid "
                               << link.last_ar_id() << '\n';
                }
                if (!firmware_fetch_seen
                    && uint32_t(word.address) >= CPU_MAIN_ADDRESS) {
                  firmware_fetch_seen = true;
                  firmware_fetch_tick = tick;
                  firmware_fetch_address = uint32_t(word.address);
                  EVENT_STREAM << "firmware_fetch " << tick << ' '
                               << hex32(firmware_fetch_address) << " main "
                               << hex32(CPU_MAIN_ADDRESS) << '\n';
                }
                if (uint32_t(word.address) <= kSlot
                    && kSlot < uint32_t(word.address) + 4u) {
                  observation.slot_fetch = true;
                  observation.slot_fetch_address = kSlot;
                }
#if HAVE_EVENT_LAYER
                EVENT_STREAM << "ifetch " << tick << ' ' << hex32(word.address)
                             << ' ' << hex32(value) << '\n';
#endif
              } else {
                ++observation.d_reads;
                // The firmware's own poll loop loads the command word until it
                // becomes non-zero; each such load is a real data read of that
                // address, so the count shows the CPU reached the loop.
                if (uint32_t(word.address) == kCommand) ++observation.poll_reads;
                if (uint32_t(word.address) >= kDataBase) {
                  observation.read_accepted = true;
                  observation.read_address = uint32_t(word.address);
                  observation.read_from_ip = false;
                  observation.read_value = value;
                }
              }
            } else {
              throw std::runtime_error("AXI4 read outside RAM and the declared target windows");
            }
          }
          if (!target_taken) {
            myfuzz::axi4::BeatResponse response;
            response.rdata = myfuzz::axi4::CpuLink::join_beat_read(low, high);
            response.error = false;
            link.beat_response(response);
          }
        }
      }
#endif
#if CPU_BUS_WISHBONE
      // The routed master beat asks for the same target port the CPU uses.  The
      // CPU keeps priority: the route is presented only while no CPU MMIO
      // transaction is in flight, and while the route owns the port the CPU's
      // data channel is stalled instead of being allowed to collide with it.
#if HAVE_DMA && DMA_ROUTE_ENABLED
      const bool route_present = route.waiting && !route.sent && !route.done
          && master_head_delay() == 0 && !mmio.busy;
      route.presented = route_present;
      const bool route_holds_port = route.waiting && (route.presented || route.sent);
#else
      const bool route_present = false;
      const bool route_holds_port = false;
#endif
      // The CPU declares a multi-bit irq vector and this host has no per-bit
      // wiring declaration for it, so the whole vector is held at zero and the
      // summary states that: no interrupt is delivered in this build.  One
      // combinational acknowledgement answers the single cyc/stb master; the
      // CPU's own mem_instr output says whether the beat is a fetch.
#if CPU_CUSTOM_IRQ
      // Pico's declared ABI latches IRQ inputs internally. Deliver one real
      // rising edge instead of holding the line high throughout the ISR,
      // which would latch a duplicate interrupt before the device clears it.
      const bool custom_irq_pulse = irq_delivered && !custom_irq_previous;
      cpu.CPU_IRQ = custom_irq_pulse ? (uint32_t(1) << CPU_CUSTOM_IRQ_BIT) : 0;
      custom_irq_previous = irq_delivered;
      if (custom_irq_pulse) ++observation.irq_delivered_high;
#else
      cpu.CPU_IRQ = 0;
#endif
      cpu.CPU_WB_ACK = dat.valid ? 1 : 0;
      cpu.CPU_WB_DAT_R = dat.valid ? dat.value : 0;
#elif CPU_BUS_AHB
      // The AHB-Lite manager has no interrupt input at this boundary: the CVW
      // wrapper exports none, so nothing is delivered and the summary says so.
      // The adapter's beat face is the only functional handshake this host
      // drives: accept a beat (req_ready) when none is outstanding, and answer
      // it (rsp_valid) as soon as its value is known.  HREADYEXT itself is
      // produced by the generated adapter, never by this host.
#if HAVE_DMA && DMA_ROUTE_ENABLED
      const bool route_present = route.waiting && !route.sent && !route.done
          && master_head_delay() == 0 && !mmio.busy;
      route.presented = route_present;
      const bool route_holds_port = route.waiting && (route.presented || route.sent);
#else
      const bool route_present = false;
      const bool route_holds_port = false;
#endif
      cpu.CPU_M_REQ_READY = beat.active ? 0 : 1;
      cpu.CPU_M_RSP_VALID = (beat.active && beat.have_value) ? 1 : 0;
      cpu.CPU_M_RSP_RDATA = beat.have_value ? beat.value : 0;
      cpu.CPU_M_RSP_ERROR = 0;
#elif CPU_BUS_AXI4
      // CpuLink drives the packed CPU<->adapter pins itself; the target/DMA
      // models below are the only ports this host still sets each tick.  The
      // interrupt entry is one of those ports: bit 0 is the machine-external
      // line the profile declares (core/csr_regfile.sv:2073, M_EXT), and bit 1
      // is the supervisor-external line the same profile holds inactive, so this
      // host drives exactly one bit and states the other as not driven.  The
      // take is observed on the retirement face (an interrupt retire with its
      // own cause/intr/mode), never inferred from an ISR store.
      cpu.CPU_IRQ = irq_delivered ? 1u : 0u;
#if HAVE_DMA && DMA_ROUTE_ENABLED
      const bool route_present = route.waiting && !route.sent && !route.done
          && master_head_delay() == 0 && !mmio.busy;
      route.presented = route_present;
      const bool route_holds_port = route.waiting && (route.presented || route.sent);
#else
      const bool route_present = false;
      const bool route_holds_port = false;
#endif
#else
      // Only a real sampled device output can assert the CPU's IRQ input.
      cpu.CPU_IRQ = irq_delivered ? 1 : 0;
      cpu.CPU_I_REQ_READY = !ins.valid;
      cpu.CPU_I_RSP_VALID = ins.valid; cpu.CPU_I_RSP_RDATA = ins.value; cpu.CPU_I_RSP_ERROR = 0;
#if HAVE_DMA && DMA_ROUTE_ENABLED
      // The routed master beat asks for the same target port the CPU uses.  The
      // CPU keeps priority: the route is presented only while no CPU MMIO
      // transaction is in flight, and while the route owns the port the CPU's
      // data channel is stalled instead of being allowed to collide with it.
      const bool route_present = route.waiting && !route.sent && !route.done
          && master_head_delay() == 0 && !mmio.busy;
      route.presented = route_present;
      const bool route_holds_port = route.waiting && (route.presented || route.sent);
#else
      const bool route_holds_port = false;
#endif
      bool target_busy = mmio.busy;
#if HAVE_DMA
      target_busy = target_busy || control.busy;
#endif
#if HAVE_DMA && DMA_ROUTE_ENABLED
      target_busy = target_busy || route_holds_port;
#endif
      cpu.CPU_D_REQ_READY = !dat.valid && !target_busy;
      cpu.CPU_D_RSP_VALID = dat.valid; cpu.CPU_D_RSP_RDATA = dat.value; cpu.CPU_D_RSP_ERROR = 0;
#endif
      // Only the target this request was routed to sees it.  Every other target
      // is driven with req_valid low but is still clocked and evaluated below.
      for_each_ip(ip_models, [&](auto constant, auto &model) {
        const bool selected_mmio = mmio.busy && !mmio.sent
            && unsigned(mmio.target) == constant();
#if HAVE_DMA && DMA_ROUTE_ENABLED
        // A routed master beat presents the declared target offset: a write route
        // forwards the whole word the device drove (the APB3 bridge has no write
        // strobes, so it is only admitted as a full-word write), a read route
        // drives PWRITE=0 and the target's own PRDATA is the answer.
        const bool selected_route = route_present
            && unsigned(constant()) == kDmaRouteTargetIndex;
#else
        const bool selected_route = false;
#endif
        const bool selected = selected_mmio || selected_route;
        const bool write = selected_mmio ? mmio.write
#if HAVE_DMA && DMA_ROUTE_ENABLED
            : !route.read;
#else
            : true;
#endif
        const uint32_t address = selected_mmio
            ? mmio.address - myfuzz_ip::IpTarget<constant()>::base
#if HAVE_DMA && DMA_ROUTE_ENABLED
            // A fixed route presents its declared offset; an aperture read
            // presents the offset the master itself addressed this beat.
            : route.offset;
#else
            : 0u;
#endif
        const uint32_t value = selected_mmio ? mmio.value
#if HAVE_DMA && DMA_ROUTE_ENABLED
            : (route.read ? 0u : route.wdata);
#else
            : 0u;
#endif
        const unsigned be = selected_mmio ? mmio.be : 15u;
        myfuzz_ip::IpTarget<constant()>::drive_request(
            model, selected, selected ? write : false,
            selected ? address : 0u, selected ? value : 0u,
            selected ? be : 0u);
      });
#if HAVE_DMA
      dma.swb_cyc = control.busy;
      dma.swb_stb = control.busy && !control.accepted;
      dma.swb_we = control.write;
      dma.swb_adr = control.offset >> 2;
      dma.swb_dat_w = control.value;
#if DMA_CONTROL_SEL
      dma.swb_sel = control.be;
#else
      if (control.busy && control.be != 15)
        throw std::runtime_error("partial DMA control write is outside this spike");
#endif
      dma.mwb_stall = master_full();
      // A routed beat is acked only after the target's APB3 bridge returned its
      // response: the master is held (stall) until then, so a route can never be
      // counted as complete just because the address decode matched.
      dma.mwb_ack = master_pending() && master_head_delay() == 0
#if DMA_ROUTE_ENABLED
          && (!master_head_entry().routed || route.done)
#endif
          ;
      // The level the device sees this tick, counted where it is driven.  A
      // pending response is exactly one stall tick on the no-delay host, so the
      // run length below is a measured number, not the declared knob.
      if (master_pending()) {
        ++observation.dma_stall_ticks;
        ++observation.dma_stall_run;
        if (observation.dma_stall_run > observation.dma_stall_max_run)
          observation.dma_stall_max_run = observation.dma_stall_run;
      } else {
        observation.dma_stall_run = 0;
      }
      // A declared error injection: the declared routed beat's response is
      // ACK+ERR, i.e. the device's own mwb_err input is driven with the ack.
      // Nothing else asserts it, and the ack is gated by the target's own
      // response exactly as an error-free beat is.
#if DMA_ROUTE_ENABLED && DMA_ROUTE_READ
      // A Wishbone error response is the ack with err in the same cycle: asserting
      // err alone would be a device-visible error the master never acknowledged.
      dma.mwb_err = (dma.mwb_ack && master_head_entry().error) ? 1 : 0;
#else
      dma.mwb_err = 0;
#endif
      dma.mwb_dat_r = master_pending() ? master_head_entry().data : 0u;
#endif
      eval_all();
#if HAVE_PINS
      // Resolve the pad wire from the ports the device just drove and drive the
      // device's own pin input with it: a pad bit is the device's output while
      // the device says that pin is an output, and the host value otherwise.  A
      // resolution is printed whenever the wire, the output or the direction
      // moved, so a pad value is never an unstated constant.
      {
        const uint32_t sampled_out = myfuzz_ip::IpTarget<0>::pin_out(ip) & kPadMask;
        const uint32_t sampled_dir = myfuzz_ip::IpTarget<0>::pin_dir(ip) & kPadMask;
        const uint32_t sampled_sync = myfuzz_ip::IpTarget<0>::pin_in_sync(ip) & kPadMask;
#if HAVE_PIN_GROUPS
        // The group holding the wire this tick: its own declared direction picks
        // the resolution (host-driven, device-driven or the per-bit dir rule), and
        // the change the resolution makes is attributed to that group alone.
        pads.ext = pin_schedule.step();
        // ``ext_value`` is the word the active group really presented, so the F2
        // acceptance compares the read wire against what was on it, not against
        // the declaration's first group.
        observation.ext_value = pads.ext;
        const uint32_t pad = pin_schedule.resolve(
            kPinGroups[pin_schedule.active], sampled_out, sampled_dir, pads.ext);
        pin_schedule.note_dir(sampled_dir);
#else
        const uint32_t pad = resolve_pads(sampled_out, sampled_dir, pads.ext);
#endif
        if (pad != pads.value || sampled_out != pads.out || sampled_dir != pads.dir) {
          if (pad != pads.value) {
            ++observation.pad_changes;
            EVENT_STREAM << "pin " << tick << " pad " << hex32(pads.value) << ' ' << hex32(pad)
                      << " out " << hex32(sampled_out) << " dir " << hex32(sampled_dir)
                      << " ext " << hex32(pads.ext)
#if HAVE_PIN_GROUPS
                      << " group " << pin_schedule.active
#endif
                      << '\n';
          }
#if HAVE_PIN_GROUPS
          pin_schedule.note_change(pads.value, pad, 0, 0);
#endif
          pads.value = pad; pads.out = sampled_out; pads.dir = sampled_dir;
        }
        pads.sync = sampled_sync;
        if ((myfuzz_ip::IpTarget<0>::pin_in(ip) & kPadMask) != pad) {
          myfuzz_ip::IpTarget<0>::set_pin_in(ip, pad);
          eval_all();
        }
        // The device's synchronizer latch is a register, so it holds the same
        // value across this cycle: this is what an APB read of PADIN returns.
        observation.padin_latch =
            myfuzz_ip::IpTarget<0>::probe_padin_latch(ip) & kPadMask;
      }
#endif
#if HAVE_SERIAL_PEER
      // The declared peer samples the device's own tx line once per host tick.
      // The frame's bit centres are the samples the line records, so a byte here
      // is a byte the device really serialized, not a copy of a register write.
      serial_peer.sample_tx(ip, tick);
#if HAVE_SERIAL_TX_EN
      serial_peer.sample_tx_en(ip);
#endif
#endif
      // The selected target's own handshake, sampled from its traits after the
      // tick's rising edge.  A non-selected target cannot answer a request it
      // never received; the common completion path below only completes this one.
      bool iptake = false, ipdone = false, iperror = false;
      uint32_t ipvalue = 0;
#if HAVE_DMA && DMA_ROUTE_ENABLED
      // The routed transaction's own handshake, sampled from the same trait
      // interface but kept apart from the CPU's MMIO request: only one of the
      // two can own the port in a tick, and the response below completes only
      // the one that was really presented.
      bool route_iptake = false, route_ipdone = false, route_iperror = false;
      uint32_t route_ipvalue = 0;
#endif
      for_each_ip(ip_models, [&](auto constant, auto &model) {
        const unsigned gate_index = constant();
        // The request handshake is a pre-edge fact: it is read on the tick whose
        // own rising boundary will latch it.  The response was registered at a
        // rising boundary of a previous tick: it is read on the tick after one.
        // A ratio-1 model satisfies both every tick, so its historical reads are
        // unchanged; a slow model is sampled once per its own cycle.
        if (mmio.busy && unsigned(mmio.target) == gate_index) {
          if (ip_trace_now[gate_index])
            iptake = !mmio.sent
                && myfuzz_ip::IpTarget<gate_index>::request_ready(model);
          if (ip_response_now[gate_index]) {
            ipdone = myfuzz_ip::IpTarget<gate_index>::response_valid(model);
            ipvalue = myfuzz_ip::IpTarget<gate_index>::response_rdata(model);
            iperror = myfuzz_ip::IpTarget<gate_index>::response_error(model);
          }
        }
#if HAVE_DMA && DMA_ROUTE_ENABLED
        if (route.presented && unsigned(gate_index) == kDmaRouteTargetIndex
            && ip_trace_now[gate_index]) {
          route_iptake = !route.sent
              && myfuzz_ip::IpTarget<gate_index>::request_ready(model);
        }
        if (route.waiting && route.sent && unsigned(gate_index) == kDmaRouteTargetIndex
            && ip_response_now[gate_index]) {
          route_ipdone = myfuzz_ip::IpTarget<gate_index>::response_valid(model);
          route_ipvalue = myfuzz_ip::IpTarget<gate_index>::response_rdata(model);
          route_iperror = myfuzz_ip::IpTarget<gate_index>::response_error(model);
        }
#if DMA_ROUTE_TRACE
        // The routed beat's own protocol trace, sampled from the target
        // artifact's passive taps in the same pre-edge phase the CPU MMIO trace
        // groups use.  The route owns the port while it is presented (the request
        // channel) or accepted and awaiting its answer (the response channel), so
        // the request payload is kept when that channel handshakes and the
        // transfer is counted once, when the target's own response completes it.
        // The CPU's MMIO transfers are not counted here: those are the other
        // owner of the port and the protocol group above already counts them.
        const bool route_owns = route.waiting
            && (route.presented || route.sent)
            && unsigned(constant()) == kDmaRouteTargetIndex
            && !mmio.busy && ip_trace_now[gate_index];
        if (route_owns) {
          if constexpr (myfuzz_ip::IpTarget<constant()>::wishbone) {
            // Wishbone classic: one held cycle terminated by the slave's ack.
            const bool cyc = myfuzz_ip::IpTarget<constant()>::wb_cyc(model);
            const bool stb = myfuzz_ip::IpTarget<constant()>::wb_stb(model);
            const bool ack = myfuzz_ip::IpTarget<constant()>::wb_ack(model);
            if (cyc && stb) ++observation.dma_route_wb_stb_pulses;
            if (cyc && ack) {
              const bool we = myfuzz_ip::IpTarget<constant()>::wb_we(model);
              const uint32_t adr = myfuzz_ip::IpTarget<constant()>::wb_adr(model);
              const uint32_t dat_w = myfuzz_ip::IpTarget<constant()>::wb_dat_w(model);
              const uint32_t dat_r = myfuzz_ip::IpTarget<constant()>::wb_dat_r(model);
              ++observation.dma_route_wb_acks;
              ++observation.dma_route_protocol_transfers;
              observation.dma_route_trace_write = we;
              observation.dma_route_trace_offset = adr * 4u;
              observation.target_ready = true;
              observation.ip_targets[constant()].ready = true;
              if (we) {
                ++observation.target_writes;
                ++observation.ip_targets[constant()].writes;
                ++observation.dma_route_target_writes;
                observation.dma_route_target_ready = 1;
                observation.dma_route_last_offset = adr * 4u;
                observation.dma_route_last_wdata = dat_w;
                observation.ip_targets[constant()].last_data = dat_w;
                observation.target_wdata = dat_w;
              } else {
                ++observation.target_reads;
                ++observation.ip_targets[constant()].reads;
                ++observation.dma_route_target_reads;
                observation.dma_route_target_ready = 1;
                observation.dma_route_last_offset = adr * 4u;
                observation.dma_route_last_rodata = dat_r;
                observation.ip_targets[constant()].last_data = dat_r;
                observation.ip_targets[constant()].last_read_offset = adr * 4u;
                observation.ip_targets[constant()].last_read_data = dat_r;
                observation.target_rdata = dat_r;
                observation.target_read_offset = adr * 4u;
                observation.target_read_data = dat_r;
              }
              EVENT_STREAM << "dma_route_wb " << tick << ' '
                           << (we ? "write" : "read") << " adr "
                           << hex32(adr) << " off " << hex32(adr * 4u)
                           << " dat_w " << hex32(dat_w) << " dat_r "
                           << hex32(dat_r) << '\n';
            }
          } else if constexpr (myfuzz_ip::IpTarget<constant()>::tlul) {
            // TL-UL: the request is one A handshake, the response one D
            // handshake.  The A payload is only valid on the request channel, so
            // it is kept when it handshakes and reported with the D completion.
            const bool a_valid = myfuzz_ip::IpTarget<constant()>::tlul_a_valid(model);
            const bool a_ready = myfuzz_ip::IpTarget<constant()>::tlul_a_ready(model);
            if (a_valid && a_ready) {
              ++observation.dma_route_tlul_a_handshakes;
              observation.dma_route_trace_offset =
                  myfuzz_ip::IpTarget<constant()>::tlul_a_address(model);
              // Opcode 4 is Get; every other admitted opcode is a write.
              observation.dma_route_trace_write =
                  myfuzz_ip::IpTarget<constant()>::tlul_a_opcode(model) != 4u;
            }
            const bool d_valid = myfuzz_ip::IpTarget<constant()>::tlul_d_valid(model);
            const bool d_ready = myfuzz_ip::IpTarget<constant()>::tlul_d_ready(model);
            if (d_valid && d_ready) {
              const uint32_t d_data = myfuzz_ip::IpTarget<constant()>::tlul_d_data(model);
              const bool d_error = myfuzz_ip::IpTarget<constant()>::tlul_d_error(model);
              ++observation.dma_route_tlul_d_handshakes;
              ++observation.dma_route_protocol_transfers;
              observation.target_ready = true;
              observation.ip_targets[constant()].ready = true;
              if (d_error) ++observation.target_errors;
              if (observation.dma_route_trace_write) {
                ++observation.target_writes;
                ++observation.ip_targets[constant()].writes;
                ++observation.dma_route_target_writes;
                observation.dma_route_target_ready = 1;
                observation.dma_route_last_offset = observation.dma_route_trace_offset;
                observation.ip_targets[constant()].last_data =
                    observation.dma_route_last_wdata;
                observation.target_wdata = observation.dma_route_last_wdata;
              } else {
                ++observation.target_reads;
                ++observation.ip_targets[constant()].reads;
                ++observation.dma_route_target_reads;
                observation.dma_route_target_ready = 1;
                observation.dma_route_last_offset = observation.dma_route_trace_offset;
                observation.dma_route_last_rodata = d_data;
                observation.ip_targets[constant()].last_data = d_data;
                observation.ip_targets[constant()].last_read_offset =
                    observation.dma_route_trace_offset;
                observation.ip_targets[constant()].last_read_data = d_data;
                observation.target_rdata = d_data;
                observation.target_read_offset = observation.dma_route_trace_offset;
                observation.target_read_data = d_data;
              }
              EVENT_STREAM << "dma_route_tlul " << tick << ' '
                           << (observation.dma_route_trace_write ? "write" : "read")
                           << " off " << hex32(observation.dma_route_trace_offset)
                           << " d_data " << hex32(d_data)
                           << " err " << int(d_error) << '\n';
            }
          } else if constexpr (myfuzz_ip::IpTarget<constant()>::axi4lite) {
            // AXI4-Lite: AW and W each handshake, B completes the write; AR
            // handshakes and R completes the read.  The address is only valid on
            // AW/AR, so it is kept when that channel handshakes.
            const bool aw = myfuzz_ip::IpTarget<constant()>::axi_awvalid(model)
                && myfuzz_ip::IpTarget<constant()>::axi_awready(model);
            const bool w = myfuzz_ip::IpTarget<constant()>::axi_wvalid(model)
                && myfuzz_ip::IpTarget<constant()>::axi_wready(model);
            if (aw) {
              ++observation.dma_route_axi_aw;
              observation.dma_route_trace_write = true;
              observation.dma_route_trace_offset =
                  myfuzz_ip::IpTarget<constant()>::axi_awaddr(model);
            }
            if (w) {
              ++observation.dma_route_axi_w;
              observation.dma_route_last_wdata =
                  myfuzz_ip::IpTarget<constant()>::axi_wdata(model);
            }
            const bool ar = myfuzz_ip::IpTarget<constant()>::axi_arvalid(model)
                && myfuzz_ip::IpTarget<constant()>::axi_arready(model);
            if (ar) {
              ++observation.dma_route_axi_ar;
              observation.dma_route_trace_write = false;
              observation.dma_route_trace_offset =
                  myfuzz_ip::IpTarget<constant()>::axi_araddr(model);
            }
            const bool b = myfuzz_ip::IpTarget<constant()>::axi_bvalid(model)
                && myfuzz_ip::IpTarget<constant()>::axi_bready(model);
            if (b) {
              ++observation.dma_route_axi_b;
              ++observation.dma_route_protocol_transfers;
              observation.target_ready = true;
              observation.ip_targets[constant()].ready = true;
              ++observation.target_writes;
              ++observation.ip_targets[constant()].writes;
              ++observation.dma_route_target_writes;
              observation.dma_route_target_ready = 1;
              observation.dma_route_last_offset = observation.dma_route_trace_offset;
              observation.ip_targets[constant()].last_data =
                  observation.dma_route_last_wdata;
              observation.target_wdata = observation.dma_route_last_wdata;
              EVENT_STREAM << "dma_route_axi write off "
                           << hex32(observation.dma_route_trace_offset)
                           << " dat_w " << hex32(observation.dma_route_last_wdata)
                           << " bresp "
                           << unsigned(myfuzz_ip::IpTarget<constant()>::axi_bresp(model))
                           << '\n';
            }
            const bool r = myfuzz_ip::IpTarget<constant()>::axi_rvalid(model)
                && myfuzz_ip::IpTarget<constant()>::axi_rready(model);
            if (r) {
              const uint32_t rdata =
                  myfuzz_ip::IpTarget<constant()>::axi_rdata(model);
              ++observation.dma_route_axi_r;
              ++observation.dma_route_protocol_transfers;
              observation.target_ready = true;
              observation.ip_targets[constant()].ready = true;
              ++observation.target_reads;
              ++observation.ip_targets[constant()].reads;
              ++observation.dma_route_target_reads;
              observation.dma_route_target_ready = 1;
              observation.dma_route_last_offset = observation.dma_route_trace_offset;
              observation.dma_route_last_rodata = rdata;
              observation.ip_targets[constant()].last_data = rdata;
              observation.ip_targets[constant()].last_read_offset =
                  observation.dma_route_trace_offset;
              observation.ip_targets[constant()].last_read_data = rdata;
              observation.target_rdata = rdata;
              observation.target_read_offset = observation.dma_route_trace_offset;
              observation.target_read_data = rdata;
              EVENT_STREAM << "dma_route_axi read off "
                           << hex32(observation.dma_route_trace_offset)
                           << " rdata " << hex32(rdata) << " rresp "
                           << unsigned(myfuzz_ip::IpTarget<constant()>::axi_rresp(model))
                           << '\n';
            }
          }
        }
#endif
#endif
      });
#if CPU_BUS_WISHBONE
      // The single Wishbone master: one request stream, its fetch/data identity
      // taken from the CPU's own mem_instr output.
      const bool request = cpu.CPU_WB_CYC && cpu.CPU_WB_STB;
      const bool fetch_beat = cpu.CPU_WB_INSTR;
      const bool req_write = cpu.CPU_WB_WE;
      const uint64_t req_wide = cpu.CPU_WB_ADR;
      const uint32_t req_addr = uint32_t(req_wide);
      const uint32_t req_wdata = cpu.CPU_WB_DAT_W;
      const unsigned req_sel = cpu.CPU_WB_SEL;
      // A response that was pending at the start of this tick is acknowledged
      // now; the CPU drops cyc/stb after sampling it, so one beat is one case of
      // the two conditions below.
      const bool wb_acked = request && dat.valid;
#elif CPU_BUS_AXI4
      // The AXI4 beat service above already consumed or started the adapter
      // beat; the target model's own APB transaction is the common completion
      // path below.
#elif CPU_BUS_AHB
      // The address phase this edge accepts, sampled pre-edge from the CPU's own
      // manager-domain pins: manager_ready is the aggregate HREADY (not the
      // target's HREADYEXT), bus_reset_n is the synchronized HRESETn, and
      // HPROT[0] says instruction or data.  The classifier must be advanced
      // before the backend beat of this edge is classified.
      const bool ahb_hsel = cpu.CPU_AHB_TRACE_HSEL;
      const unsigned ahb_htrans = unsigned(cpu.CPU_AHB_TRACE_HTRANS);
      const unsigned ahb_hprot = unsigned(cpu.CPU_AHB_TRACE_HPROT);
      const uint64_t ahb_haddr = uint64_t(cpu.CPU_AHB_TRACE_HADDR);
      const bool ahb_hwrite = cpu.CPU_AHB_TRACE_HWRITE;
      const bool ahb_manager_ready = cpu.AHB_MANAGER_READY;
      const bool ahb_bus_reset_n = cpu.AHB_BUS_RESET_N;
      identity.edge(ahb_bus_reset_n, ahb_manager_ready, ahb_hsel, ahb_htrans,
                    ahb_haddr, ahb_hwrite, ahb_hprot);
      // One backend beat at a time: the adapter's request is a promise that the
      // whole request (address, and for a write the data phase) is valid.
      const bool ahb_request = cpu.CPU_M_REQ_VALID && !beat.active;
      const bool ahb_write = cpu.CPU_M_REQ_WRITE;
      const uint64_t ahb_wide = cpu.CPU_M_REQ_ADDR;
      const uint32_t ahb_addr = uint32_t(ahb_wide);
      const uint32_t ahb_wdata = cpu.CPU_M_REQ_WDATA;
      const unsigned ahb_be = unsigned(cpu.CPU_M_REQ_BE);
      // The response this host is presenting on this edge, and the answer the
      // adapter just consumed (rsp_ready is high only in its COMPLETE state).
      const bool ahb_response_taken = beat.active && beat.have_value && cpu.CPU_M_RSP_READY;
#elif CPU_BUS_AXI4
      // The AXI4 beat service above already consumed or started the adapter
      // beat; the target model's own APB transaction is the common completion
      // path below.
#else
      const bool itake = cpu.CPU_I_REQ_VALID && cpu.CPU_I_REQ_READY;
      const bool dtake = cpu.CPU_D_REQ_VALID && cpu.CPU_D_REQ_READY;
      const bool iconsume = cpu.CPU_I_RSP_VALID && cpu.CPU_I_RSP_READY;
      const bool dconsume = cpu.CPU_D_RSP_VALID && cpu.CPU_D_RSP_READY;
      const uint32_t ia = cpu.CPU_I_REQ_ADDR;
      const uint32_t da = cpu.CPU_D_REQ_ADDR, dv = cpu.CPU_D_REQ_WDATA;
      const unsigned dbe = cpu.CPU_D_REQ_BE;
      const bool dw = cpu.CPU_D_REQ_WRITE;
#endif
#if HAVE_DMA
      // The DMA's own bus is sampled on the same terms as a target's: the accept
      // is a pre-edge fact of the tick whose rising boundary latches it, and the
      // ack is read on the tick after a rising boundary registered it.  A ratio-1
      // DMA satisfies both every tick, so its historical handshake is unchanged.
      const bool control_accept = dma_trace_now && control.busy && !control.accepted
          && !dma.swb_stall;
      const bool control_ack = dma_trace_now && control.busy && dma.swb_ack;
      const uint32_t control_data = dma.swb_dat_r;
      if (control_ack && !control.accepted)
        throw std::runtime_error("DMA control ACK before acceptance");
      const bool master_accept = dma_trace_now && dma.mwb_cyc && dma.mwb_stb
          && !dma.mwb_stall;
      const bool master_ack = dma_trace_now && dma.mwb_cyc && dma.mwb_ack;
      const bool master_write = dma.mwb_we;
      const uint64_t master_wide_address = uint64_t(dma.mwb_adr) << DMA_MASTER_SHIFT;
      if (master_accept && master_wide_address > UINT32_MAX)
        throw std::runtime_error("DMA master address out of range");
      const uint32_t master_address = uint32_t(master_wide_address);
      const uint32_t master_value = dma.mwb_dat_w;
      const unsigned master_select =
#if DMA_MASTER_SEL
        dma.mwb_sel;
#else
        15;
#endif
      // With one response outstanding the master has to hold its cycle until the
      // ack.  A pipelined master may legitimately end its request burst and drop cyc
      // while earlier acks are still owed, so the invariant is stated for the depth
      // at which it holds instead of being imposed on a declared pipeline.
      if (kDmaOutstanding == 1 && master_pending() && !dma.mwb_cyc)
        throw std::runtime_error("DMA dropped a pending master cycle");
#endif
#if HAVE_CPU_TAKE
      if (cpu.CPU_IRQ_TAKE) {
        if (!irq_delivered)
          throw std::runtime_error("CPU took an interrupt no delivered source asserted");
        ++observation.irq_takes;
        EVENT_STREAM << "irq_take " << tick << '\n';
#if HAVE_IRQ_LINKS && IRQ_TARGET_LINK_COUNT > 0
        // A declared level link the handler did not deassert re-enters the
        // handler on every MRET, so the case would never reach its own end.  At
        // the take limit the storm is a recorded case failure, not a batch
        // abort: the flag makes F5/F6 fail, the link is sampled as still high,
        // and only the devices are reset so the level falls.  The check is not
        // flow-gated: a storm that begins during another flow is still stopped
        // and reported, and the Python classifier names that interference.  The
        // CPU keeps its state and finishes the handler it is in; the case still
        // ends on the handler's own mailbox store, which is the point where the
        // CPU is back in its poll loop and the next input can be installed.
        if (observation.irq_takes > IRQ_TAKE_LIMIT && !level_stuck_recovered) {
          bool level_high = false;
          for (std::size_t index = 0; index < irq_links.size(); ++index)
            if (index < unsigned(IRQ_TARGET_LINK_COUNT) && kIrqLinkLevel[index]
                && irq_links[index].last)
              level_high = true;
          if (level_high) {
            observation.level_stuck = true;
            level_stuck_recovered = true;
            storm_waiting_mailbox = true;
            frame_done = true;
            EVENT_STREAM << "level_stuck_abort " << tick << '\n';
            // Reported, not masked: device_resets counts this reset and the case
            // line still states the level and the take count that caused it.
            recover_devices();
          }
        }
#endif
      }
#endif
#if CPU_CUSTOM_IRQ
      // Pico's EOI vector is a real CPU output; it shows that this bit was
      // accepted, even if its input pulse has ended before the CPU responds.
      const bool custom_eoi = (uint32_t(cpu.CPU_IRQ_EOI) >> CPU_CUSTOM_IRQ_BIT) & 1u;
      if (custom_eoi && !custom_eoi_previous) {
        ++observation.irq_takes;
        EVENT_STREAM << "irq_take " << tick << '\n';
      }
      custom_eoi_previous = custom_eoi;
#endif
#if TARGET_HAS_AXI4LITE
      // One AXI4-Lite transaction, sampled pre-edge from the routed target's own
      // passive taps.  A handshake is valid and ready in the same sample, so a
      // channel that is only half-present is not a transfer.  The five channels
      // are counted apart and joined at the beat response below, where the
      // declaration's own shape (one outstanding single beat) makes the join
      // checkable: a write needs AW, W and B exactly once, a read AR and R.
      // A mixed build reaches this block for every target but only an AXI4-Lite
      // one has those taps; the APB3 targets are skipped at compile time.
      for_each_ip(ip_models, [&](auto constant, auto &model) {
        const unsigned index = constant();
        if constexpr (!myfuzz_ip::IpTarget<index>::axi4lite) {
          (void)model;
          return;
        } else {
        // One sample per target cycle: this tick contains the rising boundary
        // that latches the handshake the low phase is showing.
        if (!ip_trace_now[index]) return;
        if (!mmio.busy || unsigned(mmio.target) != index) return;
        const bool aw_hs = myfuzz_ip::IpTarget<index>::axi_awvalid(model)
            && myfuzz_ip::IpTarget<index>::axi_awready(model);
        const bool w_hs = myfuzz_ip::IpTarget<index>::axi_wvalid(model)
            && myfuzz_ip::IpTarget<index>::axi_wready(model);
        const bool b_hs = myfuzz_ip::IpTarget<index>::axi_bvalid(model)
            && myfuzz_ip::IpTarget<index>::axi_bready(model);
        const bool ar_hs = myfuzz_ip::IpTarget<index>::axi_arvalid(model)
            && myfuzz_ip::IpTarget<index>::axi_arready(model);
        const bool r_hs = myfuzz_ip::IpTarget<index>::axi_rvalid(model)
            && myfuzz_ip::IpTarget<index>::axi_rready(model);
        if (aw_hs) {
          ++observation.axi_aw;
          observation.target_offset = myfuzz_ip::IpTarget<index>::axi_awaddr(model);
          EVENT_STREAM << "axi aw " << tick << ' '
                       << hex32(observation.target_offset)
                       << " prot " << myfuzz_ip::IpTarget<index>::axi_awprot(model) << '\n';
        }
        if (w_hs) {
          ++observation.axi_w;
          observation.target_wdata = myfuzz_ip::IpTarget<index>::axi_wdata(model);
          observation.target_wstrb = myfuzz_ip::IpTarget<index>::axi_wstrb(model);
          EVENT_STREAM << "axi w " << tick << ' ' << hex32(observation.target_wdata)
                       << " strb " << observation.target_wstrb << '\n';
        }
        if (b_hs) {
          ++observation.axi_b;
          observation.target_resp = myfuzz_ip::IpTarget<index>::axi_bresp(model);
          EVENT_STREAM << "axi b " << tick << " resp " << observation.target_resp << '\n';
        }
        if (ar_hs) {
          ++observation.axi_ar;
          observation.target_offset = myfuzz_ip::IpTarget<index>::axi_araddr(model);
          EVENT_STREAM << "axi ar " << tick << ' ' << hex32(observation.target_offset)
                       << " prot " << myfuzz_ip::IpTarget<index>::axi_arprot(model) << '\n';
        }
        if (r_hs) {
          ++observation.axi_r;
          observation.target_rdata = myfuzz_ip::IpTarget<index>::axi_rdata(model);
          observation.target_resp = myfuzz_ip::IpTarget<index>::axi_rresp(model);
          EVENT_STREAM << "axi r " << tick << ' ' << hex32(observation.target_rdata)
                       << " resp " << observation.target_resp << '\n';
        }
        }
      });
#endif  // TARGET_PROTOCOL_AXI4LITE || TARGET_PROTOCOLS_MIXED
#if !TARGET_PROTOCOL_AXI4LITE || TARGET_PROTOCOLS_MIXED
      // The routed target's own APB3 taps.  A non-routed target receives no
      // request, so its trace is not a transfer of this case.  A routed DMA write
      // is counted from this trace too: the target's psel/penable/pready sample is
      // the transfer, and the APB3 bridge's response below is what releases the
      // held master beat.  A mixed build reaches this block for every target but
      // only an APB3 one has those taps.
      for_each_ip(ip_models, [&](auto constant, auto &model) {
        const unsigned index = constant();
        if constexpr (!myfuzz_ip::IpTarget<index>::apb) {
          (void)model;
          return;
        } else {
        // One sample per target cycle: this tick contains the rising boundary
        // that latches the APB access the low phase is showing.
        if (!ip_trace_now[index]) return;
#if HAVE_DMA && DMA_ROUTE_ENABLED
        const bool route_transfer = route.waiting && route.sent
            && unsigned(index) == kDmaRouteTargetIndex;
#else
        const bool route_transfer = false;
#endif
        const bool mmio_transfer = mmio.busy && unsigned(mmio.target) == index;
        if (!mmio_transfer && !route_transfer) return;
        if (!(myfuzz_ip::IpTarget<index>::apb_sel(model)
              && myfuzz_ip::IpTarget<index>::apb_enable(model)
              && myfuzz_ip::IpTarget<index>::apb_ready(model))) return;
        // A completed APB3 transfer: psel, penable and pready in one sample.
        observation.target_ready = true;
        observation.ip_targets[index].ready = true;
        const uint32_t offset = myfuzz_ip::IpTarget<index>::apb_addr(model);
        const uint32_t wdata = myfuzz_ip::IpTarget<index>::apb_wdata(model);
        const uint32_t rdata = myfuzz_ip::IpTarget<index>::apb_rdata(model);
        observation.target_offset = offset;
        observation.ip_targets[index].last_offset = offset;
        if (myfuzz_ip::IpTarget<index>::apb_write(model)) {
#if HAVE_DMA && DMA_ROUTE_ENABLED
          if (route_transfer && !mmio_transfer) {
            // A routed DMA push: a real target write, counted under the target's
            // own counters.  It is not an F5 trigger or clear write, so those
            // counters are deliberately not touched.
            ++observation.target_writes;
            ++observation.ip_targets[index].writes;
            ++observation.dma_route_target_writes;
            observation.dma_route_target_ready = 1;
            observation.dma_route_last_offset = offset;
            observation.dma_route_last_wdata = wdata;
            observation.ip_targets[index].last_data = wdata;
            observation.target_wdata = wdata;
            EVENT_STREAM << "dma_route_apb " << tick << ' ' << hex32(offset) << ' '
                         << hex32(wdata) << '\n';
          } else
#endif
          {
            note_target_write(observation, record, index, offset, wdata);
            observation.ip_targets[index].last_data = wdata;
            observation.target_wdata = wdata;
          }
        } else {
          ++observation.target_reads;
          ++observation.ip_targets[index].reads;
          observation.ip_targets[index].last_data = rdata;
          observation.ip_targets[index].last_read_offset = offset;
          observation.ip_targets[index].last_read_data = rdata;
          observation.target_rdata = rdata;
          observation.target_read_offset = offset;
          observation.target_read_data = rdata;
#if HAVE_DMA && DMA_ROUTE_ENABLED && DMA_ROUTE_READ
          if (route_transfer && !mmio_transfer) {
            // A routed DMA read: the target's own completed APB3 read, counted
            // under the target's counters.  Its PRDATA is kept so the host can
            // check that the bridge returned the same word the trace sampled.
            ++observation.dma_route_target_reads;
            observation.dma_route_target_ready = 1;
            observation.dma_route_last_rodata = rdata;
            EVENT_STREAM << "dma_route_apb_read " << tick << ' ' << hex32(offset)
                         << ' ' << hex32(rdata) << '\n';
          }
#endif
        }
        EVENT_STREAM << "apb " << tick << ' '
                     << (myfuzz_ip::IpTarget<index>::apb_write(model) ? "write" : "read")
                     << ' ' << hex32(offset) << ' ' << hex32(wdata)
                     << ' ' << hex32(rdata) << '\n';
#if HAVE_EVENT_LAYER && HAVE_APB_PSLVERR
        // The target's own error response, on the transfer it belongs to.  The
        // APB trace carries the target offset, not a CPU address, so the offset
        // is what the event records.  A mixed build only reaches this for a
        // target whose own profile exposes pslverr.
        if constexpr (myfuzz_ip::IpTarget<index>::apb_error_sampled) {
          if (myfuzz_ip::IpTarget<index>::apb_error(model)) {
            ++observation.target_errors;
            EVENT_STREAM << "bus_error " << tick << " apb " << hex32(offset) << '\n';
          }
        }
#endif
        }
      });
#endif  // !TARGET_PROTOCOL_AXI4LITE || TARGET_PROTOCOLS_MIXED
#if TARGET_HAS_WISHBONE
      // The routed target's own Wishbone classic handshake, sampled pre-edge from
      // its passive taps.  A transfer is one cycle in which the master holds cyc
      // and stb and the slave answers with ack in the same sample - the classic
      // single-cycle handshake the admitted registered-ack template states.  The
      // slave's own address port carries a word address (the variant is
      // word-addressed), so the byte offset it means is that value times four;
      // the value the host prints is the one the slave really decoded, not the
      // request the host drove.
      for_each_ip(ip_models, [&](auto constant, auto &model) {
        const unsigned index = constant();
        if constexpr (!myfuzz_ip::IpTarget<index>::wishbone) {
          (void)model;
          return;
        } else {
        if (!ip_trace_now[index]) return;
        if (!mmio.busy || unsigned(mmio.target) != index) return;
        const bool cyc = myfuzz_ip::IpTarget<index>::wb_cyc(model);
        const bool stb = myfuzz_ip::IpTarget<index>::wb_stb(model);
        const bool ack = myfuzz_ip::IpTarget<index>::wb_ack(model);
        if constexpr (myfuzz_ip::IpTarget<index>::wb_stall_sampled) {
          if (myfuzz_ip::IpTarget<index>::wb_stall(model)) ++observation.wb_stalls;
        }
        // The request phase of the admitted registered-ack variants is a
        // one-cycle STB pulse with CYC held through the answer, so the pulse is
        // counted where it really is (cyc and stb in one sample) and the
        // completion where the target really answers (cyc held with ack).  A
        // classic held-STB target would show several pulse samples; the two
        // variants this builder admits state exactly one.
        if (cyc && stb) ++observation.wb_stb_pulses;
        if (!(cyc && ack)) return;
        // One completed cycle: the address/data phase rides on the held cycle,
        // not on the pulse, so the pins are recorded from the sample that holds
        // CYC and sees ACK.  STB is stated as it really is at that sample.
        observation.wb_cyc = cyc;
        observation.wb_stb = stb;
        observation.wb_ack = ack;
        ++observation.wb_acks;
        observation.wb_we = myfuzz_ip::IpTarget<index>::wb_we(model);
        observation.wb_adr = myfuzz_ip::IpTarget<index>::wb_adr(model);
        observation.wb_dat_w = myfuzz_ip::IpTarget<index>::wb_dat_w(model);
        observation.wb_dat_r = myfuzz_ip::IpTarget<index>::wb_dat_r(model);
        observation.wb_sel = myfuzz_ip::IpTarget<index>::wb_sel(model);
        const uint32_t offset = observation.wb_adr * 4u;
        observation.target_ready = true;
        observation.ip_targets[index].ready = true;
        observation.target_offset = offset;
        observation.ip_targets[index].last_offset = offset;
        if (observation.wb_we) {
          note_target_write(observation, record, index, offset,
                            observation.wb_dat_w);
          observation.ip_targets[index].last_data = observation.wb_dat_w;
          observation.target_wdata = observation.wb_dat_w;
        } else {
          ++observation.target_reads;
          ++observation.ip_targets[index].reads;
          observation.ip_targets[index].last_data = observation.wb_dat_r;
          observation.ip_targets[index].last_read_offset = offset;
          observation.ip_targets[index].last_read_data = observation.wb_dat_r;
          observation.target_rdata = observation.wb_dat_r;
          observation.target_read_offset = offset;
          observation.target_read_data = observation.wb_dat_r;
        }
        EVENT_STREAM << "wb " << tick << ' '
                     << (observation.wb_we ? "write" : "read")
                     << " adr " << hex32(observation.wb_adr)
                     << " off " << hex32(offset)
                     << " dat_w " << hex32(observation.wb_dat_w)
                     << " dat_r " << hex32(observation.wb_dat_r)
                     << " sel " << observation.wb_sel << '\n';
        }
      });
#endif  // TARGET_HAS_WISHBONE
#if TARGET_HAS_TLUL
      // The routed target's own TL-UL channels, sampled pre-edge.  The request is
      // one A-channel handshake (a_valid and a_ready in the same sample); the
      // response is one D-channel handshake (d_valid and d_ready).  The payload
      // the case reports is the accepted A channel's address/data/mask and the
      // completed D channel's data/error - the values the target's own pins
      // carried, captured while the channel was valid.
      for_each_ip(ip_models, [&](auto constant, auto &model) {
        const unsigned index = constant();
        if constexpr (!myfuzz_ip::IpTarget<index>::tlul) {
          (void)model;
          return;
        } else {
        if (!ip_trace_now[index]) return;
        if (!mmio.busy || unsigned(mmio.target) != index) return;
        const bool a_valid = myfuzz_ip::IpTarget<index>::tlul_a_valid(model);
        const bool a_ready = myfuzz_ip::IpTarget<index>::tlul_a_ready(model);
        const bool a_hs = a_valid && a_ready;
        if (a_hs) ++observation.tlul_a_handshakes;
        if (a_valid || a_hs) {
          // The A channel's payload is meaningful while the channel is valid; the
          // last sample before acceptance is the request the target took.
          observation.tlul_a_valid = a_valid;
          observation.tlul_a_ready = a_ready;
          observation.tlul_a_opcode = myfuzz_ip::IpTarget<index>::tlul_a_opcode(model);
          observation.tlul_a_address = myfuzz_ip::IpTarget<index>::tlul_a_address(model);
          observation.tlul_a_mask = myfuzz_ip::IpTarget<index>::tlul_a_mask(model);
          observation.tlul_a_data = myfuzz_ip::IpTarget<index>::tlul_a_data(model);
        }
        const bool d_valid = myfuzz_ip::IpTarget<index>::tlul_d_valid(model);
        const bool d_ready = myfuzz_ip::IpTarget<index>::tlul_d_ready(model);
        if (!d_valid) return;
        // The D channel's sample is the response the target drove; the last one
        // before completion is the handshake the case states.
        observation.tlul_d_valid = d_valid;
        observation.tlul_d_ready = d_ready;
        observation.tlul_d_data = myfuzz_ip::IpTarget<index>::tlul_d_data(model);
        observation.tlul_d_error = myfuzz_ip::IpTarget<index>::tlul_d_error(model);
        if (!(d_valid && d_ready)) return;
        // One completed response: this is the case's target transfer.
        ++observation.tlul_d_handshakes;
        const uint32_t offset = observation.tlul_a_address;
        const bool write = observation.tlul_a_opcode != 4u;  // Get is 4.
        observation.target_ready = true;
        observation.ip_targets[index].ready = true;
        observation.target_offset = offset;
        observation.ip_targets[index].last_offset = offset;
        if (write) {
          note_target_write(observation, record, index, offset,
                            observation.tlul_a_data);
          observation.ip_targets[index].last_data = observation.tlul_a_data;
          observation.target_wdata = observation.tlul_a_data;
        } else {
          ++observation.target_reads;
          ++observation.ip_targets[index].reads;
          observation.ip_targets[index].last_data = observation.tlul_d_data;
          observation.ip_targets[index].last_read_offset = offset;
          observation.ip_targets[index].last_read_data = observation.tlul_d_data;
          observation.target_rdata = observation.tlul_d_data;
          observation.target_read_offset = offset;
          observation.target_read_data = observation.tlul_d_data;
        }
        if (observation.tlul_d_error) {
          ++observation.tlul_errors;
          ++observation.target_errors;
#if HAVE_EVENT_LAYER
          EVENT_STREAM << "bus_error " << tick << " tlul " << hex32(offset) << '\n';
#endif
        }
        EVENT_STREAM << "tlul " << tick << ' ' << (write ? "write" : "read")
                     << " op " << observation.tlul_a_opcode
                     << " addr " << hex32(offset)
                     << " mask " << observation.tlul_a_mask
                     << " a_data " << hex32(observation.tlul_a_data)
                     << " d_data " << hex32(observation.tlul_d_data)
                     << " err " << int(observation.tlul_d_error) << '\n';
        }
      });
#endif  // TARGET_HAS_TLUL
#if TARGET_HAS_AHB
      // The routed AHB-Lite target's own slave port, sampled pre-edge in its two
      // phases.  An address phase is one sample in which the target's HSEL and a
      // non-idle HTRANS are on its pins and HREADYIN completes it; the data phase
      // is the next sample of the same transfer, where HREADYOUT completes it and
      // HRDATA/HRESP (read) or HWDATA (write) carry the payload.  Nothing here is
      // inferred from the host's own request: every field is the target's pin.
      for_each_ip(ip_models, [&](auto constant, auto &model) {
        const unsigned index = constant();
        if constexpr (!myfuzz_ip::IpTarget<index>::ahb) {
          (void)model;
          return;
        } else {
        if (!ip_trace_now[index]) return;
        if (!mmio.busy || unsigned(mmio.target) != index) return;
        const bool hsel = myfuzz_ip::IpTarget<index>::ahb_hsel(model);
        const unsigned htrans = myfuzz_ip::IpTarget<index>::ahb_htrans(model);
        const bool hreadyin = myfuzz_ip::IpTarget<index>::ahb_hreadyin(model);
        if (hsel && (htrans & 2u)) {
          // One address phase on the target's pins.  HREADYIN is that phase's
          // completion: with it low the same address phase is still pending in
          // the next sample, so only an accepted one is counted here.
          if (!hreadyin) return;
          ++observation.ahb_address_phases;
          observation.ahb_address_seen = true;
          observation.ahb_hsel = hsel;
          observation.ahb_htrans = htrans;
          observation.ahb_haddr = myfuzz_ip::IpTarget<index>::ahb_haddr(model);
          observation.ahb_hwrite = myfuzz_ip::IpTarget<index>::ahb_hwrite(model);
          observation.ahb_hsize = myfuzz_ip::IpTarget<index>::ahb_hsize(model);
          observation.ahb_hreadyin = hreadyin;
          EVENT_STREAM << "ahb address " << tick << ' '
                       << hex32(observation.ahb_haddr) << ' '
                       << (observation.ahb_hwrite ? "write" : "read")
                       << " size " << observation.ahb_hsize << '\n';
          return;
        }
        // The data phase belongs to the address phase this case just accepted.
        // Any other idle sample is not a transfer and is not counted.
        if (!observation.ahb_address_seen) return;
        observation.ahb_address_seen = false;
        const bool hreadyout = myfuzz_ip::IpTarget<index>::ahb_hreadyout(model);
        observation.ahb_hwdata = myfuzz_ip::IpTarget<index>::ahb_hwdata(model);
        observation.ahb_hreadyout = hreadyout;
        observation.ahb_hresp = myfuzz_ip::IpTarget<index>::ahb_hresp(model);
        if (!hreadyout) return;  // the target has not completed this phase yet
        // One completed AHB-Lite transfer: the data phase the target answered.
        ++observation.ahb_data_phases;
        const uint32_t offset = observation.ahb_haddr;
        observation.target_ready = true;
        observation.ip_targets[index].ready = true;
        observation.target_offset = offset;
        observation.ip_targets[index].last_offset = offset;
        if (observation.ahb_hwrite) {
          note_target_write(observation, record, index, offset,
                            observation.ahb_hwdata);
          observation.ip_targets[index].last_data = observation.ahb_hwdata;
          observation.target_wdata = observation.ahb_hwdata;
        } else {
          const uint32_t rdata = myfuzz_ip::IpTarget<index>::ahb_hrdata(model);
          observation.ahb_hrdata = rdata;
          ++observation.target_reads;
          ++observation.ip_targets[index].reads;
          observation.ip_targets[index].last_data = rdata;
          observation.ip_targets[index].last_read_offset = offset;
          observation.ip_targets[index].last_read_data = rdata;
          observation.target_rdata = rdata;
          observation.target_read_offset = offset;
          observation.target_read_data = rdata;
        }
        EVENT_STREAM << "ahb data " << tick << ' '
                     << (observation.ahb_hwrite ? "write" : "read")
                     << " off " << hex32(offset)
                     << " wdata " << hex32(observation.ahb_hwdata)
                     << " rdata " << hex32(observation.ahb_hrdata)
                     << " hresp " << int(observation.ahb_hresp) << '\n';
        }
      });
#endif  // TARGET_HAS_AHB
#if CPU_BUS_AXI4
      // The target/DMA models take the boundary that belongs to this phase; the
      // CPU/adapter edge is CpuLink's end_tick below.
      apply_phase_boundary(false);
      eval_ip();
#if HAVE_DMA
      dma.eval();
#endif
#else
      // The reference CPU's half period is kCpuHalfTicks grid steps, so its rise
      // is the last boundary of that many low steps.  A model declared faster
      // than the CPU toggles inside those low steps (that is the sub-stepping),
      // so its own boundaries are applied and evaluated here, before the CPU's
      // rise and before this tick's trace/retirement samples; for a ratio-1
      // reference clock the loop is empty and this is the historical single
      // boundary.
      for (unsigned s = 1; s < kCpuHalfTicks; ++s) {
        apply_phase_boundary(cpu_clock_drive()); eval_all();
        timed_advance_to(context.time() + TIMED_GRID_PS);
      }
      apply_phase_boundary(cpu_clock_drive()); eval_all();
      // The rising boundary is where each model whose half period is now takes
      // its high level.  A timed model's high phase is its own declared half
      // period and its scheduled events run inside it, so the retirement face
      // and the target/DMA samples below read a model whose real time has reached
      // the end of the high step of its own cycle.  The high half is likewise
      // kCpuHalfTicks steps: a faster model's edges inside it are applied before
      // the sample below, which is where this host reads registered outputs.
      for (unsigned s = 1; s < kCpuHalfTicks; ++s) {
        timed_advance_to(context.time() + TIMED_GRID_PS);
        apply_phase_boundary(cpu_clock_drive()); eval_all();
      }
      timed_advance_to(context.time() + TIMED_GRID_PS);
#endif

#if HAVE_PINS
      // The device's transition probes are registered comparator outputs, so a
      // transition becomes visible at a rising edge; they are sampled in the same
      // phase as the device's interrupt output below, which makes the transition
      // and the interrupt it causes comparable on one tick index.  The sample is
      // taken once per the device's own cycle (a probe that stays high for a slow
      // device's whole half period is one transition, not R of them).
      if (ip_probe_now[0]) {
        const uint32_t rise = myfuzz_ip::IpTarget<0>::probe_rise(ip) & kPadMask;
        const uint32_t fall = myfuzz_ip::IpTarget<0>::probe_fall(ip) & kPadMask;
        if (rise || fall) {
          EVENT_STREAM << "pin " << tick << " edge rise " << hex32(rise)
                    << " fall " << hex32(fall) << '\n';
          observation.rise_mask |= rise;
          observation.fall_mask |= fall;
          observation.transition_mask |= rise | fall;
          if (rise) ++observation.pad_rise_events;
          if (fall) ++observation.pad_fall_events;
#if HAVE_PIN_GROUPS
          // The device's own edge probes belong to whichever declared group held
          // the wire at this tick, so a rise is attributed instead of being added
          // to the case only.
          pin_schedule.note_change(pads.value, pads.value, rise, fall);
#endif
          if (rise && !observation.first_rise_tick) observation.first_rise_tick = tick;
          if (fall && !observation.first_fall_tick) observation.first_fall_tick = tick;
          if (!observation.first_transition_tick)
            observation.first_transition_tick = tick;
        }
      }
#endif
#if HAVE_DMA
      const bool master_post_stb = dma.mwb_stb;
#endif
#if !CPU_BUS_AHB && (!CPU_BUS_AXI4 || HAVE_RVFI_ADAPTER)
      // The CVW AHB wrapper exports no RVFI/commit channel, so that build has no
      // retirement observation at all: the block below compiles out and F1 is
      // refused by name instead of being inferred from a fetch.  A packed AXI4
      // build reaches this block only when its probe-bundle adapter is present
      // (HAVE_RVFI_ADAPTER): the CVA6 exports the 6974-bit RVFI probe bundle and
      // the pinned scoreboard cva6_rvfi.sv, Verilated beside this run, turns it
      // into the same one-record-per-clock RVFI face the OBI/Wishbone CPU models
      // expose.  `cpu_retirement` names whichever object carries that face.
      if (cpu_retirement.CPU_RVFI_VALID) {
        // CVA6 is an RV64 core: its RVFI pc_rdata / rd_wdata are 64 bits wide,
        // while this trace, its FNV-1a hash and the Python reference trace are
        // 32-bit.  The admitted F1 subset is RV32IM straight-line records inside
        // the 64 KiB image window, so the low 32 bits are the whole value for pc,
        // and the low 32 bits of the 64-bit RV64 writeback are the RV32 result the
        // reference model computes (RV64 sign-extends a 32-bit OP/OP-IMM result
        // into the upper half, which is outside this comparison).  The truncation
        // is therefore explicit, in one place, and the summary states the
        // projection it belongs to.
        const uint32_t pc = uint32_t(cpu_retirement.CPU_RVFI_PC_RDATA);
        const uint32_t insn = uint32_t(cpu_retirement.CPU_RVFI_INSN);
        // The trampoline program is the run of words the host installed, from
        // kSlot to its own return jump.  Retirements are attributed by address,
        // so a program word that never retires simply lowers the count; the
        // firmware's own retirements are not counted as program words.
        const uint32_t program_end = kSlot + 4 * record.words;
        const bool in_program = pc >= kSlot && pc < program_end;
        ++observation.retires;
#if HAVE_RVFI_INTR_PORT && !HAVE_CPU_TAKE && !CPU_CUSTOM_IRQ && !HAVE_RVFI_TRAP_WITNESS
        // A CPU with no take probe and no EOI still states the architectural
        // first-handler-retirement flag on its RVFI face.  It is counted as an
        // interrupt take only while this host really has an interrupt asserted
        // (``irq_delivered``), so a synchronous exception's handler entry - which
        // also sets rvfi_intr - is never mistaken for an interrupt take.  The
        // entry gates the flows that need a take witness on this port's presence;
        // this block makes the count a measurement from that real port.
        if (irq_delivered && cpu_retirement.CPU_RVFI_INTR) {
          ++observation.irq_takes;
          EVENT_STREAM << "irq_take " << tick << " rvfi_intr\n";
        }
#endif
        if (in_program) {
          const unsigned index = (pc - kSlot) / 4u;
          ++observation.prog_retires;
#if F1_TRACED
          // The distance from the previous retirement to this one is a fact of
          // the *previous* instruction: an insn whose bits [1:0] are not ``11``
          // was a 16-bit parcel (RVFI states it as {16'b0, parcel}) and advanced
          // the PC by 2, anything else was a whole 32-bit record word and
          // advanced it by 4.  A branch, jump or compressed control transfer may
          // legally jump forward; a bounded loop legally repeats PCs, and that
          // repeat is counted (prog_pc_repeat) instead of being called an
          // ordering fault.  The strict-rise flag stays honest either way.
          if (observation.prog_retires > 1 && pc <= observation.prog_last_pc)
            ++observation.prog_pc_repeat;
#if F1_ALLOW_LOOPS
          if (observation.prog_retires > 1 && pc <= observation.prog_last_pc)
            observation.prog_pc_ordered = false;
#elif F1_ALLOW_BRANCHES || F1_ALLOW_JUMPS || F1_ALLOW_COMPRESSED_CONTROL
          if (observation.prog_retires > 1 && pc <= observation.prog_last_pc)
            observation.prog_pc_ordered = false;
#else
          const uint32_t step =
              ((observation.prog_last_insn & 3u) != 3u) ? 2u : 4u;
          if (observation.prog_retires > 1
              && pc != observation.prog_last_pc + step)
            observation.prog_pc_ordered = false;
#endif
#else
          if (observation.prog_retires > 1 && pc != observation.prog_last_pc + 4)
            observation.prog_pc_ordered = false;
#endif
#if F1_ALLOW_COMPRESSED
          // A compressed retirement is compared with the 16-bit parcel of the
          // installed record word at its own half; a whole 32-bit instruction is
          // compared with the installed word, exactly as before.
          const bool compressed_word = (word_at(record, index) & 3u) != 3u;
          const uint32_t installed = compressed_word
              ? f1_parcels::parcel_at(word_at(record, index), (pc - kSlot) & 3u)
              : word_at(record, index);
#else
          const uint32_t installed = word_at(record, index);
#endif
          if (record.flow != kF1 || installed != insn)
            observation.prog_insns_match = false;
          observation.prog_last_pc = pc;
          observation.prog_last_insn = insn;
        }
#if HAVE_EVENT_LAYER && HAVE_RVFI_WRITEBACK
        // The retirement index and the register writeback the model already
        // produces.  The line is one per RVFI-valid retirement, the same
        // validity that admits the retire line below.
        const uint64_t order = uint64_t(cpu_retirement.CPU_RVFI_ORDER);
        const unsigned rd_addr = unsigned(cpu_retirement.CPU_RVFI_RD_ADDR);
        // The low 32 bits of the (RV64) writeback; see the projection note above.
        const uint32_t rd_wdata = uint32_t(cpu_retirement.CPU_RVFI_RD_WDATA);
        if (observation.retires > 1 && order <= observation.rvfi_order)
          observation.rvfi_order_monotonic = false;
        observation.rvfi_order = order;
        if (rd_addr) ++observation.rvfi_writebacks;
        if (in_program && rd_addr) {
          // The registers this program really wrote, and its last writeback:
          // sampled from the CPU's own RVFI channel, never derived from the
          // instruction words the host installed.
          observation.prog_rd_mask |= uint32_t(1) << rd_addr;
          observation.prog_last_rd = rd_addr;
          observation.prog_last_wdata = rd_wdata;
          // The full RV64 writeback and PC, for the 64-bit declaration below
          // and for the case line that prints them beside the projected pair.
          observation.prog_last_wdata64 =
              uint64_t(cpu_retirement.CPU_RVFI_RD_WDATA);
          observation.prog_last_pc64 = uint64_t(cpu_retirement.CPU_RVFI_PC_RDATA);
          ++observation.prog_writebacks;
        }
#if F1_TRACED
        if (in_program) {
          // The retirement trace itself: one FNV-1a update over the four fields
          // RVFI exposes.  A retirement that writes no register has rd_addr 0
          // and rd_wdata 0 (RVFI's own rule), which is exactly the projection
          // the Python reference trace is hashed with.  ``insn`` is the whole
          // installed record word for a 32-bit instruction and the 16-bit parcel
          // for a compressed one - the same value the Python reference trace
          // carries as ``insn_word`` - so the two hashes are comparable.  The
          // witness is the real retirement stream, never the installed words.
#if !F1_RV64
          observation.prog_trace_hash = f1_trace::entry(
              observation.prog_trace_hash, pc, insn, rd_addr, rd_wdata);
#else
          // A 64-bit declaration hashes the record's own 64-bit pc and writeback
          // with FNV-1a 64 over the same four fields (it never reuses the 32-bit
          // digest above).  ``insn`` stays the 32-bit instruction word and ``rd``
          // the 5-bit register index, each widened to the 8-byte field the
          // Python reference hashes.
          observation.prog_trace_hash64 = f1_trace64::entry(
              observation.prog_trace_hash64,
              uint64_t(cpu_retirement.CPU_RVFI_PC_RDATA), uint64_t(insn),
              uint64_t(rd_addr), uint64_t(cpu_retirement.CPU_RVFI_RD_WDATA));
#endif
          ++observation.prog_trace_count;
        }
#endif
        EVENT_STREAM << "rvfi " << tick << ' ' << order << ' ' << rd_addr << ' '
                     << hex32(rd_wdata) << '\n';
#endif
#if HAVE_EVENT_LAYER && HAVE_RVFI_EXPANDED
        // Expanded-instruction validity is a separate fact: it is counted, and a
        // zero count is reported as missing evidence, not as a passing check.
        if (cpu_retirement.CPU_RVFI_EXPANDED_VALID) ++observation.rvfi_expanded;
#endif
#if HAVE_EVENT_LAYER
#if HAVE_RVFI_TRAP_PORT
        if (cpu_retirement.CPU_RVFI_TRAP) {
          // A trap is an observed retirement event of this case, and the case -
          // not the whole run - is the thing that fails when it was not
          // declared.  A CPU whose RVFI face carries the witness states the
          // commit lane's own cause and privilege level; one that does not keeps
          // the honest "cause unknown".
#if HAVE_RVFI_TRAP_WITNESS
          const uint64_t cause = uint64_t(cpu_retirement.CPU_RVFI_CAUSE);
          const uint64_t intr = uint64_t(cpu_retirement.CPU_RVFI_INTR);
          const unsigned mode = unsigned(cpu_retirement.CPU_RVFI_MODE);
          if (observation.trap_count == 0) {
            observation.trap_pc = pc;
            observation.trap_insn = insn;
            observation.trap_cause = cause;
            observation.trap_intr = intr;
            observation.trap_mode = mode;
          }
          ++observation.trap_count;
          EVENT_STREAM << "trap " << tick << " pc " << hex32(pc) << " insn "
                       << hex32(insn) << " cause " << hex64(cause)
                       << " intr " << hex64(intr) << " mode " << mode << '\n';
#else
          EVENT_STREAM << "trap " << tick << " pc " << hex32(pc) << " insn "
                       << hex32(insn) << " cause unknown\n";
#endif
          ++observation.traps;
          if (in_program) ++observation.prog_traps;
        }
#else
        // This CPU model assigns no ``rvfi_trap`` output, so a trap is not an
        // observation this host can make.  Nothing is counted and nothing is
        // asserted; the case line prints ``traps unknown`` instead.
        (void)in_program;
#endif  // HAVE_RVFI_TRAP_PORT
#else
#if HAVE_RVFI_TRAP_PORT
        if (cpu_retirement.CPU_RVFI_TRAP) throw std::runtime_error("CPU retirement trap");
#else
        (void)in_program;
#endif  // HAVE_RVFI_TRAP_PORT
#endif  // HAVE_EVENT_LAYER
        EVENT_STREAM << "retire " << tick << ' ' << hex32(pc) << ' ' << hex32(insn) << '\n';
        if (pc == kSlot) {
          observation.slot_retire = true;
          observation.slot_retire_pc = pc;
          observation.slot_retire_insn = insn;
        } else if (observation.slot_retire && pc == program_end) {
          // The fixed return jump right after the program's last word: its
          // retirement is the successor that proves the trampoline was left.
          observation.slot_successor = true;
          observation.slot_successor_pc = pc;
        }
      }
#endif  // !CPU_BUS_AHB
#if HAVE_RVFI_TRAP_WITNESS
      // The scoreboard's registered CSR readback, sampled every tick (not only
      // on a retirement): after the trap is taken, mcause/mepc are the values
      // the core wrote and the firmware handler reads.  A change is printed as
      // its own event, so the CSR state is a measured fact and not inferred from
      // the record's cause.  ``rvfi_csr_samples`` counts the ticks this build
      // sampled the readback on; a zero count would mean no evidence at all.
      {
        const uint64_t mcause = uint64_t(cpu_retirement.CPU_RVFI_CSR_MCAUSE);
        const uint64_t mepc = uint64_t(cpu_retirement.CPU_RVFI_CSR_MEPC);
        ++observation.rvfi_csr_samples;
        observation.rvfi_mcause_final = mcause;
        observation.rvfi_mepc_final = mepc;
        // An interrupt the core really took, observed on its own `mcause` state:
        // bit 63 is the interrupt bit and the low bits are the cause.  The F5 ISR
        // clears mcause after the entry (a build-level fact, IRQ_TAKE_CLEAR), so
        // each take is its own 0 -> interrupt transition and a later case cannot
        // inherit this one's cause.  This is the only take witness the packed
        // AXI4 boundary offers: it exports no probe port, and a store from the
        // ISR is never accepted as a take.
        if ((mcause >> 63) != 0) {
          if (mcause != observation.rvfi_take_mcause_last) {
            ++observation.irq_takes;
            observation.rvfi_take_mcause_last = mcause;
            EVENT_STREAM << "irq_take " << tick << " mcause " << hex64(mcause)
                         << '\n';
#if !HAVE_CPU_TAKE && HAVE_IRQ_LINKS && IRQ_TARGET_LINK_COUNT > 0
            // The same level-storm stop the probe-port CPUs apply, for a build
            // whose takes are counted from the readback: a declared level link
            // the handler did not deassert re-enters forever, so at the take
            // limit the storm is a recorded case failure (level_stuck) and only
            // the devices are reset so the line falls.
            if (observation.irq_takes > IRQ_TAKE_LIMIT && !level_stuck_recovered) {
              bool level_high = false;
              for (std::size_t index = 0; index < irq_links.size(); ++index)
                if (index < unsigned(IRQ_TARGET_LINK_COUNT) && kIrqLinkLevel[index]
                    && irq_links[index].last)
                  level_high = true;
              if (level_high) {
                observation.level_stuck = true;
                level_stuck_recovered = true;
                storm_waiting_mailbox = true;
                frame_done = true;
                EVENT_STREAM << "level_stuck_abort " << tick << '\n';
                recover_devices();
              }
            }
#endif
          }
        } else {
          observation.rvfi_take_mcause_last = 0;
        }
        if (mcause != 0 && !observation.rvfi_csr_trap_seen) {
          // The trap entry: the core's own mcause/mepc, before the handler's
          // CSRRS write moves mepc.  This snapshot is the one the case compares.
          observation.rvfi_csr_trap_seen = true;
          observation.rvfi_mcause = mcause;
          observation.rvfi_mepc = mepc;
          observation.rvfi_mtval = uint64_t(cpu_retirement.CPU_RVFI_CSR_MTVAL);
          observation.rvfi_mtvec = uint64_t(cpu_retirement.CPU_RVFI_CSR_MTVEC);
          observation.rvfi_mstatus =
              uint64_t(cpu_retirement.CPU_RVFI_CSR_MSTATUS);
          EVENT_STREAM << "csr_trap " << tick << " mcause " << hex64(mcause)
                       << " mepc " << hex64(mepc)
                       << " mtval " << hex64(observation.rvfi_mtval)
                       << " mtvec " << hex64(observation.rvfi_mtvec)
                       << " mstatus " << hex64(observation.rvfi_mstatus) << '\n';
        } else if (observation.rvfi_csr_trap_seen
                   && mepc != observation.rvfi_mepc_last) {
          // A later change after the trap entry: the handler's own CSRRS write
          // to mepc (it advances past the ECALL).  Printed as its own fact, never
          // folded into the entry snapshot, and only when the value changed.
          EVENT_STREAM << "csr_mepc " << tick << " mcause " << hex64(mcause)
                       << " mepc " << hex64(mepc) << '\n';
        }
        observation.rvfi_mepc_last = mepc;
      }
#endif
#if HAVE_IP_IRQ
      if ((uint64_t(ip.IP_IRQ) >> IP_IRQ_BIT) & 1u) ++observation.ip_irq_high;
#endif
#if IP_COUNT > 1
      // Refresh each target's own interrupt level.  Every declaring target's
      // value feeds its own link lambdas; a target that exposes an output without
      // declaring a link is counted here and is never delivered to the CPU.
      for_each_ip(ip_models, [&](auto constant, auto &model) {
        if constexpr (myfuzz_ip::IpTarget<constant()>::has_irq) {
          g_ip_irq[constant()] = myfuzz_ip::IpTarget<constant()>::irq_value(model);
          if (g_ip_irq[constant()]) ++observation.target_irq_high[constant()];
        }
      });
#endif
#if HAVE_IRQ_LINKS
      // Sample the real device outputs once per tick and shape delivery exactly
      // as the declaration says (pulse width, or level passthrough).  The
      // device-high count and the delivered-high count are kept apart: the
      // host stretches a pulse, so the CPU input can be high longer than the
      // device output ever was.  Every link's contribution is OR'ed into the one
      // CPU input; the per-target delivered counter records which target's own
      // link held that contribution.
      irq_delivered = false;
      for (std::size_t index = 0; index < irq_links.size(); ++index) {
        IrqLink &link = irq_links[index];
        const unsigned raw = link.sample();
        if (raw) ++observation.irq_high;
        bool edge = false;
        bool contributed = false;
        if (link.pulse_ticks) {
          if (raw && !link.last) {
            link.remaining = link.pulse_ticks;
            ++link.edges;
            edge = true;
          } else if (link.remaining) {
            --link.remaining;
          }
          if (link.remaining) contributed = true;
        } else {
          if (raw && !link.last) {
            ++link.edges;
            edge = true;
          }
          if (raw) contributed = true;
        }
        if (contributed) {
          irq_delivered = true;
#if IRQ_TARGET_LINK_COUNT > 0
          if (index < unsigned(IRQ_TARGET_LINK_COUNT)
              && kIrqLinkTarget[index] < unsigned(IP_COUNT))
            ++observation.target_irq_delivered[kIrqLinkTarget[index]];
#endif
        }
        if (edge) {
          ++observation.irq_link_edges[index];
          EVENT_STREAM << "irq_edge " << index << ' ' << tick << '\n';
#if HAVE_PINS
          // The pins of the edge are the transition the device reported at this
          // tick and the enable mask it was gated with: the host records both so
          // a pin interrupt's cause is attributable, not assumed.
          if (index == 0 && !observation.first_irq_tick) {
            observation.first_irq_tick = tick;
            observation.irq_cause_pins = observation.rise_mask;
            observation.inten_at_irq = myfuzz_ip::IpTarget<0>::probe_inten(ip) & kPadMask;
          }
#endif
#if HAVE_EVENT_LAYER && HAVE_DMA
          // The DMA model exposes one functional port, o_interrupt: no busy and
          // no done output.  Completion is therefore derived, never sampled -
          // the completion IRQ edge that follows the last accepted master
          // write of this case - and the summary states that derivation.
          if (index == unsigned(IRQ_DMA_LINK_INDEX) && observation.dma_writes > 0
              && !observation.dma_done) {
            observation.dma_done = true;
            observation.dma_done_tick = tick;
            EVENT_STREAM << "dma_done " << tick << '\n';
          }
#endif
        }
        link.last = raw != 0;
      }
#if !CPU_CUSTOM_IRQ
      if (irq_delivered) ++observation.irq_delivered_high;
#endif
      observation.irq_edges = 0;
      for (const IrqLink &link : irq_links) observation.irq_edges += link.edges;
#endif
#if CPU_BUS_AXI4
      link.end_tick();
      ++cpu_rises;  // the link's one CPU rising edge for this tick
      apply_phase_boundary(false); eval_ip();
#if HAVE_DMA
      dma.eval();
#endif
#else
      apply_phase_boundary(cpu_clock_drive()); eval_all();
#endif
      // See the reset-time gate above: a timed model's pending event is its next
      // scheduled task, and the scheduler advances to it on the next phase.
      if (!kTimedModel && timed_events())
        throw std::runtime_error("unsupported timed model events");
#if CPU_BUS_WISHBONE
      // One acknowledged Wishbone beat: the response the CPU sampled at this
      // tick's edge is retired, and a request that was not answered yet is
      // decoded now.  The two are exclusive, so a beat is never answered twice.
      if (wb_acked) {
        dat.valid = false;
        if (ack_pending) { ack_pending = false; frame_done = true; }
      } else if (request && !mmio.busy
#if HAVE_DMA
                 && !control.busy
#endif
                 ) {
        if (req_wide > UINT32_MAX)
          throw std::runtime_error("Wishbone address out of range");
        if (in_ip(req_addr)) {
          // A partial store into the target window is still refused: the
          // declared APB3 target is word-addressed and no scenario declares a
          // byte-lane contract for it.  Only the RAM route below accepts the
          // CPU's byte enables.
          if (fetch_beat)
            throw std::runtime_error("instruction fetch inside the target window");
          if (req_write && req_sel != 15)
            throw std::runtime_error("partial Wishbone store is outside this spike");
          mmio.busy = true; mmio.sent = false; mmio.write = req_write;
          mmio.address = req_addr; mmio.value = req_wdata; mmio.be = req_sel;
          mmio.target = unsigned(ip_index_of(req_addr));
          observation.target_index = int(mmio.target);
          EVENT_STREAM << "cpu_mmio " << tick << ' ' << (req_write ? "write" : "read")
                    << ' ' << hex32(req_addr) << ' ' << hex32(req_wdata) << '\n';
#if HAVE_DMA
        } else if (in_dma(req_addr)) {
          if (fetch_beat) throw std::runtime_error("instruction fetch inside the DMA window");
          if (req_write && req_sel != 15) throw std::runtime_error("partial DMA control write is outside this spike");
          control.busy = true; control.accepted = false; control.write = req_write;
          control.offset = req_addr - kDmaBase; control.value = req_wdata;
          control.be = req_write ? req_sel : 15;
          EVENT_STREAM << "cpu_control " << tick << ' ' << (req_write ? "write" : "read")
                    << ' ' << hex32(req_addr) << ' ' << hex32(req_wdata) << '\n';
#endif
        } else if (in_ram(req_addr & ~3u)) {
          // The RAM word a subword access belongs to is the aligned word it
          // covers; the CPU's own byte enables carry which lanes it wrote, and
          // the address stays the CPU's real byte address in the evidence.
          const uint32_t ram_addr = req_addr & ~3u;
          if (req_write) {
            memory.write(ram_addr, req_wdata, req_sel);
            dat.value = 0;
            ++observation.d_writes;
            if (ram_addr == kCommand && req_sel == 15 && req_wdata == 0) ack_pending = true;
            if (ram_addr == kEcho && req_sel == 15) {
              observation.echo_stored = true;
              observation.echo_value = req_wdata;
            }
            if (ram_addr >= kDataBase) {
              observation.write_accepted = true;
              observation.write_address = req_addr;
              observation.write_value = req_wdata;
              observation.write_be = req_sel;
            }
          } else if (fetch_beat) {
            ++observation.i_fetches;
            if (ram_addr == kSlot) {
              observation.slot_fetch = true;
              observation.slot_fetch_address = ram_addr;
            }
#if HAVE_EVENT_LAYER
            EVENT_STREAM << "ifetch " << tick << ' ' << hex32(ram_addr) << ' '
                      << hex32(memory.read(ram_addr)) << '\n';
#endif
            dat.value = memory.read(ram_addr);
          } else {
            ++observation.d_reads;
            dat.value = memory.read(ram_addr);
            if (ram_addr >= kDataBase) {
              observation.read_accepted = true;
              observation.read_address = req_addr;
              observation.read_from_ip = false;
              observation.read_value = dat.value;
            }
          }
          dat.valid = true;
        } else {
          throw std::runtime_error("CPU bus access outside RAM and the declared target windows");
        }
        EVENT_STREAM << "wb " << tick << ' '
                  << (fetch_beat ? "fetch" : (req_write ? "write" : "read")) << ' '
                  << hex32(req_addr) << ' ' << hex32(req_wdata)
                  << std::dec << " sel " << req_sel << '\n';
      }
#elif CPU_BUS_AHB
      // One AHB beat, in the order the adapter produces it:
      //   * the backend request is presented only after the data phase of a
      //     write, so accepting it here means the whole request is valid;
      //   * the answer is returned on a later edge, when the adapter is in its
      //     COMPLETE state and exposes rsp_ready;
      //   * one beat is outstanding at a time, which is the CPU's declared
      //     max_outstanding.
      // The identity comes from the sampled address phase: a beat whose address
      // phase the classifier never saw (the CPU's own synchronized HRESETn had
      // not been observed yet) is *served* and counted as unknown, never guessed
      // into a fetch.
      if (ahb_response_taken) {
        if (beat.command_store) frame_done = true;
        beat = AhbBeat();
      }
      if (ahb_request && !mmio.busy
#if HAVE_DMA
                 && !control.busy
#endif
                 ) {
        if (ahb_wide > UINT32_MAX)
          throw std::runtime_error("AHB beat address leaves the 32-bit window");
        const unsigned be = ahb_write ? ahb_be : 15u;
        if (be > 15u) throw std::runtime_error("invalid AHB byte enable");
        const AhbIdentity::Kind kind = identity.classify(ahb_wide, ahb_write);
        const bool fetch_beat = kind == AhbIdentity::Instruction;
        if (kind == AhbIdentity::Instruction && ahb_write)
          throw std::runtime_error("AHB classifier produced an instruction write");
        // The RAM service is word-addressed; a subword access belongs to the
        // aligned word it covers and the CPU's own byte enables carry the lanes.
        const uint32_t addr = uint32_t(ahb_wide & ~uint64_t(3));
        AhbBeat next;
        next.active = true;
        next.write = ahb_write;
        next.address = uint32_t(ahb_wide);
        next.be = be;
        ++observation.ahb_beats;
        if (kind == AhbIdentity::Unknown) {
          ++observation.ahb_unknown;
          if (!ahb_bus_reset_n) ++observation.ahb_unknown_reset;
          // The sampled manager-domain facts at the edge whose beat has no
          // established address phase: this is what makes the unknown a
          // measurement rather than a label.
          EVENT_STREAM << "ahb_identity " << tick << " unknown "
                    << hex32(next.address) << " manager_ready "
                    << int(ahb_manager_ready) << " hsel " << int(ahb_hsel)
                    << " htrans " << ahb_htrans << " hprot " << ahb_hprot
                    << " bus_reset_n " << int(ahb_bus_reset_n) << '\n';
        }
        if (in_ip(addr)) {
          if (fetch_beat)
            throw std::runtime_error("instruction fetch inside the target window");
          if (ahb_write && be != 15u)
            throw std::runtime_error("partial AHB target write is outside this spike");
          mmio.busy = true; mmio.sent = false; mmio.write = ahb_write;
          mmio.address = addr; mmio.value = ahb_wdata; mmio.be = be;
          mmio.target = unsigned(ip_index_of(addr));
          observation.target_index = int(mmio.target);
          EVENT_STREAM << "cpu_mmio " << tick << ' ' << (ahb_write ? "write" : "read")
                    << ' ' << hex32(addr) << ' ' << hex32(ahb_wdata) << '\n';
#if HAVE_DMA
        } else if (in_dma(addr)) {
          throw std::runtime_error("an AHB build has no DMA control port");
#endif
        } else if (in_ram(addr)) {
          if (ahb_write) {
            memory.write(addr, ahb_wdata, be);
            next.value = 0;
            next.have_value = true;
            ++observation.d_writes;
            if (addr == kCommand && be == 15u && ahb_wdata == 0) next.command_store = true;
            if (addr == kEcho && be == 15u) {
              observation.echo_stored = true;
              observation.echo_value = ahb_wdata;
            }
            if (addr >= kDataBase) {
              observation.write_accepted = true;
              observation.write_address = next.address;
              observation.write_value = ahb_wdata;
              observation.write_be = be;
            }
          } else if (fetch_beat) {
            ++observation.i_fetches;
#if CPU_BUS_AHB
            if (!first_fetch_seen) {
              first_fetch_seen = true;
              first_fetch_address = addr;
              first_fetch_tick = tick;
            }
#endif
            if (addr == kSlot) {
              observation.slot_fetch = true;
              observation.slot_fetch_address = addr;
            }
#if HAVE_EVENT_LAYER
            EVENT_STREAM << "ifetch " << tick << ' ' << hex32(addr) << ' '
                      << hex32(memory.read(addr)) << '\n';
#endif
            next.value = memory.read(addr);
            next.have_value = true;
          } else if (kind == AhbIdentity::Data) {
            ++observation.d_reads;
            next.value = memory.read(addr);
            next.have_value = true;
            if (addr >= kDataBase) {
              observation.read_accepted = true;
              observation.read_address = next.address;
              observation.read_from_ip = false;
              observation.read_value = next.value;
            }
          } else {
            // No accepted address phase for this beat: answer it from RAM as
            // the address says, and count it apart from fetches and data.
            next.value = memory.read(addr);
            next.have_value = true;
          }
        } else {
          throw std::runtime_error("CPU bus access outside RAM and the declared target windows");
        }
        beat = next;
        EVENT_STREAM << "ahb " << tick << ' '
                  << (kind == AhbIdentity::Instruction ? "fetch"
                      : kind == AhbIdentity::Data ? (ahb_write ? "write" : "read")
                                                  : "unknown")
                  << ' ' << hex32(next.address) << ' ' << hex32(ahb_wdata)
                  << std::dec << " be " << be << '\n';
      }
#elif CPU_BUS_AXI4
      // No OBI request/response channel exists in this build; CpuLink owns the
      // CPU side and the beat service above owns RAM/target routing.
      (void)0;
#else
      if (iconsume) ins.valid = false;
      if (dconsume) {
        dat.valid = false;
        if (ack_pending) { ack_pending = false; frame_done = true; }
      }
      if (itake) {
        if (!in_ram(ia))
          throw std::runtime_error("CPU instruction fetch outside the declared RAM");
        ++observation.i_fetches;
        if (ia == kSlot) {
          observation.slot_fetch = true;
          observation.slot_fetch_address = ia;
        }
#if HAVE_EVENT_LAYER
        // The accepted fetch beat itself: address the CPU asked for and the
        // word this host answered with.  A fetch is not a retirement.
        EVENT_STREAM << "ifetch " << tick << ' ' << hex32(ia) << ' '
                  << hex32(memory.read(ia)) << '\n';
#endif
        ins.value = memory.read(ia);
        ins.valid = true;
      }
      if (dtake) {
        if (in_ip(da)) {
          if (dbe != 15)
            throw std::runtime_error("partial APB word access is outside this spike");
          mmio.busy = true; mmio.sent = false; mmio.write = dw;
          mmio.address = da; mmio.value = dv; mmio.be = dbe;
          mmio.target = unsigned(ip_index_of(da));
          observation.target_index = int(mmio.target);
          EVENT_STREAM << "cpu_mmio " << tick << ' ' << (dw ? "write" : "read")
                    << ' ' << hex32(da) << ' ' << hex32(dv) << '\n';
#if HAVE_DMA
        } else if (in_dma(da)) {
          if (dbe != 15)
            throw std::runtime_error("partial DMA control access is outside this spike");
          control.busy = true; control.accepted = false; control.write = dw;
          control.offset = da - kDmaBase; control.value = dv; control.be = dbe;
          EVENT_STREAM << "cpu_control " << tick << ' ' << (dw ? "write" : "read")
                    << ' ' << hex32(da) << ' ' << hex32(dv) << '\n';
#endif
        } else if (in_ram(da & ~3u)) {
          // The OBI data channel exposes a BYTE address (the local harness's
          // cpu_session states the same convention), while the RAM service is
          // word-addressed and requires 4-byte alignment.  A subword access
          // therefore belongs to the aligned word it covers; the CPU's own byte
          // enables carry the lanes and are not rewritten here.  The boundary
          // is checked on the aligned address so the last three bytes of the
          // window are not refused.
          const uint32_t ram_addr = da & ~3u;
          if (dbe > 15) throw std::runtime_error("invalid RAM byte enable");
          if (dw) {
            memory.write(ram_addr, dv, dbe);
            ++observation.d_writes;
            if (ram_addr == kCommand && dbe == 15 && dv == 0) ack_pending = true;
            if (ram_addr == kEcho && dbe == 15) {
              observation.echo_stored = true;
              observation.echo_value = dv;
            }
            if (ram_addr >= kDataBase) {
              observation.write_accepted = true;
              observation.write_address = da;
              observation.write_value = dv;
              observation.write_be = dbe;
            }
          } else {
            ++observation.d_reads;
            if (ram_addr >= kDataBase) {
              observation.read_accepted = true;
              observation.read_address = da;
              observation.read_from_ip = false;
              observation.read_value = memory.read(ram_addr);
            }
          }
          dat.value = dw ? 0 : memory.read(ram_addr);
          dat.valid = true;
        } else {
          throw std::runtime_error("CPU data access outside RAM and the declared target windows");
        }
        EVENT_STREAM << "cpu_data " << tick << ' ' << (dw ? "write" : "read") << ' '
                  << hex32(da) << ' ' << hex32(dv) << std::dec << " be " << dbe << '\n';
      }
#endif
      if (iptake) {
        mmio.sent = true;
        // Mark the counters at the moment this request was accepted: the
        // completion check below is a delta from here.
        axi_mark = axi_mark_of(observation.axi_aw, observation.axi_w,
                               observation.axi_b, observation.axi_ar,
                               observation.axi_r);
      }
      if (ipdone) {
        // A TL-UL target's own d_error is a real response the case can state and
        // fail on (its trace counted it), exactly as an AXI4-Lite BRESP/RRESP code
        // is recorded rather than aborting the batch.  Every other protocol keeps
        // the historical abort: a bridge that raises its beat error without a
        // sampled protocol error is a host-side inconsistency, not an observation.
        if (!mmio.busy || !mmio.sent
            || (iperror && !ip_is_tlul(int(mmio.target))))
          throw std::runtime_error(TARGET_NAME " target answered without a completed request");
        const unsigned completed_target = mmio.target;
        observation.target_index = int(completed_target);
#if TARGET_HAS_AXI4LITE
        // The declared shape is one outstanding single beat, so the transfer is
        // one transaction: AW+W+B for a write, AR+R for a read.  A response code
        // other than OKAY is recorded as the observation it is (the case then
        // fails on its own declared response check) and printed as a bus error on
        // this protocol's channel, instead of aborting the round.  The protocol is
        // the completed target's own: an APB3 target in a mixed build already had
        // its transfer counted by the psel/penable/pready sample above.
        if (ip_is_axi4lite(int(completed_target))) {
          observation.target_ready = true;
          observation.ip_targets[completed_target].ready = true;
          observation.ip_targets[completed_target].last_offset = observation.target_offset;
          if (mmio.write) {
            // Exactly one AW, W and B *for this request*: the case-wide totals
            // may already include another target transaction (a routed F6 case
            // reads the same target twice for its evidence word), so the check
            // is the delta from the mark taken when this request was accepted.
            if (observation.axi_aw - axi_mark.aw != 1
                || observation.axi_w - axi_mark.w != 1
                || observation.axi_b - axi_mark.b != 1)
              throw std::runtime_error(
                  "AXI4-Lite write did not complete AW, W and B exactly once");
            {
              note_target_write(observation, record, completed_target,
                                observation.target_offset,
                                observation.target_wdata);
              observation.ip_targets[completed_target].last_data = observation.target_wdata;
            }
          } else {
            // One AR and one R *for this request*: see the write check above.
            if (observation.axi_ar - axi_mark.ar != 1
                || observation.axi_r - axi_mark.r != 1)
              throw std::runtime_error(
                  "AXI4-Lite read did not complete AR and R exactly once");
            ++observation.target_reads;
            ++observation.ip_targets[completed_target].reads;
            observation.ip_targets[completed_target].last_data = observation.target_rdata;
            observation.ip_targets[completed_target].last_read_offset =
                observation.target_offset;
            observation.ip_targets[completed_target].last_read_data =
                observation.target_rdata;
            observation.target_read_offset = observation.target_offset;
            observation.target_read_data = observation.target_rdata;
          }
          if (observation.target_resp != 0) {
            ++observation.axi_resp_non_okay;
            ++observation.target_errors;
#if HAVE_EVENT_LAYER
            EVENT_STREAM << "bus_error " << tick << ' '
                         << ip_bus_channel(int(completed_target)) << ' '
                         << hex32(observation.target_offset) << '\n';
#endif
          }
        }
#endif
        if (!mmio.write && !iperror) {
          observation.read_accepted = true;
          observation.read_address = mmio.address;
          observation.read_from_ip = true;
          observation.read_value = ipvalue;
#if HAVE_PINS
          // The pad the host resolved from the device's own ports, and the
          // device's synchronizer latch, both taken at the tick the read
          // completed: the value the CPU committed is compared with these.
          observation.pad_at_read = pads.value;
          observation.sync_at_read = pads.sync;
          observation.padin_latch_at_read = observation.padin_latch;
#endif
        }
#if CPU_BUS_AHB
        // The AHB beat that started this target access now has its answer; the
        // adapter returns it on the next edge (its COMPLETE state), so the
        // value is attached here and the transfer completes there.
        if (!beat.active)
          throw std::runtime_error(TARGET_NAME " target answered a beat that is not in flight");
        beat.value = ipvalue;
        beat.have_value = true;
#else
        dat.value = ipvalue;
        dat.valid = true;
#endif
        mmio = Mmio();
#if CPU_BUS_AXI4
        if (axi4_target.active && dat.valid) {
          myfuzz::axi4::BeatResponse response;
          response.rdata = 0;
          if (!axi4_target.write) {
            const uint32_t value = dat.value;
            response.rdata = ((axi4_target.address & 4u) != 0)
                ? (uint64_t(value) << 32) : uint64_t(value);
          }
          response.error = false;
          link.beat_response(response);
          axi4_target.active = false;
          dat = Response();
        }
#endif
      }
#if HAVE_DMA && DMA_ROUTE_ENABLED
      // The routed beat's own completion.  The request is accepted by the same
      // APB3 bridge the CPU uses; its response is the only thing that lets the
      // master beat finish, and the accepted master beat is counted here (not at
      // address decode) so "the target really answered" is the route's evidence.
      if (route_iptake) route.sent = true;
      if (route_ipdone) {
        if (route_iperror || !route.waiting || !route.sent)
          throw std::runtime_error(
              TARGET_NAME " routed target answered without a completed route request");
        route.done = true;
        route.rdata = route_ipvalue;
        ++observation.dma_route_acks;
#if DMA_ROUTE_READ
        if (route.read) {
          // The captured word is the target's own PRDATA.  It is handed to the
          // DMA as the read beat's data (``master.data`` is what the host drives
          // on mwb_dat_r) and kept for the case's evidence.  The routed read
          // beats are numbered by the order the master presented them.
          const unsigned index = observation.dma_route_reads > 0
              ? observation.dma_route_reads - 1 : 0;
          if (index < unsigned(DMA_BLOCK_WORDS))
            observation.dma_route_read_capture[index] = route.rdata;
          if (observation.dma_route_reads == 1) {
            observation.dma_route_read_first = route.rdata;
            observation.dma_first_read_value = route.rdata;
          }
          observation.dma_route_read_value = route.rdata;
          if (route.rdata == observation.dma_route_read_first)
            ++observation.dma_route_read_stable;
          master_head_entry().data = route.rdata;
          EVENT_STREAM << "dma_route_read_done " << tick << ' '
                       << hex32(kDmaRouteAddress) << ' ' << hex32(route.rdata)
                       << '\n';
        } else
#endif
        EVENT_STREAM << "dma_route_done " << tick << ' ' << hex32(kDmaRouteAddress)
                     << ' ' << hex32(route.wdata) << '\n';
      }
#endif
#if HAVE_DMA
      if (control_accept) control.accepted = true;
      if (control_ack) {
        if (control.write) {
          ++observation.ctl_writes;
          if (control.offset == kDmaControlOffset) {
            // Whether a clear write is expected at all is the declaration's
            // decision, not this host's: DMA_CLEAR_DECLARED and the declared
            // clear mask come from the entry that rendered this header.
#if DMA_CLEAR_DECLARED
            if ((control.value & DMA_CLEAR_MASK) == DMA_CLEAR_MASK)
              ++observation.ctl_clear_writes;
            else if (control.value == kDmaStartWord) {
              ++observation.ctl_start_writes;
              observation.dma_start_seen = true;
              observation.dma_start_write = control.value;
            }
#else
            if (control.value == kDmaStartWord) {
              ++observation.ctl_start_writes;
              observation.dma_start_seen = true;
              observation.dma_start_write = control.value;
            }
#endif
          } else {
            ++observation.ctl_config_writes;
          }
          EVENT_STREAM << "dma_control " << tick << " write " << hex32(control.offset) << ' '
                    << hex32(control.value) << '\n';
        } else {
          ++observation.ctl_reads;
          observation.ctl_status = control_data;
          // Reads before the start write are the "before" sample; the ISR read
          // after the transfer is the "after" sample.
          if (control.offset == kDmaControlOffset && observation.ctl_start_writes == 0)
            ++observation.ctl_reads_before_start;
          if ((control_data >> DMA_BUSY_BIT) & 1u) ++observation.busy_high_reads;
          EVENT_STREAM << "dma_control " << tick << " read " << hex32(control.offset) << ' '
                    << hex32(control_data) << '\n';
        }
        dat.value = control_data;
        dat.valid = true;
        control = Control();
      }
      if (master_pending() && master_head_delay()) --master_head_entry().delay;
      if (master_ack) {
        // The response being answered is the oldest one this host owes.
        Master &master = master_head_entry();
        // Measured, not declared: the ticks between taking this beat and
        // returning its response.  The no-delay host always spends one tick
        // pending, so `delayed_acks` counts responses that waited longer.
        const unsigned waited = unsigned(tick - master.accept_tick);
        if (observation.dma_acks == 0 || waited < observation.dma_wait_min)
          observation.dma_wait_min = waited;
        if (waited > observation.dma_wait_max) observation.dma_wait_max = waited;
        observation.dma_wait_total += waited;
        ++observation.dma_acks;
        if (waited > 1) ++observation.dma_delayed_acks;
#if DMA_ROUTE_ENABLED
        if (master.routed) {
          // The ack was gated on the target's response above; reaching here
          // without it would be a host bug, not a device fact.
          if (!route.done || !route.waiting)
            throw std::runtime_error("DMA routed beat acked without a target response");
          route = MasterRoute();
        }
#endif
        master_pop();
      }
      if (master_accept) {
        // The accepted beat becomes the newest outstanding response; every
        // assignment below writes that record.
        Master &master = master_push();
        // The measured pipeline depth: this many responses are outstanding at
        // this instant, and the case reports the largest such count it saw.
        if (observation.dma_outstanding_peak < master_count)
          observation.dma_outstanding_peak = master_count;
        if (master_select == 0)
          throw std::runtime_error("DMA master presented an empty byte enable");
#if DMA_MASTER_PARTIAL
        // A declared lane mask: the device's own strobes have to be one of the
        // patterns the plan declares, otherwise this run is refused by name.
        {
          bool declared = false;
          for (unsigned lane = 0; lane < DMA_MASTER_LANE_COUNT; ++lane) {
            const unsigned mask = ((1u << DMA_MASTER_LANES_PER_BEAT) - 1u)
                << (lane * DMA_MASTER_LANES_PER_BEAT);
            if (master_select == mask) declared = true;
          }
          if (!declared) {
            ++observation.dma_sel_undeclared;
            throw std::runtime_error("DMA master presented an undeclared byte enable");
          }
        }
#else
        if (master_select != 15) {
          ++observation.dma_sel_undeclared;
          throw std::runtime_error("non-full DMA master byte enable outside this spike");
        }
#endif
#if HAVE_DMA && DMA_ROUTE_ENABLED
        // A fixed route: the device presents the declared route address on every
        // beat and the host forwards it to the routed target's APB3 port.  An
        // aperture route: the device advances the source address itself, so every
        // beat must present the next declared aperture address.  The target's own
        // APB register file decodes the offset, so the address the master presents
        // and the offset the request carries are two declared facts the host
        // cross-checks instead of translating one into the other.
#if DMA_ROUTE_READ
        const uint32_t route_beat = unsigned(observation.dma_route_reads);
#else
        // A write route is fixed: it has no routed-beat table and no read count.
        const uint32_t route_beat = 0u;
#endif
        const bool routed = kDmaRouteAperture
            ? (master_address >= kDmaRouteAddress
               && master_address < kDmaRouteAddress
                   + 4u * uint64_t(kDmaRouteApertureCount)
               && (master_address - kDmaRouteAddress) % 4u == 0
               && (master_address - kDmaRouteAddress) / 4u == route_beat)
            : (kDmaRouteFixed && master_address == kDmaRouteAddress);
        if (kDmaRouteAperture && !routed
            && master_address >= kDmaRouteAddress
            && master_address < kDmaRouteAddress
                + 4u * uint64_t(kDmaRouteApertureCount))
          throw std::runtime_error(
              "DMA master presented the declared aperture out of order");
        const bool route_window = master_address >= kDmaRouteTargetBase
            && master_address - kDmaRouteTargetBase
                <= uint64_t(DMA_ROUTE_TARGET_SIZE) - 4;
        if (!routed && route_window)
          throw std::runtime_error(
              "DMA master addressed the declared route window at a non-declared "
              "destination");
        if (!routed && !in_ram(master_address))
          throw std::runtime_error("DMA master access outside the declared RAM");
#else
        const bool routed = false;
        if (!in_ram(master_address))
          throw std::runtime_error("DMA master access outside the declared RAM");
#endif
#if HAVE_DMA && DMA_ROUTE_ENABLED
        if (routed) {
          if (master_select != 15)
            throw std::runtime_error("DMA routed master presented a partial byte enable");
          if (route.waiting)
            throw std::runtime_error("DMA routed a second beat while one was outstanding");
          route.waiting = true; route.presented = false;
          route.sent = false; route.done = false;
#if DMA_ROUTE_READ
          if (!master_write) {
            // A read route: the master's read beat *is* the routed register
            // read.  RAM is not read for it; the word is captured from the
            // target's PRDATA when the APB3 bridge answers (the completion block
            // above) and returned to the DMA on mwb_dat_r with the ack.
            route.read = true;
            route.wdata = 0;
            route.offset = kDmaRouteAperture
                ? kDmaRouteOffset + 4u * route_beat : kDmaRouteOffset;
            // Count the declared injection before the beat is numbered: the
            // declaration names the 0-based routed read beat whose response is
            // ACK+ERR, and the count of accepted routed reads is that number.
            const bool inject_error = kDmaRouteErrorBeat >= 0
                && unsigned(kDmaRouteErrorBeat) == observation.dma_route_reads;
            if (inject_error) {
              ++observation.dma_error_injections;
              observation.dma_error_beat = kDmaRouteErrorBeat;
            }
            if (kDmaRouteAperture && route_beat < kDmaRouteApertureCount) {
              observation.dma_route_beat_offset[route_beat] = route.offset;
              // The address the device presented has to be the declared address
              // of this beat, not merely the one the arithmetic expects: the
              // table is the entry's own declaration of the aperture.
              if (master_address == kDmaRouteApertureAddress[route_beat])
                ++observation.dma_route_sequence;
            }
            ++observation.dma_reads;
            ++observation.dma_route_reads;
            if (observation.dma_route_reads == 1) {
              observation.dma_first_read_address = master_address;
              observation.dma_first_read_value = 0;
            }
            observation.dma_route_last_offset = route.offset;
            master.pending = true;
            master.routed = true;
            master.data = 0;
            master.error = inject_error;
            // The declared delay is owed before the target request starts; the
            // ack itself waits for the target's response regardless.
            master.delay = unsigned(DMA_RESPONSE_DELAY);
            master.accept_tick = tick;
            EVENT_STREAM << "dma_route_read " << tick << ' '
                         << hex32(master_address) << std::dec << " sel "
                         << master_select << " off " << hex32(route.offset)
                         << (inject_error ? " error" : "") << '\n';
          } else
#else
          if (!master_write)
            throw std::runtime_error("DMA read route is outside this spike");
#endif
          {
            route.read = false;
            route.wdata = master_value;
            ++observation.dma_writes;
            ++observation.dma_route_writes;
            observation.dma_last_write_address = master_address;
            observation.dma_last_write_value = master_value;
            route.offset = kDmaRouteOffset;
            observation.dma_route_last_offset = route.offset;
            observation.dma_route_last_wdata = master_value;
            // The device's own lane bits are still the declared full word; the
            // destination block in RAM is never touched by a routed beat.
            ++observation.dma_sel_full;
            master.pending = true;
            master.routed = true;
            master.data = 0;
            // A declared response delay is owed before the target request starts,
            // so the measured wait still includes it; the ack itself waits for the
            // target response regardless.
            master.delay = unsigned(DMA_RESPONSE_DELAY)
                + ((master_write && !master_post_stb) ? 1u : 0u);
            master.accept_tick = tick;
            EVENT_STREAM << "dma_route_write " << tick << ' '
                         << hex32(master_address) << ' ' << hex32(master_value)
                         << std::dec << " sel " << master_select << '\n';
          }
        } else
#endif
        if (master_write) {
          memory.write(master_address, master_value, master_select);
          ++observation.dma_writes;
          ++observation.dma_ram_writes;
          observation.dma_last_write_address = master_address;
          observation.dma_last_write_value = master_value;
          if (master_select == 15) ++observation.dma_sel_full;
          else ++observation.dma_sel_partial;
          // Lane coverage of the declared destination block, byte by byte.  A
          // strobe outside the block is counted, never folded into its last
          // word, so "the neighbours were untouched" is a measurement.
          for (unsigned lane = 0; lane < 4; ++lane) {
            if (!((master_select >> lane) & 1u)) continue;
            const uint32_t byte_address = master_address + lane;
            if (byte_address >= kDmaDestinationBase
                && byte_address < kDmaDestinationBase + 4u * kDmaBlockWords) {
              unsigned &hits = observation.dma_dst_lane_hits[byte_address - kDmaDestinationBase];
              if (hits == 1) ++observation.dma_lane_extra;
              ++hits;
            } else {
              ++observation.dma_bytes_outside_block;
            }
          }
        } else {
          ++observation.dma_reads;
          if (master_select != 15) ++observation.dma_read_lane_partial;
          if (observation.dma_reads == 1) {
            observation.dma_first_read_address = master_address;
            observation.dma_first_read_value = memory.read(master_address);
          }
        }
#if HAVE_DMA && DMA_ROUTE_ENABLED
        if (!routed) {
#endif
        master.pending = true;
        master.data = master_write ? 0 : memory.read(master_address);
        // The declared response delay, plus the one-cycle write-data-late case
        // the bus itself produces (a write whose stb dropped after the accept).
        master.delay = unsigned(DMA_RESPONSE_DELAY)
            + ((master_write && !master_post_stb) ? 1u : 0u);
        master.accept_tick = tick;
        EVENT_STREAM << "dma_" << (master_write ? "write " : "read ") << tick << ' '
                  << hex32(master_address) << ' '
                  << hex32(master_write ? master_value : master.data)
                  << std::dec << " sel " << master_select << '\n';
#if HAVE_DMA && DMA_ROUTE_ENABLED
        }
#endif
      }
#endif
      if (tick - case_tick + 1 > CASE_TICK_BUDGET)
        throw std::runtime_error("tick budget exceeded for the case");
      bool idle = !mmio.busy;
#if CPU_BUS_AHB
      // A beat whose answer is still outstanding is in flight: the case is not
      // over until the adapter has consumed the response.
      idle = idle && !beat.active;
#endif
#if CPU_BUS_AXI4
      // The target beat and the adapter's whole beat are both part of the case:
      // the request handshake, the answer the host drives, and the B/R the
      // adapter still owes the CPU.  The case is over only when all three are
      // done, so a command-word store really completed at the CPU boundary.
      idle = idle && !axi4_target.active && !link.busy();
#endif
#if HAVE_DMA
      idle = idle && !control.busy && !master_pending()
#if DMA_ROUTE_ENABLED
          // A routed beat is in flight from the accepted master cycle until the
          // target's response was delivered back to the DMA; the case is not over
          // while any part of that round trip is outstanding.
          && !route.waiting
#endif
          ;
#endif
      // A storm-aborted case has already been reported and failed, but it is not
      // over until the handler it interrupted stores the mailbox command back to
      // zero: installing the next input before that store would let the old
      // handler overwrite the next case's command word.  The per-case tick budget
      // still bounds a handler that never returns (that stays a batch abort, not
      // a silent pass).
      if (storm_waiting_mailbox && memory.read(kCommand) != 0) continue;
      if (!frame_done || dat.valid || !idle) continue;

      // The CPU's own store of zero into the command word is the only case
      // delimiter; everything below is what the models already did.
      const uint32_t ram_after = record.flow == kF3 ? memory.read(word_at(record, 0)) : 0;
      if (record.flow == kF1) {
        // The program's own stores into the declared data window, sampled after
        // the case: every changed word is a real effect of a real retirement.
        // The install-time snapshot is the baseline, not a re-derivation from
        // the instruction stream.
        observation.data_hash_after = window_hash(memory, kDataBase, PROGRAM_DATA_WORDS);
        for (unsigned index = 0; index < PROGRAM_DATA_WORDS; ++index)
          if (memory.read(kDataBase + 4 * index) != data_before[index])
            ++observation.data_changed;
      }
#if HAVE_PINS
      // The pad state the case ended in, and the device's own status word, both
      // sampled from the device ports rather than summarised by the host.
      if (record.flow == kF2 && word_at(record, 0) == kIpBase + IP_PADIN_OFFSET
          && observation.read_from_ip)
        observation.pad_settled = observation.read_value == observation.pad_at_read;
      observation.pad_after = pads.value;
      observation.out_after = pads.out;
      observation.dir_after = pads.dir;
      observation.padin_latch = pads.sync;
      observation.status_after_read = myfuzz_ip::IpTarget<0>::probe_status(ip) & kPadMask;
#if HAVE_PIN_GROUPS
      // Every declared group's own executed facts, copied out of the schedule so
      // the case line states them after the case rather than while it runs.
      observation.pin_group_declared = kPinGroupCount;
      observation.pin_stimulus_group = pin_schedule.stimulus_override;
      for (unsigned index = 0; index < kPinGroupCount; ++index) {
        observation.pin_groups[index] = pin_schedule.groups[index];
        observation.pin_group_ticks += pin_schedule.groups[index].ticks;
        observation.pin_group_changes += pin_schedule.groups[index].changes;
        observation.pin_group_conflicts += pin_schedule.groups[index].conflicts;
        if (pin_schedule.groups[index].applied) ++observation.pin_group_executed;
      }
#endif
#endif
#if HAVE_SERIAL_PEER
      // The peer's own case facts: the frame it drove (if the case asked for one)
      // and every byte it decoded from the device's tx line while the case ran.
      observation.serial_rx_frames = serial_peer.rx_frames;
      observation.serial_rx_bits = serial_peer.rx_bits;
      observation.serial_rx_held_ticks = serial_peer.rx_held;
      observation.serial_rx_byte = serial_peer.rx_byte;
      observation.serial_rx_levels = serial_peer.rx_levels;
      observation.serial_rx_parity = serial_peer.rx_parity_level;
      observation.serial_rx_first_tick = serial_peer.rx_first_tick;
      observation.serial_rx_last_tick = serial_peer.rx_last_tick;
      observation.serial_tx_frames = serial_peer.tx_frames;
      observation.serial_tx_bits = serial_peer.tx_bits;
      observation.serial_tx_framing_ok = serial_peer.tx_framing_ok;
      observation.serial_tx_stop_ok = serial_peer.tx_stop_ok;
      observation.serial_tx_byte = serial_peer.tx_byte;
      observation.serial_tx_levels = serial_peer.tx_levels;
      observation.serial_tx_parity = serial_peer.tx_parity_level;
      observation.serial_tx_first_tick = serial_peer.tx_first_tick;
      observation.serial_tx_last_tick = serial_peer.tx_last_tick;
      observation.serial_tx_en_ticks = serial_peer.tx_en_ticks;
      observation.serial_tx_en_level = serial_peer.tx_en_level;
#endif
#if HAVE_IRQ_LINKS
      if (record.flow == kF5) {
        observation.isr_result = memory.read(kIpResult);
        // 1 is the handler's own flag; 2 is the firmware's wait timeout marker.
        const uint32_t flag_value = memory.read(kFlagAddress);
        observation.isr_flag = flag_value == 1;
        observation.wait_timeout = flag_value == 2;
        // What the handler addressed and stored, named as what the declaration
        // says it is.  The timer's offset 0 is its counter, not a cause; the
        // summary reports the cause as unknown because the device has none.  A
        // link states the window it addresses, so a multi-target case names the
        // selected target's own status word, not the first target's.
        bool both = false;
#if IRQ_BOTH_ENABLED && IRQ_TARGET_LINK_COUNT > 0
        both = is_both_f5(record);
        if (both) {
          // One ISR body stored both reads: member 0 in kIpResult and member 1
          // in kIpResult2, each at that member link's own status address.  The
          // case is never reduced to one target_index.
          observation.isr_result2 = memory.read(kIpResult2);
          observation.isr_read_address =
              kIrqLinkBase[kIrqBothLink[0]] + kIrqLinkStatus[kIrqBothLink[0]];
          observation.isr_read_address2 =
              kIrqLinkBase[kIrqBothLink[1]] + kIrqLinkStatus[kIrqBothLink[1]];
          observation.isr_read_value = observation.isr_result;
          observation.isr_read_value2 = observation.isr_result2;
        }
#endif
        if (!both) {
#if IRQ_TARGET_LINK_COUNT > 0
          observation.isr_read_address = kIrqLinkBase[selected_f5_link(record)]
              + kIrqLinkStatus[selected_f5_link(record)];
#else
          observation.isr_read_address = kIrqTargetBase + kIpStatusOffset;
#endif
          observation.isr_read_value = observation.isr_result;
        }
      }
#endif
#if HAVE_DMA
      if (record.flow == kF6) {
        observation.isr_result = memory.read(kDmaResult);
        const uint32_t flag_value = memory.read(kFlagAddress);
        observation.isr_flag = flag_value == 1;
        observation.wait_timeout = flag_value == 2;
        observation.isr_read_address = kDmaBase + kDmaControlOffset;
        observation.isr_read_value = observation.isr_result;
        // The declared control word read before the start write, and the one
        // the handler read after completion: the completion criterion is the
        // declared busy/error bits, not "the word is not zero".
        observation.ctl_before = memory.read(kDmaCtlBefore);
        observation.busy_before = (observation.ctl_before >> DMA_BUSY_BIT) & 1u;
        observation.err_before = (observation.ctl_before >> DMA_ERR_BIT) & 1u;
        observation.busy_after = (observation.ctl_status >> DMA_BUSY_BIT) & 1u;
        observation.err_after = (observation.ctl_status >> DMA_ERR_BIT) & 1u;
        // The two guard words bracketing the declared destination block: they
        // are read from RAM after the transfer, so a write outside the block is
        // visible in the value instead of being assumed absent.
        observation.dma_guard_lo = memory.read(kDmaDestinationBase - 4);
        observation.dma_guard_hi = memory.read(kDmaDestinationBase + 4 * kDmaBlockWords);
#if DMA_ROUTE_ENABLED
        // The evidence the route declared: the word the F6 firmware read before
        // and after the routed transfer, and the declared field of each.  A cell
        // that still holds the sentinel was never written by this case and is
        // reported as not written rather than as a stale level.
        const uint32_t before = memory.read(kDmaRouteBefore);
        const uint32_t after = memory.read(kDmaRouteAfter);
        observation.dma_route_before_written = before != kDmaRouteCellPrefill;
        observation.dma_route_after_written = after != kDmaRouteCellPrefill;
        observation.fifo_status_before = before;
        observation.fifo_status_after = after;
        observation.tx_fifo_level_before = observation.dma_route_before_written
            ? dma_route_level(before) : 0;
        observation.tx_fifo_level_after = observation.dma_route_after_written
            ? dma_route_level(after) : 0;
        observation.dma_route_expected_level =
            dma_route_expected_level(observation.tx_fifo_level_before);
        // The accepted pushes are the measured difference of the two readbacks;
        // a level that fell would be a device fact the criteria must fail on, so
        // the subtraction is only used when the readback did not go backwards.
        observation.dma_route_accepted =
            observation.dma_route_after_written && observation.dma_route_before_written
                && observation.tx_fifo_level_after >= observation.tx_fifo_level_before
            ? observation.tx_fifo_level_after - observation.tx_fifo_level_before : 0;
        observation.dma_route_partial =
            observation.dma_route_accepted < kDmaRoutePushes;
#if DMA_ROUTE_READ
        // A read route's case-end evidence: the CPU's own readback cells for the
        // RAM destination block, and the comparison of every destination word
        // with the word the DMA captured on the matching read beat.  The
        // captured array is the host's record of the target's PRDATA, never the
        // RAM content, so a stale or sentinel destination cannot pass.
        observation.dma_route_cpu_written = false;
        observation.dma_route_cpu_matched = 0;
        observation.dma_route_read_matched = 0;
        for (unsigned index = 0; index < kDmaBlockWords; ++index) {
          const uint32_t dst = memory.read(kDmaDestinationBase + 4 * index);
          observation.dma_route_cpu_dst[index] = memory.read(kDmaRouteDst + 4 * index);
          if (dst == observation.dma_route_read_capture[index])
            ++observation.dma_route_read_matched;
          if (observation.dma_route_cpu_dst[index]
              == observation.dma_route_read_capture[index])
            ++observation.dma_route_cpu_matched;
        }
        if (kDmaBlockWords > 0)
          observation.dma_route_cpu_written =
              observation.dma_route_cpu_dst[0] != kDmaRouteCellPrefill;
        // A declared expected word: how many captured words are exactly that
        // word.  The comparison is against the declaration, not against the
        // first capture, so a FIFO of equal words still has to match the value
        // the scenario declared for its port.
        observation.dma_route_fifo_matched = 0;
        if (kDmaRouteExpectWord) {
          for (unsigned index = 0; index < kDmaBlockWords; ++index)
            if (observation.dma_route_read_capture[index] == kDmaRouteExpectValue)
              ++observation.dma_route_fifo_matched;
        }
        // An aperture read's independent witness: the CPU's own read of every
        // declared aperture word, after the transfer.  A read of these registers
        // leaves them unchanged, so the CPU's word and the DMA's captured word
        // must be the same word.
        observation.dma_route_cpu_aper_matched = 0;
        if (kDmaRouteAperture) {
          for (unsigned index = 0; index < kDmaBlockWords; ++index) {
            observation.dma_route_cpu_aper[index] =
                memory.read(kDmaRouteApertureCells + 4 * index);
            if (observation.dma_route_cpu_aper[index]
                == observation.dma_route_read_capture[index])
              ++observation.dma_route_cpu_aper_matched;
          }
        }
#endif
#endif
      }
#endif
#if HAVE_IRQ_LINKS
      // What each sampled link's raw output held on the last tick of this case.
      // Only declared level links are considered: a pulse source's one-tick
      // pulse is not a stuck level.  A level still asserted after the handler
      // ran is a real fact, not something the host may clear silently.
      observation.irq_level_final = 0;
      observation.irq_link_last = 0;
      for (std::size_t index = 0; index < irq_links.size(); ++index) {
        // The raw last sample of every declared link, pulse or level, so a
        // two-source case can state that both device outputs ended low even
        // when one of them is a one-tick pulse.
        if (irq_links[index].last && index < 32)
          observation.irq_link_last |= (1u << index);
        // A build whose only source is the DMA completion line has no declared
        // target link at all, so the link table is not even declared there.
#if IRQ_TARGET_LINK_COUNT > 0
        const bool level = (index < unsigned(IRQ_TARGET_LINK_COUNT)
                            && kIrqLinkLevel[index])
                           || (index == IRQ_DMA_LINK_INDEX && DMA_IRQ_LEVEL);
#else
        const bool level = index == IRQ_DMA_LINK_INDEX && DMA_IRQ_LEVEL;
#endif
        if (level && irq_links[index].last) observation.irq_level_final |= 1u << index;
      }
      // A level the case-end sample still sees stays a failure; a storm already
      // reported at the take limit keeps its flag even though the devices-only
      // reset cleared the line before this sample (so irq_level_final may be 0).
      observation.level_stuck = observation.level_stuck
          || (observation.irq_level_final != 0
              && (record.flow == kF5 || record.flow == kF6));
#endif
      // A bounded loop legitimately repeats PCs, so its case's ordering
      // criterion is the reference trace (count, repeat count and hash), not the
      // strict-rise flag the other shapes keep.  The flag is still printed.
      bool pc_order_ok = observation.prog_pc_ordered;
#if F1_TRAP_PROGRAM
      // The words the firmware's own trap handler stored before it returned: it
      // read mcause/mepc with CSRRS, advanced mepc past the ECALL, stored the
      // two values and set its flag.  A sentinel that survives means the handler
      // never ran for this case, which is reported instead of being read as the
      // previous case's value.
      if (record.flow == kF1) {
        observation.trap_stored_cause = memory.read(TRAP_CAUSE_CELL);
        observation.trap_stored_epc = memory.read(TRAP_EPC_CELL);
        observation.trap_flag = memory.read(TRAP_FLAG_CELL);
      }
#endif
#if F1_ALLOW_LOOPS
      if (record.loop_mode) pc_order_ok = true;
#endif
      // Every target but the routed one has to stay quiet: a transfer counted on
      // a target this case did not address is a routing defect, not a pass.  A
      // one-target build has no other target, so the term is constant true there
      // and the historical case criteria are unchanged.  F5 and F6 are excluded:
      // a multi-link F5 case may service more than one declaring target, and a
      // routed F6 transfer writes the route's target by design.
      auto other_targets_quiet = [&] {
        bool quiet = true;
        for_each_ip(ip_models, [&](auto constant, auto &) {
          const unsigned index = constant();
          if (int(index) == observation.target_index) return;
          if (observation.ip_targets[index].reads
              || observation.ip_targets[index].writes) quiet = false;
        });
        return quiet;
      };
      bool passed = true;
      switch (record.flow) {
        case kF1:
#if F1_TRAP_PROGRAM
          // The declared trap program.  The slot's first word is a real ECALL the
          // M-mode core traps on; the firmware image's own handler (installed by
          // the boot code through mtvec, not written by the slot program) reads
          // mcause and mepc with CSRRS, stores them to the declared cells,
          // advances mepc past the ECALL and returns with MRET, so the words
          // after it really execute.  Every fact below is measured: the RVFI
          // record's own trap / cause / intr / mode for that word, the CSR
          // readback the scoreboard registers, and the two words the handler
          // stored.  A fetch or the trap bit alone is never enough.
          passed = observation.slot_fetch
              && observation.prog_retires == record.words
              && pc_order_ok && observation.prog_insns_match
              && observation.trap_count == 1
              && observation.prog_traps == 1
              && observation.trap_pc == kSlot
              && observation.trap_insn == word_at(record, 0)
              && observation.trap_cause == uint64_t(F1_TRAP_CAUSE)
              && observation.trap_mode == 3u
              && observation.trap_intr == 0u
              && observation.rvfi_mcause == uint64_t(F1_TRAP_CAUSE)
              && observation.rvfi_mepc == uint64_t(kSlot)
              // The handler's own CSRRS write is visible in the readback: the
              // last snapshot has mepc advanced past the ECALL, which is what
              // makes the returned word after it execute.
              && observation.rvfi_mepc_final == uint64_t(kSlot + 4)
              && observation.trap_stored_cause == F1_TRAP_CAUSE
              && observation.trap_stored_epc == kSlot
              && observation.trap_flag == 1u
              && observation.slot_retire
              && observation.slot_retire_pc == kSlot
              && observation.slot_retire_insn == word_at(record, 0)
              && observation.slot_successor
              && observation.slot_successor_pc == kSlot + 4 * record.words
              && !rvfi.retire_dropped;
          break;
#else
          // The trampoline was entered, its first word retired, the words it
          // retired are the words the host installed (in address order, or - for
          // a bounded loop - the exact statically proven count), the fixed return
          // jump that follows the last word retired, and nothing in the program
          // trapped.  The witness is the CPU's own RVFI retirement stream.  In a
          // straight-line build every installed word must retire; a branch, jump,
          // loop or compressed build retires a sequence the entry compares with
          // the Python reference trace (prog_trace_hash/prog_trace_count).
          passed = observation.slot_fetch
#if F1_ALLOW_LOOPS
              // The whole-image pass proved the loop trip count, so the exact
              // retirement count is known when the image has no other control
              // transfer; otherwise the range is the same one a branch uses.
              && (record.loop_mode
                      ? (record.exact_retires
                             ? observation.prog_retires == record.expected_retires
                             : (observation.prog_retires >= 1
                                && observation.prog_retires <= record.expected_retires))
                      : (observation.prog_retires >= 1
                         && observation.prog_retires <= record.words))
#elif F1_ALLOW_COMPRESSED
              // A compressed image retires two instructions per pair word, so the
              // expected count is the image's instruction count - never the
              // record-word count.  With a control transfer declared a taken
              // transfer may legally retire fewer; the exact sequence is then the
              // entry's reference-trace comparison.
#if F1_ALLOW_BRANCHES || F1_ALLOW_COMPRESSED_CONTROL
              && observation.prog_retires >= 1
              && observation.prog_retires
                     <= f1_parcels::instruction_count(&record.values[0], record.words)
#else
              && observation.prog_retires
                     == f1_parcels::instruction_count(&record.values[0], record.words)
#endif
#elif F1_ALLOW_BRANCHES || F1_ALLOW_JUMPS
              && observation.prog_retires >= 1
              && observation.prog_retires <= record.words
#else
              && observation.prog_retires == record.words
#endif
              && pc_order_ok && observation.prog_insns_match
              && observation.prog_traps == 0
              && observation.slot_retire
              && observation.slot_retire_pc == kSlot
#if F1_ALLOW_COMPRESSED
              // The first instruction of a pair word is its low parcel, which is
              // what RVFI reports as ``insn`` for a compressed retirement; a
              // whole 32-bit word is itself.
              && observation.slot_retire_insn
                     == f1_parcels::first_instruction(word_at(record, 0))
#else
              && observation.slot_retire_insn == word_at(record, 0)
#endif
              && observation.slot_successor
              && observation.slot_successor_pc == kSlot + 4 * record.words
#if CPU_BUS_WISHBONE
              // The Wishbone CPU declares its own retirement index; the host
              // insists it rose at every retirement of this case.
              && observation.rvfi_order_monotonic
#endif
#if CPU_BUS_AXI4 && HAVE_RVFI_ADAPTER
              // The CVA6 probe-bundle adapter states whether one of its retirement
              // records was ever lost while two commit lanes were serialised.  A
              // lost record is a retirement this case cannot claim, so it fails
              // the case instead of shrinking the count silently.
              && !rvfi.retire_dropped
#endif
              ;
#endif  // F1_TRAP_PROGRAM (the else branch of the kF1 rule)
          break;
        case kF2:
          passed = observation.read_accepted && observation.read_address == word_at(record, 0)
              && observation.echo_stored && observation.echo_value == observation.read_value
              && (observation.read_from_ip ? observation.target_reads == 1
                                           : observation.target_reads == 0)
              // A RAM read performed no target transfer, and a target read was
              // carried by exactly the routed target: every other declared
              // target stays at zero reads and zero writes.
              && other_targets_quiet()
              // A Wishbone read is one completed classic cycle in the read
              // direction: the slave's own ack and a cleared we pin are the
              // evidence, not a host-side assumption.
              && (!ip_is_wishbone(observation.target_index)
                  || (observation.wb_acks == 1 && !observation.wb_we
                      && observation.wb_stb_pulses == 1))
              // A TL-UL read is one A-channel handshake of a Get opcode followed
              // by one D-channel handshake, and the response carried no error.
              && (!ip_is_tlul(observation.target_index)
                  || (observation.tlul_a_handshakes == 1
                      && observation.tlul_d_handshakes == 1
                      && observation.tlul_a_opcode == 4u
                      && observation.tlul_errors == 0))
              // An AHB-Lite read is one accepted address phase (HSEL with a
              // non-idle HTRANS, completed by HREADYIN) followed by one data
              // phase the target completed with HREADYOUT.  The wrapper's HRESP
              // is a tied-low response pin, so this checks the phases and never
              // claims a clean bus from it.
              && (!ip_is_ahb(observation.target_index)
                  || (observation.ahb_address_phases == 1
                      && observation.ahb_data_phases == 1
                      && observation.ahb_htrans == 2u
                      && observation.ahb_hsize == 2u
                      && observation.ahb_hreadyin
                      && observation.ahb_hreadyout
                      && !observation.ahb_hwrite))
#if HAVE_PINS
              // A read of the declared PADIN word is the CPU reading the value
              // the device's own synchronizer latched.  The instantaneous wire
              // may already have moved (that is the synchronizer's declared
              // latency), so it is reported as pad_settled, not required to be
              // equal; the host-driven pins still have to carry this case's
              // driver value on the wire.
              && (word_at(record, 0) != kIpBase + IP_PADIN_OFFSET
                  || (observation.read_from_ip
                      && observation.read_value == observation.padin_latch_at_read
                      && (observation.pad_at_read & ~observation.dir_after & kPadMask)
                          == (observation.ext_value & ~observation.dir_after & kPadMask)))
#endif
#if HAVE_SERIAL_PEER
              // A case that asked the declared peer for a byte has to show the
              // whole frame on the wire at the declared bit period: the declared
              // number of bit times held for exactly ``bit_ticks`` each, a start
              // bit at the active level and a stop bit at the idle level, and the
              // byte the record asked for.  A case with no stimulus word requires
              // nothing here (``record.words != 2``).
              && (record.words != 2
                  || (observation.serial_rx_frames == 1
                      && observation.serial_rx_bits
                             == int(SerialPeer<IP_MODEL>::kFrameBits)
                      && observation.serial_rx_byte == (word_at(record, 1) & 0xffu)
                      && observation.serial_rx_held_ticks
                             == int(SerialPeer<IP_MODEL>::kFrameBits
                                    * SerialPeer<IP_MODEL>::kBitTicks)
                      && (observation.serial_rx_levels & 1u) == 0u
                      && ((observation.serial_rx_levels
                           >> (SerialPeer<IP_MODEL>::kFrameBits - 1)) & 1u)
                             == SerialPeer<IP_MODEL>::kIdle))
#endif
              ;
          break;
        case kF3:
          passed = observation.write_accepted && observation.write_address == word_at(record, 0)
              && observation.write_value == word_at(record, 1) && observation.write_be == 15
              && ram_after == word_at(record, 1)
              // A RAM store reached no target window: every declared target has
              // to be at zero reads and zero writes.
              && other_targets_quiet();
          break;
        case kF4:
          // One completed target write of the record's value at the record's
          // offset inside the declared window, and no RAM store of it.  The
          // protocol-specific extras (full strobes and an OKAY response) are
          // checked where the protocol has them: the routed target's own
          // protocol decides, so a mixed build checks each write against the
          // bridge that really carried it.
          passed = observation.target_writes == 1 && observation.target_ready
              && observation.target_offset
                     == word_at(record, 0) - ip_base_of(observation.target_index)
              && observation.target_wdata == word_at(record, 1)
              && !observation.write_accepted
              && other_targets_quiet()
              && (!ip_is_axi4lite(observation.target_index)
                  || (observation.target_wstrb == 15 && observation.target_resp == 0
                      && observation.axi_aw == 1 && observation.axi_w == 1
                      && observation.axi_b == 1 && observation.axi_resp_non_okay == 0))
              // A Wishbone write is one request phase and one completed cycle in
              // the write direction, with the full strobe set the profile
              // declares (sel_implemented true, partial_write true).
              && (!ip_is_wishbone(observation.target_index)
                  || (observation.wb_acks == 1 && observation.wb_we
                      && observation.wb_stb_pulses == 1
                      && observation.wb_sel == 15))
              // A TL-UL write is one A-channel handshake of a PUT opcode (0 =
              // PutFullData, 1 = PutPartialData) with a full-word mask, followed
              // by one D-channel handshake that carried no error.
              && (!ip_is_tlul(observation.target_index)
                  || (observation.tlul_a_handshakes == 1
                      && observation.tlul_d_handshakes == 1
                      && observation.tlul_a_opcode <= 1u
                      && observation.tlul_a_mask == 15
                      && observation.tlul_errors == 0))
              // An AHB-Lite write is the mirror image of the read: the same two
              // phases, with HWRITE asserted in the address phase and the word
              // carried on HWDATA in the data phase.
              && (!ip_is_ahb(observation.target_index)
                  || (observation.ahb_address_phases == 1
                      && observation.ahb_data_phases == 1
                      && observation.ahb_htrans == 2u
                      && observation.ahb_hsize == 2u
                      && observation.ahb_hreadyin
                      && observation.ahb_hreadyout
                      && observation.ahb_hwrite))
#if HAVE_PINS
              // The declared side effect of the written pads: the output port the
              // host sampled afterwards follows the register the CPU wrote, the
              // device-driven pads show it, and the host-driven pads still show
              // this case's driver value (no other stimulus moved them).
              && ({
                   const uint32_t offset =
                       word_at(record, 0) - ip_base_of(observation.target_index);
                   uint32_t expected = observation.out_before;
                   if (offset == IP_PADOUT_OFFSET) expected = word_at(record, 1);
                   else if (offset == IP_PADOUTSET_OFFSET) expected = observation.out_before | word_at(record, 1);
                   else if (offset == IP_PADOUTCLR_OFFSET) expected = observation.out_before & ~word_at(record, 1);
                   expected &= kPadMask;
                   observation.out_after == expected
                       && (observation.pad_after & observation.dir_after & kPadMask)
                           == (expected & observation.dir_after & kPadMask)
                       && (observation.pad_after & ~observation.dir_after & kPadMask)
                           == (observation.ext_value & ~observation.dir_after & kPadMask);
                 })
#endif
              ;
          break;
#if HAVE_IRQ_LINKS && TRIGGER_COUNT > 0
        case kF5: {
          // Every term is a real completion of the link this input selected: its
          // declared trigger writes, one ISR read of its declared status word, the
          // dependent RAM store, the handler flag and the CPU's own IRQ take.
          bool both = false;
#if IRQ_BOTH_ENABLED && IRQ_TARGET_LINK_COUNT > 0
          both = is_both_f5(record);
          if (both) {
            // A two-source case: one OR'ed CPU input, two real status reads.
            // Each member target's own status word must have been read at its
            // own address, the stored result must equal that read, each declared
            // clear must have happened with the declared address/value, each
            // member link must have raised its own output, and both raw outputs
            // must be low at the end.  No CPU vector is claimed: the CPU has one
            // external input, so the vector is the status content the ISR read.
            passed = observation.irq_takes >= 1 && observation.irq_edges >= 1
                && observation.isr_flag && !observation.wait_timeout
                && !observation.level_stuck;
            unsigned total_triggers = 0, total_clears = 0;
            for (unsigned member = 0; member < kIrqBothMemberCount && passed;
                 ++member) {
              const unsigned link = kIrqBothLink[member];
              const unsigned target = kIrqLinkTarget[link];
              const unsigned trigger_count = kIrqBothTriggerCount[member];
              const unsigned trigger_position = kIrqBothTriggerPosition[member];
              const bool cause_declared = kIrqBothCauseDeclared[member] != 0;
              const uint32_t cause_mask = kIrqBothCauseMask[member];
              const bool clear_declared = kIrqBothClearDeclared[member] != 0;
              const uint32_t stored_result = member == 0
                  ? observation.isr_result : observation.isr_result2;
              const uint32_t last_read = observation.ip_targets[target].last_read_data;
              total_triggers += trigger_count;
              total_clears += clear_declared ? 1u : 0u;
              passed = (observation.irq_link_last & (1u << link)) == 0
                  && observation.irq_link_edges[link] >= 1
                  && observation.target_irq_high[target] >= 1
                  && observation.ip_targets[target].reads >= 1
                  && observation.ip_targets[target].last_read_offset
                      == kIrqLinkStatus[link]
                  && stored_result == last_read
                  && observation.ip_targets[target].trigger_writes == trigger_count
                  && observation.ip_targets[target].clear_writes
                      == (clear_declared ? 1u : 0u)
                  && observation.ip_targets[target].last_trigger_offset
                      == kIrqLinkTriggerLast[link]
                  && observation.ip_targets[target].last_trigger_data
                      == word_at(record, trigger_position + trigger_count - 1)
                  && (!clear_declared
                      || (observation.ip_targets[target].last_clear_offset
                              == kIrqBothClearOffset[member]
                          && observation.ip_targets[target].last_clear_data
                              == kIrqBothClearValue[member]))
                  && (!cause_declared || (last_read & cause_mask) != 0);
            }
            passed = passed && observation.trigger_writes == total_triggers
                && observation.clear_writes == total_clears;
          } else
#endif
          {
            const unsigned link = selected_f5_link(record);
            const unsigned trigger_count = kIrqLinkTriggerCount[link];
            const unsigned trigger_base = IRQ_TARGET_LINK_COUNT > 1 ? 1u : 0u;
            const uint32_t status_offset = kIrqLinkStatus[link];
            const bool cause_declared = kIrqLinkCauseDeclared[link] != 0;
            const uint32_t cause_mask = kIrqLinkCauseMask[link];
            const unsigned clear_count = kIrqLinkClearCount[link] != 0
                ? kIrqLinkClearCount[link] : kIrqLinkClearDeclared[link];
            const bool level_link = kIrqLinkLevel[link] != 0;
            // The last declared clear step's own address and value: the case has
            // to end having performed the whole ordered sequence, not just its
            // first write.
            const uint32_t last_clear_offset = clear_count > 1
                ? kIrqLinkClear2Offset[link] : kIrqLinkClearOffset[link];
            const uint32_t last_clear_value = clear_count > 1
                ? kIrqLinkClear2Value[link] : kIrqLinkClearValue[link];
            passed = observation.irq_link_edges[link] >= 1 && observation.irq_takes >= 1
                && observation.trigger_writes == trigger_count
                && observation.clear_writes == clear_count
                // The last clear step really happened at the declared address and
                // value, in order (the classifier advances only on a match).
                && (clear_count == 0
                    || (observation.target_last_clear_offset == last_clear_offset
                        && observation.target_last_clear_data == last_clear_value))
                // The case's transfers went to the target that declared this link:
                // a status read of another target's window is not this link's pass.
                && observation.target_index == int(kIrqLinkTarget[link])
                && observation.target_reads == 1
                && observation.target_read_offset == status_offset
                && observation.isr_result == observation.target_read_data
                && observation.isr_flag && !observation.wait_timeout
                // A reported level storm is never a pass, even after the
                // devices-only reset cleared the line at the take limit.
                && !observation.level_stuck
                && observation.target_last_trigger_offset == kIrqLinkTriggerLast[link]
                && observation.target_last_trigger_data
                    == word_at(record, trigger_base + trigger_count - 1)
                && (!level_link
                    || (observation.irq_level_final & (1u << link)) == 0)
                && (!cause_declared
                    || (observation.target_read_data & cause_mask) != 0)
#if HAVE_PINS
                // A causal pin interrupt: a pad transition the device itself
                // reported happened first, the interrupt edge is not earlier than
                // it, and the asserted source has an enabled pin in its cause mask.
                // Either direction counts: the device's programmed interrupt type
                // decides whether a rise or a fall is the cause.
                && (observation.pad_rise_events + observation.pad_fall_events) >= 1
                && observation.first_irq_tick >= observation.first_transition_tick
                && (observation.irq_cause_pins & observation.inten_at_irq) != 0
#endif
                ;
          }
          break;
        }
#endif
#if HAVE_DMA && DMA_BLOCK_WORDS > 0
        case kF6: {
          // A declared error injection aborts the transfer at the injected beat:
          // that many reads were answered (the last one with ERR) and the writes
          // of the completed beats came before it.  Every later destination word
          // is still the declared sentinel, and the device's own sticky ERR bit
          // is the status readback the criteria below require.
#if DMA_ROUTE_ENABLED && DMA_ROUTE_READ
          const bool injected = kDmaRouteErrorBeat >= 0;
          const unsigned routed_beats = injected
              ? unsigned(kDmaRouteErrorBeat) + 1 : DMA_EXPECTED_READS;
          // The pinned ZipDMA's read side buffers the whole chunk before its
          // write side drains it (measured: four reads then four writes on the
          // fixed register route), so an error injected on any read beat of the
          // block aborts the transfer before a single write lands.
          const unsigned written_beats = injected ? 0u : DMA_EXPECTED_WRITES;
#else
          const bool injected = false;
          const unsigned routed_beats = DMA_EXPECTED_READS;
          const unsigned written_beats = DMA_EXPECTED_WRITES;
#endif
#if DMA_ROUTE_ENABLED && DMA_ROUTE_READ
          bool copied = observation.dma_reads == routed_beats
              && observation.dma_writes == written_beats;
          // A read route lands in RAM: every written destination word has to
          // equal the word the DMA captured on the matching read beat (the
          // target's own PRDATA), not the record payload and not a sentinel.  A
          // word the aborted transfer never reached keeps the sentinel.
          for (unsigned index = 0; index < kDmaBlockWords && copied; ++index)
            copied = index >= written_beats
                ? memory.read(kDmaDestinationBase + 4 * index) == DMA_DEST_SENTINEL
                : memory.read(kDmaDestinationBase + 4 * index)
                      == observation.dma_route_read_capture[index];
#else
          bool copied = observation.dma_reads == DMA_EXPECTED_READS
              && observation.dma_writes == DMA_EXPECTED_WRITES;
#endif
#if DMA_ROUTE_ENABLED && DMA_ROUTE_READ
          // (a read route's destination words were compared above)
#elif DMA_ROUTE_ENABLED
#elif DMA_ROUTE_ENABLED
          // A routed write block does not land in RAM: every declared destination
          // word and both guards must keep the sentinel, and the transfer is
          // proven by the target's own responses plus the evidence readback below.
          for (unsigned index = 0; index < kDmaBlockWords && copied; ++index)
            copied = memory.read(kDmaDestinationBase + 4 * index) == DMA_DEST_SENTINEL;
#else
          for (unsigned index = 0; index < kDmaBlockWords && copied; ++index)
            copied = memory.read(kDmaDestinationBase + 4 * index) == word_at(record, index);
#endif
          // The declared block's bytes, lane by lane: each written exactly once
          // and none left over.  That is a stronger fact than "the word reads
          // back", because a masked write of the same value would pass the word
          // comparison but leave its neighbours in the old value.
          unsigned lane_written = 0, lane_missing = 0;
          for (unsigned byte = 0; byte < 4u * kDmaBlockWords; ++byte) {
            if (observation.dma_dst_lane_hits[byte] == 1) ++lane_written;
            else if (observation.dma_dst_lane_hits[byte] == 0) ++lane_missing;
          }
          passed = copied
#if DMA_ROUTE_ENABLED && DMA_ROUTE_READ
              // A read route reads the routed source: the master's first read
              // is the route address, the target answered every routed read, no
              // routed read was served from RAM, and every written RAM
              // destination word and CPU readback cell equals the captured word.
              && observation.dma_first_read_address == kDmaRouteAddress
              && observation.dma_route_reads == routed_beats
              // A complete transfer routes the whole declared block; an injected
              // error stops it at the declared beat, which is the point of the
              // declaration, so the "all declared reads" term only applies to a
              // transfer that was not aborted.
              && (injected || observation.dma_route_reads == kDmaRouteReads)
              && observation.dma_route_acks == routed_beats
              && observation.dma_route_target_reads == routed_beats
              && observation.dma_route_target_ready == 1
              && observation.dma_ram_reads == 0
              && observation.dma_ram_writes == written_beats
              && observation.dma_route_read_matched == written_beats
              // The CPU destination readback is required for a completed
              // transfer; an aborted one leaves the destination block at its
              // sentinel, so its readback cells legitimately equal it.
              && (injected || observation.dma_route_cpu_written)
              && observation.dma_route_cpu_matched == written_beats
              && observation.dma_route_last_rodata == observation.dma_route_read_value
              && observation.dma_route_before_written
              && observation.dma_route_after_written
              && observation.dma_last_write_address
                  == (written_beats
                          ? kDmaDestinationBase + 4 * (written_beats - 1) : 0u)
              && lane_written == 4u * written_beats
              && lane_missing == 4u * (kDmaBlockWords - written_beats)
              && observation.dma_lane_extra == 0
              && observation.dma_bytes_outside_block == 0
              && observation.dma_guard_lo == DMA_DEST_SENTINEL
              && observation.dma_guard_hi == DMA_DEST_SENTINEL
              // A FIFO read: the declared level before the transfer is the beat
              // count, the declared level after it is zero, and every popped word
              // is the declared word of the port.  The level is the CPU's own
              // readback of the declared field, taken before the DMA was configured
              // and after the completion handler ran.
              && (!kDmaRouteFifo
                  || (observation.tx_fifo_level_before
                          == unsigned(kDmaRouteLevelBefore)
                      // Each accepted read popped exactly one entry, so the level
                      // the transfer leaves is the declared fill minus the reads
                      // it really made (an injected error stops it early).
                      && observation.tx_fifo_level_after
                          == unsigned(kDmaRouteLevelBefore) - routed_beats
                      && observation.dma_route_read_stable == routed_beats
                      && (!kDmaRouteExpectWord
                          || observation.dma_route_fifo_matched
                              == written_beats)))
              // An aperture read: every beat presented the next declared aperture
              // address, and the CPU's own read of every aperture word equals the
              // captured word.
              && (!kDmaRouteAperture
                  || (observation.dma_route_sequence == routed_beats
                      && observation.dma_route_cpu_aper_matched
                          == written_beats))
              // A fixed register read: the register does not change, so every
              // read returns the same word.
              && (kDmaRouteFifo || kDmaRouteAperture
                  || observation.dma_route_read_stable == routed_beats)
              // The declared error injection as it executed: exactly one error
              // response, on the declared beat, with the device's own sticky ERR
              // status bit read back by the completion handler.
              && (!injected
                  || (observation.dma_error_injections == 1
                      && observation.dma_error_beat == kDmaRouteErrorBeat
                      && observation.err_after == 1))
#elif DMA_ROUTE_ENABLED
              && observation.dma_first_read_address == kDmaSourceBase
              // The routed destination, the target's own completed APB writes and
              // the FIFO level the firmware read back are the evidence: an ack
              // alone is never enough.
              && observation.dma_last_write_address == kDmaRouteAddress
              && observation.dma_route_writes == DMA_EXPECTED_WRITES
              && observation.dma_route_acks == DMA_EXPECTED_WRITES
              && observation.dma_route_target_writes == DMA_EXPECTED_WRITES
              && observation.dma_route_target_ready == 1
              && observation.dma_ram_writes == 0
              && observation.dma_guard_lo == DMA_DEST_SENTINEL
              && observation.dma_guard_hi == DMA_DEST_SENTINEL
              && observation.dma_route_before_written
              && observation.dma_route_after_written
              && observation.tx_fifo_level_before == 0
              && observation.tx_fifo_level_after
                  == observation.dma_route_expected_level
              && observation.dma_route_expected_level
                  <= kDmaRouteEvidenceDepth
              // The readback itself says how many pushes the FIFO accepted; a
              // block larger than the declared depth is a partial acceptance and
              // must say so instead of being counted as a full transfer.
              && observation.dma_route_accepted
                  == dma_route_expected_level(observation.tx_fifo_level_before)
              && observation.dma_route_partial
                  == (observation.tx_fifo_level_before + kDmaRoutePushes
                      > kDmaRouteEvidenceDepth)
#else
              && observation.dma_first_read_address == kDmaSourceBase
              && observation.dma_last_write_address == kDmaDestinationBase
                  + 4 * (kDmaBlockWords - 1)
              && lane_written == 4u * kDmaBlockWords && lane_missing == 0
              && observation.dma_lane_extra == 0
              && observation.dma_bytes_outside_block == 0
              && observation.dma_guard_lo == DMA_DEST_SENTINEL
              && observation.dma_guard_hi == DMA_DEST_SENTINEL
#endif
              // The byte enables the device presented are the ones the plan
              // declares: a full-word transfer writes full words, a declared
              // lane transfer writes one declared mask per beat and no full word.
              && (DMA_MASTER_PARTIAL
                      ? (observation.dma_sel_partial == written_beats
                         && observation.dma_sel_full == 0)
                      : (observation.dma_sel_full == written_beats
                         && observation.dma_sel_partial == 0))
              && observation.dma_sel_undeclared == 0
              // The firmware's start write is the one the plan declares; the
              // host counted it only when the value matched DMA_START_WORD.
              && observation.dma_start_seen
              && observation.dma_start_write == kDmaStartWord
              && observation.ctl_config_writes == 3 && observation.ctl_start_writes == 1
#if DMA_CLEAR_DECLARED
              && observation.ctl_clear_writes == 1
#else
              && observation.ctl_clear_writes == 0
#endif
              && observation.ctl_reads == 2 && observation.ctl_reads_before_start == 1
              && observation.ctl_status != 0
              // The completion criterion is the declared control word's busy and
              // error bits, sampled once before the start and once by the ISR;
              // the transfer length alone is not a completion flag.  A declared
              // error injection is the one case where the ERR bit is expected to
              // be set: it is the device's own sticky latch of the injected
              // response, read back by the completion handler.
              && observation.busy_after == 0
              && (injected ? observation.err_after == 1
                           : observation.err_after == 0)
              && observation.isr_result == observation.ctl_status
              && observation.isr_flag && !observation.wait_timeout
              // A reported level storm is never a pass, even when the DMA
              // completion link was the one left asserted.
              && !observation.level_stuck
              && observation.irq_edges >= 1 && observation.irq_takes >= 1
#if DMA_RESPONSE_DELAY > 0
              // A declared response delay has to have been observed, per
              // response: the measured wait is longer than the host's single
              // pending tick by at least the declared number of ticks.
              && observation.dma_acks == observation.dma_reads + observation.dma_writes
              && observation.dma_delayed_acks == observation.dma_reads + observation.dma_writes
              && observation.dma_wait_min >= DMA_RESPONSE_DELAY + 1
              && observation.dma_stall_max_run >= DMA_RESPONSE_DELAY + 1
#endif
              ;
          break;
        }
#endif
        default:
          passed = false;
          break;
      }
      // A trapped retirement belongs to this case: it fails the case, it never
      // aborts the round.
#if F1_TRAP_PROGRAM
      // Except in the declared trap mode, where the one ECALL the program
      // installs *is* the case's witness: the kF1 rule above already compared
      // its record, its CSR readback and the handler's stored words.  A second
      // trap, or a trap anywhere but the slot, still fails the case.
      if (observation.traps
          && !(record.flow == kF1 && observation.traps == 1
               && observation.prog_traps == 1
               && observation.trap_pc == kSlot)) passed = false;
#elif HAVE_RVFI_TRAP_PORT
      if (observation.traps) passed = false;
#endif
      // A CPU whose RVFI face has no trap bit cannot fail this check: there is
      // no observation to fail.  The case line states ``traps unknown`` and the
      // retirement trace (count, order, installed words) is still compared.
      const double case_seconds =
          std::chrono::duration<double>(std::chrono::steady_clock::now() - case_started).count();
      std::string record_text = std::string(flow_name(record.flow)) + ':' + hex8(word_at(record, 0));
      for (unsigned index = 1; index < record.words; ++index)
        record_text += ':' + hex8(word_at(record, index));
      std::cout << "case " << cases << ' ' << (passed ? "observations_passed" : "failed")
                << " flow " << flow_name(record.flow)
                << " record " << record_text
                << " ticks " << (tick - case_tick + 1)
                << " seconds " << seconds_text(case_seconds)
                << " i_fetches " << observation.i_fetches
                << " d_reads " << observation.d_reads
                << " d_writes " << observation.d_writes
                << ' ' << KEY_TARGET_READS << ' ' << observation.target_reads
                << ' ' << KEY_TARGET_WRITES << ' ' << observation.target_writes;
#if IP_COUNT > 1
      // Per-target counters: every case states which declared window it was
      // routed to and what each target's own window carried.  A target the case
      // never selected stays at zero, which is what makes the multi-IP routing
      // an observation instead of a claim.
      std::cout << " target_index " << observation.target_index;
      for (unsigned target_index = 0; target_index < IP_COUNT; ++target_index) {
        std::cout << " target" << target_index << "_reads "
                  << observation.ip_targets[target_index].reads
                  << " target" << target_index << "_writes "
                  << observation.ip_targets[target_index].writes
                  << " target" << target_index << "_ready "
                  << int(observation.ip_targets[target_index].ready)
                  << " target" << target_index << "_last_offset "
                  << hex32(observation.ip_targets[target_index].last_offset)
                  << " target" << target_index << "_last_data "
                  << hex32(observation.ip_targets[target_index].last_data)
                  << " target" << target_index << "_irq_high_ticks "
                  << observation.target_irq_high[target_index];
      }
#endif
#if CPU_BUS_AHB
      // What the address phase really said about this case's beats.  An unknown
      // beat is served but never counted as a fetch or as a data access.
      std::cout << " ahb_beats " << observation.ahb_beats
                << " ahb_unknown " << observation.ahb_unknown
                << " ahb_unknown_reset " << observation.ahb_unknown_reset;
#endif
#if HAVE_PINS
      // The pad model's facts, under neutral names: what the wire was before the
      // case, what it is after, the device's own output and direction ports, and
      // the host driver value that the non-output pins resolved to.
      std::cout << " pad_before " << hex32(observation.pad_before)
                << " pad_after " << hex32(observation.pad_after)
                << " out_before " << hex32(observation.out_before)
                << " out_after " << hex32(observation.out_after)
                << " dir_after " << hex32(observation.dir_after)
                << " ext_value " << hex32(observation.ext_value)
                << " pad_changes " << observation.pad_changes
                << " pad_rise_events " << observation.pad_rise_events
                << " rise_mask " << hex32(observation.rise_mask)
                << " fall_mask " << hex32(observation.fall_mask);
#endif
#if HAVE_PINS && HAVE_PIN_GROUPS
      // The declared pad groups, group by group: what each one presented, how long
      // it held the wire, what it changed and what its declared direction says
      // about the device's own dir port.  A case that ran every declared group
      // states ``pin_groups_executed`` equal to ``pin_groups_declared``.
      std::cout << " pin_groups_declared " << observation.pin_group_declared
                << " pin_groups_executed " << observation.pin_group_executed
                << " pin_groups_ticks " << observation.pin_group_ticks
                << " pin_groups_changes " << observation.pin_group_changes
                << " pin_groups_direction_conflicts "
                << observation.pin_group_conflicts
                << " pin_stimulus_group "
                << (observation.pin_stimulus_group ? "0" : "none");
      for (unsigned index = 0; index < observation.pin_group_declared; ++index) {
        const PinGroupCase &group = observation.pin_groups[index];
        const PinGroupRow &row = kPinGroups[index];
        std::cout << " pin_group" << index << "_name " << row.name
                  << " pin_group" << index << "_kind " << PIN_GROUP_KIND_WORD
                  << " pin_group" << index << "_ext " << hex32(group.ext)
                  << " pin_group" << index << "_direction "
                  << pin_group_direction_name(row.direction)
                  << " pin_group" << index << "_hold_ticks " << row.hold_ticks
                  << " pin_group" << index << "_ticks " << group.ticks
                  << " pin_group" << index << "_changes " << group.changes
                  << " pin_group" << index << "_rise_events " << group.rise
                  << " pin_group" << index << "_fall_events " << group.fall
                  << " pin_group" << index << "_direction_witness "
                  << (group.conflicts ? "contradicted" : "honoured")
                  << " pin_group" << index << "_pad_before "
                  << hex32(group.pad_before)
                  << " pin_group" << index << "_pad_after "
                  << hex32(group.pad_after);
      }
#endif
#if HAVE_SERIAL_PEER
      // The declared peer's own tick-level facts.  The rx family is the frame the
      // host clocked onto the wire (enabled only when the case carried a byte),
      // and the tx family is every frame the host decoded from the device's tx
      // line while the case ran.  ``levels`` is the frame's levels in temporal
      // order, bit 0 first (start bit).
      std::cout << " serial_peer_name " << SERIAL_PEER_NAME
                << " serial_peer_frame " << SERIAL_PEER_FRAME
                << " serial_peer_bit_ticks " << SerialPeer<IP_MODEL>::kBitTicks
                << " serial_peer_idle_level " << SerialPeer<IP_MODEL>::kIdle
                << " serial_rx_frames " << observation.serial_rx_frames
                << " serial_rx_bits " << observation.serial_rx_bits
                << " serial_rx_byte " << hex32(observation.serial_rx_byte)
                << " serial_rx_levels " << hex32(observation.serial_rx_levels)
                << " serial_rx_first_tick " << observation.serial_rx_first_tick
                << " serial_rx_last_tick " << observation.serial_rx_last_tick
                << " serial_rx_parity_bit " << observation.serial_rx_parity
                << " serial_rx_framing_ok "
                << (observation.serial_rx_frames
                        && observation.serial_rx_bits
                               == int(SerialPeer<IP_MODEL>::kFrameBits) ? 1 : 0)
                << " serial_rx_cpu_held_ticks "
                << observation.serial_rx_held_ticks
                << " serial_tx_frames " << observation.serial_tx_frames
                << " serial_tx_bits " << observation.serial_tx_bits
                << " serial_tx_byte " << hex32(observation.serial_tx_byte)
                << " serial_tx_levels " << hex32(observation.serial_tx_levels)
                << " serial_tx_first_tick " << observation.serial_tx_first_tick
                << " serial_tx_last_tick " << observation.serial_tx_last_tick
                << " serial_tx_parity_bit " << observation.serial_tx_parity
                << " serial_tx_framing_ok " << observation.serial_tx_framing_ok
                << " serial_tx_stop_bits_ok " << observation.serial_tx_stop_ok
                << " serial_tx_en_ticks " << observation.serial_tx_en_ticks
                << " serial_tx_en_level " << observation.serial_tx_en_level;
#endif
#if HAVE_EVENT_LAYER
      std::cout << " retires " << observation.retires
                << " rvfi_writebacks " << observation.rvfi_writebacks
                << " rvfi_order_monotonic " << int(observation.rvfi_order_monotonic)
#if HAVE_RVFI_TRAP_PORT
                << " traps " << observation.traps
#else
                // No ``rvfi_trap`` output: the count is not observed.  The
                // word is ``unknown`` so no reader can mistake it for a zero
                // that was really measured.
                << " traps unknown"
#endif
                << " bus_errors " << observation.target_errors;
#endif
#if CPU_BUS_AXI4
      // The CPU really reached the firmware's poll loop: this case's own data
      // loads of the command word, and how many adapter beats it took.
      std::cout << " poll_reads " << observation.poll_reads;
#endif
#if TARGET_HAS_AXI4LITE
      // The same transaction under its protocol-neutral name and its own channel
      // counters.  A response code is only printed for a transaction that reached
      // its B or R channel; printing a zero default would look like an observed
      // beat, so the field is absent until the channel handshook.  A mixed build
      // prints this channel group for every case (the five channels are this
      // build's AXI4-Lite target's, so a case routed to another target states
      // zero handshakes, which is what happened) and names the routed target's
      // protocol beside it.  The shared neutral words (target_transfers and
      // target_error) are printed by exactly one protocol group: the AXI4-Lite
      // one when this build has an AXI4-Lite target (the historical pair's
      // spelling), otherwise by the Wishbone or TL-UL group below.
#if TARGET_NEUTRAL_COUNTERS_AXI
      std::cout << ' ' << KEY_TARGET_TRANSFERS << ' '
                << (observation.target_reads + observation.target_writes);
#endif
      std::cout << " axi_aw " << observation.axi_aw << " axi_w " << observation.axi_w
                << " axi_b " << observation.axi_b << " axi_ar " << observation.axi_ar
                << " axi_r " << observation.axi_r;
#if TARGET_NEUTRAL_COUNTERS_AXI
      std::cout << " target_error "
                << (observation.axi_resp_non_okay ? "observed" : "unknown");
#else
      // Another protocol group states the shared target_error word for this
      // build; this channel's own observation is named so it is not confused
      // with it.
      std::cout << " axi_error "
                << (observation.axi_resp_non_okay ? "observed" : "unknown");
#endif
      if (observation.target_resp || observation.axi_b || observation.axi_r)
        std::cout << " target_resp " << observation.target_resp;
      if (observation.axi_w) std::cout << " target_wstrb " << observation.target_wstrb;
#endif
#if TARGET_HAS_WISHBONE
      // The neutral transaction group plus this build's own Wishbone handshake
      // counters.  A classic Wishbone target whose profile declares
      // ``has_error: false`` has no error channel, so the word stays unknown
      // rather than claiming a clean one.  The shared neutral words are printed
      // here only when this build has no AXI4-Lite target (see above).
#if TARGET_NEUTRAL_COUNTERS_WB
      std::cout << ' ' << KEY_TARGET_TRANSFERS << ' '
                << (observation.target_reads + observation.target_writes);
#endif
      std::cout << " wb_acks " << observation.wb_acks
                << " wb_stb_pulses " << observation.wb_stb_pulses
                << " wb_stalls " << observation.wb_stalls;
#if TARGET_NEUTRAL_COUNTERS_WB
      std::cout << " target_error unknown";
#else
      std::cout << " wb_error unknown";
#endif
#endif
#if TARGET_HAS_TLUL
      // The neutral transaction group plus the two channels this build sampled.
      // ``target_error`` states a real observation: an error is only claimed when
      // the target's own D channel carried ``d_error``.  The shared neutral words
      // are printed here only when this build has no AXI4-Lite and no Wishbone
      // target (see above).
#if TARGET_NEUTRAL_COUNTERS_TLUL
      std::cout << ' ' << KEY_TARGET_TRANSFERS << ' '
                << (observation.target_reads + observation.target_writes);
#endif
      std::cout << " tlul_a_handshakes " << observation.tlul_a_handshakes
                << " tlul_d_handshakes " << observation.tlul_d_handshakes
                << " tlul_errors " << observation.tlul_errors;
#if TARGET_NEUTRAL_COUNTERS_TLUL
      std::cout << " target_error "
                << (observation.tlul_errors ? "observed" : "unknown");
#else
      std::cout << " tlul_error "
                << (observation.tlul_errors ? "observed" : "unknown");
#endif
#endif
#if TARGET_HAS_AHB
      // The neutral transaction group plus this build's own AHB-Lite phase
      // counters.  The shared neutral words are printed here only when this build
      // has no AXI4-Lite, Wishbone or TL-UL target (see above), so every build
      // that existed before this protocol keeps the line it always printed.  The
      // error word can only ever be unknown: the pinned wrapper drives HRESP from
      // a tied-low ``err`` input (sha256_ctrl.sv: .err(1'b0)) and its profile
      // declares has_error false, so a zero pin is not evidence of a clean bus.
#if TARGET_NEUTRAL_COUNTERS_AHB
      std::cout << ' ' << KEY_TARGET_TRANSFERS << ' '
                << (observation.target_reads + observation.target_writes);
#endif
      std::cout << " ahb_address_phases " << observation.ahb_address_phases
                << " ahb_data_phases " << observation.ahb_data_phases;
#if TARGET_NEUTRAL_COUNTERS_AHB
      std::cout << " target_error unknown";
#else
      std::cout << " ahb_error unknown";
#endif
#endif
#if TARGET_PROTOCOL_VERBOSE
      // Which target protocol carried this case.  A case with no target access
      // (an F3 store, an F2 RAM read, a RAM-only F6) states ``none``: the word
      // describes the bridge that carried the transfer, not the build.
      std::cout << " target_protocol "
                << (observation.target_index < 0 ? "none"
                    : ip_protocol_word(observation.target_index));
#endif
      if (record.flow == kF1)
        std::cout << " fetch " << hex32(observation.slot_fetch_address)
                  << " retire_pc " << hex32(observation.slot_retire_pc)
                  << " retire_insn " << hex32(observation.slot_retire_insn)
                  << " successor_pc " << hex32(observation.slot_successor_pc)
                  // The short program: its own words that really retired, the
                  // registers the CPU wrote back, its last writeback, any trap
                  // inside the program and the declared data window it changed.
                  << " prog_words " << record.words
                  << " prog_retires " << observation.prog_retires
                  << " prog_pc_ordered " << int(observation.prog_pc_ordered)
                  << " prog_insns_match " << int(observation.prog_insns_match)
                  << " prog_writebacks " << observation.prog_writebacks
                  << " prog_rd_mask " << hex32(observation.prog_rd_mask)
                  << " prog_last_rd " << observation.prog_last_rd
                  << " prog_last_wdata " << hex32(observation.prog_last_wdata)
                  << " prog_last_pc " << hex32(observation.prog_last_pc)
                  << " prog_last_insn " << hex32(observation.prog_last_insn)
#if HAVE_RVFI_TRAP_PORT
                  << " prog_traps " << observation.prog_traps
#else
                  // Unobservable without the CPU's trap bit; the retirement
                  // trace below is what the program is judged on.
                  << " prog_traps unknown"
#endif
                  << " data_hash_before " << hex32(observation.data_hash_before)
                  << " data_hash_after " << hex32(observation.data_hash_after)
                  << " data_changed " << observation.data_changed
#if F1_RV64
                  // The RV64 record's own values, not the low-32 projection: the
                  // host's PC and last writeback as the 64-bit RVFI record
                  // carried them.
                  << " prog_last_wdata64 " << hex64(observation.prog_last_wdata64)
                  << " prog_last_pc64 " << hex64(observation.prog_last_pc64)
#endif
#if F1_TRAP_PROGRAM
                  // The trap witness: the RVFI record's own cause/intr/mode for
                  // the ECALL, the CSR readback the scoreboard registered, and
                  // the words the firmware's handler stored to RAM.
                  << " trap_count " << observation.trap_count
                  << " trap_pc " << hex32(observation.trap_pc)
                  << " trap_insn " << hex32(observation.trap_insn)
                  << " trap_cause " << hex64(observation.trap_cause)
                  << " trap_intr " << hex64(observation.trap_intr)
                  << " trap_mode " << observation.trap_mode
                  << " rvfi_mcause " << hex64(observation.rvfi_mcause)
                  << " rvfi_mepc " << hex64(observation.rvfi_mepc)
                  << " rvfi_mepc_final " << hex64(observation.rvfi_mepc_final)
                  << " rvfi_mtval " << hex64(observation.rvfi_mtval)
                  << " rvfi_mtvec " << hex64(observation.rvfi_mtvec)
                  << " rvfi_mstatus " << hex64(observation.rvfi_mstatus)
                  << " trap_stored_cause " << hex32(observation.trap_stored_cause)
                  << " trap_stored_epc " << hex32(observation.trap_stored_epc)
                  << " trap_flag " << observation.trap_flag
#endif
          ;
#if F1_TRACED
      if (record.flow == kF1) {
        // The case's retirement evidence, and the data window as it was sampled
        // immediately before the case.  A branch or jump program retires a
        // subsequence of its installed words, a bounded loop repeats them, and a
        // compressed record retires two instructions per pair word and steps 2
        // bytes for each of them.  The Python reference run is initialized from
        // exactly these window words, and data_hash_before is the host's own FNV
        // over them, so the printed window is tied to the same sample the case
        // states rather than being a second guess.  ``prog_pc_repeat`` counts the
        // retirements whose PC did not advance, so a loop case states the same
        // repeat count the reference trace has.
#if !F1_RV64
        std::cout << " prog_trace_hash " << hex32(observation.prog_trace_hash);
#endif
        std::cout << " prog_trace_count " << observation.prog_trace_count
                  << " prog_pc_order " << int(observation.prog_pc_ordered)
                  << " prog_pc_repeat " << observation.prog_pc_repeat;
#if F1_RV64
        // A 64-bit declaration states the RV64 trace digest instead: the same
        // four fields at the record's own width.  The 32-bit digest is the
        // low-32 projection and is not printed (or claimed) in this mode.
        std::cout << " prog_trace_hash64 " << hex64(observation.prog_trace_hash64);
#endif
        for (unsigned data_index = 0; data_index < PROGRAM_DATA_WORDS; ++data_index)
          std::cout << " prog_data_" << data_index << ' '
                    << hex32(data_before[data_index]);
      }
#endif
      if (record.flow == kF2) {
        std::cout << " read_addr " << hex32(observation.read_address)
                  << " read_value " << hex32(observation.read_value)
                  << " echo_value " << hex32(observation.echo_value)
                  << " read_from "
                  << (observation.read_from_ip ? KEY_READ_FROM_TARGET : "ram")
                  << ' ' << KEY_TARGET_RDATA << ' ' << hex32(observation.target_rdata);
#if !TARGET_PROTOCOL_APB3 || TARGET_PROTOCOLS_MIXED
        // The offset the read channel really carried, printed only when a target
        // read happened: a RAM read performed no target transfer, and a zero
        // default would look like an observed address.  A mixed build prints it
        // for the routed target's own protocol, so this is the address the APB3
        // paddr, the AXI4-Lite araddr, the Wishbone adr or the TL-UL a_address
        // really carried.
        if (observation.target_reads)
          std::cout << ' ' << KEY_TARGET_OFFSET << ' ' << hex32(observation.target_offset)
                    << ' ' << KEY_TARGET_READY << ' ' << int(observation.target_ready);
#endif
#if HAVE_PINS
        // A pin target: the pad as the host resolved it and the device's own
        // synchronizer latch, taken at the tick the read completed, plus whether
        // this case's own stimulus word was applied.
        std::cout << " pad_at_read " << hex32(observation.pad_at_read)
                  << " padin_latch " << hex32(observation.padin_latch_at_read)
                  << " pad_settled " << int(observation.pad_settled)
                  << " pin_stimulus "
                  << (observation.pin_stimulus ? "applied" : "declared_default");
#endif
      }
      if (record.flow == kF3)
        std::cout << " write_addr " << hex32(observation.write_address)
                  << " write_value " << hex32(observation.write_value)
                  << " write_be " << observation.write_be
                  << " ram_before " << hex32(observation.ram_before)
                  << " ram_after " << hex32(ram_after);
      if (record.flow == kF4)
        std::cout << " mmio_addr " << hex32(word_at(record, 0))
                  << " mmio_value " << hex32(word_at(record, 1))
                  << ' ' << KEY_TARGET_OFFSET << ' ' << hex32(observation.target_offset)
                  << ' ' << KEY_TARGET_WDATA << ' ' << hex32(observation.target_wdata)
                  << ' ' << KEY_TARGET_READY << ' ' << int(observation.target_ready);
#if TARGET_HAS_WISHBONE
      // The Wishbone handshake this case's transfer really presented, printed on
      // the flow that carried it.  A RAM-only case printed none of it and keeps
      // its line unchanged, and a mixed build prints it only for a case whose
      // routed target is the Wishbone one: another target's case did not sample
      // this slave's pins, so it must not read as a zero handshake.
      if ((record.flow == kF2 || record.flow == kF4)
          && (observation.target_reads || observation.target_writes)
          && ip_is_wishbone(observation.target_index))
        std::cout << " wb_cyc " << int(observation.wb_cyc)
                  << " wb_stb " << int(observation.wb_stb)
                  << " wb_ack " << int(observation.wb_ack)
                  << " wb_we " << int(observation.wb_we)
                  << " wb_adr " << observation.wb_adr
                  << " wb_dat_w " << hex32(observation.wb_dat_w)
                  << " wb_dat_r " << hex32(observation.wb_dat_r)
                  << " wb_sel " << observation.wb_sel;
#endif
#if TARGET_HAS_AHB
      // Both AHB-Lite phases this case's transfer really presented, printed only
      // for a case whose routed target is the AHB-Lite one: another target's case
      // did not sample this slave's pins.  ``ahb_hresp`` is the sampled pin and
      // carries no error contract (see the counter group above).
      if ((record.flow == kF2 || record.flow == kF4)
          && (observation.target_reads || observation.target_writes)
          && ip_is_ahb(observation.target_index))
        std::cout << " ahb_hsel " << int(observation.ahb_hsel)
                  << " ahb_htrans " << observation.ahb_htrans
                  << " ahb_haddr " << hex32(observation.ahb_haddr)
                  << " ahb_hwrite " << int(observation.ahb_hwrite)
                  << " ahb_hsize " << observation.ahb_hsize
                  << " ahb_hwdata " << hex32(observation.ahb_hwdata)
                  << " ahb_hreadyin " << int(observation.ahb_hreadyin)
                  << " ahb_hreadyout " << int(observation.ahb_hreadyout)
                  << " ahb_hrdata " << hex32(observation.ahb_hrdata)
                  << " ahb_hresp " << int(observation.ahb_hresp);
#endif
#if TARGET_HAS_TLUL
      // The two TL-UL channels this case's transfer really presented, printed
      // only for a case whose routed target is the TL-UL one: another target's
      // case did not sample these channels.
      if ((record.flow == kF2 || record.flow == kF4)
          && (observation.target_reads || observation.target_writes)
          && ip_is_tlul(observation.target_index))
        std::cout << " tlul_a_valid " << int(observation.tlul_a_valid)
                  << " tlul_a_ready " << int(observation.tlul_a_ready)
                  << " tlul_a_opcode " << observation.tlul_a_opcode
                  << " tlul_a_address " << hex32(observation.tlul_a_address)
                  << " tlul_a_mask " << observation.tlul_a_mask
                  << " tlul_a_data " << hex32(observation.tlul_a_data)
                  << " tlul_d_valid " << int(observation.tlul_d_valid)
                  << " tlul_d_ready " << int(observation.tlul_d_ready)
                  << " tlul_d_data " << hex32(observation.tlul_d_data)
                  << " tlul_d_error " << int(observation.tlul_d_error);
#endif
#if IRQ_TARGET_LINK_COUNT > 0
      if (record.flow == kF5) {
        bool both = false;
        unsigned both_link0 = 0, both_index = 0;
        unsigned declared_triggers = 0;
#if IRQ_BOTH_ENABLED && IRQ_TARGET_LINK_COUNT > 0
        both = is_both_f5(record);
        if (both) {
          both_link0 = kIrqBothLink[0];
          both_index = IRQ_BOTH_LINK_INDEX;
          declared_triggers = IRQ_BOTH_TRIGGER_WORDS;
        }
#endif
        const unsigned link = both ? both_link0 : selected_f5_link(record);
        if (!both) declared_triggers = kIrqLinkTriggerCount[link];
        std::cout << " trigger_writes " << declared_triggers
                  << ' ' << KEY_TARGET_READ_OFFSET << ' '
                  << hex32(observation.target_read_offset)
                  << ' ' << KEY_TARGET_READ_DATA << ' '
                  << hex32(observation.target_read_data)
                  << ' ' << KEY_TARGET_LAST_WRITE_OFFSET << ' '
                  << hex32(observation.target_last_write_offset)
                  << ' ' << KEY_TARGET_LAST_WRITE_DATA << ' '
                  << hex32(observation.target_last_write_data)
                  << " irq_edges " << observation.irq_edges
                  << " irq_high_ticks " << observation.irq_high
                  << " device_high_ticks " << observation.irq_high
                  << " delivered_high_ticks " << observation.irq_delivered_high
                  << " irq_takes " << observation.irq_takes
                  << " wait_timeout " << int(observation.wait_timeout)
                  << " isr_result " << hex32(observation.isr_result)
                  << " isr_flag " << int(observation.isr_flag)
                  << " isr_read_addr " << hex32(observation.isr_read_address)
                  << " isr_read_value " << hex32(observation.isr_read_value)
                  << " isr_read_register_kind " << kIrqLinkStatusKind[link]
                  << " trigger_writes_declared " << declared_triggers
                  << " trigger_writes_observed " << observation.trigger_writes
                  << " clear_writes " << observation.clear_writes
                  << " last_trigger_offset " << hex32(observation.target_last_trigger_offset)
                  << " last_trigger_data " << hex32(observation.target_last_trigger_data)
                  << " last_clear_offset " << hex32(observation.target_last_clear_offset)
                  << " last_clear_data " << hex32(observation.target_last_clear_data)
                  << " isr_cause "
                  // Member 0 is a physical link, so its own cause declaration
                  // names the mask for the first stored result too.
                  << (kIrqLinkCauseDeclared[link]
                          ? hex32((both ? observation.isr_result
                                        : observation.target_read_data)
                                  & kIrqLinkCauseMask[link])
                          : std::string("unknown"))
                  << " irq_link " << (both ? both_index : link)
                  // Which declared target the link belongs to.  Printed only for a
                  // multi-declaring build, so a one-target case line (including
                  // the historical multi-link timer one) is unchanged; the entry
                  // checks it against the link's target instead of assuming the
                  // first target.  A both case names its members and targets in
                  // its own group below, because no single target_index describes
                  // an ISR that read two of them.
                  << (IP_F5_TARGET_MULTI && !both
                          ? " irq_link_target " + std::to_string(kIrqLinkTarget[link])
                          : std::string())
                  << " irq_link_edges " << observation.irq_link_edges[link]
                  // A status word whose own profile says a read clears it (PULP
                  // GPIO INTSTATUS) makes a deasserted level with no clear write
                  // explainable; the field appears only for such a link, so the
                  // historical timer/I2C case lines are unchanged.
                  << (kIrqLinkReadClears[link] ? " isr_read_clears 1"
                                               : std::string())
                  << " irq_level_final " << hex32(observation.irq_level_final)
                  // The storm fact, kept beside the final level: the level may
                  // already read 0 because the reported devices-only reset
                  // cleared it, and that reset is never hidden.
                  << " level_stuck " << int(observation.level_stuck)
#if HAVE_PINS
                  // The device-reported transition the interrupt is attributed
                  // to, the enable mask it was gated with and the status word the
                  // device held after the handler's read: all sampled.
                  << " irq_cause_pins " << hex32(observation.irq_cause_pins)
                  << " inten_at_irq " << hex32(observation.inten_at_irq)
                  << " first_rise_tick "
                  << tick_text(observation.first_rise_tick != 0, observation.first_rise_tick)
                  << " first_fall_tick "
                  << tick_text(observation.first_fall_tick != 0, observation.first_fall_tick)
                  << " first_transition_tick "
                  << tick_text(observation.first_transition_tick != 0,
                               observation.first_transition_tick)
                  << " first_irq_tick "
                  << tick_text(observation.first_irq_tick != 0, observation.first_irq_tick)
                  << " status_after_read " << hex32(observation.status_after_read)
#endif
                  ;
#if IRQ_BOTH_ENABLED && IRQ_TARGET_LINK_COUNT > 0
        if (both) {
          // The two-source group: both stored results at both status addresses,
          // both cause masks, each member link's own edge and final raw level,
          // and every member target's read/trigger/clear counters.  This is what
          // the entry's correspondence re-checks; it never claims a CPU vector.
          unsigned observed_triggers = 0, observed_clears = 0;
          std::cout << " both_link " << IRQ_BOTH_LINK_INDEX << " both_members ";
          for (unsigned member = 0; member < kIrqBothMemberCount; ++member) {
            if (member) std::cout << ',';
            std::cout << kIrqBothLink[member];
          }
          std::cout << " both_targets ";
          for (unsigned member = 0; member < kIrqBothMemberCount; ++member) {
            if (member) std::cout << ',';
            std::cout << kIrqBothTarget[member];
          }
          std::cout << " both_link_edges ";
          for (unsigned member = 0; member < kIrqBothMemberCount; ++member) {
            if (member) std::cout << ',';
            std::cout << observation.irq_link_edges[kIrqBothLink[member]];
          }
          for (unsigned member = 0; member < kIrqBothMemberCount; ++member) {
            const unsigned target = kIrqBothTarget[member];
            observed_triggers += observation.ip_targets[target].trigger_writes;
            observed_clears += observation.ip_targets[target].clear_writes;
          }
          std::cout << " both_trigger_writes " << observed_triggers
                    << " both_clear_writes " << observed_clears
                    << " both_level_final " << hex32(observation.irq_link_last)
                    << " isr_result2 " << hex32(observation.isr_result2)
                    << " isr_read_addr2 " << hex32(observation.isr_read_address2)
                    << " isr_read_value2 " << hex32(observation.isr_read_value2)
                    << " isr_read_register_kind2 "
                    << kIrqLinkStatusKind[kIrqBothLink[1]]
                    << " isr_cause2 "
                    << (kIrqBothCauseDeclared[1]
                            ? hex32(observation.isr_result2 & kIrqBothCauseMask[1])
                            : std::string("unknown"));
          for (unsigned target = 0; target < unsigned(IP_COUNT); ++target) {
            std::cout << " target" << target << "_read_offset "
                      << hex32(observation.ip_targets[target].last_read_offset)
                      << " target" << target << "_read_data "
                      << hex32(observation.ip_targets[target].last_read_data)
                      << " target" << target << "_last_trigger_offset "
                      << hex32(observation.ip_targets[target].last_trigger_offset)
                      << " target" << target << "_last_trigger_data "
                      << hex32(observation.ip_targets[target].last_trigger_data)
                      << " target" << target << "_clear_writes "
                      << observation.ip_targets[target].clear_writes
                      << " target" << target << "_last_clear_offset "
                      << hex32(observation.ip_targets[target].last_clear_offset)
                      << " target" << target << "_last_clear_data "
                      << hex32(observation.ip_targets[target].last_clear_data);
          }
        }
#endif
      }
#endif
      // A non-F5/F6 flow can still take an interrupt (for example an F4 store
      // to a timer count that overflows).  Publish the accepted-edge count for
      // every flow so the case classifier can name that interference instead of
      // treating the missing write effect as a device defect.
      if (record.flow != kF5 && record.flow != kF6)
        std::cout << " irq_edges " << observation.irq_edges
                  << " irq_takes " << observation.irq_takes;
#if HAVE_DMA
      if (record.flow == kF6) {
        std::cout << " dma_reads " << observation.dma_reads
                  << " dma_writes " << observation.dma_writes
                  << " dma_first_read_addr " << hex32(observation.dma_first_read_address)
                  << " dma_first_read_value " << hex32(observation.dma_first_read_value)
                  << " dma_last_write_addr " << hex32(observation.dma_last_write_address)
                  << " dma_last_write_value " << hex32(observation.dma_last_write_value)
#if DMA_DEVICE_REPORTED
                  // Which DMA device carried this transfer, on which channel, what
                  // one beat is on it, and how deep the host's response pipeline was
                  // declared and how deep it really got.  A build whose device is
                  // the historical single-channel 32-bit ZipDMA shape prints none of
                  // this, so every saved ZipDMA F6 case line keeps its exact bytes
                  // and this group can only make a line *more* specific.
                  << " dma_device " << DMA_DEVICE_FAMILY
                  << " dma_channels " << unsigned(DMA_DEVICE_CHANNELS)
                  << " dma_channel 0"
                  << " dma_beat_bytes " << unsigned(DMA_DEVICE_BEAT_BYTES)
                  << " dma_max_outstanding " << kDmaOutstanding
                  << " dma_outstanding_peak " << observation.dma_outstanding_peak
#endif
#if DMA_ROUTE_ENABLED && DMA_ROUTE_READ
                  // A read route prints its own facts: the routed source, the
                  // captured PRDATA, the routed/target read counts, and the RAM
                  // read count that proves the routed beat was not served from
                  // RAM.  A write route keeps the line it always printed.
                  << " dma_route_enabled 1"
                  << " dma_route_direction read"
                  << " dma_route_target_index " << unsigned(kDmaRouteTargetIndex)
                  << " dma_route_source " << hex32(kDmaRouteAddress)
                  << " dma_route_offset " << hex32(kDmaRouteOffset)
                  << " dma_route_reads " << observation.dma_route_reads
                  << " dma_route_acks " << observation.dma_route_acks
                  << " dma_route_target_reads " << observation.dma_route_target_reads
                  << " dma_route_target_ready " << observation.dma_route_target_ready
                  << " dma_route_read_value " << hex32(observation.dma_route_read_value)
                  << " dma_route_read_stable " << observation.dma_route_read_stable
                  << " dma_route_read_matched " << observation.dma_route_read_matched
                  << " dma_route_cpu_matched " << observation.dma_route_cpu_matched
                  << " dma_ram_reads " << observation.dma_ram_reads
                  << " dma_ram_writes " << observation.dma_ram_writes
                  << " dma_route_address_mode "
                  << (kDmaRouteAperture ? "aperture" : "fixed")
                  << " dma_route_source_kind "
                  << (kDmaRouteFifo ? "fifo" : "register")
                  // The declared read evidence as measured: the FIFO level the
                  // CPU read back before and after the pops, the word the popped
                  // entries had to carry, and how many captured words were that
                  // word.
                  << " dma_route_level_before " << observation.tx_fifo_level_before
                  << " dma_route_level_after " << observation.tx_fifo_level_after
                  << " dma_route_level_before_declared "
                  << unsigned(kDmaRouteLevelBefore)
                  << " dma_route_level_after_declared "
                  << unsigned(kDmaRouteLevelAfter)
                  << " dma_route_expected_word "
                  << (kDmaRouteExpectWord ? hex32(kDmaRouteExpectValue)
                                          : std::string("none"))
                  << " dma_route_fifo_matched " << observation.dma_route_fifo_matched
                  // The aperture the master really walked: how many beats
                  // presented the next declared address in order, and each
                  // beat's target offset.
                  << " dma_route_sequence " << observation.dma_route_sequence
                  << " dma_route_cpu_aper_matched "
                  << observation.dma_route_cpu_aper_matched
                  // The declared error injection as it executed: whether one was
                  // declared, how many responses carried ERR, and on which beat.
                  << " dma_error_injected "
                  << ((kDmaRouteErrorBeat >= 0) ? 1 : 0)
                  << " dma_error_injections " << observation.dma_error_injections
                  << " dma_error_beat " << observation.dma_error_beat
#elif DMA_ROUTE_ENABLED
                  // The routed transfer as it executed: the declared target and
                  // destination, how many accepted master writes went there, how
                  // many the target answered, and the target's own completed APB
                  // writes.  ``dma_ram_writes`` is the other half of dma_writes.
                  << " dma_route_enabled 1"
                  << " dma_route_target_index " << unsigned(kDmaRouteTargetIndex)
                  << " dma_route_destination " << hex32(kDmaRouteAddress)
                  << " dma_route_offset " << hex32(kDmaRouteOffset)
                  << " dma_route_writes " << observation.dma_route_writes
                  << " dma_route_acks " << observation.dma_route_acks
                  << " dma_route_target_writes " << observation.dma_route_target_writes
                  << " dma_route_target_ready " << observation.dma_route_target_ready
                  << " dma_ram_writes " << observation.dma_ram_writes
                  << " dma_route_expected_level "
                  << observation.dma_route_expected_level
#endif
                  << " ctl_config_writes " << observation.ctl_config_writes
                  << " ctl_start_writes " << observation.ctl_start_writes
                  << " ctl_clear_writes " << observation.ctl_clear_writes
                  << " ctl_reads " << observation.ctl_reads
                  << " ctl_status " << hex32(observation.ctl_status)
                  << " irq_edges " << observation.irq_edges
                  << " irq_high_ticks " << observation.irq_high
                  << " device_high_ticks " << observation.irq_high
                  << " delivered_high_ticks " << observation.irq_delivered_high
                  << " irq_takes " << observation.irq_takes
                  << " wait_timeout " << int(observation.wait_timeout)
                  << " level_stuck " << int(observation.level_stuck)
                  << " isr_result " << hex32(observation.isr_result)
                  << " isr_flag " << int(observation.isr_flag)
                  << " ctl_reads_before_start " << observation.ctl_reads_before_start
                  << " busy_before " << observation.busy_before
                  << " err_before " << observation.err_before
                  << " busy_after " << observation.busy_after
                  << " err_after " << observation.err_after
                  << " dma_clear_declared " << int(DMA_CLEAR_DECLARED)
                  << " dma_status_kind " << DMA_STATUS_KIND
                  << " dma_done_tick "
                  << tick_text(observation.dma_done, observation.dma_done_tick)
                  // The declared transfer shape, printed beside what the host
                  // measured: the plan's start word and block, the declared beat
                  // count and lane pattern, and the declared response delay.
                  << " dma_start_word " << hex32(kDmaStartWord)
                  << " dma_block_words " << kDmaBlockWords
                  << " dma_master_beats_per_word " << unsigned(DMA_MASTER_BEATS_PER_WORD)
                  << " dma_master_partial " << int(DMA_MASTER_PARTIAL)
                  << " dma_lane_count " << unsigned(DMA_MASTER_LANE_COUNT)
                  << " dma_lane_masks " << hex32(dma_lane_mask_word())
                  << " dma_expected_reads " << unsigned(DMA_EXPECTED_READS)
                  << " dma_expected_writes " << unsigned(DMA_EXPECTED_WRITES)
                  << " dma_start_write "
                  << (observation.dma_start_seen
                          ? hex32(observation.dma_start_write)
                          : std::string("none"))
                  // Backpressure as measured, plus the declared expectation so a
                  // reader can see whether a delay was declared at all.
                  << " dma_response_delay_declared " << unsigned(DMA_RESPONSE_DELAY)
                  << " dma_acks " << observation.dma_acks
                  << " dma_delayed_acks " << observation.dma_delayed_acks
                  << " dma_wait_min " << observation.dma_wait_min
                  << " dma_wait_max " << observation.dma_wait_max
                  << " dma_wait_total " << observation.dma_wait_total
                  << " dma_stall_ticks " << observation.dma_stall_ticks
                  << " dma_max_consecutive_stalls " << observation.dma_stall_max_run
                  // Byte enables as the device presented them, and the lane
                  // coverage of the declared destination block.
                  << " dma_sel_full " << observation.dma_sel_full
                  << " dma_sel_partial " << observation.dma_sel_partial
                  << " dma_sel_undeclared " << observation.dma_sel_undeclared
                  << " dma_read_lane_partial " << observation.dma_read_lane_partial;
        {
          unsigned lane_written = 0, lane_missing = 0;
          for (unsigned byte = 0; byte < 4u * kDmaBlockWords; ++byte) {
            if (observation.dma_dst_lane_hits[byte] == 1) ++lane_written;
            else if (observation.dma_dst_lane_hits[byte] == 0) ++lane_missing;
          }
          std::cout <<
#if DMA_ROUTE_ENABLED
              // On a routed build these bytes belong to the RAM destination
              // block, which the routed transfer must leave untouched.  The name
              // says so, instead of reporting the target's pushes as "missing".
              " dma_ram_lane_written " << lane_written
                    << " dma_ram_lane_missing " << lane_missing;
#else
              " dma_lane_written " << lane_written
                    << " dma_lane_missing " << lane_missing;
#endif
        }
        std::cout << " dma_lane_extra " << observation.dma_lane_extra
                  << " dma_bytes_outside_block " << observation.dma_bytes_outside_block
                  << " dma_guard_lo " << hex32(observation.dma_guard_lo)
                  << " dma_guard_hi " << hex32(observation.dma_guard_hi)
                  << " dma_delay_evidence " << dma_delay_evidence(observation)
                  << " dma_stall_expectation "
                  << (DMA_RESPONSE_DELAY ? "declared" : "none_declared")
                  << " dma_stall_expect_min " << unsigned(DMA_STALL_EXPECT_MIN)
                  << " dma_stall_expect_max " << unsigned(DMA_STALL_EXPECT_MAX);
#if DMA_ROUTE_ENABLED && DMA_ROUTE_READ
        // A read route's evidence, as read back by the CPU: the whole register
        // word it read before and after the transfer.  A cell the firmware never
        // wrote is printed as `none`, never as a stale word.
        std::cout << " dma_route_evidence_before "
                  << (observation.dma_route_before_written
                          ? hex32(observation.fifo_status_before)
                          : std::string("none"))
                  << " dma_route_evidence_after "
                  << (observation.dma_route_after_written
                          ? hex32(observation.fifo_status_after)
                          : std::string("none"))
                  << " dma_route_evidence "
                  << ((observation.dma_route_before_written
                       && observation.dma_route_after_written) ? "observed"
                                                              : "missing")
                  << " dma_route_reset_before_case "
                  << int(kDmaRouteResetBeforeCase);
#elif DMA_ROUTE_ENABLED
        // The declared evidence, as read back by the firmware: the whole status
        // word it read before and after the routed transfer, the declared field
        // of each, and the level the declared pushes should leave.  A cell the
        // firmware never wrote is printed as `none`, never as a stale word.
        std::cout << " fifo_status_before "
                  << (observation.dma_route_before_written
                          ? hex32(observation.fifo_status_before)
                          : std::string("none"))
                  << " fifo_status_after "
                  << (observation.dma_route_after_written
                          ? hex32(observation.fifo_status_after)
                          : std::string("none"))
                  << " tx_fifo_level_before " << observation.tx_fifo_level_before
                  << " tx_fifo_level_after " << observation.tx_fifo_level_after
                  << " dma_route_accepted " << observation.dma_route_accepted
                  << " dma_route_partial " << int(observation.dma_route_partial)
                  << " dma_route_evidence "
                  << ((observation.dma_route_before_written
                       && observation.dma_route_after_written) ? "observed"
                                                              : "missing")
                  << " dma_route_reset_before_case "
                  << int(kDmaRouteResetBeforeCase);
#endif
        for (unsigned index = 0; index < kDmaBlockWords; ++index)
          std::cout << " dst" << index << ' ' << hex32(memory.read(kDmaDestinationBase + 4 * index));
#if DMA_ROUTE_ENABLED && DMA_ROUTE_TRACE
        // The routed beat's own protocol trace: the wire the beat crossed, how
        // many routed beats that target completed on its own port, and that
        // protocol's own handshake counters.  Only the routed target's protocol
        // group is printed, so no other protocol's zero is reported as if it had
        // been sampled.  An APB3 route prints none of these and keeps its case
        // line exactly as it was.
        std::cout << " dma_route_protocol " << kDmaRouteProtocol
                  << " dma_route_protocol_transfers "
                  << observation.dma_route_protocol_transfers;
        if constexpr (myfuzz_ip::IpTarget<kDmaRouteTargetIndex>::wishbone) {
          std::cout << " dma_route_wb_acks " << observation.dma_route_wb_acks
                    << " dma_route_wb_stb_pulses "
                    << observation.dma_route_wb_stb_pulses;
        } else if constexpr (myfuzz_ip::IpTarget<kDmaRouteTargetIndex>::tlul) {
          std::cout << " dma_route_tlul_a_handshakes "
                    << observation.dma_route_tlul_a_handshakes
                    << " dma_route_tlul_d_handshakes "
                    << observation.dma_route_tlul_d_handshakes;
        } else if constexpr (myfuzz_ip::IpTarget<kDmaRouteTargetIndex>::axi4lite) {
          std::cout << " dma_route_axi_aw " << observation.dma_route_axi_aw
                    << " dma_route_axi_w " << observation.dma_route_axi_w
                    << " dma_route_axi_b " << observation.dma_route_axi_b
                    << " dma_route_axi_ar " << observation.dma_route_axi_ar
                    << " dma_route_axi_r " << observation.dma_route_axi_r;
        }
#endif
#if DMA_ROUTE_READ
        // The CPU's own readback of the RAM destination block, cell by cell.
        for (unsigned index = 0; index < kDmaBlockWords; ++index)
          std::cout << " dma_route_cpu_dst" << index << ' '
                    << hex32(observation.dma_route_cpu_dst[index]);
        if (kDmaRouteAperture) {
          // The address every routed beat really presented, and the CPU's own
          // read of the same aperture word after the transfer.
          for (unsigned index = 0; index < kDmaBlockWords; ++index)
            std::cout << " dma_route_beat_offset" << index << ' '
                      << hex32(observation.dma_route_beat_offset[index]);
          for (unsigned index = 0; index < kDmaBlockWords; ++index)
            std::cout << " dma_route_cpu_aper" << index << ' '
                      << hex32(observation.dma_route_cpu_aper[index]);
        }
#endif
      }
#endif
      std::cout << '\n';
      // Per-model clock evidence for this case, on its own line so the case line's
      // historical bytes are unchanged.  These are the rising edges the host
      // really applied to each model's clock, with the ratio the header declared:
      // a ratio-R model shows about ticks/R edges.  Nothing here is derived from
      // a bus success.
      std::cout << "clockcase " << cases << " ticks " << (tick - case_tick + 1)
                << " plan " << CLOCK_PLAN_MODE
                << " grid_steps_per_tick " << kGridStepsPerTick
                << " grid_lcm_hz " << CLOCK_GRID_LCM_HZ
                << " cpu_half_ticks " << kCpuHalfTicks
                << " cpu_rises " << (cpu_rises - case_cpu_rises);
      for_each_ip(ip_models, [&](auto constant, auto &) {
        std::cout << " target" << constant() << "_half_ticks "
                  << ip_half_ticks(constant())
                  << " target" << constant() << "_rises "
                  << (ip_rises[constant()] - case_ip_rises[constant()]);
      });
#if HAVE_DMA
      std::cout << " dma_half_ticks " << kDmaHalfTicks
                << " dma_rises " << (dma_rises - case_dma_rises);
#endif
      std::cout << '\n';
      total_target_reads += observation.target_reads;
      total_target_writes += observation.target_writes;
#if TARGET_HAS_WISHBONE
      total_wb_acks += observation.wb_acks;
      total_wb_stalls += observation.wb_stalls;
      total_wb_stb_pulses += observation.wb_stb_pulses;
#endif
#if TARGET_HAS_TLUL
      total_tlul_a += observation.tlul_a_handshakes;
      total_tlul_d += observation.tlul_d_handshakes;
      total_tlul_errors += observation.tlul_errors;
#endif
#if TARGET_HAS_AHB
      total_ahb_address_phases += observation.ahb_address_phases;
      total_ahb_data_phases += observation.ahb_data_phases;
#endif
      for (unsigned target_index = 0; target_index < IP_COUNT; ++target_index) {
        total_ip_reads[target_index] += observation.ip_targets[target_index].reads;
        total_ip_writes[target_index] += observation.ip_targets[target_index].writes;
        total_ip_irq_high[target_index] += observation.target_irq_high[target_index];
        total_ip_irq_delivered[target_index] +=
            observation.target_irq_delivered[target_index];
      }
      total_d_reads += observation.d_reads;
      total_d_writes += observation.d_writes;
      total_fetches += observation.i_fetches;
#if CPU_BUS_AXI4
      total_poll_reads += observation.poll_reads;
#endif
      total_retires += observation.retires;
      total_rvfi_writebacks += observation.rvfi_writebacks;
      total_traps += observation.traps;
      total_target_errors += observation.target_errors;
      total_rvfi_expanded += observation.rvfi_expanded;
      total_rvfi_order_monotonic = total_rvfi_order_monotonic && observation.rvfi_order_monotonic;
#if CPU_BUS_AHB
      total_ahb_beats += observation.ahb_beats;
      total_ahb_unknown += observation.ahb_unknown;
      total_ahb_unknown_reset += observation.ahb_unknown_reset;
#endif
#if TARGET_HAS_AXI4LITE
      total_axi_aw += observation.axi_aw;
      total_axi_w += observation.axi_w;
      total_axi_b += observation.axi_b;
      total_axi_ar += observation.axi_ar;
      total_axi_r += observation.axi_r;
      total_resp_non_okay += observation.axi_resp_non_okay;
      if (observation.axi_w == 1 && observation.target_wstrb == 15) ++total_wstrb_full;
#endif
#if HAVE_IRQ_LINKS
      total_irq_high += observation.irq_high;
      total_irq_delivered_high += observation.irq_delivered_high;
#else
      total_irq_high += observation.ip_irq_high;
#endif
      total_irq_edges += observation.irq_edges;
      total_irq_takes += observation.irq_takes;
#if IRQ_BOTH_ENABLED && IRQ_TARGET_LINK_COUNT > 0
      if (is_both_f5(record)) ++total_both_cases;
#endif
      if (observation.wait_timeout) ++total_wait_timeouts;
#if HAVE_IRQ_LINKS
      for (unsigned index = 0; index < IRQ_SOURCE_COUNT; ++index)
        total_irq_link_edges[index] += observation.irq_link_edges[index];
      if (observation.level_stuck) ++total_level_stuck;
#endif
#if HAVE_DMA
      total_dma_reads += observation.dma_reads;
      total_dma_writes += observation.dma_writes;
      total_ctl_writes += observation.ctl_writes;
      if (observation.dma_done) ++total_dma_done;
      total_busy_high_reads += observation.busy_high_reads;
      if (record.flow == kF6) {
        ++total_dma_f6_cases;
        total_dma_acks += observation.dma_acks;
        total_dma_delayed += observation.dma_delayed_acks;
        total_dma_stall += observation.dma_stall_ticks;
        if (observation.dma_stall_max_run > total_dma_max_stall)
          total_dma_max_stall = observation.dma_stall_max_run;
        total_dma_sel_full += observation.dma_sel_full;
        total_dma_sel_partial += observation.dma_sel_partial;
        total_dma_lane_extra += observation.dma_lane_extra;
        total_dma_outside += observation.dma_bytes_outside_block;
        for (unsigned byte = 0; byte < 4u * kDmaBlockWords; ++byte) {
          if (observation.dma_dst_lane_hits[byte] == 1) ++total_dma_lane_written;
          else if (observation.dma_dst_lane_hits[byte] == 0) ++total_dma_lane_missing;
        }
#if DMA_ROUTE_ENABLED
        total_dma_route_writes += observation.dma_route_writes;
        total_dma_route_acks += observation.dma_route_acks;
        total_dma_route_target_writes += observation.dma_route_target_writes;
        total_dma_ram_writes += observation.dma_ram_writes;
#if DMA_ROUTE_TRACE
        total_dma_route_protocol_transfers +=
            observation.dma_route_protocol_transfers;
#endif
#if DMA_ROUTE_READ
        total_dma_route_reads += observation.dma_route_reads;
        total_dma_route_target_reads += observation.dma_route_target_reads;
        total_dma_ram_reads += observation.dma_ram_reads;
        if (observation.dma_route_reads) ++total_dma_route_f6_cases;
#else
        if (observation.dma_route_writes) ++total_dma_route_f6_cases;
#endif
#endif
      }
#endif
#if HAVE_PINS
      total_pad_changes += observation.pad_changes;
      total_pad_rise_events += observation.pad_rise_events;
      if (observation.pin_stimulus) ++total_pin_stimulus;
#if HAVE_PIN_GROUPS
      total_pin_group_ticks += observation.pin_group_ticks;
      total_pin_group_changes += observation.pin_group_changes;
      total_pin_group_conflicts += observation.pin_group_conflicts;
#endif
#endif
#if HAVE_SERIAL_PEER
      total_serial_rx_frames += observation.serial_rx_frames;
      total_serial_rx_bits += observation.serial_rx_bits;
      total_serial_tx_frames += observation.serial_tx_frames;
      total_serial_tx_framing_ok += observation.serial_tx_framing_ok;
#endif
#if HAVE_PINS
      if (record.flow == kF2 && observation.read_from_ip
          && word_at(record, 0) == kIpBase + IP_PADIN_OFFSET
          && !observation.pad_settled)
        ++total_pad_unsettled_reads;
#endif
      ++cases;
      // A failed case is a recorded fact of this run, not a reason to lose the
      // remaining cases and the summary.
      if (!passed) ++failed_cases;
      // A storm-aborted handler may leave the command word uncleared because the
      // case was already reported as failed; the next install overwrites that
      // word, so it is not a lost mailbox.  Every other flow keeps the invariant.
      if (memory.read(kCommand) != 0 && !observation.level_stuck)
        throw std::runtime_error("CPU did not consume the mailbox");
      if (observation.wait_timeout) {
        // The device may still be counting toward an interrupt the case never
        // saw; reset the devices so the next case starts from a neutral device
        // state.  This is reported as a device reset, not hidden.
        recover_devices();
      }
      if (observation.level_stuck && !level_stuck_recovered) {
        // The handler did not deassert a declared level link.  The case is
        // already failed; reset only the devices so the still-asserted line
        // cannot silently poison the next case.  This is a reported recovery,
        // not a mask: the final level is in the case line.  A storm abort
        // already performed exactly this reset at the take limit, and that one
        // is counted once under device_resets.
        recover_devices();
      }
#if HAVE_IRQ_LINKS
      // The next case starts from a low interrupt baseline; a source that is
      // still asserted belongs to the case that just ended.
      for (IrqLink &link : irq_links) { link.edges = 0; link.remaining = 0; }
#endif
      if (!online) {
        if (cases == records.size()) { normal_finish = true; break; }
        install(records[cases]);
        continue;
      }
      if (cases == records.size()) { normal_finish = true; break; }
      if (!receive(cases)) { normal_finish = true; break; }
    }
    const auto elapsed =
        std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    const bool ok = normal_finish && cases > 0 && failed_cases == 0;
    const uint64_t executed = tick + (tick < kMaxTicks ? 1 : 0);
    std::string link_edge_text;
#if IRQ_SOURCE_COUNT > 0
    for (unsigned index = 0; index < IRQ_SOURCE_COUNT; ++index) {
      if (index) link_edge_text += ',';
      link_edge_text += std::to_string(total_irq_link_edges[index]);
    }
#endif
    // The global link numbering as "link:target" pairs.  A build without target
    // links has no pairs; a one-target one never prints them.
    std::string link_target_text;
#if IRQ_TARGET_LINK_COUNT > 0
    for (unsigned index = 0; index < unsigned(IRQ_TARGET_LINK_COUNT); ++index) {
      if (index) link_target_text += ',';
      link_target_text += std::to_string(index) + ':' +
                          std::to_string(kIrqLinkTarget[index]);
    }
#endif
    // A multi-target build states the target list, each target's totals and,
    // for a target whose output is not wired, that it was observed but not
    // delivered.  A one-target build appends nothing here, so its saved summary
    // line is byte-identical.
    const std::string ip_summary = [&] {
      std::ostringstream text;
#if IP_COUNT > 1
      text << " ip_count " << IP_COUNT << " target_index_scope selected_or_-1";
      text << " ip_windows ";
      for (unsigned index = 0; index < IP_COUNT; ++index) {
        if (index) text << ',';
        text << "target" << index << '=' << hex32(ip_base_of(int(index)))
             << ':' << ip_size_of(int(index));
      }
#if TARGET_PROTOCOLS_MIXED
      // Each target's own protocol and the bridge that carried its transfers.
      // A one-protocol build never prints these, so its saved summary line keeps
      // the fields it always had; a mixed build states the declaration here and
      // the routed protocol per case.
      text << " target_protocols ";
      for (unsigned index = 0; index < IP_COUNT; ++index) {
        if (index) text << ',';
        text << ip_protocol_word(int(index));
      }
      for (unsigned index = 0; index < IP_COUNT; ++index) {
        text << " target" << index << "_protocol " << ip_protocol_word(int(index))
             << " target" << index << "_bridge " << ip_bridge_of(int(index))
             << " target" << index << "_fixed_inputs "
             << ip_fixed_input_count(int(index));
      }
#endif
      for (unsigned index = 0; index < IP_COUNT; ++index) {
        text << " target" << index << "_reads_total " << total_ip_reads[index]
             << " target" << index << "_writes_total " << total_ip_writes[index]
             << " target" << index << "_irq_high_ticks " << total_ip_irq_high[index]
             << " target" << index << "_irq_delivered_ticks "
             << total_ip_irq_delivered[index]
             << " target" << index << "_irq "
             << (!ip_has_irq(int(index)) ? std::string("none")
                 : (ip_irq_delivered(int(index))
                        ? std::string("delivered") : std::string("observe_only")))
             << " target" << index << "_f5 "
             << (ip_has_f5(int(index)) ? "yes" : "no");
      }
#endif
#if TARGET_PROTOCOL_VERBOSE && IP_COUNT == 1
      // A one-target Wishbone/TL-UL build states its own protocol, bridge and
      // sampled-input count: the per-case ``target_protocol`` word is checked
      // against this declaration, and a reader of the summary sees the bridge
      // that carried every transfer without reading the header.
      text << " target_protocols " << ip_protocol_word(0)
           << " target0_protocol " << ip_protocol_word(0)
           << " target0_bridge " << ip_bridge_of(0)
           << " target0_fixed_inputs " << ip_fixed_input_count(0);
#endif
      return text.str();
    }();
    // The declared schedule and the model cycles it produced, on the same
    // measured basis as the per-case clock lines: each model's own rising-edge
    // count, the declared half period in reference half periods and the one
    // simulation-time grid step.  A ratio-R model's cycle count is about the
    // tick count divided by R, which is what makes the ratio an observation.
    const std::string clock_summary = [&] {
      std::ostringstream text;
      text << " clock_plan " << CLOCK_PLAN_MODE
           << " clock_grid_ps " << TIMED_GRID_PS
           << " clock_reference_half_ps " << CLOCK_REFERENCE_HALF_PERIOD_PS
           << " clock_reference_hz " << CLOCK_REFERENCE_HZ
           << " clock_cpu_half_ticks " << kCpuHalfTicks
           << " clock_cpu_cycles " << cpu_rises;
      for_each_ip(ip_models, [&](auto constant, auto &) {
        text << " clock_target" << constant() << "_half_ticks "
             << ip_half_ticks(constant())
             << " clock_target" << constant() << "_cycles " << ip_rises[constant()];
      });
#if HAVE_DMA
      text << " clock_dma_half_ticks " << kDmaHalfTicks
           << " clock_dma_cycles " << dma_rises;
#endif
      text << " clock_cpu_take_witness " << CPU_TAKE_WITNESS
           // The exact grid the half-period counts above are stated in: one host
           // tick advances clock_grid_steps_per_tick steps of 1 / (2 x
           // clock_grid_lcm_hz) seconds, so a target's cycle count divided by the
           // CPU's is the declared rate ratio without any rounding.
           << " clock_grid_steps_per_tick " << kGridStepsPerTick
           << " clock_grid_lcm_hz " << CLOCK_GRID_LCM_HZ;
      return text.str();
    }();
    std::cout << "summary " << (ok ? "observations_passed" : "failed") << " cases " << cases
              << " ticks " << executed << " instruction_fetches " << total_fetches
              << " ram_reads " << total_d_reads << " ram_writes " << total_d_writes
              << ' ' << KEY_TARGET_TRANSFERS << ' '
              << (total_target_reads + total_target_writes)
              << ' ' << KEY_TARGET_READS << ' ' << total_target_reads
              << ' ' << KEY_TARGET_WRITES << ' ' << total_target_writes
              << ip_summary
              << clock_summary
#if TARGET_HAS_AXI4LITE
              << " axi_aw " << total_axi_aw << " axi_w " << total_axi_w
              << " axi_b " << total_axi_b << " axi_ar " << total_axi_ar
              << " axi_r " << total_axi_r
              << " target_wstrb_full " << total_wstrb_full
              << " target_resp_okay " << (total_axi_b + total_axi_r - total_resp_non_okay)
              << " target_resp_non_okay " << total_resp_non_okay
              // BRESP/RRESP are physical pins and are sampled, but this slave has
              // only ever driven OKAY: the error path is stated as unknown, not as
              // a clean bus that was covered.  A build with another sampled
              // protocol group names this channel's word instead, so the shared
              // target_error key is printed once per summary line.
#if TARGET_NEUTRAL_COUNTERS_AXI
              << " target_error unknown"
#else
              << " axi_error unknown"
#endif
#if !TARGET_PROTOCOLS_MIXED
              << " fixed_target_inputs " << IP_FIXED_INPUT_COUNT
#endif
#endif
#if TARGET_HAS_WISHBONE
              // The classic handshake totals of this build's own sampled cycles.
              << " wb_acks " << total_wb_acks
              << " wb_stb_pulses " << total_wb_stb_pulses
              << " wb_stalls " << total_wb_stalls
#if TARGET_NEUTRAL_COUNTERS_WB
              << " target_error unknown"
#else
              << " wb_error unknown"
#endif
#endif
#if TARGET_HAS_TLUL
              << " tlul_a_handshakes " << total_tlul_a
              << " tlul_d_handshakes " << total_tlul_d
              << " tlul_errors " << total_tlul_errors
#if TARGET_NEUTRAL_COUNTERS_TLUL
              << " target_error "
              << (total_tlul_errors ? "observed" : "unknown")
#else
              << " tlul_error "
              << (total_tlul_errors ? "observed" : "unknown")
#endif
#endif
#if TARGET_HAS_AHB
              // The two phases every completed AHB-Lite transfer of this batch
              // presented.  The error word is unknown for the whole batch for the
              // same wrapper fact the case lines state.
              << " ahb_address_phases " << total_ahb_address_phases
              << " ahb_data_phases " << total_ahb_data_phases
#if TARGET_NEUTRAL_COUNTERS_AHB
              << " target_error unknown"
#else
              << " ahb_error unknown"
#endif
#endif
#if HAVE_IRQ_LINKS
              << " irq_high_ticks " << total_irq_high
              << " device_high_ticks " << total_irq_high
              << " delivered_high_ticks " << total_irq_delivered_high
              << " irq_edges " << total_irq_edges << " irq_takes " << total_irq_takes
              << " wait_timeouts " << total_wait_timeouts
              << " level_stuck " << total_level_stuck
              << " device_resets " << recovery_resets
              << " recovery_scope devices_only_cpu_and_ram_retained"
              << " irq_delivery observed"
              << " irq_sources " << IRQ_SOURCE_COUNT
              << " irq_target_links " << IRQ_TARGET_LINK_COUNT
#if IRQ_BOTH_ENABLED && IRQ_TARGET_LINK_COUNT > 0
              << " irq_both_cases " << total_both_cases
#endif
              << " irq_link_edges "
              << (link_edge_text.empty() ? std::string("none") : link_edge_text)
              // The link-to-target mapping of a multi-declaring build, printed as
              // "link:target" pairs.  A one-target build appends nothing, so its
              // saved summary line is unchanged.
              << (IP_F5_TARGET_MULTI ? " irq_link_targets " + link_target_text
                                     : std::string())
#else
              << " ip_irq_high_ticks " << total_irq_high
              << " irq_delivery unknown"
#endif
#if HAVE_DMA
              << " dma observed"
              << " dma_reads " << total_dma_reads << " dma_writes " << total_dma_writes
              << " dma_control_writes " << total_ctl_writes
              // The declared transfer shape of this build, so a saved summary
              // states the block, start word, lane pattern and delay the header
              // rendered even when no F6 case ran.
              << " dma_block_words " << kDmaBlockWords
              << " dma_start_word " << hex32(kDmaStartWord)
              << " dma_master_beats_per_word " << unsigned(DMA_MASTER_BEATS_PER_WORD)
              << " dma_master_partial " << int(DMA_MASTER_PARTIAL)
              << " dma_lane_masks " << hex32(dma_lane_mask_word())
              << " dma_expected_reads " << unsigned(DMA_EXPECTED_READS)
              << " dma_expected_writes " << unsigned(DMA_EXPECTED_WRITES)
              << " dma_response_delay_declared " << unsigned(DMA_RESPONSE_DELAY)
              // What the F6 cases measured.  An empty F6 set keeps every count
              // at zero and the delay evidence unknown.
              << " dma_f6_cases " << total_dma_f6_cases
              << " dma_acks " << total_dma_acks
              << " dma_delayed_acks " << total_dma_delayed
              << " dma_stall_ticks " << total_dma_stall
              << " dma_max_consecutive_stalls " << total_dma_max_stall
              << " dma_sel_full " << total_dma_sel_full
              << " dma_sel_partial " << total_dma_sel_partial
#if DMA_ROUTE_ENABLED
              // The RAM destination block's byte coverage; a routed transfer
              // writes the target, so these stay at zero/untouched.
              << " dma_ram_lane_written " << total_dma_lane_written
              << " dma_ram_lane_missing " << total_dma_lane_missing
#else
              << " dma_lane_written " << total_dma_lane_written
              << " dma_lane_missing " << total_dma_lane_missing
#endif
              << " dma_lane_extra " << total_dma_lane_extra
              << " dma_bytes_outside_block " << total_dma_outside
              << " dma_delay_evidence "
              << (DMA_RESPONSE_DELAY == 0 ? "not_declared"
                  : (total_dma_f6_cases && total_dma_delayed == total_dma_acks
                     ? "observed" : "unknown"))
#if DMA_ROUTE_ENABLED && DMA_ROUTE_READ
              // The declared read route as a whole: the target, the fixed
              // source register, the evidence word and the totals the routed
              // cases produced.  The case lines carry the per-case readback.
              << " dma_route fixed_read"
              << " dma_route_target_index " << unsigned(kDmaRouteTargetIndex)
              << " dma_route_source " << hex32(kDmaRouteAddress)
              << " dma_route_offset " << hex32(kDmaRouteOffset)
              << " dma_route_evidence_offset " << hex32(kDmaRouteEvidenceOffset)
              << " dma_route_reset_before_case " << int(kDmaRouteResetBeforeCase)
              << " dma_route_cases " << total_dma_route_f6_cases
              << " dma_route_reads " << total_dma_route_reads
              << " dma_route_acks " << total_dma_route_acks
              << " dma_route_target_reads " << total_dma_route_target_reads
              << " dma_ram_reads " << total_dma_ram_reads
              << " dma_ram_writes " << total_dma_ram_writes
#if DMA_ROUTE_TRACE
              // The routed target's own adapter protocol and the totals its own
              // protocol trace counted across every routed case.  An APB3 route
              // prints neither, so its summary line is unchanged.
              << " dma_route_protocol " << kDmaRouteProtocol
              << " dma_route_protocol_transfers "
              << total_dma_route_protocol_transfers
#endif
#elif DMA_ROUTE_ENABLED
              // The declared route as a whole: the target, the fixed address, the
              // evidence word's field and depth, and the totals the routed cases
              // produced.  The case lines carry the per-case readback.
              << " dma_route fixed_write"
              << " dma_route_target_index " << unsigned(kDmaRouteTargetIndex)
              << " dma_route_destination " << hex32(kDmaRouteAddress)
              << " dma_route_offset " << hex32(kDmaRouteOffset)
              << " dma_route_evidence_offset " << hex32(kDmaRouteEvidenceOffset)
              << " dma_route_evidence_bits "
              << unsigned(kDmaRouteEvidenceLow) << ':' << unsigned(kDmaRouteEvidenceHigh)
              << " dma_route_evidence_depth " << unsigned(kDmaRouteEvidenceDepth)
              << " dma_route_reset_before_case " << int(kDmaRouteResetBeforeCase)
              << " dma_route_cases " << total_dma_route_f6_cases
              << " dma_route_writes " << total_dma_route_writes
              << " dma_route_acks " << total_dma_route_acks
              << " dma_route_target_writes " << total_dma_route_target_writes
              << " dma_ram_writes " << total_dma_ram_writes
#if DMA_ROUTE_TRACE
              // The routed target's own adapter protocol and the routed protocol
              // transfers it completed, totalled over the batch.
              << " dma_route_protocol " << kDmaRouteProtocol
              << " dma_route_protocol_transfers "
              << total_dma_route_protocol_transfers
#endif
#endif
#else
              << " dma not_present"
#endif
#if CPU_BUS_WISHBONE
              // The one Wishbone master this build drives: its fetch/data
              // identity is the CPU's own mem_instr output, and the multi-bit
              // irq vector is held at zero because no per-bit wiring is declared.
              // An OBI build prints no such word: its saved summary line is the
              // one every earlier binding already produced.
              << " cpu_bus wishbone-single-master"
              << " fetch_marker mem_instr"
              << " cpu_irq_width " << CPU_IRQ_WIDTH
#if CPU_CUSTOM_IRQ
              << " cpu_irq declared_custom_bit_" << CPU_CUSTOM_IRQ_BIT
              << " cpu_irq_observation eoi cpu_irq_delivery edge_to_latched_input"
#else
              << " cpu_irq held_at_zero"
#endif
#endif
#if CPU_BUS_AHB
              // The one AHB-Lite manager this build drives.  The identity of a
              // beat is the address phase the classifier sampled (HTRANS valid
              // and HSEL at the CPU's aggregate HREADY, then HPROT[0]); a beat
              // whose address phase was never observed is counted apart and is
              // not a fetch.  There is no RVFI channel at this boundary, so the
              // summary states the retirement observation as missing rather
              // than inheriting another CPU's evidence word.
              << " cpu_bus ahb-lite-single-manager"
              << " instruction_identity hprot0_at_manager_ready_address_phase"
              << " ahb_beats " << total_ahb_beats
              << " ahb_unknown_beats " << total_ahb_unknown
              << " ahb_unknown_before_bus_reset " << total_ahb_unknown_reset
              << " ahb_instruction_beats " << total_fetches
              << " ahb_data_read_beats " << total_d_reads
              << " ahb_data_write_beats " << total_d_writes
              << " cpu_irq none_exported"
              << " retirement_observation none:ahb_cvw_no_rvfi"
              << " first_fetch "
              << (first_fetch_seen ? hex32(first_fetch_address) : std::string("unknown"))
              << " first_fetch_tick "
              << tick_text(first_fetch_seen, first_fetch_tick)
#endif
#if CPU_BUS_AXI4
              // The one packed AXI4 master this build drives (CVA6).  Fetch and
              // data identity is the pinned configuration's own ARID/RID map (0
              // = I$, everything else = D$), never the address; the counts below
              // are handshakes the two models really made.  The archive exports
              // no RVFI/commit bundle, so retirement is stated as none (not as
              // "missing data" and never inferred from a fetch).
              << " cpu_bus axi4-packed-single-master"
              << " instruction_identity arid0_rid0_at_address_phase"
              // The `cpu_axi_*` spelling is the CPU-side port; the AXI4-Lite
              // target's own taps keep their `axi_*` names so one run never
              // reports two different channels under one word.
              << " cpu_axi_ar " << link.counts().ar
              << " cpu_axi_r " << link.counts().r
              << " cpu_axi_aw " << link.counts().aw
              << " cpu_axi_w " << link.counts().w
              << " cpu_axi_b " << link.counts().b
              << " cpu_axi_ar_instruction " << link.counts().ar_instruction
              << " cpu_axi_ar_data " << link.counts().ar_data
              << " cpu_axi_r_instruction " << link.counts().r_instruction
              << " cpu_axi_r_data " << link.counts().r_data
              << " cpu_axi_beat_requests " << link.traffic().requests
              << " cpu_axi_beat_responses " << link.traffic().responses
              << " cpu_axi_beat_errors " << link.traffic().errors
              << " cpu_axi_w_full_strobe " << link.traffic().full_strobe
              << " cpu_axi_w_partial_strobe " << link.traffic().partial_strobe
#if CPU_IRQ_WIRED
              // The packed AXI4 CPU's two-bit irq_i entry: bit 0 is the
              // machine-external line this host drives from the declared device
              // outputs, bit 1 is the supervisor-external line the profile holds
              // inactive and no composition drives.  The take is observed on the
              // retirement face, so no vector is claimed from the OR'ed line.
              << " cpu_irq driven_bit0_machine_external"
              << " cpu_irq_bit1 not_driven"
#else
              << " cpu_irq held_at_zero"
#endif
#if HAVE_RVFI_ADAPTER
              // The retirement face this build really has: the CPU's exported
              // rvfi_probes_o bundle, the pinned scoreboard cva6_rvfi driving it,
              // and the projection the trace compares (the low 32 bits of the
              // RV64 record).  The adapter's own probe-width output proves the
              // two widths agree; retire_dropped is stated, never hidden.
              << " retirement_observation rvfi:cva6_rvfi_probes"
              << " rvfi_bundle rvfi_probes_o"
              << " rvfi_bundle_width " << unsigned(rvfi.rvfi_probes_width_o)
              << " rvfi_scoreboard cva6_rvfi"
              // What the case trace compares, as the declaration states it:
              // the low-32 projection of the RV32 subset, the RVFI record's own
              // 64-bit fields in the RV64 mode, or the record's trap/cause plus
              // the CSR readback in the declared trap mode.
#if F1_TRAP_PROGRAM
              << " rvfi_projection trap_cause_csr_and_stored_words"
#elif F1_RV64
              << " rvfi_projection native_rv64_record"
#else
              << " rvfi_projection low32_of_rv64"
#endif
              << " rvfi_trap_witness " << (HAVE_RVFI_TRAP_WITNESS ? "cause_intr_mode_csr" : "none")
              << " rvfi_retire_dropped " << int(rvfi.retire_dropped ? 1 : 0)
#else
              << " retirement_observation none:cva6_no_rvfi_exported"
#endif
              << " boot_address " << hex32(CPU_BOOT_ADDRESS)
              << " boot_fetch " << (boot_fetch_seen ? "observed" : "missing")
              << " boot_fetch_tick "
              << tick_text(boot_fetch_seen, boot_fetch_tick)
              << " main_address " << hex32(CPU_MAIN_ADDRESS)
              << " firmware_fetch " << (firmware_fetch_seen ? "observed" : "missing")
              << " firmware_fetch_addr "
              << (firmware_fetch_seen ? hex32(firmware_fetch_address)
                                      : std::string("unknown"))
              << " firmware_fetch_tick "
              << tick_text(firmware_fetch_seen, firmware_fetch_tick)
              << " poll_reads " << total_poll_reads
              << " first_fetch "
              << (first_fetch_seen ? hex32(first_fetch_address) : std::string("unknown"))
              << " first_fetch_tick "
              << tick_text(first_fetch_seen, first_fetch_tick)
              << " first_fetch_arid " << first_fetch_arid
              << " first_fetch_kind "
              << (first_fetch_seen ? "instruction" : "unknown")
#endif
#if HAVE_PINS
              << " pad_changes " << total_pad_changes
              << " pad_rise_events " << total_pad_rise_events
              << " pad_unsettled_reads " << total_pad_unsettled_reads
              << " final_pad " << hex32(pads.value)
              << " final_out " << hex32(pads.out) << " final_dir " << hex32(pads.dir)
              << " pad_driver device_when_dir_high_else_host"
              << " pin_model observed"
              << " pin_stimulus " << (total_pin_stimulus ? "observed" : "declared_default_only")
#endif
#if HAVE_PINS && HAVE_PIN_GROUPS
              // The declared group list as this run executed it: how many groups
              // the declaration states, the per-group tick and change totals, and
              // the direction witnesses the device's own dir port really produced.
              << " pin_group_count " << PIN_GROUP_COUNT
              << " pin_group_ticks " << total_pin_group_ticks
              << " pin_group_changes " << total_pin_group_changes
              << " pin_group_direction_conflicts " << total_pin_group_conflicts
              << " pin_group_driver ordered_declared_groups"
#endif
#if HAVE_SERIAL_PEER
              // The declared peer's own totals: frames the host clocked out at the
              // declared bit period, and frames it decoded from the device's tx
              // line (with the count that was well framed).
              << " serial_peer_frame " << SERIAL_PEER_FRAME
              << " serial_peer_bit_ticks " << SerialPeer<IP_MODEL>::kBitTicks
              << " serial_rx_frames " << total_serial_rx_frames
              << " serial_rx_bits " << total_serial_rx_bits
              << " serial_tx_frames " << total_serial_tx_frames
              << " serial_tx_framing_ok " << total_serial_tx_framing_ok
#endif
              // The two evidence words are derived from the counts this run
              // measured, never written as a constant.
              << " instruction_fetch_evidence " << (total_fetches ? "observed" : "missing")
              << " retirement_evidence " << (total_retires ? "observed" : "missing")
              // Event-layer counts and the tri-state of each event family.  An
              // error response is only observed where a model produces it: the
              // OBI response error wires are host inputs and the DMA model
              // exposes no error output, so the overall word is unknown and the
              // APB target's sampled pslverr is listed per channel.  Every
              // inferred value states its derivation.
              << " ifetch_events " << total_fetches
              << " ifetch_evidence " << (total_fetches ? "observed" : "missing")
              << " retirements " << total_retires
              << " rvfi_writebacks " << total_rvfi_writebacks
              << " rvfi_order_monotonic " << int(total_rvfi_order_monotonic)
              << " rvfi_writeback_evidence " << (total_rvfi_writebacks ? "observed" : "missing")
#if HAVE_RVFI_TRAP_PORT
              << " traps " << total_traps
              << " trap_evidence " << (total_retires ? "observed" : "missing")
#else
              << " traps unknown"
              << " trap_evidence unobservable"
#endif
              << " expanded_insn_events " << total_rvfi_expanded
              << " expanded_insn_evidence " << (total_rvfi_expanded ? "observed" : "missing")
              << ' ' << KEY_TARGET_ERRORS << ' ' << total_target_errors
              << " bus_error unknown"
#if TARGET_PROTOCOLS_MIXED
              // A mixed build states each channel it really samples, one word per
              // channel.  The AXI4-Lite slave's BRESP/RRESP are sampled per
              // transfer, but only OKAY has ever been driven, so that channel
              // stays unknown even though the pins exist; a Wishbone target's
              // cycle has no error pin, and a TL-UL target's d_error is a real
              // sampled output.  The APB3 channel is observed only when its
              // target's trace carries pslverr.  Each word names its own channel,
              // so none stands for another.
#if TARGET_HAS_AXI4LITE
              << " bus_error_axi unknown"
#endif
#if TARGET_HAS_WISHBONE
              << " bus_error_wb unknown"
#endif
#if TARGET_HAS_TLUL
              << " bus_error_tlul unknown"
#endif
#if TARGET_HAS_AHB
              // The AHB-Lite target's HRESP is a real trace pin, but the pinned
              // wrapper drives it from a tied-low err input; the channel is
              // therefore unknown rather than observed-clean.
              << " bus_error_ahb unknown"
#endif
#if TARGET_HAS_APB3 && HAVE_EVENT_LAYER && HAVE_APB_PSLVERR
              << " bus_error_apb observed"
#elif TARGET_HAS_APB3
              << " bus_error_apb unknown"
#endif
#elif TARGET_PROTOCOL_AXI4LITE
              // The AXI4-Lite slave's BRESP/RRESP are sampled per transfer, but
              // only OKAY has ever been driven, so this channel stays unknown
              // even though the pins exist: a clean bus is not what was observed.
              << " bus_error_" TARGET_BUS_CHANNEL " unknown"
#elif TARGET_PROTOCOL_AHB
              // The AHB-Lite target's HRESP pin exists, but the pinned wrapper
              // drives it from a tied-low err input: the channel is unknown, not
              // observed-clean.
              << " bus_error_ahb unknown"
#elif HAVE_EVENT_LAYER && HAVE_APB_PSLVERR
              << " bus_error_apb observed"
#else
              << " bus_error_apb unknown"
#endif
#if CPU_BUS_WISHBONE
              // The one CPU bus of this build: its response error input is a host
              // input with no model output behind it, so the channel is unknown.
              << " bus_error_wb unknown"
#elif CPU_BUS_AHB
              << " bus_error_ahb unknown"
#elif CPU_BUS_AXI4
              // The AXI4 CPU side's rsp_error_i is host-driven (see the event
              // declaration above); the adapter's own DECERR fallback for an
              // unsupported beat is the only producer behind it, so unknown.
              << " bus_error_axi unknown"
#else
              << " bus_error_obi_i unknown bus_error_obi_d unknown"
#endif
#if HAVE_DMA
              << " bus_error_mwb unknown"
#endif
#if IP_CAUSE_DECLARED
              << " irq_cause observed"
#else
              << " irq_cause unknown irq_cause_bits none_declared"
#endif
#if HAVE_DMA
              << " dma_done_events " << total_dma_done
              << " dma_done_evidence " << (total_dma_done ? "observed" : "missing")
              << " dma_done_derivation last_master_write_ack+irq_edge"
              << " dma_busy_port missing"
              << " dma_busy_high_reads " << total_busy_high_reads
              << " dma_busy_evidence " << (total_busy_high_reads ? "observed" : "missing")
              << " dma_status_bits undeclared_in_profile"
#endif
              << " failures " << failed_cases
              << " runtime_seconds " << seconds_text(elapsed) << '\n';
    finalize();
    return ok ? 0 : 1;
  } catch (const std::exception &error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
