#include "../../scripts/inprocess_ahb_identity.h"
#include <cassert>

int main() {
  AhbIdentity tracker;
  // HPROT[0] belongs to the accepted address phase, not the live bus when
  // the adapter produces its later backend request.
  tracker.edge(false, false, false, 0, 0, false, 0);
  tracker.edge(true, true, true, 2, 0xc0000100u, false, 0);
  tracker.edge(true, false, true, 2, 0x40000000u, true, 1);
  auto first = tracker.classify(0xc0000100u, false);
  assert(first == AhbIdentity::Instruction);
  assert(tracker.classify(0x40000000u, true) == AhbIdentity::Unknown);

  // Completion and the next selected address can share an edge.
  tracker.edge(true, true, true, 2, 0x40000000u, true, 1);
  assert(tracker.classify(0x40000000u, true) == AhbIdentity::Data);
  assert(tracker.classify(0x40000000u, false) == AhbIdentity::Unknown);

  // IDLE/BUSY/non-selected and reset are not address acceptances.
  tracker.edge(true, true, false, 2, 0xc0000000u, false, 0);
  assert(tracker.classify(0x40000000u, true) == AhbIdentity::Unknown);
  tracker.edge(true, true, true, 1, 0xc0000000u, false, 0);
  assert(tracker.classify(0xc0000000u, false) == AhbIdentity::Unknown);
  tracker.edge(true, true, true, 2, 0xc0000000u, false, 0);
  tracker.edge(false, false, false, 0, 0, false, 0);
  assert(tracker.classify(0xc0000000u, false) == AhbIdentity::Unknown);

  // Full 34-bit physical address must remain distinct from the low 32 bits.
  tracker.edge(true, true, true, 2, 0x1c0000000ull, false, 0);
  assert(tracker.classify(0xc0000000u, false) == AhbIdentity::Unknown);
  assert(tracker.classify(0x1c0000000ull, false) == AhbIdentity::Instruction);
}
