# GPIO pin → PADIN → OBI → dependent RAM live feedback

Root executed the unified `configs/search/gpio-shared-f2.json` entry using the state policy. Evidence is retained at `research/input-strategy-audit-20261027/runs/pin-live-20261028/state/{original,fresh}`; existing evidence was not rewritten by the implementation agent.

Original and strict fresh both exited 0. The budget admitted six of eight planned cases: F4, F2, F4, F5 low, F5 low, F2. The first PADIN read was unattributed. The final read produced one certified semantic pin-low relation, attributed to the last actual F5-low admission, through native PADIN sampling, CPU OBI consumption and dependent RAM. Fresh independently revalidated the facts and reported verified session boundary, within-invocation and cross-invocation matching. This is one pin-low relation, not an IRQ acceptance/ISR/retirement closure; IRQ consumption remains unknown.

The original cProfile run took about 163 seconds while the unprofiled fresh execution took 65.42 seconds. These are different measurement conditions and must not be used as a speedup comparison. The profile at `/tmp/myfuzz-gpio-pin-native-20261028.prof` identified overlapping cumulative costs: deepcopy 97.3 seconds, 39 events_since calls 60.1 seconds, and 50 runtime `_stable` calls 58.8 seconds. Those cumulative times overlap and are not additive.

The subsequent narrow software change authenticates each opaque settlement report once and shares that authenticated projection between credit and metrics. Pin observation no longer invokes full runtime `_stable` on every query. Full execution validation remains at runtime begin, submit and finish; the observer still checks actual runner/session/authority/registry/method identity, live process ownership, epochs, native versions and live source attribution. Reports and authorities grant no execution permission. The software change has not itself been native validated at this report's freeze point.

## Optimized state/uniform comparison

Root's subsequent `pin-live-20261028/optimized-compare` run completed both policies with eight actual cases each. State original/fresh execution took 69.728/64.595 seconds; uniform took 54.383/52.725 seconds. Each reported one genuine relation and fully verified strict fresh. Both RTL measurements were 48/189; respectively 1034/1031 replay replies matched. Primary, execution and coverage were comparable. This single-seed observation does not establish a policy winner.

The next narrow change replaces only pin exact-checker input copying with the runner's private synchronous `_event_refs_since` borrowing API. The installed observer pins the method object and code, rejects instance overrides, and detaches the checker output recursively before retaining evidence. Public journal projection remains independent. This later source change requires its own native validation; the comparison above belongs to the earlier frozen source.

## Ten-case native validation after event borrowing

Root completed the later ten-case original and strict fresh run under `pin-live-20261028/borrowed-events`. High and low each produced a genuine semantic relation, and the independently rechecked semantic sets matched. RTL coverage was 48/189 with 1294 matching replay replies. Original/fresh execution took 82.854/80.544 seconds. This establishes the two-value pin/PADIN/OBI/dependent-RAM loop on that frozen source; it does not establish a significant speedup or IRQ acceptance/ISR closure.
