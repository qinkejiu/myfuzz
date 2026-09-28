"""G4 scenario campaign matrix, execution accounting, and strict gate.

A provider implements ``search(cell, output, manifest)`` and
``replay(cell, output, manifest)``. It must measure effective search time
inside the search loop, excluding build, setup and corpus replay. The
orchestrator never substitutes wall time for that measurement.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path
import random
import time
from typing import Mapping, Protocol

from .scenario_rfuzz import ScenarioRfuzzExecutor


STRATEGIES = ("dependency_guided", "uniform_source", "independent_drive")
DIRECTIONS = ("CPU_TO_IP_TO_CPU", "IP_TO_CPU_TO_IP")
MINIMUM_G4_SECONDS = 60.0
BOUND_COMPARISON_ENERGY = 8
CAMPAIGN_TESTCASE_WALL_TIME_MS = 5_000


def _campaign_budgeted_factory(factory):
    """Arm the wall clock on each fresh testcase, after fixture preparation."""
    from myfuzz.scenario.contracts import ResourceBudget

    def make_runner():
        runner = factory()
        runner.set_resource_budget(ResourceBudget(
            max_wall_time_ms=CAMPAIGN_TESTCASE_WALL_TIME_MS))
        return runner

    return make_runner


def _replay_saved_failure_trace(genome, factory, expected: dict) -> bool:
    """Compare a saved failure, including the stable prefix of a wall cut."""
    from myfuzz.integration.scenario_rfuzz import _trace_wall_cut
    from myfuzz.integration.scenario_rfuzz_replay import (
        _wall_cut_factory, _wall_cut_mismatch)
    from myfuzz.scenario.replay import ScenarioTrace, record_scenario

    marker = _trace_wall_cut(ScenarioTrace(**expected))
    actual = record_scenario(
        genome, _wall_cut_factory(factory, marker) if marker else factory)
    if marker is not None:
        return (actual.genome_sha256 == expected["genome_sha256"]
                and actual.manifest_sha256 == expected["manifest_sha256"]
                and _wall_cut_mismatch(marker, actual) is None)
    actual_document = json.loads(json.dumps(
        asdict(actual), sort_keys=True, separators=(",", ":")))
    return expected == actual_document


@dataclass(frozen=True)
class CampaignConfig:
    bound_manifest: Path
    independent_manifest: Path
    seconds: float = MINIMUM_G4_SECONDS
    seeds: tuple[int, ...] = (20260927, 20260928, 20260929)

    def __post_init__(self) -> None:
        if not math.isfinite(self.seconds) or not 0 < self.seconds <= 3600:
            raise ValueError("campaign seconds must be in (0, 3600]")
        if len(self.seeds) != 3 or len(set(self.seeds)) != 3 or any(
                type(seed) is not int or seed < 0 for seed in self.seeds):
            raise ValueError("G4 requires three distinct nonnegative integer seeds")
        if Path(self.bound_manifest) == Path(self.independent_manifest):
            raise ValueError("independent drive needs a separate baseline manifest")


@dataclass(frozen=True)
class CampaignCell:
    strategy: str
    direction: str
    seed: int
    requested_seconds: float
    direction_role: str

    @property
    def cell_id(self) -> str:
        return f"{self.strategy}__{self.direction}__seed_{self.seed}"


@dataclass(frozen=True)
class SearchEvidence:
    status: str
    effective_search_seconds: float | None
    seed_status: str
    testcases: int
    local_cycles: Mapping[str, int]
    valid_testcases: int
    completed_chains: int | None
    coverage_count: int
    failures: Mapping[str, int]
    saved_corpus_entries: int
    error: str | None = None
    client_binary_sha256: str | None = None
    applied_source_uses: Mapping[str, int] | None = None
    post_seed_mutation_batches: int | None = None
    post_seed_effective_genotypes: int | None = None
    post_seed_completed_chains: int | None = None


@dataclass(frozen=True)
class ReplayEvidence:
    total_entries: int
    matched_entries: int
    failure_entries: int
    matched_failure_entries: int
    error: str | None = None


class CampaignProvider(Protocol):
    def search(self, cell: CampaignCell, output: Path,
               manifest: Path) -> SearchEvidence: ...

    def replay(self, cell: CampaignCell, output: Path,
               manifest: Path) -> ReplayEvidence: ...


class CampaignBlocked(RuntimeError):
    """A required campaign arm lacks an executable, verified implementation."""


class UniformSourceScenarioExecutor(ScenarioRfuzzExecutor):
    """Select each reachable, mutable upstream source with equal probability.

    Source choice does not inspect observed coverage. The same decoder,
    ownership map, RTL factory and initial corpus are used by the guided arm.
    """

    def __init__(self, *, search_seed: int, **kwargs) -> None:
        super().__init__(**kwargs)
        self._uniform_rng = random.Random(search_seed)
        choices = []
        for template_index, template in enumerate(self.decoder.templates):
            paths = self.decoder.graph.paths_to(
                template.target_id, direction=template.genome.direction)
            for path_index, path in enumerate(paths):
                for source_index, source_id in enumerate(path.source_ids):
                    source = self.decoder.graph.sources[source_id]
                    if self.decoder._choices(template.genome, source):
                        choices.append((template_index, path_index, source_index,
                                        source_id))
        if len({choice[3] for choice in choices}) < 2:
            raise CampaignBlocked(
                "uniform_source needs at least two reachable, mutable upstream sources")
        self._uniform_choices = tuple(choices)

    def mutation_hint(self) -> dict:
        template, path, source, source_id = self._uniform_rng.choice(
            self._uniform_choices)
        self._hint_sequence += 1
        return {"schema_version": "scenario_mutation_hint.v1",
                "run_id": self.run_id, "sequence": self._hint_sequence,
                **self._feedback_hint_fields(),
                "target_id": self.decoder.templates[template].target_id,
                "template": template, "path": path, "source": source,
                "energy": BOUND_COMPARISON_ENERGY}


def _comparison_hint(hint: dict, strategy: str) -> dict:
    """Hold mutation energy constant for the two real-bound G4 arms.

    The base executor retains adaptive energy for other campaigns. This
    controlled G4 comparison isolates source selection from candidate count.
    """
    if strategy in ("dependency_guided", "uniform_source"):
        return {**hint, "energy": BOUND_COMPARISON_ENERGY}
    return dict(hint)


def campaign_matrix(config: CampaignConfig) -> tuple[CampaignCell, ...]:
    return tuple(CampaignCell(
        strategy, direction, seed, config.seconds,
        "budget_group" if strategy == "independent_drive" else "causal_direction")
        for strategy in STRATEGIES for direction in DIRECTIONS
        for seed in config.seeds)


def _campaign_source_identity(config: CampaignConfig) -> dict[str, str | None]:
    """Hash the campaign transport and Rust sources separately from RTL traces."""
    from myfuzz.scenario.host_identity import host_source_identity

    root = Path(__file__).resolve().parents[3]
    paths = (
        "src/myfuzz/integration/scenario_campaign.py",
        "src/myfuzz/integration/cva6_scenario_campaign.py",
        "src/myfuzz/integration/scenario_rfuzz.py",
        "src/myfuzz/integration/scenario_rfuzz_live.py",
        "src/myfuzz/integration/scenario_rfuzz_replay.py",
        "scripts/run_scenario_campaign.py",
        "third_party/rfuzz/upstream/rfuzz_reference/fuzzer/src/main.rs",
        "third_party/rfuzz/upstream/rfuzz_reference/fuzzer/src/mutation/mod.rs",
        "third_party/rfuzz/upstream/rfuzz_reference/fuzzer/src/mutation/scenario.rs",
        "third_party/rfuzz/upstream/rfuzz_reference/fuzzer/src/queue.rs",
        "third_party/rfuzz/upstream/rfuzz_reference/fuzzer/src/run/buffered.rs",
    )
    identity = {path: hashlib.sha256((root / path).read_bytes()).hexdigest()
                for path in paths}
    identity["scenario_host_source_identity_sha256"] = hashlib.sha256(
        json.dumps(host_source_identity(), sort_keys=True,
                   separators=(",", ":")).encode("utf-8")).hexdigest()
    for name, manifest in (("bound_manifest", config.bound_manifest),
                           ("independent_manifest", config.independent_manifest)):
        path = Path(manifest)
        identity[name] = hashlib.sha256(path.read_bytes()).hexdigest() \
            if path.is_file() else None
    # The bound reverse fixture and the two independent baseline seeds are
    # loaded indirectly by the provider. Include their bytes in the frozen
    # campaign identity so an edit between cells invalidates the report.
    def hash_indirect_seed(directory: Path, filename: str) -> str | None:
        path = directory / filename
        if not path.resolve().is_relative_to(directory.resolve()):
            raise ValueError("independent or bound seed path escapes manifest directory")
        return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None

    bound_dir = Path(config.bound_manifest).parent
    for name, filename in (
            ("bound_reverse_seed_ibex",
             "external_gpio_ibex_gpio_closed_two_rounds_variant.json"),
            ("bound_reverse_seed_cva6",
             "cva6_external_two_gpio_campaign_seed.json")):
        identity[name] = hash_indirect_seed(bound_dir, filename)
    baseline = Path(config.independent_manifest)
    if baseline.is_file():
        try:
            baseline_document = json.loads(baseline.read_text(encoding="utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise ValueError("independent baseline manifest is not JSON") from exc
        for key, name in (("cpu_seed", "independent_cpu_seed"),
                          ("reverse_seed", "independent_reverse_seed")):
            filename = baseline_document.get(key)
            if filename is None:
                identity[name] = None
                continue
            if (not isinstance(filename, str) or not filename
                    or Path(filename).name != filename
                    or filename in (".", "..")):
                raise ValueError("independent baseline seed path is invalid")
            identity[name] = hash_indirect_seed(baseline.parent, filename)
    return identity


def _assess_closed_chain(direction: str, events, final_state: Mapping) -> dict | None:
    """Call the independent ordered RTL checker with observed source values."""
    from myfuzz.scenario.checker import (check_cpu_gpio_closed_chain,
                                         check_gpio_cpu_gpio_closed_chain)

    stream = tuple(events)
    if direction == "CPU_TO_IP_TO_CPU":
        writes = [event.get("write_value") for event in stream
                  if event.get("kind") == "mmio_delivery"
                  and event.get("device_id") == "gpio_a"
                  and event.get("offset") == 0x14 and event.get("write") is True
                  and event.get("write_value") != 0]
        if (len(writes) < 2 or any(type(value) is not int
                                   or not 0 < value < 256 for value in writes)):
            return None
        if len(set(writes)) == 1:
            value = writes[0]
            report = dict(check_cpu_gpio_closed_chain(
                stream, final_state, expected_value=value, min_rounds=2))
            report["expected_value"] = value
            return report
        return _assess_cpu_variable_round_chain(stream, final_state)
    if direction == "IP_TO_CPU_TO_IP":
        injections = {name: [event for event in stream
                             if event.get("kind") == "source_injection"
                             and event.get("component") == "gpio_b"
                             and event.get("port") == "gpio_in"
                             and event.get("action_id") == name]
                      for name in ("first-rise", "second-rise")}
        if any(len(items) != 1 for items in injections.values()):
            return None
        first, second = (injections[name][0] for name in
                         ("first-rise", "second-rise"))
        values = (first.get("value"), second.get("value"))
        if (first.get("event_id", 0) >= second.get("event_id", 0)
                or any(type(value) is not int or not 0 < value < 1 << 32
                       for value in values)):
            return None
        report = dict(check_gpio_cpu_gpio_closed_chain(
            stream, final_state, expected_values=values))
        report["expected_values"] = values
        return report
    return None


def _assess_cpu_variable_round_chain(stream: tuple[Mapping, ...],
                                     final_state: Mapping) -> dict:
    """Prove two ordered real Ibex→GPIO A→GPIO B→Ibex rounds.

    Each round's expected byte comes from its accepted CPU MMIO write. The
    checker does not infer an output from that write: it separately observes
    GPIO A, routed GPIO B input, real IRQ and the CPU response transaction.
    """
    findings: list[str] = []
    if any(event.get("kind") == "reset_barrier" for event in stream):
        findings.append("unexpected_reset")
    ids = [event.get("event_id") for event in stream]
    if any(type(item) is not int for item in ids) or ids != sorted(set(ids)):
        findings.append("event_ids_not_strictly_ordered")

    def find(after: int, predicate):
        return next((event for event in stream
                     if event.get("event_id", 0) > after and predicate(event)), None)

    b_prior = 0
    rises: set[int] = set()
    falls: set[int] = set()
    for event in stream:
        if event.get("component") != "gpio_b" or "outputs" not in event:
            continue
        irq = event["outputs"].get("irq")
        if irq == 1 and b_prior == 0:
            rises.add(event["event_id"])
        if irq == 0 and b_prior == 1:
            falls.add(event["event_id"])
        if irq in (0, 1):
            b_prior = irq

    def transaction_identity(event: Mapping) -> tuple:
        tx = event.get("source_transaction", event.get("transaction", {}))
        if not isinstance(tx, Mapping):
            return ()
        return tuple(tx.get(key) for key in (
            "execution_id", "testcase_id", "source_component", "source_epoch",
            "channel_id", "source_sequence"))

    prior_end = 0
    used_transactions: set[tuple] = set()
    values: list[int] = []
    for round_index in range(2):
        write_a = find(prior_end, lambda e:
                       e.get("kind") == "mmio_delivery"
                       and e.get("device_id") == "gpio_a"
                       and e.get("offset") == 0x14 and e.get("write") is True
                       and type(e.get("write_value")) is int
                       and 0 < e["write_value"] < 256)
        if write_a is None:
            findings.append(f"round_{round_index + 1}:cpu_write_a_missing")
            break
        value = write_a["write_value"]
        a_output = find(write_a["event_id"], lambda e:
                        e.get("component") == "gpio_a"
                        and e.get("outputs", {}).get("gpio_out") == value)
        a_delivery = None if a_output is None else find(
            a_output["event_id"], lambda e:
            e.get("kind") == "dataflow_delivery"
            and tuple(e.get("source", ())) == ("gpio_a", "gpio_out")
            and tuple(e.get("target", ())) == ("gpio_b", "gpio_in")
            and e.get("producer_event_id") == a_output["event_id"]
            and e.get("value") == value)
        b_rise = None if a_delivery is None else find(
            a_delivery["event_id"], lambda e:
            e.get("event_id") in rises
            and e.get("inputs", {}).get("gpio_in", -1) & 0xff == value)
        irq_delivery = None if b_rise is None else find(
            b_rise["event_id"], lambda e:
            e.get("kind") == "dataflow_delivery"
            and tuple(e.get("source", ())) == ("gpio_b", "irq")
            and tuple(e.get("target", ())) == ("cpu", "irq")
            and e.get("producer_event_id") == b_rise["event_id"]
            and e.get("value") == 1)
        cpu_take = None if irq_delivery is None else find(
            irq_delivery["event_id"], lambda e:
            e.get("component") == "cpu"
            and e.get("inputs", {}).get("irq") == 1
            and e.get("outputs", {}).get("irq_taken_pre") == 1)
        read_b = None if cpu_take is None else find(
            cpu_take["event_id"], lambda e:
            e.get("kind") == "mmio_delivery"
            and e.get("device_id") == "gpio_b"
            and e.get("offset") == 0x10 and e.get("write") is False
            and e.get("read_value") == value)
        tx = read_b.get("source_transaction", {}) if read_b else {}
        consumed = None if read_b is None else find(
            read_b["event_id"], lambda e:
            e.get("component") == "cpu"
            and e.get("outputs", {}).get("data_rsp_consumed") == 1
            and e["outputs"].get("data_rsp_rdata") == value
            and e["outputs"].get("data_rsp_source_epoch") ==
            tx.get("source_epoch")
            and e["outputs"].get("data_rsp_source_sequence") ==
            tx.get("source_sequence"))
        ram_write = None if consumed is None else find(
            consumed["event_id"], lambda e:
            e.get("kind") == "memory_write"
            and e.get("address") == 0x200 and e.get("value") == value)
        clear_b = None if ram_write is None else find(
            ram_write["event_id"], lambda e:
            e.get("kind") == "mmio_delivery"
            and e.get("device_id") == "gpio_b"
            and e.get("offset") == 0 and e.get("write") is True
            and e.get("write_value", 0) & 1 == 1)
        b_fall = None if clear_b is None else find(
            clear_b["event_id"], lambda e:
            e.get("event_id") in falls)
        cpu_low = None if b_fall is None else find(
            b_fall["event_id"], lambda e:
            e.get("component") == "cpu"
            and e.get("inputs", {}).get("irq") == 0)
        stages = (write_a, a_output, a_delivery, b_rise, irq_delivery, cpu_take,
                  read_b, consumed, ram_write, clear_b, b_fall, cpu_low)
        if any(stage is None for stage in stages):
            names = ("cpu_write_a", "a_output", "a_to_b", "b_irq_rise",
                     "b_to_cpu", "cpu_take", "cpu_read_b", "cpu_consume_rdata",
                     "cpu_ram_write", "cpu_clear_b", "b_irq_fall", "cpu_irq_low")
            findings.append(f"round_{round_index + 1}:" +
                            names[next(i for i, stage in enumerate(stages)
                                       if stage is None)] + "_missing")
            break
        for stage in (write_a, read_b, ram_write, clear_b):
            identity = transaction_identity(stage)
            if not identity or any(item is None for item in identity):
                findings.append(f"round_{round_index + 1}:transaction_identity_missing")
            elif identity in used_transactions:
                findings.append(f"round_{round_index + 1}:transaction_reused")
            used_transactions.add(identity)
        values.append(value)
        prior_end = cpu_low["event_id"]

    pending = final_state.get("pending_responses", {})
    if not isinstance(pending, Mapping) or any(value != 0 for value in pending.values()):
        findings.append("pending_responses_at_end")
    inputs = final_state.get("inputs", {})
    if not isinstance(inputs, Mapping) or inputs.get("cpu", {}).get("irq") != 0:
        findings.append("cpu_irq_high_at_end")
    if b_prior != 0:
        findings.append("gpio_b_irq_high_at_end")
    if len(values) < 2:
        findings.append("too_few_closed_rounds")
    report = {"complete": not findings, "rounds": len(values),
              "findings": findings, "expected_values": tuple(values)}
    if len(set(values)) == 1:
        report["expected_value"] = values[0]
    return report


def _search_manifest_status(receipts) -> str:
    """A cell cannot mix different RTL or host source identities."""
    identities = {receipt.manifest_sha256 for receipt in receipts}
    return "ok" if len(identities) == 1 and None not in identities else "mixed_manifest"


def _post_seed_real_mutation_batches(receipts) -> int:
    """Count later RFuzz buffers that produced at least one RTL observation."""
    if not receipts:
        return 0
    seed_buffer_id = receipts[0].buffer_id
    return len({receipt.buffer_id for receipt in receipts[1:]
                if receipt.buffer_id != seed_buffer_id
                and receipt.genome_sha256 is not None
                and receipt.total_local_ticks > 0
                and receipt.applied_sources})


def _post_seed_effective_genotypes(receipts) -> set[str]:
    """Distinct executable variants after the seed, with real RTL execution."""
    if not receipts or not receipts[0].effective_genome_sha256:
        return set()
    seed_hash = receipts[0].effective_genome_sha256
    return {receipt.effective_genome_sha256 for receipt in receipts[1:]
            if receipt.status in ("complete", "dut_violation")
            and receipt.total_local_ticks > 0
            and receipt.effective_genome_sha256
            and receipt.effective_genome_sha256 != seed_hash}


def _post_seed_completed_causal_chains(receipts, chain_checks) -> int:
    variants = _post_seed_effective_genotypes(receipts)
    complete_trace_hashes = {check["genome_sha256"] for check in chain_checks
                             if check["assessment"]
                             and check["assessment"].get("complete")}
    return sum(receipt.genome_sha256 in complete_trace_hashes
               for receipt in receipts[1:]
               if receipt.status in ("complete", "dut_violation")
               and receipt.total_local_ticks > 0
               and receipt.effective_genome_sha256 in variants)


def _validated_search(cell: CampaignCell, evidence: SearchEvidence) -> None:
    if not isinstance(evidence, SearchEvidence):
        raise ValueError("provider must return SearchEvidence")
    numeric = (evidence.testcases, evidence.valid_testcases,
               evidence.coverage_count,
               evidence.saved_corpus_entries, *evidence.local_cycles.values(),
               *evidence.failures.values())
    if any(type(value) is not int or value < 0 for value in numeric):
        raise ValueError("search counts must be nonnegative integers")
    if evidence.valid_testcases > evidence.testcases:
        raise ValueError("valid testcase count exceeds testcase count")
    if evidence.completed_chains is not None and (
            type(evidence.completed_chains) is not int or evidence.completed_chains < 0
            or evidence.completed_chains > evidence.testcases):
        raise ValueError("completed chain count is invalid")
    if cell.strategy == "independent_drive" and evidence.completed_chains:
        raise ValueError("independent drive cannot claim a bound causal chain")
    if not evidence.local_cycles:
        raise ValueError("per-instance local cycles are required")
    if evidence.effective_search_seconds is not None and (
            not isinstance(evidence.effective_search_seconds, (int, float))
            or not math.isfinite(evidence.effective_search_seconds)
            or not 0 <= evidence.effective_search_seconds <= 3600):
        raise ValueError("effective search seconds are invalid")


def _validated_replay(evidence: ReplayEvidence) -> None:
    if not isinstance(evidence, ReplayEvidence):
        raise ValueError("provider must return ReplayEvidence")
    counts = (evidence.total_entries, evidence.matched_entries,
              evidence.failure_entries, evidence.matched_failure_entries)
    if any(type(value) is not int or value < 0 for value in counts):
        raise ValueError("replay counts must be nonnegative integers")
    if (evidence.matched_entries > evidence.total_entries
            or evidence.failure_entries > evidence.total_entries
            or evidence.matched_failure_entries > evidence.failure_entries):
        raise ValueError("replay counts are inconsistent")


def _gate_failures(cell: CampaignCell, search: SearchEvidence | None,
                   replay: ReplayEvidence | None,
                   search_wall_seconds: float) -> list[str]:
    if search is None:
        return ["search_not_run"]
    failures: list[str] = []
    if search.status != "ok":
        failures.append("search_status_not_ok")
    if search.error:
        failures.append("search_error")
    if search.effective_search_seconds is None:
        failures.append("effective_search_time_unmeasured")
    elif search.effective_search_seconds < max(MINIMUM_G4_SECONDS,
                                               cell.requested_seconds):
        failures.append("search_budget_short")
    if (search.effective_search_seconds is not None
            and search.effective_search_seconds > search_wall_seconds + 0.05):
        failures.append("search_time_unsubstantiated")
    if search.seed_status != "supported":
        failures.append("deterministic_seed_unsupported")
    if search.testcases == 0:
        failures.append("no_testcases")
    if cell.strategy != "independent_drive" and (
            search.testcases <= 9 or search.post_seed_mutation_batches is None
            or search.post_seed_mutation_batches < 2):
        failures.append("insufficient_mutation_batches")
    if cell.strategy != "independent_drive" and (
            search.post_seed_effective_genotypes is None
            or search.post_seed_effective_genotypes < 2):
        failures.append("insufficient_effective_genome_diversity")
    if cell.strategy != "independent_drive" and (
            search.post_seed_completed_chains is None
            or search.post_seed_completed_chains < 1):
        failures.append("no_post_seed_causal_chain")
    if search.completed_chains is None:
        failures.append("causal_chain_unmeasured")
    elif cell.strategy != "independent_drive" and search.completed_chains == 0:
        failures.append("no_verified_causal_chains")
    if any(search.failures.get(kind, 0) for kind in
           ("environment_error", "uncertain_effect")):
        failures.append("unresolved_execution_failures")
    if replay is None or replay.error or replay.total_entries == 0 or (
            replay.total_entries != search.saved_corpus_entries
            or replay.matched_entries != replay.total_entries
            or replay.matched_failure_entries != replay.failure_entries):
        failures.append("corpus_replay_incomplete")
    return failures


def run_scenario_campaign(config: CampaignConfig, output_dir: Path, *,
                          provider: CampaignProvider | None = None) -> dict:
    """Execute all 18 cells and write a report; incomplete work fails closed.

    The provider owns strategy implementation and certifies its effective
    search timer. A missing provider produces an explicit blocked matrix.
    """
    output = Path(output_dir).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("campaign output directory must be new")
    output.mkdir(parents=True)
    source_identity_start = _campaign_source_identity(config)
    cells: list[dict] = []
    for cell in campaign_matrix(config):
        manifest = (config.independent_manifest if cell.strategy == "independent_drive"
                    else config.bound_manifest)
        cell_output = output / cell.cell_id
        search: SearchEvidence | None = None
        replay: ReplayEvidence | None = None
        search_wall = 0.0
        replay_wall = 0.0
        error: str | None = None
        if provider is not None:
            cell_output.mkdir()
            started = time.monotonic()
            try:
                search = provider.search(cell, cell_output, Path(manifest))
                _validated_search(cell, search)
            except CampaignBlocked as exc:
                error = f"blocked: {exc}"
                search = None
            except Exception as exc:
                error = f"search: {type(exc).__name__}: {exc}"
                search = None
            finally:
                search_wall = time.monotonic() - started
            if search is not None:
                started = time.monotonic()
                try:
                    replay = provider.replay(cell, cell_output, Path(manifest))
                    _validated_replay(replay)
                except Exception as exc:
                    error = f"replay: {type(exc).__name__}: {exc}"
                    replay = None
                finally:
                    replay_wall = time.monotonic() - started
        gate_failures = _gate_failures(cell, search, replay, search_wall)
        cells.append({
            **asdict(cell), "cell_id": cell.cell_id,
            "manifest": str(manifest),
            "status": ("blocked" if provider is None or
                       (error is not None and error.startswith("blocked:")) else
                       "error" if error else
                       "complete" if not gate_failures else "incomplete"),
            "search": asdict(search) if search is not None else None,
            "valid_rate": (search.valid_testcases / search.testcases
                           if search is not None and search.testcases else None),
            "replay": asdict(replay) if replay is not None else None,
            "cost": {"search_wall_seconds": search_wall,
                     "replay_wall_seconds": replay_wall,
                     "effective_search_seconds":
                         search.effective_search_seconds if search else None},
            "gate_failures": gate_failures,
            "error": error,
        })
    source_coverage = {}
    for strategy in ("dependency_guided", "uniform_source"):
        for direction in DIRECTIONS:
            group = [cell for cell in cells if cell["strategy"] == strategy
                     and cell["direction"] == direction]
            measured = [cell["search"]["applied_source_uses"]
                        for cell in group if cell["search"] is not None]
            if len(measured) != len(config.seeds) or any(
                    uses is None for uses in measured):
                missing = True
                declared = set()
                used = set()
            else:
                missing = False
                declared = set().union(*(uses.keys() for uses in measured))
                used = {source for source in declared if any(
                    uses.get(source, 0) > 0 for uses in measured)}
            source_coverage[f"{strategy}__{direction}"] = {
                "declared": sorted(declared), "executed": sorted(used),
                "measured": not missing}
            if missing or len(declared) < 2 or used != declared:
                failure = ("direction_source_unmeasured" if missing else
                           "direction_source_not_exercised")
                for cell in group:
                    if failure not in cell["gate_failures"]:
                        cell["gate_failures"].append(failure)
                    if cell["status"] == "complete":
                        cell["status"] = "incomplete"
    effective = sum((cell["cost"]["effective_search_seconds"] or 0)
                    for cell in cells)
    source_identity_end = _campaign_source_identity(config)
    source_identity_stable = source_identity_start == source_identity_end
    report = {
        "schema_version": "scenario_campaign.v1",
        "gate": "G4",
        "gate_status": "complete" if source_identity_stable and all(
            cell["status"] == "complete" for cell in cells) else "incomplete",
        "required_cells": 18,
        "required_effective_search_seconds":
            len(cells) * max(MINIMUM_G4_SECONDS, config.seconds),
        "effective_search_seconds": effective,
        "clock_model": "independent_local_ticks_and_causal_order",
        "cost_clock_model": "host_search_and_replay_wall_seconds",
        "timing_rule": "provider_measured_search_only_excludes_build_setup_replay",
        "global_seed_rule": "supported_only_when_provider_proves_seeded_search",
        "campaign_source_identity": source_identity_start,
        "campaign_source_identity_end": source_identity_end,
        "campaign_source_identity_stable": source_identity_stable,
        "actual_source_coverage": source_coverage,
        "cells": cells,
    }
    (output / "campaign_report.json").write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    return report


class IbexTwoGpioBoundProvider:
    """Run the bound fixtures and the explicitly separate independent baseline."""

    def __init__(self, client_binary: Path | None = None) -> None:
        root = Path(__file__).resolve().parents[3]
        self.client_binary = (Path(client_binary) if client_binary is not None else
                              root / "third_party/rfuzz/upstream/rfuzz_reference/"
                              "fuzzer/target/release/kfuzz")

    @staticmethod
    def _assess_trace_chain(direction: str, events, final_state: Mapping) -> dict | None:
        """Preserve the original Ibex checker while allowing CPU-specific evidence."""
        return _assess_closed_chain(direction, events, final_state)

    @staticmethod
    def _fixture(direction: str, bound_manifest: Path | None = None):
        from myfuzz.scenario.dependency import (DependencyGraph, DependencyRule,
                                                FuzzableSource)
        from myfuzz.scenario.feedback import CoverageTarget
        from myfuzz.scenario.genome import GenomeCodec
        from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder

        if bound_manifest is None:
            root = Path(__file__).resolve().parents[3]
            bound_manifest = root / "configs/scenario/ibex_two_gpio_closed_two_rounds.json"
        bound_manifest = Path(bound_manifest)
        if direction == "CPU_TO_IP_TO_CPU":
            from myfuzz.scenario.examples import make_ibex_two_gpio_runner

            factory = make_ibex_two_gpio_runner
            genome_path = bound_manifest
            if not genome_path.is_file():
                raise CampaignBlocked(f"seed genome is missing: {genome_path}")
            seed = GenomeCodec.decode(genome_path.read_bytes())
            main_image = next((image for image in seed.initial_images
                               if image.image_id == "cpu.main"), None)
            if main_image is None or main_image.data[8:12] != bytes.fromhex("13011000"):
                raise CampaignBlocked("CPU source mask needs the pinned addi instruction")
            runner = factory()
            # Main bit 84 controls the first output (1 or 0). The real IRQ
            # then reaches the vector instruction, whose bit 117 controls
            # whether the later GPIO A output is 3. Restricting these bits
            # keeps both sources genuine prerequisites for out_3.
            vector_image = next((image for image in seed.initial_images
                                 if image.image_id == "cpu.isr.vector"), None)
            if (vector_image is None or
                    vector_image.data[12:16] != bytes.fromhex("93011000")):
                raise CampaignBlocked("CPU ISR source mask needs the pinned addi instruction")
            sources = (
                FuzzableSource("cpu.program", "cpu", "cpu.main", 84, 1,
                               (direction,), "memory_image"),
                FuzzableSource("cpu.isr.vector", "cpu", "cpu.isr.vector", 117, 1,
                               (direction,), "memory_image"),
            )
            source_bindings = (
                ("cpu.program", "memory_image", "cpu", "cpu.main", 84, 1,
                 "initial_image:cpu:cpu.main", 0x10080),
                ("cpu.isr.vector", "memory_image", "cpu", "cpu.isr.vector",
                 117, 1, "initial_image:cpu:cpu.isr.vector", 0x1012c),
            )
            target = CoverageTarget("gpio_a.out_3", "gpio_a", "gpio_out",
                                    0xff, 3)
        elif direction == "IP_TO_CPU_TO_IP":
            from myfuzz.scenario.ip_cpu_ip_example import (
                make_external_gpio_ibex_gpio_runner,
            )

            factory = make_external_gpio_ibex_gpio_runner
            genome_path = (bound_manifest.parent /
                           "external_gpio_ibex_gpio_closed_two_rounds_variant.json")
            if not genome_path.is_file():
                raise CampaignBlocked(f"seed genome is missing: {genome_path}")
            seed = GenomeCodec.decode(genome_path.read_bytes())
            runner = factory()
            sources = (
                FuzzableSource("b.pin8", "gpio_b", "gpio_in", 8, 1,
                               (direction,)),
                FuzzableSource("b.pin9", "gpio_b", "gpio_in", 9, 1,
                               (direction,)),
            )
            source_bindings = (
                ("b.pin8", "source", "gpio_b", "gpio_in", 8, 1,
                 "external_b"),
                ("b.pin9", "source", "gpio_b", "gpio_in", 9, 1,
                 "external_b"),
            )
            target = CoverageTarget("gpio_a.out_0x300", "gpio_a", "gpio_out",
                                    0x300, 0x300)
        else:
            raise CampaignBlocked(f"unsupported direction: {direction}")
        if seed.direction != direction:
            raise CampaignBlocked(f"seed genome direction mismatch: {genome_path}")
        expected_shape = ((330, 20) if direction == "CPU_TO_IP_TO_CPU"
                          else (270, 16))
        if (seed.max_steps, seed.quiesce_steps) != expected_shape:
            raise CampaignBlocked("bound campaign needs fixed closed-two-rounds Genome")
        from myfuzz.scenario.dependency import SourceBinding, SourceBindings

        graph = DependencyGraph(
            sources=sources,
            rules=(DependencyRule(target.target_id,
                                  tuple(source.source_id for source in sources),
                                  "DATA_BINDING"),))
        bindings = SourceBindings(tuple(SourceBinding(*entry)
                                        for entry in source_bindings))
        decoder = GenomeRecordDecoder(
            graph=graph, ownership=runner.ownership,
            templates=(DecoderTemplate(target.target_id, seed),),
            source_bindings=bindings)
        return factory, decoder, (target,), seed

    @staticmethod
    def _independent_fixture(direction: str, manifest: Path):
        """Keep three real RTL instances; give each a local, unbound environment."""
        from myfuzz.scenario.dependency import (DependencyGraph, DependencyRule,
                                                FuzzableSource)
        from myfuzz.scenario.feedback import CoverageTarget
        from myfuzz.scenario.genome import GenomeCodec
        from myfuzz.scenario.gpio_session import OpenTitanGpioSession
        from myfuzz.scenario.ibex_session import IbexCpuSession
        from myfuzz.scenario.memory import MemoryRegion, PersistentMemory
        from myfuzz.scenario.ownership import (InputField, InputOwner,
                                               compile_ownership)
        from myfuzz.scenario.rfuzz_decoder import DecoderTemplate, GenomeRecordDecoder
        from myfuzz.scenario.router import DataflowRouter, DeviceWindow
        from myfuzz.scenario.runner import ScenarioRunner

        manifest = Path(manifest)
        if not manifest.is_file():
            raise CampaignBlocked("independent baseline manifest is missing")
        document = json.loads(manifest.read_text(encoding="utf-8"))
        if (document.get("schema_version") != "scenario_independent_baseline.v1"
                or document.get("local_response_model") != "persistent_shadow_registers"
                or document.get("cross_component_bindings") != []
                or document.get("cpu_irq") != "constant_zero"):
            raise CampaignBlocked("independent baseline manifest is invalid")
        if direction == "CPU_TO_IP_TO_CPU":
            seed_name = document.get("cpu_seed")
            source = FuzzableSource("cpu.program", "cpu", "cpu.main", 84, 8,
                                    (direction,), "memory_image")
            source_binding = ("cpu.program", "memory_image", "cpu", "cpu.main",
                              84, 8, "initial_image:cpu:cpu.main", 0x10080)
            target = CoverageTarget("gpio_b.irq_high", "gpio_b", "irq", 1, 1)
            memory_seed = 47
            mask = document.get("gpio_b_local_irq_setup", {}).get("cpu_group_mask")
        elif direction == "IP_TO_CPU_TO_IP":
            seed_name = document.get("reverse_seed")
            source = FuzzableSource("b.pin9", "gpio_b", "gpio_in", 9, 1,
                                    (direction,))
            source_binding = ("b.pin9", "source", "gpio_b", "gpio_in", 9, 1,
                              "external_b")
            target = CoverageTarget("gpio_a.out_0x300", "gpio_a", "gpio_out",
                                    0x300, 0x300)
            memory_seed = 53
            mask = document.get("gpio_b_local_irq_setup", {}).get("ip_group_mask")
        else:
            raise CampaignBlocked(f"unsupported direction: {direction}")
        if (not isinstance(seed_name, str) or Path(seed_name).name != seed_name
                or type(mask) is not int or mask <= 0 or mask >= 1 << 32):
            raise CampaignBlocked("independent baseline seed or local setup is invalid")
        genome_path = manifest.parent / seed_name
        if not genome_path.is_file():
            raise CampaignBlocked(f"independent seed genome is missing: {genome_path}")
        seed = GenomeCodec.decode(genome_path.read_bytes())
        expected_shape = ((330, 20) if direction == "CPU_TO_IP_TO_CPU"
                          else (270, 16))
        if (seed.direction != direction
                or (seed.max_steps, seed.quiesce_steps) != expected_shape):
            raise CampaignBlocked("independent baseline needs fixed two-round Genome")

        class LocalRegisterModel:
            """Persistent per-testcase CPU response model, never an IP RTL view."""

            def __init__(self):
                self.words: dict[int, int] = {}

            def write_register(self, offset: int, value: int, *, be: int = 15):
                old = self.words.get(offset, 0)
                mask_bytes = sum(0xff << (8 * byte) for byte in range(4)
                                 if be & (1 << byte))
                self.words[offset] = ((old & ~mask_bytes) | (value & mask_bytes)) \
                    & 0xffffffff

            def read_register(self, offset: int) -> int:
                return self.words.get(offset, 0)

        class LocallyConfiguredGpio(OpenTitanGpioSession):
            # The two startup register writes do not add persistent host state.
            # Bound the JSON final-state growth from one operation, including
            # the GPIO session's local tick and pending-settle counters.
            max_final_state_growth_bytes_per_operation = 65536
            max_evidence_record_bytes = 8192

            def begin_case(self, testcase_id: str) -> None:
                super().begin_case(testcase_id)
                self.write_register(0x4, mask)
                self.write_register(0x2c, mask)

        def factory():
            memory = PersistentMemory(
                regions=(MemoryRegion("ram", 0, 0x20000),),
                initialization_seed=memory_seed, max_initialized_bytes=0x20000)
            gpio_a = OpenTitanGpioSession()
            gpio_b = LocallyConfiguredGpio()
            router = DataflowRouter((
                DeviceWindow("gpio_a_local", 0x40001000, 0x1000, LocalRegisterModel()),
                DeviceWindow("gpio_b_local", 0x40000000, 0x1000, LocalRegisterModel())))
            cpu = IbexCpuSession(memory=memory, router=router)
            ownership = compile_ownership(
                (InputField("cpu", "irq", 2), InputField("gpio_a", "gpio_in", 32),
                 InputField("gpio_b", "gpio_in", 32)),
                (InputOwner("cpu", "irq", 0, 2, "fixed", "constant_zero"),
                 InputOwner("gpio_a", "gpio_in", 0, 32, "source", "external_a"),
                 InputOwner("gpio_b", "gpio_in", 0, 32, "source", "external_b")))
            return ScenarioRunner(sessions={"cpu": cpu, "gpio_a": gpio_a,
                                            "gpio_b": gpio_b},
                                  ownership=ownership, bindings=(),
                                  independent_baseline=True)

        runner = factory()
        from myfuzz.scenario.dependency import SourceBinding, SourceBindings

        graph = DependencyGraph(
            sources=(source,),
            rules=(DependencyRule(target.target_id, (source.source_id,),
                                  "BASELINE_GROUPING"),))
        bindings = SourceBindings((SourceBinding(*source_binding),))
        decoder = GenomeRecordDecoder(
            graph=graph, ownership=runner.ownership,
            templates=(DecoderTemplate(target.target_id, seed),),
            source_bindings=bindings)
        return factory, decoder, (target,), seed

    def search(self, cell: CampaignCell, output: Path,
               manifest: Path) -> SearchEvidence:
        if cell.strategy not in STRATEGIES:
            raise CampaignBlocked(f"unknown strategy: {cell.strategy}")
        if not manifest.is_file():
            raise CampaignBlocked("scenario manifest is missing")
        if not self.client_binary.is_file():
            raise CampaignBlocked("pinned Rust RFuzz binary is missing")
        from myfuzz.integration.scenario_rfuzz import ScenarioRfuzzExecutor
        from myfuzz.integration.scenario_rfuzz_live import run_scenario_rfuzz_live
        from myfuzz.scenario.genome import GenomeCodec

        factory, decoder, targets, seed = (
            self._independent_fixture(cell.direction, manifest)
            if cell.strategy == "independent_drive" else
            self._fixture(cell.direction, manifest))
        (output / "seed_genome.json").write_bytes(GenomeCodec.encode(seed) + b"\n")
        if cell.strategy == "independent_drive":
            (output / "baseline_model.json").write_text(json.dumps({
                "schema_version": "scenario_independent_model.v1",
                "cross_component_bindings": [],
                "cpu_mmio_response_model": "persistent_shadow_registers",
                "cpu_irq": "constant_zero",
                "gpio_b_local_irq_setup": "manifest_declared",
                "causal_chain_claim": False,
            }, sort_keys=True) + "\n", encoding="utf-8")
        latest_runner: dict[str, object] = {}
        chain_checks: list[dict] = []

        budgeted_factory = _campaign_budgeted_factory(factory)

        def tracked_factory():
            runner = budgeted_factory()
            latest_runner["runner"] = runner
            return runner

        def assess_trace(trace):
            if cell.strategy == "independent_drive":
                return ()
            runner = latest_runner["runner"]
            assessment = self._assess_trace_chain(
                cell.direction, trace.events, runner.final_state_document())
            chain_checks.append({"genome_sha256": trace.genome_sha256,
                                 "status": trace.status,
                                 "assessment": assessment})
            return ()

        executor_kwargs = dict(run_id=cell.cell_id, decoder=decoder,
                               factory=tracked_factory, targets=targets,
                               checker=assess_trace)
        executor = (UniformSourceScenarioExecutor(
            **executor_kwargs, search_seed=cell.seed)
            if cell.strategy == "uniform_source" else
            ScenarioRfuzzExecutor(**executor_kwargs))
        mutation_selections: list[dict] = []
        original_hint = executor.mutation_hint

        def logged_hint():
            hint = _comparison_hint(original_hint(), cell.strategy)
            mutation_selections.append(dict(hint))
            return hint

        executor.mutation_hint = logged_hint
        (output / "comparison_policy.json").write_text(json.dumps({
            "schema_version": "scenario_comparison_policy.v1",
            "strategy": cell.strategy,
            "search_seed": cell.seed,
            "bound_mutation_energy": (
                BOUND_COMPARISON_ENERGY if cell.strategy != "independent_drive"
                else None),
            "adaptive_energy_in_core": True,
            "testcase_max_wall_time_ms": CAMPAIGN_TESTCASE_WALL_TIME_MS,
            "controlled_difference": (
                "source_selection" if cell.strategy != "independent_drive"
                else "cross_component_bindings_removed"),
        }, sort_keys=True) + "\n", encoding="utf-8")
        result = run_scenario_rfuzz_live(
            executor=executor, client_binary=self.client_binary,
            output_dir=output / "live", duration_seconds=cell.requested_seconds,
            search_seed=cell.seed, max_runs_per_batch=1)
        with (output / "chain_checks.jsonl").open("w", encoding="utf-8") as handle:
            for check in chain_checks:
                handle.write(json.dumps(check, sort_keys=True) + "\n")
        with (output / "mutation_selections.jsonl").open(
                "w", encoding="utf-8") as handle:
            for selection in mutation_selections:
                handle.write(json.dumps(selection, sort_keys=True) + "\n")
        local_cycles: dict[str, int] = {}
        for receipt in executor.receipts:
            for component, ticks in (receipt.local_ticks or {}).items():
                local_cycles[component] = local_cycles.get(component, 0) + ticks
        saved = len(tuple((result.output_dir / "corpus").glob("entry_*.json")))
        valid = sum(receipt.status in ("complete", "dut_violation")
                    for receipt in executor.receipts)
        measured_chains = (0 if cell.strategy == "independent_drive" else
                           sum(bool(check["assessment"]
                                    and check["assessment"]["complete"])
                               for check in chain_checks) if chain_checks else None)
        coverage = sum(any(int(receipt.coverage_hex[2 * index:2 * index + 2], 16)
                           for receipt in executor.receipts)
                       for index in range(len(targets)))
        post_seed_genotypes = _post_seed_effective_genotypes(executor.receipts)
        post_seed_completed_chains = _post_seed_completed_causal_chains(
            executor.receipts, chain_checks)
        return SearchEvidence(
            status=(_search_manifest_status(executor.receipts)
                    if result.client_returncode == 0 else "client_error"),
            effective_search_seconds=result.effective_search_seconds,
            seed_status="supported" if result.client_returncode == 0 else "unverified",
            testcases=result.tests, local_cycles=local_cycles,
            valid_testcases=valid, completed_chains=measured_chains,
            coverage_count=coverage, failures=result.statuses,
            saved_corpus_entries=saved,
            error=("cell receipts used different source manifests"
                   if result.client_returncode == 0 and
                   _search_manifest_status(executor.receipts) != "ok" else
                   None if result.client_returncode == 0 else
                   f"RFuzz exited {result.client_returncode}"),
            client_binary_sha256=hashlib.sha256(
                self.client_binary.read_bytes()).hexdigest(),
            applied_source_uses=executor.applied_source_uses,
            post_seed_mutation_batches=_post_seed_real_mutation_batches(
                executor.receipts),
            post_seed_effective_genotypes=len(post_seed_genotypes),
            post_seed_completed_chains=post_seed_completed_chains)

    def replay(self, cell: CampaignCell, output: Path,
               manifest: Path) -> ReplayEvidence:
        from myfuzz.integration.scenario_rfuzz_replay import replay_scenario_rfuzz_corpus
        from myfuzz.scenario.genome import GenomeCodec

        factory, _, _, _ = (
            self._independent_fixture(cell.direction, manifest)
            if cell.strategy == "independent_drive" else
            self._fixture(cell.direction, manifest))
        budgeted_factory = _campaign_budgeted_factory(factory)
        result = replay_scenario_rfuzz_corpus(output / "live", budgeted_factory)
        failure_dir = output / "live" / "failures"
        failures = sorted(failure_dir.glob("*.json")) if failure_dir.exists() else []
        matched_failures = 0
        mismatches = list(result.mismatches)
        for path in failures:
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
                genome = GenomeCodec.decode(json.dumps(
                    document["genome"], sort_keys=True,
                    separators=(",", ":")).encode("utf-8"))
                expected = document["trace"]
                if _replay_saved_failure_trace(genome, budgeted_factory,
                                               expected):
                    matched_failures += 1
                else:
                    mismatches.append(f"{path.name}: full trace differs")
            except (OSError, ValueError, TypeError, KeyError) as exc:
                mismatches.append(f"{path.name}: {type(exc).__name__}: {exc}")
        return ReplayEvidence(
            total_entries=result.total_entries,
            matched_entries=result.matched_entries,
            failure_entries=len(failures),
            matched_failure_entries=matched_failures,
            error="; ".join(mismatches) if mismatches else None)
