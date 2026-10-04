"""Save one continuous testcase and replay it from fresh local RTL state."""

from __future__ import annotations

from dataclasses import asdict
import ctypes
import errno
import hashlib
import inspect
import json
import os
from pathlib import Path
import tempfile
import time
from typing import Callable

from .checker import (check_cpu_gpio_closed_chain,
                      check_gpio_cpu_gpio_closed_chain,
                      check_gpio_direct_out, check_uart_early_irq_chain)
from .contracts import ResourceBudget, ResourceUsage
from .feedback import CoverageTarget, observed_targets
from .genome import GenomeCodec, ScenarioGenome
from .host_identity import verify_host_source_identity
from .replay import (ReplayComparison, ScenarioTrace, _canonical,
                     _difference_context, _record_with_runner)
from .runner import ScenarioRunner


_EVENT_FILES = {
    "initialization.jsonl": {"initial_image", "memory_initialization"},
    "schedule.jsonl": {"source_injection", "dataflow_delivery",
                       "quiesce_start", "quiesce_end", "quiesce_failure"},
    "transactions.jsonl": {"memory_read", "memory_write",
                           "mmio_acceptance", "mmio_delivery", "memory_commit"},
    "state_versions.jsonl": {"state_dependency"},
    "resets.jsonl": {"reset_barrier", "reset_failure"},
}


def _write_json(path: Path, document: object) -> None:
    path.write_bytes(_canonical(document) + b"\n")


def _write_jsonl(path: Path, records: tuple[dict, ...]) -> None:
    path.write_bytes(b"".join(_canonical(record) + b"\n" for record in records))


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _publish_new_evidence_directory(staged: Path, output: Path) -> None:
    """Atomically publish a directory only if its destination is still absent.

    Linux renameat2(RENAME_NOREPLACE) closes the race between an existence
    precheck and rename. Plain os.replace would overwrite a racing empty
    directory and silently replace another testcase's reserved output name.
    """
    rename = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if rename is None:
        raise RuntimeError("atomic no-replace evidence publish requires Linux renameat2")
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p,
                       ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(staged), -100, os.fsencode(output), 1) == 0:
        return
    error = ctypes.get_errno()
    if error in (errno.EEXIST, errno.ENOTEMPTY):
        raise ValueError("evidence directory must be new")
    raise OSError(error, os.strerror(error), str(output))


def _factory_identity(factory: Callable) -> dict:
    source = inspect.getsourcefile(factory)
    if source is None or not Path(source).is_file():
        raise ValueError("factory source file is unavailable for evidence")
    return {"module": factory.__module__,
            "qualname": factory.__qualname__,
            "source_file": Path(source).name,
            "source_sha256": _sha(Path(source))}


def _evidence_base_bytes(genome: ScenarioGenome, identity: dict,
                         factory_identity: dict,
                         coverage_targets: tuple[CoverageTarget, ...] = ()) -> int:
    """Immutable material counted before any RTL process starts."""
    encoded = GenomeCodec.encode(genome)
    coverage_max = _canonical({
        "targets": [asdict(item) for item in coverage_targets],
        "hits": sorted({item.target_id for item in coverage_targets})})
    return (len(_canonical(identity)) + 1
            + len(_canonical(factory_identity)) + 1
            + len(encoded) + len(_canonical(json.loads(encoded))) + 1
            + sum(len(image.data) for image in genome.initial_images)
            + len(coverage_max) + 1)


def _event_file_copy_counts() -> dict[str, int]:
    counts: dict[str, int] = {}
    for kinds in _EVENT_FILES.values():
        for kind in kinds:
            counts[kind] = counts.get(kind, 0) + 1
    return counts


def _initial_image_event_bytes(genome: ScenarioGenome) -> int:
    # Each record appears in trace.json and initialization.jsonl.
    return sum(2 * (len(_canonical({
        "event_id": index + 1, "kind": "initial_image",
        "image_id": image.image_id, "component": image.component,
        "address": image.address, "data_hex": image.data_hex})) + 1)
               for index, image in enumerate(genome.initial_images))


_CHECKER_CONFIG_FIELDS = {
    "gpio_direct_out.v1": ("checker", "devices"),
    "cpu_gpio_closed_chain.v1": ("checker", "expected_value", "min_rounds"),
    "gpio_cpu_gpio_closed_chain.v1": ("checker", "expected_values"),
    "uart_early_irq_chain.v1": ("checker",),
}


def _checker_config_bytes(checks: tuple[dict, ...] | list[dict]) -> int:
    """Reserve immutable checker declarations before any RTL step."""
    return sum(len(_canonical({field: check[field] for field in
                                _CHECKER_CONFIG_FIELDS[check["checker"]]})) + 1
               for check in checks)


def _checker_future_bytes(checks: tuple[dict, ...] | list[dict],
                          budget: ResourceBudget) -> int:
    """Reserve bounded causal-checker findings before their RTL facts exist.

    A completed closed-chain round consumes twelve ordered event identities.
    Each round can report at most four transaction-identity findings; one
    incomplete round and fixed end-state findings fit in the additional sixteen
    slots. GPIO DIRECT_OUT findings are metered from live MMIO/output events.
    """
    total = 0
    for check in checks:
        checker = check["checker"]
        if checker == "cpu_gpio_closed_chain.v1":
            requested = check["min_rounds"]
        elif checker == "gpio_cpu_gpio_closed_chain.v1":
            requested = len(check["expected_values"])
        elif checker == "uart_early_irq_chain.v1":
            total += 16 * (len(_canonical("cpu_early_status_consume_missing")) + 1)
            continue
        else:
            continue
        rounds = min(requested, budget.max_semantic_records // 12 + 1)
        longest = len(_canonical(
            f"round_{max(1, rounds)}:transaction_identity_missing")) + 1
        total += (4 * rounds + 16) * longest
    return total


def _termination_reserve_floor(genome: ScenarioGenome, runner: ScenarioRunner,
                               budget: ResourceBudget,
                               checks: tuple[dict, ...] | list[dict]) -> int:
    """Reject a tail too small for fixed terminal files before starting RTL.

    The index length is exact because every indexed SHA-256 has 64 characters.
    Other terms allow counters, declared input values, pending identities and
    checker wrappers to grow beyond the empty initial state. Final file bytes
    remain subject to the exact hard cap at publication.
    """
    names = {"manifest.json", "factory_source.json", "genome.bin",
             "genome.json", "trace.json", "final_state.json",
             "observations.jsonl", "checks.jsonl", "coverage.json",
             "result.json", *_EVENT_FILES}
    names.update(f"images/{index:04d}.bin"
                 for index in range(len(genome.initial_images)))
    index_bytes = len(_canonical({
        "schema_version": "scenario_evidence_index.v1",
        "files": {name: "0" * 64 for name in sorted(names)}})) + 1
    initial_state_bytes = len(_canonical(runner.final_state_document())) + 1
    input_bytes = sum(
        len(field["component_id"].encode("utf-8"))
        + len(field["port"].encode("utf-8"))
        + (field["width"] * 30103 + 99999) // 100000 + 16
        for field in runner.ownership.document()["fields"])
    components = tuple(runner.sessions)
    component_bytes = sum(2 * len(name.encode("utf-8")) + 1024
                          for name in components)
    budget_bytes = len(_canonical(budget.to_document()))
    return (index_bytes + initial_state_bytes + input_bytes + component_bytes
            + budget_bytes + 4096 + 512 * len(checks)
            + 2 * len(genome.testcase_id.encode("utf-8")))


def _final_state_growth_bound(genome: ScenarioGenome,
                              runner: ScenarioRunner,
                              budget: ResourceBudget) -> int:
    """One-operation growth backed by audited sessions or an explicit contract.

    Exact built-in classes have fixed pending counters. CPU uncertainty can
    add at most two Ibex keys or one CVA6 key during a local operation; the
    key's variable fields are the immutable testcase/component names and
    bounded sequence/epoch counters. Subclasses must declare their own bound.
    """
    from .ibex_session import IbexCpuSession
    from .cva6_session import Cva6CpuSession
    from .gpio_session import OpenTitanGpioSession
    from .uart_session import OpenTitanUartSession
    from myfuzz.local_harness.session import GeneratedLocalSession

    largest = 0
    digits = len(str(max(budget.max_scheduler_steps,
                         budget.max_transactions,
                         budget.max_semantic_records)))
    for component, session in runner.sessions.items():
        component_bytes = len(component.encode("utf-8"))
        if type(session) in (OpenTitanGpioSession, OpenTitanUartSession):
            bound = 8192 + 4 * component_bytes
        elif type(session) in (IbexCpuSession, Cva6CpuSession):
            keys = 2 if type(session) is IbexCpuSession else 1
            key_bytes = (512 + 4 * len(genome.testcase_id.encode("utf-8"))
                         + 4 * component_bytes + 4 * digits)
            bound = 8192 + 4 * component_bytes + keys * key_bytes
        elif isinstance(session, GeneratedLocalSession) and (
                type(session).__dict__.get('artifact_kind') ==
                session.artifact.runtime_document.get('kind')):
            # A generated command contributes one fixed-width RTL snapshot;
            # the CPU may also add one persistent memory transaction key.
            # Include the variable testcase and component identity lengths.
            bound = (32_768 + 16 * len(genome.testcase_id.encode("utf-8"))
                     + 16 * component_bytes + 64 * digits)
        else:
            bound = getattr(session,
                            "max_final_state_growth_bytes_per_operation", None)
            if type(bound) is not int or bound < 0:
                raise ValueError(f"{component}: final state growth bound is required")
        router = getattr(session, "router", None)
        if router is not None:
            # A queued target can first appear as a key in the persistent
            # pending-target map after an otherwise small local operation.
            bound += sum(len(_canonical(window.device_id)) + 32
                         for window in router.windows)
        largest += bound
    return largest


def _evidence_record_bound(genome: ScenarioGenome,
                           runner: ScenarioRunner,
                           budget: ResourceBudget) -> int:
    """Maximum declared raw event size; the tail holds up to three copies."""
    from .ibex_session import IbexCpuSession
    from .cva6_session import Cva6CpuSession
    from .gpio_session import OpenTitanGpioSession
    from .uart_session import OpenTitanUartSession
    from myfuzz.local_harness.session import GeneratedLocalSession

    digits = len(str(max(budget.max_scheduler_steps,
                         budget.max_transactions,
                         budget.max_semantic_records)))
    # A source injection can echo a declared source_ref; dataflow/IRQ events
    # echo declared ports. These names are immutable but need not be short.
    ownership = getattr(runner, "ownership", None)
    ownership_bytes = (len(_canonical(ownership.document()))
                       if ownership is not None else 0)
    bound = len(GenomeCodec.encode(genome)) + ownership_bytes + 8192
    for component, session in runner.sessions.items():
        writer_lanes = 0
        if type(session) in (IbexCpuSession, Cva6CpuSession,
                             OpenTitanGpioSession, OpenTitanUartSession):
            # A memory read records one transaction plus a writer identity
            # for every byte. CVA6 reads eight bytes; Ibex reads four. A
            # repeated, long testcase ID can therefore dominate one record.
            writer_lanes = (8 if type(session) is Cva6CpuSession else
                            4 if type(session) is IbexCpuSession else 0)
            session_bound = (8192
                             + 4 * max(1, writer_lanes) * len(
                                 genome.testcase_id.encode("utf-8"))
                             + 4 * len(component.encode("utf-8"))
                             + max(4, writer_lanes + 1) * 4 * digits)
        elif isinstance(session, GeneratedLocalSession) and (
                type(session).__dict__.get('artifact_kind') ==
                session.artifact.runtime_document.get('kind')):
            limits = session.artifact.runtime_document['driver_limits']
            reservation = limits['reply_reservation_bytes']
            if type(reservation) is not int or reservation < 1:
                raise ValueError(f"{component}: invalid generated reply reservation")
            writer_lanes = 4 if getattr(session, 'memory', None) is not None else 0
            # One generated reply bounds all native pre/post samples of one
            # command. Router, source and observation records may repeat its
            # decoded fields; reserve four copies plus identity overhead.
            session_bound = (4 * reservation + 16_384
                             + 16 * len(genome.testcase_id.encode("utf-8"))
                             + 16 * len(component.encode("utf-8"))
                             + 64 * digits)
        else:
            session_bound = getattr(session, "max_evidence_record_bytes", None)
            if type(session_bound) is not int or session_bound < 1:
                raise ValueError(f"{component}: evidence record bound is required")
        bound += session_bound
        memory = getattr(session, "memory", None)
        if memory is not None:
            # A reset barrier can list every declared region in one record.
            # On first read, each byte's persistent writer identity includes
            # the selected region name ("init:<region>:<offset>"). Only one
            # region can supply a read, so reserve the longest name per lane.
            memory_names = tuple(len(_canonical(memory_id))
                                 for memory_id in memory.memory_ids)
            bound += (sum(size + 16 for size in memory_names)
                      + writer_lanes * max(memory_names, default=0))
        router = getattr(session, "router", None)
        if router is not None:
            # MMIO events and queued-target records echo these declarations.
            bound += sum(len(_canonical(window.device_id)) + 16
                         for window in router.windows)
    for index, image in enumerate(genome.initial_images):
        bound = max(bound, len(_canonical({
            "event_id": index + 1, "kind": "initial_image",
            "image_id": image.image_id, "component": image.component,
            "address": image.address, "data_hex": image.data_hex})) + 1)
    return bound


def _configured_checkers(gpio_check_devices: tuple[str, ...],
                         closed_chain_expected_value: int | None,
                         closed_chain_min_rounds: int,
                         reverse_chain_expected_values: tuple[int, ...] | None,
                         uart_early_irq: bool) -> tuple[dict, ...]:
    checks: list[dict] = []
    if gpio_check_devices:
        checks.append({"checker": "gpio_direct_out.v1",
                       "devices": gpio_check_devices})
    if closed_chain_expected_value is not None:
        checks.append({"checker": "cpu_gpio_closed_chain.v1",
                       "expected_value": closed_chain_expected_value,
                       "min_rounds": closed_chain_min_rounds})
    if reverse_chain_expected_values is not None:
        checks.append({"checker": "gpio_cpu_gpio_closed_chain.v1",
                       "expected_values": reverse_chain_expected_values})
    if uart_early_irq:
        checks.append({"checker": "uart_early_irq_chain.v1"})
    return tuple(checks)


def _checker_records(events: tuple[dict, ...], final_state: dict,
                     gpio_check_devices: tuple[str, ...],
                     closed_chain_expected_value: int | None,
                     closed_chain_min_rounds: int,
                     reverse_chain_expected_values: tuple[int, ...] | None,
                     uart_early_irq: bool = False) -> tuple[dict, ...]:
    checks: list[dict] = []
    if gpio_check_devices:
        findings = check_gpio_direct_out(events, gpio_check_devices)
        checks.append({"checker": "gpio_direct_out.v1",
                       "devices": gpio_check_devices,
                       "findings": [asdict(item) for item in findings]})
    if closed_chain_expected_value is not None:
        report = check_cpu_gpio_closed_chain(
            events, final_state, expected_value=closed_chain_expected_value,
            min_rounds=closed_chain_min_rounds)
        checks.append({"checker": "cpu_gpio_closed_chain.v1",
                       "expected_value": closed_chain_expected_value,
                       "min_rounds": closed_chain_min_rounds,
                       **report})
    if reverse_chain_expected_values is not None:
        report = check_gpio_cpu_gpio_closed_chain(
            events, final_state, expected_values=reverse_chain_expected_values)
        checks.append({"checker": "gpio_cpu_gpio_closed_chain.v1",
                       "expected_values": reverse_chain_expected_values,
                       **report})
    if uart_early_irq:
        checks.append({"checker": "uart_early_irq_chain.v1",
                       **check_uart_early_irq_chain(events, final_state)})
    return tuple(checks)


def _budget_preflight(genome: ScenarioGenome, runner: ScenarioRunner,
                      budget: ResourceBudget) -> None:
    """Check immutable input and enforce a memory service cap before RTL begins."""
    if len(genome.actions) > budget.max_source_actions:
        raise ValueError("max_source_actions budget exceeded")
    if genome.max_steps > budget.max_scheduler_steps:
        raise ValueError("max_scheduler_steps budget exceeded")
    if genome.quiesce_steps > budget.max_quiesce_steps:
        raise ValueError("max_quiesce_steps budget exceeded")
    image_bytes: dict[tuple[str, str], set[int]] = {}
    for component, session in runner.sessions.items():
        memory = getattr(session, "memory", None)
        if memory is not None and memory.max_initialized_bytes > (
                budget.max_materialized_bytes_per_memory):
            raise ValueError(f"max_materialized_bytes_per_memory is below {component} service cap")
    for image in genome.initial_images:
        session = runner.sessions.get(image.component)
        memory = getattr(session, "memory", None)
        if memory is None:
            raise ValueError(f"image {image.image_id} has no memory service")
        regions = memory.identity_document()["regions"]
        matches = []
        for region in regions:
            for base in (region["base"], *region["aliases"]):
                if (region["writable"] and base <= image.address
                        and image.address + len(image.data) <= base + region["size"]):
                    matches.append((region["memory_id"], image.address - base))
        if len(matches) != 1:
            raise ValueError(f"image {image.image_id} is outside one writable memory region")
        memory_id, offset = matches[0]
        used = image_bytes.setdefault((image.component, memory_id), set())
        used.update(range(offset, offset + len(image.data)))
        if len(used) > budget.max_materialized_bytes_per_memory:
            raise ValueError("max_materialized_bytes_per_memory budget exceeded")


def _measured_usage(genome: ScenarioGenome, runner: ScenarioRunner,
                    trace: ScenarioTrace, started_at: float) -> ResourceUsage:
    materialized: dict[str, int] = {}
    for component, session in runner.sessions.items():
        memory = getattr(session, "memory", None)
        if memory is None:
            continue
        # PersistentMemory has one authoritative byte table; count each ID
        # separately, including bytes that were materialized during execution.
        for memory_id, _offset in memory._bytes:
            key = f"{component}.{memory_id}"
            materialized[key] = materialized.get(key, 0) + 1
    quiesce_steps = sum(int(event.get("steps", 0)) for event in trace.events
                        if event.get("kind") == "quiesce_end")
    return ResourceUsage(
        local_cycles=dict(trace.local_ticks), materialized_bytes=materialized,
        scheduler_steps=sum(trace.local_ticks.values()),
        source_actions=sum(event.get("kind") == "source_injection"
                           for event in trace.events),
        transactions=sum(event.get("kind") in ("memory_read", "memory_write",
                                                      "mmio_delivery")
                         for event in trace.events),
        semantic_records=len(trace.events), evidence_bytes=0,
        # A failed prepare_local build precedes testcase start. Its separately
        # bounded setup time is never charged to the testcase wall budget.
        wall_time_ms=(int((time.monotonic() - runner._wall_started_at) * 1000)
                      if runner._wall_started_at is not None else 0),
        quiesce_steps=quiesce_steps)


def _wall_cut_event(status: str, events: tuple[dict, ...] | list[dict]) -> dict | None:
    cuts = [event for event in events
            if event.get("kind") == "budget_exhausted"
            and event.get("limit") == "max_wall_time_ms"]
    if not cuts:
        return None
    if len(cuts) != 1 or cuts[0] != events[-1]:
        raise ValueError("invalid wall budget termination trace")
    previous_status = cuts[0].get("status_before_finalize")
    if previous_status is None:
        if status != "budget_exhausted":
            raise ValueError("invalid wall budget termination status")
    elif (cuts[0].get("phase") != "inflight_finalize"
          or not isinstance(previous_status, str) or not previous_status
          or status != previous_status):
        raise ValueError("invalid prior failure wall budget status")
    if cuts[0].get("phase") in ("before_begin", "inflight_begin"):
        cut = cuts[0]
        prefix = cut.get("prefix_event_count")
        ticks = cut.get("prefix_local_ticks")
        failed = cut.get("failed_component")
        started = cut.get("started_components")
        if (type(prefix) is not int or prefix != len(events) - 1
                or not isinstance(ticks, dict)
                or not ticks
                or any(type(value) is not int or value != 0
                       for value in ticks.values())
                or cut.get("local_ticks") != ticks
                or cut.get("effect_may_have_occurred") is not
                (cut["phase"] == "inflight_begin")
                or not isinstance(failed, str) or not failed
                or failed not in ticks
                or not isinstance(started, (tuple, list))
                or any(not isinstance(name, str) or name not in ticks
                       for name in started)
                or len(set(started)) != len(started)
                or failed in started):
            raise ValueError("invalid begin wall prefix marker")
    if cuts[0].get("phase") in ("inflight_step", "inflight_reset",
                               "inflight_finalize"):
        prefix = cuts[0].get("prefix_event_count")
        ticks = cuts[0].get("prefix_local_ticks")
        if (type(prefix) is not int or not 0 <= prefix <= len(events) - 1
                or not isinstance(ticks, dict)
                or any(type(value) is not int or value < 0
                       for value in ticks.values())
                or cuts[0].get("effect_may_have_occurred") is not True
                or (cuts[0]["phase"] in ("inflight_reset", "inflight_finalize")
                    and prefix != len(events) - 1)):
            raise ValueError("invalid inflight wall prefix marker")
    return cuts[0]


def _save_budgeted_bundle(output: Path, genome: ScenarioGenome,
                          identity: dict, factory_identity: dict,
                          trace: ScenarioTrace, runner: ScenarioRunner,
                          budget: ResourceBudget, started_at: float,
                          gpio_check_devices: tuple[str, ...],
                          coverage_targets: tuple[CoverageTarget, ...],
                          closed_chain_expected_value: int | None,
                          closed_chain_min_rounds: int,
                          reverse_chain_expected_values: tuple[int, ...] | None,
                          uart_early_irq: bool,
                          state_growth_bound: int,
                          record_bound: int) -> None:
    """Serialize to memory, check exact file bytes, then create the directory."""
    usage = _measured_usage(genome, runner, trace, started_at)
    wall_cut = _wall_cut_event(trace.status, trace.events)
    # The event meter keeps ordinary execution below the normal capacity.
    # Final state, checks, coverage, result and index use the reserved tail.
    budget.check_usage(usage, terminating=True,
                       allow_wall_overrun=wall_cut is not None)
    final_state = runner.final_state_document()
    encoded_genome = GenomeCodec.encode(genome)
    files = {
        "manifest.json": _canonical(identity) + b"\n",
        "factory_source.json": _canonical(factory_identity) + b"\n",
        "genome.bin": encoded_genome,
        "genome.json": _canonical(json.loads(encoded_genome)) + b"\n",
        "trace.json": _canonical(asdict(trace)) + b"\n",
        "final_state.json": _canonical(final_state) + b"\n",
    }
    for index, item in enumerate(genome.initial_images):
        files[f"images/{index:04d}.bin"] = item.data
    for name, kinds in _EVENT_FILES.items():
        files[name] = b"".join(_canonical(event) + b"\n" for event in trace.events
                               if event.get("kind") in kinds)
    files["observations.jsonl"] = b"".join(
        _canonical(event) + b"\n" for event in trace.events
        if "outputs" in event or event.get("kind") in ("harness_failure", "begin_failure"))
    checks = _checker_records(trace.events, final_state, gpio_check_devices,
                              closed_chain_expected_value,
                              closed_chain_min_rounds,
                              reverse_chain_expected_values, uart_early_irq)
    files["checks.jsonl"] = b"".join(_canonical(item) + b"\n" for item in checks)
    hits = observed_targets(trace.events, coverage_targets)
    files["coverage.json"] = _canonical({
        "targets": [asdict(item) for item in coverage_targets],
        "hits": sorted(hits)}) + b"\n"
    base_result = {
        "status": trace.status, "genome_sha256": trace.genome_sha256,
        "manifest_sha256": trace.manifest_sha256,
        "semantic_sha256": trace.semantic_sha256,
        "local_ticks": trace.local_ticks,
        "final_state_sha256": hashlib.sha256(_canonical(final_state)).hexdigest(),
        "event_count": len(trace.events),
        "checker_findings": sum(len(item["findings"]) for item in checks),
        "coverage_hits": len(hits), "schema_version": "scenario_evidence.v1",
        "resource_budget": budget.to_document(),
        "final_state_growth_bound_bytes": state_growth_bound,
        "evidence_record_bound_bytes": record_bound,
    }
    # The numeric evidence_bytes field changes its own serialized size at
    # decimal boundaries. Iterate until the actual byte count stabilizes.
    for _ in range(12):
        files["result.json"] = _canonical({**base_result,
            "resource_usage": usage.to_document()}) + b"\n"
        hashes = {name: hashlib.sha256(data).hexdigest()
                  for name, data in sorted(files.items())}
        index = _canonical({"schema_version": "scenario_evidence_index.v1",
                            "files": hashes}) + b"\n"
        actual_size = sum(map(len, files.values())) + len(index)
        if actual_size == usage.evidence_bytes:
            break
        usage = ResourceUsage(**{**usage.to_document(), "evidence_bytes": actual_size})
    else:
        raise RuntimeError("evidence byte accounting did not converge")
    budget.check_usage(usage, terminating=True,
                       allow_wall_overrun=wall_cut is not None)
    output.mkdir(parents=True)
    for name, data in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (output / "bundle_index.json").write_bytes(index)


def save_evidence_bundle(genome: ScenarioGenome,
                         factory: Callable[[], ScenarioRunner],
                         output_dir: Path, *,
                         gpio_check_devices: tuple[str, ...] = (),
                         coverage_targets: tuple[CoverageTarget, ...] = (),
                         budget: ResourceBudget | None = None,
                         closed_chain_expected_value: int | None = None,
                         closed_chain_min_rounds: int = 2,
                         reverse_chain_expected_values: tuple[int, ...] | None = None,
                         uart_early_irq: bool = False,
                         ) -> ScenarioTrace:
    """Publish a complete evidence tree only after every file was written."""
    output = Path(output_dir)
    if output.exists() or output.is_symlink():
        raise ValueError("evidence directory must be new")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f".{output.name}.staging-",
                                     dir=output.parent) as staging_parent:
        staged = Path(staging_parent) / "bundle"
        trace = _save_evidence_bundle_unstaged(
            genome, factory, staged, gpio_check_devices=gpio_check_devices,
            coverage_targets=coverage_targets, budget=budget,
            closed_chain_expected_value=closed_chain_expected_value,
            closed_chain_min_rounds=closed_chain_min_rounds,
            reverse_chain_expected_values=reverse_chain_expected_values,
            uart_early_irq=uart_early_irq)
        _publish_new_evidence_directory(staged, output)
        return trace


def _save_evidence_bundle_unstaged(genome: ScenarioGenome,
                                  factory: Callable[[], ScenarioRunner],
                                  output_dir: Path, *,
                                  gpio_check_devices: tuple[str, ...],
                                  coverage_targets: tuple[CoverageTarget, ...],
                                  budget: ResourceBudget | None,
                                  closed_chain_expected_value: int | None,
                                  closed_chain_min_rounds: int,
                                  reverse_chain_expected_values: tuple[int, ...] | None,
                                  uart_early_irq: bool,
                                  ) -> ScenarioTrace:
    """Run once and save immutable inputs and actual observations separately."""
    if not isinstance(genome, ScenarioGenome):
        raise ValueError("ScenarioGenome is required")
    if budget is not None and not isinstance(budget, ResourceBudget):
        raise ValueError("ResourceBudget is required")
    if budget is not None:
        if len(genome.actions) > budget.max_source_actions:
            raise ValueError("max_source_actions budget exceeded")
        if genome.max_steps > budget.max_scheduler_steps:
            raise ValueError("max_scheduler_steps budget exceeded")
    output = Path(output_dir)
    if output.exists() or output.is_symlink():
        raise ValueError("evidence directory must be new")
    runner = factory()
    if not isinstance(runner, ScenarioRunner):
        raise ValueError("factory must return a fresh ScenarioRunner")
    if budget is not None:
        _budget_preflight(genome, runner, budget)
        runner.set_resource_budget(budget)
    identity = runner.identity_document()
    factory_identity = _factory_identity(factory)
    if budget is not None:
        declared_checks = _configured_checkers(
            gpio_check_devices, closed_chain_expected_value,
            closed_chain_min_rounds, reverse_chain_expected_values,
            uart_early_irq)
        state_growth_bound = _final_state_growth_bound(genome, runner, budget)
        record_bound = _evidence_record_bound(genome, runner, budget)
        if (budget.evidence_termination_reserve_bytes <
                _termination_reserve_floor(genome, runner, budget,
                                           declared_checks)
                + 2 * state_growth_bound + 3 * record_bound):
            raise ValueError("max_evidence_bytes termination reserve is too small")
        base_bytes = (_evidence_base_bytes(
            genome, identity, factory_identity, coverage_targets)
            + _checker_config_bytes(declared_checks)
            + _checker_future_bytes(declared_checks, budget))
        if (base_bytes + _initial_image_event_bytes(genome) >
                budget.max_evidence_bytes
                - budget.evidence_termination_reserve_bytes):
            raise ValueError("max_evidence_bytes initial material exceeds normal capacity")
        runner.arm_evidence_meter(
            base_bytes,
            _event_file_copy_counts(),
            max_final_state_growth_bytes_per_operation=state_growth_bound,
            max_evidence_record_bytes=record_bound,
            gpio_checker_devices=gpio_check_devices)
    started_at = time.monotonic()
    trace = _record_with_runner(genome, runner)
    if hashlib.sha256(_canonical(identity)).hexdigest() != trace.manifest_sha256:
        raise RuntimeError("manifest identity changed during testcase execution")
    if budget is not None:
        _save_budgeted_bundle(output, genome, identity, factory_identity, trace,
                              runner, budget, started_at, gpio_check_devices,
                              coverage_targets, closed_chain_expected_value,
                              closed_chain_min_rounds,
                              reverse_chain_expected_values, uart_early_irq,
                              state_growth_bound, record_bound)
        return trace
    output.mkdir(parents=True)
    _write_json(output / "manifest.json", identity)
    _write_json(output / "factory_source.json", factory_identity)
    encoded_genome = GenomeCodec.encode(genome)
    (output / "genome.bin").write_bytes(encoded_genome)
    _write_json(output / "genome.json", json.loads(encoded_genome))
    images = output / "images"
    images.mkdir()
    for index, item in enumerate(genome.initial_images):
        (images / f"{index:04d}.bin").write_bytes(item.data)
    _write_json(output / "trace.json", asdict(trace))
    final_state = runner.final_state_document()
    _write_json(output / "final_state.json", final_state)
    for name, kinds in _EVENT_FILES.items():
        _write_jsonl(output / name, tuple(event for event in trace.events
                                         if event.get("kind") in kinds))
    _write_jsonl(output / "observations.jsonl", tuple(event for event in trace.events
                                                      if "outputs" in event or
                                                      event.get("kind") in (
                                                          "harness_failure",
                                                          "begin_failure")))
    checks = _checker_records(trace.events, final_state, gpio_check_devices,
                              closed_chain_expected_value,
                              closed_chain_min_rounds,
                              reverse_chain_expected_values, uart_early_irq)
    _write_jsonl(output / "checks.jsonl", checks)
    hits = observed_targets(trace.events, coverage_targets)
    _write_json(output / "coverage.json", {
        "targets": [asdict(item) for item in coverage_targets],
        "hits": sorted(hits)})
    _write_json(output / "result.json", {
        "status": trace.status, "genome_sha256": trace.genome_sha256,
        "manifest_sha256": trace.manifest_sha256,
        "semantic_sha256": trace.semantic_sha256,
        "local_ticks": trace.local_ticks,
        "final_state_sha256": hashlib.sha256(_canonical(final_state)).hexdigest(),
        "event_count": len(trace.events),
        "checker_findings": sum(len(item["findings"]) for item in checks),
        "coverage_hits": len(hits),
        "schema_version": "scenario_evidence.v1"})
    hashes = {path.relative_to(output).as_posix(): _sha(path)
              for path in sorted(output.rglob("*")) if path.is_file()}
    _write_json(output / "bundle_index.json", {
        "schema_version": "scenario_evidence_index.v1", "files": hashes})
    return trace


def _verify_evidence_host_identity(identity: dict) -> None:
    """Bind saved v2 host bytes to the generated sessions in this bundle."""
    if not isinstance(identity, dict) or not isinstance(identity.get("sessions"), dict):
        raise ValueError("invalid evidence session identity")
    generated = []
    for record in identity["sessions"].values():
        if not isinstance(record, dict) or not isinstance(record.get("identity"), dict):
            raise ValueError("invalid evidence session identity")
        session = record["identity"]
        if session.get("schema_version") == "generated_local_session_identity.v1":
            generated.append(session)
    verify_host_source_identity(identity["host_sources"],
                                harness_identities=tuple(generated))


def replay_evidence_bundle(output_dir: Path,
                           factory: Callable[[], ScenarioRunner], *,
                           allow_factory_mismatch: bool = False) -> ReplayComparison:
    """Check saved material first, then execute fresh RTL and compare events."""
    output = Path(output_dir)
    index = json.loads((output / "bundle_index.json").read_text(encoding="utf-8"))
    if (index.get("schema_version") != "scenario_evidence_index.v1"
            or not isinstance(index.get("files"), dict)):
        raise ValueError("invalid evidence index")
    required = {"manifest.json", "factory_source.json",
                "genome.bin", "genome.json", "trace.json", "final_state.json",
                "observations.jsonl", "checks.jsonl", "coverage.json",
                "result.json", *_EVENT_FILES}
    if not required <= set(index["files"]):
        raise ValueError("evidence index omits required files")
    actual_names = {path.relative_to(output).as_posix()
                    for path in output.rglob("*") if path.is_file()
                    and path.name not in ("bundle_index.json", "replay_report.json")}
    if actual_names != set(index["files"]):
        raise ValueError("evidence files disagree with index")
    for name, expected in index["files"].items():
        path = output / name
        if (not isinstance(name, str) or Path(name).is_absolute()
                or ".." in Path(name).parts or path.is_symlink()
                or not path.is_file()):
            raise ValueError(f"{name}: missing or invalid evidence file")
        if _sha(path) != expected:
            raise ValueError(f"{name}: hash mismatch")
    genome_bytes = (output / "genome.bin").read_bytes()
    genome = GenomeCodec.decode(genome_bytes)
    if json.loads((output / "genome.json").read_text(encoding="utf-8")) != json.loads(
            genome_bytes):
        raise ValueError("genome JSON disagrees with binary material")
    for number, image in enumerate(genome.initial_images):
        filename = output / "images" / f"{number:04d}.bin"
        if not filename.is_file() or filename.read_bytes() != image.data:
            raise ValueError("image material disagrees with genome")
    saved = json.loads((output / "trace.json").read_text(encoding="utf-8"))
    identity = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    if hashlib.sha256(genome_bytes).hexdigest() != saved["genome_sha256"]:
        raise ValueError("genome identity mismatch")
    if hashlib.sha256(_canonical(identity)).hexdigest() != saved["manifest_sha256"]:
        raise ValueError("manifest identity mismatch")
    if "host_sources" not in identity:
        raise ValueError("legacy evidence lacks host_sources; rerecord the bundle")
    _verify_evidence_host_identity(identity)
    expected_semantic = hashlib.sha256(_canonical({
        "status": saved["status"], "events": saved["events"],
        "local_ticks": saved["local_ticks"]})).hexdigest()
    if expected_semantic != saved["semantic_sha256"]:
        raise ValueError("saved trace semantic hash mismatch")
    result = json.loads((output / "result.json").read_text(encoding="utf-8"))
    for key in ("status", "genome_sha256", "manifest_sha256",
                "semantic_sha256", "local_ticks"):
        if result.get(key) != saved[key]:
            raise ValueError(f"result and trace disagree on {key}")
    if result.get("event_count") != len(saved["events"]):
        raise ValueError("result and trace disagree on event count")
    saved_final_state = json.loads((output / "final_state.json").read_text(
        encoding="utf-8"))
    if (hashlib.sha256(_canonical(saved_final_state)).hexdigest()
            != result.get("final_state_sha256")):
        raise ValueError("final state digest disagrees with result")
    if "resource_budget" in result or "resource_usage" in result:
        if not {"resource_budget", "resource_usage"} <= set(result):
            raise ValueError("resource_budget and resource_usage must appear together")
        budget = ResourceBudget.from_document(result["resource_budget"])
        usage_record = result["resource_usage"]
        if not isinstance(usage_record, dict):
            raise ValueError("resource_usage must be an object")
        try:
            usage = ResourceUsage(**usage_record)
        except TypeError as exc:
            raise ValueError("resource_usage has unknown or missing fields") from exc
        expected_counts = {
            "semantic_records": len(saved["events"]),
            "scheduler_steps": sum(saved["local_ticks"].values()),
            "source_actions": sum(event.get("kind") == "source_injection"
                                  for event in saved["events"]),
            "transactions": sum(event.get("kind") in ("memory_read", "memory_write",
                                                    "mmio_delivery")
                                for event in saved["events"]),
            "evidence_bytes": (sum((output / name).stat().st_size
                                   for name in index["files"])
                               + (output / "bundle_index.json").stat().st_size),
        }
        for name, expected in expected_counts.items():
            if getattr(usage, name) != expected:
                raise ValueError(f"resource_usage.{name} disagrees with evidence")
        if usage.local_cycles != saved["local_ticks"]:
            raise ValueError("resource_usage.local_cycles disagrees with trace")
        for component, state in saved_final_state["memories"].items():
            count = sum(amount for key, amount in usage.materialized_bytes.items()
                        if key.startswith(component + "."))
            if count != state["initialized_bytes"]:
                raise ValueError("resource_usage.materialized_bytes disagrees with final state")
        wall_cut = _wall_cut_event(saved["status"], saved["events"])
        budget.check_usage(usage, terminating=True,
                           allow_wall_overrun=wall_cut is not None)
    for name, kinds in _EVENT_FILES.items():
        expected_rows = [event for event in saved["events"]
                         if event.get("kind") in kinds]
        if _read_jsonl(output / name) != expected_rows:
            raise ValueError(f"{name} disagrees with trace")
    observations = [event for event in saved["events"]
                    if "outputs" in event or event.get("kind") in (
                        "harness_failure", "begin_failure")]
    if _read_jsonl(output / "observations.jsonl") != observations:
        raise ValueError("observations disagree with trace")
    checks = _read_jsonl(output / "checks.jsonl")
    for check in checks:
        if check.get("checker") == "gpio_direct_out.v1":
            expected_check = _checker_records(
                tuple(saved["events"]), saved_final_state,
                tuple(check["devices"]), None, 2, None)[0]
        elif check.get("checker") == "cpu_gpio_closed_chain.v1":
            expected_check = _checker_records(
                tuple(saved["events"]), saved_final_state, (),
                check["expected_value"], check["min_rounds"], None)[0]
        elif check.get("checker") == "gpio_cpu_gpio_closed_chain.v1":
            expected_check = _checker_records(
                tuple(saved["events"]), saved_final_state, (), None, 2,
                tuple(check["expected_values"]))[0]
        elif check.get("checker") == "uart_early_irq_chain.v1":
            expected_check = _checker_records(
                tuple(saved["events"]), saved_final_state, (), None, 2,
                None, True)[0]
        else:
            raise ValueError("unknown evidence checker")
        if check != json.loads(_canonical(expected_check)):
            raise ValueError("saved checker findings disagree with trace")
    saved_coverage = json.loads((output / "coverage.json").read_text(
        encoding="utf-8"))
    targets = tuple(CoverageTarget(**item) for item in saved_coverage["targets"])
    if saved_coverage.get("hits") != sorted(observed_targets(saved["events"], targets)):
        raise ValueError("saved coverage disagrees with trace")
    if (result.get("checker_findings") != sum(len(item["findings"]) for item in checks)
            or result.get("coverage_hits") != len(saved_coverage["hits"])):
        raise ValueError("result checker or coverage count disagrees")
    saved_factory = json.loads((output / "factory_source.json").read_text(
        encoding="utf-8"))
    if not allow_factory_mismatch and saved_factory != _factory_identity(factory):
        raise ValueError("replay factory source identity mismatch")
    runner = factory()
    if not isinstance(runner, ScenarioRunner):
        raise ValueError("factory must return a fresh ScenarioRunner")
    if _canonical(identity) != _canonical(runner.identity_document()):
        raise ValueError("replay manifest identity mismatch")
    wall_cut = None
    if "resource_budget" in result:
        budget = ResourceBudget.from_document(result["resource_budget"])
        runner.set_resource_budget(budget)
        state_growth_bound = _final_state_growth_bound(genome, runner, budget)
        record_bound = _evidence_record_bound(genome, runner, budget)
        if result.get("final_state_growth_bound_bytes") != state_growth_bound:
            raise ValueError("final state growth bound mismatch")
        if result.get("evidence_record_bound_bytes") != record_bound:
            raise ValueError("evidence record bound mismatch")
        if (budget.evidence_termination_reserve_bytes <
                _termination_reserve_floor(genome, runner, budget, checks)
                + 2 * state_growth_bound + 3 * record_bound):
            raise ValueError("max_evidence_bytes termination reserve is too small")
        runner.arm_evidence_meter(
            (_evidence_base_bytes(genome, identity, saved_factory, targets)
            + _checker_config_bytes(checks)
             + _checker_future_bytes(checks, budget)),
            _event_file_copy_counts(),
            max_final_state_growth_bytes_per_operation=state_growth_bound,
            max_evidence_record_bytes=record_bound,
            gpio_checker_devices=next((tuple(check["devices"]) for check in checks
                                       if check["checker"] == "gpio_direct_out.v1"), ()))
        wall_cut = _wall_cut_event(saved["status"], saved["events"])
        if wall_cut is not None:
            runner.set_replay_wall_cut(
                sum(wall_cut.get("prefix_local_ticks",
                                 wall_cut["local_ticks"]).values()),
                wall_cut["phase"],
                **({"failed_component": wall_cut["failed_component"],
                    "started_components": tuple(wall_cut["started_components"])}
                   if wall_cut["phase"] in ("before_begin", "inflight_begin")
                   else {}))
    actual = _record_with_runner(genome, runner)
    actual_final_state = runner.final_state_document()
    if wall_cut is not None and wall_cut["phase"] in (
            "inflight_step", "inflight_reset", "before_begin",
            "inflight_begin", "inflight_finalize"):
        prefix = wall_cut["prefix_event_count"]
        expected_events = saved["events"]
        actual_events = json.loads(_canonical(actual.events))
        difference = next((index for index in range(prefix)
                           if index >= len(actual_events)
                           or expected_events[index] != actual_events[index]), None)
        marker = actual_events[prefix] if prefix < len(actual_events) else None
        if difference is None and (len(actual_events) != prefix + 1
                                   or actual.status != saved["status"]
                                   or not isinstance(marker, dict)
                                   or marker.get("kind") != "budget_exhausted"
                                   or marker.get("limit") != "max_wall_time_ms"
                                   or marker.get("phase") != wall_cut["phase"]
                                   or marker.get("effect_may_have_occurred") is not
                                   (wall_cut["phase"] != "before_begin")
                                   or marker.get("prefix_event_count") != prefix
                                   or marker.get("prefix_local_ticks") !=
                                   wall_cut["prefix_local_ticks"]
                                   or marker.get("status_before_finalize") !=
                                   wall_cut.get("status_before_finalize")
                                   or (wall_cut["phase"] in
                                       ("before_begin", "inflight_begin")
                                       and (marker.get("failed_component") !=
                                            wall_cut["failed_component"]
                                            or marker.get("started_components") !=
                                            wall_cut["started_components"]))):
            difference = prefix
        if difference is None:
            comparison = ReplayComparison(
                True, None, None, None, actual, None, "semantic_prefix")
        else:
            expected = expected_events[difference]
            observed = (actual_events[difference]
                        if difference < len(actual_events) else None)
            comparison = ReplayComparison(
                False, difference, expected, observed, actual,
                _difference_context(expected, observed, difference),
                "semantic_prefix")
        _write_json(output / "replay_report.json", {
            "matches": comparison.matches,
            "verification_scope": comparison.verification_scope,
            "first_difference": comparison.first_difference,
            "difference_context": comparison.difference_context,
            "actual_semantic_sha256": actual.semantic_sha256})
        return comparison
    actual_checks = []
    for check in checks:
        if check["checker"] == "gpio_direct_out.v1":
            expected_check = _checker_records(
                actual.events, actual_final_state, tuple(check["devices"]),
                None, 2, None)[0]
        elif check["checker"] == "cpu_gpio_closed_chain.v1":
            expected_check = _checker_records(
                actual.events, actual_final_state, (),
                check["expected_value"], check["min_rounds"], None)[0]
        elif check["checker"] == "uart_early_irq_chain.v1":
            expected_check = _checker_records(
                actual.events, actual_final_state, (), None, 2, None, True)[0]
        else:
            expected_check = _checker_records(
                actual.events, actual_final_state, (), None, 2,
                tuple(check["expected_values"]))[0]
        actual_checks.append(json.loads(_canonical(expected_check)))
    actual_hits = sorted(observed_targets(actual.events, targets))
    expected_events = saved["events"]
    actual_events = json.loads(_canonical(actual.events))
    difference = next((index for index in range(max(len(expected_events),
                                                    len(actual_events)))
                       if (expected_events[index] if index < len(expected_events) else None)
                       != (actual_events[index] if index < len(actual_events) else None)),
                      None)
    if difference is not None:
        expected = expected_events[difference] if difference < len(expected_events) else None
        observed = actual_events[difference] if difference < len(actual_events) else None
        comparison = ReplayComparison(False, difference, expected, observed,
                                      actual, _difference_context(expected,
                                                                  observed, difference))
    elif (saved["status"] != actual.status
          or saved["local_ticks"] != actual.local_ticks
          or saved["semantic_sha256"] != actual.semantic_sha256
          or _canonical(saved_final_state) != _canonical(actual_final_state)
          or checks != actual_checks
          or saved_coverage["hits"] != actual_hits):
        difference = len(expected_events)
        comparison = ReplayComparison(False, difference, None, None, actual,
                                      {"event_index": difference,
                                       "expected_status": saved["status"],
                                       "actual_status": actual.status,
                                       "expected_local_ticks": saved["local_ticks"],
                                       "actual_local_ticks": actual.local_ticks,
                                       "expected_final_state": saved_final_state,
                                       "actual_final_state": actual_final_state,
                                       "expected_checks": checks,
                                       "actual_checks": actual_checks,
                                       "expected_coverage_hits": saved_coverage["hits"],
                                       "actual_coverage_hits": actual_hits})
    else:
        comparison = ReplayComparison(True, None, None, None, actual)
    _write_json(output / "replay_report.json", {
        "matches": comparison.matches,
        "verification_scope": comparison.verification_scope,
        "first_difference": comparison.first_difference,
        "difference_context": comparison.difference_context,
        "actual_semantic_sha256": actual.semantic_sha256})
    return comparison
