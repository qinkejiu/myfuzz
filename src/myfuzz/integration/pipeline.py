"""Typed orchestration boundary between composition and harness producers."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
import copy
from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import secrets
import stat

import fcntl

from myfuzz.contracts import validate_contract
from myfuzz.experiments import (
    Component,
    Port,
    ProtocolEndpoint,
    SourceList,
    load_experiment_config,
)

from .manifest import merge_candidate_manifest
from .memory_lock import MemoryTokenPool


_FORBIDDEN_GENERATOR_FIELDS = frozenset(
    (
        "evaluator_command",
        "evaluator_path",
        "original_soc",
        "original_top",
        "reference",
        "reference_command",
        "reference_path",
        "reference_top",
    )
)
_GROUPS = ("flat-direct", "candidate-direct", "candidate-depaware")
_SOFT_LIMIT_BYTES = 256 * 1024 * 1024
_HARD_LIMIT_BYTES = 512 * 1024 * 1024
_TOKEN_BYTES = 64 * 1024 * 1024
_MAX_CONFIG_BYTES = 1024 * 1024
_MAX_MANIFEST_BYTES = 16 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class GenerationRequest:
    """Reference-free, immutable inputs visible to the composition adapter."""

    target_id: int
    source_lists: tuple[SourceList, ...]
    components: tuple[Component, ...]
    ports: tuple[Port, ...]
    protocol_endpoints: tuple[ProtocolEndpoint, ...]
    top_k: int
    dry_run: bool


@dataclass(frozen=True, slots=True)
class RuntimeRequest:
    """Minimal immutable settings visible to the harness-runtime adapter."""

    target_id: int
    raw_width: int
    coverage_metric: str
    harness_groups: tuple[str, ...]
    dry_run: bool


CompositionProducer = Callable[[GenerationRequest], Iterable[Mapping[str, object]]]
RuntimePreparer = Callable[[dict[str, object], RuntimeRequest], object]


def _read_config_document(path: Path) -> dict[str, object]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect experiment config: {path}") from error
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_CONFIG_BYTES:
        raise ValueError("experiment config must be a bounded regular file")
    try:
        payload = path.read_bytes()
        document = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot load experiment config: {path}") from error
    if len(payload) > _MAX_CONFIG_BYTES or not isinstance(document, dict):
        raise ValueError("experiment config must be a bounded object")
    return document


def _assert_reference_free(value: object, path: str = "config") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} contains a non-string key")
            if key in _FORBIDDEN_GENERATOR_FIELDS:
                raise ValueError(f"generator config field is forbidden: {path}.{key}")
            _assert_reference_free(item, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            _assert_reference_free(item, f"{path}[{index}]")


def _collect_candidates(value: object, expected_count: int) -> list[dict[str, object]]:
    if isinstance(value, (Mapping, str, bytes, bytearray)) or not isinstance(value, Iterable):
        raise ValueError("composition producer must return an iterable of candidate manifests")
    candidates: list[dict[str, object]] = []
    candidate_ids: set[object] = set()
    for index, item in enumerate(value):
        if index >= expected_count:
            raise ValueError(
                f"composition producer must return exactly {expected_count} candidates"
            )
        if not isinstance(item, Mapping):
            raise ValueError("candidate manifest must be an object")
        detached = copy.deepcopy(dict(item))
        _assert_reference_free(detached, f"candidate[{index}]")
        validate_contract(detached, "candidate_manifest.v1")
        candidate_id = detached.get("candidate_id")
        if candidate_id in candidate_ids:
            raise ValueError("composition producer returned duplicate candidate IDs")
        candidate_ids.add(candidate_id)
        candidates.append(detached)
    if len(candidates) != expected_count:
        raise ValueError(f"composition producer must return exactly {expected_count} candidates")
    return candidates


def _fragment(value: object) -> dict[str, object]:
    if isinstance(value, Mapping):
        detached = copy.deepcopy(dict(value))
        _assert_reference_free(detached, "runtime_fragment")
        return detached
    fragment_method = getattr(value, "manifest_fragment", None)
    if callable(fragment_method):
        result = fragment_method()
        if isinstance(result, Mapping):
            detached = copy.deepcopy(dict(result))
            _assert_reference_free(detached, "runtime_fragment")
            return detached
    fragment_value = getattr(value, "manifest_fragment", None)
    if isinstance(fragment_value, Mapping):
        detached = copy.deepcopy(dict(fragment_value))
        _assert_reference_free(detached, "runtime_fragment")
        return detached
    raise ValueError("runtime preparer must return a manifest fragment")


def _prepare_output_dir(output_dir: Path) -> None:
    try:
        metadata = output_dir.lstat()
    except FileNotFoundError:
        output_dir.mkdir(parents=True, exist_ok=True)
        metadata = output_dir.lstat()
    except OSError as error:
        raise ValueError(f"cannot inspect output directory: {output_dir}") from error
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("output_dir must be a real directory")


def _workspace_memory_state_path() -> Path:
    """Resolve a gate shared by every worktree of the current Git repository."""
    for root in Path(__file__).resolve().parents:
        marker = root / ".git"
        if marker.is_dir():
            return marker / "myfuzz-memory-tokens.json"
        if not marker.is_file():
            continue
        try:
            marker_text = marker.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as error:
            raise RuntimeError("cannot read Git workspace metadata") from error
        if len(marker_text) > 4096 or not marker_text.startswith("gitdir: "):
            raise RuntimeError("Git workspace metadata is invalid")
        git_dir = Path(marker_text.removeprefix("gitdir: ").strip())
        if not git_dir.is_absolute():
            git_dir = root / git_dir
        git_dir = git_dir.resolve()
        common_marker = git_dir / "commondir"
        if common_marker.is_file():
            try:
                common_text = common_marker.read_text(encoding="utf-8")
            except (OSError, UnicodeError) as error:
                raise RuntimeError("cannot read Git common-directory metadata") from error
            if len(common_text) > 4096 or not common_text.strip():
                raise RuntimeError("Git common-directory metadata is invalid")
            common_dir = Path(common_text.strip())
            if not common_dir.is_absolute():
                common_dir = git_dir / common_dir
            git_dir = common_dir.resolve()
        if not git_dir.is_dir():
            raise RuntimeError("Git common directory does not exist")
        return git_dir / "myfuzz-memory-tokens.json"
    raise RuntimeError("memory_state_path is required outside a Git workspace")


@contextmanager
def _output_run_lock(output_dir: Path) -> Iterator[None]:
    lock_path = output_dir / ".pipeline.lock"
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as error:
        raise RuntimeError("cannot open output directory run lock") from error
    locked = False
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise RuntimeError("output directory run lock must be a regular file")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("output directory is already in use") from error
        locked = True
        if any(output_dir.glob("candidate-*.json")):
            raise FileExistsError("output_dir already contains candidate manifests")
        yield
    finally:
        try:
            if locked:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        try:
            written = os.write(descriptor, payload[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise RuntimeError("manifest write made no progress")
        offset += written


def _encode_manifest(document: Mapping[str, object]) -> bytes:
    payload = (
        json.dumps(
            document,
            sort_keys=True,
            ensure_ascii=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if len(payload) > _MAX_MANIFEST_BYTES:
        raise ValueError("candidate manifest exceeds size limit")
    return payload


def _atomic_write_payload(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    descriptor: int | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(temporary, flags, 0o600)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def run_candidate_pipeline(
    input_config: Path,
    *,
    output_dir: Path,
    top_k: int,
    dry_run: bool,
    composition_producer: CompositionProducer,
    runtime_preparer: RuntimePreparer,
    memory_state_path: Path | None = None,
) -> dict[str, object]:
    """Run explicit A/B adapters and persist one detached manifest per candidate."""
    if not isinstance(input_config, Path) or not isinstance(output_dir, Path):
        raise TypeError("input_config and output_dir must be pathlib.Path instances")
    if isinstance(top_k, bool) or not isinstance(top_k, int) or top_k <= 0:
        raise ValueError("top_k must be positive")
    if not isinstance(dry_run, bool):
        raise TypeError("dry_run must be bool")
    if not callable(composition_producer) or not callable(runtime_preparer):
        raise TypeError("composition_producer and runtime_preparer must be callable")
    if memory_state_path is not None and not isinstance(memory_state_path, Path):
        raise TypeError("memory_state_path must be a pathlib.Path")

    raw_document = _read_config_document(input_config)
    _assert_reference_free(raw_document)
    config = load_experiment_config(input_config)
    if config.document != raw_document:
        raise RuntimeError("experiment config changed while it was being validated")
    if config.generated_candidate_count != top_k:
        raise ValueError("top_k must equal the configured generated candidate count")

    generation_request = GenerationRequest(
        config.target_id,
        config.source_lists,
        config.components,
        config.ports,
        config.protocol_endpoints,
        top_k,
        dry_run,
    )
    runtime_request = RuntimeRequest(
        config.target_id,
        config.raw_width,
        config.coverage_metric,
        _GROUPS,
        dry_run,
    )

    _prepare_output_dir(output_dir)
    with _output_run_lock(output_dir):
        pool = MemoryTokenPool(
            _SOFT_LIMIT_BYTES,
            _HARD_LIMIT_BYTES,
            memory_state_path if memory_state_path is not None else _workspace_memory_state_path(),
        )
        wait_timeout = 30.0
        with pool.lease(
            "composition",
            _TOKEN_BYTES,
            exclusive_build=True,
            wait_timeout=wait_timeout,
        ):
            candidates = _collect_candidates(composition_producer(generation_request), top_k)

        merged: list[dict[str, object]] = []
        for index, candidate in enumerate(candidates):
            with pool.lease(
                f"runtime-{index}",
                _TOKEN_BYTES,
                exclusive_build=True,
                wait_timeout=wait_timeout,
            ):
                runtime_candidate = copy.deepcopy(candidate)
                fragment = _fragment(runtime_preparer(runtime_candidate, runtime_request))
                merged_manifest = merge_candidate_manifest(candidate, fragment)
            merged.append(merged_manifest)

        encoded = [_encode_manifest(merged_manifest) for merged_manifest in merged]
        published: list[Path] = []
        try:
            for index, payload in enumerate(encoded):
                destination = output_dir / f"candidate-{index:03d}.json"
                _atomic_write_payload(destination, payload)
                published.append(destination)
        except BaseException:
            for destination in reversed(published):
                destination.unlink(missing_ok=True)
            raise

        result = {
            "candidate_count": len(merged),
            "groups": list(_GROUPS),
            "memory": pool.snapshot(),
            "reference_used": False,
            "manifests": copy.deepcopy(merged),
            "dry_run": dry_run,
        }
    return result


__all__ = [
    "CompositionProducer",
    "GenerationRequest",
    "RuntimePreparer",
    "RuntimeRequest",
    "run_candidate_pipeline",
]
