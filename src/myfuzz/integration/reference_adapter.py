"""Run a trusted reference evaluator outside the candidate generator boundary.

The adapter constrains command provenance, environment, process lifetime, and output
publication. It is not a filesystem, network, or hostile-code sandbox; an evaluator
inside ``allowed_root`` remains trusted code.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


_MAX_SUMMARY_BYTES = 2 * 1024 * 1024
_MAX_ERROR_BYTES = 4096
_SUPERVISOR_SHUTDOWN_SECONDS = 2.0
_SAFE_OPTION = re.compile(r"-{1,2}[A-Za-z0-9][A-Za-z0-9_.:-]*\Z")
_SAFE_SCALAR = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]*\Z")
_SAFE_GENERATOR_PATH_COMPONENT = re.compile(
    r"(?:[A-Za-z0-9_][A-Za-z0-9_.-]*|\.[A-Za-z0-9_.-]+)\Z"
)
_CONCRETE_PATH_TYPE = type(Path())


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _allowed_root(path: Path) -> Path:
    if not isinstance(path, Path):
        raise TypeError("allowed_root must be a pathlib.Path")
    root = path.resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(path)
    return root


def _validate_generator_path(path: Path) -> None:
    for component in path.parts:
        if component in {path.anchor, ".", ".."}:
            continue
        if _SAFE_GENERATOR_PATH_COMPONENT.fullmatch(component) is None:
            raise ValueError("generator path contains ambiguous option syntax")


def _validated_command(command: Sequence[str], root: Path) -> tuple[tuple[str, ...], int]:
    if isinstance(command, (str, bytes, bytearray)) or not command:
        raise ValueError("reference_command must be a non-empty sequence")
    if any(not isinstance(argument, str) or not argument or "\0" in argument for argument in command):
        raise ValueError("reference_command contains an invalid argument")

    executable_input = Path(command[0])
    candidate = executable_input if executable_input.is_absolute() else root / executable_input
    if candidate.is_symlink():
        raise PermissionError("reference evaluator symlinks are not allowed")
    try:
        executable = candidate.resolve(strict=True)
    except OSError as error:
        raise PermissionError("reference evaluator is unavailable") from error
    if not _within(executable, root):
        raise PermissionError("reference evaluator is outside the allowed root")
    mode = executable.stat().st_mode
    if not stat.S_ISREG(mode) or mode & 0o111 == 0:
        raise PermissionError("reference evaluator must be an executable regular file")
    for argument in command[1:]:
        option, separator, value = argument.partition("=")
        safe = bool(_SAFE_OPTION.fullmatch(option) or _SAFE_SCALAR.fullmatch(option))
        if separator:
            safe = safe and bool(_SAFE_SCALAR.fullmatch(value))
        if not safe:
            raise PermissionError(
                "reference evaluator path-bearing arguments are not allowed; "
                "use MYFUZZ_REFERENCE_ROOT"
            )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(executable, flags)
    except OSError as error:
        raise PermissionError("reference evaluator is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o111 == 0:
            raise PermissionError("reference evaluator must be an executable regular file")
    except BaseException:
        os.close(descriptor)
        raise
    return ((f"/proc/self/fd/{descriptor}", *command[1:]), descriptor)


def _safe_environment(output_path: Path, root: Path) -> dict[str, str]:
    return {
        "PATH": os.defpath,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "MYFUZZ_REFERENCE_OUTPUT": os.fspath(output_path),
        "MYFUZZ_REFERENCE_ROOT": os.fspath(root),
    }


def _read_summary(path: Path) -> dict[str, object]:
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError("reference evaluator did not produce a readable summary file") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("reference evaluator did not produce a regular summary file")
        if metadata.st_size <= 0 or metadata.st_size > _MAX_SUMMARY_BYTES:
            raise ValueError("reference evaluator summary size is invalid")
        payload = bytearray()
        while len(payload) <= _MAX_SUMMARY_BYTES:
            chunk = os.read(
                descriptor,
                min(64 * 1024, _MAX_SUMMARY_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        if not payload or len(payload) > _MAX_SUMMARY_BYTES:
            raise ValueError("reference evaluator summary size is invalid")
    finally:
        os.close(descriptor)
    try:
        document = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("reference evaluator summary is not valid UTF-8 JSON") from error
    if not isinstance(document, Mapping):
        raise ValueError("reference evaluator summary must be a JSON object")
    summary = dict(document)
    summary["comparison_scope"] = "reference-descriptive"
    return summary


def _publish_summary(destination: Path, summary: Mapping[str, object]) -> None:
    text = json.dumps(summary, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    published: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=".reference-publish.",
            suffix=".json",
            dir=destination.parent,
            delete=False,
        ) as stream:
            published = Path(stream.name)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(published, destination)
        published = None
    finally:
        if published is not None:
            published.unlink(missing_ok=True)


def _supervisor_command(command: Sequence[str], status_descriptor: int) -> tuple[str, ...]:
    supervisor = Path(__file__).with_name("_reference_supervisor.py").resolve(strict=True)
    return (
        sys.executable,
        os.fspath(supervisor),
        "--status-fd",
        str(status_descriptor),
        "--",
        *command,
    )


def _read_supervisor_status(descriptor: int) -> bool:
    try:
        try:
            return os.read(descriptor, 2) == b"1"
        except OSError:
            return False
    finally:
        os.close(descriptor)


def _terminate_supervisor(process: subprocess.Popen[bytes]) -> int:
    if process.poll() is not None:
        return int(process.returncode)
    process.terminate()
    try:
        return process.wait(timeout=_SUPERVISOR_SHUTDOWN_SECONDS)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait()
        raise RuntimeError("reference evaluator supervisor could not clean up") from error


@dataclass(frozen=True, slots=True)
class ReferenceAdapter:
    """Execute trusted allowlisted code and return bounded descriptive data.

    Command arguments are deliberately scalar-only. Evaluators locate their trusted
    source root through ``MYFUZZ_REFERENCE_ROOT`` and publish the one result through
    ``MYFUZZ_REFERENCE_OUTPUT``.
    """

    reference_command: Sequence[str]
    allowed_root: Path
    timeout_seconds: float = 60.0

    def run(self, output_dir: Path) -> dict[str, object]:
        root = _allowed_root(self.allowed_root)
        if not isinstance(output_dir, Path):
            raise TypeError("output_dir must be a pathlib.Path")
        if not isinstance(self.timeout_seconds, (int, float)) or isinstance(self.timeout_seconds, bool):
            raise TypeError("timeout_seconds must be numeric")
        if not math.isfinite(float(self.timeout_seconds)) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

        command, evaluator_descriptor = _validated_command(self.reference_command, root)
        temporary: Path | None = None
        try:
            if output_dir.is_symlink():
                raise PermissionError("reference output directory symlinks are not allowed")
            output_dir.mkdir(parents=True, exist_ok=True)
            output = output_dir.resolve(strict=True)
            if not output.is_dir():
                raise NotADirectoryError(output_dir)
            destination = output / "reference_summary.json"

            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".reference-summary.",
                suffix=".json",
                dir=output,
            )
            os.close(descriptor)
            temporary = Path(temporary_name)
            with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
                status_reader, status_writer = os.pipe()
                try:
                    process = subprocess.Popen(
                        _supervisor_command(command, status_writer),
                        cwd=root,
                        env=_safe_environment(temporary, root),
                        stdin=subprocess.DEVNULL,
                        stdout=stdout,
                        stderr=stderr,
                        start_new_session=True,
                        pass_fds=(status_writer, evaluator_descriptor),
                    )
                except BaseException:
                    os.close(status_reader)
                    raise
                finally:
                    os.close(status_writer)
                timed_out = False
                try:
                    returncode = process.wait(timeout=float(self.timeout_seconds))
                except subprocess.TimeoutExpired:
                    timed_out = True
                    returncode = _terminate_supervisor(process)
                if not _read_supervisor_status(status_reader):
                    raise RuntimeError("reference evaluator process tree did not terminate")
                if timed_out:
                    raise TimeoutError("reference evaluator timed out")
                if returncode != 0:
                    stderr.seek(0)
                    detail = stderr.read(_MAX_ERROR_BYTES).decode("utf-8", errors="replace").strip()
                    suffix = f": {detail}" if detail else ""
                    raise RuntimeError(
                        f"reference evaluator exited with status {returncode}{suffix}"
                    )
            summary = _read_summary(temporary)
            _publish_summary(destination, summary)
            return summary
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
            os.close(evaluator_descriptor)


class GeneratorFlag(str, Enum):
    """Closed set of path-free generator switches."""

    DEREFERENCE = "--dereference"
    PREFERENCE = "--preference"


class GeneratorPathSyntax(Enum):
    """Closed rendering forms for path-bearing generator arguments."""

    POSITIONAL = "positional"
    INCLUDE = "include"
    SYSTEM_INCLUDE = "system-include"
    INCDIR = "incdir"
    SOURCE = "source"
    SOURCE_COLON = "source-colon"
    SOURCES = "sources"
    RESPONSE = "response"
    DIRECTORIES = "directories"
    DIRECTORY_PAREN = "directory-paren"


_GENERATOR_PATH_RENDERING: dict[GeneratorPathSyntax, tuple[str, str, str]] = {
    GeneratorPathSyntax.POSITIONAL: ("", "", ""),
    GeneratorPathSyntax.INCLUDE: ("-I", "", ""),
    GeneratorPathSyntax.SYSTEM_INCLUDE: ("-isystem", "", ""),
    GeneratorPathSyntax.INCDIR: ("+incdir+", "", ""),
    GeneratorPathSyntax.SOURCE: ("--source=", "", ""),
    GeneratorPathSyntax.SOURCE_COLON: ("--source:", "", ""),
    GeneratorPathSyntax.SOURCES: ("--sources=", ",", ""),
    GeneratorPathSyntax.RESPONSE: ("@", "", ""),
    GeneratorPathSyntax.DIRECTORIES: ("--dirs=", ";", ""),
    GeneratorPathSyntax.DIRECTORY_PAREN: ("--dir=(", "", ")"),
}


@dataclass(frozen=True, slots=True)
class GeneratorPathArgument:
    """One argv token rendered exclusively from typed filesystem paths."""

    paths: tuple[Path, ...]
    syntax: GeneratorPathSyntax = GeneratorPathSyntax.POSITIONAL

    def __post_init__(self) -> None:
        if not isinstance(self.paths, tuple) or not self.paths:
            raise TypeError("paths must be a non-empty tuple of pathlib.Path values")
        if any(type(path) is not _CONCRETE_PATH_TYPE for path in self.paths):
            raise TypeError("paths must use the concrete pathlib.Path type")
        if any("\0" in os.fspath(path) for path in self.paths):
            raise TypeError("paths must contain only valid pathlib.Path values")
        for path in self.paths:
            _validate_generator_path(path)
        if not isinstance(self.syntax, GeneratorPathSyntax):
            raise TypeError("syntax must be a GeneratorPathSyntax")
        if self.syntax not in {
            GeneratorPathSyntax.SOURCES,
            GeneratorPathSyntax.DIRECTORIES,
        } and len(self.paths) != 1:
            raise ValueError("this generator path syntax accepts exactly one path")

    def render(self) -> str:
        return _render_generator_path(self)


def _render_generator_path(argument: GeneratorPathArgument) -> str:
    prefix, separator, suffix = _GENERATOR_PATH_RENDERING[argument.syntax]
    return prefix + separator.join(os.fspath(path) for path in argument.paths) + suffix


GeneratorArgument = GeneratorFlag | GeneratorPathArgument


@dataclass(frozen=True, slots=True)
class GeneratorCommand:
    """Generator argv whose filesystem provenance has exactly one typed source."""

    executable: str
    arguments: tuple[GeneratorArgument, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.executable, str) or _SAFE_SCALAR.fullmatch(self.executable) is None:
            raise TypeError("executable must be a non-path scalar command name")
        if not isinstance(self.arguments, tuple) or any(
            type(argument) not in {GeneratorFlag, GeneratorPathArgument}
            for argument in self.arguments
        ):
            raise TypeError("arguments must be typed generator arguments")

    @property
    def argv(self) -> tuple[str, ...]:
        return (
            self.executable,
            *(
                argument.value if type(argument) is GeneratorFlag else _render_generator_path(argument)
                for argument in self.arguments
            ),
        )

    @property
    def filesystem_arguments(self) -> tuple[Path, ...]:
        return tuple(
            path
            for argument in self.arguments
            if type(argument) is GeneratorPathArgument
            for path in argument.paths
        )


def assert_reference_not_in_generator_argv(
    command: GeneratorCommand,
    forbidden_path: Path,
    *,
    base_root: Path | None = None,
) -> None:
    """Reject a structured generator command that can reach the evaluator root."""
    if type(command) is not GeneratorCommand:
        raise TypeError("command must be a GeneratorCommand with structured filesystem arguments")
    if not isinstance(forbidden_path, Path):
        raise TypeError("forbidden_path must be a pathlib.Path")
    root = forbidden_path.resolve(strict=False)
    if base_root is not None and not isinstance(base_root, Path):
        raise TypeError("base_root must be a pathlib.Path")
    base = (base_root or Path.cwd()).resolve(strict=False)
    for candidate in command.filesystem_arguments:
        resolved = (
            candidate.resolve(strict=False)
            if candidate.is_absolute()
            else (base / candidate).resolve(strict=False)
        )
        if _within(resolved, root):
            raise PermissionError("reference evaluator path crossed the generator boundary")
