"""Pinned, source-only HDL interface evidence collection.

The crawler deliberately consumes an already materialized local checkout.  It
does not acquire sources or invoke a HDL compiler; callers can therefore use
it in constrained, reproducible analysis environments.
"""

from __future__ import annotations

import hashlib
import re
import shlex
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path

from myfuzz.contracts import validate_contract
from myfuzz.protocols.catalog import ProtocolCatalog
from myfuzz.protocols.model import ProtocolDefinitionError
from myfuzz.protocols.widths import ProtocolWidthError, compile_width_expression
from myfuzz.scripts.source_only_frontend import (
    HDL_SUFFIXES,
    IDENT_RE,
    RANGE_RE,
    const_int,
    find_matching,
    line_col,
    mask_comments_and_strings,
    width_from_ranges,
)

from .interface_description import EndpointDescription, FieldHint, InterfaceDescription, SourceLocator


_MODULE_RE = re.compile(r"\bmodule\s+([A-Za-z_][A-Za-z0-9_$]*)\b")
_ENDMODULE_RE = re.compile(r"\bendmodule\b")
_DIRECTION_RE = re.compile(r"\b(input|output|inout)\b")
_DECL_KEYWORDS = frozenset(
    {
        "input", "output", "inout", "ref", "wire", "reg", "logic", "signed", "unsigned",
        "tri", "bit", "var", "const", "integer", "time", "realtime", "byte", "shortint",
        "int", "longint",
    }
)
_SOURCE_TAG_RE = re.compile(
    r"myfuzz:\s*endpoint=([^\s]+)\s+field=([^\s]+)", re.IGNORECASE
)
_PIN_RE = re.compile(r"(?:git:[0-9a-f]{40}|sha256:[0-9a-f]{64})\Z")


class SourceCrawlError(ValueError):
    """Raised when source evidence is unsafe, unpinned, or insufficient."""


@dataclass(frozen=True, slots=True)
class SourcePortFact:
    module: str
    name: str
    direction: str
    width: int
    signed: bool
    source_file: str
    line: int
    column: int


@dataclass(frozen=True, slots=True)
class TimingObservation:
    kind: str
    fields: tuple[str, ...]
    clock: str | None
    source_file: str
    line: int
    module: str = ""


@dataclass(frozen=True, slots=True)
class SourceSnapshot:
    revision: str
    content_hash: str
    files: tuple[str, ...]
    modules: tuple[str, ...]
    ports: tuple[SourcePortFact, ...]
    timing: tuple[TimingObservation, ...]
    # (parent module, instance name, child module); no elaboration is inferred.
    instances: tuple[tuple[str, str, str], ...] = ()
    # (module, port, source file, line, endpoint, field); immutable source evidence.
    documentation_tags: tuple[tuple[str, str, str, int, str, str], ...] = ()


def _relative(root: Path, value: Path) -> str:
    try:
        return value.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise SourceCrawlError("path-outside-source-root") from error


def source_tree_hash(root: Path, files: Sequence[Path]) -> str:
    """Hash unique sorted paths and bytes using unsigned 64-bit length framing.

    The domain tag and length prefixes delimit paths, contents, and entries;
    neither the absolute root nor caller ordering participates in the hash.
    Filelists must be included alongside HDL when pinning a filelist input.
    """
    resolved_root = root.resolve()
    contents = {}
    for path in files:
        relative = _relative(resolved_root, path)
        if not path.is_file():
            raise SourceCrawlError(f"source-file-missing:{relative}")
        contents[relative] = path.read_bytes()
    return _content_hash(contents)


def _content_hash(contents: Mapping[str, bytes]) -> str:
    digest = hashlib.sha256(b"myfuzz-source-tree-v2\0")
    for relative, content in sorted(contents.items()):
        name = relative.encode("utf-8")
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return f"sha256:{digest.hexdigest()}"


def _safe_child(root: Path, raw: str) -> Path:
    path = Path(raw)
    if (not raw or "\\" in raw or "\0" in raw or re.match(r"[A-Za-z]:", raw)
            or path.is_absolute() or ".." in path.parts):
        raise SourceCrawlError("path-outside-source-root")
    candidate = (root / path).resolve()
    _relative(root, candidate)
    # A symlink's resolved target is not the declared pinned tree entry.
    current = root
    for part in path.parts:
        current = current / part
        if current.is_symlink():
            raise SourceCrawlError("unsupported-source-symlink")
    return candidate


def _declared_files(
    root: Path, locator: SourceLocator, read: Callable[[Path], bytes],
) -> tuple[Path, ...]:
    files: set[Path] = set()

    def add_source(raw: str) -> None:
        source = _safe_child(root, raw)
        if source.suffix not in HDL_SUFFIXES or not source.is_file():
            raise SourceCrawlError(f"source-file-missing:{raw}")
        read(source)
        files.add(source)

    def local_path(parent: Path, raw: str) -> Path:
        # Validate the raw option too: joining an absolute path must not erase it.
        _safe_child(root, raw)
        return _safe_child(root, (parent.relative_to(root) / raw).as_posix())

    def include_root(parent: Path, raw: str) -> None:
        directory = local_path(parent, raw)
        if not directory.is_dir():
            raise SourceCrawlError(f"include-root-missing:{raw}")

    def expand_filelist(path: Path, seen: set[Path]) -> None:
        path = path.resolve()
        _relative(root, path)
        if path in seen:
            return
        if not path.is_file():
            raise SourceCrawlError(f"source-file-missing:{_relative(root, path)}")
        seen.add(path)
        # Verify before interpreting even the first directive; hash filelists too.
        try:
            tokens = iter(shlex.split(read(path).decode("utf-8"), comments=True))
            for item in tokens:
                if item in ("-f", "-F"):
                    parent = path.parent if item == "-f" else root
                    expand_filelist(local_path(parent, next(tokens)), seen)
                elif item.startswith("+incdir+"):
                    for directory in item[len("+incdir+"):].split("+"):
                        include_root(path.parent, directory)
                elif item == "-I" or item.startswith("-I"):
                    include_root(path.parent, next(tokens) if item == "-I" else item[2:])
                elif item.startswith("+define+"):
                    continue
                elif item.startswith(("-", "+")):
                    raise SourceCrawlError(f"unsupported-filelist-option:{item}")
                else:
                    add_source(_relative(root, local_path(path.parent, item)))
        except (StopIteration, UnicodeDecodeError, ValueError) as error:
            if isinstance(error, SourceCrawlError):
                raise
            raise SourceCrawlError("invalid-filelist") from error

    for raw in locator.files:
        add_source(raw)
    if locator.filelist is not None:
        expand_filelist(_safe_child(root, locator.filelist), set())
    for raw in locator.include_roots:
        include_root(root, raw)
    return tuple(sorted(files, key=lambda item: _relative(root, item)))


def _parts(text: str, offset: int) -> list[tuple[str, int]]:
    result: list[tuple[str, int]] = []
    start = 0
    paren = bracket = brace = 0
    for index, char in enumerate(text):
        if char == "(":
            paren += 1
        elif char == ")" and paren:
            paren -= 1
        elif char == "[":
            bracket += 1
        elif char == "]" and bracket:
            bracket -= 1
        elif char == "{":
            brace += 1
        elif char == "}" and brace:
            brace -= 1
        elif char == "," and not (paren or bracket or brace):
            result.append((text[start:index], offset + start))
            start = index + 1
    if text[start:].strip():
        result.append((text[start:], offset + start))
    return result


def _constant_width(fragment: str) -> int:
    remainder = RANGE_RE.sub("", fragment)
    if "[" in remainder or "]" in remainder:
        raise SourceCrawlError("unsupported-port-width")
    for most_significant, least_significant in RANGE_RE.findall(fragment):
        if const_int(most_significant) is None or const_int(least_significant) is None:
            raise SourceCrawlError("unsupported-port-width")
    return width_from_ranges(fragment)


def _port_shape(prefix: str) -> tuple[int, bool]:
    """Recognize integral builtins only; opaque types require elaboration.

    An unresolved typedef/record must never acquire a fabricated scalar width.
    Integer atom types have an implicit width and signedness, unlike vectors.
    """
    width = _constant_width(prefix)
    words = RANGE_RE.sub("", prefix).split()
    atoms = {"byte": 8, "shortint": 16, "int": 32, "integer": 32,
             "longint": 64, "time": 64}
    types = {"logic", "bit", "reg", *atoms}
    allowed = types | {"input", "output", "inout", "wire", "tri", "var", "signed", "unsigned"}
    if any(word not in allowed for word in words):
        raise SourceCrawlError("unsupported-port-type")
    declared = [word for word in words if word in types]
    if len(declared) > 1 or ("signed" in words and "unsigned" in words):
        raise SourceCrawlError("unsupported-port-type")
    kind = declared[0] if declared else "logic"
    if kind in atoms:
        if "[" in prefix:
            raise SourceCrawlError("unsupported-port-type:packed-integer-atom")
        width = atoms[kind]
    signed = "signed" in words or (kind in atoms and kind != "time" and "unsigned" not in words)
    return width, signed


def _declaration_ports(
    original: str,
    masked: str,
    offset: int,
    module: str,
    source_file: str,
) -> list[tuple[SourcePortFact, int]]:
    records: list[tuple[SourcePortFact, int]] = []
    direction = ""
    width = 1
    signed = False
    for fragment, fragment_offset in _parts(masked, offset):
        if "=" in fragment:
            raise SourceCrawlError("unsupported-port-default")
        # Ignore identifiers inside ranges when locating the declared port name.
        # Any range after that name is unpacked, including inherited declarations.
        name_fragment = re.sub(r"\[[^\]]*\]", lambda match: " " * len(match.group()), fragment)
        names = [match for match in IDENT_RE.finditer(name_fragment)
                 if match.group(0) not in _DECL_KEYWORDS]
        if not names:
            continue
        name_match = names[-1]
        if "[" in fragment[name_match.end():]:
            raise SourceCrawlError("unsupported-unpacked-port")
        matched_direction = _DIRECTION_RE.search(fragment)
        if matched_direction is not None:
            direction = matched_direction.group(1)
            width, signed = _port_shape(fragment[:name_match.start()])
        if not direction:
            continue
        absolute = fragment_offset + name_match.start()
        line, column = line_col(original, absolute)
        records.append(
            (
                SourcePortFact(module, name_match.group(0), direction, width, signed, source_file, line, column),
                absolute,
            )
        )
    return records


def _module_ports(
    original: str,
    masked: str,
    module_match: re.Match[str],
    module_end: int,
    module: str,
    source_file: str,
) -> list[tuple[SourcePortFact, int]]:
    # A packed record in an ANSI header can contain semicolons. Locate the
    # module-header terminator outside parentheses before validating its type.
    depth = 0
    semi = -1
    for position in range(module_match.end(), module_end):
        char = masked[position]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == ";" and depth == 0:
            semi = position
            break
    if semi < 0:
        return []
    opens: list[int] = []
    cursor = module_match.end()
    while True:
        opening = masked.find("(", cursor, semi)
        if opening < 0:
            break
        closing = find_matching(masked, opening, "(", ")")
        if closing < 0 or closing > semi:
            break
        opens.append(opening)
        cursor = closing + 1
    header_ports: list[tuple[SourcePortFact, int]] = []
    if opens:
        opening = opens[-1]
        closing = find_matching(masked, opening, "(", ")")
        header_ports = _declaration_ports(
            original, masked[opening + 1:closing], opening + 1, module, source_file
        )
    if header_ports:
        return header_ports
    body = masked[semi + 1:module_end]
    records: list[tuple[SourcePortFact, int]] = []
    for declaration in re.finditer(r"\b(?:input|output|inout)\b[^;]*;", body):
        start = semi + 1 + declaration.start()
        records.extend(_declaration_ports(original, declaration.group(0)[:-1], start, module, source_file))
    return records


def _timing(
    original: str, masked: str, start: int, end: int, source_file: str
) -> list[TimingObservation]:
    observations: list[TimingObservation] = []
    body = masked[start:end]
    always_re = re.compile(r"\balways(?:_ff)?\s*@\s*\(([^)]*)\)")
    for always in always_re.finditer(body):
        event = always.group(1)
        edges = re.findall(r"\b(posedge|negedge)\s+([A-Za-z_][A-Za-z0-9_$]*)", event)
        clock = next((name for edge, name in edges if edge == "posedge"), None)
        resets = tuple(name for edge, name in edges if edge == "negedge")
        begin = re.match(r"\s*begin\b", body[always.end():])
        if begin is None:
            block_end = body.find(";", always.end()) + 1
            if block_end <= 0:
                block_end = len(body)
            block_start = always.end()
        else:
            begin_word = always.end() + begin.end() - len("begin")
            block_start = begin_word + len("begin")
            # Nested blocks are uncommon in the source-only subset.  Find a balanced
            # begin/end region so assignments in the enclosing block are retained.
            depth = 0
            block_end = len(body)
            for token in re.finditer(r"\b(begin|end)\b", body[begin_word:]):
                if token.group(1) == "begin":
                    depth += 1
                else:
                    depth -= 1
                    if depth == 0:
                        block_end = begin_word + token.end()
                        break
        block = body[block_start:block_end]
        for assignment in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_$]*)\s*(?:<=|=)", block):
            line, _ = line_col(original, start + block_start + assignment.start())
            observations.append(
                TimingObservation("sequential_assignment" if clock else "combinational_assignment", (assignment.group(1),), clock, source_file, line)
            )
            if clock and resets:
                observations.append(
                    TimingObservation("reset_membership", (assignment.group(1), *resets), clock, source_file, line)
                )
        for stalled in re.finditer(
            r"\bif\s*\(\s*([A-Za-z_][A-Za-z0-9_$]*)\s*&&\s*!\s*([A-Za-z_][A-Za-z0-9_$]*)\s*\)\s*(?:begin\s*)?\s*([A-Za-z_][A-Za-z0-9_$]*)\s*<=\s*\3\b",
            block,
        ):
            line, _ = line_col(original, start + block_start + stalled.start())
            observations.append(TimingObservation("stall_holds_payload", stalled.groups(), clock, source_file, line))
        for transfer in re.finditer(
            r"\bif\s*\(\s*([A-Za-z_][A-Za-z0-9_$]*)\s*&&\s*([A-Za-z_][A-Za-z0-9_$]*)\s*\)",
            block,
        ):
            if "!" not in transfer.group(0) and _is_handshake_pair(*transfer.groups()):
                line, _ = line_col(original, start + block_start + transfer.start())
                observations.append(TimingObservation("transfer_accept", transfer.groups(), clock, source_file, line))
    for combinational in re.finditer(r"\balways_(?:comb|latch)\b", body):
        line, _ = line_col(original, start + combinational.start())
        observations.append(TimingObservation("combinational_assignment", (), None, source_file, line))
    return observations


def _is_handshake_pair(first: str, second: str) -> bool:
    names = (_normalized(first), _normalized(second))
    pairs = (("valid", "ready"), ("req", "ack"), ("request", "ack"),
             ("request", "grant"))
    return any((left in names[0] and right in names[1]) or
               (left in names[1] and right in names[0])
               for left, right in pairs)


def _normalized(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _instances(body: str, parent: str) -> list[tuple[str, str, str]]:
    """Recognize simple module instances, retaining duplicates for ambiguity.

    Array/generate scopes are not elaborated: hierarchy hints requiring those
    shapes remain unresolved rather than inventing an instance path.
    """
    # Keep only unscoped declaration statements. Mask procedural/generate
    # blocks so nested declarations cannot acquire a fabricated flat path.
    masked = list(body)
    depth = 0
    start = 0
    for token in re.finditer(r"\b(begin|end|generate|endgenerate)\b", body):
        if token.group() in ("begin", "generate"):
            if depth == 0:
                start = token.start()
            depth += 1
        elif depth:
            depth -= 1
            if depth == 0:
                masked[start:token.end()] = " " * (token.end() - start)
    if depth:
        masked[start:] = " " * (len(body) - start)
    body = "".join(masked)
    instances = []
    for match in re.finditer(r"(?:^|;)\s*([A-Za-z_][A-Za-z0-9_$]*)\s+", body):
        cursor = match.end()
        if body[cursor:cursor + 1] == "#":
            cursor += 1
            while cursor < len(body) and body[cursor].isspace():
                cursor += 1
            if body[cursor:cursor + 1] != "(":
                continue
            closing = find_matching(body, cursor, "(", ")")
            if closing < 0:
                continue
            cursor = closing + 1
        instance = re.match(r"\s*([A-Za-z_][A-Za-z0-9_$]*)\s*\(", body[cursor:])
        if instance is not None:
            instances.append((parent, instance.group(1), match.group(1)))
    return instances


class SourceCrawler:
    def crawl(self, locator: SourceLocator, *, base_dir: Path) -> SourceSnapshot:
        if _PIN_RE.fullmatch(locator.revision) is None:
            raise SourceCrawlError("invalid-source-pin")
        root = _safe_child(base_dir.resolve(), locator.source_root)
        if not root.is_dir():
            raise SourceCrawlError("source-root-missing")
        git_root: Path | None = None
        if locator.revision.startswith("git:"):
            revision = locator.revision[4:]
            command = ["git", "-C", root.as_posix(), "rev-parse", "--verify", f"{revision}^{{commit}}"]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            if result.returncode != 0 or result.stdout.strip() != revision:
                raise SourceCrawlError("git-revision-mismatch")
            head = subprocess.run(
                ["git", "-C", root.as_posix(), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=False,
            )
            if head.returncode != 0 or head.stdout.strip() != revision:
                raise SourceCrawlError("git-revision-mismatch")
            top = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
                capture_output=True, text=True, check=False,
            )
            if top.returncode != 0:
                raise SourceCrawlError("git-revision-mismatch")
            git_root = Path(top.stdout.strip()).resolve()

        contents: dict[str, bytes] = {}

        def read(path: Path) -> bytes:
            relative = _relative(root, path)
            if relative not in contents:
                if not path.is_file():
                    raise SourceCrawlError(f"source-file-missing:{relative}")
                content = path.read_bytes()
                if git_root is not None:
                    tree_path = path.relative_to(git_root).as_posix()
                    blob = subprocess.run(
                        ["git", "-C", str(git_root), "cat-file", "blob", f"{revision}:{tree_path}"],
                        capture_output=True, check=False,
                    )
                    if blob.returncode != 0 or blob.stdout != content:
                        raise SourceCrawlError(f"git-content-mismatch:{relative}")
                contents[relative] = content
            return contents[relative]

        files = _declared_files(root, locator, read)
        content_hash = _content_hash(contents)
        if locator.revision.startswith("sha256:") and locator.revision != content_hash:
            raise SourceCrawlError("content-hash-mismatch")

        ports: list[SourcePortFact] = []
        modules: list[str] = []
        timing: list[TimingObservation] = []
        instances: list[tuple[str, str, str]] = []
        documentation_tags: list[tuple[str, str, str, int, str, str]] = []
        for path in files:
            relative = _relative(root, path)
            try:
                original = read(path).decode("utf-8")
            except UnicodeDecodeError as error:
                raise SourceCrawlError(f"invalid-source-encoding:{relative}") from error
            masked = mask_comments_and_strings(original)
            matches = list(_MODULE_RE.finditer(masked))
            for module_match in matches:
                module = module_match.group(1)
                end_match = _ENDMODULE_RE.search(masked, module_match.end())
                if end_match is None:
                    continue
                modules.append(module)
                records = _module_ports(original, masked, module_match, end_match.start(), module, relative)
                ports.extend(record[0] for record in records)
                tags = [
                    (tag.start(), tag.group(1), tag.group(2))
                    for tag in _SOURCE_TAG_RE.finditer(original, module_match.start(), end_match.end())
                ]
                for port, position in records:
                    attached = tuple(
                        (endpoint, field)
                        for tag_position, endpoint, field in tags
                        if tag_position < position
                        and not any(other_position < position and other_position > tag_position for _, other_position in records)
                    )
                    if attached:
                        documentation_tags.extend(
                            (port.module, port.name, port.source_file, port.line, endpoint, field)
                            for endpoint, field in attached
                        )
                header_end = masked.find(";", module_match.end(), end_match.start())
                if header_end >= 0:
                    timing.extend(replace(item, module=module) for item in
                                  _timing(original, masked, header_end + 1, end_match.start(), relative))
                    instances.extend(_instances(masked[header_end + 1:end_match.start()], module))
        return SourceSnapshot(
            locator.revision,
            content_hash,
            tuple(sorted(contents)),
            tuple(sorted(modules)),
            tuple(sorted(ports, key=lambda item: (item.module, item.name, item.source_file, item.line, item.column))),
            tuple(sorted(timing, key=lambda item: (item.source_file, item.line, item.kind, item.fields))),
            tuple(sorted(instance for instance in instances if instance[2] in modules)),
            tuple(sorted(documentation_tags)),
        )

    def _module_ports(
        self, snapshot: SourceSnapshot, endpoint: EndpointDescription, top_module: str,
    ) -> tuple[tuple[SourcePortFact, ...], str, str]:
        def hierarchy(parts: tuple[str, ...]) -> list[str]:
            if not parts:
                return []
            current = parts[0] if parts[0] in snapshot.modules else top_module
            remaining = parts[1:] if parts[0] in snapshot.modules else parts
            if snapshot.modules.count(current) > 1:
                raise SourceCrawlError(f"endpoint-ambiguous:{endpoint.endpoint_id}")
            for name in remaining:
                children = [child for parent, instance, child in snapshot.instances
                            if parent == current and name in (instance, child)]
                if len(children) > 1:
                    raise SourceCrawlError(f"endpoint-ambiguous:{endpoint.endpoint_id}")
                if not children:
                    return []
                current = children[0]
                if snapshot.modules.count(current) > 1:
                    raise SourceCrawlError(f"endpoint-ambiguous:{endpoint.endpoint_id}")
            return [current] if current in snapshot.modules else []

        # An explicit but invalid selector is not permission to choose the top.
        if endpoint.module is not None:
            candidates, evidence = [endpoint.module], "explicit_module"
        elif endpoint.hierarchy:
            candidates, evidence = hierarchy(endpoint.hierarchy), "hierarchy_hint"
        elif endpoint.aliases:
            candidates = []
            tags = snapshot.documentation_tags
            for alias in sorted(set(endpoint.aliases)):
                named = hierarchy(tuple(re.split(r"[./]", alias)))
                tagged = sorted({module for module, _, _, _, tag_endpoint, _ in tags
                                 if tag_endpoint == alias})
                # Corroborating tags may agree with one selector, but different
                # instance aliases are still different endpoint candidates.
                candidates.extend(sorted(set(named + tagged)))
            evidence = "endpoint_alias"
        else:
            candidates, evidence = [top_module], "source_top_module"
        if not candidates:
            raise SourceCrawlError(f"endpoint-unresolved:{endpoint.endpoint_id}")
        if len(candidates) != 1 or snapshot.modules.count(candidates[0]) > 1:
            raise SourceCrawlError(f"endpoint-ambiguous:{endpoint.endpoint_id}")
        module = candidates[0]
        matches = tuple(port for port in snapshot.ports if port.module == module)
        if not matches:
            raise SourceCrawlError(f"endpoint-unresolved:{endpoint.endpoint_id}")
        return matches, module, evidence

    def _field_port(
        self, snapshot: SourceSnapshot, endpoint: EndpointDescription, field: FieldHint,
        ports: tuple[SourcePortFact, ...]
    ) -> tuple[SourcePortFact, str]:
        aliases = set(field.aliases)
        explicit = tuple(port for port in ports if port.name in aliases)
        tagged = tuple(
            port for port in ports
            if any(tag_endpoint in (endpoint.endpoint_id, *endpoint.aliases)
                   and tag_field == field.role
                   for module, name, source_file, line, tag_endpoint, tag_field
                   in snapshot.documentation_tags
                   if (module, name, source_file, line) ==
                   (port.module, port.name, port.source_file, port.line))
        )
        if explicit and tagged and {port.name for port in explicit} != {port.name for port in tagged}:
            raise SourceCrawlError(f"source-semantic-conflict:{endpoint.endpoint_id}:{field.role}")
        candidates: tuple[SourcePortFact, ...]
        evidence: str
        if explicit:
            candidates, evidence = explicit, "explicit_alias"
        elif tagged:
            candidates, evidence = tagged, "source_documentation"
        else:
            exact = tuple(port for port in ports if port.name == field.role)
            if exact:
                candidates, evidence = exact, "exact_role_label"
            else:
                candidates = tuple(port for port in ports if _normalized(port.name) == _normalized(field.role))
                evidence = "normalized_name"
        if not candidates:
            raise SourceCrawlError(f"field-unresolved:{endpoint.endpoint_id}:{field.role}")
        if len(candidates) != 1:
            raise SourceCrawlError(f"field-ambiguous:{endpoint.endpoint_id}:{field.role}")
        return candidates[0], evidence

    @staticmethod
    def _protocol_candidates(
        endpoint: EndpointDescription,
        fields: list[dict[str, object]],
        catalog: ProtocolCatalog | None,
    ) -> list[dict[str, object]]:
        if endpoint.protocol is None:
            return []
        protocol_id, version = endpoint.protocol
        candidate: dict[str, object] = {"id": protocol_id, "version": version, "evidence": "declared"}
        if catalog is None:
            raise SourceCrawlError(f"protocol-catalog-required:{endpoint.endpoint_id}")
        try:
            plugin = catalog.require(protocol_id, version)
        except ProtocolDefinitionError as error:
            raise SourceCrawlError(f"protocol-unsupported:{endpoint.endpoint_id}:{protocol_id}@{version}") from error
        # Semantic role tokens describe orientation, never a CPU or port name.
        tokens = set(re.split(r"[^a-z0-9]+", endpoint.function.lower()))
        host = bool(tokens & {"master", "host", "initiator"})
        device = bool(tokens & {"slave", "device", "target"})
        if host == device:
            raise SourceCrawlError(f"protocol-orientation-ambiguous:{endpoint.endpoint_id}")
        candidate["orientation"] = "host" if host else "device"
        by_role: dict[str, dict[str, object]] = {}
        aliases = {"addr": "address", "wdata": "writedata", "rdata": "readdata"}
        for field in fields:
            normalized = _normalized(str(field["role"]))
            role = aliases.get(normalized, normalized)
            if role in by_role:
                raise SourceCrawlError(f"protocol-conflict:{endpoint.endpoint_id}:ambiguous-role:{role}")
            by_role[role] = field
        matched_specs = []
        parameters: dict[str, int] = {}
        for spec in plugin.fields:
            role = aliases.get(_normalized(spec.field_id), _normalized(spec.field_id))
            matched = by_role.get(role)
            if matched is None:
                if spec.required:
                    raise SourceCrawlError(f"protocol-conflict:{endpoint.endpoint_id}:missing:{spec.field_id}")
                continue
            if spec.direction not in ("host_to_device", "device_to_host"):
                raise SourceCrawlError(f"protocol-conflict:{endpoint.endpoint_id}:direction:{spec.field_id}")
            expected = "output" if (spec.direction == "host_to_device") == host else "input"
            if matched["direction"] != expected:
                raise SourceCrawlError(f"protocol-conflict:{endpoint.endpoint_id}:direction:{spec.field_id}")
            width = matched["width"]
            if not isinstance(width, int) or isinstance(width, bool) or width <= 0:
                raise SourceCrawlError(f"protocol-conflict:{endpoint.endpoint_id}:width:{spec.field_id}")
            expression = spec.width_expression.strip()
            # A bare symbol anchors a parameter to an observed physical width.
            # Repeated symbols must agree; compound expressions cannot invent
            # missing parameters and are evaluated only after all anchors exist.
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expression):
                if parameters.setdefault(expression, width) != width:
                    raise SourceCrawlError(f"protocol-conflict:{endpoint.endpoint_id}:width:{spec.field_id}")
            matched_specs.append((spec, width))
        for spec, width in matched_specs:
            try:
                expected_width = compile_width_expression(spec.width_expression, parameters)
            except ProtocolWidthError as error:
                raise SourceCrawlError(f"protocol-conflict:{endpoint.endpoint_id}:width:{spec.field_id}") from error
            if width != expected_width:
                raise SourceCrawlError(f"protocol-conflict:{endpoint.endpoint_id}:width:{spec.field_id}")
        candidate["status"] = "consistent"
        return [candidate]

    def annotate(
        self,
        snapshot: SourceSnapshot,
        description: InterfaceDescription,
        *,
        protocol_catalog: ProtocolCatalog | None = None,
    ) -> dict[str, object]:
        endpoint_documents: list[dict[str, object]] = []
        for endpoint in description.endpoints:
            try:
                ports, module, endpoint_evidence = self._module_ports(snapshot, endpoint, description.source.top_module)
            except SourceCrawlError:
                if endpoint.required:
                    raise
                continue
            fields: list[dict[str, object]] = []
            matched_names: dict[str, str] = {}
            for field in endpoint.fields:
                try:
                    port, evidence = self._field_port(snapshot, endpoint, field, ports)
                except SourceCrawlError:
                    if field.required:
                        raise
                    continue
                if port.name in matched_names:
                    raise SourceCrawlError(f"duplicate-port-mapping:{endpoint.endpoint_id}:{port.name}")
                matched_names[port.name] = field.role
                fields.append(
                    {
                        "role": field.role,
                        "port": port.name,
                        "direction": port.direction,
                        "width": port.width,
                        "signed": port.signed,
                        "source": {"file": port.source_file, "line": port.line, "column": port.column},
                        "evidence": [evidence, "hdl_declaration"],
                        "confidence": "high" if evidence != "normalized_name" else "low",
                    }
                )
            related = [observation for observation in snapshot.timing
                       if observation.module in ("", module) and set(observation.fields) & set(matched_names)]
            clocks = sorted({observation.clock for observation in related if observation.clock is not None})
            if len(clocks) > 1:
                raise SourceCrawlError(f"clock-ambiguous:{endpoint.endpoint_id}")
            resets = sorted(
                {
                    reset
                    for observation in related
                    if observation.kind == "reset_membership"
                    for reset in observation.fields[1:]
                }
            )
            endpoint_documents.append(
                {
                    "endpoint_id": endpoint.endpoint_id,
                    "function": endpoint.function,
                    "module": module,
                    "fields": sorted(fields, key=lambda item: str(item["role"])),
                    "clock": clocks[0] if clocks else None,
                    "reset": resets[0] if len(resets) == 1 else None,
                    "timing": [
                        {
                            "kind": observation.kind,
                            "fields": [matched_names[name] for name in observation.fields if name in matched_names],
                            # Internal HDL names and other endpoints' ports are
                            # evidence, not semantic roles of this endpoint.
                            "external_fields": [name for name in observation.fields if name not in matched_names],
                            "clock": observation.clock,
                            "source": {"file": observation.source_file, "line": observation.line},
                            "evidence": ["hdl_observation"],
                        }
                        for observation in related
                    ],
                    "protocol_candidates": self._protocol_candidates(endpoint, fields, protocol_catalog),
                    "evidence": [endpoint_evidence],
                    "confidence": "high",
                    "diagnostics": [],
                }
            )
        document: dict[str, object] = {
            "schema_version": "interface_annotations.v1",
            "source": {
                "revision": snapshot.revision,
                "content_hash": snapshot.content_hash,
                "files": list(snapshot.files),
                "modules": list(snapshot.modules),
            },
            "endpoints": sorted(endpoint_documents, key=lambda item: str(item["endpoint_id"])),
            "diagnostics": [],
        }
        validate_contract(document, "interface_annotations.v1")
        return document


def annotate_interfaces(
    description: InterfaceDescription,
    *,
    base_dir: Path,
    protocol_catalog: ProtocolCatalog | None = None,
) -> dict[str, object]:
    crawler = SourceCrawler()
    return crawler.annotate(
        crawler.crawl(description.source, base_dir=base_dir),
        description,
        protocol_catalog=protocol_catalog,
    )
