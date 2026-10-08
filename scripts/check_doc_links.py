#!/usr/bin/env python3
"""Validate relative Markdown cross references across the repository documents.

Reports, plans and progress entry points are deliverables in this repository,
so a cross reference that stops resolving is a delivery defect.  This tool
scans the documentation scope, resolves every relative Markdown link target and
verifies both the file and, for Markdown targets, the heading anchor.

Usage::

    python3 scripts/check_doc_links.py [--root DIR] [--json-out PATH]
                                       [--include-runs] [--allow-code-spans]

The JSON report carries ``schema_version="doc_link_check.v1"`` and the fields
``files_scanned``, ``links_checked``, ``broken``, ``skipped_schemes`` and
``rules_version``.  Exit status is 1 when at least one reference is broken and
0 otherwise.

Scope (relative to ``--root``)
-----------------------------
``docs/**/*.md``, ``README.md``, ``QUICKSTART.md``, ``agent.md`` and
``.superpowers/sdd/*.md`` (direct children of that directory, per the scope
definition).  ``runs/**/*.md`` is added only with ``--include-runs``.  Paths
below ``.git/``, ``third_party/``, ``archive/`` and ``__pycache__/`` are always
skipped, and ``runs/`` is skipped unless ``--include-runs`` is given.

Parsing rules
-------------
* Inline links ``[text](target)``, image references ``![alt](target)`` (they are
  file references too) and reference definitions ``[label]: target`` are
  parsed.  A definition is checked even when no usage resolves to it.
* Skipped targets: external URLs (``http://``, ``https://``, ``mailto:`` and any
  other ``scheme:`` target such as ``data:``), pure anchors (``#...``) and
  targets that fall inside masked code.
* The path part before ``#`` is resolved against the directory of the document
  that holds the link; directories count as existing.  ``<...>`` wrappers,
  percent escapes and a ``?query`` suffix are handled.
* By default nothing inside fenced code blocks or inline code spans is parsed,
  so documented example commands cannot be mistaken for references.
  ``--allow-code-spans`` parses the raw text instead.

Anchor rules (``rules_version = doc_link_slug.v1``)
--------------------------------------------------
For a Markdown target (including the current document) ``#anchor`` is accepted
when it equals a computed GitHub-style heading slug or the exact rendered
heading text.  Slugs are lowercase; inline markup (emphasis, code spans, links,
HTML tags, escapes, entities) is rendered away first; every character that is
not a letter, digit, combining mark, ``-``, ``_`` or space is dropped; spaces
become ``-``; repeated headings get ``-1``, ``-2`` ... suffixes.  Known
deviations from GitHub's ``github-slugger``: the heading text is stripped before
slugging, and the exact-heading-text fallback accepts anchors that GitHub would
normalise differently.
"""

from __future__ import annotations

import argparse
import html
import json
import os
from pathlib import Path
import re
import unicodedata
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
import sys
from urllib.parse import unquote


SCHEMA_VERSION = "doc_link_check.v1"
RULES_VERSION = "doc_link_slug.v1"

REASON_MISSING_FILE = "missing_file"
REASON_MISSING_ANCHOR = "missing_anchor"

_DEFAULT_ROOT = Path(__file__).resolve().parents[1]
_SCOPE_GLOBS = ("docs/**/*.md", "README.md", "QUICKSTART.md", "agent.md", ".superpowers/sdd/*.md")
_RUN_GLOBS = ("runs/**/*.md",)
_ALWAYS_PRUNED = frozenset({".git", "third_party", "archive", "__pycache__"})
_CONDITIONAL_PRUNED = frozenset({"runs"})
_MARKDOWN_SUFFIXES = frozenset({".md", ".markdown"})

_MASK_CHAR = "\x00"
_FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")
_BACKTICK_RUN_RE = re.compile(r"`+")
_ATX_HEADING_RE = re.compile(r"^ {0,3}(#{1,6})(?:[ \t]+(.*?))?[ \t]*$")
_SETEXT_UNDERLINE_RE = re.compile(r"^ {0,3}(=+|-+)[ \t]*$")
_CLOSING_HASHES_RE = re.compile(r"[ \t]+#+[ \t]*$")
_INLINE_LINK_RE = re.compile(
    r"!?\[(?P<text>[^\[\]]*)\]\(\s*"
    r"(?P<target><[^<>]*>|[^()\s]+?)"
    r"\s*(?P<title>\"[^\"]*\"|'[^']*'|\([^()]*\))?\s*\)"
)
_REFERENCE_DEFINITION_RE = re.compile(
    r"^ {0,3}\[(?P<label>[^\[\]]+)\]:[ \t]*"
    r"(?P<target><[^<>]*>|\S+?)"
    r"(?:[ \t]+(?P<title>\"[^\"]*\"|'[^']*'|\([^()]*\)))?[ \t]*$",
    re.MULTILINE,
)
_HTML_TAG_RE = re.compile(r"<[^<>]*>")
_LINK_TEXT_RE = re.compile(r"!?\[(?P<text>[^\[\]]*)\]\([^()]*\)")
_REFERENCE_USAGE_RE = re.compile(r"!?\[(?P<text>[^\[\]]*)\]\[[^\[\]]*\]")
_EMPHASIS_RE = re.compile(r"(\*{1,3}|_{1,3}|~{2})(?=\S)(.*?)(?<=\S)\1")
_ESCAPE_RE = re.compile(r"\\([!\"#$%&'()*+,\-./:;<=>?@\[\\\]^_`{|}~])")
_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*):")
_PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")


# ---------------------------------------------------------------------------
# code masking
# ---------------------------------------------------------------------------
def _blank(segment: str) -> str:
    """Replace every non-newline character so offsets and line numbers survive."""
    return re.sub(r"[^\n]", _MASK_CHAR, segment)


def _apply_spans(text: str, spans: Sequence[tuple[int, int]]) -> str:
    if not spans:
        return text
    pieces: list[str] = []
    cursor = 0
    for start, end in spans:
        if start < cursor:
            continue
        pieces.append(text[cursor:start])
        pieces.append(_blank(text[start:end]))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def _fenced_spans(text: str) -> list[tuple[int, int]]:
    """Spans of fenced code blocks, including their fence lines."""
    spans: list[tuple[int, int]] = []
    open_start = -1
    open_char = ""
    open_length = 0
    offset = 0
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\n").rstrip("\r")
        match = _FENCE_RE.match(body)
        if match:
            run, info = match.group(1), match.group(2)
            if open_start < 0:
                if not (run[0] == "`" and "`" in info):
                    open_start, open_char, open_length = offset, run[0], len(run)
            elif run[0] == open_char and len(run) >= open_length and not info.strip():
                spans.append((open_start, offset + len(line)))
                open_start = -1
        offset += len(line)
    if open_start >= 0:
        spans.append((open_start, len(text)))
    return spans


def _inline_code_spans(text: str) -> list[tuple[int, int]]:
    """CommonMark code spans: a backtick run closes on the next equal-length run."""
    runs = [(match.start(), match.end(), match.end() - match.start())
            for match in _BACKTICK_RUN_RE.finditer(text)]
    spans: list[tuple[int, int]] = []
    index = 0
    while index < len(runs):
        start, _end, length = runs[index]
        closer = next((position for position in range(index + 1, len(runs))
                       if runs[position][2] == length), None)
        if closer is None:
            index += 1
            continue
        spans.append((start, runs[closer][1]))
        index = closer + 1
    return spans


def mask_code(text: str) -> str:
    """Mask fenced blocks and inline code spans, preserving offsets and lines."""
    return _apply_spans(_apply_spans(text, _fenced_spans(text)), _inline_code_spans(text))


# ---------------------------------------------------------------------------
# headings and slugs
# ---------------------------------------------------------------------------
def render_heading_text(heading: str) -> str:
    """Approximate the text GitHub renders for a heading line."""
    text = _HTML_TAG_RE.sub("", heading)
    text = _LINK_TEXT_RE.sub(lambda match: match.group("text"), text)
    text = _REFERENCE_USAGE_RE.sub(lambda match: match.group("text"), text)
    text = text.replace("`", "")
    text = _EMPHASIS_RE.sub(lambda match: match.group(2), text)
    text = _ESCAPE_RE.sub(lambda match: match.group(1), text)
    return html.unescape(text).strip()


def slugify(text: str) -> str:
    """GitHub-style heading slug (see the module docstring for the rules)."""
    rendered = render_heading_text(text).lower()
    kept: list[str] = []
    for character in rendered:
        if character == " ":
            kept.append("-")
        elif character in "-_" or character.isalnum():
            kept.append(character)
        elif unicodedata.category(character).startswith("M"):
            kept.append(character)
    return "".join(kept)


def _iter_headings(masked_text: str) -> Iterator[str]:
    """Rendered heading text, in order, from text whose fences are masked."""
    lines = masked_text.splitlines()
    if lines and lines[0].strip() == "---":
        # YAML front matter must not turn into setext headings.
        for index in range(1, len(lines)):
            if lines[index].strip() in {"---", "..."}:
                lines = [""] * (index + 1) + lines[index + 1:]
                break
    for index, line in enumerate(lines):
        match = _ATX_HEADING_RE.match(line)
        if match:
            title = _CLOSING_HASHES_RE.sub("", match.group(2) or "")
            if title.strip():
                yield render_heading_text(title)
            continue
        if not _SETEXT_UNDERLINE_RE.match(line) or index == 0:
            continue
        previous = lines[index - 1]
        stripped = previous.strip()
        if not stripped or stripped[0] in "|>#-*+" or _SETEXT_UNDERLINE_RE.match(previous):
            continue
        if re.match(r"^ {0,3}\d+[.)]\s", previous):
            continue
        yield render_heading_text(previous)


def heading_index(text: str) -> tuple[list[str], list[str]]:
    """Return ``(slugs, rendered_headings)`` for a raw Markdown document."""
    masked = _apply_spans(text, _fenced_spans(text))
    slugs: list[str] = []
    headings: list[str] = []
    seen: Counter[str] = Counter()
    for heading in _iter_headings(masked):
        base = slugify(heading)
        if not base:
            continue
        occurrence = seen[base]
        seen[base] += 1
        slugs.append(base if occurrence == 0 else f"{base}-{occurrence}")
        headings.append(heading)
    return slugs, headings


def heading_slugs(text: str) -> list[str]:
    """Public helper: the ordered, de-duplicated slug list of a document."""
    return heading_index(text)[0]


# ---------------------------------------------------------------------------
# documents
# ---------------------------------------------------------------------------
class _Document:
    """A Markdown document parsed exactly once."""

    __slots__ = ("path", "relative", "text", "scan", "headings", "slugs")

    def __init__(self, path: Path, relative: str, text: str, *, allow_code_spans: bool):
        self.path = path
        self.relative = relative
        self.text = text
        self.scan = text if allow_code_spans else mask_code(text)
        self.slugs, self.headings = heading_index(text)

    def line_of(self, offset: int) -> int:
        return self.text.count("\n", 0, offset) + 1


def iter_documents(root: Path, *, include_runs: bool = False) -> list[str]:
    """Relative POSIX paths of the in-scope Markdown documents, sorted."""
    patterns = list(_SCOPE_GLOBS) + (list(_RUN_GLOBS) if include_runs else [])
    pruned = set(_ALWAYS_PRUNED) if include_runs else set(_ALWAYS_PRUNED) | set(_CONDITIONAL_PRUNED)
    found: set[str] = set()
    for pattern in patterns:
        for path in root.glob(pattern):
            if not path.is_file():
                continue
            relative = path.relative_to(root)
            if any(part in pruned for part in relative.parts[:-1]):
                continue
            found.add(relative.as_posix())
    return sorted(found)


def load_document(root: Path, relative: str, *, allow_code_spans: bool = False) -> _Document:
    path = root / relative
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        text = ""
    return _Document(path, relative, text, allow_code_spans=allow_code_spans)


# ---------------------------------------------------------------------------
# link targets
# ---------------------------------------------------------------------------
class _Target:
    __slots__ = ("scheme", "path", "anchor")

    def __init__(self, scheme: str | None, path: str, anchor: str | None):
        self.scheme = scheme
        self.path = path
        self.anchor = anchor


def classify_target(raw: str) -> _Target:
    """Split a raw link target into scheme / path / anchor parts."""
    target = raw.strip()
    if target.startswith("<") and target.endswith(">"):
        target = target[1:-1].strip()
    if target.startswith("#"):
        return _Target(None, "", target[1:] or None)
    scheme_match = _SCHEME_RE.match(target)
    if scheme_match:
        return _Target(scheme_match.group(1).lower(), "", None)
    path_part, separator, anchor_part = target.partition("#")
    anchor = anchor_part if separator and anchor_part else None
    if "?" in path_part:
        path_part = path_part.split("?", 1)[0]
    return _Target(None, path_part, anchor)


def _resolve_target(document_path: Path, path_part: str) -> Path | None:
    """The existing filesystem entry for a relative target, or ``None``."""
    candidate = Path(os.path.normpath(os.path.join(document_path.parent, path_part)))
    if candidate.exists():
        return candidate
    if _PERCENT_ESCAPE_RE.search(path_part):
        decoded = Path(os.path.normpath(os.path.join(document_path.parent, unquote(path_part))))
        if decoded.exists():
            return decoded
    return None


def extract_links(document: _Document) -> Iterator[tuple[int, str]]:
    """Yield ``(offset, target)`` for inline links, images and definitions."""
    for match in _INLINE_LINK_RE.finditer(document.scan):
        yield match.start(), match.group("target")
    for match in _REFERENCE_DEFINITION_RE.finditer(document.scan):
        if match.group("label").startswith("^"):
            continue  # footnote definition, not a link reference
        yield match.start(), match.group("target")


# ---------------------------------------------------------------------------
# checking
# ---------------------------------------------------------------------------
class _HeadingCache:
    """Heading indexes by resolved path; every document is read at most once."""

    def __init__(self, documents: Mapping[Path, _Document]):
        self._entries: dict[str, tuple[list[str], list[str]]] = {
            str(path): (document.slugs, document.headings) for path, document in documents.items()
        }

    def get(self, path: Path) -> tuple[list[str], list[str]]:
        key = str(path)
        if key not in self._entries:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            self._entries[key] = heading_index(text)
        return self._entries[key]


def check_repository(
    root: Path,
    *,
    include_runs: bool = False,
    allow_code_spans: bool = False,
) -> dict:
    """Scan ``root`` and return the ``doc_link_check.v1`` report."""
    root = Path(root)
    relatives = iter_documents(root, include_runs=include_runs)
    documents = {root / relative: load_document(root, relative, allow_code_spans=allow_code_spans)
                 for relative in relatives}
    headings = _HeadingCache(documents)

    broken: list[dict] = []
    skipped_schemes: Counter[str] = Counter()
    links_checked = 0

    for path in sorted(documents, key=lambda item: item.as_posix()):
        document = documents[path]
        for offset, raw_target in extract_links(document):
            if _MASK_CHAR in raw_target:
                continue  # the target sits inside masked code
            target = classify_target(raw_target)
            if target.scheme is not None:
                skipped_schemes[target.scheme] += 1
                continue
            if not target.path:
                continue  # pure anchor, nothing to resolve
            links_checked += 1
            line = document.line_of(offset)
            resolved = _resolve_target(path, target.path)
            if resolved is None:
                broken.append({"file": document.relative, "line": line,
                               "target": raw_target, "reason": REASON_MISSING_FILE})
                continue
            if target.anchor is None or resolved.suffix.lower() not in _MARKDOWN_SUFFIXES:
                continue
            if not resolved.is_file():
                continue
            slugs, rendered = headings.get(resolved)
            anchor = unquote(target.anchor)
            if anchor not in slugs and anchor not in rendered:
                broken.append({"file": document.relative, "line": line,
                               "target": raw_target, "reason": REASON_MISSING_ANCHOR})

    broken.sort(key=lambda item: (item["file"], item["line"], item["target"]))
    return {
        "schema_version": SCHEMA_VERSION,
        "files_scanned": len(relatives),
        "links_checked": links_checked,
        "broken": broken,
        "skipped_schemes": dict(sorted(skipped_schemes.items())),
        "rules_version": RULES_VERSION,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="check_doc_links.py",
        description="Validate relative Markdown cross references in the repository documents.",
    )
    parser.add_argument("--root", default=str(_DEFAULT_ROOT),
                        help="repository root to scan (default: the repository holding this script)")
    parser.add_argument("--json-out", default=None,
                        help="write the doc_link_check.v1 JSON report to this path")
    parser.add_argument("--include-runs", action="store_true",
                        help="also scan runs/**/*.md")
    parser.add_argument("--allow-code-spans", action="store_true",
                        help="parse links inside fenced code blocks and inline code spans too")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = check_repository(Path(args.root), include_runs=args.include_runs,
                              allow_code_spans=args.allow_code_spans)

    if args.json_out:
        destination = Path(args.json_out)
        if destination.parent != Path(""):
            destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                               encoding="utf-8")

    print(f"{report['schema_version']}: files_scanned={report['files_scanned']} "
          f"links_checked={report['links_checked']} broken={len(report['broken'])} "
          f"skipped_schemes={json.dumps(report['skipped_schemes'], sort_keys=True)}")
    for item in report["broken"]:
        print(f"  {item['file']}:{item['line']}: {item['target']} ({item['reason']})")
    return 1 if report["broken"] else 0


if __name__ == "__main__":
    sys.exit(main())
