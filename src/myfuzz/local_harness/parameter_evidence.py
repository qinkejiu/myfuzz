"""Conservative parameter-header evidence from already pinned source snapshots.

Only simple explicit parameter declarations and package enum typedefs are
supported. No preprocessor interpretation, inherited types or scope guessing.
"""
from __future__ import annotations
import hashlib
import re
from myfuzz.scripts.source_only_frontend import mask_comments_and_strings, find_matching
from .port_rendering import LocalPortRenderError

_IDENTIFIER = r'[A-Za-z_][A-Za-z0-9_]*'


def parameter_evidence(top: str, names: tuple[str, ...], sources: tuple[tuple[str, str], ...]) -> list[dict[str, object]]:
    if not names:
        return []
    masked = [(name, text, mask_comments_and_strings(text)) for name, text in sources]
    matches = [(name, text, body, match) for name, text, body in masked
               for match in re.finditer(r'\bmodule\s+' + re.escape(top) + r'\b', body)]
    if len(matches) != 1:
        raise LocalPortRenderError('parameter-top-declaration-not-unique')
    filename, original, body, match = matches[0]
    cursor = match.end()
    imports = []
    while imported := re.match(r'\s*import\s+(' + _IDENTIFIER + r')::(\*|' + _IDENTIFIER + r')\s*;', body[cursor:]):
        imports.append((imported[1], imported[2]))
        cursor += imported.end()
    start = re.match(r'\s*#\s*\(', body[cursor:])
    if not start:
        raise LocalPortRenderError('parameter-header-required')
    opening = cursor + start.end()-1
    closing = find_matching(body, opening, '(', ')')
    if closing < 0:
        raise LocalPortRenderError('parameter-header-unclosed')
    if '`' in body[match.start():closing]:
        raise LocalPortRenderError('parameter-preprocessor-unsupported')
    header = body[opening+1:closing]
    if '`' in header:
        raise LocalPortRenderError('parameter-preprocessor-unsupported')
    declarations = {}
    for fragment in header.split(','):
        declaration = re.fullmatch(r'\s*parameter\s+(?:(.*?)\s+)?(' + _IDENTIFIER + r')\s*=\s*([^,]+?)\s*', fragment, re.S)
        if not declaration or declaration[2] in declarations:
            raise LocalPortRenderError('parameter-declaration-unsupported-or-duplicate')
        declarations[declaration[2]] = (declaration[1] or '', ' '.join(fragment.split()))
    rows = []
    for name in sorted(names):
        if name not in declarations:
            raise LocalPortRenderError(f'parameter-declaration-missing:{name}')
        type_name, declaration = declarations[name]
        builtin = re.fullmatch(r'(?:(?:bit|logic|reg|int|integer|longint|shortint|byte|time)(?:\s+(?:unsigned|signed))?(?:\s*\[\s*\d+\s*:\s*\d+\s*\])?|)', type_name)
        row = dict(name=name, source_file=filename, declaration=declaration,
                   source_sha256=hashlib.sha256(original.encode()).hexdigest(), qualified_type=None)
        if not builtin:
            named = re.fullmatch(r'(?:((' + _IDENTIFIER + r'))::)?(' + _IDENTIFIER + r')', type_name)
            if not named:
                raise LocalPortRenderError(f'parameter-type-unsupported:{name}')
            explicit_package, short = named[1], named[3]
            candidates = []
            for package_file, package_original, package_body in masked:
                for package in re.finditer(r'\bpackage\s+(' + _IDENTIFIER + r')\s*;(.*?)\bendpackage\b', package_body, re.S):
                    package_name = package[1]
                    visible = package_name == explicit_package if explicit_package else any(
                        p == package_name and imported in ('*', short) for p, imported in imports)
                    if not visible:
                        continue
                    for typedef in re.finditer(r'\btypedef\s+enum\b[^;]*?\}\s*' + re.escape(short) + r'\s*;', package[2], re.S):
                        if '`' in package[2]:
                            raise LocalPortRenderError(f'parameter-type-preprocessor-unsupported:{name}')
                        candidates.append((package_name, package_file, package_original, typedef[0]))
            if len(candidates) != 1:
                raise LocalPortRenderError(f'parameter-type-origin-not-unique:{name}')
            package_name, package_file, package_original, typedef = candidates[0]
            row.update(qualified_type=package_name + '::' + short, type_source_file=package_file,
                       type_declaration=' '.join(typedef.split()),
                       type_source_sha256=hashlib.sha256(package_original.encode()).hexdigest())
        rows.append(row)
    return rows
