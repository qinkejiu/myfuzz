"""Deterministic structural wrapper and its versioned ABI/build documents."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from .plan import LocalHarnessPlan
from .parameter_evidence import parameter_evidence
from .port_rendering import LocalPortRenderError, render_port_connections, require_identifier


def _sha(document: object) -> str:
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class RenderedLocalHarness:
    module_name: str
    wrapper_sv: str
    abi_document: dict[str, object]
    build_document: dict[str, object]


def render_local_harness(plan: LocalHarnessPlan) -> RenderedLocalHarness:
    """Render exactly one real DUT; no simulator driver or session is implied."""
    declarations, local, connections, rows = render_port_connections(plan)
    source = plan.profile.source
    if source.filelist is not None:
        raise LocalPortRenderError('filelist-build-options-not-retained')
    if not plan.facts.files:
        raise LocalPortRenderError('source-files-required')
    settings = source.elaboration
    parameters = {} if settings is None else dict(settings.parameters)
    for name, value in parameters.items():
        require_identifier(name)
        if not isinstance(value, str) or re.fullmatch(r'-?(?:0|[1-9][0-9]*)', value) is None:
            raise LocalPortRenderError(f'invalid-parameter-value:{name}')
    evidence = parameter_evidence(source.top_module, tuple(parameters), plan.parameter_sources)
    types = {row['name']: row['qualified_type'] for row in evidence}
    expressions = {name: f"{types[name]}'({value})" if types[name] else value
                   for name, value in parameters.items()}
    parameter_text = '' if not parameters else ' #(\n' + ',\n'.join(
        f'    .{name}({value})' for name, value in sorted(expressions.items())) + '\n  )'
    module = 'local_' + plan.request.instance_id
    ports = ['input logic clk', 'input logic reset', *declarations]
    wrapper = ('module ' + module + ' (\n  ' + ',\n  '.join(ports) + '\n);\n'
               + '\n'.join('  ' + line for line in local) + '\n'
               + '  ' + source.top_module + parameter_text + ' u_dut (\n    '
               + ',\n    '.join(connections) + '\n  );\nendmodule\n')
    files = [source.source_root + '/' + name for name in plan.facts.files]
    includes = [source.source_root + '/' + name for name in source.include_roots]
    defines = [] if settings is None else [f'{name}={value}' for name, value in settings.defines]
    abi = dict(schema_version='local_harness_abi.v1', plan_sha256=_sha(plan.document()),
               module_name=module, reset_assertion='active_high', ports=rows, parameter_evidence=evidence,
               dispositions=[entry.document() for entry in sorted(plan.dispositions, key=lambda e: (e.port, -e.bit_hi))])
    build = dict(schema_version='local_harness_build.v1', status='structural_only',
                 profile_sha256=plan.profile_sha256, source_revision=plan.facts.revision,
                 source_content_hash=plan.facts.content_hash, source_files=files,
                 include_roots=includes, defines=defines, parameter_overrides=parameters,
                 parameter_evidence=evidence, wrapper_sha256=hashlib.sha256(wrapper.encode()).hexdigest(),
                 lint_argv=['verilator', '--lint-only', '-Wno-fatal', '--top-module', module,
                            *('-I' + name for name in includes), *('-D' + name for name in defines), *files])
    return RenderedLocalHarness(module, wrapper, abi, build)
