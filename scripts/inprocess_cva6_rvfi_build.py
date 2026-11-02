"""Verilate the pinned CVA6 RVFI scoreboard beside one in-process run.

``cva6_rvfi.sv`` is *not* part of the pinned core filelist (``core/Flist.cva6``
lists only ``cva6_rvfi_probes.sv``), and the generated harness model is compiled
from exactly that closure.  Adding the scoreboard there would mutate the pinned
closure and its revision checks, so the scoreboard is built as its own Verilated
model and linked beside the run, the same way
``axi4_processor_memory_adapter`` is (see ``build_axi4_adapter``).

``pinned_root`` is the generated model's own cached input tree (the ``inputs``
directory of the local-harness build receipt).  Every source this build compiles
that exists there is compared byte for byte with the copy used here, and a
mismatch fails the build: the scoreboard therefore observes the *same* pinned
sources the CPU model was elaborated from, and the one file that is outside the
core closure (``cva6_rvfi.sv``) is named as such in the evidence instead of being
quietly taken from another tree.  Every compiled source's SHA-256 is written
next to the Verilator log.

The wrapper itself is the repository's own RTL
(``src/myfuzz/local_harness/rtl/cva6_rvfi_top.sv``): it flattens the pinned
scoreboard's RVFI records onto a one-record-per-clock face and declares the
probe-bundle type from the pinned ``rvfi_types.svh`` macros, so a probe-width
disagreement is an elaboration error instead of a reinterpretation of bits.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess

from myfuzz.local_harness.build import _toolchain

#: The pinned sources the scoreboard needs, relative to the CVA6 source root.
#: These are exactly the packages ``cva6_rvfi.sv`` imports (config_pkg,
#: riscv_pkg, the cv64a6 configuration package, ariane_pkg, build_config_pkg)
#: plus the scoreboard itself.
CVA6_SOURCE_ROOT = 'third_party/cva6_upstream_reference'
RVFI_SOURCES = (
    'core/include/config_pkg.sv',
    'core/include/riscv_pkg.sv',
    'core/include/cv64a6_imafdc_sv39_config_pkg.sv',
    'core/include/ariane_pkg.sv',
    'core/include/build_config_pkg.sv',
    'core/cva6_rvfi.sv',
)
#: ``cva6_rvfi.sv`` is the one compiled file that is not in the core filelist,
#: so it has no copy in the generated model's pinned input tree.  It is stated
#: here instead of being treated as verified.
RVFI_OUTSIDE_CORE_CLOSURE = ('core/cva6_rvfi.sv',)
RVFI_INCLUDE_ROOTS = (
    'core/include',
    'vendor/pulp-platform/common_cells/include',
)
#: The repository wrapper that exposes the scoreboard as a flat RVFI face.
RVFI_WRAPPER = 'src/myfuzz/local_harness/rtl/cva6_rvfi_top.sv'
RVFI_MODULE = 'cva6_rvfi_top'


def _digest(path):
    return sha256(Path(path).read_bytes()).hexdigest()


def build_cva6_rvfi_adapter(source_root, output, *, pinned_root=None,
                            wrapper_root=None, jobs=2, probes_width=6974):
    """Verilate the pinned CVA6 RVFI scoreboard and its wrapper.

    ``source_root`` holds ``third_party/cva6_upstream_reference`` (the pinned
    checkout); ``pinned_root`` is the generated CPU model's cached input tree,
    used to prove the compiled sources are the same bytes.  ``wrapper_root``
    (default: the repository itself) holds the wrapper RTL.  Returns the include
    directory and static archive the link step needs, plus the evidence (source
    hashes, which files were byte-compared against the model's own inputs, the
    exact command and the log path).
    """
    input_root = Path(source_root)
    repository = Path(wrapper_root) if wrapper_root is not None else Path(__file__).resolve().parents[1]
    pinned = None if pinned_root is None else Path(pinned_root)
    source = input_root / CVA6_SOURCE_ROOT
    wrapper = repository / RVFI_WRAPPER
    if not source.is_dir():
        raise RuntimeError('CVA6 RVFI adapter: pinned source root missing: ' + str(source))
    if not wrapper.is_file():
        raise RuntimeError('CVA6 RVFI adapter: wrapper missing: ' + str(wrapper))
    rows = []
    for name in RVFI_SOURCES:
        path = source / name
        if not path.is_file():
            raise RuntimeError('CVA6 RVFI adapter: pinned source missing: ' + str(path))
        digest = _digest(path)
        row = dict(path=name, sha256=digest,
                   outside_core_closure=name in RVFI_OUTSIDE_CORE_CLOSURE)
        if pinned is not None:
            copy = pinned / CVA6_SOURCE_ROOT / name
            if copy.is_file():
                copy_digest = _digest(copy)
                if copy_digest != digest:
                    raise RuntimeError(
                        'CVA6 RVFI adapter: %s differs from the generated model\'s own '
                        'pinned input (%s != %s)' % (name, digest, copy_digest))
                row['verified_against'] = 'generated_model_inputs'
        rows.append(row)
    output = Path(output)
    directory = output / 'cva6-rvfi'
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True)
    dummy = directory / 'rvfi-dummy-main.cpp'
    dummy.write_text('int main() { return 0; }\n')
    files = [str(source / name) for name in RVFI_SOURCES] + [str(wrapper)]
    includes = [str(source / name) for name in RVFI_INCLUDE_ROOTS]
    toolchain = _toolchain()
    verilator = toolchain['verilator']['path']
    command = [verilator, '--cc', '--exe', '--build', '-j', str(jobs),
               '--top-module', RVFI_MODULE, '-Wno-fatal',
               '-GPROBES_WIDTH=' + str(probes_width),
               *('-I' + path for path in includes),
               '--Mdir', str(directory), '-o', 'rvfi-dummy',
               *files, str(dummy)]
    completed = subprocess.run(command, capture_output=True, text=True)
    (output / 'cva6-rvfi-build.log').write_text(completed.stdout + completed.stderr)
    if completed.returncode:
        raise RuntimeError('CVA6 RVFI adapter Verilator build failed; see '
                           'cva6-rvfi-build.log')
    archive = directory / ('V' + RVFI_MODULE + '__ALL.a')
    if not archive.is_file():
        raise RuntimeError('CVA6 RVFI adapter archive was not produced: ' + str(archive))
    evidence = dict(
        schema_version='cva6_rvfi_adapter_build.v1',
        module=RVFI_MODULE,
        wrapper=dict(path=RVFI_WRAPPER, sha256=_digest(wrapper)),
        source_root=str(source_root),
        pinned_input_root=(None if pinned is None else str(pinned)),
        sources=rows,
        include_roots=list(RVFI_INCLUDE_ROOTS),
        probes_width=probes_width,
        probe_source_signal='rvfi_probes_o',
        clock='the generated CPU model\'s own clk/reset edge',
        verilator=str(verilator),
        verilator_argv=[str(part) for part in command],
        log='cva6-rvfi-build.log',
        archive=dict(path=str(archive), sha256=_digest(archive)),
    )
    (output / 'cva6-rvfi-build.json').write_text(json.dumps(evidence, indent=2) + '\n')
    return dict(include=str(directory), archive=str(archive), module=RVFI_MODULE,
                evidence=evidence)
