#!/usr/bin/env python3
"""Run a reproducible real-CPU/real-peripheral composition matrix.

The runner provisions only temporary upstream checkouts for CV32E40P and
CV32E20.  It never edits ``third_party``.  Each selected composition is
planned through the generic processor-memory-beat backend, published, linted
with Verilator, and exercised by a clocked smoke testbench.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import selectors
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from myfuzz.composition import (
    GenericCompositionRequest,
    load_interface_description,
    plan_generic_composition,
    write_generic_composition,
)
from myfuzz.components import load_real_component_catalog
from myfuzz.composition.ids import canonical_id


ROOT = Path(__file__).resolve().parents[1]
PROCESSOR_BEAT = ("processor-memory-beat", "1")
_MAX_LOG_BYTES = 64 * 1024
REPO_URLS = {
    "cv32e40p": "https://github.com/openhwgroup/cv32e40p.git",
    "cv32e20": "https://github.com/openhwgroup/cve2.git",
}

# Reuse is deliberate: every CPU occurs at least twice and every 32-bit real
# peripheral occurs in more than one CPU composition.  The 64-bit set keeps
# CVA6's AXI width honest instead of silently truncating it to 32 bits.
COMBINATIONS: tuple[dict[str, Any], ...] = (
    # Keep instruction fetch backed by a coherent RAM in every case.  The
    # remaining targets are real AXI/APB/TL wrappers, so reuse is still
    # exercised without asking a CPU to execute from a peripheral register.
    {"cpu": "ibex", "width": 32, "peripherals": ("real_ram", "real_uart", "real_timer")},
    {"cpu": "ibex", "width": 32, "peripherals": ("real_ram", "real_gpio", "real_spi")},
    {"cpu": "cv32e40p", "width": 32, "peripherals": ("real_ram", "real_spi", "real_gpio")},
    {"cpu": "cv32e40p", "width": 32, "peripherals": ("real_ram", "real_uart", "real_timer")},
    {"cpu": "cv32e20", "width": 32, "peripherals": ("real_ram", "real_gpio", "real_uart")},
    {"cpu": "cv32e20", "width": 32, "peripherals": ("real_ram", "real_spi", "real_timer")},
    {"cpu": "cva6", "width": 64, "peripherals": ("real_ram64", "real_uart64", "real_timer64")},
    {"cpu": "cva6", "width": 64, "peripherals": ("real_ram64", "real_gpio64", "real_spi64")},
    {"cpu": "cva6", "width": 64, "peripherals": ("real_ram64", "real_timer64", "real_uart64")},
)

BRIDGES = {
    "real_ram": "TL-UL",
    "real_ram64": "TL-UL",
    "real_uart": "AXI4-Lite",
    "real_uart64": "AXI4-Lite",
    "real_spi": "AXI4-Lite",
    "real_spi64": "AXI4-Lite",
    "real_timer": "APB4",
    "real_timer64": "APB4",
    "real_gpio": "APB4",
    "real_gpio64": "APB4",
}


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate a command and all compiler/simulator descendants."""
    # The leader may have exited while a compiler/simulator child still owns
    # the pipes.  The process group remains the cleanup boundary in that case.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _run(command: tuple[str, ...], *, cwd: Path, timeout: int) -> subprocess.CompletedProcess[str]:
    # Verilator invokes make/compiler descendants.  Drain both pipes while
    # retaining only an in-memory tail, and use a process group so timeout or
    # interruption cannot leave descendants running or fill a pipe forever.
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    assert process.stdout is not None and process.stderr is not None
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    selector = selectors.DefaultSelector()
    for stream in streams:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)

    def read_available(stream: object, tail: bytearray) -> bool:
        try:
            chunk = os.read(stream.fileno(), 65536)  # type: ignore[attr-defined]
        except BlockingIOError:
            return True
        except OSError:
            return False
        if not chunk:
            return False
        tail.extend(chunk)
        if len(tail) > _MAX_LOG_BYTES:
            del tail[:-_MAX_LOG_BYTES]
        return True

    timed_out = False
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _kill_process_group(process)
                break
            for key, _ in selector.select(min(remaining, 0.25)):
                if not read_available(key.fileobj, streams[key.fileobj]):
                    selector.unregister(key.fileobj)
                    key.fileobj.close()

        if process.poll() is None:
            if timed_out:
                _kill_process_group(process)
            else:
                try:
                    process.wait(timeout=max(0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    timed_out = True
                    _kill_process_group(process)
    except BaseException:
        _kill_process_group(process)
        raise
    finally:
        for key in tuple(selector.get_map().values()):
            selector.unregister(key.fileobj)
            key.fileobj.close()
        selector.close()

    def decode(tail: bytearray) -> str:
        return bytes(tail).decode("utf-8", errors="replace")

    return subprocess.CompletedProcess(
        command,
        124 if timed_out else process.returncode,
        decode(streams[process.stdout]),
        decode(streams[process.stderr]),
    )


def _diagnostic(result: subprocess.CompletedProcess[str], limit: int = 4000) -> str:
    text = (result.stdout + "\n" + result.stderr).strip()
    return text[-limit:] if text else f"returncode={result.returncode}"


def _manifest_sources(repo: Path, manifest: str) -> list[Path]:
    """Expand the two upstream manifests enough for source-pinned planning."""
    paths: list[Path] = []
    for raw in (repo / manifest).read_text(encoding="utf-8").splitlines():
        token = raw.strip()
        if not token or token.startswith("//") or token.startswith("+") or token.startswith("#"):
            continue
        token = token.replace("${DESIGN_RTL_DIR}", "rtl")
        path = (repo / token).resolve()
        if path.is_file() and path.suffix in {".sv", ".v", ".vh", ".svh"}:
            paths.append(path)
    return list(dict.fromkeys(paths))


def _provision(stage: Path) -> tuple[dict[str, Path], dict[str, str], dict[str, str]]:
    """Clone CV32 sources and commit the temporary source root for provenance."""
    repositories: dict[str, Path] = {}
    errors: dict[str, str] = {}
    revisions: dict[str, str] = {}
    for cpu, url in REPO_URLS.items():
        destination = stage / cpu
        result = _run(("git", "clone", "--depth", "1", url, destination.as_posix()), cwd=ROOT, timeout=180)
        if result.returncode:
            errors[cpu] = f"clone failed: {_diagnostic(result)}"
            continue
        repositories[cpu] = destination
        revision = _run(("git", "rev-parse", "HEAD"), cwd=destination, timeout=30)
        if revision.returncode == 0 and revision.stdout.strip():
            revisions[cpu] = revision.stdout.strip()
        else:
            errors[cpu] = f"revision lookup failed: {_diagnostic(revision)}"

    # Nested upstream .git directories would make Git treat the CPU checkout as
    # a submodule.  The temporary root is intentionally a single provenance
    # boundary, so remove only those newly-created nested metadata directories.
    for nested_git in tuple(stage.glob("*/.git")):
        if nested_git.is_dir():
            shutil.rmtree(nested_git)
    (stage / "wrappers").mkdir()
    shutil.copy2(
        ROOT / "configs/cpus/cv32e40p/cv32e40p_real_wrapper.sv",
        stage / "wrappers/cv32e40p_real_wrapper.sv",
    )
    shutil.copy2(
        ROOT / "configs/cpus/cv32e20/cv32e20_real_wrapper.sv",
        stage / "wrappers/cv32e20_real_wrapper.sv",
    )
    init = _run(("git", "init", "-q"), cwd=stage, timeout=30)
    if init.returncode:
        raise RuntimeError(f"temporary source git init failed: {_diagnostic(init)}")
    for command in (
        ("git", "config", "user.email", "myfuzz-matrix@example.invalid"),
        ("git", "config", "user.name", "MyFuzz matrix"),
        ("git", "add", "-A"),
        ("git", "commit", "-qm", "provisioned upstream CPU sources"),
    ):
        result = _run(command, cwd=stage, timeout=60)
        if result.returncode:
            raise RuntimeError(f"temporary source git command failed: {_diagnostic(result)}")
    return repositories, errors, revisions


def _cv32_description(stage: Path, cpu: str, repo: Path) -> Any:
    is_e40p = cpu == "cv32e40p"
    manifest = "cv32e40p_manifest.flist" if is_e40p else "cv32e20_manifest.flist"
    top = "real_cv32e40p_core" if is_e40p else "real_cv32e20_core"
    wrapper = "wrappers/cv32e40p_real_wrapper.sv" if is_e40p else "wrappers/cv32e20_real_wrapper.sv"
    sources = _manifest_sources(repo, manifest)
    if not is_e40p:
        # CVE2 includes this macro header from cve2_controller.sv.  It is
        # explicit in the source closure so source provenance includes it.
        sources.append(repo / "vendor/lowrisc_ip/dv/sv/dv_utils/dv_fcov_macros.svh")
    sources.append(stage / wrapper)
    sources = list(dict.fromkeys(path.resolve() for path in sources if path.is_file()))
    relative_sources = [path.relative_to(stage).as_posix() for path in sources]
    revision = "git:" + _run(("git", "rev-parse", "HEAD"), cwd=stage, timeout=30).stdout.strip()
    root_name = stage.relative_to(ROOT).as_posix()
    include_roots = (
        [f"{cpu}/rtl/include"]
        if is_e40p
        else [
            f"{cpu}/rtl",
            f"{cpu}/vendor/lowrisc_ip/ip/prim/rtl",
            f"{cpu}/vendor/lowrisc_ip/dv/sv/dv_utils",
        ]
    )
    memory_fields = [
        {"role": "req", "aliases": ["{prefix}_req_o"]},
        {"role": "gnt", "aliases": ["{prefix}_gnt_i"]},
        {"role": "addr", "aliases": ["{prefix}_addr_o"]},
        {"role": "rvalid", "aliases": ["{prefix}_rvalid_i"]},
        {"role": "rdata", "aliases": ["{prefix}_rdata_i"]},
    ]
    instruction = [{**field, "aliases": [field["aliases"][0].format(prefix="instr")]} for field in memory_fields]
    data = [{**field, "aliases": [field["aliases"][0].format(prefix="data")]} for field in memory_fields]
    data.extend([
        {"role": "we", "aliases": ["data_we_o"]},
        {"role": "wdata", "aliases": ["data_wdata_o"]},
        {"role": "be", "aliases": ["data_be_o"]},
    ])
    # The generic OBI adapter treats error as an explicit extension.  The
    # CV32E40P shell exposes the field for fail-closed simulation checking but
    # has no architectural error channel; CVE2 forwards its real error pins.
    instruction.append({"role": "error", "aliases": ["instr_err_i"]})
    data.append({"role": "error", "aliases": ["data_err_i"]})
    endpoints = [
        {"endpoint_id": "processor.clock", "function": "clock", "module": top, "fields": [{"role": "clock", "aliases": ["clock"]}]},
        {"endpoint_id": "processor.reset", "function": "reset", "module": top, "fields": [{"role": "reset", "aliases": ["reset"]}]},
        {"endpoint_id": "processor.instruction", "function": "instruction_memory_master", "module": top, "protocol": ["obi", "1"], "fields": instruction},
        {"endpoint_id": "processor.data", "function": "data_memory_master", "module": top, "protocol": ["obi", "1"], "fields": data},
    ]
    return load_interface_description({
        "schema_version": "interface_description.v1",
        "source": {
            "root": root_name,
            "revision": revision,
            "top_module": top,
            "files": relative_sources,
            "include_roots": include_roots,
            "elaboration": {"frontend": "verilator-json", "warning_policy": "recorded-nonfatal"},
        },
        "endpoints": endpoints,
    })


def _description(cpu: str, stage: Path, repositories: dict[str, Path]) -> Any:
    if cpu == "cv32e40p":
        return _cv32_description(stage, cpu, repositories[cpu])
    if cpu == "cv32e20":
        return _cv32_description(stage, cpu, repositories[cpu])
    path = ROOT / "configs/cpus" / cpu / "official_core_interface_description.json"
    return load_interface_description(path)


def _lint(output: Path) -> tuple[str, str]:
    result = _run(
        ("verilator", "--lint-only", "--sv", "-Wno-fatal", "--top-module", "generic_composition_top", "-f", "sources.f"),
        cwd=output,
        timeout=180,
    )
    return ("passed", "") if result.returncode == 0 else ("failed", _diagnostic(result))


def _top_ports(output: Path) -> tuple[tuple[str, int, str], ...]:
    text = (output / "generic_composition_top.sv").read_text(encoding="utf-8")
    header = text.split(");", 1)[0]
    pattern = re.compile(
        r"^\s*(input|output)\s+logic(?:\s+signed)?"
        r"(?:\s+\[(\d+):0\])?\s+([A-Za-z_][A-Za-z0-9_$]*)\s*,?\s*$",
        re.MULTILINE,
    )
    ports = []
    for match in pattern.finditer(header):
        direction, upper, name = match.groups()
        ports.append((direction, int(upper) + 1 if upper is not None else 1, name))
    if not ports:
        raise ValueError("generated top has no parseable ports")
    return tuple(ports)


def _smoke(output: Path) -> tuple[str, str]:
    execution = json.loads(
        (output / "processor_execution.v1.json").read_text(encoding="utf-8")
    )
    controls = execution.get("audit", {}).get("controls", {})
    if not isinstance(controls, dict):
        return "failed", "processor execution control evidence is missing"
    try:
        clock_control = controls["clock"]
        reset_control = controls["reset"]
        clock_identity = f"{clock_control['endpoint_id']}:clock:{clock_control['port']}"
        reset_identity = f"{reset_control['endpoint_id']}:reset:{reset_control['port']}"
        clock_port = f"p_{canonical_id('generic-top-port', clock_identity):016x}"
        reset_port = f"p_{canonical_id('generic-top-port', reset_identity):016x}"
    except (KeyError, TypeError, ValueError) as error:
        return "failed", f"processor execution control evidence is malformed: {error}"
    try:
        ports = _top_ports(output)
    except (OSError, UnicodeError, ValueError) as error:
        return "failed", str(error)
    port_names = {name for _direction, _width, name in ports}
    if clock_port not in port_names or reset_port not in port_names:
        return "failed", "generated top does not expose clock/reset controls"
    try:
        layout = json.loads((output / "input_layout.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return "failed", f"input layout evidence is unavailable: {error}"
    drive_values: dict[str, str] = {}
    for field in layout.get("fields", ()):
        if not isinstance(field, dict) or not isinstance(field.get("binding"), dict):
            continue
        binding = field["binding"]
        owner = field.get("owner")
        role = field.get("role")
        source_port = binding.get("port")
        if not all(isinstance(item, str) and item for item in (owner, role, source_port)):
            continue
        opaque = f"p_{canonical_id('generic-top-port', f'{owner}:{role}:{source_port}'):016x}"
        # The CPU's architectural instruction stream is deliberately seeded by
        # the coherent RAM wrapper; controls that gate fetching/scanning must
        # therefore be enabled, while all optional controls remain benign zero.
        if role in {"fetch_enable", "scan_reset"}:
            drive_values[opaque] = "'1"
    connections = []
    for direction, _width, name in ports:
        if direction == "output":
            connections.append(f"        .{name}()")
        elif name == clock_port:
            connections.append(f"        .{name}(clock)")
        elif name == reset_port:
            connections.append(f"        .{name}(reset_n)")
        else:
            connections.append(f"        .{name}({drive_values.get(name, "'0")})")
    testbench = output / "matrix_smoke_tb.sv"
    testbench.write_text(
        "module matrix_smoke_tb;\n"
        "  logic clock = 1'b0;\n"
        "  logic reset_n = 1'b0;\n"
        "  integer request_count = 0;\n"
        "  integer response_count = 0;\n"
        "  always #1 clock = ~clock;\n"
        "  generic_composition_top dut(\n"
        + ",\n".join(connections)
        + "\n  );\n"
        "  always @(posedge clock) begin\n"
        "    if (!reset_n) begin\n"
        "      request_count <= 0;\n"
        "      response_count <= 0;\n"
        "    end else begin\n"
        "      if (dut.backend_target_req_valid && dut.backend_target_req_ready)\n"
        "        request_count <= request_count + 1;\n"
        "      if (dut.backend_target_rsp_valid && dut.backend_target_rsp_ready)\n"
        "        response_count <= response_count + 1;\n"
        "    end\n"
        "  end\n"
        "  initial begin\n"
        "    #5;\n"
        "    reset_n = 1'b1;\n"
        # CVA6 clears its 16 KiB instruction cache during reset before the
        # first external fetch; 2048 edges leaves room for that flush while
        # remaining a bounded smoke rather than an open-ended simulation.
        "    repeat (2048) @(posedge clock);\n"
        "    if (request_count == 0) $fatal(1, \"MATRIX_SMOKE_NO_REQUEST\");\n"
        "    if (response_count == 0) $fatal(1, \"MATRIX_SMOKE_NO_RESPONSE\");\n"
        "    $display(\"MATRIX_SMOKE_PASS requests=%0d responses=%0d\", request_count, response_count);\n"
        "    $finish;\n"
        "  end\n"
        "endmodule\n",
        encoding="utf-8",
    )
    result = _run(
        (
            "verilator", "--binary", "--timing", "-Wno-fatal",
            "--top-module", "matrix_smoke_tb", "-f", "sources.f", "matrix_smoke_tb.sv",
        ),
        cwd=output,
        timeout=240,
    )
    if result.returncode:
        return "failed", _diagnostic(result)
    executable = output / "obj_dir" / "Vmatrix_smoke_tb"
    if not executable.is_file():
        return "failed", "verilator produced no smoke executable"
    run = _run((executable.as_posix(),), cwd=output, timeout=30)
    return ("passed", "") if run.returncode == 0 and "MATRIX_SMOKE_PASS" in run.stdout else ("failed", _diagnostic(run))


def _case_id(index: int, case: dict[str, Any]) -> str:
    return f"{index:02d}-{case['cpu']}-" + "-".join(case["peripherals"])


def run_matrix(*, seed: int, out_dir: Path, keep_artifacts: bool) -> dict[str, Any]:
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    if keep_artifacts:
        try:
            out_dir.relative_to(ROOT)
        except ValueError as error:
            raise RuntimeError(
                "--keep-artifacts requires --out-dir inside the repository root"
            ) from error
        stage = out_dir / "provisioned_sources"
        if stage.exists():
            raise RuntimeError(f"artifact source directory already exists: {stage}")
        stage.mkdir()
        temporary = None
        composition_root = out_dir / "compositions"
        composition_root.mkdir()
        composition_temporary = None
    else:
        temporary = tempfile.TemporaryDirectory(prefix=".real-cpu-matrix-", dir=ROOT)
        stage = Path(temporary.name)
        # Publication output must not be inside the source root: the generic
        # writer rejects an artifact directory that overlaps source evidence.
        composition_temporary = tempfile.TemporaryDirectory(prefix=".real-cpu-matrix-output-", dir=ROOT)
        composition_root = Path(composition_temporary.name)

    try:
        repositories, provisioning_errors, provisioning_revisions = _provision(stage)
        component_catalog = load_real_component_catalog()
        descriptions: dict[str, Any] = {}
        for cpu in ("ibex", "cva6"):
            descriptions[cpu] = _description(cpu, stage, repositories)
        for cpu, repo in repositories.items():
            descriptions[cpu] = _cv32_description(stage, cpu, repo)

        selected = list(COMBINATIONS)
        random.Random(seed).shuffle(selected)
        report_cases: list[dict[str, Any]] = []
        for index, case in enumerate(selected, start=1):
            record: dict[str, Any] = {
                "id": _case_id(index, case),
                "cpu": case["cpu"],
                "data_width": case["width"],
                "peripherals": list(case["peripherals"]),
                "bridges": {item: BRIDGES[item] for item in case["peripherals"]},
                "plan": "not-run",
                "publication": "not-run",
                "lint": "not-run",
                "smoke": "not-run",
                "status": "failed",
                "diagnostic": "",
            }
            if case["cpu"] in provisioning_errors:
                record["diagnostic"] = provisioning_errors[case["cpu"]]
                report_cases.append(record)
                continue
            description = descriptions.get(case["cpu"])
            if description is None:
                record["diagnostic"] = provisioning_errors.get(case["cpu"], "CPU source unavailable")
                report_cases.append(record)
                continue
            try:
                plan = plan_generic_composition(
                    GenericCompositionRequest(
                        description,
                        tuple(case["peripherals"]),
                        (PROCESSOR_BEAT,),
                        seed=seed + index,
                    ),
                    base_dir=ROOT,
                    component_catalog=component_catalog,
                )
                record["plan"] = "passed"
                output = composition_root / record["id"]
                write_generic_composition(plan, output, base_dir=ROOT)
                record["publication"] = "passed"
                lint, lint_diag = _lint(output)
                record["lint"] = lint
                if lint_diag:
                    record["diagnostic"] = lint_diag
                if lint == "passed":
                    smoke, smoke_diag = _smoke(output)
                    record["smoke"] = smoke
                    if smoke_diag:
                        record["diagnostic"] = smoke_diag
                record["status"] = "passed" if record["smoke"] == "passed" else "failed"
                if keep_artifacts:
                    record["artifact_dir"] = output.relative_to(ROOT).as_posix()
            except Exception as error:  # keep every failed case in the report
                record["diagnostic"] = str(error)[-4000:]
            report_cases.append(record)

        cpu_reuse: dict[str, int] = {}
        peripheral_reuse: dict[str, int] = {}
        for case in selected:
            cpu_reuse[case["cpu"]] = cpu_reuse.get(case["cpu"], 0) + 1
            for peripheral in case["peripherals"]:
                peripheral_reuse[peripheral] = peripheral_reuse.get(peripheral, 0) + 1
        passed = sum(item["status"] == "passed" for item in report_cases)
        report = {
            "schema": "real-cpu-peripheral-matrix.v1",
            "seed": seed,
            "cpu_reuse": cpu_reuse,
            "peripheral_reuse": peripheral_reuse,
            "provisioning_errors": provisioning_errors,
            "provisioning_revisions": provisioning_revisions,
            "summary": {"total": len(report_cases), "passed": passed, "failed": len(report_cases) - passed},
            "cases": report_cases,
        }
        (out_dir / "matrix_report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        (out_dir / "matrix_report.txt").write_text(
            "real CPU/peripheral matrix\n"
            f"seed={seed} passed={passed}/{len(report_cases)}\n"
            + "\n".join(
                f"{item['id']}: {item['status']} plan={item['plan']} lint={item['lint']} smoke={item['smoke']}"
                for item in report_cases
            )
            + "\n",
            encoding="utf-8",
        )
        return report
    finally:
        if temporary is not None:
            temporary.cleanup()
        if composition_temporary is not None:
            composition_temporary.cleanup()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20260909)
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=ROOT / "examples/real_cpu_peripheral_matrix/results",
    )
    parser.add_argument("--keep-artifacts", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = run_matrix(seed=args.seed, out_dir=args.out_dir, keep_artifacts=args.keep_artifacts)
    except Exception as error:
        print(f"matrix runner failed: {error}", file=sys.stderr)
        return 2
    print(
        f"real CPU/peripheral matrix: {report['summary']['passed']}/"
        f"{report['summary']['total']} passed; report={args.out_dir.resolve() / 'matrix_report.json'}"
    )
    return 0 if report["summary"]["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
