import os
import hashlib
import json
import shutil
import signal
import subprocess
import sys
import time
from types import SimpleNamespace
from pathlib import Path
import tempfile
import unittest
from contextlib import contextmanager
from unittest.mock import patch
from tests.integration.test_rfuzz_simulator import make_plan
from myfuzz.components.catalog import ComponentCatalog
from myfuzz.components.model import PeripheralProfile
from myfuzz.composition import GenericCompositionRequest, load_interface_description, plan_generic_composition
from myfuzz.integration import (
    RiscvExecutionFacts, RiscvExecutionProvenance, build_minimal_boot_image,
)
from myfuzz.protocols.catalog import load_protocol_catalog
from myfuzz.isa.constraints import IsaContract
from myfuzz.integration.rfuzz_simulator import RtlSimulator, build_simulator
try:
    from myfuzz.integration.rfuzz_live import run_live
except ImportError:
    run_live = None


def make_ibex_rfuzz_artifact(root, work):
    document = json.loads(
        (root / "configs/cpus/ibex/official_core_interface_description.json").read_text()
    )
    for endpoint in document["endpoints"]:
        if endpoint["endpoint_id"] == "processor.interrupts":
            for field in endpoint["fields"]:
                field["randomizable"] = True
    description = load_interface_description(document)
    memory = PeripheralProfile(
        "boot-memory", "riscv_boot_memory_32", (("processor-memory-beat", "1"),),
        4, 4096, False, (), "implemented",
        ("src/myfuzz/integration/rtl/riscv_boot_memory.sv",), True, {},
        protocol_features={("processor-memory-beat", "1"): ("reset_flush",)},
    )
    plan = plan_generic_composition(
        GenericCompositionRequest(
            description, ("boot-memory",), isa=IsaContract(32, ("I", "M", "C"), instruction_alignment=2)
        ),
        base_dir=root,
        component_catalog=ComponentCatalog((memory,)),
        protocol_catalog=load_protocol_catalog(root / "src/myfuzz/protocols/plugins"),
    )
    facts = RiscvExecutionFacts(
        isa="rv32imc", xlen=32, reset_vector=0x80, pass_address=0x400,
        pass_value=0x600DCAFE, protocol=("obi", "1"), max_cycles=400,
        provenance=RiscvExecutionProvenance(
            source_identity=description.source.source_root, source_hash="sha256:" + plan.source_evidence_hash.removeprefix("sha256:"),
            profile_identity="rv32imc-reset-0x80", profile_hash="sha256:" + hashlib.sha256(b"rv32imc:32:128:1024:1611516670").hexdigest(),
            interface_identity="task14-ibex-interface", interface_hash="sha256:" + hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest(),
            isa="rv32imc", xlen=32, reset_vector=0x80,
        ),
    )
    boot = build_minimal_boot_image(facts, work / "boot")
    return build_simulator(
        plan, work / "sim", base_dir=root, coverage_ports=(),
        coverage_signals=(("backend_target_req_valid", 0), ("backend_target_rsp_valid", 0)),
        randomized_controls=("interrupt",),
        control_defaults={"boot_address": facts.reset_vector, "hart_id": 0,
                          "request": 0, "interrupt": 0,
                          "fetch_enable": 5, "scan_reset": 1, "test_enable": 0,
                          "counter_enable_writable": 5, "cheriot_enable": 10,
                          **{role: 0 for role in (
                              "instruction_integrity", "data_integrity", "data_tag",
                              "trvk_heap_base", "trvk_grant", "trvk_response_valid",
                              "trvk_read_data", "trvk_read_integrity", "trvk_error",
                              "scramble_key_valid", "scramble_key", "scramble_nonce")}},
        simulator_args=(f"+riscv_boot_image={boot.memory_hex_path}",),
        simulator="verilator", isolate_tests=False,
    )


@contextmanager
def live_directory():
    retained = os.environ.get("MYFUZZ_RFuzz_RUNS")
    if retained:
        parent = Path(retained).resolve()
        parent.mkdir(parents=True, exist_ok=True)
        root = Path(tempfile.mkdtemp(prefix="live-", dir=parent))
        print(f"Retained RFuzz artifacts: {root}", flush=True)
        yield str(root)
    else:
        with tempfile.TemporaryDirectory() as tmp:
            yield tmp


@unittest.skipUnless(os.environ.get("MYFUZZ_RFuzz_CLIENT"), "official RFuzz binary opt-in")
class LiveTests(unittest.TestCase):
    def test_official_mutator_uses_actual_rtl_feedback(self):
        self.assertIsNotNone(run_live, "live upstream RFuzz runner missing")
        with live_directory() as tmp:
            root=Path(tmp)
            plan,names=make_plan(root)
            artifact=build_simulator(plan,root/"sim",base_dir=root,
                coverage_ports=tuple((names[-1],i) for i in range(3)))
            result=run_live(artifact,Path(os.environ["MYFUZZ_RFuzz_CLIENT"]),root/"run",duration_seconds=2)
            self.assertEqual(result["returncode"],0)
            self.assertGreater(result["tests"],1)
            self.assertGreater(result["corpus_entries"],1)
            self.assertTrue(any(result["counter_maxima"]))
            self.assertEqual(result["coverage_kind"],artifact.coverage_kind)
            self.assertEqual(result["remaining_segments"],[])
            from myfuzz.integration.rfuzz_live import replay_corpus
            replay = replay_corpus(artifact, root / "run/corpus")
            self.assertEqual(replay["entries"], result["corpus_entries"])
            (root / "run/replay.json").write_text(json.dumps(replay, sort_keys=True) + "\n")


@unittest.skipUnless(shutil.which("iverilog") and shutil.which("vvp"), "Icarus required")
class LiveFailureTests(unittest.TestCase):
    def test_simulator_diagnostics_are_counted_with_bounded_retained_samples(self):
        from myfuzz.integration import rfuzz_live
        record = getattr(rfuzz_live, "_record_simulator_diagnostics", None)
        self.assertTrue(callable(record), "live report must retain bounded RTL diagnostics")
        state = {}
        simulator = SimpleNamespace(last_diagnostics=tuple(f"RTL diagnostic {i}" for i in range(40)))
        record(state, simulator)
        record(state, simulator)
        self.assertEqual(state["simulator_diagnostics"]["lines"], 80)
        self.assertEqual(len(state["simulator_diagnostics"]["samples"]), 32)
        self.assertEqual(state["simulator_diagnostics"]["samples"][0], "RTL diagnostic 0")

    def test_replay_identity_is_bound_to_raw_layout_constraints_and_binary(self):
        from myfuzz.integration.rfuzz_live import replay_identity
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "sim.vvp"
            binary.write_bytes(b"simulator-v1")
            artifact = SimpleNamespace(
                layout=SimpleNamespace(layout_hash="sha256:layout"),
                projector=SimpleNamespace(constraint_hash="sha256:constraints"),
                executable=binary,
            )
            first = replay_identity(artifact, b"raw-input")
            second = replay_identity(artifact, b"raw-input")
            changed = replay_identity(artifact, b"other-input")
            self.assertEqual(first, second)
            self.assertNotEqual(first["replay_key"], changed["replay_key"])
            self.assertEqual("sha256:layout", first["layout_hash"])
            self.assertEqual("sha256:constraints", first["constraint_hash"])
            self.assertEqual(first["binary_sha256"], first["binary_hash"])

    def test_corpus_manifest_records_wire_inputs_and_actual_feedback_identity(self):
        from myfuzz.integration import rfuzz_live
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "sim.vvp"
            binary.write_bytes(b"simulator-v1")
            corpus = root / "corpus"
            corpus.mkdir()
            (corpus / "entry_0000.json").write_text(json.dumps({
                "entry": {"inputs": [0, 0, 0, 0, 0, 0, 0, 0]},
                "trace_bits": [1, 0, 0, 0, 0, 0],
            }))
            artifact = SimpleNamespace(
                layout=SimpleNamespace(layout_hash="sha256:layout"),
                projector=SimpleNamespace(constraint_hash="sha256:constraints"),
                executable=binary,
                transport=SimpleNamespace(byte_count=8),
            )
            identity = rfuzz_live.replay_identity(artifact, bytes([0] * 8))
            with patch.object(rfuzz_live, "replay_corpus", return_value={
                "replays": [{"file": "entry_0000.json", "input_sha256": identity["raw_sha256"],
                              "counters": [1, 0, 0, 0, 0, 0]}],
            }):
                manifest = rfuzz_live.build_corpus_manifest(artifact, corpus)
            self.assertEqual("rfuzz_corpus_manifest.v1", manifest["schema_version"])
            self.assertEqual(1, manifest["entries"])
            self.assertIn("replay_key", manifest["replays"][0])
            self.assertEqual(8, manifest["replays"][0]["input_bytes"])

    def test_zero_work_client_is_not_completed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, names = make_plan(root)
            artifact = build_simulator(plan, root / "sim", base_dir=root,
                coverage_ports=((names[-1], 0),))
            with self.assertRaisesRegex(RuntimeError, "no RTL tests"):
                run_live(artifact, Path(shutil.which("true")), root / "run", duration_seconds=1)
            self.assertEqual(json.loads((root / "run/report.json").read_text())["status"], "failed")

    def test_aggregate_soft_limit_stops_before_serving(self):
        from myfuzz.integration import rfuzz_live
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, names = make_plan(root)
            artifact = build_simulator(plan, root / "sim", base_dir=root,
                coverage_ports=((names[-1], 0),))
            client = root / "client"
            client.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(5)\n")
            client.chmod(0o700)
            with patch.object(rfuzz_live, "read_process_group_rss_bytes", return_value=260 * 1024 * 1024), \
                    patch.object(rfuzz_live.FifoEndpoint, "receive", side_effect=RuntimeError("served above soft limit")):
                with self.assertRaisesRegex(MemoryError, "soft"):
                    run_live(artifact, client, root / "run", duration_seconds=1)
            result = json.loads((root / "run/report.json").read_text())
            self.assertEqual(result["status"], "failed")
            self.assertGreaterEqual(result["peak_rss_bytes"], 520 * 1024 * 1024)
            self.assertIn("runner", result["memory_scope"])

    def test_sigterm_reports_failure_and_restores_previous_handler(self):
        self._sigterm_case("receive")

    def test_sigterm_during_client_initialization_cleans_group(self):
        self._sigterm_case("launch")

    def test_sigterm_during_cleanup_finishes_cleanup(self):
        self._sigterm_case("cleanup")

    def _sigterm_case(self, phase):
        with tempfile.TemporaryDirectory() as tmp:
            # Isolate the signal test so RED cannot terminate the test worker.
            script = r'''
import os, signal, sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch, MagicMock
from myfuzz.integration import rfuzz_live
root=Path(sys.argv[1])
artifact=SimpleNamespace(layout=SimpleNamespace(layout_hash="test"),
    coverage_kind="test", coverage_ports=(("flag",0),),
    transport=SimpleNamespace(document=lambda: {}, byte_count=8))
previous=signal.getsignal(signal.SIGTERM)
client=MagicMock(pid=1000000000, returncode=0, args=("fake",))
client.poll.return_value=None
phase=sys.argv[2]
def terminate(*args, **kwargs):
    os.kill(os.getpid(), signal.SIGTERM)
def launch(*args, **kwargs):
    if phase=="launch": terminate()
    return client
def receive(*args, **kwargs):
    if phase=="receive": terminate()
    elif phase=="cleanup": raise RuntimeError("execution failure")
def cleanup(*args, **kwargs):
    if phase=="cleanup": terminate()
    (root/"cleanup.calls").open("a").write("cleanup\n")
with patch.object(rfuzz_live, "_configuration", return_value="test"), \
     patch.object(rfuzz_live, "RtlSimulator"), \
     patch.object(rfuzz_live.subprocess, "Popen", side_effect=launch), \
     patch.object(rfuzz_live.os, "killpg", side_effect=cleanup), \
     patch.object(rfuzz_live, "read_process_group_rss_bytes", return_value=0), \
     patch.object(rfuzz_live.FifoEndpoint, "receive", side_effect=receive):
    try:
        rfuzz_live.run_live(artifact, Path(sys.executable), root/"run", duration_seconds=1)
    except BaseException:
        assert signal.getsignal(signal.SIGTERM) == previous
        sys.exit(7)
sys.exit(0)
'''
            process = subprocess.run((sys.executable, "-c", script, tmp, phase),
                                     capture_output=True, timeout=5)
            self.assertEqual(process.returncode, 7, process.stderr.decode())
            result = json.loads((Path(tmp) / "run/report.json").read_text())
            self.assertEqual(result["status"], "failed")
            if phase != "cleanup":
                self.assertIn("SIGTERM", result["error"])
            self.assertEqual((Path(tmp) / "cleanup.calls").read_text().count("cleanup"), 2)

    def test_replay_accepts_supported_large_wire_record(self):
        from myfuzz.integration import rfuzz_live
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            # Exercise the JSON admission boundary without compiling a huge
            # fixture. Actual RTL replay is covered in the companion test.
            document = {"entry": {"inputs": [255] * (8192 * 200)},
                        "trace_bits": [1, 0, 0, 0, 0, 0]}
            (root / "entry_0000.json").write_text(json.dumps(document))
            artifact = SimpleNamespace(coverage_ports=(("out", 0),),
                transport=SimpleNamespace(byte_count=8192),
                layout=SimpleNamespace(layout_hash="test"), coverage_kind="test")
            with patch.object(rfuzz_live, "RtlSimulator") as constructor:
                constructor.return_value.__enter__.return_value.run_test.return_value = b"\1"
                try:
                    result = rfuzz_live.replay_corpus(artifact, root)
                except ValueError as error:
                    self.fail(f"supported maximum-width record rejected: {error}")
                self.assertEqual(result["entries"], 1)

    def test_interrupt_cleans_client_descendant_and_reports_failure(self):
        from myfuzz.integration import rfuzz_live
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, names = make_plan(root)
            artifact = build_simulator(plan, root / "sim", base_dir=root,
                coverage_ports=((names[-1], 0),))
            pids = root / "child.pid"
            client = root / "client"
            client.write_text(f"#!{sys.executable}\nimport subprocess,sys,time\n"
                "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])\n"
                f"open({str(pids)!r},'w').write(str(child.pid))\n"
                "time.sleep(30)\n")
            client.chmod(0o700)
            started = time.monotonic()
            def interrupt(*args, **kwargs):
                if pids.exists() or time.monotonic() - started > 3:
                    raise KeyboardInterrupt("test interrupt")
                time.sleep(.01)
                return None
            child = None
            try:
                with patch.object(rfuzz_live.FifoEndpoint, "receive", side_effect=interrupt):
                    with self.assertRaises(KeyboardInterrupt):
                        run_live(artifact, client, root / "run", duration_seconds=5)
                self.assertTrue(pids.exists(), "client did not launch")
                child = int(pids.read_text())
                status = Path(f"/proc/{child}/stat")
                deadline = time.monotonic() + 1
                while status.exists() and status.read_text().split(") ", 1)[1][0] != "Z" and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(not status.exists() or status.read_text().split(") ", 1)[1][0] == "Z",
                                "client descendant survived interrupt cleanup")
                result = json.loads((root / "run/report.json").read_text())
                self.assertEqual(result["status"], "failed")
                self.assertIn("KeyboardInterrupt", result["error"])
            finally:
                if child is None and pids.exists():
                    child = int(pids.read_text())
                if child is not None:
                    try:
                        os.kill(child, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    def test_simulator_start_failure_has_durable_report(self):
        from myfuzz.integration import rfuzz_live
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, names = make_plan(root)
            artifact = build_simulator(plan, root / "sim", base_dir=root,
                coverage_ports=((names[-1], 0),))
            with patch.object(rfuzz_live, "RtlSimulator", side_effect=RuntimeError("startup failure")):
                with self.assertRaisesRegex(RuntimeError, "startup failure"):
                    run_live(artifact, Path(shutil.which("true")), root / "run", duration_seconds=1)
            report = root / "run/report.json"
            self.assertTrue(report.exists(), "startup failure lost its report")
            result = json.loads(report.read_text())
            self.assertEqual(result["status"], "failed")
            self.assertIn("startup failure", result["error"])
            self.assertEqual(result["tests"], 0)
            provenance = result.get("artifact_provenance")
            self.assertIsNotNone(provenance, "report lost source and composition identity")
            self.assertEqual(provenance["composition_ir_hash"], plan.composition_ir_hash)
            self.assertEqual(provenance["interface_description"]["source"]["revision"],
                             plan.interface_description.source.revision)
            self.assertEqual(provenance["composition_seed"], plan.request.seed)

    def test_corpus_replay_checks_actual_rtl_and_wire_padding(self):
        from myfuzz.integration import rfuzz_live
        replay = getattr(rfuzz_live, "replay_corpus", None)
        self.assertIsNotNone(replay, "durable corpus RTL replay missing")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            plan, names = make_plan(root)
            artifact = build_simulator(plan, root / "sim", base_dir=root,
                coverage_ports=((names[-1], 0),))
            raw = sum(1 << field.raw_lo for field in artifact.layout.fields)
            corpus = root / "corpus"
            corpus.mkdir()
            entry = {"entry": {"inputs": list(artifact.transport.pack(raw))},
                     "trace_bits": [1, 0, 0, 0, 0, 0]}
            path = corpus / "entry_0000.json"
            path.write_text(json.dumps(entry))
            result = replay(artifact, corpus)
            self.assertEqual(result["entries"], 1)
            self.assertEqual(result["replays"][0].get("trace_sha256"),
                             "sha256:" + hashlib.sha256(bytes(entry["trace_bits"])).hexdigest())
            entry["trace_bits"][0] = 0
            path.write_text(json.dumps(entry))
            with self.assertRaisesRegex(ValueError, "coverage mismatch"):
                replay(artifact, corpus)
            entry["trace_bits"] = [1, 0, 0, 0, 0, 1]
            path.write_text(json.dumps(entry))
            with self.assertRaisesRegex(ValueError, "padding"):
                replay(artifact, corpus)


class ReplayIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        binary = self.root / "sim.vvp"
        binary.write_bytes(b"simulator-v1")
        self.artifact = SimpleNamespace(
            layout=SimpleNamespace(layout_hash="sha256:layout"),
            projector=SimpleNamespace(constraint_hash="sha256:constraints"),
            executable=binary,
            transport=SimpleNamespace(byte_count=8),
            coverage_ports=(("out", 0),),
            coverage_kind="test",
        )
        self.payload = bytes(8)

    def test_replay_identity_binds_transducer_and_header_hashes(self):
        from myfuzz.integration.rfuzz_live import replay_identity
        self.artifact.transducer_hash = "sha256:transducer-v1"
        self.artifact.header_hash = "sha256:header-v1"
        identity = replay_identity(self.artifact, self.payload)
        for key in ("transducer_hash", "header_hash"):
            with self.subTest(key=key):
                self.assertEqual(getattr(self.artifact, key), identity.get(key))
                changed = SimpleNamespace(**vars(self.artifact))
                setattr(changed, key, "sha256:changed")
                self.assertNotEqual(
                    identity["replay_key"],
                    replay_identity(changed, self.payload)["replay_key"],
                )

    def test_absent_transducer_metadata_preserves_legacy_identity(self):
        from myfuzz.integration.rfuzz_live import replay_identity
        legacy = replay_identity(self.artifact, self.payload)
        self.artifact.transducer_hash = None
        self.artifact.header_hash = None
        self.assertEqual(legacy, replay_identity(self.artifact, self.payload))
        self.assertNotIn("transducer_hash", legacy)
        self.assertNotIn("header_hash", legacy)

    def test_corpus_rejects_changed_transducer_metadata_before_execution(self):
        from myfuzz.integration import rfuzz_live
        self.artifact.transducer_hash = "sha256:transducer-v1"
        self.artifact.header_hash = "sha256:header-v1"
        for operation in (rfuzz_live.replay_corpus, rfuzz_live.build_corpus_manifest):
            for key in ("transducer_hash", "header_hash"):
                with self.subTest(operation=operation.__name__, key=key):
                    self._write_corpus({key: "sha256:other"})
                    with patch.object(rfuzz_live, "RtlSimulator") as constructor:
                        simulator = constructor.return_value.__enter__.return_value
                        simulator.run_test.return_value = b"\1"
                        with self.assertRaisesRegex(ValueError, "replay identity mismatch"):
                            operation(self.artifact, self.root)
                        simulator.run_test.assert_not_called()

    def test_corpus_rejects_saved_transducer_binding_without_artifact_metadata(self):
        from myfuzz.integration import rfuzz_live
        for key in ("transducer_hash", "header_hash"):
            with self.subTest(key=key):
                self._write_corpus({key: "sha256:saved"})
                with patch.object(rfuzz_live, "RtlSimulator") as constructor:
                    simulator = constructor.return_value.__enter__.return_value
                    simulator.run_test.return_value = b"\1"
                    with self.assertRaisesRegex(ValueError, "replay identity mismatch"):
                        rfuzz_live.replay_corpus(self.artifact, self.root)
                    simulator.run_test.assert_not_called()

    def test_corpus_manifest_retains_transducer_metadata(self):
        from myfuzz.integration import rfuzz_live
        self.artifact.transducer_hash = "sha256:transducer-v1"
        self.artifact.header_hash = "sha256:header-v1"
        self._write_corpus(rfuzz_live.replay_identity(self.artifact, self.payload))
        with patch.object(rfuzz_live, "RtlSimulator") as constructor:
            constructor.return_value.__enter__.return_value.run_test.return_value = b"\1"
            manifest = rfuzz_live.build_corpus_manifest(self.artifact, self.root)
        self.assertEqual(1, manifest["entries"])
        for key in ("transducer_hash", "header_hash"):
            self.assertEqual(getattr(self.artifact, key), manifest["replays"][0].get(key))

    def _write_corpus(self, identity):
        (self.root / "entry_0000.json").write_text(json.dumps({
            "entry": {"inputs": list(self.payload)},
            "trace_bits": [1, 0, 0, 0, 0, 0],
            "replay_identity": identity,
        }))


@unittest.skipUnless(
    os.environ.get("MYFUZZ_RFuzz_REAL_CPU") and shutil.which("verilator"),
    "real CPU RFuzz opt-in",
)
class RealCpuOptInTests(unittest.TestCase):
    def test_ibex_runtime_uses_real_cpu_and_internal_feedback_signals(self):
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory(prefix="task14-ibex-", dir=root / "runs") as tmp:
            artifact = make_ibex_rfuzz_artifact(root, Path(tmp))
            with RtlSimulator(artifact) as simulator:
                payload = artifact.transport.pack(0)
                counters = simulator.run_test((payload,) * 80)
            self.assertEqual(2, len(counters))
            self.assertTrue(any(counters))

    @unittest.skipUnless(os.environ.get("MYFUZZ_RFuzz_CLIENT"), "official RFuzz client opt-in")
    def test_ibex_official_client_round_trips_real_feedback_and_corpus(self):
        self.assertIsNotNone(run_live, "live upstream RFuzz runner missing")
        root = Path(__file__).resolve().parents[2]
        with live_directory() as tmp:
            work = Path(tmp)
            artifact = make_ibex_rfuzz_artifact(root, work)
            result = run_live(
                artifact, Path(os.environ["MYFUZZ_RFuzz_CLIENT"]), work / "run", duration_seconds=2, seed_cycles=80
            )
            self.assertGreater(result["tests"], 1)
            self.assertGreater(result["corpus_entries"], 1)
            self.assertTrue(result["corpus_manifest"]["replays"][0]["coverage_verified"])
            self.assertEqual(result["status"], "completed")
