"""G6 saved evidence: ``generic_runtime_bundle.v1`` writer, verifier, tampers.

Every fixture is synthetic (no RTL, no native session, no preparation).  The
documents are built from the real ``GenericExecutionPlan``/``EffectEvidence``
contracts so the saved shape is the production shape, and each tamper is
re-sealed (manifest hashes and receipts recomputed) so the refusal comes from a
semantic reconstruction rather than from a stale byte pin.
"""
from __future__ import annotations

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from myfuzz.runtime.contracts import (
    AdapterSelection,
    GenericExecutionPlan,
    VerifiedComponent,
    canonical_json_bytes,
)
from myfuzz.runtime.evidence.contracts import EffectEvidence, EvidenceRef
from myfuzz.runtime.evidence.saved import (
    BUNDLE_SCHEMA,
    CASE_SCHEMA,
    SavedBundleRefused,
    case_receipt_sha256,
    source_closure_sha256,
    transaction_document,
    verify_saved_bundle,
    version_sha256,
    write_bundle,
)
from myfuzz.scenario.ledger import TransactionKey

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_generic_runtime.py"

READ_FLOW = "F2"
EFFECT_FLOW = "F4"
EXECUTION = "gen-run-g6saved"
REGISTER = "TIMER0_CTRL"
ADDRESS = 0x1000
BINDING = sha256(b"binding:generic-apb-timer").hexdigest()
D2 = sha256(b"generic:d2").hexdigest()
D3 = sha256(b"generic:d3").hexdigest()
BUILD = sha256(b"build:generic").hexdigest()
BINARY = sha256(b"binary:generic").hexdigest()

CPU_ARTIFACT = sha256(b"artifact:processor").hexdigest()
CPU_SEMANTIC = sha256(b"semantic:processor").hexdigest()
IP_ARTIFACT = sha256(b"artifact:peripheral").hexdigest()
IP_SEMANTIC = sha256(b"semantic:peripheral").hexdigest()

ARCHIVE_FILES = (
    ("configs/scenarios/generic-storage-contracts/compose.json",
     "archive/configs/scenarios/generic-storage-contracts/compose.json",
     b'{"compose":"timer-and-cpu"}\n'),
    ("configs/peripherals/generic-timer/component_profile.json",
     "archive/configs/peripherals/generic-timer/component_profile.json",
     b'{"profile":"generic-timer"}\n'),
    ("src/myfuzz/integration/generated_storage_consumer.py",
     "archive/src/myfuzz/integration/generated_storage_consumer.py",
     b"# archived storage consumer v1\n"),
)
GENERATED_FILES = {
    "peripheral": {
        "runtime.sv": b"module timer_runtime; endmodule\n",
        "artifact.json": b'{"kind":"generic-timer"}\n',
    },
    "processor": {
        "runtime.sv": b"module cpu_runtime; endmodule\n",
        "artifact.json": b'{"kind":"generic-processor"}\n',
    },
}
GENERATED_TOP = {"generated/wiring_contract.json": b'{"wiring":"timer"}\n'}

COMPOSE = "configs/scenarios/generic-storage-contracts/compose.json"
CAPABILITY = "configs/scenarios/generic-storage-contracts/test_capability.json"
SUPPLEMENT = ("configs/scenarios/generic-storage-contracts/"
              "execution_supplement.json")
PRODUCER = {"id": "myfuzz.generic_runtime.saved_fixture",
            "version": "fixture-v1",
            "implementation_sha256": sha256(b"fixture-producer").hexdigest()}

IDENTITY_FIELDS = (
    "processes/peripheral/nonce",
    "processes/peripheral/pid",
    "processes/processor/nonce",
    "processes/processor/pid",
)


def _digest(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


def _endpoint(endpoint_id, role, protocol, template, semantic_kind,
              operations, address_width):
    return {
        "endpoint_id": endpoint_id,
        "role": role,
        "protocol": list(protocol),
        "template": list(template),
        "semantic_kind": semantic_kind,
        "operations": sorted(operations),
        "data_width": 32,
        "address_width": address_width,
        "address_units": "byte",
        "max_outstanding": 1,
        "completion_kind": "transaction",
        "byte_enable": True,
        "evidence_capabilities": ["component.semantic.effect",
                                  "physical.protocol.sample"],
    }


def _component(instance_id, artifact, semantic, endpoint):
    return {
        "schema_version": "verified_component_descriptor.v1",
        "instance_id": instance_id,
        "source_sha256": _digest(instance_id + ":source"),
        "profile_sha256": _digest(instance_id + ":profile"),
        "artifact_sha256": artifact,
        "semantic_contract_sha256": semantic,
        "source_verifier": {
            "id": "apb.storage.admission.v1",
            "version": "fixture-v1",
            "implementation_sha256": _digest("verifier:" + instance_id),
        },
        "endpoints": [endpoint],
    }


CPU_COMPONENT = _component(
    "processor", CPU_ARTIFACT, CPU_SEMANTIC,
    _endpoint("cpu-data", "cpu", ("obi", "v1"), ("obi", "v1", "cpu-data"),
              "cpu.obi.v1", ("read", "write"), 32))
IP_COMPONENT = _component(
    "peripheral", IP_ARTIFACT, IP_SEMANTIC,
    _endpoint("apb-target", "target", ("apb3", "v1"),
              ("apb3", "v1", "generic-storage"), "storage.readwrite.v1",
              ("read", "write"), 12))

CPU_SELECTION = {
    "adapter_id": "obi.cpu.v1",
    "adapter_version": "fixture-v1",
    "implementation_sha256": _digest("adapter:obi.cpu"),
    "component_artifact_sha256": CPU_ARTIFACT,
    "semantic_contract_sha256": CPU_SEMANTIC,
}
IP_SELECTION = {
    "adapter_id": "apb3.storage.v1",
    "adapter_version": "fixture-v1",
    "implementation_sha256": _digest("adapter:apb3.storage"),
    "component_artifact_sha256": IP_ARTIFACT,
    "semantic_contract_sha256": IP_SEMANTIC,
}


# ---------------------------------------------------------------------------
# synthetic but internally consistent bundle spec
# ---------------------------------------------------------------------------
def build_spec(*, flow=EFFECT_FLOW, values=(0x11, 0x22, 0x33),
               pid_cpu=41001, pid_ip=41002, nonce_cpu="cpu-nonce-a",
               nonce_ip="ip-nonce-a", execution=EXECUTION,
               reset_epoch=1, tick_base=1000):
    """One run: same plan/processes, one accepted case per value."""
    archive_closure = sorted(
        (archive_path, sha256(payload).hexdigest())
        for _, archive_path, payload in ARCHIVE_FILES)
    closure = source_closure_sha256(archive_closure)
    archive_map = []
    files = {}
    for repository_path, archive_path, payload in ARCHIVE_FILES:
        archive_map.append((repository_path, archive_path))
        files[archive_path] = payload
    for instance_id, names in GENERATED_FILES.items():
        for name, payload in names.items():
            files[f"generated/{instance_id}/{name}"] = payload
    files.update(GENERATED_TOP)

    plan_document = {
        "schema_version": "generic_execution_plan.v1",
        "components": [
            {"instance_id": "processor", "artifact_sha256": CPU_ARTIFACT,
             "semantic_contract_sha256": CPU_SEMANTIC},
            {"instance_id": "peripheral", "artifact_sha256": IP_ARTIFACT,
             "semantic_contract_sha256": IP_SEMANTIC},
        ],
        "selections": [CPU_SELECTION, IP_SELECTION],
        "paths": [{"path_id": "path-timer", "flow_id": flow,
                   "bound_inputs": [{"input_id": "bound-timer",
                                     "instance_id": "peripheral"}]}],
        "sources": [{"source_id": "stream-timer", "component": "processor",
                     "channel_id": "processor.timer.bus", "flow_id": flow,
                     "source_closure_sha256": closure}],
        "constraints": [{"constraint_id": "non-alias-offset",
                         "register": REGISTER}],
        "seeds": [{"seed_id": "seed-1", "width": 32}],
        "assertions": [{"assertion_id": "apb-response", "status": "checked"}],
        "memory": {"model": "persistent", "reset_between_cases": False},
        "scheduling": {"rounds_per_case": 8, "persistent_session": True},
        "termination": {"max_cases": 8, "on_error": "faulted"},
        "evidence_obligations": ["component.semantic.effect",
                                 "physical.protocol.sample"],
        "input_digests": {"d2": D2, "d3": D3},
    }

    process_cpu = {"session": "processor", "pid": pid_cpu, "nonce": nonce_cpu,
                   "executable_sha256": _digest("executable:processor")}
    process_ip = {"session": "peripheral", "pid": pid_ip, "nonce": nonce_ip,
                  "executable_sha256": _digest("executable:peripheral")}
    processes = {
        "sessions": {
            "processor": {"pid": pid_cpu, "nonce": nonce_cpu,
                          "executable_sha256": process_cpu["executable_sha256"],
                          "ready": True},
            "peripheral": {"pid": pid_ip, "nonce": nonce_ip,
                           "executable_sha256": process_ip["executable_sha256"],
                           "ready": True},
        },
        "build_sha256": BUILD,
        "binary_sha256": BINARY,
    }

    events = []
    cases = []
    evidence = []
    storage_value = 0
    write_count = 0
    command_sequence = 0
    tick = tick_base
    effect = flow == EFFECT_FLOW
    for index, record in enumerate(values):
        testcase = f"{execution}:case:{index}"
        key = TransactionKey(execution, testcase, "processor", reset_epoch,
                             "processor.timer.bus", index)
        key_document = transaction_document(key)
        # The current stable state is re-issued as the case prerequisite; the
        # persisted value/write_count carry over, the counters do not.
        before_version = {
            "schema_version": "apb_storage_register_version.v1",
            "register": REGISTER,
            "value": storage_value,
            "write_count": write_count,
            "reset_epoch": reset_epoch,
            "command_sequence": command_sequence,
            "local_tick": tick,
            "field_version": write_count,
            "version_basis": "all_measured_writes_since_first_command",
        }
        command_sequence += 1
        tick += 1
        after_version = dict(before_version)
        if effect:
            after_version["value"] = record
            after_version["write_count"] = write_count + 1
            after_version["field_version"] = write_count + 1
            data = record
            read_return = 0
        else:
            data = storage_value
            read_return = storage_value
        after_version["command_sequence"] = command_sequence
        after_version["local_tick"] = tick
        command_sequence += 1
        tick += 1
        write_count = after_version["write_count"]

        before_id = len(events)
        events.append({
            "event_id": before_id,
            "component": "peripheral",
            "kind": "ip_register_version",
            "tick": tick_base + 4 * index,
            "provenance": {"case_id": testcase,
                           "transaction": key_document,
                           "process": dict(process_ip)},
            "payload": {"phase": "before", "version": before_version},
        })
        source_id = len(events)
        events.append({
            "event_id": source_id,
            "component": "processor",
            "kind": "cpu_source_accept",
            "tick": tick_base + 4 * index + 1,
            "provenance": {"case_id": testcase,
                           "transaction": key_document,
                           "process": dict(process_cpu)},
            "payload": {"operation": "write" if effect else "read",
                        "address": ADDRESS,
                        "data": data},
        })
        native_id = len(events)
        events.append({
            "event_id": native_id,
            "component": "peripheral",
            "kind": "apb_storage_probe",
            "tick": tick_base + 4 * index + 2,
            "provenance": {"case_id": testcase,
                           "transaction": key_document,
                           "process": dict(process_ip)},
            "payload": {"write": effect,
                        "address": ADDRESS,
                        "wdata": record if effect else 0,
                        "rdata": 0 if effect else read_return,
                        "be": 15,
                        "build_sha256": BUILD},
        })
        after_id = len(events)
        events.append({
            "event_id": after_id,
            "component": "peripheral",
            "kind": "ip_register_version",
            "tick": tick_base + 4 * index + 3,
            "provenance": {"case_id": testcase,
                           "transaction": key_document,
                           "process": dict(process_ip)},
            "payload": {"phase": "after", "version": after_version},
        })

        evidence.append([EffectEvidence(
            key, "certified", "component_semantic_effect", BINDING, IP_SEMANTIC,
            (EvidenceRef("processor", source_id, "cpu_source_accept"),),
            (EvidenceRef("peripheral", native_id, "apb_storage_probe"),),
            (EvidenceRef("peripheral", before_id, "ip_register_version"),
             EvidenceRef("peripheral", after_id, "ip_register_version")),
            (("physical.sample.joined", "certified"),
             ("register.version.issued", "certified")),
        )])
        cases.append({
            "index": index,
            "testcase_id": testcase,
            "path_id": "path-timer",
            "flow_id": flow,
            "source_id": "stream-timer",
            "raw_records_hex": [f"{record:08x}"],
            "instruction_sha256": _digest(f"instruction:{flow}:{index}"),
            "certificate": {
                "schema_version": "generic_case_certificate.v1",
                "case_id": testcase,
                "path_id": "path-timer",
                "status": "certified",
                "commit": {"before": before_version["value"],
                           "after": after_version["value"]},
                "read_return": read_return,
            },
            "version_chain": {
                "before_sha256": version_sha256(before_version),
                "after_sha256": version_sha256(after_version),
            },
        })
        storage_value = after_version["value"]

    inputs = {
        "compose": COMPOSE,
        "capability_paths": [CAPABILITY],
        "supplement": SUPPLEMENT,
        "flows": [flow],
        "input_digests": {"d2": D2, "d3": D3},
        "source_closure": [{"path": path, "sha256": digest}
                           for path, digest in archive_closure],
        "generated": [
            {"instance_id": instance_id,
             "files": {name: sha256(payload).hexdigest()
                       for name, payload in GENERATED_FILES[instance_id].items()}}
            for instance_id in sorted(GENERATED_FILES)],
    }
    sources = {
        "source_closure_sha256": closure,
        "files": sorted(
            ({"path": repository_path, "archive_path": archive_path,
              "sha256": sha256(payload).hexdigest()}
             for repository_path, archive_path, payload in ARCHIVE_FILES),
            key=lambda row: row["archive_path"]),
    }
    manifest = {
        "schema_version": BUNDLE_SCHEMA,
        "producer": dict(PRODUCER),
        "preparation": {"compose": COMPOSE,
                        "capability_paths": [CAPABILITY],
                        "supplement": SUPPLEMENT,
                        "flows": [flow]},
        "input_digests": {"d2": D2, "d3": D3},
        "source_closure_sha256": closure,
        "case_count": len(cases),
        "exit_status": "closed",
        "fresh_of": None,
        "normalized_identity_fields": [],
    }
    return {
        "plan_document": plan_document,
        "inputs": inputs,
        "sources": sources,
        "components": [deepcopy(CPU_COMPONENT), deepcopy(IP_COMPONENT)],
        "selections": [deepcopy(CPU_SELECTION), deepcopy(IP_SELECTION)],
        "cases": cases,
        "evidence": evidence,
        "events": events,
        "processes": processes,
        "prefix": {"schema_version": "generic_prefix_fixture.v1",
                   "cases": len(cases),
                   "semantic_hash": _digest("prefix-semantic")},
        "audit": {"closed": True,
                  "exits": {"processor": 0, "peripheral": 0}},
        "manifest": manifest,
        "files": files,
        "archive_map": archive_map,
        "closure": closure,
    }


# ---------------------------------------------------------------------------
# sealing helpers (hand-built directories, no writer involved)
# ---------------------------------------------------------------------------
def _documents(spec, *, plan_bytes, reseal_receipts=True,
               plan_identity=None):
    """Canonical saved documents for a spec, including the manifest."""
    documents = {
        "inputs.json": deepcopy(spec["inputs"]),
        "sources.json": deepcopy(spec["sources"]),
        "components.json": {"components": deepcopy(spec["components"])},
        "selections.json": {"selections": deepcopy(spec["selections"])},
        "evidence.json": {"cases": [
            {"index": index, "evidence": [document.document()
                                          for document in documents_]}
            for index, documents_ in enumerate(spec["evidence"])]},
        "events.json": deepcopy(spec["events"]),
        "prefix.json": deepcopy(spec["prefix"]),
        "execution_audit.json": deepcopy(spec["audit"]),
        "processes.json": deepcopy(spec["processes"]),
    }
    cases = deepcopy(spec["cases"])
    for index, case in enumerate(cases):
        if reseal_receipts:
            case["receipt_sha256"] = case_receipt_sha256(case)
        else:
            case.setdefault("receipt_sha256", "0" * 64)
    plan_digest = sha256(plan_bytes).hexdigest()
    documents["cases.json"] = {"schema_version": CASE_SCHEMA,
                               "plan_sha256": plan_digest,
                               "cases": cases}
    manifest = deepcopy(spec["manifest"])
    manifest["plan"] = {"schema_version": "generic_execution_plan.v1",
                        "document_sha256": plan_digest,
                        "identity_sha256": plan_identity or plan_digest}
    return documents, manifest


def materialize(root, spec, *, refresh_chains=False, plan_bytes=None,
                plan_identity=None, reseal_receipts=True, manifest=None,
                files=None) -> Path:
    """Write a bundle directory directly: no writer, no live object."""
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    if refresh_chains:
        _refresh_version_chains(spec)
    if plan_bytes is None:
        if "plan_bytes" in spec:
            plan_bytes = spec["plan_bytes"]
        else:
            plan_bytes = canonical_json_bytes(spec["plan_document"])
    documents, manifest_document = _documents(
        spec, plan_bytes=plan_bytes, reseal_receipts=reseal_receipts,
        plan_identity=plan_identity)
    if manifest is not None:
        manifest_document = manifest(manifest_document)
    payloads = dict(files if files is not None else spec["files"])
    for name, document in documents.items():
        payloads[name] = canonical_json_bytes(document)
    payloads["plan.json"] = plan_bytes
    hashes = {}
    for name in sorted(payloads):
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payloads[name])
        hashes[name] = sha256(payloads[name]).hexdigest()
    manifest_document["files"] = [{"path": name, "sha256": hashes[name]}
                                  for name in sorted(hashes)]
    (root / "bundle.json").write_bytes(canonical_json_bytes(manifest_document))
    return root


def _refresh_version_chains(spec) -> None:
    """Recompute each case chain from its archived before/after versions."""
    before_versions, after_versions = {}, {}
    for event in spec["events"]:
        provenance = event.get("provenance") or {}
        case_id = provenance.get("case_id")
        payload = event.get("payload") or {}
        if event.get("kind") != "ip_register_version" or case_id is None:
            continue
        if payload.get("phase") == "before":
            before_versions[case_id] = payload["version"]
        elif payload.get("phase") == "after":
            after_versions[case_id] = payload["version"]
    for case in spec["cases"]:
        case["version_chain"] = {
            "before_sha256": version_sha256(before_versions[case["testcase_id"]]),
            "after_sha256": version_sha256(after_versions[case["testcase_id"]]),
        }


def _bundle_id(root: Path) -> str:
    return sha256((Path(root) / "bundle.json").read_bytes()).hexdigest()


def _write(root, spec, *, base, fresh_of=None, normalized=(),
           reseal=True) -> Path:
    """Publish through ``write_bundle`` (writer -> verifier path)."""
    base = Path(base)
    plan = GenericExecutionPlan.freeze(spec["plan_document"])
    if not reseal:
        spec = deepcopy(spec)
        _refresh_version_chains(spec)
    components = [
        VerifiedComponent(document["instance_id"], document["source_sha256"],
                          document["profile_sha256"],
                          document["artifact_sha256"],
                          document["semantic_contract_sha256"],
                          canonical_json_bytes(document))
        for document in spec["components"]]
    selections = [AdapterSelection(**document)
                  for document in spec["selections"]]
    source_pairs = []
    for repository_path, archive_path in spec["archive_map"]:
        target = base / repository_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(spec["files"][archive_path])
        source_pairs.append((repository_path, archive_path))
    generated = {}
    for instance_id, names in GENERATED_FILES.items():
        generated[instance_id] = {}
        for name in names:
            path = base / "generated-out" / instance_id / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(spec["files"][f"generated/{instance_id}/{name}"])
            generated[instance_id][name] = path
    cases = []
    for case in deepcopy(spec["cases"]):
        cases.append({name: case[name] for name in case})
    write_bundle(
        Path(root),
        producer=spec["manifest"]["producer"],
        preparation=spec["manifest"]["preparation"],
        input_digests=spec["manifest"]["input_digests"],
        plan=plan,
        components=components,
        selections=selections,
        source_files=source_pairs,
        generated=generated,
        cases=cases,
        evidence=spec["evidence"],
        events=deepcopy(spec["events"]),
        processes=deepcopy(spec["processes"]),
        prefix=deepcopy(spec["prefix"]),
        execution_audit=deepcopy(spec["audit"]),
        exit_status=spec["manifest"]["exit_status"],
        fresh_of=fresh_of,
        normalized_identity_fields=normalized,
        base_dir=base,
    )
    return Path(root)


def _expect_refusal(bundle, *, fresh=None, code, pointer=None):
    with pytest.raises(SavedBundleRefused) as caught:
        verify_saved_bundle(bundle, fresh_bundle_dir=fresh)
    error = caught.value
    assert error.code == code, error.document()
    if pointer is not None:
        assert error.pointer == pointer, error.document()
    assert error.checks, "a refusal must retain the checks completed so far"
    return error


# ---------------------------------------------------------------------------
# baseline: written and hand-built bundles verify
# ---------------------------------------------------------------------------
def test_written_bundle_verifies_without_touching_the_repository(tmp_path):
    spec = build_spec()
    bundle = _write(tmp_path / "written", spec, base=tmp_path / "repo")
    report = verify_saved_bundle(bundle)
    assert report["schema_version"] == "generic_runtime_saved_verification.v1"
    assert report["verdict"] == "verified"
    assert report["case_count"] == 3
    assert report["tampered_refusals"] == []
    assert report["fresh_verified"] is False
    assert report["plan_identity_sha256"] == sha256(
        (bundle / "plan.json").read_bytes()).hexdigest()
    assert report["source_closure_sha256"] == spec["closure"]
    assert report["execution_identity"] == EXECUTION
    assert set(report["processes"]) == {"processor", "peripheral"}
    names = {row["name"] for row in report["checks"]}
    for required in ("manifest-canonical-and-closed", "files-closed-and-hashed",
                     "plan-canonical-and-identified", "case-order-plan-join-and-receipts",
                     "evidence-joins-and-derived-status", "source-closure-recomputed-from-archive",
                     "exit-status-consistency"):
        assert required in names, required
    assert report["limitations"]
    # The verifier reads archived bytes only: a copy outside the workspace
    # still verifies even though no repository or live object exists there.
    copied = tmp_path / "elsewhere" / "copy"
    _copy_tree(bundle, copied)
    assert verify_saved_bundle(copied)["verdict"] == "verified"


def test_repository_changes_cannot_change_the_saved_verdict(tmp_path):
    spec = build_spec()
    base = tmp_path / "repo"
    bundle = _write(tmp_path / "bundle", spec, base=base)
    # The mutable tree moves on; the archived copies stay authoritative.
    (base / "configs/peripherals/generic-timer/component_profile.json"
     ).write_bytes(b'{"profile":"changed-in-the-mutable-tree"}\n')
    assert verify_saved_bundle(bundle)["verdict"] == "verified"
    archived = (bundle / "archive/configs/peripherals/generic-timer/"
                         "component_profile.json")
    archived.write_bytes(b'{"profile":"changed-archived-copy"}\n')
    _expect_refusal(bundle, code="saved-bundle-hash-mismatch")


def test_hand_built_bundle_is_verified_on_its_own_merits(tmp_path):
    spec = build_spec()
    bundle = materialize(tmp_path / "hand" / "bundle", spec)
    report = verify_saved_bundle(bundle)
    assert report["verdict"] == "verified"
    assert report["case_count"] == 3
    # No writer, no GenericExecutionPlan instance and no live handle existed;
    # the archived plan bytes alone reproduce the identity.
    assert report["plan_identity_sha256"] == sha256(
        (bundle / "plan.json").read_bytes()).hexdigest()


def test_read_flow_bundle_with_zero_returns_verifies(tmp_path):
    spec = build_spec(flow=READ_FLOW, values=(0, 0, 0))
    bundle = materialize(tmp_path / "read", spec)
    assert verify_saved_bundle(bundle)["verdict"] == "verified"


def test_manifest_reports_exit_status_and_case_count(tmp_path):
    spec = build_spec()
    spec["manifest"]["exit_status"] = "faulted"
    spec["audit"]["closed"] = False
    bundle = materialize(tmp_path / "faulted", spec)
    report = verify_saved_bundle(bundle)
    # An incomplete but intact run is auditable, never labelled "verified".
    assert report["verdict"] == "integrity_verified_incomplete_run"
    assert report["exit_status"] == "faulted"


# ---------------------------------------------------------------------------
# tamper class: plan bytes / identity
# ---------------------------------------------------------------------------
def test_plan_identity_tamper_is_refused(tmp_path):
    spec = build_spec()
    bundle = materialize(tmp_path / "bundle", spec,
                         plan_identity=_digest("other-plan"))
    _expect_refusal(bundle, code="saved-plan-identity-mismatch",
                    pointer="/bundle.json/plan")


def test_non_canonical_plan_bytes_are_refused(tmp_path):
    spec = build_spec()
    pretty = json.dumps(spec["plan_document"], indent=2).encode()
    bundle = materialize(tmp_path / "bundle", spec, plan_bytes=pretty)
    _expect_refusal(bundle, code="saved-plan-not-canonical",
                    pointer="/plan.json")


def test_plan_path_tamper_breaks_the_case_join(tmp_path):
    spec = build_spec()

    def tamper(spec):
        spec["plan_document"]["paths"][0]["path_id"] = "path-other"

    tamper(spec)
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-case-plan-join",
                    pointer="/cases.json/cases/0/path_id")


def test_plan_component_digest_tamper_is_refused(tmp_path):
    spec = build_spec()
    spec["plan_document"]["components"][1]["artifact_sha256"] = _digest("x")
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-component-mismatch",
                    pointer="/plan.json/components")


def test_plan_input_digest_tamper_is_refused(tmp_path):
    spec = build_spec()
    spec["plan_document"]["input_digests"]["d3"] = _digest("other-d3")
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-input-digest-mismatch",
                    pointer="/plan.json/input_digests")


def test_resealed_plan_content_change_still_verifies(tmp_path):
    # Honest limitation: purely free plan content is not independently anchored.
    spec = build_spec()
    spec["plan_document"]["memory"]["model"] = "per-case"
    bundle = materialize(tmp_path / "bundle", spec)
    assert verify_saved_bundle(bundle)["verdict"] == "verified"


def test_manifest_d2_d3_tamper_is_refused(tmp_path):
    spec = build_spec()
    spec["manifest"]["input_digests"]["d2"] = _digest("other-d2")
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-input-digest-mismatch",
                    pointer="/inputs.json/input_digests")


def test_plan_missing_field_is_refused(tmp_path):
    spec = build_spec()
    spec["plan_document"].pop("memory")
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-plan-invalid", pointer="/plan.json")


def test_preparation_mismatch_is_refused(tmp_path):
    spec = build_spec()
    spec["manifest"]["preparation"]["compose"] = "configs/other/compose.json"
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-preparation-mismatch",
                    pointer="/inputs.json")


def test_absolute_archive_path_is_refused(tmp_path):
    spec = build_spec()
    bundle = materialize(tmp_path / "bundle", spec)

    def mutate(manifest):
        manifest["files"][0]["path"] = "/etc/passwd"

    _rewrite_manifest(bundle, mutate)
    _expect_refusal(bundle, code="saved-bundle-manifest")


def test_exit_status_contradiction_is_refused(tmp_path):
    spec = build_spec()
    spec["audit"]["closed"] = False
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-exit-status-mismatch",
                    pointer="/execution_audit.json/closed")


def test_case_plan_digest_tamper_is_refused(tmp_path):
    spec = build_spec()
    bundle = materialize(tmp_path / "bundle", spec)
    documents = json.loads((bundle / "cases.json").read_text())
    documents["plan_sha256"] = _digest("other-plan")
    _rewrite_document(bundle, "cases.json", documents)
    _expect_refusal(bundle, code="saved-case-plan-join",
                    pointer="/cases.json/plan_sha256")


def test_evidence_shape_tamper_is_refused(tmp_path):
    spec = build_spec()
    bundle = materialize(tmp_path / "bundle", spec)
    document = json.loads((bundle / "evidence.json").read_text())
    document["cases"][0]["evidence"][0].pop("obligation_results")
    _rewrite_document(bundle, "evidence.json", document)
    _expect_refusal(bundle, code="saved-evidence-shape",
                    pointer="/evidence.json/cases/0/evidence/0/"
                            "obligation_results")


def test_event_severed_from_its_case_is_contradicted(tmp_path):
    spec = build_spec()
    bundle = materialize(tmp_path / "bundle", spec)
    events = json.loads((bundle / "events.json").read_text())
    events[1]["provenance"].pop("case_id")
    _rewrite_document(bundle, "events.json", events)
    _expect_refusal(bundle, code="saved-evidence-contradicted",
                    pointer="/evidence.json/cases/0/evidence/0/source_refs/0")


def test_event_without_provenance_is_refused(tmp_path):
    spec = build_spec()
    bundle = materialize(tmp_path / "bundle", spec)
    events = json.loads((bundle / "events.json").read_text())
    events[0].pop("provenance")
    _rewrite_document(bundle, "events.json", events)
    _expect_refusal(bundle, code="saved-event-shape",
                    pointer="/events.json/0/provenance")


# ---------------------------------------------------------------------------
# tamper class: archived bytes, archive set, symlinks
# ---------------------------------------------------------------------------
def test_archived_byte_change_is_refused(tmp_path):
    spec = build_spec()
    bundle = materialize(tmp_path / "bundle", spec)
    target = bundle / "cases.json"
    target.write_bytes(target.read_bytes() + b" ")
    _expect_refusal(bundle, code="saved-bundle-hash-mismatch")


def test_missing_archive_file_is_refused(tmp_path):
    spec = build_spec()
    bundle = materialize(tmp_path / "bundle", spec)
    (bundle / "archive/configs/peripherals/generic-timer/"
              "component_profile.json").unlink()
    _expect_refusal(bundle, code="saved-bundle-missing-file")


def test_extra_archived_file_is_refused(tmp_path):
    spec = build_spec()
    bundle = materialize(tmp_path / "bundle", spec)
    (bundle / "archive/unexpected.json").write_bytes(b"{}\n")
    _expect_refusal(bundle, code="saved-bundle-extra-file")


def test_symlinked_archive_file_is_refused(tmp_path):
    spec = build_spec()
    bundle = materialize(tmp_path / "bundle", spec)
    target = bundle / "archive/src/myfuzz/integration/generated_storage_consumer.py"
    payload = target.read_bytes()
    side = tmp_path / "side.py"
    side.write_bytes(payload)
    target.unlink()
    target.symlink_to(side)
    _expect_refusal(bundle, code="saved-bundle-symlink")


# ---------------------------------------------------------------------------
# tamper class: source closure / contract bytes
# ---------------------------------------------------------------------------
def test_source_closure_byte_tamper_is_refused(tmp_path):
    spec = build_spec()
    archive_path = ("archive/configs/peripherals/generic-timer/"
                    "component_profile.json")
    spec["files"][archive_path] = b'{"profile":"generic-timer","tampered":1}\n'
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-source-closure-mismatch")


def test_source_closure_digest_tamper_is_refused(tmp_path):
    spec = build_spec()
    spec["sources"]["source_closure_sha256"] = _digest("other-closure")
    spec["manifest"]["source_closure_sha256"] = _digest("other-closure")
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-source-closure-mismatch",
                    pointer="/sources.json/source_closure_sha256")


def test_plan_closure_evidence_tamper_is_refused(tmp_path):
    spec = build_spec()
    spec["plan_document"]["sources"][0]["source_closure_sha256"] = _digest(
        "other-closure")
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-source-closure-mismatch",
                    pointer="/plan.json/sources")


# ---------------------------------------------------------------------------
# tamper class: components / selections
# ---------------------------------------------------------------------------
def test_component_descriptor_tamper_is_refused(tmp_path):
    spec = build_spec()
    spec["components"][1]["source_verifier"]["version"] = ""
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-component-mismatch")


def test_component_instance_rename_is_refused(tmp_path):
    spec = build_spec()
    spec["components"][0]["instance_id"] = "processor-renamed"
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-component-mismatch",
                    pointer="/plan.json/components")


def test_selection_semantic_tamper_is_refused(tmp_path):
    spec = build_spec()
    spec["selections"][1]["semantic_contract_sha256"] = _digest("other")
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-selection-mismatch")


# ---------------------------------------------------------------------------
# tamper class: cases, records, receipts
# ---------------------------------------------------------------------------
def test_duplicate_case_index_is_refused(tmp_path):
    spec = build_spec()
    spec["cases"][2]["index"] = 1
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-case-order",
                    pointer="/cases.json/cases/2/index")


def test_truncated_raw_record_is_refused(tmp_path):
    spec = build_spec()
    spec["cases"][1]["raw_records_hex"] = ["000022"]
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-case-records",
                    pointer="/cases.json/cases/1/raw_records_hex")


def test_case_count_tamper_is_refused(tmp_path):
    spec = build_spec()
    spec["cases"] = spec["cases"][:2]
    spec["evidence"] = spec["evidence"][:2]
    spec["manifest"]["case_count"] = 3
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-case-count-mismatch",
                    pointer="/bundle.json/case_count")


def test_receipt_digest_tamper_is_refused(tmp_path):
    spec = build_spec()
    bundle = materialize(tmp_path / "sealed", spec)
    # Keep the archived receipt but change the certificate it seals.
    documents = json.loads((bundle / "cases.json").read_text())
    documents["cases"][1]["certificate"]["commit"]["after"] = 0x99
    _rewrite_document(bundle, "cases.json", documents)
    _expect_refusal(bundle, code="saved-receipt-mismatch",
                    pointer="/cases.json/cases/1/receipt_sha256")


# ---------------------------------------------------------------------------
# tamper class: read return value / write data
# ---------------------------------------------------------------------------
def test_read_return_value_tamper_is_refused(tmp_path):
    spec = build_spec(flow=READ_FLOW, values=(0, 0, 0))
    spec["events"][5]["payload"]["data"] = 0x5A
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-read-return-mismatch",
                    pointer="/cases.json/cases/1")


def test_read_return_version_tamper_is_refused(tmp_path):
    spec = build_spec(flow=READ_FLOW, values=(0, 0, 0))
    spec["events"][6]["payload"]["rdata"] = 0x5A
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-read-return-mismatch")


def test_write_data_tamper_is_refused(tmp_path):
    spec = build_spec()
    spec["events"][2]["payload"]["wdata"] = 0x77
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-write-data-mismatch",
                    pointer="/cases.json/cases/0")


def test_write_count_that_does_not_advance_is_refused(tmp_path):
    spec = build_spec()
    spec["events"][3]["payload"]["version"]["write_count"] = spec["events"][0][
        "payload"]["version"]["write_count"]
    bundle = materialize(tmp_path / "bundle", spec, refresh_chains=True)
    _expect_refusal(bundle, code="saved-counter-conflict",
                    pointer="/cases.json/cases/0/version_chain")


# ---------------------------------------------------------------------------
# tamper class: byte version / version chain
# ---------------------------------------------------------------------------
def test_version_document_byte_tamper_is_refused(tmp_path):
    spec = build_spec()
    spec["events"][7]["payload"]["version"]["value"] += 1
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-version-chain-break",
                    pointer="/cases.json/cases/1/version_chain/after_sha256")


def test_version_chain_continuity_break_is_refused(tmp_path):
    spec = build_spec()
    # Case 1's archived before-state no longer matches case 0's after-state,
    # while every stored digest is re-sealed consistently.
    spec["events"][4]["payload"]["version"]["value"] = 0x99
    bundle = materialize(tmp_path / "bundle", spec, refresh_chains=True)
    _expect_refusal(bundle, code="saved-version-chain-break",
                    pointer="/cases.json/cases/1/version_chain/before_sha256")


def test_vanished_before_version_event_is_refused(tmp_path):
    spec = build_spec()
    # Drop the "before" phase marker of case 1 by relabelling it.
    spec["events"][4]["payload"]["phase"] = "after"
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-version-chain-break")


def test_reset_epoch_change_between_cases_is_refused(tmp_path):
    spec = build_spec()
    # Case 2 was replayed after a reset: version and key epoch agree with each
    # other, so only the cross-case reset ordering is wrong.
    for event in spec["events"][8:]:
        if "version" in event["payload"]:
            event["payload"]["version"]["reset_epoch"] = 2
        if event["kind"] == "cpu_source_accept":
            event["provenance"]["transaction"]["source_epoch"] = 2
    spec["evidence"][2] = [_rekey(document, epoch=2)
                           for document in spec["evidence"][2]]
    bundle = materialize(tmp_path / "bundle", spec, refresh_chains=True)
    _expect_refusal(bundle, code="saved-reset-order-change",
                    pointer="/cases.json/cases/2/version_chain")


# ---------------------------------------------------------------------------
# tamper class: raw event refs
# ---------------------------------------------------------------------------
def test_missing_event_ref_is_refused(tmp_path):
    spec = build_spec()
    spec["evidence"][1] = [_replace_refs(spec["evidence"][1][0],
                                         source_event=999)]
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-evidence-ref-missing",
                    pointer="/evidence.json/cases/1/evidence/0/source_refs/0")


def test_event_ref_to_another_case_is_refused(tmp_path):
    spec = build_spec()
    spec["evidence"][1] = [_replace_refs(spec["evidence"][1][0],
                                         source_event=1)]
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-evidence-contradicted",
                    pointer="/evidence.json/cases/1/evidence/0/source_refs/0")


def test_evidence_document_reused_across_cases_is_refused(tmp_path):
    spec = build_spec()
    spec["evidence"][2] = list(spec["evidence"][0])
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-evidence-reuse",
                    pointer="/evidence.json/cases/2/evidence/0")


def test_event_reused_by_two_evidence_documents_is_refused(tmp_path):
    spec = build_spec()
    first = spec["evidence"][0][0]
    spec["evidence"][0] = [first, _rebind(first, binding=_digest("second"))]
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-evidence-reuse",
                    pointer="/evidence.json/cases/0/evidence/1/source_refs/0")


# ---------------------------------------------------------------------------
# tamper class: counter / event id
# ---------------------------------------------------------------------------
def test_duplicate_event_id_is_refused(tmp_path):
    spec = build_spec()
    spec["events"][3]["event_id"] = 2
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-counter-conflict",
                    pointer="/events.json/3/event_id")


def test_event_id_gap_is_refused(tmp_path):
    spec = build_spec()
    spec["events"][3]["event_id"] = 9
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-event-sequence",
                    pointer="/events.json/3/event_id")


def test_command_sequence_does_not_advance_is_refused(tmp_path):
    spec = build_spec()
    spec["events"][3]["payload"]["version"]["command_sequence"] = spec[
        "events"][0]["payload"]["version"]["command_sequence"]
    bundle = materialize(tmp_path / "bundle", spec, refresh_chains=True)
    _expect_refusal(bundle, code="saved-counter-conflict")


def test_source_sequence_reuse_is_refused(tmp_path):
    spec = build_spec()
    _set_case_sequence(spec, 2, 0)
    _set_case_sequence(spec, 1, 0)
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-counter-conflict",
                    pointer="/evidence.json/cases/1/evidence/0/key")


# ---------------------------------------------------------------------------
# tamper class: native nonce / pid and build identity
# ---------------------------------------------------------------------------
def test_per_case_pid_change_is_refused(tmp_path):
    spec = build_spec()
    spec["events"][6]["provenance"]["process"]["pid"] = 41999
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-process-identity-change")


def test_process_record_pid_tamper_is_refused(tmp_path):
    spec = build_spec()
    spec["processes"]["sessions"]["peripheral"]["pid"] = 41999
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-process-identity-change")


def test_native_event_without_process_identity_is_refused(tmp_path):
    spec = build_spec()
    spec["events"][2]["provenance"].pop("process")
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-process-identity-change")


def test_build_identity_tamper_is_refused(tmp_path):
    spec = build_spec()
    spec["processes"]["build_sha256"] = _digest("other-build")
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-process-identity-change")


# ---------------------------------------------------------------------------
# tamper class: evidence status derivation
# ---------------------------------------------------------------------------
def test_status_downgrade_is_refused(tmp_path):
    spec = build_spec()
    spec["evidence"][1] = [_restatus(spec["evidence"][1][0], "missing")]
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-evidence-status-mismatch",
                    pointer="/evidence.json/cases/1/evidence/0/status")


def test_unsupported_status_is_never_upgraded(tmp_path):
    spec = build_spec()
    spec["evidence"][0] = [_restatus(spec["evidence"][0][0], "unsupported")]
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-evidence-unsupported",
                    pointer="/cases.json/cases/0")


def test_semantic_contract_not_admitted_is_refused(tmp_path):
    spec = build_spec()
    spec["evidence"][0] = [_rebind(spec["evidence"][0][0], semantic=_digest("x"))]
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-evidence-contradicted",
                    pointer="/evidence.json/cases/0/evidence/0/"
                            "semantic_contract_sha256")


# ---------------------------------------------------------------------------
# tamper class: effect values
# ---------------------------------------------------------------------------
def test_repeated_effect_value_is_refused(tmp_path):
    spec = build_spec(values=(0x11, 0x11))
    bundle = materialize(tmp_path / "bundle", spec, refresh_chains=True)
    _expect_refusal(bundle, code="saved-case-values",
                    pointer="/cases.json/cases")
    # A repeated equal write is legal when another case carries a real change.
    spec = build_spec(values=(0x11, 0x11, 0x22))
    control = materialize(tmp_path / "control", spec, refresh_chains=True)
    assert verify_saved_bundle(control)["verdict"] == "verified"


def test_zero_only_effect_values_are_refused(tmp_path):
    spec = build_spec(values=(0, 0))
    bundle = materialize(tmp_path / "bundle", spec, refresh_chains=True)
    _expect_refusal(bundle, code="saved-case-values",
                    pointer="/cases.json/cases")


def test_single_effect_bundle_cannot_show_distinct_values(tmp_path):
    spec = build_spec(values=(0x11,))
    bundle = materialize(tmp_path / "bundle", spec, refresh_chains=True)
    _expect_refusal(bundle, code="saved-case-values",
                    pointer="/cases.json/cases")


# ---------------------------------------------------------------------------
# normalization declarations
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("field", (
    "cases/0/raw_records_hex",
    "events/3/payload/version/value",
    "sources/files/0/sha256",
    "cases/1/version_chain/reset_epoch",
    "evidence/cases/0/evidence/0/status",
    "processes/processor/unknown",
))
def test_illegal_normalization_field_is_refused(tmp_path, field):
    spec = build_spec()
    spec["manifest"]["normalized_identity_fields"] = [field]
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-normalization-refused",
                    pointer="/bundle.json/normalized_identity_fields/0")


def test_normalization_field_must_resolve(tmp_path):
    spec = build_spec()
    spec["manifest"]["normalized_identity_fields"] = ["processes/absent/pid"]
    bundle = materialize(tmp_path / "bundle", spec)
    _expect_refusal(bundle, code="saved-normalization-refused",
                    pointer="/bundle.json/normalized_identity_fields/0")


# ---------------------------------------------------------------------------
# fresh comparison
# ---------------------------------------------------------------------------
def _fresh_pair(tmp_path, *, fresh_overrides=None, fresh_tamper=None,
                original_fields=IDENTITY_FIELDS,
                fresh_fields=IDENTITY_FIELDS, use_writer=False):
    original_spec = build_spec()
    original_spec["manifest"]["normalized_identity_fields"] = list(
        original_fields)
    if use_writer:
        original = _write(tmp_path / "original", original_spec,
                          base=tmp_path / "repo",
                          normalized=original_fields)
    else:
        original = materialize(tmp_path / "original", original_spec)
    overrides = {"pid_cpu": 42001, "pid_ip": 42002,
                 "nonce_cpu": "cpu-nonce-b", "nonce_ip": "ip-nonce-b"}
    overrides.update(fresh_overrides or {})
    fresh_spec = build_spec(**overrides)
    fresh_spec["manifest"]["normalized_identity_fields"] = list(fresh_fields)
    if fresh_tamper is not None:
        fresh_tamper(fresh_spec)
    if use_writer:
        fresh = _write(tmp_path / "fresh", fresh_spec, base=tmp_path / "repo",
                       fresh_of=_bundle_id(original), normalized=fresh_fields)
    else:
        fresh_spec["manifest"]["fresh_of"] = _bundle_id(original)
        fresh = materialize(tmp_path / "fresh", fresh_spec,
                            refresh_chains=True)
    return original, fresh


def test_fresh_replay_verifies(tmp_path):
    original, fresh = _fresh_pair(tmp_path)
    report = verify_saved_bundle(original, fresh_bundle_dir=fresh)
    assert report["verdict"] == "verified"
    assert report["fresh_verified"] is True
    assert len(report["bundle_ids"]) == 2
    assert report["bundle_ids"][0] != report["bundle_ids"][1]
    assert report["bundle_ids"][1] == _bundle_id(fresh)
    names = {row["name"] for row in report["checks"]}
    for required in ("fresh.plan-identity", "fresh.source-closure",
                     "fresh.process-identity-renewed",
                     "fresh.accepted-case-sequence", "fresh.raw-events",
                     "fresh.evidence"):
        assert required in names, required


def test_fresh_written_pair_verifies(tmp_path):
    original, fresh = _fresh_pair(tmp_path, use_writer=True)
    assert verify_saved_bundle(original, fresh_bundle_dir=fresh)[
        "verdict"] == "verified"


def test_fresh_pid_reuse_is_refused(tmp_path):
    original, fresh = _fresh_pair(
        tmp_path, fresh_overrides={"pid_cpu": 41001})
    _expect_refusal(original, fresh=fresh, code="saved-fresh-identity-reuse",
                    pointer="/processes.json/sessions/processor/pid")


def test_fresh_nonce_reuse_is_refused(tmp_path):
    original, fresh = _fresh_pair(
        tmp_path, fresh_overrides={"nonce_ip": "ip-nonce-a"})
    _expect_refusal(original, fresh=fresh, code="saved-fresh-identity-reuse",
                    pointer="/processes.json/sessions/peripheral/nonce")


def test_fresh_of_pointer_mismatch_is_refused(tmp_path):
    original, fresh = _fresh_pair(tmp_path)

    def retarget(spec):
        spec["manifest"]["fresh_of"] = _digest("some-other-bundle")

    materialize(tmp_path / "fresh2", _retampered(fresh, original, retarget),
                refresh_chains=True)
    _expect_refusal(original, fresh=tmp_path / "fresh2",
                    code="saved-fresh-link-mismatch",
                    pointer="/bundle.json/fresh_of")


def test_fresh_plan_difference_is_refused(tmp_path):
    original, fresh = _fresh_pair(tmp_path)

    def tamper(spec):
        spec["plan_document"]["scheduling"]["rounds_per_case"] = 16

    materialize(tmp_path / "fresh2", _retampered(fresh, original, tamper),
                refresh_chains=True)
    _expect_refusal(original, fresh=tmp_path / "fresh2",
                    code="saved-fresh-plan-mismatch")


def test_fresh_source_set_difference_is_refused(tmp_path):
    original, fresh = _fresh_pair(tmp_path)

    def tamper(spec):
        spec["sources"]["files"][0]["path"] = "configs/other/compose.json"

    materialize(tmp_path / "fresh2", _retampered(fresh, original, tamper),
                refresh_chains=True)
    _expect_refusal(original, fresh=tmp_path / "fresh2",
                    code="saved-fresh-source-mismatch",
                    pointer="/sources.json")


def test_fresh_payload_change_is_not_normalized_away(tmp_path):
    original, fresh = _fresh_pair(tmp_path)

    def tamper(spec):
        spec["events"][1]["tick"] = 987654

    materialize(tmp_path / "fresh2", _retampered(fresh, original, tamper),
                refresh_chains=True)
    _expect_refusal(original, fresh=tmp_path / "fresh2",
                    code="saved-fresh-event-mismatch",
                    pointer="/events.json")


def test_fresh_evidence_difference_is_refused(tmp_path):
    original, fresh = _fresh_pair(tmp_path)

    def tamper(spec):
        for index, documents in enumerate(spec["evidence"]):
            spec["evidence"][index] = [
                _rebind(document, binding=_digest("other-binding"))
                for document in documents]

    materialize(tmp_path / "fresh2", _retampered(fresh, original, tamper),
                refresh_chains=True)
    _expect_refusal(original, fresh=tmp_path / "fresh2",
                    code="saved-fresh-evidence-mismatch",
                    pointer="/evidence.json")


def test_fresh_missing_event_is_refused(tmp_path):
    original, fresh = _fresh_pair(tmp_path)

    def tamper(spec):
        del spec["events"][2]
        for position, event in enumerate(spec["events"]):
            event["event_id"] = position

    materialize(tmp_path / "fresh2", _retampered(fresh, original, tamper),
                refresh_chains=True)
    _expect_refusal(original, fresh=tmp_path / "fresh2",
                    code="saved-fresh-bundle-refused")


def test_fresh_declared_normalization_set_must_match(tmp_path):
    original, fresh = _fresh_pair(
        tmp_path, fresh_fields=IDENTITY_FIELDS[:2])
    _expect_refusal(original, fresh=fresh,
                    code="saved-fresh-normalization-mismatch",
                    pointer="/bundle.json/normalized_identity_fields")


def test_fresh_illegal_normalization_is_refused(tmp_path):
    original, fresh = _fresh_pair(
        tmp_path, fresh_fields=IDENTITY_FIELDS + ("events/0/payload/tick",))
    _expect_refusal(original, fresh=fresh,
                    code="saved-fresh-bundle-refused")


def test_identity_normalization_only_touches_declared_fields():
    from myfuzz.runtime.evidence.saved import normalize_identity

    rules = (("pid", 41001, "<normalized:pid>"),)
    document = {"pid": 41001, "payload": {"pid": 41001, "text": "41001"},
                "nested": [{"pid": 41001, "note": "keep"}]}
    normalized = normalize_identity(document, rules)
    assert normalized["pid"] == "<normalized:pid>"
    # A payload member named pid is identity too; payload *bytes* stay intact.
    assert normalized["payload"]["pid"] == "<normalized:pid>"
    assert normalized["payload"]["text"] == "41001"
    assert normalized["nested"][0]["note"] == "keep"
    assert document["pid"] == 41001


def test_fresh_instruction_digest_difference_is_refused(tmp_path):
    original, fresh = _fresh_pair(tmp_path)

    def tamper(spec):
        spec["cases"][1]["instruction_sha256"] = _digest("other-instruction")

    materialize(tmp_path / "fresh2", _retampered(fresh, original, tamper),
                refresh_chains=True)
    _expect_refusal(original, fresh=tmp_path / "fresh2",
                    code="saved-fresh-case-mismatch",
                    pointer="/cases.json/cases/1/instruction_sha256")


def test_fresh_component_difference_is_refused(tmp_path):
    original, fresh = _fresh_pair(tmp_path)

    def tamper(spec):
        spec["components"][1]["endpoints"][0]["data_width"] = 64

    materialize(tmp_path / "fresh2", _retampered(fresh, original, tamper),
                refresh_chains=True)
    _expect_refusal(original, fresh=tmp_path / "fresh2",
                    code="saved-fresh-components-mismatch",
                    pointer="/components.json")


def test_fresh_build_identity_difference_is_refused(tmp_path):
    original, fresh = _fresh_pair(tmp_path)

    def tamper(spec):
        other = _digest("other-build")
        spec["processes"]["build_sha256"] = other
        for event in spec["events"]:
            payload = event.get("payload") or {}
            if "build_sha256" in payload:
                payload["build_sha256"] = other

    materialize(tmp_path / "fresh2", _retampered(fresh, original, tamper),
                refresh_chains=True)
    _expect_refusal(original, fresh=tmp_path / "fresh2",
                    code="saved-fresh-build-mismatch",
                    pointer="/processes.json")


# ---------------------------------------------------------------------------
# writer refusals
# ---------------------------------------------------------------------------
def test_writer_refuses_to_overwrite_a_non_empty_bundle(tmp_path):
    spec = build_spec()
    bundle = _write(tmp_path / "bundle", spec, base=tmp_path / "repo")
    with pytest.raises(SavedBundleRefused) as caught:
        _write(bundle, build_spec(), base=tmp_path / "repo" / "other")
    assert caught.value.code == "saved-bundle-exists"
    # The original bytes were not touched.
    assert verify_saved_bundle(bundle)["verdict"] == "verified"


def test_writer_refuses_to_publish_an_inconsistent_bundle(tmp_path):
    spec = build_spec()
    spec["evidence"][1] = [_replace_refs(spec["evidence"][1][0],
                                         source_event=777)]
    with pytest.raises(SavedBundleRefused) as caught:
        _write(tmp_path / "bundle", spec, base=tmp_path / "repo")
    assert caught.value.code == "saved-evidence-ref-missing"
    assert not (tmp_path / "bundle").exists()
    assert not [path for path in (tmp_path).iterdir()
                if path.name.startswith(".bundle.tmp-")]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cli(*arguments):
    environment = dict(os.environ)
    environment["PYTHONPATH"] = "src:."
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run([sys.executable, str(SCRIPT), *map(str, arguments)],
                          cwd=str(ROOT), capture_output=True, text=True,
                          env=environment, timeout=300)


def test_cli_help_exits_zero():
    result = _cli("--help")
    assert result.returncode == 0, result.stderr
    assert "--fresh-bundle" in result.stdout


def test_cli_success_writes_report(tmp_path):
    spec = build_spec()
    bundle = _write(tmp_path / "bundle", spec, base=tmp_path / "repo")
    output = tmp_path / "report.json"
    result = _cli("--bundle", bundle, "--output", output)
    assert result.returncode == 0, result.stderr
    report = json.loads(output.read_text())
    assert report["verdict"] == "verified"
    assert report["schema_version"] == "generic_runtime_saved_verification.v1"
    assert report["scope"]["bundle"] == str(bundle)
    assert report["tampered_refusals"] == []
    assert report["checks"]


def test_cli_success_with_fresh_bundle(tmp_path):
    original, fresh = _fresh_pair(tmp_path)
    output = tmp_path / "report.json"
    result = _cli("--bundle", original, "--fresh-bundle", fresh,
                  "--output", output)
    assert result.returncode == 0, result.stderr
    report = json.loads(output.read_text())
    assert report["fresh_verified"] is True
    assert report["verdict"] == "verified"


def test_cli_missing_bundle_refuses_and_writes_json(tmp_path):
    output = tmp_path / "refusal.json"
    result = _cli("--bundle", tmp_path / "absent", "--output", output)
    assert result.returncode == 2, result.stdout + result.stderr
    refusal = json.loads(output.read_text())
    assert refusal["verdict"] == "refused"
    assert refusal["refusal"]["code"] == "saved-bundle-missing"
    assert refusal["tampered_refusals"]


def test_cli_tampered_bundle_refuses_with_specific_code(tmp_path):
    spec = build_spec()
    bundle = materialize(tmp_path / "bundle", spec)
    (bundle / "events.json").write_bytes(b"[]")
    output = tmp_path / "refusal.json"
    result = _cli("--bundle", bundle, "--output", output)
    assert result.returncode == 2, result.stdout + result.stderr
    refusal = json.loads(output.read_text())
    assert refusal["refusal"]["code"] == "saved-bundle-hash-mismatch"


# ---------------------------------------------------------------------------
# small document helpers
# ---------------------------------------------------------------------------
def _copy_tree(source: Path, target: Path) -> Path:
    import shutil
    shutil.copytree(source, target)
    return Path(target)


def _replace_refs(document, *, source_event=None, native_event=None,
                  before_event=None, after_event=None):
    source = document.source_refs
    if source_event is not None:
        source = (EvidenceRef(source[0].component, source_event,
                              source[0].kind),)
    native = document.native_refs
    if native_event is not None:
        native = (EvidenceRef(native[0].component, native_event,
                              native[0].kind),)
    destination = document.destination_refs
    if before_event is not None:
        destination = (EvidenceRef(destination[0].component, before_event,
                                   destination[0].kind), destination[1])
    if after_event is not None:
        destination = (destination[0],
                       EvidenceRef(destination[1].component, after_event,
                                   destination[1].kind))
    return EffectEvidence(document.key, document.status, document.scope,
                          document.binding_sha256,
                          document.semantic_contract_sha256, source, native,
                          destination, document.obligation_results)


def _restatus(document, status):
    obligations = document.obligation_results
    if status == "certified":
        obligations = tuple((name, "certified") for name, _ in obligations)
    return EffectEvidence(document.key, status, document.scope,
                          document.binding_sha256,
                          document.semantic_contract_sha256,
                          document.source_refs, document.native_refs,
                          document.destination_refs, obligations)


def _rebind(document, *, binding=None, semantic=None):
    return EffectEvidence(document.key, document.status, document.scope,
                          binding or document.binding_sha256,
                          semantic or document.semantic_contract_sha256,
                          document.source_refs, document.native_refs,
                          document.destination_refs,
                          document.obligation_results)


def _retampered(fresh_root: Path, original: Path, tamper):
    """Rebuild a fresh spec from the saved fresh directory plus one tamper."""
    spec = build_spec(pid_cpu=42001, pid_ip=42002, nonce_cpu="cpu-nonce-b",
                      nonce_ip="ip-nonce-b")
    spec["manifest"]["normalized_identity_fields"] = list(IDENTITY_FIELDS)
    spec["manifest"]["fresh_of"] = _bundle_id(original)
    spec["plan_document"] = json.loads((fresh_root / "plan.json").read_text())
    spec["evidence"] = _evidence_from_documents(fresh_root)
    spec["events"] = json.loads((fresh_root / "events.json").read_text())
    spec["processes"] = json.loads((fresh_root / "processes.json").read_text())
    spec["sources"] = json.loads((fresh_root / "sources.json").read_text())
    spec["inputs"] = json.loads((fresh_root / "inputs.json").read_text())
    tamper(spec)
    return spec


def _evidence_from_documents(root: Path):
    from myfuzz.runtime.evidence.saved import parse_effect_evidence
    document = json.loads((root / "evidence.json").read_text())
    return [[parse_effect_evidence(entry)
             for entry in case["evidence"]]
            for case in document["cases"]]

def _rewrite_document(root: Path, name: str, document) -> None:
    """Change one saved document and re-seal only its manifest hash."""
    root = Path(root)
    payload = canonical_json_bytes(document)
    (root / name).write_bytes(payload)
    manifest = json.loads((root / "bundle.json").read_text())
    for row in manifest["files"]:
        if row["path"] == name:
            row["sha256"] = sha256(payload).hexdigest()
    (root / "bundle.json").write_bytes(canonical_json_bytes(manifest))


def _rekey(document, *, epoch):
    return EffectEvidence(
        TransactionKey(document.key.execution_id, document.key.testcase_id,
                       document.key.source_component, epoch,
                       document.key.channel_id, document.key.source_sequence),
        document.status, document.scope, document.binding_sha256,
        document.semantic_contract_sha256, document.source_refs,
        document.native_refs, document.destination_refs,
        document.obligation_results)

def _set_case_sequence(spec, case_index, sequence):
    case = spec["cases"][case_index]
    document = spec["evidence"][case_index][0]
    spec["evidence"][case_index] = [
        EffectEvidence(
            TransactionKey(document.key.execution_id,
                           document.key.testcase_id,
                           document.key.source_component,
                           document.key.source_epoch,
                           document.key.channel_id, sequence),
            document.status, document.scope, document.binding_sha256,
            document.semantic_contract_sha256, document.source_refs,
            document.native_refs, document.destination_refs,
            document.obligation_results)]
    for event in spec["events"]:
        if event["provenance"].get("case_id") == case["testcase_id"]:
            event["provenance"]["transaction"]["source_sequence"] = sequence

def _rewrite_manifest(root: Path, mutate) -> None:
    root = Path(root)
    manifest = json.loads((root / "bundle.json").read_text())
    mutate(manifest)
    (root / "bundle.json").write_bytes(canonical_json_bytes(manifest))
