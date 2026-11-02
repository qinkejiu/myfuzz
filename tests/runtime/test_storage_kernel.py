"""G5: the storage flow kernel derives requirements from declared D3 rows.

Everything here is software evidence.  No RTL is built or run, no native
process is started, no token is issued and no effect is certified: the fixtures
are explicit fakes and the certificates below are structural stand-ins whose
references are resolved against a fake raw event log.
"""
from __future__ import annotations

import json
import unittest

from myfuzz.runtime.contracts import GenericExecutionPlan, GenericRuntimeRefused
from myfuzz.runtime.flows.storage import (
    CASE_SEQUENCE_SCHEMA,
    OBLIGATIONS,
    FLOW_EXECUTORS,
    CompiledFlowSpec,
    FlowContext,
    StorageFlowBackend,
    StorageFlowKernel,
    StorageFlowChannel,
    load_case_sequence,
    refuse_mixed_flows,
)
from myfuzz.scenario.f2_read_contract import build_f2_read_contract
from myfuzz.scenario.ledger import TransactionKey

PLAN_SHA = "a" * 64
MIRROR_KEYS = ("source_id", "origin", "kind", "width", "bit_offset", "mask",
               "alignment", "range", "constraint_basis", "register_access")

ACCESS_READ = {
    "schema_version": "register_source_access.v1",
    "source_component": "cpu0", "source_endpoint": "cpu0_data",
    "target_component": "timer0", "target_endpoint": "timer0_apb",
    "device_id": "timer0_dev", "register": "TIMER0_CTRL", "field": "CTRL",
    "register_offset": 0, "address": 0x1000, "window_base": 0x1000,
    "window_size": 0x1000, "window_alignment": 4, "access_alignment": 4,
    "width_bytes": 4, "byte_enable_domain": "target_word_lanes",
    "allowed_byte_enables": [15], "operation": "read",
    "value_origin": "bound_target_rdata",
    "register_origin": "bound_target_register_commit",
    "value_mask": 0xffffffff,
}
ACCESS_WRITE = dict(ACCESS_READ, operation="write",
                    value_origin="cpu_transaction_wdata")


# ---------------------------------------------------------------------------
# declared D3 / plan path fixtures (values only; no component-name behaviour)
# ---------------------------------------------------------------------------

def _image_source(component="cpu0", endpoint="cpu0_instr", port="ram0"):
    return {
        "source_id": f"{component}.image", "origin": "fuzzable",
        "kind": "instruction_image", "component": component,
        "endpoint_id": endpoint, "port": port, "bit_offset": 0, "width": 2048,
        "mask": 0xffffffff, "alignment": 4,
        "range": [0x80000000, 0x800000ff],
        "constraint_basis": "declared read+execute region containing the reset "
                            "vector",
        "origin_ref": "wiring:path_wiring.v1",
    }


def _load_source(component="cpu0", endpoint="cpu0_data"):
    return {
        "source_id": f"timer0.TIMER0_CTRL.CTRL.address", "origin": "fuzzable",
        "kind": "cpu_load_stream", "component": component,
        "endpoint_id": endpoint, "port": None, "bit_offset": 0, "width": 32,
        "register": "TIMER0_CTRL", "field": "CTRL", "mask": 0xffffffff,
        "alignment": 4, "range": [0x1000, 0x1000],
        "register_access": dict(ACCESS_READ),
        "constraint_basis": "the CPU-side load stream is the fuzzable source",
        "origin_ref": "wiring:path_wiring.v1",
    }


def _store_source(component="cpu0", endpoint="cpu0_data"):
    return {
        "source_id": "timer0.TIMER0_CTRL.CTRL.value", "origin": "fuzzable",
        "kind": "cpu_mmio_stream", "component": component,
        "endpoint_id": endpoint, "port": None, "bit_offset": 0, "width": 32,
        "register": "TIMER0_CTRL", "field": "CTRL", "mask": 0xffffffff,
        "alignment": 4, "range": [0x1000, 0x1000],
        "register_access": dict(ACCESS_WRITE),
        "constraint_basis": "the CPU-side store stream is the fuzzable source",
        "origin_ref": "wiring:path_wiring.v1",
    }


def _mirror(row):
    return {name: row[name] for name in MIRROR_KEYS if name in row}


ASSERTIONS = (
    {"expectation_id": "cross_component.declared_edge_hops",
     "assertion_class": "cross_component_provenance_and_order",
     "asserts": "every declared edge hop is observed", "declared_by": "v1"},
    {"expectation_id": "protocol_checker.receipt_violations",
     "assertion_class": "protocol_checker",
     "asserts": "the receipt has no violation", "declared_by": "v1"},
)


CPU_EVIDENCE = ("cross_component_consumption", "cross_component_source",
                "physical_protocol_sample")
TARGET_EVIDENCE = ("component_semantic_effect", "cross_component_consumption",
                   "cross_component_source", "physical_protocol_sample")


def cpu_binding(flow_id="F4", *, operations=("read", "write"),
                required=("write",), obligations=CPU_EVIDENCE,
                instance="cpu0", endpoint="cpu0_data"):
    document = {
        "role": "cpu", "instance_id": instance, "endpoint_id": endpoint,
        "protocol": ["obi", "1"], "template": ["cpu.obi", "1", "read-write"],
        "semantic_kind": "cpu.obi.v1", "operations": list(operations),
        "required_operations": list(required),
        "supported_operations": list(operations),
        "data_width": 32, "address_width": 32, "address_units": "byte",
        "max_outstanding": 1, "completion_kind": "grant_then_response",
        "byte_enable": True,
        "supported_evidence": list(CPU_EVIDENCE),
        "adapter": {"adapter_id": "obi.cpu.v1", "adapter_version": "1",
                    "implementation_sha256": "c" * 64},
        "descriptor_sha256": "d" * 64, "flows": [flow_id],
        "path_ids": [f"{flow_id}:timer0"],
    }
    if obligations is not None:
        document["evidence_obligations"] = list(obligations)
    return document


def target_binding(flow_id="F4", *, required=("write",), semantic="storage.rw.v1",
                   obligations=TARGET_EVIDENCE,
                   template=("target.apb3", "1", "full-word"), instance="timer0",
                   endpoint="timer0_apb"):
    document = {
        "role": "target", "instance_id": instance, "endpoint_id": endpoint,
        "protocol": ["apb", "3"], "template": list(template),
        "semantic_kind": semantic, "operations": ["read", "write"],
        "required_operations": list(required),
        "supported_operations": ["read", "write"],
        "data_width": 32, "address_width": 12, "address_units": "byte",
        "max_outstanding": 1, "completion_kind": "setup_access_response",
        "byte_enable": False,
        "supported_evidence": list(TARGET_EVIDENCE),
        "adapter": {"adapter_id": "apb3.storage.v1", "adapter_version": "1",
                    "implementation_sha256": "e" * 64},
        "descriptor_sha256": "f" * 64, "flows": [flow_id],
        "path_ids": [f"{flow_id}:timer0"],
    }
    if obligations is not None:
        document["evidence_obligations"] = list(obligations)
    return document


def raw_path(flow_id="F4", *, path_id=None, cpu="cpu0", target="timer0",
             bindings=None, statements=True):
    """A raw D3-shaped path row for F2 or F4 (declared values only)."""
    path_id = path_id or f"{flow_id}:timer0"
    image = _image_source(component=cpu)
    stream = _load_source(component=cpu) if flow_id == "F2" \
        else _store_source(component=cpu)
    access = stream["register_access"]
    access = dict(access)
    access["source_component"] = cpu
    if flow_id == "F4":
        access["target_component"] = target
    stream["register_access"] = access
    edges = [
        {"kind": "instruction_fetch", "rule_index": 0,
         "prerequisite": f"{cpu}.image", "target": f"{cpu}.request"},
        {"kind": "mmio_access", "rule_index": 1,
         "prerequisite": f"{cpu}.request", "target": f"{target}.apb"},
    ]
    if flow_id == "F2":
        edges.append({"kind": "read_consume", "rule_index": 2,
                      "prerequisite": f"{target}.apb",
                      "target": f"{cpu}.consume"})
    document = {
        "path_id": path_id, "flow_id": flow_id, "status": "executable",
        "direction": "CPU_TO_IP",
        "sources": [image, stream],
        "bound_inputs": ([{"input_id": f"{target}.timer0_apb.read_response",
                           "origin": "bound", "kind": "ip_read_response",
                           "component": target, "endpoint_id": "timer0_apb"}]
                         if flow_id == "F2" else []),
        "assertions": [dict(row) for row in ASSERTIONS],
        "constraints": {
            "schema_version": "input_constraint.v1",
            "policy_hash": "1" * 64, "layout_hash": "2" * 64,
            "rule_ids": [], "rules": [], "register_field_constraints": [],
            "source_constraints": [_mirror(image), _mirror(stream)],
        },
        "termination_observation": {"kind": "consumption",
                                    "basis": "the CPU consumes the effect"},
        "runtime_path_identity": {
            "path_id": f"runtime:{flow_id}:{cpu}.{target}",
            "source_ids": [row["source_id"] for row in (image, stream)],
            "edges": edges,
        },
        "bindings": (list(bindings) if bindings is not None
                     else [cpu_binding(flow_id,
                                       required=(access["operation"],),
                                       instance=cpu),
                           target_binding(flow_id,
                                          required=(access["operation"],),
                                          instance=target)]),
    }
    if flow_id == "F2":
        document["execution_contract"] = build_f2_read_contract(document)
    return document


def plan_shaped_path(raw, *, bindings=None, components_semantic="9" * 64):
    """The same declared facts in G4's compiled plan-path shape."""
    sources = []
    for row in raw["sources"]:
        stripped = {name: value for name, value in row.items()
                    if name != "register_access"}
        stripped["basis"] = row.get("constraint_basis")
        sources.append(stripped)
    return {
        "path_id": raw["path_id"],
        "flow_id": raw["flow_id"],
        "status": "executable",
        "flow_name": f"{raw['flow_id']} path",
        "direction": raw["direction"],
        "runtime_path_id": raw["runtime_path_identity"]["path_id"],
        "runtime_source_ids": list(raw["runtime_path_identity"]["source_ids"]),
        "kernel": {"id": f"generic.flow.{raw['flow_id']}.static.v1",
                   "flow_id": raw["flow_id"], "version": "1",
                   "executor": FLOW_EXECUTORS[raw["flow_id"]]},
        "bindings": [dict(row) for row in (bindings or raw["bindings"])],
        "edges": [
            {"kind": edge["kind"], "relation": "mmio_route",
             "rule_index": edge["rule_index"], "from": edge["prerequisite"],
             "to": edge["target"],
             "provider": {"kind": "target_endpoint"}}
            for edge in raw["runtime_path_identity"]["edges"]],
        "target": {"component": "timer0", "node": "timer0.apb"},
        "sources": sources,
        "bound_inputs": [dict(row) for row in raw["bound_inputs"]],
        "seeds": [{"source_id": row["source_id"], "seed": None}
                  for row in sources],
        "assertions": [dict(row) for row in raw["assertions"]],
        "constraints": json.loads(json.dumps(raw["constraints"])),
        "termination": dict(raw["termination_observation"]),
        "execution_contract": raw.get("execution_contract"),
        "semantic_contract_sha256": components_semantic,
    }


# ---------------------------------------------------------------------------
# live-shape fakes (documented stand-ins; no native authority)
# ---------------------------------------------------------------------------

class EventLog:
    """Fake raw event store; component/kind are read back by EvidenceRef."""

    def __init__(self):
        self.rows = []
        self.next_id = 1

    def add(self, component, kind):
        event_id = self.next_id
        self.next_id += 1
        self.rows.append({"event_id": event_id, "component": component,
                          "kind": kind})
        return event_id


class FakeProcess:
    def __init__(self, pid, returncode=None):
        self.pid = pid
        self.returncode = returncode

    def poll(self):
        return self.returncode


class FakeLedger:
    def __init__(self):
        self.pending_keys = []
        self.uncertain_keys = []


class FakeService:
    def __init__(self):
        self.ledger = FakeLedger()


class FakeMemory:
    def __init__(self, seed=0):
        self.seed = seed
        self.writes = []


class FakeHarnessSession:
    def __init__(self, name, pid, memory=None):
        self.name = name
        self.process = FakeProcess(pid)
        self.memory = memory if memory is not None else FakeMemory()
        self.service = FakeService()
        self.mmio_ledger = None


class FakeRunner:
    def __init__(self, sessions, log=None):
        self.sessions = dict(sessions)
        self._log = log if log is not None else EventLog()
        self.local_ticks = {name: 0 for name in self.sessions}
        self.began = 0

    @property
    def events(self):
        return tuple(self._log.rows)

    @property
    def log(self):
        return self._log


class FakeScenarioSession:
    """Stand-in for ScenarioSession: begun exactly once, never re-created."""

    def __init__(self):
        self._begun = True
        self._finished = False
        self.manifest = "b" * 64
        self.cases = []

    @property
    def manifest_sha256(self):
        if not self._begun:
            raise RuntimeError("online session identity is unavailable before begin")
        return self.manifest


class FakeBoundPlan:
    """Structural BoundExecutionPlan: live objects + assert_current counter."""

    def __init__(self, plan, runner, *, fail_after=None):
        self.plan = plan
        self.plan_sha256 = plan.identity_sha256
        self.runner = runner
        self.sessions = dict(runner.sessions)
        self.prepared_paths = {"prepared": "fake"}
        self.adapters = ()
        self.assert_calls = 0
        self.fail_after = fail_after
        self.closed = 0

    def assert_current(self):
        self.assert_calls += 1
        if self.fail_after is not None and self.assert_calls > self.fail_after:
            raise GenericRuntimeRefused("generic-binding-drift", "/binding",
                                        {"reason": "fake-live-binding-changed"})

    def documentary(self):
        return {"plan_sha256": self.plan_sha256,
                "sessions": sorted(self.sessions),
                "prepared_paths": ["prepared:F4:timer0"],
                "live_handle": True}

    def close(self):
        self.closed += 1


def execution_plan(paths, *, components=None):
    document = {
        "schema_version": "generic_execution_plan.v1",
        "components": list(components if components is not None else [
            {"instance_id": "timer0", "source_sha256": "3" * 64,
             "profile_sha256": "4" * 64, "artifact_sha256": "5" * 64,
             "semantic_contract_sha256": "9" * 64,
             "descriptor_sha256": "6" * 64, "descriptor": {}},
        ]),
        "selections": [], "paths": list(paths), "sources": [],
        "constraints": [], "seeds": [], "assertions": [], "memory": {},
        "scheduling": {}, "termination": {}, "evidence_obligations": [],
        "input_digests": {"d2": "1" * 64, "d3": "2" * 64},
    }
    return GenericExecutionPlan.freeze(document)


def campaign_world(flow_id="F4", *, path=None, bindings=None,
                   fail_after_asserts=None):
    """Bound plan + runner + sessions + plan document for one selected path."""
    raw = path if path is not None else raw_path(flow_id, bindings=bindings)
    plan_path = plan_shaped_path(raw, bindings=bindings)
    log = EventLog()
    runner = FakeRunner({"cpu0": FakeHarnessSession("cpu0", 4242, FakeMemory(0)),
                         "timer0": FakeHarnessSession("timer0", 4343,
                                                      FakeMemory(1))}, log)
    plan = execution_plan([plan_path])
    bound = FakeBoundPlan(plan, runner, fail_after=fail_after_asserts)
    return bound, runner, log, plan_path


def _transaction(testcase_id, sequence, *, write=True, value=0):
    return {"execution_id": "campaign-1", "testcase_id": testcase_id,
            "source_component": "cpu0", "source_epoch": 0,
            "channel_id": "timer0.TIMER0_CTRL.CTRL",
            "source_sequence": sequence,
            "write": write, "value": value}


def f4_certificate(log, *, case_id="case-0", value=0x11223344,
                   status="certified", include_native=True,
                   unresolved_native=False, commit_mismatch=False,
                   extra=None, transactions=None):
    """Structural stand-in for one real compiled_F4_chain.v3 certificate."""
    transaction = transactions or {}
    write = _transaction(case_id, transaction.get("write_sequence", 2),
                         value=value)
    write.pop("write", None)
    write.pop("value", None)
    read = _transaction(case_id, transaction.get("read_sequence", 3),
                        write=False)
    read.pop("write", None)
    read.pop("value", None)
    dest = _transaction(case_id, transaction.get("destination_sequence", 4),
                        value=value)
    dest.pop("write", None)
    dest.pop("value", None)
    ids = {}

    def ref(log_key, component, kind):
        if not include_native and component == "timer0":
            return None
        event_id = log.add(component, kind)
        ids.setdefault(log_key, []).append(event_id)
        if unresolved_native and component == "timer0":
            log.rows.pop()
            return 9000 + len(ids[log_key])
        return event_id

    joins = [
        {"delivery_event": log.add("cpu0", "cpu_mmio_delivery"),
         "acceptance_event": log.add("cpu0", "cpu_source_acceptance"),
         "native_APB_event": ref("native", "timer0", "apb_storage_sample_pre"),
         "native_post_event": ref("native", "timer0", "apb_storage_sample_post"),
         "source_transaction": dict(write), "write": True, "tick": 40},
        {"delivery_event": log.add("cpu0", "cpu_mmio_delivery"),
         "acceptance_event": log.add("cpu0", "cpu_source_acceptance"),
         "native_APB_event": ref("native", "timer0", "apb_storage_sample_pre"),
         "native_post_event": ref("native", "timer0", "apb_storage_sample_post"),
         "source_transaction": dict(read), "write": False, "tick": 60},
    ]
    commit_after = (value ^ 0x1) if commit_mismatch else value
    document = {
        "schema_version": "compiled_F4_chain.v3",
        "status": status,
        "case_id": case_id,
        "execution_binding_sha256": "f" * 64,
        "prerequisite": {"value": 0, "write_count": 0},
        "commit": {"tick": 40, "before": 0, "after": commit_after, "epoch": 0,
                   "command_sequence": 5},
        "postcondition": {"value": value, "write_count": 1, "field_version": 1},
        "joins": joins,
        "exact_hops": {
            "data_hops": [{"native_APB_event": ids.get("native", [None])[0]}],
            "ram_write_hop": {
                "memory_write_event": log.add("cpu0", "memory_write"),
                "transaction": dict(dest), "address": 0x800000fc,
                "value": value},
        },
    }
    if extra:
        document.update(extra)
    return document


def f2_certificate(log, *, case_id="case-0", value=0x55,
                   status="certified", include_native=True,
                   version_mismatch=False, extra=None):
    read = _transaction(case_id, 2, write=False)
    read.pop("write", None)
    read.pop("value", None)
    dest = _transaction(case_id, 3, write=False)
    dest.pop("write", None)
    dest.pop("value", None)
    native_pre = None
    native_post = None
    if include_native:
        native_pre = log.add("timer0", "apb_storage_sample_pre")
        native_post = log.add("timer0", "apb_storage_sample_post")
    joins = [{
        "delivery_event": log.add("cpu0", "cpu_mmio_delivery"),
        "acceptance_event": log.add("cpu0", "cpu_source_acceptance"),
        "native_APB_event": native_pre,
        "native_post_event": native_post,
        "source_transaction": dict(read), "write": False, "tick": 30,
    }]
    document = {
        "schema_version": "compiled_F2_chain.v1",
        "status": status,
        "case_id": case_id,
        "execution_binding_sha256": "f" * 64,
        "version_before": {"value": value, "write_count": 0},
        "version_witness": {"value": (value ^ 1) if version_mismatch else value,
                            "write_count": 0},
        "postcondition": {"value": value, "write_count": 0,
                          "field_version": 0},
        "joins": joins,
        "exact_hops": {
            "data_hops": [{"native_APB_event": native_pre}],
            "ram_write_hop": {
                "memory_write_event": log.add("cpu0", "memory_write"),
                "transaction": dict(dest), "address": 0x800000fc,
                "value": value},
        },
    }
    if extra:
        document.update(extra)
    return document


def directed_sequence(*cases, plan_sha256=PLAN_SHA, schema=CASE_SEQUENCE_SCHEMA):
    return {"schema_version": schema, "plan_sha256": plan_sha256,
            "cases": list(cases)}


def directed_case(testcase_id, *, path_id="F4:timer0", source_id=None,
                  records=("44332211",)):
    return {"testcase_id": testcase_id, "path_id": path_id,
            "source_id": source_id or "timer0.TIMER0_CTRL.CTRL.value",
            "raw_records_hex": list(records)}


def prepared_context(flow_id="F4", **kwargs):
    bound, runner, log, plan_path = campaign_world(flow_id, **kwargs)
    kernel = StorageFlowKernel()
    context = kernel.prepare(bound, plan_path["path_id"])
    return kernel, context, bound, runner, log, plan_path


# ---------------------------------------------------------------------------
# requirements come from the declared rows
# ---------------------------------------------------------------------------

class RequirementTests(unittest.TestCase):
    def setUp(self):
        self.kernel = StorageFlowKernel()

    def test_requirements_come_from_the_declared_d3_rows(self):
        path = raw_path("F4")
        requirements = self.kernel.requirements(path)
        self.assertEqual(("cpu", "target"),
                         tuple(row.role for row in requirements))
        cpu, target = requirements
        cpu_row, target_row = path["bindings"]
        for requirement, row in ((cpu, cpu_row), (target, target_row)):
            self.assertEqual(row["endpoint_id"], requirement.endpoint_id)
            self.assertEqual(tuple(row["protocol"]), requirement.protocol)
            self.assertEqual(tuple(row["template"]), requirement.template)
            self.assertEqual(row["semantic_kind"], requirement.semantic_kind)
            self.assertEqual(row["data_width"], requirement.data_width)
            self.assertEqual(row["address_width"], requirement.address_width)
            self.assertEqual(row["address_units"], requirement.address_units)
            self.assertEqual(row["max_outstanding"],
                             requirement.max_outstanding)
            self.assertEqual(row["completion_kind"],
                             requirement.completion_kind)
            self.assertEqual(row["byte_enable"], requirement.byte_enable_required)
            self.assertEqual(tuple(row["required_operations"]),
                             requirement.operations)
            self.assertEqual(tuple(sorted(row["evidence_obligations"])),
                             requirement.evidence_obligations)
        self.assertEqual("storage.rw.v1", target.semantic_kind)

    def test_requirements_ignore_component_names(self):
        first = self.kernel.requirements(raw_path("F4"))
        renamed = raw_path("F4", cpu="processor_x", target="peripheral_y")
        second = self.kernel.requirements(renamed)
        self.assertEqual([row.sha256() for row in first],
                         [row.sha256() for row in second])

    def test_missing_template_token_is_a_template_refusal(self):
        path = plan_shaped_path(raw_path("F4"))
        del path["bindings"][1]["template"]
        with self.assertRaises(GenericRuntimeRefused) as raised:
            self.kernel.requirements(path)
        self.assertEqual("generic-template-mismatch", raised.exception.code)
        self.assertIn("/bindings/1/template", raised.exception.pointer)

    def test_missing_protocol_token_is_a_template_refusal(self):
        path = plan_shaped_path(raw_path("F4"))
        del path["bindings"][0]["protocol"]
        with self.assertRaises(GenericRuntimeRefused) as raised:
            self.kernel.requirements(path)
        self.assertEqual("generic-template-mismatch", raised.exception.code)

    def test_non_storage_semantic_kind_refused(self):
        bindings = [cpu_binding("F4"),
                    target_binding("F4", semantic="fifo.push.v1")]
        path = raw_path("F4", bindings=bindings)
        with self.assertRaises(GenericRuntimeRefused) as raised:
            self.kernel.requirements(path)
        self.assertEqual("generic-semantic-unsupported", raised.exception.code)
        self.assertIn("storage-semantic-required",
                      json.dumps(raised.exception.detail))

    def test_declared_obligations_cannot_remove_a_flow_obligation(self):
        bindings = [cpu_binding("F4"),
                    target_binding("F4",
                                   obligations=("physical_protocol_sample",))]
        with self.assertRaises(GenericRuntimeRefused) as raised:
            self.kernel.requirements(raw_path("F4", bindings=bindings))
        self.assertEqual("generic-evidence-missing", raised.exception.code)
        self.assertIn("declared-obligations-remove-a-flow-obligation",
                      json.dumps(raised.exception.detail))

    def test_flow_minimum_obligations_used_when_the_plan_declares_none(self):
        bindings = [cpu_binding("F4", obligations=None),
                    target_binding("F4", obligations=None)]
        path = raw_path("F4", bindings=bindings)
        requirements = {
            row.role: row for row in self.kernel.requirements(path)}
        self.assertEqual(
            ("component_semantic_effect", "cross_component_consumption",
             "physical_protocol_sample"),
            requirements["target"].evidence_obligations)
        self.assertEqual(
            ("cross_component_source", "physical_protocol_sample"),
            requirements["cpu"].evidence_obligations)
        f2_bindings = [cpu_binding("F2", required=("read",), obligations=None),
                       target_binding("F2", required=("read",), obligations=None)]
        f2 = {row.role: row
              for row in self.kernel.requirements(raw_path("F2", bindings=f2_bindings))}
        self.assertEqual(
            ("component_semantic_effect", "cross_component_source",
             "physical_protocol_sample"),
            f2["target"].evidence_obligations)
        self.assertEqual(
            ("cross_component_consumption", "physical_protocol_sample"),
            f2["cpu"].evidence_obligations)

    def test_unsupported_flow_refused(self):
        path = raw_path("F4")
        path["flow_id"] = "F6"
        with self.assertRaises(GenericRuntimeRefused) as raised:
            self.kernel.requirements(path)
        self.assertEqual("generic-flow-unsupported", raised.exception.code)

    def test_second_register_access_refused(self):
        path = raw_path("F4")
        mirror = dict(path["constraints"]["source_constraints"][1])
        path["constraints"]["source_constraints"].append(mirror)
        with self.assertRaises(GenericRuntimeRefused) as raised:
            self.kernel.requirements(path)
        self.assertEqual("generic-semantic-unsupported", raised.exception.code)


# ---------------------------------------------------------------------------
# prepare references the live binding and never builds a runtime
# ---------------------------------------------------------------------------

class PrepareTests(unittest.TestCase):
    def test_prepare_reuses_the_bound_plan_without_driving_rtl(self):
        bound, runner, log, plan_path = campaign_world("F4")
        kernel = StorageFlowKernel()
        before_events = len(runner.events)
        context = kernel.prepare(bound, plan_path["path_id"])
        self.assertIsInstance(context, FlowContext)
        self.assertIs(bound, context.bound_plan)
        self.assertIs(bound.runner, runner)
        self.assertEqual(bound.plan.identity_sha256, context.plan_sha256)
        self.assertEqual(4, context.record_length)
        self.assertEqual(before_events, len(runner.events))
        self.assertEqual(0, runner.began)
        document = context.document()
        self.assertFalse(document["owns_session"])
        self.assertFalse(document["owns_runner"])
        self.assertFalse(document["owns_memory"])
        self.assertFalse(document["live_handle"])
        self.assertEqual("9" * 64, document["semantic_contract_sha256"])
        self.assertEqual(1, len(document["mutation_domains"]))

    def test_prepare_accepts_the_compiled_plan_shape(self):
        raw = raw_path("F2")
        plan_path = plan_shaped_path(raw)
        log = EventLog()
        runner = FakeRunner({"cpu0": FakeHarnessSession("cpu0", 10),
                             "timer0": FakeHarnessSession("timer0", 11)}, log)
        bound = FakeBoundPlan(execution_plan([plan_path]), runner)
        context = StorageFlowKernel().prepare(bound, plan_path["path_id"])
        self.assertEqual("F2", context.flow_id)
        self.assertEqual(4, context.record_length)
        # The F2 fuzzable source is one declared address: no invented domain.
        self.assertEqual([1], [row.steps for row in context.domains])

    def test_prepare_refuses_an_unknown_path(self):
        bound, _, _, _ = campaign_world("F4")
        with self.assertRaises(GenericRuntimeRefused) as raised:
            StorageFlowKernel().prepare(bound, "F4:not-declared")
        self.assertEqual("generic-plan-mismatch", raised.exception.code)

    def test_prepare_refuses_a_bound_digest_that_is_not_the_plan_identity(self):
        bound, _, _, plan_path = campaign_world("F4")
        bound.plan_sha256 = "0" * 64
        with self.assertRaises(GenericRuntimeRefused) as raised:
            StorageFlowKernel().prepare(bound, plan_path["path_id"])
        self.assertEqual("generic-plan-mismatch", raised.exception.code)


# ---------------------------------------------------------------------------
# lower: closed directed shape, refused before admission
# ---------------------------------------------------------------------------

class LowerTests(unittest.TestCase):
    def setUp(self):
        (self.kernel, self.context, self.bound, self.runner, self.log,
         self.path) = prepared_context("F4")
        self.path_id = self.path["path_id"]

    def case(self, *, records=("44332211",), **overrides):
        document = directed_case("case-0", path_id=self.path_id,
                                 records=records)
        document.update(overrides)
        return document

    def test_lower_keeps_every_raw_record(self):
        case = self.case(records=("44332211", "88776655"))
        lowered = self.kernel.lower(self.context, case)
        self.assertEqual((bytes.fromhex("44332211"), bytes.fromhex("88776655")),
                         lowered.raw_records)
        self.assertEqual(["44332211", "88776655"],
                         lowered.document()["raw_records_hex"])

    def test_lower_refuses_extra_field(self):
        case = self.case(expected_value=0x1234)
        with self.assertRaises(GenericRuntimeRefused) as raised:
            self.kernel.lower(self.context, case)
        self.assertEqual("generic-contract-shape", raised.exception.code)
        self.assertIn("/case/expected_value", raised.exception.pointer)

    def test_lower_refuses_a_missing_field(self):
        case = self.case()
        del case["source_id"]
        with self.assertRaises(GenericRuntimeRefused) as raised:
            self.kernel.lower(self.context, case)
        self.assertEqual("generic-contract-shape", raised.exception.code)

    def test_lower_refuses_wrong_path(self):
        case = self.case(path_id="F4:other-path")
        with self.assertRaises(GenericRuntimeRefused) as raised:
            self.kernel.lower(self.context, case)
        self.assertEqual("generic-plan-mismatch", raised.exception.code)

    def test_lower_refuses_an_unbound_source(self):
        case = self.case(source_id="timer0.UNDECLARED.REG.value")
        with self.assertRaises(GenericRuntimeRefused) as raised:
            self.kernel.lower(self.context, case)
        self.assertEqual("generic-source-unverified", raised.exception.code)
        self.assertIn("source-not-a-declared-fuzzable-source",
                      json.dumps(raised.exception.detail))

    def test_lower_refuses_a_truncated_or_resized_record(self):
        for record in ("4433", "44332211ff", ""):
            case = self.case(records=(record,))
            with self.assertRaises(GenericRuntimeRefused) as raised:
                self.kernel.lower(self.context, case)
            self.assertIn(raised.exception.code,
                          ("generic-case-shape",))
        case = self.case(records=())
        with self.assertRaises(GenericRuntimeRefused) as raised:
            self.kernel.lower(self.context, case)
        self.assertEqual("generic-case-shape", raised.exception.code)

    def test_lower_refuses_odd_hex(self):
        case = self.case(records=("4433221",))
        with self.assertRaises(GenericRuntimeRefused) as raised:
            self.kernel.lower(self.context, case)
        self.assertEqual("generic-case-shape", raised.exception.code)


class SequenceTests(unittest.TestCase):
    def setUp(self):
        self.flows = {"F2:timer0": "F2", "F4:timer0": "F4"}
        self.path_id = "F4:timer0"

    def test_closed_top_level_shape(self):
        document = directed_sequence(directed_case("case-0"))
        document["unexpected"] = True
        with self.assertRaises(GenericRuntimeRefused) as raised:
            load_case_sequence(plan_sha256=PLAN_SHA, path_flows=self.flows,
                               document=document)
        self.assertEqual("generic-contract-shape", raised.exception.code)

    def test_wrong_schema_refused(self):
        document = directed_sequence(directed_case("case-0"),
                                     schema="generic_case_sequence.v2")
        with self.assertRaises(GenericRuntimeRefused) as raised:
            load_case_sequence(plan_sha256=PLAN_SHA, path_flows=self.flows,
                               document=document)
        self.assertEqual("generic-case-shape", raised.exception.code)

    def test_wrong_plan_digest_refused(self):
        document = directed_sequence(directed_case("case-0"),
                                     plan_sha256="0" * 64)
        with self.assertRaises(GenericRuntimeRefused) as raised:
            load_case_sequence(plan_sha256=PLAN_SHA, path_flows=self.flows,
                               document=document)
        self.assertEqual("generic-plan-mismatch", raised.exception.code)

    def test_duplicate_case_refused(self):
        document = directed_sequence(directed_case("case-0"),
                                     directed_case("case-0"))
        with self.assertRaises(GenericRuntimeRefused) as raised:
            load_case_sequence(plan_sha256=PLAN_SHA, path_flows=self.flows,
                               document=document)
        self.assertEqual("generic-case-duplicate", raised.exception.code)

    def test_unknown_path_refused(self):
        document = directed_sequence(directed_case("case-0",
                                                   path_id="F2:unknown"))
        with self.assertRaises(GenericRuntimeRefused) as raised:
            load_case_sequence(plan_sha256=PLAN_SHA, path_flows=self.flows,
                               document=document)
        self.assertEqual("generic-plan-mismatch", raised.exception.code)

    def test_extra_case_field_refused(self):
        case = directed_case("case-0")
        case["expected"] = "0x1"
        document = directed_sequence(case)
        with self.assertRaises(GenericRuntimeRefused) as raised:
            load_case_sequence(plan_sha256=PLAN_SHA, path_flows=self.flows,
                               document=document)
        self.assertEqual("generic-contract-shape", raised.exception.code)

    def test_mixed_flow_sequence_is_refused_not_downgraded(self):
        document = directed_sequence(
            directed_case("case-0", path_id="F4:timer0"),
            directed_case("case-1", path_id="F2:timer0",
                          source_id="timer0.TIMER0_CTRL.CTRL.address"))
        with self.assertRaises(GenericRuntimeRefused) as raised:
            load_case_sequence(plan_sha256=PLAN_SHA, path_flows=self.flows,
                               document=document)
        self.assertEqual("generic-flow-mixed-unsupported",
                         raised.exception.code)
        self.assertEqual(["F2", "F4"], raised.exception.detail["flows"])

    def test_refuse_mixed_flows_helper(self):
        refuse_mixed_flows(("F4",))
        with self.assertRaises(GenericRuntimeRefused) as raised:
            refuse_mixed_flows(("F4", "F2"))
        self.assertEqual("generic-flow-mixed-unsupported",
                         raised.exception.code)


# ---------------------------------------------------------------------------
# capture: four-state evidence, never a promoted observation
# ---------------------------------------------------------------------------

class CaptureTests(unittest.TestCase):
    def setUp(self):
        (self.kernel, self.context, self.bound, self.runner, self.log,
         self.path) = prepared_context("F4")

    def test_certified_chain_maps_to_all_four_obligations(self):
        certificate = f4_certificate(self.log, value=0x0BADF00D)
        evidence = self.kernel.capture(self.context, certificate)
        self.assertTrue(evidence)
        first = evidence[0]
        self.assertEqual("certified", first.status)
        self.assertEqual("cross_component_consumption", first.scope)
        self.assertEqual(
            (("component_semantic_effect", "certified"),
             ("cross_component_consumption", "certified"),
             ("cross_component_source", "certified"),
             ("physical_protocol_sample", "certified")),
            first.obligation_results)
        self.assertEqual("f" * 64, first.binding_sha256)
        self.assertTrue(first.native_refs)
        self.assertEqual("timer0", first.native_refs[0].component)
        self.assertEqual(TransactionKey("campaign-1", "case-0", "cpu0", 0,
                                        "timer0.TIMER0_CTRL.CTRL", 2),
                         first.key)
        self.assertEqual(2, len(evidence))
        self.assertEqual("cross_component_consumption", evidence[1].scope)
        self.assertEqual(4, evidence[1].key.source_sequence)

    def test_claimed_reference_absent_from_the_event_log_is_missing(self):
        certificate = f4_certificate(self.log, unresolved_native=True)
        evidence = self.kernel.capture(self.context, certificate)
        results = dict(evidence[0].obligation_results)
        self.assertEqual("missing", results["physical_protocol_sample"])
        self.assertEqual("missing", evidence[0].status)

    def test_absent_native_witness_is_unsupported(self):
        certificate = f4_certificate(self.log, include_native=False)
        evidence = self.kernel.capture(self.context, certificate)
        results = dict(evidence[0].obligation_results)
        self.assertEqual("unsupported", results["physical_protocol_sample"])
        self.assertEqual("unsupported", evidence[0].status)
        self.assertNotEqual("certified", evidence[0].status)

    def test_contradicting_commit_witness_is_contradicted(self):
        certificate = f4_certificate(self.log, value=0x1234,
                                     commit_mismatch=True)
        evidence = self.kernel.capture(self.context, certificate)
        results = dict(evidence[0].obligation_results)
        self.assertEqual("contradicted",
                         results["component_semantic_effect"])
        self.assertEqual("contradicted", evidence[0].status)

    def test_uncertified_receipt_cannot_certify(self):
        certificate = f4_certificate(self.log, status="finding")
        evidence = self.kernel.capture(self.context, certificate)
        self.assertEqual("missing", evidence[0].status)
        self.assertTrue(all(status != "certified"
                            for _, status in evidence[0].obligation_results))

    def test_missing_execution_binding_digest_refused(self):
        certificate = f4_certificate(self.log)
        certificate["execution_binding_sha256"] = "not-a-digest"
        with self.assertRaises(GenericRuntimeRefused) as raised:
            self.kernel.capture(self.context, certificate)
        self.assertEqual("generic-evidence-missing", raised.exception.code)

    def test_missing_transaction_key_refused(self):
        certificate = f4_certificate(self.log)
        for join in certificate["joins"]:
            join["source_transaction"] = {"execution_id": "campaign-1"}
        with self.assertRaises(GenericRuntimeRefused) as raised:
            self.kernel.capture(self.context, certificate)
        self.assertEqual("generic-evidence-missing", raised.exception.code)

    def test_f2_chain_maps_the_read_effect(self):
        (kernel, context, _, _, log,
         _) = prepared_context("F2")
        certificate = f2_certificate(log, value=0x77)
        evidence = kernel.capture(context, certificate)
        results = dict(evidence[0].obligation_results)
        self.assertEqual("certified", results["physical_protocol_sample"])
        self.assertEqual("certified", results["cross_component_source"])
        self.assertEqual("certified", results["cross_component_consumption"])
        self.assertEqual("certified", evidence[0].status)
        self.assertEqual("cross_component_consumption", evidence[0].scope)

    def test_f2_contradicting_version_witness(self):
        (kernel, context, _, _, log,
         _) = prepared_context("F2")
        certificate = f2_certificate(log, value=0x77, version_mismatch=True)
        evidence = kernel.capture(context, certificate)
        self.assertEqual("contradicted",
                         dict(evidence[0].obligation_results)[
                             "component_semantic_effect"])


# ---------------------------------------------------------------------------
# backend: adopt the existing runtime, never rebuild it
# ---------------------------------------------------------------------------

class FakeCaseRuntime:
    """Structural stand-in for an existing CompiledF2/F4 persistent runtime."""

    def __init__(self, runner, session, *, first_fetch=None):
        self.runner = runner
        self.session = session
        self.first_fetch = first_fetch or {"address": 0x80000000, "event_id": 1}
        self.records = []
        self.finished = False
        self.execution_binding = {"execution_binding_sha256": "a" * 64}
        self.authority = object()
        self.submit_calls = 0

    def submit(self, raw):
        self.submit_calls += 1
        self.records.append({"raw": raw.hex()})
        return {"case_id": f"case-{self.submit_calls}", "status": "certified"}

    def finish(self):
        self.finished = True
        return {"schema_version": "fake_prefix.v1"}

    def feedback(self):
        return {"cases": len(self.records)}

    def execution_audit(self):
        return {"exits": {name: {"returncode": 0}
                          for name in self.runner.sessions}}


class BackendTests(unittest.TestCase):
    def runtime(self, flow_id="F4"):
        log = EventLog()
        runner = FakeRunner({"cpu0": FakeHarnessSession("cpu0", 11),
                             "timer0": FakeHarnessSession("timer0", 12)}, log)
        runtime = FakeCaseRuntime(runner, FakeScenarioSession())
        return runtime, runner

    def test_backend_adopts_the_existing_runtime(self):
        runtime, runner = self.runtime()
        backend = StorageFlowBackend(runtime=runtime, flow_id="F4")
        channel = backend.open()
        self.assertIsInstance(channel, StorageFlowChannel)
        self.assertIs(runtime.runner, channel.runner)
        self.assertEqual({"cpu0", "timer0"}, set(channel.sessions))
        self.assertIs(runner.sessions["cpu0"].memory, channel.memory)
        self.assertIs(runtime.authority, channel.authority)
        self.assertEqual({"build": 1, "begin": 0, "init": 0},
                         channel.counters())
        channel.begin_once()
        self.assertEqual({"build": 1, "begin": 1, "init": 1},
                         channel.counters())
        with self.assertRaises(GenericRuntimeRefused) as raised:
            channel.begin_once()
        self.assertEqual("generic-binding-drift", raised.exception.code)
        self.assertIs(channel, backend.open())

    def test_backend_requires_exactly_one_source(self):
        with self.assertRaises(GenericRuntimeRefused) as raised:
            StorageFlowBackend(flow_id="F4")
        self.assertEqual("generic-contract-type", raised.exception.code)

    def test_backend_refuses_another_flow(self):
        runtime, _ = self.runtime()
        backend = StorageFlowBackend(runtime=runtime, flow_id="F4")
        backend.require_flow("F4")
        with self.assertRaises(GenericRuntimeRefused) as raised:
            backend.require_flow("F2")
        self.assertEqual("generic-plan-mismatch", raised.exception.code)

    def test_backend_refuses_an_unknown_executor(self):
        spec = CompiledFlowSpec(artifacts={}, compiled_inputs={},
                                executor="compiled_f6_obi_apb",
                                base_dir=".", cache_dir=".")
        with self.assertRaises(GenericRuntimeRefused) as raised:
            StorageFlowBackend(spec=spec)
        self.assertEqual("generic-adapter-missing", raised.exception.code)

    def test_channel_surface_must_be_complete(self):
        with self.assertRaises(GenericRuntimeRefused) as raised:
            StorageFlowChannel(object(), flow_id="F4")
        self.assertEqual("generic-adapter-missing", raised.exception.code)
        self.assertIn("runtime-surface-incomplete",
                      json.dumps(raised.exception.detail))

    def test_single_flow_backend_reports_its_mixed_flow_limit(self):
        runtime, _ = self.runtime()
        text = " ".join(StorageFlowBackend(runtime=runtime,
                                           flow_id="F4").unresolved())
        self.assertIn("generic-flow-mixed-unsupported", text)
        self.assertNotIn("no campaign is wired", text)


class FixedInterfaceTests(unittest.TestCase):
    def test_module_level_design_interface_is_code_owned(self):
        from myfuzz.runtime.flows import storage
        kernel = StorageFlowKernel()
        path = raw_path("F4")
        self.assertEqual(
            [row.sha256() for row in kernel.requirements(path)],
            [row.sha256() for row in storage.requirements(path)])
        bound, _, _, plan_path = campaign_world("F4")
        self.assertIsInstance(storage.prepare(bound, plan_path["path_id"]),
                              FlowContext)
        for name in ("requirements", "prepare", "lower", "capture", "feedback"):
            self.assertTrue(callable(getattr(storage, name)))
        self.assertEqual(("F2", "F4"), StorageFlowKernel.flow_ids)
        document = kernel.document()
        self.assertEqual("storage.kernel.v1", document["kernel_id"])
        self.assertFalse(document["native_authority"])
        self.assertEqual(list(OBLIGATIONS), sorted(document["obligations"]))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
