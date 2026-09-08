from __future__ import annotations

import json
import unittest
from pathlib import Path

from myfuzz.composition.endpoint_capabilities import normalize_annotations
from myfuzz.composition.interface_description import load_interface_description
from myfuzz.composition.source_crawler import SourceCrawler
from myfuzz.composition.processor_adapters import resolve_processor_adapter
from myfuzz.composition.input_layout import build_input_layout
from myfuzz.composition.runtime_projection import RuntimeProjector
from myfuzz.composition.processor_boundary import (
    ProcessorBoundaryError,
    build_processor_boundary,
    processor_boundary_document,
)
from myfuzz.protocols.catalog import ProtocolCatalog
from myfuzz.protocols.model import FieldSpec, ProtocolPlugin


ROOT = Path(__file__).resolve().parents[2]


def _source(line: int) -> dict[str, object]:
    return {"file": "rtl/core.sv", "line": line, "column": 1}


def _field(
    role: str,
    port: str,
    direction: str,
    width: int = 1,
    *,
    line: int = 1,
    member: tuple[str, ...] = (),
    raw_lo: int | None = None,
    container_width: int | None = None,
) -> dict[str, object]:
    value: dict[str, object] = {
        "role": role,
        "port": port,
        "direction": direction,
        "width": width,
        "signed": False,
        "source": _source(line),
        "evidence": ["hdl_declaration"],
    }
    if member:
        assert raw_lo is not None and container_width is not None
        value.update(
            member_path=list(member),
            raw_lo=raw_lo,
            raw_hi=raw_lo + width - 1,
            container_width=container_width,
            evidence=["explicit_member", "compiler_elaboration"],
        )
    return value


def _endpoint(
    endpoint_id: str,
    function: str,
    fields: list[dict[str, object]],
    *,
    protocol: tuple[str, str] | None = None,
    side: str | None = None,
    clock: str | None = None,
    reset: str | None = None,
) -> dict[str, object]:
    return {
        "endpoint_id": endpoint_id,
        "function": function,
        "fields": fields,
        **({} if protocol is None else {"protocol": list(protocol)}),
        **({} if side is None else {"side": side}),
        **({} if clock is None else {"clock": clock}),
        **({} if reset is None else {"reset": reset}),
    }


def _catalog() -> ProtocolCatalog:
    return ProtocolCatalog((ProtocolPlugin(
        "test-memory", "1",
        (
            FieldSpec("request", "host_to_device", "1", True, 0),
            FieldSpec("address", "host_to_device", "32", True, 0),
            FieldSpec("response", "device_to_host", "1", True, 0),
            FieldSpec("read_data", "device_to_host", "32", True, 0),
        ),
        (),
    ),))


def _valid_document(*, split: bool = False, identity: bool = True) -> dict[str, object]:
    controls = [
        _endpoint("control.clock", "clock", [_field("clock", "renamed_clk", "input")]),
        _endpoint("control.reset", "reset", [_field("reset", "renamed_reset", "input")]),
    ]
    memory_fields = [
        _field("request", "opaque_req", "output", line=10),
        _field("address", "opaque_addr", "output", 32, line=11),
        _field("response", "opaque_rsp", "input", line=12),
        _field("read_data", "opaque_rdata", "input", 32, line=13),
    ]
    if split:
        memories = [
            _endpoint("memory.instruction", "instruction_memory_master", memory_fields,
                      protocol=("test-memory", "1"), side="initiator",
                      clock="renamed_clk", reset="renamed_reset"),
            _endpoint("memory.data", "data_memory_master", [
                {**field, "port": "data_" + str(field["port"]),
                 "source": _source(20 + index)}
                for index, field in enumerate(memory_fields)
            ], protocol=("test-memory", "1"), side="initiator",
                clock="renamed_clk", reset="renamed_reset"),
        ]
    else:
        memories = [_endpoint("memory.unified", "memory_master", memory_fields,
                              protocol=("test-memory", "1"), side="initiator")]
    if identity and not split:
        memory = memories[0]
        assert isinstance(memory, dict)
        fields = memory["fields"]
        assert isinstance(fields, list)
        fields.append(_field("instruction_identity", "mem_instr", "output", line=14))
    return {"schema_version": "interface_annotations.v1", "endpoints": controls + memories}


class ProcessorBoundaryTests(unittest.TestCase):
    def build(self, document: dict[str, object]):
        return build_processor_boundary(
            normalize_annotations(document), protocol_catalog=_catalog()
        )

    def test_builds_unified_boundary_from_roles_without_cpu_name_dispatch(self) -> None:
        boundary = self.build(_valid_document())

        self.assertEqual("control.clock", boundary.clock.endpoint_id)
        self.assertEqual("control.reset", boundary.reset.endpoint_id)
        self.assertEqual(("memory.unified",), tuple(item.endpoint_id for item in boundary.memories))
        rendered = processor_boundary_document(boundary)
        self.assertEqual("processor_boundary.v1", rendered["schema_version"])
        self.assertEqual("test-memory", rendered["memories"][0]["protocol"][0])
        self.assertNotIn("ibex", repr(rendered).lower())
        self.assertNotIn("cva6", repr(rendered).lower())
        self.assertNotIn("boom", repr(rendered).lower())

    def test_accepts_split_instruction_and_data_memory_masters(self) -> None:
        boundary = self.build(_valid_document(split=True))
        self.assertEqual(
            ("data_memory_master", "instruction_memory_master"),
            tuple(item.function for item in boundary.memories),
        )

    def test_unified_memory_uses_source_backed_instruction_identity(self) -> None:
        document = _valid_document()

        boundary = self.build(document)

        self.assertEqual("explicit_signal", boundary.classification.mode)
        self.assertEqual("instruction_identity", boundary.classification.field_role)
        self.assertEqual("mem_instr", boundary.classification.port)
        self.assertEqual(1, boundary.classification.instruction_value)
        self.assertEqual(0, boundary.classification.data_value)

    def test_unified_memory_without_instruction_identity_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            ProcessorBoundaryError, "missing-instruction-identity"
        ):
            self.build(_valid_document(identity=False))

    def test_instruction_identity_requires_output_one_bit_and_source(self) -> None:
        for mutation, reason in (
            (lambda field: field.update(width=2), "instruction-identity-width"),
            (lambda field: field.update(direction="input"), "instruction-identity-direction"),
            (lambda field: field.pop("source"), "source-evidence"),
        ):
            document = _valid_document(identity=False)
            memory = document["endpoints"][-1]
            assert isinstance(memory, dict)
            fields = memory["fields"]
            assert isinstance(fields, list)
            identity = _field("instruction_identity", "mem_instr", "output")
            mutation(identity)
            fields.append(identity)
            with self.subTest(reason=reason), self.assertRaisesRegex(
                ProcessorBoundaryError, reason
            ):
                self.build(document)

    def test_split_memory_boundary_records_function_classification(self) -> None:
        boundary = self.build(_valid_document(split=True))
        self.assertEqual("split_function", boundary.classification.mode)

    def test_read_only_obi_instruction_endpoint_uses_declared_capabilities(self) -> None:
        document = {
            "schema_version": "interface_annotations.v1",
            "endpoints": [
                _endpoint("control.clock", "clock", [_field("clock", "clk_x", "input")]),
                _endpoint("control.reset", "reset", [_field("reset", "rst_x", "input")]),
                _endpoint("memory.instruction", "instruction_memory_master", [
                    _field("req", "fetch_req_x", "output"),
                    _field("gnt", "fetch_gnt_x", "input"),
                    _field("addr", "fetch_addr_x", "output", 32),
                    _field("rvalid", "fetch_rvalid_x", "input"),
                    _field("rdata", "fetch_rdata_x", "input", 32),
                    _field("error", "fetch_error_x", "input"),
                ], protocol=("obi", "1"), side="initiator",
                    clock="clk_x", reset="rst_x"),
            ],
        }
        boundary = build_processor_boundary(
            normalize_annotations(document), protocol_catalog=_catalog_for_path()
        )
        adapter = resolve_processor_adapter(boundary.memories[0])

        self.assertEqual("obi-to-processor-memory-beat", adapter.adapter_id)
        self.assertIn(("READ_ONLY", 1), adapter.parameter_values)

        memory = document["endpoints"][2]
        assert isinstance(memory, dict)
        fields = memory["fields"]
        assert isinstance(fields, list)
        fields.append(_field("we", "bad_we_x", "input"))
        with self.assertRaisesRegex(ProcessorBoundaryError, "field-direction:we"):
            build_processor_boundary(
                normalize_annotations(document), protocol_catalog=_catalog_for_path()
            )

    def test_rejects_missing_or_ambiguous_required_functions(self) -> None:
        cases = {
            "clock": lambda endpoints: endpoints.pop(0),
            "reset": lambda endpoints: endpoints.pop(1),
            "memory": lambda endpoints: endpoints.pop(),
            "duplicate-clock": lambda endpoints: endpoints.append(
                {**endpoints[0], "endpoint_id": "control.clock.second"}
            ),
        }
        for reason, mutate in cases.items():
            with self.subTest(reason=reason):
                document = _valid_document()
                endpoints = document["endpoints"]
                assert isinstance(endpoints, list)
                mutate(endpoints)
                with self.assertRaisesRegex(ProcessorBoundaryError, reason):
                    self.build(document)

    def test_rejects_target_unknown_protocol_missing_role_and_unproven_field(self) -> None:
        mutations = (
            ("memory-side", lambda memory: memory.update(side="target")),
            ("unsupported-protocol", lambda memory: memory.update(protocol=["missing", "1"])),
            ("required-field:read_data", lambda memory: memory["fields"].pop(3)),
            ("field-width:address", lambda memory: memory["fields"][1].update(width=31)),
            ("source-evidence", lambda memory: memory["fields"][0].pop("source")),
        )
        for reason, mutate in mutations:
            with self.subTest(reason=reason):
                document = _valid_document()
                memory = document["endpoints"][-1]
                assert isinstance(memory, dict)
                mutate(memory)
                with self.assertRaisesRegex(ProcessorBoundaryError, reason):
                    self.build(document)

    def test_requires_complete_nonoverlapping_packed_input_coverage(self) -> None:
        document = _valid_document()
        memory = document["endpoints"][-1]
        assert isinstance(memory, dict)
        fields = memory["fields"]
        assert isinstance(fields, list)
        fields[2] = _field("response", "packed_rsp", "input", 1, member=("valid",), raw_lo=32, container_width=33)
        fields[3] = _field("read_data", "packed_rsp", "input", 32, member=("data",), raw_lo=0, container_width=33)
        boundary = self.build(document)
        packed = processor_boundary_document(boundary)["packed_input_containers"]
        self.assertEqual([{
            "endpoint_id": "memory.unified", "port": "packed_rsp",
            "width": 33, "covered_bits": 33,
        }], packed)

        for reason, mutation in (
            ("incomplete-packed-input", lambda fs: (
                fs[2].update(container_width=34), fs[3].update(container_width=34)
            )),
            ("overlapping-packed-input", lambda fs: fs[2].update(raw_lo=31, raw_hi=31)),
            ("inconsistent-packed-container", lambda fs: fs[2].update(container_width=34)),
        ):
            with self.subTest(reason=reason):
                broken = _valid_document()
                broken_memory = broken["endpoints"][-1]
                assert isinstance(broken_memory, dict)
                broken_fields = broken_memory["fields"]
                assert isinstance(broken_fields, list)
                broken_fields[2] = _field("response", "packed_rsp", "input", 1, member=("valid",), raw_lo=32, container_width=33)
                broken_fields[3] = _field("read_data", "packed_rsp", "input", 32, member=("data",), raw_lo=0, container_width=33)
                mutation(broken_fields)
                with self.assertRaisesRegex(ProcessorBoundaryError, reason):
                    self.build(broken)

    def test_unrelated_endpoint_cannot_fill_processor_packed_input(self) -> None:
        document = _valid_document()
        memory = document["endpoints"][-1]
        assert isinstance(memory, dict)
        fields = memory["fields"]
        assert isinstance(fields, list)
        fields[2] = _field(
            "response", "packed_rsp", "input", 1,
            member=("valid",), raw_lo=32, container_width=34,
        )
        fields[3] = _field(
            "read_data", "packed_rsp", "input", 32,
            member=("data",), raw_lo=0, container_width=34,
        )
        endpoints = document["endpoints"]
        assert isinstance(endpoints, list)
        filler = _field(
            "filler", "packed_rsp", "input", 1,
            member=("filler",), raw_lo=33, container_width=34,
        )
        filler.pop("source")
        endpoints.append(_endpoint("unrelated", "unrelated", [filler]))

        with self.assertRaisesRegex(
            ProcessorBoundaryError, "source-evidence|split-packed-input"
        ):
            self.build(document)

    def test_optional_controls_reject_unknown_roles_widths_and_protocols(self) -> None:
        mutations = (
            ("control-role", {"role": "nonsense"}),
            ("control-width", {"width": 7}),
        )
        for reason, mutation in mutations:
            with self.subTest(reason=reason):
                document = _valid_document()
                endpoints = document["endpoints"]
                assert isinstance(endpoints, list)
                endpoints.append(_endpoint(
                    "control.debug", "debug_transport",
                    [_field("request", "debug_x", "input")],
                ))
                control = endpoints[-1]
                assert isinstance(control, dict)
                control_fields = control["fields"]
                assert isinstance(control_fields, list)
                control_fields[0].update(mutation)
                with self.assertRaisesRegex(ProcessorBoundaryError, reason):
                    self.build(document)

        document = _valid_document()
        endpoints = document["endpoints"]
        assert isinstance(endpoints, list)
        endpoints.append(_endpoint(
            "control.boot", "boot_control",
            [_field("boot_address", "boot_x", "input", 32)],
            protocol=("test-memory", "1"), side="initiator",
        ))
        with self.assertRaisesRegex(ProcessorBoundaryError, "control-protocol"):
            self.build(document)

    def test_official_cva6_sample_declares_every_packed_memory_member(self) -> None:
        description = load_interface_description(
            ROOT / "configs/cpus/cva6/official_core_interface_description.json"
        )
        memory = next(
            endpoint for endpoint in description.endpoints
            if endpoint.function == "memory_master"
        )
        by_container: dict[str, set[tuple[str, ...]]] = {}
        by_role = {field.role: field for field in memory.fields}
        for field in memory.fields:
            assert field.physical is not None
            by_container.setdefault(field.physical.port, set()).add(
                field.physical.member_path
            )

        self.assertEqual(32, len(by_container["noc_req_o"]))
        self.assertEqual(13, len(by_container["noc_resp_i"]))
        self.assertEqual(45, len(by_role))
        self.assertEqual(
            {field.field_id for field in _catalog_for_path().require("axi4", "1").fields},
            set(by_role) - {
                "awlock", "awcache", "awprot", "awqos", "awregion", "awatop", "awuser",
                "wuser", "buser", "arlock", "arcache", "arprot", "arqos", "arregion",
                "aruser", "ruser",
            },
        )

    @unittest.skipUnless(
        (ROOT / "third_party/cva6_upstream_reference/.git").exists(),
        "official CVA6 checkout is not materialized",
    )
    def test_real_cva6_compiler_evidence_rejects_missing_instruction_identity(self) -> None:
        description = load_interface_description(
            ROOT / "configs/cpus/cva6/official_core_interface_description.json"
        )
        catalog = _catalog_for_path()
        crawler = SourceCrawler()
        snapshot = crawler.crawl(description.source, base_dir=ROOT)
        annotations = crawler.annotate(
            snapshot, description, protocol_catalog=catalog
        )
        with self.assertRaisesRegex(
            ProcessorBoundaryError, "missing-instruction-identity"
        ):
            build_processor_boundary(
                normalize_annotations(annotations), protocol_catalog=catalog
            )
        assert snapshot.elaboration_evidence is not None
        evidence = json.loads(snapshot.elaboration_evidence)

        self.assertEqual(
            "sha256:c5c43bf31209c575fd472111b074077b6a4bc4910c68501f13b66da5a04efe75",
            snapshot.content_hash,
        )
        self.assertEqual(464, evidence["warning_summary"]["warning_count"])
        memory_annotation = next(
            item for item in annotations["endpoints"]
            if item["function"] == "memory_master"
        )
        self.assertEqual(45, len(memory_annotation["fields"]))
        layout = build_input_layout(annotations)
        packed_ports = RuntimeProjector(layout).project_ports(
            (1 << layout.raw_width) - 1
        )
        self.assertEqual((1 << 210) - 1, packed_ports["noc_resp_i"])


def _catalog_for_path() -> ProtocolCatalog:
    from myfuzz.protocols.catalog import load_protocol_catalog

    return load_protocol_catalog(ROOT / "src/myfuzz/protocols/plugins")


if __name__ == "__main__":
    unittest.main()
