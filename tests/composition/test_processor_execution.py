from __future__ import annotations

import json
import unittest
import tempfile
from dataclasses import replace
from pathlib import Path

from myfuzz.composition.endpoint_capabilities import EndpointFieldFact, SourceReference
from myfuzz.composition.input_layout import InputLayout, LayoutField
from myfuzz.composition.processor_adapters import resolve_processor_adapter
from myfuzz.composition.processor_boundary import (
    PackedInputContainer,
    ProcessorBoundary,
    ProcessorControlBinding,
    ProcessorMemoryBinding,
    RequestClassification,
)
from myfuzz.composition.processor_execution import (
    ProcessorExecutionError,
    build_processor_execution,
    processor_execution_document,
)
from myfuzz.composition.auto import GenericCompositionRequest, plan_generic_composition
from myfuzz.composition.interface_description import load_interface_description
from myfuzz.composition.protocol_composer import write_generic_composition
from myfuzz.composition.source_crawler import source_tree_hash
from myfuzz.protocols.catalog import load_protocol_catalog
from myfuzz.protocols.widths import compile_width_expression


ROOT = Path(__file__).resolve().parents[2]


def _field(role: str, direction: str, width: int, port: str) -> EndpointFieldFact:
    return EndpointFieldFact(
        role, port, direction, width, False,
        SourceReference("rtl/renamed_core.sv", 1, 1), ("compiler",),
    )


def _memory(
    protocol: tuple[str, str], *, endpoint: str = "processor.memory.renamed",
    function: str = "memory_master", packed_inputs: bool = False,
) -> tuple[ProcessorMemoryBinding, tuple[PackedInputContainer, ...]]:
    catalog = load_protocol_catalog(ROOT / "src/myfuzz/protocols/plugins")
    plugin = catalog.require(*protocol)
    parameters = {"address_width": 32, "data_width": 32, "id_width": 4}
    fields = [
        _field(
            spec.field_id,
            "output" if spec.direction == "host_to_device" else "input",
            compile_width_expression(spec.width_expression, parameters),
            f"renamed_{spec.field_id}",
        )
        for spec in plugin.fields
    ]
    protocol_roles = {field.role for field in fields}
    extensions = []
    if protocol == ("obi", "1"):
        extensions.append(_field("error", "input", 1, "renamed_error"))
        fields.extend(extensions)
    adapter = resolve_processor_adapter(
        ProcessorMemoryBinding(
            endpoint, function, protocol, tuple(fields), tuple(extensions),
        )
    )
    for policy in adapter.extension_policies:
        if policy.role in protocol_roles or any(
            field.role == policy.role for field in extensions
        ):
            continue
        width = policy.width
        if width is None and policy.width_of is not None:
            reference = next(field for field in fields if field.role == policy.width_of)
            width = reference.width // policy.width_divisor
        if width is None and policy.width_group == "user":
            width = 3
        assert width is not None
        extension = _field(
            policy.role, policy.direction, width, f"renamed_{policy.role}",
        )
        extensions.append(extension)
        fields.append(extension)

    containers: tuple[PackedInputContainer, ...] = ()
    if packed_inputs:
        cursor = 0
        packed = []
        for field in fields:
            if field.direction != "input":
                packed.append(field)
                continue
            packed.append(replace(
                field, port="renamed_response_bundle", member_path=(field.role,),
                raw_lo=cursor, raw_hi=cursor + field.width - 1,
            ))
            cursor += field.width
        fields = [
            replace(field, container_width=cursor)
            if field.direction == "input" else field
            for field in packed
        ]
        containers = (PackedInputContainer(endpoint, "renamed_response_bundle", cursor, cursor),)
    return (
        ProcessorMemoryBinding(endpoint, function, protocol, tuple(fields), tuple(extensions)),
        containers,
    )


def _ready_valid_memory() -> tuple[ProcessorMemoryBinding, RequestClassification]:
    fields = (
        _field("valid", "output", 1, "mem_valid"),
        _field("ready", "input", 1, "mem_ready"),
        _field("addr", "output", 32, "mem_addr"),
        _field("wdata", "output", 32, "mem_wdata"),
        _field("wstrb", "output", 4, "mem_wstrb"),
        _field("rdata", "input", 32, "mem_rdata"),
        _field("instruction_identity", "output", 1, "mem_instr"),
    )
    memory = ProcessorMemoryBinding(
        "processor.memory.unified", "memory_master", ("ready-valid-memory", "1"),
        fields, (fields[-1],),
    )
    return memory, RequestClassification(
        "explicit_signal", memory.endpoint_id, "instruction_identity", fields[-1], 1, 0,
    )


def _boundary(memory: ProcessorMemoryBinding, containers=()) -> ProcessorBoundary:
    clock = ProcessorControlBinding("processor.clock", "clock", (_field("clock", "input", 1, "clk"),))
    reset = ProcessorControlBinding("processor.reset", "reset", (_field("reset", "input", 1, "rst_n"),))
    return ProcessorBoundary(clock, reset, (memory,), (), tuple(containers))


def _layout(*fields: LayoutField) -> InputLayout:
    return InputLayout("input_layout.v1", sum(field.width for field in fields), fields, "layout")


def _generic_processor_plan(
    catalog, *, module: str = "processor_top", endpoint: str = "processor.memory",
    request_value: str = "1'b1", boot_width: int | None = None,
    duplicate_clock: bool = False, include_reset: bool = True,
    timing_associated: bool = True,
):
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name)
    source = root / "source" / "rtl" / f"{module}.sv"
    source.parent.mkdir(parents=True)
    boot_port = "" if boot_width is None else f", input logic [{boot_width - 1}:0] boot_address"
    behavior = (
        "always_ff @(posedge clk or negedge rst_n) "
        f"if (!rst_n) req <= 1'b0; else req <= {request_value};"
        if timing_associated else f"assign req = {request_value};"
    )
    source.write_text(
        f"module {module}(input logic clk, input logic rst_n, output logic req, "
        "input logic gnt, output logic [31:0] addr, input logic rvalid, "
        f"input logic [31:0] rdata, input logic error, output logic mem_instr{boot_port}); "
        f"{behavior} assign mem_instr = 1'b0; endmodule\n",
        encoding="utf-8",
    )
    adapter_source = root / "src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv"
    adapter_source.parent.mkdir(parents=True)
    adapter_source.write_text(
        (ROOT / "src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )
    endpoints = [
        {"endpoint_id": f"{endpoint}.clock", "function": "clock", "module": module,
         "fields": [{"role": "clock", "aliases": ["clk"]}]},
        {"endpoint_id": endpoint, "function": "processor_memory_master", "module": module,
         "protocol": ["obi", "1"], "fields": [
             {"role": role, "aliases": [role]}
             for role in ("req", "gnt", "addr", "rvalid", "rdata", "error")
         ] + [{"role": "instruction_identity", "aliases": ["mem_instr"]}]},
    ]
    if include_reset:
        endpoints.insert(1, {
            "endpoint_id": f"{endpoint}.reset", "function": "reset", "module": module,
            "fields": [{"role": "reset", "aliases": ["rst_n"]}],
        })
    if duplicate_clock:
        endpoints.insert(1, {
            "endpoint_id": f"{endpoint}.clock.alternate", "function": "clock",
            "module": module, "fields": [{"role": "clock", "aliases": ["clk"]}],
        })
    if boot_width is not None:
        endpoints.append({
            "endpoint_id": f"{endpoint}.boot", "function": "boot_control", "module": module,
            "fields": [{"role": "boot_address", "aliases": ["boot_address"]}],
        })
    description = load_interface_description({
        "schema_version": "interface_description.v1",
        "source": {
            "root": "source",
            "revision": source_tree_hash(root / "source", (source,)),
            "top_module": module,
            "files": [f"rtl/{module}.sv"],
        },
        "endpoints": endpoints,
    })
    try:
        plan = plan_generic_composition(
            GenericCompositionRequest(description, ()), base_dir=root,
            protocol_catalog=catalog,
        )
    except BaseException:
        temporary.cleanup()
        raise
    return temporary, plan


class ProcessorExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = load_protocol_catalog(ROOT / "src/myfuzz/protocols/plugins")

    def test_records_protocol_selected_routes_widths_ports_and_backend_contract(self) -> None:
        selections = []
        for index, protocol in enumerate((("obi", "1"), ("axi4", "1"), ("tl-ul", "1"))):
            memory, containers = _memory(
                protocol, endpoint=f"processor.memory.endpoint_{index}", packed_inputs=True,
            )
            plan = build_processor_execution(
                _boundary(memory, containers), protocol_catalog=self.catalog,
                input_layout=_layout(LayoutField(
                    "control:request", "control", "request", 1, 0, 0, "bits", {},
                    port=f"external_control_{index}", direction="input",
                )),
            )
            document = processor_execution_document(plan)
            route = document["routes"][0]

            self.assertEqual("processor_execution.v1", document["schema_version"])
            self.assertEqual(list(protocol), route["source_protocol"])
            self.assertEqual(["processor-memory-beat", "1"], route["target_protocol"])
            self.assertEqual(32, route["widths"]["address"])
            self.assertEqual(32, route["widths"]["data"])
            self.assertEqual("single_outstanding_request_response", route["backend_contract"]["mode"])
            self.assertEqual(
                {
                    "req_valid": "req_valid_o", "req_ready": "req_ready_i",
                    "write": "req_write_o", "addr": "req_addr_o",
                    "wdata": "req_wdata_o", "be": "req_be_o",
                    "rsp_valid": "rsp_valid_i", "rsp_ready": "rsp_ready_o",
                    "rdata": "rsp_rdata_i", "error": "rsp_error_i",
                },
                {
                    item["field_id"]: item["adapter_port"]
                    for item in route["backend_contract"]["fields"]
                },
            )
            self.assertIn("ADDRESS_WIDTH", route["parameters"])
            self.assertIn("DATA_WIDTH", route["parameters"])
            adapter = resolve_processor_adapter(memory)
            explicit_source_ports = {
                role: port for role, port, _direction in adapter.source_ports
            }
            self.assertEqual(
                explicit_source_ports,
                {
                    item["field_id"]: item["adapter_port"]
                    for item in route["field_connections"]
                },
            )
            input_connection = next(item for item in route["field_connections"] if item["direction"] == "input")
            self.assertEqual("renamed_response_bundle", input_connection["physical"]["container_port"])
            self.assertIn("part_select", input_connection["physical"])
            selections.append((route["adapter_id"], route["rtl_module"], route["rtl_source"]))

        self.assertEqual(
            [
                ("obi-to-processor-memory-beat", "obi_processor_memory_adapter", "src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv"),
                ("axi4-to-processor-memory-beat", "axi4_processor_memory_adapter", "src/myfuzz/protocols/rtl/axi4_processor_memory_adapter.sv"),
                ("tl-ul-to-processor-memory-beat", "tl_ul_processor_memory_adapter", "src/myfuzz/protocols/rtl/tl_ul_processor_memory_adapter.sv"),
            ],
            selections,
        )

    def test_execution_document_contains_explicit_classification(self) -> None:
        memory, classification = _ready_valid_memory()
        plan = build_processor_execution(
            replace(_boundary(memory), classification=classification),
            protocol_catalog=self.catalog,
        )
        document = processor_execution_document(plan)
        self.assertEqual("explicit_signal", document["classification"]["mode"])
        self.assertEqual("instruction_identity", document["classification"]["field_role"])

    def test_rejects_invalid_or_ambiguous_execution_facts(self) -> None:
        memory, containers = _memory(("axi4", "1"), packed_inputs=True)
        cases = []
        cases.append((
            "missing-field",
            _boundary(replace(memory, fields=memory.fields[1:]), containers),
            _layout(),
        ))
        araddr = next(field for field in memory.fields if field.role == "araddr")
        cases.append((
            "width-mismatch",
            _boundary(replace(memory, fields=tuple(
                replace(field, width=31)
                if field is araddr else field for field in memory.fields
            )), containers),
            _layout(),
        ))
        mystery = _field("mystery", "output", 1, "mystery")
        cases.append((
            "unsupported-extension",
            _boundary(replace(
                memory, fields=(*memory.fields, mystery),
                extension_fields=(*memory.extension_fields, mystery),
            ), containers),
            _layout(),
        ))
        cases.append((
            "unsupported-extension",
            _boundary(replace(
                memory, fields=(*memory.fields, mystery),
            ), containers),
            _layout(),
        ))
        cases.append((
            "ambiguous-memory",
            replace(_boundary(memory, containers), memories=(memory, replace(memory, endpoint_id="other"))),
            _layout(),
        ))
        cases.append((
            "incomplete-packed-input",
            _boundary(memory, (replace(containers[0], covered_bits=containers[0].width - 1),)),
            _layout(),
        ))
        driven = next(field for field in memory.fields if field.direction == "input")
        cases.append((
            "duplicate-input-driver",
            _boundary(memory, containers),
            _layout(LayoutField(
                "rfuzz:response", "rfuzz", "response", driven.width, 0,
                driven.width - 1, "bits", {}, port=driven.port, direction="input",
                member_path=driven.member_path, port_raw_lo=driven.raw_lo,
                port_raw_hi=driven.raw_hi, port_width=driven.container_width,
            )),
        ))

        for reason, boundary, layout in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(ProcessorExecutionError, reason):
                build_processor_execution(
                    boundary, protocol_catalog=self.catalog, input_layout=layout,
                )

    def test_generic_plan_embeds_execution_and_adapter_source_name_independently(self) -> None:
        stable_documents = []
        execution_hashes = []
        generic_irs = []
        generic_hashes = []
        for index, (module, endpoint) in enumerate((("first_cpu", "cpu.first"), ("renamed_cpu", "cpu.renamed"))):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source = root / "source" / "rtl" / f"{module}.sv"
                source.parent.mkdir(parents=True)
                source.write_text(
                    f"module {module}(input logic clk, input logic rst_n, output logic req, "
                    "input logic gnt, output logic [31:0] addr, input logic rvalid, "
                    "input logic [31:0] rdata, input logic error, output logic mem_instr); "
                    "always_ff @(posedge clk or negedge rst_n) "
                    "if (!rst_n) req <= 1'b0; else req <= 1'b1; assign mem_instr = 1'b0; endmodule\n",
                    encoding="utf-8",
                )
                adapter_source = root / "src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv"
                adapter_source.parent.mkdir(parents=True)
                adapter_source.write_text(
                    (ROOT / "src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv").read_text(encoding="utf-8"),
                    encoding="utf-8",
                )
                description = load_interface_description({
                    "schema_version": "interface_description.v1",
                    "source": {
                        "root": "source",
                        "revision": source_tree_hash(root / "source", (source,)),
                        "top_module": module,
                        "files": [f"rtl/{module}.sv"],
                    },
                    "endpoints": [
                        {"endpoint_id": f"{endpoint}.clock", "function": "clock", "module": module,
                         "fields": [{"role": "clock", "aliases": ["clk"]}]},
                        {"endpoint_id": f"{endpoint}.reset", "function": "reset", "module": module,
                         "fields": [{"role": "reset", "aliases": ["rst_n"]}]},
                        {"endpoint_id": endpoint, "function": "processor_memory_master", "module": module,
                         "protocol": ["obi", "1"], "fields": [
                             {"role": role, "aliases": [role]}
                             for role in ("req", "gnt", "addr", "rvalid", "rdata", "error")
                         ] + [{"role": "instruction_identity", "aliases": ["mem_instr"]}]},
                    ],
                })
                plan = plan_generic_composition(
                    GenericCompositionRequest(description, ()), base_dir=root,
                    protocol_catalog=self.catalog,
                )
                execution = plan.ir["processor_execution"]
                self.assertIsNotNone(plan.processor_execution)
                self.assertIn(
                    "src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv",
                    plan.source_files,
                )
                self.assertEqual(plan.processor_execution.execution_hash, execution["execution_hash"])
                self.assertEqual(2, len(plan.ir["source_file_ids"]))
                self.assertTrue(plan.ir["capabilities"])
                stable_documents.append(processor_execution_document(plan.processor_execution))
                execution_hashes.append(plan.processor_execution.execution_hash)
                generic_irs.append(plan.ir)
                generic_hashes.append(plan.composition_ir_hash)
                if index == 0:
                    output = root / "published"
                    write_generic_composition(plan, output, base_dir=root)
                    published = output / "processor_execution.v1.json"
                    self.assertTrue(published.is_file())
                    published_document = json.loads(published.read_text(encoding="utf-8"))
                    self.assertEqual("processor_backend.v1", published_document["backend_route"]["schema_version"])
                    self.assertTrue(published_document["source_hashes"])
                    self.assertRegex(published_document["publication_hash"], r"^sha256:[0-9a-f]{64}$")
                    from myfuzz.contracts import content_hash
                    publication_payload = {
                        key: value for key, value in published_document.items()
                        if key != "publication_hash"
                    }
                    self.assertEqual(
                        content_hash(publication_payload),
                        published_document["publication_hash"],
                    )
                    audit = published_document["audit"]
                    self.assertEqual(module, audit["source_top_module"])
                    self.assertEqual("clk", audit["controls"]["clock"]["port"])
                    self.assertEqual("rst_n", audit["controls"]["reset"]["port"])
                    self.assertEqual(
                        {item.endpoint_id for item in description.endpoints},
                        {item["endpoint_id"] for item in audit["endpoints"]},
                    )
                    planning_projection = {
                        key: value for key, value in published_document.items()
                        if key not in {"audit", "backend_route", "source_hashes", "publication_hash"}
                    }
                    self.assertEqual(
                        stable_documents[-1],
                        planning_projection,
                    )

        self.assertEqual(stable_documents[0], stable_documents[1])
        self.assertEqual(execution_hashes[0], execution_hashes[1])
        self.assertEqual(generic_irs[0], generic_irs[1])
        self.assertEqual(generic_hashes[0], generic_hashes[1])

    def test_processor_classification_fails_closed_on_missing_or_ambiguous_timing(self) -> None:
        cases = (
            ("duplicate-clock", {"duplicate_clock": True}),
            ("reset", {"include_reset": False}),
            ("memory-clock", {"timing_associated": False}),
        )
        for reason, options in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                temporary, _plan = _generic_processor_plan(self.catalog, **options)
                temporary.cleanup()

    def test_processor_ir_tracks_control_and_source_evidence(self) -> None:
        temporaries = []
        try:
            for options in ({}, {"request_value": "1'b0"}, {"boot_width": 32}, {"boot_width": 64}):
                temporary, plan = _generic_processor_plan(self.catalog, **options)
                temporaries.append(temporary)
                if options == {}:
                    baseline = plan
                elif options == {"request_value": "1'b0"}:
                    content_changed = plan
                elif options == {"boot_width": 32}:
                    control_32 = plan
                else:
                    control_64 = plan

            self.assertNotEqual(
                baseline.composition_ir_hash, content_changed.composition_ir_hash,
            )
            self.assertNotEqual(
                baseline.ir["source_file_ids"], content_changed.ir["source_file_ids"],
            )
            self.assertNotEqual(control_32.composition_ir_hash, control_64.composition_ir_hash)
        finally:
            for temporary in temporaries:
                temporary.cleanup()

    def test_clocked_mmio_without_processor_timing_association_keeps_legacy_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source" / "rtl" / "clocked_mmio.sv"
            source.parent.mkdir(parents=True)
            source.write_text(
                "module clocked_mmio(input logic clk, input logic rst_n, output logic req, "
                "input logic gnt, output logic [31:0] addr, input logic rvalid, "
                "input logic [31:0] rdata, input logic error); "
                "always_ff @(posedge clk or negedge rst_n) "
                "if (!rst_n) req <= 1'b0; else req <= gnt; endmodule\n",
                encoding="utf-8",
            )
            description = load_interface_description({
                "schema_version": "interface_description.v1",
                "source": {
                    "root": "source",
                    "revision": source_tree_hash(root / "source", (source,)),
                    "top_module": "clocked_mmio",
                    "files": ["rtl/clocked_mmio.sv"],
                },
                "endpoints": [
                    {"endpoint_id": "peripheral.clock", "function": "clock", "module": "clocked_mmio",
                     "fields": [{"role": "clock", "aliases": ["clk"]}]},
                    {"endpoint_id": "peripheral.reset", "function": "reset", "module": "clocked_mmio",
                     "fields": [{"role": "reset", "aliases": ["rst_n"]}]},
                    {"endpoint_id": "peripheral.mmio", "function": "memory_master", "module": "clocked_mmio",
                     "protocol": ["obi", "1"], "fields": [
                         {"role": role, "aliases": [role]}
                         for role in ("req", "gnt", "addr", "rvalid", "rdata", "error")
                     ]},
                ],
            })
            plan = plan_generic_composition(
                GenericCompositionRequest(description, ()), base_dir=root,
                protocol_catalog=self.catalog,
            )

            self.assertIsNone(plan.processor_execution)
            self.assertNotIn("processor_execution", plan.ir)
            mmio = next(item for item in plan.capabilities if item.function == "memory_master")
            self.assertEqual("clk", mmio.clock)
            self.assertEqual("rst_n", mmio.reset)


if __name__ == "__main__":
    unittest.main()
