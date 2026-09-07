from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from myfuzz.composition import source_elaboration
from myfuzz.composition.source_elaboration import ElaborationError, extract_physical_ports


SOURCE = "/validated/rtl/renamed.sv"


def node(kind: str, address: str, **fields: object) -> dict[str, object]:
    return {"type": kind, "addr": address, **fields}


def fixture() -> tuple[dict[str, object], dict[str, object]]:
    types = [
        node("BASICDTYPE", "(logic)", keyword="logic", loc="s,1:1,1:5", rangep=[]),
        node("BASICDTYPE", "(addr)", keyword="logic", range="12:0", signed=True, loc="s,2:1,2:6", rangep=[]),
        node("BASICDTYPE", "(nibble)", keyword="bit", range="3:0", loc="s,3:1,3:4", rangep=[]),
        node("PACKARRAYDTYPE", "(lanes)", refDTypep="(nibble)", declRange="[1:0]", loc="s,4:1,4:4", rangep=[]),
        node(
            "STRUCTDTYPE", "(request)", packed=True, loc="s,5:1,5:7",
            membersp=[
                node("MEMBERDTYPE", "(valid-member)", name="valid", refDTypep="(logic)", loc="s,5:20,5:25"),
                node("MEMBERDTYPE", "(address-member)", name="address", refDTypep="(addr)", loc="s,5:30,5:37"),
            ],
        ),
        node("REFDTYPE", "(request-ref)", name="request_t", refDTypep="(request)", loc="s,6:1,6:10"),
        node(
            "STRUCTDTYPE", "(bundle)", packed=True, loc="s,7:1,7:7",
            membersp=[
                node("MEMBERDTYPE", "(req-member)", name="req", refDTypep="(request-ref)", loc="s,7:20,7:23"),
                node("MEMBERDTYPE", "(lanes-member)", name="lanes", refDTypep="(lanes)", loc="s,7:30,7:35"),
            ],
        ),
        node("PARAMTYPEDTYPE", "(bundle-param)", name="payload_t", dtypep="(bundle)", loc="s,8:1,8:10"),
        node("REFDTYPE", "(bundle-ref)", name="payload_t", refDTypep="(bundle-param)", loc="s,9:1,9:10"),
    ]
    module = node(
        "MODULE", "(module)", name="renamed_top", loc="s,10:8,10:19",
        stmtsp=[
            node("VAR", "(clk-port)", name="renamed_clock", varType="PORT", isPrimaryIO=True, direction="INPUT", dtypep="(logic)", loc="s,11:15,11:28"),
            node("VAR", "(request-port)", name="renamed_payload", varType="PORT", isPrimaryIO=True, direction="INPUT", dtypep="(bundle-ref)", loc="s,12:25,12:40"),
            node("VAR", "(result-port)", name="renamed_result", varType="PORT", isPrimaryIO=True, direction="OUTPUT", dtypep="(addr)", loc="s,13:26,13:40"),
        ],
    )
    tree = node("NETLIST", "(root)", modulesp=[module], miscsp=[{"typesp": types}])
    metadata = {"files": {"s": {"realpath": SOURCE, "filename": SOURCE}}}
    return tree, metadata


class SourceElaborationTests(unittest.TestCase):
    def test_extracts_parameter_type_nested_struct_and_msb_first_offsets(self) -> None:
        tree, metadata = fixture()

        document = extract_physical_ports(
            tree, metadata, top_module="renamed_top", source_files={SOURCE: "rtl/stable.sv"}
        )

        self.assertEqual("elaborated_ports.v1", document["schema_version"])
        self.assertEqual("renamed_top", document["top_module"])
        self.assertEqual(
            {
                "name": "renamed_payload",
                "direction": "input",
                "width": 22,
                "signed": False,
                "source": {"file": "rtl/stable.sv", "line": 12, "column": 25},
                "members": [
                    {"path": ["req", "valid"], "width": 1, "raw_lo": 21, "raw_hi": 21, "signed": False, "source": {"file": "rtl/stable.sv", "line": 5, "column": 20}},
                    {"path": ["req", "address"], "width": 13, "raw_lo": 8, "raw_hi": 20, "signed": True, "source": {"file": "rtl/stable.sv", "line": 5, "column": 30}},
                    {"path": ["lanes"], "width": 8, "raw_lo": 0, "raw_hi": 7, "signed": False, "source": {"file": "rtl/stable.sv", "line": 7, "column": 30}},
                ],
            },
            document["ports"][1],
        )
        self.assertEqual(("renamed_clock", 1, []), (document["ports"][0]["name"], document["ports"][0]["width"], document["ports"][0]["members"]))
        self.assertEqual(("renamed_result", "output", 13, True), tuple(document["ports"][2][key] for key in ("name", "direction", "width", "signed")))

    def test_missing_range_requires_explicitly_empty_compiler_range_nodes(self) -> None:
        for label, rangep in (("missing", None), ("nonempty", [{"type": "RANGE"}]), ("malformed", "")):
            with self.subTest(label=label):
                tree, metadata = fixture()
                scalar = tree["miscsp"][0]["typesp"][0]
                if rangep is None:
                    scalar.pop("rangep")
                else:
                    scalar["rangep"] = rangep
                with self.assertRaisesRegex(ElaborationError, "range"):
                    extract_physical_ports(tree, metadata, top_module="renamed_top", source_files={SOURCE: "rtl/stable.sv"})

    def test_rejects_each_traversed_type_node_outside_source_allowlist(self) -> None:
        traversed_type_ids = ("(logic)", "(bundle-ref)", "(bundle-param)", "(bundle)", "(request-ref)", "(request)", "(addr)", "(lanes)", "(nibble)")
        for type_id in traversed_type_ids:
            with self.subTest(type_id=type_id):
                tree, metadata = fixture()
                metadata["files"]["external"] = {
                    "realpath": "/compiler/library/external.sv",
                    "filename": "external.sv",
                }
                dtype = next(item for item in tree["miscsp"][0]["typesp"] if item["addr"] == type_id)
                dtype["loc"] = "external,2:3,2:8"
                with self.assertRaisesRegex(ElaborationError, "source mapping"):
                    extract_physical_ports(tree, metadata, top_module="renamed_top", source_files={SOURCE: "rtl/stable.sv"})

    def test_rejects_nested_structure_member_outside_source_allowlist(self) -> None:
        tree, metadata = fixture()
        metadata["files"]["external"] = {
            "realpath": "/compiler/library/external.sv",
            "filename": "external.sv",
        }
        bundle = next(item for item in tree["miscsp"][0]["typesp"] if item["addr"] == "(bundle)")
        bundle["membersp"][0]["loc"] = "external,2:3,2:8"

        with self.assertRaisesRegex(ElaborationError, "source mapping"):
            extract_physical_ports(tree, metadata, top_module="renamed_top", source_files={SOURCE: "rtl/stable.sv"})

    @unittest.skipUnless(shutil.which("verilator"), "verilator is required")
    def test_reads_real_verilator_nested_package_parameter_type(self) -> None:
        source_text = """package physical_types;
  typedef struct packed { logic valid; logic signed [12:0] address; } request_t;
  typedef struct packed { request_t req; bit [1:0][3:0] lanes; } bundle_t;
endpackage
module runtime_top #(parameter type payload_t = physical_types::bundle_t) (
  input logic clk,
  input payload_t request_i,
  output logic [12:0] value_o
);
  assign value_o = request_i.req.address;
endmodule
"""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "typed_ports.sv"
            source.write_text(source_text, encoding="utf-8")
            environment = os.environ.copy()
            environment["JOBS"] = "1"
            completed = subprocess.run(
                (
                    "nice", "-n15", "verilator", "--json-only",
                    "--json-only-output", (root / "ports.json").as_posix(),
                    "--json-only-meta-output", (root / "ports.meta.json").as_posix(),
                    "--top-module", "runtime_top", source.as_posix(),
                ),
                cwd=root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            tree = json.loads((root / "ports.json").read_text(encoding="utf-8"))
            metadata = json.loads((root / "ports.meta.json").read_text(encoding="utf-8"))

            document = extract_physical_ports(
                tree, metadata, top_module="runtime_top", source_files={str(source.resolve()): "rtl/typed_ports.sv"}
            )

        request = document["ports"][1]
        self.assertEqual(22, request["width"])
        self.assertEqual(
            [(["req", "valid"], 21, 21), (["req", "address"], 8, 20), (["lanes"], 0, 7)],
            [(member["path"], member["raw_lo"], member["raw_hi"]) for member in request["members"]],
        )

    def test_total_output_leaf_budget_is_shared_across_ports(self) -> None:
        tree, metadata = fixture()
        duplicate = copy.deepcopy(tree["modulesp"][0]["stmtsp"][1])
        duplicate.update(addr="(request-port-2)", name="second_payload", loc="s,14:25,14:39")
        tree["modulesp"][0]["stmtsp"].append(duplicate)

        with mock.patch.object(source_elaboration, "_MAX_MEMBERS", 5):
            with self.assertRaisesRegex(ElaborationError, "total.*member|member.*total"):
                extract_physical_ports(tree, metadata, top_module="renamed_top", source_files={SOURCE: "rtl/stable.sv"})

    def test_rejects_duplicate_member_names_in_one_structure(self) -> None:
        tree, metadata = fixture()
        request = next(item for item in tree["miscsp"][0]["typesp"] if item["addr"] == "(request)")
        request["membersp"][1]["name"] = "valid"

        with self.assertRaisesRegex(ElaborationError, "duplicate.*member"):
            extract_physical_ports(tree, metadata, top_module="renamed_top", source_files={SOURCE: "rtl/stable.sv"})

    def test_rejects_non_boolean_signed_flags(self) -> None:
        for type_id in ("(logic)", "(bundle)", "(lanes)"):
            with self.subTest(type_id=type_id):
                tree, metadata = fixture()
                dtype = next(item for item in tree["miscsp"][0]["typesp"] if item["addr"] == type_id)
                dtype["signed"] = "false"
                with self.assertRaisesRegex(ElaborationError, "signed"):
                    extract_physical_ports(tree, metadata, top_module="renamed_top", source_files={SOURCE: "rtl/stable.sv"})

    def test_rejects_unresolved_and_cyclic_type_references(self) -> None:
        for label, replacement in (
            ("unresolved", "(missing)"),
            ("cycle", "(bundle-ref)"),
        ):
            with self.subTest(label=label):
                tree, metadata = fixture()
                types = tree["miscsp"][0]["typesp"]
                bundle_ref = next(item for item in types if item["addr"] == "(bundle-ref)")
                bundle_ref["refDTypep"] = replacement
                with self.assertRaisesRegex(ElaborationError, label):
                    extract_physical_ports(tree, metadata, top_module="renamed_top", source_files={SOURCE: "rtl/stable.sv"})

    def test_rejects_unsupported_unpacked_array_union_and_interface(self) -> None:
        for kind in ("UNPACKARRAYDTYPE", "UNIONDTYPE", "IFACEREFDTYPE"):
            with self.subTest(kind=kind):
                tree, metadata = fixture()
                tree["miscsp"][0]["typesp"].append(node(kind, "(bad)", loc="s,20:1,20:2"))
                tree["modulesp"][0]["stmtsp"][0]["dtypep"] = "(bad)"
                with self.assertRaisesRegex(ElaborationError, "unsupported"):
                    extract_physical_ports(tree, metadata, top_module="renamed_top", source_files={SOURCE: "rtl/stable.sv"})

    def test_rejects_bad_range_location_and_missing_source_mapping(self) -> None:
        cases = []
        tree, metadata = fixture()
        tree["miscsp"][0]["typesp"][1]["range"] = "WIDTH-1:0"
        cases.append(("range", tree, metadata, {SOURCE: "rtl/stable.sv"}))
        tree, metadata = fixture()
        tree["modulesp"][0]["stmtsp"][0]["loc"] = "not-a-location"
        cases.append(("location", tree, metadata, {SOURCE: "rtl/stable.sv"}))
        tree, metadata = fixture()
        cases.append(("source mapping", tree, metadata, {}))
        for message, tree, metadata, sources in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ElaborationError, message):
                extract_physical_ports(tree, metadata, top_module="renamed_top", source_files=sources)

    def test_rejects_missing_duplicate_modules_ports_and_type_ids(self) -> None:
        cases = []
        tree, metadata = fixture()
        cases.append(("module", tree, metadata, "absent"))
        tree, metadata = fixture()
        tree["modulesp"].append(copy.deepcopy(tree["modulesp"][0]))
        tree["modulesp"][1]["addr"] = "(module-2)"
        cases.append(("module", tree, metadata, "renamed_top"))
        tree, metadata = fixture()
        tree["modulesp"][0]["stmtsp"].append(copy.deepcopy(tree["modulesp"][0]["stmtsp"][0]))
        tree["modulesp"][0]["stmtsp"][-1]["addr"] = "(duplicate-port)"
        cases.append(("duplicate port", tree, metadata, "renamed_top"))
        tree, metadata = fixture()
        tree["miscsp"][0]["typesp"].append(node("BASICDTYPE", "(logic)", keyword="logic", loc="s,1:1,1:5"))
        cases.append(("duplicate type", tree, metadata, "renamed_top"))
        for message, tree, metadata, top in cases:
            with self.subTest(message=message), self.assertRaisesRegex(ElaborationError, message):
                extract_physical_ports(tree, metadata, top_module=top, source_files={SOURCE: "rtl/stable.sv"})


if __name__ == "__main__":
    unittest.main()
