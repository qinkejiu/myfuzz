from __future__ import annotations

import unittest
import copy
import json
from pathlib import Path

from myfuzz.contracts import ContractError, validate_contract

try:
    from jsonschema import Draft202012Validator
except ImportError:
    Draft202012Validator = None


def valid_annotation_document() -> dict[str, object]:
    return {
        "schema_version": "interface_annotations.v1",
        "source": {"revision": "git:" + "a" * 40, "content_hash": "sha256:" + "b" * 64,
                   "files": ["rtl/top.sv"], "modules": ["top"]},
        "endpoints": [{
            "endpoint_id": "bus", "function": "memory_master", "module": "top",
            "clock": "clk", "reset": None,
            "fields": [{"role": "valid", "port": "q", "direction": "output", "width": 1,
                        "signed": False, "source": {"file": "rtl/top.sv", "line": 2, "column": 3},
                        "evidence": ["explicit_alias", "hdl_declaration"], "confidence": "high"}],
            "timing": [{"kind": "sequential_assignment", "fields": ["valid"], "clock": "clk",
                        "source": {"file": "rtl/top.sv", "line": 5}}],
            "protocol_candidates": [{"id": "bus", "version": "1", "status": "consistent",
                                     "orientation": "host", "evidence": "declared"}],
            "evidence": ["explicit_module"], "confidence": "high", "diagnostics": [],
        }],
        "diagnostics": [{"code": "source-note", "severity": "info", "message": "Observed source."}],
    }


# Known members have a closed value contract; only additional members are open.
ANNOTATION_MUTATIONS = (
    (("source", "files"), [False]), (("source", "files"), ["../escape"]),
    (("source", "files"), []), (("source", "modules"), [3]),
    (("source", "modules"), []), (("source", "revision"), "git:main"),
    (("source", "content_hash"), "invalid"),
    (("endpoints", 0, "clock"), 7), (("endpoints", 0, "reset"), ""),
    (("endpoints", 0, "fields", 0, "role"), False),
    (("endpoints", 0, "fields", 0, "port"), ""),
    (("endpoints", 0, "fields", 0, "direction"), []),
    (("endpoints", 0, "fields", 0, "width"), True),
    (("endpoints", 0, "fields", 0, "width"), 0),
    (("endpoints", 0, "fields", 0, "signed"), "false"),
    (("endpoints", 0, "fields", 0, "source", "line"), True),
    (("endpoints", 0, "fields", 0, "source", "column"), 0),
    (("endpoints", 0, "timing"), "wrong"),
    (("endpoints", 0, "timing"), [{}]),
    (("endpoints", 0, "timing", 0, "kind"), "guessed"),
    (("endpoints", 0, "timing", 0, "fields"), [5]),
    (("endpoints", 0, "timing", 0, "clock"), False),
    (("endpoints", 0, "timing", 0, "source", "file"), "../outside"),
    (("endpoints", 0, "timing", 0, "source", "line"), 0),
    (("endpoints", 0, "protocol_candidates"), "wrong"),
    (("endpoints", 0, "protocol_candidates"), [{}]),
    (("endpoints", 0, "protocol_candidates", 0, "id"), ""),
    (("endpoints", 0, "protocol_candidates", 0, "version"), 1),
    (("endpoints", 0, "protocol_candidates", 0, "status"), "unverified"),
    (("endpoints", 0, "protocol_candidates", 0, "orientation"), "unknown"),
    (("endpoints", 0, "protocol_candidates", 0, "evidence"), []),
    (("endpoints", 0, "evidence"), []),
    (("endpoints", 0, "evidence"), "explicit_module"),
    (("endpoints", 0, "evidence"), ["guessed"]),
    (("endpoints", 0, "fields", 0, "evidence"), [False]),
    (("endpoints", 0, "fields", 0, "evidence"), []),
    (("endpoints", 0, "confidence"), "certain"),
    (("endpoints", 0, "fields", 0, "confidence"), 1.0),
    (("endpoints", 0, "diagnostics"), [False]),
    (("diagnostics",), "wrong"), (("diagnostics",), [{}]),
    (("diagnostics", 0, "severity"), "fatal"),
    (("diagnostics", 0, "code"), ""), (("diagnostics", 0, "message"), []),
)


def mutated_annotation(path, value):
    document = valid_annotation_document()
    target = document
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    return document


class AnnotationContractTests(unittest.TestCase):
    def test_malformed_annotation_known_members_fail_runtime_validation(self) -> None:
        for path, value in ANNOTATION_MUTATIONS:
            with self.subTest(path=path, value=value):
                with self.assertRaises(ContractError):
                    validate_contract(mutated_annotation(path, value), "interface_annotations.v1")

    def test_nested_required_annotation_members_cannot_be_omitted(self) -> None:
        document = valid_annotation_document()
        for path in (("source",), ("endpoints", 0), ("endpoints", 0, "fields", 0),
                     ("endpoints", 0, "fields", 0, "source"), ("endpoints", 0, "timing", 0),
                     ("endpoints", 0, "timing", 0, "source"),
                     ("endpoints", 0, "protocol_candidates", 0), ("diagnostics", 0)):
            original = document
            for part in path:
                original = original[part]
            for key in original:
                with self.subTest(path=path, missing=key):
                    changed = copy.deepcopy(original)
                    del changed[key]
                    with self.assertRaises(ContractError):
                        validate_contract(mutated_annotation(path, changed), "interface_annotations.v1")

    def test_annotations_validate_source_references_and_unique_mappings(self) -> None:
        for path, value in (
            (("endpoints", 0, "module"), "absent"),
            (("endpoints", 0, "fields", 0, "source", "file"), "absent.sv"),
            (("endpoints", 0, "timing", 0, "source", "file"), "absent.sv"),
        ):
            with self.subTest(path=path):
                with self.assertRaises(ContractError):
                    validate_contract(mutated_annotation(path, value), "interface_annotations.v1")
        for array_path in (("endpoints",), ("endpoints", 0, "fields")):
            document = valid_annotation_document()
            target = document
            for part in array_path:
                target = target[part]
            target.append(copy.deepcopy(target[0]))
            with self.subTest(path=array_path):
                with self.assertRaises(ContractError):
                    validate_contract(document, "interface_annotations.v1")

    def test_annotations_accept_valid_values_and_unknown_members(self) -> None:
        document = valid_annotation_document()
        for target in (document, document["source"], document["endpoints"][0],
                       document["endpoints"][0]["fields"][0], document["endpoints"][0]["timing"][0],
                       document["endpoints"][0]["protocol_candidates"][0], document["diagnostics"][0]):
            target["future_member"] = {"arbitrary": True}
        validate_contract(document, "interface_annotations.v1")

    @unittest.skipIf(Draft202012Validator is None, "optional jsonschema package unavailable")
    def test_json_schema_enforces_nested_annotation_contract(self) -> None:
        schema = json.loads((Path(__file__).resolve().parents[2] / "schemas" /
                             "interface_annotations.v1.schema.json").read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        validator.validate(valid_annotation_document())
        for path, value in ANNOTATION_MUTATIONS:
            with self.subTest(path=path, value=value):
                self.assertTrue(list(validator.iter_errors(mutated_annotation(path, value))))


def valid_interface_document() -> dict[str, object]:
    return {
        "schema_version": "interface_description.v1",
        "source": {
            "root": "third_party/cpu",
            "revision": "sha256:" + "a" * 64,
            "top_module": "cpu_top",
            "files": ["rtl/top.sv", "rtl/bus.sv"],
            "filelist": "rtl/files.f",
            "include_roots": ["rtl/include"],
        },
        "endpoints": [{
            "endpoint_id": "cpu.memory_master",
            "function": "memory_master",
            "module": "cpu_top",
            "hierarchy": ["core", "data_bus"],
            "aliases": ["data_master"],
            "protocol": ["ready-valid-mmio", "1"],
            "fields": [
                {"role": "address", "aliases": ["opaque_addr"]},
                {"role": "write_data", "required": False},
            ],
        }],
    }


class InterfaceContractTests(unittest.TestCase):
    @unittest.skipIf(Draft202012Validator is None, "optional jsonschema package unavailable")
    def test_warning_policy_schema_matches_runtime_for_explicit_fatal(self) -> None:
        schema = json.loads((Path(__file__).resolve().parents[2] / "schemas/interface_description.v1.schema.json").read_text())
        validator = Draft202012Validator(schema)
        for policy in ("fatal", "recorded-nonfatal"):
            document = valid_interface_document()
            document["source"]["elaboration"] = {"frontend": "verilator-json", "warning_policy": policy}
            validate_contract(document, "interface_description.v1")
            assert not list(validator.iter_errors(document))

    def test_member_annotation_requires_complete_range_and_compiler_evidence(self) -> None:
        mutations = (
            {"raw_lo": 0, "raw_hi": 0, "container_width": 1},
            {"member_path": ["data"], "raw_lo": 0, "raw_hi": 0, "container_width": 1,
             "evidence": ["explicit_member"]},
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                document = valid_annotation_document()
                document["endpoints"][0]["fields"][0].update(mutation)
                with self.assertRaises(ContractError):
                    validate_contract(document, "interface_annotations.v1")

    def test_direction_width_and_timing_are_not_required_in_input(self) -> None:
        document = {
            "schema_version": "interface_description.v1",
            "source": {
                "root": "third_party/cpu",
                "revision": "sha256:" + "a" * 64,
                "top_module": "cpu_top",
            },
            "endpoints": [{
                "endpoint_id": "cpu.memory_master",
                "function": "memory_master",
                "fields": [{"role": "address", "aliases": ["opaque_addr"]}],
            }],
        }

        validate_contract(document, "interface_description.v1")

    def test_missing_revision_is_rejected(self) -> None:
        document = valid_interface_document()
        del document["source"]["revision"]  # type: ignore[index]

        with self.assertRaisesRegex(
            ContractError,
            r"^interface_description\.v1:source:revision:missing$",
        ):
            validate_contract(document, "interface_description.v1")

    def test_full_git_revision_is_accepted_and_malformed_git_revisions_are_rejected(self) -> None:
        document = valid_interface_document()
        document["source"]["revision"] = "git:" + "a" * 40  # type: ignore[index]

        validate_contract(document, "interface_description.v1")

        for revision in ("git:" + "a" * 39, "git:" + "a" * 41, "git:main"):
            with self.subTest(revision=revision):
                document = valid_interface_document()
                document["source"]["revision"] = revision  # type: ignore[index]

                with self.assertRaisesRegex(
                    ContractError,
                    r"^interface_description\.v1:source:revision:invalid-hash$",
                ):
                    validate_contract(document, "interface_description.v1")

    def test_duplicate_endpoint_id_and_field_role_are_rejected(self) -> None:
        document = valid_interface_document()
        document["endpoints"].append(dict(document["endpoints"][0]))  # type: ignore[index]
        with self.assertRaisesRegex(
            ContractError,
            r"^interface_description\.v1:endpoints\[1\]:endpoint_id:duplicate-role$",
        ):
            validate_contract(document, "interface_description.v1")

        document = valid_interface_document()
        document["endpoints"][0]["fields"].append({"role": "address"})  # type: ignore[index]
        with self.assertRaisesRegex(
            ContractError,
            r"^interface_description\.v1:endpoints\[0\]:fields\[2\]:role:duplicate-role$",
        ):
            validate_contract(document, "interface_description.v1")

    def test_invalid_source_paths_and_empty_functions_are_rejected(self) -> None:
        document = valid_interface_document()
        document["source"]["root"] = "../cpu"  # type: ignore[index]
        with self.assertRaisesRegex(
            ContractError,
            r"^interface_description\.v1:source:root:invalid-path$",
        ):
            validate_contract(document, "interface_description.v1")

        document = valid_interface_document()
        document["endpoints"][0]["function"] = ""  # type: ignore[index]
        with self.assertRaisesRegex(
            ContractError,
            r"^interface_description\.v1:endpoints\[0\]:function:type$",
        ):
            validate_contract(document, "interface_description.v1")

    def test_drive_qualified_source_paths_are_rejected(self) -> None:
        for key in ("root", "files", "filelist", "include_roots"):
            with self.subTest(key=key):
                document = valid_interface_document()
                if key in ("files", "include_roots"):
                    document["source"][key] = ["C:/outside/source"]  # type: ignore[index]
                    path_pattern = rf"source:{key}\[0\]"
                else:
                    document["source"][key] = "C:/outside/source"  # type: ignore[index]
                    path_pattern = f"source:{key}"

                with self.assertRaisesRegex(
                    ContractError,
                    rf"^interface_description\.v1:{path_pattern}:invalid-path$",
                ):
                    validate_contract(document, "interface_description.v1")

    def test_unknown_members_are_forward_compatible(self) -> None:
        document = valid_interface_document()
        document["future_member"] = {"wire_version": 2}
        document["endpoints"][0]["future_member"] = True  # type: ignore[index]

        validate_contract(document, "interface_description.v1")


if __name__ == "__main__":
    unittest.main()
