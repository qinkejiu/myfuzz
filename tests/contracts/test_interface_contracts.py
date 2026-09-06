from __future__ import annotations

import unittest

from myfuzz.contracts import ContractError, validate_contract


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

    def test_unknown_members_are_forward_compatible(self) -> None:
        document = valid_interface_document()
        document["future_member"] = {"wire_version": 2}
        document["endpoints"][0]["future_member"] = True  # type: ignore[index]

        validate_contract(document, "interface_description.v1")


if __name__ == "__main__":
    unittest.main()
