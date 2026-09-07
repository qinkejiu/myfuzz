from __future__ import annotations

import copy
import unittest

from myfuzz.composition.processor_backend import (
    ProcessorBackendError,
    build_processor_backend,
    processor_backend_document,
)


def _route(route_id: int, function: str, *, read_only: bool = False) -> dict[str, object]:
    parameters = {"ADDRESS_WIDTH": 32, "DATA_WIDTH": 32}
    if read_only:
        parameters.update({"READ_ONLY": 1, "HAS_BE": 0, "HAS_ERROR": 1})
    return {
        "route_id": route_id,
        "function": function,
        "source_protocol": ["obi", "1"],
        "target_protocol": ["processor-memory-beat", "1"],
        "adapter_id": "obi-to-processor-memory-beat",
        "rtl_module": "obi_processor_memory_adapter",
        "rtl_source": "src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv",
        "parameters": parameters,
        "widths": {"address": 32, "data": 32},
        "field_connections": [],
        "extension_policies": [],
        "backend_contract": {
            "mode": "single_outstanding_request_response",
            "protocol": ["processor-memory-beat", "1"],
            "fields": [],
            "capabilities": {
                "max_outstanding": 1,
                "byte_enable": True,
                "partial_write": True,
                "stall_supported": True,
                "completion": "ack_or_err",
                "max_wait_cycles": 16,
                "ordering": "in_order_single_id",
            },
        },
    }


def _execution(*routes: dict[str, object]) -> dict[str, object]:
    return {
        "schema_version": "processor_execution.v1",
        "adapter_sources": ["src/myfuzz/protocols/rtl/obi_processor_memory_adapter.sv"],
        "routes": list(routes),
        "execution_hash": "sha256:" + "1" * 64,
    }


REGIONS = [
    {"region_id": 22, "component_id": "uart0", "base": 0x2000,
     "size": 0x100, "end": 0x2100, "address_width": 32},
    {"region_id": 11, "component_id": "ram0", "base": 0,
     "size": 0x1000, "end": 0x1000, "address_width": 32},
]


class ProcessorBackendTests(unittest.TestCase):
    def test_single_route_is_direct_and_preserves_allocated_decode_windows(self) -> None:
        plan = build_processor_backend(
            _execution(_route(91, "processor_memory_master")), REGIONS
        )
        document = processor_backend_document(plan)

        self.assertEqual("processor_backend.v1", document["schema_version"])
        self.assertEqual("direct", document["routing"]["mode"])
        self.assertEqual([], document["rtl_sources"])
        self.assertEqual([91], [item["route_id"] for item in document["initiators"]])
        self.assertEqual(
            [("ram0", 0, 0x1000), ("uart0", 0x2000, 0x2100)],
            [(item["component_id"], item["base"], item["end"])
             for item in document["address_decode"]["regions"]],
        )
        self.assertEqual(
            {"completion": "error", "rdata": 0, "side_effect": False},
            document["address_decode"]["unmapped"],
        )
        self.assertRegex(document["backend_hash"], r"^sha256:[0-9a-f]{64}$")

    def test_split_routes_use_fair_arbiter_and_reject_instruction_writes(self) -> None:
        plan = build_processor_backend(
            _execution(
                _route(80, "instruction_memory_master", read_only=True),
                _route(40, "data_memory_master"),
            ),
            REGIONS,
        )
        document = processor_backend_document(plan)

        self.assertEqual("round_robin", document["routing"]["mode"])
        self.assertEqual(
            {"polarity": "active_low", "synchrony": "asynchronous"},
            document["routing"]["backend_reset_contract"],
        )
        self.assertEqual("processor_memory_arbiter", document["routing"]["rtl_module"])
        self.assertEqual(
            "src/myfuzz/protocols/rtl/processor_memory_arbiter.sv",
            document["routing"]["rtl_source"],
        )
        self.assertEqual(
            {"polarity": "active_low", "synchrony": "asynchronous"},
            document["routing"]["reset_contract"],
        )
        self.assertEqual(
            ["src/myfuzz/protocols/rtl/processor_memory_arbiter.sv"],
            document["rtl_sources"],
        )
        self.assertEqual(
            ["data_memory_master", "instruction_memory_master"],
            [item["function"] for item in document["initiators"]],
        )
        instruction = document["initiators"][1]
        self.assertEqual("read_only", instruction["access"])
        self.assertEqual("error_without_backend_request", instruction["write_policy"])
        self.assertEqual(
            {
                "max_wait_cycles": 16,
                "completion": "single_error",
                "cancellation": {
                    "valid": "cancel_valid_o",
                    "ready": "cancel_ready_i",
                    "scope": "all_preceding_accepted_requests",
                    "acknowledgment": "no_response_after_handshake",
                },
                "timeout": {
                    "accepted_request": "cancel_or_drain_before_reuse",
                    "late_response_before_cancel_ack": "discard",
                },
                "reset": {
                    "initiator_completion": "none",
                    "backend": "cancel_all_pre_reset_requests",
                    "release": "after_cancel_ack",
                },
            },
            document["recovery"],
        )

    def test_document_and_hash_are_independent_of_route_and_region_input_order(self) -> None:
        first = processor_backend_document(build_processor_backend(
            _execution(_route(80, "instruction_memory_master", read_only=True),
                       _route(40, "data_memory_master")), REGIONS,
        ))
        second = processor_backend_document(build_processor_backend(
            _execution(_route(40, "data_memory_master"),
                       _route(80, "instruction_memory_master", read_only=True)),
            list(reversed(REGIONS)),
        ))
        self.assertEqual(first, second)

    def test_rejects_incompatible_routes_and_overlapping_or_invalid_regions(self) -> None:
        cases: list[tuple[str, dict[str, object], list[dict[str, object]]]] = []
        width_mismatch = _execution(
            _route(40, "data_memory_master"),
            _route(80, "instruction_memory_master", read_only=True),
        )
        width_mismatch["routes"][1]["widths"]["data"] = 64
        cases.append(("width-mismatch", width_mismatch, REGIONS))

        writable_instruction = _execution(
            _route(40, "data_memory_master"),
            _route(80, "instruction_memory_master"),
        )
        cases.append(("instruction-write-policy", writable_instruction, REGIONS))

        overlap = copy.deepcopy(REGIONS)
        overlap[0].update({"base": 0x800, "end": 0x900})
        cases.append(("address-overlap", _execution(_route(91, "memory_master")), overlap))

        invalid_end = copy.deepcopy(REGIONS)
        invalid_end[0]["end"] = 0x2200
        cases.append(("address-region", _execution(_route(91, "memory_master")), invalid_end))

        for reason, execution, regions in cases:
            with self.subTest(reason=reason), self.assertRaisesRegex(
                ProcessorBackendError, reason
            ):
                build_processor_backend(execution, regions)


if __name__ == "__main__":
    unittest.main()
