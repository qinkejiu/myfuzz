from __future__ import annotations

from types import SimpleNamespace
import unittest


class ObiRuntimeContractTests(unittest.TestCase):
    def test_no_error_obi_endpoint_uses_the_shared_shape_without_fabricated_error_pin(self) -> None:
        from myfuzz.local_harness.runtime_renderer import _obi_shape

        endpoint = SimpleNamespace(
            endpoint_id="processor.instruction",
            fields=tuple(SimpleNamespace(
                role=role, direction=direction, width=width,
                port="physical_" + role, raw_lo=0, raw_hi=width - 1,
            ) for role, direction, width in (
                ("req", "output", 1), ("addr", "output", 32),
                ("gnt", "input", 1), ("rvalid", "input", 1),
                ("rdata", "input", 32),
            )),
        )
        abi = tuple({
            "endpoint_id": endpoint.endpoint_id,
            "role": field.role,
            "physical_port": field.port,
            "bit_lo": field.raw_lo,
            "bit_hi": field.raw_hi,
            "width": field.width,
            "direction": field.direction,
            "disposition": "functional",
            "wrapper_name": "cpu_" + field.role,
        } for field in endpoint.fields)

        wires = _obi_shape(endpoint, abi, read_only=True, error_response=False)

        self.assertEqual({"req", "addr", "gnt", "rvalid", "rdata"}, set(wires))
        self.assertEqual("link_cpu_req", wires["req"])

    def test_error_obi_endpoint_retains_its_physical_error_binding(self) -> None:
        from myfuzz.local_harness.runtime_renderer import _obi_shape

        endpoint = SimpleNamespace(
            endpoint_id="processor.instruction",
            fields=tuple(SimpleNamespace(
                role=role, direction=direction, width=width,
                port="physical_" + role, raw_lo=0, raw_hi=width - 1,
            ) for role, direction, width in (
                ("req", "output", 1), ("addr", "output", 32),
                ("gnt", "input", 1), ("rvalid", "input", 1),
                ("rdata", "input", 32), ("error", "input", 1),
            )),
        )
        abi = tuple({
            "endpoint_id": endpoint.endpoint_id,
            "role": field.role,
            "physical_port": field.port,
            "bit_lo": field.raw_lo,
            "bit_hi": field.raw_hi,
            "width": field.width,
            "direction": field.direction,
            "disposition": "functional",
            "wrapper_name": "cpu_" + field.role,
        } for field in endpoint.fields)

        wires = _obi_shape(endpoint, abi, read_only=True, error_response=True)

        self.assertEqual("link_cpu_error", wires["error"])


if __name__ == "__main__":
    unittest.main()
