from __future__ import annotations

import unittest

import myfuzz.protocols as protocols
from myfuzz.protocols.bridge import (
    Apb4BridgeModel,
    Axi4LiteBridgeModel,
    BridgeCycle,
    MmioRequest,
    MmioResponse,
    TileLinkUlBridgeModel,
)


class BridgeValueTest(unittest.TestCase):
    def test_bridge_types_are_exported_from_protocol_package(self) -> None:
        self.assertIs(protocols.MmioRequest, MmioRequest)
        self.assertIs(protocols.MmioResponse, MmioResponse)
        self.assertIs(protocols.BridgeCycle, BridgeCycle)
        self.assertIs(protocols.Apb4BridgeModel, Apb4BridgeModel)
        self.assertIs(protocols.Axi4LiteBridgeModel, Axi4LiteBridgeModel)
        self.assertIs(protocols.TileLinkUlBridgeModel, TileLinkUlBridgeModel)
        self.assertTrue(callable(protocols.compile_runtime_protocol))

    def test_value_objects_expose_the_common_mmio_contract(self) -> None:
        request = MmioRequest(0x20, True, 0xA5A5_5A5A, 0b0101)
        response = MmioResponse(True, 0x1234_5678, True)
        cycle = BridgeCycle("idle", {}, False, request, response, None)

        self.assertEqual(request.address, 0x20)
        self.assertTrue(request.write)
        self.assertEqual(request.wdata, 0xA5A5_5A5A)
        self.assertEqual(request.byte_enable, 0b0101)
        self.assertTrue(response.done)
        self.assertEqual(cycle.target_request, request)
        self.assertEqual(cycle.response, response)

    def test_constructor_bounds_are_enforced(self) -> None:
        for model_type in (Apb4BridgeModel, Axi4LiteBridgeModel, TileLinkUlBridgeModel):
            with self.subTest(model=model_type.__name__, case="address_width"):
                with self.assertRaisesRegex(ValueError, "address_width must be positive"):
                    model_type(address_width=0)
            with self.subTest(model=model_type.__name__, case="data_width"):
                with self.assertRaisesRegex(ValueError, "data_width must be positive"):
                    model_type(data_width=0)
            for bound in (0, 17):
                with self.subTest(model=model_type.__name__, max_wait_cycles=bound):
                    with self.assertRaisesRegex(ValueError, "max_wait_cycles must be in 1..16"):
                        model_type(max_wait_cycles=bound)


class Apb4BridgeModelTest(unittest.TestCase):
    def test_setup_precedes_access_and_access_fields_remain_stable(self) -> None:
        model = Apb4BridgeModel()
        request = MmioRequest(0x24, True, 0x1122_3344, 0b0101)

        setup = model.step(request)
        waiting = model.step(target_ready=False)
        still_waiting = model.step(MmioRequest(0x80, False), target_ready=False)
        completed = model.step(target_ready=True, target_error=True, response_ready=False)
        held = model.step(target_ready=False, target_rdata=0xFFFF, response_ready=False)

        self.assertEqual(setup.phase, "setup")
        self.assertEqual(
            setup.protocol_fields,
            {
                "paddr": 0x24,
                "pprot": 0,
                "psel": 1,
                "penable": 0,
                "pwrite": 1,
                "pwdata": 0x1122_3344,
                "pstrb": 0b0101,
                "pready": 0,
                "prdata": 0,
                "pslverr": 0,
            },
        )
        self.assertFalse(setup.target_valid)
        self.assertEqual(waiting.phase, "access")
        self.assertTrue(waiting.target_valid)
        for field in ("paddr", "pprot", "psel", "penable", "pwrite", "pwdata", "pstrb"):
            self.assertEqual(waiting.protocol_fields[field], still_waiting.protocol_fields[field])
        self.assertEqual(completed.response, MmioResponse(done=True, error=True))
        self.assertEqual(completed.error, "APB target error")
        self.assertEqual(held.phase, "response")
        self.assertEqual(held.protocol_fields["psel"], 0)
        self.assertEqual(held.protocol_fields["penable"], 0)
        self.assertEqual(held.protocol_fields["pready"], 0)
        self.assertFalse(held.target_valid)
        self.assertEqual(held.response, completed.response)
        released = model.step(response_ready=True)
        self.assertEqual(released.phase, "response")
        self.assertEqual(released.response, completed.response)
        self.assertEqual(released.protocol_fields["psel"], 0)
        self.assertEqual(released.protocol_fields["penable"], 0)
        self.assertEqual(released.protocol_fields["pready"], 0)
        self.assertEqual(model.step().phase, "idle")

    def test_read_data_is_returned_on_access_completion(self) -> None:
        model = Apb4BridgeModel()
        setup = model.step(MmioRequest(0x10, False, byte_enable=0b1010))

        completed = model.step(target_rdata=0xCAFE_BABE)

        self.assertEqual(setup.protocol_fields["pstrb"], 0)
        self.assertEqual(completed.protocol_fields["pstrb"], 0)
        self.assertEqual(completed.response, MmioResponse(True, 0xCAFE_BABE, False))


class Axi4LiteBridgeModelTest(unittest.TestCase):
    def test_write_address_and_data_handshake_independently(self) -> None:
        model = Axi4LiteBridgeModel()
        request = MmioRequest(0x30, True, 0xDEAD_BEEF, 0b0011)

        aw_wait = model.step(request, target_ready=False)
        aw_done = model.step(MmioRequest(0x88, False), target_ready=True)
        w_wait = model.step(target_ready=False)
        w_held = model.step(MmioRequest(0x8C, True, 0x1234_5678, 0b1100), target_ready=False)
        w_done = model.step(target_ready=True, target_error=True)
        b_wait = model.step(response_ready=False)
        b_held = model.step(target_error=False, response_ready=False)

        self.assertEqual(aw_wait.phase, "write_address")
        self.assertEqual(aw_wait.protocol_fields["awvalid"], 1)
        self.assertEqual(aw_wait.protocol_fields["awaddr"], 0x30)
        self.assertEqual(aw_wait.protocol_fields["wvalid"], 0)
        self.assertEqual(aw_done.protocol_fields["awaddr"], 0x30)
        self.assertEqual(w_wait.phase, "write_data")
        self.assertEqual(w_wait.protocol_fields["wvalid"], 1)
        self.assertEqual(w_wait.protocol_fields["wdata"], 0xDEAD_BEEF)
        self.assertEqual(w_wait.protocol_fields["wstrb"], 0b0011)
        self.assertEqual(w_held.protocol_fields, w_wait.protocol_fields)
        self.assertEqual(w_done.target_request, request)
        self.assertTrue(w_done.target_valid)
        self.assertEqual(b_wait.phase, "write_response")
        self.assertEqual(b_wait.protocol_fields["bvalid"], 1)
        self.assertEqual(b_wait.protocol_fields["bresp"], 2)
        self.assertEqual(b_wait.response, MmioResponse(True, 0, True))
        self.assertEqual(b_wait.error, "AXI write response error")
        self.assertEqual(b_held.protocol_fields, b_wait.protocol_fields)
        self.assertEqual(b_held.response, b_wait.response)
        model.step(response_ready=True)
        self.assertEqual(model.step().phase, "idle")

    def test_read_response_is_held_under_backpressure(self) -> None:
        model = Axi4LiteBridgeModel()
        request = MmioRequest(0x44, False)

        ar_wait = model.step(request, target_ready=False)
        ar_done = model.step(target_ready=True, target_rdata=0x1234_5678)
        r_wait = model.step(response_ready=False)
        r_held = model.step(target_rdata=0, target_error=True, response_ready=False)

        self.assertEqual(ar_wait.phase, "read_address")
        self.assertEqual(ar_wait.protocol_fields["arvalid"], 1)
        self.assertEqual(ar_wait.protocol_fields["araddr"], 0x44)
        self.assertTrue(ar_done.target_valid)
        self.assertEqual(r_wait.phase, "read_response")
        self.assertEqual(r_wait.protocol_fields["rvalid"], 1)
        self.assertEqual(r_wait.protocol_fields["rdata"], 0x1234_5678)
        self.assertEqual(r_wait.protocol_fields["rresp"], 0)
        self.assertEqual(r_held.protocol_fields, r_wait.protocol_fields)
        self.assertEqual(r_held.response, MmioResponse(True, 0x1234_5678, False))


class TileLinkUlBridgeModelTest(unittest.TestCase):
    def test_write_opcode_and_mask_map_to_a_channel(self) -> None:
        full_model = TileLinkUlBridgeModel()
        partial_model = TileLinkUlBridgeModel()

        full = full_model.step(MmioRequest(0x40, True, 0x0102_0304, 0b1111), target_ready=False)
        partial = partial_model.step(MmioRequest(0x40, True, 0x0102_0304, 0b0101), target_ready=False)
        held = partial_model.step(
            MmioRequest(0x80, True, 0xA5A5_5A5A, 0b1010), target_ready=False
        )

        self.assertEqual(full.phase, "a_channel")
        self.assertEqual(full.protocol_fields["a_opcode"], 0)
        self.assertEqual(partial.protocol_fields["a_opcode"], 1)
        self.assertEqual(partial.protocol_fields["a_mask"], 0b0101)
        self.assertEqual(partial.protocol_fields["a_size"], 2)
        self.assertEqual(partial.protocol_fields["a_valid"], 1)
        self.assertEqual(held.protocol_fields, partial.protocol_fields)

    def test_get_response_maps_denied_to_mmio_error_and_is_held(self) -> None:
        model = TileLinkUlBridgeModel()
        request = MmioRequest(0x48, False)

        a_wait = model.step(request, target_ready=False)
        a_done = model.step(target_ready=True, target_rdata=0x89AB_CDEF, target_error=True)
        d_wait = model.step(response_ready=False)
        d_held = model.step(target_error=False, target_rdata=0, response_ready=False)

        self.assertEqual(a_wait.protocol_fields["a_opcode"], 4)
        self.assertEqual(a_wait.protocol_fields["a_mask"], 0b1111)
        self.assertEqual(a_done.target_request, request)
        self.assertEqual(d_wait.phase, "d_channel")
        self.assertEqual(d_wait.protocol_fields["d_opcode"], 1)
        self.assertEqual(d_wait.protocol_fields["d_denied"], 1)
        self.assertEqual(d_wait.protocol_fields["d_data"], 0x89AB_CDEF)
        self.assertEqual(d_wait.response, MmioResponse(True, 0x89AB_CDEF, True))
        self.assertEqual(d_wait.error, "TileLink response denied")
        self.assertEqual(d_held.protocol_fields, d_wait.protocol_fields)
        self.assertEqual(d_held.response, d_wait.response)


class BridgeErrorTest(unittest.TestCase):
    def test_all_models_reject_non_integer_byte_enable_deterministically(self) -> None:
        for model_type in (Apb4BridgeModel, Axi4LiteBridgeModel, TileLinkUlBridgeModel):
            with self.subTest(model=model_type.__name__):
                cycle = model_type().step(
                    MmioRequest(0x04, True, byte_enable="invalid")  # type: ignore[arg-type]
                )

                self.assertEqual(cycle.phase, "error")
                self.assertEqual(
                    cycle.error, "byte_enable must be an integer mask: 'invalid'"
                )
                self.assertEqual(cycle.response, MmioResponse(True, 0, True))

    def test_all_models_reject_invalid_requests_deterministically(self) -> None:
        for model_type in (Apb4BridgeModel, Axi4LiteBridgeModel, TileLinkUlBridgeModel):
            with self.subTest(model=model_type.__name__, case="alignment"):
                cycle = model_type().step(MmioRequest(0x02, False))
                self.assertEqual(cycle.phase, "error")
                self.assertEqual(cycle.error, "misaligned MMIO address: 0x2")
                self.assertEqual(cycle.response, MmioResponse(True, 0, True))
            with self.subTest(model=model_type.__name__, case="byte_enable"):
                cycle = model_type().step(MmioRequest(0x04, True, byte_enable=0x10))
                self.assertEqual(cycle.phase, "error")
                self.assertEqual(cycle.error, "byte_enable exceeds 4 data bytes: 0x10")
                self.assertEqual(cycle.response, MmioResponse(True, 0, True))

    def test_sixteen_wait_cycles_timeout_and_error_is_held(self) -> None:
        for model_type in (Apb4BridgeModel, Axi4LiteBridgeModel, TileLinkUlBridgeModel):
            with self.subTest(model=model_type.__name__):
                model = model_type(max_wait_cycles=16)
                first = model.step(MmioRequest(0x20, False), target_ready=False)
                self.assertNotEqual(first.phase, "error")
                for _ in range(14):
                    waiting = model.step(target_ready=False)
                    self.assertNotEqual(waiting.phase, "error")
                timed_out = model.step(target_ready=False, response_ready=False)
                self.assertEqual(timed_out.phase, "error")
                self.assertEqual(timed_out.error, "protocol timeout after 16 cycles")
                self.assertEqual(timed_out.response, MmioResponse(True, 0, True))
                held = model.step(response_ready=False)
                self.assertEqual(held.error, timed_out.error)
                self.assertEqual(held.response, timed_out.response)

    def test_timeout_clears_immediately_when_error_response_is_ready(self) -> None:
        for model_type in (Apb4BridgeModel, Axi4LiteBridgeModel, TileLinkUlBridgeModel):
            with self.subTest(model=model_type.__name__):
                model = model_type(max_wait_cycles=1)

                timed_out = model.step(MmioRequest(0x20, False), target_ready=False)

                self.assertEqual(timed_out.phase, "error")
                self.assertEqual(model.step().phase, "idle")


if __name__ == "__main__":
    unittest.main()
