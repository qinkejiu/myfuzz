import unittest

from myfuzz.builder import (
    ConstraintInterpreter,
    ExperimentInputDecoder,
    build_large_soc_external_contract,
    build_superset_constraint_ir,
    build_superset_input_contract,
    emit_large_flat_soc,
    emit_large_generated_soc,
    emit_large_soc_transaction_harness,
)


class LargeGeneratedSocTest(unittest.TestCase):
    def test_both_cpu_backends_share_external_pin_contract(self):
        for cpu_id in ("picorv32", "ultra_riscv"):
            emitted = emit_large_generated_soc(cpu_id, rom_words=49)
            self.assertEqual(len(emitted.slave_ids) - (3 if cpu_id == "picorv32" else 2), 8)
            self.assertIn("input wire [31:0] gpio_input", emitted.rtl)
            self.assertIn("zipcpu_axilgpio_level1_adapter i_gpio0", emitted.rtl)
            self.assertIn("zipcpu_axil2apb_level1_adapter i_apb0", emitted.rtl)
            self.assertIn("input wire apb_ready", emitted.rtl)

    def test_flat_variants_expose_same_nine_component_boundaries_without_connections(self):
        expected_input_bits = {"picorv32": 799, "ultra_riscv": 934}
        for cpu_id in ("picorv32", "ultra_riscv"):
            flat = emit_large_flat_soc(cpu_id)
            self.assertEqual(flat.instances, (
                "apb0", "cpu0", "dp_ram0", "gpio0", "lfsr0",
                "ram0", "ram1", "regs0", "regs1",
            ))
            self.assertNotIn("fabric", flat.rtl)
            self.assertNotIn("mailbox", flat.rtl)
            self.assertNotIn("level1_external_rom", flat.rtl)
            flat_inputs = tuple(
                {"target": port["name"], "width": port["width"]}
                for port in flat.external_ports if port["direction"] == "input"
            )
            self.assertEqual(sum(item["width"] for item in flat_inputs), expected_input_bits[cpu_id])
            superset = build_superset_input_contract(flat_inputs)
            use = {item.scheme: item for item in superset.scheme_use}
            self.assertEqual(use["flat_random"].used_bits, expected_input_bits[cpu_id])
            self.assertEqual(use["generated_raw"].used_bits, 169)

    def test_external_contract_excludes_access_records_and_changes_only_c_mapping(self):
        contract = build_large_soc_external_contract()
        targets = {entry.target for entry in contract.layout.entries}
        self.assertEqual(targets, {
            "apb_ready", "apb_read_data", "apb_error", "fuzz_irq", "gpio_input",
        })
        self.assertFalse(any("record" in target for target in targets))
        self.assertEqual({item.source for item in contract.report}, {
            "protocol_profile", "cpu_profile", "user_annotation",
        })

        entries = {entry.target: entry for entry in contract.layout.entries}
        raw = 0
        raw |= 0xA5A5A5A5 << entries["apb_read_data"].offset
        raw |= 1 << entries["apb_error"].offset
        raw |= 7 << entries["fuzz_irq"].offset
        raw |= 0x12345678 << entries["gpio_input"].offset
        raw_interpreter = ConstraintInterpreter(contract.layout, contract.constraint_ir)
        constrained_interpreter = ConstraintInterpreter(contract.layout, contract.constraint_ir)
        b = raw_interpreter.step(raw, constrained=False)
        c = constrained_interpreter.step(raw, constrained=True)

        self.assertEqual(b["apb_read_data"], 0xA5A5A5A5)
        self.assertEqual(b["apb_error"], 1)
        self.assertEqual(c["apb_read_data"], 0)
        self.assertEqual(c["apb_error"], 0)
        self.assertEqual(b["fuzz_irq"], 7)
        self.assertEqual(c["fuzz_irq"], 1 << 7)
        self.assertEqual(b["gpio_input"], 0x12345678)
        self.assertEqual(c["gpio_input"], 0)

        update_raw = raw | (1 << (entries["gpio_input"].offset + 32))
        updated = constrained_interpreter.step(update_raw, constrained=True)
        held = constrained_interpreter.step(0, constrained=True)
        self.assertEqual(updated["gpio_input"], 0x12345678)
        self.assertEqual(held["gpio_input"], 0x12345678)

    def test_superset_slot_pairs_records_and_reports_ignored_bits(self):
        contract = build_superset_input_contract((
            {"target": "cpu_axi_response", "width": 67},
            {"target": "gpio_axi_request", "width": 71},
        ))
        entries = {entry.target: entry for entry in contract.layout.entries}

        def put(value, target, payload):
            entry = entries[target]
            return value | ((payload & ((1 << entry.raw_width) - 1)) << entry.offset)

        raw = 0
        raw = put(raw, "record__ip_select", 6)
        raw = put(raw, "record__read_write", 1)
        raw = put(raw, "record__offset", 9)
        raw = put(raw, "record__data", 0xDEADBEEF)
        raw = put(raw, "external__apb_ready", 0)
        raw = put(raw, "external__apb_read_data", 0x12345678)
        raw = put(raw, "flat__cpu_axi_response", 0x55)
        raw = put(raw, "flat__gpio_axi_request", 0x66)

        raw_decoder = ExperimentInputDecoder(contract)
        constrained_decoder = ExperimentInputDecoder(contract)
        a = raw_decoder.decode(raw, sequence=12, scheme="flat_random")
        b = raw_decoder.decode(raw, sequence=12, scheme="generated_raw")
        c = constrained_decoder.decode(raw, sequence=12, scheme="generated_constrained")
        self.assertIsNone(a.access_record)
        self.assertEqual(a.flat_inputs, {"cpu_axi_response": 0x55, "gpio_axi_request": 0x66})
        self.assertEqual(b.access_record, c.access_record)
        self.assertEqual(b.access_record.to_dict(), {
            "ip_select": 6, "read_write": 1, "offset": 9, "data": 0xDEADBEEF,
            "schema": "myfuzz.access-record/v1",
        })
        self.assertEqual(b.external_inputs["apb_read_data"], 0x12345678)
        self.assertEqual(c.external_inputs["apb_read_data"], 0)

        use = {item.scheme: item for item in contract.scheme_use}
        self.assertEqual(use["generated_raw"].used_mask, use["generated_constrained"].used_mask)
        self.assertEqual(use["flat_random"].used_bits, 138)
        self.assertEqual(use["generated_raw"].used_bits, 169)
        self.assertEqual(use["flat_random"].used_mask & use["generated_raw"].used_mask, 0)
        lifted = build_superset_constraint_ir(contract)
        constraints = {item["target"]: item for item in lifted.constraints}
        self.assertEqual(constraints["record__data"]["primitive"], "DIRECT")
        self.assertEqual(constraints["flat__cpu_axi_response"]["primitive"], "DIRECT")
        self.assertEqual(constraints["external__apb_read_data"]["source"],
                         "external__apb_ready")

    def test_transaction_harness_is_one_rtl_for_b_and_c(self):
        contract = build_superset_input_contract(({"target": "flat_pin", "width": 1},))
        emitted = emit_large_soc_transaction_harness("my_soc", contract, rom_words=49)
        self.assertIn("parameter integer ROM_WORDS=49", emitted.rtl)
        self.assertIn("input wire mode_constrained_i", emitted.rtl)
        self.assertIn("wire record_fire=record_valid&&record_ready", emitted.rtl)
        self.assertIn("apb_read_data<=mode_constrained_i&&!raw_apb_ready ? 0", emitted.rtl)
        self.assertIn("fuzz_irq<=mode_constrained_i ? (32'b1<<raw_fuzz_irq)", emitted.rtl)
        self.assertIn("if (!mode_constrained_i || raw_gpio_input[32])", emitted.rtl)
        self.assertEqual(emitted.layout_digest, contract.layout.digest)


if __name__ == "__main__":
    unittest.main()
