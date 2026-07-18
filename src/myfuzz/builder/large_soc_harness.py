"""Transaction-paced B/C wrapper emission over the superset RawBits slot ABI."""

from __future__ import annotations

from dataclasses import dataclass

from .experiment_inputs import SupersetInputContract
from .input_model import InputValidationError


@dataclass(frozen=True)
class EmittedLargeSocHarness:
    module_name: str
    rtl: str
    layout_digest: str


def emit_large_soc_transaction_harness(
    soc_module: str,
    contract: SupersetInputContract,
    *,
    module_name: str = "generated_large_soc_harness",
    rom_words: int = 1,
    rom_hex_file: str = "level1_rom.hex",
) -> EmittedLargeSocHarness:
    for value, label in ((soc_module, "soc_module"), (module_name, "module_name")):
        if not value.isidentifier():
            raise InputValidationError(f"{label} must be a Verilog identifier")
    if not rom_hex_file or '"' in rom_hex_file or "\n" in rom_hex_file:
        raise InputValidationError("rom_hex_file must be a non-empty safe Verilog string")
    if isinstance(rom_words, bool) or not isinstance(rom_words, int) or rom_words <= 0:
        raise InputValidationError("rom_words must be a positive integer")
    entries = {entry.target: entry for entry in contract.layout.entries}
    required = {
        "record__ip_select", "record__read_write", "record__offset", "record__data",
        "external__apb_ready", "external__apb_read_data", "external__apb_error",
        "external__fuzz_irq", "external__gpio_input",
    }
    if not required.issubset(entries):
        raise InputValidationError("superset layout is missing a generated-SoC field")

    def raw(target: str) -> str:
        entry = entries[target]
        return f"raw_bits_i[{entry.offset} +: {entry.raw_width}]"

    width = contract.layout.cycle_width
    rtl = f"""module {module_name} #(
  parameter integer ROM_WORDS={rom_words},
  parameter ROM_HEX_FILE="{rom_hex_file}",
  parameter integer MAX_TRANSACTION_CYCLES=1024
) (
  input wire clk_i, input wire resetn_i,
  input wire mode_constrained_i,
  input wire [255:0] layout_digest_i,
  input wire [{width - 1}:0] raw_bits_i,
  input wire raw_bits_valid_i, output wire raw_bits_ready_o, output wire raw_bits_consumed_o,
  input wire [31:0] sequence_i, input wire terminal_capture_ack_i,
  output wire terminal_valid_o, output wire terminal_timed_out_o,
  output wire [31:0] terminal_sequence_o, output wire [7:0] terminal_route_o,
  output wire terminal_read_write_o, output wire [31:0] terminal_address_o,
  output wire [1:0] terminal_response_o, output wire [31:0] terminal_cycles_o,
  output wire cpu_fault_o, output wire recovering_o, output wire [31:0] restart_count_o,
  output wire recovery_error_o, output wire format_error_o
);
  localparam [255:0] EXPECTED_LAYOUT_DIGEST=256'h{contract.layout.digest};
  wire format_ok=layout_digest_i==EXPECTED_LAYOUT_DIGEST;
  wire record_ready;
  wire record_valid=raw_bits_valid_i&&format_ok;
  wire record_fire=record_valid&&record_ready;
  wire [31:0] record_ip_select={raw('record__ip_select')};
  wire record_read_write={raw('record__read_write')};
  wire [31:0] record_offset={raw('record__offset')};
  wire [31:0] record_data={raw('record__data')};
  wire raw_apb_ready={raw('external__apb_ready')};
  wire [31:0] raw_apb_read_data={raw('external__apb_read_data')};
  wire raw_apb_error={raw('external__apb_error')};
  wire [4:0] raw_fuzz_irq={raw('external__fuzz_irq')};
  wire [32:0] raw_gpio_input={raw('external__gpio_input')};
  reg apb_ready,apb_error; reg [31:0] apb_read_data,fuzz_irq,gpio_input;
  wire [31:0] gpio_output; wire gpio_interrupt;
  wire apb_select,apb_enable,apb_write; wire [11:0] apb_address;
  wire [31:0] apb_write_data; wire [3:0] apb_write_strobe;
  wire loader_busy,loader_done,loader_error;

  assign format_error_o=!format_ok;
  assign raw_bits_ready_o=format_ok&&record_ready;
  assign raw_bits_consumed_o=record_fire;

  always @(posedge clk_i or negedge resetn_i) begin
    if (!resetn_i) begin
      apb_ready<=0; apb_read_data<=0; apb_error<=0; fuzz_irq<=0; gpio_input<=0;
    end else if (record_fire) begin
      apb_ready<=raw_apb_ready;
      apb_read_data<=mode_constrained_i&&!raw_apb_ready ? 0 : raw_apb_read_data;
      apb_error<=mode_constrained_i&&!raw_apb_ready ? 0 : raw_apb_error;
      fuzz_irq<=mode_constrained_i ? (32'b1<<raw_fuzz_irq) : {{27'b0,raw_fuzz_irq}};
      if (!mode_constrained_i || raw_gpio_input[32]) gpio_input<=raw_gpio_input[31:0];
    end
  end

  {soc_module} #(.ROM_WORDS(ROM_WORDS),.ROM_HEX_FILE(ROM_HEX_FILE),
    .MAX_TRANSACTION_CYCLES(MAX_TRANSACTION_CYCLES)) i_soc(
    .clk(clk_i),.resetn(resetn_i),.fuzz_irq(fuzz_irq),
    .gpio_input(gpio_input),.gpio_output(gpio_output),.gpio_interrupt(gpio_interrupt),
    .apb_ready(apb_ready),.apb_read_data(apb_read_data),.apb_error(apb_error),
    .apb_select(apb_select),.apb_enable(apb_enable),.apb_write(apb_write),
    .apb_address(apb_address),.apb_write_data(apb_write_data),.apb_write_strobe(apb_write_strobe),
    .record_valid(record_valid),.record_ready(record_ready),.record_sequence(sequence_i),
    .record_ip_select(record_ip_select),.record_read_write(record_read_write),
    .record_offset(record_offset),.record_data(record_data),
    .terminal_capture_ack(terminal_capture_ack_i),.terminal_valid(terminal_valid_o),
    .terminal_timed_out(terminal_timed_out_o),.terminal_sequence(terminal_sequence_o),
    .terminal_route(terminal_route_o),.terminal_read_write(terminal_read_write_o),
    .terminal_address(terminal_address_o),.terminal_response(terminal_response_o),
    .terminal_cycles(terminal_cycles_o),.cpu_fault(cpu_fault_o),
    .loader_busy(loader_busy),.loader_done(loader_done),.loader_error(loader_error),
    .recovering(recovering_o),.restart_count(restart_count_o),.recovery_error(recovery_error_o));
endmodule
"""
    return EmittedLargeSocHarness(module_name, rtl, contract.layout.digest)
