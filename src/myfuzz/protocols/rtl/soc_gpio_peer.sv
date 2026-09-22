// Generic external GPIO peer for a profile-driven SoC harness.
//
// The peer models one bidirectional pin per bit: the value the environment
// drives, the value the component drives, the direction the component declares
// and the electrical resolution of the resulting line.  Nothing in this file
// selects behaviour by component or model name: the pin count, the level of a
// pin nobody drives and the error treatment of a contention are parameters, and
// an out-of-range parameterization is rejected at time 0 with $fatal.
//
// Port convention
//   peer_drive_valid_i   1 = the peer drives this pin, 0 = the peer is high
//                        impedance on it.
//   peer_drive_value_i   the value the peer drives.
//   component_out_i      the component's pin output value.
//   component_dir_i      the component's pin direction, 1 = the component
//                        drives the pin, 0 = the component is high impedance.
//   pin_o                the resolved line, presented to the component pin
//                        input.  It is combinational on purpose: a wire has no
//                        clock, and a component has to see a drive change in the
//                        cycle it happens.  A component with a combinational
//                        path from its pin input back to its pin output would
//                        close a loop through this model.
//   pin_value_o          the resolved line registered on clk_i (observation).
//   direction_o          component_dir_i registered on clk_i.
//   contention_o         per-pin contention flag registered on clk_i: the pin is
//                        contended when both sides drive it and drive opposite
//                        values.
//   contention_count_o   one count per pin that enters contention.  A pin that
//                        stays in contention for many cycles counts once, and
//                        two pins that enter contention in the same cycle count
//                        twice.
//   contention_error_o   sticky flag, set on the first contention event when
//                        CONTENTION_IS_ERROR is non-zero and cleared only by
//                        reset.  The model never calls $fatal at run time, so
//                        the policy decision stays with the environment.
//
// Resolution (per pin)
//   peer high-Z, component high-Z  -> DEFAULT_INPUT_LEVEL
//   peer drives, component high-Z  -> the peer value
//   component drives, peer high-Z  -> the component value, read back to it
//   both drive the same value      -> that value, and it is not a contention
//   both drive opposite values     -> contention: contention_o marks the pin,
//                                     contention_count_o counts the event, and
//                                     the resolved level is CONTENTION_LEVEL,
//                                     a driven low (0).  It is a defined level,
//                                     never X.
module soc_gpio_peer #(
    parameter integer PINS = 1,                  // number of pins, >= 1
    parameter integer DEFAULT_INPUT_LEVEL = 0,   // level of an undriven pin, 0 or 1
    parameter integer CONTENTION_IS_ERROR = 0    // 1 = a contention event raises contention_error_o
) (
    input  logic             clk_i,
    input  logic             rst_ni,
    input  logic [PINS-1:0]  peer_drive_valid_i,
    input  logic [PINS-1:0]  peer_drive_value_i,
    input  logic [PINS-1:0]  component_out_i,
    input  logic [PINS-1:0]  component_dir_i,
    output logic [PINS-1:0]  pin_o,
    output logic [PINS-1:0]  pin_value_o,
    output logic [PINS-1:0]  direction_o,
    output logic [PINS-1:0]  contention_o,
    output logic [31:0]     contention_count_o,
    output logic             contention_error_o
);
  localparam logic DEFAULT_LEVEL = (DEFAULT_INPUT_LEVEL == 0) ? 1'b0 : 1'b1;
  // A driven low wins a contention: a defined level, never X.
  localparam logic CONTENTION_LEVEL = 1'b0;
  localparam logic [PINS-1:0] CONTENTION_VECTOR = {PINS{CONTENTION_LEVEL}};
  localparam logic [PINS-1:0] DEFAULT_VECTOR = {PINS{DEFAULT_LEVEL}};

  logic [PINS-1:0] contended_w;
  logic [PINS-1:0] agreed_w;
  logic [PINS-1:0] resolved_w;
  logic [PINS-1:0] contention_rise_w;
  logic [31:0]     rise_count_w;

  integer pin_index;

  initial begin
    if ((PINS < 1) ||
        ((DEFAULT_INPUT_LEVEL != 0) && (DEFAULT_INPUT_LEVEL != 1)) ||
        ((CONTENTION_IS_ERROR != 0) && (CONTENTION_IS_ERROR != 1)))
      $fatal(1, "invalid soc_gpio_peer parameters");
  end

  assign contended_w = peer_drive_valid_i & component_dir_i &
                       (peer_drive_value_i ^ component_out_i);

  // The value a pin carries when it is not contended: the peer's drive when the
  // peer drives, otherwise the component's drive, otherwise the declared
  // default level of a pin nobody drives.
  assign agreed_w = (peer_drive_valid_i & peer_drive_value_i) |
                    (component_dir_i & component_out_i) |
                    (~(peer_drive_valid_i | component_dir_i) & DEFAULT_VECTOR);

  assign resolved_w = (contended_w & CONTENTION_VECTOR) |
                      (~contended_w & agreed_w);
  assign pin_o = resolved_w;

  assign contention_rise_w = contended_w & ~contention_o;

  always_comb begin
    rise_count_w = 32'd0;
    for (pin_index = 0; pin_index < PINS; pin_index = pin_index + 1)
      if (contention_rise_w[pin_index])
        rise_count_w = rise_count_w + 32'd1;
  end

  always_ff @(posedge clk_i) begin
    if (!rst_ni) begin
      pin_value_o <= {PINS{1'b0}};
      direction_o <= {PINS{1'b0}};
      contention_o <= {PINS{1'b0}};
      contention_count_o <= '0;
      contention_error_o <= 1'b0;
    end else begin
      pin_value_o <= resolved_w;
      direction_o <= component_dir_i;
      contention_o <= contended_w;
      if (contention_rise_w != 0) begin
        contention_count_o <= contention_count_o + rise_count_w;
        if (CONTENTION_IS_ERROR != 0)
          contention_error_o <= 1'b1;
      end
    end
  end
endmodule
