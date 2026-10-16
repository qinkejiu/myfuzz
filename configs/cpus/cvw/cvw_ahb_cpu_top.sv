// cvw_ahb_cpu_top: a typed top for CVW's AHB-Lite CPU boundary.
//
// WHY THIS FILE EXISTS
//   CVW's core modules take `parameter cvw_t P`, and `P` is built by
//   `config/shared/parameter-defs.vh` as `localparam cvw_t P = '{...}` out of the
//   selected configuration headers.  A struct-typed parameter cannot be overridden
//   from a Verilator command line, so there is no way to elaborate the real
//   boundary without a module that includes the headers and instantiates the core
//   with that localparam.  This is that module.
//
// THIS IS NOT UPSTREAM CVW SOURCE.  It is a verification wrapper written for this
// repository, and it is deliberately thin: it declares no logic of its own, it
// only re-exports the ports the repository's AHB-Lite declaration describes
// (configs/cpus/cvw/interface_description.json).
//
// WHY wallypipelinedsoc AND NOT wallywrapper
//   `testbench/wallywrapper.sv` looks like the obvious top, but it is only a
//   lint shell: it declares HRDATAEXT/HADDR/... as *internal wires* and ties them
//   to constants, so it does not expose the AHB interface at all.  The real
//   boundary is `wallypipelinedsoc`, whose AHB signals are genuine module ports.
//
// WHICH CONFIGURATION
//   The configuration is chosen by the include path, exactly as CVW's own
//   `bin/lint-wally` does it: pass `-I<root>/config/shared -I<root>/config/<name>`.
//   Widths therefore follow the selected config; for rv32imc the real values are
//   AHBW = XLEN = 32 and PA_BITS = 34 (see config/shared/config-shared.vh).
//
// PORTS DELIBERATELY NOT EXPORTED
//   The uncore (GPIO/UART/SPI/SDC/PWM), the timer clock and the internal reset
//   output are left out.  This wrapper describes the CPU's *memory* boundary,
//   which is what the repository's profile declares; anything else would widen the
//   declared interface without a consumer.
//
// WHERE IT LIVES AND WHY
//   It sits beside the profile that elaborates it (configs/cpus/cvw/), the same
//   way configs/peripherals/opentitan_spi_host/closure_wrapper.sv sits beside its
//   own profile.  That profile declares source root "." with the union sha256 pin
//   over its declared files and the declared include roots - the pin convention
//   the repository's local target profiles already use - so a repository-authored
//   top can be a declared source.  A `git:` pin could not contain these bytes:
//   no pinned upstream commit does.
//
// ELABORATION STATUS.  This wrapper is the elaborated top of
// configs/cpus/cvw/component_profile.json, and every port/width/direction in that
// profile comes from the port-fact extractor run over this boundary (Verilator
// JSON under runs/soc-source-elaboration/cvw/, closure recorded in
// configs/soc/closures/cvw.json, config rv32imc).  It is not upstream source and
// is not part of the pinned CVW git revision, so the repository's source-lock
// verifier cannot authenticate its bytes against `git:2f2ddfd`; that limitation
// is recorded in the lock record's closure_note rather than hidden.
`include "config.vh"

module cvw_ahb_cpu_top import cvw::*; (
    input  logic                    clk,
    input  logic                    reset_ext,
    // AHB-Lite external bus.  Names and directions are wallypipelinedsoc's own:
    // the CPU is the manager, so the address/write side is driven and the
    // subordinate's completion is received.  Read data is HRDATAEXT, not HRDATA:
    // src/ebu/ebu.sv has no HRDATA port ("HRDATA is sent to all controllers at
    // the core level").
    input  logic [P.AHBW-1:0]       HRDATAEXT,
    input  logic                    HREADYEXT,
    input  logic                    HRESPEXT,
    output logic                    HCLK,
    output logic                    HRESETn,
    output logic [P.PA_BITS-1:0]    HADDR,
    output logic [P.AHBW-1:0]       HWDATA,
    output logic [P.XLEN/8-1:0]     HWSTRB,
    output logic                    HWRITE,
    output logic [2:0]              HSIZE,
    output logic [2:0]              HBURST,
    output logic [3:0]              HPROT,
    output logic [1:0]              HTRANS,
    output logic                    HMASTLOCK,
    output logic                    HREADY,
    output logic                    HSELEXT
);

`include "parameter-defs.vh"

    // Unused uncore boundary: named so the instantiation is explicit rather than
    // relying on positional omission.
    logic        reset;
    logic        unused_ExternalStall;
    logic [31:0] unused_GPIOIN, unused_GPIOOUT, unused_GPIOEN;
    logic        unused_UARTSin, unused_UARTSout;
    logic        unused_SPIIn, unused_SPIOut, unused_SDCIn, unused_SDCCmd;
    logic [3:0]  unused_SPICS, unused_SDCCS, unused_PWMGPIO;
    logic        unused_SPICLK, unused_SDCCLK;

    assign unused_ExternalStall = 1'b0;
    assign unused_GPIOIN = '0;
    assign unused_UARTSin = 1'b1;
    assign unused_SPIIn = 1'b0;
    assign unused_SDCIn = 1'b0;

    wallypipelinedsoc #(P) dut (
        .clk, .reset_ext, .reset, .ExternalStall(unused_ExternalStall),
        .HRDATAEXT, .HREADYEXT, .HRESPEXT, .HSELEXT,
        .HCLK, .HRESETn, .HADDR, .HWDATA, .HWSTRB, .HWRITE, .HSIZE, .HBURST,
        .HPROT, .HTRANS, .HMASTLOCK, .HREADY,
        .TIMECLK(1'b0),
        .GPIOIN(unused_GPIOIN), .GPIOOUT(unused_GPIOOUT), .GPIOEN(unused_GPIOEN),
        .UARTSin(unused_UARTSin), .UARTSout(unused_UARTSout),
        .SPIIn(unused_SPIIn), .SPIOut(unused_SPIOut), .SPICS(unused_SPICS),
        .SPICLK(unused_SPICLK), .SDCIn(unused_SDCIn), .SDCCmd(unused_SDCCmd),
        .SDCCS(unused_SDCCS), .SDCCLK(unused_SDCCLK), .PWMGPIO(unused_PWMGPIO));

endmodule
