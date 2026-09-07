module generic_processor_ram (
    input  logic        clock,
    input  logic        reset,
    input  logic        req_valid,
    output logic        req_ready,
    input  logic        write,
    input  logic [31:0] addr,
    input  logic [31:0] wdata,
    input  logic [3:0]  be,
    output logic        rsp_valid,
    input  logic        rsp_ready,
    output logic [31:0] rdata,
    output logic        error
);
    logic [31:0] memory [0:63];
    logic pending_q;
    logic [31:0] rdata_q;
    integer lane;

    assign req_ready = !pending_q;
    assign rsp_valid = pending_q;
    assign rdata = rdata_q;
    assign error = 1'b0;

    always_ff @(posedge clock or negedge reset) begin
        if (!reset) begin
            pending_q <= 1'b0;
            rdata_q <= '0;
            memory[0] <= 32'h13579bdf;
            memory[1] <= 32'haabbccdd;
        end else begin
            if (req_valid && req_ready) begin
                pending_q <= 1'b1;
                rdata_q <= memory[addr[7:2]];
                if (write)
                    for (lane = 0; lane < 4; lane = lane + 1)
                        if (be[lane])
                            memory[addr[7:2]][lane*8 +: 8] <= wdata[lane*8 +: 8];
            end
            if (rsp_valid && rsp_ready)
                pending_q <= 1'b0;
        end
    end
endmodule
