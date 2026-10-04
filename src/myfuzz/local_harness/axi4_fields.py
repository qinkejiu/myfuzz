"""Physical ZipCPU full AXI4 signal shape and one-tick response order."""

AXI_INPUT_FIELDS = (
    'awready', 'wready', 'bvalid', 'bid', 'bresp',
    'arready', 'rvalid', 'rid', 'rdata', 'rlast', 'rresp',
)

AXI_OUTPUT_FIELDS = (
    'awvalid', 'awid', 'awaddr', 'awlen', 'awsize', 'awburst',
    'awlock', 'awcache', 'awprot', 'awqos',
    'wvalid', 'wdata', 'wstrb', 'wlast', 'bready',
    'arvalid', 'arid', 'araddr', 'arlen', 'arsize', 'arburst',
    'arlock', 'arcache', 'arprot', 'arqos',
    'rready',
)

AXI_WIDTHS = {
    'awvalid': 1, 'awready': 1, 'awid': 1, 'awaddr': 32,
    'awlen': 8, 'awsize': 3, 'awburst': 2, 'awlock': 1,
    'awcache': 4, 'awprot': 3, 'awqos': 4,
    'wvalid': 1, 'wready': 1, 'wdata': 32, 'wstrb': 4,
    'wlast': 1, 'bvalid': 1, 'bready': 1, 'bid': 1, 'bresp': 2,
    'arvalid': 1, 'arready': 1, 'arid': 1, 'araddr': 32,
    'arlen': 8, 'arsize': 3, 'arburst': 2, 'arlock': 1,
    'arcache': 4, 'arprot': 3, 'arqos': 4,
    'rvalid': 1, 'rready': 1, 'rid': 1, 'rdata': 32,
    'rlast': 1, 'rresp': 2,
}

AXI_SHAPE = {
    role: ('input' if role in AXI_INPUT_FIELDS else 'output', width)
    for role, width in AXI_WIDTHS.items()
}

AXI_STEP_PORTS = tuple(prefix + '_' + role for prefix in ('i', 'd')
                       for role in AXI_INPUT_FIELDS)
AXI_STEP_MAXIMA = tuple((1 << AXI_WIDTHS[name.split('_', 1)[1]]) - 1
                        for name in AXI_STEP_PORTS)
