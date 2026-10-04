"""Pinned CVA6 cv64a6_imafdc_sv39 packed AXI4 boundary.

These widths are checked again against compiler-derived member spans by
runtime_renderer._shape. They are not a generic AXI4 width policy.
"""

CVA6_AXI_INPUT_FIELDS = frozenset({
    'awready', 'wready', 'bvalid', 'bid', 'bresp', 'buser',
    'arready', 'rvalid', 'rid', 'rdata', 'rlast', 'rresp', 'ruser',
})

CVA6_AXI_WIDTHS = {
    'awid': 4, 'awaddr': 64, 'awlen': 8, 'awsize': 3, 'awburst': 2,
    'awlock': 1, 'awcache': 4, 'awprot': 3, 'awqos': 4,
    'awregion': 4, 'awatop': 6, 'awuser': 64, 'awvalid': 1,
    'wdata': 64, 'wstrb': 8, 'wlast': 1, 'wuser': 64, 'wvalid': 1,
    'bready': 1, 'arid': 4, 'araddr': 64, 'arlen': 8, 'arsize': 3,
    'arburst': 2, 'arlock': 1, 'arcache': 4, 'arprot': 3,
    'arqos': 4, 'arregion': 4, 'aruser': 64, 'arvalid': 1,
    'rready': 1, 'awready': 1, 'arready': 1, 'wready': 1,
    'bvalid': 1, 'bid': 4, 'bresp': 2, 'buser': 64,
    'rvalid': 1, 'rid': 4, 'rdata': 64, 'rresp': 2,
    'rlast': 1, 'ruser': 64,
}

CVA6_AXI_SHAPE = {
    role: ('input' if role in CVA6_AXI_INPUT_FIELDS else 'output', width)
    for role, width in CVA6_AXI_WIDTHS.items()
}

CVA6_AXI_STEP_ROLES = (
    'awready', 'wready', 'bvalid', 'bid', 'bresp', 'buser',
    'arready', 'rvalid', 'rid', 'rdata', 'rlast', 'rresp', 'ruser',
)
CVA6_AXI_STEP_PORTS = ('irq_external', *(f'axi_{role}' for role in CVA6_AXI_STEP_ROLES))
CVA6_AXI_STEP_MAXIMA = (1, *( (1 << CVA6_AXI_WIDTHS[role]) - 1
                              for role in CVA6_AXI_STEP_ROLES))
