"""Bounded, independently progressing AXI-Lite v4 fabric contract and model."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Mapping

from .input_model import InputValidationError


@dataclass(frozen=True)
class AxiLiteFabricV4Capability:
    address_width: int
    data_width: int
    slave_count: int
    bases: tuple[int, ...]
    sizes: tuple[int, ...]
    aw_depth: int = 4
    w_depth: int = 4
    ar_depth: int = 4
    write_reorder_depth: int = 4
    read_reorder_depth: int = 4
    max_write_per_target: int = 1
    max_read_per_target: int = 1
    awprot_present: bool = False
    arprot_present: bool = False
    schema: str = "myfuzz.axi-lite-fabric-capability/v4"

    def __post_init__(self) -> None:
        integers = (
            self.address_width, self.data_width, self.slave_count, self.aw_depth,
            self.w_depth, self.ar_depth, self.write_reorder_depth,
            self.read_reorder_depth, self.max_write_per_target,
            self.max_read_per_target,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0 for value in integers):
            raise InputValidationError("AXI-Lite v4 fabric widths and depths must be positive integers")
        if self.data_width % 8:
            raise InputValidationError("AXI-Lite v4 data_width must be a multiple of 8")
        if len(self.bases) != self.slave_count or len(self.sizes) != self.slave_count:
            raise InputValidationError("AXI-Lite v4 address window count mismatch")
        limit = 1 << self.address_width
        windows = sorted(zip(self.bases, self.sizes))
        for base, size in windows:
            if base < 0 or size <= 0 or base + size > limit:
                raise InputValidationError("AXI-Lite v4 address window exceeds address space")
        if any(left_base + left_size > right_base for (left_base, left_size), (right_base, _right_size) in zip(windows, windows[1:])):
            raise InputValidationError("AXI-Lite v4 address windows overlap")
        if self.max_write_per_target != 1 or self.max_read_per_target != 1:
            raise InputValidationError("AXI-Lite targets without IDs support one issued request per channel")
        if not isinstance(self.awprot_present, bool) or not isinstance(self.arprot_present, bool):
            raise InputValidationError("AXI-Lite v4 PROT capability flags must be boolean")

    def manifest(self) -> Mapping[str, object]:
        return {
            "schema": self.schema,
            "address_width": self.address_width,
            "data_width": self.data_width,
            "slave_count": self.slave_count,
            "windows": [
                {"target": index, "base": base, "size": size}
                for index, (base, size) in enumerate(zip(self.bases, self.sizes))
            ],
            "queues": {"aw": self.aw_depth, "w": self.w_depth, "ar": self.ar_depth},
            "reorder": {"write": self.write_reorder_depth, "read": self.read_reorder_depth},
            "target_issue_limits": {"write": 1, "read": 1},
            "optional_signals": {"awprot": self.awprot_present, "arprot": self.arprot_present},
            "write_pairing": "nth_aw_with_nth_w",
            "response_order": {"write": "acceptance", "read": "acceptance"},
            "read_write_progress": "independent",
            "reset": "clear_all_queues_sequences_and_reorder_state",
        }


@dataclass(frozen=True)
class AxiLiteFabricV4Input:
    awvalid: bool = False
    awaddr: int = 0
    awprot: int = 0
    wvalid: bool = False
    wdata: int = 0
    wstrb: int = 0
    bready: bool = False
    arvalid: bool = False
    araddr: int = 0
    arprot: int = 0
    rready: bool = False


@dataclass(frozen=True)
class AxiLiteTargetFeedbackV4:
    awready: tuple[bool, ...]
    wready: tuple[bool, ...]
    bvalid: tuple[bool, ...]
    bresp: tuple[int, ...]
    arready: tuple[bool, ...]
    rvalid: tuple[bool, ...]
    rdata: tuple[int, ...]
    rresp: tuple[int, ...]

    @classmethod
    def idle(cls, targets: int) -> "AxiLiteTargetFeedbackV4":
        false = (False,) * targets
        zero = (0,) * targets
        return cls(false, false, false, zero, false, false, zero, zero)


@dataclass(frozen=True)
class AxiLiteFabricV4Output:
    awready: bool
    wready: bool
    arready: bool
    bvalid: bool
    bresp: int
    rvalid: bool
    rdata: int
    rresp: int
    slave_awvalid: tuple[bool, ...]
    slave_awaddr: tuple[int, ...]
    slave_awprot: tuple[int, ...]
    slave_wvalid: tuple[bool, ...]
    slave_wdata: tuple[int, ...]
    slave_wstrb: tuple[int, ...]
    slave_bready: tuple[bool, ...]
    slave_arvalid: tuple[bool, ...]
    slave_araddr: tuple[int, ...]
    slave_arprot: tuple[int, ...]
    slave_rready: tuple[bool, ...]


@dataclass
class _WriteEntry:
    sequence: int
    target: int | None
    address: int
    data: int
    strobe: int
    prot: int
    aw_sent: bool = False
    w_sent: bool = False
    response: int | None = None


@dataclass
class _ReadEntry:
    sequence: int
    target: int | None
    address: int
    prot: int = 0
    ar_sent: bool = False
    response: tuple[int, int] | None = None


class AxiLiteFabricV4Model:
    """Cycle model with ordinal AW/W pairing and per-channel reorder state."""

    def __init__(self, capability: AxiLiteFabricV4Capability) -> None:
        self.capability = capability
        self.reset()

    def reset(self) -> None:
        self.aw = deque()
        self.w = deque()
        self.ar = deque()
        self.writes: deque[_WriteEntry] = deque()
        self.reads: deque[_ReadEntry] = deque()
        self.write_sequence = 0
        self.read_sequence = 0

    def step(self, master: AxiLiteFabricV4Input, slave: AxiLiteTargetFeedbackV4) -> AxiLiteFabricV4Output:
        self._validate(master, slave)
        count = self.capability.slave_count
        sawvalid = [False] * count; sawaddr = [0] * count; sawprot = [0] * count
        swvalid = [False] * count; swdata = [0] * count; swstrb = [0] * count
        sbready = [False] * count; sarvalid = [False] * count; saraddr = [0] * count; sarprot = [0] * count
        srready = [False] * count

        write_by_target = {entry.target: entry for entry in self.writes if entry.target is not None and entry.response is None}
        for target, entry in write_by_target.items():
            if not entry.aw_sent:
                sawvalid[target] = True; sawaddr[target] = entry.address - self.capability.bases[target]; sawprot[target] = entry.prot
            if not entry.w_sent:
                swvalid[target] = True; swdata[target] = entry.data; swstrb[target] = entry.strobe
            if entry.aw_sent and entry.w_sent:
                sbready[target] = True

        read_by_target = {entry.target: entry for entry in self.reads if entry.target is not None and entry.response is None}
        for target, entry in read_by_target.items():
            if not entry.ar_sent:
                sarvalid[target] = True; saraddr[target] = entry.address - self.capability.bases[target]; sarprot[target] = entry.prot
            else:
                srready[target] = True

        bvalid = bool(self.writes and self.writes[0].response is not None)
        bresp = self.writes[0].response if bvalid else 0
        rvalid = bool(self.reads and self.reads[0].response is not None)
        rdata, rresp = self.reads[0].response if rvalid else (0, 0)
        output = AxiLiteFabricV4Output(
            len(self.aw) < self.capability.aw_depth,
            len(self.w) < self.capability.w_depth,
            len(self.ar) < self.capability.ar_depth,
            bvalid, int(bresp), rvalid, rdata, rresp,
            tuple(sawvalid), tuple(sawaddr), tuple(sawprot), tuple(swvalid), tuple(swdata), tuple(swstrb),
            tuple(sbready), tuple(sarvalid), tuple(saraddr), tuple(sarprot), tuple(srready),
        )

        if output.bvalid and master.bready:
            self.writes.popleft()
        if output.rvalid and master.rready:
            self.reads.popleft()
        for target, entry in write_by_target.items():
            if sawvalid[target] and slave.awready[target]: entry.aw_sent = True
            if swvalid[target] and slave.wready[target]: entry.w_sent = True
            if entry.aw_sent and entry.w_sent and slave.bvalid[target]: entry.response = slave.bresp[target]
        for target, entry in read_by_target.items():
            if sarvalid[target] and slave.arready[target]: entry.ar_sent = True
            if entry.ar_sent and slave.rvalid[target]: entry.response = (slave.rdata[target], slave.rresp[target])
        if output.awready and master.awvalid: self.aw.append((master.awaddr, master.awprot))
        if output.wready and master.wvalid: self.w.append((master.wdata, master.wstrb))
        if output.arready and master.arvalid: self.ar.append((master.araddr, master.arprot))
        self._allocate()
        return output

    def _allocate(self) -> None:
        busy_w = {entry.target for entry in self.writes if entry.target is not None and entry.response is None}
        while self.aw and self.w and len(self.writes) < self.capability.write_reorder_depth:
            target = self._target(self.aw[0][0])
            if target is not None and target in busy_w: break
            address, prot = self.aw.popleft(); data, strobe = self.w.popleft()
            entry = _WriteEntry(self.write_sequence, target, address, data, strobe, prot)
            self.write_sequence += 1
            if target is None: entry.response = 3
            else: busy_w.add(target)
            self.writes.append(entry)
        busy_r = {entry.target for entry in self.reads if entry.target is not None and entry.response is None}
        while self.ar and len(self.reads) < self.capability.read_reorder_depth:
            target = self._target(self.ar[0][0] if isinstance(self.ar[0], tuple) else self.ar[0])
            if target is not None and target in busy_r: break
            address, prot = self.ar.popleft(); entry = _ReadEntry(self.read_sequence, target, address, prot)
            self.read_sequence += 1
            if target is None: entry.response = (0, 3)
            else: busy_r.add(target)
            self.reads.append(entry)

    def _target(self, address: int) -> int | None:
        for index, (base, size) in enumerate(zip(self.capability.bases, self.capability.sizes)):
            if base <= address < base + size: return index
        return None

    def _validate(self, master: AxiLiteFabricV4Input, slave: AxiLiteTargetFeedbackV4) -> None:
        count = self.capability.slave_count
        fields = (slave.awready, slave.wready, slave.bvalid, slave.bresp, slave.arready, slave.rvalid, slave.rdata, slave.rresp)
        if any(len(field) != count for field in fields):
            raise InputValidationError("AXI-Lite target feedback width does not match slave_count")
        limits = ((master.awaddr, self.capability.address_width), (master.araddr, self.capability.address_width), (master.wdata, self.capability.data_width), (master.wstrb, self.capability.data_width // 8), (master.awprot, 3), (master.arprot, 3))
        if any(value < 0 or value >= 1 << width for value, width in limits):
            raise InputValidationError("AXI-Lite master payload exceeds capability width")


def emit_axi_lite_fabric_v4(
    capability: AxiLiteFabricV4Capability,
    module_name: str = "myfuzz_axi_lite_fabric_v4",
) -> str:
    """Emit the bounded independent-channel fabric described by the capability."""
    if not module_name.isidentifier():
        raise InputValidationError("fabric module_name must be a Verilog identifier")
    c = capability
    aw_ptr = max(1, (c.aw_depth - 1).bit_length())
    w_ptr = max(1, (c.w_depth - 1).bit_length())
    ar_ptr = max(1, (c.ar_depth - 1).bit_length())
    seq_width = max(1, max(c.write_reorder_depth, c.read_reorder_depth).bit_length())
    lines = [
        f"module {module_name} #(parameter integer ADDR_WIDTH={c.address_width}, DATA_WIDTH={c.data_width}, SLAVES={c.slave_count}, AW_DEPTH={c.aw_depth}, W_DEPTH={c.w_depth}, AR_DEPTH={c.ar_depth}, WR_DEPTH={c.write_reorder_depth}, RR_DEPTH={c.read_reorder_depth}) (",
        " input logic aclk, input logic aresetn,",
        " input logic [ADDR_WIDTH-1:0] m_awaddr, input logic m_awvalid, output logic m_awready,",
        " input logic [DATA_WIDTH-1:0] m_wdata, input logic [DATA_WIDTH/8-1:0] m_wstrb, input logic m_wvalid, output logic m_wready,",
        " output logic [1:0] m_bresp, output logic m_bvalid, input logic m_bready,",
        " input logic [ADDR_WIDTH-1:0] m_araddr, input logic m_arvalid, output logic m_arready,",
        " output logic [DATA_WIDTH-1:0] m_rdata, output logic [1:0] m_rresp, output logic m_rvalid, input logic m_rready,",
        " output logic [SLAVES-1:0] s_awvalid, output logic [SLAVES-1:0][ADDR_WIDTH-1:0] s_awaddr, input logic [SLAVES-1:0] s_awready,",
        " output logic [SLAVES-1:0] s_wvalid, output logic [SLAVES-1:0][DATA_WIDTH-1:0] s_wdata, output logic [SLAVES-1:0][DATA_WIDTH/8-1:0] s_wstrb, input logic [SLAVES-1:0] s_wready,",
        " input logic [SLAVES-1:0] s_bvalid, input logic [SLAVES-1:0][1:0] s_bresp, output logic [SLAVES-1:0] s_bready,",
        " output logic [SLAVES-1:0] s_arvalid, output logic [SLAVES-1:0][ADDR_WIDTH-1:0] s_araddr, input logic [SLAVES-1:0] s_arready,",
        " input logic [SLAVES-1:0] s_rvalid, input logic [SLAVES-1:0][DATA_WIDTH-1:0] s_rdata, input logic [SLAVES-1:0][1:0] s_rresp, output logic [SLAVES-1:0] s_rready",
        ");",
        f" logic [ADDR_WIDTH-1:0] aw_q [0:AW_DEPTH-1], ar_q [0:AR_DEPTH-1]; logic [DATA_WIDTH-1:0] wdata_q [0:W_DEPTH-1]; logic [DATA_WIDTH/8-1:0] wstrb_q [0:W_DEPTH-1];",
        f" integer aw_count, w_count, ar_count, aw_rd, w_rd, ar_rd, aw_wr, w_wr, ar_wr; integer i, target;",
        " localparam integer SLOTS=SLAVES+1;",
        f" logic w_active[0:SLOTS-1], w_aw_sent[0:SLOTS-1], w_w_sent[0:SLOTS-1], w_done[0:SLOTS-1]; logic [ADDR_WIDTH-1:0] w_addr[0:SLOTS-1]; logic [DATA_WIDTH-1:0] w_data[0:SLOTS-1]; logic [DATA_WIDTH/8-1:0] w_strb[0:SLOTS-1]; logic [{seq_width-1}:0] w_seq[0:SLOTS-1]; logic [1:0] w_resp[0:SLOTS-1];",
        f" logic r_active[0:SLOTS-1], r_ar_sent[0:SLOTS-1], r_done[0:SLOTS-1]; logic [ADDR_WIDTH-1:0] r_addr[0:SLOTS-1]; logic [{seq_width-1}:0] r_seq[0:SLOTS-1]; logic [DATA_WIDTH-1:0] r_data[0:SLOTS-1]; logic [1:0] r_resp[0:SLOTS-1];",
        f" logic [{seq_width-1}:0] w_alloc_seq, w_next_seq, r_alloc_seq, r_next_seq; integer aw_target, ar_target; logic aw_hit, ar_hit;",
    ]
    if c.awprot_present:
        lines.insert(3, " input logic [2:0] m_awprot, output logic [SLAVES-1:0][2:0] s_awprot,")
    if c.arprot_present:
        lines.insert(7 if c.awprot_present else 6, " input logic [2:0] m_arprot, output logic [SLAVES-1:0][2:0] s_arprot,")
    if c.awprot_present:
        lines.insert(-1, " logic [2:0] awprot_q[0:AW_DEPTH-1], w_prot[0:SLOTS-1];")
    if c.arprot_present:
        lines.insert(-1, " logic [2:0] arprot_q[0:AR_DEPTH-1], r_prot[0:SLOTS-1];")
    for index, (base, size) in enumerate(zip(c.bases, c.sizes)):
        lines.append(f" localparam logic [ADDR_WIDTH-1:0] BASE_{index}={c.address_width}'h{base:x}; localparam logic [ADDR_WIDTH-1:0] END_{index}={c.address_width}'h{base + size:x};")
    lines += [
        " always_comb begin",
        "  aw_hit=1'b0; aw_target=-1; ar_hit=1'b0; ar_target=-1;",
    ]
    for index in range(c.slave_count):
        lines.append(f"  if (aw_q[aw_rd] >= BASE_{index} && aw_q[aw_rd] < END_{index}) begin aw_hit=1'b1; aw_target={index}; end")
        lines.append(f"  if (ar_q[ar_rd] >= BASE_{index} && ar_q[ar_rd] < END_{index}) begin ar_hit=1'b1; ar_target={index}; end")
    lines += [
        "  m_awready=(aw_count<AW_DEPTH); m_wready=(w_count<W_DEPTH); m_arready=(ar_count<AR_DEPTH);",
        "  s_awvalid='0; s_awaddr='0; s_wvalid='0; s_wdata='0; s_wstrb='0; s_bready='0; s_arvalid='0; s_araddr='0; s_rready='0;",
        "  for (i=0;i<SLAVES;i=i+1) begin",
        "   if (w_active[i] && !w_done[i]) begin s_awvalid[i]=!w_aw_sent[i]; s_wvalid[i]=!w_w_sent[i]; s_wdata[i]=w_data[i]; s_wstrb[i]=w_strb[i]; s_bready[i]=w_aw_sent[i]&&w_w_sent[i]; end",
        "   if (r_active[i] && !r_done[i]) begin s_arvalid[i]=!r_ar_sent[i]; s_rready[i]=r_ar_sent[i]; end",
        "  end",
    ]
    for index in range(c.slave_count):
        lines.append(f"  if(w_active[{index}]) s_awaddr[{index}]=w_addr[{index}]-BASE_{index}; if(r_active[{index}]) s_araddr[{index}]=r_addr[{index}]-BASE_{index};")
    if c.awprot_present:
        lines.append("  s_awprot='0; for(i=0;i<SLAVES;i=i+1) if(w_active[i]) s_awprot[i]=w_prot[i];")
    if c.arprot_present:
        lines.append("  s_arprot='0; for(i=0;i<SLAVES;i=i+1) if(r_active[i]) s_arprot[i]=r_prot[i];")
    lines += [
        "  m_bvalid=1'b0; m_bresp=2'b11; for (i=0;i<SLOTS;i=i+1) if (w_active[i]&&w_done[i]&&(w_seq[i]==w_next_seq)) begin m_bvalid=1'b1; m_bresp=w_resp[i]; end",
        "  m_rvalid=1'b0; m_rdata='0; m_rresp=2'b11; for (i=0;i<SLOTS;i=i+1) if (r_active[i]&&r_done[i]&&(r_seq[i]==r_next_seq)) begin m_rvalid=1'b1; m_rdata=r_data[i]; m_rresp=r_resp[i]; end",
        " end",
        " always_ff @(posedge aclk or negedge aresetn) begin",
        "  if (!aresetn) begin aw_count<=0;w_count<=0;ar_count<=0;aw_rd<=0;w_rd<=0;ar_rd<=0;aw_wr<=0;w_wr<=0;ar_wr<=0;w_alloc_seq<=0;w_next_seq<=0;r_alloc_seq<=0;r_next_seq<=0; for(i=0;i<SLOTS;i=i+1) begin w_active[i]<=0;w_aw_sent[i]<=0;w_w_sent[i]<=0;w_done[i]<=0;r_active[i]<=0;r_ar_sent[i]<=0;r_done[i]<=0; end end else begin",
        "   if(m_awvalid&&m_awready) begin aw_q[aw_wr]<=m_awaddr;" + (" awprot_q[aw_wr]<=m_awprot;" if c.awprot_present else "") + " aw_wr<=(aw_wr+1)%AW_DEPTH; aw_count<=aw_count+1; end",
        "   if(m_wvalid&&m_wready) begin wdata_q[w_wr]<=m_wdata; wstrb_q[w_wr]<=m_wstrb; w_wr<=(w_wr+1)%W_DEPTH; w_count<=w_count+1; end",
        "   if(m_arvalid&&m_arready) begin ar_q[ar_wr]<=m_araddr;" + (" arprot_q[ar_wr]<=m_arprot;" if c.arprot_present else "") + " ar_wr<=(ar_wr+1)%AR_DEPTH; ar_count<=ar_count+1; end",
        "   if(aw_count>0&&w_count>0) begin target=-1; for(i=0;i<SLAVES;i=i+1) if(!w_active[i]&&aw_hit&&aw_target==i) target=i; if(!aw_hit&&!w_active[SLAVES]) target=SLAVES; if(target>=0) begin w_active[target]<=1;w_addr[target]<=aw_q[aw_rd];w_data[target]<=wdata_q[w_rd];w_strb[target]<=wstrb_q[w_rd];w_seq[target]<=w_alloc_seq;w_alloc_seq<=w_alloc_seq+1;aw_rd<=(aw_rd+1)%AW_DEPTH;w_rd<=(w_rd+1)%W_DEPTH;aw_count<=aw_count-1;w_count<=w_count-1;" + ("w_prot[target]<=awprot_q[aw_rd];" if c.awprot_present else "") + "if(!aw_hit) begin w_done[target]<=1;w_resp[target]<=3;end end end",
        "   if(ar_count>0) begin target=-1; for(i=0;i<SLAVES;i=i+1) if(!r_active[i]&&ar_hit&&ar_target==i) target=i; if(!ar_hit&&!r_active[SLAVES]) target=SLAVES; if(target>=0) begin r_active[target]<=1;r_addr[target]<=ar_q[ar_rd];r_seq[target]<=r_alloc_seq;r_alloc_seq<=r_alloc_seq+1;ar_rd<=(ar_rd+1)%AR_DEPTH;ar_count<=ar_count-1;" + ("r_prot[target]<=arprot_q[ar_rd];" if c.arprot_present else "") + "if(!ar_hit) begin r_done[target]<=1;r_data[target]<='0;r_resp[target]<=3;end end end",
        "   for(i=0;i<SLAVES;i=i+1) begin if(w_active[i]&&!w_done[i]) begin if(!w_aw_sent[i]&&s_awvalid[i]&&s_awready[i]) w_aw_sent[i]<=1; if(!w_w_sent[i]&&s_wvalid[i]&&s_wready[i]) w_w_sent[i]<=1; if(w_aw_sent[i]&&w_w_sent[i]&&s_bvalid[i]) begin w_done[i]<=1;w_resp[i]<=s_bresp[i];end end if(r_active[i]&&!r_done[i]) begin if(!r_ar_sent[i]&&s_arvalid[i]&&s_arready[i]) r_ar_sent[i]<=1; if(r_ar_sent[i]&&s_rvalid[i]) begin r_done[i]<=1;r_data[i]<=s_rdata[i];r_resp[i]<=s_rresp[i];end end end for(i=0;i<SLOTS;i=i+1) begin if(m_bvalid&&m_bready&&w_active[i]&&w_done[i]&&(w_seq[i]==w_next_seq)) begin w_active[i]<=0;w_done[i]<=0;w_aw_sent[i]<=0;w_w_sent[i]<=0;w_next_seq<=w_next_seq+1;end if(m_rvalid&&m_rready&&r_active[i]&&r_done[i]&&(r_seq[i]==r_next_seq)) begin r_active[i]<=0;r_done[i]<=0;r_ar_sent[i]<=0;r_next_seq<=r_next_seq+1;end end",
        "  end end",
        "endmodule",
    ]
    return "\n".join(lines) + "\n"
