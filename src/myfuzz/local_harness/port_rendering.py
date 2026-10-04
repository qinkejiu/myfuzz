"""Flat, bit-preserving physical connections for a single local DUT."""
from __future__ import annotations

import re
from myfuzz.composition.soc_port_dispositions import constant_expression, port_segments
from .plan import LocalHarnessPlan


class LocalPortRenderError(ValueError):
    """The plan cannot be represented without losing physical ownership."""


def require_identifier(name: str) -> None:
    # Escaped names and SV keywords are deliberately unsupported in this ABI.
    if not isinstance(name, str) or re.fullmatch(r'[A-Za-z_][A-Za-z0-9_$]*', name) is None:
        raise LocalPortRenderError(f'invalid-sv-identifier:{name}')
    keywords = set("""
accept_on alias always always_comb always_ff always_latch and assert assign assume
 automatic before begin bind bins binsof bit break buf bufif0 bufif1 byte case
 casex casez cell chandle checker class clocking cmos config const constraint
 context continue cover covergroup coverpoint cross deassign default defparam
 design disable dist do edge else end endcase endchecker endclass endclocking
 endconfig endfunction endgenerate endgroup endinterface endmodule endpackage
 endprimitive endprogram endproperty endspecify endsequence endtable endtask
 enum event eventually expect export extends extern final first_match for force
 foreach forever fork forkjoin function generate genvar global highz0 highz1
 if iff ifnone ignore_bins illegal_bins implements implies import incdir include
 initial inout input inside instance int integer interconnect interface intersect
 join join_any join_none large let liblist library local localparam logic longint
 macromodule matches medium modport module nand negedge nettype new nexttime nmos
 nor noshowcancelled not notif0 notif1 null or output package packed parameter
 pmos posedge primitive priority program property protected pull0 pull1 pulldown
 pullup pulmos pure rand randc randcase randsequence rcmos real realtime ref reg
 reject_on release repeat restrict return rnmos rpmos rtran rtranif0 rtranif1
 s_always s_eventually s_nexttime s_until s_until_with scalared sequence shortint
 shortreal showcancelled signed small soft solve specify specparam static string
 strong strong0 strong1 struct super supply0 supply1 sync_accept_on sync_reject_on
 table tagged task this throughout time timeprecision timeunit tran tranif0
 tranif1 tri tri0 tri1 triand trior trireg type typedef union unique unique0
 unsigned until until_with untyped use uwire var vectored virtual void wait
 wait_order wand weak weak0 weak1 while wildcard wire with within wor xnor xor
""".split())
    if name in keywords:
        raise LocalPortRenderError(f'invalid-sv-identifier:{name}')


def render_port_connections(plan: LocalHarnessPlan) -> tuple[list[str], list[str], list[str], list[dict[str, object]]]:
    """Return ports, internal declarations/assignments, connections and ABI rows.

    Validate the ledger again: frozen dataclasses can still be replaced by callers.
    Each backing vector is connected once and tiled by descending raw slices.
    """
    if not isinstance(plan, LocalHarnessPlan) or plan.facts.selection != 'all':
        raise LocalPortRenderError('full-top-required')
    if len(plan.profile.clocks) != 1 or len(plan.profile.resets) != 1:
        raise LocalPortRenderError('single-clock-reset-domain-required')
    for name in (plan.request.instance_id, plan.profile.source.top_module, plan.facts.top_module):
        require_identifier(name)
    if plan.profile.source.top_module != plan.facts.top_module:
        raise LocalPortRenderError('top-module-mismatch')
    grouped = port_segments(plan.dispositions)
    facts = {p.name: p for p in plan.facts.ports}
    if len(facts) != len(plan.facts.ports) or set(grouped) != set(facts):
        raise LocalPortRenderError('physical-port-set-mismatch')
    resets = {r.port: r.polarity for r in plan.profile.resets}
    clocks = {c.port for c in plan.profile.clocks}
    declarations, local, connections, abi = [], [], [], []
    for index, name in enumerate(sorted(facts)):
        require_identifier(name)
        fact = facts[name]
        if fact.direction not in ('input', 'output') or fact.width < 1:
            raise LocalPortRenderError(f'unsupported-port:{name}')
        backing = f'dut_p_{index}'
        local.append(f'logic [{fact.width-1}:0] {backing};')
        connections.append(f'.{name}({backing})')
        cursor = fact.width - 1
        for entry in grouped[name]:
            width = entry.bit_hi-entry.bit_lo+1
            if (entry.instance_id != plan.request.instance_id or entry.component_id != plan.profile.component_id
                    or entry.direction != fact.direction or entry.width != fact.width
                    or entry.bit_hi != cursor or entry.bit_lo < 0 or width < 1):
                raise LocalPortRenderError(f'invalid-port-coverage:{name}')
            cursor = entry.bit_lo-1
            span = f'{backing}[{entry.bit_hi}:{entry.bit_lo}]'
            if entry.role in ('clock', 'reset'):
                if entry.direction != 'input' or width != 1 or entry.disposition != 'functional':
                    raise LocalPortRenderError(f'invalid-clock-reset:{name}')
                if entry.role == 'clock' and name in clocks:
                    expression = 'clk'
                elif entry.role == 'reset' and resets.get(name) in ('active_high', 'active_low'):
                    expression = '~reset' if resets[name] == 'active_low' else 'reset'
                else:
                    raise LocalPortRenderError(f'undeclared-clock-reset:{name}')
                local.append(f'assign {span} = {expression};')
            elif entry.disposition == 'constant':
                if entry.direction != 'input' or type(entry.value) is not int or not 0 <= entry.value < 1 << width:
                    raise LocalPortRenderError(f'invalid-constant:{name}')
                local.append(f'assign {span} = {constant_expression(entry)};')
            elif entry.disposition == 'unconnected' and entry.direction == 'output':
                continue
            else:
                allowed = ('functional', 'external', 'fuzz', 'peer') if entry.direction == 'input' else ('functional', 'external', 'observe', 'peer')
                if entry.disposition not in allowed:
                    raise LocalPortRenderError(f'unsupported-disposition:{name}:{entry.disposition}')
                wrapper = f'lh_p_{index}_{entry.bit_hi}_{entry.bit_lo}'
                declarations.append(f'{entry.direction} logic [{width-1}:0] {wrapper}')
                lhs, rhs = (span, wrapper) if entry.direction == 'input' else (wrapper, span)
                local.append(f'assign {lhs} = {rhs};')
                abi.append(dict(wrapper_name=wrapper, physical_port=name, bit_lo=entry.bit_lo,
                                bit_hi=entry.bit_hi, width=width, direction=entry.direction,
                                disposition=entry.disposition, endpoint_id=entry.endpoint_id, role=entry.role))
        if cursor != -1:
            raise LocalPortRenderError(f'incomplete-port-coverage:{name}')
    return declarations, local, connections, abi
