"""Observe execution at the generated, protocol-independent memory boundary."""

from myfuzz.composition.contract_transducer import MAX_MEMORY_CAPACITY_ENTRIES


METRICS = ("cycles", "requests", "successful_reads", "progress_events",
           "completions", "pass_completions", "errors", "first_fetch_matched")
CONTRACT_METRICS = ("cycles", "requests", "completions", "instruction_requests",
                    "instruction_responses", "instruction_initializations",
                    "protocol_errors", "transducer_errors", "errors")


def validate_monitor(value):
    if value is None:
        return None
    if isinstance(value, dict) and value.get("mode") == "contract_transducer":
        if set(value) != {"mode", "memory_capacity_entries"}:
            raise ValueError("contract execution monitor requires mode and memory capacity")
        capacity = value["memory_capacity_entries"]
        if type(capacity) is not int or not 1 <= capacity <= MAX_MEMORY_CAPACITY_ENTRIES:
            raise ValueError("invalid contract execution monitor memory capacity")
        return dict(value)
    keys = {"reset_vector", "first_fetch_data", "pass_address", "pass_value"}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("execution monitor requires explicit boot/pass facts")
    if any(type(v) is not int or not 0 <= v < 1 << 64 for v in value.values()):
        raise ValueError("invalid execution monitor fact")
    return dict(value)


def _contract_monitor_rtl(clock, reset, active, facts):
    """Track one outstanding beat and successful allocations in a shared domain.

    An instruction response is any completed instruction-tagged request, including
    an error. Initialization requires a successful instruction read of a beat
    never previously read successfully or written with nonzero byte enables.
    Backend response errors without a corresponding target error expose outer
    watchdog failures. The backend error bit alone is sticky and is not an event.
    """
    return (f"""
integer exec_cycles=0, exec_requests=0, exec_completions=0;
integer exec_instruction_requests=0, exec_instruction_responses=0;
integer exec_instruction_initializations=0;
integer exec_protocol_errors=0, exec_transducer_errors=0, exec_errors=0;
localparam integer EXEC_MEMORY_CAPACITY={facts['memory_capacity_entries']};
localparam logic [63:0] EXEC_ADDRESS_MASK=~(64'($bits(dut.backend_target_be))-1);
logic [63:0] exec_initialized_addr[0:EXEC_MEMORY_CAPACITY-1];
integer exec_initialized_count=0, exec_lookup_index;
logic exec_initialized_hit;
logic [63:0] exec_pending_addr=0;
logic exec_pending=0, exec_pending_write=0, exec_pending_instruction=0;
logic exec_pending_nonempty_write=0;
logic exec_target_error_pending=0, exec_backend_response_seen=0;
always @(posedge {clock}) begin
  if ({reset} == 1'b{active}) begin
    exec_cycles=0; exec_requests=0; exec_completions=0;
    exec_instruction_requests=0; exec_instruction_responses=0;
    exec_instruction_initializations=0;
    exec_protocol_errors=0; exec_transducer_errors=0; exec_errors=0;
    exec_initialized_count=0; exec_pending_addr=0;
    exec_pending=0; exec_pending_write=0; exec_pending_instruction=0;
    exec_pending_nonempty_write=0;
    exec_target_error_pending=0; exec_backend_response_seen=0;
  end else begin
    exec_cycles=exec_cycles+1;
    if (dut.backend_target_rsp_valid && dut.backend_target_rsp_ready) begin
      exec_completions=exec_completions+1;
      if (dut.backend_target_error) exec_transducer_errors=exec_transducer_errors+1;
      if (!exec_pending) exec_protocol_errors=exec_protocol_errors+1;
      else begin
        if (exec_pending_instruction)
          exec_instruction_responses=exec_instruction_responses+1;
        if (dut.backend_target_error) exec_target_error_pending=1;
        else if (!exec_pending_write || exec_pending_nonempty_write) begin
          exec_initialized_hit=0;
          for (exec_lookup_index=0; exec_lookup_index<exec_initialized_count;
               exec_lookup_index=exec_lookup_index+1)
            if (exec_initialized_addr[exec_lookup_index]==exec_pending_addr)
              exec_initialized_hit=1;
          if (!exec_initialized_hit) begin
            if (exec_initialized_count==EXEC_MEMORY_CAPACITY)
              exec_protocol_errors=exec_protocol_errors+1;
            else begin
              exec_initialized_addr[exec_initialized_count]=exec_pending_addr;
              exec_initialized_count=exec_initialized_count+1;
              if (exec_pending_instruction && !exec_pending_write)
                exec_instruction_initializations=exec_instruction_initializations+1;
            end
          end
        end
      end
      exec_pending=0;
    end
    if (dut.backend_rsp_valid && !exec_backend_response_seen) begin
      if (dut.backend_error && !exec_target_error_pending) begin
        exec_protocol_errors=exec_protocol_errors+1;
        exec_pending=0;
      end
      exec_target_error_pending=0;
    end
    exec_backend_response_seen=dut.backend_rsp_valid;
    if (dut.backend_target_req_valid && dut.backend_target_req_ready) begin
      exec_requests=exec_requests+1;
      if (dut.backend_target_req_instruction)
        exec_instruction_requests=exec_instruction_requests+1;
      if (exec_pending) exec_protocol_errors=exec_protocol_errors+1;
      else begin
        exec_pending=1;
        exec_pending_addr=64'(dut.backend_target_addr) & EXEC_ADDRESS_MASK;
        exec_pending_write=dut.backend_target_write;
        exec_pending_instruction=dut.backend_target_req_instruction;
        exec_pending_nonempty_write=(|dut.backend_target_be);
      end
    end
    exec_errors=exec_protocol_errors+exec_transducer_errors;
  end
end
""",)


def monitor_rtl(clock, reset, active, facts):
    if facts is None:
        return ()
    facts = validate_monitor(facts)
    if facts.get("mode") == "contract_transducer":
        return _contract_monitor_rtl(clock, reset, active, facts)
    return (f"""
integer exec_cycles=0, exec_requests=0, exec_successful_reads=0;
integer exec_progress_events=0, exec_completions=0, exec_pass_completions=0;
integer exec_errors=0, exec_first_fetch_matched=0;
logic [63:0] exec_pending_addr=0, exec_last_read=0;
logic exec_pending_write=0, exec_pending_pass=0, exec_pending=0;
always @(posedge {clock}) begin
  if ({reset} == 1'b{active}) begin
    exec_cycles=0; exec_requests=0; exec_successful_reads=0;
    exec_progress_events=0; exec_completions=0; exec_pass_completions=0;
    exec_errors=0; exec_first_fetch_matched=0;
    exec_pending_addr=0; exec_last_read=0;
    exec_pending_write=0; exec_pending_pass=0; exec_pending=0;
  end else begin
    exec_cycles=exec_cycles+1;
    if (dut.backend_target_rsp_valid && dut.backend_target_rsp_ready) begin
      exec_completions=exec_completions+1;
      if (!exec_pending || dut.backend_target_error) exec_errors=exec_errors+1;
      else begin
        if (exec_pending_pass) exec_pass_completions=exec_pass_completions+1;
        if (!exec_pending_write) begin
          if (exec_successful_reads==0 && exec_pending_addr==64'h{facts['reset_vector']:x}
              && dut.backend_target_rdata[31:0]==32'h{facts['first_fetch_data'] & 0xffffffff:x})
            exec_first_fetch_matched=1;
          if (exec_successful_reads==0 || exec_pending_addr!=exec_last_read)
            exec_progress_events=exec_progress_events+1;
          exec_last_read=exec_pending_addr;
          exec_successful_reads=exec_successful_reads+1;
        end
      end
      exec_pending=0;
    end
    if (dut.backend_target_req_valid && dut.backend_target_req_ready) begin
      if (exec_pending) exec_errors=exec_errors+1;
      exec_pending=1; exec_requests=exec_requests+1;
      exec_pending_addr=64'(dut.backend_target_addr);
      exec_pending_write=dut.backend_target_write;
      exec_pending_pass=dut.backend_target_write
          && 64'(dut.backend_target_addr)==64'h{facts['pass_address']:x}
          && dut.backend_target_wdata[31:0]==32'h{facts['pass_value'] & 0xffffffff:x}
          && (&dut.backend_target_be[3:0]);
    end
  end
end
""",)


def monitor_output(facts):
    if facts is None:
        return ()
    facts = validate_monitor(facts)
    names = CONTRACT_METRICS if facts.get("mode") == "contract_transducer" else METRICS
    return ('$write(" EXEC ' + ','.join('%0d' for _ in names) + '",'
            + ','.join('exec_' + key for key in names) + ');',)


def parse_metrics(payload, facts=None):
    facts = validate_monitor(facts)
    names = CONTRACT_METRICS if facts and facts.get("mode") == "contract_transducer" else METRICS
    values = payload.decode("ascii").split(",")
    if len(values) != len(names) or any(not v.isdecimal() for v in values):
        raise ValueError("invalid RTL execution metrics")
    result = dict(zip(names, map(int, values)))
    if any(v > 65536 for v in result.values()):
        raise ValueError("oversized RTL execution metric")
    return result


def validate_execution(metrics):
    """Check contract consistency, or legacy fixed-program execution progress.

    A bounded contract test may stop before its first request or with a single
    unfinished request. Campaign/probe progress is validated by its caller.
    """
    if not isinstance(metrics, dict) or set(metrics) not in (set(METRICS), set(CONTRACT_METRICS)):
        raise ValueError("execution acceptance failed: incomplete metrics")
    if any(type(value) is not int or value < 0 for value in metrics.values()):
        raise ValueError("execution acceptance failed: invalid metric")
    if set(metrics) == set(CONTRACT_METRICS):
        outstanding = metrics["requests"] - metrics["completions"]
        instruction_outstanding = metrics["instruction_requests"] - metrics["instruction_responses"]
        accepted = (
            metrics["requests"] <= metrics["cycles"]
            and 0 <= outstanding <= 1
            and 0 <= instruction_outstanding <= outstanding
            and metrics["instruction_requests"] <= metrics["requests"]
            and metrics["instruction_responses"] <= metrics["completions"]
            and metrics["instruction_initializations"] <= metrics["instruction_responses"]
            and metrics["errors"] == metrics["protocol_errors"] + metrics["transducer_errors"] == 0
        )
        if not accepted:
            raise ValueError(f"execution acceptance failed: {metrics}")
        return dict(metrics)
    accepted = (
        metrics["cycles"] > 0
        and metrics["requests"] > 0
        and metrics["requests"] == metrics["completions"]
        and metrics["successful_reads"] > 0
        and metrics["progress_events"] > 1
        and metrics["pass_completions"] > 0
        and metrics["errors"] == 0
        and metrics["first_fetch_matched"] == 1
    )
    if not accepted:
        raise ValueError(f"execution acceptance failed: {metrics}")
    return dict(metrics)
