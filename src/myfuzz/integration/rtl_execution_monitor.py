"""Observe execution at the generated, protocol-independent memory boundary."""

METRICS = ("cycles", "requests", "successful_reads", "progress_events",
           "completions", "pass_completions", "errors", "first_fetch_matched")


def validate_monitor(value):
    if value is None:
        return None
    keys = {"reset_vector", "first_fetch_data", "pass_address", "pass_value"}
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("execution monitor requires explicit boot/pass facts")
    if any(type(v) is not int or not 0 <= v < 1 << 64 for v in value.values()):
        raise ValueError("invalid execution monitor fact")
    return dict(value)


def monitor_rtl(clock, reset, active, facts):
    if facts is None:
        return ()
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
    return ('$write(" EXEC ' + ','.join('%0d' for _ in METRICS) + '",'
            + ','.join('exec_' + key for key in METRICS) + ');',)


def parse_metrics(payload):
    values = payload.decode("ascii").split(",")
    if len(values) != len(METRICS) or any(not v.isdecimal() for v in values):
        raise ValueError("invalid RTL execution metrics")
    result = dict(zip(METRICS, map(int, values)))
    if any(v > 65536 for v in result.values()):
        raise ValueError("oversized RTL execution metric")
    return result


def validate_execution(metrics):
    """Fail closed unless one test proves complete CPU/backend progress."""
    if not isinstance(metrics, dict) or set(metrics) != set(METRICS):
        raise ValueError("execution acceptance failed: incomplete metrics")
    if any(type(value) is not int or value < 0 for value in metrics.values()):
        raise ValueError("execution acceptance failed: invalid metric")
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
