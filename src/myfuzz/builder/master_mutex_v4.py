"""Testcase-scoped CPU/trace master exclusivity boundary."""

from __future__ import annotations

from dataclasses import dataclass

from .input_model import InputValidationError


@dataclass(frozen=True)
class MasterMutexSnapshot:
    locked: bool
    trace_selected: bool
    cpu_drive: bool
    trace_drive: bool


class MasterMutexV4:
    def __init__(self) -> None:
        self.locked = False
        self.trace_selected = False

    def begin_testcase(self, *, trace_selected: bool) -> MasterMutexSnapshot:
        if self.locked:
            raise InputValidationError("master selection can change only at infrastructure reset")
        if not isinstance(trace_selected, bool):
            raise InputValidationError("trace_selected must be boolean")
        self.trace_selected = trace_selected
        self.locked = True
        return self.snapshot()

    def infrastructure_reset(self) -> MasterMutexSnapshot:
        self.locked = False
        self.trace_selected = False
        return self.snapshot()

    def snapshot(self) -> MasterMutexSnapshot:
        return MasterMutexSnapshot(self.locked, self.trace_selected, self.locked and not self.trace_selected, self.locked and self.trace_selected)


def emit_master_mutex_v4_rtl(module_name: str = "myfuzz_master_mutex_v4") -> str:
    if not module_name.isidentifier():
        raise InputValidationError("master mutex module name must be an identifier")
    return f'''module {module_name}(
  input logic clk_i, input logic infrastructure_reset_i,
  input logic select_trace_i, input logic cpu_valid_i, input logic trace_valid_i,
  output logic cpu_drive_o, output logic trace_drive_o, output logic locked_o,
  output logic trace_selected_o
);
  always_ff @(posedge clk_i) begin
    if (infrastructure_reset_i) begin
      locked_o <= 1'b0; trace_selected_o <= 1'b0;
    end else if (!locked_o) begin
      locked_o <= 1'b1; trace_selected_o <= select_trace_i;
    end
  end
  always_comb begin
    cpu_drive_o = locked_o && !trace_selected_o && cpu_valid_i;
    trace_drive_o = locked_o && trace_selected_o && trace_valid_i;
  end
endmodule
'''
