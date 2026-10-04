"""Generate bounded C++ transport around an admitted, complete runtime top."""
from __future__ import annotations

import copy
from dataclasses import replace
import hashlib
import json
from pathlib import Path

from .renderer import _sha
from .runtime_artifact import LocalRuntimeArtifact
from .runtime_renderer import render_local_runtime
from .axi4_fields import AXI_STEP_PORTS

_HEADERS = ('src/myfuzz/local_harness/rtl/local_driver_v1.h',
            'src/myfuzz/scenario/rtl/local_command_replay.h')
_SPI_HEADER = 'src/myfuzz/local_harness/rtl/pulp_spi_mode0_peer.h'
_I2C_HEADER = 'src/myfuzz/local_harness/rtl/pulp_i2c_single_slave_peer.h'


def _literal(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def render_local_driver(artifact: LocalRuntimeArtifact, *, base_dir: Path) -> LocalRuntimeArtifact:
    """Return new driver bytes/identity without changing the admitted runtime top.

    The final digest is injected as the bare lowercase-hex compile definition
    MYFUZZ_ARTIFACT_DIGEST and stringified by C++; embedding it in these bytes
    would create a circular digest. Builder admission must refresh header hashes.
    """
    if not isinstance(artifact, LocalRuntimeArtifact):
        raise ValueError('driver-artifact-required')
    if artifact.runtime_document.get('status') != 'top_only' or artifact.cpp_text:
        raise ValueError('driver-top-only-required')
    root = Path(base_dir).resolve()
    refreshed = render_local_runtime(artifact.plan, artifact.structural,
                                    artifact.source_verification, base_dir=root)
    if refreshed != artifact:
        raise ValueError('driver-runtime-identity-mismatch')
    document = copy.deepcopy(artifact.runtime_document)
    kind = document['kind']
    exports = document['physical_exports']
    backend = document['backend_ports']
    fields = {}
    if kind == 'apb_gpio':
        for role, alias in [('in', 'gpio_in'), ('out', 'gpio_out'), ('dir', 'gpio_dir'),
                            ('in_sync', 'gpio_in_sync'), ('padcfg', 'gpio_padcfg')]:
            rows = [row for row in exports if row['role'] == role]
            if len(rows) != 1:
                raise ValueError('driver-gpio-field:' + role)
            fields[alias] = rows[0]['runtime_name']
        pulses = [row for row in exports if row['endpoint_id'] is None and
                  row['disposition'] == 'observe' and row['direction'] == 'output' and row['width'] == 1]
        if len(pulses) != 1:
            raise ValueError('driver-gpio-pulse-observation-required')
        fields['interrupt'] = pulses[0]['runtime_name']
        allowed_inputs = {fields['gpio_in']}
    elif kind == 'tlul_gpio':
        for role, alias in [('in', 'gpio_in'), ('out', 'gpio_out'),
                            ('en', 'gpio_dir'), ('strap_en', 'strap_en')]:
            rows = [row for row in exports if row['endpoint_id'] == 'gpio.pins' and row['role'] == role]
            if len(rows) != 1:
                raise ValueError('driver-tlul-pin-field:' + role)
            fields[alias] = rows[0]['runtime_name']
        irq = [row for row in exports if row['endpoint_id'] == 'gpio.interrupts'
               and row['role'] == 'irq' and row['width'] == 32 and row['direction'] == 'output']
        if len(irq) != 1:
            raise ValueError('driver-tlul-irq-field')
        fields['interrupt'] = irq[0]['runtime_name']
        allowed_inputs = {fields['gpio_in'], fields['strap_en']}
    elif kind == 'tlul_timer':
        irq = [row for row in exports if row['endpoint_id'] == 'timer.interrupts'
               and row['role'] == 'irq' and row['width'] == 1 and row['direction'] == 'output']
        if len(irq) != 1:
            raise ValueError('driver-tlul-timer-irq-field')
        fields['irq'] = irq[0]['runtime_name']
        allowed_inputs = set()
    elif kind == 'wishbone_timer':
        irq = [row for row in exports if row['physical_port'] == 'o_int'
               and row['width'] == 1 and row['direction'] == 'output'
               and row['disposition'] == 'observe']
        if len(irq) != 1:
            raise ValueError('driver-timer-native-irq-required')
        fields['interrupt'] = irq[0]['runtime_name']
        allowed_inputs = set()
    elif kind == 'apb_spi':
        for role in ('sck', 'mode', *(f'csn{i}' for i in range(4)),
                     *(f'sdo{i}' for i in range(4)), *(f'sdi{i}' for i in range(4))):
            rows = [row for row in exports if row['endpoint_id'] == 'spi.pins' and row['role'] == role]
            if len(rows) != 1:
                raise ValueError('driver-spi-pin-field:' + role)
            fields['spi_' + ('clk' if role == 'sck' else role)] = rows[0]['runtime_name']
        events = [row for row in exports if row['physical_port'] == 'events_o'
                  and row['disposition'] == 'observe' and row['width'] == 2]
        if len(events) != 1:
            raise ValueError('driver-spi-native-events-required')
        fields['events_o'] = events[0]['runtime_name']
        allowed_inputs = {fields[f'spi_sdi{i}'] for i in range(4)}
    elif kind == 'apb_timer':
        events = [row for row in exports if row['physical_port'] == 'irq_o'
                  and row['disposition'] == 'observe' and row['direction'] == 'output'
                  and row['width'] == 4]
        if len(events) != 1:
            raise ValueError('driver-timer-native-events-required')
        fields['irq_o'] = events[0]['runtime_name']
        allowed_inputs = set()
    elif kind == 'axi4_lite_uart':
        for role in ('rx', 'tx', 'cts_n', 'rts_n'):
            rows = [row for row in exports if row['endpoint_id'] == 'uart.pins'
                    and row['role'] == role and row['width'] == 1]
            if len(rows) != 1:
                raise ValueError('driver-axi-lite-uart-pin:' + role)
            fields['uart_' + role] = rows[0]['runtime_name']
        for role in ('rx', 'tx', 'rxfifo', 'txfifo'):
            rows = [row for row in exports if row['endpoint_id'] == 'uart.interrupts'
                    and row['role'] == role and row['width'] == 1]
            if len(rows) != 1:
                raise ValueError('driver-axi-lite-uart-interrupt:' + role)
            fields['uart_' + role + '_int'] = rows[0]['runtime_name']
        allowed_inputs = {fields['uart_rx'], fields['uart_cts_n']}
    elif kind == 'apb_i2c':
        for role in ('scl_pad_i', 'scl_pad_o', 'scl_padoen_o',
                     'sda_pad_i', 'sda_pad_o', 'sda_padoen_o'):
            rows = [row for row in exports if row['role'] == role]
            if len(rows) != 1 or rows[0]['width'] != 1:
                raise ValueError('driver-i2c-pin-field:' + role)
            fields[role] = rows[0]['runtime_name']
        irq = [row for row in exports if row['physical_port'] == 'interrupt_o'
               and row['disposition'] == 'observe' and row['direction'] == 'output'
               and row['width'] == 1]
        if len(irq) != 1:
            raise ValueError('driver-i2c-native-irq-required')
        fields['interrupt_o'] = irq[0]['runtime_name']
        allowed_inputs = {fields['scl_pad_i'], fields['sda_pad_i']}
    elif kind in ('native_memory_cpu', 'wishbone_cpu', 'axi4_lite_cpu', 'axi4_cpu'):
        allowed_inputs = set()
    elif kind == 'obi_cpu':
        cpu = artifact.plan.profile.cpu
        irq = [row for row in exports if row['endpoint_id'] == cpu.irq_entry_endpoint and
               row['role'] == cpu.irq_entry_role and row['direction'] == 'input' and row['width'] == 1]
        if len(irq) != 1:
            raise ValueError('driver-cpu-irq-field')
        fields['irq_external'] = irq[0]['runtime_name']
        allowed_inputs = {fields['irq_external']}
    else:
        raise ValueError('driver-runtime-kind')
    if {row['runtime_name'] for row in exports if row['direction'] == 'input'} != allowed_inputs:
        raise ValueError('driver-unmapped-physical-input')
    ports = document['runtime_ports']
    initializers = '\n'.join(f'  dut.{row["name"]} = 0;' for row in ports if row['direction'] == 'input')

    def signal(row, name_key='runtime_name'):
        name, width = row[name_key], row['width']
        return (f'quote(wide_hex(dut.{name}, {width}))' if width > 64
                else f'std::to_string(static_cast<std::uint64_t>(dut.{name}))')

    backend_items = ',\n'.join('    {' + _literal(row['name']) + ', ' + signal(row, 'name') + '}' for row in backend)
    physical_items = ',\n'.join('    {' + _literal(row['runtime_name']) + ', ' + signal(row) + '}' for row in exports)
    aliases = ''
    if kind in ('apb_gpio', 'apb_spi', 'apb_timer', 'tlul_gpio', 'tlul_timer',
                'wishbone_timer', 'axi4_lite_uart', 'apb_i2c'):
        by_name = {row['runtime_name']: row for row in exports}
        aliases = ''.join(f'  values[{_literal(alias)}] = {signal(by_name[name])};\n'
                          for alias, name in fields.items()
                          if (kind in ('apb_gpio', 'tlul_gpio') and alias not in ('gpio_in', 'strap_en'))
                          or kind == 'wishbone_timer'
                          or kind == 'apb_timer'
                          or kind == 'tlul_timer'
                          or (kind == 'apb_spi' and (alias == 'events_o' or not alias.startswith('spi_sdi')))
                          or (kind == 'axi4_lite_uart' and alias not in ('uart_rx', 'uart_cts_n'))
                          or kind == 'apb_i2c')

    max_wait = document['effective_max_wait_cycles']
    max_samples = (1 if kind in ('obi_cpu', 'native_memory_cpu',
                                'wishbone_cpu', 'axi4_lite_cpu', 'axi4_cpu')
                   else 2 * max_wait + 5)
    # Conservative serialized upper bound, before issuing any command effects.
    maxima_backend = {row['name']: (1 << row['width']) - 1 for row in backend}
    maxima_physical = {row['runtime_name']: ('f' * row['hex_digits'] if row['width'] > 64
                                            else (1 << row['width']) - 1) for row in exports}
    maximum_snapshot = dict(backend=maxima_backend, physical=maxima_physical)
    for alias, name in fields.items():
        if ((kind in ('apb_gpio', 'tlul_gpio') and alias not in ('gpio_in', 'strap_en'))
                or kind == 'wishbone_timer'
                or kind == 'apb_timer'
                or kind == 'tlul_timer'
                or (kind == 'apb_spi' and (alias == 'events_o' or not alias.startswith('spi_sdi')))
                or (kind == 'axi4_lite_uart' and alias not in ('uart_rx', 'uart_cts_n'))
                or kind == 'apb_i2c'):
            maximum_snapshot[alias] = maxima_physical[name]
    snapshot_size = len(json.dumps(maximum_snapshot, sort_keys=True, separators=(',', ':')))
    # 128 bytes per sample exceeds its numeric tick and object delimiters;
    # 1024 covers root keys, pre_backend, RESULT identity, and terminal ERROR.
    reservation = 2 * (max_samples * (2 * snapshot_size + 128) +
                       snapshot_size + len(json.dumps(maxima_backend)) + 1024) + 512
    if reservation > 2 * 1024 * 1024 + 512:
        raise ValueError('driver-result-reservation-too-large')

    if kind == 'axi4_lite_uart':
        dispatch = f'''      dut.{fields['uart_rx']} = command.fields[0];
      dut.{fields['uart_cts_n']} = command.fields[1];
      dut.eval();
      pre_backend = backend_snapshot(dut);
      if (command.operation == "STEP_AXIL_UART") {{
        tick(dut, &samples);
      }} else {{
        const bool write = command.fields[2] != 0;
        const unsigned address = command.fields[3];
        if (write) {{
          dut.axil_awaddr = address; dut.axil_awprot = 0; dut.axil_awvalid = 1;
          dut.axil_wdata = command.fields[4]; dut.axil_wstrb = command.fields[5];
          dut.axil_wvalid = 1; dut.axil_bready = 1;
          bool aw_done = false, w_done = false, b_done = false;
          for (unsigned waits = 0; waits < {2 * max_wait + 5}; ++waits) {{
            dut.eval();
            const bool aw = !aw_done && dut.axil_awvalid && dut.axil_awready;
            const bool w = !w_done && dut.axil_wvalid && dut.axil_wready;
            const bool b = aw_done && w_done && dut.axil_bvalid && dut.axil_bready;
            if (b) {{ error = dut.axil_bresp; b_done = true; }}
            tick(dut, &samples);
            if (aw) {{ aw_done = true; dut.axil_awvalid = 0; }}
            if (w) {{ w_done = true; dut.axil_wvalid = 0; }}
            if (b_done) break;
          }}
          dut.axil_bready = 0;
          if (!aw_done || !w_done || !b_done) throw std::runtime_error("axil_write_timeout");
        }} else {{
          dut.axil_araddr = address; dut.axil_arprot = 0; dut.axil_arvalid = 1;
          dut.axil_rready = 1;
          bool ar_done = false, r_done = false;
          for (unsigned waits = 0; waits < {2 * max_wait + 5}; ++waits) {{
            dut.eval();
            const bool ar = !ar_done && dut.axil_arvalid && dut.axil_arready;
            const bool r = ar_done && dut.axil_rvalid && dut.axil_rready;
            if (r) {{ rdata = dut.axil_rdata; error = dut.axil_rresp; r_done = true; }}
            tick(dut, &samples);
            if (ar) {{ ar_done = true; dut.axil_arvalid = 0; }}
            if (r_done) break;
          }}
          dut.axil_rready = 0;
          if (!ar_done || !r_done) throw std::runtime_error("axil_read_timeout");
        }}
        dut.eval();
      }}
'''
        operation_check = ('command.operation != "STEP_AXIL_UART" && '
                           'command.operation != "ACCESS_AXIL_UART"')
    elif kind == 'axi4_cpu':
        assignments = '\n'.join(f'      dut.{name} = command.fields[{index}];'
                                for index, name in enumerate(AXI_STEP_PORTS))
        dispatch = assignments + '''
      dut.eval();
      pre_backend = backend_snapshot(dut);
      tick(dut, &samples);
'''
        operation_check = 'command.operation != "STEP_AXI4"'
    elif kind == 'wishbone_cpu':
        dispatch = r'''      dut.wb_ack = command.fields[0];
      dut.wb_dat_r = command.fields[1];
      dut.eval();
      pre_backend = backend_snapshot(dut);
      if (dut.wb_ack && !(dut.wb_cyc && dut.wb_stb)) {
        terminal = error_reply(command.execution, command.sequence, local_ticks,
                               "protocol_environment", "wishbone_unsolicited_ack");
      } else {
        tick(dut, &samples);
      }
'''
        operation_check = 'command.operation != "STEP_WISHBONE"'
    elif kind in ('native_memory_cpu', 'axi4_lite_cpu'):
        dispatch = "\n".join(f'      dut.{name} = command.fields[{index}];' for index, name in enumerate([
            'm_req_ready', 'm_rsp_valid', 'm_rsp_rdata', 'm_rsp_error'])) + r'''
      dut.eval();
      pre_backend = backend_snapshot(dut);
      if (@FAULT_CHECK@ || (dut.m_rsp_valid && !dut.m_rsp_ready)) {
        terminal = error_reply(command.execution, command.sequence, local_ticks,
                               "protocol_environment", "native_unsolicited_or_fault");
      } else {
        tick(dut, &samples);
        if (@FAULT_CHECK@) {
          terminal = error_reply(command.execution, command.sequence, local_ticks,
                                 "protocol_environment", "native_completion_fault");
        }
      }
'''
        dispatch = dispatch.replace('@FAULT_CHECK@', 'dut.m_fault' if kind == 'native_memory_cpu' else 'false')
        operation_check = 'command.operation != "STEP_MEMORY"'
    elif kind == 'obi_cpu':
        assignments = '\n'.join(f'      dut.{name} = command.fields[{index}];' for index, name in enumerate([
            fields['irq_external'], 'i_req_ready', 'i_rsp_valid', 'i_rsp_rdata', 'i_rsp_error',
            'd_req_ready', 'd_rsp_valid', 'd_rsp_rdata', 'd_rsp_error']))
        dispatch = assignments + '''
      dut.eval();
      pre_backend = backend_snapshot(dut);
      if ((dut.i_rsp_valid && !dut.i_rsp_ready) || (dut.d_rsp_valid && !dut.d_rsp_ready)) {
        terminal = error_reply(command.execution, command.sequence, local_ticks,
                               "protocol_environment", "unsolicited_response");
      } else {
        tick(dut, &samples);
      }
'''
        operation_check = 'command.operation != "STEP_CPU"'
    else:
        spi = kind == 'apb_spi'
        timer = kind in ('apb_timer', 'wishbone_timer', 'tlul_timer')
        channel = ('spi' if spi else 'timer' if timer else
                   'i2c' if kind == 'apb_i2c' else 'gpio')
        command_channel = ('TLUL_GPIO' if kind == 'tlul_gpio' else
                           'TLUL_TIMER' if kind == 'tlul_timer' else
                           'WB_TIMER' if kind == 'wishbone_timer' else channel.upper())
        input_assignment = (f'      dut.{fields["gpio_in"]} = command.fields[0];\n'
                            if kind in ('apb_gpio', 'tlul_gpio') else '')
        if kind == 'tlul_gpio':
            input_assignment += f'      dut.{fields["strap_en"]} = command.fields[1];\n'
        index = 2 if kind == 'tlul_gpio' else 1 if kind == 'apb_gpio' else 0
        source_branch = '''      if (command.operation == "SOURCE_SPI") {
        peer.append(command.fields[0], command.fields[1], command.fields[2]);
        dut.eval();
        pre_backend = backend_snapshot(dut);
      } else {
''' if spi else '''      if (command.operation == "SOURCE_I2C") {
        pre_backend = backend_snapshot(dut);
        if (!peer.set_response(static_cast<std::uint8_t>(command.fields[0]))) {
          terminal = error_reply(command.execution, command.sequence, local_ticks,
                                 "invalid_source", "peer_response_already_bound");
        }
      } else {
''' if kind == 'apb_i2c' else ''
        dispatch = input_assignment + source_branch + f'''      dut.eval();
      if (command.operation == "STEP_{command_channel}") {{
        pre_backend = backend_snapshot(dut);
        tick(dut, &samples);
      }} else {{
        dut.{channel}_req_valid = 1;
        dut.{channel}_req_write = command.fields[{index}];
        dut.{channel}_req_addr = command.fields[{index+1}];
        dut.{channel}_req_wdata = command.fields[{index+2}];
        dut.{channel}_req_be = command.fields[{index+3}];
        dut.{channel}_rsp_ready = 0;
        dut.eval();
        pre_backend = backend_snapshot(dut);
        unsigned waits = 0;
        while (!dut.{channel}_req_ready) {{
          if (waits++ >= {max_wait}) throw std::runtime_error("request_timeout");
          tick(dut, &samples);
        }}
        tick(dut, &samples);
        dut.{channel}_req_valid = 0;
        dut.eval();
        waits = 0;
        while (!dut.{channel}_rsp_valid) {{
          if (waits++ >= {max_wait + 3}) throw std::runtime_error("response_timeout");
          tick(dut, &samples);
        }}
        rdata = dut.{channel}_rsp_rdata;
        error = dut.{channel}_rsp_error;
        dut.{channel}_rsp_ready = 1;
        tick(dut, &samples);
        dut.{channel}_rsp_ready = 0;
        dut.eval();
      }}
''' + ('      }\n' if spi or kind == 'apb_i2c' else '')
        operation_check = (f'command.operation != "STEP_{command_channel}" && '
                           f'command.operation != "ACCESS_{command_channel}"' +
                           (' && command.operation != "SOURCE_SPI"' if spi else
                            ' && command.operation != "SOURCE_I2C"'
                            if kind == 'apb_i2c' else ''))

    spi_active_cs = ' | '.join(f'((!dut.{fields[f"spi_csn{i}"]}) << {i})' for i in range(4)) if kind == 'apb_spi' else ''
    spi_observe = (f'peer.observe(dut.{fields["spi_clk"]}, {spi_active_cs}, '
                   f'dut.{fields["spi_mode"]}, dut.{fields["spi_sdo0"]});') if kind == 'apb_spi' else ''
    spi_drive = ('  ' + '\n  '.join(f'dut.{fields[f"spi_sdi{i}"]} = '
                                      + ('peer.drive_bit();' if i == 1 else '0;')
                                      for i in range(4)) + '\n') if kind == 'apb_spi' else ''
    i2c_resolve = (f'  dut.{fields["scl_pad_i"]} = dut.{fields["scl_padoen_o"]} ? 1 : 0;\n'
                   f'  dut.{fields["sda_pad_i"]} = '
                   f'(dut.{fields["sda_padoen_o"]} && !peer.sda_low()) ? 1 : 0;\n'
                   '  dut.eval();') if kind == 'apb_i2c' else ''
    i2c_observe = (f'  peer.observe(dut.{fields["scl_pad_i"]}, dut.{fields["sda_pad_i"]}, '
                   f'dut.{fields["scl_pad_o"]}, dut.{fields["sda_pad_o"]}, '
                   f'dut.{fields["scl_padoen_o"]}, dut.{fields["sda_padoen_o"]});') if kind == 'apb_i2c' else ''
    template = r'''#include "V@MODULE@.h"
#include "verilated.h"
#include "local_driver_v1.h"
@SPI_HEADER@
@I2C_HEADER@
#include <iostream>
#include <map>
#include <string>
#include <vector>

#ifndef MYFUZZ_ARTIFACT_DIGEST
#error MYFUZZ_ARTIFACT_DIGEST must identify the final generated artifact
#endif
#define MYFUZZ_STRINGIFY_IMPL(value) #value
#define MYFUZZ_STRINGIFY(value) MYFUZZ_STRINGIFY_IMPL(value)

using Model = V@MODULE@;
using namespace myfuzz::local_driver_v1;
using JsonObject = std::map<std::string, std::string>;
static std::uint64_t local_ticks = 0;
@SPI_PEER@

static std::string quote(const std::string &value) {
  return "\"" + value + "\"";
}
static std::string object(const JsonObject &values) {
  std::string answer = "{";
  for (const auto &entry : values) {
    if (answer.size() > 1) answer += ',';
    answer += quote(entry.first) + ':' + entry.second;
  }
  return answer + '}';
}
static std::string array(const std::vector<std::string> &values) {
  std::string answer = "[";
  for (const auto &value : values) {
    if (answer.size() > 1) answer += ',';
    answer += value;
  }
  return answer + ']';
}
template <typename Wide>
static std::string wide_hex(const Wide &value, unsigned width) {
  const char *digits = "0123456789abcdef";
  std::string answer((width + 3) / 4, '0');
  for (unsigned nibble = 0; nibble < answer.size(); ++nibble) {
    const unsigned bit = 4 * nibble;
    const unsigned remaining = width - bit;
    const unsigned mask = remaining < 4 ? (1u << remaining) - 1 : 15;
    answer[answer.size() - nibble - 1] = digits[(value[bit / 32] >> (bit % 32)) & mask];
  }
  return answer;
}
static std::string backend_snapshot(const Model &dut) {
  return object({
@BACKEND@
  });
}
static std::string snapshot(const Model &dut) {
  JsonObject values = {
    {"backend", backend_snapshot(dut)},
    {"physical", object({
@PHYSICAL@
    })}
  };
@ALIASES@  return object(values);
}
static void tick(Model &dut, std::vector<std::string> *samples) {
@SPI_DRIVE@
  dut.clk = 0; dut.eval();
@I2C_RESOLVE@
@SPI_OBSERVE@
@I2C_OBSERVE@
  const auto pre = samples ? snapshot(dut) : "";
  dut.clk = 1; dut.eval();
@I2C_RESOLVE@
  ++local_ticks;
@SPI_OBSERVE@
@I2C_OBSERVE@
  const auto post = samples ? snapshot(dut) : "";
  dut.clk = 0; dut.eval();
  if (samples) samples->push_back(object({{"local_tick", std::to_string(local_ticks)},
                                       {"pre", pre}, {"post", post}}));
}
static std::string encode_hex(const std::string &value) {
  if (value.size() > kMaxPayloadJsonBytes) throw std::length_error("payload_bound");
  const char *digits = "0123456789abcdef";
  std::string answer;
  answer.reserve(2 * value.size());
  for (const unsigned char byte : value) {
    answer += digits[byte >> 4];
    answer += digits[byte & 15];
  }
  return answer;
}
// A bounded reader never materializes an arbitrarily long input line. Oversize
// input is drained through newline, then rejected before replay admission.
static bool read_command(std::string &line, bool &oversize) {
  line.clear(); oversize = false;
  char byte;
  while (std::cin.get(byte)) {
    if (byte == '\n') return true;
    if (line.size() < kMaxCommandBytes) line += byte;
    else oversize = true;
  }
  return !line.empty() || oversize;
}
int main(int argc, char **argv) {
  Verilated::commandArgs(argc, argv);
  Model dut;
@INITIALIZERS@
  // Evaluate inactive reset first to create a real asynchronous assertion edge.
  dut.reset = 0; dut.eval();
  dut.reset = 1; dut.eval();
  std::uint64_t asserted_ticks = 0, released_ticks = 0;
  for (unsigned i = 0; i < @ASSERT@; ++i) {
    tick(dut, nullptr);
    ++asserted_ticks;
  }
  dut.reset = 0; dut.eval();
  for (unsigned i = 0; i < @RELEASE@; ++i) {
    tick(dut, nullptr);
    ++released_ticks;
  }
  local_ticks = 0;
  std::cout << "READY local_driver.v1 " << MYFUZZ_STRINGIFY(MYFUZZ_ARTIFACT_DIGEST)
            << " " << hex_integer(asserted_ticks) << " " << hex_integer(released_ticks) << std::endl;
  BoundedReplay replay(@CACHE@, kMaxReplyBytes);
  std::string line;
  bool oversize;
  while (read_command(line, oversize)) {
    if (!oversize && line == "END") break;
    if (oversize) {
      std::cout << error_reply("-", 0, local_ticks, "command_too_long", "wire_bound") << std::endl;
      continue;
    }
    const auto parsed = parse_command(line);
    if (!parsed.ok) {
      std::cout << error_reply(parsed.command.execution, parsed.command.sequence,
          local_ticks, parsed.code, parsed.detail) << std::endl;
      continue;
    }
    const auto &command = parsed.command;
    if (@OPERATION_CHECK@) {
      std::cout << error_reply(command.execution, command.sequence, local_ticks,
                              "invalid_operation", "wrong_runtime_kind") << std::endl;
      continue;
    }
    const auto admission = replay.accept(command, local_ticks, @RESERVATION@);
    if (admission.decision != Decision::Fresh) {
      std::cout << admission.reply << std::endl;
      continue;
    }
    const auto before = local_ticks;
    std::vector<std::string> samples;
    std::string pre_backend, terminal;
    std::uint32_t rdata = 0, error = 0;
    try {
@DISPATCH@
      if (terminal.empty()) {
        const auto payload = object({
          {"schema_version", quote("local_driver_result.v1")}, {"kind", quote("@KIND@")},
          {"samples", array(samples)}, {"observations", snapshot(dut)},
          {"pre_backend", pre_backend}, {"rdata", std::to_string(rdata)},
          {"error", std::to_string(error)}
        });
        terminal = "RESULT " + command.execution + ' ' + hex_integer(command.sequence) + ' ' +
            hex_integer(before) + ' ' + hex_integer(local_ticks) + ' ' + encode_hex(payload);
      }
      replay.finish(command.sequence, terminal);
      std::cout << terminal << std::endl;
    } catch (const std::exception &) {
      const auto failure = error_reply(command.execution, command.sequence, local_ticks,
                                       "uncertain_effect", "driver_execution_failed");
      // Best effort receipt; incomplete replay still prevents another execution.
      try { replay.finish(command.sequence, failure); } catch (const std::exception &) {}
      std::cout << failure << std::endl;
      break;
    }
  }
  dut.final();
  return 0;
}
'''
    values = dict(MODULE=document['module_name'], BACKEND=backend_items, PHYSICAL=physical_items,
                  ALIASES=aliases, INITIALIZERS=initializers,
                  SPI_HEADER='#include "pulp_spi_mode0_peer.h"' if kind == 'apb_spi' else '',
                  I2C_HEADER='#include "pulp_i2c_single_slave_peer.h"' if kind == 'apb_i2c' else '',
                  SPI_PEER=('static PulpSpiMode0Peer peer;' if kind == 'apb_spi' else
                            'static PulpI2cSingleSlavePeer peer;' if kind == 'apb_i2c' else ''),
                  SPI_DRIVE=spi_drive, SPI_OBSERVE=spi_observe,
                  I2C_RESOLVE=i2c_resolve, I2C_OBSERVE=i2c_observe,
                  ASSERT=str(artifact.plan.request.reset_assert_ticks),
                  RELEASE=str(artifact.plan.request.reset_release_ticks), CACHE=str(64 * 1024 * 1024),
                  RESERVATION=str(reservation), OPERATION_CHECK=operation_check,
                  DISPATCH=dispatch, KIND=kind)
    cpp = template
    for key, value in values.items():
        cpp = cpp.replace('@' + key + '@', value)
    headers = [{'path': name, 'sha256': hashlib.sha256((root / name).read_bytes()).hexdigest()}
               for name in (*_HEADERS, *([_SPI_HEADER] if kind == 'apb_spi' else []),
                            *([_I2C_HEADER] if kind == 'apb_i2c' else []))]
    document.update(driver_schema_version='local_driver_generation.v1', status='driver_generated',
                    driver_status='generated', driver_header_sources=headers,
                    cpp_sha256=hashlib.sha256(cpp.encode()).hexdigest(),
                    driver_field_map=fields,
                    driver_reset=dict(schema_version='generated_local_reset.v1',
                        reset_assert_ticks=artifact.plan.request.reset_assert_ticks,
                        reset_release_ticks=artifact.plan.request.reset_release_ticks),
                    driver_limits=dict(max_command_bytes=1024, max_payload_json_bytes=1024 * 1024,
                        max_reply_line_bytes=2 * 1024 * 1024 + 512,
                        max_cached_bytes=64 * 1024 * 1024,
                        reply_reservation_bytes=reservation, max_samples_per_command=max_samples))
    document.pop('artifact_digest')
    document['artifact_digest'] = _sha(document)
    return replace(copy.deepcopy(artifact), cpp_text=cpp, runtime_document=document)
