#pragma once

#include "../../scenario/rtl/local_command_replay.h"

#include <cstdint>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// Versioned boundary for generated drivers; no DUT or simulator dependency.
// getline callers pass a line without its newline. Commands use single ASCII
// spaces and lowercase hex, without signs/prefixes. END is handled by the owner.
namespace myfuzz {
namespace local_driver_v1 {

inline constexpr const char *kVersion = "local_driver.v1";
inline constexpr std::size_t kMaxCommandBytes = 1024;
// The wire limit includes two hex characters per decoded JSON byte.
inline constexpr std::size_t kMaxPayloadJsonBytes = 1024 * 1024;
inline constexpr std::size_t kMaxPayloadHexBytes = 2 * kMaxPayloadJsonBytes;
inline constexpr std::size_t kMaxReplyBytes = kMaxPayloadHexBytes + 512;

inline std::string hex_integer(std::uint64_t value) {
  std::ostringstream stream;
  stream << std::hex << value;
  return stream.str();
}

inline bool parse_hex(const std::string &token, std::uint64_t maximum,
                      std::uint64_t &value) {
  if (token.empty() || token.size() > 16) return false;
  value = 0;
  for (const char character : token) {
    std::uint64_t digit;
    if (character >= '0' && character <= '9') digit = character - '0';
    else if (character >= 'a' && character <= 'f') digit = character - 'a' + 10;
    else return false;
    if (digit > maximum || value > (maximum - digit) / 16) return false;
    value = value * 16 + digit;
  }
  return true;
}

// This validates/decodes only the wire bytes. The session must additionally
// enforce UTF-8, canonical JSON and local_driver_result.v1 payload schema.
inline std::string decode_payload_hex(const std::string &encoded) {
  if (encoded.empty() || encoded.size() % 2 != 0 ||
      encoded.size() > kMaxPayloadHexBytes ||
      encoded.size() / 2 > kMaxPayloadJsonBytes)
    throw std::invalid_argument("invalid payload hex length");
  std::string decoded;
  decoded.reserve(encoded.size() / 2);
  for (std::size_t index = 0; index < encoded.size(); index += 2) {
    std::uint64_t byte;
    if (!parse_hex(encoded.substr(index, 2), 255, byte))
      throw std::invalid_argument("invalid payload hex encoding");
    decoded += static_cast<char>(byte);
  }
  return decoded;
}

inline bool valid_execution(const std::string &execution) {
  if (execution.size() != 32) return false;
  for (const char character : execution) {
    if (!((character >= '0' && character <= '9') ||
          (character >= 'a' && character <= 'f'))) return false;
  }
  return true;
}

struct Command {
  // Invalid/unparsed identity uses '-' and 0 in the parse-error envelope.
  std::string execution = "-";
  std::uint64_t sequence = 0;
  std::string operation;
  std::vector<std::uint64_t> fields;
  std::string request;
};

struct ParseResult {
  bool ok = false;
  Command command;
  std::string code = "invalid_command";
  std::string detail = "invalid_grammar";
};

struct AckResult {
  bool ok = false;
  std::string execution = "-";
  std::uint64_t sequence = 0;
  std::string code = "invalid_ack";
  std::string detail = "invalid_grammar";
};

inline AckResult parse_ack(const std::string &line) {
  AckResult result;
  if (line.size() > kMaxCommandBytes) return result;
  std::istringstream input(line);
  std::string marker, execution, sequence, extra;
  if (!(input >> marker >> execution >> sequence) || input >> extra ||
      marker != "ACK" || line != marker + " " + execution + " " + sequence)
    return result;
  if (!valid_execution(execution)) {
    result.code = "invalid_execution";
    result.detail = "invalid_identity";
    return result;
  }
  result.execution = execution;
  if (!parse_hex(sequence, std::numeric_limits<std::uint64_t>::max(),
                 result.sequence) || result.sequence == 0) {
    result.sequence = 0;
    result.code = "invalid_sequence";
    result.detail = "invalid_identity";
    return result;
  }
  result.ok = true;
  return result;
}

inline ParseResult parse_command(const std::string &line) {
  ParseResult result;
  if (line.size() > kMaxCommandBytes) {
    result.code = "command_too_long";
    result.detail = "wire_bound";
    return result;
  }
  std::vector<std::string> tokens;
  std::string token;
  for (const char character : line) {
    if (character == ' ') {
      if (token.empty()) return result;
      tokens.push_back(token);
      token.clear();
    } else {
      if (character < '!' || character > '~') return result;
      token += character;
    }
  }
  if (token.empty()) return result;
  tokens.push_back(token);
  if (tokens.size() < 4 || tokens[0] != "CMD") return result;
  if (!valid_execution(tokens[1])) {
    result.code = "invalid_execution";
    result.detail = "invalid_identity";
    return result;
  }
  result.command.execution = tokens[1];
  if (!parse_hex(tokens[2], std::numeric_limits<std::uint64_t>::max(),
                 result.command.sequence) || result.command.sequence == 0) {
    result.command.sequence = 0;
    result.code = "invalid_sequence";
    result.detail = "invalid_identity";
    return result;
  }
  result.command.operation = tokens[3];
  constexpr std::uint64_t word = 0xffffffffULL;
  std::vector<std::uint64_t> maxima;
  if (tokens[3] == "STEP_CPU") maxima = {1, 1, 1, word, 1, 1, 1, word, 1};
  else if (tokens[3] == "STEP_AXI4") {
    for (unsigned bus = 0; bus < 2; ++bus) {
      const std::vector<std::uint64_t> channel =
          {1, 1, 1, 1, 3, 1, 1, 1, word, 1, 3};
      maxima.insert(maxima.end(), channel.begin(), channel.end());
    }
  }
  else if (tokens[3] == "STEP_CVA6_AXI4") {
    maxima = {1, 1, 1, 1, 1, 15, 3,
              std::numeric_limits<std::uint64_t>::max(),
              1, 1, 15,
              std::numeric_limits<std::uint64_t>::max(),
              1, 3,
              std::numeric_limits<std::uint64_t>::max()};
  }
  else if (tokens[3] == "STEP_WISHBONE") maxima = {1, word};
  else if (tokens[3] == "STEP_WISHBONE_IRQ") maxima = {1, word, word};
  else if (tokens[3] == "STEP_MEMORY") maxima = {1, 1, word, 1};
  else if (tokens[3] == "STEP_RVX_MEMORY") maxima = {1, 1, word};
  else if (tokens[3] == "STEP_GPIO") maxima = {word};
  else if (tokens[3] == "ACCESS_GPIO") maxima = {word, 1, 4092, word, 15};
  else if (tokens[3] == "STEP_TLUL_GPIO") maxima = {word, 1};
  else if (tokens[3] == "ACCESS_TLUL_GPIO") maxima = {word, 1, 1, 124, word, 15};
  else if (tokens[3] == "STEP_TLUL_TIMER") maxima = {};
  else if (tokens[3] == "ACCESS_TLUL_TIMER") maxima = {1, 4092, word, 15};
  else if (tokens[3] == "STEP_TLUL_SPI_HOST") maxima = {15};
  else if (tokens[3] == "ACCESS_TLUL_SPI_HOST") maxima = {15, 1, 4092, word, 15};
  else if (tokens[3] == "STEP_TLUL_UART") maxima = {1};
  else if (tokens[3] == "ACCESS_TLUL_UART") maxima = {1, 1, 4092, word, 15};
  else if (tokens[3] == "STEP_TLUL_I2C") maxima = {};
  else if (tokens[3] == "ACCESS_TLUL_I2C") maxima = {1, 124, word, 15};
  else if (tokens[3] == "SOURCE_TLUL_I2C") maxima = {255};
  else if (tokens[3] == "STEP_TLUL_REG") maxima = {};
  else if (tokens[3] == "ACCESS_TLUL_REG") maxima = {1, 8188, word, 15};
  else if (tokens[3] == "SOURCE_TLUL_REG") maxima = {63, std::numeric_limits<std::uint64_t>::max()};
  else if (tokens[3] == "BIND_TLUL_REG") maxima = {63, std::numeric_limits<std::uint64_t>::max()};
  else if (tokens[3] == "STEP_APB3_REG") maxima = {};
  else if (tokens[3] == "ACCESS_APB3_REG") maxima = {1, 4092, word, 15};
  else if (tokens[3] == "SOURCE_APB3_REG") maxima = {63, std::numeric_limits<std::uint64_t>::max()};
  else if (tokens[3] == "BIND_APB3_REG") maxima = {63, std::numeric_limits<std::uint64_t>::max()};
  else if (tokens[3] == "STEP_WB_REG") maxima = {};
  else if (tokens[3] == "ACCESS_WB_REG") maxima = {1, 4092, word, 15};
  else if (tokens[3] == "STEP_TLUL_SPI_DEVICE") maxima = {1, 1, 1, 15};
  else if (tokens[3] == "ACCESS_TLUL_SPI_DEVICE") maxima = {1, 1, 1, 15, 1, 8188, word, 15};
  else if (tokens[3] == "STEP_WB_TIMER") maxima = {};
  else if (tokens[3] == "ACCESS_WB_TIMER") maxima = {1, 0, word, 15};
  else if (tokens[3] == "STEP_WB_UART") maxima = {1, 1};
  else if (tokens[3] == "ACCESS_WB_UART") maxima = {1, 1, 1, 12, word, 15};
  else if (tokens[3] == "STEP_SPI") maxima = {1};
  else if (tokens[3] == "ACCESS_SPI") maxima = {1, 4092, word, 15};
  else if (tokens[3] == "STEP_TIMER") maxima = {1};
  else if (tokens[3] == "ACCESS_TIMER") maxima = {1, 4092, word, 15};
  else if (tokens[3] == "STEP_AXIL_UART") maxima = {1, 1};
  else if (tokens[3] == "ACCESS_AXIL_UART") maxima = {1, 1, 1, 12, word, 15};
  else if (tokens[3] == "STEP_I2C") maxima = {1};
  else if (tokens[3] == "ACCESS_I2C") maxima = {1, 4092, word, 15};
  else if (tokens[3] == "SOURCE_I2C") maxima = {255};
  else if (tokens[3] == "SOURCE_SPI") maxima = {3, word, 32};
  else {
    result.code = "invalid_operation";
    result.detail = "unknown_operation";
    return result;
  }
  if (tokens.size() != maxima.size() + 4) {
    result.code = "invalid_fields";
    result.detail = "field_count";
    return result;
  }
  for (std::size_t index = 0; index < maxima.size(); ++index) {
    std::uint64_t value;
    if (!parse_hex(tokens[index + 4], maxima[index], value)) {
      result.code = "invalid_fields";
      result.detail = "field_range_or_encoding";
      return result;
    }
    result.command.fields.push_back(value);
  }
  if ((tokens[3] == "ACCESS_TLUL_SPI_HOST" && result.command.fields[2] % 4 != 0) ||
      (tokens[3] == "ACCESS_GPIO" && result.command.fields[2] % 4 != 0) ||
      (tokens[3] == "ACCESS_TLUL_GPIO" && result.command.fields[3] % 4 != 0) ||
      (tokens[3] == "ACCESS_TLUL_TIMER" && result.command.fields[1] % 4 != 0) ||
      (tokens[3] == "ACCESS_TLUL_REG" && result.command.fields[1] % 4 != 0) ||
      (tokens[3] == "ACCESS_APB3_REG" &&
       (result.command.fields[1] % 4 != 0 || result.command.fields[3] != 15)) ||
      (tokens[3] == "ACCESS_WB_UART" && result.command.fields[3] % 4 != 0) ||
      (tokens[3] == "ACCESS_TLUL_UART" && result.command.fields[2] % 4 != 0) ||
      (tokens[3] == "ACCESS_TLUL_I2C" && result.command.fields[1] % 4 != 0) ||
      (tokens[3] == "ACCESS_TLUL_SPI_DEVICE" && result.command.fields[5] % 4 != 0) ||
      (tokens[3] == "ACCESS_SPI" && result.command.fields[1] % 4 != 0) ||
      (tokens[3] == "ACCESS_TIMER" && result.command.fields[1] % 4 != 0) ||
      (tokens[3] == "ACCESS_AXIL_UART" && result.command.fields[3] % 4 != 0) ||
      (tokens[3] == "ACCESS_I2C" && result.command.fields[1] % 4 != 0) ||
      (tokens[3] == "SOURCE_SPI" && result.command.fields[2] == 0)) {
    result.code = "invalid_fields";
    result.detail = "unaligned_offset";
    return result;
  }
  result.command.request = line;
  result.ok = true;
  result.code.clear();
  result.detail.clear();
  return result;
}

// Codes/details supplied by the driver are single tokens, not raw exception
// text. This helper refuses whitespace/control injection into the envelope.
inline std::string error_reply(const std::string &execution,
                               std::uint64_t sequence, std::uint64_t ticks,
                               const std::string &code, const std::string &detail) {
  const auto valid_token = [](const std::string &value) {
    if (value.empty()) return false;
    for (const char character : value) {
      if (!((character >= 'a' && character <= 'z') ||
            (character >= '0' && character <= '9') || character == '_')) return false;
    }
    return true;
  };
  if ((execution != "-" && !valid_execution(execution)) ||
      !valid_token(code) || !valid_token(detail))
    throw std::invalid_argument("invalid v1 error envelope");
  return "ERROR " + execution + " " + hex_integer(sequence) + " " +
      hex_integer(ticks) + " " + code + " " + detail;
}

enum class Decision { Fresh, Cached, Rejected };
struct Admission {
  Decision decision;
  std::string reply;
};

// Wrap legacy replay verdicts rather than changing exactly-once semantics.
// Integration: parse -> accept(worst_case_reply_bytes) -> effects -> finish.
// Fresh reserves request bytes plus the *maximum full terminal line* before
// effects. finish releases unused reservation. An explicit cumulative ACK
// retires only fully received receipts, leaving a monotonic exactly-once floor.
// retained_bytes accounts request/receipt string contents, not allocator/map
// overhead. The owner must separately budget process memory and command count.
// Capacity rejection does not consume identity/sequence and advances no DUT.
// A failed/oversize finish leaves legacy replay incomplete: retry is uncertain,
// never Fresh. Callers must terminate/classify uncertain effects accordingly.
class BoundedReplay {
 public:
  explicit BoundedReplay(std::size_t max_cached_bytes,
                         std::size_t max_reply_bytes = kMaxReplyBytes)
      : max_cached_bytes_(max_cached_bytes), max_reply_bytes_(max_reply_bytes) {}

  Admission accept(const Command &command, std::uint64_t ticks,
                   std::size_t reply_reservation) {
    const auto parsed = parse_command(command.request);
    if (!parsed.ok || parsed.command.execution != command.execution ||
        parsed.command.sequence != command.sequence ||
        parsed.command.operation != command.operation ||
        parsed.command.fields != command.fields)
      return reject(command, ticks, "invalid_command", "unvalidated_command");

    // Metadata only predicts the capacity-requiring Fresh case. All identity,
    // conflict, order and incomplete-receipt verdicts remain legacy decisions.
    const bool fresh_candidate = entries_.count(command.sequence) == 0 &&
        command.sequence == next_sequence_ &&
        (execution_.empty() || execution_ == command.execution);
    if (fresh_candidate &&
        (reply_reservation == 0 || reply_reservation > max_reply_bytes_ ||
         command.request.size() > max_cached_bytes_ - retained_bytes_ ||
         reply_reservation > max_cached_bytes_ - retained_bytes_ - command.request.size()))
      return reject(command, ticks, "resource_limit", "replay_capacity");

    std::string reply;
    const auto decision = replay_.accept(command.execution, command.sequence,
                                         command.request, reply);
    if (decision == LocalCommandReplay::Decision::Cached)
      return {Decision::Cached, reply};
    if (decision == LocalCommandReplay::Decision::Error) {
      // Legacy errors consist of 'ERROR ' plus one stable code token.
      return reject(command, ticks, reply.substr(6), "replay_rejected");
    }
    entries_.emplace(command.sequence, Entry{command.request.size(), reply_reservation, false});
    retained_bytes_ += command.request.size() + reply_reservation;
    execution_ = command.execution;
    ++next_sequence_;
    return {Decision::Fresh, ""};
  }

  void finish(std::uint64_t sequence, const std::string &reply) {
    auto &entry = entries_.at(sequence);
    if (entry.complete) throw std::logic_error("receipt already complete");
    if (reply.size() > entry.reply_bytes || reply.size() > max_reply_bytes_)
      throw std::length_error("reply exceeds reservation");
    replay_.finish(sequence, reply);
    retained_bytes_ -= entry.reply_bytes - reply.size();
    entry.reply_bytes = reply.size();
    entry.complete = true;
  }

  // Empty string means ACK accepted. Repeated/older ACKs are idempotent.
  // Future, stale-execution and unfinished entries leave all state untouched.
  std::string retire(const std::string &execution, std::uint64_t sequence) {
    if (execution_.empty() || execution != execution_) return "stale_execution";
    if (sequence == 0 || sequence >= next_sequence_) return "ack_out_of_order";
    if (sequence <= retired_through_) return "";
    for (auto it = entries_.begin(); it != entries_.end() && it->first <= sequence; ++it)
      if (!it->second.complete) return "ack_incomplete";
    if (!replay_.retire_through(execution, sequence)) return "ack_incomplete";
    auto end = entries_.upper_bound(sequence);
    for (auto it = entries_.begin(); it != end; ++it)
      retained_bytes_ -= it->second.request_bytes + it->second.reply_bytes;
    entries_.erase(entries_.begin(), end);
    retired_through_ = sequence;
    return "";
  }

  std::size_t retained_bytes() const { return retained_bytes_; }

 private:
  struct Entry {
    std::size_t request_bytes;
    std::size_t reply_bytes;
    bool complete;
  };
  Admission reject(const Command &command, std::uint64_t ticks,
                   const std::string &code, const std::string &detail) const {
    const auto execution = valid_execution(command.execution) ? command.execution : "-";
    return {Decision::Rejected, error_reply(execution, command.sequence, ticks, code, detail)};
  }
  LocalCommandReplay replay_;
  std::map<std::uint64_t, Entry> entries_;
  const std::size_t max_cached_bytes_;
  const std::size_t max_reply_bytes_;
  std::size_t retained_bytes_ = 0;
  std::string execution_;
  std::uint64_t next_sequence_ = 1;
  std::uint64_t retired_through_ = 0;
};

}  // namespace local_driver_v1
}  // namespace myfuzz
