#pragma once

#include <cstdint>
#include <map>
#include <string>

// A command owns exactly one local RTL advance. A repeated command returns
// its original full reply and cannot execute the target again.
class LocalCommandReplay {
 public:
  enum class Decision { Fresh, Cached, Error };

  Decision accept(const std::string &execution, std::uint64_t sequence,
                  const std::string &request, std::string &reply) {
    if (execution.empty() || sequence == 0) {
      reply = "ERROR invalid_command_identity";
      return Decision::Error;
    }
    if (!execution_.empty() && execution != execution_) {
      reply = "ERROR stale_execution";
      return Decision::Error;
    }
    if (sequence <= retired_through_) {
      reply = "ERROR retired_command";
      return Decision::Error;
    }
    auto prior = entries_.find(sequence);
    if (prior != entries_.end()) {
      if (prior->second.request != request) {
        reply = "ERROR identity_conflict";
        return Decision::Error;
      }
      if (!prior->second.complete) {
        reply = "ERROR uncertain_effect";
        return Decision::Error;
      }
      reply = prior->second.reply;
      return Decision::Cached;
    }
    if (sequence != next_sequence_) {
      reply = "ERROR out_of_order_command";
      return Decision::Error;
    }
    if (execution_.empty()) execution_ = execution;
    entries_.emplace(sequence, Entry{request, "", false});
    ++next_sequence_;
    return Decision::Fresh;
  }

  void finish(std::uint64_t sequence, const std::string &reply) {
    auto &entry = entries_.at(sequence);
    entry.reply = reply;
    entry.complete = true;
  }

  // The host may retire only a fully received contiguous prefix. A permanent
  // floor preserves exactly-once after the large request/reply strings go.
  bool retire_through(const std::string &execution, std::uint64_t sequence) {
    if (execution_.empty() || execution != execution_ ||
        sequence >= next_sequence_) return false;
    if (sequence <= retired_through_) return true;
    for (auto it = entries_.begin(); it != entries_.end() && it->first <= sequence; ++it)
      if (!it->second.complete) return false;
    auto end = entries_.upper_bound(sequence);
    entries_.erase(entries_.begin(), end);
    retired_through_ = sequence;
    return true;
  }

 private:
  struct Entry {
    std::string request;
    std::string reply;
    bool complete;
  };
  std::string execution_;
  std::uint64_t next_sequence_ = 1;
  std::uint64_t retired_through_ = 0;
  std::map<std::uint64_t, Entry> entries_;
};
