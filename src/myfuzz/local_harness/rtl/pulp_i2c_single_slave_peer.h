#pragma once

#include <cstdint>
#include <stdexcept>

// One 7-bit slave at 0x42. It never stretches SCL, and has one testcase byte.
// Pull-ups resolve every released line high; the peer may only pull SDA low.
class PulpI2cSingleSlavePeer {
 public:
  bool sda_low() const { return drive_low_; }
  bool set_response(std::uint8_t response) {
    if (configured_ && response != response_) return false;
    response_ = response;
    configured_ = true;
    return true;
  }

  void observe(unsigned scl, unsigned sda, unsigned scl_out,
               unsigned sda_out, unsigned scl_oen, unsigned sda_oen) {
    if (scl > 1 || sda > 1 || scl_out != 0 || sda_out != 0 ||
        scl_oen > 1 || sda_oen > 1)
      throw std::runtime_error("i2c_invalid_open_drain_pins");
    if (last_scl_ && scl && last_sda_ && !sda) {
      phase_ = Phase::Address;
      count_ = 0;
      received_ = 0;
      selected_ = false;
      read_ = false;
      drive_low_ = false;
    } else if (last_scl_ && scl && !last_sda_ && sda) {
      phase_ = Phase::Idle;
      drive_low_ = false;
    }
    if (!last_scl_ && scl) {
      if (phase_ == Phase::Address || phase_ == Phase::Write) {
        received_ = static_cast<std::uint8_t>((received_ << 1) | sda);
        ++count_;
        if (count_ == 8 && phase_ == Phase::Address) {
          selected_ = (received_ >> 1) == 0x42;
          read_ = (received_ & 1) != 0;
        }
      } else if (phase_ == Phase::Ack) {
        ack_clock_done_ = true;
      } else if (phase_ == Phase::Read) {
        ++count_;
      } else if (phase_ == Phase::MasterAck) {
        master_ack_done_ = true;
      }
    }
    if (last_scl_ && !scl) {
      if ((phase_ == Phase::Address || phase_ == Phase::Write) && count_ == 8) {
        next_read_ = phase_ == Phase::Address && selected_ && read_;
        phase_ = Phase::Ack;
        drive_low_ = selected_;
        ack_clock_done_ = false;
      } else if (phase_ == Phase::Ack && ack_clock_done_) {
        phase_ = next_read_ ? Phase::Read : Phase::Write;
        count_ = 0;
        received_ = 0;
        drive_low_ = next_read_ && ((response_ & 0x80) == 0);
        ack_clock_done_ = false;
      } else if (phase_ == Phase::Read) {
        if (count_ == 8) {
          phase_ = Phase::MasterAck;
          drive_low_ = false;
          master_ack_done_ = false;
        } else {
          drive_low_ = ((response_ >> (7 - count_)) & 1) == 0;
        }
      } else if (phase_ == Phase::MasterAck && master_ack_done_) {
        // Only one read byte is admitted. A second is released as 0xff.
        phase_ = Phase::Idle;
        drive_low_ = false;
      }
    }
    last_scl_ = scl;
    last_sda_ = sda;
  }

 private:
  enum class Phase { Idle, Address, Write, Ack, Read, MasterAck };
  std::uint8_t response_ = 0xff;
  bool configured_ = false;
  Phase phase_ = Phase::Idle;
  bool last_scl_ = true;
  bool last_sda_ = true;
  bool drive_low_ = false;
  bool selected_ = false;
  bool read_ = false;
  bool next_read_ = false;
  bool ack_clock_done_ = false;
  bool master_ack_done_ = false;
  unsigned count_ = 0;
  std::uint8_t received_ = 0;
};
