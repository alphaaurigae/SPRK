#ifndef NET_REKEY_UTIL_H
#define NET_REKEY_UTIL_H

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>

constexpr uint32_t DEFAULT_REKEY_INTERVAL = 1024;
constexpr uint32_t DEFAULT_MAX_SEQ_GAP = 100;
constexpr uint32_t DEFAULT_SEQ_JITTER_BUFFER = 3;
constexpr uint64_t DEFAULT_MESSAGE_TIMEOUT_MS = 60000;

[[nodiscard]] constexpr bool should_rekey(uint32_t sequence_number, 
                                          uint32_t rekey_interval = DEFAULT_REKEY_INTERVAL) noexcept
{
    return sequence_number >= rekey_interval;
}

[[nodiscard]] constexpr bool is_sequence_in_jitter_range(uint32_t received_seq,
                                                          uint32_t expected_seq,
                                                          uint32_t jitter_buffer = DEFAULT_SEQ_JITTER_BUFFER) noexcept
{
    return received_seq > expected_seq && 
           (received_seq - expected_seq) <= jitter_buffer;
}

[[nodiscard]] constexpr bool is_sequence_gap_valid(uint32_t received_seq,
                                                    uint32_t expected_seq,
                                                    uint32_t max_gap = DEFAULT_MAX_SEQ_GAP,
                                                    uint32_t jitter_buffer = DEFAULT_SEQ_JITTER_BUFFER) noexcept
{
    return received_seq >= expected_seq && 
           (received_seq - expected_seq) <= (max_gap + jitter_buffer);
}

[[nodiscard]] constexpr bool is_replay_attack(uint32_t received_seq,
                                               uint32_t expected_seq) noexcept
{
    return received_seq < expected_seq;
}

[[nodiscard]] inline bool is_message_timeout_exceeded(uint64_t last_message_time_ms,
                                                       uint64_t current_time_ms,
                                                       uint64_t timeout_ms = DEFAULT_MESSAGE_TIMEOUT_MS) noexcept
{
    return last_message_time_ms > 0 && 
           (current_time_ms - last_message_time_ms) > timeout_ms;
}

[[nodiscard]] inline std::string build_key_derivation_context(std::string_view fp1,
                                                               std::string_view fp2) noexcept
{
    return (fp1 < fp2) ? std::string(fp1) + "|" + std::string(fp2)
                       : std::string(fp2) + "|" + std::string(fp1);
}

[[nodiscard]] inline std::string build_username_context(std::string_view username1,
                                                         std::string_view username2) noexcept
{
    return (username1 < username2) ? std::string(username1) + "|" + std::string(username2)
                                   : std::string(username2) + "|" + std::string(username1);
}

[[nodiscard]] inline uint64_t get_current_timestamp_ms() noexcept
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
}

struct RateLimitState
{
    uint32_t counter = 0;
    uint64_t window_start_ms = 0;
};

[[nodiscard]] inline bool check_rate_limit(RateLimitState& state,
                                            uint64_t current_time_ms,
                                            uint32_t max_messages = 100,
                                            uint64_t window_ms = 1000) noexcept
{
    if (current_time_ms - state.window_start_ms > window_ms)
    {
        state.counter = 0;
        state.window_start_ms = current_time_ms;
    }
    
    return ++state.counter <= max_messages;
}

#endif