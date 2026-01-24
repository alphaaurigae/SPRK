#ifndef SHARED_NET_REKEY_UTIL_H
#define SHARED_NET_REKEY_UTIL_H

#include <Poco/Timestamp.h>
#include <asio/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

constexpr uint32_t DEFAULT_REKEY_INTERVAL     = 1024;
constexpr uint32_t DEFAULT_MAX_SEQ_GAP        = 100;
constexpr uint32_t DEFAULT_SEQ_JITTER_BUFFER  = 3;
constexpr uint64_t DEFAULT_MESSAGE_TIMEOUT_MS = 60000;

[[nodiscard]] constexpr bool
should_rekey(uint32_t sequence_number,
             uint32_t rekey_interval = DEFAULT_REKEY_INTERVAL) noexcept
{
    return sequence_number >= rekey_interval;
}

[[nodiscard]] constexpr bool is_sequence_in_jitter_range(
    uint32_t received_seq, uint32_t expected_seq,
    uint32_t jitter_buffer = DEFAULT_SEQ_JITTER_BUFFER) noexcept
{
    return received_seq > expected_seq &&
           (received_seq - expected_seq) <= jitter_buffer;
}

[[nodiscard]] constexpr bool is_sequence_gap_valid(
    uint32_t received_seq, uint32_t expected_seq,
    uint32_t max_gap       = DEFAULT_MAX_SEQ_GAP,
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

[[nodiscard]] inline bool is_message_timeout_exceeded(
    uint64_t last_message_time_ms, uint64_t current_time_ms,
    uint64_t timeout_ms = DEFAULT_MESSAGE_TIMEOUT_MS) noexcept
{
    return last_message_time_ms > 0 &&
           (current_time_ms - last_message_time_ms) > timeout_ms;
}

[[nodiscard]] inline std::string
build_key_derivation_context(std::string_view fp1,
                             std::string_view fp2) noexcept
{
    return (fp1 < fp2) ? std::string(fp1) + "|" + std::string(fp2)
                       : std::string(fp2) + "|" + std::string(fp1);
}

[[nodiscard]] inline std::string
build_username_context(std::string_view username1,
                       std::string_view username2) noexcept
{
    return (username1 < username2)
               ? std::string(username1) + "|" + std::string(username2)
               : std::string(username2) + "|" + std::string(username1);
}

[[nodiscard]] inline uint64_t get_current_timestamp_ms_poco() noexcept
{
    return static_cast<uint64_t>(Poco::Timestamp().epochMicroseconds() / 1000);
}

[[nodiscard]] inline uint64_t get_current_timestamp_ms() noexcept
{
    return get_current_timestamp_ms_poco();
}

struct RateLimitState
{
    uint32_t counter         = 0;
    uint64_t window_start_ms = 0;

    constexpr void reset(uint64_t current_ms) noexcept
    {
        counter         = 0;
        window_start_ms = current_ms;
    }
};

[[nodiscard]] inline bool check_rate_limit(RateLimitState &state,
                                           uint64_t        current_time_ms,
                                           uint32_t        max_messages = 100,
                                           uint64_t window_ms = 1000) noexcept
{
    if (current_time_ms - state.window_start_ms > window_ms)
    {
        state.counter         = 0;
        state.window_start_ms = current_time_ms;
    }

    return ++state.counter <= max_messages;
}
class RekeyTimer
{
  public:
    explicit RekeyTimer(asio::io_context         &io,
                        std::chrono::milliseconds interval =
                            std::chrono::milliseconds{
                                DEFAULT_MESSAGE_TIMEOUT_MS})
        : timer_{io, interval}, interval_ms_{interval}, active_{false}
    {
    }

    RekeyTimer(const RekeyTimer &)                = delete;
    RekeyTimer &operator=(const RekeyTimer &)     = delete;
    RekeyTimer(RekeyTimer &&) noexcept            = default;
    RekeyTimer &operator=(RekeyTimer &&) noexcept = default;

    void start(std::function<void(const std::error_code &)> callback)
    {
        callback_ = std::move(callback);
        active_   = true;
        schedule_next();
    }

    void stop() noexcept
    {
        active_ = false;
        std::error_code ec;
        timer_.cancel(ec);
    }

    void reset()
    {
        if (active_)
        {
            stop();
            timer_.expires_after(interval_ms_);
            active_ = true;
            schedule_next();
        }
    }

    [[nodiscard]] bool active() const noexcept { return active_; }

    void set_interval(std::chrono::milliseconds interval)
    {
        interval_ms_ = interval;
        if (active_)
        {
            reset();
        }
    }

    [[nodiscard]] std::chrono::milliseconds interval() const noexcept
    {
        return interval_ms_;
    }

  private:
    void schedule_next()
    {
        if (!active_)
            return;

        timer_.async_wait(
            [this](const std::error_code &ec)
            {
                if (ec || !active_)
                    return;

                if (callback_)
                {
                    callback_(ec);
                }

                if (active_)
                {
                    timer_.expires_after(interval_ms_);
                    schedule_next();
                }
            });
    }

    asio::steady_timer                           timer_;
    std::chrono::milliseconds                    interval_ms_;
    std::function<void(const std::error_code &)> callback_;
    bool                                         active_;
};

class OneShotTimer
{
  public:
    explicit OneShotTimer(asio::io_context &io) : timer_{io}, armed_{false} {}

    OneShotTimer(const OneShotTimer &)                = delete;
    OneShotTimer &operator=(const OneShotTimer &)     = delete;
    OneShotTimer(OneShotTimer &&) noexcept            = default;
    OneShotTimer &operator=(OneShotTimer &&) noexcept = default;

    void start(std::chrono::milliseconds                    delay,
               std::function<void(const std::error_code &)> callback)
    {
        armed_ = true;
        timer_.expires_after(delay);
        timer_.async_wait(
            [this, cb = std::move(callback)](const std::error_code &ec)
            {
                armed_ = false;
                if (!ec && cb)
                {
                    cb(ec);
                }
            });
    }

    void cancel() noexcept
    {
        armed_ = false;
        std::error_code ec;
        timer_.cancel(ec);
    }

    [[nodiscard]] bool active() const noexcept { return armed_; }

  private:
    asio::steady_timer timer_;
    bool               armed_;
};

class RekeyTimeoutManager
{
  public:
    explicit RekeyTimeoutManager(asio::io_context &io) : io_{io} {}

    RekeyTimeoutManager(const RekeyTimeoutManager &)                = delete;
    RekeyTimeoutManager &operator=(const RekeyTimeoutManager &)     = delete;
    RekeyTimeoutManager(RekeyTimeoutManager &&) noexcept            = delete;
    RekeyTimeoutManager &operator=(RekeyTimeoutManager &&) noexcept = delete;

    [[nodiscard]] std::unique_ptr<RekeyTimer>
    create_timer(std::chrono::milliseconds interval)
    {
        return std::make_unique<RekeyTimer>(io_, interval);
    }

    [[nodiscard]] std::unique_ptr<OneShotTimer> create_oneshot()
    {
        return std::make_unique<OneShotTimer>(io_);
    }

    void schedule_rekey(std::chrono::milliseconds delay,
                        std::function<void()>     callback)
    {
        auto timer = std::make_shared<OneShotTimer>(io_);

        // Keep timer in pending list so cleanup can prune it later
        pending_timers_.push_back(timer);

        // Capture timer as shared_ptr to keep it alive until callback completes
        timer->start(delay,
                     [cb              = std::move(callback),
                      timer_keepalive = timer](const std::error_code &ec)
                     {
                         if (!ec && cb)
                         {
                             cb();
                         }
                         // timer_keepalive goes out of scope here, allowing
                         // timer destruction
                     });

        // Periodic cleanup of completed timers (not immediate)
        cleanup_completed_timers();
    }

    void cleanup_completed_timers() noexcept
    {
        pending_timers_.erase(
            std::remove_if(pending_timers_.begin(), pending_timers_.end(),
                           [](const auto &t) { return !t->active(); }),
            pending_timers_.end());
    }

  private:
    asio::io_context                          &io_;
    std::vector<std::shared_ptr<OneShotTimer>> pending_timers_;
};

#endif