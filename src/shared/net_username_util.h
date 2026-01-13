#ifndef NET_USERNAME_UTIL_H
#define NET_USERNAME_UTIL_H

#include <algorithm>
#include <cctype>
#include <ranges>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

constexpr size_t MAX_USERNAME_LENGTH = 64;
constexpr size_t MIN_USERNAME_LENGTH = 1;

[[nodiscard]] constexpr bool is_valid_username_char(unsigned char c) noexcept
{
    return (std::isalnum(c) != 0) || c == '_' || c == '-';
}

[[nodiscard]] inline bool is_valid_username(std::string_view name) noexcept
{
    return name.size() >= MIN_USERNAME_LENGTH && 
           name.size() <= MAX_USERNAME_LENGTH &&
           std::ranges::all_of(name, is_valid_username_char);
}

[[nodiscard]] inline int compute_lcs_length(std::string_view a, std::string_view b) noexcept
{
    const size_t n = a.size();
    const size_t m = b.size();
    
    std::vector<int> prev(m + 1, 0);
    std::vector<int> cur(m + 1, 0);

    for (size_t i = 1; i <= n; ++i)
    {
        for (size_t j = 1; j <= m; ++j)
        {
            cur[j] = (a[i - 1] == b[j - 1]) 
                ? prev[j - 1] + 1 
                : std::max(prev[j], cur[j - 1]);
        }
        prev.swap(cur);
        std::ranges::fill(cur, 0);
    }
    return prev[m];
}

[[nodiscard]] inline bool is_username_too_similar(std::string_view candidate,
                                                   std::string_view existing,
                                                   int similarity_threshold_percent = 85) noexcept
{
    const int lcs = compute_lcs_length(candidate, existing);
    const size_t maxlen = std::max(candidate.size(), existing.size());
    
    return maxlen > 0 && 
           (100 * lcs) >= (similarity_threshold_percent * static_cast<int>(maxlen));
}

template<typename MapType>
[[nodiscard]] inline bool has_similar_username(std::string_view username,
                                                const MapType& existing_users,
                                                int similarity_threshold = 85) noexcept
{
    return std::ranges::any_of(existing_users,
        [username, similarity_threshold](const auto& kv) noexcept {
            return is_username_too_similar(username, kv.first, similarity_threshold);
        });
}

[[nodiscard]] inline bool is_valid_session_id(std::string_view sid) noexcept
{
    constexpr size_t SESSION_ID_LENGTH = 60;
    constexpr std::string_view BASE58_CHARS =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    
    return sid.size() == SESSION_ID_LENGTH &&
           std::ranges::all_of(sid, [BASE58_CHARS](char c) noexcept {
               return BASE58_CHARS.find(c) != std::string_view::npos;
           });
}

[[nodiscard]] inline std::string generate_session_id()
{
    constexpr std::string_view BASE58_CHARS =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    constexpr size_t SESSION_ID_LENGTH = 60;
    constexpr size_t CHARSET_SIZE = BASE58_CHARS.size();
    constexpr unsigned int REJECT_THRESHOLD = 256U / CHARSET_SIZE * CHARSET_SIZE;
    
    std::string sid;
    sid.reserve(SESSION_ID_LENGTH);
    
    unsigned char byte = 0;
    for (size_t i = 0; i < SESSION_ID_LENGTH; ++i)
    {
        do {
            if (RAND_bytes(&byte, 1) != 1)
                throw std::runtime_error("RAND_bytes failed");
        } while (static_cast<unsigned int>(byte) >= REJECT_THRESHOLD);
        
        sid += BASE58_CHARS[static_cast<unsigned int>(byte) % CHARSET_SIZE];
    }
    
    return sid;
}

#endif