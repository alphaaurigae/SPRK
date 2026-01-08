#include "crypto.h"
#include "protocol.h"
#include "util.h"
#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <ranges>

int make_listen(int port)
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
    {
        perror("socket");
        return -1;
    }

    int one = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0)
    {
        close(s);
        perror("setsockopt SO_REUSEADDR");
        return -1;
    }
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
#endif

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
    int flags = fcntl(s, F_GETFD);
    if (flags >= 0)
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
        fcntl(s, F_SETFD, flags | FD_CLOEXEC);

    sockaddr_in addr{};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(static_cast<uint16_t>(port));

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-cstyle-cast)
    if (bind(s, (sockaddr *)&addr, sizeof(addr)) != 0)
    {
        perror("bind");
        close(s);
        return -1;
    }

    if (listen(s, 16) != 0)
    {
        perror("listen");
        close(s);
        return -1;
    }

    return s;
}

int set_nonblock(int fd)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
        return -1;

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
    int f2 = fcntl(fd, F_GETFD);
    if (f2 >= 0)
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
        fcntl(fd, F_SETFD, f2 | FD_CLOEXEC);

    return 0;
}

inline bool accept_new_client(int listen_fd, std::vector<int> &clients)
{
    int c = accept(listen_fd, nullptr, nullptr);
    if (c < 0)
        return false;

    if (c >= FD_SETSIZE)
    {
        close(c);
        return true;
    }

    if (set_nonblock(c) != 0)
    {
        close(c);
        return true;
    }

    clients.push_back(c);
    return true;
}

inline std::string trim(std::string s)
{
    auto is_space = [](unsigned char c)
    { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [&](unsigned char c)
                                    { return !is_space(c); }));
    s.erase(std::find_if(s.rbegin(), s.rend(),
                         [&](unsigned char c) { return !is_space(c); })
                .base(),
            s.end());
    return s;
}

struct SessionData
{
    std::unordered_map<int, std::string> nick_by_fd;
    std::unordered_map<std::string, int> fd_by_nick;

    std::unordered_map<int, std::string>         fingerprint_hex_by_fd;
    std::unordered_map<std::string, int>         fd_by_fingerprint;
    std::unordered_map<std::string, std::string> nick_by_fingerprint;
    std::unordered_map<std::string, std::vector<unsigned char>>
        eph_by_fingerprint;
    std::unordered_map<std::string, std::vector<unsigned char>>
        identity_pk_by_fingerprint;
    std::unordered_map<std::string, std::vector<unsigned char>>
        hello_message_by_fingerprint;
};

static int lcs_len(const std::string &a, const std::string &b)
{
    size_t n = a.size();
    size_t m = b.size();
    std::vector<int> prev(m + 1, 0);
    std::vector<int> cur(m + 1, 0);

    for (size_t i = 1; i <= n; ++i)
    {
        for (size_t j = 1; j <= m; ++j)
        {
            if (a[i - 1] == b[j - 1])
                cur[j] = prev[j - 1] + 1;
            else
                cur[j] = std::max(prev[j], cur[j - 1]);
        }
        prev.swap(cur);
        std::fill(cur.begin(), cur.end(), 0);
    }
    return prev[m];
}

static bool too_similar_username(const std::string &u,
                                 const std::unordered_map<std::string, int> &existing)
{
    return std::ranges::any_of(existing, [&u](const auto& kv) {
        const std::string& e = kv.first;
        int l = lcs_len(u, e);
        size_t maxlen = std::max(u.size(), e.size());
        return maxlen > 0 && (100 * l) >= (85 * static_cast<int>(maxlen));
    });
}

inline bool recv_full_frame(int fd, std::vector<unsigned char>& frame)
{
    std::array<unsigned char, 4> lenbuf{};
    ssize_t n = recv(fd, lenbuf.data(), lenbuf.size(), MSG_PEEK);

    if (n < static_cast<ssize_t>(lenbuf.size())) {
        return (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
        // Returns true only on EAGAIN/EWOULDBLOCK, false on partial header or real error
    }

    uint32_t payload_len = read_u32_be(lenbuf.data());
    if (payload_len > 64 * 1024)
        return false;

    frame.resize(4 + payload_len);
    ssize_t got = full_recv(fd, frame.data(), frame.size());
    return got > 0;
}

inline void cleanup_disconnected_client(
    int c,
    std::vector<int>& clients,
    std::unordered_map<int, std::string>& session_by_fd,
    std::unordered_map<std::string, SessionData>& sessions)
{
    auto sid_it = session_by_fd.find(c);
    if (sid_it == session_by_fd.end()) {
        close(c);
        clients.erase(std::remove(clients.begin(), clients.end(), c), clients.end());
        return;
    }

    std::string sid = sid_it->second;
    auto session_it = sessions.find(sid);
    if (session_it == sessions.end()) {
        session_by_fd.erase(c);
        close(c);
        clients.erase(std::remove(clients.begin(), clients.end(), c), clients.end());
        return;
    }

    SessionData& sd = session_it->second;

    std::string nick;
    auto nit = sd.nick_by_fd.find(c);
    if (nit != sd.nick_by_fd.end())
        nick = nit->second;

    std::string fp_hex;
    auto iit = sd.fingerprint_hex_by_fd.find(c);
    if (iit != sd.fingerprint_hex_by_fd.end())
        fp_hex = iit->second;

    if (!fp_hex.empty()) {
        sd.fd_by_fingerprint.erase(fp_hex);
        sd.nick_by_fingerprint.erase(fp_hex);
        sd.eph_by_fingerprint.erase(fp_hex);
        sd.identity_pk_by_fingerprint.erase(fp_hex);
        sd.hello_message_by_fingerprint.erase(fp_hex);
        sd.fingerprint_hex_by_fd.erase(c);
    }

    if (!nick.empty()) {
        sd.fd_by_nick.erase(nick);
        sd.nick_by_fd.erase(c);
    }

    std::cout << "disconnect " << nick << " session=" << sid << "\n";

    session_by_fd.erase(c);
    close(c);
    clients.erase(std::remove(clients.begin(), clients.end(), c), clients.end());
}






// Returns empty string on success, error message on failure
static std::string validate_hello_basics(const Parsed& p, std::string& uname, std::string& sid)
{
    uname = trim(p.username);
    sid   = trim(p.session_id);

    if (sid.empty()) {
        sid = std::string(reinterpret_cast<const char*>(p.eph_pk.data()),
                          p.eph_pk.size());
    }

    if (p.id_alg == 0 || p.identity_pk.empty() || p.signature.empty()) {
        return "missing identity or signature";
    }

    std::vector<unsigned char> sig_data;
    sig_data.reserve(p.eph_pk.size() + p.session_id.size());
    sig_data.insert(sig_data.end(), p.eph_pk.begin(), p.eph_pk.end());
    sig_data.insert(sig_data.end(), p.session_id.begin(), p.session_id.end());

    bool sig_ok = (p.id_alg == ALGO_MLDSA87) &&
                  pqsig_verify("ML-DSA-87", p.identity_pk, sig_data, p.signature);

    if (!sig_ok) {
        return "invalid signature";
    }

    return {}; // empty string = success
}






static void cleanup_old_nickname(SessionData& sd, int client_fd, const std::string& new_uname)
{
    auto it_oldnick = sd.nick_by_fd.find(client_fd);
    if (it_oldnick == sd.nick_by_fd.end() || it_oldnick->second == new_uname) {
        return; // no cleanup needed
    }

    const std::string oldnick = it_oldnick->second;
    sd.fd_by_nick.erase(oldnick);

    auto it_fp = sd.fingerprint_hex_by_fd.find(client_fd);
    if (it_fp != sd.fingerprint_hex_by_fd.end()) {
        const std::string oldfp = it_fp->second;

        sd.fd_by_fingerprint.erase(oldfp);
        sd.nick_by_fingerprint.erase(oldfp);
        sd.eph_by_fingerprint.erase(oldfp);
        sd.identity_pk_by_fingerprint.erase(oldfp);
        sd.hello_message_by_fingerprint.erase(oldfp);
        sd.fingerprint_hex_by_fd.erase(client_fd);
    }

    sd.nick_by_fd.erase(client_fd);
}





static bool check_username_conflicts(SessionData& sd, 
                                     const std::string& uname, 
                                     int client_fd,
                                     std::vector<int>& to_remove)
{
    auto it_existing = sd.fd_by_nick.find(uname);

    // Exact match with different fd → reject
    if (it_existing != sd.fd_by_nick.end() && it_existing->second != client_fd) {
        std::cout << "REJECTED: username already in use " << uname << "\n";
        to_remove.push_back(client_fd);
        return false;
    }

    // Similar username, but not the same client re-connecting
    if (too_similar_username(uname, sd.fd_by_nick) &&
        (it_existing == sd.fd_by_nick.end() || it_existing->second != client_fd)) {
        std::cout << "REJECTED: username too similar to existing user " << uname << "\n";
        to_remove.push_back(client_fd);
        return false;
    }

    return true; // username is acceptable
}





static void register_client(SessionData& sd,
                            int client_fd,
                            const std::string& uname,
                            const Parsed& p,
                            const std::vector<unsigned char>& frame)
{
    // Compute fingerprint if identity key present
    std::string fp_hex;
    if (!p.identity_pk.empty()) {
        auto fp_arr = fingerprint_sha256(p.identity_pk);
        fp_hex = fingerprint_to_hex(fp_arr);
    }

    // Always register nickname
    sd.nick_by_fd[client_fd] = uname;
    sd.fd_by_nick[uname] = client_fd;

    // Register identity/fingerprint data if present
    if (!fp_hex.empty()) {
        sd.fingerprint_hex_by_fd[client_fd] = fp_hex;
        sd.fd_by_fingerprint[fp_hex] = client_fd;
        sd.nick_by_fingerprint[fp_hex] = uname;
        sd.eph_by_fingerprint[fp_hex] = p.eph_pk;
        sd.identity_pk_by_fingerprint[fp_hex] = p.identity_pk;
        sd.hello_message_by_fingerprint[fp_hex] = frame;
    } else {
        sd.hello_message_by_fingerprint[""] = frame;
    }
}



static void broadcast_hello_to_peers(const SessionData& sd,
                                    int client_fd,
                                    const std::vector<unsigned char>& frame)
{
    for (const auto& kv : sd.fd_by_nick) {
        int fd = kv.second;
        if (fd == client_fd) continue;
        full_send(fd, frame.data(), frame.size());
    }
}




inline bool handle_hello_message(
    int client_fd,
    const Parsed& p,
    const std::vector<unsigned char>& frame,
    std::unordered_map<std::string, SessionData>& sessions,
    std::unordered_map<int, std::string>& session_by_fd,
    std::vector<int>& to_remove)
{
    std::string uname;
    std::string sid;
    std::string error = validate_hello_basics(p, uname, sid);

    if (!error.empty()) {
        std::cout << "REJECTED: " << error << " for " << uname << "\n";
        to_remove.push_back(client_fd);
        return false;
    }

    SessionData& sd = sessions[sid];

    if (!check_username_conflicts(sd, uname, client_fd, to_remove)) {
        return false;
    }

    cleanup_old_nickname(sd, client_fd, uname);
    register_client(sd, client_fd, uname, p, frame);

    session_by_fd[client_fd] = sid;
    std::cout << "connect " << uname << " session=" << sid << "\n";

    broadcast_hello_to_peers(sd, client_fd, frame);

    // Send existing hellos to new client (core protocol handshake — keep visible)
    for (const auto& kv : sd.hello_message_by_fingerprint) {
        const std::string& existing_fp = kv.first;
        if (!existing_fp.empty()) {
            auto itn = sd.nick_by_fingerprint.find(existing_fp);
            if (itn != sd.nick_by_fingerprint.end() && itn->second == uname)
                continue;
        }
        const auto& existing_hello = kv.second;
        try {
            uint32_t existing_payload_len = read_u32_be(existing_hello.data());
            Parsed p2 = parse_payload(existing_hello.data() + 4, existing_payload_len);
            std::vector<unsigned char> empty_encaps;
            auto stripped = build_hello(
                p2.username, ALGO_KYBER512, p2.eph_pk,
                p2.id_alg, p2.identity_pk, p2.signature,
                empty_encaps, p2.session_id);
            full_send(client_fd, stripped.data(), stripped.size());
        } catch (...) {
            full_send(client_fd, existing_hello.data(), existing_hello.size());
        }
    }

    return true;
}








inline void handle_chat_message(
    int client_fd,
    const Parsed& p,
    const std::vector<unsigned char>& frame,
    const std::unordered_map<int, std::string>& session_by_fd,
    std::unordered_map<std::string, SessionData>& sessions)
{
    auto sid_it = session_by_fd.find(client_fd);
    if (sid_it == session_by_fd.end()) return;

    auto sess_it = sessions.find(sid_it->second);
    if (sess_it == sessions.end()) return;

    SessionData& sd = sess_it->second;

    int dst = -1;

    // Fast path: exact nickname
    if (auto it = sd.fd_by_nick.find(p.to); it != sd.fd_by_nick.end()) {
        dst = it->second;
    }
    // Slow path: only if needed
    else if (p.to.size() >= 4) {
        std::string lower = p.to;
        std::ranges::transform(lower, lower.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

        if (auto it = std::ranges::find_if(sd.fd_by_fingerprint,
            [&lower](const auto& kv) {
                const std::string& fp = kv.first;
                if (fp.size() < lower.size()) return false;
                return std::ranges::equal(lower.begin(), lower.end(),
                                          fp.begin(), fp.begin() + lower.size(),
                                          [](unsigned char a, unsigned char b) {
                                              return std::tolower(a) == std::tolower(b);
                                          });
            });
            it != sd.fd_by_fingerprint.end())
        {
            dst = it->second;
        }
    }

    // Branchless send
    size_t size = static_cast<size_t>(dst != -1) * frame.size();
    full_send(dst, frame.data(), size);
}


inline void handle_list_request(
    int client_fd,
    const std::unordered_map<int, std::string>& session_by_fd,
    std::unordered_map<std::string, SessionData>& sessions)
{
    auto sid_it = session_by_fd.find(client_fd);
    if (sid_it == session_by_fd.end())
        return;

    const std::string& sid = sid_it->second;
    auto session_it = sessions.find(sid);
    if (session_it == sessions.end())
        return;

    SessionData& sd = session_it->second;
    std::vector<std::string> users;
    users.reserve(sd.fd_by_nick.size());
    for (auto& kv : sd.fd_by_nick)
        users.push_back(kv.first);
    auto resp = build_list_response(users);
    full_send(client_fd, resp.data(), resp.size());
}

inline void handle_pubkey_request(
    int client_fd,
    const Parsed& p,
    const std::unordered_map<int, std::string>& session_by_fd,
    std::unordered_map<std::string, SessionData>& sessions)
{
    auto sid_it = session_by_fd.find(client_fd);
    if (sid_it == session_by_fd.end())
        return;

    const std::string& sid = sid_it->second;
    auto session_it = sessions.find(sid);
    if (session_it == sessions.end())
        return;

    SessionData& sd = session_it->second;
    std::string target = trim(p.username);

    std::vector<unsigned char> pk;

    auto itn = sd.fd_by_nick.find(target);
    if (itn != sd.fd_by_nick.end())
    {
        int dstfd = itn->second;
        auto itfp = sd.fingerprint_hex_by_fd.find(dstfd);
        if (itfp != sd.fingerprint_hex_by_fd.end())
        {
            auto itpk = sd.identity_pk_by_fingerprint.find(itfp->second);
            if (itpk != sd.identity_pk_by_fingerprint.end())
                pk = itpk->second;
        }
    }
    else
    {
        std::vector<std::string> matches;
        for (auto& kv : sd.identity_pk_by_fingerprint)
        {
            const std::string& hexfp = kv.first;
            if (hexfp.size() >= target.size())
            {
                bool ok = true;
                for (size_t i = 0; i < target.size(); ++i)
                {
                    if (std::tolower((unsigned char)hexfp[i]) !=
                        std::tolower((unsigned char)target[i]))
                    {
                        ok = false;
                        break;
                    }
                }
                if (ok)
                    matches.push_back(hexfp);
            }
        }
        if (matches.size() == 1)
        {
            pk = sd.identity_pk_by_fingerprint[matches[0]];
        }
    }
    auto resp = build_pubkey_response(target, pk);
    full_send(client_fd, resp.data(), resp.size());
}

static void prune_invalid_clients(std::vector<int>& clients)
{
    clients.erase(std::remove_if(clients.begin(), clients.end(),
        [](int fd) {
            if (fd >= FD_SETSIZE) {
                close(fd);
                return true;
            }
            return false;
        }),
        clients.end());
}

static int prepare_select(fd_set& rfds, int listen_fd, const std::vector<int>& clients)
{
    FD_ZERO(&rfds);
    FD_SET(listen_fd, &rfds);
    int maxfd = listen_fd;

    for (int c : clients) {
        FD_SET(c, &rfds);
        if (c > maxfd) maxfd = c;
    }

    return maxfd;
}

static void process_client_events(
    const fd_set& rfds,
    const std::vector<int>& clients,
    std::unordered_map<std::string, SessionData>& sessions,
    std::unordered_map<int, std::string>& session_by_fd,
    std::vector<int>& to_remove)
{
    for (int c : clients) {
        if (!FD_ISSET(c, &rfds))
            continue;

        std::vector<unsigned char> frame;
        if (!recv_full_frame(c, frame)) {
            to_remove.push_back(c);
            continue;
        }

        uint32_t payload_len = read_u32_be(frame.data());
        try {
            Parsed p = parse_payload(frame.data() + 4, payload_len);

            switch (p.type) {
                case MSG_HELLO:
                    handle_hello_message(c, p, frame, sessions, session_by_fd, to_remove);
                    break;
                case MSG_CHAT:
                    handle_chat_message(c, p, frame, session_by_fd, sessions);
                    break;
                case MSG_LIST_REQUEST:
                    handle_list_request(c, session_by_fd, sessions);
                    break;
                case MSG_PUBKEY_REQUEST:
                    handle_pubkey_request(c, p, session_by_fd, sessions);
                    break;
                default:
                    break;
            }
        } catch (const std::exception& e) {
            std::cerr << "server parse exception: " << e.what() << "\n";
            to_remove.push_back(c);
        } catch (...) {
            std::cerr << "server parse exception: unknown\n";
            to_remove.push_back(c);
        }
    }
}


int main(int argc, char **argv)
{
    if (argc < 2) {
        std::cout << "Usage: chat_server <port>\n";
        return 1;
    }

    int port = std::stoi(argv[1]);
    int listen_fd = make_listen(port);
    if (listen_fd < 0) return 1;

    if (set_nonblock(listen_fd) < 0) {
        close(listen_fd);
        return 1;
    }

    std::vector<int> clients;
    std::unordered_map<std::string, SessionData> sessions;
    std::unordered_map<int, std::string> session_by_fd;

    while (true) {
        prune_invalid_clients(clients);

        fd_set rfds;
        int maxfd = prepare_select(rfds, listen_fd, clients);

        timeval tv{0, 200000};
        int r = select(maxfd + 1, &rfds, nullptr, nullptr, &tv);
        if (r < 0) {
            perror("select");
            break;
        }

        if (FD_ISSET(listen_fd, &rfds)) {
            accept_new_client(listen_fd, clients);
        }

        std::vector<int> to_remove;
        process_client_events(rfds, clients, sessions, session_by_fd, to_remove);

        for (int c : to_remove) {
            cleanup_disconnected_client(c, clients, session_by_fd, sessions);
        }
    }

    close(listen_fd);
    return 0;
}
