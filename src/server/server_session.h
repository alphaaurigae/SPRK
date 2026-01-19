#ifndef SERVER_SESSION_H
#define SERVER_SESSION_H

#include "shared_net_common_protocol.h"

#include <string>
#include <unordered_map>
#include <vector>

struct SessionData
{
    std::unordered_map<int, std::string>         nick_by_fd;
    std::unordered_map<std::string, int>         fd_by_nick;
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

// Returns empty string on success, error message on failure
static std::string validate_hello_basics(const Parsed &p, std::string &uname,
                                         std::string &sid)
{
    uname = trim(p.username);
    sid   = trim(p.session_id);

    if (sid.empty())
    {
        sid = std::string(reinterpret_cast<const char *>(p.eph_pk.data()),
                          p.eph_pk.size());
    }

    if (p.id_alg == 0 || p.identity_pk.empty() || p.signature.empty())
    {
        return "missing identity or signature";
    }

    std::vector<unsigned char> sig_data;
    sig_data.reserve(p.eph_pk.size() + p.session_id.size());
    sig_data.insert(sig_data.end(), p.eph_pk.begin(), p.eph_pk.end());
    sig_data.insert(sig_data.end(), p.session_id.begin(), p.session_id.end());

    bool sig_ok =
        (p.id_alg == ALGO_MLDSA87) &&
        pqsig_verify(SIG_ALG_NAME, p.identity_pk, sig_data, p.signature);

    if (!sig_ok)
    {
        return "invalid signature";
    }

    return {}; // empty string = success
}

static void cleanup_old_nickname(SessionData &sd, int client_fd,
                                 const std::string &new_uname)
{
    auto it_oldnick = sd.nick_by_fd.find(client_fd);
    if (it_oldnick == sd.nick_by_fd.end() || it_oldnick->second == new_uname)
    {
        return; // no cleanup needed
    }

    const std::string oldnick = it_oldnick->second;
    sd.fd_by_nick.erase(oldnick);

    auto it_fp = sd.fingerprint_hex_by_fd.find(client_fd);
    if (it_fp != sd.fingerprint_hex_by_fd.end())
    {
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

static bool check_username_conflicts(SessionData &sd, const std::string &uname,
                                     int client_fd, std::vector<int> &to_remove)
{
    auto it_existing = sd.fd_by_nick.find(uname);

    // Exact match with different fd → reject
    if (it_existing != sd.fd_by_nick.end() && it_existing->second != client_fd)
    {
        std::cout << "REJECTED: username already in use " << uname << "\n";
        to_remove.push_back(client_fd);
        return false;
    }

    // Similar username, but not the same client re-connecting
    if (has_similar_username(uname, sd.fd_by_nick, 85) &&
        (it_existing == sd.fd_by_nick.end() ||
         it_existing->second != client_fd))
    {
        std::cout << "REJECTED: username too similar to existing user " << uname
                  << "\n";
        to_remove.push_back(client_fd);
        return false;
    }

    return true; // username is acceptable
}

static void register_client(SessionData &sd, int client_fd,
                            const std::string &uname, const Parsed &p,
                            const std::vector<unsigned char> &frame)
{

    // In handle_hello_message → register_client block
    // Compute fingerprint if identity key present
    std::string fp_hex =
        p.identity_pk.empty() ? "" : compute_fingerprint_hex(p.identity_pk);

    // Always register nickname
    sd.nick_by_fd[client_fd] = uname;
    sd.fd_by_nick[uname]     = client_fd;

    // Register identity/fingerprint data if present
    if (!fp_hex.empty())
    {
        sd.fingerprint_hex_by_fd[client_fd]     = fp_hex;
        sd.fd_by_fingerprint[fp_hex]            = client_fd;
        sd.nick_by_fingerprint[fp_hex]          = uname;
        sd.eph_by_fingerprint[fp_hex]           = p.eph_pk;
        sd.identity_pk_by_fingerprint[fp_hex]   = p.identity_pk;
        sd.hello_message_by_fingerprint[fp_hex] = frame;
    }
    else
    {
        sd.hello_message_by_fingerprint[""] = frame;
    }
}
#endif