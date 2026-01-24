#ifndef SHARED_NET_MESSAGE_UTIL_H
#define SHARED_NET_MESSAGE_UTIL_H

#include "shared_common_crypto.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

template <typename T> struct PeerMap;

struct MessageContext {
  std::vector<unsigned char> aad;
  uint32_t seq = 0;
  secure_vector session_key;
  std::string shortfp = "(no fp)";
  std::string target_username = "(unknown)";
  bool valid = false;
};

template <typename PeerMap>
inline MessageContext prepare_message_context(const std::string &recipient_fp,
                                              const std::string &my_fp_hex,
                                              PeerMap &peers,
                                              std::mutex &peers_mtx) {
  MessageContext ctx;
  const std::lock_guard<std::mutex> lk(peers_mtx);
  const auto it = peers.find(recipient_fp);
  if (it == peers.end())
    return ctx;
  auto &pi = it->second;
  if (!pi.ready)
    return ctx;
  ctx.seq = pi.send_seq;
  ctx.session_key = pi.sk.key;
  ctx.target_username = pi.username;
  const std::string hexfp = pi.peer_fp_hex;
  ctx.shortfp = hexfp.size() > 10 ? hexfp.substr(0, 10) : hexfp;

  // AAD must use same sorted order as encryption defined in
  // shared_common_crypto.h struct AADBuilder
  const std::string aad_str =
      AADBuilder{
          my_fp_hex,     // me (sender) - local_fp
          pi.peer_fp_hex // peer (receiver) - remote_fp
      }
          .build_for_seq(ctx.seq);
  ctx.aad.assign(aad_str.begin(), aad_str.end());

  ctx.valid = true;
  return ctx;
}

#endif