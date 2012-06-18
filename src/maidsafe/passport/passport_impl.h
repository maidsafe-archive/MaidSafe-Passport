/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Description:  API to MaidSafe Passport
* Version:      1.0
* Created:      2010-10-13-14.01.23
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#ifndef MAIDSAFE_PASSPORT_PASSPORT_IMPL_H_
#define MAIDSAFE_PASSPORT_PASSPORT_IMPL_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "boost/thread/mutex.hpp"

#include "maidsafe/common/rsa.h"

#include "maidsafe/passport/passport_config.h"
#include "maidsafe/passport/identity_packets.h"

namespace maidsafe {

namespace passport {

namespace impl {

std::string MidName(const std::string &username, const std::string &pin, bool surrogate);

std::string DecryptRid(const std::string &username,
                       const std::string &pin,
                       const std::string &encrypted_rid);

std::string DecryptMasterData(const std::string &username,
                              const std::string &pin,
                              const std::string &password,
                              const std::string &encrypted_master_data);

std::string PacketDebugString(const int &packet_type);

}

struct IdentityPackets {
  IdentityPackets() : mid(), smid(), tmid(), stmid() {}
  MidPacket mid, smid;
  TmidPacket tmid, stmid;
};

struct SelectableIdentity {
  SelectableIdentity() : anmpid(), mpid(), mmid() {}
  asymm::Keys anmpid;
  asymm::Keys mpid;
  asymm::Keys mmid;
};

class PassportImpl {
 public:
  PassportImpl();
  int CreateSigningPackets();
  int ConfirmSigningPackets();
  int SetIdentityPackets(const std::string &username,
                         const std::string &pin,
                         const std::string &password,
                         const std::string &master_data,
                         const std::string &surrogate_data);
  int ConfirmIdentityPackets();
  void Clear(bool signature, bool identity, bool selectable);

  // Serialisation
  std::string Serialise();
  int Parse(const std::string& serialised_passport);

  // Getters
  std::string IdentityPacketName(PacketType packet_type, bool confirmed);
  std::string IdentityPacketValue(PacketType packet_type, bool confirmed);
  asymm::Keys SignaturePacketDetails(PacketType packet_type,
                                     bool confirmed,
                                     const std::string &chosen_name = "");

  // Selectable Identity (aka MPID)
  int CreateSelectableIdentity(const std::string &chosen_name);
  int ConfirmSelectableIdentity(const std::string &chosen_name);
  int DeleteSelectableIdentity(const std::string &chosen_name);

  int MoveMaidsafeInbox(const std::string &chosen_identity);
  int ConfirmMovedMaidsafeInbox(const std::string &chosen_identity);

 private:
  PassportImpl(const PassportImpl&);
  PassportImpl& operator=(const PassportImpl&);

  std::map<PacketType, asymm::Keys> pending_signature_packets_, confirmed_signature_packets_;
  IdentityPackets pending_identity_packets_, confirmed_identity_packets_;
  std::map<std::string, SelectableIdentity> pending_selectable_packets_,
                                            confirmed_selectable_packets_;
  boost::mutex signature_mutex_, identity_mutex_, selectable_mutex_;
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_PASSPORT_IMPL_H_
