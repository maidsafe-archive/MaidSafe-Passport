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

#ifndef MAIDSAFE_PASSPORT_PASSPORT_H_
#define MAIDSAFE_PASSPORT_PASSPORT_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "maidsafe/common/rsa.h"

#include "maidsafe/passport/passport_config.h"


namespace maidsafe {

namespace passport {

std::string MidName(const std::string &username, const std::string &pin, bool surrogate);

std::string DecryptRid(const std::string &username,
                       const std::string &pin,
                       const std::string &encrypted_rid);

std::string DecryptMasterData(const std::string &username,
                              const std::string &pin,
                              const std::string &password,
                              const std::string &encrypted_master_data);

std::string PacketDebugString(const int &packet_type);

namespace test { class PassportTest; }

class PassportImpl;

class Passport {
 public:
  Passport();
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

  friend class test::PassportTest;

 private:
  Passport(const Passport&);
  Passport& operator=(const Passport&);

  std::shared_ptr<PassportImpl> impl_;
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_PASSPORT_H_
