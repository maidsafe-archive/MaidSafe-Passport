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

#include "maidsafe/passport/passport_config.h"
#include "maidsafe/passport/version.h"

#if MAIDSAFE_PASSPORT_VERSION != 109
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-passport library.
#endif


namespace maidsafe {

namespace passport {

std::string MidName(const std::string &username,
                    const std::string &pin,
                    bool surrogate);

std::string DecryptRid(const std::string &username,
                       const std::string &pin,
                       const std::string &encrypted_rid,
                       bool surrogate);

std::string PacketDebugString(const int &packet_type);

namespace test { class PassportTest; }

class SystemPacketHandler;

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

  // Serialisation
  std::string SerialiseKeyring() const;
  int ParseKeyring(const std::string &serialised_keyring);

  // Getters
  std::string PacketName(PacketType packet_type, bool confirmed) const;
  std::string PacketValue(PacketType packet_type, bool confirmed) const;
  std::string PacketSignature(PacketType packet_type, bool confirmed) const;

  friend class test::PassportTest;
 
 private:
  Passport(const Passport&);
  Passport& operator=(const Passport&);
  std::shared_ptr<SystemPacketHandler> handler_;
  std::string kSmidAppendix_;
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_PASSPORT_H_
