/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Setters and getters for system packets
* Version:      1.0
* Created:      14/10/2010 11:43:59
* Revision:     none
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

#ifndef MAIDSAFE_PASSPORT_SYSTEM_PACKETS_H_
#define MAIDSAFE_PASSPORT_SYSTEM_PACKETS_H_

#include <cstdint>
#include <memory>
#include <string>

#include "maidsafe/passport/passport_config.h"

namespace maidsafe {

namespace passport {

namespace detail {

std::string MidName(const std::string &username, const std::string &pin, bool surrogate);

}  // namespace detail

namespace test { class IdentityPacketsTest; }

class MidPacket {
 public:
  MidPacket();
  MidPacket(const std::string &username,
            const std::string &pin,
            const std::string &smid_appendix);
  ~MidPacket() {}
  std::string name() const { return name_; }
  std::string value() const { return encrypted_rid_; }
  bool Equals(const MidPacket& other) const;
  void SetRid(const std::string &rid);
  std::string DecryptRid(const std::string &encrypted_rid);
  std::string username() const { return username_; }
  std::string pin() const { return pin_; }
  std::string rid() const { return rid_; }

 private:
  friend class test::IdentityPacketsTest;
  void Initialise();
  void Clear();
  PacketType packet_type_;
  std::string name_, username_, pin_, smid_appendix_, rid_, encrypted_rid_,
              salt_, secure_key_, secure_iv_;
};

class TmidPacket {
 public:
  TmidPacket();
  TmidPacket(const std::string &username,
             const std::string &pin,
             bool surrogate,
             const std::string &password,
             const std::string &plain_text_master_data);
  ~TmidPacket() {}
  std::string name() const { return name_; }
  std::string value() const { return encrypted_master_data_; }
  bool Equals(const TmidPacket& other) const;
  std::string DecryptMasterData(const std::string &password,
                                const std::string &encrypted_master_data);
  void SetToSurrogate() { packet_type_ = kStmid; }
  std::string username() const { return username_; }
  std::string pin() const { return pin_; }
  std::string password() const { return password_; }

 private:
  friend class test::IdentityPacketsTest;  void Initialise();
  bool SetPassword();
  bool SetPlainData();
  bool ObfuscatePlainData();
  bool ClarifyObfuscatedData();
  void Clear();
  PacketType packet_type_;
  std::string name_, username_, pin_, password_, rid_, plain_text_master_data_, salt_,
              secure_key_, secure_iv_, encrypted_master_data_,
              obfuscated_master_data_, obfuscation_salt_;
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_SYSTEM_PACKETS_H_
