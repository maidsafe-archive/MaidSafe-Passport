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

#ifndef MAIDSAFE_PASSPORT_IDENTITY_PACKETS_H_
#define MAIDSAFE_PASSPORT_IDENTITY_PACKETS_H_

#include <cstdint>
#include <memory>
#include <string>

#include "maidsafe/passport/passport_config.h"

namespace maidsafe {

namespace passport {

namespace detail {

Identity MidName(NonEmptyString username, uint32_t pin, bool surrogate);

}  // namespace detail

namespace test { class IdentityPacketsTest; }

class MidPacket {
 public:
  MidPacket();
  MidPacket(const NonEmptyString &username,
            const uint32_t pin,
            bool surrogate);
  ~MidPacket() {}
  Identity name() const { return name_; }
  NonEmptyString value() const { return encrypted_rid_; }
  bool operator==(const MidPacket& other) const;
  void SetRid(const Identity &rid);
  Identity DecryptRid(const NonEmptyString &encrypted_rid);
  NonEmptyString username() const { return username_; }
  uint32_t pin() const { return pin_; }
  NonEmptyString rid() const { return rid_; }

 private:
  friend class test::IdentityPacketsTest;
  void Initialise();
  void Clear();
  PacketType packet_type_;
  bool surrogate_;
  uint32_t pin_;
  Identity name_;
  NonEmptyString username_, rid_, encrypted_rid_, salt_;
  crypto::AES256Key secure_key_;
  crypto::AES256InitialisationVector secure_iv_;
};

class TmidPacket {
 public:
  TmidPacket();
  TmidPacket(const NonEmptyString &username,
             const uint32_t pin,
             bool surrogate,
             const NonEmptyString &password);
  TmidPacket(const NonEmptyString &username,
             const uint32_t pin,
             bool surrogate,
             const NonEmptyString &password,
             const NonEmptyString &plain_text_master_data);
  ~TmidPacket() {}
  Identity name() const { return name_; }
  NonEmptyString value() const { return encrypted_master_data_; }
  bool operator==(const TmidPacket& other) const;
  NonEmptyString DecryptMasterData(const NonEmptyString &password,
                                const NonEmptyString &encrypted_master_data);
  void SetToSurrogate() { packet_type_ = kStmid; }
  NonEmptyString username() const { return username_; }
  uint32_t pin() const { return pin_; }
  NonEmptyString password() const { return password_; }

 private:
  friend class test::IdentityPacketsTest;
  void Initialise();
  bool SetSecurePassword();
  bool SetPlainData();
  bool ObfuscatePlainData();
  bool ClarifyObfuscatedData();
  void Clear();
  PacketType packet_type_;
  Identity name_;
  NonEmptyString username_;
  uint32_t pin_;
  NonEmptyString  password_, rid_, plain_text_master_data_, salt_;
  crypto::AES256Key secure_key_;
  crypto::AES256InitialisationVector secure_iv_;
  NonEmptyString encrypted_master_data_, obfuscated_master_data_, obfuscation_salt_;
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_IDENTITY_PACKETS_H_
