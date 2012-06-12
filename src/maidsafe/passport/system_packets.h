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

#include "maidsafe/pki/packet.h"
#include "maidsafe/passport/passport_config.h"


namespace testing { class AssertionResult; }

namespace maidsafe {

namespace passport {

typedef std::shared_ptr<pki::Packet> PacketPtr;
typedef std::shared_ptr<pki::SignaturePacket> SignaturePacketPtr;

class MidPacket;
class TmidPacket;
class Key;
class Passport;

namespace test {

testing::AssertionResult Empty(PacketPtr packet);
class SystemPacketsTest_BEH_CreateSig_Test;
class SystemPacketsTest_BEH_PutToAndGetFromKey_Test;
struct ExpectedMidContent;
testing::AssertionResult Equal(std::shared_ptr<ExpectedMidContent> expected,
                               std::shared_ptr<MidPacket> mid);
struct ExpectedTmidContent;
testing::AssertionResult Equal(std::shared_ptr<ExpectedTmidContent> expected,
                               std::shared_ptr<TmidPacket> mid);
class PassportTest_BEH_SetNewUserData_Test;
class PassportTest_BEH_ConfirmNewUserData_Test;
class PassportTest;

}  // namespace test

std::string GetMidName(const std::string &username,
                       const std::string &pin,
                       const std::string &smid_appendix);

std::string DebugString(const int &packet_type);

bool IsSignature(const int &packet_type, bool check_for_self_signer);

class MidPacket : public pki::Packet {
 public:
  MidPacket();
  MidPacket(const std::string &username,
            const std::string &pin,
            const std::string &smid_appendix);
  ~MidPacket() {}
  std::string value() const { return encrypted_rid_; }
  bool Equals(const std::shared_ptr<pki::Packet> other) const;
  void SetRid(const std::string &rid);
  std::string DecryptRid(const std::string &encrypted_rid);
  std::string username() const { return username_; }
  std::string pin() const { return pin_; }
  std::string rid() const { return rid_; }
 private:
  friend testing::AssertionResult test::Empty(PacketPtr packet);
  friend testing::AssertionResult test::Equal(std::shared_ptr<test::ExpectedMidContent> expected,
                                              std::shared_ptr<MidPacket> mid);
  void Initialise();
  void Clear();
  std::string username_, pin_, smid_appendix_, rid_, encrypted_rid_, salt_;
  std::string secure_key_, secure_iv_;
};

class TmidPacket : public pki::Packet {
 public:
  TmidPacket();
  TmidPacket(const std::string &username,
             const std::string &pin,
             bool surrogate,
             const std::string &password,
             const std::string &plain_text_master_data);
  ~TmidPacket() {}
  std::string value() const { return encrypted_master_data_; }
  bool Equals(const std::shared_ptr<pki::Packet> other) const;
  std::string DecryptMasterData(const std::string &password,
                                const std::string &encrypted_master_data);
  void SetToSurrogate() { packet_type_ = kStmid; }
  std::string username() const { return username_; }
  std::string pin() const { return pin_; }
  std::string password() const { return password_; }

 private:
  friend testing::AssertionResult test::Empty(PacketPtr packet);
  friend testing::AssertionResult test::Equal(std::shared_ptr<test::ExpectedTmidContent> expected,
                                              std::shared_ptr<TmidPacket> tmid);
  void Initialise();
  bool SetPassword();
  bool SetPlainData();
  bool ObfuscatePlainData();
  bool ClarifyObfuscatedData();
  void Clear();
  std::string username_, pin_, password_, rid_, plain_text_master_data_, salt_,
              secure_key_, secure_iv_, encrypted_master_data_,
              obfuscated_master_data_, obfuscation_salt_;
};

class MpidPacket : public pki::Packet {
 public:
  MpidPacket();
  ~MpidPacket() {}
};

class McidPacket : public pki::Packet {
 public:
  McidPacket();
  McidPacket(const std::string &mmid_name,
             const MpidPacket &mpid,
             const asymm::PublicKey &recipient_public_key);
  ~McidPacket() {}
  std::string value() const { return value_; }
 private:
  std::string value_;
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_SYSTEM_PACKETS_H_
