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

#include "maidsafe/passport/identity_packets.h"

#include <cstdio>

#include "boost/lexical_cast.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/rsa.h"

namespace maidsafe {

namespace passport {

namespace detail {

std::string MidName(const std::string &username, const std::string &pin, bool surrogate) {
  return crypto::Hash<crypto::SHA512>(username + pin + (surrogate ? kSmidAppendix : ""));
}

}  // namespace detail

MidPacket::MidPacket()
    : packet_type_(kUnknown),
      name_(),
      username_(),
      pin_(),
      smid_appendix_(),
      rid_(),
      encrypted_rid_(),
      salt_(),
      secure_key_(),
      secure_iv_() {}

MidPacket::MidPacket(const std::string &username,
                     const std::string &pin,
                     const std::string &smid_appendix)
    : packet_type_(smid_appendix.empty() ? kMid : kSmid),
      name_(),
      username_(username),
      pin_(pin),
      smid_appendix_(smid_appendix),
      rid_(),
      encrypted_rid_(),
      salt_(),
      secure_key_(),
      secure_iv_() {
  Initialise();
}

void MidPacket::Initialise() {
  if (username_.empty() || pin_.empty())
    return Clear();

  salt_ = crypto::Hash<crypto::SHA512>(pin_ + username_);
  uint32_t pin;
  try {
    pin = boost::lexical_cast<uint32_t>(pin_);
  }
  catch(boost::bad_lexical_cast & e) {
    LOG(kError) << "MidPacket::Initialise: Bad pin:" << e.what();
    return Clear();
  }

  std::string secure_password;
  int result = crypto::SecurePassword(username_, salt_, pin, &secure_password);
  if (result != kSuccess) {
    LOG(kError) << "Failed to create secure pasword.  Result: " << result;
    return Clear();
  }

  secure_key_ = secure_password.substr(0, crypto::AES256_KeySize);
  secure_iv_ = secure_password.substr(crypto::AES256_KeySize, crypto::AES256_IVSize);
  name_ = detail::MidName(username_, pin_, !smid_appendix_.empty());
  if (name_.empty())
    Clear();
}

void MidPacket::SetRid(const std::string &rid) {
  rid_ = rid;
  if (rid_.empty()) {
    LOG(kError) << "Empty given RID";
    Clear();
    return;
  }

  encrypted_rid_ = crypto::SymmEncrypt(rid_, secure_key_, secure_iv_);
  if (encrypted_rid_.empty()) {
    LOG(kError) << "Failed to encrypt given RID";
    Clear();
  }
}

std::string MidPacket::DecryptRid(const std::string &encrypted_rid) {
  if (username_.empty() || pin_.empty() || encrypted_rid.empty()) {
    LOG(kError) << "MidPacket::DecryptRid: Empty encrypted RID or user data.";
    Clear();
    return "";
  }

  encrypted_rid_ = encrypted_rid;
  rid_ = crypto::SymmDecrypt(encrypted_rid_, secure_key_, secure_iv_);
  if (rid_.empty()) {
    LOG(kError) << "MidPacket::DecryptRid: Failed decryption.";
    Clear();
    return "";
  }

  return rid_;
}

void MidPacket::Clear() {
  name_.clear();
  username_.clear();
  pin_.clear();
  smid_appendix_.clear();
  encrypted_rid_.clear();
  salt_.clear();
  secure_key_.clear();
  secure_iv_.clear();
  rid_.clear();
}

bool MidPacket::Equals(const MidPacket& other) const {
  return packet_type_ == other.packet_type_ &&
         name_ == other.name_ &&
         username_ == other.username_ &&
         pin_ == other.pin_ &&
         smid_appendix_ == other.smid_appendix_ &&
         encrypted_rid_ == other.encrypted_rid_ &&
         salt_ == other.salt_ &&
         secure_key_ == other.secure_key_ &&
         secure_iv_ == other.secure_iv_ &&
         rid_ == other.rid_;
}


TmidPacket::TmidPacket()
    : packet_type_(kUnknown),
      name_(),
      username_(),
      pin_(),
      password_(),
      rid_(),
      plain_text_master_data_(),
      salt_(),
      secure_key_(),
      secure_iv_(),
      encrypted_master_data_(),
      obfuscated_master_data_(),
      obfuscation_salt_() {}

TmidPacket::TmidPacket(const std::string &username,
                       const std::string &pin,
                       bool surrogate,
                       const std::string &password,
                       const std::string &plain_text_master_data)
    : packet_type_(surrogate ? kStmid : kTmid),
      name_(),
      username_(username),
      pin_(pin),
      password_(password),
      rid_(crypto::Hash<crypto::SHA512>(pin)),
      plain_text_master_data_(plain_text_master_data),
      salt_(),
      secure_key_(),
      secure_iv_(),
      encrypted_master_data_(),
      obfuscated_master_data_(),
      obfuscation_salt_() {
  Initialise();
}

void TmidPacket::Initialise() {
  if (username_.empty() || pin_.empty() || rid_.empty()) {
    LOG(kError) << "TmidPacket::Initialise: Empty uname/pin";
    return Clear();
  }

  if (!SetPassword()) {
    LOG(kError) << "TmidPacket::Initialise: Password set failure";
    return;
  }
  if (!ObfuscatePlainData()) {
    LOG(kError) << "TmidPacket::Initialise: Obfuscation failure";
    return;
  }
  if (!SetPlainData()) {
    LOG(kError) << "TmidPacket::Initialise: Plain data failure";
    return;
  }

  name_ = crypto::Hash<crypto::SHA512>(encrypted_master_data_);
  if (name_.empty())
    LOG(kError) << "TmidPacket::Initialise: Empty kTmid name";
}

bool TmidPacket::SetPassword() {
  if (password_.empty() || rid_.size() < 4U) {
    salt_.clear();
    secure_key_.clear();
    secure_iv_.clear();
    LOG(kError) << "Password empty or RID too small(" << rid_.size() << ")";
    return false;
  }

  salt_ = crypto::Hash<crypto::SHA512>(rid_ + password_);
  if (salt_.empty()) {
    Clear();
    LOG(kError) << "Salt empty";
    return false;
  }

  uint32_t random_no_from_rid(0);
  int64_t a(1);
  for (int i = 0; i < 4; ++i) {
    uint8_t temp(static_cast<uint8_t>(rid_.at(i)));
    random_no_from_rid += static_cast<uint32_t>(temp * a);
    a *= 256;
  }

  std::string secure_password;
  int result = crypto::SecurePassword(password_, salt_, random_no_from_rid, &secure_password);
  if (result != kSuccess) {
    Clear();
    LOG(kError) << "Failed to create secure pasword.  Result: " << result;
    return false;
  }
  secure_key_ = secure_password.substr(0, crypto::AES256_KeySize);
  secure_iv_ = secure_password.substr(crypto::AES256_KeySize, crypto::AES256_IVSize);

  return true;
}

bool TmidPacket::ObfuscatePlainData() {
  if (plain_text_master_data_.empty() || username_.empty() || pin_.empty()) {
    LOG(kError) << "TmidPacket::ObfuscatePlainData: " << plain_text_master_data_.empty() << " - "
                << username_.empty() << " - " << pin_.empty();
    obfuscated_master_data_.clear();
    return false;
  }

  obfuscation_salt_ = crypto::Hash<crypto::SHA512>(password_ + rid_);
  uint32_t numerical_pin(boost::lexical_cast<uint32_t>(pin_));
  uint32_t rounds(numerical_pin / 2 == 0 ? numerical_pin * 3 / 2 : numerical_pin / 2);
  std::string obfuscation_str;
  int result = crypto::SecurePassword(username_, obfuscation_salt_, rounds, &obfuscation_str);
  if (result != kSuccess) {
    LOG(kError) << "Failed to create secure pasword.  Result: " << result;
    return false;
  }

  // make the obfuscation_str of same size for XOR
  if (plain_text_master_data_.size() < obfuscation_str.size()) {
    obfuscation_str.resize(plain_text_master_data_.size());
  } else if (plain_text_master_data_.size() > obfuscation_str.size()) {
    while (plain_text_master_data_.size() > obfuscation_str.size())
      obfuscation_str += obfuscation_str;
    obfuscation_str.resize(plain_text_master_data_.size());
  }

  obfuscated_master_data_ = crypto::XOR(plain_text_master_data_, obfuscation_str);

  return true;
}

bool TmidPacket::SetPlainData() {
  if (obfuscated_master_data_.empty() || secure_key_.empty() || secure_iv_.empty()) {
    encrypted_master_data_.clear();
    return false;
  }


  encrypted_master_data_ = crypto::SymmEncrypt(obfuscated_master_data_, secure_key_, secure_iv_);
  if (encrypted_master_data_.empty()) {
    Clear();
    return false;
  } else {
    return true;
  }
}

bool TmidPacket::ClarifyObfuscatedData() {
  uint32_t numerical_pin(boost::lexical_cast<uint32_t>(pin_));
  uint32_t rounds(numerical_pin / 2 == 0 ? numerical_pin * 3 / 2 : numerical_pin / 2);
  std::string obfuscation_str;
  int result =
      crypto::SecurePassword(username_,
                             crypto::Hash<crypto::SHA512>(password_ + rid_),
                             rounds,
                             &obfuscation_str);
  if (result != kSuccess) {
    LOG(kError) << "Failed to create secure pasword.  Result: " << result;
    return false;
  }

  // make the obfuscation_str of same sizer for XOR
  if (obfuscated_master_data_.size() < obfuscation_str.size()) {
    obfuscation_str.resize(obfuscated_master_data_.size());
  } else if (obfuscated_master_data_.size() > obfuscation_str.size()) {
    while (obfuscated_master_data_.size() > obfuscation_str.size())
      obfuscation_str += obfuscation_str;
    obfuscation_str.resize(obfuscated_master_data_.size());
  }

  plain_text_master_data_ = crypto::XOR(obfuscated_master_data_, obfuscation_str);
  return true;
}

std::string TmidPacket::DecryptMasterData(const std::string &password,
                                          const std::string &encrypted_master_data) {
  password_ = password;
  if (!SetPassword()) {
    LOG(kError) << "TmidPacket::DecryptMasterData: failed to set password.";
    return "";
  }

  if (encrypted_master_data.empty()) {
    LOG(kError) << "TmidPacket::DecryptMasterData: bad encrypted data.";
    password_.clear();
    salt_.clear();
    secure_key_.clear();
    secure_iv_.clear();
    return "";
  }

  encrypted_master_data_ = encrypted_master_data;
  obfuscated_master_data_ = crypto::SymmDecrypt(encrypted_master_data_, secure_key_, secure_iv_);
  if (obfuscated_master_data_.empty())
    Clear();

  // Undo obfuscation of master data
  if (!ClarifyObfuscatedData())
    return "";

  return plain_text_master_data_;
}

void TmidPacket::Clear() {
  name_.clear();
  username_.clear();
  pin_.clear();
  password_.clear();
  rid_.clear();
  plain_text_master_data_.clear();
  salt_.clear();
  secure_key_.clear();
  secure_iv_.clear();
  encrypted_master_data_.clear();
  obfuscated_master_data_.clear();
  obfuscation_salt_.clear();
}

bool TmidPacket::Equals(const TmidPacket& other) const {
//  return packet_type_ == other.packet_type_ &&
//         name_ == other.name_ &&
//         username_ == other.username_ &&
//         pin_ == other.pin_ &&
//         password_ == other.password_ &&
//         rid_ == other.rid_ &&
//         plain_text_master_data_ == other.plain_text_master_data_ &&
//         salt_ == other.salt_ &&
//         secure_key_ == other.secure_key_ &&
//         secure_iv_ == other.secure_iv_ &&
//         encrypted_master_data_ == other.encrypted_master_data_;
  if (packet_type_ != other.packet_type_) {
    LOG(kInfo) << "packet_type_";
    return false;
  }
  if (name_ != other.name_) {
    LOG(kInfo) << "name_";
    return false;
  }
  if (username_ != other.username_) {
    LOG(kInfo) << "username_";
    return false;
  }
  if (pin_ != other.pin_) {
    LOG(kInfo) << "pin_";
    return false;
  }
  if (password_ != other.password_) {
    LOG(kInfo) << "password_";
    return false;
  }
  if (rid_ != other.rid_) {
    LOG(kInfo) << "rid_";
    return false;
  }
  if (plain_text_master_data_ != other.plain_text_master_data_) {
    LOG(kInfo) << "plain_text_master_data_";
    return false;
  }
  if (salt_ != other.salt_) {
    LOG(kInfo) << "salt_";
    return false;
  }
  if (secure_key_ != other.secure_key_) {
    LOG(kInfo) << "secure_key_";
    return false;
  }
  if (secure_iv_ != other.secure_iv_) {
    LOG(kInfo) << "secure_iv_";
    return false;
  }
  if (encrypted_master_data_ != other.encrypted_master_data_) {
    LOG(kInfo) << "encrypted_master_data_";
    return false;
  }

  return true;
}

}  // namespace passport

}  // namespace maidsafe
