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

Identity MidName(NonEmptyString username, uint32_t pin, bool surrogate) {
  
  return surrogate ?  
    crypto::Hash<crypto::SHA512>(username +  boost::lexical_cast<NonEmptyString>(pin)) :
    crypto::Hash<crypto::SHA512>(crypto::Hash<crypto::SHA512>(username +
                                boost::lexical_cast<NonEmptyString>(pin)));
}

}  // namespace detail

MidPacket::MidPacket()
    : packet_type_(kUnknown),
      surrogate_(false),
      pin_(),
      name_(),
      username_(),
      rid_(),
      encrypted_rid_(),
      salt_(),
      secure_key_(),
      secure_iv_() {}

MidPacket::MidPacket(const NonEmptyString &username,
                     const uint32_t pin,
                     bool surrogate)
    : packet_type_(surrogate ? kSmid : kMid),
      surrogate_(surrogate),
      pin_(pin),
      name_(),
      username_(username),
      rid_(),
      encrypted_rid_(),
      salt_(),
      secure_key_(),
      secure_iv_() {
  Initialise();
}

void MidPacket::Initialise() {

  salt_ = crypto::Hash<crypto::SHA512>(boost::lexical_cast<NonEmptyString>(pin_) + username_);

  UserPassword secure_password(crypto::CreateSecurePassword(UserPassword(username_),
                                                    crypto::Salt(crypto::Hash<crypto::SHA512>(
                                                      boost::lexical_cast<std::string>(pin_)
                                                      + username_.string())),
                                                    pin_));

  secure_key_ =  NonEmptyString(secure_password.string().substr(0, crypto::AES256_KeySize));
  secure_iv_ = NonEmptyString(secure_password.string().substr(crypto::AES256_KeySize,
                                                              crypto::AES256_IVSize));
  name_ = detail::MidName(username_, pin_, surrogate_);
}

void MidPacket::SetRid(const Identity &rid) {
  rid_ = rid;

  encrypted_rid_ = crypto::SymmEncrypt(crypto::PlainText(rid_),
                                       crypto::AES256Key(secure_key_),
                                       crypto::AES256InitialisationVector(secure_iv_));
}

Identity MidPacket::DecryptRid(const NonEmptyString &encrypted_rid) {

  encrypted_rid_ = encrypted_rid;
  return Identity(crypto::SymmDecrypt(encrypted_rid_, secure_key_, secure_iv_));
}

bool MidPacket::operator==(const MidPacket& other) const {
  return packet_type_ == other.packet_type_ &&
         surrogate_ == other.surrogate_ &&
         name_ == other.name_ &&
         username_ == other.username_ &&
         pin_ == other.pin_ &&
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

TmidPacket::TmidPacket(const NonEmptyString &username,
                       uint32_t pin,
                       bool surrogate,
                       const NonEmptyString &password,
                       const NonEmptyString &plain_text_master_data)
    : packet_type_(surrogate ? kStmid : kTmid),
      name_(),
      username_(username),
      pin_(pin),
      password_(password),
      rid_(crypto::Hash<crypto::SHA512>(boost::lexical_cast<NonEmptyString>(pin))),
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
}

bool TmidPacket::SetPassword() {

  salt_ = crypto::Hash<crypto::SHA512>(rid_ + password_);

  uint32_t random_no_from_rid(0);
  int64_t a(1);
  for (int i = 0; i < 4; ++i) {
    uint8_t temp(static_cast<uint8_t>(rid_.string().at(i)));
    random_no_from_rid += static_cast<uint32_t>(temp * a);
    a *= 256;
  }

  NonEmptyString secure_password(crypto::CreateSecurePassword(password_, salt_, random_no_from_rid));
  secure_key_ = crypto::AES256Key(secure_password.string().substr(0, crypto::AES256_KeySize));
  secure_iv_ = crypto::AES256InitialisationVector(
      secure_password.string().substr(crypto::AES256_KeySize, crypto::AES256_IVSize));

  return true;
}

bool TmidPacket::ObfuscatePlainData() {

  obfuscation_salt_ = crypto::Hash<crypto::SHA512>(password_ + rid_);
  uint32_t rounds(pin_ / 2 == 0 ? pin_ * 3 / 2 : pin_ / 2);
  std::string obfuscation_str = crypto::CreateSecurePassword(username_,
                                                          obfuscation_salt_,
                                                          rounds).string();

  // make the obfuscation_str of same size for XOR
  if (plain_text_master_data_.string().size() < obfuscation_str.size()) {
    obfuscation_str.resize(plain_text_master_data_.string().size());
  } else if (plain_text_master_data_.string().size() > obfuscation_str.size()) {
    while (plain_text_master_data_.string().size() > obfuscation_str.size())
      obfuscation_str += obfuscation_str;
    obfuscation_str.resize(plain_text_master_data_.string().size());
  }

  maidsafe::detail::BoundedString<obfuscation_str.size(), obfuscation_str.size()> XorType;

  XorType result = crypto::XOR(XorType(plain_text_master_data_), XorType(obfuscation_str));
  obfuscated_master_data_ = result;

  return true;
}

bool TmidPacket::SetPlainData() {
  encrypted_master_data_ = crypto::SymmEncrypt(obfuscated_master_data_, secure_key_, secure_iv_);
  return true;
}

bool TmidPacket::ClarifyObfuscatedData() {
  uint32_t rounds(pin_ / 2 == 0 ? pin_ * 3 / 2 : pin_ / 2);
  crypto::SecurePassword obfuscation_str = crypto::SecurePassword(username_,
                             crypto::Hash<crypto::SHA512>(password_ + rid_),
                             rounds);

  // make the obfuscation_str of same sizer for XOR
  if (obfuscated_master_data_.size() < obfuscation_str.size()) {
    obfuscation_str.resize(obfuscated_master_data_.size());
  } else if (obfuscated_master_data_.size() > obfuscation_str.size()) {
    while (obfuscated_master_data_.size() > obfuscation_str.size())
      obfuscation_str += obfuscation_str;
    obfuscation_str.resize(obfuscated_master_data_.size());
  }
  BoundedString<obfuscation_str.size(), obfuscation_str.size()> XorType;

  XorType result = crypto::XOR(XorType(obfuscated_master_data_), XorType(obfuscation_str));
  plain_text_master_data_ = result;
  return true;
}

NonEmptyString TmidPacket::DecryptMasterData(const NonEmptyString &password,
                                          const NonEmptyString &encrypted_master_data) {
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

bool TmidPacket::operator==(const TmidPacket& other) const {
 return packet_type_ == other.packet_type_ &&
        name_ == other.name_ &&
        username_ == other.username_ &&
        pin_ == other.pin_ &&
        password_ == other.password_ &&
        rid_ == other.rid_ &&
        plain_text_master_data_ == other.plain_text_master_data_ &&
        salt_ == other.salt_ &&
        secure_key_ == other.secure_key_ &&
        secure_iv_ == other.secure_iv_ &&
        encrypted_master_data_ == other.encrypted_master_data_;
}

}  // namespace passport

}  // namespace maidsafe
