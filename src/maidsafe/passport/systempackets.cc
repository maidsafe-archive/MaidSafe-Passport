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

#include "maidsafe/passport/systempackets.h"
#include <cstdio>
#include "boost/lexical_cast.hpp"
#include "maidsafe/common/log.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/passport/signaturepacket.pb.h"

namespace maidsafe {

namespace passport {

std::string DebugString(const int &packet_type) {
  switch (packet_type) {
    case UNKNOWN:
      return "unknown";
    case MID:
      return "MID";
    case SMID:
      return "SMID";
    case TMID:
      return "TMID";
    case STMID:
      return "STMID";
    case MPID:
      return "MPID";
    case PMID:
      return "PMID";
    case MAID:
      return "MAID";
    case ANMID:
      return "ANMID";
    case ANSMID:
      return "ANSMID";
    case ANTMID:
      return "ANTMID";
    case ANMPID:
      return "ANMPID";
    case ANMAID:
      return "ANMAID";
    case MSID:
      return "MSID";
    case PD_DIR:
      return "PD_DIR";
    default:
      return "error";
  }
}

bool IsSignature(const int &packet_type, bool check_for_self_signer) {
  switch (packet_type) {
    case MPID:
    case PMID:
    case MAID:
      return !check_for_self_signer;
    case ANMID:
    case ANSMID:
    case ANTMID:
    case ANMPID:
    case ANMAID:
    case MSID:
      return true;
    default:
      return false;
  }
}

SignaturePacket::SignaturePacket()
    : pki::Packet(UNKNOWN),
      public_key_(),
      private_key_(),
      signer_private_key_(),
      public_key_signature_() {}

SignaturePacket::SignaturePacket(const PacketType &packet_type,
                                 const std::string &public_key,
                                 const std::string &private_key,
                                 const std::string &signer_private_key,
                                 const std::string &public_name)
    : pki::Packet(packet_type),
      public_key_(public_key),
      private_key_(private_key),
      signer_private_key_(signer_private_key),
      public_key_signature_() {
  if (packet_type == MPID)
    name_ = crypto::Hash<crypto::SHA512>(public_name);
  Initialise();
}

SignaturePacket::SignaturePacket(const Key &key)
    : pki::Packet(key.packet_type()),
      public_key_(key.public_key()),
      private_key_(key.private_key()),
      signer_private_key_(key.has_signer_private_key() ?
                          key.signer_private_key() : key.private_key()),
      public_key_signature_(key.public_key_signature()) {
  name_ = key.name();
}

void SignaturePacket::Initialise() {
  if (!IsSignature(packet_type_, false)) {
    packet_type_ = UNKNOWN;
    return Clear();
  }
  if (public_key_.empty() || private_key_.empty())
    return Clear();

  if (IsSignature(packet_type_, true)) {  // this is a self-signing packet
    if (signer_private_key_.empty()) {
      signer_private_key_ = private_key_;
    } else if (signer_private_key_ != private_key_) {
      return Clear();
    }
  } else if (signer_private_key_.empty() ||
             (signer_private_key_ == private_key_)) {
    return Clear();
  }

  public_key_signature_ = crypto::AsymSign(public_key_, signer_private_key_);
  if (packet_type_ != MPID)
    name_ = crypto::Hash<crypto::SHA512>(public_key_ + public_key_signature_);
  if (name_.empty())
    Clear();
}

void SignaturePacket::Clear() {
  name_.clear();
  public_key_.clear();
  private_key_.clear();
  signer_private_key_.clear();
  public_key_signature_.clear();
}

bool SignaturePacket::Equals(const pki::Packet *other) const {
  const SignaturePacket *rhs = static_cast<const SignaturePacket*>(other);
  return packet_type_ == rhs->packet_type_ &&
         name_ == rhs->name_ &&
         public_key_ == rhs->public_key_ &&
         private_key_ == rhs->private_key_ &&
         signer_private_key_ == rhs->signer_private_key_ &&
         public_key_signature_ == rhs->public_key_signature_;
}

void SignaturePacket::PutToKey(Key *key) {
  key->set_name(name_);
  key->set_packet_type(packet_type_);
  key->set_public_key(public_key_);
  key->set_private_key(private_key_);
  if (signer_private_key_ != private_key_)
    key->set_signer_private_key(signer_private_key_);
  key->set_public_key_signature(public_key_signature_);
}



MidPacket::MidPacket()
    : pki::Packet(UNKNOWN),
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
    : pki::Packet(smid_appendix.empty() ? MID : SMID),
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
  boost::uint32_t pin;
  try {
    pin = boost::lexical_cast<boost::uint32_t>(pin_);
  }
  catch(boost::bad_lexical_cast & e) {
#ifdef DEBUG
    printf("MidPacket::Initialise: Bad pin: %s\n", e.what());
#endif
    return Clear();
  }
  std::string secure_password = crypto::SecurePassword(username_, salt_, pin);
  secure_key_ = secure_password.substr(0, crypto::AES256_KeySize);
  secure_iv_ = secure_password.substr(crypto::AES256_KeySize,
                                      crypto::AES256_IVSize);
  name_ = crypto::Hash<crypto::SHA512>(username_ + pin_ + smid_appendix_);
  if (name_.empty())
    Clear();
}

void MidPacket::SetRid(const std::string &rid) {
  rid_ = rid;
  if (rid_.empty())
    encrypted_rid_.clear();
  else
    encrypted_rid_ = crypto::SymmEncrypt(rid_, secure_key_, secure_iv_);
  if (encrypted_rid_.empty())
    Clear();
}

std::string MidPacket::DecryptRid(const std::string &encrypted_rid) {
  if (username_.empty() || pin_.empty() || encrypted_rid.empty()) {
#ifdef DEBUG
    printf("MidPacket::DecryptRid: Bad encrypted RID or user data empty.\n");
#endif
    Clear();
    return 0;
  }

  encrypted_rid_ = encrypted_rid;
  rid_ = crypto::SymmDecrypt(encrypted_rid_, secure_key_, secure_iv_);
  if (rid_.empty())
    Clear();
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

bool MidPacket::Equals(const pki::Packet *other) const {
  const MidPacket *rhs = static_cast<const MidPacket*>(other);
  return packet_type_ == rhs->packet_type_ &&
         name_ == rhs->name_ &&
         username_ == rhs->username_ &&
         pin_ == rhs->pin_ &&
         smid_appendix_ == rhs->smid_appendix_ &&
         encrypted_rid_ == rhs->encrypted_rid_ &&
         salt_ == rhs->salt_ &&
         secure_key_ == rhs->secure_key_ &&
         secure_iv_ == rhs->secure_iv_ &&
         rid_ == rhs->rid_;
}



TmidPacket::TmidPacket()
    : pki::Packet(UNKNOWN),
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
                       const std::string &rid,
                       bool surrogate,
                       const std::string &password,
                       const std::string &plain_text_master_data)
    : pki::Packet(surrogate ? STMID : TMID),
      username_(username),
      pin_(pin),
      password_(password),
      rid_(rid),
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
  if (username_.empty() || pin_.empty() || rid_.empty())
    return Clear();

  name_ = crypto::Hash<crypto::SHA512>(username_ + pin_ + rid_);
  if (!SetPassword()) {
    DLOG(ERROR) << "TmidPacket::Initialise: Password set failure" << std::endl;
    return;
  }
  if (!ObfuscatePlainData()) {
    DLOG(ERROR) << "TmidPacket::Initialise: Obfuscation failure" << std::endl;
    return;
  }
  if (!SetPlainData()) {
    DLOG(ERROR) << "TmidPacket::Initialise: Plain data failure" << std::endl;
    return;
  }
  if (name_.empty())
    Clear();
}

bool TmidPacket::SetPassword() {
  if (password_.empty() || rid_.size() < 4U) {
    salt_.clear();
    secure_key_.clear();
    secure_iv_.clear();
    return false;
  }

  salt_ = crypto::Hash<crypto::SHA512>(rid_ + password_);
  boost::uint32_t random_no_from_rid(0);
  int a = 1;
  for (int i = 0; i < 4; ++i) {
    boost::uint8_t temp(static_cast<boost::uint8_t>(rid_.at(i)));
    random_no_from_rid += (temp * a);
    a *= 256;
  }

  std::string secure_password = crypto::SecurePassword(password_, salt_,
                                                       random_no_from_rid);
  secure_key_ = secure_password.substr(0, crypto::AES256_KeySize);
  secure_iv_ = secure_password.substr(crypto::AES256_KeySize,
                                      crypto::AES256_IVSize);
  if (salt_.empty()) {
    Clear();
    return false;
  } else {
    return true;
  }
}

bool TmidPacket::ObfuscatePlainData() {
  if (plain_text_master_data_.empty() || username_.empty() || pin_.empty()) {
    obfuscated_master_data_.clear();
    return false;
  }

  obfuscation_salt_ = crypto::Hash<crypto::SHA512>(password_ + rid_);
  boost::uint32_t numerical_pin(boost::lexical_cast<boost::uint32_t>(pin_));
  boost::uint32_t rounds(numerical_pin / 2 == 0 ?
                         numerical_pin * 3 / 2 : numerical_pin / 2);
  std::string obfuscation_str = crypto::SecurePassword(username_,
                                                       obfuscation_salt_,
                                                       rounds);

  // make the obfuscation_str of same size for XOR
  if (plain_text_master_data_.size() < obfuscation_str.size()) {
    obfuscation_str.resize(plain_text_master_data_.size());
  } else if (plain_text_master_data_.size() > obfuscation_str.size()) {
    while (plain_text_master_data_.size() > obfuscation_str.size())
      obfuscation_str += obfuscation_str;
    obfuscation_str.resize(plain_text_master_data_.size());
  }

  obfuscated_master_data_ = crypto::XOR(plain_text_master_data_,
                                        obfuscation_str);

  return true;
}

bool TmidPacket::SetPlainData() {
  if (obfuscated_master_data_.empty() || secure_key_.empty() ||
      secure_iv_.empty()) {
    encrypted_master_data_.clear();
    return false;
  }


  encrypted_master_data_ = crypto::SymmEncrypt(obfuscated_master_data_,
                                               secure_key_, secure_iv_);
  if (encrypted_master_data_.empty()) {
    Clear();
    return false;
  } else {
    return true;
  }
}

bool TmidPacket::ClarifyObfuscatedData() {
  boost::uint32_t numerical_pin(boost::lexical_cast<boost::uint32_t>(pin_));
  boost::uint32_t rounds(numerical_pin / 2 == 0 ?
                         numerical_pin * 3 / 2 : numerical_pin / 2);
  std::string obfuscation_str =
      crypto::SecurePassword(username_,
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

  plain_text_master_data_ = crypto::XOR(obfuscated_master_data_,
                                        obfuscation_str);
  return true;
}

std::string TmidPacket::DecryptPlainData(
    const std::string &password,
    const std::string &encrypted_master_data) {
  password_ = password;
  if (!SetPassword())
    return "";
  if (encrypted_master_data.empty()) {
#ifdef DEBUG
    printf("TmidPacket::DecryptPlainData: bad encrypted data.\n");
#endif
    password_.clear();
    salt_.clear();
    secure_key_.clear();
    secure_iv_.clear();
    return "";
  }

  encrypted_master_data_ = encrypted_master_data;
  obfuscated_master_data_ = crypto::SymmDecrypt(encrypted_master_data_,
                                                secure_key_, secure_iv_);
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

bool TmidPacket::Equals(const pki::Packet *other) const {
  const TmidPacket *rhs = static_cast<const TmidPacket*>(other);
  return packet_type_ == rhs->packet_type_ &&
         name_ == rhs->name_ &&
         username_ == rhs->username_ &&
         pin_ == rhs->pin_ &&
         password_ == rhs->password_ &&
         rid_ == rhs->rid_ &&
         plain_text_master_data_ == rhs->plain_text_master_data_ &&
         salt_ == rhs->salt_ &&
         secure_key_ == rhs->secure_key_ &&
         secure_iv_ == rhs->secure_iv_ &&
         encrypted_master_data_ == rhs->encrypted_master_data_;
}

}  // namespace passport

}  // namespace maidsafe
