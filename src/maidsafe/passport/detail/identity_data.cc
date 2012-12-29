/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

#include "maidsafe/passport/detail/identity_data.h"

#include "maidsafe/common/utils.h"

#include "maidsafe/passport/detail/fob.h"
#include "maidsafe/passport/detail/passport_pb.h"


namespace maidsafe {

namespace passport {

namespace detail {

namespace {

crypto::AES256Key SecureKey(const crypto::SecurePassword& secure_password) {
  return crypto::AES256Key(secure_password.string().substr(0, crypto::AES256_KeySize));
}

crypto::AES256InitialisationVector SecureIv(const crypto::SecurePassword& secure_password) {
  return crypto::AES256InitialisationVector(
      secure_password.string().substr(crypto::AES256_KeySize, crypto::AES256_IVSize));
}

crypto::SecurePassword CreateSecureMidPassword(const UserPassword& keyword, uint32_t pin) {
  crypto::Salt salt(crypto::Hash<crypto::SHA512>(std::to_string(pin) + keyword.string()));
  return crypto::CreateSecurePassword(keyword, salt, pin);
}

crypto::SecurePassword CreateSecureTmidPassword(const UserPassword& password,
                                                uint32_t pin,
                                                const crypto::SHA512Hash& pin_hash) {
  crypto::Salt salt(crypto::Hash<crypto::SHA512>(pin_hash.string() + password.string()));
  return crypto::CreateSecurePassword(password, salt, pin);
}

NonEmptyString XorData(const UserPassword& keyword,
                       uint32_t pin,
                       const UserPassword& password,
                       const crypto::SHA512Hash& pin_hash,
                       const NonEmptyString& data) {
  uint32_t rounds(pin / 2 == 0 ? (pin * 3) / 2 : pin / 2);
  std::string obfuscation_str =
      crypto::CreateSecurePassword(keyword,
                                   crypto::Salt(crypto::Hash<crypto::SHA512>(password + pin_hash)),
                                   rounds).string();
  // make the obfuscation_str of same size for XOR
  if (data.string().size() < obfuscation_str.size()) {
    obfuscation_str.resize(data.string().size());
  } else if (data.string().size() > obfuscation_str.size()) {
    obfuscation_str.reserve(data.string().size());
    while (data.string().size() > obfuscation_str.size())
      obfuscation_str += obfuscation_str;
    obfuscation_str.resize(data.string().size());
  }
  return NonEmptyString(crypto::XOR(data.string(), obfuscation_str));
}

}  // unnamed namespace


void MidFromProtobuf(const NonEmptyString& serialised_mid,
                     int enum_value,
                     EncryptedTmidName& encrypted_tmid_name,
                     asymm::Signature& validation_token) {
  protobuf::Mid proto_mid;
  if (!proto_mid.ParseFromString(serialised_mid.string()))
    ThrowError(PassportErrors::mid_parsing_error);
  validation_token = asymm::Signature(proto_mid.validation_token());
  encrypted_tmid_name = EncryptedTmidName(NonEmptyString(proto_mid.encrypted_tmid_name()));
  if (enum_value != proto_mid.type())
    ThrowError(PassportErrors::mid_parsing_error);
}

NonEmptyString MidToProtobuf(int enum_value,
                             const EncryptedTmidName& encrypted_tmid_name,
                             const asymm::Signature& validation_token) {
  protobuf::Mid proto_mid;
  proto_mid.set_type(enum_value);
  proto_mid.set_encrypted_tmid_name(encrypted_tmid_name.data.string());
  proto_mid.set_validation_token(validation_token.string());
  return NonEmptyString(proto_mid.SerializeAsString());
}


template<>
crypto::SHA512Hash GenerateMidName<MidData<MidTag>>(const crypto::SHA512Hash& keyword_hash,  // NOLINT (Fraser)
                                                    const crypto::SHA512Hash& pin_hash) {
  return crypto::Hash<crypto::SHA512>(keyword_hash.string() + pin_hash.string());
}

template<>
crypto::SHA512Hash GenerateMidName<MidData<SmidTag>>(const crypto::SHA512Hash& keyword_hash,  // NOLINT (Fraser)
                                                     const crypto::SHA512Hash& pin_hash) {
  return crypto::Hash<crypto::SHA512>(crypto::Hash<crypto::SHA512>(keyword_hash.string() +
                                                                   pin_hash.string()));
}

crypto::SHA512Hash HashOfPin(uint32_t pin) {
  return crypto::Hash<crypto::SHA512>(std::to_string(pin));
}



TmidData::TmidData(const TmidData& other)
    : name_(other.name_),
      encrypted_session_(other.encrypted_session_),
      validation_token_(other.validation_token_) {}

TmidData& TmidData::operator=(const TmidData& other) {
  name_ = other.name_;
  encrypted_session_ = other.encrypted_session_;
  validation_token_ = other.validation_token_;
  return *this;
}

TmidData::TmidData(TmidData&& other)
    : name_(std::move(other.name_)),
      encrypted_session_(std::move(other.encrypted_session_)),
      validation_token_(std::move(other.validation_token_)) {}

TmidData& TmidData::operator=(TmidData&& other) {
  name_ = std::move(other.name_);
  encrypted_session_ = std::move(other.encrypted_session_);
  validation_token_ = std::move(other.validation_token_);
  return *this;
}

TmidData::TmidData(const EncryptedSession& encrypted_session, const signer_type& signing_fob)
    : name_(crypto::Hash<crypto::SHA512>(encrypted_session.data)),
      encrypted_session_(encrypted_session),
      validation_token_(asymm::Sign(encrypted_session.data, signing_fob.private_key())) {}

TmidData::TmidData(const name_type& name, const serialised_type& serialised_tmid)
    : name_(name),
      encrypted_session_(),
      validation_token_() {
  protobuf::Tmid proto_tmid;
  if (!proto_tmid.ParseFromString(serialised_tmid.data.string()))
    ThrowError(PassportErrors::tmid_parsing_error);
  validation_token_ = asymm::Signature(proto_tmid.validation_token());
  encrypted_session_ = EncryptedSession(NonEmptyString(proto_tmid.encrypted_session()));
  if (detail::TmidTag::kEnumValue != maidsafe::detail::DataTagValue(proto_tmid.type()))
    ThrowError(PassportErrors::tmid_parsing_error);
}

TmidData::serialised_type TmidData::Serialise() const {
  protobuf::Tmid proto_tmid;
  proto_tmid.set_type(static_cast<int>(detail::TmidTag::kEnumValue));
  proto_tmid.set_encrypted_session(encrypted_session_.data.string());
  proto_tmid.set_validation_token(validation_token_.string());
  return serialised_type(NonEmptyString(proto_tmid.SerializeAsString()));
}


EncryptedSession EncryptSession(const UserPassword& keyword,
                                uint32_t pin,
                                const UserPassword& password,
                                const NonEmptyString& serialised_session) {
  auto pin_hash(HashOfPin(pin));
  crypto::SecurePassword secure_password(CreateSecureTmidPassword(password, pin, pin_hash));
  return EncryptedSession(
      crypto::SymmEncrypt(XorData(keyword, pin, password, pin_hash, serialised_session),
                          SecureKey(secure_password),
                          SecureIv(secure_password)));
}

EncryptedTmidName EncryptTmidName(const UserPassword& keyword,
                                  uint32_t pin,
                                  const TmidData::name_type& tmid_name) {
  crypto::SecurePassword secure_password(CreateSecureMidPassword(keyword, pin));
  return EncryptedTmidName(crypto::SymmEncrypt(crypto::PlainText(tmid_name.data),
                                               SecureKey(secure_password),
                                               SecureIv(secure_password)));
}

TmidData::name_type DecryptTmidName(const UserPassword& keyword,
                                    uint32_t pin,
                                    const EncryptedTmidName& encrypted_tmid_name) {
  crypto::SecurePassword secure_password(CreateSecureMidPassword(keyword, pin));
  return TmidData::name_type(Identity(crypto::SymmDecrypt(encrypted_tmid_name.data,
                                                          SecureKey(secure_password),
                                                          SecureIv(secure_password)).string()));
}

NonEmptyString DecryptSession(const UserPassword& keyword,
                              uint32_t pin,
                              const UserPassword& password,
                              const EncryptedSession& encrypted_session) {
  auto pin_hash(HashOfPin(pin));
  crypto::SecurePassword secure_password(CreateSecureTmidPassword(password, pin, pin_hash));
  return XorData(keyword, pin, password, pin_hash,
                 crypto::SymmDecrypt(encrypted_session.data,
                                     SecureKey(secure_password),
                                     SecureIv(secure_password)));
}


#ifdef TESTING

template<>
std::string DebugString<MidData<MidTag>::name_type>(const MidData<MidTag>::name_type& name) {
  return "Mid     " + HexSubstr(name.data);
}

template<>
std::string DebugString<MidData<SmidTag>::name_type>(const MidData<SmidTag>::name_type& name) {
  return "Smid    " + HexSubstr(name.data);
}

template<>
std::string DebugString<TmidData::name_type>(const TmidData::name_type& name) {
  return "Tmid    " + HexSubstr(name.data);
}

#endif  // TESTING


}  // namespace detail

}  // namespace passport

}  // namespace maidsafe
