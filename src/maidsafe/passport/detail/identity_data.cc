/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#include "maidsafe/passport/detail/identity_data.h"

#include <limits>

#include "maidsafe/common/utils.h"

#include "maidsafe/passport/detail/fob.h"
#include "maidsafe/passport/detail/passport.pb.h"

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

crypto::SecurePassword CreateSecureMidPassword(const Keyword& keyword, const Pin& pin) {
  crypto::Salt salt(crypto::Hash<crypto::SHA512>(pin.string() + keyword.string()));
  assert(pin.Value() <= std::numeric_limits<uint32_t>::max());
  return crypto::CreateSecurePassword<Keyword>(keyword, salt, static_cast<uint32_t>(pin.Value()));
}

crypto::SecurePassword CreateSecureTmidPassword(const Password& password, const Pin& pin) {
  crypto::Salt salt(crypto::Hash<crypto::SHA512>(pin.Hash<crypto::SHA512>() + password.string()));
  assert(pin.Value() <= std::numeric_limits<uint32_t>::max());
  return crypto::CreateSecurePassword<Password>(password, salt, static_cast<uint32_t>(pin.Value()));
}

NonEmptyString XorData(const Keyword& keyword,
                       const Pin& pin,
                       const Password& password,
                       const NonEmptyString& data) {
  assert(pin.Value() <= std::numeric_limits<uint32_t>::max());
  uint32_t pin_value(static_cast<uint32_t>(pin.Value()));
  uint32_t rounds(pin_value / 2 == 0 ? (pin_value * 3) / 2 : pin_value / 2);
  std::string obfuscation_str =
      crypto::CreateSecurePassword<Keyword>(keyword,
                                   crypto::Salt(crypto::Hash<crypto::SHA512>(
                                                  password.string() + pin.Hash<crypto::SHA512>())),
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
                     DataTagValue enum_value,
                     EncryptedTmidName& encrypted_tmid_name,
                     asymm::Signature& validation_token) {
  protobuf::Mid proto_mid;
  if (!proto_mid.ParseFromString(serialised_mid.string()))
    ThrowError(PassportErrors::mid_parsing_error);
  validation_token = asymm::Signature(proto_mid.validation_token());
  encrypted_tmid_name = EncryptedTmidName(NonEmptyString(proto_mid.encrypted_tmid_name()));
  if (static_cast<uint32_t>(enum_value) != proto_mid.type())
    ThrowError(PassportErrors::mid_parsing_error);
}

NonEmptyString MidToProtobuf(DataTagValue enum_value,
                             const EncryptedTmidName& encrypted_tmid_name,
                             const asymm::Signature& validation_token) {
  protobuf::Mid proto_mid;
  proto_mid.set_type(static_cast<uint32_t>(enum_value));
  proto_mid.set_encrypted_tmid_name(encrypted_tmid_name->string());
  proto_mid.set_validation_token(validation_token.string());
  return NonEmptyString(proto_mid.SerializeAsString());
}


template<>
SecureString::Hash GenerateMidName<MidData<MidTag>>(const Keyword& keyword,  // NOLINT (Fraser)
                                                    const Pin& pin) {
  return crypto::Hash<crypto::SHA512>(keyword.Hash<crypto::SHA512>().string() +
                                      pin.Hash<crypto::SHA512>().string());
}

template<>
SecureString::Hash GenerateMidName<MidData<SmidTag>>(const Keyword& keyword,  // NOLINT (Fraser)
                                                     const Pin& pin) {
  SecureString::Hash secure_string_hash(
      crypto::Hash<crypto::SHA512>(keyword.Hash<crypto::SHA512>().string() +
                                   pin.Hash<crypto::SHA512>().string()));
  return crypto::Hash<crypto::SHA512>(secure_string_hash.string());
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

TmidData::TmidData(const Name& name, const serialised_type& serialised_tmid)
    : name_(name),
      encrypted_session_(),
      validation_token_() {
  protobuf::Tmid proto_tmid;
  if (!proto_tmid.ParseFromString(serialised_tmid->string()))
    ThrowError(PassportErrors::tmid_parsing_error);
  validation_token_ = asymm::Signature(proto_tmid.validation_token());
  encrypted_session_ = EncryptedSession(NonEmptyString(proto_tmid.encrypted_session()));
  if (static_cast<uint32_t>(detail::TmidTag::kValue) != proto_tmid.type())
    ThrowError(PassportErrors::tmid_parsing_error);
}

TmidData::serialised_type TmidData::Serialise() const {
  protobuf::Tmid proto_tmid;
  proto_tmid.set_type(static_cast<uint32_t>(detail::TmidTag::kValue));
  proto_tmid.set_encrypted_session(encrypted_session_->string());
  proto_tmid.set_validation_token(validation_token_.string());
  return serialised_type(NonEmptyString(proto_tmid.SerializeAsString()));
}


EncryptedSession EncryptSession(const Keyword& keyword,
                                const Pin& pin,
                                const Password& password,
                                const NonEmptyString& serialised_session) {
  crypto::SecurePassword secure_password(CreateSecureTmidPassword(password, pin));
  return EncryptedSession(
      crypto::SymmEncrypt(XorData(keyword, pin, password, serialised_session),
                          SecureKey(secure_password),
                          SecureIv(secure_password)));
}

NonEmptyString DecryptSession(const Keyword& keyword,
                              const Pin& pin,
                              const Password& password,
                              const EncryptedSession& encrypted_session) {
  crypto::SecurePassword secure_password(CreateSecureTmidPassword(password, pin));
  return XorData(keyword, pin, password,
                 crypto::SymmDecrypt(encrypted_session.data,
                                     SecureKey(secure_password),
                                     SecureIv(secure_password)));
}

EncryptedTmidName EncryptTmidName(const Keyword& keyword,
                                  const Pin& pin,
                                  const TmidData::Name& tmid_name) {
  crypto::SecurePassword secure_password(CreateSecureMidPassword(keyword, pin));
  return EncryptedTmidName(crypto::SymmEncrypt(crypto::PlainText(tmid_name.value),
                                               SecureKey(secure_password),
                                               SecureIv(secure_password)));
}

TmidData::Name DecryptTmidName(const Keyword& keyword,
                               const Pin& pin,
                               const EncryptedTmidName& encrypted_tmid_name) {
  crypto::SecurePassword secure_password(CreateSecureMidPassword(keyword, pin));
  return TmidData::Name(Identity(crypto::SymmDecrypt(encrypted_tmid_name.data,
                                                     SecureKey(secure_password),
                                                     SecureIv(secure_password)).string()));
}

#ifdef TESTING

template<>
std::string DebugString<MidData<MidTag>::Name>(const MidData<MidTag>::Name& name) {
  return "Mid     " + HexSubstr(name.value);
}

template<>
std::string DebugString<MidData<SmidTag>::Name>(const MidData<SmidTag>::Name& name) {
  return "Smid    " + HexSubstr(name.value);
}

template<>
std::string DebugString<TmidData::Name>(const TmidData::Name& name) {
  return "Tmid    " + HexSubstr(name.value);
}

#endif  // TESTING


}  // namespace detail
}  // namespace passport
}  // namespace maidsafe
