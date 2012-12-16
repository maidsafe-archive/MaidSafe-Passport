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


template<>
crypto::SHA512Hash GenerateMidName<MidData<MidTag>>(const crypto::SHA512Hash& keyword_hash,
                                                    const crypto::SHA512Hash& pin_hash) {
  return crypto::Hash<crypto::SHA512>(keyword_hash + pin_hash);
}

template<>
crypto::SHA512Hash GenerateMidName<MidData<SmidTag>>(const crypto::SHA512Hash& keyword_hash,
                                                     const crypto::SHA512Hash& pin_hash) {
  return crypto::Hash<crypto::SHA512>(crypto::Hash<crypto::SHA512>(keyword_hash + pin_hash));
}

crypto::SHA512Hash HashOfPin(uint32_t pin) {
  return crypto::Hash<crypto::SHA512>(std::to_string(pin));
}

TmidData<TmidTag>::name_type DecryptTmidName(const UserPassword& keyword,
                                             uint32_t pin,
                                             const crypto::CipherText& encrypted_tmid_name) {
  crypto::SecurePassword secure_password(CreateSecureMidPassword(keyword, pin));
  return TmidData<TmidTag>::name_type(
      Identity(crypto::SymmDecrypt(encrypted_tmid_name,
                                   SecureKey(secure_password),
                                   SecureIv(secure_password)).string()));
}

crypto::CipherText EncryptTmidName(const UserPassword& keyword,
                                   uint32_t pin,
                                   const TmidData<TmidTag>::name_type& tmid_name) {
  crypto::SecurePassword secure_password(CreateSecureMidPassword(keyword, pin));
  return crypto::SymmEncrypt(crypto::PlainText(tmid_name.data),
                             SecureKey(secure_password),
                             SecureIv(secure_password));
}

crypto::CipherText EncryptSession(UserPassword keyword,
                                  uint32_t pin,
                                  UserPassword password,
                                  const NonEmptyString& serialised_session) {
  auto pin_hash(HashOfPin(pin));
  crypto::SecurePassword secure_password(CreateSecureTmidPassword(password, pin, pin_hash));
  return crypto::SymmEncrypt(XorData(keyword, pin, password, pin_hash, serialised_session),
                             SecureKey(secure_password),
                             SecureIv(secure_password));
}

NonEmptyString DecryptSession(const UserPassword& keyword,
                              uint32_t pin,
                              const UserPassword password,
                              const crypto::CipherText& encrypted_session) {
  auto pin_hash(HashOfPin(pin));
  crypto::SecurePassword secure_password(CreateSecureTmidPassword(password, pin, pin_hash));
  return XorData(keyword, pin, password, pin_hash,
                 crypto::SymmDecrypt(encrypted_session,
                                     SecureKey(secure_password),
                                     SecureIv(secure_password)));
}

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe
