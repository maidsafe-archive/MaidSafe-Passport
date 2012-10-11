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

namespace {

crypto::AES256Key SecureKey(crypto::SecurePassword secure_password) {
  return crypto::AES256Key(secure_password.string().substr(0, crypto::AES256_KeySize));
}

crypto::AES256InitialisationVector SecureIv(crypto::SecurePassword secure_password) {
  return crypto::AES256InitialisationVector(
      secure_password.string().substr(crypto::AES256_KeySize, crypto::AES256_IVSize));
}

crypto::SecurePassword CreateSecureMidPassword(UserPassword keyword, uint32_t pin) {
  crypto::Salt salt(crypto::Salt(crypto::Hash<crypto::SHA512>(
                                     boost::lexical_cast<std::string>(pin) +
                                     keyword.string())));
  return crypto::CreateSecurePassword(keyword, salt, pin);
}

crypto::SecurePassword CreateSecureTmidPassword(UserPassword password, crypto::PlainText rid) {
  uint32_t random_no_from_rid(0);
  int64_t a(1);
  for (int i = 0; i < 4; ++i) {
    uint8_t temp(static_cast<uint8_t>(rid.string().at(i)));
    random_no_from_rid += static_cast<uint32_t>(temp * a);
    a *= 256;
  }
  return crypto::CreateSecurePassword(password,
                                      crypto::Salt(crypto::Hash<crypto::SHA512>(rid + password)),
                                      random_no_from_rid);
}

NonEmptyString XorData(UserPassword keyword,
                       uint32_t pin,
                       UserPassword password,
                       crypto::PlainText rid,
                       NonEmptyString data) {
  uint32_t rounds(pin / 2 == 0 ? pin * 3 / 2 : pin / 2);
  std::string obfuscation_str =
      crypto::CreateSecurePassword(keyword,
                                   crypto::Salt(crypto::Hash<crypto::SHA512>(password + rid)),
                                   rounds).string();
  // make the obfuscation_str of same size for XOR
  if (data.string().size() < obfuscation_str.size()) {
    obfuscation_str.resize(data.string().size());
  } else if (data.string().size() > obfuscation_str.size()) {
    while (data.string().size() > obfuscation_str.size())
      obfuscation_str += obfuscation_str;
    obfuscation_str.resize(data.string().size());
  }
  return NonEmptyString(crypto::XOR(data.string(), obfuscation_str));
}

}  // unnamed namespace


Identity MidName(NonEmptyString keyword, uint32_t pin, bool surrogate) {
  NonEmptyString keyword_hash(crypto::Hash<crypto::SHA512>(keyword));
  NonEmptyString pin_hash(crypto::Hash<crypto::SHA512>(boost::lexical_cast<std::string>(pin)));
  return surrogate ? crypto::Hash<crypto::SHA512>(crypto::Hash<crypto::SHA512>(keyword_hash +
                                                                               pin_hash)) :
                     crypto::Hash<crypto::SHA512>(keyword_hash + pin_hash);
}

crypto::PlainText DecryptRid(UserPassword keyword,
                             uint32_t pin,
                             crypto::CipherText encrypted_tmid_name) {
  crypto::SecurePassword secure_password(CreateSecureMidPassword(keyword, pin));
  return crypto::SymmDecrypt(encrypted_tmid_name,
                             SecureKey(secure_password),
                             SecureIv(secure_password));
}

crypto::CipherText EncryptRid(UserPassword keyword, uint32_t pin, Identity tmid_name) {
  crypto::SecurePassword secure_password(CreateSecureMidPassword(keyword, pin));
  return crypto::SymmEncrypt(crypto::PlainText(tmid_name),
                             SecureKey(secure_password),
                             SecureIv(secure_password));
}


Identity TmidName(const crypto::CipherText& encrypted_tmid) {
  return crypto::Hash<crypto::SHA512>(encrypted_tmid);
}

crypto::CipherText EncryptSession(UserPassword keyword,
                                  uint32_t pin,
                                  UserPassword password,
                                  crypto::PlainText rid,
                                  const NonEmptyString& serialised_session) {
  crypto::SecurePassword secure_password(CreateSecureTmidPassword(password, rid));
  return crypto::SymmEncrypt(crypto::PlainText(XorData(keyword,
                                                       pin,
                                                       password,
                                                       rid,
                                                       serialised_session)),
                             SecureKey(secure_password),
                             SecureIv(secure_password));
}

NonEmptyString DecryptSession(UserPassword keyword,
                              uint32_t pin,
                              UserPassword password,
                              crypto::PlainText rid,
                              const crypto::CipherText& encrypted_session) {
  crypto::SecurePassword secure_password(CreateSecureTmidPassword(password, rid));
  return XorData(keyword, pin, password, rid, crypto::SymmDecrypt(encrypted_session,
                                                                  SecureKey(secure_password),
                                                                  SecureIv(secure_password)));
}

}  // namespace passport

}  // namespace maidsafe
