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

#include "maidsafe/passport/detail/config.h"


namespace maidsafe {

namespace passport {

namespace detail {

template<typename Tag>
struct NameAndValue {
  typedef TaggedValue<Identity, Tag> name_type;
  typedef typename Signer<typename Tag>::type signer_type;
  NameAndValue() : name(), value() {}
  name_type name;
  NonEmptyString value;
};


Mid::name_type MidName(NonEmptyString keyword, uint32_t pin, bool surrogate);

Identity DecryptRid(UserPassword keyword, uint32_t pin, crypto::CipherText encrypted_tmid_name);

crypto::CipherText EncryptRid(UserPassword keyword, uint32_t pin, Identity tmid_name);


Identity TmidName(const crypto::CipherText& encrypted_tmid);

crypto::CipherText EncryptSession(UserPassword keyword,
                                  uint32_t pin,
                                  UserPassword password,
                                  crypto::PlainText salt,
                                  const NonEmptyString& serialised_session);

NonEmptyString DecryptSession(UserPassword keyword,
                              uint32_t pin,
                              UserPassword password,
                              crypto::PlainText salt,
                              const crypto::CipherText& encrypted_session);

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_IDENTITY_PACKETS_H_
