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

#ifndef MAIDSAFE_PASSPORT_DETAIL_IDENTITY_DATA_H_
#define MAIDSAFE_PASSPORT_DETAIL_IDENTITY_DATA_H_

#include <cstdint>
#include <memory>
#include <string>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/types.h"

#include "maidsafe/passport/detail/config.h"


namespace maidsafe {

namespace passport {

namespace detail {

template<typename Tag>
struct MidData {
  typedef TaggedValue<Identity, Tag> name_type;
  typedef typename Signer<Tag>::type signer_type;
  static name_type Name(const NonEmptyString& keyword, uint32_t pin);
};

template<typename Tag>
struct TmidData {
  typedef TaggedValue<Identity, Tag> name_type;
  typedef typename Signer<Tag>::type signer_type;
};

NonEmptyString EncryptSession(const UserPassword& keyword,
                              uint32_t pin,
                              const UserPassword& password,
                              const NonEmptyString& serialised_session);

TmidData<TmidTag>::name_type TmidName(const NonEmptyString& encrypted_tmid);

// TMID name is now what used to be RID (Random ID)
NonEmptyString EncryptTmidName(const UserPassword& keyword,
                               uint32_t pin,
                               const TmidData<TmidTag>::name_type& tmid_name);

TmidData<TmidTag>::name_type DecryptTmidName(const UserPassword& keyword,
                                             uint32_t pin,
                                             const NonEmptyString& encrypted_tmid_name);

NonEmptyString DecryptSession(const UserPassword& keyword,
                              uint32_t pin,
                              const UserPassword password,
                              const NonEmptyString& encrypted_session);

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#include "maidsafe/passport/detail/identity_data-inl.h"

#endif  // MAIDSAFE_PASSPORT_DETAIL_IDENTITY_DATA_H_
