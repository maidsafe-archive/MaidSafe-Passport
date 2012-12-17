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

#ifndef MAIDSAFE_PASSPORT_DETAIL_IDENTITY_DATA_INL_H_
#define MAIDSAFE_PASSPORT_DETAIL_IDENTITY_DATA_INL_H_

#include <cstdio>
#include <string>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/rsa.h"


namespace maidsafe {

namespace passport {

namespace detail {

template<typename MidType>
crypto::SHA512Hash GenerateMidName(const crypto::SHA512Hash& keyword_hash,
                                   const crypto::SHA512Hash& pin_hash);

crypto::SHA512Hash HashOfPin(uint32_t pin);

template<typename Tag>
typename MidData<Tag>::name_type MidData<Tag>::Name(const NonEmptyString& keyword, uint32_t pin) {
  return MidData<Tag>::name_type(GenerateMidName<MidData<Tag>>(  // NOLINT (Fraser)
      crypto::Hash<crypto::SHA512>(keyword),
      HashOfPin(pin)));
}

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_IDENTITY_DATA_INL_H_
