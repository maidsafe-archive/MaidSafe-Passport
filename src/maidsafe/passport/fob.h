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

#ifndef MAIDSAFE_PRIVATE_UTILS_FOB_H_
#define MAIDSAFE_PRIVATE_UTILS_FOB_H_

#include <type_traits>
#include <vector>

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"

#include "maidsafe/passport/passport_config.h"


namespace maidsafe {

namespace passport {

namespace detail {

template<typename KeyTag>
struct is_self_signed : std::true_type {};

template<>
struct is_self_signed<MaidTag> : std::false_type {};
template<>
struct is_self_signed<PmidTag> : std::false_type {};
template<>
struct is_self_signed<MidTag> : std::false_type {};
template<>
struct is_self_signed<SmidTag> : std::false_type {};
template<>
struct is_self_signed<TmidTag> : std::false_type {};
template<>
struct is_self_signed<StmidTag> : std::false_type {};
template<>
struct is_self_signed<MpidTag> : std::false_type {};
template<>
struct is_self_signed<MmidTag> : std::false_type {};


// This object is immutable by design, it does not allow any alteration after construction.
template<typename KeyTag>
class Fob {
 public:
  template<typename std::enable_if<is_self_signed<KeyTag>::value>::type = 0>
  Fob();
  Fob(Identity signed_by, asymm::PrivateKey private_key);
  Fob(Identity identity,
      asymm::PublicKey public_key,
      asymm::PrivateKey private_key,
      asymm::Signature validation_token);
  Fob(Identity identity,
      asymm::PublicKey public_key,
      asymm::PrivateKey private_key,
      asymm::Signature validation_token,
      Identity signed_by,
      asymm::PrivateKey signed_by_private_key);
  Identity identity() const;
  asymm::PublicKey public_key() const;
  asymm::PrivateKey private_key() const;
  asymm::Signature validation_token() const;
  Identity signed_by() const;

 private:
  asymm::Signature CreateValidation();
  asymm::Signature CreateChainedValidation(const asymm::PrivateKey& private_key);
  Identity CreateIdentity();
  void CreateKeys();

  Identity identity_;
  asymm::PublicKey public_key_;
  asymm::PrivateKey private_key_;
  asymm::Signature validation_token_;
  Identity signed_by_;
};

// Serialise the fob using protocol buffers
template<typename KeyTag>
NonEmptyString SerialiseFob(const Fob<KeyTag>& fob);

// Parse a serialised protocol buffer to a fob
template<typename KeyTag>
Fob<KeyTag> ParseFob(const NonEmptyString& serialised_fob);

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_UTILS_FOB_H_
