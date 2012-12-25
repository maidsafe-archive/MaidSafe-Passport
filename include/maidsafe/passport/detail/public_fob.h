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

#ifndef MAIDSAFE_PASSPORT_DETAIL_PUBLIC_FOB_H_
#define MAIDSAFE_PASSPORT_DETAIL_PUBLIC_FOB_H_

#include <type_traits>

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"

#include "maidsafe/passport/detail/config.h"
#include "maidsafe/passport/detail/fob.h"


namespace maidsafe {

namespace passport {

namespace detail {

template<typename Tag>
class PublicFob {
 public:
  typedef TaggedValue<Identity, Tag> name_type;
  typedef typename Signer<Tag>::type signer_type;
  typedef TaggedValue<NonEmptyString, Tag> serialised_type;

  PublicFob(const PublicFob& other);
  PublicFob& operator=(const PublicFob& other);
  PublicFob(PublicFob&& other);
  PublicFob& operator=(PublicFob&& other);

  explicit PublicFob(const Fob<Tag>& fob);
  PublicFob(const name_type& name, const serialised_type& serialised_public_fob);
  serialised_type Serialise() const;

  name_type name() const { return name_; }
  asymm::PublicKey public_key() const { return public_key_; }
  asymm::Signature validation_token() const { return validation_token_; }

 private:
  PublicFob();
  name_type name_;
  asymm::PublicKey public_key_;
  asymm::Signature validation_token_;
};

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#include "maidsafe/passport/detail/public_fob-inl.h"

#endif  // MAIDSAFE_PASSPORT_DETAIL_PUBLIC_FOB_H_
