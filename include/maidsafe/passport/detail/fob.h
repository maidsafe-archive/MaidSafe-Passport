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

#ifndef MAIDSAFE_PASSPORT_DETAIL_FOB_H_
#define MAIDSAFE_PASSPORT_DETAIL_FOB_H_

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"

#include "maidsafe/passport/detail/config.h"
#include "maidsafe/passport/detail/passport_pb.h"


namespace maidsafe {

namespace passport {

namespace detail {

class PassportImpl;

template<typename Tag>
class Fob {
 public:
  typedef TaggedValue<Identity, Tag> name_type;
  typedef typename Signer<Tag>::type signer_type;
  typedef typename std::is_same<Fob<Tag>,
                                typename Signer<Tag>::type> is_self_signed;
  // This constructor is only available for self-signing Fobs.
  Fob();
  // This constructor is only available for non-self-signing Fobs.
  Fob(const signer_type& signing_fob);
  // This constructor is used for parsing a Fob which was serialised to the Passport protobuf.
  Fob(const protobuf::Fob& proto_fob);
  NonEmptyString Serialise() const;
  name_type name() const;
  asymm::Signature validation_token() const;
  asymm::PrivateKey private_key() const;
  asymm::PublicKey public_key() const;

 private:
  name_type CreateName();
  asymm::Keys keys_;
  asymm::Signature validation_token_;
  name_type name_;
};

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#include "maidsafe/passport/detail/fob-inl.h"

#endif  // MAIDSAFE_PASSPORT_DETAIL_FOB_H_
