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

#include <type_traits>

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"

#include "maidsafe/passport/detail/config.h"


namespace maidsafe {

namespace passport {

namespace detail {

class PassportImpl;

namespace protobuf { class Fob; }

template<typename FobType>
struct is_self_signed : public std::false_type {};

template<>
struct is_self_signed<AnmidTag> : public std::true_type {};
template<>
struct is_self_signed<AnsmidTag> : public std::true_type {};
template<>
struct is_self_signed<AntmidTag> : public std::true_type {};
template<>
struct is_self_signed<AnmaidTag> : public std::true_type {};
template<>
struct is_self_signed<AnmpidTag> : public std::true_type {};


template<typename Tag, typename Enable>
class Fob {
 public:
  typedef TaggedValue<Identity, Tag> name_type;
  typedef typename Signer<Tag>::type signer_type;
  Fob(const Fob& other);
  Fob& operator=(const Fob& other);
  Fob(Fob&& other);
  Fob& operator=(Fob&& other);
  explicit Fob(const protobuf::Fob& proto_fob);
  void ToProtobuf(protobuf::Fob* proto_fob) const;
  name_type name() const;
  asymm::Signature validation_token() const;
  asymm::PrivateKey private_key() const;
  asymm::PublicKey public_key() const;

 private:
  asymm::Keys keys_;
  asymm::Signature validation_token_;
  name_type name_;
};

template<typename Tag>
class Fob<Tag, typename std::enable_if<is_self_signed<Tag>::value>::type> {
 public:
  typedef TaggedValue<Identity, Tag> name_type;
  typedef typename Signer<Tag>::type signer_type;
  // This constructor is only available to this specialisation (i.e. self-signed fob)
  Fob();
  Fob(const Fob& other);
  Fob& operator=(const Fob& other);
  Fob(Fob&& other);
  Fob& operator=(Fob&& other);
  explicit Fob(const protobuf::Fob& proto_fob);
  void ToProtobuf(protobuf::Fob* proto_fob) const;
  name_type name() const { return name_; }
  asymm::Signature validation_token() const { return validation_token_; }
  asymm::PrivateKey private_key() const { return keys_.private_key; }
  asymm::PublicKey public_key() const { return keys_.public_key; }

 private:
  asymm::Keys keys_;
  asymm::Signature validation_token_;
  name_type name_;
};

template<typename Tag>
class Fob<Tag, typename std::enable_if<!is_self_signed<Tag>::value>::type> {
 public:
  typedef TaggedValue<Identity, Tag> name_type;
  typedef typename Signer<Tag>::type signer_type;
  Fob(const Fob& other);
  // This constructor is only available to this specialisation (i.e. non-self-signed fob)
  explicit Fob(const signer_type& signing_fob,
               typename std::enable_if<!std::is_same<Fob<Tag>,
                                                     signer_type>::value>::type* = 0);
  Fob& operator=(const Fob& other);
  Fob(Fob&& other);
  Fob& operator=(Fob&& other);
  explicit Fob(const protobuf::Fob& proto_fob);
  void ToProtobuf(protobuf::Fob* proto_fob) const;
  name_type name() const { return name_; }
  asymm::Signature validation_token() const { return validation_token_; }
  asymm::PrivateKey private_key() const { return keys_.private_key; }
  asymm::PublicKey public_key() const { return keys_.public_key; }

 private:
  Fob();
  asymm::Keys keys_;
  asymm::Signature validation_token_;
  name_type name_;
};

NonEmptyString SerialisePmid(const Fob<PmidTag>& pmid);

Fob<PmidTag> ParsePmid(const NonEmptyString& serialised_pmid);

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#include "maidsafe/passport/detail/fob-inl.h"

#endif  // MAIDSAFE_PASSPORT_DETAIL_FOB_H_
