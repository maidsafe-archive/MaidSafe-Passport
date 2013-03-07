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
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"

#include "maidsafe/passport/detail/config.h"


namespace maidsafe {

namespace passport {

typedef TaggedValue<NonEmptyString, struct EncryptedTmidNameTag> EncryptedTmidName;
typedef TaggedValue<NonEmptyString, struct EncryptedSessionTag> EncryptedSession;


namespace detail {

template<typename Tag>
class MidData {
 public:
  typedef TaggedValue<Identity, Tag> name_type;
  typedef typename Signer<Tag>::type signer_type;
  typedef TaggedValue<NonEmptyString, Tag> serialised_type;

  static name_type GenerateName(const NonEmptyString& keyword, uint32_t pin);

  MidData(const MidData& other);
  MidData& operator=(const MidData& other);
  MidData(MidData&& other);
  MidData& operator=(MidData&& other);

  MidData(const name_type& name,
          const EncryptedTmidName& encrypted_tmid_name,
          const signer_type& signing_fob);
  MidData(const name_type& name, const serialised_type& serialised_mid);
  serialised_type Serialise() const;

  name_type name() const { return name_; }
  EncryptedTmidName encrypted_tmid_name() const { return encrypted_tmid_name_; }
  asymm::Signature validation_token() const { return validation_token_; }
  static DataTagValue type_enum_value() { return Tag::kEnumValue; }

 private:
  MidData();
  name_type name_;
  EncryptedTmidName encrypted_tmid_name_;
  asymm::Signature validation_token_;
};


class TmidData {
 public:
  typedef TaggedValue<Identity, detail::TmidTag> name_type;
  typedef Signer<detail::TmidTag>::type signer_type;
  typedef TaggedValue<NonEmptyString, detail::TmidTag> serialised_type;

  TmidData(const TmidData& other);
  TmidData& operator=(const TmidData& other);
  TmidData(TmidData&& other);
  TmidData& operator=(TmidData&& other);

  TmidData(const EncryptedSession& encrypted_session, const signer_type& signing_fob);
  TmidData(const name_type& name, const serialised_type& serialised_tmid);
  serialised_type Serialise() const;

  name_type name() const { return name_; }
  EncryptedSession encrypted_session() const { return encrypted_session_; }
  asymm::Signature validation_token() const { return validation_token_; }
  static DataTagValue type_enum_value() { return detail::TmidTag::kEnumValue; }

 private:
  TmidData();
  name_type name_;
  EncryptedSession encrypted_session_;
  asymm::Signature validation_token_;
};


EncryptedSession EncryptSession(const UserKeyword& keyword,
                                uint32_t pin,
                                const UserPassword& password,
                                const NonEmptyString& serialised_session);

// TMID name is now what used to be RID (Random ID)
EncryptedTmidName EncryptTmidName(const UserKeyword& keyword,
                                  uint32_t pin,
                                  const TmidData::name_type& tmid_name);

TmidData::name_type DecryptTmidName(const UserKeyword& keyword,
                                    uint32_t pin,
                                    const EncryptedTmidName& encrypted_tmid_name);

NonEmptyString DecryptSession(const UserKeyword& keyword,
                              uint32_t pin,
                              const UserPassword& password,
                              const EncryptedSession& encrypted_session);

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#include "maidsafe/passport/detail/identity_data-inl.h"

#endif  // MAIDSAFE_PASSPORT_DETAIL_IDENTITY_DATA_H_
