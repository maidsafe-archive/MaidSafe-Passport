/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#ifndef MAIDSAFE_PASSPORT_DETAIL_FOB_H_
#define MAIDSAFE_PASSPORT_DETAIL_FOB_H_

#include <type_traits>
#include <string>
#include <vector>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"

#include "maidsafe/passport/detail/config.h"

namespace maidsafe {

namespace passport {

namespace detail {

namespace protobuf { class Fob; }

Identity CreateFobName(const asymm::PublicKey& public_key,
                       const asymm::Signature& validation_token);

Identity CreateMpidName(const NonEmptyString& chosen_name);

void FobFromProtobuf(const protobuf::Fob& proto_fob, DataTagValue enum_value, asymm::Keys& keys,
                     asymm::Signature& validation_token, Identity& name);

void FobToProtobuf(DataTagValue enum_value, const asymm::Keys& keys,
                   const asymm::Signature& validation_token, const std::string& name,
                   protobuf::Fob* proto_fob);

template <typename TagType>
struct is_self_signed {
  typedef typename std::is_same<typename SignerFob<TagType>::Tag, TagType>::type type;
};



// ========== Self-signed Fob ======================================================================
template <typename TagType>
class Fob<TagType, typename std::enable_if<is_self_signed<TagType>::type::value>::type> {
 public:
  typedef maidsafe::detail::Name<Fob> Name;
  typedef Fob<typename SignerFob<TagType>::Tag> Signer;
  typedef TagType Tag;

  // This constructor is only available to this specialisation (i.e. self-signed fob).
  Fob() : keys_(asymm::GenerateKeyPair()),
      validation_token_(asymm::Sign(asymm::PlainText{ asymm::EncodeKey(keys_.public_key) },
                                    keys_.private_key)),
      name_(CreateFobName(keys_.public_key, validation_token_)) {
    static_assert(std::is_same<Fob<Tag>, Signer>::value,
                  "This constructor is only applicable for self-signing fobs.");
  }

  Fob(const Fob& other) : keys_(other.keys_), validation_token_(other.validation_token_),
      name_(other.name_) {}

  Fob(Fob&& other) : keys_(std::move(other.keys_)),
      validation_token_(std::move(other.validation_token_)), name_(std::move(other.name_)) {}

  friend void swap(Fob& lhs, Fob& rhs) {
    using std::swap;
    swap(lhs.keys_, rhs.keys_);
    swap(lhs.validation_token_, rhs.validation_token_);
    swap(lhs.name_, rhs.name_);
  }

  Fob& operator=(Fob other) {
    swap(*this, other);
    return *this;
  }

  explicit Fob(const protobuf::Fob& proto_fob) : keys_(), validation_token_(), name_() {
    Identity name;
    FobFromProtobuf(proto_fob, Tag::kValue, keys_, validation_token_, name);
    name_ = Name{ name };
  }

  void ToProtobuf(protobuf::Fob* proto_fob) const {
    FobToProtobuf(Tag::kValue, keys_, validation_token_, name_->string(), proto_fob);
  }

  Name name() const { return name_; }
  asymm::Signature validation_token() const { return validation_token_; }
  asymm::PrivateKey private_key() const { return keys_.private_key; }
  asymm::PublicKey public_key() const { return keys_.public_key; }

 private:
  asymm::Keys keys_;
  asymm::Signature validation_token_;
  Name name_;
};



// ========== Non-self-signed Fob ==================================================================
template <typename TagType>
class Fob<TagType, typename std::enable_if<!is_self_signed<TagType>::type::value>::type> {
 public:
  typedef maidsafe::detail::Name<Fob> Name;
  typedef Fob<typename SignerFob<TagType>::Tag> Signer;
  typedef TagType Tag;

  // This constructor is only available to this specialisation (i.e. non-self-signed fob)
  explicit Fob(const Signer& signing_fob,
               typename std::enable_if<!std::is_same<Fob<Tag>, Signer>::value>::type* = 0)
      : keys_(asymm::GenerateKeyPair()),
        validation_token_(asymm::Sign(asymm::PlainText{ asymm::EncodeKey(keys_.public_key) },
                                      signing_fob.private_key())),
        name_(CreateFobName(keys_.public_key, validation_token_)) {}

  Fob(const Fob& other) : keys_(other.keys_), validation_token_(other.validation_token_),
      name_(other.name_) {}

  Fob(Fob&& other) : keys_(std::move(other.keys_)),
      validation_token_(std::move(other.validation_token_)), name_(std::move(other.name_)) {}

  friend void swap(Fob& lhs, Fob& rhs) {
    using std::swap;
    swap(lhs.keys_, rhs.keys_);
    swap(lhs.validation_token_, rhs.validation_token_);
    swap(lhs.name_, rhs.name_);
  }

  Fob& operator=(Fob other) {
    swap(*this, other);
    return *this;
  }

  explicit Fob(const protobuf::Fob& proto_fob) : keys_(), validation_token_(), name_() {
    Identity name;
    FobFromProtobuf(proto_fob, Tag::kValue, keys_, validation_token_, name);
    name_ = Name{ name };
  }

  void ToProtobuf(protobuf::Fob* proto_fob) const {
    FobToProtobuf(Tag::kValue, keys_, validation_token_, name_->string(), proto_fob);
  }

  Name name() const { return name_; }
  asymm::Signature validation_token() const { return validation_token_; }
  asymm::PrivateKey private_key() const { return keys_.private_key; }
  asymm::PublicKey public_key() const { return keys_.public_key; }

 private:
  Fob() = delete;
  asymm::Keys keys_;
  asymm::Signature validation_token_;
  Name name_;
};



// ========== Public ID Fob ========================================================================
template <>
class Fob<MpidTag> {
 public:
  typedef maidsafe::detail::Name<Fob> Name;
  typedef Fob<typename SignerFob<MpidTag>::Tag> Signer;
  typedef MpidTag Tag;

  // This constructor is only available to this specialisation (i.e. Mpid)
  Fob(const NonEmptyString& chosen_name, const Signer& signing_fob);

  Fob(const Fob& other);
  Fob(Fob&& other);
  friend void swap(Fob& lhs, Fob& rhs) {
    using std::swap;
    swap(lhs.keys_, rhs.keys_);
    swap(lhs.validation_token_, rhs.validation_token_);
    swap(lhs.name_, rhs.name_);
  }
  Fob& operator=(Fob other);

  explicit Fob(const protobuf::Fob& proto_fob);
  void ToProtobuf(protobuf::Fob* proto_fob) const;

  Name name() const { return name_; }
  asymm::Signature validation_token() const { return validation_token_; }
  asymm::PrivateKey private_key() const { return keys_.private_key; }
  asymm::PublicKey public_key() const { return keys_.public_key; }

 private:
  Fob();
  asymm::Keys keys_;
  asymm::Signature validation_token_;
  Name name_;
};



// ========== General ==============================================================================
NonEmptyString SerialisePmid(const Fob<PmidTag>& pmid);
Fob<PmidTag> ParsePmid(const NonEmptyString& serialised_pmid);

#ifdef TESTING

std::vector<Fob<PmidTag>> ReadPmidList(const boost::filesystem::path& file_path);

bool WritePmidList(const boost::filesystem::path& file_path,
                   const std::vector<Fob<PmidTag>>& pmid_list);  // NOLINT (Fraser)

struct AnmaidToPmid {
  AnmaidToPmid(Fob<AnmaidTag> anmaid_in, Fob<MaidTag> maid_in, Fob<AnpmidTag> anpmid_in,
               Fob<PmidTag> pmid_in)
      : anmaid(std::move(anmaid_in)), maid(std::move(maid_in)),
        anpmid(std::move(anpmid_in)), pmid(std::move(pmid_in)), chain_size(4) {}
  AnmaidToPmid() : anmaid(), maid(anmaid), anpmid(), pmid(anpmid), chain_size(4) {}
  Fob<AnmaidTag> anmaid;
  Fob<MaidTag> maid;
  Fob<AnpmidTag> anpmid;
  Fob<PmidTag> pmid;
  int chain_size;
};

std::vector<AnmaidToPmid> ReadKeyChainList(const boost::filesystem::path& file_path);

bool WriteKeyChainList(const boost::filesystem::path& file_path,
                       const std::vector<AnmaidToPmid>& keychain_list);

#endif

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_FOB_H_
