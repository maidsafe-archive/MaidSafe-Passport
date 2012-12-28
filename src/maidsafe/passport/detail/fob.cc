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

#include "maidsafe/passport/detail/fob.h"

#include "maidsafe/common/utils.h"

#include "maidsafe/passport/detail/passport_pb.h"


namespace maidsafe {

namespace passport {

namespace detail {

Identity CreateFobName(const asymm::PublicKey& public_key,
                       const asymm::Signature& validation_token) {
  return Identity(crypto::Hash<crypto::SHA512>(asymm::EncodeKey(public_key) + validation_token));
}

Identity CreateMpidName(const NonEmptyString& chosen_name) {
  return Identity(crypto::Hash<crypto::SHA512>(chosen_name));
}


Fob<MpidTag>::Fob(const Fob<MpidTag>& other)
    : keys_(other.keys_),
      validation_token_(other.validation_token_),
      name_(other.name_) {}

Fob<MpidTag>::Fob(const NonEmptyString& chosen_name, const signer_type& signing_fob)
    : keys_(asymm::GenerateKeyPair()),
      validation_token_(asymm::Sign(asymm::PlainText(asymm::EncodeKey(keys_.public_key)),
                                    signing_fob.private_key())),
      name_(CreateMpidName(chosen_name)) {}

Fob<MpidTag>& Fob<MpidTag>::operator=(const Fob<MpidTag>& other) {
  keys_ = other.keys_;
  validation_token_ = other.validation_token_;
  name_ = other.name_;
  return *this;
}

Fob<MpidTag>::Fob(Fob<MpidTag>&& other)
    : keys_(std::move(other.keys_)),
      validation_token_(std::move(other.validation_token_)),
      name_(std::move(other.name_)) {}

Fob<MpidTag>& Fob<MpidTag>::operator=(Fob<MpidTag>&& other) {
  keys_ = std::move(other.keys_);
  validation_token_ = std::move(other.validation_token_);
  name_ = std::move(other.name_);
  return *this;
}

Fob<MpidTag>::Fob(const protobuf::Fob& proto_fob) : keys_(), validation_token_(), name_() {
  Identity name;
  FobFromProtobuf(proto_fob, MpidTag::kEnumValue, keys_, validation_token_, name);
  name_ = name_type(name);
}

void Fob<MpidTag>::ToProtobuf(protobuf::Fob* proto_fob) const {
  FobToProtobuf(MpidTag::kEnumValue, keys_, validation_token_, name_.data.string(), proto_fob);
}


void FobFromProtobuf(const protobuf::Fob& proto_fob,
                     int enum_value,
                     asymm::Keys& keys,
                     asymm::Signature& validation_token,
                     Identity& name) {
  if (!proto_fob.IsInitialized())
    ThrowError(PassportErrors::fob_parsing_error);

  validation_token = asymm::Signature(proto_fob.validation_token());
  name = Identity(proto_fob.name());

  asymm::PlainText plain(RandomString(64));
  keys.private_key = asymm::DecodeKey(asymm::EncodedPrivateKey(proto_fob.encoded_private_key()));
  keys.public_key = asymm::DecodeKey(asymm::EncodedPublicKey(proto_fob.encoded_public_key()));
  if ((enum_value != MpidTag::kEnumValue &&
       CreateFobName(keys.public_key, validation_token) != name) ||
      asymm::Decrypt(asymm::Encrypt(plain, keys.public_key), keys.private_key) != plain ||
      enum_value != proto_fob.type()) {
    ThrowError(PassportErrors::fob_parsing_error);
  }
}

void FobToProtobuf(int enum_value,
                   const asymm::Keys& keys,
                   const asymm::Signature& validation_token,
                   const std::string& name,
                   protobuf::Fob* proto_fob) {
  proto_fob->set_type(enum_value);
  proto_fob->set_name(name);
  proto_fob->set_encoded_private_key(asymm::EncodeKey(keys.private_key).string());
  proto_fob->set_encoded_public_key(asymm::EncodeKey(keys.public_key).string());
  proto_fob->set_validation_token(validation_token.string());
}

NonEmptyString SerialisePmid(const Fob<PmidTag>& pmid) {
  protobuf::Fob proto_fob;
  pmid.ToProtobuf(&proto_fob);
  return NonEmptyString(proto_fob.SerializeAsString());
}

Fob<PmidTag> ParsePmid(const NonEmptyString& serialised_pmid) {
  protobuf::Fob proto_fob;
  proto_fob.ParseFromString(serialised_pmid.string());
  return Fob<PmidTag>(proto_fob);
}

#ifdef TESTING

std::vector<Fob<PmidTag>> ReadPmidList(const boost::filesystem::path& file_path) {
  std::vector<Fob<PmidTag>> pmid_list;
  protobuf::PmidList pmid_list_msg;
  pmid_list_msg.ParseFromString(ReadFile(file_path).string());
  for (int i = 0; i < pmid_list_msg.pmids_size(); ++i)
    pmid_list.push_back(std::move(
        passport::detail::ParsePmid(NonEmptyString(pmid_list_msg.pmids(i).pmid()))));
  return pmid_list;
}

bool WritePmidList(const boost::filesystem::path& file_path,
                   const std::vector<Fob<PmidTag>>& pmid_list) {  // NOLINT (Fraser)
  protobuf::PmidList pmid_list_msg;
  for (auto &pmid : pmid_list) {
    auto entry = pmid_list_msg.add_pmids();
    entry->set_pmid(passport::detail::SerialisePmid(pmid).string());
  }
  return WriteFile(file_path, pmid_list_msg.SerializeAsString());
}

template<>
std::string DebugString<Fob<AnmidTag>::name_type>(const Fob<AnmidTag>::name_type& name) {
  return "[" + HexSubstr(name.data) + " Anmid] ";
}

template<>
std::string DebugString<Fob<AnsmidTag>::name_type>(const Fob<AnsmidTag>::name_type& name) {
  return "[" + HexSubstr(name.data) + " Ansmid]";
}

template<>
std::string DebugString<Fob<AntmidTag>::name_type>(const Fob<AntmidTag>::name_type& name) {
  return "[" + HexSubstr(name.data) + " Antmid]";
}

template<>
std::string DebugString<Fob<AnmaidTag>::name_type>(const Fob<AnmaidTag>::name_type& name) {
  return "[" + HexSubstr(name.data) + " Anmaid]";
}

template<>
std::string DebugString<Fob<MaidTag>::name_type>(const Fob<MaidTag>::name_type& name) {
  return "[" + HexSubstr(name.data) + " Maid]  ";
}

template<>
std::string DebugString<Fob<PmidTag>::name_type>(const Fob<PmidTag>::name_type& name) {
  return "[" + HexSubstr(name.data) + " Pmid]  ";
}

template<>
std::string DebugString<Fob<AnmpidTag>::name_type>(const Fob<AnmpidTag>::name_type& name) {
  return "[" + HexSubstr(name.data) + " Anmpid]";
}

template<>
std::string DebugString<Fob<MpidTag>::name_type>(const Fob<MpidTag>::name_type& name) {
  return "[" + HexSubstr(name.data) + " Mpid]  ";
}

#endif  // TESTING

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe
