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

#include "maidsafe/passport/passport.h"

#include <map>
#include <vector>

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/detail/passport.pb.h"

namespace maidsafe {

namespace passport {

NonEmptyString SerialisePmid(const Pmid& pmid) { return detail::SerialisePmid(pmid); }

Pmid ParsePmid(const NonEmptyString& serialised_pmid) { return detail::ParsePmid(serialised_pmid); }

Passport::Passport()
    : anmaid_(maidsafe::make_unique<Anmaid>()),
      maid_(maidsafe::make_unique<Maid>(*anmaid_)),
      anpmid_(maidsafe::make_unique<Anpmid>()),
      pmid_(maidsafe::make_unique<Pmid>(*anpmid_)),
      selectable_fobs_(),
      fobs_mutex_(),
      selectable_fobs_mutex_() {}

Passport::Passport(const NonEmptyString& serialised_passport)
    : anmaid_(),
      maid_(),
      anpmid_(),
      pmid_(),
      selectable_fobs_(),
      fobs_mutex_(),
      selectable_fobs_mutex_() {
  detail::protobuf::Passport proto_passport;
  if (!proto_passport.ParseFromString(serialised_passport.string()) ||
      !proto_passport.IsInitialized()) {
    LOG(kError) << "Failed to parse passport.";
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::passport_parsing_error));
  }

  if (proto_passport.fob_size() != 6) {
    LOG(kError) << "Parsed passport should have 6 fobs, actually has " << proto_passport.fob_size();
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::passport_parsing_error));
  }

  std::lock(fobs_mutex_, selectable_fobs_mutex_);
  std::lock_guard<std::mutex> fobs_lock{ fobs_mutex_, std::adopt_lock };
  std::lock_guard<std::mutex> selectable_fobs_lock{ selectable_fobs_mutex_, std::adopt_lock };

  anmaid_ = maidsafe::make_unique<Anmaid>(proto_passport.fob(0));
  maid_ = maidsafe::make_unique<Maid>(proto_passport.fob(1));
  anpmid_ = maidsafe::make_unique<Anpmid>(proto_passport.fob(2));
  pmid_ = maidsafe::make_unique<Pmid>(proto_passport.fob(3));

  assert(NoFobsNull());

  for (int i(0); i != proto_passport.public_identity_size(); ++i) {
    NonEmptyString public_id{ proto_passport.public_identity(i).public_id() };
    SelectableFobPair fob;
    fob.anmpid = maidsafe::make_unique<Anmpid>(proto_passport.public_identity(i).anmpid());
    fob.mpid = maidsafe::make_unique<Mpid>(proto_passport.public_identity(i).mpid());
    selectable_fobs_[public_id] = std::move(fob);
  }
}

bool Passport::NoFobsNull() const {
  if (!anmaid_) {
    LOG(kError) << "No Anmaid.";
    return false;
  }
  if (!maid_) {
    LOG(kError) << "No Maid.";
    return false;
  }
  if (!anpmid_) {
    LOG(kError) << "No Anpmid.";
    return false;
  }
  if (!pmid_) {
    LOG(kError) << "No Pmid.";
    return false;
  }
  return true;
}

NonEmptyString Passport::Serialise() const {
  detail::protobuf::Passport proto_passport;
  assert(NoFobsNull());

  std::lock(fobs_mutex_, selectable_fobs_mutex_);
  std::lock_guard<std::mutex> fobs_lock{ fobs_mutex_, std::adopt_lock };
  std::lock_guard<std::mutex> selectable_fobs_lock{ selectable_fobs_mutex_, std::adopt_lock };

  detail::protobuf::Fob* proto_fob{ proto_passport.add_fob() };
  anmaid_->ToProtobuf(proto_fob);
  proto_fob = proto_passport.add_fob();
  maid_->ToProtobuf(proto_fob);
  proto_fob = proto_passport.add_fob();
  anpmid_->ToProtobuf(proto_fob);
  proto_fob = proto_passport.add_fob();
  pmid_->ToProtobuf(proto_fob);

  for (const auto& selectable_fob : selectable_fobs_) {
    assert(selectable_fob.second.anmpid);
    assert(selectable_fob.second.mpid);
    detail::protobuf::PublicIdentity* proto_public_identity{ proto_passport.add_public_identity() };
    proto_public_identity->set_public_id(selectable_fob.first.string());
    selectable_fob.second.anmpid->ToProtobuf(proto_public_identity->mutable_anmpid());
    selectable_fob.second.mpid->ToProtobuf(proto_public_identity->mutable_mpid());
  }

  return NonEmptyString{ proto_passport.SerializeAsString() };
}

template <>
Anmaid Passport::Get<Anmaid>() const {
  std::lock_guard<std::mutex> lock{ fobs_mutex_ };
  if (!anmaid_)
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::uninitialised_fob));
  return *anmaid_;
}

template <>
Maid Passport::Get<Maid>() const {
  std::lock_guard<std::mutex> lock{ fobs_mutex_ };
  if (!maid_)
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::uninitialised_fob));
  return *maid_;
}

template <>
Anpmid Passport::Get<Anpmid>() const {
  std::lock_guard<std::mutex> lock{ fobs_mutex_ };
  if (!anpmid_)
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::uninitialised_fob));
  return *anpmid_;
}

template <>
Pmid Passport::Get<Pmid>() const {
  std::lock_guard<std::mutex> lock{ fobs_mutex_ };
  if (!pmid_)
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::uninitialised_fob));
  return *pmid_;
}

void Passport::CreateMpid(const NonEmptyString& name) {
  SelectableFobPair selectable_fob_pair;
  selectable_fob_pair.anmpid.reset(new Anmpid);
  selectable_fob_pair.mpid.reset(new Mpid(name, *selectable_fob_pair.anmpid));
  std::lock_guard<std::mutex> lock(selectable_fobs_mutex_);
  auto result(selectable_fobs_.insert(std::make_pair(name, std::move(selectable_fob_pair))));
  if (!result.second)
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::public_id_already_exists));
}

void Passport::DeleteMpid(const NonEmptyString& name) {
  std::lock_guard<std::mutex> lock(selectable_fobs_mutex_);
  selectable_fobs_.erase(name);
}

Anmpid Passport::GetAnmpid(const NonEmptyString& name) const {
  return GetSelectableFob<Anmpid>(name);
}

Mpid Passport::GetMpid(const NonEmptyString& name) const {
  return GetSelectableFob<Mpid>(name);
}

template <>
Anmpid Passport::GetFromSelectableFobPair(const SelectableFobPair& selectable_fob_pair) const {
  if (!selectable_fob_pair.anmpid)
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::uninitialised_fob));
  return *selectable_fob_pair.anmpid;
}

template <>
Mpid Passport::GetFromSelectableFobPair(const SelectableFobPair& selectable_fob_pair) const {
  if (!selectable_fob_pair.mpid)
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::uninitialised_fob));
  return *selectable_fob_pair.mpid;
}

}  // namespace passport

}  // namespace maidsafe
