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
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/detail/identity_data.h"
#include "maidsafe/passport/detail/passport.pb.h"

namespace maidsafe {
namespace passport {

EncryptedSession EncryptSession(const detail::Keyword& keyword, const detail::Pin& pin,
                                const detail::Password& password,
                                const NonEmptyString& serialised_session) {
  return detail::EncryptSession(keyword, pin, password, serialised_session);
}

EncryptedTmidName EncryptTmidName(const detail::Keyword& keyword, const detail::Pin& pin,
                                  const Tmid::Name& tmid_name) {
  return detail::EncryptTmidName(keyword, pin, tmid_name);
}

Mid::Name MidName(const detail::Keyword& keyword, const detail::Pin& pin) {
  return Mid::GenerateName(keyword, pin);
}

Smid::Name SmidName(const detail::Keyword& keyword, const detail::Pin& pin) {
  return Smid::GenerateName(keyword, pin);
}

NonEmptyString DecryptSession(const detail::Keyword& keyword, const detail::Pin& pin,
                              const detail::Password& password,
                              const EncryptedSession& encrypted_session) {
  return detail::DecryptSession(keyword, pin, password, encrypted_session);
}

Tmid::Name DecryptTmidName(const detail::Keyword& keyword, const detail::Pin& pin,
                           const EncryptedTmidName& encrypted_tmid_name) {
  return detail::DecryptTmidName(keyword, pin, encrypted_tmid_name);
}

NonEmptyString SerialisePmid(const Pmid& pmid) { return detail::SerialisePmid(pmid); }

Pmid ParsePmid(const NonEmptyString& serialised_pmid) { return detail::ParsePmid(serialised_pmid); }

Passport::Passport()
    : fobs_(),
      selectable_fobs_(),
      fobs_mutex_(),
      selectable_fobs_mutex_() {
  std::lock_guard<std::mutex> lock(fobs_mutex_);
  fobs_.anmid.reset(new Anmid);
  fobs_.ansmid.reset(new Ansmid);
  fobs_.antmid.reset(new Antmid);
  fobs_.anmaid.reset(new Anmaid);
  fobs_.maid.reset(new Maid(*fobs_.anmaid));
  fobs_.pmid.reset(new Pmid(*fobs_.maid));
}

Passport::Passport(Passport&& passport)
    : fobs_(std::move(passport.fobs_)),
      selectable_fobs_(std::move(passport.selectable_fobs_)),
      fobs_mutex_(),
      selectable_fobs_mutex_() {}

Passport& Passport::operator=(Passport&& passport) {
  fobs_ = std::move(passport.fobs_);
  selectable_fobs_ = std::move(passport.selectable_fobs_);
  return *this;
}

Passport::Passport(const NonEmptyString& serialised_passport)
    : fobs_(),
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
  std::lock_guard<std::mutex> fobs_lock(fobs_mutex_, std::adopt_lock);
  std::lock_guard<std::mutex> selectable_fobs_lock(selectable_fobs_mutex_, std::adopt_lock);

  fobs_.anmid.reset(new Anmid(proto_passport.fob(0)));
  fobs_.ansmid.reset(new Ansmid(proto_passport.fob(1)));
  fobs_.antmid.reset(new Antmid(proto_passport.fob(2)));
  fobs_.anmaid.reset(new Anmaid(proto_passport.fob(3)));
  fobs_.maid.reset(new Maid(proto_passport.fob(4)));
  fobs_.pmid.reset(new Pmid(proto_passport.fob(5)));

  assert(NoFobsNull());

  for (int i(0); i != proto_passport.public_identity_size(); ++i) {
    NonEmptyString public_id(proto_passport.public_identity(i).public_id());
    SelectableFobPair fob;
    fob.anmpid.reset(new Anmpid(proto_passport.public_identity(i).anmpid()));
    fob.mpid.reset(new Mpid(proto_passport.public_identity(i).mpid()));
    selectable_fobs_[public_id] = std::move(fob);
  }
}

bool Passport::NoFobsNull() const {
  const Fobs& fobs(fobs_);
  std::string error_message("Not all fobs were found in container.");

  if (!fobs.anmid || !fobs.ansmid || !fobs.antmid || !fobs.anmaid || !fobs.maid || !fobs.pmid) {
    LOG(kError) << error_message;
    return false;
  }
  return true;
}

NonEmptyString Passport::Serialise() {
  detail::protobuf::Passport proto_passport;
  assert(NoFobsNull());

  std::lock(fobs_mutex_, selectable_fobs_mutex_);
  std::lock_guard<std::mutex> fobs_lock(fobs_mutex_, std::adopt_lock);
  std::lock_guard<std::mutex> selectable_fobs_lock(selectable_fobs_mutex_, std::adopt_lock);

  auto proto_fob(proto_passport.add_fob());
  fobs_.anmid->ToProtobuf(proto_fob);
  proto_fob = proto_passport.add_fob();
  fobs_.ansmid->ToProtobuf(proto_fob);
  proto_fob = proto_passport.add_fob();
  fobs_.antmid->ToProtobuf(proto_fob);
  proto_fob = proto_passport.add_fob();
  fobs_.anmaid->ToProtobuf(proto_fob);
  proto_fob = proto_passport.add_fob();
  fobs_.maid->ToProtobuf(proto_fob);
  proto_fob = proto_passport.add_fob();
  fobs_.pmid->ToProtobuf(proto_fob);

  for (auto& selectable_fob : selectable_fobs_) {
    assert(selectable_fob.second.anmpid);
    assert(selectable_fob.second.mpid);
    auto proto_public_identity(proto_passport.add_public_identity());
    proto_public_identity->set_public_id(selectable_fob.first.string());
    auto proto_anmpid(proto_public_identity->mutable_anmpid());
    selectable_fob.second.anmpid->ToProtobuf(proto_anmpid);
    auto proto_mpid(proto_public_identity->mutable_mpid());
    selectable_fob.second.mpid->ToProtobuf(proto_mpid);
  }

  return NonEmptyString(proto_passport.SerializeAsString());
}


void Passport::CreateSelectableFobPair(const NonEmptyString& name) {
  SelectableFobPair selectable_fob_pair;
  selectable_fob_pair.anmpid.reset(new Anmpid);
  selectable_fob_pair.mpid.reset(new Mpid(name, *selectable_fob_pair.anmpid));
  std::lock_guard<std::mutex> lock(selectable_fobs_mutex_);
  auto result(selectable_fobs_.insert(std::make_pair(name, std::move(selectable_fob_pair))));
  if (!result.second)
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::public_id_already_exists));
}

void Passport::DeleteSelectableFobPair(const NonEmptyString& name) {
  std::lock_guard<std::mutex> lock(selectable_fobs_mutex_);
  selectable_fobs_.erase(name);
}

template <>
Anmid Passport::Get<Anmid>() {
  std::lock_guard<std::mutex> lock(fobs_mutex_);
  if (!fobs_.anmid)
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::uninitialised_fob));
  return *fobs_.anmid;
}

template <>
Ansmid Passport::Get<Ansmid>() {
  std::lock_guard<std::mutex> lock(fobs_mutex_);
  if (!fobs_.ansmid)
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::uninitialised_fob));
  return *fobs_.ansmid;
}

template <>
Antmid Passport::Get<Antmid>() {
  std::lock_guard<std::mutex> lock(fobs_mutex_);
  if (!fobs_.antmid)
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::uninitialised_fob));
  return *fobs_.antmid;
}

template <>
Anmaid Passport::Get<Anmaid>() {
  std::lock_guard<std::mutex> lock(fobs_mutex_);
  if (!fobs_.anmaid)
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::uninitialised_fob));
  return *fobs_.anmaid;
}

template <>
Maid Passport::Get<Maid>() {
  std::lock_guard<std::mutex> lock(fobs_mutex_);
  if (!fobs_.maid)
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::uninitialised_fob));
  return *fobs_.maid;
}

template <>
Pmid Passport::Get<Pmid>() {
  std::lock_guard<std::mutex> lock(fobs_mutex_);
  if (!fobs_.pmid)
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::uninitialised_fob));
  return *fobs_.pmid;
}

template <>
Anmpid Passport::GetFromSelectableFobPair(const SelectableFobPair& selectable_fob_pair) {
  if (!selectable_fob_pair.anmpid)
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::uninitialised_fob));
  return *selectable_fob_pair.anmpid;
}

template <>
Mpid Passport::GetFromSelectableFobPair(const SelectableFobPair& selectable_fob_pair) {
  if (!selectable_fob_pair.mpid)
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::uninitialised_fob));
  return *selectable_fob_pair.mpid;
}

}  // namespace passport
}  // namespace maidsafe
