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

EncryptedSession EncryptSession(const detail::Keyword& keyword,
                                const detail::Pin& pin,
                                const detail::Password& password,
                                const NonEmptyString& serialised_session) {
  return detail::EncryptSession(keyword, pin, password, serialised_session);
}

EncryptedTmidName EncryptTmidName(const detail::Keyword& keyword,
                                  const detail::Pin& pin,
                                  const Tmid::name_type& tmid_name) {
  return detail::EncryptTmidName(keyword, pin, tmid_name);
}

Mid::name_type MidName(const detail::Keyword& keyword, const detail::Pin& pin) {
  return Mid::GenerateName(keyword, pin);
}

Smid::name_type SmidName(const detail::Keyword& keyword, const detail::Pin& pin) {
  return Smid::GenerateName(keyword, pin);
}

NonEmptyString DecryptSession(const detail::Keyword& keyword,
                              const detail::Pin& pin,
                              const detail::Password& password,
                              const EncryptedSession& encrypted_session) {
  return detail::DecryptSession(keyword, pin, password, encrypted_session);
}

Tmid::name_type DecryptTmidName(const detail::Keyword& keyword,
                                const detail::Pin& pin,
                                const EncryptedTmidName& encrypted_tmid_name) {
  return detail::DecryptTmidName(keyword, pin, encrypted_tmid_name);
}

NonEmptyString SerialisePmid(const Pmid& pmid) {
  return detail::SerialisePmid(pmid);
}

Pmid ParsePmid(const NonEmptyString& serialised_pmid) {
  return detail::ParsePmid(serialised_pmid);
}


Passport::Passport()
    : pending_fobs_(),
      confirmed_fobs_(),
      pending_selectable_fobs_(),
      confirmed_selectable_fobs_(),
      fobs_mutex_(),
      selectable_mutex_() {}

void Passport::CreateFobs() {
  std::lock_guard<std::mutex> lock(fobs_mutex_);
  pending_fobs_.anmid.reset(new Anmid);
  pending_fobs_.ansmid.reset(new Ansmid);
  pending_fobs_.antmid.reset(new Antmid);
  pending_fobs_.anmaid.reset(new Anmaid);
  pending_fobs_.maid.reset(new Maid(*pending_fobs_.anmaid));
  pending_fobs_.pmid.reset(new Pmid(*pending_fobs_.maid));
}

bool Passport::NoFobsNull(bool confirmed) {
  const Fobs& fobs(confirmed ? confirmed_fobs_ : pending_fobs_);
  std::string error_message(confirmed ? "Not all fobs were found in confirmed container." :
                                        "Not all fobs were found in pending container.");
  if (!fobs.anmid) {
    LOG(kError) << error_message;
    return false;
  }
  if (!fobs.ansmid) {
    LOG(kError) << error_message;
    return false;
  }
  if (!fobs.antmid) {
    LOG(kError) << error_message;
    return false;
  }
  if (!fobs.anmaid) {
    LOG(kError) << error_message;
    return false;
  }
  if (!fobs.maid) {
    LOG(kError) << error_message;
    return false;
  }
  if (!fobs.pmid) {
    LOG(kError) << error_message;
    return false;
  }
  return true;
}

void Passport::ConfirmFobs() {
  std::lock_guard<std::mutex> lock(fobs_mutex_);
  assert(NoFobsNull(false));
  confirmed_fobs_ = std::move(pending_fobs_);
  pending_fobs_ = std::move(Fobs());
}

NonEmptyString Passport::Serialise() {
  detail::protobuf::Passport proto_passport;
  assert(NoFobsNull(true));

  std::lock(fobs_mutex_, selectable_mutex_);
  std::lock_guard<std::mutex> fobs_lock(fobs_mutex_, std::adopt_lock);
  std::lock_guard<std::mutex> selectable_lock(selectable_mutex_, std::adopt_lock);

  auto proto_fob(proto_passport.add_fob());
  confirmed_fobs_.anmid->ToProtobuf(proto_fob);
  proto_fob = proto_passport.add_fob();
  confirmed_fobs_.ansmid->ToProtobuf(proto_fob);
  proto_fob = proto_passport.add_fob();
  confirmed_fobs_.antmid->ToProtobuf(proto_fob);
  proto_fob = proto_passport.add_fob();
  confirmed_fobs_.anmaid->ToProtobuf(proto_fob);
  proto_fob = proto_passport.add_fob();
  confirmed_fobs_.maid->ToProtobuf(proto_fob);
  proto_fob = proto_passport.add_fob();
  confirmed_fobs_.pmid->ToProtobuf(proto_fob);

  for (auto& selectable_fob : confirmed_selectable_fobs_) {
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

void Passport::Parse(const NonEmptyString& serialised_passport) {
  detail::protobuf::Passport proto_passport;
  if (!proto_passport.ParseFromString(serialised_passport.string()) ||
      !proto_passport.IsInitialized()) {
    LOG(kError) << "Failed to parse passport.";
    ThrowError(PassportErrors::passport_parsing_error);
  }

  if (proto_passport.fob_size() != 6) {
    LOG(kError) << "Parsed passport should have 6 fobs, actually has " << proto_passport.fob_size();
    ThrowError(PassportErrors::passport_parsing_error);
  }

  std::lock(fobs_mutex_, selectable_mutex_);
  std::lock_guard<std::mutex> fobs_lock(fobs_mutex_, std::adopt_lock);
  std::lock_guard<std::mutex> selectable_lock(selectable_mutex_, std::adopt_lock);

  confirmed_fobs_.anmid.reset(new Anmid(proto_passport.fob(0)));
  confirmed_fobs_.ansmid.reset(new Ansmid(proto_passport.fob(1)));
  confirmed_fobs_.antmid.reset(new Antmid(proto_passport.fob(2)));
  confirmed_fobs_.anmaid.reset(new Anmaid(proto_passport.fob(3)));
  confirmed_fobs_.maid.reset(new Maid(proto_passport.fob(4)));
  confirmed_fobs_.pmid.reset(new Pmid(proto_passport.fob(5)));

  for (int i(0); i != proto_passport.public_identity_size(); ++i) {
    NonEmptyString public_id(proto_passport.public_identity(i).public_id());
    SelectableFobPair fob;
    fob.anmpid.reset(new Anmpid(proto_passport.public_identity(i).anmpid()));
    fob.mpid.reset(new Mpid(proto_passport.public_identity(i).mpid()));
    confirmed_selectable_fobs_[public_id] = std::move(fob);
  }
}

void Passport::CreateSelectableFobPair(const NonEmptyString& chosen_name) {
  SelectableFobPair selectable_fob_pair;
  selectable_fob_pair.anmpid.reset(new Anmpid);
  selectable_fob_pair.mpid.reset(new Mpid(chosen_name, *selectable_fob_pair.anmpid));
  std::lock_guard<std::mutex> lock(selectable_mutex_);
  auto result(pending_selectable_fobs_.insert(std::make_pair(chosen_name,
                                                             std::move(selectable_fob_pair))));
  if (!result.second)
    ThrowError(PassportErrors::public_id_already_exists);
}

void Passport::ConfirmSelectableFobPair(const NonEmptyString& chosen_name) {
  std::lock_guard<std::mutex> lock(selectable_mutex_);
  auto itr(pending_selectable_fobs_.find(chosen_name));
  if (itr == pending_selectable_fobs_.end())
    ThrowError(PassportErrors::no_such_public_id);

  auto result(confirmed_selectable_fobs_.insert(std::make_pair(chosen_name,
                                                               std::move((*itr).second))));
  if (!result.second)
    ThrowError(PassportErrors::public_id_already_exists);

  pending_selectable_fobs_.erase(itr);
}

void Passport::DeleteSelectableFobPair(const NonEmptyString& chosen_name) {
  std::lock_guard<std::mutex> lock(selectable_mutex_);
  confirmed_selectable_fobs_.erase(chosen_name);
  pending_selectable_fobs_.erase(chosen_name);
}



template<>
Anmid Passport::Get<Anmid>(bool confirmed) {
  std::lock_guard<std::mutex> lock(fobs_mutex_);
  if (confirmed) {
    if (!confirmed_fobs_.anmid)
      ThrowError(PassportErrors::no_confirmed_fob);
    return *confirmed_fobs_.anmid;
  } else {
    if (!pending_fobs_.anmid)
      ThrowError(PassportErrors::no_pending_fob);
    return *pending_fobs_.anmid;
  }
}

template<>
Ansmid Passport::Get<Ansmid>(bool confirmed) {
  std::lock_guard<std::mutex> lock(fobs_mutex_);
  if (confirmed) {
    if (!confirmed_fobs_.ansmid)
      ThrowError(PassportErrors::no_confirmed_fob);
    return *confirmed_fobs_.ansmid;
  } else {
    if (!pending_fobs_.ansmid)
      ThrowError(PassportErrors::no_pending_fob);
    return *pending_fobs_.ansmid;
  }
}

template<>
Antmid Passport::Get<Antmid>(bool confirmed) {
  std::lock_guard<std::mutex> lock(fobs_mutex_);
  if (confirmed) {
    if (!confirmed_fobs_.antmid)
      ThrowError(PassportErrors::no_confirmed_fob);
    return *confirmed_fobs_.antmid;
  } else {
    if (!pending_fobs_.antmid)
      ThrowError(PassportErrors::no_pending_fob);
    return *pending_fobs_.antmid;
  }
}

template<>
Anmaid Passport::Get<Anmaid>(bool confirmed) {
  std::lock_guard<std::mutex> lock(fobs_mutex_);
  if (confirmed) {
    if (!confirmed_fobs_.anmaid)
      ThrowError(PassportErrors::no_confirmed_fob);
    return *confirmed_fobs_.anmaid;
  } else {
    if (!pending_fobs_.anmaid)
      ThrowError(PassportErrors::no_pending_fob);
    return *pending_fobs_.anmaid;
  }
}

template<>
Maid Passport::Get<Maid>(bool confirmed) {
  std::lock_guard<std::mutex> lock(fobs_mutex_);
  if (confirmed) {
    if (!confirmed_fobs_.maid)
      ThrowError(PassportErrors::no_confirmed_fob);
    return *confirmed_fobs_.maid;
  } else {
    if (!pending_fobs_.maid)
      ThrowError(PassportErrors::no_pending_fob);
    return *pending_fobs_.maid;
  }
}

template<>
Pmid Passport::Get<Pmid>(bool confirmed) {
  std::lock_guard<std::mutex> lock(fobs_mutex_);
  if (confirmed) {
    if (!confirmed_fobs_.pmid)
      ThrowError(PassportErrors::no_confirmed_fob);
    return *confirmed_fobs_.pmid;
  } else {
    if (!pending_fobs_.pmid)
      ThrowError(PassportErrors::no_pending_fob);
    return *pending_fobs_.pmid;
  }
}

template<>
Anmpid Passport::GetFromSelectableFobPair(bool confirmed,
                                          const SelectableFobPair& selectable_fob_pair) {
  if (!selectable_fob_pair.anmpid)
    ThrowError(confirmed ? PassportErrors::no_confirmed_fob : PassportErrors::no_pending_fob);
  return *selectable_fob_pair.anmpid;
}

template<>
Mpid Passport::GetFromSelectableFobPair(bool confirmed,
                                        const SelectableFobPair& selectable_fob_pair) {
  if (!selectable_fob_pair.mpid)
    ThrowError(confirmed ? PassportErrors::no_confirmed_fob : PassportErrors::no_pending_fob);
  return *selectable_fob_pair.mpid;
}


}  // namespace passport

}  // namespace maidsafe
