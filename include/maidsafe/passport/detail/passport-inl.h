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

#ifndef MAIDSAFE_PASSPORT_DETAIL_PASSPORT_INL_H_
#define MAIDSAFE_PASSPORT_DETAIL_PASSPORT_INL_H_


namespace maidsafe {

namespace passport {

template<>
Anmid Passport::Get<Anmid>(bool confirmed);

template<>
Ansmid Passport::Get<Ansmid>(bool confirmed);

template<>
Antmid Passport::Get<Antmid>(bool confirmed);

template<>
Anmaid Passport::Get<Anmaid>(bool confirmed);

template<>
Maid Passport::Get<Maid>(bool confirmed);

template<>
Pmid Passport::Get<Pmid>(bool confirmed);

template<>
Anmpid Passport::GetFromSelectableFobPair(bool confirmed,
                                          const SelectableFobPair& selectable_fob_pair);

template<>
Mpid Passport::GetFromSelectableFobPair(bool confirmed,
                                        const SelectableFobPair& selectable_fob_pair);

template<typename FobType>
FobType Passport::GetSelectableFob(bool confirmed, const NonEmptyString &chosen_name) {
  std::lock_guard<std::mutex> lock(selectable_mutex_);
  if (confirmed) {
    auto itr(confirmed_selectable_fobs_.find(chosen_name));
    if (itr == confirmed_selectable_fobs_.end())
      ThrowError(PassportErrors::no_pending_fob);
    return GetFromSelectableFobPair<FobType>(confirmed, (*itr).second);
  } else {
    auto itr(pending_selectable_fobs_.find(chosen_name));
    if (itr == pending_selectable_fobs_.end())
      ThrowError(PassportErrors::no_pending_fob);
    return GetFromSelectableFobPair<FobType>(confirmed, (*itr).second);
  }
}

}  // namespace passport

}  // namespace maidsafe


#endif  // MAIDSAFE_PASSPORT_DETAIL_PASSPORT_INL_H_
