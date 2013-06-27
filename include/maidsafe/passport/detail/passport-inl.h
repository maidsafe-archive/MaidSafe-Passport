/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

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
