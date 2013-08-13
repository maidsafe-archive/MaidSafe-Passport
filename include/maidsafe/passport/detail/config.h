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

#ifndef MAIDSAFE_PASSPORT_DETAIL_CONFIG_H_
#define MAIDSAFE_PASSPORT_DETAIL_CONFIG_H_

#include <string>

#include "maidsafe/data_types/data_type_values.h"


namespace maidsafe {

namespace passport {

namespace detail {

typedef maidsafe::detail::Tag<DataTagValue::kAnmidValue> AnmidTag;
typedef maidsafe::detail::Tag<DataTagValue::kAnsmidValue> AnsmidTag;
typedef maidsafe::detail::Tag<DataTagValue::kAntmidValue> AntmidTag;
typedef maidsafe::detail::Tag<DataTagValue::kAnmaidValue> AnmaidTag;
typedef maidsafe::detail::Tag<DataTagValue::kMaidValue> MaidTag;
typedef maidsafe::detail::Tag<DataTagValue::kPmidValue> PmidTag;
typedef maidsafe::detail::Tag<DataTagValue::kMidValue> MidTag;
typedef maidsafe::detail::Tag<DataTagValue::kSmidValue> SmidTag;
typedef maidsafe::detail::Tag<DataTagValue::kTmidValue> TmidTag;
typedef maidsafe::detail::Tag<DataTagValue::kAnmpidValue> AnmpidTag;
typedef maidsafe::detail::Tag<DataTagValue::kMpidValue> MpidTag;

template<typename Tag, class Enable = void>
class Fob;

template<typename Tag>
class MidData;

class TmidData;

template<typename Tag>
struct Signer {
  typedef Fob<Tag> type;
};

template<>
struct Signer<MaidTag> {
  typedef Fob<AnmaidTag> type;
};

template<>
struct Signer<PmidTag> {
  typedef Fob<MaidTag> type;
};

template<>
struct Signer<MidTag> {
  typedef Fob<AnmidTag> type;
};

template<>
struct Signer<SmidTag> {
  typedef Fob<AnsmidTag> type;
};

template<>
struct Signer<TmidTag> {
  typedef Fob<AntmidTag> type;
};

template<>
struct Signer<MpidTag> {
  typedef Fob<AnmpidTag> type;
};


#ifdef TESTING

template<typename NameType>
std::string DebugString(const NameType& name);

#endif

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_CONFIG_H_
