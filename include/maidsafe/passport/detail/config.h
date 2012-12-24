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

#ifndef MAIDSAFE_PASSPORT_DETAIL_CONFIG_H_
#define MAIDSAFE_PASSPORT_DETAIL_CONFIG_H_

#include "maidsafe/detail/data_type_values.h"

namespace maidsafe {

namespace passport {

namespace detail {

struct AnmidTag  { static const int kEnumValue = maidsafe::detail::kAnmidValue;  };  // NOLINT (Fraser)
struct AnsmidTag { static const int kEnumValue = maidsafe::detail::kAnsmidValue; };  // NOLINT (Fraser)
struct AntmidTag { static const int kEnumValue = maidsafe::detail::kAntmidValue; };  // NOLINT (Fraser)
struct AnmaidTag { static const int kEnumValue = maidsafe::detail::kAnmaidValue; };  // NOLINT (Fraser)
struct MaidTag   { static const int kEnumValue = maidsafe::detail::kMaidValue;   };  // NOLINT (Fraser)
struct PmidTag   { static const int kEnumValue = maidsafe::detail::kPmidValue;   };  // NOLINT (Fraser)
struct MidTag    { static const int kEnumValue = maidsafe::detail::kMidValue;    };  // NOLINT (Fraser)
struct SmidTag   { static const int kEnumValue = maidsafe::detail::kSmidValue;   };  // NOLINT (Fraser)
struct TmidTag   { static const int kEnumValue = maidsafe::detail::kTmidValue;   };  // NOLINT (Fraser)
struct AnmpidTag { static const int kEnumValue = maidsafe::detail::kAnmpidValue; };  // NOLINT (Fraser)
struct MpidTag   { static const int kEnumValue = maidsafe::detail::kMpidValue;   };  // NOLINT (Fraser)

template<typename Tag, class Enable = void>
class Fob;

template<typename Tag>
struct MidData;

template<typename Tag>
struct TmidData;

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

}  // namespace detail

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_DETAIL_CONFIG_H_
