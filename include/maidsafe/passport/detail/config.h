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

#include <string>

#include "maidsafe/data_types/data_type_values.h"


namespace maidsafe {

namespace passport {

namespace detail {

struct AnmidTag {
  static const DataTagValue kEnumValue = DataTagValue::kAnmidValue;
};

struct AnsmidTag {
  static const DataTagValue kEnumValue = DataTagValue::kAnsmidValue;
};

struct AntmidTag {
  static const DataTagValue kEnumValue = DataTagValue::kAntmidValue;
};

struct AnmaidTag {
  static const DataTagValue kEnumValue = DataTagValue::kAnmaidValue;
};

struct MaidTag {
  static const DataTagValue kEnumValue = DataTagValue::kMaidValue;
};

struct PmidTag {
  static const DataTagValue kEnumValue = DataTagValue::kPmidValue;
};

struct MidTag {
  static const DataTagValue kEnumValue = DataTagValue::kMidValue;
};

struct SmidTag {
  static const DataTagValue kEnumValue = DataTagValue::kSmidValue;
};

struct TmidTag {
  static const DataTagValue kEnumValue = DataTagValue::kTmidValue;
};

struct AnmpidTag {
  static const DataTagValue kEnumValue = DataTagValue::kAnmpidValue;
};

struct MpidTag {
  static const DataTagValue kEnumValue = DataTagValue::kMpidValue;
};

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
