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

#ifndef MAIDSAFE_PASSPORT_TYPES_H_
#define MAIDSAFE_PASSPORT_TYPES_H_

#include "maidsafe/common/tagged_value.h"
#include "maidsafe/common/types.h"

#include "maidsafe/passport/detail/config.h"


namespace maidsafe {

namespace passport {

typedef detail::Fob<detail::AnmidTag> Anmid;
typedef detail::Fob<detail::AnsmidTag> Ansmid;
typedef detail::Fob<detail::AntmidTag> Antmid;
typedef detail::Fob<detail::AnmaidTag> Anmaid;
typedef detail::Fob<detail::MaidTag> Maid;
typedef detail::Fob<detail::PmidTag> Pmid;

typedef detail::NameAndValue<detail::MidTag> Mid;
typedef detail::NameAndValue<detail::SmidTag> Smid;
typedef detail::NameAndValue<detail::TmidTag> Tmid;
typedef detail::NameAndValue<detail::StmidTag> Stmid;

typedef detail::Fob<detail::AnmpidTag> Anmpid;
typedef detail::Fob<detail::MpidTag> Mpid;

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_CONFIG_H_
