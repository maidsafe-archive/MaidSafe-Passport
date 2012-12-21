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

#include "maidsafe/common/types.h"

#include "maidsafe/passport/detail/config.h"
#include "maidsafe/passport/detail/fob.h"
#include "maidsafe/passport/detail/public_fob.h"
#include "maidsafe/passport/detail/identity_data.h"


namespace maidsafe {

namespace passport {

typedef detail::Fob<detail::AnmidTag> Anmid;
typedef detail::Fob<detail::AnsmidTag> Ansmid;
typedef detail::Fob<detail::AntmidTag> Antmid;
typedef detail::Fob<detail::AnmaidTag> Anmaid;
typedef detail::Fob<detail::MaidTag> Maid;
typedef detail::Fob<detail::PmidTag> Pmid;

typedef detail::PublicFob<detail::AnmidTag> PublicAnmid;
typedef detail::PublicFob<detail::AnsmidTag> PublicAnsmid;
typedef detail::PublicFob<detail::AntmidTag> PublicAntmid;
typedef detail::PublicFob<detail::AnmaidTag> PublicAnmaid;
typedef detail::PublicFob<detail::MaidTag> PublicMaid;
typedef detail::PublicFob<detail::PmidTag> PublicPmid;

typedef detail::MidData<detail::MidTag> Mid;
typedef detail::MidData<detail::SmidTag> Smid;
typedef detail::TmidData<detail::TmidTag> Tmid, Stmid;

typedef detail::Fob<detail::AnmpidTag> Anmpid;
typedef detail::Fob<detail::MpidTag> Mpid;

typedef detail::PublicFob<detail::AnmpidTag> PublicAnmpid;
typedef detail::PublicFob<detail::MpidTag> PublicMpid;

}  // namespace passport

template<>
struct is_short_term_cacheable<passport::Anmid::name_type> : public std::true_type {};
template<>
struct is_short_term_cacheable<passport::Ansmid::name_type> : public std::true_type {};
template<>
struct is_short_term_cacheable<passport::Antmid::name_type> : public std::true_type {};
template<>
struct is_short_term_cacheable<passport::Anmaid::name_type> : public std::true_type {};
template<>
struct is_short_term_cacheable<passport::Maid::name_type> : public std::true_type {};
template<>
struct is_short_term_cacheable<passport::Pmid::name_type> : public std::true_type {};
template<>
struct is_short_term_cacheable<passport::Anmpid::name_type> : public std::true_type {};
template<>
struct is_short_term_cacheable<passport::Mpid::name_type> : public std::true_type {};

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_TYPES_H_
