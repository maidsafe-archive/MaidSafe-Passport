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

#ifndef MAIDSAFE_PASSPORT_TYPES_H_
#define MAIDSAFE_PASSPORT_TYPES_H_

#include "maidsafe/common/tagged_value.h"
#include "maidsafe/common/types.h"

#include "maidsafe/passport/detail/config.h"
#include "maidsafe/passport/detail/fob.h"
#include "maidsafe/passport/detail/public_fob.h"

namespace maidsafe {

namespace passport {

// The Fob class template provides the unique identity elements required for encrypted, self
// authenticated storage/retrieval and communication on the MaidSafe network.  Identities, are
// defined in terms of a Fob.

// Maidsafe Anonymous Identification: Identifies a client on the network and is used by the client
// software for anonymous authenticatable network transactions (e.g. Put/Delete data).  It is signed
// by the Anmaid passed during its construction.
typedef detail::Fob<detail::MaidTag> Maid;

// Proxy Maidsafe Identification: Identifies a vault on the network, see
// https://github.com/maidsafe/MaidSafe-Vault/wiki for more information about vaults.  It is signed
// by the Anpmid passed during its construction.
typedef detail::Fob<detail::PmidTag> Pmid;

// Maidsafe Public Identification: Identifies a public client on the network and is used by the
// client software for public authenticatable network transactions (e.g messaging).  It is signed by
// the Anmpid passed during its construction.  Its name is user-chosen.
typedef detail::Fob<detail::MpidTag> Mpid;

// Anonymous Maid: Used only to sign the Maid and is self-signed.
typedef detail::Fob<detail::AnmaidTag> Anmaid;

// Anonymous Pmid: Used only to sign the Pmid and is self-signed.
typedef detail::Fob<detail::AnpmidTag> Anpmid;

// Anonymous Mpid: Used only to sign the Mpid and is self-signed.
typedef detail::Fob<detail::AnmpidTag> Anmpid;


// Public key types allowing peers to encrypt communications to eachother on the network.  The
// digital signatures are generated using the RSA-probabilistic signature scheme, RSA-PSS.  More
// information can be found at http://www.rsa.com/rsalabs, or http://www.cryptopp.com for the
// implementation.
typedef detail::PublicFob<detail::AnmaidTag> PublicAnmaid;
typedef detail::PublicFob<detail::MaidTag> PublicMaid;

typedef detail::PublicFob<detail::AnpmidTag> PublicAnpmid;
typedef detail::PublicFob<detail::PmidTag> PublicPmid;

typedef detail::PublicFob<detail::AnmpidTag> PublicAnmpid;
typedef detail::PublicFob<detail::MpidTag> PublicMpid;

// Public key type traits.
template <typename T>
struct is_public_key_type : public std::false_type {};

template <>
struct is_public_key_type<PublicAnmaid> : public std::true_type {};
template <>
struct is_public_key_type<PublicMaid> : public std::true_type {};
template <>
struct is_public_key_type<PublicAnpmid> : public std::true_type {};
template <>
struct is_public_key_type<PublicPmid> : public std::true_type {};
template <>
struct is_public_key_type<PublicAnmpid> : public std::true_type {};
template <>
struct is_public_key_type<PublicMpid> : public std::true_type {};

}  // namespace passport

// Short term cacheability traits.
template <>
struct is_short_term_cacheable<passport::PublicMaid> : public std::true_type {};
template <>
struct is_short_term_cacheable<passport::PublicPmid> : public std::true_type {};
template <>
struct is_short_term_cacheable<passport::PublicMpid> : public std::true_type {};

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_TYPES_H_
