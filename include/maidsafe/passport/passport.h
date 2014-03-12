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

#ifndef MAIDSAFE_PASSPORT_PASSPORT_H_
#define MAIDSAFE_PASSPORT_PASSPORT_H_

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>

#include "maidsafe/common/config.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"

#include "maidsafe/passport/types.h"
#include "maidsafe/passport/detail/fob.h"
#include "maidsafe/passport/detail/secure_string.h"

namespace maidsafe {

namespace passport {

// The Passport API is a realisation of a Public Key Infrastructure, PKI, free from central
// authority and the notion of a web of trust. In fact, based on the precepts inherent in the DHT,
// https://github.com/maidsafe/MaidSafe-Routing/wiki, and vault
// https://github.com/maidsafe/MaidSafe-Vault/wiki libraries, all nodes on the network are assumed
// to be operating in a hostile environment. In contrast, cooperating/collaborating nodes are
// essential for network stability and health. To resolve these conflicting notions, groups of nodes
// close to a given network addressable element, NAE, determine the validity of requests to/from any
// other node with respect to that NAE. The Passport library provides the necessary types and
// methods required for this, including secure communications/transactions, and private/public
// resource sharing and self-authentication on the network.

// Password-Based Key Derivation Function 2, PBKDF2, methods for cryptographically hashing client
// session data from input user details. The PBKDF2 implementation is based on the PKCS #5 v2.0
// standard from RSA laboratories, http://www.rsa.com/rsalabs, see also the cryptographic component
// of the https://github.com/maidsafe/MaidSafe-Common/wiki project. The following methods are used
// for self-authenticated network identity' storage/retrieval on the network.

// Methods for serialising/parsing the identity required for data storage.
NonEmptyString SerialisePmid(const Pmid& pmid);
Pmid ParsePmid(const NonEmptyString& serialised_pmid);

// The Passport class contains identity types for the various network related tasks available, see
// types.h for details about the identity types.
class Passport {
 public:
  // Creates Fobs during construction.
  Passport();

  explicit Passport(const NonEmptyString& serialised_passport);

  NonEmptyString Serialise() const;

  template <typename FobType>
  FobType Get() const;

  // There's no restriction on the number of Mpids an application can create/use.
  void CreateMpid(const NonEmptyString& name);
  void DeleteMpid(const NonEmptyString& name);

  Anmpid GetAnmpid(const NonEmptyString& name) const;
  Mpid GetMpid(const NonEmptyString& name) const;

 private:
  Passport(const Passport&) MAIDSAFE_DELETE;
  Passport(Passport&&) MAIDSAFE_DELETE;
  Passport& operator=(Passport) MAIDSAFE_DELETE;

  struct SelectableFobPair {
    SelectableFobPair() : anmpid(), mpid() {}

    SelectableFobPair(SelectableFobPair&& other)
        : anmpid(std::move(other.anmpid)), mpid(std::move(other.mpid)) {}

    SelectableFobPair& operator=(SelectableFobPair&& other) {
      anmpid = std::move(other.anmpid);
      mpid = std::move(other.mpid);
      return *this;
    }

    std::unique_ptr<Anmpid> anmpid;
    std::unique_ptr<Mpid> mpid;

   private:
    SelectableFobPair(const SelectableFobPair&) MAIDSAFE_DELETE;
    SelectableFobPair& operator=(const SelectableFobPair&) MAIDSAFE_DELETE;
  };

  bool NoFobsNull() const;

  template <typename FobType>
  FobType GetSelectableFob(const NonEmptyString& name) const;

  template <typename FobType>
  FobType GetFromSelectableFobPair(const SelectableFobPair& selectable_fob_pair) const;

  std::unique_ptr<Anmaid> anmaid_;
  std::unique_ptr<Maid> maid_;
  std::unique_ptr<Anpmid> anpmid_;
  std::unique_ptr<Pmid> pmid_;

  std::map<NonEmptyString, SelectableFobPair> selectable_fobs_;
  mutable std::mutex fobs_mutex_, selectable_fobs_mutex_;
};

template <>
Anmaid Passport::Get<Anmaid>() const;

template <>
Maid Passport::Get<Maid>() const;

template <>
Anpmid Passport::Get<Anpmid>() const;

template <>
Pmid Passport::Get<Pmid>() const;

template <typename FobType>
FobType Passport::GetSelectableFob(const NonEmptyString& name) const {
  std::lock_guard<std::mutex> lock(selectable_fobs_mutex_);
  auto itr(selectable_fobs_.find(name));
  if (itr == selectable_fobs_.end())
    BOOST_THROW_EXCEPTION(MakeError(PassportErrors::uninitialised_fob));
  return GetFromSelectableFobPair<FobType>(itr->second);
}

template <>
Anmpid Passport::GetFromSelectableFobPair(const SelectableFobPair& selectable_fob_pair) const;

template <>
Mpid Passport::GetFromSelectableFobPair(const SelectableFobPair& selectable_fob_pair) const;

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_PASSPORT_H_
