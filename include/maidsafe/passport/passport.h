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

#ifndef MAIDSAFE_PASSPORT_PASSPORT_H_
#define MAIDSAFE_PASSPORT_PASSPORT_H_

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"

#include "maidsafe/passport/types.h"
#include "maidsafe/passport/detail/fob.h"
#include "maidsafe/passport/detail/identity_data.h"
#include "maidsafe/passport/detail/secure_string.h"

namespace maidsafe {
namespace passport {

// The Passport API is a realisation of a Public Key Infrastructure, PKI, free from central
// authority and the notion of a web of trust. In fact, based on the precepts inherent in the DHT,
// http://maidsafe.github.io/MaidSafe-Routing/, and vault http://maidsafe.github.io/MaidSafe-Vault/,
// libraries, all nodes on the network are assumed to be operating in a hostile environment. In
// contrast, cooperating/collaborating nodes are essential for network stability and health. To
// resolve these conflicting notions, groups of nodes close to a given network addressable element,
// NAE, determine the validity of requests to/from any other node with respect to that NAE. The
// Passport library provides the necessary types and methods required for this, including secure
// communications/transactions, private/public resource sharing and self-authentication on the
// network.

// Password-Based Key Derivation Function 2, PBKDF2, methods for cryptographically hashing client
// session data from input user details. The PBKDF2 implementation is based on the PKCS #5 v2.0
// standard from RSA laboratories, http://www.rsa.com/rsalabs, see also the cryptographic component
// of the http://maidsafe.github.io/MaidSafe-Common/ project. The following methods are used for
// self-authenticated network identity' storage/retrieval on the network.

// Encrypts a users credentials prior to network storage.
EncryptedSession EncryptSession(const detail::Keyword& keyword,
                                const detail::Pin& pin,
                                const detail::Password& password,
                                const NonEmptyString& serialised_session);
// Retrieves a users credentials previously stored on the network.
NonEmptyString DecryptSession(const detail::Keyword& keyword,
                              const detail::Pin& pin,
                              const detail::Password& password,
                              const EncryptedSession& encrypted_session);

// PBKDF2 generated location to store Tmid data on network.
EncryptedTmidName EncryptTmidName(const detail::Keyword& keyword,
                                  const detail::Pin& pin,
                                  const Tmid::name_type& tmid_name);
Tmid::name_type DecryptTmidName(const detail::Keyword& keyword,
                                const detail::Pin& pin,
                                const EncryptedTmidName& encrypted_tmid_name);

// PBKDF2 generated location to store Mid/Smid data on network.
Mid::name_type MidName(const detail::Keyword& keyword, const detail::Pin& pin);
Smid::name_type SmidName(const detail::Keyword& keyword, const detail::Pin& pin);

// Methods for serialising/parsing the identity required for data storage.
NonEmptyString SerialisePmid(const Pmid& pmid);
Pmid ParsePmid(const NonEmptyString& serialised_pmid);

namespace test { class PassportTest; }

// The Passport class contains identity types for the various network related tasks available, see
// types.h for details about the identity types.
class Passport {
 public:
  Passport();
  // Method for the initial creation of Fobs.
  void CreateFobs();
  // Copies pending fobs to confirmed fobs and clears pending fobs struct.
  void ConfirmFobs();

  // Serialises Fobs for network storage.
  NonEmptyString Serialise();
  // Parses previously serialised Fobs and intialises data members accordingly.
  void Parse(const NonEmptyString& serialised_passport);

  // Returns the Fob type requested in it's template argument.
  template<typename FobType>
  FobType Get(bool confirmed);

  // Selectable Fob, aka Anmpid & Mpid, manipulation methods. There's no restriction on the number
  // of selectable Fobs an application can create/use.
  template<typename FobType>
  FobType GetSelectableFob(bool confirmed, const NonEmptyString& chosen_name);
  void CreateSelectableFobPair(const NonEmptyString& chosen_name);
  void ConfirmSelectableFobPair(const NonEmptyString& chosen_name);
  void DeleteSelectableFobPair(const NonEmptyString& chosen_name);

  friend class test::PassportTest;

 private:
  Passport(const Passport&);
  Passport& operator=(const Passport&);

  struct Fobs {
    Fobs() : anmid(), ansmid(), antmid(), anmaid(), maid(), pmid() {}
    Fobs(Fobs&& other)
        : anmid(std::move(other.anmid)),
          ansmid(std::move(other.ansmid)),
          antmid(std::move(other.antmid)),
          anmaid(std::move(other.anmaid)),
          maid(std::move(other.maid)),
          pmid(std::move(other.pmid)) {}
    Fobs& operator=(Fobs&& other) {
      anmid = std::move(other.anmid);
      ansmid = std::move(other.ansmid);
      antmid = std::move(other.antmid);
      anmaid = std::move(other.anmaid);
      maid = std::move(other.maid);
      pmid = std::move(other.pmid);
      return *this;
    }
    std::unique_ptr<Anmid> anmid;
    std::unique_ptr<Ansmid> ansmid;
    std::unique_ptr<Antmid> antmid;
    std::unique_ptr<Anmaid> anmaid;
    std::unique_ptr<Maid> maid;
    std::unique_ptr<Pmid> pmid;

   private:
    Fobs(const Fobs&);
    Fobs& operator=(const Fobs&);
  };

  struct SelectableFobPair {
    SelectableFobPair() : anmpid(), mpid() {}
    SelectableFobPair(SelectableFobPair&& other)
        : anmpid(std::move(other.anmpid)),
          mpid(std::move(other.mpid)) {}
    SelectableFobPair& operator=(SelectableFobPair&& other) {
      anmpid = std::move(other.anmpid);
      mpid = std::move(other.mpid);
      return *this;
    }
    std::unique_ptr<Anmpid> anmpid;
    std::unique_ptr<Mpid> mpid;

   private:
#ifdef MAIDSAFE_WIN32
    SelectableFobPair(const SelectableFobPair&);
#else
    SelectableFobPair(const SelectableFobPair&) = delete;
#endif
    SelectableFobPair& operator=(const SelectableFobPair&);
  };

  bool NoFobsNull(bool confirmed);
  template<typename FobType>
  FobType GetFromSelectableFobPair(bool confirmed, const SelectableFobPair& selectable_fob_pair);

  Fobs pending_fobs_, confirmed_fobs_;
  std::map<NonEmptyString, SelectableFobPair> pending_selectable_fobs_, confirmed_selectable_fobs_;
  std::mutex fobs_mutex_, selectable_mutex_;
};

}  // namespace passport
}  // namespace maidsafe

#include "maidsafe/passport/detail/passport-inl.h"

#endif  // MAIDSAFE_PASSPORT_PASSPORT_H_
