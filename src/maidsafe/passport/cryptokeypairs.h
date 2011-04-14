/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Class that generates in thread RSA key pairs and keeps a buffer
                full
* Version:      1.0
* Created:      2010-03-18-00.23.23
* Revision:     none
* Author:       Jose Cisneros
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#ifndef MAIDSAFE_PASSPORT_CRYPTOKEYPAIRS_H_
#define MAIDSAFE_PASSPORT_CRYPTOKEYPAIRS_H_

#include <memory>
#include <list>
#include <vector>
#include "boost/thread.hpp"
#include "maidsafe/common/crypto.h"

namespace maidsafe {

namespace passport {

namespace test { class CachePassport; }

class CryptoKeyPairs {
 public:
  CryptoKeyPairs(const boost::uint16_t &rsa_key_size,
                 const boost::int8_t &max_crypto_thread_count);
  ~CryptoKeyPairs();
  bool StartToCreateKeyPairs(const boost::int16_t &no_of_keypairs);
  bool GetKeyPair(crypto::RsaKeyPair *keypair);
  void Stop();
 private:
  CryptoKeyPairs &operator=(const CryptoKeyPairs&);
  CryptoKeyPairs(const CryptoKeyPairs&);
  friend class test::CachePassport;
  void CreateKeyPair();
  void FinishedCreating();
  const boost::uint16_t kRsaKeySize_;
  const boost::int8_t kMaxCryptoThreadCount_;
  boost::int16_t keypairs_done_, keypairs_todo_, pending_requests_;
  std::list<crypto::RsaKeyPair> keypairs_;
  std::vector< std::shared_ptr<boost::thread> > thrds_;
  boost::mutex keyslist_mutex_, keys_done_mutex_, start_mutex_, req_mutex_;
  boost::condition_variable keys_cond_, req_cond_;
  bool started_, stopping_;
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_CRYPTOKEYPAIRS_H_
