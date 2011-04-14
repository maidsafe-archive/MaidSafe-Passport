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

#include "maidsafe/passport/cryptokeypairs.h"
#include <functional>

namespace maidsafe {

namespace passport {

CryptoKeyPairs::CryptoKeyPairs(const boost::uint16_t &rsa_key_size,
                               const boost::int8_t &max_crypto_thread_count)
    : kRsaKeySize_(rsa_key_size),
      kMaxCryptoThreadCount_(max_crypto_thread_count),
      keypairs_done_(0),
      keypairs_todo_(0),
      pending_requests_(0),
      keypairs_(),
      thrds_(kMaxCryptoThreadCount_, std::shared_ptr<boost::thread>()),
      keyslist_mutex_(),
      keys_done_mutex_(),
      start_mutex_(),
      req_mutex_(),
      keys_cond_(),
      req_cond_(),
      started_(false),
      stopping_(false) {}

CryptoKeyPairs::~CryptoKeyPairs() {
  Stop();
}

bool CryptoKeyPairs::StartToCreateKeyPairs(
    const boost::int16_t &no_of_keypairs) {
  {
    boost::mutex::scoped_lock lock(start_mutex_);
    if (started_)
      return false;
    started_ = true;
    stopping_ = false;
  }
  keypairs_todo_ = no_of_keypairs;
  keypairs_done_ = keypairs_.size();
  boost::int16_t keys_needed = keypairs_todo_ - keypairs_done_;
  boost::int16_t i = 0;
  for (auto it = thrds_.begin(); it != thrds_.end() && i < keys_needed; ++it) {
    try {
      it->reset(new boost::thread(&CryptoKeyPairs::CreateKeyPair, this));
      ++i;
    }
    catch(const boost::thread_resource_error&) {
      break;
    }
  }
  if (i == 0) {
    started_ = false;
  }
  return started_;
}

void CryptoKeyPairs::CreateKeyPair() {
  boost::this_thread::at_thread_exit(
      std::bind(&CryptoKeyPairs::FinishedCreating, this));
  bool work_todo = true;
  while (work_todo && !stopping_) {
    crypto::RsaKeyPair rsakp;
    rsakp.GenerateKeys(kRsaKeySize_);
    {
      boost::mutex::scoped_lock lock(keyslist_mutex_);
      keypairs_.push_back(rsakp);
    }
    keys_cond_.notify_all();
    {
      boost::mutex::scoped_lock lock(keys_done_mutex_);
      ++keypairs_done_;
      if (kMaxCryptoThreadCount_ - (keypairs_todo_ - keypairs_done_) > 0) {
        work_todo = false;
      }
    }
  }
}

void CryptoKeyPairs::FinishedCreating() {
  bool finished = false;
  {
    boost::mutex::scoped_lock lock(keys_done_mutex_);
    if (keypairs_todo_ == keypairs_done_)
      finished = true;
  }
  if (finished) {
    boost::mutex::scoped_lock lock(start_mutex_);
    started_ = false;
  }
  keys_cond_.notify_all();
}

bool CryptoKeyPairs::GetKeyPair(crypto::RsaKeyPair *keypair) {
  bool result;
  // All keys that were asked for have been created, all threads have finished
  if (!started_) {
    boost::mutex::scoped_lock lock(keyslist_mutex_);
    if (keypairs_.empty()) {
      result = false;
    } else {
      *keypair = keypairs_.front();
      keypairs_.pop_front();
      result = true;
    }
  } else {
    {
      boost::mutex::scoped_lock lock(req_mutex_);
      ++pending_requests_;
    }
    {
      boost::mutex::scoped_lock lock(keyslist_mutex_);
      while (keypairs_.empty() && started_) {
        keys_cond_.wait(lock);
      }
      if (!keypairs_.empty()) {
        *keypair = keypairs_.front();
        keypairs_.pop_front();
        result = true;
      } else {
        result = false;
      }
    }
    {
      boost::mutex::scoped_lock lock(req_mutex_);
      --pending_requests_;
      if (stopping_) {
        req_cond_.notify_one();
      }
    }
  }
  return result;
}

void CryptoKeyPairs::Stop() {
  stopping_ = true;
  for (auto it = thrds_.begin(); it != thrds_.end(); ++it) {
    if (*it) {
      (*it)->join();
    }
  }
  // waiting for pending requests to exit
  {
    boost::mutex::scoped_lock lock(req_mutex_);
    while (pending_requests_ > 0) {
      req_cond_.timed_wait(lock, boost::posix_time::seconds(10));
    }
  }
}

}  // namespace passport

}  // namespace maidsafe
