/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Test for CryptoKeyPairs class
* Version:      1.0
* Created:      2010-03-15-17.21.51
* Revision:     none
* Compiler:     gcc
* Author:       Fraser Hutchison (fh), fraser.hutchison@maidsafe.net
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

#include "gtest/gtest.h"
#include "maidsafe/passport/cryptokeypairs.h"

namespace maidsafe {

namespace passport {

namespace test {

const boost::uint16_t kRsaKeySize(4096);
const boost::uint8_t kMaxThreadCount(5);

TEST(CryptoKeyPairsTest, BEH_PASSPORT_GetCryptoKey) {
  CryptoKeyPairs ckp(kRsaKeySize, kMaxThreadCount);
  crypto::RsaKeyPair kp;
  ASSERT_FALSE(ckp.GetKeyPair(&kp));
  ASSERT_TRUE(ckp.StartToCreateKeyPairs(1));
  ASSERT_TRUE(ckp.GetKeyPair(&kp));
  ASSERT_FALSE(kp.public_key().empty());
  ASSERT_FALSE(kp.private_key().empty());
}

TEST(CryptoKeyPairsTest, FUNC_PASSPORT_GetMultipleCryptoKeys) {
  CryptoKeyPairs ckp(kRsaKeySize, kMaxThreadCount);
  boost::int16_t no_of_keys = 20;
  std::vector<crypto::RsaKeyPair> kps;
  ASSERT_TRUE(ckp.StartToCreateKeyPairs(no_of_keys));
  ASSERT_FALSE(ckp.StartToCreateKeyPairs(no_of_keys));

  boost::this_thread::sleep(boost::posix_time::seconds(1));
  crypto::RsaKeyPair kp;
  while (ckp.GetKeyPair(&kp)) {
    kps.push_back(kp);
    ASSERT_FALSE(kp.public_key().empty());
    ASSERT_FALSE(kp.private_key().empty());
    kp.ClearKeys();
    boost::this_thread::sleep(boost::posix_time::seconds(1));
  }
  ASSERT_EQ(static_cast<size_t>(no_of_keys), kps.size());
}

TEST(CryptoKeyPairsTest, FUNC_PASSPORT_ReuseObject) {
  CryptoKeyPairs ckp(kRsaKeySize, kMaxThreadCount);
  boost::int16_t no_of_keys(5);
  std::vector<crypto::RsaKeyPair> kps;
  ASSERT_TRUE(ckp.StartToCreateKeyPairs(no_of_keys));
  ASSERT_FALSE(ckp.StartToCreateKeyPairs(no_of_keys));

  boost::this_thread::sleep(boost::posix_time::seconds(1));
  crypto::RsaKeyPair kp;
  boost::int16_t i(0), keys_rec(3);
  while (ckp.GetKeyPair(&kp)) {
    if (i == keys_rec)
      break;
    kps.push_back(kp);
    ASSERT_FALSE(kp.public_key().empty());
    ASSERT_FALSE(kp.private_key().empty());
    kp.ClearKeys();
    ++i;
    boost::this_thread::sleep(boost::posix_time::seconds(1));
  }

  while (!ckp.StartToCreateKeyPairs(no_of_keys))
    boost::this_thread::sleep(boost::posix_time::seconds(1));

  while (ckp.GetKeyPair(&kp)) {
    kps.push_back(kp);
    ASSERT_FALSE(kp.public_key().empty());
    ASSERT_FALSE(kp.private_key().empty());
    kp.ClearKeys();
    boost::this_thread::sleep(boost::posix_time::seconds(1));
  }
  ASSERT_EQ(static_cast<size_t>(no_of_keys + keys_rec), kps.size());
}

void GetKeys(CryptoKeyPairs *ckp, int *counter, const boost::int16_t &total) {
  for (int i = 0; i < total; ++i) {
    crypto::RsaKeyPair kp;
    while (!ckp->GetKeyPair(&kp)) {
      kp.ClearKeys();
      if (ckp->StartToCreateKeyPairs(total)) {
      }
    }
    ASSERT_FALSE(kp.private_key().empty());
    ASSERT_FALSE(kp.public_key().empty());
    ++(*counter);
  }
}

TEST(CryptoKeyPairsTest, FUNC_PASSPORT_AccessFromDiffThreads) {
  CryptoKeyPairs ckp(kRsaKeySize, kMaxThreadCount);
  boost::int16_t no_of_keys(6), no_of_thrds(4);
  std::vector<crypto::RsaKeyPair> kps;
  ASSERT_TRUE(ckp.StartToCreateKeyPairs(no_of_keys));
  boost::thread_group thrds;
  std::vector<int> keys_gen(no_of_thrds, 0);
  for (int i = 0; i < no_of_thrds; ++i) {
    thrds.create_thread(boost::bind(&GetKeys, &ckp, &keys_gen[i], no_of_keys));
  }
  thrds.join_all();
  for (int i = 0; i < no_of_thrds; ++i) {
    ASSERT_EQ(no_of_keys, keys_gen[i]);
  }
}

void GetKeyPair(CryptoKeyPairs *ckp, int *counter) {
  crypto::RsaKeyPair kp;
  if (ckp->GetKeyPair(&kp)) {
    ASSERT_FALSE(kp.private_key().empty());
    ASSERT_FALSE(kp.public_key().empty());
    ++(*counter);
  }
}

TEST(CryptoKeyPairsTest, BEH_PASSPORT_DestroyObjectWhileGenKeys) {
  CryptoKeyPairs *ckp = new CryptoKeyPairs(kRsaKeySize, kMaxThreadCount);
  ckp->StartToCreateKeyPairs(20);
  boost::this_thread::sleep(boost::posix_time::seconds(3));
  delete ckp;
}

TEST(CryptoKeyPairsTest, BEH_PASSPORT_DestroyObjectWithGetKeyReq) {
  CryptoKeyPairs *ckp = new CryptoKeyPairs(kRsaKeySize, kMaxThreadCount);
  ckp->StartToCreateKeyPairs(1);
  boost::thread_group thrds;
  int counter = 0;
  for (int i = 0; i < 3; ++i) {
    thrds.create_thread(boost::bind(&GetKeyPair, ckp, &counter));
  }
  boost::this_thread::sleep(boost::posix_time::seconds(1));
  delete ckp;
  thrds.join_all();
  ASSERT_EQ(1, counter);
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
