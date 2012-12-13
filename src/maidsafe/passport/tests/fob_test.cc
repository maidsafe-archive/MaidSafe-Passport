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


#include <string>

#include "maidsafe/common/test.h"

#include "maidsafe/passport/types.h"


namespace maidsafe {

namespace passport {

namespace test {

class FobTest : public testing::Test {
};

TEST_F(FobTest, BEH_FobGenerationAndValidation) {
  maidsafe::test::RunInParallel(6, [=] {
      Anmid anmid;
      Ansmid ansmid;
      Antmid antmid;
      Anmaid anmaid;
      Maid maid(anmaid);
      Pmid pmid(maid);
      Mid mid(anmid);
      Smid smid(ansmid);
      Tmid tmid(antmid);
      Stmid stmid(antmid);
      Anmpid anmpid;
      Mpid mpid(anmpid);
  });
}

//TEST_F(FobTest, BEH_FobSerialisationAndParsing) {
//  maidsafe::test::RunInParallel(6, [=] {
//      Fob ring(GenerateFob(nullptr));
//      NonEmptyString serialised_ring1(SerialiseFob(ring));
//      NonEmptyString serialised_ring2(SerialiseFob(ring));
//      ASSERT_EQ(serialised_ring1.string(), serialised_ring2.string());
//      Fob re_ring1(ParseFob(serialised_ring2));
//      Fob re_ring2(ParseFob(serialised_ring1));
//      ASSERT_EQ(re_ring1.identity.string(), re_ring2.identity.string());
//      ASSERT_EQ(re_ring1.validation_token.string(), re_ring2.validation_token.string());
//      ASSERT_TRUE(asymm::MatchingKeys(re_ring1.keys.public_key, re_ring2.keys.public_key));
//      ASSERT_TRUE(asymm::MatchingKeys(re_ring1.keys.private_key, re_ring2.keys.private_key));
//  });
//}
//
}  // namespace test

}  // namespace passport

}  // namespace maidsafe
