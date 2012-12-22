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

#include "maidsafe/passport/passport.h"

#include <cstdint>
#include <future>

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/detail/fob.h"
#include "maidsafe/passport/detail/identity_data.h"
#include "maidsafe/passport/detail/passport_pb.h"


namespace pb = maidsafe::passport::detail::protobuf;

namespace maidsafe {

namespace passport {

namespace test {

template<typename Fobtype>
bool AllFieldsMatch(const Fobtype& lhs, const Fobtype& rhs) {
  if (lhs.validation_token() != rhs.validation_token() ||
      !rsa::MatchingKeys(lhs.private_key(), rhs.private_key()) ||
      !rsa::MatchingKeys(lhs.public_key(), rhs.public_key()) ||
      lhs.name() != rhs.name())
    return false;
  return true;
}

template<typename Fobtype>
bool NoFieldsMatch(const Fobtype& lhs, const Fobtype& rhs) {
  if (lhs.validation_token() == rhs.validation_token()) {
    LOG(kError) << "Validation tokens match.";
    return false;
  }
  if (rsa::MatchingKeys(lhs.private_key(), rhs.private_key())) {
    LOG(kError) << "Private keys match.";
    return false;
  }
  if (rsa::MatchingKeys(lhs.public_key(), rhs.public_key())) {
    LOG(kError) << "Public keys match.";
    return false;
  }
  if (lhs.name() == rhs.name()) {
    LOG(kError) << "Names match";
    return false;
  }
  return true;
}


struct TestFobs {
  TestFobs(Anmid anmid1, Ansmid ansmid1, Antmid antmid1, Anmaid anmaid1, Maid maid1, Pmid pmid1)
    : anmid(anmid1),
      ansmid(ansmid1),
      antmid(antmid1),
      anmaid(anmaid1),
      maid(maid1),
      pmid(pmid1) {}
    TestFobs(const TestFobs& other)
      : anmid(other.anmid),
        ansmid(other.ansmid),
        antmid(other.antmid),
        anmaid(other.anmaid),
        maid(other.maid),
        pmid(other.pmid) {}

  Anmid anmid;
  Ansmid ansmid;
  Antmid antmid;
  Anmaid anmaid;
  Maid maid;
  Pmid pmid;
};

bool AllFobFieldsMatch(const TestFobs& lhs, const TestFobs& rhs) {
  return (AllFieldsMatch(lhs.anmid, rhs.anmid) &&
          AllFieldsMatch(lhs.ansmid, rhs.ansmid) &&
          AllFieldsMatch(lhs.antmid, rhs.antmid) &&
          AllFieldsMatch(lhs.anmaid, rhs.anmaid) &&
          AllFieldsMatch(lhs.maid, rhs.maid) &&
          AllFieldsMatch(lhs.pmid, rhs.pmid));
}

class PassportTest : public testing::Test {
 public:
  PassportTest()
    : passport_() {}

  TestFobs GetFobs(bool confirmed) {
    return TestFobs(passport_.Get<Anmid>(confirmed),
                    passport_.Get<Ansmid>(confirmed),
                    passport_.Get<Antmid>(confirmed),
                    passport_.Get<Anmaid>(confirmed),
                    passport_.Get<Maid>(confirmed),
                    passport_.Get<Pmid>(confirmed));
  }

 protected:
  Passport passport_;
};

TEST_F(PassportTest, BEH_CreateFobs) {
  passport_.CreateFobs();

  TestFobs old_p_fobs(GetFobs(false));
  EXPECT_THROW(passport_.Get<Anmid>(true), std::exception);
  EXPECT_THROW(passport_.Get<Ansmid>(true), std::exception);
  EXPECT_THROW(passport_.Get<Antmid>(true), std::exception);
  EXPECT_THROW(passport_.Get<Anmaid>(true), std::exception);
  EXPECT_THROW(passport_.Get<Maid>(true), std::exception);
  EXPECT_THROW(passport_.Get<Pmid>(true), std::exception);

  passport_.CreateFobs();

  TestFobs new_p_fobs(GetFobs(false));
  EXPECT_THROW(passport_.Get<Anmid>(true), std::exception);
  EXPECT_THROW(passport_.Get<Ansmid>(true), std::exception);
  EXPECT_THROW(passport_.Get<Antmid>(true), std::exception);
  EXPECT_THROW(passport_.Get<Anmaid>(true), std::exception);
  EXPECT_THROW(passport_.Get<Maid>(true), std::exception);
  EXPECT_THROW(passport_.Get<Pmid>(true), std::exception);

  EXPECT_TRUE(NoFieldsMatch(old_p_fobs.anmid, new_p_fobs.anmid));
  EXPECT_TRUE(NoFieldsMatch(old_p_fobs.ansmid, new_p_fobs.ansmid));
  EXPECT_TRUE(NoFieldsMatch(old_p_fobs.antmid, new_p_fobs.antmid));
  EXPECT_TRUE(NoFieldsMatch(old_p_fobs.anmaid, new_p_fobs.anmaid));
  EXPECT_TRUE(NoFieldsMatch(old_p_fobs.maid, new_p_fobs.maid));
  EXPECT_TRUE(NoFieldsMatch(old_p_fobs.pmid, new_p_fobs.pmid));
}

TEST_F(PassportTest, BEH_ConfirmFobs) {
  passport_.CreateFobs();

  TestFobs old_p_fobs(GetFobs(false));

  passport_.ConfirmFobs();

  TestFobs new_c_fobs(GetFobs(true));

  EXPECT_TRUE(AllFobFieldsMatch(old_p_fobs, new_c_fobs));
}

TEST_F(PassportTest, BEH_CreateConfirmGetSelectableFobs) {
  NonEmptyString chosen_name(RandomAlphaNumericString(1 + RandomUint32() % 100));

  EXPECT_THROW(passport_.GetSelectableFob<Mpid>(false, chosen_name), std::exception);
  EXPECT_THROW(passport_.GetSelectableFob<Anmpid>(false, chosen_name), std::exception);
  EXPECT_THROW(passport_.GetSelectableFob<Mpid>(true, chosen_name), std::exception);
  EXPECT_THROW(passport_.GetSelectableFob<Anmpid>(true, chosen_name), std::exception);

  passport_.CreateSelectableFobPair(chosen_name);

  Mpid p_mpid(passport_.GetSelectableFob<Mpid>(false, chosen_name));
  Anmpid p_anmpid(passport_.GetSelectableFob<Anmpid>(false, chosen_name));
  EXPECT_THROW(passport_.GetSelectableFob<Mpid>(true, chosen_name), std::exception);
  EXPECT_THROW(passport_.GetSelectableFob<Anmpid>(true, chosen_name), std::exception);

  EXPECT_THROW(passport_.CreateSelectableFobPair(chosen_name), std::exception);

  passport_.ConfirmSelectableFobPair(chosen_name);

  EXPECT_THROW(passport_.GetSelectableFob<Mpid>(false, chosen_name), std::exception);
  EXPECT_THROW(passport_.GetSelectableFob<Anmpid>(false, chosen_name), std::exception);
  Mpid c_mpid(passport_.GetSelectableFob<Mpid>(true, chosen_name));
  Anmpid c_anmpid(passport_.GetSelectableFob<Anmpid>(true, chosen_name));

  EXPECT_TRUE(AllFieldsMatch(p_mpid, c_mpid));
  EXPECT_TRUE(AllFieldsMatch(p_anmpid, c_anmpid));

  passport_.CreateSelectableFobPair(chosen_name);
  EXPECT_THROW(passport_.ConfirmSelectableFobPair(chosen_name), std::exception);
}

TEST_F(PassportTest, BEH_DeleteSelectableFobs) {
  NonEmptyString chosen_name(RandomAlphaNumericString(1 + RandomUint32() % 100));

  passport_.DeleteSelectableFobPair(chosen_name);

  EXPECT_NO_THROW(passport_.CreateSelectableFobPair(chosen_name));

  passport_.DeleteSelectableFobPair(chosen_name);

  EXPECT_THROW(passport_.GetSelectableFob<Mpid>(false, chosen_name), std::exception);
  EXPECT_THROW(passport_.GetSelectableFob<Anmpid>(false, chosen_name), std::exception);

  EXPECT_NO_THROW(passport_.CreateSelectableFobPair(chosen_name));
  EXPECT_NO_THROW(passport_.ConfirmSelectableFobPair(chosen_name));

  passport_.DeleteSelectableFobPair(chosen_name);

  EXPECT_THROW(passport_.GetSelectableFob<Mpid>(true, chosen_name), std::exception);
  EXPECT_THROW(passport_.GetSelectableFob<Anmpid>(true, chosen_name), std::exception);

  EXPECT_NO_THROW(passport_.CreateSelectableFobPair(chosen_name));
  EXPECT_NO_THROW(passport_.ConfirmSelectableFobPair(chosen_name));
  EXPECT_NO_THROW(passport_.CreateSelectableFobPair(chosen_name));

  passport_.DeleteSelectableFobPair(chosen_name);

  EXPECT_THROW(passport_.GetSelectableFob<Mpid>(false, chosen_name), std::exception);
  EXPECT_THROW(passport_.GetSelectableFob<Anmpid>(false, chosen_name), std::exception);
  EXPECT_THROW(passport_.GetSelectableFob<Mpid>(true, chosen_name), std::exception);
  EXPECT_THROW(passport_.GetSelectableFob<Anmpid>(true, chosen_name), std::exception);
}

TEST_F(PassportTest, FUNC_MultipleSelectableFobs) {
  std::vector<NonEmptyString> chosen_names;
  uint16_t max_value(40);  // choice of this?
  uint16_t cutoff(20);  // choice of this?
  ASSERT_LE(cutoff, max_value);

  for (uint16_t i(0); i < max_value; ++i) {
    NonEmptyString chosen_name(RandomAlphaNumericString(static_cast<size_t>(i + 1)));
    chosen_names.push_back(chosen_name);
  }

  for (uint16_t i(0); i < cutoff; ++i) {
    passport_.CreateSelectableFobPair(chosen_names.at(i));
  }
  for (uint16_t i(0); i < cutoff; ++i) {
    EXPECT_NO_THROW(passport_.GetSelectableFob<Mpid>(false, chosen_names.at(i)));
    EXPECT_NO_THROW(passport_.GetSelectableFob<Anmpid>(false, chosen_names.at(i)));
  }
  for (uint16_t i(0); i < cutoff; ++i) {
    passport_.ConfirmSelectableFobPair(chosen_names.at(i));
  }

  for (uint16_t i(cutoff); i < max_value; ++i) {
    passport_.CreateSelectableFobPair(chosen_names.at(i));
    passport_.ConfirmSelectableFobPair(chosen_names.at(i));
  }

  for (uint16_t i(0); i < max_value; ++i) {
    EXPECT_NO_THROW(passport_.GetSelectableFob<Mpid>(true, chosen_names.at(i)));
    EXPECT_NO_THROW(passport_.GetSelectableFob<Anmpid>(true, chosen_names.at(i)));
  }
}

class PassportParallelTest : public PassportTest {
 public:
  PassportParallelTest()
    : chosen_name_1_(RandomAlphaNumericString(1 + RandomUint32() % 100)),
      chosen_name_2_(RandomAlphaNumericString(1 + RandomUint32() % 100)),
      chosen_name_3_(RandomAlphaNumericString(1 + RandomUint32() % 100)),
      chosen_name_4_(RandomAlphaNumericString(1 + RandomUint32() % 100)),
      chosen_name_5_(RandomAlphaNumericString(1 + RandomUint32() % 100)) {}

  void TearDown() {
    ConsistentFobStates(false);
    ConsistentFobStates(true);
    ConsistentSelectableFobStates(false, chosen_name_1_);
    ConsistentSelectableFobStates(false, chosen_name_2_);
    ConsistentSelectableFobStates(false, chosen_name_3_);
    ConsistentSelectableFobStates(false, chosen_name_4_);
    ConsistentSelectableFobStates(false, chosen_name_5_);
    ConsistentSelectableFobStates(true, chosen_name_1_);
    ConsistentSelectableFobStates(true, chosen_name_2_);
    ConsistentSelectableFobStates(true, chosen_name_3_);
    ConsistentSelectableFobStates(true, chosen_name_4_);
    ConsistentSelectableFobStates(true, chosen_name_5_);
  }

  void ConsistentFobStates(bool confirmed) {
    try {
      LOG(kInfo) << "Trying ConsistentFobStates...";
      passport_.Get<Anmid>(confirmed);
      EXPECT_NO_THROW(passport_.Get<Ansmid>(confirmed));
      EXPECT_NO_THROW(passport_.Get<Antmid>(confirmed));
      EXPECT_NO_THROW(passport_.Get<Anmaid>(confirmed));
      EXPECT_NO_THROW(passport_.Get<Maid>(confirmed));
      EXPECT_NO_THROW(passport_.Get<Pmid>(confirmed));
      LOG(kInfo) << "...ConsistentFobStates successful (no throw)";
    } catch(const std::exception&) {
      EXPECT_THROW(passport_.Get<Ansmid>(confirmed), std::exception);
      EXPECT_THROW(passport_.Get<Antmid>(confirmed), std::exception);
      EXPECT_THROW(passport_.Get<Anmaid>(confirmed), std::exception);
      EXPECT_THROW(passport_.Get<Maid>(confirmed), std::exception);
      EXPECT_THROW(passport_.Get<Pmid>(confirmed), std::exception);
      LOG(kInfo) << "...ConsistentFobStates successful (throw)";
    }
  }

  void ConsistentSelectableFobStates(bool confirmed, const NonEmptyString& chosen_name) {
    try {
      LOG(kInfo) << "Trying ConsistentSelectableFobStates...";
      passport_.GetSelectableFob<Mpid>(confirmed, chosen_name);
      EXPECT_NO_THROW(passport_.GetSelectableFob<Anmpid>(confirmed, chosen_name));
      LOG(kInfo) << "...ConsistentSelectableFobStates successful (no throw)";
    } catch(const std::exception&) {
      EXPECT_THROW(passport_.GetSelectableFob<Anmpid>(confirmed, chosen_name), std::exception);
      LOG(kInfo) << "...ConsistentSelectableFobStates successful (throw)";
    }
  }

  NonEmptyString chosen_name_1_;
  NonEmptyString chosen_name_2_;
  NonEmptyString chosen_name_3_;
  NonEmptyString chosen_name_4_;
  NonEmptyString chosen_name_5_;
};

TEST_F(PassportParallelTest, FUNC_ParallelCreateConfirmGetDelete) {
  {
    auto a1 = std::async([&] { return passport_.CreateFobs(); });  // NOLINT (Alison)
    auto a2 = std::async([&] { return passport_.CreateSelectableFobPair(chosen_name_1_); });  // NOLINT (Alison)
    auto a3 = std::async([&] { return passport_.CreateSelectableFobPair(chosen_name_2_); });  // NOLINT (Alison)
    auto a4 = std::async([&] { return passport_.CreateSelectableFobPair(chosen_name_5_); });  // NOLINT (Alison)
    a4.get();
    a3.get();
    a2.get();
    a1.get();
  }

  passport_.ConfirmSelectableFobPair(chosen_name_5_);
  TestFobs pending_fobs(GetFobs(false));

  {
    auto a1 = std::async([&] { return passport_.ConfirmFobs(); });                             // NOLINT (Alison)
    auto a2 = std::async([&] { return passport_.ConfirmSelectableFobPair(chosen_name_2_); });  // NOLINT (Alison)
    auto a3 = std::async([&] { return passport_.CreateFobs(); });                              // NOLINT (Alison)
    auto a4 = std::async([&] { return passport_.GetSelectableFob<Anmpid>(false, chosen_name_1_); });  // NOLINT (Alison)
    auto a5 = std::async([&] { return passport_.GetSelectableFob<Mpid>(false, chosen_name_1_); });    // NOLINT (Alison)
    auto a6 = std::async([&] { return passport_.GetSelectableFob<Anmpid>(true, chosen_name_5_); });   // NOLINT (Alison)
    auto a7 = std::async([&] { return passport_.GetSelectableFob<Mpid>(true, chosen_name_5_); });     // NOLINT (Alison)
    a7.get();
    a6.get();
    a5.get();
    a4.get();
    a3.get();
    a2.get();
    a1.get();
  }

  TestFobs confirmed_fobs(GetFobs(true));
  EXPECT_TRUE(AllFobFieldsMatch(pending_fobs, confirmed_fobs));
  passport_.CreateSelectableFobPair(chosen_name_3_);

  {
    auto a1 = std::async([&] { return passport_.CreateSelectableFobPair(chosen_name_4_); });   // NOLINT (Alison)
    auto a2 = std::async([&] { return passport_.ConfirmSelectableFobPair(chosen_name_3_); });  // NOLINT (Alison)
    auto a3 = std::async([&] { return passport_.DeleteSelectableFobPair(chosen_name_1_); });   // NOLINT (Alison)
    auto a4 = std::async([&] { return passport_.DeleteSelectableFobPair(chosen_name_2_); });   // NOLINT (Alison)
    a4.get();
    a3.get();
    a2.get();
    a1.get();
  }

  NonEmptyString string(passport_.Serialise());
  passport_.Parse(string);
}

TEST_F(PassportParallelTest, FUNC_ParallelSerialiseParse) {
  passport_.CreateFobs();
  passport_.ConfirmFobs();
  passport_.CreateSelectableFobPair(chosen_name_1_);
  passport_.ConfirmSelectableFobPair(chosen_name_1_);
  passport_.CreateSelectableFobPair(chosen_name_2_);
  NonEmptyString serialised;
  {
    auto a1 = std::async([&] { return passport_.CreateFobs(); });                              // NOLINT (Alison)
    auto a2 = std::async([&] { return passport_.ConfirmSelectableFobPair(chosen_name_2_); });  // NOLINT (Alison)
    auto a3 = std::async([&] { return passport_.CreateSelectableFobPair(chosen_name_3_); });   // NOLINT (Alison)
    auto a4 = std::async([&] { return passport_.Serialise(); });                               // NOLINT (Alison)
    auto a5 = std::async([&] { return passport_.DeleteSelectableFobPair(chosen_name_1_); });   // NOLINT (Alison)
    a5.get();
    serialised = a4.get();
    a3.get();
    a2.get();
    a1.get();
  }

  passport_.Parse(serialised);
  passport_.CreateSelectableFobPair(chosen_name_1_);
  passport_.CreateSelectableFobPair(chosen_name_5_);
  passport_.ConfirmSelectableFobPair(chosen_name_5_);

  {
    auto a1 = std::async([&] { return passport_.Parse(serialised); });                        // NOLINT (Alison)
    auto a2 = std::async([&] { return passport_.ConfirmFobs(); });                            // NOLINT (Alison)
    auto a3 = std::async([&] { return passport_.CreateSelectableFobPair(chosen_name_4_); });  // NOLINT (Alison)
    auto a4 = std::async([&] { return passport_.GetSelectableFob<Anmpid>(false, chosen_name_1_); });  // NOLINT (Alison)
    auto a5 = std::async([&] { return passport_.GetSelectableFob<Mpid>(false, chosen_name_1_); });    // NOLINT (Alison)
    auto a6 = std::async([&] { return passport_.GetSelectableFob<Anmpid>(true, chosen_name_5_); });   // NOLINT (Alison)
    auto a7 = std::async([&] { return passport_.GetSelectableFob<Mpid>(true, chosen_name_5_); });     // NOLINT (Alison)
    a7.get();
    a6.get();
    a5.get();
    a4.get();
    a3.get();
    a2.get();
    a1.get();
  }

  NonEmptyString string(passport_.Serialise());
  passport_.Parse(string);
}

TEST_F(PassportTest, BEH_SerialiseParseNoSelectables) {
  passport_.CreateFobs();
  passport_.ConfirmFobs();

  TestFobs fobs1(GetFobs(true));

  NonEmptyString serialised(passport_.Serialise());
  passport_.Parse(serialised);

  TestFobs fobs2(GetFobs(true));

  EXPECT_TRUE(AllFobFieldsMatch(fobs1, fobs2));

  NonEmptyString serialised_2(passport_.Serialise());
  EXPECT_EQ(serialised, serialised_2);
  passport_.Parse(serialised);

  TestFobs fobs3(GetFobs(true));

  EXPECT_TRUE(AllFobFieldsMatch(fobs2, fobs3));
}

TEST_F(PassportTest, FUNC_SerialiseParseWithSelectables) {
  passport_.CreateFobs();
  passport_.ConfirmFobs();

  std::vector<NonEmptyString> chosen_names;
  for (uint16_t i(0); i < 20; ++i) {  // choice of max value?
    NonEmptyString chosen_name(RandomAlphaNumericString(static_cast<size_t>(i + 1)));
    passport_.CreateSelectableFobPair(chosen_name);
    passport_.ConfirmSelectableFobPair(chosen_name);
    chosen_names.push_back(chosen_name);
  }

  TestFobs fobs1(GetFobs(true));

  std::vector<Anmpid> anmpids1;
  std::vector<Mpid> mpids1;
  for (auto chosen_name : chosen_names) {
    anmpids1.push_back(passport_.GetSelectableFob<Anmpid>(true, chosen_name));
    mpids1.push_back(passport_.GetSelectableFob<Mpid>(true, chosen_name));
  }

  NonEmptyString serialised(passport_.Serialise());
  passport_.Parse(serialised);

  TestFobs fobs2(GetFobs(true));

  std::vector<Anmpid> anmpids2;
  std::vector<Mpid> mpids2;
  for (auto chosen_name : chosen_names) {
    anmpids2.push_back(passport_.GetSelectableFob<Anmpid>(true, chosen_name));
    mpids2.push_back(passport_.GetSelectableFob<Mpid>(true, chosen_name));
  }

  EXPECT_TRUE(AllFobFieldsMatch(fobs1, fobs2));

  for (uint16_t i(0); i < chosen_names.size(); ++i) {
    EXPECT_TRUE(AllFieldsMatch(anmpids1.at(i), anmpids2.at(i)));
    EXPECT_TRUE(AllFieldsMatch(mpids1.at(i), mpids2.at(i)));
  }

  NonEmptyString serialised_2(passport_.Serialise());
  EXPECT_EQ(serialised, serialised_2);
}

TEST_F(PassportTest, BEH_ParseBadString) {
  NonEmptyString bad_string(RandomAlphaNumericString(1 + RandomUint32() % 1000));
  EXPECT_THROW(passport_.Parse(bad_string), std::exception);
}

class PassportParsePbTest : public PassportTest {
 public:
  PassportParsePbTest()
    : anmid_(),
      ansmid_(),
      antmid_(),
      anmaid_(),
      maid_(anmaid_),
      pmid_(maid_),
      proto_passport_() {}

  void GenerateSixFobs(uint16_t bad_index = 7) {  // generate all good fobs by default
    for (uint16_t i(0); i < 6; ++i) {
      auto proto_fob(proto_passport_.add_fob());
      uint16_t type(i);
      if (i == bad_index) {
        while (type == i)
          type = RandomUint32() % 6;
        LOG(kInfo) << "Entry in position " << bad_index << " will be of type " << type;
      }
      switch (type) {
        case 0:
          anmid_.ToProtobuf(proto_fob);
          break;
        case 1:
          ansmid_.ToProtobuf(proto_fob);
          break;
        case 2:
          antmid_.ToProtobuf(proto_fob);
          break;
        case 3:
          anmaid_.ToProtobuf(proto_fob);
          break;
        case 4:
          maid_.ToProtobuf(proto_fob);
          break;
        case 5:
          pmid_.ToProtobuf(proto_fob);
          break;
        default:
          LOG(kError) << "Type " << type << " is not permitted here.";
      }
    }
  }

  Anmid anmid_;
  Ansmid ansmid_;
  Antmid antmid_;
  Anmaid anmaid_;
  Maid maid_;
  Pmid pmid_;
  pb::Passport proto_passport_;
};

TEST_F(PassportParsePbTest, BEH_GoodProtobuf) {
  GenerateSixFobs();

  NonEmptyString chosen_name(RandomAlphaNumericString(1 + RandomUint32() % 20));
  Anmpid anmpid;
  Mpid mpid(chosen_name, anmpid);

  auto proto_public_identity(proto_passport_.add_public_identity());
  proto_public_identity->set_public_id(chosen_name.string());
  auto proto_anmpid(proto_public_identity->mutable_anmpid());
  anmpid.ToProtobuf(proto_anmpid);
  auto proto_mpid(proto_public_identity->mutable_mpid());
  mpid.ToProtobuf(proto_mpid);

  NonEmptyString string(proto_passport_.SerializeAsString());
  EXPECT_NO_THROW(passport_.Parse(string));
}

TEST_F(PassportParsePbTest, BEH_FiveFobs) {
  auto proto_fob(proto_passport_.add_fob());
  anmid_.ToProtobuf(proto_fob);
  proto_fob = proto_passport_.add_fob();
  ansmid_.ToProtobuf(proto_fob);
  proto_fob = proto_passport_.add_fob();
  antmid_.ToProtobuf(proto_fob);
  proto_fob = proto_passport_.add_fob();
  anmaid_.ToProtobuf(proto_fob);
  proto_fob = proto_passport_.add_fob();
  maid_.ToProtobuf(proto_fob);

  NonEmptyString string(proto_passport_.SerializeAsString());
  EXPECT_THROW(passport_.Parse(string), std::exception);
}

TEST_F(PassportParsePbTest, BEH_SevenFobs) {
  GenerateSixFobs();
  auto proto_fob(proto_passport_.add_fob());
  pmid_.ToProtobuf(proto_fob);

  NonEmptyString string(proto_passport_.SerializeAsString());
  EXPECT_THROW(passport_.Parse(string), std::exception);
}

TEST_F(PassportParsePbTest, BEH_ParseReorderedFobs) {
  GenerateSixFobs(RandomUint32() % 6);

  NonEmptyString string(proto_passport_.SerializeAsString());
  EXPECT_THROW(passport_.Parse(string), std::exception);
}

class PassportParsePbSelectableTest : public PassportParsePbTest {
  void SetUp() {
    auto proto_fob(proto_passport_.add_fob());
    anmid_.ToProtobuf(proto_fob);
    proto_fob = proto_passport_.add_fob();
    ansmid_.ToProtobuf(proto_fob);
    proto_fob = proto_passport_.add_fob();
    antmid_.ToProtobuf(proto_fob);
    proto_fob = proto_passport_.add_fob();
    anmaid_.ToProtobuf(proto_fob);
    proto_fob = proto_passport_.add_fob();
    maid_.ToProtobuf(proto_fob);
    proto_fob = proto_passport_.add_fob();
    pmid_.ToProtobuf(proto_fob);
  }
};

TEST_F(PassportParsePbSelectableTest, BEH_GoodProtobuf) {
  NonEmptyString string(proto_passport_.SerializeAsString());
  EXPECT_NO_THROW(passport_.Parse(string));
}

TEST(PassportIndependentSerialiseTest, BEH_Uninitialised) {
  pb::Passport proto_passport;
  EXPECT_THROW(NonEmptyString(proto_passport.SerializeAsString()), std::exception);
}

class PassportSerialiseTest : public testing::Test {
 public:
  PassportSerialiseTest()
    : anmid_(),
      ansmid_(),
      antmid_(),
      anmaid_(),
      maid_(anmaid_),
      pmid_(maid_),
      proto_passport_() {}

  void SetUp() {
    auto proto_fob(proto_passport_.add_fob());
    anmid_.ToProtobuf(proto_fob);
    proto_fob = proto_passport_.add_fob();
    ansmid_.ToProtobuf(proto_fob);
    proto_fob = proto_passport_.add_fob();
    antmid_.ToProtobuf(proto_fob);
    proto_fob = proto_passport_.add_fob();
    anmaid_.ToProtobuf(proto_fob);
    proto_fob = proto_passport_.add_fob();
    maid_.ToProtobuf(proto_fob);
    proto_fob = proto_passport_.add_fob();
    pmid_.ToProtobuf(proto_fob);
  }

  Anmid anmid_;
  Ansmid ansmid_;
  Antmid antmid_;
  Anmaid anmaid_;
  Maid maid_;
  Pmid pmid_;
  pb::Passport proto_passport_;
};

TEST_F(PassportSerialiseTest, BEH_GoodProtobuf) {
  EXPECT_NO_THROW(NonEmptyString(proto_passport_.SerializeAsString()));
}

TEST_F(PassportSerialiseTest, BEH_NoChosenName) {
  Anmpid anmpid;
  EXPECT_THROW(Mpid mpid_bad(NonEmptyString(), anmpid), std::exception);
  Mpid mpid(NonEmptyString(RandomAlphaNumericString(1 + RandomUint32() % 100)), anmpid);

  auto proto_public_identity(proto_passport_.add_public_identity());
  auto proto_anmpid(proto_public_identity->mutable_anmpid());
  anmpid.ToProtobuf(proto_anmpid);
  auto proto_mpid(proto_public_identity->mutable_mpid());
  mpid.ToProtobuf(proto_mpid);

  EXPECT_THROW(NonEmptyString(proto_passport_.SerializeAsString()), std::exception);
}

TEST_F(PassportSerialiseTest, BEH_NoAnmpid) {
  NonEmptyString chosen_name(RandomAlphaNumericString(1 + RandomUint32() % 20));
  Anmpid anmpid;
  Mpid mpid(chosen_name, anmpid);

  auto proto_public_identity(proto_passport_.add_public_identity());
  proto_public_identity->set_public_id(chosen_name.string());
  auto proto_mpid(proto_public_identity->mutable_mpid());
  mpid.ToProtobuf(proto_mpid);

  EXPECT_THROW(NonEmptyString(proto_passport_.SerializeAsString()), std::exception);
}

TEST_F(PassportSerialiseTest, BEH_NoMpid) {
  NonEmptyString chosen_name(RandomAlphaNumericString(1 + RandomUint32() % 20));
  Anmpid anmpid;

  auto proto_public_identity(proto_passport_.add_public_identity());
  proto_public_identity->set_public_id(chosen_name.string());
  auto proto_anmpid(proto_public_identity->mutable_anmpid());
  anmpid.ToProtobuf(proto_anmpid);

  EXPECT_THROW(NonEmptyString(proto_passport_.SerializeAsString()), std::exception);
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
