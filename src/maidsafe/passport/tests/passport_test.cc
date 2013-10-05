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

#include "maidsafe/passport/passport.h"

#include <cstdint>
#include <future>
#include <memory>

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/detail/fob.h"
#include "maidsafe/passport/detail/identity_data.h"
#include "maidsafe/passport/detail/passport.pb.h"

namespace pb = maidsafe::passport::detail::protobuf;

namespace maidsafe {

namespace passport {

namespace test {

template <typename Fobtype>
bool AllFieldsMatch(const Fobtype& lhs, const Fobtype& rhs) {
  return (lhs.validation_token() == rhs.validation_token() &&
      rsa::MatchingKeys(lhs.private_key(), rhs.private_key()) &&
      rsa::MatchingKeys(lhs.public_key(), rhs.public_key()) &&
      lhs.name() == rhs.name());
}

template <typename Fobtype>
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
      : anmid(std::move(anmid1)),
        ansmid(std::move(ansmid1)),
        antmid(std::move(antmid1)),
        anmaid(std::move(anmaid1)),
        maid(std::move(maid1)),
        pmid(std::move(pmid1)) {}
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
  return (AllFieldsMatch(lhs.anmid, rhs.anmid) && AllFieldsMatch(lhs.ansmid, rhs.ansmid) &&
          AllFieldsMatch(lhs.antmid, rhs.antmid) && AllFieldsMatch(lhs.anmaid, rhs.anmaid) &&
          AllFieldsMatch(lhs.maid, rhs.maid) && AllFieldsMatch(lhs.pmid, rhs.pmid));
}

class PassportTest : public testing::Test {
 public:
  PassportTest() : passport_() {}

  TestFobs GetFobs() {
    return TestFobs(passport_.Get<Anmid>(), passport_.Get<Ansmid>(), passport_.Get<Antmid>(),
                    passport_.Get<Anmaid>(), passport_.Get<Maid>(), passport_.Get<Pmid>());
  }

  TestFobs GetFobs(Passport& passport) {
    return TestFobs(passport.Get<Anmid>(), passport.Get<Ansmid>(), passport.Get<Antmid>(),
                    passport.Get<Anmaid>(), passport.Get<Maid>(), passport.Get<Pmid>());
  }

 protected:
  Passport passport_;
};

TEST_F(PassportTest, BEH_Construct) {
  Passport constucted_passport;

  EXPECT_NO_THROW(passport_.Get<Anmid>());
  EXPECT_NO_THROW(passport_.Get<Ansmid>());
  EXPECT_NO_THROW(passport_.Get<Antmid>());
  EXPECT_NO_THROW(passport_.Get<Anmaid>());
  EXPECT_NO_THROW(passport_.Get<Maid>());
  EXPECT_NO_THROW(passport_.Get<Pmid>());
  TestFobs fobs(GetFobs());

  EXPECT_NO_THROW(constucted_passport.Get<Anmid>());
  EXPECT_NO_THROW(constucted_passport.Get<Ansmid>());
  EXPECT_NO_THROW(constucted_passport.Get<Antmid>());
  EXPECT_NO_THROW(constucted_passport.Get<Anmaid>());
  EXPECT_NO_THROW(constucted_passport.Get<Maid>());
  EXPECT_NO_THROW(constucted_passport.Get<Pmid>());
  TestFobs constructed_fobs(GetFobs(constucted_passport));

  EXPECT_TRUE(NoFieldsMatch(fobs.anmid, constructed_fobs.anmid));
  EXPECT_TRUE(NoFieldsMatch(fobs.ansmid, constructed_fobs.ansmid));
  EXPECT_TRUE(NoFieldsMatch(fobs.antmid, constructed_fobs.antmid));
  EXPECT_TRUE(NoFieldsMatch(fobs.anmaid, constructed_fobs.anmaid));
  EXPECT_TRUE(NoFieldsMatch(fobs.maid, constructed_fobs.maid));
  EXPECT_TRUE(NoFieldsMatch(fobs.pmid, constructed_fobs.pmid));

  Passport moved_passport(std::move(passport_));

  EXPECT_THROW(passport_.Get<Anmid>(), std::exception);
  EXPECT_THROW(passport_.Get<Ansmid>(), std::exception);
  EXPECT_THROW(passport_.Get<Antmid>(), std::exception);
  EXPECT_THROW(passport_.Get<Anmaid>(), std::exception);
  EXPECT_THROW(passport_.Get<Maid>(), std::exception);
  EXPECT_THROW(passport_.Get<Pmid>(), std::exception);

  EXPECT_NO_THROW(moved_passport.Get<Anmid>());
  EXPECT_NO_THROW(moved_passport.Get<Ansmid>());
  EXPECT_NO_THROW(moved_passport.Get<Antmid>());
  EXPECT_NO_THROW(moved_passport.Get<Anmaid>());
  EXPECT_NO_THROW(moved_passport.Get<Maid>());
  EXPECT_NO_THROW(moved_passport.Get<Pmid>());
  TestFobs moved_fobs(GetFobs(moved_passport));

  EXPECT_TRUE(AllFieldsMatch(fobs.anmid, moved_fobs.anmid));
  EXPECT_TRUE(AllFieldsMatch(fobs.ansmid, moved_fobs.ansmid));
  EXPECT_TRUE(AllFieldsMatch(fobs.antmid, moved_fobs.antmid));
  EXPECT_TRUE(AllFieldsMatch(fobs.anmaid, moved_fobs.anmaid));
  EXPECT_TRUE(AllFieldsMatch(fobs.maid, moved_fobs.maid));
  EXPECT_TRUE(AllFieldsMatch(fobs.pmid, moved_fobs.pmid));
}

TEST_F(PassportTest, BEH_CreateGetSelectableFobs) {
  NonEmptyString name(RandomAlphaNumericString(1 + RandomUint32() % 100));

  EXPECT_THROW(passport_.GetSelectableFob<Mpid>(name), std::exception);
  EXPECT_THROW(passport_.GetSelectableFob<Anmpid>(name), std::exception);

  passport_.CreateSelectableFobPair(name);

  EXPECT_NO_THROW(passport_.GetSelectableFob<Mpid>(name));
  EXPECT_NO_THROW(passport_.GetSelectableFob<Anmpid>(name));

  EXPECT_THROW(passport_.CreateSelectableFobPair(name), std::exception);
}

TEST_F(PassportTest, BEH_DeleteSelectableFobs) {
  NonEmptyString name(RandomAlphaNumericString(1 + RandomUint32() % 100));

  passport_.DeleteSelectableFobPair(name);

  EXPECT_NO_THROW(passport_.CreateSelectableFobPair(name));

  passport_.DeleteSelectableFobPair(name);

  EXPECT_THROW(passport_.GetSelectableFob<Mpid>(name), std::exception);
  EXPECT_THROW(passport_.GetSelectableFob<Anmpid>(name), std::exception);

  EXPECT_NO_THROW(passport_.CreateSelectableFobPair(name));

  passport_.DeleteSelectableFobPair(name);

  EXPECT_THROW(passport_.GetSelectableFob<Mpid>(name), std::exception);
  EXPECT_THROW(passport_.GetSelectableFob<Anmpid>(name), std::exception);

  EXPECT_NO_THROW(passport_.CreateSelectableFobPair(name));
  EXPECT_THROW(passport_.CreateSelectableFobPair(name), std::exception);

  EXPECT_NO_THROW(passport_.GetSelectableFob<Mpid>(name));
  EXPECT_NO_THROW(passport_.GetSelectableFob<Anmpid>(name));

  passport_.DeleteSelectableFobPair(name);

  EXPECT_THROW(passport_.GetSelectableFob<Mpid>(name), std::exception);
  EXPECT_THROW(passport_.GetSelectableFob<Anmpid>(name), std::exception);
}

TEST_F(PassportTest, FUNC_MultipleSelectableFobs) {
  std::vector<NonEmptyString> names;
  uint16_t max_value(40);  // choice of this?
  uint16_t cutoff(20);     // choice of this?
  ASSERT_LE(cutoff, max_value);

  for (uint16_t i(0); i < max_value; ++i) {
    NonEmptyString name(RandomAlphaNumericString(static_cast<size_t>(i + 1)));
    names.push_back(name);
  }

  for (uint16_t i(0); i < cutoff; ++i) {
    passport_.CreateSelectableFobPair(names.at(i));
  }
  for (uint16_t i(0); i < cutoff; ++i) {
    EXPECT_NO_THROW(passport_.GetSelectableFob<Mpid>(names.at(i)));
    EXPECT_NO_THROW(passport_.GetSelectableFob<Anmpid>(names.at(i)));
  }

  for (uint16_t i(cutoff); i < max_value; ++i) {
    passport_.CreateSelectableFobPair(names.at(i));
  }

  for (uint16_t i(0); i < max_value; ++i) {
    EXPECT_NO_THROW(passport_.GetSelectableFob<Mpid>(names.at(i)));
    EXPECT_NO_THROW(passport_.GetSelectableFob<Anmpid>(names.at(i)));
  }
}

class PassportParallelTest : public PassportTest {
 public:
  PassportParallelTest()
      : name_1_(RandomAlphaNumericString(1 + RandomUint32() % 100)),
        name_2_(RandomAlphaNumericString(1 + RandomUint32() % 100)),
        name_3_(RandomAlphaNumericString(1 + RandomUint32() % 100)),
        name_4_(RandomAlphaNumericString(1 + RandomUint32() % 100)),
        name_5_(RandomAlphaNumericString(1 + RandomUint32() % 100)) {}

  void TearDown() override {
    ConsistentFobStates();
    ConsistentSelectableFobStates(name_1_);
    ConsistentSelectableFobStates(name_2_);
    ConsistentSelectableFobStates(name_3_);
    ConsistentSelectableFobStates(name_4_);
    ConsistentSelectableFobStates(name_5_);
  }

  void ConsistentFobStates() {
    try {
      LOG(kInfo) << "Trying ConsistentFobStates...";
      passport_.Get<Anmid>();
      passport_.Get<Ansmid>();
      passport_.Get<Antmid>();
      passport_.Get<Anmaid>();
      passport_.Get<Maid>();
      passport_.Get<Pmid>();
      LOG(kInfo) << "...ConsistentFobStates successful";
    }
    catch (const std::exception&) {
      LOG(kInfo) << "...ConsistentFobStates unsuccessful";
    }
  }

  void ConsistentSelectableFobStates(const NonEmptyString& name) {
    try {
      LOG(kInfo) << "Trying ConsistentSelectableFobStates...";
      passport_.GetSelectableFob<Mpid>(name);
      passport_.GetSelectableFob<Anmpid>(name);
      LOG(kInfo) << "...ConsistentSelectableFobStates successful";
    }
    catch (const std::exception&) {
      LOG(kInfo) << "...ConsistentSelectableFobStates successful";
    }
  }

  NonEmptyString name_1_;
  NonEmptyString name_2_;
  NonEmptyString name_3_;
  NonEmptyString name_4_;
  NonEmptyString name_5_;
};

TEST_F(PassportParallelTest, FUNC_ParallelGetDelete) {
  {
    auto a1 = std::async([&] { return passport_.CreateSelectableFobPair(name_1_); });
    auto a2 = std::async([&] { return passport_.CreateSelectableFobPair(name_2_); });
    auto a3 = std::async([&] { return passport_.CreateSelectableFobPair(name_5_); });
    a3.get();
    a2.get();
    a1.get();
  }

  TestFobs fobs(GetFobs());

  {
    auto a1 = std::async([&] { return passport_.GetSelectableFob<Anmpid>(name_1_); });
    auto a2 = std::async([&] {
      return std::make_shared<Mpid>(passport_.GetSelectableFob<Mpid>(name_1_));
    });
    auto a3 = std::async([&] { return passport_.GetSelectableFob<Anmpid>(name_5_); });
    auto a4 = std::async([&] {
      return std::make_shared<Mpid>(passport_.GetSelectableFob<Mpid>(name_5_));
    });
    a4.get();
    a3.get();
    a2.get();
    a1.get();
  }

  TestFobs identical_fobs(GetFobs());
  EXPECT_TRUE(AllFobFieldsMatch(fobs, identical_fobs));
  passport_.CreateSelectableFobPair(name_3_);

  {
    auto a1 = std::async([&] { return passport_.CreateSelectableFobPair(name_4_); });
    auto a2 = std::async([&] { return passport_.DeleteSelectableFobPair(name_1_); });
    auto a3 = std::async([&] { return passport_.DeleteSelectableFobPair(name_2_); });
    a3.get();
    a2.get();
    a1.get();
  }

  EXPECT_NO_THROW(Passport test(Passport(passport_.Serialise())));
}

TEST_F(PassportParallelTest, FUNC_ParallelSerialiseParse) {
  passport_.CreateSelectableFobPair(name_1_);
  passport_.CreateSelectableFobPair(name_2_);
  NonEmptyString serialised;
  {
    auto a1 = std::async([&] { return passport_.CreateSelectableFobPair(name_3_); });
    auto a2 = std::async([&] { return passport_.Serialise(); });
    auto a3 = std::async([&] { return passport_.DeleteSelectableFobPair(name_1_); });
    a3.get();
    serialised = a2.get();
    a1.get();
  }

  EXPECT_NO_THROW(TestFobs fobs(GetFobs()));

  Passport passport(serialised);

  passport.CreateSelectableFobPair(name_5_);

  {
    auto a1 = std::async([&] { return passport.CreateSelectableFobPair(name_4_); });
    auto a2 = std::async([&] { return passport.GetSelectableFob<Anmpid>(name_5_); });
    auto a3 = std::async([&] {
      return std::make_shared<Mpid>(passport.GetSelectableFob<Mpid>(name_5_));
    });
    a3.get();
    a2.get();
    a1.get();
  }

  EXPECT_NO_THROW(Passport test(passport_.Serialise()));
}

TEST_F(PassportTest, BEH_SerialiseParseNoSelectables) {
  TestFobs fobs1(GetFobs());

  EXPECT_NO_THROW(Passport test(Passport(passport_.Serialise())));

  TestFobs fobs2(GetFobs());

  EXPECT_TRUE(AllFobFieldsMatch(fobs1, fobs2));

  NonEmptyString serialised_2(passport_.Serialise());
  EXPECT_EQ(passport_.Serialise(), serialised_2);

  TestFobs fobs3(GetFobs());

  EXPECT_TRUE(AllFobFieldsMatch(fobs2, fobs3));
}

TEST_F(PassportTest, FUNC_SerialiseParseWithSelectables) {
  std::vector<NonEmptyString> names;
  for (uint16_t i(0); i < 20; ++i) {  // choice of max value?
    NonEmptyString name(RandomAlphaNumericString(static_cast<size_t>(i + 1)));
    passport_.CreateSelectableFobPair(name);
    names.push_back(name);
  }

  TestFobs fobs1(GetFobs());

  std::vector<Anmpid> anmpids1;
  std::vector<Mpid> mpids1;
  for (auto name : names) {
    anmpids1.push_back(passport_.GetSelectableFob<Anmpid>(name));
    mpids1.push_back(passport_.GetSelectableFob<Mpid>(name));
  }

  EXPECT_NO_THROW(Passport test(Passport(passport_.Serialise())));

  TestFobs fobs2(GetFobs());

  std::vector<Anmpid> anmpids2;
  std::vector<Mpid> mpids2;
  for (auto name : names) {
    anmpids2.push_back(passport_.GetSelectableFob<Anmpid>(name));
    mpids2.push_back(passport_.GetSelectableFob<Mpid>(name));
  }

  EXPECT_TRUE(AllFobFieldsMatch(fobs1, fobs2));

  for (uint16_t i(0); i < names.size(); ++i) {
    EXPECT_TRUE(AllFieldsMatch(anmpids1.at(i), anmpids2.at(i)));
    EXPECT_TRUE(AllFieldsMatch(mpids1.at(i), mpids2.at(i)));
  }
}

TEST_F(PassportTest, BEH_ParseBadString) {
  NonEmptyString bad_string(RandomAlphaNumericString(1 + RandomUint32() % 1000));
  EXPECT_THROW(Passport test((Passport(bad_string))), std::exception);
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

  NonEmptyString name(RandomAlphaNumericString(1 + RandomUint32() % 20));
  Anmpid anmpid;
  Mpid mpid(name, anmpid);

  auto proto_public_identity(proto_passport_.add_public_identity());
  proto_public_identity->set_public_id(name.string());
  auto proto_anmpid(proto_public_identity->mutable_anmpid());
  anmpid.ToProtobuf(proto_anmpid);
  auto proto_mpid(proto_public_identity->mutable_mpid());
  mpid.ToProtobuf(proto_mpid);

  EXPECT_NO_THROW(Passport test(Passport(NonEmptyString(proto_passport_.SerializeAsString()))));;
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

  EXPECT_THROW(Passport test((Passport(NonEmptyString(proto_passport_.SerializeAsString())))),
                             std::exception);
}

TEST_F(PassportParsePbTest, BEH_SevenFobs) {
  GenerateSixFobs();
  auto proto_fob(proto_passport_.add_fob());
  pmid_.ToProtobuf(proto_fob);

  EXPECT_THROW(Passport test((Passport(NonEmptyString(proto_passport_.SerializeAsString())))),
                             std::exception);
}

TEST_F(PassportParsePbTest, BEH_ParseReorderedFobs) {
  GenerateSixFobs(RandomUint32() % 6);

  EXPECT_THROW(Passport test((Passport(NonEmptyString(proto_passport_.SerializeAsString())))),
                             std::exception);
}

class PassportParsePbSelectableTest : public PassportParsePbTest {
  void SetUp() override {
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
  EXPECT_NO_THROW(Passport test((Passport(NonEmptyString(proto_passport_.SerializeAsString())))));
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

  void SetUp() override {
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
  NonEmptyString name(RandomAlphaNumericString(1 + RandomUint32() % 20));
  Anmpid anmpid;
  Mpid mpid(name, anmpid);

  auto proto_public_identity(proto_passport_.add_public_identity());
  proto_public_identity->set_public_id(name.string());
  auto proto_mpid(proto_public_identity->mutable_mpid());
  mpid.ToProtobuf(proto_mpid);

  EXPECT_THROW(NonEmptyString(proto_passport_.SerializeAsString()), std::exception);
}

TEST_F(PassportSerialiseTest, BEH_NoMpid) {
  NonEmptyString name(RandomAlphaNumericString(1 + RandomUint32() % 20));
  Anmpid anmpid;

  auto proto_public_identity(proto_passport_.add_public_identity());
  proto_public_identity->set_public_id(name.string());
  auto proto_anmpid(proto_public_identity->mutable_anmpid());
  anmpid.ToProtobuf(proto_anmpid);

  EXPECT_THROW(NonEmptyString(proto_passport_.SerializeAsString()), std::exception);
}

}  // namespace test

}  // namespace passport

}  // namespace maidsafe
