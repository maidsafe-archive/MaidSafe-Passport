/***************************************************************************************************
 *  Copyright 2013 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

#include "boost/regex.hpp"

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/bounded_string.h"

#include "maidsafe/passport/detail/secure_string.h"

namespace maidsafe {
namespace passport {
namespace test {

typedef passport::detail::SecureString SecureString;
typedef passport::detail::SafeString SafeString;
typedef passport::detail::Password Password;
typedef passport::detail::Pin Pin;

TEST(SecureStringTest, BEH_CreateSecureString) {
  SecureString secure_string;

  EXPECT_NO_THROW(secure_string.Append('p'));
  EXPECT_NO_THROW(secure_string.Append('a'));
  EXPECT_NO_THROW(secure_string.Append('s'));
  EXPECT_NO_THROW(secure_string.Append('s'));
  EXPECT_NO_THROW(secure_string.Append('w'));
  EXPECT_NO_THROW(secure_string.Append('o'));
  EXPECT_NO_THROW(secure_string.Append('r'));
  EXPECT_NO_THROW(secure_string.Append('d'));
  EXPECT_NO_THROW(secure_string.Finalise());

  ASSERT_EQ(SafeString("password"), secure_string.string());
}

TEST(SecureStringTest, BEH_HashSecureStringString) {
  typedef maidsafe::detail::BoundedString<crypto::SHA512::DIGESTSIZE, crypto::SHA512::DIGESTSIZE>
      BoundedString;
  SafeString string("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
  BoundedString hash(crypto::Hash<crypto::SHA512>(string));
}

TEST(SecureStringTest, BEH_CreatePassword) {
  Password password;

  EXPECT_NO_THROW(password.Insert(3, 's'));
  EXPECT_NO_THROW(password.Insert(7, 'd'));
  EXPECT_NO_THROW(password.Insert(4, 'w'));
  EXPECT_NO_THROW(password.Insert(6, 'r'));
  EXPECT_NO_THROW(password.Insert(1, 'a'));
  EXPECT_NO_THROW(password.Insert(0, 'p'));
  EXPECT_NO_THROW(password.Insert(2, 's'));
  EXPECT_NO_THROW(password.Insert(5, 'o'));

  EXPECT_NO_THROW(password.Remove(2, 3));
  EXPECT_NO_THROW(password.Insert(2, 'l'));
  EXPECT_NO_THROW(password.Insert(2, 'y'));
  EXPECT_NO_THROW(password.Remove(5, 1));
  EXPECT_NO_THROW(password.Insert(5, 'a'));

  EXPECT_NO_THROW(password.Finalise());

  ASSERT_EQ(SafeString("payload"), password.string());
}

TEST(SecureStringTest, BEH_CreatePasswordString) {
  SafeString safe_password("password");
  EXPECT_NO_THROW(Password password(safe_password));
  std::string std_password("drowssap");
  EXPECT_NO_THROW(Password password(std_password));

  {
    Password password(safe_password);
    ASSERT_EQ(SafeString("password"), password.string());

    EXPECT_NO_THROW(password.Insert(safe_password.size(), std_password));

    EXPECT_NO_THROW(password.Finalise());

    ASSERT_EQ(SafeString("passworddrowssap"), password.string());
  }

  {
    Password password;
    EXPECT_NO_THROW(password.Insert(0, safe_password));
    EXPECT_NO_THROW(password.Insert(1, std_password));

    EXPECT_NO_THROW(password.Finalise());

    ASSERT_EQ(SafeString("passworddrowssap"), password.string());
  }
}

TEST(SecureStringTest, BEH_RemoveFirstPasswordCharacter) {
  Password password;

  EXPECT_NO_THROW(password.Insert(3, 's'));
  EXPECT_NO_THROW(password.Insert(7, 'd'));
  EXPECT_NO_THROW(password.Insert(4, 'w'));
  EXPECT_NO_THROW(password.Insert(6, 'r'));
  EXPECT_NO_THROW(password.Insert(1, 'a'));
  EXPECT_NO_THROW(password.Insert(0, 'p'));
  EXPECT_NO_THROW(password.Insert(2, 's'));
  EXPECT_NO_THROW(password.Insert(5, 'o'));

  EXPECT_NO_THROW(password.Remove(0, 1));

  EXPECT_NO_THROW(password.Finalise());

  ASSERT_EQ(SafeString("assword"), password.string());
}

TEST(SecureStringTest, BEH_RemoveLastPasswordCharacter) {
  Password password;

  EXPECT_NO_THROW(password.Insert(3, 's'));
  EXPECT_NO_THROW(password.Insert(7, 'd'));
  EXPECT_NO_THROW(password.Insert(4, 'w'));
  EXPECT_NO_THROW(password.Insert(6, 'r'));
  EXPECT_NO_THROW(password.Insert(1, 'a'));
  EXPECT_NO_THROW(password.Insert(0, 'p'));
  EXPECT_NO_THROW(password.Insert(2, 's'));
  EXPECT_NO_THROW(password.Insert(5, 'o'));

  EXPECT_NO_THROW(password.Remove(7, 1));

  EXPECT_NO_THROW(password.Finalise());

  ASSERT_EQ(SafeString("passwor"), password.string());
}

TEST(SecureStringTest, BEH_InsertRemoveAfterPasswordFinalise) {
  Password password;

  EXPECT_NO_THROW(password.Insert(3, 's'));
  EXPECT_NO_THROW(password.Insert(7, 'd'));
  EXPECT_NO_THROW(password.Insert(4, 'w'));
  EXPECT_NO_THROW(password.Insert(6, 'r'));
  EXPECT_NO_THROW(password.Insert(1, 'a'));
  EXPECT_NO_THROW(password.Insert(0, 'p'));
  EXPECT_NO_THROW(password.Insert(2, 's'));
  EXPECT_NO_THROW(password.Insert(5, 'o'));

  EXPECT_NO_THROW(password.Finalise());

  EXPECT_NO_THROW(password.Insert(0, 'p'));
  EXPECT_NO_THROW(password.Remove(0, 1));

  EXPECT_NO_THROW(password.Finalise());

  ASSERT_EQ(SafeString("password"), password.string());
}

TEST(SecureStringTest, BEH_CreatePasswordWithMissingIndex) {
  Password password;

  EXPECT_NO_THROW(password.Insert(3, 's'));
  EXPECT_NO_THROW(password.Insert(8, 'd'));
  EXPECT_NO_THROW(password.Insert(5, 'w'));
  EXPECT_NO_THROW(password.Insert(7, 'r'));
  EXPECT_NO_THROW(password.Insert(1, 'a'));
  EXPECT_NO_THROW(password.Insert(0, 'p'));
  EXPECT_NO_THROW(password.Insert(2, 's'));
  EXPECT_NO_THROW(password.Insert(6, 'o'));

  EXPECT_THROW(password.Finalise(), std::exception);

  EXPECT_NO_THROW(password.Insert(4, 'D'));

  EXPECT_NO_THROW(password.Finalise());

  ASSERT_EQ(SafeString("passDword"), password.string());
}

TEST(SecureStringTest, BEH_CreateInvalidLengthPassword) {
  Password password;

  EXPECT_THROW(password.Finalise(), std::exception);
}

TEST(SecureStringTest, BEH_ClearPasswordThenRedo) {
  Password password;

  EXPECT_NO_THROW(password.Insert(3, 's'));
  EXPECT_NO_THROW(password.Insert(7, 'd'));
  EXPECT_NO_THROW(password.Insert(4, 'w'));
  EXPECT_NO_THROW(password.Insert(6, 'r'));
  EXPECT_NO_THROW(password.Insert(1, 'a'));
  EXPECT_NO_THROW(password.Insert(0, 'p'));
  EXPECT_NO_THROW(password.Insert(2, 's'));
  EXPECT_NO_THROW(password.Insert(5, 'o'));

  EXPECT_NO_THROW(password.Clear());

  EXPECT_NO_THROW(password.Insert(7, 'd'));
  EXPECT_NO_THROW(password.Insert(2, 's'));
  EXPECT_NO_THROW(password.Insert(1, 'a'));
  EXPECT_NO_THROW(password.Insert(0, 'p'));
  EXPECT_NO_THROW(password.Insert(6, 'r'));
  EXPECT_NO_THROW(password.Insert(3, 's'));
  EXPECT_NO_THROW(password.Insert(5, 'o'));
  EXPECT_NO_THROW(password.Insert(4, 'w'));

  EXPECT_NO_THROW(password.Finalise());

  EXPECT_NO_THROW(password.Remove(7, 1));
  EXPECT_NO_THROW(password.Remove(2, 1));
  EXPECT_NO_THROW(password.Remove(4, 1));
  EXPECT_NO_THROW(password.Remove(4, 1));
  EXPECT_NO_THROW(password.Remove(1, 1));
  EXPECT_NO_THROW(password.Remove(2, 1));
  EXPECT_NO_THROW(password.Remove(1, 1));
  EXPECT_NO_THROW(password.Remove(0, 1));

  EXPECT_NO_THROW(password.Insert(7, 'd'));
  EXPECT_NO_THROW(password.Insert(2, 's'));
  EXPECT_NO_THROW(password.Insert(1, 'a'));
  EXPECT_NO_THROW(password.Insert(0, 'p'));
  EXPECT_NO_THROW(password.Insert(6, 'r'));
  EXPECT_NO_THROW(password.Insert(3, 's'));
  EXPECT_NO_THROW(password.Insert(5, 'o'));
  EXPECT_NO_THROW(password.Insert(4, 'w'));

  EXPECT_NO_THROW(password.Finalise());

  ASSERT_EQ(SafeString("password"), password.string());
}

TEST(SecureStringTest, BEH_ClearPasswordAfterFinalise) {
  Password password;

  EXPECT_NO_THROW(password.Insert(3, 's'));
  EXPECT_NO_THROW(password.Insert(7, 'd'));
  EXPECT_NO_THROW(password.Insert(4, 'w'));
  EXPECT_NO_THROW(password.Insert(6, 'r'));
  EXPECT_NO_THROW(password.Insert(1, 'a'));
  EXPECT_NO_THROW(password.Insert(0, 'p'));
  EXPECT_NO_THROW(password.Insert(2, 's'));
  EXPECT_NO_THROW(password.Insert(5, 'o'));

  EXPECT_NO_THROW(password.Finalise());

  EXPECT_NO_THROW(password.Clear());

  EXPECT_THROW(password.Finalise(), std::exception);
  EXPECT_THROW(password.string(), std::exception);
}

TEST(SecureStringTest, BEH_GetPasswordTextBeforeFinalise) {
  Password password;

  EXPECT_NO_THROW(password.Insert(3, 's'));
  EXPECT_NO_THROW(password.Insert(7, 'd'));
  EXPECT_NO_THROW(password.Insert(4, 'w'));
  EXPECT_NO_THROW(password.Insert(6, 'r'));
  EXPECT_NO_THROW(password.Insert(1, 'a'));
  EXPECT_NO_THROW(password.Insert(0, 'p'));
  EXPECT_NO_THROW(password.Insert(2, 's'));
  EXPECT_NO_THROW(password.Insert(5, 'o'));

  EXPECT_THROW(password.string(), std::exception);

  EXPECT_NO_THROW(password.Finalise());

  ASSERT_EQ(SafeString("password"), password.string());
}

TEST(SecureStringTest, BEH_CheckPasswordValidForAllChars) {
  Password password;
  for (size_t i(0); i != 23; ++i)
    EXPECT_NO_THROW(password.Insert(i, static_cast<char>(RandomInt32())));

  ASSERT_TRUE(password.IsValid(boost::regex(".")));

  EXPECT_NO_THROW(password.Finalise());
}

TEST(SecureStringTest, BEH_CreatePin) {
  Pin pin;

  EXPECT_NO_THROW(pin.Insert(1, '1'));
  EXPECT_NO_THROW(pin.Insert(3, '3'));
  EXPECT_NO_THROW(pin.Insert(0, '0'));
  EXPECT_NO_THROW(pin.Insert(2, '2'));

  EXPECT_NO_THROW(pin.Finalise());

  ASSERT_EQ(SafeString("0123"), pin.string());
  ASSERT_EQ(123, pin.Value());
}

TEST(SecureStringTest, BEH_CreateInvalidLengthPin) {
  {
    Pin pin;

    EXPECT_THROW(pin.Finalise(), std::exception);

    EXPECT_NO_THROW(pin.Insert(0, '0'));

    EXPECT_NO_THROW(pin.Finalise());

    ASSERT_EQ(SafeString("0"), pin.string());
  }
}

TEST(SecureStringTest, BEH_InsertInvalidPinValue) {
  Pin pin;

  EXPECT_NO_THROW(pin.Insert(1, '1'));
  EXPECT_NO_THROW(pin.Insert(3, '3'));
  EXPECT_NO_THROW(pin.Insert(0, 'a'));
  EXPECT_NO_THROW(pin.Insert(2, '2'));

  EXPECT_NO_THROW(pin.Finalise());

  ASSERT_EQ(SafeString("a123"), pin.string());
  EXPECT_TRUE(pin.IsValid(boost::regex(".")));
  EXPECT_THROW(pin.Value(), std::exception);

  EXPECT_NO_THROW(pin.Remove(0, 1));
  EXPECT_NO_THROW(pin.Insert(0, '0'));
  EXPECT_NO_THROW(pin.Finalise());
  EXPECT_TRUE(pin.IsValid(boost::regex(".")));

  EXPECT_NO_THROW(pin.Finalise());
  ASSERT_EQ(123, pin.Value());
}

}  // namespace test
}  // namespace passport
}  // namespace maidsafe
