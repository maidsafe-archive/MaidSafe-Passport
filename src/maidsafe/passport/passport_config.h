/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Definition of error codes, typedef, forward declarations, etc.
* Version:      1.0
* Created:      2009-10-12-13.48.44
* Revision:     none
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

#ifndef MAIDSAFE_PASSPORT_PASSPORT_CONFIG_H_
#define MAIDSAFE_PASSPORT_PASSPORT_CONFIG_H_

#include "maidsafe/passport/version.h"

#if MAIDSAFE_PASSPORT_VERSION != 106
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-passport library.
#endif


// *** typedefs, enums and consts ***
namespace maidsafe {

namespace passport {

enum ReturnCode {
  kSuccess = 0,
  kPassportError = -100001,
  kNoPendingMid = -100002,
  kNoPendingSmid = -100003,
  kNoPendingTmid = -100004,
  kNoPendingStmid = -100005,
  kNoPendingPacket = -100006,
  kNoMid = -100007,
  kNoSmid = -100008,
  kNoTmid = -100009,
  kNoStmid = -100010,
  kNoSigningPacket = -100011,
  kNoPacket = -100012,
  kBadSerialisedMidRid = -100013,
  kBadSerialisedSmidRid = -100014,
  kBadSerialisedTmidData = -100015,
  kBadSerialisedStmidData = -100016,
  kBadSerialisedKeyring = -100017,
  kKeyringNotEmpty = -100018,
  kPacketsNotEqual = -100019,
  kMissingDependentPackets = -100020,
  kNullPointer = -100021
};

enum PacketType {
  UNKNOWN = -1,
  MID,
  SMID,
  TMID,
  STMID,
  MPID,
  MAID,
  PMID,
  ANMID,
  ANSMID,
  ANTMID,
  ANMPID,
  ANMAID,
  MSID,
  PD_DIR
};

const std::uint16_t kCryptoKeyBufferCount(6);

}  // namespace passport

}  // namespace maidsafe


// *** Forward declarations ***
namespace testing { class AssertionResult; }

namespace maidsafe {

namespace passport {

class MidPacket;
class TmidPacket;
class Key;
class Passport;

namespace test {
testing::AssertionResult Empty(std::shared_ptr<pki::Packet> packet);
class SystemPacketsTest_BEH_CreateSig_Test;
class SystemPacketsTest_BEH_PutToAndGetFromKey_Test;
struct ExpectedMidContent;
testing::AssertionResult Equal(
    std::shared_ptr<ExpectedMidContent> expected,
    std::shared_ptr<MidPacket> mid);
struct ExpectedTmidContent;
testing::AssertionResult Equal(
    std::shared_ptr<ExpectedTmidContent> expected,
    std::shared_ptr<TmidPacket> mid);
class SystemPacketHandlerTest_FUNC_All_Test;
class PassportTest_BEH_SetNewUserData_Test;
class PassportTest_BEH_ConfirmNewUserData_Test;
}  // namespace test

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_PASSPORT_CONFIG_H_
