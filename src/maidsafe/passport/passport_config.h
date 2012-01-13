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

#include <tuple>

#include <string>
#include <vector>

#include "maidsafe/common/rsa.h"

#include "maidsafe/passport/version.h"

#if MAIDSAFE_PASSPORT_VERSION != 110
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-passport library.
#endif


namespace maidsafe {

namespace passport {

enum ReturnCode {
  kSuccess = 0,
  kPassportError = -100001,
  kNoPendingPacket = -100002,
  kNoPacket = -100003,
  kBadSerialisedKeyChain = -100004,
  kKeyChainNotEmpty = -100005,
  kPacketsNotEqual = -100006,
  kMissingDependentPackets = -100007,
  kNullPointer = -100008,
  kEmptyParameter = -100009,
  kFailedToCreatePacket = -100010,
  kFailedToConfirmPacket = -100011,
  kFailedToRevertPacket = -100012,
  kFailedToFindSelectableIdentity = -100013,
  kFailedToAddSelectableIdentity = -100014,
  kFailedToConfirmSelectableIdentity = -100015,
  kFailedToDeleteSelectableIdentity = -100016,
  kFailedToGetSelectableIdentityData = -100017
};

enum PacketType {
  kUnknown = -1,
  kAnmid,
  kAnsmid,
  kAntmid,
  kAnmaid,
  kMaid,
  kPmid,
  kMid,
  kSmid,
  kTmid,
  kStmid,
  kAnmpid,
  kMpid,
  kMmid,
  kMcid
};

const std::string g_smid_appendix("1");

typedef std::tuple<std::string, std::string, asymm::PrivateKey, bool>
        SelectableIdData;
typedef std::tuple<std::string, asymm::PublicKey, std::string> PacketData;
typedef std::vector<PacketData> SelectableIdentityData;

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_PASSPORT_CONFIG_H_
