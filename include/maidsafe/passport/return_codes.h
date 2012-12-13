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

#ifndef MAIDSAFE_PASSPORT_RETURN_CODES_H_
#define MAIDSAFE_PASSPORT_RETURN_CODES_H_


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

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_RETURN_CODES_H_
