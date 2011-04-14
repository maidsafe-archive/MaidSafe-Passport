/*
* ============================================================================
*
* Copyright [2010] maidsafe.net limited
*
* Description:  Class for manipulating database of system packets
* Version:      1.0
* Created:      14/10/2010 11:43:59
* Revision:     none
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

#ifndef MAIDSAFE_PASSPORT_SYSTEMPACKETHANDLER_H_
#define MAIDSAFE_PASSPORT_SYSTEMPACKETHANDLER_H_

#include <memory>
#include <map>
#include <string>
#include "boost/thread/mutex.hpp"

#include "maidsafe/passport/systempackets.h"

namespace maidsafe {

namespace passport {

class SystemPacketHandler {
 public:
  SystemPacketHandler() : packets_(), mutex_() {}
  ~SystemPacketHandler() {}
  // Add packet which is pending confirmation of storing
  bool AddPendingPacket(std::shared_ptr<pki::Packet> packet);
  // Change packet from pending to stored
  int ConfirmPacket(std::shared_ptr<pki::Packet> packet);
  // Removes a pending packet (leaving last stored copy)
  bool RevertPacket(const PacketType &packet_type);
  // Returns a *copy* of the confirmed or pending packet
  std::shared_ptr<pki::Packet> GetPacket(const PacketType &packet_type,
                                         bool confirmed);
  bool Confirmed(const PacketType &packet_type);
  std::string SerialiseKeyring(const std::string &public_name);
  int ParseKeyring(const std::string &serialised_keyring,
                   std::string *public_name);
  void ClearKeyring();
  int DeletePacket(const PacketType &packet_type);
  void Clear();
 private:
  struct PacketInfo {
    PacketInfo() : pending(), stored() {}
    explicit PacketInfo(std::shared_ptr<pki::Packet> pend)
        : pending(), stored() {
      if (pend) {
        // keep a copy of the contents
        if (pend->packet_type() == TMID || pend->packet_type() == STMID) {
          pending = std::shared_ptr<TmidPacket>(new TmidPacket(
              *std::static_pointer_cast<TmidPacket>(pend)));
        } else if (pend->packet_type() == MID || pend->packet_type() == SMID) {
          pending = std::shared_ptr<MidPacket>(new MidPacket(
              *std::static_pointer_cast<MidPacket>(pend)));
        } else if (IsSignature(pend->packet_type(), false)) {
          pending = std::shared_ptr<SignaturePacket>(new SignaturePacket(
              *std::static_pointer_cast<SignaturePacket>(pend)));
        }
      }
    }
    std::shared_ptr<pki::Packet> pending, stored;
  };
  typedef std::map<PacketType, PacketInfo> SystemPacketMap;
  friend class test::SystemPacketHandlerTest_FUNC_PASSPORT_All_Test;
  SystemPacketHandler &operator=(const SystemPacketHandler&);
  SystemPacketHandler(const SystemPacketHandler&);
  bool IsConfirmed(SystemPacketMap::iterator it);
  SystemPacketMap packets_;
  boost::mutex mutex_;
};

}  // namespace passport

}  // namespace maidsafe

#endif  // MAIDSAFE_PASSPORT_SYSTEMPACKETHANDLER_H_

