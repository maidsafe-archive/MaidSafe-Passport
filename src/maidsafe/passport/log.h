/*
* ============================================================================
*
* Copyright [2009] maidsafe.net limited
*
* Description:  Logging
* Version:      1.0
* Created:      2011-05-06-12.59.00
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

#ifndef MAIDSAFE_PASSPORT_LOG_H_
#define MAIDSAFE_PASSPORT_LOG_H_

#include "maidsafe/common/log.h"

#undef LOG
#define LOG(severity) MAIDSAFE_LOG(passport, severity)

#endif  // MAIDSAFE_PASSPORT_LOG_H_
