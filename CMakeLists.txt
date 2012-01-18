#==============================================================================#
#                                                                              #
#  Copyright (c) 2011 MaidSafe.net limited                                     #
#                                                                              #
#  The following source code is property of MaidSafe.net limited and is not    #
#  meant for external use.  The use of this code is governed by the license    #
#  file licence.txt found in the root directory of this project and also on    #
#  www.maidsafe.net.                                                           #
#                                                                              #
#  You are not free to copy, amend or otherwise use this source code without   #
#  the explicit written permission of the board of directors of MaidSafe.net.  #
#                                                                              #
#==============================================================================#


SET(MS_PROJECT_NAME maidsafe_passport)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8.4 FATAL_ERROR)
MESSAGE("================================================================================\n")

GET_FILENAME_COMPONENT(CMAKE_BUILD_TYPE_DIR ${CMAKE_BINARY_DIR} NAME)

# Variable MSVC is not set until after "PROJECT" command below
IF(CMAKE_BUILD_TYPE_DIR MATCHES "Win_MSVC")
  SET(CMAKE_BUILD_TYPE_DIR Release)
ELSEIF(CMAKE_BUILD_TYPE_DIR MATCHES "kdev")
  SET(CMAKE_BUILD_TYPE_DIR Debug)
  SET(KDEV 1)
ENDIF()

IF(NOT ${CMAKE_C_COMPILER_WORKS})
  MESSAGE(FATAL_ERROR "No generator previously specified.\nTo see a full list of generators, run:\n\tcmake --help\n")
ENDIF()

# This "PROJECT" command resets CMAKE_BUILD_TYPE, hence it's copied from CMAKE_BUILD_TYPE_DIR which is set above.
IF((CMAKE_BUILD_TYPE_DIR MATCHES "Release") OR (DEFINED ${KDEV}))
  PROJECT(${MS_PROJECT_NAME})
ELSE()
  STRING(TOLOWER ${CMAKE_BUILD_TYPE_DIR} MS_PROJECT_NAME_APPENDIX)
  PROJECT(${MS_PROJECT_NAME}_${MS_PROJECT_NAME_APPENDIX})
ENDIF()

SET(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE_DIR} CACHE INTERNAL "Except for MSVC, the build type is set by running cmake from the appropriate build subdirectory e.g. for a Debug build, \"cd build/Linux/Debug && cmake ../../..\"." FORCE)


###################################################################################################
# MaidSafe Common, PKI and DHT library search                                                     #
###################################################################################################
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/build)
INCLUDE(maidsafe_find_common)
ADD_MAIDSAFE_LIBRARY(MaidSafe-PKI)


###################################################################################################
# Standard setup                                                                                  #
###################################################################################################
SET(PROTO_SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)
FILE(GLOB PROTO_FILES RELATIVE ${PROTO_SOURCE_DIR} "${PROTO_SOURCE_DIR}/maidsafe/passport/*.proto")
INCLUDE(maidsafe_standard_setup)
HANDLE_VERSIONS(${PROJECT_SOURCE_DIR}/src/maidsafe/passport/version.h)


###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
FILE(GLOB SOURCE_FILES_PASSPORT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/*.cc")
FILE(GLOB HEADER_FILES_PASSPORT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/*.h")
SET(ALL_FILES_PASSPORT_DIR ${SOURCE_FILES_PASSPORT_DIR} ${HEADER_FILES_PASSPORT_DIR})
SOURCE_GROUP("Passport Source Files" FILES ${SOURCE_FILES_PASSPORT_DIR})
SOURCE_GROUP("Passport Header Files" FILES ${HEADER_FILES_PASSPORT_DIR})

FILE(GLOB SOURCE_FILES_PASSPORT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/tests/*.cc")
FILE(GLOB HEADER_FILES_PASSPORT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/tests/*.h")
SET(ALL_FILES_PASSPORT_TESTS_DIR ${SOURCE_FILES_PASSPORT_TESTS_DIR} ${HEADER_FILES_PASSPORT_TESTS_DIR})
SOURCE_GROUP("Passport Source Files" FILES ${SOURCE_FILES_PASSPORT_DIR})
SOURCE_GROUP("Passport Header Files" FILES ${HEADER_FILES_PASSPORT_DIR})

SET(STYLE_PASSPORT ${ALL_FILES_PASSPORT_DIR} ${ALL_FILES_PASSPORT_TESTS_DIR})
LIST(REMOVE_ITEM STYLE_PASSPORT "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/signature_packet.pb.cc")
LIST(REMOVE_ITEM STYLE_PASSPORT "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/signature_packet.pb.h")


###################################################################################################
# Define MaidSafe libraries and executables                                                       #
###################################################################################################
MS_ADD_STATIC_LIBRARY(${MS_PROJECT_NAME} ${ALL_FILES_PASSPORT_DIR})
MS_ADD_EXECUTABLE(TESTpassport Tests ${ALL_FILES_PASSPORT_TESTS_DIR})

TARGET_LINK_LIBRARIES(maidsafe_passport_static maidsafe_pki_static protobuf_static)
TARGET_LINK_LIBRARIES(TESTpassport maidsafe_passport_static gtest_static)


###################################################################################################
# Set compiler and linker flags                                                                   #
###################################################################################################
INCLUDE(maidsafe_standard_flags)

IF(MSVC)
  SET_SOURCE_FILES_PROPERTIES(${PROJECT_SOURCE_DIR}/src/maidsafe/passport/signature_packet.pb.cc PROPERTIES COMPILE_FLAGS "/W0")
ELSEIF(UNIX)
  SET_SOURCE_FILES_PROPERTIES(${PROJECT_SOURCE_DIR}/src/maidsafe/passport/signature_packet.pb.cc PROPERTIES COMPILE_FLAGS "-Wno-effc++")
ENDIF()


###################################################################################################
# Tests                                                                                           #
###################################################################################################
ADD_STYLE_TEST(${STYLE_PASSPORT})
ADD_GTESTS(TESTpassport)
TEST_SUMMARY_OUTPUT()


###################################################################################################
# Install details                                                                                 #
###################################################################################################
FINAL_MESSAGE()
RENAME_OUTDATED_BUILT_EXES()

SET(MAIDSAFE_PASSPORT_INSTALL_FILES
      ${PROJECT_SOURCE_DIR}/src/maidsafe/passport/passport.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/passport/passport_config.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/passport/version.h)

MS_INSTALL_LIBS(maidsafe_passport_static)
MS_INSTALL_HEADERS(passport ${MAIDSAFE_PASSPORT_INSTALL_FILES})
MS_INSTALL_EXPORT()
