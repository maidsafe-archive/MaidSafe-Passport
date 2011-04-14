# ============================================================================ #
#                                                                              #
# Copyright [2010] maidsafe.net limited                                        #
#                                                                              #
# Description:  CMakeList for Passport project.                                #
# Version:      1.0                                                            #
# Created:      2010-10-12-01.53.23                                            #
# Revision:     none                                                           #
# Compiler:     N/A                                                            #
# Author:       Team                                                           #
# Company:      maidsafe.net limited                                           #
#                                                                              #
# The following source code is property of maidsafe.net limited and is not     #
# meant for external use.  The use of this code is governed by the license     #
# file LICENSE.TXT found in the root of this directory and also on             #
# www.maidsafe.net.                                                            #
#                                                                              #
# You are not free to copy, amend or otherwise use this source code without    #
# the explicit written permission of the board of directors of maidsafe.net.   #
#                                                                              #
# ============================================================================ #


CMAKE_MINIMUM_REQUIRED(VERSION 2.8 FATAL_ERROR)
MESSAGE("================================================================================\n")

SET(ERROR_MESSAGE_CMAKE_PATH "cmake ../../..")
GET_FILENAME_COMPONENT(CMAKE_BUILD_TYPE_DIR ${CMAKE_BINARY_DIR} NAME)

# Variable MSVC is not set until after PROJECT command below
IF(CMAKE_BUILD_TYPE_DIR MATCHES "Win_MSVC")
  SET(CMAKE_BUILD_TYPE_DIR Release)
  SET(ERROR_MESSAGE_CMAKE_PATH "   cmake ..\\..")
ELSEIF(CMAKE_BUILD_TYPE_DIR MATCHES "kdev")
  SET(CMAKE_BUILD_TYPE_DIR Debug)
  SET(KDEV 1)
ENDIF()

SET(ERROR_MESSAGE "No generator previously specified.\nTo see a full list of generators, run:\n\t${ERROR_MESSAGE_CMAKE_PATH} --help\n")
IF(NOT ${CMAKE_C_COMPILER_WORKS})
  MESSAGE(FATAL_ERROR ${ERROR_MESSAGE})
ENDIF()

IF((CMAKE_BUILD_TYPE_DIR MATCHES "Release") OR (DEFINED ${KDEV}))
  SET(PROJECT_NAME passport)
ELSE()
  SET(PROJECT_NAME passport_${CMAKE_BUILD_TYPE_DIR})
ENDIF()
OPTION (BUILD_SHARED_LIBS "Build shared libraries." OFF)

# This call resets CMAKE_BUILD_TYPE, hence it's copied from CMAKE_BUILD_TYPE_DIR which is set above.
PROJECT(${PROJECT_NAME})
SET(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE_DIR} CACHE INTERNAL "Except for MSVC, the build type is set by running cmake from the appropriate build subdirectory e.g. for a Debug build, \"cd build/Linux/Debug && cmake ../../..\"." FORCE)

###################################################################################################
# MaidSafe Common PKI and DHT library search                                                          #
###################################################################################################
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/build)
INCLUDE(maidsafe_find_common)
ADD_MAIDSAFE_LIBRARY(PKI)
ADD_MAIDSAFE_LIBRARY(MaidSafe-DHT)

###################################################################################################
# Standard setup                                                                                  #
###################################################################################################
INCLUDE(maidsafe_standard_setup)
HANDLE_VERSIONS(${PROJECT_SOURCE_DIR}/src/maidsafe/passport/version.h)

###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
FILE(GLOB SOURCE_FILES_PASSPORT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/*.cc")
FILE(GLOB HEADER_FILES_PASSPORT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/*.h")
SET(ALL_FILES_PASSPORT_DIR ${SOURCE_FILES_PASSPORT_DIR} ${HEADER_FILES_PASSPORT_DIR})
SOURCE_GROUP("passport Source Files" FILES ${SOURCE_FILES_PASSPORT_DIR})
SOURCE_GROUP("passport Header Files" FILES ${HEADER_FILES_PASSPORT_DIR})

FILE(GLOB ALL_FILES_PASSPORT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/tests/*.cc" "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/tests/*.h")

###################################################################################################
# All Platforms:  Add Test Exes and Create all passport libs                                      #
###################################################################################################
ADD_LIBRARY(passport_static STATIC ${ALL_FILES_PASSPORT_DIR})
ADD_EXECUTABLE(TESTpassport ${ALL_FILES_PASSPORT_TESTS_DIR})
# Force renaming of exes to match standard CMake library renaming policy
RENAME_EXECUTABLE(TESTpassport)

SET_TARGET_PROPERTIES(passport_static PROPERTIES OUTPUT_NAME passport)

TARGET_LINK_LIBRARIES(passport_static pki_static boost_thread boost_system protobuf_static)
TARGET_LINK_LIBRARIES(TESTpassport passport_static gtest_static)

###################################################################################################
# Builds                                                                                          #
###################################################################################################
INCLUDE(maidsafe_standard_flags)

IF(MSVC)
  SET_TARGET_PROPERTIES(passport_static PROPERTIES STATIC_LIBRARY_FLAGS_RELEASE "/LTCG")
  SET_TARGET_PROPERTIES(TESTpassport PROPERTIES
                          LINK_FLAGS "/STACK:1048576"
                          LINK_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG /INCREMENTAL:NO ${LINKER_LIBS_DIRS_RELEASE}"
                          LINK_FLAGS_DEBUG "${LINKER_LIBS_DIRS_DEBUG}"
                          LINK_FLAGS_RELWITHDEBINFO "${LINKER_LIBS_DIRS_DEBUG}"
                          LINK_FLAGS_MINSIZEREL "${LINKER_LIBS_DIRS_DEBUG}")
ENDIF()

###################################################################################################
# Tests                                                                                           #
###################################################################################################
IF(PYTHONINTERP_FOUND)
  IF(UNIX)
    ADD_TEST(STYLE_CHECK python ${MaidSafeCommon_TOOLS_DIR}/cpplint.py ${ALL_FILES_PASSPORT_DIR} ${ALL_FILES_PASSPORT_TESTS_DIR})
  ELSE()
    STRING(REPLACE "/" "\\\\" STYLE_CHECK_SOURCE ${PROJECT_SOURCE_DIR})
    ADD_TEST(STYLE_CHECK ${MaidSafeCommon_TOOLS_DIR}/run_cpplint.bat ${STYLE_CHECK_SOURCE} ${MaidSafeCommon_TOOLS_DIR}/cpplint.py)
  ENDIF()
  SET_PROPERTY(TEST STYLE_CHECK PROPERTY LABELS Functional CodingStyle)
ENDIF()

ADD_GTESTS(TESTpassport)

TEST_SUMMARY_OUTPUT()

###################################################################################################
# Install details                                                                                 #
###################################################################################################
FINAL_MESSAGE()

SET(EXPORT_NAME passport)
INSTALL(TARGETS passport_static EXPORT ${EXPORT_NAME} ARCHIVE DESTINATION lib)
INSTALL(FILES ${PROJECT_SOURCE_DIR}/src/maidsafe/passport/passport.h
			  ${PROJECT_SOURCE_DIR}/src/maidsafe/passport/passportconfig.h
			  ${PROJECT_SOURCE_DIR}/src/maidsafe/passport/signaturepacket.pb.h
			  ${PROJECT_SOURCE_DIR}/src/maidsafe/passport/systempackethandler.h
			  ${PROJECT_SOURCE_DIR}/src/maidsafe/passport/systempackets.h
              ${PROJECT_SOURCE_DIR}/src/maidsafe/passport/version.h
              DESTINATION include/maidsafe/passport)
INSTALL(EXPORT ${EXPORT_NAME} DESTINATION share/maidsafe)
ADD_VERSION_INFO_TO_INSTALLED_FILE()
