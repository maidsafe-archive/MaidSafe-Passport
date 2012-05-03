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


set(MS_PROJECT_NAME maidsafe_passport)

cmake_minimum_required(VERSION 2.8.4 FATAL_ERROR)
message("================================================================================\n")

get_filename_component(CMAKE_BUILD_TYPE_DIR ${CMAKE_BINARY_DIR} NAME)

# Variable MSVC is not set until after "PROJECT" command below
if(CMAKE_BUILD_TYPE_DIR MATCHES "Win_MSVC")
  set(CMAKE_BUILD_TYPE_DIR Release)
elseif(CMAKE_BUILD_TYPE_DIR MATCHES "kdev")
  set(CMAKE_BUILD_TYPE_DIR Debug)
  set(KDEV 1)
endif()

if(NOT ${CMAKE_C_COMPILER_WORKS})
  message(FATAL_ERROR "No generator previously specified.\nTo see a full list of generators, run:\n\tcmake --help\n")
endif()

# This "PROJECT" command resets CMAKE_BUILD_TYPE, hence it's copied from CMAKE_BUILD_TYPE_DIR which is set above.
if((CMAKE_BUILD_TYPE_DIR MATCHES "Release") OR (DEFINED ${KDEV}))
  project(${MS_PROJECT_NAME})
else()
  string(TOLOWER ${CMAKE_BUILD_TYPE_DIR} MS_PROJECT_NAME_APPENDIX)
  project(${MS_PROJECT_NAME}_${MS_PROJECT_NAME_APPENDIX})
endif()

set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE_DIR} CACHE INTERNAL "Except for MSVC, the build type is set by running cmake from the appropriate build subdirectory e.g. for a Debug build, \"cd build/Linux/Debug && cmake ../../..\"." FORCE)


###################################################################################################
# MaidSafe Common, PKI and DHT library search                                                     #
###################################################################################################
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/build)
include(maidsafe_find_common)
add_maidsafe_library(MaidSafe-PKI)


###################################################################################################
# Standard setup                                                                                  #
###################################################################################################
set(PROTO_SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)
file(GLOB PROTO_FILES RELATIVE ${PROTO_SOURCE_DIR} "${PROTO_SOURCE_DIR}/maidsafe/passport/*.proto")
include(maidsafe_standard_setup)
handle_versions(${PROJECT_SOURCE_DIR}/src/maidsafe/passport/version.h)


###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
file(GLOB SOURCE_FILES_PASSPORT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/*.cc")
file(GLOB HEADER_FILES_PASSPORT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/*.h")
set(ALL_FILES_PASSPORT_DIR ${SOURCE_FILES_PASSPORT_DIR} ${HEADER_FILES_PASSPORT_DIR})
source_group("Passport Source Files" FILES ${SOURCE_FILES_PASSPORT_DIR})
source_group("Passport Header Files" FILES ${HEADER_FILES_PASSPORT_DIR})

file(GLOB SOURCE_FILES_PASSPORT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/tests/*.cc")
file(GLOB HEADER_FILES_PASSPORT_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/tests/*.h")
set(ALL_FILES_PASSPORT_TESTS_DIR ${SOURCE_FILES_PASSPORT_TESTS_DIR} ${HEADER_FILES_PASSPORT_TESTS_DIR})
source_group("Passport Source Files" FILES ${SOURCE_FILES_PASSPORT_DIR})
source_group("Passport Header Files" FILES ${HEADER_FILES_PASSPORT_DIR})

set(STYLE_PASSPORT ${ALL_FILES_PASSPORT_DIR} ${ALL_FILES_PASSPORT_TESTS_DIR})
list(REMOVE_ITEM STYLE_PASSPORT "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/signature_packet.pb.cc")
list(REMOVE_ITEM STYLE_PASSPORT "${PROJECT_SOURCE_DIR}/src/maidsafe/passport/signature_packet.pb.h")


###################################################################################################
# Define MaidSafe libraries and executables                                                       #
###################################################################################################
ms_add_static_library(${MS_PROJECT_NAME} ${ALL_FILES_PASSPORT_DIR})
ms_add_executable(TESTpassport Tests ${ALL_FILES_PASSPORT_TESTS_DIR})

target_link_libraries(maidsafe_passport_static maidsafe_pki_static protobuf_static)
target_link_libraries(TESTpassport maidsafe_passport_static gtest_static)


###################################################################################################
# Set compiler and linker flags                                                                   #
###################################################################################################
include(maidsafe_standard_flags)

if(MSVC)
  set_source_files_properties(${PROJECT_SOURCE_DIR}/src/maidsafe/passport/signature_packet.pb.cc PROPERTIES COMPILE_FLAGS "/W0")
elseif(UNIX)
  set_source_files_properties(${PROJECT_SOURCE_DIR}/src/maidsafe/passport/signature_packet.pb.cc PROPERTIES COMPILE_FLAGS "-Wno-effc++")
endif()


###################################################################################################
# Tests                                                                                           #
###################################################################################################
add_style_test(${STYLE_PASSPORT})
add_gtests(TESTpassport)
test_summary_output()


###################################################################################################
# Install details                                                                                 #
###################################################################################################
final_message()
rename_outdated_built_exes()

set(MAIDSAFE_PASSPORT_INSTALL_FILES
      ${PROJECT_SOURCE_DIR}/src/maidsafe/passport/passport.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/passport/passport_config.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/passport/version.h)

ms_install_libs(maidsafe_passport_static)
ms_install_headers(passport ${MAIDSAFE_PASSPORT_INSTALL_FILES})
ms_install_export()
