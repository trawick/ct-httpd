# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

PROJECT(mod_ssl_ct C)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8)

IF(NOT EXISTS ${CMAKE_INSTALL_PREFIX}/lib/libhttpd.lib)
  MESSAGE(FATAL_ERROR "libhttpd.lib was not found in prefix ${CMAKE_INSTALL_PREFIX}")
ENDIF()

IF(NOT EXISTS "${CMAKE_INSTALL_PREFIX}/lib/libapr-1.lib")
  MESSAGE(FATAL_ERROR "APR libraries were not found in prefix ${CMAKE_INSTALL_PREFIX}")
ENDIF()

SET(apr_libraries
    ${CMAKE_INSTALL_PREFIX}/lib/libapr-1.lib
    ${CMAKE_INSTALL_PREFIX}/lib/libaprutil-1.lib)

# Misc. options
OPTION(INSTALL_PDB "Install .pdb file (if generated)" ON)

SET(mod_ssl_ct_sources
    mod_ssl_ct.c
    ssl_ct_log_config.c
    ssl_ct_sct.c
    ssl_ct_util.c
#   mod_ssl_ct.rc
   )

INCLUDE_DIRECTORIES(${CMAKE_INSTALL_PREFIX}/include)
ADD_LIBRARY(mod_ssl_ct SHARED ${mod_ssl_ct_sources})
# magic base address taken from traditional Windows build
# FIXME SET_TARGET_PROPERTIES(mod_ssl_ct PROPERTIES SUFFIX .so LINK_FLAGS /base:0x46430000)
TARGET_LINK_LIBRARIES(mod_ssl_ct ${CMAKE_INSTALL_PREFIX}/lib/libhttpd.lib ${apr_libraries})
INSTALL(TARGETS mod_ssl_ct RUNTIME DESTINATION modules)
IF(INSTALL_PDB)
  INSTALL(FILES ${CMAKE_BINARY_DIR}/mod_ssl_ct.pdb DESTINATION modules
          CONFIGURATIONS RelWithDebInfo Debug)
ENDIF()
