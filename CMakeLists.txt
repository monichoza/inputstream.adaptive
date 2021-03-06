cmake_minimum_required(VERSION 3.5)
project(inputstream.adaptive)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR})

find_package(Kodi REQUIRED)

set(ADP_SOURCES
	src/main.cpp
	src/common/AdaptiveTree.cpp
	src/parser/DASHTree.cpp
	src/parser/HLSTree.cpp
	src/parser/SmoothTree.cpp
	src/parser/TTML.cpp
	src/parser/WebVTT.cpp
	src/parser/PRProtectionParser.cpp
	src/common/AdaptiveStream.cpp
	src/helpers.cpp
	src/oscompat.cpp
	src/TSReader.cpp
	src/aes_decrypter.cpp
	src/ADTSReader.cpp
	src/md5.cpp
	src/WebmReader.cpp
	)

set(ADP_HEADERS
	src/helpers.h
	src/main.h
	src/oscompat.h
	src/SSD_dll.h
	src/common/AdaptiveStream.h
	src/common/AdaptiveTree.h
	src/parser/DASHTree.h
	src/parser/HLSTree.h
	src/parser/SmoothTree.h
	src/parser/TTML.h
	src/parser/WebVTT.h
	src/parser/PRProtectionParser.h
	src/TSReader.h
	src/log.h
	src/aes_decrypter.h
	src/ADTSReader.h
	src/md5.h
	src/WebmReader.h
	)

if(WIN32)
  find_package(dlfcn-win32 REQUIRED)
  list(APPEND DEPLIBS ${dlfcn-win32_LIBRARIES})
  include_directories(${dlfcn-win32_INCLUDE_DIRS})
endif()

include_directories(${INCLUDES}
                    ${KODI_INCLUDE_DIR}
                    lib/libbento4/Core
                    lib/webm_parser/include
)

include(FindEXPAT)
find_package(EXPAT REQUIRED)
include_directories(${EXPAT_INCLUDE_DIRS})
list(APPEND DEPLIBS ${EXPAT_LIBRARIES})

if(WIN32)
  add_definitions(-DXML_STATIC -D_CRT_NONSTDC_NO_DEPRECATE)
  list(APPEND DEPLIBS ws2_32)
else()
  add_definitions(-D__STDC_FORMAT_MACROS)
endif()

add_definitions(-DUNICODE -D_UNICODE)

add_subdirectory(lib/mpegts)

add_subdirectory(lib/webm_parser)

if(CORE_SYSTEM_NAME STREQUAL ios OR CORE_SYSTEM_NAME STREQUAL darwin_embedded)
  set(BENTOUSESTCFS 1)
  add_subdirectory(lib/libbento4)
else()
  add_subdirectory(wvdecrypter)
  set(ADP_ADDITIONAL_BINARY $<TARGET_FILE:ssd_wv>)
endif()

if(CORE_SYSTEM_NAME STREQUAL android)
  set(DECRYPTERPATH "special://xbmcbinaddons")
else()
  set(DECRYPTERPATH "special://home/cdm")
endif()

list(APPEND DEPLIBS bento4)
list(APPEND DEPLIBS mpegts)
list(APPEND DEPLIBS webm_parser)

build_addon(inputstream.adaptive ADP DEPLIBS)

include(CPack)

if(NOT CMAKE_CROSSCOMPILING)
  #Tests
  find_package( Threads )
  add_executable(Test_DashTree
    src/parser/DASHTreeTest.cpp
    src/parser/DASHTree.cpp
    src/parser/PRProtectionParser.cpp
    src/common/AdaptiveTree.cpp
    src/helpers.cpp
    src/oscompat.cpp
    )
  target_link_libraries(Test_DashTree ${EXPAT_LIBRARIES} Threads::Threads)

  enable_testing()

  add_test(6play_live Test_DashTree "${CMAKE_SOURCE_DIR}/src/parser/testfiles/6play.mpd")
endif()