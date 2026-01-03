cmake_minimum_required(VERSION 3.0)
set(CMAKE_PROJECT_NAME xClient)

link_directories()
include_directories()

set(SOURCE_FILES_XLIENT
	"../s5.h"
	"../s5.c"
	"../text_in_color.h"
	"../text_in_color.c"
	"../sockaddr_universal.h"
	"../sockaddr_universal.c"
	"../configure.h"
	"../configure.c"
	"../mycert.h"
	"xClient.c"
	)
	
add_definitions(-DINNO_CLIENT=1)
add_executable(xClient ${SOURCE_FILES_XLIENT})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${LIBUVDIR}/include)
include_directories(${MBEDTLS_ROOT_DIR}/include)
target_link_libraries(xClient  mbedtls uv_a pthread)

