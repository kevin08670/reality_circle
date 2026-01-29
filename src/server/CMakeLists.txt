cmake_minimum_required(VERSION 3.5)
set(CMAKE_PROJECT_NAME server)
link_directories()
include_directories()
set(SOURCE_FILES_REALITY
	"../s5.h"
	"../s5.c"
	"../text_in_color.h"
	"../text_in_color.c"
	"../sockaddr_universal.h"
	"../sockaddr_universal.c"
	"../configure.h"
	"../configure.c"
	"inno_tls.h"
	"inno_tls.c"
	"addr_mgr.h"
	"addr_mgr.c"
	"cert_mgr.h"
	"cert_mgr.c"
	"user_mgr.h"
	"user_mgr.c"
	"server.c"
)
add_definitions(-DINNO_SERVER=1)
add_executable(server ${SOURCE_FILES_REALITY})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${LIBUVDIR}/include)
include_directories(${MBEDTLS_ROOT_DIR}/include)
include_directories(${CSTL_ROOT_DIR}/inc)
include_directories(${LIB_JSON_C_BIN_DIR}/..)
target_link_libraries(server  mbedtls cstl uv_a json-c pthread)