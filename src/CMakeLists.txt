cmake_minimum_required(VERSION 3.5)
set(CMAKE_PROJECT_NAME reality)
link_directories()
include_directories()
set(SOURCE_FILES_CLIENT
	"s5.h"
	"s5.c"
	"text_in_color.h"
	"text_in_color.c"
	"sockaddr_universal.h"
	"sockaddr_universal.c"
	"configure.h"
	"configure.c"
	"reality.c"
)
add_definitions(-DINNO_CLIENT=1)
if((NOT APPLE) AND (NOT ANDROID))
	add_executable(reality ${SOURCE_FILES_CLIENT})
else()
	add_library(reality SHARED ${SOURCE_FILES_CLIENT})
endif()
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${LIBUVDIR}/include)
include_directories(${MBEDTLS_ROOT_DIR}/include)
target_link_libraries(reality  mbedtls uv_a pthread)

