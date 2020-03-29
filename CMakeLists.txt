
file(GLOB SOURCES
	${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/http-parser/*.c
)

include(DefineRelativeFilePaths)

cmake_append_nobuiltin_macro_compiler_flags()
cmake_define_relative_file_paths("${SOURCES}")

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/http-parser)

add_library(mockhttpd STATIC
	${SOURCES}
)

find_package(OpenSSL REQUIRED)
target_link_libraries(mockhttpd PRIVATE OpenSSL::SSL OpenSSL::Crypto)

find_package(Libevent CONFIG REQUIRED)
target_link_libraries(mockhttpd PRIVATE event_shared event_core_shared event_extra_shared event_openssl_shared)

