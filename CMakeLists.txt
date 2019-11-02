
file(GLOB SOURCES
	${CMAKE_CURRENT_SOURCE_DIR}/*.cpp
	${CMAKE_CURRENT_SOURCE_DIR}/http-parser/*.c
)

add_compile_options(-Wno-builtin-macro-redefined)

  foreach (SOURCE IN LISTS SOURCES)
    file (
      RELATIVE_PATH RELATIVE_SOURCE_PATH
      ${PROJECT_SOURCE_DIR} ${SOURCE}
    )

    set_source_files_properties (
      ${SOURCE} PROPERTIES
      COMPILE_DEFINITIONS __RELATIVE_FILE_PATH__="${RELATIVE_SOURCE_PATH}"
    )
  endforeach ()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/http-parser)

add_library(mockhttpd STATIC
	${SOURCES}
)
