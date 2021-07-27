#Generate project VisualStudio with Win64!
cmake_minimum_required(VERSION 3.11)

project (file_hash_maker)

add_executable (${PROJECT_NAME})


set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /std:c++17")


#openssl dependency
set (OPENSLL libcrypto)

add_library(${OPENSLL} STATIC IMPORTED GLOBAL)

set_target_properties(${OPENSLL}
	PROPERTIES
		INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/openssl/include"
		IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/openssl/bin/${OPENSLL}.lib"
)

target_link_libraries (${PROJECT_NAME}
  PUBLIC
    ${OPENSLL}
)


file(GLOB SOURCES_FILES
    "file_hash_maker/file_hash_maker.cpp")

target_sources(${PROJECT_NAME}
  PRIVATE
    ${SOURCES_FILES}
)

add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_SOURCE_DIR}/openssl/bin/libcrypto-1_1-x64.dll" "${CMAKE_BINARY_DIR}/$<CONFIG>/")

