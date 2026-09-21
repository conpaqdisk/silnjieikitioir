cmake_minimum_required(VERSION 3.20)
project(plugin_loader LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")

if (NOT MSVC)
    message(FATAL_ERROR "This project targets MSVC (Windows x64).")
endif()

add_library(plugin_api INTERFACE)
target_include_directories(plugin_api INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

# ---------- Host ----------
add_executable(host
    src/host/main.cpp
    src/host/logger.cpp
    src/host/safe_dll_dir.cpp
    src/host/pe_validator.cpp
    src/host/manifest.cpp
    src/host/dep_graph.cpp
    src/host/plugin_loader.cpp)
target_include_directories(host PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/host)
target_link_libraries(host PRIVATE plugin_api bcrypt)
target_compile_definitions(host PRIVATE UNICODE _UNICODE)
set_target_properties(host PROPERTIES WIN32_EXECUTABLE FALSE)

# ---------- Plugins ----------
function(add_plugin NAME)
    add_library(${NAME} SHARED ${ARGN})
    target_include_directories(${NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(${NAME} PRIVATE plugin_api)
    set_target_properties(${NAME} PROPERTIES PREFIX "" OUTPUT_NAME "${NAME}")
endfunction()

add_plugin(plugin_success          src/plugins/success/plugin_success.cpp)
add_plugin(plugin_missing_export   src/plugins/missing_export/plugin_missing_export.cpp)
add_plugin(plugin_bad_api          src/plugins/bad_api/plugin_bad_api.cpp)
add_plugin(plugin_init_fail        src/plugins/init_fail/plugin_init_fail.cpp)
add_plugin(plugin_dependency       src/plugins/dependency/plugin_dependency.cpp)
add_plugin(plugin_circular_a       src/plugins/circular/plugin_circular.cpp)
add_plugin(plugin_circular_b       src/plugins/circular/plugin_circular.cpp)

# ---------- Tests ----------
add_executable(test_runner
    tests/test_runner.cpp
    src/host/logger.cpp
    src/host/safe_dll_dir.cpp
    src/host/pe_validator.cpp
    src/host/manifest.cpp
    src/host/dep_graph.cpp
    src/host/plugin_loader.cpp)
target_include_directories(test_runner PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/host)
target_link_libraries(test_runner PRIVATE plugin_api bcrypt)

# Create output directories at configure time
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/plugins ${CMAKE_BINARY_DIR}/test_plugins)

# Copy artifacts to build/plugins + test_plugins
add_custom_command(TARGET plugin_success          POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/plugins
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/test_plugins
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:plugin_success> ${CMAKE_BINARY_DIR}/plugins/
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:plugin_success> ${CMAKE_BINARY_DIR}/test_plugins/)

add_custom_command(TARGET plugin_missing_export   POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/plugins
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/test_plugins
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:plugin_missing_export> ${CMAKE_BINARY_DIR}/plugins/
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:plugin_missing_export> ${CMAKE_BINARY_DIR}/test_plugins/)

add_custom_command(TARGET plugin_bad_api          POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/plugins
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/test_plugins
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:plugin_bad_api> ${CMAKE_BINARY_DIR}/plugins/
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:plugin_bad_api> ${CMAKE_BINARY_DIR}/test_plugins/)

add_custom_command(TARGET plugin_init_fail        POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/plugins
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/test_plugins
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:plugin_init_fail> ${CMAKE_BINARY_DIR}/plugins/
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:plugin_init_fail> ${CMAKE_BINARY_DIR}/test_plugins/)

add_custom_command(TARGET plugin_dependency       POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/plugins
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/test_plugins
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:plugin_dependency> ${CMAKE_BINARY_DIR}/plugins/
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:plugin_dependency> ${CMAKE_BINARY_DIR}/test_plugins/)

add_custom_command(TARGET plugin_circular_a       POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/test_plugins
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:plugin_circular_a> ${CMAKE_BINARY_DIR}/test_plugins/)

add_custom_command(TARGET plugin_circular_b       POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/test_plugins
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:plugin_circular_b> ${CMAKE_BINARY_DIR}/test_plugins/)

# Manifests (checked in next to the source — copied to both dirs)
file(GLOB MANIFESTS ${CMAKE_CURRENT_SOURCE_DIR}/manifests/*.ini)
foreach(m ${MANIFESTS})
    get_filename_component(fn ${m} NAME)
    add_custom_command(TARGET plugin_success POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/plugins
        COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/test_plugins
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${m}" "${CMAKE_BINARY_DIR}/plugins/${fn}"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${m}" "${CMAKE_BINARY_DIR}/test_plugins/${fn}")
endforeach()