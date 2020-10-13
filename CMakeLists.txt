cmake_minimum_required(VERSION 3.7)

set (CMAKE_C_FLAGS "-m32")
set (CMAKE_CXX_FLAGS "-m32")

project(h7shim LANGUAGES C)
find_package(SDL2 REQUIRED)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_custom_target(HEAVEN7W_C.EXE
    COMMAND cp "${CMAKE_SOURCE_DIR}/HEAVEN7W.EXE" "${CMAKE_BINARY_DIR}/HEAVEN7W_tmp.EXE"
    COMMAND upx -d "${CMAKE_BINARY_DIR}/HEAVEN7W_tmp.EXE"
    COMMAND mv "${CMAKE_BINARY_DIR}/HEAVEN7W_tmp.EXE" "${CMAKE_BINARY_DIR}/HEAVEN7W_C.EXE"

)

add_executable(h7shim h7shim.c)
add_dependencies(h7shim HEAVEN7W_C.EXE)
target_link_libraries(h7shim PRIVATE Threads::Threads SDL2::SDL2)
