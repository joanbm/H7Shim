cmake_minimum_required(VERSION 3.7)

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")

project(h7shim LANGUAGES C)
find_package(SDL2 REQUIRED)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_executable(h7shim h7shim.c winapi2sdl.c)
target_link_libraries(h7shim PRIVATE Threads::Threads SDL2::SDL2)
