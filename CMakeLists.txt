cmake_minimum_required(VERSION 3.0)
project(mobileqq_fp_cracker C)

set(CMAKE_C_STANDARD 11)

set(common_compiler_args "-Wall -Werror -Wno-unused")
set(CMAKE_CXX_FLAGS_DEBUG "${common_compiler_args} -g -ggdb -fsanitize=address -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "${common_compiler_args} -O3 -DNDEBUG")

add_executable(fp_cracker main.c)

target_link_libraries(fp_cracker libtomcrypt.a pthread)