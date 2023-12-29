cmake_minimum_required(VERSION 3.10.2)

project(newp)

# set(SRC Alice.cpp)
# set(SRC Cloud.cpp)
# set(SRC Verify.cpp)

set(SRC client.cpp)
find_package (OpenMP)

link_libraries(-lcrypto -lssl)
link_libraries(gmp gmpxx)


include_directories(/usr/local/inlcude)

link_directories(/usr/local/lib)

add_executable(main ${SRC})

target_link_libraries(main ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(main OpenMP::OpenMP_CXX)
