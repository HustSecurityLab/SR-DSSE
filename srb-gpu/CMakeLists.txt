cmake_minimum_required(VERSION 3.10.2)

project(cudatest)

find_package(CUDA REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -O3")

set(CUDA_NVCC_FLAGS ${CUDA_NVCC_FLAGS};-std=c++11;)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)
set(SRC test.cu)
set(THREADS_PREFER_PTHREAD_FLAG ON)

link_libraries(-lcrypto -lssl)
link_libraries(gmp gmpxx)

link_directories(/usr/local/lib)
link_directories(/usr/local/lib)
link_directories(/home/dhc/cufhe)


CUDA_ADD_EXECUTABLE(main ${SRC})

target_link_libraries(main cufhe_gpu)


