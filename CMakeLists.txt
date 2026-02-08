cmake_minimum_required(VERSION 3.16)
project(fpcap-python LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Required for linking static libraries into a shared Python extension module
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(FetchContent)

# --- Fetch pybind11 ---
FetchContent_Declare(
    pybind11
    GIT_REPOSITORY https://github.com/pybind/pybind11.git
    GIT_TAG        v3.0.1
)
FetchContent_MakeAvailable(pybind11)

# --- Fetch fpcap ---
FetchContent_Declare(
    fpcap
    GIT_REPOSITORY https://github.com/fpcap/fpcap.git
    GIT_TAG        v0.2.0
)
set(FPCAP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(FPCAP_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(fpcap)

# --- Build the Python extension module ---
pybind11_add_module(_fpcap src/bindings.cpp)
target_link_libraries(_fpcap PRIVATE fpcap::fpcap)

install(TARGETS _fpcap LIBRARY DESTINATION .)
