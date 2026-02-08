cmake_minimum_required(VERSION 3.16)
project(fpcap-python LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Required for linking static libraries into a shared Python extension module
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(FetchContent)

# Use CMake's FindPython (not pybind11's legacy compatibility mode)
set(PYBIND11_FINDPYTHON ON)

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

if(MSVC)
    # Disable MSVC C++20 module scanning (we don't use C++ modules and the scanner
    # fails on Windows because it lacks platform architecture defines)
    set_target_properties(_fpcap PROPERTIES CXX_SCAN_FOR_MODULES OFF)

    # Fix "No Target Architecture" error: Python.h pulls in winnt.h which needs
    # _AMD64_/_X86_/_ARM64_ defined. MSVC defines _M_AMD64 intrinsically, but the
    # macro-to-define chain in winnt.h can fail with certain header include orders
    # (Python.h + C++20 + recent Windows SDK). Define the architecture explicitly.
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        target_compile_definitions(_fpcap PRIVATE _AMD64_)
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
        target_compile_definitions(_fpcap PRIVATE _X86_)
    endif()
endif()

install(TARGETS _fpcap LIBRARY DESTINATION .)
