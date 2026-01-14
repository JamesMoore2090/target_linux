cmake_minimum_required(VERSION 3.10)
project(TARGEX-CLI VERSION 1.0)

# Specify C++ Standard (C++17 or C++20 is recommended for modern features)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(FetchContent)

FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz
)

FetchContent_MakeAvailable(json)

FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v1.12.0
)
FetchContent_MakeAvailable(spdlog)

FetchContent_Declare(
    Crow
    GIT_REPOSITORY https://github.com/CrowCpp/Crow.git
    GIT_TAG        master
)
FetchContent_MakeAvailable(Crow)

# Include directories
include_directories(include)

# Define source files
file(GLOB_RECURSE SOURCES "src/*.cpp")

# Create the executable
add_executable(targex_cli ${SOURCES})

# (Optional) Link libraries here, e.g., for threading or networking
# target_link_libraries(targex_cli pthread)
target_link_libraries(targex_cli PRIVATE 
    nlohmann_json::nlohmann_json 
    spdlog::spdlog 
    Crow::Crow
)