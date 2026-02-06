cmake_minimum_required(VERSION 3.10...3.31)
project(TARGEX VERSION 1.0)

# 1. Set policy for FetchContent download timestamps to avoid warnings
if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()

# 2. Windows-Specific Configuration
if(WIN32)
    # Target Windows 10/11 to satisfy httplib and modern socket requirements
    add_compile_definitions(_WIN32_WINNT=0x0A00 WIN32_LEAN_AND_MEAN NOMINMAX)
    # Link necessary Windows system libraries
    set(PLATFORM_LIBS ws2_32 crypt32)
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# 3. Enable Qt-specific compilation tools
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

# 4. Find Required Packages
find_package(Qt6 REQUIRED COMPONENTS Widgets)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# 5. Handle External Dependencies
include(FetchContent)

# We have removed the FetchContent block for JSON because we are using 
# the single-header 'include/json.hpp' already in the project.

FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v1.12.0
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(spdlog)

# 6. Include Directories and Sources
include_directories(include)
include_directories(${OPENSSL_INCLUDE_DIR})

file(GLOB_RECURSE SOURCES "src/*.cpp")
file(GLOB_RECURSE HEADERS "include/*.hpp")

# 7. Create Executable
# WIN32 flag prevents a console window from appearing on launch
add_executable(TargexApp WIN32 ${SOURCES} ${HEADERS})

# 8. Link Libraries
target_link_libraries(TargexApp PRIVATE 
    Qt6::Widgets
    spdlog::spdlog 
    Threads::Threads
    OpenSSL::SSL    
    OpenSSL::Crypto
    ${PLATFORM_LIBS}
)

# 9. Installation Rules
include(GNUInstallDirs)
install(TARGETS TargexApp RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY public/ DESTINATION ${CMAKE_INSTALL_DATADIR}/targex/public)

if(WIN32)
    # Find the windeployqt executable
    get_target_property(_qt_bin_dir Qt6::Core LOCATION)
    get_filename_component(_qt_bin_dir "${_qt_bin_dir}" DIRECTORY)
    find_program(WINDEPLOYQT_EXECUTABLE windeployqt HINTS "${_qt_bin_dir}")

    # Run windeployqt after the build finishes
    add_custom_command(TARGET TargexApp POST_BUILD
        COMMAND "${WINDEPLOYQT_EXECUTABLE}"
                --release
                --no-translations
                "$<TARGET_FILE:TargexApp>"
        COMMENT "Deploying Qt dependencies for TargexApp..."
    )
endif()