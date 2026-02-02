#!/bin/bash

# ==========================================
# TARGEX CLI - Development Manager
# ==========================================


# Define paths
BUILD_DIR="build"
BIN_NAME="targex_cli"
CONFIG_FILE="resources/config.json"

# Helper function to print headers
print_header() {
    echo -e "\n\033[1;34m[TARGEX] $1\033[0m"
}

# 1. CLEAN FUNCTION
do_clean() {
    print_header "Cleaning Build Directory..."
    if [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
        echo " - Build directory removed."
    else
        echo " - No build directory found. Skipping."
    fi
}

# 2. BUILD FUNCTION (Updates CMake automatically)
do_build() {
    print_header "Building Project..."
    
    # Create build dir if missing
    if [ ! -d "$BUILD_DIR" ]; then
        mkdir "$BUILD_DIR"
    fi

    # Configure (This picks up new files because of file(GLOB) in CMakeLists)
    cmake -S . -B "$BUILD_DIR"
    
    # Compile
    # The --j$(nproc) flag uses all CPU cores for faster builds
    if cmake --build "$BUILD_DIR" -- -j$(nproc); then
        echo -e "\033[1;32m - Build Successful.\033[0m"
    else
        echo -e "\033[1;31m - Build Failed.\033[0m"
        exit 1
    fi
}

# 3. RUN FUNCTION
do_run() {
    print_header "Running TARGEX-CLI..."
    if [ ! -d "logs" ]; then
        echo " - Creating logs directory..."
        mkdir "logs"
    fi
    if [ ! -d "output" ]; then
        echo " - Creating output directory..."
        mkdir "output"
    fi
    if [ -f "$BUILD_DIR/$BIN_NAME" ]; then
        # Pass any extra arguments to the app
        # ./"$BUILD_DIR/$BIN_NAME"
        ./"$BUILD_DIR/$BIN_NAME" "$CONFIG_FILE"
    else
        echo -e "\033[1;31m - Error: Executable not found. Did the build fail?\033[0m"
        exit 1
    fi
}

# ==========================================
# LOGIC CONTROLLER
# ==========================================

case "$1" in
    clean)
        do_clean
        ;;
    build)
        do_build
        ;;
    run)
        do_run
        ;;
    all)
        # "Clean and Build and Run"
        do_clean
        do_build
        do_run
        ;;
    dev)
        # "Build and Run" (Most common dev cycle)
        do_build
        do_run
        ;;
    *)
        echo "Usage: ./manage.sh {clean|build|run|dev|all}"
        echo "  clean : Remove build artifacts"
        echo "  build : Detect new files and compile"
        echo "  run   : Run the application"
        echo "  dev   : Build + Run (Fast iteration)"
        echo "  all   : Clean + Build + Run (Fresh start)"
        exit 1
        ;;
esac