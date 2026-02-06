@echo off
set EXE_PATH=build\Release\TargexApp.exe
set QT_BIN=C:\Qt\6.10.2\msvc2022_64\bin

if not exist %EXE_PATH% (
    echo [ERROR] TargexApp.exe not found. Build the project in Release mode first.
    exit /b 1
)

echo [INFO] Deploying Qt dependencies...
"%QT_BIN%\windeployqt.exe" --release --no-translations --compiler-runtime %EXE_PATH%

echo [INFO] Copying OpenSSL DLLs...
copy "C:\Program Files\OpenSSL-Win64\bin\libcrypto-3-x64.dll" "build\Release\"
copy "C:\Program Files\OpenSSL-Win64\bin\libssl-3-x64.dll" "build\Release\"

echo [SUCCESS] Release folder is ready.