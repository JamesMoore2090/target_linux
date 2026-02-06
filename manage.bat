@echo off
SETLOCAL EnableDelayedExpansion

:: Define paths and executable names
set BUILD_DIR=C:\TARGEX
set EXE_NAME=TargexApp.exe
set CONFIG=Release

if "%~1"=="" goto usage
if "%~1"=="build" goto build
if "%~1"=="clean" goto clean
if "%~1"=="run" goto run
if "%~1"=="rebuild" goto rebuild

:usage
echo Usage: manage.bat [build^|clean^|run^|rebuild]
goto end

:clean
if exist %BUILD_DIR% (
    echo [INFO] Removing build directory...
    rmdir /s /q %BUILD_DIR%
)
goto end
:build
if not exist %BUILD_DIR% mkdir %BUILD_DIR%
echo [INFO] Configuring CMake...
set QT_PATH=C:\Qt\6.10.2\msvc2022_64
set OPENSSL_PATH=C:/Program Files/OpenSSL-Win64

cmake -G "Visual Studio 18 2026" -A x64 -B %BUILD_DIR% -S . ^
      -DCMAKE_PREFIX_PATH="%QT_PATH%" ^
      -DOPENSSL_ROOT_DIR="%OPENSSL_PATH%" ^
      -DOPENSSL_USE_STATIC_LIBS=FALSE
      
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%

echo [INFO] Building %CONFIG%...
cmake --build %BUILD_DIR% --config %CONFIG%
echo [INFO] Copying Web Files...
xcopy /E /I /Y "public" "%BUILD_DIR%\Release\public"
xcopy /E /I /Y "resources" "%BUILD_DIR%\Release\resources"
if %ERRORLEVEL% neq 0 exit /b %ERRORLEVEL%
goto end

:run
set RUN_PATH=%BUILD_DIR%\%CONFIG%\%EXE_NAME%
if exist "%RUN_PATH%" (
    echo [INFO] Launching %EXE_NAME%...
    start "" "%RUN_PATH%"
) else (
    echo [ERROR] Executable not found at %RUN_PATH%. Run 'manage.bat build' first.
)
goto end

:rebuild
call :clean
call :build
goto end

:end
ENDLOCAL