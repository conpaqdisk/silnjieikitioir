@echo off
setlocal enabledelayedexpansion

echo ===============================================================================
echo  BUILDING PLUGIN_LOADER (x64)
echo ===============================================================================

set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\vcvarsall.bat"
if not exist "%VCVARS%" (
    echo [ERROR] vcvarsall.bat not found at "%VCVARS%"!
    exit /b 1
)

call "%VCVARS%" x64
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to initialize MSVC x64 environment!
    exit /b %ERRORLEVEL%
)

set "PROJ_DIR=%~dp0"
cd /d "%PROJ_DIR%"

echo.
echo [1/3] Configuring CMake project...
cmake -B build -S . -A x64
if %ERRORLEVEL% neq 0 (
    echo [ERROR] CMake configure failed!
    exit /b %ERRORLEVEL%
)

echo.
echo [2/3] Building Release configuration...
cmake --build build --config Release
if %ERRORLEVEL% neq 0 (
    echo [ERROR] CMake build failed!
    exit /b %ERRORLEVEL%
)

echo.
echo [3/3] Deploying binaries to project directory...
if not exist "%PROJ_DIR%plugins" mkdir "%PROJ_DIR%plugins"
if not exist "%PROJ_DIR%test_plugins" mkdir "%PROJ_DIR%test_plugins"

if exist "%PROJ_DIR%build\Release\host.exe" copy /y "%PROJ_DIR%build\Release\host.exe" "%PROJ_DIR%host.exe" >nul
if exist "%PROJ_DIR%build\Release\test_runner.exe" copy /y "%PROJ_DIR%build\Release\test_runner.exe" "%PROJ_DIR%test_runner.exe" >nul

if exist "%PROJ_DIR%build\Release\plugin_success.dll" copy /y "%PROJ_DIR%build\Release\*.dll" "%PROJ_DIR%plugins\" >nul
copy /y "%PROJ_DIR%manifests\*.ini" "%PROJ_DIR%plugins\" >nul

if exist "%PROJ_DIR%build\Release\plugin_success.dll" copy /y "%PROJ_DIR%build\Release\*.dll" "%PROJ_DIR%test_plugins\" >nul
copy /y "%PROJ_DIR%manifests\*.ini" "%PROJ_DIR%test_plugins\" >nul

REM Also copy to build\Release\plugins and build\Release\test_plugins for direct execution
if not exist "%PROJ_DIR%build\Release\plugins" mkdir "%PROJ_DIR%build\Release\plugins"
if not exist "%PROJ_DIR%build\Release\test_plugins" mkdir "%PROJ_DIR%build\Release\test_plugins"

if exist "%PROJ_DIR%build\Release\plugin_success.dll" copy /y "%PROJ_DIR%build\Release\*.dll" "%PROJ_DIR%build\Release\plugins\" >nul
copy /y "%PROJ_DIR%manifests\*.ini" "%PROJ_DIR%build\Release\plugins\" >nul
if exist "%PROJ_DIR%build\Release\plugin_success.dll" copy /y "%PROJ_DIR%build\Release\*.dll" "%PROJ_DIR%build\Release\test_plugins\" >nul
copy /y "%PROJ_DIR%manifests\*.ini" "%PROJ_DIR%build\Release\test_plugins\" >nul

echo.
echo ===============================================================================
echo  BUILD SUCCESSFUL!
echo ===============================================================================
