@echo off
setlocal enabledelayedexpansion

echo ===============================================================================
echo  BUILDING UNIFIED POINTERSCANNER ^& PLUGIN LOADER CONTROL CENTER (GUI)
echo ===============================================================================

set "PROJ_DIR=%~dp0"
cd /d "%PROJ_DIR%"

echo.
echo [1/3] Verifying Python and PyInstaller...
python --version
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Python not found on PATH!
    exit /b 1
)

echo.
echo [2/3] Compiling Standalone Single-File Windows GUI Executable...
python -m PyInstaller ^
    --noconfirm ^
    --clean ^
    --onefile ^
    --windowed ^
    --name "PointerScannerControlCenter" ^
    --icon "app_icon.ico" ^
    --add-data "pattern_database.json;." ^
    --add-data "logo.jpg;." ^
    --add-data "app_icon.ico;." ^
    --add-data "plugins;plugins" ^
    --add-data "manifests;manifests" ^
    --hidden-import "pefile" ^
    --hidden-import "PIL" ^
    --hidden-import "PIL.Image" ^
    --hidden-import "PIL.ImageTk" ^
    --hidden-import "windnd" ^
    --hidden-import "plugin_engine" ^
    --hidden-import "ScannerEngine" ^
    "PointerScannerControlCenter.pyw"

if %ERRORLEVEL% neq 0 (
    echo [ERROR] PyInstaller compilation failed!
    exit /b %ERRORLEVEL%
)

echo.
echo [3/3] Deploying standalone executable to project folders...
if exist "dist\PointerScannerControlCenter.exe" (
    copy /y "dist\PointerScannerControlCenter.exe" "%PROJ_DIR%PointerScannerControlCenter.exe" >nul
    copy /y "dist\PointerScannerControlCenter.exe" "%PROJ_DIR%..\PointerScannerControlCenter.exe" >nul
    copy /y "dist\PointerScannerControlCenter.exe" "%PROJ_DIR%..\temiz\PointerScannerControlCenter.exe" >nul
    echo Copied PointerScannerControlCenter.exe to:
    echo   - %PROJ_DIR%PointerScannerControlCenter.exe
    echo   - %PROJ_DIR%..\PointerScannerControlCenter.exe
    echo   - %PROJ_DIR%..\temiz\PointerScannerControlCenter.exe
)

echo.
echo ===============================================================================
echo  GUI BUILD COMPLETED SUCCESSFULLY!
echo ===============================================================================
