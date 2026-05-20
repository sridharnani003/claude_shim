@echo off
:: run_fls30.bat — Launch FLS30 with packet shim
:: ================================================
:: Tries fls30_loader.exe (injection path) first.
:: If Norton blocks it, falls back to direct launch
:: which requires AppInit_DLLs to be registered
:: (run enable_appinit.reg once as Administrator).

setlocal
cd /d "%~dp0"

:: ── Check required files ──────────────────────
if not exist "%~dp0FLS30.exe" (
    echo [!] FLS30.exe not found in %~dp0
    pause & exit /b 1
)
if not exist "%~dp0packet_shim.dll" (
    echo [!] packet_shim.dll not found in %~dp0
    pause & exit /b 1
)

:: ── Try injection path ────────────────────────
if exist "%~dp0fls30_loader.exe" (
    echo [*] Launching via fls30_loader ...
    "%~dp0fls30_loader.exe" "%~dp0FLS30.exe"
    if %errorlevel% equ 0 goto done
    echo [!] fls30_loader failed ^(exit %errorlevel%^) — trying direct launch
)

:: ── Fallback: direct launch (AppInit_DLLs path) ──
echo [*] Launching FLS30.exe directly ^(AppInit_DLLs shim^)
echo     ^(If shim is not active: run enable_appinit.reg as Administrator first^)
start "" "%~dp0FLS30.exe"

:done
endlocal
