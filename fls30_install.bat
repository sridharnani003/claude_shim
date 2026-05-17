@echo off
:: fls30_install.bat
:: ==========================================
:: Sets up everything needed to run FLS30.exe
:: on Windows 11 via the Npcap shim approach.
::
:: Run as Administrator.
:: ==========================================

setlocal enabledelayedexpansion
echo.
echo  FLS30 Packet Shim Installer
echo  ============================
echo.

:: -- Check admin --
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Please run as Administrator
    pause & exit /b 1
)

set "SCRIPT_DIR=%~dp0"
set "NPCAP_INSTALLER=%SCRIPT_DIR%npcap-installer.exe"
set "FLS30_DIR=%SCRIPT_DIR%"

:: ── Step 1: Install Npcap ──────────────────────────────────────
echo [1/4] Checking Npcap...

sc query npcap >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] Npcap already installed
    goto step2
)

sc query NPF >nul 2>&1
if %errorlevel% equ 0 (
    echo [+] WinPcap/Npcap service found
    goto step2
)

if not exist "%NPCAP_INSTALLER%" (
    echo [*] Downloading Npcap...
    :: Download latest Npcap installer
    powershell -Command ^
        "Invoke-WebRequest -Uri 'https://npcap.com/dist/npcap-1.79.exe' ^
         -OutFile '%NPCAP_INSTALLER%' -UseBasicParsing"
    if not exist "%NPCAP_INSTALLER%" (
        echo [!] Download failed. Get Npcap from https://npcap.com
        echo     and place npcap-installer.exe next to this script.
        pause & exit /b 1
    )
)

echo [*] Installing Npcap (silent)...
"%NPCAP_INSTALLER%" /S /winpcap_mode=yes /loopback_support=no
timeout /t 5 /nobreak >nul

sc query npcap >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Npcap installation failed
    pause & exit /b 1
)
echo [+] Npcap installed

:step2
:: ── Step 2: Copy shim files ────────────────────────────────────
echo.
echo [2/4] Installing shim files...

:: Verify required files exist
if not exist "%SCRIPT_DIR%packet_shim.dll" (
    echo [!] packet_shim.dll not found in %SCRIPT_DIR%
    echo     Build it first: see BUILD.txt
    pause & exit /b 1
)
if not exist "%SCRIPT_DIR%fls30_loader.exe" (
    echo [!] fls30_loader.exe not found in %SCRIPT_DIR%
    echo     Build it first: see BUILD.txt
    pause & exit /b 1
)

echo [+] Shim files present

:: ── Step 3: Adapter GUID ───────────────────────────────────────
echo.
echo [3/4] Network adapter for DAU communication...
echo.
echo  Available network adapters:
echo  ----------------------------
powershell -Command ^
    "Get-NetAdapter | Format-Table -AutoSize Name, InterfaceDescription, MacAddress, InterfaceGuid"

echo.
echo  TIP: You can set the adapter now OR leave it blank and the
echo       GUI picker will appear automatically on the first FLS30
echo       launch (adapter saved to fls30_shim.ini for future runs).
echo.
echo  Paste the InterfaceGuid of the Ethernet port connected to the
echo  DAU (including braces), or press ENTER to use the GUI picker.
echo.
set /p "USER_GUID=  GUID (or ENTER to use first-run picker): "

if not "!USER_GUID!"=="" (
    :: Create or update fls30_shim.ini with the chosen GUID
    if not exist "%SCRIPT_DIR%fls30_shim.ini" (
        echo [Npcap]> "%SCRIPT_DIR%fls30_shim.ini"
        echo AdapterGUID=>> "%SCRIPT_DIR%fls30_shim.ini"
        echo.>> "%SCRIPT_DIR%fls30_shim.ini"
        echo [Adapter]>> "%SCRIPT_DIR%fls30_shim.ini"
        echo FriendlyName=FLS30DAU>> "%SCRIPT_DIR%fls30_shim.ini"
        echo.>> "%SCRIPT_DIR%fls30_shim.ini"
        echo [Debug]>> "%SCRIPT_DIR%fls30_shim.ini"
        echo TestMode=0>> "%SCRIPT_DIR%fls30_shim.ini"
    )
    powershell -Command ^
        "(Get-Content '%SCRIPT_DIR%fls30_shim.ini') ^
         -replace '^AdapterGUID=.*', 'AdapterGUID=!USER_GUID!' ^
         | Set-Content '%SCRIPT_DIR%fls30_shim.ini'"
    echo [+] Adapter GUID saved to fls30_shim.ini: !USER_GUID!
) else (
    echo [*] No GUID entered — GUI picker will appear on first FLS30 launch
)

:: ── Step 4: Create launch shortcut ────────────────────────────
echo.
echo [4/4] Creating FLS30 shortcut...

powershell -Command ^
    "$ws = New-Object -ComObject WScript.Shell; ^
     $sc = $ws.CreateShortcut('%USERPROFILE%\Desktop\FLS30 (Win11).lnk'); ^
     $sc.TargetPath = '%SCRIPT_DIR%fls30_loader.exe'; ^
     $sc.Arguments = '%SCRIPT_DIR%FLS30.exe'; ^
     $sc.WorkingDirectory = '%SCRIPT_DIR%'; ^
     $sc.Description = 'FLS30 with Npcap shim'; ^
     $sc.Save()"

echo [+] Shortcut created on Desktop: "FLS30 (Win11)"

:: ── Done ──────────────────────────────────────────────────────
echo.
echo  ============================================
echo   Installation complete!
echo  ============================================
echo.
echo   To run FLS30:  fls30_loader.exe FLS30.exe
echo              or: use the Desktop shortcut
echo.
echo   To debug:  Run DebugView (Sysinternals) as Admin
echo              Enable: Capture ^> Capture Win32
echo              Filter: [PacketShim]
echo.
pause
