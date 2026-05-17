@echo off
setlocal
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x86 >nul 2>&1
cd /d "%~dp0"
cl /nologo /LD /W4 /O2 /MT /DUNICODE /D_UNICODE ^
   packet_shim.c ^
   /link /DLL /SUBSYSTEM:WINDOWS /MACHINE:X86 ^
   kernel32.lib advapi32.lib ws2_32.lib user32.lib ^
   /OUT:packet_shim.dll /DEF:packet_shim.def
