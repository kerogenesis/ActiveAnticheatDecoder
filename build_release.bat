@echo off
setlocal enabledelayedexpansion


echo   Building ActiveAnticheatDecoder (Release x86)

rustup target add i686-pc-windows-msvc
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to add Rust i686-pc-windows-msvc target.
    pause
    exit /b 1
)

where cl >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [INFO] Searching for Visual Studio vcvars32.bat...
    set "VCVARS="

    set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
    if exist "!VSWHERE!" (
        for /f "tokens=*" %%i in ('"!VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath') do (
            if exist "%%i\VC\Auxiliary\Build\vcvars32.bat" (
                set "VCVARS=%%i\VC\Auxiliary\Build\vcvars32.bat"
            )
        )
    )

    if not defined VCVARS (
        if exist "%ProgramFiles%\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars32.bat" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars32.bat"
        if exist "%ProgramFiles%\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvars32.bat" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\18\Professional\VC\Auxiliary\Build\vcvars32.bat"
        if exist "%ProgramFiles%\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars32.bat" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars32.bat"
        if exist "%ProgramFiles%\Microsoft Visual Studio\2026\Community\VC\Auxiliary\Build\vcvars32.bat" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2026\Community\VC\Auxiliary\Build\vcvars32.bat"
        if exist "%ProgramFiles%\Microsoft Visual Studio\2026\Professional\VC\Auxiliary\Build\vcvars32.bat" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2026\Professional\VC\Auxiliary\Build\vcvars32.bat"
        if exist "%ProgramFiles%\Microsoft Visual Studio\2026\Enterprise\VC\Auxiliary\Build\vcvars32.bat" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2026\Enterprise\VC\Auxiliary\Build\vcvars32.bat"
        if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat"
        if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars32.bat" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars32.bat"
        if exist "%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars32.bat" set "VCVARS=%ProgramFiles%\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars32.bat"
        if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat" set "VCVARS=%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars32.bat"
        if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars32.bat" set "VCVARS=%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Professional\VC\Auxiliary\Build\vcvars32.bat"
        if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars32.bat" set "VCVARS=%ProgramFiles(x86)%\Microsoft Visual Studio\2019\Enterprise\VC\Auxiliary\Build\vcvars32.bat"
    )

    if defined VCVARS (
        call "!VCVARS!" >nul
    ) else (
        echo [ERROR] Could not find MSVC compiler cl.exe or vcvars32.bat.
        echo Please run this script from a Developer Command Prompt for Visual Studio.
        pause
        exit /b 1
    )
)

echo [1/2] Compiling aa_proxy.dll...
if not exist "target\proxy_build" mkdir "target\proxy_build"

cl /nologo /O2 /MT /std:c++20 /EHsc /LD /Iproxy\vendor proxy\aa_proxy.cpp /Fo:target\proxy_build\ /Fe:target\proxy_build\aa_proxy.dll /link /MACHINE:X86 user32.lib kernel32.lib >nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to compile C++ proxy DLL!
    pause
    exit /b 1
)

echo [2/2] Building Rust executable...
set "AA_PROXY_DLL=%CD%\target\proxy_build\aa_proxy.dll"

cargo build --release --target i686-pc-windows-msvc
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Cargo build failed!
    pause
    exit /b 1
)

echo.
echo [SUCCESS] Binary successfully compiled to:
echo target\i686-pc-windows-msvc\release\decoder.exe
echo.
pause
