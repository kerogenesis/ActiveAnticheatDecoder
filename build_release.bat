@echo off
setlocal


echo   Building ActiveAnticheatDecoder (Release x86)

rustup target add i686-pc-windows-msvc
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to add Rust i686-pc-windows-msvc target.
    pause
    exit /b 1
)

cargo build --release --target i686-pc-windows-msvc
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Cargo build failed!
    pause
    exit /b 1
)

echo Signing the binary (same self-signed signature as CI)...
where pwsh >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    set "PWSH=pwsh"
) else (
    set "PWSH=powershell"
)
%PWSH% -NoProfile -ExecutionPolicy Bypass -Command "Import-Module Microsoft.PowerShell.Security; . '.\res\sign\Invoke-LazySign.ps1'; Invoke-LazySign -Target 'target\i686-pc-windows-msvc\release\decoder.exe' -Domain 'twitter.com' -Password 'kyprivet999'; if ((Get-AuthenticodeSignature 'target\i686-pc-windows-msvc\release\decoder.exe').Status -eq 'NotSigned') { exit 1 }"
if %ERRORLEVEL% NEQ 0 (
    echo [WARN] Signing failed, continuing unsigned.
)

if not exist "bin" mkdir "bin"
copy /Y "target\i686-pc-windows-msvc\release\decoder.exe" "bin\ActiveAnticheatDecoder.exe" >nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to copy the binary to bin!
    pause
    exit /b 1
)

rmdir /S /Q target

echo.
echo [SUCCESS] Binary successfully compiled to:
echo bin\ActiveAnticheatDecoder.exe
echo.
pause
