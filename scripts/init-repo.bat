@echo off
REM BackupShield - Initialize Repository (Windows)
REM Usage: init-repo.bat <repo_path> [--encrypt]
REM Example: init-repo.bat D:\Backups\repo

setlocal enabledelayedexpansion

if "%~1"=="" (
    echo Usage: init-repo.bat ^<repo_path^> [--encrypt]
    echo Example: init-repo.bat D:\Backups\repo
    exit /b 1
)

set "REPO_PATH=%~1"
set "ENCRYPT=0"

if /i "%~2"=="--encrypt" set "ENCRYPT=1"

set "BINARY=backup-shield.exe"

echo Initializing backup-shield repository at: %REPO_PATH%
echo Encrypt: %ENCRYPT%

REM Create parent directory if needed
for %%I in ("%REPO_PATH%") do set "PARENT=%%~dpI"
if not exist "%PARENT%" mkdir "%PARENT%"

REM Find binary (check current dir and release folder)
if not exist "%BINARY%" (
    if not exist "target\release\%BINARY%" (
        echo Error: backup-shield.exe not found
        echo Please compile with: cargo build --release
        exit /b 1
    )
    set "BINARY=target\release\%BINARY%"
)

if %ENCRYPT%==1 (
    "%BINARY%" init "%REPO_PATH%" --encrypt
) else (
    "%BINARY%" init "%REPO_PATH%"
)

if errorlevel 1 (
    echo Error: Failed to initialize repository
    exit /b 1
)

echo.
echo Repository initialized at: %REPO_PATH%
echo.
echo To make a backup:
echo   %BINARY% backup C:\Users\YourName\Documents --repo %REPO_PATH% -t "my backup"
echo.
echo To list snapshots:
echo   %BINARY% snapshots --repo %REPO_PATH%

endlocal