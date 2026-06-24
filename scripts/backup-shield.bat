@echo off
REM BackupShield - Main Backup Script (Windows)
REM Usage: backup-shield.bat <source_path> <repo_path> [options]
REM 
REM Options:
REM   -t, --tag TAG          Tag for this backup
REM   --keep-daily N         Backup giornalieri da mantenere (default: 7)
REM   --keep-weekly N        Backup settamanali da mantenere (default: 4)
REM
REM Example:
REM   backup-shield.bat C:\Users\YourName\Documents D:\Backups\repo -t "backup giornaliero"

setlocal enabledelayedexpansion

set "SOURCE_PATH="
set "REPO_PATH="
set "TAG="
set "KEEP_DAILY=7"
set "KEEP_WEEKLY=4"

REM Parse arguments
:parse_args
if "%~1"=="" goto end_parse
if "%~1"=="-t" (
    set "TAG=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--tag" (
    set "TAG=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--keep-daily" (
    set "KEEP_DAILY=%~2"
    shift
    shift
    goto parse_args
)
if /i "%~1"=="--keep-weekly" (
    set "KEEP_WEEKLY=%~2"
    shift
    shift
    goto parse_args
)
if "%SOURCE_PATH%"=="" (
    set "SOURCE_PATH=%~1"
) else if "%REPO_PATH%"=="" (
    set "REPO_PATH=%~1"
)
shift
goto parse_args

:end_parse

if "%SOURCE_PATH%"=="" (
    echo Usage: backup-shield.bat ^<source_path^> ^<repo_path^> [options]
    echo.
    echo Arguments:
    echo   source_path    Path da backuppare (es. C:\Users\utente\Documenti)
    echo   repo_path      Path del repository backup-shield
    echo.
    echo Options:
    echo   -t, --tag TAG          Tag per questo backup
    echo   --keep-daily N         Backup giornalieri da mantenere (default: 7)
    echo   --keep-weekly N       Backup settimanali da mantenere (default: 4)
    echo.
    echo Example:
    echo   backup-shield.bat C:\Users\utente\Documents D:\Backups\repo -t "backup giornaliero"
    exit /b 1
)
if "%REPO_PATH%"=="" (
    echo Usage: backup-shield.bat ^<source_path^> ^<repo_path^> [options]
    echo.
    echo Arguments:
    echo   source_path    Path da backuppare (es. C:\Users\utente\Documenti)
    echo   repo_path      Path del repository backup-shield
    echo.
    echo Options:
    echo   -t, --tag TAG          Tag per questo backup
    echo   --keep-daily N         Backup giornalieri da mantenere (default: 7)
    echo   --keep-weekly N       Backup settimanali da mantenere (default: 4)
    echo.
    echo Example:
    echo   backup-shield.bat C:\Users\utente\Documents D:\Backups\repo -t "backup giornaliero"
    exit /b 1
)

if not exist "%SOURCE_PATH%" (
    echo Error: Source path does not exist: %SOURCE_PATH%
    exit /b 1
)

if not exist "%REPO_PATH%" (
    echo Error: Repository does not exist: %REPO_PATH%
    echo Run: init-repo.bat %REPO_PATH%
    exit /b 1
)

set "BINARY=backup-shield.exe"

REM Find binary
if not exist "%BINARY%" (
    if not exist "target\release\%BINARY%" (
        echo Error: backup-shield.exe not found
        echo Please compile with: cargo build --release
        exit /b 1
    )
    set "BINARY=target\release\%BINARY%"
)

echo ========================================
echo   BackupShield - Windows Backup Script
echo ========================================
echo.
echo Source:      %SOURCE_PATH%
echo Repository:  %REPO_PATH%
echo Tag:         %TAG%
echo Keep:        %KEEP_DAILY% daily, %KEEP_WEEKLY% weekly
echo.

REM Run backup
echo Starting backup...
set "START_TIME=%TIME%"

if defined TAG (
    "%BINARY%" backup "%SOURCE_PATH%" --repo "%REPO_PATH%" -t "%TAG%"
) else (
    "%BINARY%" backup "%SOURCE_PATH%" --repo "%REPO_PATH%"
)

if errorlevel 1 (
    echo Error: Backup failed
    exit /b 1
)

echo.
echo Backup completed

REM Prune old backups
echo Pruning old backups...
"%BINARY%" prune "%REPO_PATH%" --keep-daily %KEEP_DAILY% --keep-weekly %KEEP_WEEKLY%

REM Verify
echo Verifying repository...
"%BINARY%" verify "%REPO_PATH%" --quick

REM Show stats
echo.
echo Repository stats:
"%BINARY%" stats "%REPO_PATH%"

echo.
echo Backup completed successfully!

endlocal