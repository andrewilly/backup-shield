# BackupShield - Install Scheduled Tasks (Windows)
# Usage: .\install-schedule.ps1 -Schedule daily -RepoPath "D:\Backups\repo" -SourcePath "C:\Users\YourUser\Documents"
#        .\install-schedule.ps1 -Schedule hourly -RepoPath "D:\Backups\repo" -SourcePath "C:\Users\YourUser\Documents"

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("hourly", "daily", "weekly")]
    [string]$Schedule,

    [Parameter(Mandatory=$true)]
    [string]$RepoPath,

    [Parameter(Mandatory=$true)]
    [string]$SourcePath,

    [string]$Tag = "automatic",

    [switch]$Uninstall
)

$BinaryPath = Join-Path $PSScriptRoot "..\target\release\backup-shield.exe"

if (-not (Test-Path $BinaryPath)) {
    Write-Host "Error: backup-shield.exe not found at $BinaryPath" -ForegroundColor Red
    Write-Host "Please compile with: cargo build --release" -ForegroundColor Yellow
    exit 1
}

$TaskName = "BackupShield-$Schedule"

if ($Uninstall) {
    Write-Host "Uninstalling scheduled task: $TaskName" -ForegroundColor Yellow
    schtasks /delete /tn $TaskName /f 2>$null
    Write-Host "Done." -ForegroundColor Green
    exit 0
}

# Build arguments
$Args = "backup `"$SourcePath`" --repo `"$RepoPath`" -t `"$Tag`""

# Determine schedule type
$ScheduleArgs = switch ($Schedule) {
    "hourly" { "/sc hourly" }
    "daily"  { "/sc daily /st 02:00" }
    "weekly" { "/sc weekly /d SUN /st 03:00" }
}

Write-Host "Installing BackupShield $Schedule backup task..." -ForegroundColor Cyan
Write-Host "  Task Name: $TaskName"
Write-Host "  Source:    $SourcePath"
Write-Host "  Repo:      $RepoPath"
Write-Host "  Tag:       $Tag"
Write-Host "  Binary:    $BinaryPath"
Write-Host ""

# Create scheduled task
$Result = schtasks /create /tn $TaskName /tr "`"$BinaryPath`" $Args" $ScheduleArgs /f 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host "Scheduled task installed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "To run manually: schtasks /run /tn $TaskName" -ForegroundColor White
    Write-Host "To disable:      schtasks /change /tn $TaskName /disable" -ForegroundColor White
    Write-Host "To remove:        schtasks /delete /tn $TaskName /f" -ForegroundColor White
} else {
    Write-Host "Error creating scheduled task: $Result" -ForegroundColor Red
    exit 1
}