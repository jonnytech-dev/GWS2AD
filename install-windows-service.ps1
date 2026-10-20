# install-windows-service.ps1
# ===================================================================
# GWS2AD Flask App - Windows Service Installation Script
# ===================================================================
#
# WHAT THIS SCRIPT DOES:
# 1. Creates a Windows Service that runs the Flask app
# 2. Runs the service as a dedicated service account (NOT Administrator)
# 3. Sets it to auto-start on server reboot
# 4. Installs and starts the service
#
# HOW TO RUN:
#   1. Create service account in Active Directory (see docs/deployment.md)
#   2. Run as Administrator:
#      powershell -ExecutionPolicy Bypass -File install-windows-service.ps1
#   3. Answer the prompts (press Enter to accept the shown default)
#   4. Enter service account password when prompted
#   5. Service will start and auto-start on reboot
#
# THE SERVICE ACCOUNT:
#   - Should be a dedicated account created in Active Directory
#   - NOT your personal admin account
#   - Has permissions only to: this app's folder, AD sync OU, GWS API
#   - Password never expires (required for service accounts)
#   - Cannot be used for interactive login

# Requires Administrator privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "ERROR: This script must be run as Administrator" -ForegroundColor Red
    exit 1
}

Write-Host "========================================" -ForegroundColor Green
Write-Host "GWS2AD Flask - Windows Service Setup" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

# ==================== CONFIGURATION (interactive) ====================
# Auto-detected, but every value below can be overridden - press Enter
# to accept the default shown in [brackets], or type a different value.
#
# This script sits in the project folder, next to app.py. If you keep
# the app somewhere else, type the path when asked.
$DetectedAppDirectory = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($DetectedAppDirectory)) { $DetectedAppDirectory = (Get-Location).Path }

Write-Host ""
Write-Host "Answer the following (press Enter to accept the default):" -ForegroundColor Cyan
Write-Host ""

$ServiceName = Read-Host "Service name [GWS2AD-Flask]"
if ([string]::IsNullOrWhiteSpace($ServiceName)) { $ServiceName = "GWS2AD-Flask" }

$AppDirectory = Read-Host "App folder (contains app.py, venv, .env, etc.) [$DetectedAppDirectory]"
if ([string]::IsNullOrWhiteSpace($AppDirectory)) { $AppDirectory = $DetectedAppDirectory }

$AppPath = Join-Path $AppDirectory "app.py"

$DetectedPythonExe = Join-Path $AppDirectory "venv\Scripts\python.exe"
Write-Host "  (Defaults to the venv's own python.exe, not a system-wide install -"
Write-Host "   this is what actually has your pip-installed packages in it.)"
$PythonExe = Read-Host "Python executable [$DetectedPythonExe]"
if ([string]::IsNullOrWhiteSpace($PythonExe)) { $PythonExe = $DetectedPythonExe }

Write-Host ""
Write-Host "The service account should be a dedicated AD account created" -ForegroundColor Yellow
Write-Host "just for this app - NOT your personal admin account." -ForegroundColor Yellow
$ServiceAccount = Read-Host "Service account name (e.g. svc_gws2ad or DOMAIN\svc_gws2ad)"
while ([string]::IsNullOrWhiteSpace($ServiceAccount)) {
    Write-Host "  A service account name is required - there's no safe default." -ForegroundColor Red
    $ServiceAccount = Read-Host "Service account name (e.g. svc_gws2ad or DOMAIN\svc_gws2ad)"
}
# ==================== END CONFIGURATION ====================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "SERVICE ACCOUNT CONFIGURATION" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This service will run under a SERVICE ACCOUNT (not Administrator)." -ForegroundColor Yellow
Write-Host ""
Write-Host "Service Account Details:"
Write-Host "  Name: $ServiceAccount" -ForegroundColor Cyan
Write-Host "  Purpose: Run Flask app with minimal permissions"
Write-Host ""
Write-Host "VERIFY THE SERVICE ACCOUNT EXISTS:" -ForegroundColor Yellow
Write-Host "  In Active Directory Users & Computers:"
Write-Host "    - Find the account: $ServiceAccount"
Write-Host "    - Verify it's enabled"
Write-Host "    - Verify password never expires (important!)"
Write-Host ""
Write-Host "Check account password in Windows Credential Manager:" -ForegroundColor Yellow
Write-Host "  OR know the password now (you'll be prompted to enter it)"
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Please Review Configuration:" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Service Name:    $ServiceName"
Write-Host "  Python Path:     $PythonExe"
Write-Host "  App Path:        $AppPath"
Write-Host "  System Folder:   $AppDirectory"
Write-Host "  Service Account: $ServiceAccount" -ForegroundColor Cyan
Write-Host ""

$review = Read-Host "Is this configuration correct? (y/n)"
if ($review -ne "y" -and $review -ne "Y") {
    Write-Host "`nCancelled - run this script again and enter different values at the prompts." -ForegroundColor Yellow
    exit 0
}

Write-Host "`n✓ Configuration accepted." -ForegroundColor Green

# Check if Python exists
if (-not (Test-Path $PythonExe)) {
    Write-Host "`nERROR: Python not found at $PythonExe" -ForegroundColor Red
    Write-Host "  If you haven't set up the venv yet, create it first: python -m venv venv, then venv\Scripts\pip install -r requirements.txt" -ForegroundColor Yellow
    Write-Host "  Then run this script again." -ForegroundColor Yellow
    Write-Host "  If your setup is different, just enter a different path when" -ForegroundColor Yellow
    Write-Host "  prompted for the Python executable above." -ForegroundColor Yellow
    exit 1
}

# Check if app.py exists
if (-not (Test-Path $AppPath)) {
    Write-Host "`nERROR: app.py not found at $AppPath" -ForegroundColor Red
    exit 1
}

# Check if NSSM is installed
$nssm = Get-Command nssm -ErrorAction SilentlyContinue
if (-not $nssm) {
    Write-Host "`nWARNING: NSSM (service manager) not found in PATH" -ForegroundColor Yellow
    Write-Host "  Install options:"
    Write-Host "  1. Chocolatey: choco install nssm"
    Write-Host "  2. Download: https://nssm.cc/download"
    Write-Host "  3. Extract to: C:\tools\nssm"
    Write-Host ""
    
    # Try to find NSSM in common locations
    $possiblePaths = @(
        "C:\tools\nssm\win64\nssm.exe",
        "C:\Program Files\nssm\win64\nssm.exe",
        "$env:ProgramFiles\nssm\win64\nssm.exe"
    )
    
    $nssmPath = $null
    foreach ($path in $possiblePaths) {
        if (Test-Path $path) {
            $nssmPath = $path
            Write-Host "Found NSSM at: $nssmPath" -ForegroundColor Green
            break
        }
    }
    
    if (-not $nssmPath) {
        Write-Host "`nERROR: NSSM not found. Please install it first." -ForegroundColor Red
        exit 1
    }
} else {
    $nssmPath = $nssm.Source
}

# Check if service already exists
$existingService = Get-Service $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "`nWARNING: Service '$ServiceName' already exists" -ForegroundColor Yellow
    
    $response = Read-Host "  Stop and remove existing service? (y/n)"
    if ($response -eq "y" -or $response -eq "Y") {
        Write-Host "  Stopping service..."
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        
        Write-Host "  Removing service..."
        & $nssmPath remove $ServiceName confirm
        Start-Sleep -Seconds 2
    } else {
        Write-Host "  Keeping existing service. Exiting." -ForegroundColor Yellow
        exit 0
    }
}

# Prompt for service account password
Write-Host "`nService Account Configuration:" -ForegroundColor Cyan
Write-Host "  Account: $ServiceAccount"

$securePassword = Read-Host "  Password for $ServiceAccount" -AsSecureString
$password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($securePassword))

# =========================================================================
# CREATE THE WINDOWS SERVICE (will run as service account)
# =========================================================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Creating Windows Service..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "  Installing service '$ServiceName'..."
& $nssmPath install $ServiceName "$PythonExe" "$AppPath"

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to install service" -ForegroundColor Red
    exit 1
}

Write-Host "  ✓ Service installed" -ForegroundColor Green

# =========================================================================
# CONFIGURE SERVICE ACCOUNT (THIS IS THE KEY PART)
# =========================================================================
# This section configures the service to run as the service account
# instead of the System account or current user.
# 
# When Windows starts the service:
#   1. It uses the $ServiceAccount to run the process
#   2. Flask app runs with that account's permissions
#   3. That account can access: the app folder ($AppDirectory), AD sync OU, Google APIs
#   4. The app CANNOT access: System files, other users' data, etc.

Write-Host "  Configuring service account '$ServiceAccount'..."
Write-Host "    → Service will run as: $ServiceAccount" -ForegroundColor Cyan
Write-Host "    → Not as SYSTEM, not as current user"
Write-Host "    → This is more secure (least privilege principle)"

& $nssmPath set $ServiceName AppDirectory "$AppDirectory"
& $nssmPath set $ServiceName AppUser "$ServiceAccount"
& $nssmPath set $ServiceName AppPassword "$password"

Write-Host "  ✓ Service account configured" -ForegroundColor Green

# =========================================================================
# ENABLE AUTO-START ON REBOOT
# =========================================================================
# This sets the service to start automatically whenever the server reboots

Write-Host "  Setting auto-start on boot..."
Write-Host "    → Service will automatically start when server reboots" -ForegroundColor Cyan

& $nssmPath set $ServiceName Start SERVICE_AUTO_START

Write-Host "  ✓ Auto-start enabled" -ForegroundColor Green

# =========================================================================
# CONFIGURE FAILURE RECOVERY
# =========================================================================
# If the Flask app crashes, automatically restart it

Write-Host "  Configuring failure recovery..."
Write-Host "    → If Flask crashes, it will auto-restart after 5 seconds" -ForegroundColor Cyan

& $nssmPath set $ServiceName AppRestartDelay 5000

Write-Host "  ✓ Failure recovery configured" -ForegroundColor Green

# =========================================================================
# START THE SERVICE
# =========================================================================

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Starting Service..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

Write-Host "  Starting '$ServiceName'..."
Write-Host "    (Running as $ServiceAccount)" -ForegroundColor Cyan

Start-Service -Name $ServiceName -ErrorAction SilentlyContinue

Start-Sleep -Seconds 3

# Verify service is running
$service = Get-Service $ServiceName -ErrorAction SilentlyContinue
if ($service -and $service.Status -eq "Running") {
    Write-Host "  ✓ Service is RUNNING" -ForegroundColor Green
    Write-Host "    Running under: $ServiceAccount" -ForegroundColor Green
} else {
    Write-Host "  ✗ Service is NOT running" -ForegroundColor Yellow
    Write-Host "    Check logs for errors: $AppDirectory\logs\" -ForegroundColor Yellow
    Write-Host "    Try manually: Start-Service $ServiceName" -ForegroundColor Yellow
}

# Display summary
Write-Host "`n========================================" -ForegroundColor Green
Write-Host "✓ Installation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "WHAT JUST HAPPENED:" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "1. Service Created:" -ForegroundColor Yellow
Write-Host "   Name: $ServiceName"
Write-Host ""
Write-Host "2. Service Account Configured:" -ForegroundColor Yellow
Write-Host "   Account: $ServiceAccount"
Write-Host "   The Flask app will run as this account (not Administrator)"
Write-Host ""
Write-Host "3. Auto-Start Enabled:" -ForegroundColor Yellow
Write-Host "   The service will automatically start when the server reboots"
Write-Host "   No manual intervention needed after reboot"
Write-Host ""
Write-Host "4. Service Started:" -ForegroundColor Yellow
Write-Host "   The Flask app is now running as $ServiceAccount"
Write-Host ""

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "NEXT STEPS:" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  1. Open browser: http://localhost:5000"
Write-Host "  2. Login: admin / (password shown in console on first app start - check the service's log output)"
Write-Host "  3. Test the sync feature"
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SERVICE MANAGEMENT:" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Check Service Status:"
Write-Host "  Get-Service $ServiceName"
Write-Host "  → Shows if running, will show it runs as: $ServiceAccount"
Write-Host ""
Write-Host "Start Service:"
Write-Host "  Start-Service $ServiceName"
Write-Host ""
Write-Host "Stop Service:"
Write-Host "  Stop-Service $ServiceName"
Write-Host ""
Write-Host "Restart Service:"
Write-Host "  Restart-Service $ServiceName"
Write-Host ""
Write-Host "View Service Logs:"
Write-Host "  $AppDirectory\logs\"
Write-Host ""
Write-Host "View Running Processes:"
Write-Host "  Get-Process python | Where-Object {`$_.Name -like '*python*'}"
Write-Host "  → Should show Flask running as $ServiceAccount"
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "REBOOT BEHAVIOR:" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "When the server reboots:"
Write-Host "  1. Windows starts all auto-start services"
Write-Host "  2. Service '$ServiceName' auto-starts"
Write-Host "  3. Windows launches Python (app.py) as $ServiceAccount"
Write-Host "  4. Flask app binds to 0.0.0.0:5000"
Write-Host "  5. App is ready to accept admin connections"
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "VERIFY SERVICE ACCOUNT:" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Verify the service is running as the correct account:"
Write-Host ""
Write-Host "  Option 1 - PowerShell:"
Write-Host "    Get-WmiObject Win32_Service -Filter ""name='$ServiceName'"" | Select-Object Name, StartName"
Write-Host ""
Write-Host "  Option 2 - Task Manager:"
Write-Host "    1. Open Task Manager (Ctrl+Shift+Esc)"
Write-Host "    2. View → Show Processes from All Users"
Write-Host "    3. Look for: python.exe"
Write-Host "    4. Should show User: $ServiceAccount"
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "TO UNINSTALL THIS SERVICE:" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Stop-Service $ServiceName"
Write-Host "  nssm remove $ServiceName confirm"
Write-Host ""

Write-Host "========================================" -ForegroundColor Green
Write-Host "Service is ready! Test it now." -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
