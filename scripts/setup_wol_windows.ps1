<#
.SYNOPSIS
    Configures Wake-on-LAN securely with robust error handling and hardware detection.

.DESCRIPTION
    This script automates the tedious process of enabling Wake-on-LAN (WoL) on Windows 10/11. 
    It dynamically locates your active Ethernet adapter, configures universal OS magic packet 
    listening, applies vendor-specific advanced driver properties (Intel/Realtek), disables 
    Fast Startup (which breaks WoL), adds a UDP Port 9 firewall exception, and registers the 
    adapter in the Windows kernel wake array.

.EXAMPLE
    To run this script on a fresh Windows installation, you must temporarily bypass the 
    PowerShell execution policy.

    1. Right-click the Start Menu and select "Windows PowerShell (Admin)" or "Terminal (Admin)".
    2. Run the following command to allow script execution for your current session:
       Set-ExecutionPolicy Bypass -Scope Process -Force
    3. Execute the script:
       .\setup_wol_windows.ps1
#>

[CmdletBinding()]
param ()

# ---------------------------------------------------------
# 1. ELEVATION CHECK (If-Else)
# ---------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning "This script requires Administrator privileges."
    Write-Warning "Please right-click PowerShell and select 'Run as Administrator'."
    exit
}

# ---------------------------------------------------------
# 2. MAIN EXECUTION BLOCK (Try/Catch)
# ---------------------------------------------------------
try {
    Write-Host "Scanning for physical network adapters..." -ForegroundColor Cyan
    
    # Grab the first active physical Ethernet connection
    $adapter = Get-NetAdapter | Where-Object { $_.PhysicalMediaType -eq "802.3" -and $_.Status -eq "Up" } | Select-Object -First 1

    # Fallback to offline adapters if none are 'Up'
    if (-not $adapter) {
        Write-Host "[LOG] No active wired connection found. Searching for offline adapters..." -ForegroundColor Yellow
        $adapter = Get-NetAdapter | Where-Object { $_.PhysicalMediaType -eq "802.3" } | Select-Object -First 1
    }

    if (-not $adapter) {
        throw "No physical Ethernet adapter found on this system." 
    }

    Write-Host "Targeting Adapter: $($adapter.Name) ($($adapter.InterfaceDescription))`n" -ForegroundColor Green

    # ---------------------------------------------------------
    # 3. UNIVERSAL POWER MANAGEMENT
    # ---------------------------------------------------------
    try {
        Write-Host "[LOG] Enabling Universal OS Magic Packet listening..."
        $adapter | Set-NetAdapterPowerManagement -WakeOnMagicPacket Enabled -ErrorAction Stop
    } catch {
        Write-Warning "Standard power management cmdlet failed or is not supported by this driver."
    }

    # ---------------------------------------------------------
    # 4. HARDWARE-SPECIFIC CONFIGURATION (Multi If-Else)
    # ---------------------------------------------------------
    if ($adapter.InterfaceDescription -match "Realtek") {
        Write-Host "[LOG] Realtek chipset detected. Applying custom Realtek properties..."
        Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "*ModernStandbyWoLMagicPacket" -DisplayValue "Enabled" -ErrorAction SilentlyContinue
        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Shutdown Wake-On-Lan" -DisplayValue "Enabled" -ErrorAction Stop
        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Wake on Magic Packet" -DisplayValue "Enabled" -ErrorAction SilentlyContinue
    }
    elseif ($adapter.InterfaceDescription -match "Intel") {
        Write-Host "[LOG] Intel chipset detected. Applying standard Intel properties..."
        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Wake on Magic Packet" -DisplayValue "Enabled" -ErrorAction Stop
        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Wake on Pattern Match" -DisplayValue "Enabled" -ErrorAction Stop
        Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "EnablePME" -RegistryValue "1" -ErrorAction SilentlyContinue
    }
    else {
        Write-Host "[LOG] Generic chipset detected. Applying baseline Magic Packet settings..."
        Set-NetAdapterAdvancedProperty -Name $adapter.Name -DisplayName "Wake on Magic Packet" -DisplayValue "Enabled" -ErrorAction Stop
        Set-NetAdapterAdvancedProperty -Name $adapter.Name -RegistryKeyword "EnablePME" -RegistryValue "1" -ErrorAction SilentlyContinue
    }

    # ---------------------------------------------------------
    # 5. OS POWER STATE CONFIGURATION (Nested Try/Catch)
    # ---------------------------------------------------------
    try {
        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
        $fastStartup = Get-ItemProperty -Path $regPath -Name "HiberbootEnabled" -ErrorAction Stop
        
        if ($fastStartup.HiberbootEnabled -eq 1) {
            Write-Host "[LOG] Disabling Windows Fast Startup..." -ForegroundColor Yellow
            Set-ItemProperty -Path $regPath -Name "HiberbootEnabled" -Value 0 -ErrorAction Stop
        } 
        else {
            Write-Host "[LOG] Fast Startup is already disabled. Skipping..." -ForegroundColor Green
        }
    } 
    catch {
        Write-Warning "Could not read or modify Fast Startup registry keys. They may be locked by Group Policy."
    }

    # ---------------------------------------------------------
    # 6. FIREWALL RULES
    # ---------------------------------------------------------
    try {
        Write-Host "[LOG] Checking Windows Defender Firewall for UDP Port 9..."
        $fwRule = Get-NetFirewallRule -DisplayName "Wake-on-LAN (UDP 9)" -ErrorAction SilentlyContinue
        if (-not $fwRule) {
            New-NetFirewallRule -DisplayName "Wake-on-LAN (UDP 9)" -Direction Inbound -LocalPort 9 -Protocol UDP -Action Allow -ErrorAction Stop | Out-Null
            Write-Host "  -> Firewall exception created." -ForegroundColor Green
        } else {
            Write-Host "  -> Firewall exception already exists." -ForegroundColor Green
        }
    } catch {
        Write-Warning "Could not add Firewall exception. You may need to open UDP port 9 manually."
    }

    # ---------------------------------------------------------
    # 7. KERNEL WAKE ARMING
    # ---------------------------------------------------------
    Write-Host "`n[LOG] Forcing OS Kernel to allow device wake..."
    powercfg /deviceenablewake $adapter.InterfaceDescription *>$null

    Write-Host "`n==========================================================" -ForegroundColor Cyan
    Write-Host "SUCCESS: Wake-on-LAN is configured at the OS level!" -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "IMPORTANT: You must still ensure Wake-on-LAN / PCIe Wake is" -ForegroundColor Yellow
    Write-Host "enabled in your computer's BIOS/UEFI settings for this to work." -ForegroundColor Yellow
    Write-Host "Also ensure settings like 'ErP Ready' or 'Deep Sleep' are DISABLED." -ForegroundColor Yellow
    Write-Host "==========================================================`n" -ForegroundColor Cyan
}
catch {
    # ---------------------------------------------------------
    # ERROR HANDLING
    # ---------------------------------------------------------
    Write-Host "`n[CRITICAL ERROR] The script encountered a failure:" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host "Failed at Line: $($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor DarkRed
}
finally {
    # ---------------------------------------------------------
    # CLEANUP
    # ---------------------------------------------------------
    Write-Host "`nExecution complete. Returning to prompt." -ForegroundColor DarkGray
}
