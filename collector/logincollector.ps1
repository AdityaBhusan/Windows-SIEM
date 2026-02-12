# ==========================================
# Windows Mini SIEM - Log Collector
# Collects authentication events (4625, 4624)
# ==========================================

# Get the directory where this script lives
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# Define logs directory relative to project root
$OutputDir = Join-Path $ScriptRoot "..\logs"

# Create logs directory if it doesn't exist
if (!(Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}
function Get-EventDataValue {
    param (
        [object[]]$DataNodes,
        [string]$Name
    )

    $node = $DataNodes | Where-Object { $_.Name -eq $Name }
    if ($null -eq $node) {
        return "-"
    }
    return $node.'#text'
}

function Collect-AuthEvents {
    param (
        [int]$EventID,
        [string]$OutputFile
    )

    Write-Host "[*] Collecting Event ID $EventID ..."

    # Use XPath for reliability
    $events = Get-WinEvent -LogName Security `
        -FilterXPath "*[System[(EventID=$EventID)]]" `
        -MaxEvents 50

    # FORCE a real array container
    $resultsArray = [System.Collections.ArrayList]::new()

    foreach ($event in $events) {
        $xml  = [xml]$event.ToXml()
        $data = $xml.Event.EventData.Data

        $record = @{
            timestamp   = $event.TimeCreated
            event_id    = $EventID
            username    = Get-EventDataValue $data "TargetUserName"
            source_ip   = Get-EventDataValue $data "IpAddress"
            logon_type  = Get-EventDataValue $data "LogonType"
            workstation = Get-EventDataValue $data "WorkstationName"
        }

        # Add record safely
        [void]$resultsArray.Add($record)
    }

    $resultsArray.ToArray() |
        ConvertTo-Json -Depth 3 |
        Out-File -Encoding utf8 "$OutputDir/$OutputFile"

    Write-Host "[+] Saved $($resultsArray.Count) events to $OutputFile"
}
function Collect-AdminPrivilegeEvents {
    param (
        [string]$OutputFile
    )

    Write-Host "[*] Collecting Event ID 4672 (Admin Privileges)..."

    $events = Get-WinEvent -LogName Security `
        -FilterXPath "*[System[(EventID=4672)]]" `
        -MaxEvents 50

    $resultsArray = [System.Collections.ArrayList]::new()

    foreach ($event in $events) {
        $xml  = [xml]$event.ToXml()
        $data = $xml.Event.EventData.Data

        $record = @{
            timestamp = $event.TimeCreated
            event_id  = 4672
            username  = Get-EventDataValue $data "SubjectUserName"
            privileges = Get-EventDataValue $data "PrivilegeList"
        }

        [void]$resultsArray.Add($record)
    }

    $resultsArray.ToArray() |
        ConvertTo-Json -Depth 3 |
        Out-File -Encoding utf8 "$OutputDir/$OutputFile"

    Write-Host "[+] Saved $($resultsArray.Count) admin privilege events"
}
function Collect-ProcessCreationEvents {
    param (
        [string]$OutputFile
    )

    Write-Host "[*] Collecting Event ID 4688 (Process Creation)..."

    $events = Get-WinEvent -LogName Security `
        -FilterXPath "*[System[(EventID=4688)]]" `
        -MaxEvents 50

    $resultsArray = [System.Collections.ArrayList]::new()

    foreach ($event in $events) {
        $xml  = [xml]$event.ToXml()
        $data = $xml.Event.EventData.Data

        $record = @{
            timestamp     = $event.TimeCreated
            event_id      = 4688
            username      = Get-EventDataValue $data "SubjectUserName"
            process_name  = Get-EventDataValue $data "NewProcessName"
            command_line  = Get-EventDataValue $data "CommandLine"
            parent_process = Get-EventDataValue $data "ParentProcessName"
        }

        [void]$resultsArray.Add($record)
    }

    $resultsArray.ToArray() |
        ConvertTo-Json -Depth 3 |
        Out-File -Encoding utf8 "$OutputDir/$OutputFile"

    Write-Host "[+] Saved $($resultsArray.Count) process creation events"
}



Collect-AuthEvents -EventID 4625 -OutputFile "security_4625_failed.json"
Collect-AuthEvents -EventID 4624 -OutputFile "security_4624_success.json"
Collect-AdminPrivilegeEvents -OutputFile "security_4672_admin.json"
Collect-ProcessCreationEvents -OutputFile "security_4688_process.json"

Write-Host "Authentication event collection complete"
