<#
.SYNOPSIS
    Retrieves all available DNS records for a specified domain name and exports them to a text file.

.DESCRIPTION
    By design, DNS does not support an "all-in-one" query unless Zone Transfer (AXFR) is permitted.
    This script:
    1. Queries all common record types for the apex domain (A, AAAA, MX, TXT, NS, SOA, CAA, CNAME, SRV).
    2. Attempts a Zone Transfer (AXFR) on the authoritative nameservers.
    3. Checks a list of common subdomains (e.g., www, mail, autodiscover, ftp, api).
    4. Formats and writes all discovered records to a .txt file.

.PARAMETER Domain
    The domain name to inspect (e.g. "example.com" or "mydomain.com").

.PARAMETER OutputFile
    (Optional) Path to the output text file. Defaults to "<domain>_dns_records.txt" in the current directory.

.PARAMETER SkipSubdomains
    (Optional) Skips scanning of common subdomains.

.EXAMPLE
    .\Get-DnsRecords.ps1 -Domain "google.com"
    .\Get-DnsRecords.ps1 -Domain "example.com" -OutputFile "C:\records.txt"
    .\Get-DnsRecords.ps1 -Domain "example.com" -SkipSubdomains
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Enter the domain name (e.g. example.com)")]
    [ValidateNotNullOrEmpty()]
    [string]$Domain,

    [Parameter(Position = 1)]
    [string]$OutputFile = "",

    [switch]$SkipSubdomains
)

# Sanitize domain input (remove http://, https://, trailing slashes, whitespace)
$cleanDomain = $Domain.Trim().ToLower()
$cleanDomain = $cleanDomain -replace "^https?://", ""
$cleanDomain = $cleanDomain -replace "/.*$", ""

if (-not $OutputFile) {
    $OutputFile = Join-Path -Path $PSScriptRoot -ChildPath "$($cleanDomain)_dns_records.txt"
}

$recordTypes = @('A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'CNAME', 'SRV')
$commonSubdomains = @(
    'www', 'mail', 'autodiscover', 'webmail', 'smtp', 'pop', 'imap', 
    'ftp', 'api', 'admin', 'portal', 'remote', 'vpn', 'cpanel', 
    'dev', 'staging', 'test', 'm', 'shop', 'blog', 'app', 'secure'
)

$outputLines = [System.Collections.Generic.List[string]]::new()

function Write-LogMessage {
    param([string]$Message, [switch]$ConsoleOnly)
    Write-Host $Message
    if (-not $ConsoleOnly) {
        $outputLines.Add($Message)
    }
}

Write-LogMessage "================================================================================"
Write-LogMessage " DNS RECORDS REPORT FOR: $cleanDomain"
Write-LogMessage " Generated at          : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-LogMessage "================================================================================"
Write-LogMessage ""

# 1. Retrieve authoritative nameservers
Write-LogMessage "[1] Nameservers (NS records)"
Write-LogMessage "--------------------------------------------------------------------------------"
$nameServers = @()
try {
    $nsRecords = Resolve-DnsName -Name $cleanDomain -Type NS -ErrorAction Stop | Where-Object { $_.Section -eq 'Answer' }
    foreach ($ns in $nsRecords) {
        if ($ns.NameHost) {
            $nameServers += $ns.NameHost
            Write-LogMessage ("    NS: {0}" -f $ns.NameHost)
        }
    }
}
catch {
    Write-LogMessage "    [!] Could not resolve nameservers via standard DNS."
}
Write-LogMessage ""

# 2. Attempt Zone Transfer (AXFR)
Write-LogMessage "[2] Testing Zone Transfer (AXFR)"
Write-LogMessage "--------------------------------------------------------------------------------"
$axfrSuccess = $false
if ($nameServers.Count -gt 0) {
    foreach ($ns in $nameServers) {
        try {
            $zoneTransfer = Resolve-DnsName -Name $cleanDomain -Type AXFR -Server $ns -ErrorAction Stop | Where-Object { $_.Section -eq 'Answer' }
            if ($zoneTransfer) {
                Write-LogMessage "    [!] ZONE TRANSFER SUCCEEDED on nameserver: $ns"
                foreach ($rec in $zoneTransfer) {
                    $val = switch ($rec.Type) {
                        'A'     { $rec.IPAddress }
                        'AAAA' { $rec.IPAddress }
                        'CNAME' { $rec.NameHost }
                        'MX'    { "$($rec.NameExchange) (Priority: $($rec.Preference))" }
                        'TXT'   { ($rec.Strings -join ' ') }
                        'NS'    { $rec.NameHost }
                        'SOA'   { "Primary: $($rec.PrimaryServer), Admin: $($rec.Administrator)" }
                        default { ($rec | Out-String).Trim() }
                    }
                    Write-LogMessage ("    {0,-8} {1,-35} {2}" -f $rec.Type, $rec.Name, $val)
                }
                $axfrSuccess = $true
                break
            }
        }
        catch {
            # AXFR is disabled/blocked (standard security practice)
        }
    }
}

if (-not $axfrSuccess) {
    Write-LogMessage "    Info: Zone Transfer is restricted by the nameservers (this is normal and secure)."
    Write-LogMessage ""

    # 3. Query apex domain records
    Write-LogMessage "[3] Apex domain records ($cleanDomain)"
    Write-LogMessage "--------------------------------------------------------------------------------"
    $foundApex = 0
    foreach ($type in $recordTypes) {
        try {
            $results = Resolve-DnsName -Name $cleanDomain -Type $type -ErrorAction Stop | Where-Object { $_.Section -eq 'Answer' }
            foreach ($rec in $results) {
                $foundApex++
                $val = switch ($rec.Type) {
                    'A'     { $rec.IPAddress }
                    'AAAA' { $rec.IPAddress }
                    'CNAME' { $rec.NameHost }
                    'MX'    { "{0} (Priority: {1})" -f $rec.NameExchange, $rec.Preference }
                    'TXT'   { ($rec.Strings -join ' ') }
                    'NS'    { $rec.NameHost }
                    'SOA'   { "Primary: $($rec.PrimaryServer) | Admin: $($rec.Administrator) | Serial: $($rec.SerialNumber)" }
                    'CAA'   { "Flags: $($rec.Flags) | Tag: $($rec.Tag) | Value: $($rec.Value)" }
                    'SRV'   { "Target: $($rec.NameTarget) | Port: $($rec.Port) | Priority: $($rec.Priority) | Weight: $($rec.Weight)" }
                    default { ($rec | Select-Object -Property * -ExcludeProperty Cim* | Out-String).Trim() }
                }
                Write-LogMessage ("    [{0,-6}] TTL: {1,-6} {2}" -f $rec.Type, $rec.TTL, $val)
            }
        }
        catch {
            # No records found for this type
        }
    }
    if ($foundApex -eq 0) {
        Write-LogMessage "    No standard records found."
    }
    Write-LogMessage ""

    # 4. Scan common subdomains
    if (-not $SkipSubdomains) {
        Write-LogMessage "[4] Common subdomains"
        Write-LogMessage "--------------------------------------------------------------------------------"
        $foundSubCount = 0
        foreach ($sub in $commonSubdomains) {
            $fqdn = "$sub.$cleanDomain"
            try {
                $subRecords = Resolve-DnsName -Name $fqdn -ErrorAction Stop | Where-Object { $_.Section -eq 'Answer' }
                foreach ($rec in $subRecords) {
                    $foundSubCount++
                    $val = switch ($rec.Type) {
                        'A'     { $rec.IPAddress }
                        'AAAA' { $rec.IPAddress }
                        'CNAME' { $rec.NameHost }
                        'TXT'   { ($rec.Strings -join ' ') }
                        'MX'    { "{0} (Priority: {1})" -f $rec.NameExchange, $rec.Preference }
                        default { ($rec | Select-Object -Property * -ExcludeProperty Cim* | Out-String).Trim() }
                    }
                    Write-LogMessage ("    [{0,-6}] {1,-32} -> {2}" -f $rec.Type, $fqdn, $val)
                }
            }
            catch {
                # Subdomain does not exist
            }
        }
        if ($foundSubCount -eq 0) {
            Write-LogMessage "    None of the common subdomains were found."
        }
        Write-LogMessage ""
    }
}

Write-LogMessage "================================================================================"
Write-LogMessage " Completed! Results saved to:"
Write-LogMessage " $OutputFile"
Write-LogMessage "================================================================================"

try {
    $outputLines | Out-File -FilePath $OutputFile -Encoding utf8
    Write-Host "`n[+] Text file successfully created: $OutputFile" -ForegroundColor Green
}
catch {
    Write-Error "Error saving output file: $_"
}
