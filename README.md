# DNS Records Exporter

A PowerShell script to query all available DNS records for a given domain name and export them cleanly into a text file (`.txt`).

## Overview

By design, DNS does not offer a single query to retrieve all records unless Zone Transfer (AXFR) is enabled (which is blocked by virtually all public domains for security reasons). This script addresses that by:

1. **Identifying Nameservers**: Resolves the authoritative NS records.
2. **Zone Transfer (AXFR) Check**: Checks whether the nameservers permit a full zone transfer.
3. **Apex Domain Queries**: Systematically queries standard record types for the apex domain:
   - `A` (IPv4 addresses)
   - `AAAA` (IPv6 addresses)
   - `MX` (Mail servers and preferences)
   - `TXT` (SPF, DKIM, domain verification records, etc.)
   - `NS` (Nameservers)
   - `SOA` (Start of Authority)
   - `CAA` (Certificate Authority Authorization)
   - `CNAME` / `SRV`
4. **Subdomain Discovery**: Scans common subdomains (e.g., `www`, `mail`, `autodiscover`, `ftp`, `api`, `smtp`, `vpn`, `dev`, etc.).
5. **Text File Export**: Formats all output and writes it to a `.txt` file (defaults to `<domain>_dns_records.txt`).

---

## Usage

Open PowerShell in this directory (`C:\Dev\get-dns-records`) and run:

### 1. Basic Execution
```powershell
.\Get-DnsRecords.ps1 -Domain "example.com"
```
The file `example.com_dns_records.txt` will automatically be created in the current directory.

### 2. Custom Output File
```powershell
.\Get-DnsRecords.ps1 -Domain "example.com" -OutputFile "C:\MyFolder\dns_results.txt"
```

### 3. Skip Subdomain Scanning
If you only want to query records for the apex domain:
```powershell
.\Get-DnsRecords.ps1 -Domain "example.com" -SkipSubdomains
```

---

> **Tip:** If your system restricts running unsigned PowerShell scripts due to Execution Policy, run:
> ```powershell
> powershell -ExecutionPolicy Bypass -File .\Get-DnsRecords.ps1 -Domain "example.com"
> ```
