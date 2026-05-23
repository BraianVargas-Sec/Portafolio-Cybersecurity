# powershell-hardening.ps1
# Hardening de PowerShell: logging, restricciones y configuraciones de seguridad
# Basado en CIS Benchmark y recomendaciones Microsoft
# Requiere: Administrador local
# Autor: briamrlz82

#Requires -RunAsAdministrator

param(
    [switch]$WhatIf,
    [switch]$Verbose
)

$ErrorActionPreference = "Continue"

function Write-Status {
    param([string]$msg, [string]$color = "Cyan")
    Write-Host "[*] $msg" -ForegroundColor $color
}
function Write-OK    { Write-Host "[OK] $args" -ForegroundColor Green }
function Write-WARN  { Write-Host "[!!] $args" -ForegroundColor Yellow }

Write-Status "=== PowerShell Hardening ===" "Cyan"

# ── 1. Script Block Logging ──────────────────────────────────────
Write-Status "Habilitando Script Block Logging..."
$psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $psLogPath)) { New-Item -Path $psLogPath -Force | Out-Null }
Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 1
Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockInvocationLogging" -Value 1
Write-OK "Script Block Logging habilitado"

# ── 2. Module Logging ────────────────────────────────────────────
Write-Status "Habilitando Module Logging..."
$modLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $modLogPath)) { New-Item -Path $modLogPath -Force | Out-Null }
Set-ItemProperty -Path $modLogPath -Name "EnableModuleLogging" -Value 1
$modNamesPath = "$modLogPath\ModuleNames"
if (-not (Test-Path $modNamesPath)) { New-Item -Path $modNamesPath -Force | Out-Null }
Set-ItemProperty -Path $modNamesPath -Name "*" -Value "*"
Write-OK "Module Logging habilitado para todos los módulos"

# ── 3. Transcription Logging ─────────────────────────────────────
Write-Status "Habilitando Transcription Logging..."
$transPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if (-not (Test-Path $transPath)) { New-Item -Path $transPath -Force | Out-Null }
Set-ItemProperty -Path $transPath -Name "EnableTranscripting" -Value 1
Set-ItemProperty -Path $transPath -Name "EnableInvocationHeader" -Value 1
# Cambiar la ruta de output si querés centralizar logs
Set-ItemProperty -Path $transPath -Name "OutputDirectory" -Value "C:\PSTranscripts"
if (-not (Test-Path "C:\PSTranscripts")) {
    New-Item -ItemType Directory -Path "C:\PSTranscripts" | Out-Null
}
Write-OK "Transcription Logging habilitado → C:\PSTranscripts"

# ── 4. Execution Policy ──────────────────────────────────────────
Write-Status "Configurando Execution Policy..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell" `
    -Name "ExecutionPolicy" -Value "RemoteSigned"
Write-OK "Execution Policy: RemoteSigned"

# ── 5. Deshabilitar PowerShell v2 ────────────────────────────────
Write-Status "Deshabilitando PowerShell v2 (evasión de logging)..."
try {
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart | Out-Null
    Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart | Out-Null
    Write-OK "PowerShell v2 deshabilitado"
} catch {
    Write-WARN "No se pudo deshabilitar PS v2 (puede no estar instalado): $_"
}

# ── 6. Aumentar tamaño del log de eventos PowerShell ────────────
Write-Status "Aumentando tamaño del log de eventos PowerShell..."
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:104857600  # 100MB
Write-OK "Log PowerShell/Operational: 100MB"

# ── RESUMEN ──────────────────────────────────────────────────────
Write-Host ""
Write-Status "=== RESUMEN ===" "Green"
Write-OK "Script Block Logging    → HABILITADO"
Write-OK "Module Logging          → HABILITADO"
Write-OK "Transcription           → HABILITADO (C:\PSTranscripts)"
Write-OK "Execution Policy        → RemoteSigned"
Write-OK "PowerShell v2           → DESHABILITADO"
Write-OK "Log size                → 100MB"
Write-Host ""
Write-WARN "Reiniciar para aplicar todos los cambios"
Write-WARN "Verificar con: Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
