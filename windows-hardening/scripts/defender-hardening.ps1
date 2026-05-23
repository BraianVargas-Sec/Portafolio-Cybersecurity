# defender-hardening.ps1
# Hardening de Windows Defender + ASR Rules
# Autor: briamrlz82
# REQUISITOS: PowerShell 5.1+, Administrador, Windows 10/11 con Defender activo

#Requires -RunAsAdministrator

function Write-Status {
    param([string]$msg, [string]$color = "Green")
    Write-Host "  [OK] $msg" -ForegroundColor $color
}

Write-Host "`n══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  WINDOWS DEFENDER HARDENING" -ForegroundColor Yellow
Write-Host "══════════════════════════════════════════`n" -ForegroundColor Cyan

# ── PROTECCIÓN EN TIEMPO REAL ────────────────────────────────────
Write-Host "[ Protección en tiempo real ]" -ForegroundColor Cyan

Set-MpPreference -DisableRealtimeMonitoring $false
Write-Status "Protección en tiempo real: ON"

Set-MpPreference -DisableBehaviorMonitoring $false
Write-Status "Monitoreo de comportamiento: ON"

Set-MpPreference -DisableBlockAtFirstSeen $false
Write-Status "Block at First Seen: ON"

Set-MpPreference -DisableIOAVProtection $false
Write-Status "Protección de descarga: ON"

# ── CLOUD PROTECTION ─────────────────────────────────────────────
Write-Host "`n[ Cloud-Delivered Protection ]" -ForegroundColor Cyan

Set-MpPreference -MAPSReporting Advanced
Write-Status "MAPS (cloud): Advanced"

Set-MpPreference -SubmitSamplesConsent SendAllSamples
Write-Status "Envío de muestras: habilitado"

Set-MpPreference -CloudBlockLevel High
Write-Status "Nivel de bloqueo cloud: High"

Set-MpPreference -CloudExtendedTimeout 50
Write-Status "Timeout extendido cloud: 50s"

# ── ASR RULES ────────────────────────────────────────────────────
Write-Host "`n[ Attack Surface Reduction Rules ]" -ForegroundColor Cyan
Write-Host "  Modo: 1 = Block, 2 = Audit" -ForegroundColor Gray

$asrRules = @{
    # Bloquear abuso de Office para código malicioso
    "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = @{Mode=1; Name="Block executable content from email/webmail"}
    "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = @{Mode=1; Name="Block Office apps from creating child processes"}
    "3B576869-A4EC-4529-8536-B80A7769E899" = @{Mode=1; Name="Block Office apps from creating executable content"}
    "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = @{Mode=1; Name="Block Office apps from injecting into processes"}

    # Bloquear scripts maliciosos
    "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = @{Mode=1; Name="Block obfuscated scripts"}
    "D3E037E1-3EB8-44C8-A917-57927947596D" = @{Mode=1; Name="Block JS/VBS launching downloaded executables"}

    # Protección de credenciales
    "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B0" = @{Mode=1; Name="Block credential stealing from LSASS"}

    # Ransomware
    "C1DB55AB-C21A-4637-BB3F-A12568109D35" = @{Mode=1; Name="Use advanced protection against ransomware"}

    # Ejecución desde ubicaciones sospechosas
    "01443614-CD74-433A-B99E-2ECDC07BFC25" = @{Mode=1; Name="Block untrusted/unsigned from USB"}
    "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = @{Mode=1; Name="Block untrusted processes from USB"}
}

foreach ($ruleId in $asrRules.Keys) {
    $rule = $asrRules[$ruleId]
    try {
        Add-MpPreference -AttackSurfaceReductionRules_Ids $ruleId `
                         -AttackSurfaceReductionRules_Actions $rule.Mode
        $modeLabel = if ($rule.Mode -eq 1) { "BLOCK" } else { "AUDIT" }
        Write-Host "  [OK] [$modeLabel] $($rule.Name)" -ForegroundColor Green
    } catch {
        Write-Host "  [ERR] $($rule.Name): $_" -ForegroundColor Red
    }
}

# ── VERIFICACIÓN FINAL ───────────────────────────────────────────
Write-Host "`n[ Verificación ]" -ForegroundColor Cyan
$status = Get-MpComputerStatus
Write-Host "  RealTimeProtection  : $($status.RealTimeProtectionEnabled)" -ForegroundColor $(if($status.RealTimeProtectionEnabled){"Green"}else{"Red"})
Write-Host "  AntivirusEnabled    : $($status.AntivirusEnabled)" -ForegroundColor $(if($status.AntivirusEnabled){"Green"}else{"Red"})
Write-Host "  BehaviorMonitor     : $($status.BehaviorMonitorEnabled)" -ForegroundColor $(if($status.BehaviorMonitorEnabled){"Green"}else{"Red"})
Write-Host "  TamperProtection    : $($status.IsTamperProtected)" -ForegroundColor $(if($status.IsTamperProtected){"Green"}else{"Yellow"})

$asrEnabled = (Get-MpPreference).AttackSurfaceReductionRules_Ids
Write-Host "  ASR Rules activas   : $($asrEnabled.Count)" -ForegroundColor Green

Write-Host "`n  Defender hardening completado" -ForegroundColor Green
