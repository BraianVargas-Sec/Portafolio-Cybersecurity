# hardening-baseline.ps1
# Windows Hardening — CIS Benchmark v2.0
# Autor: briamrlz82
# Repo: windows-hardening
#
# Aplica controles de seguridad basados en CIS Benchmark para Windows 10/11
# REQUISITOS: PowerShell 5.1+, ejecutar como Administrador
# USO: .\hardening-baseline.ps1 [-WhatIf] [-Verbose]

#Requires -RunAsAdministrator
param(
    [switch]$WhatIf,
    [switch]$SkipRebootControls
)

$ErrorActionPreference = "Continue"
$script:Applied = 0
$script:Skipped = 0
$script:Failed  = 0

function Write-Section {
    param([string]$title)
    Write-Host "`n══════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $title" -ForegroundColor Yellow
    Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
}

function Apply-Control {
    param(
        [string]$Name,
        [string]$CISId,
        [scriptblock]$Action
    )
    try {
        if ($WhatIf) {
            Write-Host "  [WHATIF] $CISId — $Name" -ForegroundColor Magenta
        } else {
            & $Action
            Write-Host "  [OK] $CISId — $Name" -ForegroundColor Green
            $script:Applied++
        }
    } catch {
        Write-Host "  [ERROR] $CISId — $Name : $_" -ForegroundColor Red
        $script:Failed++
    }
}

# ══════════════════════════════════════════
# SECCIÓN 1 — ACCOUNT POLICIES
# ══════════════════════════════════════════
Write-Section "SECCIÓN 1 — Account Policies"

Apply-Control -Name "Historial de contraseñas: 24" -CISId "1.1.1" -Action {
    net accounts /uniquepw:24 | Out-Null
}

Apply-Control -Name "Edad máxima de contraseña: 365 días" -CISId "1.1.2" -Action {
    net accounts /maxpwage:365 | Out-Null
}

Apply-Control -Name "Edad mínima de contraseña: 1 día" -CISId "1.1.3" -Action {
    net accounts /minpwage:1 | Out-Null
}

Apply-Control -Name "Longitud mínima de contraseña: 14" -CISId "1.1.4" -Action {
    net accounts /minpwlen:14 | Out-Null
}

Apply-Control -Name "Complejidad de contraseña: habilitada" -CISId "1.1.5" -Action {
    $tmpFile = "$env:TEMP\secpol.cfg"
    secedit /export /cfg $tmpFile /quiet
    (Get-Content $tmpFile) -replace "PasswordComplexity = 0", "PasswordComplexity = 1" |
        Set-Content $tmpFile
    secedit /configure /db "$env:TEMP\secedit.sdb" /cfg $tmpFile /quiet
    Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
}

Apply-Control -Name "Umbral de bloqueo: 5 intentos" -CISId "1.2.1" -Action {
    net accounts /lockoutthreshold:5 | Out-Null
}

Apply-Control -Name "Duración de bloqueo: 15 minutos" -CISId "1.2.2" -Action {
    net accounts /lockoutduration:15 | Out-Null
}

Apply-Control -Name "Ventana de observación de bloqueo: 15 minutos" -CISId "1.2.3" -Action {
    net accounts /lockoutwindow:15 | Out-Null
}

# ══════════════════════════════════════════
# SECCIÓN 2 — LOCAL POLICIES
# ══════════════════════════════════════════
Write-Section "SECCIÓN 2 — Local Policies"

Apply-Control -Name "Deshabilitar cuenta Guest" -CISId "2.3.1.2" -Action {
    net user Guest /active:no | Out-Null
}

Apply-Control -Name "Renombrar cuenta Administrador" -CISId "2.3.1.1" -Action {
    $newName = "LocalAdmin_$(Get-Random -Maximum 9999)"
    Rename-LocalUser -Name "Administrator" -NewName $newName -ErrorAction SilentlyContinue
}

Apply-Control -Name "No mostrar último usuario en login" -CISId "2.3.7.3" -Action {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "DontDisplayLastUserName" -Value 1 -Type DWord
}

Apply-Control -Name "Título y mensaje de aviso legal" -CISId "2.3.7.1" -Action {
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "LegalNoticeCaption" -Value "AVISO DE SEGURIDAD"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" `
        -Name "LegalNoticeText" -Value "Acceso restringido a usuarios autorizados. Toda actividad es monitoreada."
}

Apply-Control -Name "Deshabilitar envío de contraseñas sin cifrar (SMB)" -CISId "2.3.11.7" -Action {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" `
        -Name "EnablePlainTextPassword" -Value 0 -Type DWord
}

Apply-Control -Name "Nivel de autenticación LAN Manager: NTLMv2 only" -CISId "2.3.11.3" -Action {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "LmCompatibilityLevel" -Value 5 -Type DWord
}

Apply-Control -Name "Deshabilitar almacenamiento de hash LM" -CISId "2.3.11.2" -Action {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "NoLMHash" -Value 1 -Type DWord
}

# ══════════════════════════════════════════
# SECCIÓN 9 — WINDOWS FIREWALL
# ══════════════════════════════════════════
Write-Section "SECCIÓN 9 — Windows Firewall"

Apply-Control -Name "Habilitar Firewall — perfil Domain" -CISId "9.1.1" -Action {
    Set-NetFirewallProfile -Profile Domain -Enabled True
}

Apply-Control -Name "Habilitar Firewall — perfil Private" -CISId "9.2.1" -Action {
    Set-NetFirewallProfile -Profile Private -Enabled True
}

Apply-Control -Name "Habilitar Firewall — perfil Public" -CISId "9.3.1" -Action {
    Set-NetFirewallProfile -Profile Public -Enabled True
}

Apply-Control -Name "Bloquear conexiones entrantes por defecto (Domain)" -CISId "9.1.2" -Action {
    Set-NetFirewallProfile -Profile Domain -DefaultInboundAction Block
}

Apply-Control -Name "Bloquear conexiones entrantes por defecto (Public)" -CISId "9.3.2" -Action {
    Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block
}

# ══════════════════════════════════════════
# SECCIÓN — SERVICIOS INNECESARIOS
# ══════════════════════════════════════════
Write-Section "SERVICIOS — Deshabilitar servicios innecesarios"

$servicesToDisable = @(
    @{Name="Telnet";         DisplayName="Telnet"},
    @{Name="RemoteRegistry"; DisplayName="Remote Registry"},
    @{Name="WinRM";          DisplayName="Windows Remote Management"},
    @{Name="SNMP";           DisplayName="SNMP Service"},
    @{Name="Fax";            DisplayName="Fax"}
)

foreach ($svc in $servicesToDisable) {
    Apply-Control -Name "Deshabilitar $($svc.DisplayName)" -CISId "svc" -Action {
        $s = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($s) {
            Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc.Name -StartupType Disabled
        }
    }
}

# ══════════════════════════════════════════
# RESUMEN
# ══════════════════════════════════════════
Write-Host "`n══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  RESUMEN DE HARDENING" -ForegroundColor Yellow
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Controles aplicados : $($script:Applied)" -ForegroundColor Green
Write-Host "  Errores              : $($script:Failed)"  -ForegroundColor Red
Write-Host ""
Write-Host "  Ejecutar verify-controls.ps1 para validar" -ForegroundColor Gray
Write-Host "  Algunos controles requieren reinicio" -ForegroundColor Yellow
Write-Host "══════════════════════════════════════════" -ForegroundColor Cyan
