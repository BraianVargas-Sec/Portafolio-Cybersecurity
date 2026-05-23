# credential-protection.ps1
# Protección de credenciales en Windows
# Autor: briamrlz82
# Controles: WDigest, Credential Guard, PPL para LSASS, NTLM
# REQUISITOS: Administrador. Algunos controles requieren reinicio.

#Requires -RunAsAdministrator

Write-Host "`n══════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  PROTECCIÓN DE CREDENCIALES" -ForegroundColor Yellow
Write-Host "══════════════════════════════════════════`n" -ForegroundColor Cyan

# ── 1. DESHABILITAR WDIGEST ──────────────────────────────────────
# WDigest almacena credenciales en texto plano en memoria
# Mimikatz puede extraerlas si está activo
Write-Host "[ 1. WDigest — evitar credenciales en texto plano ]" -ForegroundColor Cyan

$wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
if (-not (Test-Path $wdigestPath)) {
    New-Item -Path $wdigestPath -Force | Out-Null
}
Set-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -Value 0 -Type DWord
Write-Host "  [OK] WDigest deshabilitado (UseLogonCredential = 0)" -ForegroundColor Green

# ── 2. LSASS COMO PROCESO PROTEGIDO (PPL) ───────────────────────
# PPL evita que procesos no firmados por Microsoft lean la memoria de LSASS
# Mitiga directamente Mimikatz sekurlsa::logonpasswords
Write-Host "`n[ 2. LSASS — Protected Process Light (PPL) ]" -ForegroundColor Cyan

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RunAsPPL" -Value 1 -Type DWord
Write-Host "  [OK] LSASS PPL habilitado (requiere reinicio)" -ForegroundColor Green

# ── 3. CREDENTIAL GUARD ──────────────────────────────────────────
# Virtualiza LSASS en un contenedor seguro (VSM)
# Requiere UEFI, Secure Boot y Hyper-V
Write-Host "`n[ 3. Credential Guard ]" -ForegroundColor Cyan

# Verificar si el hardware lo soporta
$devGuard = Get-CimInstance -ClassName Win32_DeviceGuard `
    -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue

if ($devGuard) {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
        -Name "LsaCfgFlags" -Value 1 -Type DWord
    Write-Host "  [OK] Credential Guard habilitado (requiere reinicio)" -ForegroundColor Green
} else {
    Write-Host "  [SKIP] Hardware no compatible o Hyper-V no disponible" -ForegroundColor Yellow
}

# ── 4. DESHABILITAR NTLM v1 ──────────────────────────────────────
# NTLMv1 es altamente vulnerable — forzar NTLMv2 mínimo
Write-Host "`n[ 4. Nivel de autenticación LAN Manager ]" -ForegroundColor Cyan

# Valor 5 = Send NTLMv2 response only, refuse LM and NTLM
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "LmCompatibilityLevel" -Value 5 -Type DWord
Write-Host "  [OK] LmCompatibilityLevel = 5 (NTLMv2 only)" -ForegroundColor Green

# ── 5. DESHABILITAR ALMACENAMIENTO DE HASH LM ────────────────────
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "NoLMHash" -Value 1 -Type DWord
Write-Host "  [OK] Almacenamiento de hash LM deshabilitado" -ForegroundColor Green

# ── 6. RESTRICCIONES ADICIONALES DE LSA ─────────────────────────
Write-Host "`n[ 5. Restricciones adicionales de LSA ]" -ForegroundColor Cyan

# Habilitar restricciones de LSA — bloquea DLLs no firmadas
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RunAsPPL" -Value 1 -Type DWord

# Deshabilitar acceso anónimo a LSA
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymous" -Value 1 -Type DWord
Write-Host "  [OK] Acceso anónimo a LSA restringido" -ForegroundColor Green

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" `
    -Name "RestrictAnonymousSAM" -Value 1 -Type DWord
Write-Host "  [OK] Acceso anónimo a SAM restringido" -ForegroundColor Green

# ── VERIFICACIÓN ─────────────────────────────────────────────────
Write-Host "`n[ Verificación de controles ]" -ForegroundColor Cyan

$lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$wdigest = (Get-ItemProperty $wdigestPath -ErrorAction SilentlyContinue).UseLogonCredential
$ppl     = (Get-ItemProperty $lsaPath).RunAsPPL
$ntlm    = (Get-ItemProperty $lsaPath).LmCompatibilityLevel
$noLM    = (Get-ItemProperty $lsaPath).NoLMHash

Write-Host "  WDigest deshabilitado  : $(if($wdigest -eq 0){'✅ SI'}else{'❌ NO'})"
Write-Host "  LSASS PPL              : $(if($ppl -eq 1){'✅ SI (requiere reinicio)'}else{'❌ NO'})"
Write-Host "  NTLMv2 only            : $(if($ntlm -eq 5){'✅ SI'}else{'❌ NO'})"
Write-Host "  Sin hash LM            : $(if($noLM -eq 1){'✅ SI'}else{'❌ NO'})"

Write-Host "`n  ⚠️  Reiniciar el sistema para aplicar PPL y Credential Guard" -ForegroundColor Yellow
