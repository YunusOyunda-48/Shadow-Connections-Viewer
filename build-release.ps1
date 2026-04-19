$ErrorActionPreference = "Stop"

$distDir = Join-Path $PSScriptRoot "dist"
$exePath = Join-Path $distDir "Shadow-Connections-Viewer.exe"

if (-not (Test-Path $distDir)) {
  New-Item -ItemType Directory -Path $distDir | Out-Null
}

if (-not (Get-PackageProvider -ListAvailable -Name NuGet -ErrorAction SilentlyContinue)) {
  Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope CurrentUser | Out-Null
}

if ((Get-PSRepository -Name "PSGallery").InstallationPolicy -ne "Trusted") {
  Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted
}

if (-not (Get-Module -ListAvailable -Name ps2exe)) {
  Install-Module -Name ps2exe -Scope CurrentUser -Force
}

Import-Module ps2exe

Invoke-ps2exe `
  -inputFile (Join-Path $PSScriptRoot "gui.ps1") `
  -outputFile $exePath `
  -title "Shadow Connections Viewer" `
  -description "Windows GUI for viewing active network connections and suspicious outbound activity." `
  -company "YunusOyunda-48" `
  -product "Shadow Connections Viewer" `
  -copyright "YunusOyunda-48" `
  -version "1.0.0.0" `
  -noConsole

Write-Host "Built:" $exePath
