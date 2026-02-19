# Metatron Cloudflare Tunnel Setup
param([string]$TunnelName = "metatron-mcp-23984")

Write-Host "🦞 PicoClaw Cloudflare Tunnel Setup"
Write-Host "===================================="

# Check cloudflared
$cf = Get-Command cloudflared -ErrorAction SilentlyContinue
if (-not $cf) {
    Write-Host "Installing cloudflared..." -ForegroundColor Yellow
    winget install Cloudflare.cloudflared
}

# Check auth
$certPath = "$env:USERPROFILE\.cloudflared\cert.pem"
if (-not (Test-Path $certPath)) {
    Write-Host "Authenticate: cloudflared tunnel login"
    cloudflared tunnel login
}

# Create tunnel
Write-Host "Creating tunnel: $TunnelName" -ForegroundColor Green
$tunnel = cloudflared tunnel create $TunnelName 2>&1 | Select-String "Created tunnel" | ForEach-Object { ($_ -split '\s+')[2] }

if (-not $tunnel) {
    $tunnel = cloudflared tunnel list | Select-String $TunnelName | ForEach-Object { ($_ -split '\s+')[0] }
}

Write-Host "Tunnel ID: $tunnel"

# Config dir
$configDir = "$env:USERPROFILE\.cloudflared"
if (-not (Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force
}

# Create config.yaml
$config = @"
tunnel: $tunnel
credentials-file: $configDir\$tunnel.json
ingress:
  - hostname: $TunnelName.trythat.ai
    service: http://localhost:3402
  - service: http_status:404
"@

$configPath = "$configDir\metatron-config.yml"
Set-Content -Path $configPath -Value $config
Write-Host "Config saved: $configPath"

# Setup DNS
Write-Host "Creating DNS route..." -ForegroundColor Green
cloudflared tunnel route dns $tunnel "$TunnelName.trythat.ai"

# Summary
Write-Host "
✅ Setup Complete!"
Write-Host "URL: https://$TunnelName.trythat.ai"
Write-Host "Local: http://localhost:3402"
Write-Host "
To start: cloudflared tunnel run $tunnel"
Write-Host "Or: & '$configPath'"
