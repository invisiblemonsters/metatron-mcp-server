# Metatron MCP Server Runner - Auto-restart on crash
$port = 3402
$scriptPath = "C:\Users\power\clawd\metatron-mcp-server\index-fixed.js"

function Test-Server {
    try {
        $response = Invoke-WebRequest -Uri "http://127.0.0.1:$port/status" -TimeoutSec 2 -ErrorAction Stop
        return $true
    } catch {
        return $false
    }
}

Write-Host "🦞 Metatron MCP Runner starting..."

while ($true) {
    if (-not (Test-Server)) {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Server not responding, starting..."

        # Kill any existing node processes on the script
        Get-Process node -ErrorAction SilentlyContinue | Where-Object {
            $_.MainWindowTitle -like "*metatron*" -or $_.Path -like "*metatron-mcp*"
        } | Stop-Process -Force -ErrorAction SilentlyContinue

        Start-Sleep -Seconds 1

        # Start server
        $env:PORT = $port
        Start-Process -FilePath "node" -ArgumentList $scriptPath -NoNewWindow

        Start-Sleep -Seconds 3

        if (Test-Server) {
            Write-Host "$(Get-Date -Format 'HH:mm:ss') - ✅ Server alive on port $port"
        } else {
            Write-Host "$(Get-Date -Format 'HH:mm:ss') - ❌ Failed to start"
        }
    }

    Start-Sleep -Seconds 10
}
