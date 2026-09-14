@echo off
setlocal enabledelayedexpansion
title LibraX - Real Active Directory Attack Lab

echo =====================================================================
echo           LIBRAX REAL ACTIVE DIRECTORY ATTACK LAB
echo =====================================================================
echo.
echo [1/4] Stopping any existing containers or port conflicts...
docker compose down >nul 2>&1
docker compose -f lab/docker-compose.yml down >nul 2>&1
taskkill /F /FI "WINDOWTITLE eq LibraX Documentation Server*" >nul 2>&1

echo.
echo [2/4] Building and launching Real AD Lab Topology:
echo       - Domain Controller : Samba 4 AD DC (LIBRAX.LOCAL @ 172.30.0.10)
echo       - Attacker Box      : Linux + Impacket / Nmap (172.30.0.66)
echo       - Log Shipper       : Python Samba Audit Tailer
echo       - Detection Engine  : LibraX API in REAL non-demo mode (:8080)
echo       - SOC Console       : React 18 / Nginx (:3000)
echo.
docker compose -f lab/docker-compose.yml up -d --build
if errorlevel 1 (
    echo [ERROR] Docker Compose failed to start the lab. Ensure Docker Desktop is running.
    pause
    exit /b 1
)

echo.
echo [3/4] Starting Documentation Server on http://127.0.0.1:8000...
start "LibraX Documentation Server" /min cmd /c "python -m mkdocs serve --dev-addr 127.0.0.1:8000"

echo.
echo [4/4] Opening Web Console in browser...
timeout /t 3 /nobreak >nul
start http://localhost:3000
start http://127.0.0.1:8000

echo.
echo =====================================================================
echo                REAL AD ATTACK LAB IS NOW RUNNING!
echo =====================================================================
echo   - Web Console:        http://localhost:3000
echo   - API Gateway:        http://localhost:8080
echo   - Documentation:      http://127.0.0.1:8000
echo =====================================================================
echo.
echo Streaming live offensive tool execution from the Attacker container:
echo (Press Ctrl+C to stop viewing logs; lab will remain running in background)
echo.
docker compose -f lab/docker-compose.yml logs -f attacker
