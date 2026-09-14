@echo off
title LibraX - Stop Real AD Attack Lab

echo =====================================================================
echo              STOPPING REAL ACTIVE DIRECTORY LAB
echo =====================================================================
echo.

echo Stopping all lab containers (dc, attacker, shipper, api, frontend)...
docker compose -f lab/docker-compose.yml down

echo Stopping documentation server...
taskkill /F /FI "WINDOWTITLE eq LibraX Documentation Server*" >nul 2>&1
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>&1
)

echo.
echo =====================================================================
echo               LAB ENVIRONMENT STOPPED SAFELY
echo =====================================================================
echo.
pause
