@echo off
title Warden - LLM Safety Firewall
cls
echo ========================================================
echo       Warden - LLM Safety & Prompt Injection Firewall
echo ========================================================
echo.
echo [1/3] Checking dependencies...
python -c "import uvicorn, fastapi" 2>nul || pip install fastapi uvicorn
if not exist "frontend\node_modules" (
    echo Installing frontend dependencies...
    cd frontend && npm install && cd ..
)

echo [2/3] Starting Backend API (Port 8003)...
start "Warden API (Port 8003)" cmd /k "cd /d %~dp0backend && python -m uvicorn src.warden.main:app --port 8003 --reload"

echo [3/3] Starting Frontend UI (Port 3003)...
start "Warden UI (Port 3003)" cmd /k "cd /d %~dp0frontend && npm run dev"

timeout /t 3 /nobreak >nul
start http://localhost:3003
echo.
echo Warden is running!
echo   Frontend : http://localhost:3003
echo   Backend  : http://localhost:8003/docs
echo.
echo Press any key to stop all Warden processes...
pause >nul
taskkill /fi "WINDOWTITLE eq Warden API*" /f >nul 2>&1
taskkill /fi "WINDOWTITLE eq Warden UI*" /f >nul 2>&1
echo Done.
