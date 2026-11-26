@echo off
rem Starts Kenuxa Heimdall on this computer: the dashboard and server, and the Heimdall app that protects your AI tools.
cd /d "%~dp0"
where node >nul 2>nul || (echo Node.js 22 or newer is needed: https://nodejs.org & pause & exit /b 1)
if not exist node_modules (
  echo First start: installing...
  call npm install || (pause & exit /b 1)
)
echo Starting the Heimdall server and dashboard...
start "Heimdall server" /min cmd /k npm run dev
echo Waiting for the server...
:wait
timeout /t 2 >nul
powershell -NoProfile -Command "try { (Invoke-WebRequest -UseBasicParsing http://localhost:8787/healthz -TimeoutSec 2) | Out-Null; exit 0 } catch { exit 1 }" || goto wait
start "" http://localhost:5173
echo Starting the Heimdall app (protection for Claude, Cursor and other AI tools on this computer)...
set HEIMDALL_URL=http://localhost:8787
start "Heimdall protection" cmd /k npm run companion
echo.
echo Heimdall is running. The first time, a code appears: click Add in the dashboard to confirm this computer.
echo Then restart Claude Desktop / Cursor once. Keep the two Heimdall windows open (or let the app start at sign-in).
pause
