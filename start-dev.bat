@echo off
setlocal

set PORTS=3000 3003

for %%P in (%PORTS%) do (
    for /f "tokens=5" %%a in ('netstat -ano ^| findstr :%%P') do (
        echo Killing process on port %%P with PID: %%a
        taskkill /PID %%a /F >nul 2>&1
    )
)

:: Start the front-end
start "" npm run dev

:: Start the back-end
start "" node ./back-end/server

:: Delay to allow processes to start
timeout /T 5 /NOBREAK >nul