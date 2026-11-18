@echo off
setlocal
chcp 65001 >nul

if exist "%~dp0TripFlare.exe" (
    start "" "%~dp0TripFlare.exe" %*
    exit /b 0
)

set "PYW="
for /f "delims=" %%P in ('where pythonw.exe 2^>nul') do (
    echo %%P | find /i "WindowsApps" >nul
    if errorlevel 1 if not defined PYW set "PYW=%%P"
)

if not defined PYW (
    for %%V in (313 312 311 310 39 38) do (
        if not defined PYW if exist "%LOCALAPPDATA%\Programs\Python\Python%%V\pythonw.exe" set "PYW=%LOCALAPPDATA%\Programs\Python\Python%%V\pythonw.exe"
        if not defined PYW if exist "%ProgramFiles%\Python%%V\pythonw.exe" set "PYW=%ProgramFiles%\Python%%V\pythonw.exe"
    )
)

if not defined PYW if exist "C:\ProgramData\miniconda3\pythonw.exe" set "PYW=C:\ProgramData\miniconda3\pythonw.exe"
if not defined PYW if exist "%USERPROFILE%\miniconda3\pythonw.exe" set "PYW=%USERPROFILE%\miniconda3\pythonw.exe"
if not defined PYW if exist "%USERPROFILE%\anaconda3\pythonw.exe" set "PYW=%USERPROFILE%\anaconda3\pythonw.exe"

if not defined PYW (
    echo [TripFlare] Python 3.8+ ^(pythonw.exe^) not found.
    echo Install Python from https://www.python.org/ or download the portable .exe release from GitHub.
    pause
    exit /b 1
)

start "" "%PYW%" "%~dp0tripflare_ui.pyw" %*
