chcp 65001 >nul
@echo off
rem TripFlare console launcher - starts the tkinter UI windowless.
set "PYW=C:\ProgramData\miniconda3\pythonw.exe"
if not exist "%PYW%" set "PYW=pythonw.exe"
start "" "%PYW%" "%~dp0tripflare_ui.pyw"
