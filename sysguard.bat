@echo off
start "" /min powershell -NoProfile -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File "%~dp0sysguard.ps1"
