@echo off
start "" /min powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0sysguard.ps1" -Guard -Interval 10
