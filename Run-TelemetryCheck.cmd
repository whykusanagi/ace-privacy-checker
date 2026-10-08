@echo off
setlocal EnableExtensions
title ACE / NIKKE telemetry check
set "HERE=%~dp0"
if not exist "%HERE%Check-AceTelemetry.ps1" (
  echo.
  echo   Check-AceTelemetry.ps1 was not found next to this file.
  echo   Extract the whole zip first ^(right-click the zip, "Extract All..."^), then run this from the extracted folder.
  echo.
  pause
  exit /b 1
)
set "DEST=%USERPROFILE%\Desktop\ACE-Telemetry"
echo.
echo   This reads what NIKKE's crash reporter and the ACE anti-cheat stored on and uploaded from this PC,
echo   decodes it, and writes a summary you can read before sharing anything. Read-only, one to three minutes.
echo   Close NIKKE and its launcher first. Do not click inside this window while it runs (press Esc if you did).
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%HERE%Check-AceTelemetry.ps1" -Destination "%DEST%"
echo.
echo   Finished. Open the SUMMARY .txt in %DEST% to see what was found.
echo   The file to share, if you decide to, is the .zip in the same folder.
echo.
pause
