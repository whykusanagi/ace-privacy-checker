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
echo.
echo   This reads what NIKKE's crash reporter and the ACE anti-cheat stored on and uploaded from this PC,
echo   decodes it, and writes a report you can read before sharing anything. Read-only, one to three minutes.
echo   Close NIKKE and its launcher first. Do not click inside this window while it runs (press Esc if you did).
echo.
echo   The report will be written next to this file, in:
echo     %HERE%ACE-Telemetry-Output
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%HERE%Check-AceTelemetry.ps1"
if errorlevel 1 (
  echo.
  echo   The check did not finish. Scroll up to read the error, or take a screenshot of this window when asking for help.
  echo.
  pause
  exit /b 1
)
echo.
echo   Finished. The report opened in Notepad. It is also here:  %HERE%ACE-Telemetry-Output
echo   The .zip in that folder is the file to share, if you decide to. Delete the folder when you are done with it.
echo.
echo   Press any key to close this window.
pause >nul
