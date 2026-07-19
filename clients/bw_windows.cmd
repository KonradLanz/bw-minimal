@echo off
REM clients/bw_windows.cmd
REM Wrapper for bw_minimal.py on Windows.
REM Requires Python 3 from python.org (available as `py -3`).
REM
REM Usage:
REM   bw_windows.cmd get nas/ssh_pass
REM   bw_windows.cmd set nas/ssh_pass mysecret

SETLOCAL
SET SCRIPT_DIR=%~dp0..
SET BW_PY=%SCRIPT_DIR%\bw_minimal.py

WHERE py >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
  py -3 "%BW_PY%" %*
  EXIT /B %ERRORLEVEL%
)

WHERE python3 >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
  python3 "%BW_PY%" %*
  EXIT /B %ERRORLEVEL%
)

WHERE python >nul 2>&1
IF %ERRORLEVEL% EQU 0 (
  python "%BW_PY%" %*
  EXIT /B %ERRORLEVEL%
)

ECHO Error: Python 3 not found. Install from https://python.org
EXIT /B 1
