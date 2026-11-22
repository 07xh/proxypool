@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    set "PYCMD=py -3"
) else (
    set "PYCMD=python"
)
echo [1/2] Checking Python syntax...
%PYCMD% -m compileall -q .
if errorlevel 1 goto failed
echo [2/2] Running all local tests...
%PYCMD% verify.py
set "RESULT=%errorlevel%"
if not "%RESULT%"=="0" goto failed
echo.
echo All tests passed.
pause
exit /b 0
:failed
echo.
echo Tests failed. Review the output above.
pause
exit /b 1
