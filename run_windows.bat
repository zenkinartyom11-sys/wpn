@echo off
rem ============================================================
rem  LOCAL VLESS CHECKER - proverka s TVOEY seti (MTS/Russia)
rem  V etoy zhe papke dolzhny lezhat:
rem    checker.py, xray.exe, sing-box.exe (minimum - xray.exe)
rem  Zapusk: dvoinoi klik po etomu faylu
rem  Python ishetsya avtomaticheski: .venv -> venv -> PATH -> py
rem ============================================================
chcp 65001 >nul
cd /d "%~dp0"

echo ============================================================
echo  Proverka serverov s TVOEY seti - zhivoi = rabotaet u tebya
echo ============================================================

rem --- Poisk Python: venv ryadom / .venv vnutri proekta / PATH / py ---
set "PYEXE="

if exist "%~dp0.venv\Scripts\python.exe" set "PYEXE=%~dp0.venv\Scripts\python.exe"
if exist "%~dp0venv\Scripts\python.exe"  set "PYEXE=%~dp0venv\Scripts\python.exe"

rem tipichnye puti PyCharm-proektov (podstav svoe imya proekta esli drugoe)
if "%PYEXE%"=="" if exist "C:\Users\User\PyCharmMiscProject\.venv\Scripts\python.exe" set "PYEXE=C:\Users\User\PyCharmMiscProject\.venv\Scripts\python.exe"

if "%PYEXE%"=="" (
  where python >nul 2>nul && set "PYEXE=python"
)
if "%PYEXE%"=="" (
  where py >nul 2>nul && set "PYEXE=py"
)

if "%PYEXE%"=="" (
  echo [!] Python ne nayden. Ustanovi s https://python.org [Add to PATH]
  pause
  exit /b 1
)

echo [i] Python: %PYEXE%

if not exist xray.exe (
  echo [!] xray.exe ne nayden v etoy papke.
  echo     Skachay: https://github.com/XTLS/Xray-core/releases/latest
  echo     Fayl Xray-windows-64.zip - dostan xray.exe syuda.
  pause
  exit /b 1
)

if not exist sing-box.exe (
  echo [!] sing-box.exe ne nayden - hysteria2 iz belogo spiska proveryatsya NE budut.
  echo     Skachay sing-box-windows-amd64.zip: https://github.com/SagerNet/sing-box/releases/latest
  echo     Prodolzhayu bez sing-box [Enter]...
  pause >nul
)

"%PYEXE%" -m pip install --quiet requests 2>nul

"%PYEXE%" checker.py

if exist .git (
  where git >nul 2>nul
  if not errorlevel 1 (
    echo.
    echo [git] Push rezultatov v repo...
    git add white_subscription.txt black_subscription.txt state.json proven.txt
    git commit -m "Local check: provereno s moey seti" || echo net izmeneniy
    git pull --rebase origin main
    git push origin main
  )
)

echo.
echo Gotovo. Obnovi podpisku v Happ.
pause
