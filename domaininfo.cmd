@echo off
setlocal
python -c "import sys; sys.exit(sys.version_info < (3,10))" >nul 2>nul
if errorlevel 1 goto try_py
python "%~dp0domaininfo.py" %*
exit /b %errorlevel%
:try_py
py -3 -c "import sys; sys.exit(sys.version_info < (3,10))" >nul 2>nul
if errorlevel 1 (
  echo Instala Python 3.10+ y activa su opcion de PATH. 1>&2
  exit /b 1
)
py -3 "%~dp0domaininfo.py" %*
exit /b %errorlevel%
