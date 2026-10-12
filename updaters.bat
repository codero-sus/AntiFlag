@echo off
rem Update this AntiFlag checkout from the branch that is currently checked out.
rem
rem Never switches branches. Fetches origin/<current branch> and fast-forwards to it.
rem Stops without changes if the working tree is dirty (unless --allow-dirty),
rem HEAD is detached, or local commits would be lost.
rem
rem Usage:
rem   updaters.bat                 update
rem   updaters.bat --test          also run the unit tests afterwards
rem   updaters.bat --allow-dirty   attempt the update with local changes
rem
rem Exit codes: 0 success or already up to date, 1 refused or failed, 2 usage error.

setlocal EnableExtensions EnableDelayedExpansion

set "REMOTE=origin"
set "ALLOW_DIRTY=0"
set "RUN_TESTS=0"

for %%A in (%*) do (
    if /i "%%~A"=="--allow-dirty" set "ALLOW_DIRTY=1"
    if /i "%%~A"=="--test" set "RUN_TESTS=1"
    if /i "%%~A"=="-h" goto :usage
    if /i "%%~A"=="--help" goto :usage
)

cd /d "%~dp0"

git rev-parse --is-inside-work-tree >nul 2>&1
if errorlevel 1 (
    echo error: not a git repository 1>&2
    exit /b 1
)

set "BRANCH="
for /f "delims=" %%B in ('git symbolic-ref --quiet --short HEAD 2^>nul') do set "BRANCH=%%B"
if not defined BRANCH (
    echo error: HEAD is detached; check out a branch before updating 1>&2
    exit /b 1
)

git remote get-url %REMOTE% >nul 2>&1
if errorlevel 1 (
    echo error: no '%REMOTE%' remote is configured 1>&2
    exit /b 1
)

if "%ALLOW_DIRTY%"=="0" (
    set "DIRTY="
    for /f "delims=" %%S in ('git status --porcelain') do set "DIRTY=1"
    if defined DIRTY (
        echo error: uncommitted changes present; commit or stash them, or pass --allow-dirty 1>&2
        exit /b 1
    )
)

git fetch --quiet %REMOTE% "%BRANCH%"
if errorlevel 1 (
    echo error: could not fetch %REMOTE%/%BRANCH%; does it exist? 1>&2
    exit /b 1
)

set "LOCAL="
set "REMOTE_HEAD="
for /f "delims=" %%H in ('git rev-parse HEAD') do set "LOCAL=%%H"
for /f "delims=" %%H in ('git rev-parse FETCH_HEAD') do set "REMOTE_HEAD=%%H"

if "%LOCAL%"=="%REMOTE_HEAD%" (
    echo %BRANCH% is already up to date ^(%LOCAL:~0,7%^)
    goto :tests
)

git merge-base --is-ancestor %LOCAL% %REMOTE_HEAD% >nul 2>&1
if not errorlevel 1 (
    git merge --ff-only FETCH_HEAD
    if errorlevel 1 (
        echo error: fast-forward failed 1>&2
        exit /b 1
    )
    echo updated %BRANCH%: %LOCAL:~0,7% -^> %REMOTE_HEAD:~0,7%
    goto :tests
)

git merge-base --is-ancestor %REMOTE_HEAD% %LOCAL% >nul 2>&1
if not errorlevel 1 (
    echo %BRANCH% is ahead of %REMOTE%/%BRANCH%; nothing to pull
    goto :tests
)

echo error: %BRANCH% has diverged from %REMOTE%/%BRANCH%; resolve it manually, nothing was changed 1>&2
exit /b 1

:tests
if "%RUN_TESTS%"=="0" exit /b 0

set "PY="
where python >nul 2>&1 && set "PY=python"
if not defined PY (
    where py >nul 2>&1 && set "PY=py -3"
)
if not defined PY (
    echo error: python not found; cannot run tests 1>&2
    exit /b 1
)

echo running tests...
%PY% -m unittest discover -s tests
exit /b %errorlevel%

:usage
echo Update this AntiFlag checkout from the current branch.
echo.
echo   updaters.bat                 update
echo   updaters.bat --test          also run the unit tests afterwards
echo   updaters.bat --allow-dirty   attempt the update with local changes
exit /b 0
