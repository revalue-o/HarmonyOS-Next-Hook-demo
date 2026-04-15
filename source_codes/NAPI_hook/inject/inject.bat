@echo off
setlocal enabledelayedexpansion

REM === NAPI Inline Hook 一键注入脚本 ===

set "CLANG=C:\Program Files\Huawei\DevEco Studio\sdk\default\openharmony\native\llvm\bin\clang.exe"
set "SYSROOT=C:\Program Files\Huawei\DevEco Studio\sdk\default\openharmony\native\sysroot"
set "SRC=inject_napi.c"
set "OUT=inject_napi"
set "REMOTE=/data/local/tmp/inject_napi"

REM 第一步：编译
echo [1/4] Compiling %SRC% ...
"%CLANG%" --target=x86_64-linux-ohos -O2 --sysroot="%SYSROOT%" -o %OUT% %SRC% -ldl
if errorlevel 1 (
    echo [ERROR] Compilation failed.
    exit /b 1
)
echo [1/4] Done.

REM 第二步：推送到模拟器
echo [2/4] Pushing to device ...
hdc file send %OUT% %REMOTE%
if errorlevel 1 (
    echo [ERROR] Push failed.
    exit /b 1
)
echo [2/4] Done.

REM 第三步：获取目标 PID
echo [3/4] Finding target process ...
for /f "tokens=2" %%a in ('hdc shell "ps -ef | grep sys_verify | grep -v grep"') do set "PID=%%a"
if "%PID%"=="" (
    echo [WARN] App not running, starting ...
    hdc shell "aa start -a EntryAbility -b com.example.sys_verify"
    timeout /t 3 /nobreak >nul
    for /f "tokens=2" %%a in ('hdc shell "ps -ef | grep sys_verify | grep -v grep"') do set "PID=%%a"
)
if "%PID%"=="" (
    echo [ERROR] Cannot find target process.
    exit /b 1
)
echo [3/4] Target PID: %PID%

REM 第四步：注入
echo [4/4] Injecting ...
hdc shell "chmod +x %REMOTE% && %REMOTE% %PID%"
if errorlevel 1 (
    echo [ERROR] Injection failed.
    exit /b 1
)

echo.
echo === Done. Click "Get Location" in the app to verify. ===
endlocal
