@echo off
echo Starting Smart QR Webhook Receiver (PHP)...
cd /d "%~dp0"

set PHP_BIN=php
if exist "D:\xampp\php\php.exe" (
    set "PHP_BIN=D:\xampp\php\php.exe"
) else if exist "C:\xampp\php\php.exe" (
    set "PHP_BIN=C:\xampp\php\php.exe"
)

echo Using PHP: %PHP_BIN%
echo -----------------------------------------------------------------
echo Server starting at: http://localhost:8000
echo Webhook URL:        http://localhost:8000/webhook.php
echo Dashboard UI:       http://localhost:8000/
echo -----------------------------------------------------------------
"%PHP_BIN%" -S localhost:8000
pause
