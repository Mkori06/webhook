@echo off
echo Starting Smart QR Webhook Receiver (Node.js)...
cd /d "%~dp0"
if not exist node_modules (
    echo Installing dependencies...
    npm install
)
npm start
pause
