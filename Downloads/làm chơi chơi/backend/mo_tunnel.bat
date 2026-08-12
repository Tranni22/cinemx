@echo off
cd /d "%~dp0"
echo Dang mo tunnel cho backend (port 5000)...
echo Nho copy URL hien ra ben duoi vao PUBLIC_BASE_URL trong .env neu can dung tinh nang sua anh.
echo.
cloudflared.exe tunnel --protocol http2 --url http://localhost:5000
pause
