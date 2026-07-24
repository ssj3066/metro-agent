@echo off
setlocal
cd /d "%~dp0"

py -3 -m pip install --upgrade pyinstaller
py -3 -m PyInstaller --onefile --noconsole --name METRO_NMS_Collecter nms_field_collector_gui.py

echo.
echo Build complete: %CD%\dist\METRO_NMS_Collecter.exe
