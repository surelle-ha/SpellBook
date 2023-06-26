@echo off

REM c:\users\0110h\appdata\local\packages\pythonsoftwarefoundation.python.3.11_qbz5n2kfra8p0\localcache\local-packages\python311\scripts\pyinstaller.exe --onefile --windowed --icon=img/icon.ico -F --noconsole --name SpellBook WebController.py
pyinstaller.exe --onefile --windowed --icon=img/icon.ico -F --noconsole --name SpellBook WebController.py

copy "dist\SpellBook.exe" "SpellBook.exe"


