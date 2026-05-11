@echo off
call venv\Scripts\activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
python -m pip install pyinstaller
pyinstaller build\timeline_demo.spec
pause
