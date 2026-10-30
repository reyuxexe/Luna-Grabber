@echo off
REM Build standalone Sentinel.exe (run on Windows, Python 3.12+)
python -m venv .venv && call .venv\Scripts\activate
pip install -r sentinel_requirements.txt
pyinstaller --noconfirm --onefile --windowed --name Sentinel --collect-submodules sentinel sentinel\main.py
echo Output: dist\Sentinel.exe
