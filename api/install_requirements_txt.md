# แบบ Manual 
Set-Location -Path 'D:\DJANGO\mojiq\mojiq-ai\longterm-backup-config\api'
py -3.11 -m venv .venv           
# หรือ python -m venv .venv หาก python เป็น 3.11
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip setuptools wheel
python -m pip install --prefer-binary -r requirements.txt