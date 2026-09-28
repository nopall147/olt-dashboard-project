git clone https://github.com/nopall147/olt-dashboard-project.git

install phyton in this website
https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe

in termminal 
py -m pip install -r requirements.txt

new virtual environment 
python -m venv venv

activate
.\venv\Scripts\Activate.ps1

install all library 
pip install -r requirements.txt

install PostgreSQL
https://www.postgresql.org/download/

restore database 
psql -U postgres -d olt_db -f database_backup.sql
