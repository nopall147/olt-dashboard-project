git clone https://github.com/nopall147/olt-dashboard-project.git

install phyton in this website
*https://www.python.org/ftp/python/3.12.7/python-3.12.7-amd64.exe*

in termminal 
*py -m pip install -r requirements.txt*

new virtual environment 
*python -m venv venv*

activate
*.\venv\Scripts\Activate.ps1*

install all library 
*pip install -r requirements.txt*

install PostgreSQL
*https://www.postgresql.org/download/*

restore database 
*psql -U postgres -d olt_db -f database_backup.sql*

OLT realtime connection (ZTE C300/C320)
---------------------------------------
Copy `.env.example` to `.env` and set each OLT's Telnet password and SNMP v2c
community. Passwords and communities are read from the environment and are not
stored in PostgreSQL. OLT names in the environment keys must match the names
shown in OLT Management. Configure non-secret IP, port, model, and username in
the OLT Management page, then use Test Connection and Sync Now.

Traffic graphs poll the selected ONU every 10 seconds while the Graphs page is
open. Traffic samples are stored in PostgreSQL and retained for 30 days. Activity
Log records operations performed by this application from the time this version
is deployed; it cannot reconstruct older events from the ONU table.

OLT Settings profile and inventory records are stored in the application
database. Physical VLAN/interface/clock changes, uplink and PON telemetry, and
OLT configuration backup are not pushed/read yet. Temperature, fan, CPU, memory,
and hardware inventory are not present in the supplied database schema.
