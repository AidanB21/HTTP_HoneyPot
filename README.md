**Working on HTTP Honeypot, however had some issues getting it to stay up with Hostinger. So just the SSH honeypot demo is available.***



1) Download
Download this repo (or just honeypot_ssh.py) into a folder, e.g. C:\Users\YOU\Desktop\sshoney (Windows) or ~/sshoney (macOS/Linux).

2) Create a virtual environment
Windows (PowerShell):
cd C:\Users\YOU\Desktop\sshoney
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install paramiko

3) Run the honeypot (local only)
python honeypot_ssh.py --host 127.0.0.1 --port 2223

You should see:
SSH honeypot listening on 127.0.0.1:2223 … logs='./logs'

4) Test it
Open a second terminal and connect:
ssh -p 2223 test@127.0.0.1
Here is where you will try your active directory commands and try and learn more about the user.

6) View logs
Two files are written in ./logs/:
audits.jsonl – connections & auth attempts
commands.jsonl – every command typed

Open another powershell under the same folder and paste these:
Get-Content .\logs\audits.jsonl -Wait |
  ForEach-Object {
    try { $_ | ConvertFrom-Json |
      Select-Object ts,event,session_id,client_ip,client_port,username,password,banner,client_version,result |
      Format-Table -AutoSize
    } catch {}
  }
Get-Content .\logs\commands.jsonl -Wait |
  ForEach-Object {
    try { $_ | ConvertFrom-Json |
      Select-Object ts,event,session_id,client_ip,command |
      Format-Table -AutoSize
    } catch {}
  }
