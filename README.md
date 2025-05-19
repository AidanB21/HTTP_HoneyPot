# HTTP HoneyPot

A lightweight HTTP honeypot to trap and log malicious web requests for threat research.

## 🚀 Features
- HTTP server that simulates common endpoints (`/login`, `/admin`, etc.)
- Logs attacker IP, headers, payloads
- Configurable templates for responses
- Pluggable modules for custom behavior

## 📦 Installation
```bash
git clone https://github.com/Ruler101/HTTP_HoneyPot.git
cd HTTP_HoneyPot
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
