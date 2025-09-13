#!/usr/bin/env python3
import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import socket
import threading
import time
from datetime import datetime, timezone

import paramiko

# ---------------------------
# Helpers
# ---------------------------
def iso_now():
    return datetime.now(timezone.utc).isoformat()

class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "ts": iso_now(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # If extra dict is attached, merge it
        if hasattr(record, "extra") and isinstance(record.extra, dict):
            payload.update(record.extra)
        return json.dumps(payload)

def build_logger(name, log_file, max_bytes=5_000_000, backups=5):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backups)
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    return logger

# ---------------------------
# Fake shell
# ---------------------------
def emulated_shell(channel, client_ip, cmd_logger):
    prompt = b"corporate-jumpbox2$ "
    channel.send(prompt)
    buf = bytearray()
    while True:
        try:
            chunk = channel.recv(1)
            if not chunk:
                channel.close()
                break
            # simple echo
            channel.send(chunk)
            # handle CR or LF as "enter"
            if chunk in (b"\r", b"\n"):
                raw = bytes(buf).strip()
                if len(raw) == 0:
                    channel.send(b"\r\n" + prompt)
                    buf.clear()
                    continue

                cmd = raw.decode(errors="replace")
                # log the command
                cmd_logger.info(
                    f"command",
                    extra={"extra": {"client_ip": client_ip, "event": "command", "command": cmd}},
                )

                # minimal command responses
                if cmd == "exit":
                    channel.send(b"\r\nGoodbye!\r\n")
                    try:
                        channel.close()
                    finally:
                        break

                elif cmd == "pwd":
                    channel.send(b"\r\n/usr/local\r\n")

                elif cmd == "whoami":
                    channel.send(b"\r\nsvc_deploy\r\n")

                elif cmd == "ls":
                    channel.send(b"\r\njumpbox1.conf  deploy.sh  .ssh  notes.txt\r\n")

                elif cmd == "cat jumpbox1.conf":
                    channel.send(b"\r\nenv=prod\npeer=jumpbox1\nnote=legacy bastion\r\n")

                else:
                    # default: "command not found" feel, but repeat back for realism
                    channel.send(b"\r\n" + raw + b": command not found\r\n")

                # next prompt
                channel.send(prompt)
                buf.clear()
            else:
                # collect normal byte
                buf += chunk

        except Exception:
            try:
                channel.close()
            finally:
                break

# ---------------------------
# Paramiko server interface
# ---------------------------
class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip, audit_logger, creds_logger, allow_user=None, allow_pass=None):
        super().__init__()
        self.client_ip = client_ip
        self.audit_logger = audit_logger
        self.creds_logger = creds_logger
        self.allow_user = allow_user
        self.allow_pass = allow_pass
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        # Log every credential attempt
        self.audit_logger.info(
            "auth_attempt",
            extra={"extra": {"event": "auth_attempt", "client_ip": self.client_ip, "username": username, "password": password}},
        )
        self.creds_logger.info(
            "creds",
            extra={"extra": {"event": "creds", "client_ip": self.client_ip, "username": username, "password": password}},
        )

        # If allow_user/allow_pass provided, only those succeed; else, always succeed
        if self.allow_user is not None and self.allow_pass is not None:
            if username == self.allow_user and password == self.allow_pass:
                return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

# ---------------------------
# Per-connection handler
# ---------------------------
def client_handle(sock, addr, host_key, banner, audit_logger, cmd_logger, allow_user, allow_pass):
    client_ip = addr[0]
    try:
        audit_logger.info("connection_open", extra={"extra": {"event": "connection_open", "client_ip": client_ip}})

        transport = paramiko.Transport(sock)
        transport.local_version = banner
        transport.add_server_key(host_key)

        server = HoneypotServer(client_ip, audit_logger, cmd_logger, allow_user, allow_pass)
        transport.start_server(server=server)

        chan = transport.accept(120)
        if chan is None:
            audit_logger.info("no_channel", extra={"extra": {"event": "no_channel", "client_ip": client_ip}})
            return

        # Small greeting
        chan.send(b"Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15 x86_64)\r\n\r\n")
        emulated_shell(chan, client_ip, cmd_logger)

    except Exception as e:
        audit_logger.info(
            "error",
            extra={"extra": {"event": "error", "client_ip": client_ip, "error": str(e)}},
        )
    finally:
        try:
            transport.close()
        except Exception:
            pass
        try:
            sock.close()
        except Exception:
            pass
        audit_logger.info("connection_close", extra={"extra": {"event": "connection_close", "client_ip": client_ip}})

# ---------------------------
# Main server loop
# ---------------------------
def run_server(bind_host, port, key_path, banner, log_dir, allow_user, allow_pass, backlog=100):
    # Prepare loggers
    audit_logger = build_logger("audit", os.path.join(log_dir, "audits.jsonl"))
    cmd_logger = build_logger("commands", os.path.join(log_dir, "commands.jsonl"))

    # Load or create host key
    if not os.path.exists(key_path):
        # Auto-generate
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(key_path)
        os.chmod(key_path, 0o600)
        audit_logger.info("generated_key", extra={"extra": {"event": "generated_key", "key_path": key_path}})
    host_key = paramiko.RSAKey(filename=key_path)

    # Socket
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((bind_host, port))
    srv.listen(backlog)

    print(f"[{iso_now()}] SSH honeypot listening on {bind_host}:{port}  banner='{banner}'  logs='{log_dir}'")
    audit_logger.info(
        "server_start",
        extra={"extra": {"event": "server_start", "bind_host": bind_host, "port": port, "banner": banner, "log_dir": log_dir}},
    )

    try:
        while True:
            client, addr = srv.accept()
            t = threading.Thread(
                target=client_handle,
                args=(client, addr, host_key, banner, audit_logger, cmd_logger, allow_user, allow_pass),
                daemon=True,
            )
            t.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        try:
            srv.close()
        except Exception:
            pass
        audit_logger.info("server_stop", extra={"extra": {"event": "server_stop"}})

# ---------------------------
# CLI
# ---------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Minimal SSH honeypot")
    p.add_argument("--host", default="127.0.0.1", help="Bind host (use 0.0.0.0 to expose on all interfaces)")
    p.add_argument("--port", type=int, default=2223, help="Bind port")
    p.add_argument("--key", default="server.key", help="Path to RSA private key (auto-generated if missing)")
    p.add_argument("--banner", default="SSH-2.0-OpenSSH_8.4p1 Ubuntu-5ubuntu1.1", help="SSH version banner to present")
    p.add_argument("--log-dir", default="./logs", help="Directory to write JSONL logs")
    p.add_argument("--allow-user", default=None, help="If set, only this username/password succeeds")
    p.add_argument("--allow-pass", default=None, help="If set, only this username/password succeeds")
    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    run_server(
        bind_host=args.host,
        port=args.port,
        key_path=args.key,
        banner=args.banner,
        log_dir=args.log_dir,
        allow_user=args.allow_user,
        allow_pass=args.allow_pass,
    )
