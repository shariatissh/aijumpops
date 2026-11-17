#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AiJumpOps User Login Watcher
Monitors JumpServer PAM periodically (e.g. every 15 minutes) to detect when a
specific user logs in or establishes an active terminal session.
Exits immediately once a login event or active session is detected, notifying the harness.
"""

import datetime
import json
import os
import sys
import time
from pathlib import Path

# Add repo dir to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

import jmsctl

WATCH_USER = "pacs.support"
INTERVAL_SECONDS = 900  # 15 minutes
LOG_FILE = BASE_DIR / "watch_pacs.log"


def log(msg: str):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{now}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def check_user_activity(target_user: str):
    cfg = jmsctl.load_config()
    client = jmsctl.JumpServerClient(cfg)

    # 1. Check active live sessions
    try:
        raw_sess = client.get_paginated(
            "/api/v1/terminal/sessions/",
            params={"is_finished": "false"},
            limit=50,
        )
        for s in raw_sess:
            u_str = str(s.get("user") or "").lower()
            if target_user.lower() in u_str:
                return {
                    "event": "ACTIVE_SESSION",
                    "session_id": s.get("id"),
                    "user": s.get("user"),
                    "asset": s.get("asset"),
                    "account": s.get("account") or s.get("system_user"),
                    "protocol": s.get("protocol"),
                    "remote_addr": s.get("remote_addr"),
                    "date_start": s.get("date_start"),
                }
    except Exception as exc:
        log(f"Warning checking active sessions: {exc}")

    # 2. Check login audit logs
    try:
        raw_logins = client.get_paginated(
            "/api/v1/audits/login-logs/",
            params={"username": target_user, "limit": 10},
            limit=10,
        )
        if raw_logins:
            latest = raw_logins[0]
            return {
                "event": "LOGIN_DETECTED",
                "id": latest.get("id"),
                "username": latest.get("username"),
                "ip": latest.get("ip"),
                "status": latest.get("status"),
                "datetime": latest.get("datetime"),
            }
    except Exception as exc:
        log(f"Warning checking login logs: {exc}")

    return None


def main():
    log(f"Starting login watcher for user '{WATCH_USER}' (checking every {INTERVAL_SECONDS // 60} minutes)...")

    # Initial check
    initial = check_user_activity(WATCH_USER)
    if initial:
        log(f"🎉 USER ACTIVITY DETECTED: {json.dumps(initial, ensure_ascii=False, indent=2)}")
        print("\n" + "="*60, flush=True)
        print(f"ALERT: User '{WATCH_USER}' has connected to PAM!", flush=True)
        print(json.dumps(initial, ensure_ascii=False, indent=2), flush=True)
        print("="*60 + "\n", flush=True)
        return 0

    log(f"User '{WATCH_USER}' has NOT logged in yet. Entering 15-minute monitoring loop...")

    iteration = 1
    while True:
        time.sleep(INTERVAL_SECONDS)
        log(f"Check #{iteration}: Probing PAM for '{WATCH_USER}'...")
        activity = check_user_activity(WATCH_USER)
        if activity:
            log(f"🎉 USER ACTIVITY DETECTED on check #{iteration}: {json.dumps(activity, ensure_ascii=False, indent=2)}")
            print("\n" + "="*60, flush=True)
            print(f"ALERT: User '{WATCH_USER}' has connected to PAM!", flush=True)
            print(json.dumps(activity, ensure_ascii=False, indent=2), flush=True)
            print("="*60 + "\n", flush=True)
            return 0
        log(f"Check #{iteration}: User '{WATCH_USER}' has not connected yet. Waiting 15 minutes for next check...")
        iteration += 1


if __name__ == "__main__":
    sys.exit(main())
