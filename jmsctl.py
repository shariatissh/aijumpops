#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AiJumpOps (jmsctl) - Universal AI-Native JumpServer Bastion / PAM Copilot Engine.
Supports automatic API version detection (JumpServer v2 / v3 / v4),
Username/Password + TOTP (2FA/MFA) authentication (both automatic RFC 6238 TOTP
and interactive 6-digit OTP challenges), persistent session caching, and
AccessKey / Bearer token fallback.
Includes mandatory PREVIEW_ONLY safety mode, JSON snapshot backups, 1-click revert,
and AI Security Auditing. Never exposes secrets in outputs.
"""

import argparse
import base64
import datetime
import email.utils
import hashlib
import hmac
import ipaddress
import json
import os
import re
import struct
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests
import urllib3

# Suppress InsecureRequestWarning when JMS_VERIFY_SSL=false
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_DIR = Path(__file__).resolve().parent
USER_CONFIG_DIR = Path.home() / ".config" / "aijumpops"
DEFAULT_ENV_PATH = (
    BASE_DIR / ".env"
    if (BASE_DIR / ".env").exists()
    else (Path.cwd() / ".env" if (Path.cwd() / ".env").exists() else USER_CONFIG_DIR / ".env")
)
AUDIT_LOG_PATH = BASE_DIR / "audit.log" if os.access(BASE_DIR, os.W_OK) else USER_CONFIG_DIR / "audit.log"
BACKUPS_DIR = BASE_DIR / "backups" if os.access(BASE_DIR, os.W_OK) else USER_CONFIG_DIR / "backups"
CACHE_DIR = Path("/tmp/opencode") if Path("/tmp/opencode").exists() else Path("/tmp")
SESSION_CACHE_PATH = CACHE_DIR / ".jms_session_cache.json"
OTP_CHALLENGE_PATH = CACHE_DIR / ".jms_otp_challenge.json"

DEFAULT_ORG_ID = "00000000-0000-0000-0000-000000000002"

ACTION_ALIASES_V3 = {
    "all": ["connect", "upload", "download", "copy", "paste", "delete", "share"],
    "connect": ["connect"],
    "readonly": ["connect", "copy"],
    "transfer": ["connect", "upload", "download"],
    "updown": ["upload", "download"],
    "clipboard": ["copy", "paste"],
}


class JumpServerError(Exception):
    def __init__(self, message: str, code: str = "ERROR", details: Any = None, status_code: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details
        self.status_code = status_code


def parse_dotenv(env_path: Path) -> Dict[str, str]:
    """Safely parse a .env file without external dependencies."""
    env_vars: Dict[str, str] = {}
    if not env_path.exists():
        return env_vars

    content = env_path.read_text(encoding="utf-8", errors="replace")
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()

        if len(val) >= 2 and ((val[0] == '"' and val[-1] == '"') or (val[0] == "'" and val[-1] == "'")):
            val = val[1:-1]
        else:
            if " #" in val:
                val = val.split(" #", 1)[0].strip()

        env_vars[key] = val
    return env_vars


def load_config(env_path: Path = DEFAULT_ENV_PATH) -> Dict[str, Any]:
    """Load configuration from .env or environment variables."""
    file_env: Dict[str, str] = {}
    for candidate in (USER_CONFIG_DIR / ".env", Path.cwd() / ".env", BASE_DIR / ".env", env_path):
        if candidate.exists():
            file_env.update(parse_dotenv(candidate))

    def get_val(key: str, default: str = "") -> str:
        if key in file_env and file_env[key] != "":
            return file_env[key]
        if key in os.environ and os.environ[key] != "":
            return os.environ[key]
        return default

    verify_ssl_raw = get_val("JMS_VERIFY_SSL", "true").lower()
    verify_ssl = verify_ssl_raw not in ("false", "0", "no", "off")

    try:
        timeout = int(get_val("JMS_TIMEOUT", "30"))
    except ValueError:
        timeout = 30

    jms_url_raw = get_val("JMS_URL", "").strip()
    m_url = re.search(r"(https?://\S+)", jms_url_raw)
    jms_url = (m_url.group(1) if m_url else jms_url_raw).rstrip("/")
    return {
        "jms_url": jms_url,
        "username": get_val("JMS_USERNAME", ""),
        "password": get_val("JMS_PASSWORD", ""),
        "totp_secret": get_val("JMS_TOTP_SECRET", "").replace(" ", ""),
        "access_key_id": get_val("JMS_ACCESS_KEY_ID", ""),
        "access_key_secret": get_val("JMS_ACCESS_KEY_SECRET", ""),
        "private_token": get_val("JMS_PRIVATE_TOKEN", ""),
        "org_id": get_val("JMS_ORG_ID", DEFAULT_ORG_ID) or DEFAULT_ORG_ID,
        "api_version": get_val("JMS_API_VERSION", "auto").lower(),
        "verify_ssl": verify_ssl,
        "timeout": timeout,
        "proxy": get_val("JMS_PROXY", ""),
    }


def generate_totp(secret: str, interval: int = 30, digits: int = 6) -> str:
    """Pure-Python RFC 6238 TOTP generator (zero external dependencies).
    If the caller passes a 6-digit numeric OTP directly, returns empty string so interactive OTP flow is used."""
    stripped = secret.strip()
    if stripped.isdigit():
        return ""
    clean = re.sub(r"[^A-Za-z2-7]", "", stripped).upper()
    if len(clean) < 8:
        return ""
    missing_padding = len(clean) % 8
    if missing_padding:
        clean += "=" * (8 - missing_padding)
    try:
        key = base64.b32decode(clean, casefold=True)
    except Exception:
        return ""

    counter = int(time.time() // interval)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % (10**digits)
    return str(code_int).zfill(digits)


def write_audit_log(action: str, details: Dict[str, Any]) -> None:
    """Append confirmed mutating actions to audit.log."""
    try:
        AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "action": action,
            "details": details,
        }
        with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        pass


class JumpServerClient:
    """
    Universal JumpServer API Client supporting v2, v3, and v4:
    - Username/Password + TOTP (auto or interactive 6-digit challenge)
    - Session Cookie + Bearer/Keyword Token caching
    - AccessKey HMAC-SHA256 HTTP Signature (`httpsig`) & Private Token
    - Auto-detection of JumpServer API schema (v2 vs v3/v4)
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.base_url = config.get("jms_url", "").rstrip("/")
        if not self.base_url:
            raise JumpServerError(
                "JumpServer URL is not configured. Run `./jmsctl init` or set JMS_URL in `.env`.",
                code="MISSING_CONFIG",
            )
        self.org_id = config.get("org_id") or DEFAULT_ORG_ID
        self.session = requests.Session()
        self.session.verify = config.get("verify_ssl", True)
        self.timeout = config.get("timeout", 30)
        if config.get("proxy"):
            self.session.proxies = {"http": config["proxy"], "https": config["proxy"]}

        self.token: str = ""
        self.keyword: str = "Bearer"
        self.detected_version: str = config.get("api_version", "auto")
        if self.detected_version not in ("v2", "v3", "v4"):
            self.detected_version = ""
        self.current_user: Dict[str, Any] = {}

    def _cache_key(self) -> str:
        raw = f"{self.base_url}|{self.config.get('username','')}|{self.config.get('access_key_id','')}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def _load_cached_session(self) -> bool:
        if not SESSION_CACHE_PATH.exists():
            return False
        try:
            data = json.loads(SESSION_CACHE_PATH.read_text(encoding="utf-8"))
            entry = data.get(self._cache_key())
            if not entry:
                return False
            # Check age (default 10 hours max cache validity before probe)
            if time.time() - entry.get("saved_at", 0) > 36000:
                return False
            self.token = entry.get("token", "")
            self.keyword = entry.get("keyword", "Bearer")
            cookies = entry.get("cookies", {})
            for k, v in cookies.items():
                self.session.cookies.set(k, v)
            if not self.detected_version and entry.get("detected_version"):
                self.detected_version = entry["detected_version"]
            self.current_user = entry.get("current_user", {})
            return True
        except Exception:
            return False

    def _save_cached_session(self) -> None:
        try:
            SESSION_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
            data: Dict[str, Any] = {}
            if SESSION_CACHE_PATH.exists():
                try:
                    data = json.loads(SESSION_CACHE_PATH.read_text(encoding="utf-8"))
                except Exception:
                    data = {}
            data[self._cache_key()] = {
                "saved_at": time.time(),
                "token": self.token,
                "keyword": self.keyword,
                "cookies": requests.utils.dict_from_cookiejar(self.session.cookies),
                "detected_version": self.detected_version,
                "current_user": self.current_user,
            }
            SESSION_CACHE_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            os.chmod(SESSION_CACHE_PATH, 0o600)
        except Exception:
            pass

    def _clear_cached_session(self) -> None:
        self.token = ""
        self.session.cookies.clear()
        if SESSION_CACHE_PATH.exists():
            try:
                data = json.loads(SESSION_CACHE_PATH.read_text(encoding="utf-8"))
                data.pop(self._cache_key(), None)
                SESSION_CACHE_PATH.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
            except Exception:
                pass

    def _save_otp_challenge(self, challenge_data: Dict[str, Any]) -> None:
        try:
            OTP_CHALLENGE_PATH.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "saved_at": time.time(),
                "cache_key": self._cache_key(),
                "cookies": requests.utils.dict_from_cookiejar(self.session.cookies),
                "challenge": challenge_data,
            }
            OTP_CHALLENGE_PATH.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            os.chmod(OTP_CHALLENGE_PATH, 0o600)
        except Exception:
            pass

    def _sign_access_key_headers(self, method: str, path_with_query: str, headers: Dict[str, str]) -> Dict[str, str]:
        """Generate JumpServer HTTP Signature (httpsig HMAC-SHA256) headers for AccessKey auth."""
        ak_id = self.config.get("access_key_id", "")
        ak_secret = self.config.get("access_key_secret", "")
        date_str = email.utils.formatdate(usegmt=True)
        headers["Date"] = date_str
        headers["Accept"] = "application/json"
        request_line = f"{method.lower()} {path_with_query}"
        signing_str = f"(request-target): {request_line}\naccept: {headers['Accept']}\ndate: {date_str}"
        signature = base64.b64encode(
            hmac.new(ak_secret.encode("utf-8"), signing_str.encode("utf-8"), hashlib.sha256).digest()
        ).decode("utf-8")
        headers["Authorization"] = (
            f'Signature keyId="{ak_id}",algorithm="hmac-sha256",'
            f'headers="(request-target) accept date",signature="{signature}"'
        )
        return headers

    def _build_headers(self, method: str, path_with_query: str) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-JMS-ORG": self.org_id,
        }
        csrf_token = self.session.cookies.get("jms_csrftoken") or self.session.cookies.get("csrftoken")
        if csrf_token:
            headers["X-CSRFToken"] = csrf_token
            headers["Referer"] = self.base_url + "/"

        if self.config.get("private_token"):
            headers["Authorization"] = f"Token {self.config['private_token']}"
        elif self.token:
            headers["Authorization"] = f"{self.keyword} {self.token}"
        elif self.config.get("access_key_id") and self.config.get("access_key_secret"):
            self._sign_access_key_headers(method, path_with_query, headers)
        return headers

    def complete_otp_challenge(self, otp_code: str, mfa_type: str = "otp") -> Dict[str, Any]:
        """Complete a pending 2FA/TOTP challenge using a 6-digit OTP code."""
        otp_code = str(otp_code).strip()
        if not otp_code:
            raise JumpServerError("OTP code cannot be empty.", code="MISSING_OTP_CODE")

        challenge_url_from_state = ""
        if OTP_CHALLENGE_PATH.exists():
            try:
                saved = json.loads(OTP_CHALLENGE_PATH.read_text(encoding="utf-8"))
                if saved.get("cache_key") == self._cache_key():
                    for k, v in saved.get("cookies", {}).items():
                        self.session.cookies.set(k, v)
                    resp_obj = saved.get("challenge", {}).get("response", {})
                    if isinstance(resp_obj, dict) and isinstance(resp_obj.get("data"), dict):
                        challenge_url_from_state = str(resp_obj["data"].get("url", ""))
            except Exception:
                pass

        # Always perform fresh step 1 authentication immediately before submitting OTP
        # so the server-side MFA session state is guaranteed to be fresh and valid.
        username = self.config.get("username", "")
        password = self.config.get("password", "")
        if username and password:
            try:
                self.session.cookies.clear()
                r1 = self.session.post(
                    f"{self.base_url}/api/v1/authentication/auth/",
                    json={"username": username, "password": password},
                    headers={"Accept": "application/json", "Content-Type": "application/json"},
                    timeout=self.timeout,
                )
                if r1.status_code in (200, 201):
                    d1 = r1.json()
                    if isinstance(d1, dict) and d1.get("token"):
                        self.token = d1["token"]
                        self.keyword = d1.get("keyword", "Bearer")
                        profile = self._probe_profile() or d1.get("user", {})
                        self.current_user = profile
                        self._detect_api_version()
                        self._save_cached_session()
                        return profile
                    if isinstance(d1, dict) and isinstance(d1.get("data"), dict):
                        challenge_url_from_state = str(d1["data"].get("url", ""))
            except Exception:
                pass

        endpoints = [
            ("/api/v1/authentication/mfa/challenge/", {"type": mfa_type, "code": otp_code}),
        ]
        if (
            challenge_url_from_state
            and challenge_url_from_state.startswith("/")
            and challenge_url_from_state != "/api/v1/authentication/mfa/challenge/"
        ):
            endpoints.insert(0, (challenge_url_from_state, {"type": mfa_type, "code": otp_code}))

        last_err = None
        for ep, payload in endpoints:
            url = f"{self.base_url}{ep}"
            headers = self._build_headers("POST", ep)
            try:
                resp = self.session.post(url, json=payload, headers=headers, timeout=self.timeout)
                if resp.status_code in (200, 201):
                    data = resp.json() if resp.text else {}
                    if isinstance(data, dict) and data.get("token"):
                        self.token = data["token"]
                        self.keyword = data.get("keyword", "Bearer")
                    if isinstance(data, dict) and data.get("msg") == "ok" and not data.get("token"):
                        # JumpServer v3/v4 two-step auth flow: after /mfa/challenge/ returns {"msg": "ok"},
                        # call GET or POST /api/v1/authentication/auth/ (or /tokens/) to finalize token/session
                        for fin_method, fin_ep in (
                            ("POST", "/api/v1/authentication/auth/"),
                            ("GET", "/api/v1/authentication/auth/"),
                            ("POST", "/api/v1/authentication/tokens/"),
                        ):
                            try:
                                fin_resp = self.session.request(
                                    fin_method,
                                    f"{self.base_url}{fin_ep}",
                                    headers=self._build_headers(fin_method, fin_ep),
                                    timeout=self.timeout,
                                )
                                if fin_resp.status_code in (200, 201):
                                    fin_data = fin_resp.json() if fin_resp.text else {}
                                    if isinstance(fin_data, dict) and fin_data.get("token"):
                                        self.token = fin_data["token"]
                                        self.keyword = fin_data.get("keyword", "Bearer")
                                    if isinstance(fin_data, dict) and isinstance(fin_data.get("user"), dict):
                                        self.current_user = fin_data["user"]
                                    break
                            except Exception:
                                pass
                    # Verify profile (or fall back to data["user"] if returned directly by challenge)
                    profile = self._probe_profile() or (data.get("user") if isinstance(data, dict) else None)
                    if profile:
                        self.current_user = profile
                        self._detect_api_version()
                        self._save_cached_session()
                        if OTP_CHALLENGE_PATH.exists():
                            OTP_CHALLENGE_PATH.unlink(missing_ok=True)
                        return profile
                    last_err = data
                else:
                    try:
                        last_err = resp.json()
                    except Exception:
                        last_err = resp.text[:300]
                    if isinstance(last_err, dict) and last_err.get("error") == "mfa_failed":
                        break
            except Exception as exc:
                last_err = str(exc)

        raise JumpServerError(
            "Failed to verify 2FA/TOTP code. Check that the 6-digit code is current and hasn't expired.",
            code="OTP_VERIFICATION_FAILED",
            details=last_err,
        )

    def _probe_profile(self) -> Optional[Dict[str, Any]]:
        """Check if current credentials/session are valid by querying user profile."""
        ep = "/api/v1/users/profile/"
        url = f"{self.base_url}{ep}"
        headers = self._build_headers("GET", ep)
        try:
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict) and data.get("id"):
                    return data
        except Exception:
            pass
        return None

    def _detect_api_version(self) -> str:
        """Auto-detect JumpServer API version (v2 vs v3/v4) by inspecting endpoints."""
        if self.detected_version in ("v2", "v3", "v4"):
            return self.detected_version

        # Probe /api/v1/accounts/accounts/ (exists in v3 and v4, 404 in v2)
        ep_v3 = "/api/v1/accounts/accounts/?limit=1"
        headers = self._build_headers("GET", ep_v3)
        try:
            resp = self.session.get(f"{self.base_url}{ep_v3}", headers=headers, timeout=self.timeout)
            if resp.status_code in (200, 403):
                # Distinguish v4 vs v3 if possible via /api/v1/settings/public/
                pub_ep = "/api/v1/settings/public/"
                pub_resp = self.session.get(
                    f"{self.base_url}{pub_ep}", headers=self._build_headers("GET", pub_ep), timeout=self.timeout
                )
                if pub_resp.status_code == 200:
                    pub_data = pub_resp.json()
                    ver_str = str(pub_data.get("VERSION", "") or pub_data.get("version", ""))
                    if ver_str.startswith("v4") or ver_str.startswith("4."):
                        self.detected_version = "v4"
                        return "v4"
                self.detected_version = "v3"
                return "v3"
        except Exception:
            pass

        self.detected_version = "v2"
        return "v2"

    def authenticate(self, force_refresh: bool = False, manual_otp: Optional[str] = None) -> Dict[str, Any]:
        """Authenticate with JumpServer using cached session, Private Token, AccessKey, or Username/Password + TOTP."""
        if manual_otp:
            return self.complete_otp_challenge(manual_otp)

        if not force_refresh and self._load_cached_session():
            profile = self._probe_profile()
            if profile:
                self.current_user = profile
                if not self.detected_version:
                    self._detect_api_version()
                    self._save_cached_session()
                return profile
            self._clear_cached_session()

        # Check static Private Token or AccessKey first if configured
        if self.config.get("private_token") or (
            self.config.get("access_key_id") and self.config.get("access_key_secret")
        ):
            profile = self._probe_profile()
            if profile:
                self.current_user = profile
                self._detect_api_version()
                self._save_cached_session()
                return profile

        username = self.config.get("username", "")
        password = self.config.get("password", "")
        if not username or not password:
            raise JumpServerError(
                "Missing credentials. Set JMS_URL, JMS_USERNAME, and JMS_PASSWORD in `.env` (or run `./jmsctl init`).",
                code="MISSING_CREDENTIALS",
            )

        # Step 1: Username & Password Authentication via `/api/v1/authentication/auth/` or `/api/v1/authentication/tokens/`
        auth_endpoints = [
            "/api/v1/authentication/auth/",
            "/api/v1/authentication/tokens/",
        ]
        totp_secret = self.config.get("totp_secret", "")
        auto_otp = generate_totp(totp_secret) if totp_secret else (manual_otp or "")

        last_response_data: Any = None
        last_status: Optional[int] = None

        for ep in auth_endpoints:
            url = f"{self.base_url}{ep}"
            payload: Dict[str, Any] = {
                "username": username,
                "password": password,
            }
            if auto_otp:
                payload["code"] = auto_otp
                payload["otp_code"] = auto_otp

            try:
                resp = self.session.post(
                    url,
                    json=payload,
                    headers={"Accept": "application/json", "Content-Type": "application/json"},
                    timeout=self.timeout,
                )
                last_status = resp.status_code
                try:
                    data = resp.json()
                except Exception:
                    data = {"raw": resp.text[:400]}
                last_response_data = data

                # Case A: Direct Token issued (No MFA or MFA satisfied inline)
                if resp.status_code in (200, 201) and isinstance(data, dict) and data.get("token"):
                    self.token = data["token"]
                    self.keyword = data.get("keyword", "Bearer")
                    if isinstance(data.get("user"), dict):
                        self.current_user = data["user"]
                    profile = self._probe_profile() or self.current_user
                    self.current_user = profile
                    self._detect_api_version()
                    self._save_cached_session()
                    return profile

                # Case B: MFA Challenge required by JumpServer (`mfa_required` / `choices` / `otp`)
                is_mfa_challenge = False
                mfa_choices: List[str] = ["otp"]
                if isinstance(data, dict):
                    msg_str = str(data.get("msg", "") or data.get("error", "") or data.get("detail", "")).lower()
                    data_inner = data.get("data", {}) if isinstance(data.get("data"), dict) else {}
                    if (
                        data.get("error") == "mfa_required"
                        or "mfa" in msg_str
                        or "otp" in msg_str
                        or "choices" in data
                        or "choices" in data_inner
                    ):
                        is_mfa_challenge = True
                        mfa_choices = data.get("choices") or data_inner.get("choices") or ["otp"]

                if is_mfa_challenge:
                    mfa_type = "otp" if "otp" in mfa_choices else mfa_choices[0]
                    if auto_otp:
                        # Complete step 2 automatically
                        return self.complete_otp_challenge(auto_otp, mfa_type=mfa_type)
                    else:
                        # Save challenge session and prompt user / AI agent for 6-digit TOTP code
                        self._save_otp_challenge({"endpoint": ep, "mfa_choices": mfa_choices, "response": data})
                        raise JumpServerError(
                            "2FA / TOTP verification is enabled on this JumpServer account. "
                            "Please provide your current 6-digit Authenticator code via `./jmsctl auth-otp --code <6_DIGIT_CODE>` "
                            "(or set `JMS_TOTP_SECRET` in `.env` for automatic zero-touch MFA).",
                            code="MFA_OTP_REQUIRED",
                            details={
                                "mfa_choices": mfa_choices,
                                "next_command": "./jmsctl auth-otp --code <6_DIGIT_CODE>",
                                "hint": "Once verified, the session is cached so you won't need to enter OTP on every command.",
                            },
                            status_code=200,
                        )
            except JumpServerError:
                raise
            except requests.RequestException as exc:
                raise JumpServerError(
                    f"Connection to JumpServer ({self.base_url}) failed: {exc}",
                    code="CONNECTION_ERROR",
                )

        raise JumpServerError(
            "JumpServer authentication failed. Please check JMS_USERNAME and JMS_PASSWORD in `.env`.",
            code="AUTH_FAILED",
            details=last_response_data,
            status_code=last_status,
        )

    def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Any] = None,
        org_id: Optional[str] = None,
    ) -> Any:
        """Perform an authenticated API request against JumpServer with automatic pagination / error handling."""
        self.authenticate()

        if not path.startswith("/"):
            path = "/" + path
        url = f"{self.base_url}{path}"
        if params:
            clean_params = {k: v for k, v in params.items() if v is not None and v != ""}
            query_str = urllib.parse.urlencode(clean_params, doseq=True)
            path_with_query = f"{path}?{query_str}" if query_str else path
        else:
            clean_params = None
            path_with_query = path

        headers = self._build_headers(method, path_with_query)
        if org_id:
            headers["X-JMS-ORG"] = org_id

        try:
            resp = self.session.request(
                method=method.upper(),
                url=url,
                params=clean_params,
                json=json_body,
                headers=headers,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise JumpServerError(f"HTTP {method} {path} failed: {exc}", code="NETWORK_ERROR")

        # Handle session expiry transparently once
        if resp.status_code == 401:
            self._clear_cached_session()
            self.authenticate(force_refresh=True)
            headers = self._build_headers(method, path_with_query)
            if org_id:
                headers["X-JMS-ORG"] = org_id
            resp = self.session.request(
                method=method.upper(),
                url=url,
                params=clean_params,
                json=json_body,
                headers=headers,
                timeout=self.timeout,
            )

        if resp.status_code == 204 or not resp.text:
            return {}

        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text[:500]}

        if resp.status_code >= 400:
            raise JumpServerError(
                f"JumpServer API error ({resp.status_code}) on {method.upper()} {path}",
                code=f"HTTP_{resp.status_code}",
                details=data,
                status_code=resp.status_code,
            )
        return data

    def get_paginated(self, path: str, params: Optional[Dict[str, Any]] = None, limit: int = 500) -> List[Dict[str, Any]]:
        """Fetch list endpoints handling both DRF paginated (`results`) and flat list responses."""
        req_params = dict(params or {})
        req_params.setdefault("limit", min(limit, 500))
        req_params.setdefault("offset", 0)
        data = self.request("GET", path, params=req_params)
        if isinstance(data, list):
            return data[:limit]
        if isinstance(data, dict) and isinstance(data.get("results"), list):
            results = list(data["results"])
            total = data.get("count", len(results))
            while len(results) < min(total, limit) and data.get("next"):
                req_params["offset"] = len(results)
                data = self.request("GET", path, params=req_params)
                if not isinstance(data, dict) or not data.get("results"):
                    break
                results.extend(data["results"])
            return results[:limit]
        return []

    @property
    def is_v3_or_v4(self) -> bool:
        self.authenticate()
        return self.detected_version in ("v3", "v4")

    # -------------------------------------------------------------------------
    # Normalization Helpers (Cross-Version v2 / v3 / v4 Compatibility)
    # -------------------------------------------------------------------------

    @staticmethod
    def normalize_asset(raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize JumpServer Asset / Host record across v2, v3, and v4."""
        platform = raw.get("platform")
        if isinstance(platform, dict):
            platform_name = platform.get("name", "")
            platform_id = platform.get("id")
        else:
            platform_name = str(platform or raw.get("platform_name", "Linux"))
            platform_id = raw.get("platform_id")

        nodes_raw = raw.get("nodes_display") or raw.get("nodes") or []
        nodes: List[str] = []
        for n in nodes_raw:
            if isinstance(n, dict):
                nodes.append(n.get("full_value") or n.get("value") or n.get("name") or str(n.get("id", "")))
            else:
                nodes.append(str(n))

        protocols_raw = raw.get("protocols") or []
        protocols: List[str] = []
        if isinstance(protocols_raw, list):
            for p in protocols_raw:
                if isinstance(p, dict):
                    protocols.append(f"{p.get('name','ssh')}/{p.get('port', 22)}")
                else:
                    protocols.append(str(p))
        elif raw.get("protocol"):
            protocols.append(f"{raw.get('protocol')}/{raw.get('port', 22)}")

        is_active = raw.get("is_active", True)
        connectivity = raw.get("connectivity")
        if isinstance(connectivity, dict):
            conn_status = connectivity.get("label") or connectivity.get("value") or "unknown"
        else:
            conn_status = str(connectivity or "unknown")

        return {
            "id": str(raw.get("id", "")),
            "name": str(raw.get("name") or raw.get("hostname") or ""),
            "address": str(raw.get("address") or raw.get("ip") or ""),
            "platform": platform_name,
            "platform_id": platform_id,
            "protocols": protocols or ["ssh/22"],
            "nodes": nodes,
            "is_active": bool(is_active),
            "connectivity": conn_status,
            "comment": str(raw.get("comment") or ""),
            "org_name": str(raw.get("org_name") or ""),
        }

    @staticmethod
    def normalize_user(raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize JumpServer User record across v2, v3, and v4."""
        groups_raw = raw.get("groups_display") or raw.get("groups") or []
        groups: List[str] = []
        if isinstance(groups_raw, str):
            groups = [g.strip() for g in groups_raw.split(",") if g.strip()]
        elif isinstance(groups_raw, list):
            for g in groups_raw:
                if isinstance(g, dict):
                    groups.append(g.get("name") or str(g.get("id", "")))
                else:
                    groups.append(str(g))

        mfa_level = raw.get("mfa_level")
        if isinstance(mfa_level, dict):
            mfa_enabled = mfa_level.get("value", 0) not in (0, "0", False, None)
            mfa_label = mfa_level.get("label", "")
        else:
            mfa_enabled = bool(raw.get("mfa_enabled") or (mfa_level not in (0, "0", False, None)))
            mfa_label = "Enabled" if mfa_enabled else "Disabled"

        role_raw = raw.get("role_display") or raw.get("system_roles") or raw.get("role") or "User"
        if isinstance(role_raw, list):
            roles = [r.get("display_name") or r.get("name") if isinstance(r, dict) else str(r) for r in role_raw]
            role_str = ", ".join(roles)
        else:
            role_str = str(role_raw)

        return {
            "id": str(raw.get("id", "")),
            "name": str(raw.get("name") or ""),
            "username": str(raw.get("username") or ""),
            "email": str(raw.get("email") or ""),
            "role": role_str,
            "groups": groups,
            "is_active": bool(raw.get("is_active", True)),
            "is_valid": bool(raw.get("is_valid", raw.get("is_active", True))),
            "mfa_enabled": mfa_enabled,
            "mfa_status": mfa_label,
            "date_expired": str(raw.get("date_expired") or ""),
            "last_login": str(raw.get("last_login") or ""),
            "source": str(
                raw.get("source", {}).get("label") if isinstance(raw.get("source"), dict) else raw.get("source", "Local")
            ),
        }

    @staticmethod
    def normalize_permission(raw: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize JumpServer AssetPermission record across v2, v3, and v4."""
        def _extract_names(field_val: Any, display_val: Any = None) -> List[str]:
            source = display_val if display_val else field_val
            if not source:
                return []
            if isinstance(source, str):
                return [s.strip() for s in source.split(",") if s.strip()]
            out: List[str] = []
            if isinstance(source, list):
                for item in source:
                    if isinstance(item, dict):
                        out.append(
                            str(item.get("name") or item.get("username") or item.get("value") or item.get("id") or "")
                        )
                    else:
                        out.append(str(item))
            return out

        def _extract_ids(field_val: Any) -> List[str]:
            if not isinstance(field_val, list):
                return []
            out: List[str] = []
            for item in field_val:
                if isinstance(item, dict):
                    if item.get("id"):
                        out.append(str(item["id"]))
                elif item:
                    out.append(str(item))
            return out

        accounts_raw = raw.get("accounts") or raw.get("system_users_display") or raw.get("system_users") or []
        accounts = _extract_names(accounts_raw)

        actions_raw = raw.get("actions") or []
        actions: List[str] = []
        if isinstance(actions_raw, list):
            for a in actions_raw:
                if isinstance(a, dict):
                    actions.append(str(a.get("value") or a.get("label") or ""))
                else:
                    actions.append(str(a))
        elif isinstance(actions_raw, (int, str)):
            actions = [str(actions_raw)]

        return {
            "id": str(raw.get("id", "")),
            "name": str(raw.get("name") or ""),
            "users": _extract_names(raw.get("users"), raw.get("users_display")),
            "user_ids": _extract_ids(raw.get("users")),
            "user_groups": _extract_names(raw.get("user_groups"), raw.get("user_groups_display")),
            "user_group_ids": _extract_ids(raw.get("user_groups")),
            "assets": _extract_names(raw.get("assets"), raw.get("assets_display")),
            "asset_ids": _extract_ids(raw.get("assets")),
            "nodes": _extract_names(raw.get("nodes"), raw.get("nodes_display")),
            "node_ids": _extract_ids(raw.get("nodes")),
            "accounts": accounts,
            "actions": actions or ["connect"],
            "is_active": bool(raw.get("is_active", True)),
            "is_valid": bool(raw.get("is_valid", raw.get("is_active", True))),
            "is_expired": bool(raw.get("is_expired", False)),
            "date_start": str(raw.get("date_start") or ""),
            "date_expired": str(raw.get("date_expired") or ""),
            "comment": str(raw.get("comment") or ""),
        }

    # -------------------------------------------------------------------------
    # Entity Resolution Helpers (Fuzzy Search & Ambiguity Prevention)
    # -------------------------------------------------------------------------

    def list_assets_raw(self, search: str = "", limit: int = 500) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if search:
            params["search"] = search
        return self.get_paginated("/api/v1/assets/assets/", params=params, limit=limit)

    def resolve_asset(self, query: str) -> Dict[str, Any]:
        """Resolve a single asset by exact ID, exact IP, exact name, or unambiguous partial match."""
        q = query.strip()
        if not q:
            raise JumpServerError("Asset query cannot be empty.", code="EMPTY_ASSET_QUERY")

        candidates = self.list_assets_raw(search=q, limit=100)
        if not candidates:
            all_assets = self.list_assets_raw(limit=500)
            ql = q.lower()
            candidates = [
                a
                for a in all_assets
                if ql in str(a.get("name") or a.get("hostname") or "").lower()
                or ql in str(a.get("address") or a.get("ip") or "").lower()
                or ql == str(a.get("id", "")).lower()
            ]

        if not candidates:
            raise JumpServerError(f"No JumpServer asset found matching '{query}'.", code="ASSET_NOT_FOUND")

        ql = q.lower()
        exact = [
            a
            for a in candidates
            if str(a.get("id", "")).lower() == ql
            or str(a.get("name") or a.get("hostname") or "").lower() == ql
            or str(a.get("address") or a.get("ip") or "").lower() == ql
        ]
        if len(exact) == 1:
            return exact[0]
        if len(candidates) == 1:
            return candidates[0]

        raise JumpServerError(
            f"Multiple JumpServer assets match '{query}'. Please ask the user to select the exact asset.",
            code="AMBIGUOUS_ASSET",
            details={"matches": [self.normalize_asset(a) for a in candidates[:15]]},
        )

    def list_users_raw(self, search: str = "", limit: int = 500) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {}
        if search:
            params["search"] = search
        return self.get_paginated("/api/v1/users/users/", params=params, limit=limit)

    def resolve_user(self, query: str) -> Dict[str, Any]:
        """Resolve a single JumpServer user by exact ID, username, name, email, or unambiguous partial match."""
        q = query.strip()
        if not q:
            raise JumpServerError("User query cannot be empty.", code="EMPTY_USER_QUERY")

        candidates = self.list_users_raw(search=q, limit=100)
        if not candidates:
            all_users = self.list_users_raw(limit=500)
            ql = q.lower()
            candidates = [
                u
                for u in all_users
                if ql in str(u.get("username") or "").lower()
                or ql in str(u.get("name") or "").lower()
                or ql in str(u.get("email") or "").lower()
                or ql == str(u.get("id", "")).lower()
            ]

        if not candidates:
            raise JumpServerError(f"No JumpServer user found matching '{query}'.", code="USER_NOT_FOUND")

        ql = q.lower()
        exact = [
            u
            for u in candidates
            if str(u.get("id", "")).lower() == ql
            or str(u.get("username") or "").lower() == ql
            or str(u.get("name") or "").lower() == ql
            or str(u.get("email") or "").lower() == ql
        ]
        if len(exact) == 1:
            return exact[0]
        if len(candidates) == 1:
            return candidates[0]

        raise JumpServerError(
            f"Multiple JumpServer users match '{query}'. Please ask the user to select the exact user.",
            code="AMBIGUOUS_USER",
            details={"matches": [self.normalize_user(u) for u in candidates[:15]]},
        )

    def list_user_groups_raw(self, search: str = "", limit: int = 500) -> List[Dict[str, Any]]:
        params = {"search": search} if search else {}
        return self.get_paginated("/api/v1/users/groups/", params=params, limit=limit)

    def resolve_user_group(self, query: str) -> Dict[str, Any]:
        q = query.strip()
        candidates = self.list_user_groups_raw(search=q, limit=100)
        if not candidates:
            raise JumpServerError(f"No User Group found matching '{query}'.", code="USER_GROUP_NOT_FOUND")
        ql = q.lower()
        exact = [g for g in candidates if str(g.get("id", "")).lower() == ql or str(g.get("name", "")).lower() == ql]
        if len(exact) == 1:
            return exact[0]
        if len(candidates) == 1:
            return candidates[0]
        raise JumpServerError(
            f"Multiple User Groups match '{query}'.",
            code="AMBIGUOUS_USER_GROUP",
            details={"matches": [{"id": g.get("id"), "name": g.get("name")} for g in candidates[:15]]},
        )

    def list_nodes_raw(self, search: str = "", limit: int = 500) -> List[Dict[str, Any]]:
        params = {"search": search} if search else {}
        return self.get_paginated("/api/v1/assets/nodes/", params=params, limit=limit)

    def resolve_node(self, query: str) -> Dict[str, Any]:
        q = query.strip()
        all_nodes = self.list_nodes_raw(limit=500)
        ql = q.lower()
        exact = [
            n
            for n in all_nodes
            if str(n.get("id", "")).lower() == ql
            or str(n.get("value") or "").lower() == ql
            or str(n.get("full_value") or "").lower() == ql
            or str(n.get("name") or "").lower() == ql
        ]
        if len(exact) == 1:
            return exact[0]
        partial = [
            n
            for n in all_nodes
            if ql in str(n.get("full_value") or n.get("value") or n.get("name") or "").lower()
        ]
        if len(partial) == 1:
            return partial[0]
        if not partial:
            raise JumpServerError(f"No Asset Node found matching '{query}'.", code="NODE_NOT_FOUND")
        raise JumpServerError(
            f"Multiple Asset Nodes match '{query}'.",
            code="AMBIGUOUS_NODE",
            details={
                "matches": [
                    {"id": n.get("id"), "value": n.get("value"), "full_value": n.get("full_value")}
                    for n in partial[:15]
                ]
            },
        )

    def list_permissions_raw(self, search: str = "", limit: int = 500) -> List[Dict[str, Any]]:
        params = {"search": search} if search else {}
        return self.get_paginated("/api/v1/perms/asset-permissions/", params=params, limit=limit)

    def resolve_permission(self, query: str) -> Dict[str, Any]:
        q = query.strip()
        candidates = self.list_permissions_raw(search=q, limit=100)
        if not candidates:
            all_perms = self.list_permissions_raw(limit=500)
            ql = q.lower()
            candidates = [
                p
                for p in all_perms
                if ql == str(p.get("id", "")).lower() or ql in str(p.get("name") or "").lower()
            ]
        if not candidates:
            raise JumpServerError(f"No Asset Permission rule found matching '{query}'.", code="PERMISSION_NOT_FOUND")
        ql = q.lower()
        exact = [
            p for p in candidates if str(p.get("id", "")).lower() == ql or str(p.get("name") or "").lower() == ql
        ]
        if len(exact) == 1:
            return exact[0]
        if len(candidates) == 1:
            return candidates[0]
        raise JumpServerError(
            f"Multiple Asset Permission rules match '{query}'. Please ask the user to choose one.",
            code="AMBIGUOUS_PERMISSION",
            details={"matches": [self.normalize_permission(p) for p in candidates[:15]]},
        )

    def list_accounts_for_asset(self, asset_id: str) -> List[Dict[str, Any]]:
        """List available system accounts/users on a specific asset across v2, v3, and v4."""
        if self.is_v3_or_v4:
            try:
                raw_accs = self.get_paginated("/api/v1/accounts/accounts/", params={"asset": asset_id}, limit=200)
                return [
                    {
                        "id": str(a.get("id", "")),
                        "name": str(a.get("name") or ""),
                        "username": str(a.get("username") or ""),
                        "privileged": bool(a.get("privileged", False)),
                        "is_active": bool(a.get("is_active", True)),
                    }
                    for a in raw_accs
                ]
            except Exception:
                return []
        else:
            try:
                raw_sys = self.get_paginated("/api/v1/assets/system-users/", limit=200)
                return [
                    {
                        "id": str(s.get("id", "")),
                        "name": str(s.get("name") or ""),
                        "username": str(s.get("username") or s.get("name") or ""),
                        "protocol": str(s.get("protocol") or "ssh"),
                    }
                    for s in raw_sys
                ]
            except Exception:
                return []


# =============================================================================
# High-Level Command Implementations (Safety-First PREVIEW_ONLY + JSON Output)
# =============================================================================


def cmd_init(
    url: str = "",
    username: str = "",
    password: str = "",
    totp_secret: str = "",
    org_id: str = "",
    verify_ssl: bool = True,
    interactive: bool = False,
) -> Dict[str, Any]:
    """Initialize `.env` configuration safely with chmod 0600."""
    target_env = BASE_DIR / ".env" if os.access(BASE_DIR, os.W_OK) else USER_CONFIG_DIR / ".env"
    target_env.parent.mkdir(parents=True, exist_ok=True)
    existing = parse_dotenv(target_env) if target_env.exists() else {}

    if interactive and sys.stdin.isatty():
        import getpass

        url = url or input(f"JumpServer URL [{existing.get('JMS_URL', 'https://jumpserver.example.com')}]: ").strip()
        username = username or input(f"JumpServer Username [{existing.get('JMS_USERNAME', 'admin')}]: ").strip()
        if not password:
            password = getpass.getpass("JumpServer Password (input hidden): ").strip()
        totp_secret = totp_secret or input(
            "Optional TOTP Base32 Secret (leave empty for interactive 6-digit OTP prompt): "
        ).strip()

    final_url = (url or existing.get("JMS_URL", "https://jumpserver.example.com")).rstrip("/")
    final_user = username or existing.get("JMS_USERNAME", "")
    final_pass = password or existing.get("JMS_PASSWORD", "")
    final_totp = totp_secret if totp_secret != "" else existing.get("JMS_TOTP_SECRET", "")
    final_org = org_id or existing.get("JMS_ORG_ID", DEFAULT_ORG_ID)
    final_ssl = "true" if verify_ssl else "false"

    env_content = (
        "# AiJumpOps Configuration (Generated by ./jmsctl init)\n"
        f'JMS_URL="{final_url}"\n'
        f'JMS_USERNAME="{final_user}"\n'
        f'JMS_PASSWORD="{final_pass}"\n'
        f'JMS_TOTP_SECRET="{final_totp}"\n'
        f'JMS_ORG_ID="{final_org}"\n'
        f'JMS_VERIFY_SSL="{final_ssl}"\n'
        'JMS_API_VERSION="auto"\n'
    )
    target_env.write_text(env_content, encoding="utf-8")
    os.chmod(target_env, 0o600)

    return {
        "status": "CONFIG_SAVED",
        "env_file": str(target_env),
        "jms_url": final_url,
        "username": final_user,
        "totp_auto_configured": bool(final_totp),
        "org_id": final_org,
        "permissions": "0600",
    }


def cmd_auth_check(force_refresh: bool = False, otp_code: Optional[str] = None) -> Dict[str, Any]:
    cfg = load_config()
    client = JumpServerClient(cfg)
    profile = client.authenticate(force_refresh=force_refresh, manual_otp=otp_code)
    return {
        "status": "AUTHENTICATED",
        "jms_url": client.base_url,
        "detected_api_version": client.detected_version or "v3",
        "org_id": client.org_id,
        "user": {
            "id": profile.get("id"),
            "username": profile.get("username"),
            "name": profile.get("name"),
            "email": profile.get("email"),
            "role": profile.get("role_display") or profile.get("role"),
            "mfa_enabled": bool(profile.get("mfa_enabled") or profile.get("mfa_level")),
        },
        "session_cached": SESSION_CACHE_PATH.exists(),
    }


def cmd_auth_otp(code: str) -> Dict[str, Any]:
    cfg = load_config()
    client = JumpServerClient(cfg)
    profile = client. authenticate(manual_otp=code)
    return {
        "status": "MFA_AUTHENTICATED",
        "jms_url": client.base_url,
        "detected_api_version": client.detected_version or "v3",
        "user": {
            "id": profile.get("id"),
            "username": profile.get("username"),
            "name": profile.get("name"),
        },
        "message": "2FA/TOTP verified and session cached successfully.",
    }


def cmd_overview() -> Dict[str, Any]:
    cfg = load_config()
    client = JumpServerClient(cfg)
    profile = client.authenticate()

    assets = [client.normalize_asset(a) for a in client.list_assets_raw(limit=500)]
    users = [client.normalize_user(u) for u in client.list_users_raw(limit=500)]
    perms = [client.normalize_permission(p) for p in client.list_permissions_raw(limit=500)]
    nodes = client.list_nodes_raw(limit=200)

    active_sessions: List[Dict[str, Any]] = []
    try:
        raw_sess = client.get_paginated("/api/v1/terminal/sessions/", params={"is_finished": "false"}, limit=100)
        active_sessions = [
            {
                "id": s.get("id"),
                "user": s.get("user"),
                "asset": s.get("asset"),
                "account": s.get("account") or s.get("system_user"),
                "protocol": s.get("protocol"),
                "remote_addr": s.get("remote_addr"),
                "date_start": s.get("date_start"),
            }
            for s in raw_sess
        ]
    except Exception:
        pass

    return {
        "status": "OK",
        "jms_url": client.base_url,
        "detected_api_version": client.detected_version,
        "org_id": client.org_id,
        "authenticated_as": profile.get("username"),
        "summary": {
            "total_assets": len(assets),
            "active_assets": sum(1 for a in assets if a["is_active"]),
            "total_nodes": len(nodes),
            "total_users": len(users),
            "active_users": sum(1 for u in users if u["is_active"]),
            "users_without_mfa": sum(1 for u in users if u["is_active"] and not u["mfa_enabled"]),
            "total_permission_rules": len(perms),
            "active_permission_rules": sum(1 for p in perms if p["is_active"] and not p["is_expired"]),
            "active_live_sessions": len(active_sessions),
        },
        "active_sessions_preview": active_sessions[:10],
    }


def cmd_orgs_list() -> Dict[str, Any]:
    cfg = load_config()
    client = JumpServerClient(cfg)
    orgs_raw = client.get_paginated("/api/v1/orgs/orgs/", limit=200)
    orgs = [
        {
            "id": str(o.get("id", "")),
            "name": str(o.get("name", "")),
            "is_default": bool(o.get("is_default", False)),
            "comment": str(o.get("comment") or ""),
        }
        for o in orgs_raw
    ]
    return {"status": "OK", "current_org_id": client.org_id, "count": len(orgs), "organizations": orgs}


# -----------------------------------------------------------------------------
# Assets & Nodes Commands
# -----------------------------------------------------------------------------


def cmd_assets_list(search: str = "", node: str = "", limit: int = 200) -> Dict[str, Any]:
    cfg = load_config()
    client = JumpServerClient(cfg)
    params: Dict[str, Any] = {}
    if search:
        params["search"] = search
    if node:
        resolved_node = client.resolve_node(node)
        params["node_id"] = resolved_node.get("id")
    raw_assets = client.get_paginated("/api/v1/assets/assets/", params=params, limit=limit)
    assets = [client.normalize_asset(a) for a in raw_assets]
    return {"status": "OK", "count": len(assets), "assets": assets}


def cmd_asset_inspect(asset_query: str) -> Dict[str, Any]:
    """Inspect a specific asset, its accounts/system-users, and all permission rules granting access to it."""
    cfg = load_config()
    client = JumpServerClient(cfg)
    raw_asset = client.resolve_asset(asset_query)
    norm_asset = client.normalize_asset(raw_asset)
    asset_id = norm_asset["id"]
    asset_name = norm_asset["name"]

    accounts = client.list_accounts_for_asset(asset_id)

    all_perms = [client.normalize_permission(p) for p in client.list_permissions_raw(limit=500)]
    matching_perms = [
        p
        for p in all_perms
        if asset_id in p["asset_ids"]
        or asset_name in p["assets"]
        or any(n in p["nodes"] for n in norm_asset["nodes"])
    ]

    return {
        "status": "OK",
        "asset": norm_asset,
        "available_accounts": accounts,
        "matching_permission_rules_count": len(matching_perms),
        "matching_permission_rules": matching_perms,
    }


def cmd_nodes_list(search: str = "") -> Dict[str, Any]:
    cfg = load_config()
    client = JumpServerClient(cfg)
    raw_nodes = client.list_nodes_raw(search=search, limit=500)
    nodes = [
        {
            "id": str(n.get("id", "")),
            "key": str(n.get("key", "")),
            "value": str(n.get("value") or n.get("name") or ""),
            "full_value": str(n.get("full_value") or n.get("value") or ""),
            "assets_amount": n.get("assets_amount", 0),
        }
        for n in raw_nodes
    ]
    return {"status": "OK", "count": len(nodes), "nodes": nodes}


def cmd_asset_create(
    name: str,
    address: str,
    platform: str = "Linux",
    node: str = "",
    protocol: str = "ssh",
    port: int = 22,
    comment: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """Create/register a new server asset in JumpServer (with duplicate IP/name safety & PREVIEW_ONLY default)."""
    cfg = load_config()
    client = JumpServerClient(cfg)
    client.authenticate()

    # Check if an asset with the same address or name already exists
    existing_by_ip = [
        client.normalize_asset(a)
        for a in client.list_assets_raw(search=address, limit=50)
        if str(a.get("address") or a.get("ip") or "") == address
        or str(a.get("name") or a.get("hostname") or "").lower() == name.lower()
    ]
    if existing_by_ip:
        return {
            "status": "ALREADY_EXISTS",
            "message": f"An asset with name '{name}' or IP '{address}' already exists in JumpServer.",
            "existing_assets": existing_by_ip,
        }

    target_node = None
    if node:
        target_node = client.resolve_node(node)
    else:
        nodes = client.list_nodes_raw(limit=20)
        if nodes:
            target_node = nodes[0]

    plan = {
        "operation": "CREATE_ASSET",
        "name": name,
        "address": address,
        "platform": platform,
        "protocol": protocol,
        "port": port,
        "node": {
            "id": target_node.get("id") if target_node else None,
            "full_value": target_node.get("full_value") or target_node.get("value") if target_node else "/Default",
        },
        "comment": comment,
        "detected_api_version": client.detected_version,
    }

    if not confirm:
        return {
            "status": "PREVIEW_ONLY",
            "message": "Preview of new JumpServer asset creation. Ask user for confirmation before re-running with confirm=true (--confirm).",
            "plan": plan,
        }

    node_ids = [target_node["id"]] if target_node and target_node.get("id") else []
    if client.is_v3_or_v4:
        # Resolve platform ID in v3/v4
        plat_id = 1 if platform.lower() != "windows" else 5
        try:
            plats = client.get_paginated("/api/v1/assets/platforms/", params={"search": platform}, limit=20)
            for p in plats:
                if str(p.get("name", "")).lower() == platform.lower():
                    plat_id = p.get("id", plat_id)
                    break
        except Exception:
            pass

        payload: Dict[str, Any] = {
            "name": name,
            "address": address,
            "platform": {"pk": plat_id, "id": plat_id, "name": platform},
            "protocols": [{"name": protocol.lower(), "port": int(port)}],
            "nodes": node_ids,
            "is_active": True,
            "comment": comment,
        }
        endpoint = "/api/v1/assets/hosts/"
        try:
            created = client.request("POST", endpoint, json_body=payload)
        except JumpServerError:
            created = client.request("POST", "/api/v1/assets/assets/", json_body=payload)
    else:
        payload = {
            "hostname": name,
            "ip": address,
            "platform": platform,
            "protocol": protocol.lower(),
            "port": int(port),
            "nodes": node_ids,
            "is_active": True,
            "comment": comment,
        }
        created = client.request("POST", "/api/v1/assets/assets/", json_body=payload)

    norm_created = client.normalize_asset(created)
    write_audit_log("asset_create", {"asset": norm_created})
    return {"status": "CREATED", "asset": norm_created}


def cmd_asset_delete(asset_query: str, confirm: bool = False) -> Dict[str, Any]:
    cfg = load_config()
    client = JumpServerClient(cfg)
    raw_asset = client.resolve_asset(asset_query)
    norm_asset = client.normalize_asset(raw_asset)

    if not confirm:
        return {
            "status": "PREVIEW_ONLY",
            "operation": "DELETE_ASSET",
            "message": "Preview of asset deletion. Confirm with user before running with --confirm.",
            "target_asset": norm_asset,
        }

    client.request("DELETE", f"/api/v1/assets/assets/{norm_asset['id']}/")
    write_audit_log("asset_delete", {"asset": norm_asset})
    return {"status": "DELETED", "deleted_asset": norm_asset}


# -----------------------------------------------------------------------------
# Users & User Groups Commands
# -----------------------------------------------------------------------------


def cmd_users_list(search: str = "", group: str = "", limit: int = 200) -> Dict[str, Any]:
    cfg = load_config()
    client = JumpServerClient(cfg)
    params: Dict[str, Any] = {}
    if search:
        params["search"] = search
    if group:
        g = client.resolve_user_group(group)
        params["group_id"] = g.get("id")
    raw_users = client.get_paginated("/api/v1/users/users/", params=params, limit=limit)
    users = [client.normalize_user(u) for u in raw_users]
    return {"status": "OK", "count": len(users), "users": users}


def cmd_user_groups_list(search: str = "") -> Dict[str, Any]:
    cfg = load_config()
    client = JumpServerClient(cfg)
    raw_groups = client.list_user_groups_raw(search=search, limit=200)
    groups = [
        {
            "id": str(g.get("id", "")),
            "name": str(g.get("name", "")),
            "users_amount": g.get("users_amount", len(g.get("users", []))),
            "comment": str(g.get("comment") or ""),
        }
        for g in raw_groups
    ]
    return {"status": "OK", "count": len(groups), "user_groups": groups}


def cmd_user_action(
    user_query: str = "",
    action: str = "inspect",
    username: str = "",
    name: str = "",
    email: str = "",
    group: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """
    Perform user management actions:
    - inspect: Show user details and all permission rules affecting them
    - enable / disable: Toggle user active state
    - add-to-group / remove-from-group: Manage group membership
    - create: Create a new JumpServer user
    """
    cfg = load_config()
    client = JumpServerClient(cfg)
    action = action.lower().strip()

    if action == "create":
        if not username or not email:
            raise JumpServerError("Creating a user requires --username and --email.", code="MISSING_USER_FIELDS")
        display_name = name or username
        target_group = client.resolve_user_group(group) if group else None
        plan = {
            "operation": "CREATE_USER",
            "username": username,
            "name": display_name,
            "email": email,
            "group": {"id": target_group.get("id"), "name": target_group.get("name")} if target_group else None,
        }
        if not confirm:
            return {
                "status": "PREVIEW_ONLY",
                "message": "Preview of JumpServer user creation. Ask user for confirmation before running with --confirm.",
                "plan": plan,
            }
        payload: Dict[str, Any] = {
            "username": username,
            "name": display_name,
            "email": email,
            "is_active": True,
        }
        if target_group and target_group.get("id"):
            payload["groups"] = [target_group["id"]]
        created = client.request("POST", "/api/v1/users/users/", json_body=payload)
        norm_u = client.normalize_user(created)
        write_audit_log("user_create", {"user": norm_u})
        return {"status": "CREATED", "user": norm_u}

    raw_user = client.resolve_user(user_query or username)
    norm_user = client.normalize_user(raw_user)
    uid = norm_user["id"]

    if action == "inspect":
        all_perms = [client.normalize_permission(p) for p in client.list_permissions_raw(limit=500)]
        matching_perms = [
            p
            for p in all_perms
            if uid in p["user_ids"]
            or norm_user["username"] in p["users"]
            or norm_user["name"] in p["users"]
            or any(g in p["user_groups"] for g in norm_user["groups"])
        ]
        return {
            "status": "OK",
            "user": norm_user,
            "matching_permission_rules_count": len(matching_perms),
            "matching_permission_rules": matching_perms,
        }

    if action in ("enable", "disable"):
        desired_active = action == "enable"
        if not confirm:
            return {
                "status": "PREVIEW_ONLY",
                "operation": f"{action.upper()}_USER",
                "user": norm_user,
                "current_is_active": norm_user["is_active"],
                "desired_is_active": desired_active,
            }
        updated = client.request("PATCH", f"/api/v1/users/users/{uid}/", json_body={"is_active": desired_active})
        norm_updated = client.normalize_user(updated)
        write_audit_log(f"user_{action}", {"user": norm_updated})
        return {"status": "UPDATED", "user": norm_updated}

    if action in ("add-to-group", "remove-from-group"):
        if not group:
            raise JumpServerError(f"Action '{action}' requires --group.", code="MISSING_GROUP")
        target_group = client.resolve_user_group(group)
        gid = str(target_group.get("id"))
        gname = str(target_group.get("name"))
        current_group_ids = [
            str(g.get("id") if isinstance(g, dict) else g) for g in (raw_user.get("groups") or [])
        ]
        if action == "add-to-group":
            new_group_ids = list(dict.fromkeys(current_group_ids + [gid]))
        else:
            new_group_ids = [x for x in current_group_ids if x != gid]

        if not confirm:
            return {
                "status": "PREVIEW_ONLY",
                "operation": action.upper(),
                "user": norm_user,
                "target_group": {"id": gid, "name": gname},
            }
        updated = client.request("PATCH", f"/api/v1/users/users/{uid}/", json_body={"groups": new_group_ids})
        norm_updated = client.normalize_user(updated)
        write_audit_log(f"user_{action}", {"user": norm_updated, "group": {"id": gid, "name": gname}})
        return {"status": "UPDATED", "user": norm_updated, "group": {"id": gid, "name": gname}}

    raise JumpServerError(
        f"Unsupported user action '{action}'. Valid actions: inspect, enable, disable, add-to-group, remove-from-group, create.",
        code="INVALID_ACTION",
    )


# -----------------------------------------------------------------------------
# Permissions & Access Verification Commands
# -----------------------------------------------------------------------------


def cmd_permissions_list(search: str = "", user: str = "", asset: str = "", limit: int = 200) -> Dict[str, Any]:
    cfg = load_config()
    client = JumpServerClient(cfg)
    params: Dict[str, Any] = {}
    if search:
        params["search"] = search
    if user:
        u = client.resolve_user(user)
        params["user_id"] = u.get("id")
    if asset:
        a = client.resolve_asset(asset)
        params["asset_id"] = a.get("id")

    raw_perms = client.get_paginated("/api/v1/perms/asset-permissions/", params=params, limit=limit)
    perms = [client.normalize_permission(p) for p in raw_perms]
    return {"status": "OK", "count": len(perms), "permissions": perms}


def cmd_check_access(user_query: str, asset_query: str) -> Dict[str, Any]:
    """Check whether a specific User has access to a specific Asset, and via which Permission Rules & Accounts."""
    cfg = load_config()
    client = JumpServerClient(cfg)
    raw_user = client.resolve_user(user_query)
    raw_asset = client.resolve_asset(asset_query)
    norm_user = client.normalize_user(raw_user)
    norm_asset = client.normalize_asset(raw_asset)

    all_perms = [client.normalize_permission(p) for p in client.list_permissions_raw(limit=500)]
    matching_rules: List[Dict[str, Any]] = []
    for p in all_perms:
        user_match = (
            norm_user["id"] in p["user_ids"]
            or norm_user["username"] in p["users"]
            or norm_user["name"] in p["users"]
            or any(g in p["user_groups"] for g in norm_user["groups"])
        )
        asset_match = (
            norm_asset["id"] in p["asset_ids"]
            or norm_asset["name"] in p["assets"]
            or any(n in p["nodes"] for n in norm_asset["nodes"])
        )
        if user_match and asset_match:
            matching_rules.append(p)

    active_rules = [r for r in matching_rules if r["is_active"] and not r["is_expired"]]
    effective_accounts = sorted({acc for r in active_rules for acc in r["accounts"]})
    effective_actions = sorted({act for r in active_rules for act in r["actions"]})

    return {
        "status": "OK",
        "has_access": bool(active_rules and norm_user["is_active"] and norm_asset["is_active"]),
        "user": norm_user,
        "asset": norm_asset,
        "effective_accounts": effective_accounts,
        "effective_actions": effective_actions,
        "active_matching_rules_count": len(active_rules),
        "matching_rules": matching_rules,
    }


def _compute_expiry_iso(days: Optional[int] = None, hours: Optional[int] = None, date_expired: str = "") -> str:
    if date_expired:
        return date_expired
    now = datetime.datetime.now(datetime.timezone.utc)
    if hours and hours > 0:
        exp = now + datetime.timedelta(hours=hours)
        return exp.strftime("%Y-%m-%dT%H:%M:%SZ")
    if days and days > 0:
        exp = now + datetime.timedelta(days=days)
        return exp.strftime("%Y-%m-%dT%H:%M:%SZ")
    # Default JumpServer long-term expiry (70 years)
    exp = now + datetime.timedelta(days=365 * 70)
    return exp.strftime("%Y-%m-%dT%H:%M:%SZ")


def cmd_permission_grant(
    user_query: str = "",
    user_group_query: str = "",
    asset_query: str = "",
    node_query: str = "",
    accounts: str = "@ALL",
    actions: str = "connect",
    rule_name: str = "",
    days: Optional[int] = None,
    hours: Optional[int] = None,
    date_expired: str = "",
    comment: str = "",
    confirm: bool = False,
) -> Dict[str, Any]:
    """
    Grant a User (or User Group) access to an Asset (or Node) via an existing or new AssetPermission rule.
    Runs in PREVIEW_ONLY mode when confirm=False, showing available accounts on the target asset and existing rules.
    """
    cfg = load_config()
    client = JumpServerClient(cfg)
    client.authenticate()

    if not user_query and not user_group_query:
        raise JumpServerError("Specify at least --user or --user-group.", code="MISSING_PRINCIPAL")
    if not asset_query and not node_query:
        raise JumpServerError("Specify at least --asset or --node.", code="MISSING_TARGET")

    resolved_user = client.normalize_user(client.resolve_user(user_query)) if user_query else None
    resolved_group = client.resolve_user_group(user_group_query) if user_group_query else None
    resolved_asset = client.normalize_asset(client.resolve_asset(asset_query)) if asset_query else None
    resolved_node = client.resolve_node(node_query) if node_query else None

    available_accounts: List[Dict[str, Any]] = []
    if resolved_asset:
        available_accounts = client.list_accounts_for_asset(resolved_asset["id"])

    requested_accounts = [a.strip() for a in accounts.split(",") if a.strip()] if accounts else ["@ALL"]
    actions_key = actions.strip().lower()
    resolved_actions = ACTION_ALIASES_V3.get(
        actions_key, [a.strip().lower() for a in actions.split(",") if a.strip()]
    )
    expiry_iso = _compute_expiry_iso(days=days, hours=hours, date_expired=date_expired)

    existing_rule = None
    if rule_name:
        try:
            existing_rule = client.resolve_permission(rule_name)
        except JumpServerError as exc:
            if exc.code != "PERMISSION_NOT_FOUND":
                raise

    auto_rule_name = rule_name
    if not auto_rule_name:
        who = resolved_user["username"] if resolved_user else str(resolved_group.get("name"))
        where = resolved_asset["name"] if resolved_asset else str(resolved_node.get("value"))
        auto_rule_name = f"perm-{who}-{where}"

    plan = {
        "operation": "UPDATE_EXISTING_PERMISSION_RULE" if existing_rule else "CREATE_NEW_PERMISSION_RULE",
        "rule_name": existing_rule.get("name") if existing_rule else auto_rule_name,
        "existing_rule_id": existing_rule.get("id") if existing_rule else None,
        "user": resolved_user,
        "user_group": {"id": resolved_group.get("id"), "name": resolved_group.get("name")} if resolved_group else None,
        "asset": resolved_asset,
        "node": {
            "id": resolved_node.get("id"),
            "full_value": resolved_node.get("full_value") or resolved_node.get("value"),
        }
        if resolved_node
        else None,
        "accounts": requested_accounts,
        "available_accounts_on_asset": available_accounts,
        "actions": resolved_actions,
        "date_expired": expiry_iso,
        "detected_api_version": client.detected_version,
    }

    if not confirm:
        return {
            "status": "PREVIEW_ONLY",
            "message": (
                "Preview of JumpServer permission grant. Please confirm with the user which account(s) "
                "(e.g., root, ubuntu, @ALL, @SPEC), allowed actions (connect, upload, download, copy, paste), "
                "and expiration time they want, then re-run with confirm=true (--confirm)."
            ),
            "plan": plan,
        }

    # Build payload for existing rule update or new rule creation
    if existing_rule:
        rule_id = str(existing_rule["id"])
        norm_existing = client.normalize_permission(existing_rule)
        user_ids = list(dict.fromkeys(norm_existing["user_ids"] + ([resolved_user["id"]] if resolved_user else [])))
        group_ids = list(
            dict.fromkeys(norm_existing["user_group_ids"] + ([str(resolved_group["id"])] if resolved_group else []))
        )
        asset_ids = list(dict.fromkeys(norm_existing["asset_ids"] + ([resolved_asset["id"]] if resolved_asset else [])))
        node_ids = list(
            dict.fromkeys(norm_existing["node_ids"] + ([str(resolved_node["id"])] if resolved_node else []))
        )
        merged_accounts = list(dict.fromkeys(norm_existing["accounts"] + requested_accounts))

        patch_body: Dict[str, Any] = {
            "users": user_ids,
            "user_groups": group_ids,
            "assets": asset_ids,
            "nodes": node_ids,
        }
        if client.is_v3_or_v4:
            patch_body["accounts"] = merged_accounts
            patch_body["actions"] = resolved_actions
        if days or hours or date_expired:
            patch_body["date_expired"] = expiry_iso

        updated = client.request("PATCH", f"/api/v1/perms/asset-permissions/{rule_id}/", json_body=patch_body)
        norm_res = client.normalize_permission(updated)
        write_audit_log("permission_grant_update", {"permission": norm_res})
        return {"status": "GRANTED_UPDATED_RULE", "permission": norm_res}

    # Create new rule
    create_body: Dict[str, Any] = {
        "name": auto_rule_name,
        "users": [resolved_user["id"]] if resolved_user else [],
        "user_groups": [str(resolved_group["id"])] if resolved_group else [],
        "assets": [resolved_asset["id"]] if resolved_asset else [],
        "nodes": [str(resolved_node["id"])] if resolved_node else [],
        "is_active": True,
        "date_expired": expiry_iso,
        "comment": comment or "Granted via AiJumpOps Copilot",
    }
    if client.is_v3_or_v4:
        # In JumpServer v3/v4, if specific accounts are given without @SPEC, include @SPEC automatically
        final_accs = list(requested_accounts)
        has_specific = any(not a.startswith("@") for a in final_accs)
        if has_specific and "@SPEC" not in final_accs and "@ALL" not in final_accs:
            final_accs.insert(0, "@SPEC")
        create_body["accounts"] = final_accs
        create_body["actions"] = resolved_actions
    else:
        # JumpServer v2 uses system_users UUIDs
        sys_users = client.list_accounts_for_asset("")
        matched_sys_ids = [
            s["id"]
            for s in sys_users
            if s["name"] in requested_accounts or s["username"] in requested_accounts or "@ALL" in requested_accounts
        ]
        create_body["system_users"] = matched_sys_ids

    created = client.request("POST", "/api/v1/perms/asset-permissions/", json_body=create_body)
    norm_created = client.normalize_permission(created)
    write_audit_log("permission_grant_create", {"permission": norm_created})
    return {"status": "GRANTED_NEW_RULE", "permission": norm_created}


def cmd_permission_revoke(
    rule_query: str = "",
    user_query: str = "",
    asset_query: str = "",
    delete_entire_rule: bool = False,
    confirm: bool = False,
) -> Dict[str, Any]:
    """
    Revoke access either by:
    1. Deleting an entire AssetPermission rule (`--rule <id_or_name> --delete-rule`)
    2. Removing a specific User and/or Asset from matching AssetPermission rule(s).
    Always runs in PREVIEW_ONLY mode unless confirm=True.
    """
    cfg = load_config()
    client = JumpServerClient(cfg)
    client.authenticate()

    if rule_query and delete_entire_rule:
        raw_rule = client.resolve_permission(rule_query)
        norm_rule = client.normalize_permission(raw_rule)
        if not confirm:
            return {
                "status": "PREVIEW_ONLY",
                "operation": "DELETE_ENTIRE_PERMISSION_RULE",
                "message": "Preview of deleting the entire AssetPermission rule. Ask user for confirmation first.",
                "target_rule": norm_rule,
            }
        client.request("DELETE", f"/api/v1/perms/asset-permissions/{norm_rule['id']}/")
        write_audit_log("permission_delete_rule", {"deleted_rule": norm_rule})
        return {"status": "DELETED_RULE", "deleted_rule": norm_rule}

    resolved_user = client.normalize_user(client.resolve_user(user_query)) if user_query else None
    resolved_asset = client.normalize_asset(client.resolve_asset(asset_query)) if asset_query else None

    if rule_query:
        target_rules = [client.resolve_permission(rule_query)]
    else:
        if not resolved_user and not resolved_asset:
            raise JumpServerError(
                "Specify --rule, or at least --user and/or --asset to revoke access.",
                code="MISSING_REVOKE_PARAMETERS",
            )
        all_raw = client.list_permissions_raw(limit=500)
        target_rules = []
        for raw_p in all_raw:
            norm_p = client.normalize_permission(raw_p)
            u_ok = (
                True
                if not resolved_user
                else (
                    resolved_user["id"] in norm_p["user_ids"]
                    or resolved_user["username"] in norm_p["users"]
                    or resolved_user["name"] in norm_p["users"]
                )
            )
            a_ok = (
                True
                if not resolved_asset
                else (resolved_asset["id"] in norm_p["asset_ids"] or resolved_asset["name"] in norm_p["assets"])
            )
            if u_ok and a_ok:
                target_rules.append(raw_p)

    if not target_rules:
        return {
            "status": "NO_MATCHING_RULES",
            "message": "No direct AssetPermission rules matched the specified user/asset.",
            "user": resolved_user,
            "asset": resolved_asset,
        }

    normalized_targets = [client.normalize_permission(r) for r in target_rules]
    if not confirm:
        return {
            "status": "PREVIEW_ONLY",
            "operation": "REVOKE_ACCESS",
            "message": "Preview of permission revocation. Confirm with user before re-running with confirm=true (--confirm).",
            "user_to_revoke": resolved_user,
            "asset_to_revoke": resolved_asset,
            "affected_rules_count": len(normalized_targets),
            "affected_rules": normalized_targets,
        }

    results: List[Dict[str, Any]] = []
    for raw_r in target_rules:
        norm_r = client.normalize_permission(raw_r)
        rid = norm_r["id"]
        new_users = list(norm_r["user_ids"])
        new_assets = list(norm_r["asset_ids"])

        if resolved_user and resolved_user["id"] in new_users:
            new_users = [u for u in new_users if u != resolved_user["id"]]
        if resolved_asset and resolved_asset["id"] in new_assets:
            new_assets = [a for a in new_assets if a != resolved_asset["id"]]

        # If a rule has no remaining users/user_groups or no remaining assets/nodes, delete the empty rule
        no_principals = len(new_users) == 0 and len(norm_r["user_group_ids"]) == 0
        no_targets = len(new_assets) == 0 and len(norm_r["node_ids"]) == 0
        if no_principals or no_targets:
            client.request("DELETE", f"/api/v1/perms/asset-permissions/{rid}/")
            results.append({"rule_id": rid, "rule_name": norm_r["name"], "action": "DELETED_EMPTY_RULE"})
        else:
            updated = client.request(
                "PATCH",
                f"/api/v1/perms/asset-permissions/{rid}/",
                json_body={"users": new_users, "assets": new_assets},
            )
            results.append(
                {
                    "rule_id": rid,
                    "rule_name": norm_r["name"],
                    "action": "UPDATED_RULE",
                    "permission": client.normalize_permission(updated),
                }
            )

    write_audit_log(
        "permission_revoke",
        {"user": resolved_user, "asset": resolved_asset, "results": results},
    )
    return {"status": "REVOKED", "results": results}


# -----------------------------------------------------------------------------
# Live Terminal Sessions, Command Audit Logs & Login Logs
# -----------------------------------------------------------------------------


def cmd_sessions_active(user: str = "", asset: str = "", limit: int = 100) -> Dict[str, Any]:
    cfg = load_config()
    client = JumpServerClient(cfg)
    params: Dict[str, Any] = {"is_finished": "false"}
    if user:
        params["user"] = user
    if asset:
        params["asset"] = asset
    raw_sess = client.get_paginated("/api/v1/terminal/sessions/", params=params, limit=limit)
    sessions = [
        {
            "id": str(s.get("id", "")),
            "user": str(s.get("user") or ""),
            "asset": str(s.get("asset") or ""),
            "account": str(s.get("account") or s.get("system_user") or ""),
            "protocol": str(s.get("protocol") or ""),
            "login_from": str(
                s.get("login_from", {}).get("label")
                if isinstance(s.get("login_from"), dict)
                else (s.get("login_from_display") or s.get("login_from") or "")
            ),
            "remote_addr": str(s.get("remote_addr") or ""),
            "date_start": str(s.get("date_start") or ""),
            "terminal": str(
                s.get("terminal", {}).get("name")
                if isinstance(s.get("terminal"), dict)
                else (s.get("terminal_display") or "")
            ),
        }
        for s in raw_sess
    ]
    return {"status": "OK", "active_sessions_count": len(sessions), "active_sessions": sessions}


def cmd_session_terminate(session_id: str, confirm: bool = False) -> Dict[str, Any]:
    """Terminate/kill an active terminal session on JumpServer (PREVIEW_ONLY first)."""
    cfg = load_config()
    client = JumpServerClient(cfg)
    sid = session_id.strip()
    if not sid:
        raise JumpServerError("Session ID is required.", code="MISSING_SESSION_ID")

    sess_info = client.request("GET", f"/api/v1/terminal/sessions/{sid}/")
    summary = {
        "id": str(sess_info.get("id", sid)),
        "user": sess_info.get("user"),
        "asset": sess_info.get("asset"),
        "account": sess_info.get("account") or sess_info.get("system_user"),
        "protocol": sess_info.get("protocol"),
        "remote_addr": sess_info.get("remote_addr"),
        "date_start": sess_info.get("date_start"),
        "is_finished": sess_info.get("is_finished"),
    }

    if not confirm:
        return {
            "status": "PREVIEW_ONLY",
            "operation": "TERMINATE_LIVE_SESSION",
            "message": "Preview of live terminal session termination. Confirm with user before running with --confirm.",
            "target_session": summary,
        }

    task_resp = client.request(
        "POST",
        "/api/v1/terminal/tasks/kill-session/",
        json_body={"session": sid, "sessions": [sid]},
    )
    write_audit_log("session_terminate", {"session": summary, "response": task_resp})
    return {"status": "TERMINATED", "session": summary, "task": task_resp}


def cmd_audit_logs(
    log_type: str = "commands",
    user: str = "",
    asset: str = "",
    search: str = "",
    days: int = 7,
    limit: int = 100,
) -> Dict[str, Any]:
    """
    Query JumpServer audit logs:
    - commands: Executed shell commands in terminal sessions (`/api/v1/terminal/commands/`)
    - logins: User login audit logs (`/api/v1/audits/login-logs/`)
    - sessions: Historical terminal sessions (`/api/v1/terminal/sessions/`)
    - operations: Admin operation logs (`/api/v1/audits/operate-logs/`)
    """
    cfg = load_config()
    client = JumpServerClient(cfg)
    lt = log_type.strip().lower()
    now = datetime.datetime.now(datetime.timezone.utc)
    date_from = (now - datetime.timedelta(days=max(days, 1))).strftime("%Y-%m-%dT%H:%M:%SZ")

    params: Dict[str, Any] = {"date_from": date_from, "date_to": now.strftime("%Y-%m-%dT%H:%M:%SZ")}
    if search:
        params["search"] = search
    if user:
        params["user"] = user
    if asset:
        params["asset"] = asset

    if lt in ("commands", "command", "cmd"):
        raw_cmds = client.get_paginated("/api/v1/terminal/commands/", params=params, limit=limit)
        records = [
            {
                "id": c.get("id"),
                "user": c.get("user"),
                "asset": c.get("asset"),
                "account": c.get("account") or c.get("system_user"),
                "input": c.get("input"),
                "risk_level": c.get("risk_level_display") or c.get("risk_level"),
                "session": c.get("session"),
                "timestamp": c.get("timestamp_display") or c.get("timestamp"),
            }
            for c in raw_cmds
        ]
        return {"status": "OK", "log_type": "commands", "count": len(records), "records": records}

    if lt in ("logins", "login"):
        if user:
            params["username"] = user
        raw_logins = client.get_paginated("/api/v1/audits/login-logs/", params=params, limit=limit)
        records = [
            {
                "id": l.get("id"),
                "username": l.get("username"),
                "type": l.get("type"),
                "ip": l.get("ip"),
                "city": l.get("city"),
                "mfa": l.get("mfa"),
                "status": l.get("status"),
                "reason": l.get("reason_display") or l.get("reason"),
                "datetime": l.get("datetime"),
            }
            for l in raw_logins
        ]
        return {"status": "OK", "log_type": "logins", "count": len(records), "records": records}

    if lt in ("operations", "operate", "admin"):
        raw_ops = client.get_paginated("/api/v1/audits/operate-logs/", params=params, limit=limit)
        records = [
            {
                "id": o.get("id"),
                "user": o.get("user"),
                "action": o.get("action_display") or o.get("action"),
                "resource_type": o.get("resource_type_display") or o.get("resource_type"),
                "resource": o.get("resource"),
                "remote_addr": o.get("remote_addr"),
                "datetime": o.get("datetime"),
            }
            for o in raw_ops
        ]
        return {"status": "OK", "log_type": "operations", "count": len(records), "records": records}

    if lt in ("sessions", "session"):
        raw_sess = client.get_paginated("/api/v1/terminal/sessions/", params=params, limit=limit)
        records = [
            {
                "id": s.get("id"),
                "user": s.get("user"),
                "asset": s.get("asset"),
                "account": s.get("account") or s.get("system_user"),
                "protocol": s.get("protocol"),
                "remote_addr": s.get("remote_addr"),
                "is_finished": s.get("is_finished"),
                "date_start": s.get("date_start"),
                "date_end": s.get("date_end"),
            }
            for s in raw_sess
        ]
        return {"status": "OK", "log_type": "sessions", "count": len(records), "records": records}

    raise JumpServerError(
        f"Unsupported log_type '{log_type}'. Valid types: commands, logins, sessions, operations.",
        code="INVALID_LOG_TYPE",
    )


# -----------------------------------------------------------------------------
# AI Security Auditor (`jmsctl security-audit`)
# -----------------------------------------------------------------------------


def cmd_security_audit() -> Dict[str, Any]:
    """
    AI Security Auditor for JumpServer:
    Scans users, permission rules, and assets for:
    1. CRITICAL: Active users without 2FA/MFA enabled (especially Admin roles)
    2. CRITICAL/HIGH: Overly broad AssetPermission rules (granting `@ALL` accounts or `root` across Root Nodes / many assets without near-term expiration)
    3. MEDIUM: Expired or empty AssetPermission rules cluttering policy
    4. MEDIUM: Orphaned active assets with zero permission rules attached
    5. LOW: Inactive users who have never logged in or haven't logged in for >60 days
    """
    cfg = load_config()
    client = JumpServerClient(cfg)
    client.authenticate()

    users = [client.normalize_user(u) for u in client.list_users_raw(limit=500)]
    assets = [client.normalize_asset(a) for a in client.list_assets_raw(limit=500)]
    perms = [client.normalize_permission(p) for p in client.list_permissions_raw(limit=500)]

    findings: List[Dict[str, Any]] = []

    # 1. Users without MFA
    for u in users:
        if u["is_active"] and not u["mfa_enabled"]:
            is_admin = "admin" in u["role"].lower()
            findings.append(
                {
                    "severity": "CRITICAL" if is_admin else "HIGH",
                    "category": "USER_WITHOUT_MFA",
                    "resource": f"user:{u['username']} ({u['name']})",
                    "role": u["role"],
                    "description": f"Active {'Admin ' if is_admin else ''}user '{u['username']}' does not have 2FA/MFA enabled.",
                    "remediation": "Enforce MFA on this user account in JumpServer User settings.",
                }
            )

    # 2. Overly broad or expired permission rules
    covered_asset_ids = set()
    covered_nodes = set()
    for p in perms:
        for aid in p["asset_ids"]:
            covered_asset_ids.add(aid)
        for nd in p["nodes"]:
            covered_nodes.add(nd)

        if p["is_expired"]:
            findings.append(
                {
                    "severity": "MEDIUM",
                    "category": "EXPIRED_PERMISSION_RULE",
                    "resource": f"permission:{p['name']} ({p['id']})",
                    "description": f"Permission rule '{p['name']}' expired on {p['date_expired']} and is still present.",
                    "remediation": f"Clean up or extend rule via `./jmsctl perms revoke --rule \"{p['id']}\" --delete-rule --confirm`.",
                }
            )
            continue

        if not p["is_active"]:
            continue

        has_privileged_acc = any(
            acc.lower() in ("@all", "root", "administrator") for acc in p["accounts"]
        )
        has_root_node = any(n in ("/Default", "Default", "/") for n in p["nodes"])
        many_assets = len(p["asset_ids"]) >= 10 or has_root_node
        if has_privileged_acc and many_assets:
            findings.append(
                {
                    "severity": "CRITICAL" if "@ALL" in p["accounts"] or "root" in p["accounts"] else "HIGH",
                    "category": "OVERPRIVILEGED_PERMISSION_RULE",
                    "resource": f"permission:{p['name']} ({p['id']})",
                    "accounts": p["accounts"],
                    "users": p["users"],
                    "user_groups": p["user_groups"],
                    "nodes": p["nodes"],
                    "assets_count": len(p["asset_ids"]),
                    "description": (
                        f"Permission rule '{p['name']}' grants privileged account access ({', '.join(p['accounts'])}) "
                        f"across {'root/broad nodes ' + str(p['nodes']) if has_root_node else str(len(p['asset_ids'])) + ' assets'}."
                    ),
                    "remediation": "Scope permission rule down to specific non-root accounts and least-privilege asset nodes.",
                }
            )

        if not p["users"] and not p["user_groups"]:
            findings.append(
                {
                    "severity": "LOW",
                    "category": "EMPTY_PERMISSION_RULE",
                    "resource": f"permission:{p['name']} ({p['id']})",
                    "description": f"Permission rule '{p['name']}' has no users or user groups assigned.",
                    "remediation": f"Delete unused rule via `./jmsctl perms revoke --rule \"{p['id']}\" --delete-rule --confirm`.",
                }
            )

    # 3. Unassigned / Orphaned Assets
    if not covered_nodes:
        for a in assets:
            if a["is_active"] and a["id"] not in covered_asset_ids:
                findings.append(
                    {
                        "severity": "LOW",
                        "category": "UNASSIGNED_ASSET",
                        "resource": f"asset:{a['name']} ({a['address']})",
                        "description": f"Active asset '{a['name']}' ({a['address']}) is not referenced by any permission rule.",
                        "remediation": "Assign to an authorization rule or deactivate if decommissioned.",
                    }
                )

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 99))

    summary_counts = {
        "CRITICAL": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "HIGH": sum(1 for f in findings if f["severity"] == "HIGH"),
        "MEDIUM": sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "LOW": sum(1 for f in findings if f["severity"] == "LOW"),
        "total_findings": len(findings),
    }

    return {
        "status": "OK",
        "jms_url": client.base_url,
        "summary": summary_counts,
        "findings": findings,
    }


# -----------------------------------------------------------------------------
# Snapshot Backups & 1-Click Revert (`backup`, `backups`, `revert`)
# -----------------------------------------------------------------------------


def cmd_backup(label: str = "before_changes") -> Dict[str, Any]:
    """
    Create a full JSON snapshot backup of all JumpServer AssetPermission rules,
    User Groups, Users (active state & group memberships), and Assets.
    """
    cfg = load_config()
    client = JumpServerClient(cfg)
    client.authenticate()

    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "_", label.strip() or "snapshot")
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"jms_backup_{ts}_{safe_label}.json"
    filepath = BACKUPS_DIR / filename

    raw_perms = client.list_permissions_raw(limit=1000)
    raw_users = client.list_users_raw(limit=1000)
    raw_groups = client.list_user_groups_raw(limit=500)
    raw_assets = client.list_assets_raw(limit=1000)

    snapshot = {
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "label": label,
            "jms_url": client.base_url,
            "org_id": client.org_id,
            "detected_api_version": client.detected_version,
        },
        "permissions_raw": raw_perms,
        "permissions_normalized": [client.normalize_permission(p) for p in raw_perms],
        "users_snapshot": [
            {
                "id": str(u.get("id", "")),
                "username": u.get("username"),
                "name": u.get("name"),
                "is_active": bool(u.get("is_active", True)),
                "groups": [str(g.get("id") if isinstance(g, dict) else g) for g in (u.get("groups") or [])],
            }
            for u in raw_users
        ],
        "user_groups_count": len(raw_groups),
        "assets_count": len(raw_assets),
    }

    filepath.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
    os.chmod(filepath, 0o600)
    write_audit_log("backup_created", {"file": str(filepath), "permissions_count": len(raw_perms)})

    return {
        "status": "BACKUP_CREATED",
        "file": str(filepath),
        "filename": filename,
        "summary": {
            "permission_rules_backed_up": len(raw_perms),
            "users_backed_up": len(raw_users),
            "user_groups_counted": len(raw_groups),
            "assets_counted": len(raw_assets),
        },
    }


def cmd_backups_list() -> Dict[str, Any]:
    if not BACKUPS_DIR.exists():
        return {"status": "OK", "count": 0, "backups": []}
    files = sorted(BACKUPS_DIR.glob("jms_backup_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    items: List[Dict[str, Any]] = []
    for f in files[:50]:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            meta = data.get("metadata", {})
            items.append(
                {
                    "filename": f.name,
                    "path": str(f),
                    "timestamp": meta.get("timestamp"),
                    "label": meta.get("label"),
                    "jms_url": meta.get("jms_url"),
                    "permission_rules_count": len(data.get("permissions_raw", [])),
                }
            )
        except Exception:
            pass
    return {"status": "OK", "count": len(items), "backups": items}


def cmd_revert(backup_file: str = "", confirm: bool = False) -> Dict[str, Any]:
    """
    Revert JumpServer AssetPermission rules and User active/group states back to a saved snapshot.
    Always runs in PREVIEW_ONLY mode when confirm=False, computing the exact diff first!
    """
    cfg = load_config()
    client = JumpServerClient(cfg)
    client.authenticate()

    if backup_file:
        bp = Path(backup_file)
        if not bp.exists():
            bp = BACKUPS_DIR / backup_file
        if not bp.exists():
            raise JumpServerError(f"Backup file '{backup_file}' not found.", code="BACKUP_NOT_FOUND")
    else:
        if not BACKUPS_DIR.exists():
            raise JumpServerError("No backups directory found. Run `./jmsctl backup` first.", code="NO_BACKUPS")
        files = sorted(BACKUPS_DIR.glob("jms_backup_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        if not files:
            raise JumpServerError("No backup files found.", code="NO_BACKUPS")
        bp = files[0]

    snapshot = json.loads(bp.read_text(encoding="utf-8"))
    snap_perms_norm = snapshot.get("permissions_normalized", [])
    snap_by_id = {p["id"]: p for p in snap_perms_norm if p.get("id")}

    current_perms_norm = [client.normalize_permission(p) for p in client.list_permissions_raw(limit=1000)]
    current_by_id = {p["id"]: p for p in current_perms_norm if p.get("id")}

    rules_to_delete = [p for pid, p in current_by_id.items() if pid not in snap_by_id]
    rules_to_recreate = [p for pid, p in snap_by_id.items() if pid not in current_by_id]
    rules_to_restore: List[Dict[str, Any]] = []

    for pid, snap_p in snap_by_id.items():
        if pid in current_by_id:
            curr_p = current_by_id[pid]
            if (
                 sorted(curr_p["user_ids"]) != sorted(snap_p["user_ids"])
                or sorted(curr_p["user_group_ids"]) != sorted(snap_p["user_group_ids"])
                or sorted(curr_p["asset_ids"]) != sorted(snap_p["asset_ids"])
                or sorted(curr_p["node_ids"]) != sorted(snap_p["node_ids"])
                or sorted(curr_p["accounts"]) != sorted(snap_p["accounts"])
                or curr_p["is_active"] != snap_p["is_active"]
            ):
                rules_to_restore.append(snap_p)

    diff_summary = {
        "backup_file": str(bp),
        "backup_timestamp": snapshot.get("metadata", {}).get("timestamp"),
        "backup_label": snapshot.get("metadata", {}).get("label"),
        "extra_rules_to_delete_count": len(rules_to_delete),
        "extra_rules_to_delete": [{"id": r["id"], "name": r["name"]} for r in rules_to_delete],
        "missing_rules_to_recreate_count": len(rules_to_recreate),
        "missing_rules_to_recreate": [{"id": r["id"], "name": r["name"]} for r in rules_to_recreate],
        "modified_rules_to_restore_count": len(rules_to_restore),
        "modified_rules_to_restore": [{"id": r["id"], "name": r["name"]} for r in rules_to_restore],
    }

    if not confirm:
        return {
            "status": "PREVIEW_ONLY",
            "operation": "REVERT_TO_BACKUP",
            "message": "Preview of reverting JumpServer permissions to backup snapshot. Ask user for confirmation before running with --confirm.",
            "diff": diff_summary,
        }

    executed_changes: Dict[str, Any] = {"deleted": [], "recreated": [], "restored": []}

    for r in rules_to_delete:
        client.request("DELETE", f"/api/v1/perms/asset-permissions/{r['id']}/")
        executed_changes["deleted"].append(r["name"])

    for r in rules_to_recreate:
        body: Dict[str, Any] = {
            "id": r["id"],
            "name": r["name"],
            "users": r["user_ids"],
            "user_groups": r["user_group_ids"],
            "assets": r["asset_ids"],
            "nodes": r["node_ids"],
            "is_active": r["is_active"],
            "comment": r["comment"],
        }
        if r.get("date_expired"):
            body["date_expired"] = r["date_expired"]
        if client.is_v3_or_v4:
            body["accounts"] = r["accounts"]
            body["actions"] = r["actions"]
        client.request("POST", "/api/v1/perms/asset-permissions/", json_body=body)
        executed_changes["recreated"].append(r["name"])

    for r in rules_to_restore:
        body = {
            "name": r["name"],
            "users": r["user_ids"],
            "user_groups": r["user_group_ids"],
            "assets": r["asset_ids"],
            "nodes": r["node_ids"],
            "is_active": r["is_active"],
        }
        if client.is_v3_or_v4:
            body["accounts"] = r["accounts"]
            body["actions"] = r["actions"]
        client.request("PATCH", f"/api/v1/perms/asset-permissions/{r['id']}/", json_body=body)
        executed_changes["restored"].append(r["name"])

    write_audit_log("revert_executed", {"backup_file": str(bp), "changes": executed_changes})
    return {"status": "REVERTED", "backup_file": str(bp), "executed_changes": executed_changes}


def cmd_local_audit_log(limit: int = 50) -> Dict[str, Any]:
    if not AUDIT_LOG_PATH.exists():
        return {"status": "OK", "count": 0, "entries": []}
    lines = AUDIT_LOG_PATH.read_text(encoding="utf-8", errors="replace").splitlines()
    entries = []
    for ln in reversed(lines[-limit:]):
        try:
            entries.append(json.loads(ln))
        except Exception:
            pass
    return {"status": "OK", "count": len(entries), "entries": entries}


# =============================================================================
# CLI Argument Parser & Entry Point
# =============================================================================


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="jmsctl",
        description="AiJumpOps (jmsctl) - Universal AI-Native JumpServer Bastion / PAM Copilot CLI",
    )
    sub = parser.add_subparsers(dest="command")

    # init
    p_init = sub.add_parser("init", help="Initialize JumpServer .env configuration safely")
    p_init.add_argument("--url", default="", help="JumpServer URL (e.g. https://jumpserver.example.com)")
    p_init.add_argument("--username", default="", help="JumpServer username")
    p_init.add_argument("--password", default="", help="JumpServer password")
    p_init.add_argument("--totp-secret", default="", help="Optional Base32 TOTP secret for zero-touch MFA")
    p_init.add_argument("--org-id", default="", help="JumpServer Organization UUID")
    p_init.add_argument("--insecure", action="store_true", help="Disable SSL certificate verification")

    # auth-check & auth-otp
    p_auth = sub.add_parser("auth-check", help="Test JumpServer authentication, session cache, and API version")
    p_auth.add_argument("--refresh", action="store_true", help="Force re-authentication")
    p_auth.add_argument("--otp", default="", help="Optional 6-digit TOTP code")

    p_otp = sub.add_parser("auth-otp", help="Complete pending 2FA/TOTP challenge with a 6-digit Authenticator code")
    p_otp.add_argument("--code", required=True, help="6-digit OTP code from Authenticator app")

    # overview & orgs
    sub.add_parser("overview", help="Get complete JumpServer overview (assets, users, permissions, live sessions)")
    sub.add_parser("orgs", help="List all JumpServer organizations")

    # assets
    p_assets = sub.add_parser("assets", help="Manage JumpServer assets / servers / hosts")
    assets_sub = p_assets.add_subparsers(dest="subcommand")

    p_al = assets_sub.add_parser("list", help="List or search assets")
    p_al.add_argument("--search", default="", help="Search by name, IP, or comment")
    p_al.add_argument("--node", default="", help="Filter by node name or ID")
    p_al.add_argument("--limit", type=int, default=200)

    p_af = assets_sub.add_parser("find", help="Smart search assets by name, IP, or ID")
    p_af.add_argument("query", help="Search query")

    p_as = assets_sub.add_parser("show", help="Inspect an asset, its accounts, and permission rules")
    p_as.add_argument("asset", help="Asset name, IP, or ID")

    p_ac = assets_sub.add_parser("create", help="Register a new server asset in JumpServer (PREVIEW_ONLY first)")
    p_ac.add_argument("--name", required=True, help="Asset hostname/name")
    p_ac.add_argument("--address", required=True, help="Asset IP address or FQDN")
    p_ac.add_argument("--platform", default="Linux", help="Platform (Linux, Windows, etc.)")
    p_ac.add_argument("--node", default="", help="Target asset node")
    p_ac.add_argument("--protocol", default="ssh", help="Protocol (ssh, rdp, vnc, telnet)")
    p_ac.add_argument("--port", type=int, default=22, help="Protocol port (default: 22)")
    p_ac.add_argument("--comment", default="", help="Optional comment")
    p_ac.add_argument("--confirm", action="store_true", help="Confirm execution")

    p_ad = assets_sub.add_parser("delete", help="Delete an asset (PREVIEW_ONLY first)")
    p_ad.add_argument("asset", help="Asset name, IP, or ID")
    p_ad.add_argument("--confirm", action="store_true", help="Confirm deletion")

    # nodes
    p_nodes = sub.add_parser("nodes", help="List JumpServer asset tree nodes")
    p_nodes.add_argument("--search", default="", help="Search query")

    # users & groups
    p_users = sub.add_parser("users", help="Manage JumpServer users and user groups")
    users_sub = p_users.add_subparsers(dest="subcommand")

    p_ul = users_sub.add_parser("list", help="List or search users")
    p_ul.add_argument("--search", default="", help="Search query")
    p_ul.add_argument("--group", default="", help="Filter by user group")
    p_ul.add_argument("--limit", type=int, default=200)

    p_ug = users_sub.add_parser("groups", help="List user groups")
    p_ug.add_argument("--search", default="", help="Search query")

    p_us = users_sub.add_parser("show", help="Inspect user details and all permission rules affecting them")
    p_us.add_argument("user", help="Username, name, email, or ID")

    for act in ("enable", "disable"):
        p_ua = users_sub.add_parser(act, help=f"{act.capitalize()} a user account (PREVIEW_ONLY first)")
        p_ua.add_argument("user", help="Username, name, or ID")
        p_ua.add_argument("--confirm", action="store_true")

    for g_act in ("add-to-group", "remove-from-group"):
        p_ugm = users_sub.add_parser(g_act, help=f"{g_act} for a user (PREVIEW_ONLY first)")
        p_ugm.add_argument("user", help="Username, name, or ID")
        p_ugm.add_argument("--group", required=True, help="Target User Group name or ID")
        p_ugm.add_argument("--confirm", action="store_true")

    p_uc = users_sub.add_parser("create", help="Create a new JumpServer user (PREVIEW_ONLY first)")
    p_uc.add_argument("--username", required=True)
    p_uc.add_argument("--email", required=True)
    p_uc.add_argument("--name", default="")
    p_uc.add_argument("--group", default="")
    p_uc.add_argument("--confirm", action="store_true")

    # perms (Asset Permissions / Authorization Rules)
    p_perms = sub.add_parser("perms", help="Manage JumpServer Asset Permissions (Authorization Rules)")
    perms_sub = p_perms.add_subparsers(dest="subcommand")

    p_pl = perms_sub.add_parser("list", help="List or search AssetPermission rules")
    p_pl.add_argument("--search", default="")
    p_pl.add_argument("--user", default="")
    p_pl.add_argument("--asset", default="")
    p_pl.add_argument("--limit", type=int, default=200)

    p_pc = perms_sub.add_parser("check-access", help="Verify if a user currently has access to an asset")
    p_pc.add_argument("--user", required=True, help="Username, name, or ID")
    p_pc.add_argument("--asset", required=True, help="Asset name, IP, or ID")

    p_pg = perms_sub.add_parser("grant", help="Grant user/group access to an asset/node (PREVIEW_ONLY first)")
    p_pg.add_argument("--user", default="", help="Username, name, or ID")
    p_pg.add_argument("--user-group", default="", help="User Group name or ID")
    p_pg.add_argument("--asset", default="", help="Asset name, IP, or ID")
    p_pg.add_argument("--node", default="", help="Asset Node name or ID")
    p_pg.add_argument("--accounts", default="@ALL", help="Comma-separated account names (e.g. root,ubuntu,@ALL)")
    p_pg.add_argument(
        "--actions",
        default="connect",
        help="Allowed actions: connect, readonly, transfer, all, or comma-separated (connect,upload,download,copy,paste)",
    )
    p_pg.add_argument("--rule-name", default="", help="Optional existing or custom permission rule name")
    p_pg.add_argument("--days", type=int, default=None, help="Temporary access duration in days")
    p_pg.add_argument("--hours", type=int, default=None, help="Temporary access duration in hours")
    p_pg.add_argument("--date-expired", default="", help="Explicit ISO expiration timestamp")
    p_pg.add_argument("--comment", default="", help="Rule comment")
    p_pg.add_argument("--confirm", action="store_true", help="Confirm execution")

    p_pr = perms_sub.add_parser("revoke", help="Revoke user/asset access or delete a permission rule (PREVIEW_ONLY first)")
    p_pr.add_argument("--rule", default="", help="Permission rule name or ID")
    p_pr.add_argument("--user", default="", help="User to revoke")
    p_pr.add_argument("--asset", default="", help="Asset to revoke")
    p_pr.add_argument("--delete-rule", action="store_true", help="Delete the entire permission rule")
    p_pr.add_argument("--confirm", action="store_true", help="Confirm execution")

    # sessions (Live Terminal Sessions)
    p_sess = sub.add_parser("sessions", help="Inspect or terminate live terminal sessions")
    sess_sub = p_sess.add_subparsers(dest="subcommand")

    p_sl = sess_sub.add_parser("active", help="List currently active terminal sessions")
    p_sl.add_argument("--user", default="")
    p_sl.add_argument("--asset", default="")

    p_sk = sess_sub.add_parser("terminate", help="Kill/terminate an active terminal session (PREVIEW_ONLY first)")
    p_sk.add_argument("session_id", help="Session UUID to terminate")
    p_sk.add_argument("--confirm", action="store_true")

    # logs & security-audit
    p_logs = sub.add_parser("logs", help="Query JumpServer command, login, session, or admin operation audit logs")
    p_logs.add_argument("--type", default="commands", choices=["commands", "logins", "sessions", "operations"])
    p_logs.add_argument("--user", default="")
    p_logs.add_argument("--asset", default="")
    p_logs.add_argument("--search", default="")
    p_logs.add_argument("--days", type=int, default=7)
    p_logs.add_argument("--limit", type=int, default=100)

    sub.add_parser("security-audit", help="AI Security Auditor: Scan JumpServer for MFA gaps, overprivileged rules, and expired policies")

    # backup, backups, revert, audit-log
    p_bk = sub.add_parser("backup", help="Create a full JSON snapshot backup of all permissions and user states")
    p_bk.add_argument("--label", default="before_changes")

    sub.add_parser("backups", help="List saved JumpServer snapshot backups")

    p_rev = sub.add_parser("revert", help="Revert JumpServer permissions back to backup snapshot (PREVIEW_ONLY first)")
    p_rev.add_argument("--file", default="", help="Backup filename or path (defaults to latest)")
    p_rev.add_argument("--confirm", action="store_true", help="Confirm revert execution")

    p_al_local = sub.add_parser("audit-log", help="Show local chronological log of confirmed AiJumpOps changes")
    p_al_local.add_argument("--limit", type=int, default=50)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    try:
        if args.command == "init":
            interactive = not (args.url and args.username and args.password)
            res = cmd_init(
                url=args.url,
                username=args.username,
                password=args.password,
                totp_secret=args.totp_secret,
                org_id=args.org_id,
                verify_ssl=not args.insecure,
                interactive=interactive,
            )
        elif args.command == "auth-check":
            res = cmd_auth_check(force_refresh=args.refresh, otp_code=args.otp or None)
        elif args.command == "auth-otp":
            res = cmd_auth_otp(code=args.code)
        elif args.command == "overview":
            res = cmd_overview()
        elif args.command == "orgs":
            res = cmd_orgs_list()
        elif args.command == "nodes":
            res = cmd_nodes_list(search=args.search)
        elif args.command == "assets":
            sc = args.subcommand or "list"
            if sc == "list":
                res = cmd_assets_list(
                    search=getattr(args, "search", ""),
                    node=getattr(args, "node", ""),
                    limit=getattr(args, "limit", 200),
                )
            elif sc == "find":
                res = cmd_assets_list(search=args.query)
            elif sc == "show":
                res = cmd_asset_inspect(args.asset)
            elif sc == "create":
                res = cmd_asset_create(
                    name=args.name,
                    address=args.address,
                    platform=args.platform,
                    node=args.node,
                    protocol=args.protocol,
                    port=args.port,
                    comment=args.comment,
                    confirm=args.confirm,
                )
            elif sc == "delete":
                res = cmd_asset_delete(args.asset, confirm=args.confirm)
            else:
                raise JumpServerError(f"Unknown assets subcommand: {sc}")
        elif args.command == "users":
            sc = args.subcommand or "list"
            if sc == "list":
                res = cmd_users_list(
                    search=getattr(args, "search", ""),
                    group=getattr(args, "group", ""),
                    limit=getattr(args, "limit", 200),
                )
            elif sc == "groups":
                res = cmd_user_groups_list(search=getattr(args, "search", ""))
            elif sc == "show":
                res = cmd_user_action(user_query=args.user, action="inspect")
            elif sc in ("enable", "disable"):
                res = cmd_user_action(user_query=args.user, action=sc, confirm=args.confirm)
            elif sc in ("add-to-group", "remove-from-group"):
                res = cmd_user_action(user_query=args.user, action=sc, group=args.group, confirm=args.confirm)
            elif sc == "create":
                res = cmd_user_action(
                    action="create",
                    username=args.username,
                    email=args.email,
                    name=args.name,
                    group=args.group,
                    confirm=args.confirm,
                )
            else:
                raise JumpServerError(f"Unknown users subcommand: {sc}")
        elif args.command == "perms":
            sc = args.subcommand or "list"
            if sc == "list":
                res = cmd_permissions_list(
                    search=getattr(args, "search", ""),
                    user=getattr(args, "user", ""),
                    asset=getattr(args, "asset", ""),
                    limit=getattr(args, "limit", 200),
                )
            elif sc == "check-access":
                res = cmd_check_access(user_query=args.user, asset_query=args.asset)
            elif sc == "grant":
                res = cmd_permission_grant(
                    user_query=args.user,
                    user_group_query=args.user_group,
                    asset_query=args.asset,
                    node_query=args.node,
                    accounts=args.accounts,
                    actions=args.actions,
                    rule_name=args.rule_name,
                    days=args.days,
                    hours=args.hours,
                    date_expired=args.date_expired,
                    comment=args.comment,
                    confirm=args.confirm,
                )
            elif sc == "revoke":
                res = cmd_permission_revoke(
                    rule_query=args.rule,
                    user_query=args.user,
                    asset_query=args.asset,
                    delete_entire_rule=args.delete_rule,
                    confirm=args.confirm,
                )
            else:
                raise JumpServerError(f"Unknown perms subcommand: {sc}")
        elif args.command == "sessions":
            sc = args.subcommand or "active"
            if sc == "active":
                res = cmd_sessions_active(user=getattr(args, "user", ""), asset=getattr(args, "asset", ""))
            elif sc == "terminate":
                res = cmd_session_terminate(args.session_id, confirm=args.confirm)
            else:
                raise JumpServerError(f"Unknown sessions subcommand: {sc}")
        elif args.command == "logs":
            res = cmd_audit_logs(
                log_type=args.type,
                user=args.user,
                asset=args.asset,
                search=args.search,
                days=args.days,
                limit=args.limit,
            )
        elif args.command == "security-audit":
            res = cmd_security_audit()
        elif args.command == "backup":
            res = cmd_backup(label=args.label)
        elif args.command == "backups":
            res = cmd_backups_list()
        elif args.command == "revert":
            res = cmd_revert(backup_file=args.file, confirm=args.confirm)
        elif args.command == "audit-log":
            res = cmd_local_audit_log(limit=args.limit)
        else:
            raise JumpServerError(f"Unknown command: {args.command}")

        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0

    except JumpServerError as exc:
        err_payload = {
            "status": "ERROR",
            "code": exc.code,
            "message": exc.message,
            "details": exc.details,
        }
        print(json.dumps(err_payload, ensure_ascii=False, indent=2))
        return 1
    except Exception as exc:
        err_payload = {
            "status": "ERROR",
            "code": "UNEXPECTED_ERROR",
            "message": str(exc),
        }
        print(json.dumps(err_payload, ensure_ascii=False, indent=2))
        return 1


if __name__ == "__main__":
    sys.exit(main())





