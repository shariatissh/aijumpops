<div align="center">

# 🛡️🤖 AiJumpOps (`jmsctl`)

**Universal AI-Native JumpServer Bastion / PAM Copilot — MCP Server, Agent Skill & Safe CLI Engine**  
**دستیار هوشمند، تعاملی و ایمن مدیریت دسترسی‌ها و سرورهای JumpServer (مبتنی بر MCP، Skill و خط فرمان)**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-3776AB.svg?logo=python&logoColor=white)](https://www.python.org/)
[![JumpServer](https://img.shields.io/badge/JumpServer-v2%20%7C%20v3%20%7C%20v4%20Auto--Detect-1ab394.svg)](https://www.jumpserver.org/)
[![MCP Compatible](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-10a37f.svg)](https://modelcontextprotocol.io/)
[![AI Agents](https://img.shields.io/badge/Agents-OpenCode%20%7C%20Claude%20%7C%20Cursor%20%7C%20ChatGPT-purple.svg)](#ai-integrations-mcp--skills)

[🇬🇧 English Documentation](#-english-documentation) • [🇮🇷 مستندات فارسی](#-مستندات-فارسی)

</div>

---

## 🇬🇧 English Documentation

### What is AiJumpOps?

**AiJumpOps** turns your AI coding & DevOps assistant (**OpenCode**, **Claude Code**, **Claude Desktop**, **Cursor**, **Windsurf**, or **ChatGPT**) into a **Senior JumpServer PAM & Infrastructure Security Engineer**.

Instead of clicking through nested JumpServer menus to find assets, accounts, user groups, and authorization rules, simply instruct your AI in natural language (English, Persian, or any language):
- *"Grant user `mohammad` access to server `app-prod-01` for 24 hours"*
- *"Check who currently has access to `db-master` and with which system accounts"*
- *"Run a security audit on JumpServer to find users without MFA and overprivileged `root` rules"*
- *"Show all active live SSH sessions right now and terminate any suspicious session"*
- *"Take a full backup of all JumpServer permission rules before cleanup, and revert if needed"*

---

### ✨ Key Differentiators & AI Safety Guardrails

1. **Zero-Config JumpServer Version Auto-Detection (`v2` / `v3` / `v4`):**  
   Automatically detects whether your JumpServer runs `v2` (`system-users`) or `v3`/`v4` (`accounts` & host platform schemas) and adapts API payloads transparently.
2. **Smart Username/Password + 2FA/TOTP Authentication with Session Caching:**  
   - Supports **Username & Password** login out of the box.
   - **2FA / TOTP Ready:** Either provide `JMS_TOTP_SECRET` in `.env` for 100% zero-touch RFC 6238 TOTP generation, or let the AI prompt you interactively for your 6-digit Authenticator code (`./jmsctl auth-otp --code 123456`).
   - Once authenticated, the session token/cookies are securely cached (`0600`) so subsequent commands execute instantaneously without re-prompting for OTP.
   - Also supports static `JMS_ACCESS_KEY_ID` / `JMS_ACCESS_KEY_SECRET` (HTTP Signature `httpsig`) and `JMS_PRIVATE_TOKEN`.
3. **Mandatory `PREVIEW_ONLY` Human-in-the-Loop Safety:**  
   Every mutating operation (granting/revoking permissions, creating/deleting assets, enabling/disabling users, killing live sessions, reverting backups) runs in **Preview Mode** by default. The AI inspects available accounts on the server, asks you clarifying questions via interactive prompts, and **only executes with `--confirm` (`confirm=true`) after your explicit approval**.
4. **Instant Permission Snapshot Backup & 1-Click Diff Revert:**  
   Snapshot all `AssetPermission` rules and user states to JSON (`./jmsctl backup`), preview the exact drift diff (`./jmsctl revert`), and roll back changes in one command (`./jmsctl revert --confirm`).
5. **AI Security Auditor (`security-audit`):**  
   Automatically scans your JumpServer organization for active users without 2FA/MFA (especially Admins), overly broad `@ALL` / `root` rules on root nodes, expired rules, and orphaned assets.

---

### 🚀 Quick Start

#### 1. Clone & Install
```bash
git clone https://github.com/shariatissh/aijumpops.git
cd aijumpops
pip install -e .
```

#### 2. Configure Your JumpServer Connection
- **Option A: Interactive or Flag-based Setup**
  ```bash
  ./jmsctl init
  ```
  Or non-interactively:
  ```bash
  ./jmsctl init \
    --url "https://jumpserver.example.com" \
    --username "admin" \
    --password "your_password"
  ```
- **Option B: Copy `.env.example`**
  ```bash
  cp .env.example .env
  chmod 600 .env
  # Edit .env and set JMS_URL, JMS_USERNAME, JMS_PASSWORD (and optional JMS_TOTP_SECRET)
  ```

#### 3. Verify Authentication (and 2FA/TOTP if enabled)
```bash
./jmsctl auth-check
# If MFA_OTP_REQUIRED is returned and JMS_TOTP_SECRET is not set:
./jmsctl auth-otp --code 123456
```

---

### 🤖 AI Integrations (MCP & Skills)

#### 1. One-Command Auto-Installer (OpenCode & Claude Code)
```bash
./install.sh
```

#### 2. Model Context Protocol (MCP) — 20 Built-in Tools
`aijumpops_mcp.py` is a zero-dependency **stdio JSON-RPC 2.0 MCP Server** exposing **20 tools**:
- `jms_overview`, `jms_auth_otp`
- `jms_assets_list`, `jms_asset_inspect`, `jms_asset_create`, `jms_nodes_list`
- `jms_accounts_list`, `jms_account_create`
- `jms_users_list`, `jms_user_groups_list`, `jms_user_action`
- `jms_permissions_list`, `jms_check_access`, `jms_permission_grant`, `jms_permission_revoke`
- `jms_sessions_active`, `jms_audit_logs`, `jms_security_audit`
- `jms_backup`, `jms_revert`

**Add to OpenCode (`~/.config/opencode/opencode.jsonc`):**
```jsonc
{
  "mcp": {
    "aijumpops": {
      "type": "local",
      "command": ["python3", "/absolute/path/to/aijumpops/aijumpops_mcp.py"],
      "enabled": true
    }
  }
}
```

**Add to Claude Desktop / Cursor (`claude_desktop_config.json`):**
```json
{
  "mcpServers": {
    "aijumpops": {
      "command": "python3",
      "args": ["/absolute/path/to/aijumpops/aijumpops_mcp.py"]
    }
  }
}
```

---

### 🛠️ Complete CLI Reference (`./jmsctl`)

| Category | Command | Description |
| :--- | :--- | :--- |
| **Setup & Auth** | `./jmsctl init` | Interactive or flag-based `.env` setup wizard (`0600` permissions) |
| | `./jmsctl auth-check [--refresh]` | Verify authentication, cached session, and auto-detected API version (`v2`/`v3`/`v4`) |
| | `./jmsctl auth-otp --code "<6_DIGIT>"` | Complete interactive 2FA/TOTP challenge and cache session |
| **Overview** | `./jmsctl overview` | Summary of assets, nodes, users, MFA coverage, permissions, and live sessions |
| | `./jmsctl orgs` | List all JumpServer organizations |
| **Assets & Nodes** | `./jmsctl assets list [--search "..."] [--node "..."]` | List or search server assets |
| | `./jmsctl assets find "<query>"` | Smart fuzzy search by hostname, IP, or UUID |
| | `./jmsctl assets show "<asset>"` | Inspect asset details, available system accounts, and matching permission rules |
| | `./jmsctl assets create --name "<n>" --address "<ip>" [--platform Linux] [--node "..."] [--protocol ssh] [--port 22] [--confirm]` | Register a new server asset (`PREVIEW_ONLY` first) |
| | `./jmsctl assets delete "<asset>" [--confirm]` | Delete an asset (`PREVIEW_ONLY` first) |
| | `./jmsctl nodes [--search "..."]` | List asset tree nodes |
| **Asset Accounts** | `./jmsctl accounts list [--asset "<asset>"]` | List system accounts defined on assets (root, ubuntu, pacs.support, etc.) |
| | `./jmsctl accounts create --asset "<asset>" --username "<user>" [--name "<name>"] [--password "<pass>"] [--privileged] [--confirm]` | Create a system account on an asset (`PREVIEW_ONLY` first) |
| **Users & Groups** | `./jmsctl users list [--search "..."] [--group "..."]` | List users with role, groups, active status, and 2FA/MFA state |
| | `./jmsctl users groups [--search "..."]` | List user groups and member counts |
| | `./jmsctl users show "<user>"` | Inspect user details and all permission rules affecting them |
| | `./jmsctl users enable\|disable "<user>" [--confirm]` | Enable or disable a user account (`PREVIEW_ONLY` first) |
| | `./jmsctl users add-to-group\|remove-from-group "<user>" --group "<g>" [--confirm]` | Add or remove user from a User Group (`PREVIEW_ONLY` first) |
| | `./jmsctl users create --username "<u>" [--email "<e>"] [--name "<n>"] [--password "<p>"] [--need-update-password] [--group "<g>"] [--confirm]` | Create a new user with password & force change on 1st login (`PREVIEW_ONLY` first) |
| **Permissions** | `./jmsctl perms list [--search "..."] [--user "<u>"] [--asset "<a>"]` | List `AssetPermission` authorization rules |
| | `./jmsctl perms check-access --user "<u>" --asset "<a>"` | Verify whether a user has access to an asset and via which accounts/rules |
| | `./jmsctl perms grant --user "<u>" --asset "<a>" --accounts "<root,ubuntu,@ALL>" --actions "<connect\|readonly\|transfer\|all>" [--days N] [--hours H] [--replace-accounts] [--confirm]` | Grant permanent or temporary access (`PREVIEW_ONLY` first) |
| | `./jmsctl perms revoke [--rule "<r>"] [--user "<u>"] [--asset "<a>"] [--delete-rule] [--confirm]` | Revoke access or delete a permission rule (`PREVIEW_ONLY` first) |
| **Sessions & Audit** | `./jmsctl sessions active [--user "<u>"] [--asset "<a>"]` | List currently active live SSH/RDP terminal sessions |
| | `./jmsctl sessions terminate "<session_id>" [--confirm]` | Kill/terminate a live terminal session (`PREVIEW_ONLY` first) |
| | `./jmsctl logs --type commands\|logins\|sessions\|operations [--user "<u>"] [--asset "<a>"] [--days 7]` | Query executed shell commands, login logs, sessions, or admin logs |
| | `./jmsctl security-audit` | Scan for users without MFA, overprivileged `@ALL`/`root` rules, and expired rules |
| **Backup & Revert** | `./jmsctl backup [--label "..."]` / `./jmsctl backups` | Snapshot all permission rules and user states to JSON |
| | `./jmsctl revert [--file "..."] [--confirm]` | Preview exact diff and roll back permission rules to backup snapshot |
| | `./jmsctl audit-log [--limit 50]` | View local chronological audit trail of confirmed changes |

---
---

<div dir="rtl">

## 🇮🇷 مستندات فارسی

### معرفی AiJumpOps

**AiJumpOps** یک کوپایلوت هوشمند و ایمن (AI-Native PAM & Bastion Copilot) برای **JumpServer** است که به مهندسین DevOps، مدیران سیستم و تیم‌های امنیت اجازه می‌دهد سرورها (Assets)، کاربران، مجوزهای دسترسی (Asset Permissions)، سشن‌های زنده و ممیزی امنیتی JumpServer خود را به زبان طبیعی (فارسی یا انگلیسی) در **OpenCode، Claude (Desktop / Code)، Cursor و ChatGPT** مدیریت کنند.

کافیست به دستیار هوش مصنوعی خود بگویید:
- *«دسترسی سرور `app-prod-01` رو توی جامپ‌سرور بده به کاربر `mohammad`»*
- *«چک کن ببین کاربر `ali` به سرور `db-master` دسترسی داره یا نه و با چه اکانتی؟»*
- *«الان چه کسانی سشن آنلاین SSH روی جامپ‌سرور دارن؟»*
- *«کل جامپ‌سرور رو ممیزی امنیتی کن ببین کدوم یوزرها MFA ندارن و کدوم قوانین دسترسی بیش از حد باز هستن»*
- *«قبل از تغییر دسترسی‌ها یه بکاپ کامل بگیر تا اگه مشکلی پیش اومد سریع Revert کنیم»*

---

### 🛡️ ویژگی‌های کلیدی و لایه‌های امنیتی هوشمند

۱. **تشخیص خودکار نسخه JumpServer (`v2` / `v3` / `v4`):**  
نیازی به تنظیم دستی نسخه API نیست؛ `./jmsctl` به‌صورت خودکار تفاوت ساختار نسخه‌های ۲ (`system-users`) و نسخه‌های ۳ و ۴ (`accounts` و `hosts`) را تشخیص داده و درخواست‌ها را منطبق می‌کند.

۲. **لاگین با یوزرنیم و پسورد + پشتیبانی کامل از کد دو مرحله‌ای (TOTP / 2FA) و کش سشن:**  
- **حالت اول (کاملاً خودکار بدون توقف):** اگر کلید پایه `JMS_TOTP_SECRET` را در `.env` قرار دهید، کد ۶ رقمی TOTP به صورت خودکار در لحظه تولید و لاگین انجام می‌شود.
- **حالت دوم (تعاملی):** اگر `JMS_TOTP_SECRET` تنظیم نشده باشد و روی اکانت شما MFA فعال باشد، دستیار هوشمند کد ۶ رقمی لحظه‌ای را از شما می‌پرسد و با `./jmsctl auth-otp --code 123456` وارد می‌شود.
- **کش هوشمند سشن:** پس از یک‌بار لاگین، توکن و کوکی سشن با دسترسی امن `600` کش می‌شود تا در دستورات بعدی نیازی به وارد کردن مجدد کد دو مرحله‌ای نباشد.

۳. **حالت پیش‌نمایش اجباری (`PREVIEW_ONLY`) و جلوگیری از خطای انسانی:**  
هیچ دستور تغییردهنده‌ای بدون فلگ `--confirm` اجرا نمی‌شود. برای مثال هنگام دادن دسترسی به یک سرور، دستیار ابتدا لیست اکانت‌های موجود روی آن سرور (`root`, `ubuntu`, `readonly`, `@ALL`) را بررسی کرده و از شما می‌پرسد:
- **با کدام اکانت سیستم؟**
- **چه مجوزهایی؟** (فقط اتصال `connect`، انتقال فایل `transfer` یا دسترسی کامل `all`)
- **دائمی یا موقت؟** (مثلاً ۲۴ ساعته یا ۷ روزه)
و **تنها پس از تایید نهایی شما** دستور را اجرا می‌کند.

۴. **پشتیبان‌گیری آنی و بازگردانی یک‌کلیکی (`backup` & `revert`):**  
پیش از هر تغییر مهم، با `./jmsctl backup` از تمام قوانین دسترسی و وضعیت کاربران اسنپ‌شات JSON گرفته می‌شود و در هر زمان با `./jmsctl revert` ابتدا تفاوت‌ها (Diff) نمایش داده شده و با `--confirm` دقیقاً به حالت قبل بازگردانده می‌شود.

</div>
