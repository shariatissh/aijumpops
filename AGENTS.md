# AiJumpOps — JumpServer Bastion / PAM Copilot Instructions (English & فارسی)

This repository contains **AiJumpOps**, an intelligent, interactive, and safe JumpServer Bastion / PAM Copilot (`./jmsctl` CLI engine and `aijumpops_mcp.py` MCP Server).
Users issue natural language commands in English or Persian (e.g., **"Grant user X access to server Y"** / **«دسترسی سرور Y رو بده به کاربر X»** or **"Who has access to server Z?"** / **«چه کسانی به سرور Z دسترسی دارن؟»**). You must execute operations accurately, safely, and with step-by-step user confirmation.

---

## 1. Golden Safety, TOTP & Privacy Rules / قوانین طلایی امنیت، دقت و احراز هویت دو مرحله‌ای

1. **Never Read or Print `.env` Secrets (عدم خواندن مستقیم `.env`):**
   - Authentication credentials live in `.env` or `~/.config/aijumpops/.env`.
   - **NEVER** read `.env` with the `read` tool or print secrets in outputs. `./jmsctl` reads `.env` internally, auto-detects the JumpServer API version (`v2`, `v3`, or `v4`), and caches sessions automatically.
   - If `./jmsctl` returns `MISSING_CONFIG` or `MISSING_CREDENTIALS`, instruct the user to run `./jmsctl init` or set `JMS_URL`, `JMS_USERNAME`, and `JMS_PASSWORD` in `.env` (see `.env.example`).

2. **Seamless 2FA / TOTP Challenge Handling (پشتیبانی کامل از TOTP دو مرحله‌ای):**
   - If `JMS_TOTP_SECRET` is configured in `.env`, `./jmsctl` generates the 6-digit TOTP code automatically.
   - If `./jmsctl` returns `MFA_OTP_REQUIRED`, ask the user via the `question` tool for their current 6-digit Authenticator code and run:
     ```bash
     ./jmsctl auth-otp --code "<6_DIGIT_CODE>"
     ```
     Once verified, the session is cached so future commands run without needing another OTP code.

3. **No Mutating Operation Without Explicit User Confirmation (عدم تغییر بدون تایید نهایی کاربر):**
   - All mutating commands in `./jmsctl` default to **`PREVIEW_ONLY`** mode when `--confirm` is omitted and make zero changes on JumpServer.
   - **ALWAYS** inspect current state first, show the exact details to the user (using the interactive `question` tool), and **ONLY after explicit user confirmation** run the command with `--confirm`.

---

## 2. Standard Interactive Workflows / فلوچارت استاندارد سناریوها

### Scenario A: "Grant User X Access to Server Y" / «دسترسی سرور Y رو بده به کاربر X»
1. **Step 1 (Preview & Inspect Available Accounts on Server):**
   ```bash
   ./jmsctl perms grant --user "<user>" --asset "<server_name_or_ip>"
   ```
   - If multiple users or servers match (`AMBIGUOUS_USER` or `AMBIGUOUS_ASSET`), ask the user via `question` to select the exact one.
2. **Step 2 (Select System Account, Actions & Duration + Get Confirmation):**
   - Review `available_accounts_on_asset` in the preview response.
   - Use the `question` tool to ask the user:
     1. **Which System Account?** (e.g., `root`, `ubuntu`, specific account, or `@ALL`)
     2. **Which Session Actions?** (`connect` only, `readonly`, `transfer` with file upload/download, or `all`)
     3. **Duration?** (Permanent or temporary e.g. `24 hours` / `7 days`)
3. **Step 3 (Final Execution After User Selection):**
   ```bash
   ./jmsctl perms grant --user "<user>" --asset "<server>" --accounts "<chosen_accounts>" --actions "<chosen_actions>" [--days N | --hours H] --confirm
   ```

### Scenario B: "Revoke User X's Access from Server Y" / «دسترسی کاربر X رو از سرور Y بردار»
1. **Step 1 (Preview Without `--confirm`):**
   ```bash
   ./jmsctl perms revoke --user "<user>" --asset "<server>"
   ```
2. **Step 2 (Explicit User Confirmation):**
   Display the resolved user, server, and affected permission rule(s), and ask for confirmation via `question`.
3. **Step 3 (Final Execution):**
   ```bash
   ./jmsctl perms revoke --user "<user>" --asset "<server>" --confirm
   ```

### Scenario C: "Backup & Revert Permissions" / «بکاپ گرفتن و بازگردانی دسترسی‌ها»
- Before bulk permission edits or security cleanups, take a full JSON snapshot backup:
  ```bash
  ./jmsctl backup --label "before_cleanup"
  ```
- To preview and revert any drift back to the backup snapshot:
  ```bash
  ./jmsctl revert
  # After user confirms the diff:
  ./jmsctl revert --confirm
  ```

---

## 3. Complete `./jmsctl` Command Reference / مرجع کامل دستورات

All `./jmsctl` outputs are structured JSON:

### Setup, Auth, Overview & Backup / راه‌اندازی، احراز هویت و پشتیبان‌گیری
- `./jmsctl init` : Interactive or flag-based `.env` setup for any JumpServer instance
- `./jmsctl auth-check [--refresh]` : Test connectivity, authentication, and auto-detected API version (`v2`/`v3`/`v4`)
- `./jmsctl auth-otp --code "<6_DIGIT_OTP>"` : Complete pending 2FA/TOTP login challenge and cache session
- `./jmsctl overview` : Full JumpServer summary (assets, nodes, users, MFA status, permissions, live sessions)
- `./jmsctl orgs` : List JumpServer organizations
- `./jmsctl backup [--label "..."]` : Full JSON snapshot of all AssetPermission rules and user states
- `./jmsctl backups` : List saved backups
- `./jmsctl revert [--file "..."] [--confirm]` : Compute diff and revert permission rules back to backup
- `./jmsctl audit-log [--limit 50]` : Local chronological audit log of confirmed changes

### Asset & Node Management (`assets`, `nodes`) / مدیریت سرورها و نودها
- `./jmsctl assets list [--search "..."] [--node "..."]` : List or search server assets
- `./jmsctl assets find "<query>"` : Smart search by hostname, partial name, IP, or UUID
- `./jmsctl assets show "<asset>"` : Inspect asset details, available system accounts, and matching permission rules
- `./jmsctl assets create --name "<name>" --address "<ip>" [--platform Linux|Windows] [--node "..."] [--protocol ssh|rdp] [--port 22] [--confirm]`
- `./jmsctl assets delete "<asset>" [--confirm]`
- `./jmsctl nodes [--search "..."]` : List asset tree nodes

### User & Group Management (`users`) / مدیریت کاربران و گروه‌ها
- `./jmsctl users list [--search "..."] [--group "..."]` : List users with role, groups, active state, and MFA status
- `./jmsctl users groups [--search "..."]` : List user groups
- `./jmsctl users show "<user>"` : Inspect user details and all permission rules granting them access
- `./jmsctl users enable|disable "<user>" [--confirm]` : Enable or disable a user account
- `./jmsctl users add-to-group|remove-from-group "<user>" --group "<group>" [--confirm]`
- `./jmsctl users create --username "<u>" --email "<e>" [--name "<n>"] [--group "<g>"] [--confirm]`

### Permissions & Access Control (`perms`) / مدیریت مجوزها و دسترسی‌ها
- `./jmsctl perms list [--search "..."] [--user "..."] [--asset "..."]` : List AssetPermission rules
- `./jmsctl perms check-access --user "<user>" --asset "<asset>"` : Check if user has access to asset and with which accounts/actions
- `./jmsctl perms grant --user "<u>" [--user-group "<g>"] --asset "<a>" [--node "<n>"] --accounts "<root,ubuntu,@ALL>" --actions "<connect|readonly|transfer|all>" [--days N] [--hours H] [--confirm]`
- `./jmsctl perms revoke [--rule "<r>"] [--user "<u>"] [--asset "<a>"] [--delete-rule] [--confirm]`

### Live Sessions, Audit Logs & AI Security Auditor (`sessions`, `logs`, `security-audit`)
- `./jmsctl sessions active [--user "..."] [--asset "..."]` : View currently connected SSH/RDP terminal sessions
- `./jmsctl sessions terminate "<session_id>" [--confirm]` : Kill/terminate an active terminal session
- `./jmsctl logs --type commands|logins|sessions|operations [--user "..."] [--asset "..."] [--search "..."] [--days 7]` : Query JumpServer audit trails
- `./jmsctl security-audit` : AI Security Auditor (scan for active users without MFA, overprivileged `@ALL`/`root` rules, expired rules, and unassigned assets)
