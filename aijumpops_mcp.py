#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AiJumpOps MCP Server (Model Context Protocol - stdio JSON-RPC 2.0)
Connects OpenCode, Claude Code, Claude Desktop, Cursor, Windsurf, and ChatGPT
directly to any JumpServer (v2 / v3 / v4) PAM / Bastion infrastructure with
built-in PREVIEW_ONLY safety, TOTP 2FA handling, snapshot backups, and 1-click revert.
Zero external MCP SDK dependencies required (uses jmsctl directly).
"""

import json
import sys
from typing import Any, Dict, List, Optional

import jmsctl

SERVER_NAME = "aijumpops-mcp"
SERVER_VERSION = "1.0.0"

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "jms_overview",
        "description": "Get a complete overview of JumpServer (detected API version, total/active assets, nodes, users, MFA coverage, permission rules, and live terminal sessions).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "jms_auth_otp",
        "description": "Complete a pending 2FA/TOTP authentication challenge when JumpServer returns MFA_OTP_REQUIRED, using the 6-digit code provided by the user.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "6-digit TOTP code from the user's Authenticator app"},
            },
            "required": ["code"],
        },
    },
    {
        "name": "jms_assets_list",
        "description": "List or search JumpServer assets (servers/hosts) with their IP addresses, platform, protocols, nodes, and active status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "search": {"type": "string", "default": "", "description": "Optional search query (hostname, IP, comment)"},
                "node": {"type": "string", "default": "", "description": "Optional asset node name or ID filter"},
                "limit": {"type": "integer", "default": 200},
            },
        },
    },
    {
        "name": "jms_asset_inspect",
        "description": "Inspect a specific JumpServer asset (by name, partial name, IP, or ID), listing its available system accounts (e.g. root, ubuntu) and all permission rules granting access to it.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "asset": {"type": "string", "description": "Asset name, IP address, or ID"},
            },
            "required": ["asset"],
        },
    },
    {
        "name": "jms_asset_create",
        "description": "Register/create a new server asset in JumpServer. Always call with confirm=false first to preview and ask user confirmation!",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Server hostname / asset name"},
                "address": {"type": "string", "description": "Server IP address or FQDN"},
                "platform": {"type": "string", "default": "Linux", "description": "Platform name (Linux, Windows, etc.)"},
                "node": {"type": "string", "default": "", "description": "Target asset tree node name or ID"},
                "protocol": {"type": "string", "default": "ssh", "description": "Connection protocol (ssh, rdp, vnc, telnet)"},
                "port": {"type": "integer", "default": 22, "description": "Protocol port (e.g. 22 for SSH, 3389 for RDP)"},
                "comment": {"type": "string", "default": ""},
                "confirm": {
                    "type": "boolean",
                    "default": False,
                    "description": "Set to true ONLY after the user explicitly confirms the previewed plan.",
                },
            },
            "required": ["name", "address"],
        },
    },
    {
        "name": "jms_nodes_list",
        "description": "List JumpServer asset tree nodes (e.g. /Default/Production, /Default/Staging) and asset counts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "search": {"type": "string", "default": ""},
            },
        },
    },
    {
        "name": "jms_users_list",
        "description": "List or search JumpServer users with their username, email, role, groups, active status, and 2FA/MFA status.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "search": {"type": "string", "default": "", "description": "Optional search query (username, name, email)"},
                "group": {"type": "string", "default": "", "description": "Optional User Group name or ID filter"},
                "limit": {"type": "integer", "default": 200},
            },
        },
    },
    {
        "name": "jms_user_groups_list",
        "description": "List all JumpServer User Groups and member counts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "search": {"type": "string", "default": ""},
            },
        },
    },
    {
        "name": "jms_user_action",
        "description": "Inspect a user's permissions, or perform a user lifecycle action (enable, disable, add-to-group, remove-from-group, create). For mutating actions, ALWAYS call with confirm=false first!",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user": {"type": "string", "default": "", "description": "Target username, display name, email, or ID"},
                "action": {
                    "type": "string",
                    "default": "inspect",
                    "enum": ["inspect", "enable", "disable", "add-to-group", "remove-from-group", "create"],
                },
                "group": {"type": "string", "default": "", "description": "Target User Group (for add-to-group, remove-from-group, or create)"},
                "username": {"type": "string", "default": "", "description": "New username (when action=create)"},
                "name": {"type": "string", "default": "", "description": "New user display name (when action=create)"},
                "email": {"type": "string", "default": "", "description": "New user email (when action=create)"},
                "confirm": {
                    "type": "boolean",
                    "default": False,
                    "description": "Set to true ONLY after the user explicitly confirms the preview.",
                },
            },
        },
    },
    {
        "name": "jms_permissions_list",
        "description": "List JumpServer AssetPermission (authorization) rules, optionally filtered by user, asset, or search query.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "search": {"type": "string", "default": ""},
                "user": {"type": "string", "default": "", "description": "Filter permissions for a specific user"},
                "asset": {"type": "string", "default": "", "description": "Filter permissions for a specific asset"},
                "limit": {"type": "integer", "default": 200},
            },
        },
    },
    {
        "name": "jms_check_access",
        "description": "Check whether a specific JumpServer User currently has access to a specific Asset, and show which permission rules, accounts (e.g. root, ubuntu), and actions apply.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user": {"type": "string", "description": "Username, display name, email, or ID"},
                "asset": {"type": "string", "description": "Asset name, IP address, or ID"},
            },
            "required": ["user", "asset"],
        },
    },
    {
        "name": "jms_permission_grant",
        "description": "Grant a JumpServer User (or User Group) access to an Asset (or Node). Always run with confirm=false first to preview available accounts on the asset, ask the user which account (root/ubuntu/@ALL), actions (connect/transfer/all), and expiry duration they want, and only set confirm=true after explicit user approval.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user": {"type": "string", "default": "", "description": "Target user (username, name, or ID)"},
                "user_group": {"type": "string", "default": "", "description": "Target User Group (name or ID)"},
                "asset": {"type": "string", "default": "", "description": "Target server asset (name, IP, or ID)"},
                "node": {"type": "string", "default": "", "description": "Target asset tree node (name or ID)"},
                "accounts": {
                    "type": "string",
                    "default": "@ALL",
                    "description": "Comma-separated system account usernames (e.g. 'root', 'ubuntu', 'root,ubuntu', or '@ALL')",
                },
                "actions": {
                    "type": "string",
                    "default": "connect",
                    "description": "Allowed session actions: 'connect', 'readonly', 'transfer', 'all', or comma-separated ('connect,upload,download,copy,paste')",
                },
                "rule_name": {"type": "string", "default": "", "description": "Optional existing or custom permission rule name"},
                "days": {"type": "integer", "description": "Optional temporary access duration in days"},
                "hours": {"type": "integer", "description": "Optional temporary access duration in hours"},
                "comment": {"type": "string", "default": ""},
                "confirm": {
                    "type": "boolean",
                    "default": False,
                    "description": "Set to true ONLY after explicit user confirmation.",
                },
            },
        },
    },
    {
        "name": "jms_permission_revoke",
        "description": "Revoke a user's access to an asset, or delete an entire AssetPermission rule. Always call with confirm=false first to preview affected rules!",
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule": {"type": "string", "default": "", "description": "Specific permission rule name or ID"},
                "user": {"type": "string", "default": "", "description": "User to remove from matching rule(s)"},
                "asset": {"type": "string", "default": "", "description": "Asset to remove from matching rule(s)"},
                "delete_entire_rule": {"type": "boolean", "default": False, "description": "Delete the entire permission rule"},
                "confirm": {
                    "type": "boolean",
                    "default": False,
                    "description": "Set to true ONLY after explicit user confirmation.",
                },
            },
        },
    },
    {
        "name": "jms_sessions_active",
        "description": "List currently active live SSH/RDP terminal sessions on JumpServer, or terminate a live session (with confirm=true after preview).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "user": {"type": "string", "default": "", "description": "Filter by username"},
                "asset": {"type": "string", "default": "", "description": "Filter by asset"},
                "terminate_session_id": {"type": "string", "default": "", "description": "Optional session UUID to kill/terminate"},
                "confirm": {
                    "type": "boolean",
                    "default": False,
                    "description": "Set to true ONLY after the user explicitly confirms terminating the session.",
                },
            },
        },
    },
    {
        "name": "jms_audit_logs",
        "description": "Query JumpServer security audit logs: executed shell commands ('commands'), user login events ('logins'), historical terminal sessions ('sessions'), or admin changes ('operations').",
        "inputSchema": {
            "type": "object",
            "properties": {
                "log_type": {
                    "type": "string",
                    "default": "commands",
                    "enum": ["commands", "logins", "sessions", "operations"],
                },
                "user": {"type": "string", "default": "", "description": "Filter by username"},
                "asset": {"type": "string", "default": "", "description": "Filter by asset name"},
                "search": {"type": "string", "default": "", "description": "Search text (e.g. 'rm -rf', 'sudo', IP)"},
                "days": {"type": "integer", "default": 7, "description": "Lookback window in days (default: 7)"},
                "limit": {"type": "integer", "default": 100},
            },
        },
    },
    {
        "name": "jms_security_audit",
        "description": "AI Security Auditor: Scan JumpServer for users without 2FA/MFA, overprivileged permission rules (e.g. @ALL or root across broad nodes), expired rules, and unassigned assets.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "jms_backup",
        "description": "Create a full JSON snapshot backup of all JumpServer AssetPermission rules and user states before making changes.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "label": {"type": "string", "default": "before_changes"},
            },
        },
    },
    {
        "name": "jms_revert",
        "description": "Revert JumpServer AssetPermission rules back to a backup snapshot. Always call with confirm=false first to preview the exact diff!",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {"type": "string", "default": "", "description": "Backup filename or path (empty = latest backup)"},
                "confirm": {
                    "type": "boolean",
                    "default": False,
                    "description": "Set to true ONLY after explicit user confirmation of the revert diff.",
                },
            },
        },
    },
]


def dispatch_tool(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if name == "jms_overview":
        return jmsctl.cmd_overview()
    if name == "jms_auth_otp":
        return jmsctl.cmd_auth_otp(code=str(arguments.get("code", "")))
    if name == "jms_assets_list":
        return jmsctl.cmd_assets_list(
            search=str(arguments.get("search", "")),
            node=str(arguments.get("node", "")),
            limit=int(arguments.get("limit", 200)),
        )
    if name == "jms_asset_inspect":
        return jmsctl.cmd_asset_inspect(asset_query=str(arguments["asset"]))
    if name == "jms_asset_create":
        return jmsctl.cmd_asset_create(
            name=str(arguments["name"]),
            address=str(arguments["address"]),
            platform=str(arguments.get("platform", "Linux")),
            node=str(arguments.get("node", "")),
            protocol=str(arguments.get("protocol", "ssh")),
            port=int(arguments.get("port", 22)),
            comment=str(arguments.get("comment", "")),
            confirm=bool(arguments.get("confirm", False)),
        )
    if name == "jms_nodes_list":
        return jmsctl.cmd_nodes_list(search=str(arguments.get("search", "")))
    if name == "jms_users_list":
        return jmsctl.cmd_users_list(
            search=str(arguments.get("search", "")),
            group=str(arguments.get("group", "")),
            limit=int(arguments.get("limit", 200)),
        )
    if name == "jms_user_groups_list":
        return jmsctl.cmd_user_groups_list(search=str(arguments.get("search", "")))
    if name == "jms_user_action":
        return jmsctl.cmd_user_action(
            user_query=str(arguments.get("user", "")),
            action=str(arguments.get("action", "inspect")),
            username=str(arguments.get("username", "")),
            name=str(arguments.get("name", "")),
            email=str(arguments.get("email", "")),
            group=str(arguments.get("group", "")),
            confirm=bool(arguments.get("confirm", False)),
        )
    if name == "jms_permissions_list":
        return jmsctl.cmd_permissions_list(
            search=str(arguments.get("search", "")),
            user=str(arguments.get("user", "")),
            asset=str(arguments.get("asset", "")),
            limit=int(arguments.get("limit", 200)),
        )
    if name == "jms_check_access":
        return jmsctl.cmd_check_access(
            user_query=str(arguments["user"]),
            asset_query=str(arguments["asset"]),
        )
    if name == "jms_permission_grant":
        return jmsctl.cmd_permission_grant(
            user_query=str(arguments.get("user", "")),
            user_group_query=str(arguments.get("user_group", "")),
            asset_query=str(arguments.get("asset", "")),
            node_query=str(arguments.get("node", "")),
            accounts=str(arguments.get("accounts", "@ALL")),
            actions=str(arguments.get("actions", "connect")),
            rule_name=str(arguments.get("rule_name", "")),
            days=arguments.get("days"),
            hours=arguments.get("hours"),
            comment=str(arguments.get("comment", "")),
            confirm=bool(arguments.get("confirm", False)),
        )
    if name == "jms_permission_revoke":
        return jmsctl.cmd_permission_revoke(
            rule_query=str(arguments.get("rule", "")),
            user_query=str(arguments.get("user", "")),
            asset_query=str(arguments.get("asset", "")),
            delete_entire_rule=bool(arguments.get("delete_entire_rule", False)),
            confirm=bool(arguments.get("confirm", False)),
        )
    if name == "jms_sessions_active":
        term_id = str(arguments.get("terminate_session_id", "")).strip()
        if term_id:
            return jmsctl.cmd_session_terminate(
                session_id=term_id,
                confirm=bool(arguments.get("confirm", False)),
            )
        return jmsctl.cmd_sessions_active(
            user=str(arguments.get("user", "")),
            asset=str(arguments.get("asset", "")),
        )
    if name == "jms_audit_logs":
        return jmsctl.cmd_audit_logs(
            log_type=str(arguments.get("log_type", "commands")),
            user=str(arguments.get("user", "")),
            asset=str(arguments.get("asset", "")),
            search=str(arguments.get("search", "")),
            days=int(arguments.get("days", 7)),
            limit=int(arguments.get("limit", 100)),
        )
    if name == "jms_security_audit":
        return jmsctl.cmd_security_audit()
    if name == "jms_backup":
        return jmsctl.cmd_backup(label=str(arguments.get("label", "before_changes")))
    if name == "jms_revert":
        return jmsctl.cmd_revert(
            backup_file=str(arguments.get("file", "")),
            confirm=bool(arguments.get("confirm", False)),
        )

    raise ValueError(f"Unknown tool: {name}")


def handle_request(req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    method = req.get("method")
    req_id = req.get("id")
    params = req.get("params") or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        }
    if method == "notifications/initialized":
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments") or {}
        try:
            res = dispatch_tool(tool_name, tool_args)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(res, ensure_ascii=False, indent=2)}],
                    "isError": False,
                },
            }
        except jmsctl.JumpServerError as exc:
            err = {"ok": False, "error_code": exc.code, "message": exc.message, "details": exc.details}
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(err, ensure_ascii=False, indent=2)}],
                    "isError": True,
                },
            }
        except Exception as exc:
            err = {"ok": False, "error_code": "MCP_TOOL_ERROR", "message": str(exc)}
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(err, ensure_ascii=False, indent=2)}],
                    "isError": True,
                },
            }

    if req_id is not None:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }
    return None


def main() -> int:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            resp = handle_request(req)
            if resp is not None:
                sys.stdout.write(json.dumps(resp, ensure_ascii=False) + "\n")
                sys.stdout.flush()
        except Exception as exc:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }
            sys.stdout.write(json.dumps(err_resp, ensure_ascii=False) + "\n")
            sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
