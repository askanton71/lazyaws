#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LazyAWS - IAM checks (account-level)

Checks:
  IAM-001 Root MFA enabled
  IAM-002 Account password policy baseline
  IAM-003 Users without MFA
  IAM-004 Access keys older than 90 days
  IAM-010 Admin policies attached (users/groups/roles)
  IAM-011 Wildcards in policies (Action/Resource)
  IAM-012 Unscoped iam:PassRole in policies
  IAM-013 Unused credentials (keys/passwords) > 90 days
  IAM-014 Root access keys present
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from aws_common import (
    get_session,
    get_traced_client,
    run_check,
    OK, WARN, BAD, NA,
)

# ------------- helpers -------------

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def make_check(code: str, title: str, scope: str, apis: List[str]) -> str:
    api_line = "API: " + "/".join(apis) if apis else "API: N/A"
    return f"{code} {title}\nScope: {scope}\n{api_line}"

def add_finding(findings: List[Dict[str, Any]], code: str, title: str, scope: str,
                apis: List[str], status_plain: str, details: str, recommendation: str):
    icon_map = {"OK": OK, "WARN": WARN, "BAD": BAD, "NA": NA}
    findings.append({
        "Check": make_check(code, title, scope, apis),
        "Status": icon_map.get(status_plain, NA),
        "StatusPlain": status_plain,
        "Details": details,
        "Recommendation": recommendation,
    })

def statements(doc: Dict[str, Any]):
    st = doc.get("Statement")
    if st is None:
        return []
    if isinstance(st, list):
        return st
    return [st]

def action_contains_wildcard(stmt: Dict[str, Any]) -> bool:
    act = stmt.get("Action")
    if act is None:
        return False
    if isinstance(act, str):
        return act == "*" or act.endswith(":*")
    if isinstance(act, list):
        for a in act:
            if isinstance(a, str) and (a == "*" or a.endswith(":*")):
                return True
    return False

def resource_contains_wildcard(stmt: Dict[str, Any]) -> bool:
    res = stmt.get("Resource")
    if res is None:
        return False
    if isinstance(res, str):
        return res == "*"
    if isinstance(res, list):
        return any(r == "*" for r in res if isinstance(r, str))
    return False

def contains_unscoped_passrole(stmt: Dict[str, Any]) -> bool:
    act = stmt.get("Action")
    acts = [act] if isinstance(act, str) else (act or [])
    if not any(isinstance(a, str) and a.lower() == "iam:passrole" for a in acts):
        return False
    return resource_contains_wildcard(stmt)

# ------------- module -------------

def add_arguments(ap: argparse.ArgumentParser):
    ap.add_argument("--profile", default=None, help="AWS profile name.")
    ap.add_argument("--region", default=None, help="Region hint for header only (IAM is global).")
    ap.add_argument("--stale-days", type=int, default=90, help="Age threshold in days for keys/passwords.")

def analyze(args):
    profile = args.profile
    region_hint = args.region
    stale_days = int(args.stale_days or 90)

    api_trace: List[Dict[str, Any]] = []
    sess = get_session(profile, None)
    iam = get_traced_client(sess, "iam", api_trace, profile, None)
    sts = get_traced_client(sess, "sts", api_trace, profile, None)

    findings: List[Dict[str, Any]] = []

    # Account identity (for header)
    try:
        ident = sts.get_caller_identity()
        account_id = ident.get("Account")
    except Exception:
        account_id = None

    # IAM-001 Root MFA
    try:
        summ = iam.get_account_summary()
        root_mfa = bool(summ.get("SummaryMap", {}).get("AccountMFAEnabled", 0))
        add_finding(findings, "IAM-001", "Root MFA enabled", "Account", ["iam:GetAccountSummary"],
                    "OK" if root_mfa else "BAD",
                    f"AccountMFAEnabled={root_mfa}",
                    "Enable and enforce hardware MFA on the root user.")
    except ClientError as e:
        add_finding(findings, "IAM-001", "Root MFA enabled", "Account", ["iam:GetAccountSummary"],
                    "WARN", f"Cannot read: {e}", "Ensure permissions to read account summary.")

    # IAM-014 Root access keys present
    try:
        summ = iam.get_account_summary()
        keys_present = bool(summ.get("SummaryMap", {}).get("AccountAccessKeysPresent", 0))
        add_finding(findings, "IAM-014", "Root access keys present", "Account", ["iam:GetAccountSummary"],
                    "BAD" if keys_present else "OK",
                    f"AccountAccessKeysPresent={keys_present}",
                    "Never use root access keys; remove if present.")
    except ClientError as e:
        add_finding(findings, "IAM-014", "Root access keys present", "Account", ["iam:GetAccountSummary"],
                    "WARN", f"Cannot read: {e}", "Ensure permissions.")

    # IAM-002 Password policy
    try:
        pol = iam.get_account_password_policy().get("PasswordPolicy", {})
        issues = []
        if pol.get("MinimumPasswordLength", 0) < 12: issues.append("MinLength<12")
        if not pol.get("RequireUppercaseCharacters", False): issues.append("NoUpper")
        if not pol.get("RequireLowercaseCharacters", False): issues.append("NoLower")
        if not pol.get("RequireNumbers", False): issues.append("NoNumber")
        if not pol.get("RequireSymbols", False): issues.append("NoSymbol")
        if pol.get("PasswordReusePrevention", 0) < 24: issues.append("ReusePrevention<24")
        if pol.get("MaxPasswordAge", 9999) > 90: issues.append("MaxAge>90")
        status = "OK" if not issues else "WARN"
        add_finding(findings, "IAM-002", "Password policy baseline", "Account", ["iam:GetAccountPasswordPolicy"],
                    status, f"Issues: {', '.join(issues) if issues else 'None'}",
                    "Set length≥12, require U/L/N/S, reuse history≥24, max age≤90 days.")
    except ClientError as e:
        add_finding(findings, "IAM-002", "Password policy baseline", "Account", ["iam:GetAccountPasswordPolicy"],
                    "WARN", f"No policy or cannot read: {e}",
                    "Define a strong account password policy.")

    # Collect users
    users: List[Dict[str, Any]] = []
    try:
        paginator = iam.get_paginator("list_users")
        for page in paginator.paginate():
            users.extend(page.get("Users", []))
    except ClientError as e:
        users = []
        add_finding(findings, "IAM-999", "List users failed", "Account", ["iam:ListUsers"],
                    "WARN", f"Cannot list users: {e}", "Ensure permissions.")

    # IAM-003 Users without MFA
    try:
        without_mfa = []
        for u in users:
            m = iam.list_mfa_devices(UserName=u["UserName"])
            if not m.get("MFADevices"):
                without_mfa.append(u["UserName"])
        status = "OK" if not without_mfa else "WARN"
        add_finding(findings, "IAM-003", "Users without MFA", "Users", ["iam:ListMFADevices"],
                    status, "None" if not without_mfa else f"No MFA: {', '.join(without_mfa)}",
                    "Enforce virtual/hardware MFA for all users.")
    except ClientError as e:
        add_finding(findings, "IAM-003", "Users without MFA", "Users", ["iam:ListMFADevices"],
                    "WARN", f"Cannot evaluate: {e}", "Ensure permissions to list MFA devices.")

    # IAM-004 Access keys older than N days
    try:
        old_keys: List[str] = []
        cutoff = datetime.now(timezone.utc) - timedelta(days=stale_days)
        for u in users:
            aks = iam.list_access_keys(UserName=u["UserName"]).get("AccessKeyMetadata", [])
            for k in aks:
                if k.get("CreateDate") and k["CreateDate"] < cutoff:
                    old_keys.append(f"{u['UserName']}:{k['AccessKeyId']}")
        add_finding(findings, "IAM-004", f"Access keys older than {stale_days} days", "Users", ["iam:ListAccessKeys"],
                    "OK" if not old_keys else "WARN",
                    "None" if not old_keys else f"Old keys: {', '.join(old_keys)}",
                    "Rotate or remove stale access keys.")
    except ClientError as e:
        add_finding(findings, "IAM-004", f"Access keys older than {stale_days} days", "Users", ["iam:ListAccessKeys"],
                    "WARN", f"Cannot list: {e}", "Ensure permissions.")

    # Collect groups & roles
    groups: List[Dict[str, Any]] = []
    try:
        paginator = iam.get_paginator("list_groups")
        for page in paginator.paginate():
            groups.extend(page.get("Groups", []))
    except ClientError:
        pass

    roles: List[Dict[str, Any]] = []
    try:
        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            roles.extend(page.get("Roles", []))
    except ClientError:
        pass

    # Helper to get attached managed policy ARNs
    def _attached_policies(entity_type: str, name: str) -> List[str]:
        arns: List[str] = []
        try:
            if entity_type == "user":
                paginator = iam.get_paginator("list_attached_user_policies")
                for p in paginator.paginate(UserName=name):
                    for ap in p.get("AttachedPolicies", []):
                        arns.append(ap.get("PolicyArn"))
            elif entity_type == "group":
                paginator = iam.get_paginator("list_attached_group_policies")
                for p in paginator.paginate(GroupName=name):
                    for ap in p.get("AttachedPolicies", []):
                        arns.append(ap.get("PolicyArn"))
            elif entity_type == "role":
                paginator = iam.get_paginator("list_attached_role_policies")
                for p in paginator.paginate(RoleName=name):
                    for ap in p.get("AttachedPolicies", []):
                        arns.append(ap.get("PolicyArn"))
        except ClientError:
            pass
        return [a for a in arns if a]

    # IAM-010 Admin policies attached
    try:
        admins: List[str] = []
        # users
        for u in users:
            for a in _attached_policies("user", u["UserName"]):
                if a.endswith("/AdministratorAccess"):
                    admins.append(f"user:{u['UserName']}")
                    break
        # groups
        for g in groups:
            for a in _attached_policies("group", g["GroupName"]):
                if a.endswith("/AdministratorAccess"):
                    admins.append(f"group:{g['GroupName']}")
                    break
        # roles
        for r in roles:
            for a in _attached_policies("role", r["RoleName"]):
                if a.endswith("/AdministratorAccess"):
                    admins.append(f"role:{r['RoleName']}")
                    break
        add_finding(findings, "IAM-010", "AdministratorAccess attached", "Users/Groups/Roles",
                    ["iam:ListAttached*Policies"], "WARN" if admins else "OK",
                    "None" if not admins else f"Admin policy on: {', '.join(admins)}",
                    "Replace with least-privilege custom policies.")
    except Exception as e:
        add_finding(findings, "IAM-010", "AdministratorAccess attached", "Users/Groups/Roles",
                    ["iam:ListAttached*Policies"], "WARN", f"Cannot evaluate: {e}",
                    "Ensure IAM permissions to list attached policies.")

    # Fetch policy documents (attached managed default versions + inline)
    def _policy_docs_for(entity_type: str, name: str) -> List[Dict[str, Any]]:
        docs: List[Dict[str, Any]] = []
        try:
            # managed
            for arn in _attached_policies(entity_type, name):
                pol = iam.get_policy(PolicyArn=arn)
                ver = pol.get("Policy", {}).get("DefaultVersionId")
                if ver:
                    doc = iam.get_policy_version(PolicyArn=arn, VersionId=ver).get("PolicyVersion", {}).get("Document")
                    if doc:
                        docs.append(doc)
            # inline
            if entity_type == "user":
                l = iam.list_user_policies(UserName=name).get("PolicyNames", [])
                for pn in l:
                    d = iam.get_user_policy(UserName=name, PolicyName=pn).get("PolicyDocument")
                    if d: docs.append(d)
            elif entity_type == "group":
                l = iam.list_group_policies(GroupName=name).get("PolicyNames", [])
                for pn in l:
                    d = iam.get_group_policy(GroupName=name, PolicyName=pn).get("PolicyDocument")
                    if d: docs.append(d)
            elif entity_type == "role":
                l = iam.list_role_policies(RoleName=name).get("PolicyNames", [])
                for pn in l:
                    d = iam.get_role_policy(RoleName=name, PolicyName=pn).get("PolicyDocument")
                    if d: docs.append(d)
        except ClientError:
            pass
        return docs

    # IAM-011 Wildcards in policies
    try:
        wildcarded: List[str] = []
        for u in users:
            for d in _policy_docs_for("user", u["UserName"]):
                for st in statements(d):
                    if action_contains_wildcard(st) or resource_contains_wildcard(st):
                        wildcarded.append(f"user:{u['UserName']}")
                        break
        for g in groups:
            for d in _policy_docs_for("group", g["GroupName"]):
                for st in statements(d):
                    if action_contains_wildcard(st) or resource_contains_wildcard(st):
                        wildcarded.append(f"group:{g['GroupName']}")
                        break
        for r in roles:
            for d in _policy_docs_for("role", r["RoleName"]):
                for st in statements(d):
                    if action_contains_wildcard(st) or resource_contains_wildcard(st):
                        wildcarded.append(f"role:{r['RoleName']}")
                        break
        uniq = sorted(set(wildcarded))
        add_finding(findings, "IAM-011", "Wildcards in policies", "Users/Groups/Roles",
                    ["iam:GetPolicyVersion","iam:Get*Policy"], "WARN" if uniq else "OK",
                    "None" if not uniq else f"Wildcards on: {', '.join(uniq)}",
                    "Replace '*' with explicit actions/resources; add conditions.")
    except Exception as e:
        add_finding(findings, "IAM-011", "Wildcards in policies", "Users/Groups/Roles",
                    ["iam:GetPolicyVersion","iam:Get*Policy"], "WARN", f"Cannot evaluate: {e}",
                    "Ensure permissions to read policy documents.")

    # IAM-012 Unscoped iam:PassRole
    try:
        offenders: List[str] = []
        for r in roles:
            for d in _policy_docs_for("role", r["RoleName"]):
                for st in statements(d):
                    if contains_unscoped_passrole(st):
                        offenders.append(r["RoleName"])
                        break
        add_finding(findings, "IAM-012", "Unscoped iam:PassRole in policies", "Roles",
                    ["iam:GetPolicyVersion","iam:GetRolePolicy"], "WARN" if offenders else "OK",
                    "None" if not offenders else f"Unscoped PassRole: {', '.join(offenders)}",
                    "Limit PassRole to explicit role ARNs with conditions.")
    except Exception as e:
        add_finding(findings, "IAM-012", "Unscoped iam:PassRole in policies", "Roles",
                    ["iam:GetPolicyVersion","iam:GetRolePolicy"], "WARN", f"Cannot evaluate: {e}",
                    "Ensure IAM permissions.")

    # IAM-013 Unused credentials (> N days)
    try:
        cutoff = datetime.now(timezone.utc) - timedelta(days=stale_days)
        unused: List[str] = []
        for u in users:
            # passwords
            pw_last = u.get("PasswordLastUsed")
            if pw_last and pw_last < cutoff:
                unused.append(f"password:{u['UserName']}")
            # keys
            aks = iam.list_access_keys(UserName=u["UserName"]).get("AccessKeyMetadata", [])
            for k in aks:
                last = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"]).get("AccessKeyLastUsed", {}).get("LastUsedDate")
                if last and last < cutoff:
                    unused.append(f"ak:{u['UserName']}:{k['AccessKeyId']}")
        add_finding(findings, "IAM-013", f"Unused credentials > {stale_days} days", "Users",
                    ["iam:GetAccessKeyLastUsed","iam:ListAccessKeys"], "WARN" if unused else "OK",
                    "None" if not unused else f"Stale: {', '.join(unused)}",
                    "Disable or remove unused credentials; prefer roles.")
    except ClientError as e:
        add_finding(findings, "IAM-013", "Unused credentials", "Users",
                    ["iam:GetAccessKeyLastUsed","iam:ListAccessKeys"], "WARN", f"Cannot evaluate: {e}",
                    "Ensure permissions.")

    meta = {
        "Service": "IAM",
        "Target": "account",
        "Region": region_hint or "—",
        "Profile": profile or "default",
        "TimeUTC": iso_now(),
    }
    aux = {"api_trace": api_trace}
    return meta, findings, aux


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LazyAWS IAM checker (account-level)")
    add_arguments(parser)
    args = parser.parse_args()
    run_check(analyze, args)
