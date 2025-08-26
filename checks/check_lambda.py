#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LazyAWS - Lambda checks (single function)

Checks:
  LAMBDA-001 Function URL publicly accessible (AuthType=NONE)
  LAMBDA-002 Resource policy wildcards (Principal='*')
  LAMBDA-003 Dead-letter queue configured
  LAMBDA-004 Async event invoke config present (retries/backoff)
  LAMBDA-005 Env vars contain secrets (heuristic)
  LAMBDA-006 X-Ray tracing enabled
  LAMBDA-007 VPC configured (best practice for private data paths)
  LAMBDA-010 Role policies: admin/wildcards/unscoped PassRole
  LAMBDA-011 Reserved concurrency set
  LAMBDA-012 Runtime EOL (heuristic list)
  LAMBDA-013 Log group retention configured
  LAMBDA-014 Code signing config attached
  LAMBDA-015 Layer policies public (*)
"""

from __future__ import annotations

import argparse
import json
import re
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from aws_common import (
    get_session,
    get_traced_client,
    run_check,
    OK, WARN, BAD, NA,
)

# ----------- helpers -----------

SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",                    # Access Key ID
    r"(?i)secret[_-]?key\s*[:=]\s*['\"][^'\"\n]{12,}['\"]",
    r"(?i)password\s*[:=]\s*['\"][^'\"\n]{6,}['\"]",
    r"(?i)token\s*[:=]\s*['\"][^'\"\n]{8,}['\"]",
    r"-----BEGIN[ A-Z]*PRIVATE KEY-----",
]

EOL_RUNTIMES = [
    # heuristic; extend as needed
    "nodejs12.x", "nodejs10.x", "nodejs8.10",
    "python3.6", "python3.7", "python3.8",
    "dotnetcore2.1", "dotnetcore1.0",
    "ruby2.5", "go1.x-legacy",
]

def iso_now() -> str:
    from datetime import datetime, timezone
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

# ----------- module -----------

def add_arguments(ap: argparse.ArgumentParser):
    ap.add_argument("--function-name", required=True, help="Lambda function name to check.")
    ap.add_argument("--region", required=True, help="AWS region of the function.")
    ap.add_argument("--profile", default=None, help="AWS profile name.")

def analyze(args):
    fn = args.function_name
    region = args.region
    profile = args.profile

    api_trace: List[Dict[str, Any]] = []
    sess = get_session(profile, region)
    lmb = get_traced_client(sess, "lambda", api_trace, profile, region)
    iam = get_traced_client(sess, "iam", api_trace, profile, None)
    logs = get_traced_client(sess, "logs", api_trace, profile, region)

    findings: List[Dict[str, Any]] = []

    # Base config
    try:
        cfg = lmb.get_function_configuration(FunctionName=fn)
    except ClientError as e:
        meta = {
            "Service": "Lambda",
            "Target": fn,
            "Region": region,
            "Profile": profile or "default",
            "TimeUTC": iso_now(),
        }
        add_finding(findings, "LAMBDA-999", "Unable to get function configuration", "Function",
                    ["lambda:GetFunctionConfiguration"], "BAD", f"Error: {e}", "Ensure IAM permissions and correct function name.")
        aux = {"api_trace": api_trace}
        return meta, findings, aux

    # LAMBDA-001 Function URL publicly accessible
    try:
        url = lmb.get_function_url_config(FunctionName=fn)
        auth = url.get("AuthType")
        status = "BAD" if auth == "NONE" else "OK"
        add_finding(findings, "LAMBDA-001", "Function URL publicly accessible", "FunctionURL",
                    ["lambda:GetFunctionUrlConfig"], status, f"AuthType={auth}", "Avoid AuthType=NONE; use IAM/AWS_IAM or remove URL.")
    except ClientError:
        add_finding(findings, "LAMBDA-001", "Function URL publicly accessible", "FunctionURL",
                    ["lambda:GetFunctionUrlConfig"], "OK", "No URL configuration", "Prefer private access patterns unless required.")

    # LAMBDA-002 Resource-based policy wildcards
    try:
        pol_resp = lmb.get_policy(FunctionName=fn)
        pol = json.loads(pol_resp.get("Policy", "{}"))
        wide = False
        for st in statements(pol):
            princ = st.get("Principal")
            if princ == "*" or (isinstance(princ, dict) and (princ.get("AWS") == "*" or princ.get("Service") == "*")):
                if str(st.get("Effect")).lower() == "allow":
                    wide = True
                    break
        add_finding(findings, "LAMBDA-002", "Resource policy wildcards", "FunctionPolicy",
                    ["lambda:GetPolicy"], "BAD" if wide else "OK",
                    "Principal='*' in Allow" if wide else "No obvious wildcard principals.",
                    "Restrict principals and scope with SourceArn/SourceAccount.")
    except ClientError:
        add_finding(findings, "LAMBDA-002", "Resource policy wildcards", "FunctionPolicy",
                    ["lambda:GetPolicy"], "OK", "No policy attached", "Attach strictly-scoped permissions only if required.")

    # LAMBDA-003 Dead-letter queue
    dlq = cfg.get("DeadLetterConfig")
    add_finding(findings, "LAMBDA-003", "Dead-letter queue configured", "Function",
                ["lambda:GetFunctionConfiguration"],
                "OK" if dlq else "WARN", f"DeadLetterConfig={bool(dlq)}",
                "Configure DLQ (SQS/SNS) to capture failed async invocations.")

    # LAMBDA-004 Async event invoke config
    try:
        eic = lmb.get_function_event_invoke_config(FunctionName=fn)
        retry = eic.get("MaximumRetryAttempts")
        add_finding(findings, "LAMBDA-004", "Async invoke config (retries/backoff)", "Function",
                    ["lambda:GetFunctionEventInvokeConfig"], "OK" if retry is not None else "WARN",
                    f"MaximumRetryAttempts={retry}", "Set reasonable retry/batch settings; avoid infinite retries.")
    except ClientError:
        add_finding(findings, "LAMBDA-004", "Async invoke config (retries/backoff)", "Function",
                    ["lambda:GetFunctionEventInvokeConfig"], "WARN", "Not configured",
                    "Set MaxRetryAttempts and, if needed, MaximumEventAgeInSeconds.")

    # LAMBDA-005 Env vars secrets (heuristic)
    env = (cfg.get("Environment") or {}).get("Variables") or {}
    env_str = json.dumps(env, ensure_ascii=False)
    has_secret = any(re.search(p, env_str) for p in SECRET_PATTERNS)
    add_finding(findings, "LAMBDA-005", "Environment variables contain secrets (heuristic)", "Function",
                ["lambda:GetFunctionConfiguration"], "WARN" if has_secret else "OK",
                "Secret-like patterns found." if has_secret else "No obvious secrets in environment.",
                "Move secrets to Secrets Manager/SSM Parameter Store; use IAM-scoped fetch at runtime.")

    # LAMBDA-006 X-Ray tracing
    tracing = (cfg.get("TracingConfig") or {}).get("Mode")
    add_finding(findings, "LAMBDA-006", "X-Ray tracing enabled", "Function",
                ["lambda:GetFunctionConfiguration"], "OK" if tracing == "Active" else "WARN",
                f"TracingMode={tracing}", "Enable Active tracing for critical paths.")

    # LAMBDA-007 VPC config
    vpc = cfg.get("VpcConfig") or {}
    vpc_ok = bool(vpc.get("SubnetIds") and vpc.get("SecurityGroupIds"))
    add_finding(findings, "LAMBDA-007", "VPC configuration", "Function",
                ["lambda:GetFunctionConfiguration"], "OK" if vpc_ok else "WARN",
                "Configured" if vpc_ok else "Not configured",
                "Attach to private subnets if function accesses private resources.")

    # LAMBDA-010 Role policy hygiene
    role_arn = cfg.get("Role")
    if role_arn and ":" in role_arn and "/" in role_arn:
        role_name = role_arn.split("/")[-1]
        # Admin?
        try:
            lap = iam.list_attached_role_policies(RoleName=role_name)
            has_admin = any((p.get("PolicyArn","").endswith("/AdministratorAccess") for p in lap.get("AttachedPolicies", [])))
            add_finding(findings, "LAMBDA-010", "Role has AdministratorAccess", "Role",
                        ["iam:ListAttachedRolePolicies"], "WARN" if has_admin else "OK",
                        "AdministratorAccess attached." if has_admin else "No AdministratorAccess.",
                        "Replace with least-privilege custom policies.")
        except ClientError as e:
            add_finding(findings, "LAMBDA-010", "Role has AdministratorAccess", "Role",
                        ["iam:ListAttachedRolePolicies"], "WARN", f"Cannot read: {e}",
                        "Ensure IAM permissions.")

        # Wildcards / PassRole
        try:
            docs: List[Dict[str, Any]] = []
            # attached managed policies
            for ap in (lap.get("AttachedPolicies", []) if 'lap' in locals() and isinstance(lap, dict) else []):
                arn = ap.get("PolicyArn")
                if not arn:
                    continue
                pol = iam.get_policy(PolicyArn=arn)
                ver = pol.get("Policy", {}).get("DefaultVersionId")
                if ver:
                    v = iam.get_policy_version(PolicyArn=arn, VersionId=ver)
                    d = v.get("PolicyVersion", {}).get("Document")
                    if d:
                        docs.append(d)
            # inline
            for pn in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                d = iam.get_role_policy(RoleName=role_name, PolicyName=pn).get("PolicyDocument")
                if d: docs.append(d)

            wc = False
            passrole_unscoped = False
            for d in docs:
                for st in statements(d):
                    if action_contains_wildcard(st) or resource_contains_wildcard(st):
                        wc = True
                    if contains_unscoped_passrole(st):
                        passrole_unscoped = True

            add_finding(findings, "LAMBDA-010", "Role policies contain wildcards", "Role",
                        ["iam:GetPolicyVersion","iam:GetRolePolicy"],
                        "WARN" if wc else "OK",
                        "Wildcards present." if wc else "No wildcards detected.",
                        "Replace '*' with explicit actions/resources; add conditions.")
            add_finding(findings, "LAMBDA-010", "Unscoped iam:PassRole in role policies", "Role",
                        ["iam:GetPolicyVersion","iam:GetRolePolicy"],
                        "WARN" if passrole_unscoped else "OK",
                        "Unscoped PassRole present." if passrole_unscoped else "PassRole appears scoped.",
                        "Limit PassRole to explicit role ARNs with conditions.")
        except ClientError as e:
            add_finding(findings, "LAMBDA-010", "Role policy analysis", "Role",
                        ["iam:GetPolicyVersion","iam:GetRolePolicy"], "WARN", f"Cannot analyze: {e}",
                        "Ensure IAM permissions.")
    else:
        add_finding(findings, "LAMBDA-010", "Role policy analysis", "Role",
                    ["iam:*"], "NA", "No role ARN associated.", "Attach a least-privilege role.")

    # LAMBDA-011 Reserved concurrency
    try:
        rc = lmb.get_function_concurrency(FunctionName=fn)
        reserved = rc.get("ReservedConcurrentExecutions")
        add_finding(findings, "LAMBDA-011", "Reserved concurrency set", "Function",
                    ["lambda:GetFunctionConcurrency"], "OK" if reserved is not None else "WARN",
                    f"ReservedConcurrentExecutions={reserved}",
                    "Set reserved concurrency to avoid noisy-neighbour & throttle blast radius.")
    except ClientError:
        add_finding(findings, "LAMBDA-011", "Reserved concurrency set", "Function",
                    ["lambda:GetFunctionConcurrency"], "WARN", "Not configured",
                    "Set reserved concurrency per function.")

    # LAMBDA-012 Runtime EOL (heuristic)
    rt = cfg.get("Runtime")
    is_eol = rt in EOL_RUNTIMES
    add_finding(findings, "LAMBDA-012", "Runtime EOL (heuristic)", "Function",
                ["lambda:GetFunctionConfiguration"], "WARN" if is_eol else "OK",
                f"Runtime={rt}", "Migrate to a supported runtime.")

    # LAMBDA-013 Log group retention
    try:
        lg_name = f"/aws/lambda/{fn}"
        d = logs.describe_log_groups(logGroupNamePrefix=lg_name, limit=1)
        lgs = d.get("logGroups", [])
        if lgs and lgs[0].get("logGroupName") == lg_name:
            retention = lgs[0].get("retentionInDays")
            add_finding(findings, "LAMBDA-013", "Log retention configured", "Logs",
                        ["logs:DescribeLogGroups"], "OK" if retention else "WARN",
                        f"retentionInDays={retention}", "Set retention (e.g., 30/90 days) to control costs & exposure.")
        else:
            add_finding(findings, "LAMBDA-013", "Log retention configured", "Logs",
                        ["logs:DescribeLogGroups"], "WARN", "Log group not found.",
                        "Create log group with explicit retention or let Lambda create then adjust.")
    except ClientError as e:
        add_finding(findings, "LAMBDA-013", "Log retention configured", "Logs",
                    ["logs:DescribeLogGroups"], "WARN", f"Cannot read: {e}", "Ensure logs:DescribeLogGroups permission.")

    # LAMBDA-014 Code signing config
    try:
        gf = lmb.get_function(FunctionName=fn)
        csc = gf.get("Configuration", {}).get("CodeSigningConfigArn")
        add_finding(findings, "LAMBDA-014", "Code signing config attached", "Function",
                    ["lambda:GetFunction"], "OK" if csc else "WARN",
                    f"CodeSigningConfigArn={csc}", "Attach CSC to enforce signed code.")
    except ClientError as e:
        add_finding(findings, "LAMBDA-014", "Code signing config attached", "Function",
                    ["lambda:GetFunction"], "WARN", f"Cannot read: {e}", "Ensure permissions.")

    # LAMBDA-015 Layer policies public
    try:
        layers = cfg.get("Layers") or []
        public_layers: List[str] = []
        for l in layers:
            arn = l.get("Arn") or ""
            # arn:aws:lambda:region:acct:layer:name:version
            parts = arn.split(":")
            if len(parts) >= 8 and parts[6] == "layer":
                name = parts[7]
                version = int(parts[8]) if len(parts) > 8 and parts[8].isdigit() else None
                if version is not None:
                    try:
                        pol = lmb.get_layer_version_policy(LayerName=name, VersionNumber=version)
                        doc = json.loads(pol.get("Policy", "{}"))
                        for st in statements(doc):
                            p = st.get("Principal")
                            if p == "*" or (isinstance(p, dict) and (p.get("AWS") == "*" or p.get("Service") == "*")):
                                if str(st.get("Effect")).lower() == "allow":
                                    public_layers.append(f"{name}:{version}")
                                    break
                    except ClientError:
                        # no policy or forbidden -> ignore
                        pass
        add_finding(findings, "LAMBDA-015", "Layer policies public (*)", "Layers",
                    ["lambda:GetLayerVersionPolicy"], "WARN" if public_layers else "OK",
                    "Public layers: " + ", ".join(public_layers) if public_layers else "No public layer policies detected.",
                    "Avoid public layer policies unless intentionally shared.")
    except Exception as e:
        add_finding(findings, "LAMBDA-015", "Layer policies public (*)", "Layers",
                    ["lambda:GetLayerVersionPolicy"], "WARN", f"Cannot evaluate: {e}",
                    "Review layer policies and limit principals.")

    meta = {
        "Service": "Lambda",
        "Target": fn,
        "Region": region,
        "Profile": profile or "default",
        "TimeUTC": iso_now(),
    }
    aux = {"api_trace": api_trace}
    return meta, findings, aux


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LazyAWS Lambda checker (single function)")
    add_arguments(parser)
    args = parser.parse_args()
    run_check(analyze, args)
