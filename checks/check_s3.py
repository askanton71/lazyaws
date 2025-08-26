#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LazyAWS - S3 checks (single bucket)

This module evaluates one bucket per run (runner.py робить enumerate/runall).
It relies on get_traced_client() to auto-capture CLI-like request/response into api_trace.

Checks included (examples):
  S3-001 Public access block (bucket)
  S3-002 Account Public Access Block (s3control)
  S3-003 Object Ownership (BucketOwnerEnforced)
  S3-004 Bucket ACL (no public grants)
  S3-005 Default encryption (prefer KMS)
  S3-006 Versioning enabled
  S3-007 Lifecycle rules present
  S3-008 Lifecycle: Abort incomplete MPU present
  S3-009 Server access logging enabled
  S3-010 Policy: Enforce TLS
  S3-011 Policy: Enforce KMS on PutObject
  S3-012 Website hosting disabled
  S3-013 CORS minimal / absent
  S3-014 Replication status
  S3-015 Notifications targets presence
  S3-016 Sample object encryption (prefer KMS)
  S3-017 Policy status (not public)
  S3-018 OwnershipControls present
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from botocore.exceptions import ClientError

from aws_common import (
    get_session,
    get_traced_client,
    run_check,
    OK, WARN, BAD, NA,
)

# ------------------------------ helpers ------------------------------

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

def get_bucket_region(s3_client, bucket: str) -> Optional[str]:
    # S3_get_bucket_location returns None or "EU"/region codes; normalize
    resp = s3_client.get_bucket_location(Bucket=bucket)
    loc = resp.get("LocationConstraint")
    if loc == "EU":  # legacy for eu-west-1
        return "eu-west-1"
    return loc or "us-east-1"

def _policy_has_tls_enforce(policy: Dict[str, Any], bucket_arn: str) -> bool:
    # Look for Deny when aws:SecureTransport == false
    stmts = policy.get("Statement", [])
    if not isinstance(stmts, list):
        stmts = [stmts]
    for s in stmts:
        if str(s.get("Effect")).lower() != "deny":
            continue
        cond = s.get("Condition", {})
        # StringEquals or Bool variants used in some templates
        val = (
            cond.get("Bool", {}).get("aws:SecureTransport") or
            cond.get("StringEquals", {}).get("aws:SecureTransport") or
            cond.get("NumericEquals", {}).get("aws:SecureTransport")
        )
        if str(val).lower() in ("false", "0"):
            # scope to this bucket or objects
            res = s.get("Resource")
            if not res:
                return True
            resources = res if isinstance(res, list) else [res]
            if any(r.startswith(bucket_arn) for r in resources):
                return True
    return False

def _policy_requires_kms_on_put(policy: Dict[str, Any], bucket_arn: str) -> bool:
    # Detect Deny for PutObject that lacks KMS SSE headers
    stmts = policy.get("Statement", [])
    if not isinstance(stmts, list):
        stmts = [stmts]
    for s in stmts:
        if str(s.get("Effect")).lower() != "deny":
            continue
        act = s.get("Action")
        acts = act if isinstance(act, list) else [act]
        if not any(str(a).lower().endswith("putobject") for a in acts):
            continue
        cond = s.get("Condition", {})
        # Require x-amz-server-side-encryption == aws:kms
        if (
            "StringNotEquals" in cond and
            "s3:x-amz-server-side-encryption" in cond["StringNotEquals"] and
            cond["StringNotEquals"]["s3:x-amz-server-side-encryption"] in ("aws:kms", "aws:kms:dsse")
        ):
            res = s.get("Resource")
            resources = res if isinstance(res, list) else [res]
            if any(r.startswith(f"{bucket_arn}/") or r == f"{bucket_arn}/*" for r in resources):
                return True
    return False

# ------------------------------ module ------------------------------

def add_arguments(ap: argparse.ArgumentParser):
    ap.add_argument("--bucket", required=True, help="S3 bucket name to check.")
    ap.add_argument("--profile", default=None, help="AWS profile name.")
    ap.add_argument("--region", default=None, help="Preferred region hint (bucket actual region will be resolved).")
    ap.add_argument("--sample-prefix", default=None, help="Optional key prefix to pick a sample object for SSE check.")

def analyze(args):
    bucket = args.bucket
    profile = args.profile
    region_hint = args.region

    api_trace: List[Dict[str, Any]] = []
    sess = get_session(profile, region_hint)
    s3 = get_traced_client(sess, "s3", api_trace, profile, None)  # regionless for some APIs
    s3control = get_traced_client(sess, "s3control", api_trace, profile, None)
    sts = get_traced_client(sess, "sts", api_trace, profile, None)

    findings: List[Dict[str, Any]] = []

    # resolve bucket region
    try:
        bucket_region = get_bucket_region(s3, bucket)
    except ClientError as e:
        bucket_region = region_hint or "—"

    # For region-specific calls, create a regional S3
    s3r = get_traced_client(sess, "s3", api_trace, profile, bucket_region)

    # Account id (for s3control & policy sanity)
    try:
        ident = sts.get_caller_identity()
        account_id = ident.get("Account")
    except Exception:
        account_id = None

    # S3-001 Public Access Block (bucket)
    try:
        pab = s3r.get_public_access_block(Bucket=bucket)
        cfg = pab.get("PublicAccessBlockConfiguration", {})
        flags = [cfg.get("BlockPublicAcls"), cfg.get("IgnorePublicAcls"),
                 cfg.get("BlockPublicPolicy"), cfg.get("RestrictPublicBuckets")]
        status = "OK" if all(flags) else "WARN"
        details = " ".join([f"BlockPublicAcls={cfg.get('BlockPublicAcls')}",
                            f"IgnorePublicAcls={cfg.get('IgnorePublicAcls')}",
                            f"BlockPublicPolicy={cfg.get('BlockPublicPolicy')}",
                            f"RestrictPublicBuckets={cfg.get('RestrictPublicBuckets')}"])
        add_finding(findings, "S3-001", "Bucket Public Access Block", "Bucket", ["s3:GetPublicAccessBlock"],
                    status, details, "Ensure all four BPA flags are true.")
    except ClientError as e:
        add_finding(findings, "S3-001", "Bucket Public Access Block", "Bucket", ["s3:GetPublicAccessBlock"],
                    "WARN", f"Cannot read: {e}", "Enable BPA on bucket.")

    # S3-002 Account-level Public Access Block
    if account_id:
        try:
            pab2 = s3control.get_public_access_block(AccountId=account_id)
            cfg = pab2.get("PublicAccessBlockConfiguration", {})
            flags = [cfg.get("BlockPublicAcls"), cfg.get("IgnorePublicAcls"),
                     cfg.get("BlockPublicPolicy"), cfg.get("RestrictPublicBuckets")]
            status = "OK" if all(flags) else "WARN"
            details = " ".join([f"BlockPublicAcls={cfg.get('BlockPublicAcls')}",
                                f"IgnorePublicAcls={cfg.get('IgnorePublicAcls')}",
                                f"BlockPublicPolicy={cfg.get('BlockPublicPolicy')}",
                                f"RestrictPublicBuckets={cfg.get('RestrictPublicBuckets')}"])
            add_finding(findings, "S3-002", "Account BPA (s3control)", "Account", ["s3control:GetPublicAccessBlock"],
                        status, details, "Consider enabling account-wide BPA.")
        except ClientError as e:
            add_finding(findings, "S3-002", "Account BPA (s3control)", "Account", ["s3control:GetPublicAccessBlock"],
                        "WARN", f"Cannot read: {e}", "Consider enabling account-wide BPA.")
    else:
        add_finding(findings, "S3-002", "Account BPA (s3control)", "Account", ["s3control:GetPublicAccessBlock"],
                    "NA", "AccountId unknown.", "Run with permissions to STS:GetCallerIdentity.")

    # S3-003 OwnershipControls
    try:
        oc = s3r.get_bucket_ownership_controls(Bucket=bucket)
        rules = oc.get("OwnershipControls", {}).get("Rules", [])
        oo = rules[0].get("ObjectOwnership") if rules else None
        status = "OK" if oo == "BucketOwnerEnforced" else "WARN"
        add_finding(findings, "S3-003", "Object Ownership", "Bucket", ["s3:GetBucketOwnershipControls"],
                    status, f"ObjectOwnership={oo}", "Use BucketOwnerEnforced to disable ACLs.")
    except ClientError as e:
        add_finding(findings, "S3-003", "Object Ownership", "Bucket", ["s3:GetBucketOwnershipControls"],
                    "WARN", f"Cannot read: {e}", "Enable BucketOwnerEnforced if possible.")

    # S3-004 Bucket ACL
    try:
        acl = s3r.get_bucket_acl(Bucket=bucket)
        grants = acl.get("Grants", [])
        public = any(
            (g.get("Grantee", {}).get("URI") in (
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"))
            for g in grants
        )
        status = "BAD" if public else "OK"
        add_finding(findings, "S3-004", "Bucket ACL", "Bucket", ["s3:GetBucketAcl"],
                    status, "Public grants present." if public else "Owner-only ACL; no public grants.",
                    "Keep ACLs disabled/minimal; prefer BucketOwnerEnforced.")
    except ClientError as e:
        add_finding(findings, "S3-004", "Bucket ACL", "Bucket", ["s3:GetBucketAcl"],
                    "WARN", f"Cannot read: {e}", "Prefer ACLs disabled with OwnershipControls.")

    # S3-005 Default encryption
    try:
        enc = s3r.get_bucket_encryption(Bucket=bucket)
        rule = enc["ServerSideEncryptionConfiguration"]["Rules"][0]["ApplyServerSideEncryptionByDefault"]
        alg = rule.get("SSEAlgorithm")
        status = "WARN" if alg == "AES256" else "OK"
        add_finding(findings, "S3-005", "Default encryption", "Bucket", ["s3:GetBucketEncryption"],
                    status, f"SSEAlgorithm={alg}",
                    "Prefer SSE-KMS with CMK for sensitive data.")
    except ClientError as e:
        add_finding(findings, "S3-005", "Default encryption", "Bucket", ["s3:GetBucketEncryption"],
                    "WARN", f"No default encryption or cannot read: {e}",
                    "Enable default encryption, preferably SSE-KMS (CMK).")

    # S3-006 Versioning
    try:
        ver = s3r.get_bucket_versioning(Bucket=bucket)
        st = ver.get("Status")
        status = "OK" if st == "Enabled" else "WARN"
        add_finding(findings, "S3-006", "Versioning", "Bucket", ["s3:GetBucketVersioning"],
                    status, f"Status={st or 'NotConfigured'}", "Enable versioning for recovery.")
    except ClientError as e:
        add_finding(findings, "S3-006", "Versioning", "Bucket", ["s3:GetBucketVersioning"],
                    "WARN", f"Cannot read: {e}", "Enable versioning for recovery.")

    # S3-007 Lifecycle
    try:
        lc = s3r.get_bucket_lifecycle_configuration(Bucket=bucket)
        rules = lc.get("Rules", [])
        status = "OK" if rules else "WARN"
        add_finding(findings, "S3-007", "Lifecycle rules", "Bucket", ["s3:GetBucketLifecycleConfiguration"],
                    status, f"{len(rules)} rule(s) configured." if rules else "No lifecycle rules.",
                    "Configure lifecycle (transition/expiration/Abort MPU).")
        # S3-008 Abort MPU
        has_abort = any("AbortIncompleteMultipartUpload" in (r.get("AbortIncompleteMultipartUpload") or r.get("NoncurrentVersionTransitions") or {}) or
                        r.get("AbortIncompleteMultipartUpload")
                        for r in rules)
        add_finding(findings, "S3-008", "Lifecycle: Abort MPU", "Bucket", ["s3:GetBucketLifecycleConfiguration"],
                    "OK" if has_abort else "WARN", "AbortIncompleteMultipartUpload present." if has_abort else "Unknown/Not set.",
                    "Add AbortIncompleteMultipartUpload to lifecycle.")
    except ClientError:
        add_finding(findings, "S3-007", "Lifecycle rules", "Bucket", ["s3:GetBucketLifecycleConfiguration"],
                    "WARN", "No lifecycle or cannot read.", "Configure lifecycle policies.")
        add_finding(findings, "S3-008", "Lifecycle: Abort MPU", "Bucket", ["s3:GetBucketLifecycleConfiguration"],
                    "WARN", "Unknown", "Add AbortIncompleteMultipartUpload to lifecycle.")

    # S3-009 Server access logging
    try:
        lg = s3r.get_bucket_logging(Bucket=bucket)
        enabled = bool(lg.get("LoggingEnabled"))
        add_finding(findings, "S3-009", "Server access logging", "Bucket", ["s3:GetBucketLogging"],
                    "OK" if enabled else "WARN",
                    "Enabled" if enabled else "Disabled",
                    "Enable server access logging or CloudTrail Data Events for S3.")
    except ClientError as e:
        add_finding(findings, "S3-009", "Server access logging", "Bucket", ["s3:GetBucketLogging"],
                    "WARN", f"Cannot read: {e}", "Enable S3 access logs / CT data events.")

    # S3-010/011 bucket policy rules
    policy_doc = None
    bucket_arn = f"arn:aws:s3:::{bucket}"
    try:
        pol = s3r.get_bucket_policy(Bucket=bucket)
        policy_doc = json.loads(pol.get("Policy", "{}"))
    except ClientError as e:
        policy_doc = None

    if policy_doc:
        tls_ok = _policy_has_tls_enforce(policy_doc, bucket_arn)
        add_finding(findings, "S3-010", "Bucket policy: Enforce TLS", "BucketPolicy", ["s3:GetBucketPolicy"],
                    "OK" if tls_ok else "WARN",
                    f"Deny aws:SecureTransport=false = {bool(tls_ok)}",
                    "Add TLS-enforcement Deny if missing.")
        kms_ok = _policy_requires_kms_on_put(policy_doc, bucket_arn)
        add_finding(findings, "S3-011", "Bucket policy: Enforce KMS on PutObject", "BucketPolicy", ["s3:GetBucketPolicy"],
                    "OK" if kms_ok else "WARN",
                    f"Deny non-KMS uploads = {bool(kms_ok)}",
                    "Add Deny for PutObject without aws:kms SSE.")
    else:
        add_finding(findings, "S3-010", "Bucket policy: Enforce TLS", "BucketPolicy", ["s3:GetBucketPolicy"],
                    "WARN", "Policy not found or unreadable.", "Add TLS-enforcement Deny.")
        add_finding(findings, "S3-011", "Bucket policy: Enforce KMS on PutObject", "BucketPolicy", ["s3:GetBucketPolicy"],
                    "WARN", "Policy not found or unreadable.", "Add Deny for PutObject without KMS SSE.")

    # S3-012 Website
    try:
        s3r.get_bucket_website(Bucket=bucket)
        add_finding(findings, "S3-012", "Website hosting", "Bucket", ["s3:GetBucketWebsite"],
                    "WARN", "Configured", "Keep disabled unless needed.")
    except ClientError:
        add_finding(findings, "S3-012", "Website hosting", "Bucket", ["s3:GetBucketWebsite"],
                    "OK", "Not configured", "Keep disabled unless needed.")

    # S3-013 CORS
    try:
        cors = s3r.get_bucket_cors(Bucket=bucket)
        rules = cors.get("CORSRules", [])
        status = "WARN" if rules else "OK"
        add_finding(findings, "S3-013", "CORS", "Bucket", ["s3:GetBucketCors"],
                    status, f"{len(rules)} rule(s) present." if rules else "Not configured",
                    "Keep minimal CORS; add only if required.")
    except ClientError:
        add_finding(findings, "S3-013", "CORS", "Bucket", ["s3:GetBucketCors"],
                    "OK", "Not configured", "Keep minimal CORS; add only if required.")

    # S3-014 Replication
    try:
        rep = s3r.get_bucket_replication(Bucket=bucket)
        add_finding(findings, "S3-014", "Replication", "Bucket", ["s3:GetBucketReplication"],
                    "OK", "Replication configured.", "Ensure CRR/SRR meets business RPO/RTO.")
    except ClientError:
        add_finding(findings, "S3-014", "Replication", "Bucket", ["s3:GetBucketReplication"],
            "NA", "No replication", "Configure if business requires CRR/SRR.")

    # S3-015 Notifications
    try:
        notif = s3r.get_bucket_notification_configuration(Bucket=bucket)
        has_any = any([
            notif.get("TopicConfigurations"),
            notif.get("QueueConfigurations"),
            notif.get("LambdaFunctionConfigurations"),
        ])
        add_finding(findings, "S3-015", "Notifications (SNS/SQS/Lambda)", "Bucket", ["s3:GetBucketNotification"],
                    "OK" if has_any else "NA", "Present" if has_any else "None",
                    "Ensure targets are KMS-encrypted and access policies are strict.")
    except ClientError:
        add_finding(findings, "S3-015", "Notifications (SNS/SQS/Lambda)", "Bucket", ["s3:GetBucketNotification"],
                    "NA", "Cannot read", "Ensure proper permissions and strict target policies.")

    # S3-016 Sample object encryption
    # Pick object: either by --sample-prefix or the very first one
    sample_key = None
    try:
        if args.sample_prefix:
            page = s3r.list_objects_v2(Bucket=bucket, Prefix=args.sample_prefix, MaxKeys=1)
        else:
            page = s3r.list_objects_v2(Bucket=bucket, MaxKeys=1)
        c = (page or {}).get("Contents") or []
        if c:
            sample_key = c[0]["Key"]
    except ClientError:
        sample_key = None
    if sample_key:
        try:
            head = s3r.head_object(Bucket=bucket, Key=sample_key)
            sse = head.get("ServerSideEncryption")
            status = "WARN" if sse == "AES256" else "OK"
            add_finding(findings, "S3-016", "Object encryption (sample)", "Object", ["s3:HeadObject"],
                        status, f"Key={sample_key} ServerSideEncryption={sse}",
                        "Prefer KMS for sensitive objects.")
        except ClientError as e:
            add_finding(findings, "S3-016", "Object encryption (sample)", "Object", ["s3:HeadObject"],
                        "NA", f"Cannot read: {e}", "Ensure permissions or supply --sample-prefix.")
    else:
        add_finding(findings, "S3-016", "Object encryption (sample)", "Object", ["s3:ListObjectsV2/s3:HeadObject"],
                    "NA", "No sample object found.", "Provide --sample-prefix to target known object prefix.")

    # S3-017 Policy status (public?)
    try:
        ps = s3r.get_bucket_policy_status(Bucket=bucket)
        is_public = bool(ps.get("PolicyStatus", {}).get("IsPublic"))
        add_finding(findings, "S3-017", "Policy status (public)", "BucketPolicy", ["s3:GetBucketPolicyStatus"],
                    "BAD" if is_public else "OK", f"IsPublic={is_public}",
                    "Avoid bucket policies that render bucket public.")
    except ClientError:
        add_finding(findings, "S3-017", "Policy status (public)", "BucketPolicy", ["s3:GetBucketPolicyStatus"],
                    "NA", "Cannot read", "Ensure permission; verify policies with Access Analyzer.")

    # S3-018 OwnershipControls present
    # (Covered partly by S3-003; here we mark NA if we couldn't read it explicitly)
    # Already done.

    meta = {
        "Service": "S3",
        "Target": bucket,
        "Region": bucket_region or "—",
        "Profile": profile or "default",
        "TimeUTC": iso_now(),
    }
    aux = {"api_trace": api_trace}
    return meta, findings, aux

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LazyAWS S3 checker (single bucket)")
    add_arguments(parser)
    args = parser.parse_args()
    run_check(analyze, args)
