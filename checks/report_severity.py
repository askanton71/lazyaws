# -*- coding: utf-8 -*-
from __future__ import annotations
import re
from typing import Dict

DEFAULT_SEVERITY = "Medium"

ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

def strip_ansi(s: str) -> str:
    return ANSI_RE.sub("", s or "")

# --- normalize outcome (handles icons, text, ANSI) ---
def _normalize_outcome_from_value(v: str) -> str:
    s = strip_ansi(v).strip().lower()
    if not s:
        return ""
    # common icons
    if s in ("✓", "ok", "pass", "passed", "success"):
        return "OK"
    if s in ("!", "warn", "warning", "⚠"):
        return "WARN"
    if s in ("✗", "x", "bad", "fail", "failed", "error"):
        return "BAD"
    if s in ("—", "-", "na", "n/a", "info", "informational"):
        return "N/A"
    # text fragments
    if "ok" in s or "pass" in s:
        return "OK"
    if "warn" in s or "⚠" in s:
        return "WARN"
    if "bad" in s or "fail" in s or "error" in s:
        return "BAD"
    if "n/a" in s or s == "na" or "inform" in s:
        return "N/A"
    return s.upper()

def get_outcome(finding: dict) -> str:
    for key in ("StatusPlain", "Status", "status", "outcome"):
        if key in finding and finding[key] is not None:
            return _normalize_outcome_from_value(str(finding[key]))
    return ""


# ---------- baseline severity per check code ----------
# S3 (aim to cover ~S3-001..S3-020)
BASE_SEVERITY: Dict[str, str] = {
    # Public exposure / access control
    "S3-001": "High",   # Public bucket/ACL/policy/website (any public data-path)
    "S3-002": "Medium", # Account-level BPA disabled/missing (s3control)
    "S3-003": "Medium", # Object Ownership not 'BucketOwnerEnforced' (ACLs enabled)
    "S3-004": "High",   # Bucket ACL grants public or cross-account write
    # Encryption / data protection
    "S3-005": "Medium", # Default encryption not KMS (only SSE-S3/AES256)
    "S3-016": "Medium", # Object-level encryption not KMS for sample object(s)
    # Resilience / governance
    "S3-006": "Low",    # Versioning disabled
    "S3-007": "Low",    # Lifecycle rules missing
    "S3-008": "Low",    # Lifecycle: Abort incomplete MPU missing
    "S3-009": "Medium", # Server access logging disabled
    # Policy hardening
    "S3-010": "Medium", # No TLS-enforcement (aws:SecureTransport)
    "S3-011": "Medium", # No policy requiring SSE-KMS on PutObject
    # Features / posture
    "S3-012": "High",   # Website hosting enabled & publicly reachable
    "S3-013": "Medium", # CORS overly permissive (e.g., "*")
    "S3-014": "Low",    # Replication not configured (business-dependent)
    "S3-015": "Low",    # Notifications present but not KMS-encrypted / lax target policy
    "S3-017": "High",   # Public via bucket policy (explicit Allow to everyone)
    "S3-018": "Medium", # OwnershipControls missing (legacy ACLs in use)
    "S3-019": "Medium", # BlockPublicAccess partially disabled (any flag False)
    "S3-020": "Low",    # Misc posture info / informational

    # EC2 (cover 000..080 that we use)
    "EC2-000": "Low",     # No instances found (info)
    "EC2-001": "Medium",  # Public IP attached (context can raise)
    "EC2-002": "High",    # SG world-open on sensitive ports
    "EC2-003": "High",    # SG world-open ALL ports
    "EC2-004": "Medium",  # SG wide egress (0.0.0.0/0 or ::/0)
    "EC2-006": "Medium",  # Subnet has IGW route (public subnet)
    "EC2-010": "Medium",  # IMDSv2 not required
    "EC2-011": "Low",     # IMDS hop limit > 1
    "EC2-012": "Low",     # No instance profile attached
    "EC2-013": "High",    # Instance role has AdministratorAccess
    "EC2-014": "High",    # Role policies contain wildcards
    "EC2-015": "High",    # Unscoped iam:PassRole
    "EC2-020": "Medium",  # Account default EBS enc disabled
    "EC2-021": "High",    # Attached volumes unencrypted
    "EC2-024": "High",    # Public AMI owned by you
    "EC2-025": "Low",     # AMI owner not in allowlist
    "EC2-027": "Low",     # DeleteOnTermination misaligned
    "EC2-030": "High",    # Secrets detected in UserData (heuristic)
    "EC2-031": "Medium",  # curl|bash in UserData
    "EC2-040": "Low",     # Not managed by SSM
    "EC2-041": "Medium",  # Patch non-compliant / unknown
    "EC2-050": "Medium",  # VPC Flow Logs disabled
    "EC2-051": "Low",     # CloudWatch agent not detected (heuristic)
    "EC2-060": "Medium",  # Termination protection disabled (critical ↑)
    "EC2-061": "Low",     # Shutdown behavior misaligned
    "EC2-070": "Medium",  # SSH key pair present (prefer SSM)

    # IAM (cover 001..020 incl. gaps 010+)
    "IAM-001": "Critical", # Root MFA disabled
    "IAM-002": "High",     # Root access keys present
    "IAM-003": "High",     # Admin* policies attached broadly
    "IAM-004": "High",     # Wildcards in Action/Resource
    "IAM-010": "Medium",   # Weak password policy
    "IAM-011": "Medium",   # Access keys age > 90 days
    "IAM-012": "Medium",   # Inactive users / no recent activity
    "IAM-013": "High",     # Unscoped iam:PassRole
    "IAM-014": "High",     # AssumeRole trust without restrictive Condition
    "IAM-015": "High",     # Console users without MFA
    "IAM-016": "Medium",   # Access Analyzer external trust findings present
    "IAM-017": "Medium",   # Inline policies on users (governance)
    "IAM-018": "Medium",   # Access key rotation disabled/org policy gaps
    "IAM-019": "Medium",   # Password reuse/expiration policy weak
    "IAM-020": "Low",      # Informational posture

    # Lambda (cover 001..020)
    "LAMBDA-001": "High",   # Public Function URL without auth
    "LAMBDA-002": "High",   # Plaintext secrets in env (heuristic)
    "LAMBDA-003": "Medium", # No reserved concurrency (DoS blast radius)
    "LAMBDA-004": "High",   # Execution role wildcards/Admin
    "LAMBDA-005": "Low",    # X-Ray tracing disabled
    "LAMBDA-006": "Medium", # No KMS key for env encryption
    "LAMBDA-007": "High",   # In public subnets / SG wide-open (egress/ingress)
    "LAMBDA-008": "Medium", # No DLQ (SNS/SQS) for async invocations
    "LAMBDA-009": "Low",    # Timeout/memory too high (cost/stability)
    "LAMBDA-010": "High",   # Runtime EOL/outdated
    "LAMBDA-011": "Medium", # Code signing not enforced
    "LAMBDA-012": "Medium", # Function URL CORS overly permissive
    "LAMBDA-013": "Medium", # Outdated/vulnerable layer(s)
    "LAMBDA-014": "Low",    # No VPC where required (data egress control)
    "LAMBDA-015": "Medium", # EFS access without IAM/KMS controls
    "LAMBDA-016": "Low",    # No description/tags/owner metadata
    "LAMBDA-017": "Medium", # Permissions allow cross-account invoke
    "LAMBDA-018": "Medium", # Unpinned dependency versions (SBOM/IA)
    "LAMBDA-019": "Low",    # No alarms/metrics for errors/throttles
    "LAMBDA-020": "Low",    # Informational posture
}

def infer_check_code(check_text: str) -> str:
    if not check_text:
        return "GEN-000"
    m = re.match(r'^\s*([A-Z]{2,12}-\d{3})\b', str(check_text).strip())
    return m.group(1) if m else "GEN-000"

def severity_for(code: str, finding: dict) -> str:
    outcome = get_outcome(finding)
    if outcome in ("OK",):
        return "OK"
    if outcome in ("N/A", "INFO"):
        return "N/A"

    sev = BASE_SEVERITY.get(code, DEFAULT_SEVERITY)
    details = (finding.get("Details") or "").lower()
    check_text = (finding.get("Check") or "").lower()

    # ---- contextual raises ----
    if code in ("EC2-002","EC2-003"):
        if "all ports" in details or "all-port" in details or "wildcard ingress" in details:
            sev = "Critical"
        if "0.0.0.0/0" in details or "::/0" in details:
            if sev != "Critical":
                sev = "High"
    if code == "EC2-010" and ("public ip" in details or "publicipv4" in details):
        sev = "High"
    if code == "EC2-021" and ("unencrypted" in details or "not encrypted" in details):
        sev = "High"
    if code == "EC2-060" and ("prod" in details or "critical" in details):
        sev = "High"

    if code in ("S3-005","S3-016"):
        if "no default encryption" in details or "server side encryption: none" in details:
            sev = "High"
    if code == "S3-010" and ("public" in details or "website" in details):
        sev = "High"
    if code == "S3-011" and ("billing" in details or "exports" in details or "pii" in details):
        sev = "High"

    if code == "IAM-010":
        if "minlength<" in details or "no mfa" in details or "password expiration: disabled" in details:
            sev = "High"

    if code == "LAMBDA-001" and ("no auth" in details or "public url" in details):
        sev = "High"
    if code == "LAMBDA-002" and ("secret" in details or "password" in details):
        sev = "High"

    return sev
