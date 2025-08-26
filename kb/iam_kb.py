# -*- coding: utf-8 -*-

# IAM knowledge base used by check_report.py
# Each entry provides: 'what', 'positive', 'negative', 'remediation'

IAM_CHECK_CATALOG = {
    # Account / Root
    "IAM-001": {
        "what": (
            "Root MFA enabled.\n"
            "• What: Validate that MFA is enabled on the account root user.\n"
            "• Why: Root has unrestricted power; without MFA it's an outsized risk.\n"
            "• Attacker perspective: Compromised root (no MFA) means full account takeover."
        ),
        "positive": "Root MFA is enabled.",
        "negative": "Root MFA is not enabled.",
        "remediation": "Enable hardware MFA on root; avoid daily root usage."
    },
    "IAM-002": {
        "what": (
            "Root access keys present.\n"
            "• What: Confirm root has no active access keys.\n"
            "• Why: Root keys are high-risk long-lived credentials.\n"
            "• Attacker perspective: Any leaked root key enables unrestricted API access."
        ),
        "positive": "No active root access keys exist.",
        "negative": "Root has active access keys.",
        "remediation": "Delete any root access keys; use IAM roles/users instead."
    },
    "IAM-003": {
        "what": (
            "Root usage recency.\n"
            "• What: Detect recent root sign-in/API usage.\n"
            "• Why: Routine root usage is an anti-pattern.\n"
            "• Attacker perspective: Recent use increases the chance of poor operational practices to exploit."
        ),
        "positive": "Root not used within the configured threshold.",
        "negative": "Root used recently.",
        "remediation": "Eliminate day-to-day root usage; keep break-glass only with MFA."
    },
    "IAM-004": {
        "what": (
            "Account alias configured.\n"
            "• What: Presence of an account alias for clearer sign-in UX.\n"
            "• Why: Reduces phishing/mis-typing during console login.\n"
            "• Attacker perspective: Absent alias can increase social-engineering surface."
        ),
        "positive": "Account alias is set.",
        "negative": "No account alias configured.",
        "remediation": "Set a unique account alias."
    },

    # Password Policy
    "IAM-010": {
        "what": (
            "Password minimum length.\n"
            "• What: Check password policy MinimumPasswordLength.\n"
            "• Why: Longer passwords resist brute force and credential stuffing.\n"
            "• Attacker perspective: Weak minimums make online guessing cheaper."
        ),
        "positive": "Minimum length meets or exceeds standard (e.g., ≥ 14).",
        "negative": "Minimum length below standard, or no policy.",
        "remediation": "Set MinimumPasswordLength per your standard (e.g., 14+)."
    },
    "IAM-011": {
        "what": (
            "Password composition requirements.\n"
            "• What: Upper/lower/digit/symbol requirements.\n"
            "• Why: Composition controls reduce weak passwords.\n"
            "• Attacker perspective: Lax composition helps dictionary attacks."
        ),
        "positive": "All composition flags enabled (unless policy states otherwise).",
        "negative": "One or more flags disabled.",
        "remediation": "Enable composition requirements or enforce via IdP."
    },
    "IAM-012": {
        "what": (
            "Password reuse prevention.\n"
            "• What: Prevent reuse of last N passwords.\n"
            "• Why: Mitigates cycling back to a known-compromised secret.\n"
            "• Attacker perspective: Easier to predict/reuse old passwords."
        ),
        "positive": "Reuse prevention threshold met (e.g., ≥ 24).",
        "negative": "History too small or not enforced.",
        "remediation": "Increase PasswordReusePrevention."
    },
    "IAM-013": {
        "what": (
            "Max password age.\n"
            "• What: Require periodic changes per your policy.\n"
            "• Why: Limits exposure window if secret leaked.\n"
            "• Attacker perspective: Long-lived passwords = more time to exploit."
        ),
        "positive": "MaxPasswordAge ≤ policy threshold (e.g., 90 days).",
        "negative": "Age not enforced or too high.",
        "remediation": "Set MaxPasswordAge as required by policy."
    },
    "IAM-014": {
        "what": (
            "Allow users to change own password.\n"
            "• What: Self-service password change.\n"
            "• Why: Encourages hygiene and quicker rotations.\n"
            "• Attacker perspective: Disabled self-service may foster insecure workarounds."
        ),
        "positive": "Users can change passwords.",
        "negative": "Self-service disabled.",
        "remediation": "Allow controlled self-service or via IdP."
    },

    # MFA Coverage
    "IAM-020": {
        "what": (
            "MFA coverage for console users.\n"
            "• What: Users with console password must have MFA.\n"
            "• Why: Reduces credential-stuffing success.\n"
            "• Attacker perspective: Password-only accounts are easy targets."
        ),
        "positive": "All console users have MFA.",
        "negative": "Some console users lack MFA.",
        "remediation": "Enforce MFA enrollment and conditional access."
    },
    "IAM-021": {
        "what": (
            "MFA required for privileged users.\n"
            "• What: Admins/operators must use MFA.\n"
            "• Why: Admin accounts are prime targets.\n"
            "• Attacker perspective: Privileged without MFA = rapid full compromise."
        ),
        "positive": "All privileged users have MFA.",
        "negative": "One or more privileged users lack MFA.",
        "remediation": "Mandate MFA for admin groups and directly attached admin policies."
    },
    "IAM-022": {
        "what": (
            "Root MFA device type (informational).\n"
            "• What: Virtual vs hardware preference.\n"
            "• Why: Hardware often considered stronger.\n"
            "• Attacker perspective: Weaker factors are easier to phish/clone."
        ),
        "positive": "Hardware MFA on root (policy-dependent).",
        "negative": "Virtual or unknown.",
        "remediation": "Use hardware MFA for root per policy."
    },

    # Access Keys Hygiene
    "IAM-030": {
        "what": (
            "Active access key rotation age.\n"
            "• What: Age of active keys vs rotation threshold.\n"
            "• Why: Long-lived keys expand blast radius.\n"
            "• Attacker perspective: Old keys likely spread across tooling and are hard to revoke everywhere."
        ),
        "positive": "All active keys rotated within policy window.",
        "negative": "Some active keys exceed rotation window.",
        "remediation": "Rotate keys regularly; prefer STS."
    },
    "IAM-031": {
        "what": (
            "Stale inactive keys present.\n"
            "• What: Presence of inactive keys that should be removed.\n"
            "• Why: Reduces clutter and confusion in audits.\n"
            "• Attacker perspective: Operational mistakes may inadvertently reactivate."
        ),
        "positive": "No stale inactive keys exist.",
        "negative": "Inactive keys still present.",
        "remediation": "Delete unused/inactive keys."
    },
    "IAM-032": {
        "what": (
            "More than one active key per user.\n"
            "• What: Detect two active keys simultaneously.\n"
            "• Why: Doubles exposure and complicates rotation.\n"
            "• Attacker perspective: More credentials to steal/use."
        ),
        "positive": "≤ 1 active key per user.",
        "negative": "Users with two active keys.",
        "remediation": "Keep only one active key; rotate properly."
    },
    "IAM-033": {
        "what": (
            "Unused access keys (last used > N days).\n"
            "• What: Keys not used recently or ever.\n"
            "• Why: Unused secrets are unnecessary risk.\n"
            "• Attacker perspective: ‘Forgotten’ keys are low-hanging fruit if leaked."
        ),
        "positive": "No unused keys beyond threshold.",
        "negative": "Some keys unused beyond threshold.",
        "remediation": "Disable/delete unused keys; migrate to STS."
    },

    # User Hygiene
    "IAM-040": {
        "what": (
            "Dormant users (no activity > N days).\n"
            "• What: Detect users without recent sign-in or key use.\n"
            "• Why: Dormant accounts are prime lateral-movement footholds.\n"
            "• Attacker perspective: Less monitored identities to hijack."
        ),
        "positive": "No dormant users beyond threshold.",
        "negative": "Dormant users detected.",
        "remediation": "Disable or remove dormant users; use break-glass patterns sparingly."
    },
    "IAM-041": {
        "what": (
            "Console users without group membership.\n"
            "• What: Users with passwords but not in any group.\n"
            "• Why: Encourages user-level policy sprawl.\n"
            "• Attacker perspective: Hidden direct grants are harder to audit/revoke."
        ),
        "positive": "All console users are managed via groups.",
        "negative": "Users with passwords but no groups.",
        "remediation": "Move privileges to groups/roles."
    },
    "IAM-042": {
        "what": (
            "Users with inline policies.\n"
            "• What: Inline policies attached directly to users.\n"
            "• Why: Hard to review/version; promotes drift.\n"
            "• Attacker perspective: Easier to hide excessive privileges."
        ),
        "positive": "No inline policies on users.",
        "negative": "Inline policies present.",
        "remediation": "Migrate to managed policies."
    },

    # Roles & Trust
    "IAM-050": {
        "what": (
            "Roles with broad trust principal ('*').\n"
            "• What: Trust policies that allow any principal.\n"
            "• Why: Overly broad trust invites abuse.\n"
            "• Attacker perspective: Alternate path to assume privileged roles."
        ),
        "positive": "No wildcard principals.",
        "negative": "One or more roles trust '*'.",
        "remediation": "Constrain trust to specific accounts/services/IdPs with conditions."
    },
    "IAM-051": {
        "what": (
            "Cross-account trust without ExternalId/OrgID condition.\n"
            "• What: Trusts to foreign accounts lacking confused-deputy mitigations.\n"
            "• Why: Prevents unintended assumption via third parties.\n"
            "• Attacker perspective: Abuse of shared integrations to assume roles."
        ),
        "positive": "ExternalId or PrincipalOrgID enforced for cross-account.",
        "negative": "Cross-account trust lacks these conditions.",
        "remediation": "Add sts:ExternalId or aws:PrincipalOrgID conditions."
    },
    "IAM-052": {
        "what": (
            "Admin-like roles without MFA requirement in trust policy.\n"
            "• What: Human-assumable admin roles should require MFA.\n"
            "• Why: Reduces impact of password-only compromises.\n"
            "• Attacker perspective: Password reuse/phish enables admin session without MFA."
        ),
        "positive": "MFA requirement present.",
        "negative": "No MFA condition in trust policy.",
        "remediation": "Add aws:MultiFactorAuthPresent condition to admin roles."
    },
    "IAM-053": {
        "what": (
            "Roles unused > N days.\n"
            "• What: Use RoleLastUsed to detect stale roles.\n"
            "• Why: Reduces attack surface and confusion.\n"
            "• Attacker perspective: Dormant roles go unnoticed if abused."
        ),
        "positive": "No stale roles beyond threshold.",
        "negative": "Stale roles detected.",
        "remediation": "Remove/archive unused roles."
    },
    "IAM-054": {
        "what": (
            "Instance profiles without roles.\n"
            "• What: Orphaned profiles increase confusion.\n"
            "• Why: Unused identities complicate audits.\n"
            "• Attacker perspective: Misused profiles can reattach to gain access."
        ),
        "positive": "No orphaned instance profiles.",
        "negative": "Orphaned profiles exist.",
        "remediation": "Delete or attach appropriate roles."
    },

    # Policies Content
    "IAM-060": {
        "what": (
            "Customer managed policies with wildcard actions.\n"
            "• What: Detect Action:'*' or service wildcards.\n"
            "• Why: Violates least privilege.\n"
            "• Attacker perspective: Easier escalation and lateral movement."
        ),
        "positive": "No wildcard actions.",
        "negative": "Wildcard actions present.",
        "remediation": "Replace with explicit actions."
    },
    "IAM-061": {
        "what": (
            "Customer managed policies allowing Resource:'*'.\n"
            "• What: Allow statements with global resources.\n"
            "• Why: Grants too broad access to resources.\n"
            "• Attacker perspective: Generic tokens can touch many resources."
        ),
        "positive": "Resources constrained to ARNs.",
        "negative": "Resource:'*' in allows.",
        "remediation": "Constrain resources; add conditions."
    },
    "IAM-062": {
        "what": (
            "iam:PassRole without resource/conditions.\n"
            "• What: Unscoped PassRole allows passing any role.\n"
            "• Why: Can chain into privilege escalation.\n"
            "• Attacker perspective: Pass arbitrary high-privilege roles to services."
        ),
        "positive": "PassRole limited to specific ARNs with conditions.",
        "negative": "Unscoped PassRole detected.",
        "remediation": "Scope resources and add conditions."
    },
    "IAM-063": {
        "what": (
            "sts:AssumeRole with Resource:'*'.\n"
            "• What: Broad AssumeRole grants.\n"
            "• Why: Enables arbitrary role assumption.\n"
            "• Attacker perspective: Jumping into sensitive accounts/roles."
        ),
        "positive": "AssumeRole constrained to specific ARNs.",
        "negative": "Broad AssumeRole detected.",
        "remediation": "Restrict resources; add conditions (MFA/SourceIdentity)."
    },
    "IAM-064": {
        "what": (
            "Inline policies inventory on principals.\n"
            "• What: Users/Roles/Groups with inline policies.\n"
            "• Why: Hard to review/version; drift risk.\n"
            "• Attacker perspective: Hide excessive grants in inline docs."
        ),
        "positive": "Minimal/no inline policies.",
        "negative": "Inline policies present.",
        "remediation": "Migrate to managed policies."
    },
    "IAM-065": {
        "what": (
            "Customer managed policy versions near/at limit (5).\n"
            "• What: Number of non-default versions.\n"
            "• Why: Hitting limit blocks updates; clutter risk.\n"
            "• Attacker perspective: Version sprawl complicates reviews."
        ),
        "positive": "≤ 3 versions typically.",
        "negative": "4 (near) or 5 (at limit).",
        "remediation": "Delete unused versions."
    },

    # Admin Sprawl / Boundaries
    "IAM-070": {
        "what": (
            "Principals with AdministratorAccess.\n"
            "• What: Users/Roles/Groups attached to admin policy.\n"
            "• Why: Expands blast radius.\n"
            "• Attacker perspective: Any compromise yields full control."
        ),
        "positive": "Minimal admins per policy.",
        "negative": "Many administrators present.",
        "remediation": "Reduce admins; prefer scoped roles and JIT elevation."
    },
    "IAM-071": {
        "what": (
            "Permissions boundaries usage (assessment).\n"
            "• What: Whether boundaries are used where required.\n"
            "• Why: Boundaries cap maximum permissions.\n"
            "• Attacker perspective: Without boundaries, policy mistakes escalate further."
        ),
        "positive": "Boundaries used per org standard.",
        "negative": "Not evaluated or not used.",
        "remediation": "Adopt boundaries per policy."
    },
    "IAM-072": {
        "what": (
            "Administrators ratio among principals.\n"
            "• What: Admin count / (users+roles).\n"
            "• Why: High ratio indicates privilege sprawl.\n"
            "• Attacker perspective: More privileged identities to target."
        ),
        "positive": "Low admin ratio (e.g., < 10%).",
        "negative": "Admin ratio high.",
        "remediation": "Constrain admins; enforce RBAC."
    },

    # Access Analyzer
    "IAM-080": {
        "what": (
            "Access Analyzer presence and active findings.\n"
            "• What: Analyzer exists and findings triage.\n"
            "• Why: Detects unintended external access in policies.\n"
            "• Attacker perspective: Misconfigurations expose resources cross-account/public."
        ),
        "positive": "Analyzer enabled with zero active findings.",
        "negative": "No analyzer or active findings exist.",
        "remediation": "Enable analyzer and resolve findings."
    },
    "IAM-081": {
        "what": (
            "Service last accessed details for custom policies (optional).\n"
            "• What: Analyze unused services/actions.\n"
            "• Why: Rightsizing to least privilege.\n"
            "• Attacker perspective: Excess permissions ease lateral movement."
        ),
        "positive": "Unused permissions identified and pruned.",
        "negative": "Not evaluated or stale permissions remain.",
        "remediation": "Run last-accessed and trim policies."
    },

    # Sessions & Misc
    "IAM-090": {
        "what": (
            "Role MaxSessionDuration threshold.\n"
            "• What: Roles set to long sessions (e.g., > 12h).\n"
            "• Why: Longer sessions extend compromise window.\n"
            "• Attacker perspective: Longer time to operate undetected."
        ),
        "positive": "Human roles limited to short sessions (1–4h).",
        "negative": "Excessively long sessions allowed.",
        "remediation": "Reduce MaxSessionDuration and require MFA."
    },
    "IAM-091": {
        "what": (
            "STS endpoint/org policy posture (informational).\n"
            "• What: Regional vs global STS usage via governance.\n"
            "• Why: Regional constraints may be required.\n"
            "• Attacker perspective: Global endpoints can bypass region guardrails."
        ),
        "positive": "Regional STS enforced where required.",
        "negative": "Not enforced or not evaluated.",
        "remediation": "Enforce regional STS via SCP if policy demands."
    },
}
