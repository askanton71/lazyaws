# -*- coding: utf-8 -*-

"""
Lambda knowledge base for LazyAWS report.
Each entry provides:
  - 'what': Deep description + attacker perspective
  - 'positive': Expected good result
  - 'negative': Bad result
  - 'remediation': Concrete fix guidance
"""

LAMBDA_CHECK_CATALOG = {

    # Inventory / Exposure
    "LAMBDA-001": {
        "what": (
            "Public Function URL exposure.\n"
            "• What: Checks if the Lambda Function URL exists and whether AuthType is NONE.\n"
            "• Why: Public URLs without auth allow anyone to execute your code and exfiltrate or mutate data.\n"
            "• Attacker perspective: Direct, anonymous invoke for data theft, crypto-mining, or DoS with cost impact."
        ),
        "positive": "No Function URL or AuthType=AWS_IAM with upstream WAF.",
        "negative": "AuthType=NONE (publicly callable).",
        "remediation": "Disable the URL or switch to AuthType=AWS_IAM; protect with WAF and throttle at the edge."
    },
    "LAMBDA-004": {
        "what": (
            "CORS allow-list on Function URL.\n"
            "• What: Verifies CORS config does not use wildcard origins.\n"
            "• Why: Wildcards let any website read responses in a user's browser context.\n"
            "• Attacker perspective: Steal sensitive data via the victim's browser through malicious origins."
        ),
        "positive": "AllowOrigins is a strict list of trusted domains; methods/headers minimized.",
        "negative": "AllowOrigins contains '*', or overly broad methods/headers.",
        "remediation": "Replace '*' with specific origins; use least-privilege methods/headers."
    },

    # Resource policy
    "LAMBDA-002": {
        "what": (
            "Resource policy wildcard principals.\n"
            "• What: Detects 'Principal: \"*\"' on function/alias/version resource policy.\n"
            "• Why: Unrestricted invoke or management across accounts/anonymous.\n"
            "• Attacker perspective: Direct invoke or policy tampering from any principal."
        ),
        "positive": "Principals are limited to required accounts/services.",
        "negative": "Principal uses '*' or equivalent broadness.",
        "remediation": "Constrain Principal; prefer account-specific ARNs and service principals only as needed."
    },
    "LAMBDA-003": {
        "what": (
            "Service principals missing SourceArn/SourceAccount.\n"
            "• What: Ensures S3/EventBridge/SNS statements include both guards to prevent confused-deputy.\n"
            "• Why: Without these, foreign accounts may trigger your function.\n"
            "• Attacker perspective: Abuse third-party integrations to generate invokes in your account."
        ),
        "positive": "All service-principal statements have SourceArn and SourceAccount conditions.",
        "negative": "Any service-principal statement without those guards.",
        "remediation": "Add aws:SourceArn and aws:SourceAccount conditions to each relevant statement."
    },

    # Runtime / Code integrity
    "LAMBDA-010": {
        "what": (
            "Deprecated/EOL runtime in use.\n"
            "• What: Compares runtime to a configured EOL list.\n"
            "• Why: EOL runtimes lack patches → RCE/exploit risk.\n"
            "• Attacker perspective: Known CVEs in VM/stdlib/deps to gain code execution."
        ),
        "positive": "Runtime is supported and up-to-date.",
        "negative": "Runtime appears in EOL list.",
        "remediation": "Upgrade runtime; fix deprecations and re-deploy."
    },
    "LAMBDA-011": {
        "what": (
            "Code signing enforcement.\n"
            "• What: Verifies a Code Signing Config (CSC) is attached.\n"
            "• Why: Prevents untrusted code/package versions from deployment.\n"
            "• Attacker perspective: Supply-chain injection without CSC."
        ),
        "positive": "CSC is configured with trusted publishers.",
        "negative": "No CSC attached.",
        "remediation": "Create CSC and require trusted signing profiles."
    },
    "LAMBDA-012": {
        "what": (
            "Third-party / external layers.\n"
            "• What: Lists layers from other AWS accounts.\n"
            "• Why: External layers can be malicious or outdated.\n"
            "• Attacker perspective: Poison updates via a layer version hijack."
        ),
        "positive": "No external layers, or they are vetted and pinned.",
        "negative": "One or more external layers present.",
        "remediation": "Mirror layers to an internal account; pin exact versions; scan frequently."
    },
    "LAMBDA-013": {
        "what": (
            "Container image scanning (ECR).\n"
            "• What: Ensures ECR image has scan findings summary.\n"
            "• Why: Detects CVEs/secrets before deploy.\n"
            "• Attacker perspective: Unscanned images ship vulnerabilities."
        ),
        "positive": "ECR scan summary exists; policy gates on severity.",
        "negative": "No scan summary or scanning disabled.",
        "remediation": "Enable scan-on-push & block deploys with high/critical CVEs."
    },

    # Secrets / Environment
    "LAMBDA-020": {
        "what": (
            "Plaintext secrets in ENV.\n"
            "• What: Heuristics for secret-looking keys/values in environment variables.\n"
            "• Why: ENV may leak via logs, errors, or memory dumps.\n"
            "• Attacker perspective: Read secrets from ENV or logs to pivot."
        ),
        "positive": "No secret-looking ENV; secrets fetched at runtime from a vault.",
        "negative": "ENV includes probable secrets.",
        "remediation": "Move to Secrets Manager/SSM; never log ENV; rotate exposed secrets."
    },
    "LAMBDA-021": {
        "what": (
            "ENV encryption with CMK.\n"
            "• What: Checks KmsKeyArn presence to prefer customer-managed keys.\n"
            "• Why: CMK provides isolation, audit, rotation control.\n"
            "• Attacker perspective: Broader AWS-managed keys ease abuse."
        ),
        "positive": "KmsKeyArn set to a CMK with tight key policy.",
        "negative": "No CMK (default AWS-managed).",
        "remediation": "Encrypt ENV with CMK; enforce key policy and grants."
    },
    "LAMBDA-022": {
        "what": (
            "Role permission to decrypt ENV CMK.\n"
            "• What: Verifies function role allows kms:Decrypt on the ENV CMK.\n"
            "• Why: Prevents runtime failures and avoids workarounds weakening security.\n"
            "• Attacker perspective: Misconfigs lead to ad-hoc broad key grants later."
        ),
        "positive": "Role has kms:Decrypt on specific CMK with conditions.",
        "negative": "No explicit kms:Decrypt found (or relies solely on key policy).",
        "remediation": "Grant minimal kms:Decrypt to the role for the CMK with strict conditions."
    },

    # IAM Role / Permissions
    "LAMBDA-030": {
        "what": (
            "AdministratorAccess on function role.\n"
            "• What: Detects the AWS managed Admin policy on the role.\n"
            "• Why: Compromise of code = full account takeover.\n"
            "• Attacker perspective: Immediate escalated operations via the role."
        ),
        "positive": "No AdministratorAccess attached.",
        "negative": "AdministratorAccess present.",
        "remediation": "Replace with minimal custom policies for required actions."
    },
    "LAMBDA-031": {
        "what": (
            "Wildcard actions/resources in role policies.\n"
            "• What: Flags '*' in Action or Resource across inline/managed policies.\n"
            "• Why: Violates least privilege, eases lateral movement.\n"
            "• Attacker perspective: Abuse '*' to reach unrelated services/resources."
        ),
        "positive": "Explicit actions and ARNs with conditions.",
        "negative": "Wildcards present.",
        "remediation": "Replace wildcards with concrete actions/resources; add conditions."
    },
    "LAMBDA-032": {
        "what": (
            "Unscoped iam:PassRole.\n"
            "• What: Detects PassRole with Resource:'*' and no conditions.\n"
            "• Why: Lets code pass arbitrary roles to services.\n"
            "• Attacker perspective: Escalate by passing privileged roles."
        ),
        "positive": "PassRole restricted to specific ARNs with conditions.",
        "negative": "Unscoped PassRole detected.",
        "remediation": "Limit to explicit ARNs; add conditions (ResourceTags, etc.)."
    },
    "LAMBDA-033": {
        "what": (
            "Role trust policy scope.\n"
            "• What: Ensures only lambda.amazonaws.com (and edgelambda) can assume the role.\n"
            "• Why: Prevents other services/accounts from assuming the function role.\n"
            "• Attacker perspective: AssumeRole from unintended principals."
        ),
        "positive": "Trust strictly limited to Lambda service.",
        "negative": "Trust allows non-Lambda or wildcard principals.",
        "remediation": "Restrict trust to Lambda and required services only."
    },

    # Networking / VPC
    "LAMBDA-040": {
        "what": (
            "VPC usage where required.\n"
            "• What: Function associated with private subnets and SGs when policy demands egress control.\n"
            "• Why: Public egress by default otherwise.\n"
            "• Attacker perspective: Easier data exfiltration if not in VPC."
        ),
        "positive": "Function runs in private subnets with controlled egress.",
        "negative": "No VPC association (when required).",
        "remediation": "Attach to VPC; route via NAT/proxy; restrict SG egress."
    },
    "LAMBDA-041": {
        "what": (
            "Security group wide egress.\n"
            "• What: Detects 0.0.0.0/0 or ::/0 egress.\n"
            "• Why: Facilitates exfiltration and C2.\n"
            "• Attacker perspective: Unrestricted outbound to the internet."
        ),
        "positive": "Egress constrained to specific CIDRs/ports.",
        "negative": "Wide egress present.",
        "remediation": "Tighten SG egress; consider egress proxy/firewall."
    },
    "LAMBDA-042": {
        "what": (
            "Public subnets (IGW route).\n"
            "• What: Subnets with route to an Internet Gateway.\n"
            "• Why: Increases exposure to the public internet.\n"
            "• Attacker perspective: Direct egress path from function ENIs."
        ),
        "positive": "Private subnets without IGW routes.",
        "negative": "Subnets routed to IGW.",
        "remediation": "Use private subnets; egress via NAT and VPC endpoints for AWS APIs."
    },

    # Triggers / Event sources
    "LAMBDA-050": {
        "what": (
            "S3 triggers without SourceArn/SourceAccount.\n"
            "• What: Resource policy statements for S3 principal must have both guards.\n"
            "• Why: Avoids cross-account abuse.\n"
            "• Attacker perspective: Foreign buckets invoke your function."
        ),
        "positive": "S3 principals guarded by SourceArn & SourceAccount.",
        "negative": "Missing one/both guards.",
        "remediation": "Add both conditions to all S3 principal statements."
    },
    "LAMBDA-051": {
        "what": (
            "Event sources not encrypted (SQS/Kinesis/DynamoDB).\n"
            "• What: Checks KMS at rest on queues/streams/tables feeding the function.\n"
            "• Why: Reduces data exposure in transit/storage.\n"
            "• Attacker perspective: Read raw sensitive events from unencrypted sources."
        ),
        "positive": "SQS/Kinesis/DynamoDB sources use KMS encryption.",
        "negative": "One or more sources lack encryption.",
        "remediation": "Enable service-level KMS encryption for each event source."
    },
    "LAMBDA-052": {
        "what": (
            "EventBridge broad match patterns.\n"
            "• What: Detects overly permissive rules targeting the function.\n"
            "• Why: Prevents noisy or abusive event injection.\n"
            "• Attacker perspective: Trigger your code via generic patterns."
        ),
        "positive": "Event patterns are tight (specific source/detail-type).",
        "negative": "Rules without patterns or with broad patterns.",
        "remediation": "Constrain patterns; add SourceAccount conditions where applicable."
    },
    "LAMBDA-053": {
        "what": (
            "S3 notifications without filters.\n"
            "• What: Keys prefixes/suffixes should filter events to relevant objects.\n"
            "• Why: Avoids cost/DoS by flooding with irrelevant keys.\n"
            "• Attacker perspective: Spam uploads to trigger excessive invocations."
        ),
        "positive": "S3 notifications use key filters.",
        "negative": "No filters (all objects).",
        "remediation": "Add filters for expected prefixes/suffixes."
    },

    # Async / Reliability
    "LAMBDA-060": {
        "what": (
            "On-failure destination / DLQ for async invokes.\n"
            "• What: Ensures failed events land in DLQ or OnFailure destination.\n"
            "• Why: Forensics & reliability.\n"
            "• Attacker perspective: Hide malicious activity in lost events."
        ),
        "positive": "DLQ or OnFailure destination configured.",
        "negative": "No failure destination configured.",
        "remediation": "Set DLQ (SQS) or OnFailure (SNS/SQS) with KMS."
    },
    "LAMBDA-061": {
        "what": (
            "Excessive async retries.\n"
            "• What: High retries amplify DoS and side effects.\n"
            "• Attacker perspective: Increase cost/impact by forcing repeated failures."
        ),
        "positive": "Retries capped at a low number (e.g., ≤ 2).",
        "negative": "High MaximumRetryAttempts.",
        "remediation": "Set sensible retry caps; implement idempotency; alert on failures."
    },

    # Observability
    "LAMBDA-070": {
        "what": (
            "CloudWatch Logs retention.\n"
            "• What: Checks that log group has finite retention meeting policy.\n"
            "• Why: Too short loses forensics; infinite causes cost/noise.\n"
            "• Attacker perspective: Short retention hides traces."
        ),
        "positive": "Retention configured to org standard (e.g., 90–365 days).",
        "negative": "No retention or below minimum.",
        "remediation": "Set retention days per policy."
    },
    "LAMBDA-071": {
        "what": (
            "X-Ray tracing enabled.\n"
            "• What: Tracing=Active on sensitive workflows.\n"
            "• Why: Aids incident response and performance analysis.\n"
            "• Attacker perspective: Lack of traces reduces detection."
        ),
        "positive": "TracingConfig.Mode=Active.",
        "negative": "Tracing disabled.",
        "remediation": "Enable Active tracing; protect traces."
    },
    "LAMBDA-072": {
        "what": (
            "Logging secrets heuristic.\n"
            "• What: Static check is hard; recommend scrubbers and redaction.\n"
            "• Why: Secrets in logs persist beyond rotation.\n"
            "• Attacker perspective: Mine logs for tokens/keys."
        ),
        "positive": "Sensitive fields redacted at source.",
        "negative": "Raw secrets appear in logs.",
        "remediation": "Adopt structured logging and redaction middleware."
    },

    # Limits / Concurrency
    "LAMBDA-080": {
        "what": (
            "Reserved concurrency on public-facing functions.\n"
            "• What: Without reserved concurrency, bursts can exhaust account concurrency.\n"
            "• Attacker perspective: DoS other workloads by flooding public endpoints."
        ),
        "positive": "Reserved concurrency set on public endpoints.",
        "negative": "No reserved concurrency for public URL/API.",
        "remediation": "Set per-function reserved concurrency and monitor usage."
    },
    "LAMBDA-081": {
        "what": (
            "Timeout/memory right-sizing.\n"
            "• What: Excessive limits magnify abuse cost and hide long-running C2.\n"
            "• Attacker perspective: Cheap to run expensive payloads under your account."
        ),
        "positive": "Timeout and memory aligned to real need.",
        "negative": "Timeout or memory significantly over-provisioned.",
        "remediation": "Lower limits; add watchdogs and SLO-driven sizing."
    },
}
