# -*- coding: utf-8 -*-

# S3 knowledge base used by check_report.py
# Each entry provides: 'what', 'positive', 'negative', 'remediation'

S3_CHECK_CATALOG = {
    "S3-001": {
        "what": (
            "Bucket reachability & region alignment (HeadBucket + Location).\n"
            "• What: Validate the bucket exists and is accessible, and the client is using the correct region.\n"
            "• Why: Region mismatches and access errors can mask misconfigurations or lead to false auditing results.\n"
            "• Attacker perspective: Name/asset discovery (OSINT), probing for mistakenly exposed buckets or region "
            "confusion to fingerprint environments and plan further access attempts."
        ),
        "positive": "HeadBucket succeeds (HTTP 200/301) in the expected region.",
        "negative": "HeadBucket fails (403/404) or redirects to a different region.",
        "remediation": "Verify bucket name/region and permissions; use the correct AWS profile and region settings."
    },
    "S3-002": {
        "what": (
            "Bucket-level Public Access Block (BPA) — four flags: BlockPublicAcls, IgnorePublicAcls, "
            "BlockPublicPolicy, RestrictPublicBuckets.\n"
            "• What: Ensure all four controls are enabled on the bucket.\n"
            "• Why: BPA prevents accidental public exposure through ACLs or bucket policies.\n"
            "• Attacker perspective: If BPA is disabled, public ACLs/policies may grant anonymous or broad access "
            "for listing, reading, or even writing/deleting objects."
        ),
        "positive": "All four BPA flags are set to true.",
        "negative": "Any flag is false or configuration is missing.",
        "remediation": "Enable all four BPA flags at the bucket level."
    },
    "S3-003": {
        "what": (
            "Account-level BPA via s3control.\n"
            "• What: Ensure BPA is enforced at the account level for new/current buckets.\n"
            "• Why: Global guardrail to prevent newly created buckets from being accidentally exposed.\n"
            "• Attacker perspective: A gap at the account level allows creation or modification of buckets without BPA, "
            "potentially making data public before detection."
        ),
        "positive": "All four account-level BPA flags are true.",
        "negative": "Not configured or any flag is false.",
        "remediation": "Enable account-level BPA in every active region."
    },
    "S3-004": {
        "what": (
            "OwnershipControls — ObjectOwnership=BucketOwnerEnforced (BOE).\n"
            "• What: Confirm that the bucket owner is the enforced owner of objects (ACLs do not control ownership).\n"
            "• Why: Prevents third parties from uploading objects that the bucket owner cannot access or manage.\n"
            "• Attacker perspective: Without BOE, an external uploader could craft ACLs that lock the owner out, "
            "creating ‘poisoned objects’ that hinder rotation/cleanup."
        ),
        "positive": "ObjectOwnership is BucketOwnerEnforced.",
        "negative": "Missing OwnershipControls or a different mode is used.",
        "remediation": "Set OwnershipControls to BucketOwnerEnforced to disable legacy ACL behavior."
    },
    "S3-005": {
        "what": (
            "Bucket ACLs — public grants (AllUsers/AuthenticatedUsers).\n"
            "• What: Detect any ACL grants that make the bucket publicly accessible.\n"
            "• Why: Public ACLs can expose data to the internet or to all AWS accounts.\n"
            "• Attacker perspective: Public grants allow unauthenticated enumeration and data collection; "
            "in misconfigured cases they could enable object writes or deletions."
        ),
        "positive": "No AllUsers or AuthenticatedUsers grants.",
        "negative": "Any public grant is present.",
        "remediation": "Remove public ACL grants; rely on IAM and bucket policies."
    },
    "S3-006": {
        "what": (
            "Default bucket encryption (SSE-S3 vs SSE-KMS).\n"
            "• What: Check the default Server-Side Encryption configuration.\n"
            "• Why: SSE-KMS provides key isolation, auditability, and tighter access control compared to SSE-S3.\n"
            "• Attacker perspective: If only SSE-S3 is used, compromised identities or systems may access data without "
            "KMS guardrails or key policies that would otherwise limit blast radius."
        ),
        "positive": "Default encryption is SSE-KMS with a customer-managed key (CMK).",
        "negative": "SSEAlgorithm is AES256 (SSE-S3) or encryption is not configured.",
        "remediation": "Enable default SSE-KMS (CMK) and consider a deny policy for non-KMS PutObject."
    },
    "S3-007": {
        "what": (
            "Versioning enabled.\n"
            "• What: Ensure object versioning is on.\n"
            "• Why: Versioning enables recovery from deletions/overwrites and supports stronger retention models.\n"
            "• Attacker perspective: Without versioning, destructive writes or deletions can cause irreversible data loss."
        ),
        "positive": "Versioning Status = Enabled.",
        "negative": "NotConfigured or Suspended.",
        "remediation": "Enable versioning on the bucket."
    },
    "S3-008": {
        "what": (
            "Lifecycle configuration (transitions/expiration) aligned with data retention policy.\n"
            "• What: Validate lifecycle rules exist and reflect expected transitions/expirations.\n"
            "• Why: Lifecycle reduces storage risk/cost and helps enforce retention/classification.\n"
            "• Attacker perspective: Lack of lifecycle may keep sensitive artifacts around indefinitely, increasing exposure "
            "if identities, access points, or downstream processors are compromised."
        ),
        "positive": "Lifecycle rules configured per data-classification/retention policy.",
        "negative": "No lifecycle configuration.",
        "remediation": "Add lifecycle rules for transition/expiration in line with business policy."
    },
    "S3-009": {
        "what": (
            "Lifecycle rule to Abort Incomplete Multipart Uploads (MPU).\n"
            "• What: Confirm an AbortIncompleteMultipartUpload rule exists (e.g., 7 days).\n"
            "• Why: Prevents orphaned parts from wasting storage and reduces attack surface for partial uploads.\n"
            "• Attacker perspective: Incomplete MPUs could be abused to inflate storage costs or create operational noise."
        ),
        "positive": "AbortIncompleteMultipartUpload is present (e.g., 7 days).",
        "negative": "No abort rule for incomplete MPUs.",
        "remediation": "Add AbortIncompleteMultipartUpload to lifecycle."
    },
    "S3-010": {
        "what": (
            "Server access logging (or CloudTrail S3 Data Events) enabled.\n"
            "• What: Verify logging of access to the bucket (target bucket protected and encrypted).\n"
            "• Why: Forensics and monitoring depend on reliable logs; without them, detecting abuse is harder.\n"
            "• Attacker perspective: Lack of logging reduces chances of detection and complicates incident response."
        ),
        "positive": "Access logging enabled to a protected target bucket, or S3 Data Events are enabled.",
        "negative": "No access logging.",
        "remediation": "Enable server access logging or CloudTrail Data Events; protect the log bucket with KMS and strict policies."
    },
    "S3-011": {
        "what": (
            "Bucket policy denies insecure transport (aws:SecureTransport=false).\n"
            "• What: Ensure TLS is enforced at the policy level.\n"
            "• Why: Prevents plaintext access paths that leak data or credentials in transit.\n"
            "• Attacker perspective: Without TLS enforcement, on-path attackers can sniff/modify traffic on misconfigured clients."
        ),
        "positive": "Explicit Deny for requests where aws:SecureTransport=false.",
        "negative": "No TLS-enforcement deny.",
        "remediation": "Add a Deny statement that blocks requests unless SecureTransport is true."
    },
    "S3-012": {
        "what": (
            "Bucket policy enforces KMS encryption on PutObject.\n"
            "• What: Require s3:x-amz-server-side-encryption=aws:kms for object uploads.\n"
            "• Why: Ensures data is encrypted with KMS keys (auditable, revocable) rather than default SSE-S3.\n"
            "• Attacker perspective: Without this control, uploads may bypass KMS, weakening key isolation and oversight."
        ),
        "positive": "Deny PutObject if SSE is not aws:kms.",
        "negative": "No deny rule for non-KMS uploads.",
        "remediation": "Add a Deny for PutObject when x-amz-server-side-encryption != aws:kms."
    },
    "S3-013": {
        "what": (
            "Bucket policy JSON validity.\n"
            "• What: Validate the bucket policy is well-formed JSON.\n"
            "• Why: Invalid JSON may silently disable intended protections or create unexpected behavior.\n"
            "• Attacker perspective: Misparsing can leave gaps in enforcement, enabling indirect privilege or open access."
        ),
        "positive": "Policy parses successfully and is valid JSON.",
        "negative": "Parsing error or invalid JSON document.",
        "remediation": "Fix structure; validate with JSON linters and IAM Policy Simulator."
    },
    "S3-014": {
        "what": (
            "Presence of a bucket policy implementing least privilege and required explicit denies.\n"
            "• What: Check that a policy exists and is not overly permissive.\n"
            "• Why: A well-designed policy is central to access governance and data protection.\n"
            "• Attacker perspective: Absent or permissive policies expand the attack surface for lateral movement and exfiltration."
        ),
        "positive": "An explicit bucket policy exists with least privilege and required denies.",
        "negative": "No bucket policy or policy cannot be read.",
        "remediation": "Create a least-privilege bucket policy with TLS/KMS enforcement and explicit denies where needed."
    },
    "S3-015": {
        "what": (
            "Static website hosting exposure.\n"
            "• What: Detect if website hosting is enabled unintentionally.\n"
            "• Why: Website endpoints are inherently public; content may be unintentionally exposed.\n"
            "• Attacker perspective: Public endpoints can be used for phishing, watering holes, or distributing tampered content."
        ),
        "positive": "Website hosting disabled unless explicitly required and governed.",
        "negative": "Website hosting enabled inadvertently.",
        "remediation": "Disable website hosting unless business-approved; otherwise harden content and controls."
    },
    "S3-016": {
        "what": (
            "CORS configuration — wildcard origins.\n"
            "• What: Inspect CORS rules for '*' in AllowedOrigins and overly broad methods/headers.\n"
            "• Why: CORS misconfigurations can allow untrusted front-ends to read data from your bucket in users’ browsers.\n"
            "• Attacker perspective: With wildcards, arbitrary sites can trick browsers into sending authenticated requests and reading responses."
        ),
        "positive": "No '*' origins; rules are scoped to specific domains and minimal methods/headers.",
        "negative": "Wildcard origins or overly broad rules.",
        "remediation": "Replace '*' with explicit origins; limit methods/headers to the minimum required."
    },
    "S3-017": {
        "what": (
            "Replication configuration (CRR/SRR) and destination hardening.\n"
            "• What: Validate replication exists when required and destinations are KMS-encrypted with strict policies.\n"
            "• Why: Replication affects data residency, DR/RPO, and multiplies the surface if destinations are weakly protected.\n"
            "• Attacker perspective: Weak destination policies or keys can be leveraged to access replicated sensitive data."
        ),
        "positive": "Replication configured as per policy; destinations are KMS-encrypted and restricted.",
        "negative": "No replication where compliance/DR requires it.",
        "remediation": "Configure replication; protect destination buckets and keys with least privilege."
    },
    "S3-018": {
        "what": (
            "Event notifications (SNS/SQS/Lambda) and destination security.\n"
            "• What: Check if notifications exist and whether destinations are properly protected and encrypted.\n"
            "• Why: Event-driven integrations can leak or process sensitive objects if destinations are misconfigured.\n"
            "• Attacker perspective: Abusing notification targets (e.g., permissive queues/functions) to pull or process data at scale."
        ),
        "positive": "Notifications configured with KMS encryption and strict destination policies.",
        "negative": "No notifications where they are expected, or destinations are weak.",
        "remediation": "Configure notifications and harden targets (KMS, policies, least privilege)."
    },
    "S3-019": {
        "what": (
            "S3 Access Points — presence and governance.\n"
            "• What: Enumerate access points and assess policy sprawl.\n"
            "• Why: Access points introduce additional policy surfaces; each must be governed and least-privileged.\n"
            "• Attacker perspective: Overly broad access point policies can provide alternative paths around bucket policy controls."
        ),
        "positive": "No unnecessary access points; all policies are strictly scoped.",
        "negative": "Access points exist without clear need or with broad policies.",
        "remediation": "Remove unused access points; review and restrict policies on those required."
    },
    "S3-020": {
        "what": (
            "Object-level encryption on sample objects (HeadObject).\n"
            "• What: Inspect sample objects to confirm server-side encryption mode (preferring aws:kms).\n"
            "• Why: Default encryption can be bypassed in certain cases; object-level checks verify real data posture.\n"
            "• Attacker perspective: If objects are not KMS-encrypted, compromised systems or identities may access data "
            "without key isolation/controls, increasing blast radius."
        ),
        "positive": "Objects are encrypted with aws:kms.",
        "negative": "Objects use AES256 (SSE-S3) or lack encryption metadata.",
        "remediation": "Re-upload with SSE-KMS and enforce a deny on non-KMS uploads."
    },
}
