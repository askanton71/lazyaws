# -*- coding: utf-8 -*-

"""
EC2 knowledge base for LazyAWS report.
Each entry provides:
  - 'what': Deep description + attacker perspective
  - 'positive': Expected good result
  - 'negative': Bad result
  - 'remediation': Concrete fix guidance
"""

EC2_CHECK_CATALOG = {

    # Inventory / Exposure
    "EC2-001": {
        "what": (
            "Public IP attachment (IPv4/IPv6).\n"
            "• What: Detects instances with public addresses directly reachable from the Internet.\n"
            "• Why: Public exposure increases attack surface (brute force, RCE, lateral movement).\n"
            "• Attacker perspective: Direct network access to management and app ports."
        ),
        "positive": "No public IPv4/IPv6; access via ALB/NLB, bastion, or SSM.",
        "negative": "Instance has public IPv4 and/or IPv6.",
        "remediation": "Place instances in private subnets; front with load balancers or SSM Session Manager."
    },
    "EC2-002": {
        "what": (
            "Security Group ingress open to the world on sensitive ports.\n"
            "• What: SSH, RDP, WinRM, database ports exposed to 0.0.0.0/0 or ::/0.\n"
            "• Why: Enables brute-force and exploitation of known service CVEs.\n"
            "• Attacker perspective: Easy foothold and credential harvesting."
        ),
        "positive": "Admin/DB ports restricted to jump hosts/VPN/allowlisted CIDRs.",
        "negative": "World-open rules on sensitive ports.",
        "remediation": "Tighten SGs; use VPN/bastions/ZTNA; limit exposure with IP allowlists."
    },
    "EC2-003": {
        "what": (
            "Security Group ingress ALL ports open to the world.\n"
            "• What: IpProtocol=-1 to 0.0.0.0/0 or ::/0.\n"
            "• Why: Trivial compromise path.\n"
            "• Attacker perspective: Full network access to host."
        ),
        "positive": "No ALL-port world-open ingress rules.",
        "negative": "An attached SG allows ALL ports to the world.",
        "remediation": "Remove wildcard rules; enforce least-privilege."
    },
    "EC2-004": {
        "what": (
            "Security Group egress wide open.\n"
            "• What: Outbound to 0.0.0.0/0 or ::/0.\n"
            "• Why: Enables data exfiltration/C2.\n"
            "• Attacker perspective: Freely beacon to external infrastructure."
        ),
        "positive": "Egress constrained to required CIDRs/ports.",
        "negative": "World-open egress.",
        "remediation": "Constrain egress; consider proxies/egress firewalls."
    },
    "EC2-006": {
        "what": (
            "Public subnet routing (Internet Gateway).\n"
            "• What: Subnet has route to an IGW; even without a public IP now, exposure risk exists.\n"
            "• Why: Easier accidental exposure and outbound to the internet.\n"
            "• Attacker perspective: Direct route for exfiltration."
        ),
        "positive": "Private subnets without IGW routes.",
        "negative": "Subnet has IGW route.",
        "remediation": "Use private subnets; outbound via NAT and VPC endpoints."
    },

    # Identity / IMDS
    "EC2-010": {
        "what": (
            "IMDSv2 enforcement (HttpTokens=required).\n"
            "• What: Ensures the instance metadata service requires session tokens.\n"
            "• Why: Prevents SSRF/local metadata theft of credentials.\n"
            "• Attacker perspective: IMDSv1 enables easy role credential theft."
        ),
        "positive": "HttpTokens=required.",
        "negative": "HttpTokens=optional.",
        "remediation": "Set HttpTokens=required; rotate credentials that may have been exposed."
    },
    "EC2-011": {
        "what": (
            "IMDS hop limit.\n"
            "• What: Checks HttpPutResponseHopLimit to prevent cross-container hops.\n"
            "• Why: Larger hop limit allows metadata calls from nested contexts.\n"
            "• Attacker perspective: Compromised containers pivot to instance role."
        ),
        "positive": "Hop limit is 1 (or minimal required).",
        "negative": "Hop limit > 1 without a strong reason.",
        "remediation": "Set hop limit to 1 for general workloads."
    },
    "EC2-012": {
        "what": (
            "IAM instance profile attached.\n"
            "• What: Enforces short-lived credentials via STS instead of static keys on disk.\n"
            "• Why: Reduces long-lived secret exposure.\n"
            "• Attacker perspective: Static credentials persist beyond compromise."
        ),
        "positive": "Instance has an IAM instance profile.",
        "negative": "No instance profile attached.",
        "remediation": "Attach an instance profile with least-privilege policies."
    },
    "EC2-013": {
        "what": (
            "AdministratorAccess on instance role.\n"
            "• What: Detects AWS managed Admin policy on role.\n"
            "• Why: Host compromise = full account compromise.\n"
            "• Attacker perspective: Immediate unrestricted AWS access."
        ),
        "positive": "No AdministratorAccess attached.",
        "negative": "AdministratorAccess is attached.",
        "remediation": "Replace with least-privilege custom policies."
    },
    "EC2-014": {
        "what": (
            "Role policies with wildcards.\n"
            "• What: Action:'*' or Resource:'*' in role policies.\n"
            "• Why: Violates least privilege; enables lateral movement.\n"
            "• Attacker perspective: Abuse broad rights to pivot."
        ),
        "positive": "Explicit actions and ARNs with conditions.",
        "negative": "Wildcards present in actions/resources.",
        "remediation": "Replace '*' with concrete actions/resources; add conditions."
    },
    "EC2-015": {
        "what": (
            "Unscoped iam:PassRole in role policies.\n"
            "• What: PassRole with Resource:'*' and no conditions.\n"
            "• Why: Enables passing privileged roles to services.\n"
            "• Attacker perspective: Privilege escalation via service impersonation."
        ),
        "positive": "PassRole restricted to specific ARNs with conditions.",
        "negative": "Unscoped PassRole detected.",
        "remediation": "Limit PassRole to explicit ARNs and add conditions."
    },

    # Storage / AMIs
    "EC2-020": {
        "what": (
            "Default EBS encryption at account/region scope.\n"
            "• What: Ensures new volumes launch encrypted by default.\n"
            "• Why: Prevents plaintext volumes created by mistake.\n"
            "• Attacker perspective: Easier data capture from unencrypted disks."
        ),
        "positive": "EbsEncryptionByDefault=True.",
        "negative": "Default encryption disabled.",
        "remediation": "Enable default EBS encryption and a CMK as default key."
    },
    "EC2-021": {
        "what": (
            "Attached EBS volumes encryption.\n"
            "• What: Checks Encrypted flag for all instance volumes.\n"
            "• Why: Data-at-rest protection and compliance.\n"
            "• Attacker perspective: Snapshot/volume copy yields plaintext data."
        ),
        "positive": "All attached volumes are encrypted.",
        "negative": "One or more attached volumes are unencrypted.",
        "remediation": "Migrate to encrypted volumes (snapshot → copy-encrypted → replace)."
    },
    "EC2-024": {
        "what": (
            "Public AMIs (owned by you).\n"
            "• What: Flags AMIs marked Public, which may leak code/secrets.\n"
            "• Why: Reduces unintentional data exposure.\n"
            "• Attacker perspective: Mine public images for secrets."
        ),
        "positive": "AMIs are private unless intentionally shared.",
        "negative": "AMI is public.",
        "remediation": "Make AMIs private; rotate any secrets embedded."
    },
    "EC2-025": {
        "what": (
            "Trusted AMI owner allowlist.\n"
            "• What: Confirms image owner is in approved list.\n"
            "• Why: Avoids backdoored base images.\n"
            "• Attacker perspective: Weaponized AMI supply-chain."
        ),
        "positive": "AMI owner account is in allowlist.",
        "negative": "Owner not in allowlist (or unknown).",
        "remediation": "Use golden images; restrict by AMI owner IDs."
    },
    "EC2-027": {
        "what": (
            "Root volume DeleteOnTermination.\n"
            "• What: Consistency with data retention policy.\n"
            "• Why: Prevents data remnants or unintended loss.\n"
            "• Attacker perspective: Residual data usable after termination."
        ),
        "positive": "Setting matches org policy (often True).",
        "negative": "Setting misaligned or unknown.",
        "remediation": "Configure DeleteOnTermination to match retention policy."
    },

    # User Data
    "EC2-030": {
        "what": (
            "Secrets in User Data (heuristic).\n"
            "• What: Scans decoded user data for secret-like patterns.\n"
            "• Why: User Data is retrievable via API; secrets can leak.\n"
            "• Attacker perspective: Dump user data and reuse tokens."
        ),
        "positive": "No secrets in User Data.",
        "negative": "User Data contains probable secrets.",
        "remediation": "Move secrets to SSM/Secrets Manager; fetch at boot with IAM."
    },
    "EC2-031": {
        "what": (
            "Shelling remote scripts in User Data (curl|bash).\n"
            "• What: Detects patterns indicating execution of remote scripts.\n"
            "• Why: Supply-chain risk via compromised endpoints.\n"
            "• Attacker perspective: Hijack bootstrap to implant backdoors."
        ),
        "positive": "No remote script piping.",
        "negative": "Found curl|bash (or wget|sh) pattern.",
        "remediation": "Pin checksums; use signed artifacts and internal repositories."
    },

    # Patch / SSM
    "EC2-040": {
        "what": (
            "Instance managed by AWS Systems Manager.\n"
            "• What: Presence in SSM inventory indicates manageability for patching and commands.\n"
            "• Why: Unmanaged hosts drift and miss patches.\n"
            "• Attacker perspective: Easier to persist on unmanaged hosts."
        ),
        "positive": "Instance appears in SSM inventory.",
        "negative": "Not managed by SSM.",
        "remediation": "Install/register SSM Agent; attach SSM role and associations."
    },
    "EC2-041": {
        "what": (
            "Patch compliance (SSM Patch Manager).\n"
            "• What: Uses SSM patch state to detect missing/failed updates.\n"
            "• Why: Unpatched hosts are a top initial access vector.\n"
            "• Attacker perspective: Exploit known CVEs to gain code execution."
        ),
        "positive": "OverallPatchState indicates compliant (INSTALLED/INSTALLED_OTHER).",
        "negative": "Non-compliant or unknown patch state.",
        "remediation": "Apply baselines; schedule patch windows; enforce maintenance."
    },

    # Logging / Forensics
    "EC2-050": {
        "what": (
            "VPC Flow Logs enabled.\n"
            "• What: Ensures network telemetry for IR/detection.\n"
            "• Why: Without flows, exfiltration and scanning are harder to detect.\n"
            "• Attacker perspective: Operate with less chance of detection."
        ),
        "positive": "Flow Logs enabled for VPC/subnet/ENIs.",
        "negative": "No flow logs.",
        "remediation": "Enable Flow Logs to CloudWatch/S3 with KMS."
    },
    "EC2-051": {
        "what": (
            "CloudWatch Agent presence (heuristic).\n"
            "• What: Host logs and metrics shipped to CloudWatch.\n"
            "• Why: Forensics/monitoring visibility.\n"
            "• Attacker perspective: Lack of telemetry helps stealth."
        ),
        "positive": "Agent installed and configured.",
        "negative": "Unknown/not installed.",
        "remediation": "Deploy CW agent via SSM State Manager; define log configs."
    },

    # Resilience / Safety
    "EC2-060": {
        "what": (
            "Termination protection for critical workloads.\n"
            "• What: Prevents accidental/unauthorized instance termination.\n"
            "• Why: Protects availability during attacks/mistakes.\n"
            "• Attacker perspective: Quick destructive action if disabled."
        ),
        "positive": "DisableApiTermination=True on prod/critical.",
        "negative": "Termination protection off.",
        "remediation": "Enable for critical instances; gate via change control."
    },
    "EC2-061": {
        "what": (
            "Instance initiated shutdown behavior.\n"
            "• What: stop vs terminate alignment with ops expectations.\n"
            "• Why: Misconfig can cause unintended data loss.\n"
            "• Attacker perspective: Abuse shutdown to cause outages."
        ),
        "positive": "Behavior set per policy (often 'stop').",
        "negative": "Misaligned or unknown behavior.",
        "remediation": "Configure to 'stop' for stateful; document procedures."
    },

    # Keys / Access
    "EC2-070": {
        "what": (
            "SSH key pair usage (hygiene).\n"
            "• What: Presence of a KeyName implies key-based SSH access.\n"
            "• Why: Key lifecycle and sharing risks; prefer SSM.\n"
            "• Attacker perspective: Stolen private keys = silent access."
        ),
        "positive": "No SSH keys; use SSM Session Manager.",
        "negative": "SSH key present and relied upon.",
        "remediation": "Reduce SSH usage; rotate keys; centralize access via SSM."
    },
}
