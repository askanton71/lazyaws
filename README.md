# LazyAWS

Metasploit-style **AWS security auditor**: enumerate, test, and report on S3, EC2, IAM, and Lambda — with a REPL-like console (`runner.py`), JSON artifacts per resource, and a rich Excel report.

> **Use only with explicit authorization.** You are responsible for complying with your organization's policies and applicable law.

---

## ✨ Features

- **REPL console** with Metasploit-inspired UX (`use`, `set`, `setg`, `run`, `runall`, `show modules`, `exit`).
- **Modules**: `s3`, `ec2`, `iam`, `lambda`, `report` (Excel builder).
- **All-regions scanning** or single region targeting.
- **Per-resource JSON** artifacts (under `RawData/`), including **CLI request/response** trace.
- **Excel report** (`Reports/LazyAWS_Report.xlsx`) with **severity** (Critical/High/Medium/Low) mapping per finding.
- **Knowledge base** for tests & severities in code (`checks/report_severity.py`) + rich “What was tested” descriptions.
- **Idempotent artifacts**: keeps latest result per resource (where implemented) to avoid file explosion on repeated runs.

---

## 🚀 Quickstart

```bash
git clone https://github.com/<your-org>/lazyaws.git
cd lazyaws

# Recommended: Python 3.9+
python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt

# Run console
./runner.py
```

Inside the console:

```
lazyaws> setg profile pentest
lazyaws> setg region eu-west-1
lazyaws> show modules

lazyaws> use s3
lazyaws (s3)> runall

lazyaws> use ec2
lazyaws (ec2)> set region all
lazyaws (ec2)> runall

lazyaws> use report
lazyaws (report)> run   # builds Reports/LazyAWS_Report.xlsx
```

Headless (CLI) examples:

```bash
# Single bucket
python checks/check_s3.py --bucket my-bucket --profile pentest --region eu-west-1

# All functions (module handles regions)
python checks/check_lambda.py --profile pentest --region all

# All instances across regions
python checks/check_ec2.py --profile pentest --region all

# Build Excel from existing RawData/*.json
python checks/check_report.py --out Reports/LazyAWS_Report.xlsx
```

---

## 🧱 Directory Layout

```
lazyaws/
  runner.py                   # REPL console
  aws_common.py               # shared session/client, printing, JSON writer, API tracing
  checks/
    check_s3.py               # S3 checks
    check_ec2.py              # EC2 checks
    check_iam.py              # IAM checks
    check_lambda.py           # Lambda checks
    check_report.py           # Excel report builder
    report_severity.py        # severity policy + normalization
    __init__.py
  RawData/                    # JSON artifacts (inputs to report)
  Reports/                    # Generated Excel
```

---

## 📦 Requirements

- Python **3.9+**
- AWS credentials with required read permissions (e.g. via `~/.aws/credentials` profile).
- Packages:
  - `boto3`
  - `botocore`
  - `openpyxl`

Install via:

```bash
pip install -r requirements.txt
```

`requirements.txt` includes pinned minimums to keep compatibility.

---

## 🧪 How it works

- Each module gathers metadata via `boto3` and writes a **normalized JSON** file into `RawData/`:
  - `Meta`: `Service`, `Target` (resource), `Region`, `Profile`, `TimeUTC`
  - `Findings`: list of checks with `Check`, `Status`/`StatusPlain`, `Details`, `Recommendation`
  - `Aux.api_trace`: ordered list of API calls with **CLI request/response** strings (or synthesized from params)
- The `report` module reads all `RawData/*.json`, normalizes status and severity, and builds per-service sheets:
  - Columns: **Resource | Region | Profile | Time (UTC) | Check | Status | Details | Recommendation | CLI request(s) | CLI response(s)**
  - Only **failed** (`WARN`/`BAD`) findings are listed by default (OK/N/A are suppressed).

> If you want to include OK/N/A rows as well, you can extend `checks/check_report.py` to skip the outcome filter.

---

## ✅ Supported Checks (examples)

### S3
- BPA flags, account BPA, Object Ownership, ACLs
- Default encryption (SSE-S3 vs KMS), versioning, lifecycle (+ abort MPU)
- Logging, TLS-enforcement, PutObject KMS policy guard
- Website hosting, CORS, replication, notifications
- Object-level KMS (sample), policy public status

### EC2
- Public IP / public subnet
- Security groups: world-open sensitive ports / all ports / wide egress
- IMDSv2 required; hop limit; instance profile; role wildcards/Admin; PassRole scoping
- Default EBS encryption; volume encryption; AMI exposure
- User Data secrets & curl|bash heuristics
- SSM management & patch state
- VPC Flow Logs; CW agent presence
- Termination protection; shutdown behavior; key pairs hygiene

### IAM
- Root MFA; root access keys
- Admin* attachments; wildcards in policies
- Password policy, key age, inactive users
- Unscoped PassRole; lax AssumeRole trust
- Console users w/o MFA; Access Analyzer findings

### Lambda
- Public Function URLs, env secrets, reserved concurrency
- Role wildcards/Admin, X-Ray, KMS for env
- VPC/SG posture, DLQ, runtime EOL, code signing
- CORS, outdated layers, EFS hardening, tagging

---

## 🔐 Safety & Legal

- **Only scan accounts and resources you are authorized to test.**
- Many checks surface misconfigurations with potential business impact; run in read-only mode and avoid destructive actions.
- Respect rate limits and API costs — particularly in **all-regions** runs.

---

## 🤝 Contributing

We welcome issues and PRs! Please see:
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)
- [CONTRIBUTING.md](./CONTRIBUTING.md)

Run lint/tests locally before submitting. Small, focused PRs are easiest to review.

---

## 🔒 Security Policy

If you discover a vulnerability that affects LazyAWS, please follow [SECURITY.md](./SECURITY.md).

---

## 🗺️ Roadmap

- Toggle to include OK/N/A rows in the Excel report
- HTML/MD export of findings
- Additional modules (RDS, EKS, CloudTrail, CloudFront, SQS/SNS)
- Pluggable custom checks
- SBOM & dependency audit

---

## 🏷️ License

MIT — see [LICENSE](./LICENSE).
