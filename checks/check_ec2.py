#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LazyAWS - EC2 checks

Runs security/best-practice checks against an EC2 instance.
If --instance-id is omitted, the module will pick the first instance found in the region.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from botocore.exceptions import ClientError

from aws_common import (
    get_session,
    get_traced_client,
    run_check,
    OK, WARN, BAD, NA,
)

# ------------------------------ utils ------------------------------

SENSITIVE_PORTS = [22, 1433, 1521, 3306, 3389, 5432, 5985, 5986, 6379, 9200, 27017]
SECRET_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"(?i)secret[_-]?key\s*[:=]\s*['\"][^'\"\n]{16,}['\"]",
    r"(?i)password\s*[:=]\s*['\"][^'\"\n]{6,}['\"]",
    r"(?i)token\s*[:=]\s*['\"][^'\"\n]{8,}['\"]",
    r"(?i)private[_-]?key",
    r"-----BEGIN[ A-Z]*PRIVATE KEY-----",
]
SHELL_PIPE_PATTERNS = [
    r"curl\s+.+\|\s*(sh|bash)",
    r"wget\s+.+\|\s*(sh|bash)",
]

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def make_check(code: str, title: str, scope: str, apis: List[str]) -> str:
    api_line = "API: " + "/".join(apis) if apis else "API: N/A"
    return f"{code} {title}\nScope: {scope}\n{api_line}"

def add_finding(findings: List[Dict[str, Any]], code: str, title: str, scope: str,
                apis: List[str], status_plain: str, details: str, recommendation: str):
    icon = {"OK": OK, "WARN": WARN, "BAD": BAD, "NA": NA}.get(status_plain, NA)
    findings.append({
        "Check": make_check(code, title, scope, apis),
        "Status": icon,
        "StatusPlain": status_plain,
        "Details": details,
        "Recommendation": recommendation,
    })

def any_open_cidr(ip_ranges: List[Dict[str, Any]]) -> bool:
    for r in ip_ranges or []:
        cidr = r.get("CidrIp") or r.get("CidrIpv6")
        if cidr in ("0.0.0.0/0", "::/0"):
            return True
    return False

def port_in_perm(perm: Dict[str, Any], port: int) -> bool:
    ip_proto = perm.get("IpProtocol")
    if ip_proto in ("-1", "all", None):
        return True
    if ip_proto not in ("tcp", "udp"):
        return False
    fp = perm.get("FromPort")
    tp = perm.get("ToPort")
    if fp is None or tp is None:
        return False
    try:
        return int(fp) <= port <= int(tp)
    except Exception:
        return False

def decode_user_data(b64_value: Optional[str]) -> str:
    if not b64_value:
        return ""
    try:
        return base64.b64decode(b64_value).decode("utf-8", errors="replace")
    except Exception:
        try:
            return base64.b64decode(b64_value).decode("latin-1", errors="replace")
        except Exception:
            return ""

# ------------------------------ args ------------------------------

def add_arguments(ap: argparse.ArgumentParser):
    ap.add_argument("--instance-id", help="EC2 InstanceId to check. If omitted, the first instance found is used.")
    ap.add_argument("--region", help="AWS region (e.g., eu-west-1).", default=None)
    ap.add_argument("--profile", help="AWS profile name.", default=None)
    ap.add_argument("--allowed-ami-owners", help="Comma-separated trusted AMI owner IDs for EC2-025.", default=None)

# ------------------------------ analyzer ------------------------------

def analyze(args):
    profile = getattr(args, "profile", None)
    region = getattr(args, "region", None)

    sess = get_session(profile, region)
    # traced clients
    ec2 = get_traced_client(sess, "ec2", api_trace := [], profile, region)
    iam = get_traced_client(sess, "iam", api_trace, profile, None)
    ssm = get_traced_client(sess, "ssm", api_trace, profile, region)
    sts = get_traced_client(sess, "sts", api_trace, profile, None)

    findings: List[Dict[str, Any]] = []

    # Account id
    try:
        ident = sts.get_caller_identity()
        account_id = ident.get("Account")
    except Exception:
        account_id = None

    # Resolve instance
    instance_id = getattr(args, "instance_id", None)
    if not instance_id:
        try:
            page = ec2.describe_instances()
            instance_id = None
            for r in page.get("Reservations", []):
                for inst in r.get("Instances", []):
                    instance_id = inst.get("InstanceId")
                    break
                if instance_id:
                    break
        except ClientError:
            instance_id = None

    if not instance_id:
        meta = {
            "Service": "EC2",
            "Target": "(none)",
            "Region": region or "—",
            "Profile": profile or "default",
            "TimeUTC": iso_now(),
        }
        add_finding(
            findings,
            "EC2-000",
            "No instances found",
            "Account/Region",
            ["ec2:DescribeInstances"],
            "NA",
            "No EC2 instances in this region or not permitted to list.",
            "Launch an instance or run in a region with instances.",
        )
        aux = {"api_trace": api_trace}
        return meta, findings, aux

    # Describe target instance
    try:
        di = ec2.describe_instances(InstanceIds=[instance_id])
        inst = di["Reservations"][0]["Instances"][0]
    except Exception as e:
        meta = {
            "Service": "EC2",
            "Target": instance_id,
            "Region": region or "—",
            "Profile": profile or "default",
            "TimeUTC": iso_now(),
        }
        add_finding(
            findings,
            "EC2-999",
            "Unable to describe instance",
            "Instance",
            ["ec2:DescribeInstances"],
            "BAD",
            f"Failed to read instance {instance_id}: {e}",
            "Ensure credentials/permissions and instance ID are valid.",
        )
        aux = {"api_trace": api_trace}
        return meta, findings, aux

    vpc_id = inst.get("VpcId")
    subnet_id = inst.get("SubnetId")
    image_id = inst.get("ImageId")
    key_name = inst.get("KeyName")
    imds = inst.get("MetadataOptions") or inst.get("InstanceMetadataOptions") or {}
    sg_ids = [g.get("GroupId") for g in inst.get("SecurityGroups", []) if g.get("GroupId")]
    eni_list = inst.get("NetworkInterfaces", []) or []

    # EC2-001 Public IPs
    pub_v4 = bool(inst.get("PublicIpAddress"))
    has_ipv6 = any( (a.get("Ipv6Address")) for ni in eni_list for a in (ni.get("Ipv6Addresses") or []) )
    status = "WARN" if (pub_v4 or has_ipv6) else "OK"
    details = f"PublicIPv4={'present' if pub_v4 else 'absent'} IPv6={'present' if has_ipv6 else 'absent'}"
    add_finding(findings, "EC2-001", "Public IP attached", "Instance", ["ec2:DescribeInstances"],
                status, details, "Prefer private subnets; expose via ALB/NLB or SSM Session Manager/bastions.")

    # Security groups
    sgs = []
    if sg_ids:
        try:
            dsg = ec2.describe_security_groups(GroupIds=sg_ids)
            sgs = dsg.get("SecurityGroups", [])
        except Exception:
            sgs = []

    # EC2-002 Sensitive ports world-open
    exposed = []
    for sg in sgs:
        for p in sg.get("IpPermissions", []) or []:
            if any_open_cidr(p.get("IpRanges", [])) or any_open_cidr(p.get("Ipv6Ranges", [])):
                for port in SENSITIVE_PORTS:
                    if port_in_perm(p, port):
                        exposed.append((sg.get("GroupId"), port))
    if exposed:
        add_finding(findings, "EC2-002", "SG wide-open ingress on sensitive ports ([22, 1433, 1521, 3306, 3389, 5432, 5985, 5986, 6379, 9200, 27017])",
                    "Instance/SG", ["ec2:DescribeSecurityGroups","ec2:DescribeNetworkInterfaces"], "BAD",
                    "World-open on: " + ", ".join(f"{gid}:{p}" for gid, p in exposed),
                    "Restrict to jump hosts/VPN/allowlists; consider ZTNA/port knocking.")
    else:
        add_finding(findings, "EC2-002", "SG wide-open ingress on sensitive ports ([22, 1433, 1521, 3306, 3389, 5432, 5985, 5986, 6379, 9200, 27017])",
                    "Instance/SG", ["ec2:DescribeSecurityGroups","ec2:DescribeNetworkInterfaces"], "OK",
                    "No world-open sensitive ports detected.",
                    "Restrict to jump hosts/VPN/CIDR allowlists; consider ZTNA/port knocking.")

    # EC2-003 ALL protocols open
    wide_all = []
    for sg in sgs:
        for p in sg.get("IpPermissions", []) or []:
            if (p.get("IpProtocol") in ("-1", "all")) and (any_open_cidr(p.get("IpRanges", [])) or any_open_cidr(p.get("Ipv6Ranges", []))):
                wide_all.append(sg.get("GroupId"))
    if wide_all:
        add_finding(findings, "EC2-003", "SG wide-open ALL ports", "Instance/SG", ["ec2:DescribeSecurityGroups"],
                    "BAD", "Groups with world-open ALL protocols: " + ", ".join(wide_all),
                    "Remove wildcard ingress; enforce least-privilege SG rules.")
    else:
        add_finding(findings, "EC2-003", "SG wide-open ALL ports", "Instance/SG", ["ec2:DescribeSecurityGroups"],
                    "OK", "No ALL-port world-open rules detected.", "Remove wildcard ingress; enforce least-privilege SG rules.")

    # EC2-004 Wide egress
    wide_egress = []
    for sg in sgs:
        for p in sg.get("IpPermissionsEgress", []) or []:
            if any_open_cidr(p.get("IpRanges", [])) or any_open_cidr(p.get("Ipv6Ranges", [])):
                wide_egress.append(sg.get("GroupId"))
                break
    add_finding(findings, "EC2-004", "SG wide egress (0.0.0.0/0 or ::/0)", "Instance/SG", ["ec2:DescribeSecurityGroups"],
                "WARN" if wide_egress else "OK",
                "At least one SG has wide egress to internet." if wide_egress else "No wide egress rules detected.",
                "Constrain egress to required CIDRs/ports; consider egress proxy/firewall.")

    # EC2-006 Public subnet (IGW route)
    if subnet_id:
        try:
            rts = ec2.describe_route_tables(Filters=[{"Name":"association.subnet-id","Values":[subnet_id]}])
            has_igw = False
            for rt in rts.get("RouteTables", []):
                for r in rt.get("Routes", []) or []:
                    if r.get("DestinationCidrBlock") == "0.0.0.0/0" and str(r.get("GatewayId","")).startswith("igw-"):
                        has_igw = True; break
                if has_igw: break
            add_finding(findings, "EC2-006", "Instance in public subnet (IGW route)", "Subnet/RouteTable", ["ec2:DescribeRouteTables"],
                        "WARN" if has_igw else "OK",
                        "Subnet has a default route via Internet Gateway (public subnet)." if has_igw else "No IGW route found for subnet.",
                        "Use private subnets without IGW; control outbound via NAT and endpoints.")
        except Exception as e:
            add_finding(findings, "EC2-006", "Instance in public subnet (IGW route)", "Subnet/RouteTable", ["ec2:DescribeRouteTables"],
                        "NA", f"Could not read route tables: {e}", "Ensure permissions.")
    else:
        add_finding(findings, "EC2-006", "Instance in public subnet (IGW route)", "Subnet/RouteTable", ["ec2:DescribeRouteTables"],
                    "NA", "No SubnetId on instance.", "Ensure instance in a VPC subnet.")

    # IMDS
    tokens = (imds.get("HttpTokens") or imds.get("HttpTokens", "optional")).lower()
    add_finding(findings, "EC2-010", "IMDSv2 enforcement (HttpTokens=required)", "Instance", ["ec2:DescribeInstances"],
                "OK" if tokens == "required" else "WARN", f"HttpTokens={imds.get('HttpTokens')}",
                "Set HttpTokens=required and rotate any potentially exposed credentials.")
    hop = imds.get("HttpPutResponseHopLimit")
    add_finding(findings, "EC2-011", "IMDS hop limit ≤ 1", "Instance", ["ec2:DescribeInstances"],
                "OK" if isinstance(hop,int) and hop <= 1 else "WARN", f"HttpPutResponseHopLimit={hop}",
                "Set hop limit to 1 (or ≤1) to prevent container/guest hops.")

    # Instance profile presence
    inst_prof_arn = (inst.get("IamInstanceProfile") or {}).get("Arn")
    if inst_prof_arn:
        add_finding(findings, "EC2-012", "Instance profile attached (best practice)", "Instance/IAM", ["iam:GetInstanceProfile"],
                    "OK", f"IamInstanceProfileArn={inst_prof_arn.split('/')[-1]}", "Use roles (STS) rather than static credentials on disk.")
    else:
        add_finding(findings, "EC2-012", "Instance profile attached (best practice)", "Instance/IAM", ["iam:GetInstanceProfile"],
                    "WARN", "No IAM instance profile attached.", "Attach a least-privileged role; avoid static creds on hosts.")

    # Role analysis
    role_name = None
    if inst_prof_arn and "/" in inst_prof_arn:
        ip_name = inst_prof_arn.split("/")[-1]
        try:
            gip = get_traced_client(sess, "iam", api_trace, profile, None).get_instance_profile(InstanceProfileName=ip_name)
            roles = gip.get("InstanceProfile", {}).get("Roles", []) or []
            if roles:
                role_name = roles[0].get("RoleName")
        except Exception:
            pass

    # EC2-013 AdminAccess?
    if role_name:
        try:
            lap = get_traced_client(sess, "iam", api_trace, profile, None).list_attached_role_policies(RoleName=role_name)
            admin = any((ap.get("PolicyArn","").endswith("/AdministratorAccess") for ap in lap.get("AttachedPolicies", [])))
            add_finding(findings, "EC2-013", "Instance profile has AdministratorAccess", "IAM Role", ["iam:ListAttachedRolePolicies"],
                        "BAD" if admin else "OK", "AdministratorAccess attached." if admin else "No AdministratorAccess detected.",
                        "Replace with least-privilege custom policies.")
        except Exception as e:
            add_finding(findings, "EC2-013", "Instance profile has AdministratorAccess", "IAM Role", ["iam:ListAttachedRolePolicies"],
                        "NA", f"Error: {e}", "Ensure IAM permissions.")
    else:
        add_finding(findings, "EC2-013", "Instance profile has AdministratorAccess", "IAM Role", ["iam:ListAttachedRolePolicies"],
                    "NA", "No role to evaluate.", "Attach role first.")

    # EC2-014 Wildcards; EC2-015 PassRole
    if role_name:
        wc = False
        passrole_unscoped = False
        try:
            iamc = get_traced_client(sess, "iam", api_trace, profile, None)
            # managed docs
            lap = iamc.list_attached_role_policies(RoleName=role_name)
            for ap in lap.get("AttachedPolicies", []):
                arn = ap.get("PolicyArn")
                if not arn: continue
                pol = iamc.get_policy(PolicyArn=arn)
                ver = pol.get("Policy", {}).get("DefaultVersionId")
                if ver:
                    doc = iamc.get_policy_version(PolicyArn=arn, VersionId=ver).get("PolicyVersion", {}).get("Document")
                    if doc:
                        for st in (doc.get("Statement") if isinstance(doc.get("Statement"), list) else [doc.get("Statement")]):
                            if st and ((
                                isinstance(st.get("Action"), str) and (st["Action"] == "*" or st["Action"].endswith(":*"))
                            ) or (
                                isinstance(st.get("Action"), list) and any(isinstance(a,str) and (a == "*" or a.endswith(":*")) for a in st["Action"])
                            ) or (
                                st.get("Resource") == "*" or (isinstance(st.get("Resource"), list) and any(r == "*" for r in st["Resource"]))
                            )):
                                wc = True
                            # passrole
                            acts = st.get("Action")
                            acts = [acts] if isinstance(acts,str) else (acts or [])
                            if any(isinstance(a,str) and a.lower()=="iam:passrole" for a in acts):
                                if st.get("Resource") == "*" or (isinstance(st.get("Resource"), list) and any(r == "*" for r in st["Resource"])):
                                    passrole_unscoped = True
            # inline docs
            for pn in iamc.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                d = iamc.get_role_policy(RoleName=role_name, PolicyName=pn).get("PolicyDocument")
                if d:
                    for st in (d.get("Statement") if isinstance(d.get("Statement"), list) else [d.get("Statement")]):
                        if st and ((
                            isinstance(st.get("Action"), str) and (st["Action"] == "*" or st["Action"].endswith(":*"))
                        ) or (
                            isinstance(st.get("Action"), list) and any(isinstance(a,str) and (a == "*" or a.endswith(":*")) for a in st["Action"])
                        ) or (
                            st.get("Resource") == "*" or (isinstance(st.get("Resource"), list) and any(r == "*" for r in st["Resource"]))
                        )):
                            wc = True
                        acts = st.get("Action")
                        acts = [acts] if isinstance(acts,str) else (acts or [])
                        if any(isinstance(a,str) and a.lower()=="iam:passrole" for a in acts):
                            if st.get("Resource") == "*" or (isinstance(st.get("Resource"), list) and any(r == "*" for r in st["Resource"])):
                                passrole_unscoped = True
        except Exception:
            pass

        add_finding(findings, "EC2-014", "Role policies contain wildcards", "IAM Role", ["iam:GetPolicyVersion","iam:GetRolePolicy"],
                    "WARN" if wc else "OK", "Wildcard Action or Resource found." if wc else "No obvious wildcards.",
                    "Replace '*' with explicit actions/resources; add conditions.")
        add_finding(findings, "EC2-015", "Unscoped iam:PassRole in role policies", "IAM Role", ["iam:GetPolicyVersion","iam:GetRolePolicy"],
                    "WARN" if passrole_unscoped else "OK", "PassRole appears unscoped." if passrole_unscoped else "PassRole appears scoped.",
                    "Limit PassRole to explicit role ARNs with conditions.")
    else:
        add_finding(findings, "EC2-014", "Role policies contain wildcards", "IAM Role", ["iam:GetPolicyVersion","iam:GetRolePolicy"],
                    "NA", "No role to evaluate.", "Attach role first.")
        add_finding(findings, "EC2-015", "Unscoped iam:PassRole in role policies", "IAM Role", ["iam:GetPolicyVersion","iam:GetRolePolicy"],
                    "NA", "No role to evaluate.", "Attach role first.")

    # Default EBS encryption (account)
    try:
        ebd = ec2.get_ebs_encryption_by_default()
        by_default = bool(ebd.get("EbsEncryptionByDefault"))
        add_finding(findings, "EC2-020", "Account default EBS encryption enabled", "Account/Region", ["ec2:GetEbsEncryptionByDefault"],
                    "OK" if by_default else "WARN", f"EbsEncryptionByDefault={by_default}",
                    "Enable default EBS encryption with a CMK.")
    except Exception as e:
        add_finding(findings, "EC2-020", "Account default EBS encryption enabled", "Account/Region", ["ec2:GetEbsEncryptionByDefault"],
                    "NA", f"Error: {e}", "Ensure permission to read setting.")

    # Volumes encryption
    try:
        vol_ids = [bdm.get("Ebs", {}).get("VolumeId")
                   for bdm in (inst.get("BlockDeviceMappings") or []) if bdm.get("Ebs")]
        vol_ids = [v for v in vol_ids if v]
        if vol_ids:
            dv = ec2.describe_volumes(VolumeIds=vol_ids)
            not_encrypted = [v["VolumeId"] for v in dv.get("Volumes", []) if not v.get("Encrypted")]
            if not_encrypted:
                add_finding(findings, "EC2-021", "Attached EBS volumes encrypted", "Instance/Volumes", ["ec2:DescribeVolumes"],
                            "BAD", "Not encrypted: " + ", ".join(not_encrypted),
                            "Migrate to encrypted volumes (snapshot → copy-encrypted → replace).")
            else:
                add_finding(findings, "EC2-021", "Attached EBS volumes encrypted", "Instance/Volumes", ["ec2:DescribeVolumes"],
                            "OK", "All attached volumes are encrypted.",
                            "Migrate to encrypted volumes where needed.")
        else:
            add_finding(findings, "EC2-021", "Attached EBS volumes encrypted", "Instance/Volumes", ["ec2:DescribeVolumes"],
                        "NA", "No EBS volumes attached.", "N/A")
    except Exception as e:
        add_finding(findings, "EC2-021", "Attached EBS volumes encrypted", "Instance/Volumes", ["ec2:DescribeVolumes"],
                    "NA", f"Error: {e}", "Ensure permission to describe volumes.")

    # Root DeleteOnTermination
    try:
        root_name = inst.get("RootDeviceName")
        root_bdm = None
        for b in inst.get("BlockDeviceMappings", []) or []:
            if b.get("DeviceName") == root_name:
                root_bdm = b; break
        if root_bdm and root_bdm.get("Ebs") is not None:
            dot = root_bdm["Ebs"].get("DeleteOnTermination")
            add_finding(findings, "EC2-027", "Root DeleteOnTermination aligned with policy", "Instance/Volumes",
                        ["ec2:DescribeInstances"], "OK" if dot else "WARN",
                        f"RootDevice={root_name} DeleteOnTermination={dot}",
                        "Ensure DeleteOnTermination matches data retention policy.")
        else:
            add_finding(findings, "EC2-027", "Root DeleteOnTermination aligned with policy", "Instance/Volumes",
                        ["ec2:DescribeInstances"], "NA", "Root device mapping not found.", "N/A")
    except Exception as e:
        add_finding(findings, "EC2-027", "Root DeleteOnTermination aligned with policy", "Instance/Volumes",
                    ["ec2:DescribeInstances"], "NA", f"Error: {e}", "N/A")

    # AMI exposure
    if image_id:
        try:
            dii = ec2.describe_images(ImageIds=[image_id])
            img = (dii.get("Images") or [{}])[0]
            is_public = img.get("Public", False)
            owner_id = img.get("OwnerId")
            if is_public and account_id and owner_id == account_id:
                add_finding(findings, "EC2-024", "Public AMI owned by you (exposure)", "AMI", ["ec2:DescribeImages"],
                            "WARN", f"ImageId={image_id} Public=True",
                            "Avoid public AMIs unless intentionally shared; rotate secrets embedded in images.")
            else:
                add_finding(findings, "EC2-024", "Public AMI owned by you (exposure)", "AMI", ["ec2:DescribeImages"],
                            "OK", f"ImageId={image_id} Public={is_public}",
                            "Avoid public AMIs unless intentionally shared; rotate secrets in images.")
        except Exception as e:
            add_finding(findings, "EC2-024", "Public AMI owned by you (exposure)", "AMI", ["ec2:DescribeImages"],
                        "NA", f"Error: {e}", "Ensure permission for DescribeImages.")
    else:
        add_finding(findings, "EC2-024", "Public AMI owned by you (exposure)", "AMI", ["ec2:DescribeImages"],
                    "NA", "No ImageId on instance.", "N/A")

    # EC2-025 AMI owner allowlist
    allowed = None
    if getattr(args, "allowed_ami_owners", None):
        allowed = [s.strip() for s in args.allowed_ami_owners.split(",") if s.strip()]
    if image_id and allowed:
        try:
            dii = ec2.describe_images(ImageIds=[image_id])
            owner_id = (dii.get("Images") or [{}])[0].get("OwnerId")
            status = "OK" if owner_id in allowed else "WARN"
            add_finding(findings, "EC2-025", "AMI owner in trusted allowlist", "AMI", ["ec2:DescribeImages"],
                        status, f"OwnerId={owner_id} Allowed={','.join(allowed)}",
                        "Define allowlist of trusted AMI owner IDs.")
        except Exception as e:
            add_finding(findings, "EC2-025", "AMI owner in trusted allowlist", "AMI", ["ec2:DescribeImages"],
                        "NA", f"Error: {e}", "Ensure permission for DescribeImages.")
    else:
        add_finding(findings, "EC2-025", "AMI owner in trusted allowlist", "AMI", ["ec2:DescribeImages"],
                    "NA", "No allowlist provided (use --allowed-ami-owners).",
                    "Define allowlist of trusted AMI owner IDs.")

    # UserData checks
    try:
        uda = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="userData")
        user_data = decode_user_data((uda.get("UserData") or {}).get("Value"))
        if user_data:
            if any(re.search(p, user_data) for p in SECRET_PATTERNS):
                add_finding(findings, "EC2-030", "User Data contains secrets (heuristic)", "Instance",
                            ["ec2:DescribeInstanceAttribute(userData)"], "WARN",
                            "UserData includes secret-like patterns.",
                            "Move secrets to SSM/Secrets Manager; fetch at boot over IAM-scoped calls.")
            else:
                add_finding(findings, "EC2-030", "User Data contains secrets (heuristic)", "Instance",
                            ["ec2:DescribeInstanceAttribute(userData)"], "OK",
                            "No obvious secret patterns detected.",
                            "Use SSM/Secrets Manager for secrets.")
        else:
            add_finding(findings, "EC2-030", "User Data contains secrets (heuristic)", "Instance",
                        ["ec2:DescribeInstanceAttribute(userData)"], "OK",
                        "UserData is empty.",
                        "Use SSM/Secrets Manager for secrets.")
        risky = any(re.search(p, user_data or "", flags=re.IGNORECASE) for p in SHELL_PIPE_PATTERNS)
        add_finding(findings, "EC2-031", "User Data shells external scripts (curl|bash)", "Instance",
                    ["ec2:DescribeInstanceAttribute(userData)"], "WARN" if risky else "OK",
                    "UserData contains shell-pipe pattern." if risky else "No obvious shell-pipe pattern.",
                    "Avoid piping remote scripts; pin checksums, use signed packages/artifacts.")
    except Exception as e:
        add_finding(findings, "EC2-030", "User Data contains secrets (heuristic)", "Instance",
                    ["ec2:DescribeInstanceAttribute(userData)"], "NA", f"Error: {e}", "Ensure permission to read user data.")
        add_finding(findings, "EC2-031", "User Data shells external scripts (curl|bash)", "Instance",
                    ["ec2:DescribeInstanceAttribute(userData)"], "NA", f"Error: {e}", "Ensure permission to read user data.")

    # SSM Managed
    try:
        infos = []
        paginator = ssm.get_paginator("describe_instance_information")
        for page in paginator.paginate():
            infos.extend(page.get("InstanceInformationList", []))
        managed = any(ii.get("InstanceId") == instance_id for ii in infos)
        add_finding(findings, "EC2-040", "Managed by SSM", "Instance/SSM", ["ssm:DescribeInstanceInformation"],
                    "OK" if managed else "WARN",
                    "Instance is registered with SSM." if managed else "Instance not registered with SSM.",
                    "Install/register SSM Agent and attach IAM role with SSM permissions.")
    except Exception as e:
        add_finding(findings, "EC2-040", "Managed by SSM", "Instance/SSM", ["ssm:DescribeInstanceInformation"],
                    "NA", f"Error: {e}", "Ensure SSM permissions.")

    # Patch compliance
    try:
        ps = ssm.describe_instance_patch_states(InstanceIds=[instance_id])
        lst = ps.get("InstancePatchStates", []) or []
        if not lst:
            add_finding(findings, "EC2-041", "Patch compliance", "Instance/SSM", ["ssm:DescribeInstancePatchStates"],
                        "WARN", "No patch state returned.",
                        "Apply baseline; schedule patch windows & maintenance.")
        else:
            st = lst[0]
            missing_crit = st.get("MissingCriticalCount", 0) or 0
            status = "OK" if missing_crit == 0 else "WARN"
            add_finding(findings, "EC2-041", "Patch compliance", "Instance/SSM", ["ssm:DescribeInstancePatchStates"],
                        status, f"MissingCriticalCount={missing_crit}",
                        "Apply baseline; schedule patch windows & maintenance.")
    except Exception as e:
        add_finding(findings, "EC2-041", "Patch compliance", "Instance/SSM", ["ssm:DescribeInstancePatchStates"],
                    "NA", f"Error: {e}", "Ensure SSM permissions.")

    # VPC Flow Logs
    if vpc_id:
        try:
            fl = ec2.describe_flow_logs(Filters=[{"Name":"resource-id","Values":[vpc_id]}])
            has_logs = bool(fl.get("FlowLogs"))
            add_finding(findings, "EC2-050", "VPC Flow Logs enabled", "VPC", ["ec2:DescribeFlowLogs"],
                        "OK" if has_logs else "WARN",
                        f"Flow logs for VPC {vpc_id}: {'FOUND' if has_logs else 'NOT FOUND'}",
                        "Enable VPC/subnet/ENI Flow Logs to CloudWatch/S3 with KMS.")
        except Exception as e:
            add_finding(findings, "EC2-050", "VPC Flow Logs enabled", "VPC", ["ec2:DescribeFlowLogs"],
                        "NA", f"Error: {e}", "Ensure permission to describe flow logs.")
    else:
        add_finding(findings, "EC2-050", "VPC Flow Logs enabled", "VPC", ["ec2:DescribeFlowLogs"],
                    "NA", "No VPC Id on instance.", "N/A")

    # CloudWatch agent heuristic (not evaluated)
    add_finding(findings, "EC2-051", "CloudWatch agent installed/enabled (heuristic)", "Instance",
                ["(SSM Inventory required)"], "NA",
                "Not evaluated (requires SSM Inventory associations).",
                "Use SSM Inventory to detect/ensure CW agent is installed & configured.")

    # Termination protection
    try:
        dat = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="disableApiTermination")
        flag = bool((dat.get("DisableApiTermination") or {}).get("Value"))
        add_finding(findings, "EC2-060", "Termination protection enabled for critical", "Instance",
                    ["ec2:DescribeInstanceAttribute(DisableApiTermination)"],
                    "OK" if flag else "WARN", f"DisableApiTermination={flag}",
                    "Enable for production/critical servers; gate changes via change control.")
    except Exception as e:
        add_finding(findings, "EC2-060", "Termination protection enabled for critical", "Instance",
                    ["ec2:DescribeInstanceAttribute(DisableApiTermination)"],
                    "NA", f"Error: {e}", "Ensure permission to read attribute.")

    # Shutdown behavior
    try:
        sib = ec2.describe_instance_attribute(InstanceId=instance_id, Attribute="instanceInitiatedShutdownBehavior")
        val = (sib.get("InstanceInitiatedShutdownBehavior") or {}).get("Value")
        add_finding(findings, "EC2-061", "Instance initiated shutdown behavior aligned", "Instance",
                    ["ec2:DescribeInstanceAttribute(InstanceInitiatedShutdownBehavior)"],
                    "OK" if val == "stop" else "WARN", f"InstanceInitiatedShutdownBehavior={val}",
                    "Align with operational policy (usually 'stop' for stateful workloads).")
    except Exception as e:
        add_finding(findings, "EC2-061", "Instance initiated shutdown behavior aligned", "Instance",
                    ["ec2:DescribeInstanceAttribute(InstanceInitiatedShutdownBehavior)"],
                    "NA", f"Error: {e}", "Ensure permission to read attribute.")

    # SSH key presence
    if key_name:
        add_finding(findings, "EC2-070", "SSH key pairs hygiene (presence)", "Instance",
                    ["ec2:DescribeInstances"], "WARN",
                    f"KeyName={key_name}",
                    "Prefer SSM Session Manager over direct SSH; centrally manage/rotate keys.")
    else:
        add_finding(findings, "EC2-070", "SSH key pairs hygiene (presence)", "Instance",
                    ["ec2:DescribeInstances"], "OK",
                    "No SSH key pair associated.",
                    "Prefer SSM Session Manager; avoid inbound SSH where possible.")

    meta = {
        "Service": "EC2",
        "Target": instance_id,
        "Region": region or "—",
        "Profile": profile or "default",
        "TimeUTC": iso_now(),
    }
    aux = {"api_trace": api_trace}
    return meta, findings, aux

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LazyAWS EC2 checker")
    add_arguments(parser)
    args = parser.parse_args()
    run_check(analyze, args)
