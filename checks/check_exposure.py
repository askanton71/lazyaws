#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LazyAWS - Internet Exposure Inventory

Enumerates (across regions) resources that are directly reachable from the Internet:
- EC2 instances with public IP + world-open SG ingress
- ELBv2 (ALB/NLB) with scheme=internet-facing (listeners listed)
- Classic ELB with scheme=internet-facing
- API Gateway v1/v2 public endpoints
- S3 buckets that are public (policy status) or have Website hosting
- RDS instances with PubliclyAccessible + world-open SG to DB port
- OpenSearch/Elasticsearch domains with public endpoint (non-VPC)
- Redshift clusters with PubliclyAccessible
- EKS clusters with endpointPublicAccess=True
- App Runner services with public ingress
- CloudFront distributions (enabled)  [global → us-east-1]
- Global Accelerator accelerators (enabled)  [global → us-west-2]
- MSK clusters with public bootstrap brokers

Emits BAD finding per internet entrypoint. If none found, emits a single OK row.
"""

from __future__ import annotations

import argparse
from typing import Any, Dict, List

from botocore.exceptions import ClientError, EndpointConnectionError

from aws_common import (
    get_session,
    get_traced_client,
    run_check,
    OK, WARN, BAD, NA,
)

# ---------------- helpers ----------------

def iso_now():
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

def any_open_cidr(ip_ranges: List[Dict[str, Any]]) -> bool:
    for r in ip_ranges or []:
        cidr = r.get("CidrIp") or r.get("CidrIpv6")
        if cidr in ("0.0.0.0/0", "::/0"):
            return True
    return False

def port_in_perm(perm: Dict[str, Any], port: int) -> bool:
    proto = perm.get("IpProtocol")
    if proto in ("-1", "all", None):
        return True
    if proto not in ("tcp", "udp"):
        return False
    fp = perm.get("FromPort")
    tp = perm.get("ToPort")
    if fp is None or tp is None:
        return False
    try:
        return int(fp) <= port <= int(tp)
    except Exception:
        return False

def sg_world_open_ports(security_groups: List[Dict[str, Any]]) -> List[int]:
    """Return a de-duplicated set of ports where SG has 0.0.0.0/0 or ::/0 ingress."""
    ports = set()
    for sg in security_groups or []:
        for p in sg.get("IpPermissions", []) or []:
            if any_open_cidr(p.get("IpRanges", [])) or any_open_cidr(p.get("Ipv6Ranges", [])):
                if p.get("IpProtocol") in ("-1", "all", None):
                    ports.add(-1)  # ALL
                else:
                    fp = p.get("FromPort")
                    tp = p.get("ToPort")
                    if fp is not None and tp is not None:
                        try:
                            fp, tp = int(fp), int(tp)
                            if fp == tp:
                                ports.add(fp)
                            else:
                                ports.add(fp)
                                ports.add(tp)
                        except Exception:
                            pass
    return sorted(ports)

# ---------------- arguments ----------------

def add_arguments(ap: argparse.ArgumentParser):
    ap.add_argument("--profile", default=None, help="AWS profile")
    ap.add_argument("--region", default="all", help="Region (or 'all')")

# ---------------- analyzers per service ----------------

def discover_ec2(sess, api_trace, region, findings):
    try:
        ec2 = get_traced_client(sess, "ec2", api_trace, None, region)
        paginator = ec2.get_paginator("describe_instances")
        sg_cache: Dict[str, Dict[str, Any]] = {}
        for page in paginator.paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    iid = inst.get("InstanceId")
                    pub_ip = inst.get("PublicIpAddress")
                    pub6 = []
                    for ni in inst.get("NetworkInterfaces", []) or []:
                        for ipv6 in (ni.get("Ipv6Addresses") or []):
                            if ipv6.get("Ipv6Address"):
                                pub6.append(ipv6["Ipv6Address"])
                    if not pub_ip and not pub6:
                        continue
                    sg_ids = [g.get("GroupId") for g in inst.get("SecurityGroups", []) if g.get("GroupId")]
                    sgs = []
                    if sg_ids:
                        miss = [x for x in sg_ids if x not in sg_cache]
                        if miss:
                            resp = ec2.describe_security_groups(GroupIds=miss)
                            for sg in resp.get("SecurityGroups", []):
                                sg_cache[sg["GroupId"]] = sg
                        sgs = [sg_cache[x] for x in sg_ids if x in sg_cache]
                    ports = sg_world_open_ports(sgs)
                    if ports:
                        ips = ", ".join([x for x in ([pub_ip] if pub_ip else []) + pub6])
                        pr = f"Public IPs: {ips}; SG world-open ports: {'ALL' if -1 in ports else ','.join(map(str,ports))}"
                        add_finding(findings, "EXPO-EC2", f"EC2 instance publicly reachable ({iid})",
                                    f"Region={region}", ["ec2:DescribeInstances","ec2:DescribeSecurityGroups"],
                                    "BAD", pr,
                                    "Move instance behind private subnets/Load Balancer; restrict SG ingress; prefer SSM over SSH.")
    except (ClientError, EndpointConnectionError):
        pass

def discover_elbv2(sess, api_trace, region, findings):
    try:
        elbv2 = get_traced_client(sess, "elbv2", api_trace, None, region)
        paginator = elbv2.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                if lb.get("Scheme") != "internet-facing":
                    continue
                name = lb.get("LoadBalancerName")
                dns = lb.get("DNSName")
                lbtype = lb.get("Type")
                ports = []
                try:
                    ls_p = elbv2.get_paginator("describe_listeners")
                    for lpage in ls_p.paginate(LoadBalancerArn=lb["LoadBalancerArn"]):
                        ports.extend([l.get("Port") for l in lpage.get("Listeners", []) if l.get("Port")])
                    ports = sorted(set([p for p in ports if p is not None]))
                except ClientError:
                    pass
                det = f"{lbtype.upper()} {name} — {dns} — ports: {','.join(map(str,ports)) if ports else 'unknown'}"
                add_finding(findings, "EXPO-ELB", "Internet-facing ELBv2", f"Region={region}",
                            ["elbv2:DescribeLoadBalancers","elbv2:DescribeListeners"],
                            "BAD", det, "Consider internal scheme or place behind WAF/CloudFront; restrict upstreams.")
    except (ClientError, EndpointConnectionError):
        pass

def discover_elb_classic(sess, api_trace, region, findings):
    try:
        elb = get_traced_client(sess, "elb", api_trace, None, region)
        paginator = elb.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancerDescriptions", []):
                if lb.get("Scheme") != "internet-facing":
                    continue
                name = lb.get("LoadBalancerName")
                dns = lb.get("DNSName")
                ports = sorted(set([
                    (l.get("Listener") or {}).get("LoadBalancerPort")
                    for l in lb.get("ListenerDescriptions", [])
                    if (l.get("Listener") or {}).get("LoadBalancerPort") is not None
                ]))
                det = f"CLB {name} — {dns} — ports: {','.join(map(str,ports)) if ports else 'unknown'}"
                add_finding(findings, "EXPO-ELB", "Internet-facing Classic ELB", f"Region={region}",
                            ["elb:DescribeLoadBalancers"],
                            "BAD", det, "Consider internal scheme / ALB + WAF; restrict exposure.")
    except (ClientError, EndpointConnectionError):
        pass

def discover_apigw_v1(sess, api_trace, region, findings):
    try:
        apigw = get_traced_client(sess, "apigateway", api_trace, None, region)
        paginator = apigw.get_paginator("get_rest_apis")
        for page in paginator.paginate():
            for api in page.get("items", []):
                cfg = api.get("endpointConfiguration", {})
                types = cfg.get("types") or []
                if "PRIVATE" in types:
                    continue
                url = f"https://{api['id']}.execute-api.{region}.amazonaws.com"
                stage = None
                try:
                    sts = apigw.get_stages(restApiId=api["id"]).get("item", [])
                    if sts:
                        stage = sts[0].get("stageName")
                except ClientError:
                    pass
                if stage:
                    url = f"{url}/{stage}"
                det = f"{api.get('name','(no-name)')} — {url} (types={','.join(types) or 'default'})"
                add_finding(findings, "EXPO-APIGW", "API Gateway (REST) public endpoint", f"Region={region}",
                            ["apigateway:GetRestApis","apigateway:GetStages"],
                            "BAD", det, "Use PRIVATE endpoints/VPC links or WAF; require AuthN/AuthZ.")
    except (ClientError, EndpointConnectionError):
        pass

def discover_apigw_v2(sess, api_trace, region, findings):
    try:
        agw2 = get_traced_client(sess, "apigatewayv2", api_trace, None, region)
        paginator = agw2.get_paginator("get_apis")
        for page in paginator.paginate():
            for api in page.get("Items", []):
                disable = api.get("DisableExecuteApiEndpoint", False)
                if not disable:
                    api_id = api.get("ApiId")
                    proto = api.get("ProtocolType")
                    url = f"https://{api_id}.execute-api.{region}.amazonaws.com"
                    det = f"{api.get('Name','(no-name)')} — {proto} — {url}"
                    add_finding(findings, "EXPO-APIGW", "API Gateway v2 public endpoint", f"Region={region}",
                                ["apigatewayv2:GetApis"], "BAD", det,
                                "Disable default endpoint or protect with WAF/Auth; use private integration if possible.")
    except (ClientError, EndpointConnectionError):
        pass

def discover_s3(sess, api_trace, findings):
    try:
        s3 = get_traced_client(sess, "s3", api_trace, None, None)  # regionless
        resp = s3.list_buckets()
        for b in resp.get("Buckets", []):
            name = b["Name"]
            is_public = False
            try:
                st = s3.get_bucket_policy_status(Bucket=name)
                is_public = bool(st.get("PolicyStatus", {}).get("IsPublic"))
            except ClientError:
                pass
            website = False
            try:
                s3.get_bucket_website(Bucket=name)
                website = True
            except ClientError:
                pass
            pab = {}
            try:
                pab = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
            except ClientError:
                pass

            if is_public or website:
                det = f"{name} — public={is_public} website={'enabled' if website else 'no'} PAB={pab or 'n/a'}"
                add_finding(findings, "EXPO-S3", "S3 bucket publicly reachable", "Global",
                            ["s3:ListBuckets","s3:GetBucketPolicyStatus","s3:GetBucketWebsite","s3:GetPublicAccessBlock"],
                            "BAD", det, "Block public access, remove public policies/ACLs, disable Website (or front with CloudFront+OAC).")
    except (ClientError, EndpointConnectionError):
        pass

def discover_rds(sess, api_trace, region, findings):
    try:
        ec2 = get_traced_client(sess, "ec2", api_trace, None, region)
        rds = get_traced_client(sess, "rds", api_trace, None, region)
        sg_cache: Dict[str, Dict[str, Any]] = {}
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                if not db.get("PubliclyAccessible"):
                    continue
                port = (db.get("Endpoint") or {}).get("Port")
                vpc_sgs = [sg.get("VpcSecurityGroupId") for sg in db.get("VpcSecurityGroups", []) if sg.get("VpcSecurityGroupId")]
                sgs = []
                miss = [x for x in vpc_sgs if x not in sg_cache]
                if miss:
                    g = ec2.describe_security_groups(GroupIds=miss).get("SecurityGroups", [])
                    for sg in g:
                        sg_cache[sg["GroupId"]] = sg
                sgs = [sg_cache[x] for x in vpc_sgs if x in sg_cache]
                world = False
                for sg in sgs:
                    for p in sg.get("IpPermissions", []) or []:
                        if port and port_in_perm(p, port) and (any_open_cidr(p.get("IpRanges", [])) or any_open_cidr(p.get("Ipv6Ranges", []))):
                            world = True
                            break
                    if world:
                        break
                if world:
                    host = (db.get("Endpoint") or {}).get("Address")
                    det = f"{db.get('DBInstanceIdentifier')} — {host}:{port} — PubliclyAccessible=True & world-open SG"
                    add_finding(findings, "EXPO-RDS", "RDS publicly reachable", f"Region={region}",
                                ["rds:DescribeDBInstances","ec2:DescribeSecurityGroups"],
                                "BAD", det, "Disable PubliclyAccessible or restrict SGs to allowlists/VPN; prefer private subnets.")
    except (ClientError, EndpointConnectionError):
        pass

def discover_opensearch(sess, api_trace, region, findings):
    # OpenSearch (new)
    try:
        oss = get_traced_client(sess, "opensearch", api_trace, None, region)
        doms = oss.list_domain_names().get("DomainNames", [])
        for d in doms:
            name = d.get("DomainName")
            if not name:
                continue
            st = oss.describe_domain(DomainName=name).get("DomainStatus", {})
            vpc = st.get("VPCOptions")
            if not vpc:  # public
                ep = st.get("Endpoint") or (st.get("Endpoints") or {}).get("vpc")
                det = f"{name} — endpoint={ep or 'unknown'}"
                add_finding(findings, "EXPO-OS", "OpenSearch public endpoint", f"Region={region}",
                            ["opensearch:ListDomainNames","opensearch:DescribeDomain"],
                            "BAD", det, "Place domain inside VPC and restrict access (SG/ACL/WAF).")
        return
    except (ClientError, EndpointConnectionError):
        pass
    # Legacy Elasticsearch (es)
    try:
        es = get_traced_client(sess, "es", api_trace, None, region)
        doms = es.list_domain_names().get("DomainNames", [])
        for d in doms:
            name = d.get("DomainName")
            if not name:
                continue
            st = es.describe_elasticsearch_domain(DomainName=name).get("DomainStatus", {})
            vpc = st.get("VPCOptions")
            if not vpc:
                ep = st.get("Endpoint")
                det = f"{name} — endpoint={ep or 'unknown'}"
                add_finding(findings, "EXPO-OS", "Elasticsearch public endpoint", f"Region={region}",
                            ["es:ListDomainNames","es:DescribeElasticsearchDomain"],
                            "BAD", det, "Place domain inside VPC and restrict access (SG/ACL/WAF).")
    except (ClientError, EndpointConnectionError):
        pass

def discover_redshift(sess, api_trace, region, findings):
    try:
        rs = get_traced_client(sess, "redshift", api_trace, None, region)
        paginator = rs.get_paginator("describe_clusters")
        for page in paginator.paginate():
            for c in page.get("Clusters", []):
                if c.get("PubliclyAccessible"):
                    ep = (c.get("Endpoint") or {}).get("Address")
                    det = f"{c.get('ClusterIdentifier')} — {ep}"
                    add_finding(findings, "EXPO-RED", "Redshift publicly reachable", f"Region={region}",
                                ["redshift:DescribeClusters"], "BAD", det,
                                "Disable PubliclyAccessible and restrict SG; prefer private subnets.")
    except (ClientError, EndpointConnectionError):
        pass

def discover_eks(sess, api_trace, region, findings):
    try:
        eks = get_traced_client(sess, "eks", api_trace, None, region)
        paginator = eks.get_paginator("list_clusters")
        for page in paginator.paginate():
            for n in page.get("clusters", []):
                d = eks.describe_cluster(name=n).get("cluster", {})
                vcfg = d.get("resourcesVpcConfig") or {}
                public = bool(vcfg.get("endpointPublicAccess"))
                if public:
                    det = f"{n} — endpoint={d.get('endpoint')}"
                    add_finding(findings, "EXPO-EKS", "EKS public API endpoint", f"Region={region}",
                                ["eks:ListClusters","eks:DescribeCluster"],
                                "BAD", det, "Disable public access or restrict CIDRs; use private endpoint/VPN/bastion.")
    except (ClientError, EndpointConnectionError):
        pass

def discover_apprunner(sess, api_trace, region, findings):
    """
    Some botocore versions have no paginator for App Runner list_services.
    Use manual NextToken loop.
    """
    try:
        ar = get_traced_client(sess, "apprunner", api_trace, None, region)
        next_token = None
        while True:
            if next_token:
                resp = ar.list_services(NextToken=next_token)
            else:
                resp = ar.list_services()
            for s in resp.get("ServiceSummaryList", []):
                arn = s.get("ServiceArn")
                try:
                    d = ar.describe_service(ServiceArn=arn).get("Service", {})
                except ClientError:
                    continue
                ingress = (d.get("IngressConfiguration") or {}).get("IsPubliclyAccessible")
                if ingress:
                    url = d.get("ServiceUrl")
                    det = f"{d.get('ServiceName')} — {url}"
                    add_finding(findings, "EXPO-APP", "App Runner public service", f"Region={region}",
                                ["apprunner:ListServices","apprunner:DescribeService"],
                                "BAD", det, "Make ingress private or protect with Auth/WAF.")
            next_token = resp.get("NextToken")
            if not next_token:
                break
    except (ClientError, EndpointConnectionError):
        pass

def discover_cloudfront(sess, api_trace, findings):
    try:
        cf = get_traced_client(sess, "cloudfront", api_trace, None, "us-east-1")  # global
        paginator = cf.get_paginator("list_distributions")
        for page in paginator.paginate():
            dlist = page.get("DistributionList", {}) or {}
            for d in dlist.get("Items", []) or []:
                if d.get("Enabled"):
                    dom = d.get("DomainName")
                    id_ = d.get("Id")
                    det = f"{id_} — {dom}"
                    add_finding(findings, "EXPO-CF", "CloudFront distribution (public edge)", "Global",
                                ["cloudfront:ListDistributions"], "BAD", det,
                                "Ensure auth/WAF/OAC as needed; limit origins' public exposure.")
    except (ClientError, EndpointConnectionError):
        pass

def discover_global_accelerator(sess, api_trace, findings):
    try:
        ga = get_traced_client(sess, "globalaccelerator", api_trace, None, "us-west-2")  # global
        paginator = ga.get_paginator("list_accelerators")
        for page in paginator.paginate():
            for a in page.get("Accelerators", []):
                if a.get("Enabled"):
                    det = f"{a.get('Name')} — {a.get('DnsName')}"
                    add_finding(findings, "EXPO-GA", "Global Accelerator (public entry)", "Global",
                                ["globalaccelerator:ListAccelerators"], "BAD", det,
                                "Ensure front-door protections (WAF) and restrict backends.")
    except (ClientError, EndpointConnectionError):
        pass

def discover_msk(sess, api_trace, region, findings):
    # MSK clusters
    try:
        msk = get_traced_client(sess, "kafka", api_trace, None, region)
        paginator = msk.get_paginator("list_clusters")
        for page in paginator.paginate():
            for c in page.get("ClusterInfoList", []):
                arn = c.get("ClusterArn")
                try:
                    bb = msk.get_bootstrap_brokers(ClusterArn=arn)
                    if any(k.startswith("Public") for k in bb.keys()):
                        det = f"{c.get('ClusterName')} — has public bootstrap brokers"
                        add_finding(findings, "EXPO-MSK", "MSK public bootstrap brokers", f"Region={region}",
                                    ["kafka:ListClusters","kafka:GetBootstrapBrokers"],
                                    "BAD", det, "Disable public access; use private connectivity.")
                except ClientError:
                    pass
    except (ClientError, EndpointConnectionError):
        pass
    # MSK v2
    try:
        msk = get_traced_client(sess, "kafka", api_trace, None, region)
        paginator = msk.get_paginator("list_clusters_v2")
        for page in paginator.paginate():
            for c in page.get("ClusterInfoList", []):
                arn = c.get("ClusterArn")
                try:
                    bb = msk.get_bootstrap_brokers(ClusterArn=arn)
                    if any(k.startswith("Public") for k in bb.keys()):
                        det = f"{c.get('ClusterName')} — has public bootstrap brokers"
                        add_finding(findings, "EXPO-MSK", "MSK (v2) public bootstrap brokers", f"Region={region}",
                                    ["kafka:ListClustersV2","kafka:GetBootstrapBrokers"],
                                    "BAD", det, "Disable public access; use private connectivity.")
                except ClientError:
                    pass
    except (ClientError, EndpointConnectionError):
        pass

# ---------------- main analyze ----------------

def analyze(args):
    profile = getattr(args, "profile", None)
    region_arg = (getattr(args, "region", "all") or "all").lower()

    api_trace: List[Dict[str, Any]] = []
    sess = get_session(profile, None)

    # Use EC2 region list as a broad superset for most services
    all_regions = sess.get_available_regions("ec2") or []
    if region_arg != "all":
        all_regions = [region_arg] if region_arg in all_regions else []

    findings: List[Dict[str, Any]] = []

    # Global-like services
    discover_s3(sess, api_trace, findings)
    discover_cloudfront(sess, api_trace, findings)
    discover_global_accelerator(sess, api_trace, findings)

    # Regional services across all regions
    for r in all_regions:
        discover_ec2(sess, api_trace, r, findings)
        discover_elbv2(sess, api_trace, r, findings)
        discover_elb_classic(sess, api_trace, r, findings)
        discover_apigw_v1(sess, api_trace, r, findings)
        discover_apigw_v2(sess, api_trace, r, findings)
        discover_rds(sess, api_trace, r, findings)
        discover_opensearch(sess, api_trace, r, findings)
        discover_redshift(sess, api_trace, r, findings)
        discover_eks(sess, api_trace, r, findings)
        discover_apprunner(sess, api_trace, r, findings)   # ← FIXED: manual pagination
        discover_msk(sess, api_trace, r, findings)

    if not findings:
        add_finding(findings, "EXPO-000", "No internet-facing entrypoints detected", "Account/All Regions",
            ["(multiple)"], "OK", "No public endpoints discovered by heuristics.",
            "Continue monitoring; ensure WAF/SG/SCP guardrails are in place.")

    meta = {
        "Service": "Exposure",
        "Target": "inventory",
        "Region": "all" if region_arg == "all" else region_arg,
        "Profile": profile or "default",
        "TimeUTC": iso_now(),
    }
    aux = {"api_trace": api_trace}
    return meta, findings, aux


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LazyAWS Internet Exposure Inventory")
    add_arguments(parser)
    args = parser.parse_args()
    run_check(analyze, args)
