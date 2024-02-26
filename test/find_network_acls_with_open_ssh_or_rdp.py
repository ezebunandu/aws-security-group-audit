#!/usr/bin/python
import boto3

ec2 = boto3.resource("ec2", region_name="us-east-1")


def has_ipv4_open_ssh_or_rdp(security_group_rule):
    for rule in security_group_rule.ip_permissions:
        if rule.get("FromPort") in [22, 3389] or rule.get("ToPort") in [22, 3389]:
            for ip4_range in rule.get("IpRanges"):
                return ip4_range.get("CidrIp") in ["0.0.0.0/0"]


def has_ipv6_open_ssh_or_rdp(security_group_rule):
    for rule in security_group_rule.ip_permissions:
        if rule.get("FromPort") in [22, 3389] or rule.get("ToPort") in [22, 3389]:
            for ipv6_range in rule.get("Ipv6Ranges"):
                return ipv6_range.get("CidrIpv6") in ["::/0"]


nacls = ec2.network_acls.all()
for nacl in nacls:
    print(nacl.entries)
