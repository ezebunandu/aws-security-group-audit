import boto3


def get_active_accounts(org_client):
    """get all the active accounts in an aws org
    returns list of {"account_name": account_name, "account_id": account_id}"""

    # Pagination is used as there can be more accounts than the default limit
    paginator = org_client.get_paginator("list_accounts")

    # List to store all accounts
    all_active_accounts = []

    for page in paginator.paginate():
        # Extracting account details from each page
        accounts = page["Accounts"]
        for account in accounts:
            account_id, account_status, account_name = (
                account["Id"],
                account["Status"],
                account["Name"],
            )
            # only add active accounts to the list
            if account_status == "ACTIVE":
                all_active_accounts.append(
                    {"account_name": account_name, "account_id": account_id}
                )
    return all_active_accounts


def list_active_regions(ec2_client):
    """List the active regions in an account using the ec2 client"""
    region_list = []

    for region in ec2_client.describe_regions()["Regions"]:
        region_name = str(region["RegionName"])
        opt_in_status = str(region["OptInStatus"])

        if opt_in_status == "not-opted-in":
            pass
        region_list.append(region_name)
    return region_list


def has_ipv4_open_ssh_or_rdp(security_group_rule):
    """returns true if the security group rule allows open ssh or rdp from 0.0.0.0/0"""
    for rule in security_group_rule.ip_permissions:
        if rule.get("FromPort") in [22, 3389] or rule.get("ToPort") in [22, 3389]:
            for ip4_range in rule.get("IpRanges"):
                return ip4_range.get("CidrIp") in ["0.0.0.0/0"]


def has_ipv6_open_ssh_or_rdp(security_group_rule):
    """returns true if the security group rule allows open ssh or rdp from ::/0"""
    for rule in security_group_rule.ip_permissions:
        if rule.get("FromPort") in [22, 3389] or rule.get("ToPort") in [22, 3389]:
            for ipv6_range in rule.get("Ipv6Ranges"):
                return ipv6_range.get("CidrIpv6") in ["::/0"]


def get_network_acls_with_open_ssh_or_rdp_all_regions(role_session, active_regions):
    pass


def get_security_groups_with_open_ssh_or_rdp_all_regions(role_session, active_regions):
    violations = []
    for region in active_regions:

        ec2 = role_session.resource("ec2", region_name=region)

        security_groups = ec2.security_groups.all()

        for security_group in security_groups:
            security_group_name = security_group.group_name
            if has_ipv4_open_ssh_or_rdp(security_group):
                violations.append(
                    {
                        security_group_name: "Has open ipv4 ssh or rdp access from the internet"
                    }
                )
            if has_ipv6_open_ssh_or_rdp(security_group):
                violations.append(
                    {
                        security_group_name: "has open ipv6 ssh or rdp access from the internet"
                    }
                )
    return violations
