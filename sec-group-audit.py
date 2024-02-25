import boto3


def list_accounts():
    """List the security groups in the AWS org"""
    # Initialize the boto3 client for AWS Organizations
    org_client = boto3.client("organizations")

    # Pagination is used as there can be more accounts than the default limit
    paginator = org_client.get_paginator("list_accounts")

    # List to store all accounts
    all_accounts = []

    for page in paginator.paginate():
        # Extracting account details from each page
        accounts = page["Accounts"]

        # Appending accounts to the list
        all_accounts.extend(accounts)

    return all_accounts


def list_active_regions():
    """List the active regions in an account using the ec2 client"""
    ec2_client = boto3.client("ec2")
    region_list = []

    for region in ec2_client.describe_regions()["Regions"]:
        region_name = str(region["RegionName"])
        opt_in_status = str(region["OptInStatus"])

        if opt_in_status == "not-opted-in":
            pass
        region_list.append(region_name)
    return region_list


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


def get_security_groups_with_open_ssh_or_rdp_all_regions(active_regions):
    # get the active regions in the account
    # for each region
    # get the security groups that have open ssh or rdp open
    # return a list of violations found
    # each violiation should include a dictionary of the security group rule
    # and should include whether its open ssh or rdp access
    pass


# There has to be a cross-account role that the script will assume into the
# member accounts to be able to do stuff
# the basic use case should just work for one account
# being the one from which it is currently being run


def main():
    # start with an empty dict
    # get the list of accounts in an aws org
    ### there has to be a cross account role that will be assumed
    # for each account
    # get_security_groups_with_open_ssh_or_rdp_all_regions()
    # add dict of {account_id: [violations]} to the empty dict
    pass


if __name__ == "__main__":
    main()
