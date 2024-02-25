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
    for rule in security_group_rule.ip_permissions:
        if rule.get("FromPort") in [22, 3389] or rule.get("ToPort") in [22, 3389]:
            for ip4_range in rule.get("IpRanges"):
                return ip4_range.get("CidrIp") in ["0.0.0.0/0"]


def has_ipv6_open_ssh_or_rdp(security_group_rule):
    for rule in security_group_rule.ip_permissions:
        if rule.get("FromPort") in [22, 3389] or rule.get("ToPort") in [22, 3389]:
            for ipv6_range in rule.get("Ipv6Ranges"):
                return ipv6_range.get("CidrIpv6") in ["::/0"]


def get_security_groups_with_open_ssh_or_rdp_all_regions(client, regions):
    # use client will be used to pass context to the different aws accounts
    # by assuming roles and using boto3 sessions
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
    master_account_org_client = boto3.client("organizations")
    master_account_ec2_client = boto3.client("ec2")
    audit_results = {}
    active_accounts = get_active_accounts(master_account_org_client)
    active_regions = list_active_regions(master_account_ec2_client)

    for account in active_accounts:
        # assume role into account ?
        # maybe in a seperate thread ?
        regions = active_regions
        account_name, account_id = account.get("account_name"), account.get(
            "account_id"
        )
        for region in regions:
            audit_results[account_name] = "violations will be added and reported"

        # the name of the master account in the test env is `securing-the-cloud`
        if account_name != "securing-the-cloud":
            print(f"Assume role here for {account_id}")

    # for each account except the master account
    # assume the cross-account role into the account
    # get_security_groups_with_open_ssh_or_rdp_all_regions()
    # add dict of {account_id: [violations]} to the empty dict
    # convert the dict to csv and write to console/file
    print(audit_results)


if __name__ == "__main__":
    main()
