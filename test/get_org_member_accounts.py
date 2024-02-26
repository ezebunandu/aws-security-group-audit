import boto3

org_client = boto3.client("organizations")

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
        if account_status == "ACTIVE" and account_name != "Master Account":
            all_active_accounts.append(
                {"account_name": account_name, "account_id": account_id}
            )

    # Appending accounts to the list
print(all_active_accounts)
