# AWS Network RDP/SSH Audit

Script to audit the security groups and network acls within all accounts in an AWS org for open ssh or rdp access (ingress) from the internet

## Assumptions

- The script will be run from the management account of the AWS org
- The script will be run with AdministratorAccess permissions
- There should be `OrganizationAccountAccessRole` roles in all the member accounts
- The script user should be assume the `OrganizationAccountAccessRole into the member accounts

## How to run

1. Ensure you have Go installed on your machine. You can download it from [here](https://golang.org/dl/).

2. Clone the repository to your local machine.

    `git clone https://github.com/ezebunandu/aws-security-group-audit`

3. Navigate to the directory containing the script.

    `cd aws-security-group-audit`

4. Run the script using the `go run` command.

    `go run main.go`

## Expected Output
