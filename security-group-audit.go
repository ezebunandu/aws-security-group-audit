package main

import (
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/organizations"
)

var CROSS_ACCOUNT_ACCESS_ROLE_NAME string = "OrganizationAccountAccessRole"
var MASTER_ACCOUNT_NAME string = "securing-the-cloud"

type Violation struct {
	AccountId string
	Type      string // "SecurityGroup" or "NetworkACL"
	Region    string
	Protocol  string
	Port      int64
}

// getActiveAccounts retrieves all active accounts in an AWS organization.
// It returns a slice of maps, where each map represents an active account with its name and ID.
func getActiveAccounts(sess *session.Session) []map[string]string {
	svc := organizations.New(sess)

	input := &organizations.ListAccountsInput{}

	result, err := svc.ListAccounts(input)
	if err != nil {
		fmt.Println("Error listing accounts,", err)
		return nil
	}

	var allActiveAccounts []map[string]string

	for _, account := range result.Accounts {
		if *account.Status == "ACTIVE" {
			allActiveAccounts = append(allActiveAccounts, map[string]string{
				"account_name": *account.Name,
				"account_id":   *account.Id,
			})
		}
	}

	return allActiveAccounts
}

// checkSecurityGroups checks the security groups of a given AWS account for rules that allow SSH or RDP traffic from all IPv4 or IPv6 addresses.
// If it finds a rule that matches the criteria, it prints a message to the console.
func checkSecurityGroups(sess *session.Session, accountId string, region string) []Violation {
	svc := ec2.New(sess)

	input := &ec2.DescribeSecurityGroupsInput{}

	result, err := svc.DescribeSecurityGroups(input)
	if err != nil {
		fmt.Println("Error describing security groups for account", accountId, "in region", region, err)
		return nil
	}

	var violations []Violation

	for _, group := range result.SecurityGroups {
		for _, permission := range group.IpPermissions {
			for _, rangeInfo := range permission.IpRanges {
				if *rangeInfo.CidrIp == "0.0.0.0/0" && *permission.IpProtocol == "tcp" && (*permission.FromPort == 22 || *permission.FromPort == 3389) {
					violations = append(violations, Violation{
						AccountId: accountId,
						Type:      "SecurityGroup",
						Region:    region,
						Protocol:  *permission.IpProtocol,
						Port:      *permission.FromPort,
					})
				}
			}
			for _, ipv6RangeInfo := range permission.Ipv6Ranges {
				if *ipv6RangeInfo.CidrIpv6 == "::/0" && *permission.IpProtocol == "tcp" && (*permission.FromPort == 22 || *permission.FromPort == 3389) {
					violations = append(violations, Violation{
						AccountId: accountId,
						Type:      "SecurityGroup",
						Region:    region,
						Protocol:  *permission.IpProtocol,
						Port:      *permission.FromPort,
					})
				}
			}
		}
	}
	return violations
}

// checkNetworkACLs checks the network ACLs of a given AWS account for entries that allow SSH or RDP traffic from all IPv4 or IPv6 addresses.
// If it finds such an entry, it prints a message to the console.
func checkNetworkACLs(sess *session.Session, accountId string, region string) []Violation {
	svc := ec2.New(sess)
	input := &ec2.DescribeNetworkAclsInput{}

	result, err := svc.DescribeNetworkAcls(input)
	if err != nil {
		fmt.Println("Error describing network ACLs for account", accountId, "in region", region, err)
		return nil
	}

	var violations []Violation
	for _, nacl := range result.NetworkAcls {
		if nacl.NetworkAclId == nil {
			continue
		}
		for _, entry := range nacl.Entries {
			if entry == nil || entry.RuleAction == nil || entry.Egress == nil || entry.Protocol == nil || entry.PortRange == nil || entry.PortRange.To == nil {
				continue
			}
			if *entry.RuleAction == "allow" && !*entry.Egress && *entry.Protocol != "-1" {
				if *entry.PortRange.To == 22 || *entry.PortRange.To == 3389 {
					if entry.CidrBlock != nil && *entry.CidrBlock == "0.0.0.0/0" {
						violations = append(violations, Violation{
							AccountId: accountId,
							Type:      "NetworkACL",
							Region:    region,
							Protocol:  *entry.Protocol,
							Port:      *entry.PortRange.To,
						})
					}
					if entry.Ipv6CidrBlock != nil && *entry.Ipv6CidrBlock == "::/0" {
						violations = append(violations, Violation{
							AccountId: accountId,
							Type:      "NetworkACL",
							Region:    region,
							Protocol:  *entry.Protocol,
							Port:      *entry.PortRange.To,
						})
					}
				}
			}
		}
	}

	return violations
}

// getActiveRegions retrieves all active regions in an AWS account.
// It returns a slice of their names.
func getActiveRegions(sess *session.Session) []string {
	svc := ec2.New(sess)

	input := &ec2.DescribeRegionsInput{}

	result, err := svc.DescribeRegions(input)
	if err != nil {
		fmt.Println("Error describing regions,", err)
		return nil
	}

	var activeRegions []string
	for _, region := range result.Regions {
		activeRegions = append(activeRegions, *region.RegionName)
	}

	return activeRegions
}

func main() {
	sess, err := session.NewSession(&aws.Config{})
	if err != nil {
		fmt.Println("Error creating session,", err)
		return
	}

	activeAccounts := getActiveAccounts(sess)
	var wg sync.WaitGroup
	for _, account := range activeAccounts {
		if account["account_name"] != MASTER_ACCOUNT_NAME {
			wg.Add(1)
			go func(account map[string]string) {
				defer wg.Done()
				roleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", account["account_id"], CROSS_ACCOUNT_ACCESS_ROLE_NAME)
				creds := stscreds.NewCredentials(sess, roleArn)
				sessWithCreds := session.Must(session.NewSession(&aws.Config{
					Credentials: creds,
				}))

				activeRegions := getActiveRegions(sessWithCreds)
				var regionWg sync.WaitGroup
				for _, region := range activeRegions {
					regionWg.Add(1)
					go func(region string) {
						defer regionWg.Done()
						sessWithRegion := sessWithCreds.Copy(&aws.Config{Region: aws.String(region)})
						violations := checkSecurityGroups(sessWithRegion, account["account_id"], region)
						for _, violation := range violations {
							fmt.Printf("Violation found: %+v\n", violation)
						}
						naclViolations := checkNetworkACLs(sessWithRegion, account["account_id"], region)
						for _, violation := range naclViolations {
							fmt.Printf("Violation found: %+v\n", violation)
						}
					}(region)
				}
				regionWg.Wait()
			}(account)
		}
	}
	wg.Wait()
}
