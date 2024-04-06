package main

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/organizations"
)

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

func checkSecurityGroups(sess *session.Session, accountId string) {
	svc := ec2.New(sess)

	input := &ec2.DescribeSecurityGroupsInput{}

	result, err := svc.DescribeSecurityGroups(input)
	if err != nil {
		fmt.Println("Error describing security groups for account", accountId, err)
		return
	}

	for _, group := range result.SecurityGroups {
		for _, permission := range group.IpPermissions {
			for _, rangeInfo := range permission.IpRanges {
				if *rangeInfo.CidrIp == "0.0.0.0/0" && *permission.IpProtocol == "tcp" && (*permission.FromPort == 22 || *permission.FromPort == 3389) {
					fmt.Println("Security Group:", *group.GroupId, "in account", accountId, "allows SSH or RDP from the internet")
				}
			}
		}
	}
}
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
	for _, account := range activeAccounts {
		if account["account_name"] == "securing-the-cloud" {
			fmt.Println("Account Name:", account["account_name"], "Account ID:", account["account_id"])
			activeRegions := getActiveRegions(sess)
			for _, region := range activeRegions {
				fmt.Println("Active Region:", region)
			}
		}
	}
}
