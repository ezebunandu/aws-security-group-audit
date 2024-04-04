package main

import (
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
)

func describeSecurityGroupsInRegion(region string, wg *sync.WaitGroup, sess *session.Session) {
	defer wg.Done()

	svc := ec2.New(sess, &aws.Config{Region: aws.String(region)})

	result, err := svc.DescribeSecurityGroups(nil)
	if err != nil {
		fmt.Println("Error describing security groups in region", region, err)
		return
	}

	for _, group := range result.SecurityGroups {
		fmt.Println("Security Group:", *group.GroupId, "Region:", region)
		for _, permission := range group.IpPermissions {
			for _, rangeInfo := range permission.IpRanges {
				if *rangeInfo.CidrIp == "0.0.0.0/0" && *permission.IpProtocol == "tcp" && *permission.FromPort == 22 {
					fmt.Println("Allows SSH from the internet")
				}
			}
			for _, rangeInfo := range permission.Ipv6Ranges {
				if *rangeInfo.CidrIpv6 == "::/0" && *permission.IpProtocol == "tcp" && *permission.FromPort == 22 {
					fmt.Println("Allows SSH from the internet over IPv6")
				}
			}
		}
	}
}

func main() {
	sess, err := session.NewSession(&aws.Config{})
	if err != nil {
		fmt.Println("Error creating session,", err)
		return
	}

	regions, ok := endpoints.RegionsForService(endpoints.DefaultPartitions(), endpoints.AwsPartitionID, endpoints.Ec2ServiceID)
	if !ok {
		fmt.Println("Error getting regions")
		return
	}

	var wg sync.WaitGroup
	for region := range regions {
		wg.Add(1)
		go describeSecurityGroupsInRegion(region, &wg, sess)
	}
	wg.Wait()
}
