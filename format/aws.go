//
// Miscellaneous AWS string formatting
//

package format

import "regexp"

//
// ARN formatting
//

var arnEc2InstanceRe = regexp.MustCompile(`^arn:aws:ec2:.+/([^/]+)`)
var arnLoadBalancerIdRe = regexp.MustCompile(`^arn:aws:elasticloadbalancing:[^:]+:\d+:loadbalancer/(.+)$`)
var arnEcsTaskToClusterRe = regexp.MustCompile(`^(arn:aws:ecs:[^:]+:\d+):task/([^/]+)/.*`)
var arnCloudFrontDistributionRe = regexp.MustCompile(`^arn:aws:cloudfront::\d+:distribution/([^/]+)`)

func Ec2InstanceIdFromArn(arn string) string {
	return arnEc2InstanceRe.ReplaceAllString(arn, "${1}")
}

func LoadBalancerIdFromArn(arn string) string {
	return arnLoadBalancerIdRe.ReplaceAllString(arn, "${1}")
}

func EcsTaskArnToClusterArn(arn string) string {
	return arnEcsTaskToClusterRe.ReplaceAllString(arn, "${1}:cluster/${2}")
}

func CloudFrontDistributionIdFromArn(arn string) string {
	return arnCloudFrontDistributionRe.ReplaceAllString(arn, "${1}")
}
