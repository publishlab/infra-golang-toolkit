//
// Miscellaneous AWS string formatting
//

package format

import "regexp"

//
// ARN formatting
//

var arnEc2InstanceRe = regexp.MustCompile(`^arn:aws:ec2:.+/([^/]+)`)
var arnEcsTaskToClusterRe = regexp.MustCompile(`^(arn:aws:ecs:[^:]+:\d+):task/([^/]+)/.*`)

func GetEc2InstanceIdFromArn(arn string) string {
	return arnEc2InstanceRe.ReplaceAllString(arn, "${1}")
}

func ConvertEcsTaskArnToClusterArn(arn string) string {
	return arnEcsTaskToClusterRe.ReplaceAllString(arn, "${1}:cluster/${2}")
}
