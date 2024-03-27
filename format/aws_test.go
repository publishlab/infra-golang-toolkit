package format

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetEc2InstanceIdFromArn(t *testing.T) {
	result := GetEc2InstanceIdFromArn("arn:aws:ec2:us-west-1:1234567890:instance/i-1234567890abcdef")
	assert.Equal(t, "i-1234567890abcdef", result)
}

func TestGetEc2InstanceIdFromArnErr(t *testing.T) {
	arn := "invalid-arn"
	result := GetEc2InstanceIdFromArn(arn)
	assert.Equal(t, arn, result)
}

func TestConvertEcsTaskArnToClusterArn(t *testing.T) {
	result := ConvertEcsTaskArnToClusterArn("arn:aws:ecs:us-west-1:1234567890:task/my-cluster/3f8fae2a-33ce-4c19-ba06-3f3009a7c33a")
	assert.Equal(t, "arn:aws:ecs:us-west-1:1234567890:cluster/my-cluster", result)
}

func TestConvertEcsTaskArnToClusterArnErr(t *testing.T) {
	arn := "invalid-arn"
	result := ConvertEcsTaskArnToClusterArn(arn)
	assert.Equal(t, arn, result)
}
